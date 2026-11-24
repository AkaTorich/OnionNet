//! The asking side of a relay's desk, over a stream on one of our circuits.
//!
//! The C# `PeerClient` is handed a `ClientStream` opened on virtual port 1 and
//! talks through its `Send`/`Receive`. That stream layer is not ported yet, so
//! the client talks through a [`DeskLink`]: send one request message, get one
//! response message. [`CircuitDeskLink`] is the straightforward binding over a
//! ported [`Circuit`] — it frames each message as a `RelayCommand::Data` cell and
//! uses `Circuit::exchange`. The message logic itself (the chunked card download,
//! the piecewise offer) is ported exactly from the C#.

use crate::protocol::relay_cell::{RelayCell, RelayCommand};
use crate::transport::circuit::Circuit;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use super::peer_protocol::{self as proto, Cursor, PeerOp, PeerStatus};
use super::peer_service::{PeerDesk, PEERS_PORT};
use crate::identity::onion_address::FINGERPRINT_SIZE;

const DEFAULT_TIMEOUT: Duration = Duration::from_secs(30);

/// The ceiling on a bundle of cards. The size is named by the far side while the
/// memory is ours; without a ceiling a hostile relay names two gigabytes and we
/// fall over before a byte has arrived.
const MAX_BUNDLE: usize = 4 * 1024 * 1024;

/// How the client reaches a remote desk: one request message in, one response
/// message out. Mirrors `ClientStream.Send` + `Receive`.
pub trait DeskLink {
    fn is_open(&self) -> bool;
    /// Sends a request and waits for the reply. `None` if the link is down or no
    /// answer came.
    fn exchange(&self, request: &[u8]) -> Option<Vec<u8>>;
}

/// A [`DeskLink`] over a built circuit: the request rides as a `RelayCommand::Data`
/// cell on a stream id, to the last hop's desk on virtual port 1.
///
/// The real stream layer would first open the stream with a `Begin` naming port
/// 1 ([`PEERS_PORT`]) and await `Connected`; until it is ported the data cells go
/// straight to the exit, which is enough for the message exchange.
pub struct CircuitDeskLink<'a> {
    circuit: &'a Circuit,
    stream_id: u16,
    timeout: Duration,
    open: AtomicBool,
}

impl<'a> CircuitDeskLink<'a> {
    pub fn new(circuit: &'a Circuit, stream_id: u16, timeout: Duration) -> CircuitDeskLink<'a> {
        CircuitDeskLink {
            circuit,
            stream_id,
            timeout,
            open: AtomicBool::new(true),
        }
    }

    /// The virtual port the stream speaks to, kept for the stream layer that will
    /// open it: [`PEERS_PORT`].
    pub fn port(&self) -> u16 {
        PEERS_PORT
    }
}

impl DeskLink for CircuitDeskLink<'_> {
    fn is_open(&self) -> bool {
        self.open.load(Ordering::Acquire)
    }

    fn exchange(&self, request: &[u8]) -> Option<Vec<u8>> {
        if !self.is_open() {
            return None;
        }
        let cell = RelayCell::new(RelayCommand::Data, self.stream_id, request.to_vec());
        match self.circuit.exchange(&cell, self.timeout) {
            Ok(Some(answer)) => Some(answer.data),
            Ok(None) => None,
            Err(_) => {
                self.open.store(false, Ordering::Release);
                None
            }
        }
    }
}

pub struct PeerClient<L: DeskLink> {
    link: L,
    timeout: Duration,
}

impl<L: DeskLink> PeerClient<L> {
    pub fn new(link: L) -> PeerClient<L> {
        PeerClient {
            link,
            timeout: DEFAULT_TIMEOUT,
        }
    }

    pub fn set_timeout(&mut self, timeout: Duration) {
        self.timeout = timeout;
    }

    pub fn timeout(&self) -> Duration {
        self.timeout
    }

    // ---- Cards -------------------------------------------------------------

    /// The cards the relay knows, as their owners signed them. `None` if they did
    /// not arrive whole.
    pub fn cards(&self) -> Option<Vec<Vec<u8>>> {
        let (status, payload) = self.ask(PeerOp::Cards, |_| {})?;
        if status == PeerStatus::Empty {
            return Some(Vec::new());
        }
        if status != PeerStatus::Ok {
            return None;
        }

        let (total, chunks) = {
            let mut r = Cursor::new(&payload);
            (r.i32_le()?, r.u16_le()?)
        };

        if total <= 0 || chunks == 0 || total as usize > MAX_BUNDLE {
            return None;
        }
        let total = total as usize;

        let mut bundle = vec![0u8; total];
        let mut position = 0usize;

        for index in 0..chunks as i32 {
            if !self.link.is_open() {
                return None;
            }

            let request = proto::request(PeerOp::CardsChunk, |w| w.extend_from_slice(&index.to_le_bytes())).ok()?;
            let answer = self.link.exchange(&request)?;

            let (got_index, content) = proto::try_read_chunk(PeerOp::CardsChunk, &answer)?;
            if got_index != index || position + content.len() > total {
                return None;
            }
            bundle[position..position + content.len()].copy_from_slice(&content);
            position += content.len();
        }

        if position != total {
            return None;
        }

        parse_bundle(&bundle)
    }

    /// Offers our own card, a piece at a time. The answer says only whether it
    /// was parsed.
    pub fn offer(&self, signed_card: &[u8]) -> PeerStatus {
        if signed_card.is_empty() || signed_card.len() > proto::MAX_OFFERED_CARD {
            // The C# throws ArgumentException; a bad call never reaches the wire.
            return PeerStatus::BadRequest;
        }

        let mut offset = 0usize;
        loop {
            let length = std::cmp::min(proto::OFFER_PIECE, signed_card.len() - offset);
            let at = offset;

            let answered = self.ask(PeerOp::Offer, |w| {
                w.extend_from_slice(&(signed_card.len() as u16).to_le_bytes());
                w.extend_from_slice(&(at as u16).to_le_bytes());
                w.extend_from_slice(&signed_card[at..at + length]);
            });

            let status = match answered {
                Some((status, _)) => status,
                None => return PeerStatus::ServerError,
            };

            offset += length;
            if status != PeerStatus::More {
                return status;
            }
            if offset >= signed_card.len() {
                return PeerStatus::BadRequest;
            }
        }
    }

    // ---- The shared request step -------------------------------------------

    /// Sends a request and reads the standard response. `None` covers every C#
    /// `Ask` failure: a closed stream, no answer, an unreadable or mismatched
    /// reply.
    fn ask<F: FnOnce(&mut Vec<u8>)>(&self, op: PeerOp, body: F) -> Option<(PeerStatus, Vec<u8>)> {
        if !self.link.is_open() {
            return None;
        }
        let request = proto::request(op, body).ok()?;
        let answer = self.link.exchange(&request)?;
        let (answered, status, payload) = proto::try_read_response(&answer)?;
        if answered != op {
            return None;
        }
        Some((status, payload))
    }
}

impl<L: DeskLink> PeerDesk for PeerClient<L> {
    fn publish_service(&self, signed: &[u8]) -> PeerStatus {
        match self.ask(PeerOp::PublishService, |w| {
            w.extend_from_slice(&(signed.len() as u16).to_le_bytes());
            w.extend_from_slice(signed);
        }) {
            Some((status, _)) => status,
            None => PeerStatus::ServerError,
        }
    }

    /// A hidden address's announcement, as the service signed it. The caller
    /// re-parses and checks the fingerprint (the C# does so inline via
    /// `ServiceDescriptor.TryParse`; that type is not ported here, so the raw
    /// signed bytes come back for the caller to verify).
    fn fetch_service(&self, fingerprint: &[u8]) -> (Option<Vec<u8>>, PeerStatus) {
        let (status, payload) = match self.ask(PeerOp::FetchService, |w| w.extend_from_slice(fingerprint)) {
            Some(r) => r,
            None => return (None, PeerStatus::ServerError),
        };
        if status != PeerStatus::Ok {
            return (None, status);
        }

        let mut r = Cursor::new(&payload);
        match read_u16_prefixed(&mut r) {
            Some(signed) => (Some(signed), PeerStatus::Ok),
            None => (None, PeerStatus::BadCard),
        }
    }

    fn announce(&self, info_hash: &[u8], holder: &[u8]) -> PeerStatus {
        if info_hash.len() != 32 || holder.len() != super::holder_proof::SIZE {
            return PeerStatus::BadRequest;
        }
        match self.ask(PeerOp::Announce, |w| {
            w.extend_from_slice(info_hash);
            w.extend_from_slice(holder);
        }) {
            Some((status, _)) => status,
            None => PeerStatus::ServerError,
        }
    }

    fn holders(&self, info_hash: &[u8]) -> Option<Vec<Vec<u8>>> {
        if info_hash.len() != 32 {
            return None;
        }
        let (status, payload) = self.ask(PeerOp::Holders, |w| w.extend_from_slice(info_hash))?;
        if status != PeerStatus::Ok {
            return None;
        }

        let mut r = Cursor::new(&payload);
        let count = r.u8()? as usize;
        let mut holders = Vec::with_capacity(count);
        for _ in 0..count {
            let fingerprint = r.take(FINGERPRINT_SIZE)?;
            holders.push(fingerprint.to_vec());
        }
        Some(holders)
    }

    fn publish_site(&self, write_secret: &[u8], record: &[u8]) -> PeerStatus {
        match self.ask(PeerOp::PublishSite, |w| {
            w.extend_from_slice(write_secret);
            w.extend_from_slice(&(record.len() as u16).to_le_bytes());
            w.extend_from_slice(record);
        }) {
            Some((status, _)) => status,
            None => PeerStatus::ServerError,
        }
    }

    fn fetch_site(&self, lookup: &[u8]) -> (Option<Vec<u8>>, PeerStatus) {
        let (status, payload) = match self.ask(PeerOp::FetchSite, |w| w.extend_from_slice(lookup)) {
            Some(r) => r,
            None => return (None, PeerStatus::ServerError),
        };
        if status != PeerStatus::Ok {
            return (None, status);
        }

        let mut r = Cursor::new(&payload);
        match read_u16_prefixed(&mut r) {
            Some(record) => (Some(record), PeerStatus::Ok),
            None => (None, PeerStatus::BadCard),
        }
    }
}

/// Parses the downloaded bundle: a `u16` count, then each card as a `u16` length
/// and its bytes. `None` on a short or inconsistent bundle.
fn parse_bundle(bundle: &[u8]) -> Option<Vec<Vec<u8>>> {
    let mut r = Cursor::new(bundle);
    let count = r.u16_le()? as usize;
    let mut cards = Vec::with_capacity(count);
    for _ in 0..count {
        let card = read_u16_prefixed(&mut r)?;
        cards.push(card);
    }
    Some(cards)
}

fn read_u16_prefixed(r: &mut Cursor) -> Option<Vec<u8>> {
    let length = r.u16_le()? as usize;
    r.take(length).map(|b| b.to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::directory::relay_descriptor::set_required_proof_bits;
    use crate::identity::sybil_proof;
    use crate::identity::NodeIdentity;
    use crate::peers::peer_service::{DeskSession, PeerService, RecordParsers, ServiceFields, SiteFields};
    use crate::peers::peer_view::{CardVerdict, PeerView};
    use crate::directory::relay_descriptor::RelayDescriptor;
    use std::sync::{Arc, Mutex};

    /// An in-memory link that routes each request straight into a `PeerService`
    /// over a single desk session — the client and the desk, no circuit.
    struct LoopbackLink {
        service: Arc<PeerService>,
        session: Mutex<DeskSession>,
    }

    impl DeskLink for LoopbackLink {
        fn is_open(&self) -> bool {
            true
        }
        fn exchange(&self, request: &[u8]) -> Option<Vec<u8>> {
            let mut session = self.session.lock().unwrap();
            self.service.on_data(&mut session, request)
        }
    }

    fn test_parsers() -> RecordParsers {
        RecordParsers {
            service: Arc::new(|signed: &[u8]| {
                if signed.len() < FINGERPRINT_SIZE + 8 {
                    return None;
                }
                let mut fp = [0u8; FINGERPRINT_SIZE];
                fp.copy_from_slice(&signed[..FINGERPRINT_SIZE]);
                let mut t = [0u8; 8];
                t.copy_from_slice(&signed[FINGERPRINT_SIZE..FINGERPRINT_SIZE + 8]);
                Some(ServiceFields {
                    fingerprint: fp,
                    published_ticks: i64::from_le_bytes(t),
                })
            }),
            site: Arc::new(|record: &[u8]| {
                if record.len() < 32 + 8 {
                    return None;
                }
                let mut v = [0u8; 8];
                v.copy_from_slice(&record[32..40]);
                Some(SiteFields {
                    lookup: record[..32].to_vec(),
                    version: i64::from_le_bytes(v),
                })
            }),
        }
    }

    fn client_over(service: Arc<PeerService>) -> PeerClient<LoopbackLink> {
        PeerClient::new(LoopbackLink {
            service,
            session: Mutex::new(DeskSession::new()),
        })
    }

    #[test]
    fn service_round_trip_over_the_protocol() {
        let service = PeerService::new(Arc::new(PeerView::new()), test_parsers());
        let client = client_over(Arc::clone(&service));

        let fp = [4u8; FINGERPRINT_SIZE];
        let mut signed = fp.to_vec();
        signed.extend_from_slice(&123i64.to_le_bytes());

        assert_eq!(client.publish_service(&signed), PeerStatus::Ok);
        let (got, status) = client.fetch_service(&fp);
        assert_eq!(status, PeerStatus::Ok);
        assert_eq!(got.unwrap(), signed);
    }

    #[test]
    fn announce_holders_and_site_round_trip() {
        let service = PeerService::new(Arc::new(PeerView::new()), test_parsers());
        let client = client_over(Arc::clone(&service));

        let hash = [6u8; 32];
        let key = crate::identity::node_identity::NodeIdentity::create("").unwrap();
        let word = crate::peers::holder_proof::make(&key, &hash);
        assert_eq!(client.announce(&hash, &word), PeerStatus::Ok);
        let holders = client.holders(&hash).unwrap();
        assert_eq!(holders, vec![key.fingerprint().to_vec()]);

        let secret = [1u8; 32];
        let mut record = [9u8; 32].to_vec();
        record.extend_from_slice(&77i64.to_le_bytes());
        assert_eq!(client.publish_site(&secret, &record), PeerStatus::Ok);
        let (fetched, status) = client.fetch_site(&[9u8; 32]);
        assert_eq!(status, PeerStatus::Ok);
        assert_eq!(fetched.unwrap(), record);
    }

    #[test]
    fn cards_download_round_trips_in_chunks() {
        // Build a handful of real, valid cards.
        let mut want = Vec::new();
        for i in 0..5u16 {
            let id = NodeIdentity::create(&format!("r{i}")).unwrap();
            let mut desc = RelayDescriptor::from_identity(&id, "198.51.100.9", 9000 + i, true);
            let challenge = RelayDescriptor::proof_challenge(&desc.fingerprint());
            let nonce = sybil_proof::solve(&challenge, 4, || false, |_, _| {}).unwrap();
            desc.set_proof(nonce, 4);
            want.push(desc.to_signed_bytes(&id).unwrap());
        }

        // Offer them into a fresh view at difficulty 4, retrying against any
        // concurrent test that raises the shared global difficulty.
        let view = loop {
            set_required_proof_bits(4);
            let v = Arc::new(PeerView::new());
            if want.iter().all(|c| matches!(v.offer_bytes(c), CardVerdict::Added)) {
                break v;
            }
        };

        let service = PeerService::new(Arc::clone(&view), test_parsers());
        let client = client_over(service);

        let got = client.cards().expect("the bundle arrives whole");
        assert_eq!(got.len(), want.len());
        // Order is randomised by the desk, so compare as sets.
        for card in &want {
            assert!(got.contains(card));
        }
    }
}
