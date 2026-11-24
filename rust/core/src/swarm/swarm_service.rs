//! Hands out the store's bundles on the torrent virtual port, and the other
//! side of the exchange: one holder of a bundle as the downloader sees it.
//!
//! The service knows nothing of what it hands out: headers, marks and encrypted
//! pieces. Who asks is unknown too — the stream came through a circuit or a
//! meeting point, and that is all there is to it.
//!
//! ## Decoupling from the relay stack
//!
//! In the C# node the service is an `IPortService` bound to a `PortStack`, and
//! the peer wraps an `IMessageChannel`. Those live in the Streams/relay layer,
//! which is being ported separately, so this module does not depend on them.
//! Instead:
//!
//! * [`ReplyStream`] is what the service answers through — the server side of one
//!   stream (the C# `ServerStream.Send` / `IsOpen`). The relay layer supplies an
//!   adapter, and binds the service on the torrent port itself.
//! * [`MessageChannel`] is the downloader's side of one stream to a seeder (the
//!   C# `IMessageChannel`). Whatever keeps the stream alive — a circuit or a
//!   meeting — is owned by the channel and released when it is dropped.
//!
//! The torrent virtual port is `5` (`WellKnownPorts.Swarm`); the relay layer
//! passes it when it binds the service, so it is noted here only as a reminder.

use crate::swarm::bundle_link::BundleLink;
use crate::swarm::bundle_manifest::Reader;
use crate::swarm::swarm_protocol as proto;
use crate::swarm::swarm_protocol::{SwarmOp, SwarmStatus};
use crate::swarm::swarm_store::{StoredBundle, SwarmStore};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

/// The torrent virtual port a holder hands bundles out on
/// (`WellKnownPorts.Swarm` in the C#). The relay layer binds the service here.
pub const TORRENT_PORT: u16 = 5;

/// The server side of one stream the service answers through.
pub trait ReplyStream {
    /// Sends one application message towards the asker.
    fn send(&self, data: &[u8]);
    /// Whether the stream is still open.
    fn is_open(&self) -> bool;
}

/// Per-stream state: which bundle was picked, and the last piece read from disk.
pub struct SwarmSession {
    bundle: Option<Arc<StoredBundle>>,
    piece_index: i32,
    piece: Option<Vec<u8>>,
}

impl Default for SwarmSession {
    fn default() -> Self {
        SwarmSession {
            bundle: None,
            piece_index: -1,
            piece: None,
        }
    }
}

pub struct SwarmService {
    store: Arc<SwarmStore>,
    pieces_served: AtomicU64,
}

impl SwarmService {
    pub fn new(store: Arc<SwarmStore>) -> SwarmService {
        SwarmService {
            store,
            pieces_served: AtomicU64::new(0),
        }
    }

    /// How many pieces went out — for the window's counter.
    pub fn pieces_served(&self) -> u64 {
        self.pieces_served.load(Ordering::Relaxed)
    }

    /// A fresh session for a newly opened stream (the C# `OnOpen`).
    pub fn on_open(&self) -> SwarmSession {
        SwarmSession::default()
    }

    /// Handles one request message on a stream.
    pub fn on_data(&self, session: &mut SwarmSession, data: &[u8], stream: &dyn ReplyStream) {
        let (op, payload) = match proto::try_read_request(data) {
            Some(parts) => parts,
            None => {
                reply(stream, SwarmOp::Open, SwarmStatus::BadRequest, &[]);
                return;
            }
        };

        match op {
            SwarmOp::Open => self.do_open(session, stream, payload),
            SwarmOp::Bitfield | SwarmOp::Header | SwarmOp::Piece => self.do_range(session, stream, op, payload),
        }
    }

    fn do_open(&self, session: &mut SwarmSession, stream: &dyn ReplyStream, payload: &[u8]) {
        if payload.len() < BundleLink::HASH_SIZE {
            reply(stream, SwarmOp::Open, SwarmStatus::BadRequest, &[]);
            return;
        }
        let hash = &payload[..BundleLink::HASH_SIZE];

        let bundle = match self.store.open(hash) {
            Some(b) => b,
            None => {
                reply(stream, SwarmOp::Open, SwarmStatus::NoBundle, &[]);
                return;
            }
        };

        let mut body = Vec::with_capacity(12);
        body.extend_from_slice(&(bundle.header().bytes().len() as i32).to_le_bytes());
        body.extend_from_slice(&bundle.header().piece_count().to_le_bytes());
        body.extend_from_slice(&bundle.have_count().to_le_bytes());

        session.bundle = Some(bundle);
        session.piece_index = -1;
        session.piece = None;

        reply(stream, SwarmOp::Open, SwarmStatus::Ok, &body);
    }

    fn do_range(&self, session: &mut SwarmSession, stream: &dyn ReplyStream, op: SwarmOp, payload: &[u8]) {
        let bundle = match session.bundle.clone() {
            Some(b) => b,
            None => {
                reply(stream, op, SwarmStatus::NotOpen, &[]);
                return;
            }
        };

        let mut reader = Reader::new(payload);

        let source: Vec<u8> = match op {
            SwarmOp::Bitfield => bundle.bitfield(),
            SwarmOp::Header => bundle.header().bytes().to_vec(),
            SwarmOp::Piece => {
                let index = match reader.i32() {
                    Ok(i) => i,
                    Err(_) => {
                        reply(stream, op, SwarmStatus::BadRequest, &[]);
                        return;
                    }
                };

                // The last piece is kept: it is asked for in windows, and reading
                // it from disk afresh for every window would cost dozens of reads
                // per piece.
                if session.piece_index != index || session.piece.is_none() {
                    session.piece = bundle.read_piece(index);
                    session.piece_index = if session.piece.is_none() { -1 } else { index };
                }

                match &session.piece {
                    Some(p) => p.clone(),
                    None => {
                        reply(stream, op, SwarmStatus::NoPiece, &[]);
                        return;
                    }
                }
            }
            SwarmOp::Open => return, // never reached
        };

        let (first, count) = match (reader.i32(), reader.u16()) {
            (Ok(f), Ok(c)) => (f, c as i32),
            _ => {
                reply(stream, op, SwarmStatus::BadRequest, &[]);
                return;
            }
        };

        let total = proto::chunks_for(source.len() as i64);
        if first < 0 || count <= 0 || count as usize > proto::MAX_CHUNKS_PER_REQUEST || (total > 0 && first >= total) {
            reply(stream, op, SwarmStatus::BadRequest, &[]);
            return;
        }

        let last = total.min(first + count);
        for chunk in first..last {
            if !stream.is_open() {
                return;
            }
            let offset = chunk as usize * proto::CHUNK_SIZE;
            let length = proto::CHUNK_SIZE.min(source.len() - offset);
            stream.send(&proto::chunk(op, chunk, &source, offset, length));
        }

        if op == SwarmOp::Piece && last == total {
            self.pieces_served.fetch_add(1, Ordering::Relaxed);
        }
    }
}

fn reply(stream: &dyn ReplyStream, op: SwarmOp, status: SwarmStatus, body: &[u8]) {
    if !stream.is_open() {
        return;
    }
    stream.send(&proto::response(op, status, body));
}

/// The downloader's side of one stream to a seeder.
///
/// Whatever keeps the stream alive — a circuit or a meeting point — is owned by
/// the implementation and released when it is dropped.
pub trait MessageChannel: Send {
    fn send(&self, data: &[u8]);
    /// Waits up to `timeout` for the next message. `None` on timeout or a closed
    /// channel.
    fn receive(&self, timeout: Duration) -> Option<Vec<u8>>;
    fn is_open(&self) -> bool;
    fn close(&self);
}

/// One holder of a bundle as the one who downloads sees it.
pub struct SwarmPeer {
    channel: Box<dyn MessageChannel>,
    timeout: Duration,
    label: String,
    header_length: i32,
    piece_count: i32,
    have_count: i32,
}

impl SwarmPeer {
    /// `channel` is a stream to the holder's torrent port.
    pub fn new(channel: Box<dyn MessageChannel>) -> SwarmPeer {
        SwarmPeer {
            channel,
            timeout: Duration::from_secs(60),
            label: String::new(),
            header_length: 0,
            piece_count: 0,
            have_count: 0,
        }
    }

    pub fn set_timeout(&mut self, timeout: Duration) {
        self.timeout = timeout;
    }

    /// The holder's address — for the log and for excluding it after a lie.
    pub fn set_label(&mut self, label: impl Into<String>) {
        self.label = label.into();
    }
    pub fn label(&self) -> &str {
        &self.label
    }

    pub fn is_open(&self) -> bool {
        self.channel.is_open()
    }
    pub fn header_length(&self) -> i32 {
        self.header_length
    }
    pub fn piece_count(&self) -> i32 {
        self.piece_count
    }
    pub fn have_count(&self) -> i32 {
        self.have_count
    }

    /// Picks the bundle. `false` if the holder does not have it.
    pub fn open(&mut self, info_hash: &[u8]) -> bool {
        self.channel.send(&proto::request(SwarmOp::Open, info_hash));

        let answer = match self.channel.receive(self.timeout) {
            Some(a) => a,
            None => return false,
        };
        let (op, status, payload) = match proto::try_read_response(&answer) {
            Some(parts) => parts,
            None => return false,
        };
        if op != SwarmOp::Open || status != SwarmStatus::Ok {
            return false;
        }

        let mut reader = Reader::new(payload);
        self.header_length = reader.i32().unwrap_or(0);
        self.piece_count = reader.i32().unwrap_or(-1);
        self.have_count = reader.i32().unwrap_or(-1);

        // The sizes come from the holder and are allocated for as they stand:
        // a lying holder must not make us reserve gigabytes.
        use crate::swarm::bundle_header::BundleHeader;
        let max_header =
            4096 + BundleHeader::MAX_PIECES as usize * BundleHeader::HASH_SIZE + BundleHeader::MAX_SEALED_MANIFEST;
        self.header_length > 0
            && self.header_length as usize <= max_header
            && self.piece_count >= 0
            && self.piece_count <= BundleHeader::MAX_PIECES
    }

    pub fn fetch_header(&self) -> Option<Vec<u8>> {
        self.fetch_range(SwarmOp::Header, self.header_length, None)
    }

    pub fn fetch_bitfield(&self) -> Option<Vec<u8>> {
        self.fetch_range(SwarmOp::Bitfield, (self.piece_count + 7) / 8, None)
    }

    /// A piece, not yet checked — the store checks it against its hash.
    pub fn fetch_piece(&self, index: i32, length: i32) -> Option<Vec<u8>> {
        self.fetch_range(SwarmOp::Piece, length, Some(index))
    }

    fn fetch_range(&self, op: SwarmOp, length: i32, prefix_index: Option<i32>) -> Option<Vec<u8>> {
        if length <= 0 {
            return Some(Vec::new());
        }

        let length = length as usize;
        let mut result = vec![0u8; length];
        let total = proto::chunks_for(length as i64);

        let mut first = 0i32;
        while first < total {
            let count = proto::MAX_CHUNKS_PER_REQUEST.min((total - first) as usize) as i32;

            let mut req = Vec::new();
            if let Some(index) = prefix_index {
                req.extend_from_slice(&index.to_le_bytes());
            }
            req.extend_from_slice(&first.to_le_bytes());
            req.extend_from_slice(&(count as u16).to_le_bytes());
            self.channel.send(&proto::request(op, &req));

            for _ in 0..count {
                let message = self.channel.receive(self.timeout)?;
                if message.len() < 2 {
                    return None;
                }
                // A refusal is an answer with a status other than Ok.
                if message[1] != SwarmStatus::Ok as u8 {
                    return None;
                }

                let (index, content) = proto::try_read_chunk(op, &message)?;
                if index < first || index >= first + count {
                    return None;
                }

                let offset = index as usize * proto::CHUNK_SIZE;
                let expected = proto::CHUNK_SIZE.min(length - offset);
                if content.len() != expected {
                    return None;
                }

                result[offset..offset + expected].copy_from_slice(content);
            }

            first += proto::MAX_CHUNKS_PER_REQUEST as i32;
        }

        Some(result)
    }
}

impl Drop for SwarmPeer {
    fn drop(&mut self) {
        self.channel.close();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::aead_aes_ctr_hmac as aead;
    use crate::swarm::bundle_header::BundleHeader;
    use sha2::{Digest, Sha256};
    use std::collections::VecDeque;
    use std::path::PathBuf;
    use std::sync::Mutex;

    // A reply stream that just records every message it is handed.
    struct Recorder {
        sent: Mutex<Vec<Vec<u8>>>,
    }
    impl ReplyStream for Recorder {
        fn send(&self, data: &[u8]) {
            self.sent.lock().unwrap().push(data.to_vec());
        }
        fn is_open(&self) -> bool {
            true
        }
    }

    // A channel that drives a SwarmService directly, in memory, so the peer and
    // the service can be tested end to end without the relay layer.
    struct LoopbackChannel {
        service: Arc<SwarmService>,
        session: Mutex<SwarmSession>,
        inbox: Mutex<VecDeque<Vec<u8>>>,
    }
    impl MessageChannel for LoopbackChannel {
        fn send(&self, data: &[u8]) {
            let recorder = Recorder { sent: Mutex::new(Vec::new()) };
            {
                let mut session = self.session.lock().unwrap();
                self.service.on_data(&mut session, data, &recorder);
            }
            let mut inbox = self.inbox.lock().unwrap();
            for m in recorder.sent.into_inner().unwrap() {
                inbox.push_back(m);
            }
        }
        fn receive(&self, _timeout: Duration) -> Option<Vec<u8>> {
            self.inbox.lock().unwrap().pop_front()
        }
        fn is_open(&self) -> bool {
            true
        }
        fn close(&self) {}
    }

    fn temp_dir(name: &str) -> PathBuf {
        let mut p = std::env::temp_dir();
        p.push(format!("stalknet_svc_{}_{}", std::process::id(), name));
        let _ = std::fs::remove_dir_all(&p);
        p
    }

    #[test]
    fn peer_fetches_header_bitfield_and_piece() {
        let root = temp_dir("svc");
        let store = Arc::new(SwarmStore::new(&root).unwrap());

        // Build a one-piece bundle by hand and adopt it complete.
        let piece = vec![0xabu8; BundleHeader::MIN_PIECE_SIZE as usize];
        let mut hash = [0u8; 32];
        hash.copy_from_slice(&Sha256::digest(&piece));
        let sealed = vec![0u8; aead::OVERHEAD];
        let header = BundleHeader::create(BundleHeader::MIN_PIECE_SIZE, piece.len() as i64, &sealed, &[hash]).unwrap();
        let info_hash = *header.info_hash();

        let bundle = store.add_header(&info_hash, header.bytes()).unwrap();
        assert!(bundle.write_piece(0, &piece));

        let service = Arc::new(SwarmService::new(store.clone()));
        let channel = Box::new(LoopbackChannel {
            service: service.clone(),
            session: Mutex::new(service.on_open()),
            inbox: Mutex::new(VecDeque::new()),
        });

        let mut peer = SwarmPeer::new(channel);
        assert!(peer.open(&info_hash));
        assert_eq!(peer.piece_count(), 1);
        assert_eq!(peer.have_count(), 1);

        let fetched_header = peer.fetch_header().unwrap();
        assert_eq!(fetched_header, header.bytes());

        let fetched_bitfield = peer.fetch_bitfield().unwrap();
        assert_eq!(fetched_bitfield, bundle.bitfield());

        let fetched_piece = peer.fetch_piece(0, piece.len() as i32).unwrap();
        assert_eq!(fetched_piece, piece);
        assert_eq!(service.pieces_served(), 1);

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn unknown_bundle_is_refused() {
        let root = temp_dir("unknown");
        let store = Arc::new(SwarmStore::new(&root).unwrap());
        let service = Arc::new(SwarmService::new(store.clone()));
        let channel = Box::new(LoopbackChannel {
            service: service.clone(),
            session: Mutex::new(service.on_open()),
            inbox: Mutex::new(VecDeque::new()),
        });
        let mut peer = SwarmPeer::new(channel);
        assert!(!peer.open(&[0u8; 32]));
        let _ = std::fs::remove_dir_all(&root);
    }
}
