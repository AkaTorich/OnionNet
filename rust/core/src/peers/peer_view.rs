//! Everything this node knows about the network's relays.
//!
//! Nobody hands the list out: cards come from the torrent network's DHT, from the relays themselves — each one shares what
//! it knows — and from the file kept since the last run. Whatever the road, a
//! card is let in only on three conditions: it is signed by the relay's own key,
//! it was signed no more than three hours ago, and it carries a hard enough
//! Argon2id pass for exactly that key. A relay signs its card afresh every hour,
//! so a relay that went away drops out of every view by itself.
//!
//! The pass is checked once per key and remembered: it costs one Argon2id run,
//! while a card comes round again every hour from several sides.
//!
//! The wire format of the kept file (`node.peers`) and every acceptance rule
//! match the C# `PeerView` byte for byte.

use crate::crypto::rand;
use crate::directory::relay_descriptor::{required_proof_bits, RelayDescriptor};
use crate::directory::relay_list::RelayList;
use std::collections::HashMap;
use std::fs;
use std::io::Write;
use std::path::Path;
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

/// One hour in .NET ticks (100 ns units), as `RelayDescriptor.published_ticks`
/// is measured.
const TICKS_PER_HOUR: i64 = 36_000_000_000;

/// A card older than this is a relay that went away. Three hours — matches
/// `PeerView.MaxAge`.
pub const MAX_AGE_TICKS: i64 = 3 * TICKS_PER_HOUR;

/// How far ahead of our clock a card may be dated. Home machines drift; much
/// more than this is a card issued in advance. Two hours — matches
/// `PeerView.FutureTolerance`.
pub const FUTURE_TOLERANCE_TICKS: i64 = 2 * TICKS_PER_HOUR;

pub const MAX_CARDS: usize = 4096;
const MAX_PROOF_MEMORY: usize = 16384;

/// `'O' 'N' 'P' 'S' 1` — the magic of the kept `node.peers` file.
const FILE_MAGIC: [u8; 5] = [b'O', b'N', b'P', b'S', 1];

/// What became of a card offered to the view.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CardVerdict {
    /// A relay we did not know.
    Added,
    /// A fresher card of a relay we knew.
    Updated,
    /// The same card or an older one — nothing changed.
    Known,
    /// The signature, the age or the pass does not hold.
    Rejected,
}

struct Inner {
    /// Keyed by the lowercase hex of the fingerprint, as the C# `Dictionary`
    /// with an ordinal comparer.
    cards: HashMap<String, RelayDescriptor>,
    /// The per-key pass cache: whether the recorded `(key, proof, bits)` held.
    proofs: HashMap<String, bool>,
}

pub struct PeerView {
    inner: Mutex<Inner>,
}

impl Default for PeerView {
    fn default() -> Self {
        PeerView::new()
    }
}

impl PeerView {
    pub fn new() -> PeerView {
        PeerView {
            inner: Mutex::new(Inner {
                cards: HashMap::new(),
                proofs: HashMap::new(),
            }),
        }
    }

    /// How many relays the view holds, stale ones included until the next
    /// pruning.
    pub fn count(&self) -> usize {
        self.inner.lock().unwrap().cards.len()
    }

    /// Offers a card as it came over the wire.
    pub fn offer_bytes(&self, signed: &[u8]) -> CardVerdict {
        match RelayDescriptor::try_parse(signed) {
            Some(card) => self.offer(card),
            None => CardVerdict::Rejected,
        }
    }

    /// Offers a parsed card. The signature was checked by the parsing.
    pub fn offer(&self, card: RelayDescriptor) -> CardVerdict {
        if card.signed_bytes().is_none() {
            return CardVerdict::Rejected;
        }
        if !PeerView::is_fresh(&card) {
            return CardVerdict::Rejected;
        }

        let key = hex(&card.fingerprint());

        {
            let inner = self.inner.lock().unwrap();
            if let Some(known) = inner.cards.get(&key) {
                if known.published_ticks >= card.published_ticks {
                    return CardVerdict::Known;
                }
            }
        }

        // Outside the lock: an Argon2id run takes tens of milliseconds, and the
        // circuits must not wait on it.
        if !self.pass_holds(&card) {
            return CardVerdict::Rejected;
        }

        let mut inner = self.inner.lock().unwrap();
        let had = inner.cards.contains_key(&key);

        // Checked again: while the pass was being checked, a fresher card of the
        // same relay may have come in by another road.
        if let Some(known) = inner.cards.get(&key) {
            if known.published_ticks >= card.published_ticks {
                return CardVerdict::Known;
            }
        }

        inner.cards.insert(key, card);
        if !had && inner.cards.len() > MAX_CARDS {
            evict_oldest(&mut inner.cards);
        }

        if had {
            CardVerdict::Updated
        } else {
            CardVerdict::Added
        }
    }

    /// Whether a card is within its age: no older than three hours, no further
    /// ahead than two.
    pub fn is_fresh(card: &RelayDescriptor) -> bool {
        let now = now_ticks();
        card.published_ticks >= now - MAX_AGE_TICKS && card.published_ticks <= now + FUTURE_TOLERANCE_TICKS
    }

    /// The relays fit for circuits right now.
    pub fn snapshot(&self) -> RelayList {
        let mut inner = self.inner.lock().unwrap();
        prune(&mut inner.cards);
        RelayList::from_relays(inner.cards.values().cloned())
    }

    pub fn find(&self, fingerprint: &[u8]) -> Option<RelayDescriptor> {
        let inner = self.inner.lock().unwrap();
        match inner.cards.get(&hex(fingerprint)) {
            Some(card) if PeerView::is_fresh(card) => Some(card.clone()),
            _ => None,
        }
    }

    pub fn remove(&self, fingerprint: &[u8]) {
        let mut inner = self.inner.lock().unwrap();
        inner.cards.remove(&hex(fingerprint));
    }

    /// Up to the given number of fresh cards, as their owners signed them, in
    /// random order: whoever asks often gets a different lot each time, and the
    /// network learns itself the faster.
    pub fn signed_cards(&self, max: usize) -> Vec<Vec<u8>> {
        let mut all: Vec<Vec<u8>> = {
            let mut inner = self.inner.lock().unwrap();
            prune(&mut inner.cards);
            inner
                .cards
                .values()
                .filter_map(|c| c.signed_bytes().map(|b| b.to_vec()))
                .collect()
        };

        // Fisher-Yates over the cryptographic RNG, exactly as the C# does.
        for i in (1..all.len()).rev() {
            let j = rand::next((i + 1) as u32) as usize;
            all.swap(i, j);
        }

        if all.len() > max {
            all.truncate(max);
        }
        all
    }

    // ---- The file kept between runs ----------------------------------------

    /// Reads the cards kept since the last run. Each one goes through the same
    /// door as any other: a file is no more trusted than the wire. Returns how
    /// many were taken. A missing or damaged file is an empty one.
    pub fn load(&self, path: &Path) -> usize {
        if !path.exists() {
            return 0;
        }

        let data = match fs::read(path) {
            Ok(d) => d,
            Err(_) => return 0,
        };

        let cards = match parse_file(&data) {
            Some(c) => c,
            None => return 0,
        };

        let mut taken = 0;
        for card in cards {
            match self.offer_bytes(&card) {
                CardVerdict::Added | CardVerdict::Updated => taken += 1,
                _ => {}
            }
        }
        taken
    }

    /// Keeps the fresh cards for the next run. Written aside and moved into place
    /// whole.
    pub fn save(&self, path: &Path) -> std::io::Result<()> {
        let cards = self.signed_cards(MAX_CARDS);

        let mut buf = Vec::new();
        buf.extend_from_slice(&FILE_MAGIC);
        buf.extend_from_slice(&(cards.len() as u16).to_le_bytes());
        for card in &cards {
            buf.extend_from_slice(&(card.len() as u16).to_le_bytes());
            buf.extend_from_slice(card);
        }

        let mut part = path.as_os_str().to_owned();
        part.push(".part");
        let part = Path::new(&part);

        {
            let mut file = fs::File::create(part)?;
            file.write_all(&buf)?;
            file.flush()?;
        }

        if path.exists() {
            fs::remove_file(path)?;
        }
        fs::rename(part, path)
    }

    // ---- Inside ------------------------------------------------------------

    /// Whether the card's pass is hard enough and solved for its key. Remembered
    /// per key and pass.
    pub fn pass_holds(&self, card: &RelayDescriptor) -> bool {
        let proof = match &card.proof {
            Some(p) => p,
            None => return false,
        };

        let key = format!("{}:{}:{}", hex(&card.fingerprint()), hex(proof), card.proof_bits);

        {
            let inner = self.inner.lock().unwrap();
            if let Some(&cached) = inner.proofs.get(&key) {
                return cached && (card.proof_bits as u32) >= required_proof_bits();
            }
        }

        let holds = card.has_valid_proof();

        {
            let mut inner = self.inner.lock().unwrap();
            if inner.proofs.len() >= MAX_PROOF_MEMORY {
                inner.proofs.clear();
            }
            inner.proofs.insert(key, holds);
        }

        holds
    }
}

/// Drops the stale cards.
fn prune(cards: &mut HashMap<String, RelayDescriptor>) {
    cards.retain(|_, card| PeerView::is_fresh(card));
}

/// The list is full: the card signed longest ago makes room.
fn evict_oldest(cards: &mut HashMap<String, RelayDescriptor>) {
    let oldest = cards
        .iter()
        .min_by_key(|(_, card)| card.published_ticks)
        .map(|(key, _)| key.clone());
    if let Some(key) = oldest {
        cards.remove(&key);
    }
}

/// Parses the kept-file body into the signed cards it holds, mirroring the C#
/// reader: a short or mismatched length stops the read where it is rather than
/// failing the whole file.
fn parse_file(data: &[u8]) -> Option<Vec<Vec<u8>>> {
    if data.len() < FILE_MAGIC.len() + 2 {
        return None;
    }
    if !rand::constant_time_equals(&data[..FILE_MAGIC.len()], &FILE_MAGIC) {
        return None;
    }

    let mut pos = FILE_MAGIC.len();
    let count = u16::from_le_bytes([data[pos], data[pos + 1]]) as usize;
    pos += 2;

    let mut cards = Vec::new();
    let mut i = 0;
    while i < count && i < MAX_CARDS {
        if pos + 2 > data.len() {
            break;
        }
        let length = u16::from_le_bytes([data[pos], data[pos + 1]]) as usize;
        pos += 2;
        if pos + length > data.len() {
            break; // a truncated card: stop, as the C# `card.Length != length` guard does
        }
        cards.push(data[pos..pos + length].to_vec());
        pos += length;
        i += 1;
    }

    Some(cards)
}

/// The current moment in .NET ticks, matching `DateTime.UtcNow.Ticks`.
fn now_ticks() -> i64 {
    const TICKS_AT_UNIX_EPOCH: i64 = 621_355_968_000_000_000;
    match SystemTime::now().duration_since(UNIX_EPOCH) {
        Ok(d) => TICKS_AT_UNIX_EPOCH + d.as_secs() as i64 * 10_000_000 + (d.subsec_nanos() / 100) as i64,
        Err(_) => TICKS_AT_UNIX_EPOCH,
    }
}

/// Lowercase hexadecimal, two digits a byte — the keying scheme of the C#
/// dictionaries.
pub(crate) fn hex(data: &[u8]) -> String {
    let mut s = String::with_capacity(data.len() * 2);
    for b in data {
        s.push_str(&format!("{:02x}", b));
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::directory::relay_descriptor::set_required_proof_bits;
    use crate::identity::sybil_proof;
    use crate::identity::NodeIdentity;

    /// A freshly signed card carrying a valid pass solved at a low difficulty.
    fn carded(host: &str, port: u16) -> Vec<u8> {
        let id = NodeIdentity::create("relay").unwrap();
        let mut desc = RelayDescriptor::from_identity(&id, host, port, true);
        let challenge = RelayDescriptor::proof_challenge(&desc.fingerprint());
        let nonce = sybil_proof::solve(&challenge, 4, || false, |_, _| {}).unwrap();
        desc.set_proof(nonce, 4);
        desc.to_signed_bytes(&id).unwrap()
    }

    /// Offers every card into a fresh view at difficulty 4. The required
    /// difficulty is a single global shared across the whole test binary, so
    /// another test (e.g. `relay_descriptor`'s) may momentarily raise it; a fresh
    /// view each attempt clears the proof cache, and the loop converges.
    pub(super) fn view_with(cards: &[Vec<u8>]) -> PeerView {
        for _ in 0..50 {
            set_required_proof_bits(4);
            let view = PeerView::new();
            if cards.iter().all(|c| matches!(view.offer_bytes(c), CardVerdict::Added)) {
                return view;
            }
        }
        panic!("the shared proof difficulty kept changing under the test");
    }

    #[test]
    fn accepts_a_fresh_signed_card_with_a_valid_pass() {
        let signed = carded("198.51.100.4", 9001);
        let view = view_with(&[signed.clone()]);
        assert_eq!(view.count(), 1);
        // The same card again changes nothing. The "already known" verdict is
        // returned before the pass is re-checked, so it holds at any difficulty.
        assert_eq!(view.offer_bytes(&signed), CardVerdict::Known);
    }

    #[test]
    fn rejects_a_card_with_no_pass() {
        // A card with no pass is refused whatever the difficulty, so this test
        // need not touch the shared global.
        let view = PeerView::new();
        let id = NodeIdentity::create("relay").unwrap();
        let mut desc = RelayDescriptor::from_identity(&id, "203.0.113.9", 443, false);
        let signed = desc.to_signed_bytes(&id).unwrap();
        let parsed = RelayDescriptor::try_parse(&signed).unwrap();
        assert!(parsed.proof.is_none());
        assert_eq!(view.offer(parsed), CardVerdict::Rejected);
    }

    #[test]
    fn rejects_a_card_outside_the_three_hour_window() {
        // Freshness is decided before the pass, so the difficulty is irrelevant.
        let view = PeerView::new();
        let id = NodeIdentity::create("relay").unwrap();
        let mut desc = RelayDescriptor::from_identity(&id, "198.51.100.5", 9001, true);
        let challenge = RelayDescriptor::proof_challenge(&desc.fingerprint());
        let nonce = sybil_proof::solve(&challenge, 4, || false, |_, _| {}).unwrap();
        desc.set_proof(nonce, 4);
        // Four hours back is past MaxAge.
        desc.published_ticks = now_ticks() - 4 * TICKS_PER_HOUR;
        let signed = desc.to_signed_bytes(&id).unwrap();
        let parsed = RelayDescriptor::try_parse(&signed).unwrap();

        assert!(!PeerView::is_fresh(&parsed));
        assert_eq!(view.offer(parsed), CardVerdict::Rejected);
    }

    #[test]
    fn file_round_trips() {
        let signed = carded("198.51.100.6", 9001);
        let view = view_with(&[signed]);
        assert_eq!(view.count(), 1);

        let dir = std::env::temp_dir();
        let path = dir.join(format!("stalknet-peers-{}.peers", std::process::id()));
        view.save(&path).unwrap();

        // The reload runs every card back through the door, so it too needs the
        // low difficulty to hold; retry against a concurrent raiser.
        let reloaded = loop {
            set_required_proof_bits(4);
            let v = PeerView::new();
            if v.load(&path) == 1 {
                break v;
            }
        };
        assert_eq!(reloaded.count(), 1);

        let _ = std::fs::remove_file(&path);
    }
}
