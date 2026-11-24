//! Which relays keep a record, with nobody to assign them.
//!
//! The rule is the one the torrent network's DHT lives by: the record's key is
//! hashed onto the same 20-byte space as the relays' fingerprints, and it is
//! kept by the relays whose fingerprints are closest to it — closest by XOR, bit
//! for bit from the top. Every node works the keepers out by itself from its own
//! list; the lists differ a little, so the record is put with three and looked
//! for among six. A relay joining or leaving moves only the records next to it,
//! and the next reminder puts them where they now belong.
//!
//! Nobody chooses where a record lies, so nobody can steer a record to
//! themselves without raising relays right beside its key — and every relay
//! costs a pass. The hashing matches the C# `Placement` byte for byte.

use crate::directory::relay_descriptor::RelayDescriptor;
use crate::directory::relay_list::RelayList;
use crate::identity::onion_address::FINGERPRINT_SIZE;
use sha2::{Digest, Sha256};

/// How many relays a record is put with.
pub const REPLICAS: usize = 3;

/// How many of the closest a record is looked for among.
pub const SEARCHED: usize = 6;

/// `stalknet-placement-v1` — the domain separator folded into every point.
const CONTEXT: &[u8] = b"stalknet-placement-v1";

/// What kind of record is filed under a key — each kind has its own row of
/// keepers.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum RecordKind {
    /// A hidden address's announcement: its key and introduction points.
    Service = 1,
    /// Who holds a bundle.
    Holders = 2,
    /// A site's sealed record.
    Site = 3,
}

/// The point in the fingerprints' space the record lies at.
pub fn point(kind: RecordKind, key: &[u8]) -> [u8; FINGERPRINT_SIZE] {
    let mut hasher = Sha256::new();
    hasher.update(CONTEXT);
    hasher.update([kind as u8]);
    hasher.update(key);
    let full = hasher.finalize();

    let mut out = [0u8; FINGERPRINT_SIZE];
    out.copy_from_slice(&full[..FINGERPRINT_SIZE]);
    out
}

/// The relays closest to the record's point, nearest first.
pub fn keepers(relays: &RelayList, kind: RecordKind, key: &[u8], count: usize) -> Vec<RelayDescriptor> {
    let target = point(kind, key);
    let mut sorted: Vec<RelayDescriptor> = relays.relays().to_vec();
    sorted.sort_by(|a, b| {
        let order = compare_distance(&a.fingerprint(), &b.fingerprint(), &target);
        order.cmp(&0)
    });
    if sorted.len() > count {
        sorted.truncate(count);
    }
    sorted
}

/// Which of two fingerprints lies closer to the point. Negative — the first.
pub fn compare_distance(a: &[u8], b: &[u8], point: &[u8]) -> i32 {
    for i in 0..point.len() {
        let da = a[i] ^ point[i];
        let db = b[i] ^ point[i];
        if da != db {
            return if da < db { -1 } else { 1 };
        }
    }
    0
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::NodeIdentity;

    #[test]
    fn compare_distance_orders_by_xor_from_the_top() {
        let point = [0x00u8; FINGERPRINT_SIZE];
        let near = {
            let mut f = [0u8; FINGERPRINT_SIZE];
            f[0] = 0x01;
            f
        };
        let far = {
            let mut f = [0u8; FINGERPRINT_SIZE];
            f[0] = 0x80;
            f
        };
        assert_eq!(compare_distance(&near, &far, &point), -1);
        assert_eq!(compare_distance(&far, &near, &point), 1);
        assert_eq!(compare_distance(&near, &near, &point), 0);

        // The top differing byte decides, even when a lower byte would say
        // otherwise.
        let mut a = [0u8; FINGERPRINT_SIZE];
        a[0] = 0x10;
        a[1] = 0xff;
        let mut b = [0u8; FINGERPRINT_SIZE];
        b[0] = 0x20;
        b[1] = 0x00;
        assert_eq!(compare_distance(&a, &b, &point), -1);
    }

    #[test]
    fn keepers_returns_the_closest_three_nearest_first() {
        let mut relays = RelayList::new();
        for i in 0..6u16 {
            let id = NodeIdentity::create(&format!("r{i}")).unwrap();
            relays.push(RelayDescriptor::from_identity(&id, "198.51.100.1", 9000 + i, true));
        }

        let key = b"some-record-key";
        let target = point(RecordKind::Holders, key);

        let chosen = keepers(&relays, RecordKind::Holders, key, REPLICAS);
        assert_eq!(chosen.len(), REPLICAS);

        // Each kept relay is no further than the next, and all are no further
        // than every relay left out.
        for w in chosen.windows(2) {
            assert!(compare_distance(&w[0].fingerprint(), &w[1].fingerprint(), &target) <= 0);
        }

        let last = chosen.last().unwrap().fingerprint();
        let chosen_fps: Vec<[u8; FINGERPRINT_SIZE]> = chosen.iter().map(|r| r.fingerprint()).collect();
        for r in relays.relays() {
            let fp = r.fingerprint();
            if chosen_fps.contains(&fp) {
                continue;
            }
            assert!(compare_distance(&last, &fp, &target) <= 0);
        }
    }

    #[test]
    fn point_is_stable_and_kind_sensitive() {
        let key = b"k";
        assert_eq!(point(RecordKind::Service, key), point(RecordKind::Service, key));
        assert_ne!(point(RecordKind::Service, key), point(RecordKind::Site, key));
    }
}
