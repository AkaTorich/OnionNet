//! Integrity tags for Relay cells — one chain per direction per hop. The tag
//! lives inside the cell itself rather than beside it.
//!
//! The room for the tag is zeroed while computing, or the verifier could not
//! repeat the sender's computation. Only the first 6 bytes go into the cell;
//! together with the two zero bytes of the recogniser that is 64 bits of
//! checking — someone else's cell passes for ours with probability 2^-64.

use crate::crypto::chaining_mac::{ChainingMac, KEY_SIZE as MAC_KEY_SIZE};
use crate::protocol::cell::PAYLOAD_SIZE;
use crate::protocol::relay_cell::{DIGEST_OFFSET, DIGEST_SIZE};

pub const KEY_SIZE: usize = MAC_KEY_SIZE;

pub struct RelayDigest {
    mac: ChainingMac,
    work: Vec<u8>,
}

impl RelayDigest {
    pub fn new(key: &[u8]) -> RelayDigest {
        RelayDigest {
            mac: ChainingMac::new(key, PAYLOAD_SIZE),
            work: vec![0u8; PAYLOAD_SIZE],
        }
    }

    /// How many cells went through this chain.
    pub fn cell_count(&self) -> u64 {
        self.mac.count()
    }

    /// Puts the tag into the cell and advances the state. Called by the sender
    /// before the cipher layers go on.
    pub fn seal(&mut self, payload: &mut [u8]) {
        assert_eq!(payload.len(), PAYLOAD_SIZE, "the payload must be {PAYLOAD_SIZE} bytes");

        for i in 0..DIGEST_SIZE {
            payload[DIGEST_OFFSET + i] = 0;
        }
        let tag = self.mac.compute(payload);
        payload[DIGEST_OFFSET..DIGEST_OFFSET + DIGEST_SIZE].copy_from_slice(&tag[..DIGEST_SIZE]);
        self.mac.commit(&tag);
    }

    /// Checks the tag. The state advances only on a match. The buffer itself is
    /// left alone — it still has to be passed on.
    pub fn verify_and_commit(&mut self, payload: &[u8]) -> bool {
        assert_eq!(payload.len(), PAYLOAD_SIZE, "the payload must be {PAYLOAD_SIZE} bytes");

        let received = &payload[DIGEST_OFFSET..DIGEST_OFFSET + DIGEST_SIZE];

        // Computed over a copy with the tag zeroed: the sender did the same.
        self.work.copy_from_slice(payload);
        for i in 0..DIGEST_SIZE {
            self.work[DIGEST_OFFSET + i] = 0;
        }
        // Clone the work buffer for the borrow checker; `verify_and_commit`
        // needs `&self.mac` mutably while reading `received`, which borrows
        // `payload`, not `self`.
        let received_copy = received.to_vec();
        let work = std::mem::take(&mut self.work);
        let ok = self.mac.verify_and_commit(&work, &received_copy);
        self.work = work;
        ok
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn seal_then_verify_advances_both_chains() {
        let key = [5u8; KEY_SIZE];
        let mut sender = RelayDigest::new(&key);
        let mut receiver = RelayDigest::new(&key);

        let mut payload = vec![7u8; PAYLOAD_SIZE];
        sender.seal(&mut payload);
        assert!(receiver.verify_and_commit(&payload));
        assert_eq!(sender.cell_count(), 1);
        assert_eq!(receiver.cell_count(), 1);
    }

    #[test]
    fn a_tampered_cell_fails() {
        let key = [5u8; KEY_SIZE];
        let mut sender = RelayDigest::new(&key);
        let mut receiver = RelayDigest::new(&key);

        let mut payload = vec![0u8; PAYLOAD_SIZE];
        sender.seal(&mut payload);
        payload[DATA_OFFSET_TEST] ^= 1;
        assert!(!receiver.verify_and_commit(&payload));
    }

    const DATA_OFFSET_TEST: usize = 13;
}
