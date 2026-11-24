//! An integrity tag computed not over one frame but over the whole sequence of
//! them: `h = HMAC(key, state || frame)`, after which the state becomes `h`.
//!
//! Because of that chaining, only the entire stream can be forged, and only
//! from the very beginning. A repeat, a reorder, an insertion or a dropped
//! frame throw the state off for good rather than spoil one check.
//!
//! One instance serves one direction of one leg.

use crate::crypto::rand;
use hmac::{Hmac, Mac};
use sha2::Sha256;
use zeroize::Zeroize;

type HmacSha256 = Hmac<Sha256>;

pub const KEY_SIZE: usize = 32;
const STATE_SIZE: usize = 32;

pub struct ChainingMac {
    key: [u8; KEY_SIZE],
    state: [u8; STATE_SIZE],
    frame_size: usize,
    count: u64,
}

impl ChainingMac {
    pub fn new(key: &[u8], frame_size: usize) -> Self {
        assert_eq!(key.len(), KEY_SIZE, "the tag key must be {KEY_SIZE} bytes");
        assert!(frame_size > 0, "frame size must be positive");

        let mut k = [0u8; KEY_SIZE];
        k.copy_from_slice(key);
        ChainingMac {
            key: k,
            state: [0u8; STATE_SIZE],
            frame_size,
            count: 0,
        }
    }

    /// How many frames were counted in — for diagnosing desync.
    pub fn count(&self) -> u64 {
        self.count
    }

    pub fn frame_size(&self) -> usize {
        self.frame_size
    }

    /// Computes a frame's tag without advancing the state. Returns all 32
    /// bytes: truncating is the caller's business. The length goes into the
    /// count (unless the frame is exactly `frame_size`): otherwise
    /// "message A + message B" and "one message AB" would give the same tag.
    pub fn compute(&self, frame: &[u8]) -> [u8; STATE_SIZE] {
        let mut mac = HmacSha256::new_from_slice(&self.key).expect("HMAC accepts any key length");
        mac.update(&self.state);
        if frame.len() != self.frame_size {
            mac.update(&(frame.len() as u64).to_le_bytes());
        }
        mac.update(frame);
        let out = mac.finalize().into_bytes();
        let mut tag = [0u8; STATE_SIZE];
        tag.copy_from_slice(&out);
        tag
    }

    /// Advances the state onto a computed tag.
    pub fn commit(&mut self, tag: &[u8; STATE_SIZE]) {
        self.state.copy_from_slice(tag);
        self.count += 1;
    }

    /// Computes the tag and compares its truncated form with the received one.
    /// The state advances only on a match: someone else's frame, or a damaged
    /// one, must not throw off the count for those that follow.
    pub fn verify_and_commit(&mut self, frame: &[u8], received_tag: &[u8]) -> bool {
        if received_tag.is_empty() || received_tag.len() > STATE_SIZE {
            return false;
        }

        let tag = self.compute(frame);
        if !rand::constant_time_equals(&tag[..received_tag.len()], received_tag) {
            return false;
        }

        self.commit(&tag);
        true
    }
}

impl Drop for ChainingMac {
    fn drop(&mut self) {
        self.key.zeroize();
        self.state.zeroize();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn verify_follows_compute() {
        let key = [9u8; KEY_SIZE];
        let frame = [1u8; 16];

        let sender = ChainingMac::new(&key, 16);
        let tag = sender.compute(&frame);

        let mut receiver = ChainingMac::new(&key, 16);
        assert!(receiver.verify_and_commit(&frame, &tag[..16]));
        assert_eq!(receiver.count(), 1);
    }

    #[test]
    fn reorder_breaks_the_chain() {
        let key = [9u8; KEY_SIZE];
        let mut sender = ChainingMac::new(&key, 4);
        let a = *b"aaaa";
        let b = *b"bbbb";
        let tag_a = sender.compute(&a);
        sender.commit(&tag_a);
        let tag_b = sender.compute(&b);

        // Receiver gets B before A: the tag computed over the fresh state will
        // not match B's tag, which was computed after A.
        let mut receiver = ChainingMac::new(&key, 4);
        assert!(!receiver.verify_and_commit(&b, &tag_b[..16]));
    }
}
