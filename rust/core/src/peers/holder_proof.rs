//! A holder's signed word that it holds a bundle.
//!
//! The keepers list who holds which bundle. Were a holder named by its bare
//! fingerprint, anybody could put anybody's fingerprint under any bundle —
//! send downloaders to addresses that hold nothing, or set a hidden address
//! down as the holder of a bundle it never touched. So the holder proves the
//! word is its own: its hidden address's public key, the time, and its
//! signature over the bundle's hash and the time. The keeper takes the
//! fingerprint from the key itself; a word older than an hour is refused.
//!
//! `public key (64) | seconds since 1970 (8, LE) | signature (64)`.

use crate::crypto::ecc_p256::SigningKey;
use crate::identity::node_identity::NodeIdentity;
use crate::identity::onion_address::{compute_fingerprint, FINGERPRINT_SIZE};

const CONTEXT: &[u8] = b"stalknet-holder-v1";
const KEY_SIZE: usize = 64;
const SIGNATURE_SIZE: usize = 64;

/// The size of a holder's signed word.
pub const SIZE: usize = KEY_SIZE + 8 + SIGNATURE_SIZE;

/// How far the word's time may stand from the keeper's clock.
pub const WINDOW_SECS: u64 = 60 * 60;

fn now_seconds() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn signed_part(info_hash: &[u8], seconds: u64) -> Vec<u8> {
    let mut data = Vec::with_capacity(CONTEXT.len() + info_hash.len() + 8);
    data.extend_from_slice(CONTEXT);
    data.extend_from_slice(info_hash);
    data.extend_from_slice(&seconds.to_le_bytes());
    data
}

/// The holder's word for `info_hash`, signed by `holder`.
pub fn make(holder: &NodeIdentity, info_hash: &[u8]) -> Vec<u8> {
    let seconds = now_seconds();
    let mut out = Vec::with_capacity(SIZE);
    out.extend_from_slice(holder.public_signing_key());
    out.extend_from_slice(&seconds.to_le_bytes());
    out.extend_from_slice(&holder.sign(&signed_part(info_hash, seconds)));
    out
}

/// The holder's fingerprint, if the word is its own, for this bundle, and fresh.
pub fn verify(info_hash: &[u8], word: &[u8]) -> Option<[u8; FINGERPRINT_SIZE]> {
    if word.len() != SIZE {
        return None;
    }
    let key = &word[..KEY_SIZE];
    let mut seconds = [0u8; 8];
    seconds.copy_from_slice(&word[KEY_SIZE..KEY_SIZE + 8]);
    let seconds = u64::from_le_bytes(seconds);
    let signature = &word[KEY_SIZE + 8..];

    if now_seconds().abs_diff(seconds) > WINDOW_SECS {
        return None;
    }
    if !SigningKey::verify(key, &signed_part(info_hash, seconds), signature) {
        return None;
    }
    Some(compute_fingerprint(key))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_word_names_its_own_signer() {
        let holder = NodeIdentity::create("").unwrap();
        let hash = [4u8; 32];
        let word = make(&holder, &hash);
        assert_eq!(verify(&hash, &word), Some(holder.fingerprint()));
    }

    #[test]
    fn a_word_does_not_move_to_another_bundle_or_break() {
        let holder = NodeIdentity::create("").unwrap();
        let word = make(&holder, &[4u8; 32]);
        assert!(verify(&[5u8; 32], &word).is_none());
        let mut broken = word.clone();
        broken[SIZE - 1] ^= 1;
        assert!(verify(&[4u8; 32], &broken).is_none());
    }

    #[test]
    fn an_old_word_is_refused() {
        let holder = NodeIdentity::create("").unwrap();
        let hash = [4u8; 32];
        let old = now_seconds() - WINDOW_SECS - 60;
        let mut word = holder.public_signing_key().to_vec();
        word.extend_from_slice(&old.to_le_bytes());
        word.extend_from_slice(&holder.sign(&signed_part(&hash, old)));
        assert!(verify(&hash, &word).is_none());
    }
}
