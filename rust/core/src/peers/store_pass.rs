//! The price of a place at the keepers.
//!
//! A hidden address's key costs nothing to make, so without a price anybody
//! could make thousands and crowd the keepers out with rubbish announcements,
//! site records and holders — not forging anybody's, but pushing the real ones
//! out. So every key that wants a place pays once: an Argon2id proof of work
//! over its fingerprint, the same kind as a relay's pass but lighter (seconds,
//! once per key). An honest service pays it once per address; whoever wants a
//! thousand places pays a thousand times. The keeper checks a pass once and
//! remembers it.
//!
//! On the wire: `bits (1) | nonce (8)`.

use crate::identity::sybil_proof;
use std::collections::HashMap;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Mutex;

/// The size of a pass on the wire.
pub const SIZE: usize = 1 + sybil_proof::NONCE_SIZE;

/// The challenge "period" for a place at the keepers: a pass for a place is
/// never the same as a relay's pass (period 0) for the same key.
const PERIOD: i64 = 1;

/// Ten bits: about a thousand Argon2id runs at 8 MiB — seconds once per key.
/// The test build asks four, so no test has to change it under another's feet.
static REQUIRED_BITS: AtomicU32 = AtomicU32::new(if cfg!(test) { 4 } else { 10 });

pub fn required_bits() -> u32 {
    REQUIRED_BITS.load(Ordering::Relaxed)
}

/// For tests: a lighter price.
pub fn set_required_bits(bits: u32) {
    REQUIRED_BITS.store(bits, Ordering::Relaxed);
}

/// Pays for a place for the key with this fingerprint. Blocks for the work.
pub fn solve(fingerprint: &[u8]) -> Vec<u8> {
    let bits = required_bits();
    let challenge = sybil_proof::build_challenge(fingerprint, PERIOD);
    let nonce = sybil_proof::solve(&challenge, bits, || false, |_, _| {}).unwrap_or([0u8; sybil_proof::NONCE_SIZE]);
    let mut pass = Vec::with_capacity(SIZE);
    pass.push(bits as u8);
    pass.extend_from_slice(&nonce);
    pass
}

/// Whether `pass` is paid for this fingerprint at the price asked now.
pub fn holds(fingerprint: &[u8], pass: &[u8]) -> bool {
    if pass.len() != SIZE {
        return false;
    }
    let bits = pass[0] as u32;
    if bits < required_bits() {
        return false;
    }
    let challenge = sybil_proof::build_challenge(fingerprint, PERIOD);
    sybil_proof::verify(&challenge, &pass[1..], bits)
}

/// A keeper's memory of the passes it has checked: one Argon2id run per key,
/// not per record.
#[derive(Default)]
pub struct Checked {
    seen: Mutex<HashMap<Vec<u8>, bool>>,
}

const MEMORY: usize = 16_384;

impl Checked {
    pub fn new() -> Checked {
        Checked::default()
    }

    pub fn holds(&self, fingerprint: &[u8], pass: &[u8]) -> bool {
        let mut key = fingerprint.to_vec();
        key.extend_from_slice(pass);
        if let Some(&known) = self.seen.lock().unwrap().get(&key) {
            return known && pass.first().map(|b| *b as u32 >= required_bits()).unwrap_or(false);
        }
        // The work runs outside the lock.
        let ok = holds(fingerprint, pass);
        let mut seen = self.seen.lock().unwrap();
        if seen.len() >= MEMORY {
            seen.clear();
        }
        seen.insert(key, ok);
        ok
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_pass_is_for_its_own_key() {
        let pass = solve(&[1u8; 20]);
        assert!(holds(&[1u8; 20], &pass));
        assert!(!holds(&[2u8; 20], &pass));
        assert!(!holds(&[1u8; 20], &[0u8; SIZE]));
        let checked = Checked::new();
        assert!(checked.holds(&[1u8; 20], &pass));
        assert!(checked.holds(&[1u8; 20], &pass)); // remembered
    }
}
