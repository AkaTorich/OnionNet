//! A memory-hard proof of work on Argon2id — the pass for a new relay.
//!
//! The weak spot of real Tor is that raising a thousand relays costs almost
//! nothing. Here every attempt costs a fixed amount of memory rather than
//! cycles alone: a graphics card and an ASIC lose their advantage because they
//! run into memory bandwidth. An honest participant pays once at registration,
//! an attacker pays for every fake node. Verification costs exactly one
//! Argon2id computation.

use crate::crypto::{argon2id, rand};
use sha2::{Digest, Sha256};
use std::time::{Duration, Instant};

pub const CHALLENGE_SIZE: usize = 32;
pub const NONCE_SIZE: usize = 8;

/// Memory per attempt. Less than for sealing a key: it has to be run many times
/// over.
pub const MEMORY_KIB: u32 = 8 * 1024;
pub const ITERATIONS: u32 = 1;
pub const PARALLELISM: u32 = 1;
const DIGEST_SIZE: usize = 32;

const CHALLENGE_CONTEXT: &str = "stalknet-sybil-challenge";

/// The challenge for one node in one period. Directories keep no issued
/// challenges: a challenge is recomputed from the fingerprint and the period
/// number, so the verifier has nothing to forget and nothing to overflow.
pub fn build_challenge(fingerprint: &[u8], period_number: i64) -> [u8; CHALLENGE_SIZE] {
    let mut hasher = Sha256::new();
    hasher.update(CHALLENGE_CONTEXT.as_bytes());
    hasher.update(fingerprint);
    hasher.update((period_number as u64).to_le_bytes());
    let out = hasher.finalize();
    let mut challenge = [0u8; CHALLENGE_SIZE];
    challenge.copy_from_slice(&out);
    challenge
}

/// Looks for a nonce at which the digest begins with the required number of
/// zero bits. Returns `None` if the work was cancelled.
///
/// * `should_cancel` — polled each attempt; returning `true` stops the search.
/// * `progress` — called now and then with the attempt count and time elapsed.
pub fn solve<C, P>(
    challenge: &[u8],
    difficulty_bits: u32,
    should_cancel: C,
    mut progress: P,
) -> Option<[u8; NONCE_SIZE]>
where
    C: Fn() -> bool,
    P: FnMut(u64, Duration),
{
    assert_eq!(challenge.len(), CHALLENGE_SIZE, "the challenge must be 32 bytes");
    assert!(difficulty_bits <= 64, "difficulty out of range");

    let salt = extract_salt(challenge);
    let mut nonce = [0u8; NONCE_SIZE];
    rand::fill(&mut nonce);

    let mut input = vec![0u8; CHALLENGE_SIZE + NONCE_SIZE];
    input[..CHALLENGE_SIZE].copy_from_slice(challenge);

    let start = Instant::now();
    let mut attempts: u64 = 0;

    loop {
        if should_cancel() {
            return None;
        }

        input[CHALLENGE_SIZE..].copy_from_slice(&nonce);

        let digest = argon2id::derive_key(&input, &salt, PARALLELISM, MEMORY_KIB, ITERATIONS, DIGEST_SIZE, None, None)
            .expect("fixed valid Argon2 parameters");
        attempts += 1;

        if leading_zero_bits(&digest) >= difficulty_bits {
            progress(attempts, start.elapsed());
            return Some(nonce);
        }

        if attempts % 64 == 0 {
            progress(attempts, start.elapsed());
        }

        increment_nonce(&mut nonce);
    }
}

/// Checks someone else's solution. One Argon2id computation.
pub fn verify(challenge: &[u8], nonce: &[u8], difficulty_bits: u32) -> bool {
    if challenge.len() != CHALLENGE_SIZE || nonce.len() != NONCE_SIZE || difficulty_bits > 64 {
        return false;
    }

    let mut input = vec![0u8; CHALLENGE_SIZE + NONCE_SIZE];
    input[..CHALLENGE_SIZE].copy_from_slice(challenge);
    input[CHALLENGE_SIZE..].copy_from_slice(nonce);

    match argon2id::derive_key(&input, &extract_salt(challenge), PARALLELISM, MEMORY_KIB, ITERATIONS, DIGEST_SIZE, None, None) {
        Ok(digest) => leading_zero_bits(&digest) >= difficulty_bits,
        Err(_) => false,
    }
}

/// The expected number of attempts at the given difficulty.
pub fn expected_attempts(difficulty_bits: u32) -> f64 {
    2f64.powi(difficulty_bits as i32)
}

fn extract_salt(challenge: &[u8]) -> [u8; 16] {
    let mut salt = [0u8; 16];
    salt.copy_from_slice(&challenge[..16]);
    salt
}

pub(crate) fn leading_zero_bits(digest: &[u8]) -> u32 {
    let mut count = 0u32;
    for &b in digest {
        if b == 0 {
            count += 8;
            continue;
        }
        for bit in (0..8).rev() {
            if b & (1 << bit) != 0 {
                return count;
            }
            count += 1;
        }
        return count;
    }
    count
}

fn increment_nonce(nonce: &mut [u8; NONCE_SIZE]) {
    for i in (0..NONCE_SIZE).rev() {
        nonce[i] = nonce[i].wrapping_add(1);
        if nonce[i] != 0 {
            return;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn leading_zero_bits_counts_correctly() {
        assert_eq!(leading_zero_bits(&[0x00, 0x00, 0x80]), 16);
        assert_eq!(leading_zero_bits(&[0x00, 0x00, 0x40]), 17);
        assert_eq!(leading_zero_bits(&[0xff]), 0);
        assert_eq!(leading_zero_bits(&[0x00, 0x00]), 16);
    }

    #[test]
    fn solve_then_verify() {
        let challenge = build_challenge(&[1u8; 20], 42);
        // A tiny difficulty keeps the test fast while still exercising the loop.
        let nonce = solve(&challenge, 4, || false, |_, _| {}).unwrap();
        assert!(verify(&challenge, &nonce, 4));
    }
}
