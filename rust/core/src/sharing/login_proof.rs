//! A memory-hard pass for a sign-in attempt (the C# `LoginProof`).
//!
//! A Windows account's password is something that can be guessed at. A failure
//! counter catches a lone stubborn attacker but not one who spread the guessing
//! over a hundred names or a thousand nodes. Here every attempt costs a fixed
//! amount of memory rather than cycles alone: the guessing runs into memory
//! bandwidth, where neither a graphics card nor a rented cloud gives any
//! advantage.
//!
//! The parameters are lighter than those of a relay's pass: an honest guest pays
//! a second or two for signing in, not a minute. The construction is wholly
//! platform-independent and byte-identical to the C# original.

use crate::crypto::{argon2id, rand};
use crate::identity::sybil_proof::leading_zero_bits;
use sha2::{Digest, Sha256};

pub const CHALLENGE_SIZE: usize = 32;
pub const NONCE_SIZE: usize = 8;

const MEMORY_KIB: u32 = 4 * 1024;
const ITERATIONS: u32 = 1;
const PARALLELISM: u32 = 1;
const DIGEST_SIZE: usize = 32;

const CONTEXT: &str = "stalknet-login-proof";

/// How many leading zero bits are required by default: about a second of work.
pub const DEFAULT_DIFFICULTY_BITS: u32 = 5;

/// The challenge is tied both to the name and to the session's random salt: a
/// solution cannot be prepared in advance and cannot be reused in another
/// session or under another name.
///
/// Layout: `context || name_len(u8) || name || salt_len(u8) || salt`, then
/// SHA-256. The name is lower-cased first. Identical to the C# `BuildChallenge`.
pub fn build_challenge(user_name: &str, session_salt: &[u8]) -> Vec<u8> {
    let context = CONTEXT.as_bytes();
    let name = user_name.to_lowercase();
    let name = name.as_bytes();

    let mut input = Vec::with_capacity(context.len() + 1 + name.len() + 1 + session_salt.len());
    input.extend_from_slice(context);
    input.push(name.len() as u8);
    input.extend_from_slice(name);
    input.push(session_salt.len() as u8);
    input.extend_from_slice(session_salt);

    Sha256::digest(&input).to_vec()
}

/// Looks for a solution. Returns `None` if the search was cancelled.
///
/// `should_cancel` is polled each attempt; returning `true` stops the search and
/// yields `None`, mirroring the C# `CancellationToken`.
pub fn solve_cancellable<C: Fn() -> bool>(
    challenge: &[u8],
    difficulty_bits: u32,
    should_cancel: C,
) -> Option<Vec<u8>> {
    assert_eq!(challenge.len(), CHALLENGE_SIZE, "the challenge must be {CHALLENGE_SIZE} bytes");
    assert!(difficulty_bits <= 64, "difficulty out of range");

    if difficulty_bits == 0 {
        return Some(vec![0u8; NONCE_SIZE]);
    }

    let salt = extract_salt(challenge);
    let mut nonce = [0u8; NONCE_SIZE];
    rand::fill(&mut nonce);

    let mut input = vec![0u8; CHALLENGE_SIZE + NONCE_SIZE];
    input[..CHALLENGE_SIZE].copy_from_slice(challenge);

    loop {
        if should_cancel() {
            return None;
        }

        input[CHALLENGE_SIZE..].copy_from_slice(&nonce);
        let digest = argon2id::derive_key(&input, &salt, PARALLELISM, MEMORY_KIB, ITERATIONS, DIGEST_SIZE, None, None)
            .expect("fixed valid Argon2 parameters");

        if leading_zero_bits(&digest) >= difficulty_bits {
            return Some(nonce.to_vec());
        }

        increment_nonce(&mut nonce);
    }
}

/// Looks for a solution, never cancelling. The common case for a client.
pub fn solve(challenge: &[u8], difficulty_bits: u32) -> Option<Vec<u8>> {
    solve_cancellable(challenge, difficulty_bits, || false)
}

/// Checks a solution. Costs exactly one Argon2id computation.
pub fn verify(challenge: &[u8], nonce: &[u8], difficulty_bits: u32) -> bool {
    if challenge.len() != CHALLENGE_SIZE {
        return false;
    }
    if difficulty_bits > 64 {
        return false;
    }
    if difficulty_bits == 0 {
        return true;
    }
    if nonce.len() != NONCE_SIZE {
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

fn extract_salt(challenge: &[u8]) -> [u8; 16] {
    let mut salt = [0u8; 16];
    salt.copy_from_slice(&challenge[..16]);
    salt
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
    fn challenge_is_deterministic_and_bound() {
        let salt = [9u8; 16];
        let a = build_challenge("Alice", &salt);
        let b = build_challenge("alice", &salt); // case-folded, so equal
        assert_eq!(a, b);
        assert_eq!(a.len(), CHALLENGE_SIZE);

        let other = build_challenge("alice", &[8u8; 16]);
        assert_ne!(a, other); // bound to the salt
    }

    #[test]
    fn zero_difficulty_is_always_satisfied() {
        let challenge = build_challenge("bob", &[1u8; 16]);
        let nonce = solve(&challenge, 0).unwrap();
        assert_eq!(nonce, vec![0u8; NONCE_SIZE]);
        assert!(verify(&challenge, &nonce, 0));
        // Even a wrong-length nonce passes at difficulty 0, as in C#.
        assert!(verify(&challenge, &[], 0));
    }

    #[test]
    fn solve_then_verify_roundtrip() {
        let challenge = build_challenge("carol", &[2u8; 16]);
        // A small difficulty keeps the test quick while exercising the loop.
        let nonce = solve(&challenge, 4).unwrap();
        assert!(verify(&challenge, &nonce, 4));
        // A different challenge must not accept the same nonce (overwhelmingly).
        let other = build_challenge("dave", &[2u8; 16]);
        assert!(!verify(&other, &nonce, 24));
    }

    #[test]
    fn verify_rejects_malformed() {
        let challenge = build_challenge("eve", &[3u8; 16]);
        assert!(!verify(&challenge[..31], &[0u8; NONCE_SIZE], 4)); // short challenge
        assert!(!verify(&challenge, &[0u8; 7], 4)); // short nonce
        assert!(!verify(&challenge, &[0u8; NONCE_SIZE], 65)); // difficulty out of range
    }

    #[test]
    fn solve_can_be_cancelled() {
        let challenge = build_challenge("frank", &[4u8; 16]);
        // A difficulty so high it would never finish; cancel at once.
        assert!(solve_cancellable(&challenge, 40, || true).is_none());
    }
}
