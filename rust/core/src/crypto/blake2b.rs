//! BLAKE2b (RFC 7693).
//!
//! The C# code hand-rolls this because the key derivation and the Argon2id
//! proof of work stand on it. Here it wraps the `blake2` crate, which is the
//! same RFC construction, so hashes match the C# node byte for byte. Supports
//! any output length from 1 to 64 bytes.
//!
//! The C# `Blake2b` also offers an optional key, but no caller in the core ever
//! uses it (every construction is unkeyed), so the keyed path is not ported.

use blake2::digest::{Update, VariableOutput};
use blake2::Blake2bVar;

/// One-shot unkeyed hash of `data` into `output_length` bytes (1..=64).
pub fn hash(output_length: usize, data: &[u8]) -> Vec<u8> {
    let mut h = Blake2b::new(output_length);
    h.update(data);
    h.finalize()
}

/// A streaming BLAKE2b hasher, matching the C# `Blake2b`.
pub struct Blake2b {
    inner: Blake2bVar,
    output_length: usize,
}

impl Blake2b {
    /// Unkeyed hasher producing `output_length` bytes (1..=64).
    pub fn new(output_length: usize) -> Self {
        assert!(
            (1..=64).contains(&output_length),
            "BLAKE2b gives out from 1 to 64 bytes"
        );
        Blake2b {
            inner: Blake2bVar::new(output_length).expect("valid BLAKE2b output length"),
            output_length,
        }
    }

    pub fn update(&mut self, data: &[u8]) {
        Update::update(&mut self.inner, data);
    }

    pub fn output_length(&self) -> usize {
        self.output_length
    }

    pub fn finalize(self) -> Vec<u8> {
        let mut out = vec![0u8; self.output_length];
        self.inner
            .finalize_variable(&mut out)
            .expect("output buffer sized");
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn known_answer_empty() {
        // BLAKE2b-512 of the empty string (RFC 7693).
        let digest = hash(64, b"");
        let hex: String = digest.iter().map(|b| format!("{:02x}", b)).collect();
        assert_eq!(
            hex,
            "786a02f742015903c6c6fd852552d272912f4740e15847618a86e217f71f5419\
             d25e1031afee585313896444934eb04b903a685b1448b755d56f701afe9be2ce"
        );
    }

    #[test]
    fn known_answer_abc() {
        // BLAKE2b-512("abc"), the canonical RFC 7693 test vector.
        let digest = hash(64, b"abc");
        let hex: String = digest.iter().map(|b| format!("{:02x}", b)).collect();
        assert_eq!(
            hex,
            "ba80a53f981c4d0d6a2797b69f12f6e94c212f14685ac4b74b12bb6fdbffa2d1\
             7d87c5392aab792dc252d5de4533cc9518d38aa8dbf1925ab92386edd4009923"
        );
    }
}
