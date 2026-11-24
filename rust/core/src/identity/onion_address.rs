//! A hidden service's address — the same as the address of a participant's
//! shared folder. It is built out of the public signing key, so an address
//! cannot be claimed: answering at it takes the private key.
//!
//! The address body: `version(1) || fingerprint(20) || checksum(2)`, which in
//! Base32 is 37 characters plus the `.stalknet` suffix.

use crate::crypto::rand;
use crate::util::base32;
use sha2::{Digest, Sha256};

pub const SUFFIX: &str = ".stalknet";
pub const FINGERPRINT_SIZE: usize = 20;
const CURRENT_VERSION: u8 = 1;
const CHECKSUM_CONTEXT: &str = "stalknet-checksum";

#[derive(Clone, Debug)]
pub struct OnionAddress {
    fingerprint: [u8; FINGERPRINT_SIZE],
    version: u8,
    text: String,
}

impl OnionAddress {
    pub fn version(&self) -> u8 {
        self.version
    }

    /// Twenty bytes pointing unambiguously at the node's signing key.
    pub fn fingerprint(&self) -> [u8; FINGERPRINT_SIZE] {
        self.fingerprint
    }

    /// The whole address, suffix included.
    pub fn text(&self) -> &str {
        &self.text
    }

    pub fn from_public_key(public_signing_key: &[u8]) -> Result<OnionAddress, &'static str> {
        if public_signing_key.len() != 64 {
            return Err("a 64-byte P-256 public key is expected");
        }
        Ok(OnionAddress::new(
            compute_fingerprint(public_signing_key),
            CURRENT_VERSION,
        ))
    }

    fn new(fingerprint: [u8; FINGERPRINT_SIZE], version: u8) -> OnionAddress {
        let text = build_text(&fingerprint, version);
        OnionAddress {
            fingerprint,
            version,
            text,
        }
    }

    pub fn try_parse(text: &str) -> Option<OnionAddress> {
        if text.is_empty() {
            return None;
        }
        let mut text = text.trim().to_ascii_lowercase();
        if let Some(stripped) = text.strip_suffix(SUFFIX) {
            text = stripped.to_string();
        }

        let body = base32::try_decode(&text)?;
        if body.len() != 1 + FINGERPRINT_SIZE + 2 {
            return None;
        }

        let version = body[0];
        if version != CURRENT_VERSION {
            return None;
        }

        let mut fingerprint = [0u8; FINGERPRINT_SIZE];
        fingerprint.copy_from_slice(&body[1..1 + FINGERPRINT_SIZE]);

        let expected = checksum(&fingerprint, version);
        if body[1 + FINGERPRINT_SIZE] != expected[0] || body[2 + FINGERPRINT_SIZE] != expected[1] {
            return None;
        }

        Some(OnionAddress::new(fingerprint, version))
    }

    pub fn parse(text: &str) -> Result<OnionAddress, String> {
        OnionAddress::try_parse(text).ok_or_else(|| format!("not a valid StalkNet address: {text}"))
    }

    /// Checks that the presented key really yields this address.
    pub fn matches(&self, public_signing_key: &[u8]) -> bool {
        if public_signing_key.len() != 64 {
            return false;
        }
        rand::constant_time_equals(&self.fingerprint, &compute_fingerprint(public_signing_key))
    }
}

/// The key's fingerprint: the first 20 bytes of SHA-256.
pub fn compute_fingerprint(public_signing_key: &[u8]) -> [u8; FINGERPRINT_SIZE] {
    let full = Sha256::digest(public_signing_key);
    let mut fingerprint = [0u8; FINGERPRINT_SIZE];
    fingerprint.copy_from_slice(&full[..FINGERPRINT_SIZE]);
    fingerprint
}

fn build_text(fingerprint: &[u8; FINGERPRINT_SIZE], version: u8) -> String {
    let mut body = [0u8; 1 + FINGERPRINT_SIZE + 2];
    body[0] = version;
    body[1..1 + FINGERPRINT_SIZE].copy_from_slice(fingerprint);
    let sum = checksum(fingerprint, version);
    body[1 + FINGERPRINT_SIZE] = sum[0];
    body[2 + FINGERPRINT_SIZE] = sum[1];
    format!("{}{}", base32::encode(&body), SUFFIX)
}

/// Two bytes against typos. The context string keeps this sum from coinciding
/// with some other hash of the same fingerprint elsewhere in the protocol.
fn checksum(fingerprint: &[u8; FINGERPRINT_SIZE], version: u8) -> [u8; 2] {
    let mut hasher = Sha256::new();
    hasher.update(CHECKSUM_CONTEXT.as_bytes());
    hasher.update(fingerprint);
    hasher.update([version]);
    let hash = hasher.finalize();
    [hash[0], hash[1]]
}

impl PartialEq for OnionAddress {
    fn eq(&self, other: &Self) -> bool {
        self.text == other.text
    }
}
impl Eq for OnionAddress {}

impl std::hash::Hash for OnionAddress {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.text.hash(state);
    }
}

impl std::fmt::Display for OnionAddress {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.text)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn address_round_trips_through_text() {
        let pk = [0x42u8; 64];
        let addr = OnionAddress::from_public_key(&pk).unwrap();
        assert!(addr.text().ends_with(SUFFIX));
        let parsed = OnionAddress::try_parse(addr.text()).unwrap();
        assert_eq!(addr, parsed);
        assert_eq!(addr.fingerprint(), parsed.fingerprint());
        assert!(addr.matches(&pk));
    }

    #[test]
    fn a_changed_character_fails_the_checksum() {
        let addr = OnionAddress::from_public_key(&[1u8; 64]).unwrap();
        let mut chars: Vec<char> = addr.text().strip_suffix(SUFFIX).unwrap().chars().collect();
        // Flip one body character to a different valid Base32 symbol.
        chars[0] = if chars[0] == 'a' { 'b' } else { 'a' };
        let broken: String = chars.into_iter().collect::<String>() + SUFFIX;
        assert!(OnionAddress::try_parse(&broken).is_none());
    }
}
