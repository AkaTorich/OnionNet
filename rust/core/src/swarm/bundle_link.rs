//! A link to a bundle: what one participant hands another so that the second
//! can fetch it.
//!
//! It carries two things. The info hash names the bundle in the swarm and
//! checks every byte that arrives: the header must hash to it, and the header
//! holds the hash of every piece. The content key opens what the pieces hold.
//! Whoever stores and hands out the pieces needs only the first, and so sees
//! nothing but ciphertext; whoever has the link has both.
//!
//! The text form: `"ont:"` and Base32 of
//! `version(1) | info hash(32) | key(32) | checksum(2)`.

use crate::crypto::rand;
use crate::util::base32;
use sha2::{Digest, Sha256};

#[derive(Clone)]
pub struct BundleLink {
    info_hash: [u8; BundleLink::HASH_SIZE],
    content_key: [u8; BundleLink::KEY_SIZE],
}

impl BundleLink {
    pub const SCHEME: &'static str = "ont:";
    pub const HASH_SIZE: usize = 32;
    pub const KEY_SIZE: usize = 32;

    const CURRENT_VERSION: u8 = 1;
    const BODY_SIZE: usize = 1 + Self::HASH_SIZE + Self::KEY_SIZE + 2;

    pub fn new(info_hash: &[u8], content_key: &[u8]) -> Option<BundleLink> {
        if info_hash.len() != Self::HASH_SIZE || content_key.len() != Self::KEY_SIZE {
            return None;
        }
        let mut link = BundleLink {
            info_hash: [0u8; Self::HASH_SIZE],
            content_key: [0u8; Self::KEY_SIZE],
        };
        link.info_hash.copy_from_slice(info_hash);
        link.content_key.copy_from_slice(content_key);
        Some(link)
    }

    pub fn info_hash(&self) -> &[u8; BundleLink::HASH_SIZE] {
        &self.info_hash
    }

    pub fn content_key(&self) -> &[u8; BundleLink::KEY_SIZE] {
        &self.content_key
    }

    /// The link's text form.
    pub fn text(&self) -> String {
        let mut body = [0u8; Self::BODY_SIZE];
        body[0] = Self::CURRENT_VERSION;
        body[1..1 + Self::HASH_SIZE].copy_from_slice(&self.info_hash);
        body[1 + Self::HASH_SIZE..1 + Self::HASH_SIZE + Self::KEY_SIZE].copy_from_slice(&self.content_key);

        let sum = checksum(&body);
        body[Self::BODY_SIZE - 2] = sum[0];
        body[Self::BODY_SIZE - 1] = sum[1];

        let text = format!("{}{}", Self::SCHEME, base32::encode(&body));
        rand::wipe(&mut body);
        text
    }

    pub fn try_parse(text: &str) -> Option<BundleLink> {
        if text.trim().is_empty() {
            return None;
        }

        let text = text.trim();
        // `get` rather than slicing: pasted text may start with a multi-byte
        // letter, and a cut inside it must not panic.
        let text = match (text.get(..Self::SCHEME.len()), text.get(Self::SCHEME.len()..)) {
            (Some(head), Some(rest)) if head.eq_ignore_ascii_case(Self::SCHEME) => rest,
            _ => text,
        };

        let body = base32::try_decode(text)?;
        if body.len() != Self::BODY_SIZE {
            return None;
        }
        if body[0] != Self::CURRENT_VERSION {
            return None;
        }

        let sum = checksum(&body);
        if body[Self::BODY_SIZE - 2] != sum[0] || body[Self::BODY_SIZE - 1] != sum[1] {
            return None;
        }

        BundleLink::new(
            &body[1..1 + Self::HASH_SIZE],
            &body[1 + Self::HASH_SIZE..1 + Self::HASH_SIZE + Self::KEY_SIZE],
        )
    }

    /// The info hash as lower-case hex — the bundle's folder name in the store.
    pub fn hex(hash: &[u8]) -> String {
        let mut text = String::with_capacity(hash.len() * 2);
        for b in hash {
            text.push_str(&format!("{:02x}", b));
        }
        text
    }
}

impl std::fmt::Display for BundleLink {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.text())
    }
}

/// Two bytes against a typo in a pasted link. Everything but the sum goes in.
fn checksum(body: &[u8]) -> [u8; 2] {
    let digest = Sha256::digest(&body[..BundleLink::BODY_SIZE - 2]);
    [digest[0], digest[1]]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn format_then_parse_round_trip() {
        let hash: Vec<u8> = (0u8..32).collect();
        let key: Vec<u8> = (100u8..132).collect();
        let link = BundleLink::new(&hash, &key).unwrap();

        let text = link.text();
        assert!(text.starts_with("ont:"));

        let parsed = BundleLink::try_parse(&text).unwrap();
        assert_eq!(parsed.info_hash(), link.info_hash());
        assert_eq!(parsed.content_key(), link.content_key());
    }

    #[test]
    fn parse_tolerates_whitespace_and_case() {
        let link = BundleLink::new(&[9u8; 32], &[3u8; 32]).unwrap();
        let text = link.text();
        let messy = format!("  ONT:{}  ", &text[4..]);
        let parsed = BundleLink::try_parse(&messy).unwrap();
        assert_eq!(parsed.info_hash(), link.info_hash());
    }

    #[test]
    fn a_typo_fails_the_checksum() {
        let link = BundleLink::new(&[1u8; 32], &[2u8; 32]).unwrap();
        let text = link.text();
        let mut chars: Vec<char> = text.chars().collect();
        let i = text.len() - 1;
        chars[i] = if chars[i] == 'a' { 'b' } else { 'a' };
        let broken: String = chars.into_iter().collect();
        assert!(BundleLink::try_parse(&broken).is_none());
    }

    #[test]
    fn hex_is_lowercase() {
        assert_eq!(BundleLink::hex(&[0x0a, 0xff, 0x00]), "0aff00");
    }
}
