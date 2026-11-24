//! What a site's address points at right now: which bundle holds the current
//! version of its pages, and the key to that bundle.
//!
//! The record lies at the storage nodes, and they must not read it. So it is
//! filed under a hash of the address rather than the address itself, and sealed
//! under a key that grows out of the address. Whoever knows the address finds
//! the record and opens it; the storage node holds only the hash and can do
//! neither — it cannot even tell which site the record is.
//!
//! Inside, the owner's signature: the address grows out of the owner's key, so
//! nobody else's version of the site will pass for theirs.
//!
//! Nobody but the owner can file a record under an address. Outside the seal
//! the record carries the owner's public key and a signature over the whole of
//! it; whoever parses it — a storage node, a visitor — checks that the key grows
//! into exactly this lookup and that the signature holds. So nobody can put a
//! copy, a stale version or rubbish under somebody else's address, not even
//! first. (The C# kept the key out of the storage node's sight and let the
//! first comer's write secret own the slot; anybody knowing an address could
//! squat it. Now the storage node learns whose site the record is — the
//! address is public anyway — and still cannot read what is inside.)
//!
//! The write secret is kept as a second lock on replacing a record.

use crate::crypto::ecc_p256::SigningKey;
use crate::crypto::{aead_aes_ctr_hmac as aead, hkdf, rand};
use crate::identity::node_identity::NodeIdentity;
use crate::identity::onion_address::{compute_fingerprint, OnionAddress};
use crate::swarm::bundle_link::BundleLink;

const SALT: &[u8] = b"stalknet-site-v1";
const SIGN_CONTEXT: &[u8] = b"stalknet-site-signed-v1";
const OUTER_CONTEXT: &[u8] = b"stalknet-site-record-v2";

pub struct SiteRecord {
    lookup: Vec<u8>,
    version: i64,
    sealed: Vec<u8>,
    /// The owner's public signing key: it grows into the lookup.
    owner_key: Vec<u8>,
    /// The owner's signature over lookup, version and sealed part.
    signature: Vec<u8>,
}

impl SiteRecord {
    pub const LOOKUP_SIZE: usize = 32;
    pub const SECRET_SIZE: usize = 32;

    const PUBLIC_KEY_SIZE: usize = 64;
    const SIGNATURE_SIZE: usize = 64;
    const INNER_SIZE: usize = Self::PUBLIC_KEY_SIZE + 8 + BundleLink::HASH_SIZE + BundleLink::KEY_SIZE + Self::SIGNATURE_SIZE;
    pub const MAX_SEALED_SIZE: usize = Self::INNER_SIZE + aead::OVERHEAD;

    /// The hash of the address the record is filed under.
    pub fn lookup(&self) -> &[u8] {
        &self.lookup
    }

    /// The version: the time it was published, in ticks. A newer one replaces an
    /// older one.
    pub fn version(&self) -> i64 {
        self.version
    }

    pub fn sealed_bytes(&self) -> &[u8] {
        &self.sealed
    }

    pub fn lookup_for(site_fingerprint: &[u8]) -> Vec<u8> {
        hkdf::derive(SALT, site_fingerprint, b"lookup", Self::LOOKUP_SIZE)
    }

    fn seal_key(site_fingerprint: &[u8]) -> Vec<u8> {
        hkdf::derive(SALT, site_fingerprint, b"seal", aead::KEY_SIZE)
    }

    /// The owner's write secret: a secret agreed by the owner's key with itself.
    /// Only the holder of the private key can compute it, and it says nothing
    /// about the key. `None` only if the identity's own onion key is unusable.
    pub fn write_secret(owner: &NodeIdentity) -> Option<Vec<u8>> {
        let mut self_secret = owner.agree(owner.public_onion_key())?;
        let secret = hkdf::derive(SALT, &self_secret, b"write", Self::SECRET_SIZE);
        rand::wipe(&mut self_secret);
        Some(secret)
    }

    pub fn create(owner: &NodeIdentity, version: i64, content: &BundleLink) -> SiteRecord {
        let fingerprint = owner.fingerprint();
        let lookup = Self::lookup_for(&fingerprint);
        let signature = owner.sign(&signed_part(owner.public_signing_key(), version, content));

        let mut inner = Vec::with_capacity(Self::INNER_SIZE);
        inner.extend_from_slice(owner.public_signing_key());
        inner.extend_from_slice(&(version as u64).to_le_bytes());
        inner.extend_from_slice(content.info_hash());
        inner.extend_from_slice(content.content_key());
        inner.extend_from_slice(&signature);

        let mut key = Self::seal_key(&fingerprint);
        let sealed = aead::seal(&key, &inner, &binding(&lookup, version));
        rand::wipe(&mut key);
        rand::wipe(&mut inner);

        let owner_key = owner.public_signing_key().to_vec();
        let signature = owner.sign(&outer_signed(&lookup, version, &sealed)).to_vec();
        SiteRecord { lookup, version, sealed, owner_key, signature }
    }

    /// Opens the record with the site's address. `None` if it is not this site's,
    /// was tampered with, or is signed by anybody but the owner.
    pub fn try_open(&self, address: &OnionAddress) -> Option<BundleLink> {
        let fingerprint = address.fingerprint();
        if !rand::constant_time_equals(&Self::lookup_for(&fingerprint), &self.lookup) {
            return None;
        }

        let mut key = Self::seal_key(&fingerprint);
        let inner = aead::open(&key, &self.sealed, &binding(&self.lookup, self.version));
        rand::wipe(&mut key);

        let mut inner = inner?;
        if inner.len() != Self::INNER_SIZE {
            return None;
        }

        let mut at = 0usize;
        let public_key = take(&inner, &mut at, Self::PUBLIC_KEY_SIZE);
        let version = read_le64(&inner, at) as i64;
        at += 8;
        let info_hash = take(&inner, &mut at, BundleLink::HASH_SIZE);
        let content_key = take(&inner, &mut at, BundleLink::KEY_SIZE);
        let signature = take(&inner, &mut at, Self::SIGNATURE_SIZE);

        if version != self.version {
            return None;
        }
        if !address.matches(&public_key) {
            return None;
        }

        let link = BundleLink::new(&info_hash, &content_key)?;
        if !SigningKey::verify(&public_key, &signed_part(&public_key, version, &link), &signature) {
            return None;
        }

        rand::wipe(&mut inner);
        Some(link)
    }

    /// `lookup(32) | version(8 LE) | sealed length(2 LE) | sealed | owner key(64)
    /// | signature(64)`.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(
            Self::LOOKUP_SIZE + 8 + 2 + self.sealed.len() + Self::PUBLIC_KEY_SIZE + Self::SIGNATURE_SIZE,
        );
        out.extend_from_slice(&self.lookup);
        out.extend_from_slice(&self.version.to_le_bytes());
        out.extend_from_slice(&(self.sealed.len() as u16).to_le_bytes());
        out.extend_from_slice(&self.sealed);
        out.extend_from_slice(&self.owner_key);
        out.extend_from_slice(&self.signature);
        out
    }

    /// Parses a record and checks that its owner's key grows into its lookup
    /// and signed it. A record filed under somebody else's address is `None`.
    pub fn try_parse(data: &[u8]) -> Option<SiteRecord> {
        if data.len() < Self::LOOKUP_SIZE + 8 + 2 {
            return None;
        }

        let lookup = data[..Self::LOOKUP_SIZE].to_vec();
        let version = i64::from_le_bytes(data[Self::LOOKUP_SIZE..Self::LOOKUP_SIZE + 8].try_into().ok()?);
        let length = u16::from_le_bytes(data[Self::LOOKUP_SIZE + 8..Self::LOOKUP_SIZE + 10].try_into().ok()?) as usize;

        if length < aead::OVERHEAD || length > Self::MAX_SEALED_SIZE {
            return None;
        }

        let start = Self::LOOKUP_SIZE + 10;
        if start + length + Self::PUBLIC_KEY_SIZE + Self::SIGNATURE_SIZE != data.len() {
            return None;
        }
        if version <= 0 {
            return None;
        }

        let sealed = data[start..start + length].to_vec();
        let key_at = start + length;
        let owner_key = data[key_at..key_at + Self::PUBLIC_KEY_SIZE].to_vec();
        let signature = data[key_at + Self::PUBLIC_KEY_SIZE..].to_vec();

        // The key must be the one this lookup grows out of, and must have
        // signed exactly this record.
        if !rand::constant_time_equals(&Self::lookup_for(&compute_fingerprint(&owner_key)), &lookup) {
            return None;
        }
        if !SigningKey::verify(&owner_key, &outer_signed(&lookup, version, &sealed), &signature) {
            return None;
        }

        Some(SiteRecord { lookup, version, sealed, owner_key, signature })
    }
}

/// What the owner signs outside the seal: the whole record.
fn outer_signed(lookup: &[u8], version: i64, sealed: &[u8]) -> Vec<u8> {
    let mut data = Vec::with_capacity(OUTER_CONTEXT.len() + lookup.len() + 8 + sealed.len());
    data.extend_from_slice(OUTER_CONTEXT);
    data.extend_from_slice(lookup);
    data.extend_from_slice(&(version as u64).to_le_bytes());
    data.extend_from_slice(sealed);
    data
}

fn signed_part(public_key: &[u8], version: i64, content: &BundleLink) -> Vec<u8> {
    let mut data = Vec::with_capacity(SIGN_CONTEXT.len() + 64 + 8 + BundleLink::HASH_SIZE + BundleLink::KEY_SIZE);
    data.extend_from_slice(SIGN_CONTEXT);
    data.extend_from_slice(public_key);
    data.extend_from_slice(&(version as u64).to_le_bytes());
    data.extend_from_slice(content.info_hash());
    data.extend_from_slice(content.content_key());
    data
}

/// The outside of the record sealed together with the inside: neither moves
/// without the other. `lookup(32) || version(8 LE)`.
fn binding(lookup: &[u8], version: i64) -> Vec<u8> {
    let mut data = Vec::with_capacity(SiteRecord::LOOKUP_SIZE + 8);
    data.extend_from_slice(lookup);
    data.extend_from_slice(&(version as u64).to_le_bytes());
    data
}

fn take(source: &[u8], at: &mut usize, length: usize) -> Vec<u8> {
    let part = source[*at..*at + length].to_vec();
    *at += length;
    part
}

fn read_le64(source: &[u8], offset: usize) -> u64 {
    let mut value: u64 = 0;
    for i in (0..8).rev() {
        value = (value << 8) | source[offset + i] as u64;
    }
    value
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn create_open_round_trip() {
        let owner = NodeIdentity::create("site-owner").unwrap();
        let link = BundleLink::new(&[5u8; 32], &[6u8; 32]).unwrap();
        let version = 638_000_000_000_000_000i64;

        let record = SiteRecord::create(&owner, version, &link);

        // Serialise and parse before opening — the wire path.
        let bytes = record.to_bytes();
        let parsed = SiteRecord::try_parse(&bytes).unwrap();
        assert_eq!(parsed.version(), version);
        assert_eq!(parsed.lookup(), record.lookup());

        let opened = parsed.try_open(owner.address()).unwrap();
        assert_eq!(opened.info_hash(), link.info_hash());
        assert_eq!(opened.content_key(), link.content_key());
    }

    #[test]
    fn another_address_cannot_open() {
        let owner = NodeIdentity::create("owner").unwrap();
        let stranger = NodeIdentity::create("stranger").unwrap();
        let link = BundleLink::new(&[1u8; 32], &[2u8; 32]).unwrap();

        let record = SiteRecord::create(&owner, 100, &link);
        assert!(record.try_open(stranger.address()).is_none());
    }

    #[test]
    fn a_tampered_record_does_not_open() {
        let owner = NodeIdentity::create("owner").unwrap();
        let link = BundleLink::new(&[3u8; 32], &[4u8; 32]).unwrap();
        let record = SiteRecord::create(&owner, 42, &link);

        // A changed byte breaks the outer signature: the record does not even
        // parse, at a storage node or anywhere.
        let mut bytes = record.to_bytes();
        bytes[SiteRecord::LOOKUP_SIZE + 12] ^= 0xff;
        assert!(SiteRecord::try_parse(&bytes).is_none());
    }

    #[test]
    fn nobody_files_a_record_under_another_address() {
        // A stranger who knows the owner's address makes a record of their own
        // and puts the owner's lookup on it: it does not parse.
        let owner = NodeIdentity::create("owner").unwrap();
        let stranger = NodeIdentity::create("stranger").unwrap();
        let link = BundleLink::new(&[7u8; 32], &[8u8; 32]).unwrap();

        let mut forged = SiteRecord::create(&stranger, 99, &link);
        forged.lookup = SiteRecord::lookup_for(&owner.fingerprint());
        forged.signature = stranger.sign(&outer_signed(&forged.lookup, 99, &forged.sealed)).to_vec();
        assert!(SiteRecord::try_parse(&forged.to_bytes()).is_none());

        // Nor with the owner's key put in front of the stranger's signature.
        forged.owner_key = owner.public_signing_key().to_vec();
        assert!(SiteRecord::try_parse(&forged.to_bytes()).is_none());
    }

    #[test]
    fn write_secret_is_stable() {
        let owner = NodeIdentity::create("owner").unwrap();
        let a = SiteRecord::write_secret(&owner).unwrap();
        let b = SiteRecord::write_secret(&owner).unwrap();
        assert_eq!(a, b);
        assert_eq!(a.len(), SiteRecord::SECRET_SIZE);
    }
}
