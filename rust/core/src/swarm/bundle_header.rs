//! A bundle's header: everything a node needs to hand the bundle out and to
//! check what it is handed, and nothing it could read.
//!
//! The layout: `"ONTB" | version(1) | piece size(4 LE) | total length(8 LE) |
//! sealed list length(4 LE) | sealed list | piece count(4 LE) | the SHA-256 of
//! every encrypted piece`.
//!
//! The SHA-256 of the whole header is the bundle's info hash. A header that
//! hashes to the link's info hash is the right one to the byte, and then every
//! piece is checked against its own hash before it is taken. So a stranger in
//! the swarm can waste our time but cannot slip us a single wrong byte.

use crate::crypto::{aead_aes_ctr_hmac as aead, ctr_stream, hkdf};
use crate::swarm::bundle_manifest::BundleManifest;
use sha2::{Digest, Sha256};

/// The keys a bundle's content key spreads into. Each under its own label:
/// knowing one gives no way to another.
pub(crate) mod keys {
    use super::*;

    const SALT: &[u8] = b"stalknet-bundle-v1";

    /// The keystream over the files' bytes.
    pub(crate) fn stream_key(content_key: &[u8]) -> Vec<u8> {
        hkdf::derive(SALT, content_key, b"stream-key", ctr_stream::KEY_SIZE)
    }

    pub(crate) fn stream_iv(content_key: &[u8]) -> Vec<u8> {
        hkdf::derive(SALT, content_key, b"stream-iv", ctr_stream::IV_SIZE)
    }

    /// The seal over the file list.
    pub(crate) fn manifest_key(content_key: &[u8]) -> Vec<u8> {
        hkdf::derive(SALT, content_key, b"manifest", aead::KEY_SIZE)
    }
}

const MAGIC: &[u8; 4] = b"ONTB";
const FORMAT_VERSION: u8 = 1;

#[derive(Clone, Debug)]
pub struct BundleHeader {
    piece_size: i32,
    total_length: i64,
    sealed_manifest: Vec<u8>,
    hashes: Vec<[u8; BundleHeader::HASH_SIZE]>,
    /// The header exactly as it travels — its hash is the info hash.
    bytes: Vec<u8>,
    info_hash: [u8; BundleHeader::HASH_SIZE],
}

impl BundleHeader {
    pub const HASH_SIZE: usize = 32;
    pub const MIN_PIECE_SIZE: i32 = 64 * 1024;
    pub const MAX_PIECE_SIZE: i32 = 16 * 1024 * 1024;

    /// Pieces stop at this count: bigger bundles get bigger pieces instead.
    pub const TARGET_PIECES: i64 = 4096;

    pub const MAX_PIECES: i32 = 65536;
    pub const MAX_SEALED_MANIFEST: usize = 8 * 1024 * 1024;

    pub fn piece_size(&self) -> i32 {
        self.piece_size
    }
    pub fn total_length(&self) -> i64 {
        self.total_length
    }
    pub fn sealed_manifest(&self) -> &[u8] {
        &self.sealed_manifest
    }
    pub fn piece_count(&self) -> i32 {
        self.hashes.len() as i32
    }
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }
    pub fn info_hash(&self) -> &[u8; BundleHeader::HASH_SIZE] {
        &self.info_hash
    }

    pub fn piece_hash(&self, index: usize) -> &[u8; BundleHeader::HASH_SIZE] {
        &self.hashes[index]
    }

    /// How long piece number `index` is: all are full but the last.
    pub fn piece_length(&self, index: i32) -> i32 {
        assert!(index >= 0 && index < self.piece_count(), "piece index out of range");
        let start = index as i64 * self.piece_size as i64;
        (self.piece_size as i64).min(self.total_length - start) as i32
    }

    /// The piece size for a bundle of this length.
    pub fn choose_piece_size(total_length: i64) -> i32 {
        let mut size = Self::MIN_PIECE_SIZE;
        while size < Self::MAX_PIECE_SIZE && Self::pieces_for(total_length, size) as i64 > Self::TARGET_PIECES {
            size *= 2;
        }
        size
    }

    pub fn pieces_for(total_length: i64, piece_size: i32) -> i32 {
        if total_length <= 0 {
            return 0;
        }
        ((total_length + piece_size as i64 - 1) / piece_size as i64) as i32
    }

    /// Puts a header together and works out its info hash.
    pub fn create(
        piece_size: i32,
        total_length: i64,
        sealed_manifest: &[u8],
        hashes: &[[u8; BundleHeader::HASH_SIZE]],
    ) -> Option<BundleHeader> {
        let mut buffer = Vec::new();
        buffer.extend_from_slice(MAGIC);
        buffer.push(FORMAT_VERSION);
        buffer.extend_from_slice(&piece_size.to_le_bytes());
        buffer.extend_from_slice(&total_length.to_le_bytes());
        buffer.extend_from_slice(&(sealed_manifest.len() as i32).to_le_bytes());
        buffer.extend_from_slice(sealed_manifest);
        buffer.extend_from_slice(&(hashes.len() as i32).to_le_bytes());
        for hash in hashes {
            buffer.extend_from_slice(hash);
        }

        Self::try_parse(&buffer)
    }

    /// Parses a header and checks it holds together. The info hash is computed
    /// here.
    pub fn try_parse(data: &[u8]) -> Option<BundleHeader> {
        if data.len() < MAGIC.len() + 1 {
            return None;
        }

        let mut position = 0usize;
        let mut take = |count: usize| -> Option<&[u8]> {
            if position + count > data.len() {
                return None;
            }
            let slice = &data[position..position + count];
            position += count;
            Some(slice)
        };

        if take(MAGIC.len())? != MAGIC {
            return None;
        }
        if take(1)?[0] != FORMAT_VERSION {
            return None;
        }

        let piece_size = i32::from_le_bytes(take(4)?.try_into().ok()?);
        let total = i64::from_le_bytes(take(8)?.try_into().ok()?);
        if piece_size < Self::MIN_PIECE_SIZE || piece_size > Self::MAX_PIECE_SIZE {
            return None;
        }
        if piece_size & (piece_size - 1) != 0 {
            return None;
        }
        if total < 0 {
            return None;
        }

        let sealed_length = i32::from_le_bytes(take(4)?.try_into().ok()?);
        if sealed_length < aead::OVERHEAD as i32 || sealed_length as usize > Self::MAX_SEALED_MANIFEST {
            return None;
        }
        let sealed_manifest = take(sealed_length as usize)?.to_vec();

        let count = i32::from_le_bytes(take(4)?.try_into().ok()?);
        if count < 0 || count > Self::MAX_PIECES {
            return None;
        }
        if count != Self::pieces_for(total, piece_size) {
            return None;
        }

        let mut hashes = Vec::with_capacity(count as usize);
        for _ in 0..count {
            let mut hash = [0u8; Self::HASH_SIZE];
            hash.copy_from_slice(take(Self::HASH_SIZE)?);
            hashes.push(hash);
        }

        if position != data.len() {
            return None;
        }

        let mut info_hash = [0u8; Self::HASH_SIZE];
        info_hash.copy_from_slice(&Sha256::digest(data));

        Some(BundleHeader {
            piece_size,
            total_length: total,
            sealed_manifest,
            hashes,
            bytes: data.to_vec(),
            info_hash,
        })
    }

    /// Opens the file list with the link's key. `None` if the key is not this
    /// bundle's.
    pub fn open_manifest(&self, content_key: &[u8]) -> Option<BundleManifest> {
        let mut key = keys::manifest_key(content_key);
        let plain = aead::open(&key, &self.sealed_manifest, &self.info_binding());
        crate::crypto::rand::wipe(&mut key);

        let plain = plain?;
        let manifest = BundleManifest::parse(&plain).ok()?;
        if manifest.total_length() == self.total_length {
            Some(manifest)
        } else {
            None
        }
    }

    /// What the file list is sealed together with: the piece size and the
    /// length. A list moved into another header will not open.
    pub(crate) fn binding(piece_size: i32, total_length: i64) -> [u8; 12] {
        let mut data = [0u8; 12];
        data[..8].copy_from_slice(&(total_length as u64).to_le_bytes());
        data[8..].copy_from_slice(&piece_size.to_le_bytes());
        data
    }

    fn info_binding(&self) -> [u8; 12] {
        Self::binding(self.piece_size, self.total_length)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sha256(data: &[u8]) -> [u8; 32] {
        let mut out = [0u8; 32];
        out.copy_from_slice(&Sha256::digest(data));
        out
    }

    #[test]
    fn create_then_parse_round_trip() {
        let sealed = vec![7u8; aead::OVERHEAD + 16];
        // 150 KiB of data, piece size 64 KiB -> 3 pieces.
        let piece_size = 64 * 1024;
        let total: i64 = 150 * 1024;
        let count = BundleHeader::pieces_for(total, piece_size);
        assert_eq!(count, 3);

        let hashes: Vec<[u8; 32]> = (0..count).map(|i| sha256(&[i as u8])).collect();
        let header = BundleHeader::create(piece_size, total, &sealed, &hashes).unwrap();

        let reparsed = BundleHeader::try_parse(header.bytes()).unwrap();
        assert_eq!(reparsed.info_hash(), header.info_hash());
        assert_eq!(reparsed.piece_count(), 3);
        assert_eq!(reparsed.piece_size(), piece_size);
        assert_eq!(reparsed.total_length(), total);
        assert_eq!(reparsed.piece_length(0), piece_size);
        assert_eq!(reparsed.piece_length(2), (total - 2 * piece_size as i64) as i32);
        assert_eq!(reparsed.piece_hash(1), header.piece_hash(1));
    }

    #[test]
    fn a_flipped_byte_changes_the_info_hash() {
        let sealed = vec![1u8; aead::OVERHEAD];
        let header = BundleHeader::create(64 * 1024, 0, &sealed, &[]).unwrap();
        let mut bytes = header.bytes().to_vec();
        bytes[10] ^= 1;
        match BundleHeader::try_parse(&bytes) {
            Some(other) => assert_ne!(other.info_hash(), header.info_hash()),
            None => {}
        }
    }

    #[test]
    fn choose_piece_size_grows_with_length() {
        assert_eq!(BundleHeader::choose_piece_size(0), BundleHeader::MIN_PIECE_SIZE);
        assert!(BundleHeader::choose_piece_size(1 << 40) > BundleHeader::MIN_PIECE_SIZE);
        // Every chosen size is a power of two within the bounds.
        let s = BundleHeader::choose_piece_size(1 << 32);
        assert_eq!(s & (s - 1), 0);
        assert!(s <= BundleHeader::MAX_PIECE_SIZE);
    }
}
