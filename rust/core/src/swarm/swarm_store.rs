//! Bundles on disk.
//!
//! Each has a folder named after its info hash: the header, the encrypted
//! contents and a mark of which pieces are already here.
//!
//! Only ciphertext is kept. The store hands bundles out to the swarm, and
//! whoever holds a piece needs no more than its hash; what is inside is opened
//! elsewhere, with the link's key, into a folder of the owner's choosing.

use crate::crypto::rand;
use crate::swarm::bundle_header::BundleHeader;
use crate::swarm::bundle_link::BundleLink;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::fs;
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

const HEADER_FILE: &str = "header.bin";
const DATA_FILE: &str = "data.bin";
const HAVE_FILE: &str = "have.bin";

pub struct SwarmStore {
    root: PathBuf,
    open: Mutex<HashMap<String, Arc<StoredBundle>>>,
}

impl SwarmStore {
    pub fn new(root: impl AsRef<Path>) -> io::Result<SwarmStore> {
        let root = canonicalize_or_absolute(root.as_ref());
        fs::create_dir_all(&root)?;
        Ok(SwarmStore {
            root,
            open: Mutex::new(HashMap::new()),
        })
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    /// Takes a header in: it must hash to the info hash, or it is not taken.
    pub fn add_header(&self, info_hash: &[u8], header_bytes: &[u8]) -> Option<Arc<StoredBundle>> {
        let header = BundleHeader::try_parse(header_bytes)?;
        if !same_hash(header.info_hash(), info_hash) {
            return None;
        }

        let mut open = self.open.lock().unwrap();
        if let Some(existing) = self.open_locked(&mut open, info_hash) {
            return Some(existing);
        }

        let folder = self.folder_for(info_hash);
        fs::create_dir_all(&folder).ok()?;
        fs::write(folder.join(HEADER_FILE), header.bytes()).ok()?;

        let have = vec![0u8; (header.piece_count() as usize + 7) / 8];
        let bundle = Arc::new(StoredBundle::new(folder, header, have));
        bundle.save_have().ok()?;
        open.insert(BundleLink::hex(info_hash), bundle.clone());
        Some(bundle)
    }

    /// Moves a bundle built aside into the store — complete, with every piece
    /// marked. The folder must hold the data file already.
    pub(crate) fn adopt(&self, built_folder: &Path, header: BundleHeader) -> io::Result<Arc<StoredBundle>> {
        let mut open = self.open.lock().unwrap();

        if let Some(existing) = self.open_locked(&mut open, header.info_hash()) {
            let _ = fs::remove_dir_all(built_folder);
            return Ok(existing);
        }

        let folder = self.folder_for(header.info_hash());
        fs::rename(built_folder, &folder)?;
        fs::write(folder.join(HEADER_FILE), header.bytes())?;

        let mut have = vec![0u8; (header.piece_count() as usize + 7) / 8];
        for i in 0..header.piece_count() as usize {
            have[i >> 3] |= 0x80u8 >> (i & 7);
        }

        let bundle = Arc::new(StoredBundle::new(folder, header, have));
        bundle.save_have()?;
        open.insert(BundleLink::hex(bundle.info_hash()), bundle.clone());
        Ok(bundle)
    }

    /// A bundle whose header is here. `None` if there is none.
    pub fn open(&self, info_hash: &[u8]) -> Option<Arc<StoredBundle>> {
        let mut open = self.open.lock().unwrap();
        self.open_locked(&mut open, info_hash)
    }

    /// Every bundle the store holds whole — what this node can hand out.
    pub fn complete(&self) -> Vec<Arc<StoredBundle>> {
        let mut result = Vec::new();

        let folders = match fs::read_dir(&self.root) {
            Ok(entries) => entries,
            Err(_) => return result,
        };

        let names: Vec<String> = folders
            .filter_map(|e| e.ok())
            .filter_map(|e| e.file_name().into_string().ok())
            .collect();

        for name in names {
            let hash = match from_hex(&name) {
                Some(h) => h,
                None => continue,
            };
            if let Some(bundle) = self.open(&hash) {
                if bundle.is_complete() {
                    result.push(bundle);
                }
            }
        }

        result
    }

    /// A folder for building a new bundle, inside the store so the move is cheap.
    pub(crate) fn new_work_folder(&self) -> io::Result<PathBuf> {
        let folder = self.root.join(format!("building-{}", BundleLink::hex(&rand::get_bytes(16))));
        fs::create_dir_all(&folder)?;
        Ok(folder)
    }

    pub(crate) fn data_path(folder: &Path) -> PathBuf {
        folder.join(DATA_FILE)
    }

    fn open_locked(
        &self,
        open: &mut HashMap<String, Arc<StoredBundle>>,
        info_hash: &[u8],
    ) -> Option<Arc<StoredBundle>> {
        let key = BundleLink::hex(info_hash);
        if let Some(bundle) = open.get(&key) {
            return Some(bundle.clone());
        }

        let folder = self.folder_for(info_hash);
        let header_path = folder.join(HEADER_FILE);
        if !header_path.exists() {
            return None;
        }

        let header = BundleHeader::try_parse(&fs::read(&header_path).ok()?)?;
        if !same_hash(header.info_hash(), info_hash) {
            return None;
        }

        let mut have = vec![0u8; (header.piece_count() as usize + 7) / 8];
        let have_path = folder.join(HAVE_FILE);
        if have_path.exists() {
            if let Ok(saved) = fs::read(&have_path) {
                if saved.len() == have.len() {
                    have = saved;
                }
            }
        }

        let bundle = Arc::new(StoredBundle::new(folder, header, have));
        open.insert(key, bundle.clone());
        Some(bundle)
    }

    fn folder_for(&self, info_hash: &[u8]) -> PathBuf {
        self.root.join(BundleLink::hex(info_hash))
    }
}

fn same_hash(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a == b
}

fn from_hex(text: &str) -> Option<Vec<u8>> {
    if text.len() != BundleLink::HASH_SIZE * 2 {
        return None;
    }
    let mut bytes = Vec::with_capacity(BundleLink::HASH_SIZE);
    let chars: Vec<char> = text.chars().collect();
    for pair in chars.chunks(2) {
        let high = hex_digit(pair[0])?;
        let low = hex_digit(pair[1])?;
        bytes.push((high << 4) | low);
    }
    Some(bytes)
}

fn hex_digit(c: char) -> Option<u8> {
    match c {
        '0'..='9' => Some(c as u8 - b'0'),
        'a'..='f' => Some(c as u8 - b'a' + 10),
        'A'..='F' => Some(c as u8 - b'A' + 10),
        _ => None,
    }
}

/// Minimal `canonicalize` that does not require the path to exist yet — matches
/// the C# `Path.GetFullPath`, which also works on a path that is not there.
fn canonicalize_or_absolute(path: &Path) -> PathBuf {
    if let Ok(canon) = std::fs::canonicalize(path) {
        return canon;
    }
    if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir()
            .map(|cwd| cwd.join(path))
            .unwrap_or_else(|_| path.to_path_buf())
    }
}

/// One bundle in the store: its header, its pieces, what is here.
pub struct StoredBundle {
    folder: PathBuf,
    header: BundleHeader,
    have: Mutex<Have>,
}

struct Have {
    bits: Vec<u8>,
    count: usize,
}

impl StoredBundle {
    fn new(folder: PathBuf, header: BundleHeader, bits: Vec<u8>) -> StoredBundle {
        let mut count = 0usize;
        for i in 0..header.piece_count() as usize {
            if bits[i >> 3] & (0x80u8 >> (i & 7)) != 0 {
                count += 1;
            }
        }
        StoredBundle {
            folder,
            header,
            have: Mutex::new(Have { bits, count }),
        }
    }

    pub fn header(&self) -> &BundleHeader {
        &self.header
    }

    pub fn info_hash(&self) -> &[u8; BundleHeader::HASH_SIZE] {
        self.header.info_hash()
    }

    /// Where the encrypted contents lie.
    pub fn data_path(&self) -> PathBuf {
        SwarmStore::data_path(&self.folder)
    }

    pub fn have_count(&self) -> i32 {
        self.have.lock().unwrap().count as i32
    }

    pub fn is_complete(&self) -> bool {
        self.have_count() == self.header.piece_count()
    }

    pub fn has(&self, index: i32) -> bool {
        if index < 0 || index >= self.header.piece_count() {
            return false;
        }
        let i = index as usize;
        self.have.lock().unwrap().bits[i >> 3] & (0x80u8 >> (i & 7)) != 0
    }

    /// A copy of the "which pieces are here" mark: a bit per piece, the oldest
    /// bit first.
    pub fn bitfield(&self) -> Vec<u8> {
        self.have.lock().unwrap().bits.clone()
    }

    /// The encrypted piece. `None` if it is not here.
    pub fn read_piece(&self, index: i32) -> Option<Vec<u8>> {
        if !self.has(index) {
            return None;
        }

        let length = self.header.piece_length(index) as usize;
        let mut piece = vec![0u8; length];

        let _guard = self.have.lock().unwrap();
        let mut file = std::fs::File::open(self.data_path()).ok()?;
        file.seek(SeekFrom::Start(index as u64 * self.header.piece_size() as u64)).ok()?;
        file.read_exact(&mut piece).ok()?;
        Some(piece)
    }

    /// Takes a piece in. It is checked against its hash first: a piece that does
    /// not match is somebody's lie or a breakage, and nothing of it reaches the
    /// disk.
    pub fn write_piece(&self, index: i32, piece: &[u8]) -> bool {
        if index < 0 || index >= self.header.piece_count() {
            return false;
        }
        if piece.len() != self.header.piece_length(index) as usize {
            return false;
        }

        let hash = Sha256::digest(piece);
        if hash.as_slice() != self.header.piece_hash(index as usize) {
            return false;
        }

        let i = index as usize;
        let mut have = self.have.lock().unwrap();
        if have.bits[i >> 3] & (0x80u8 >> (i & 7)) != 0 {
            return true;
        }

        let write_result = (|| -> io::Result<()> {
            let mut file = std::fs::OpenOptions::new()
                .create(true)
                .write(true)
                .open(self.data_path())?;
            file.seek(SeekFrom::Start(index as u64 * self.header.piece_size() as u64))?;
            file.write_all(piece)?;
            Ok(())
        })();

        if write_result.is_err() {
            return false;
        }

        have.bits[i >> 3] |= 0x80u8 >> (i & 7);
        have.count += 1;
        let _ = self.write_have_file(&have.bits);
        true
    }

    fn write_have_file(&self, bits: &[u8]) -> io::Result<()> {
        std::fs::write(self.folder.join(HAVE_FILE), bits)
    }

    pub(crate) fn save_have(&self) -> io::Result<()> {
        let have = self.have.lock().unwrap();
        self.write_have_file(&have.bits)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::aead_aes_ctr_hmac as aead;

    fn temp_dir(name: &str) -> PathBuf {
        let mut p = std::env::temp_dir();
        p.push(format!("stalknet_store_{}_{}", std::process::id(), name));
        let _ = std::fs::remove_dir_all(&p);
        p
    }

    fn make_header(piece: &[u8]) -> (BundleHeader, Vec<u8>) {
        // One piece of exactly MIN_PIECE_SIZE so piece_length(0) == piece.len().
        let piece_size = BundleHeader::MIN_PIECE_SIZE;
        let total = piece.len() as i64;
        let mut hash = [0u8; 32];
        hash.copy_from_slice(&Sha256::digest(piece));
        let sealed = vec![0u8; aead::OVERHEAD];
        let header = BundleHeader::create(piece_size, total, &sealed, &[hash]).unwrap();
        (header, sealed)
    }

    #[test]
    fn add_header_and_write_read_piece() {
        let root = temp_dir("rw");
        let store = SwarmStore::new(&root).unwrap();

        let piece = vec![0x5au8; BundleHeader::MIN_PIECE_SIZE as usize];
        let (header, _) = make_header(&piece);
        let info_hash = *header.info_hash();

        let bundle = store.add_header(&info_hash, header.bytes()).unwrap();
        assert!(!bundle.is_complete());
        assert!(bundle.read_piece(0).is_none());

        // A wrong piece is refused outright.
        let mut wrong = piece.clone();
        wrong[0] ^= 1;
        assert!(!bundle.write_piece(0, &wrong));

        // The right piece is taken and comes back byte-identical.
        assert!(bundle.write_piece(0, &piece));
        assert!(bundle.is_complete());
        assert_eq!(bundle.read_piece(0).unwrap(), piece);

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn open_reuses_the_same_bundle() {
        let root = temp_dir("reuse");
        let store = SwarmStore::new(&root).unwrap();
        let piece = vec![1u8; BundleHeader::MIN_PIECE_SIZE as usize];
        let (header, _) = make_header(&piece);
        let info_hash = *header.info_hash();

        store.add_header(&info_hash, header.bytes()).unwrap();
        let again = store.open(&info_hash).unwrap();
        assert_eq!(again.info_hash(), &info_hash);
        let _ = std::fs::remove_dir_all(&root);
    }
}
