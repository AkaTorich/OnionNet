//! Makes a bundle out of a file or a folder and opens a finished one back up.
//!
//! Every bundle gets a key of its own, random: two bundles of the same files
//! are two different bundles, and nothing in the swarm tells that they hold the
//! same thing. The files are read and encrypted as a stream, so a bundle of any
//! size never sits in memory whole.

use crate::crypto::ctr_stream::CtrStream;
use crate::crypto::{aead_aes_ctr_hmac as aead, rand};
use crate::swarm::bundle_header::{keys, BundleHeader};
use crate::swarm::bundle_link::BundleLink;
use crate::swarm::bundle_manifest::{is_safe_path, BundleFile, BundleKind, BundleManifest};
use crate::swarm::swarm_store::{StoredBundle, SwarmStore};
use crate::swarm::{Result, SwarmError};
use sha2::{Digest, Sha256};
use std::fs;
use std::io::{ErrorKind, Read, Write};
use std::path::{Component, Path, PathBuf};
use std::sync::Arc;

const COPY_BUFFER: usize = 64 * 1024;

/// Builds a bundle into the store, complete. Returns its link.
pub fn build(store: &SwarmStore, source_path: impl AsRef<Path>, kind: BundleKind) -> Result<BundleLink> {
    let source_path = source_path.as_ref();
    if source_path.as_os_str().is_empty() {
        return Err(SwarmError::Invalid("no file or folder was given".into()));
    }

    let full = absolute_lexical(source_path);
    let mut sources: Vec<PathBuf> = Vec::new();
    let manifest;

    if full.is_file() {
        let name = file_name(&full);
        let mut m = BundleManifest::new(kind, name.clone());
        m.files.push(BundleFile::new(name, fs::metadata(&full)?.len() as i64));
        sources.push(full.clone());
        manifest = m;
    } else if full.is_dir() {
        let name = file_name(&full);
        let mut m = BundleManifest::new(kind, name.clone());

        // A folder of files keeps its own name in the paths, so it unpacks as a
        // folder; a site's paths start at its root, since the root is what gets
        // served.
        let prefix = if kind == BundleKind::Site { String::new() } else { format!("{name}/") };
        collect(&full, &full, &prefix, &mut m, &mut sources)?;
        manifest = m;
    } else {
        return Err(SwarmError::Io(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            "there is no such file or folder",
        )));
    }

    for file in &manifest.files {
        if !is_safe_path(&file.path) {
            return Err(SwarmError::Invalid(format!("a file name that cannot travel: {}", file.path)));
        }
    }

    let mut content_key = rand::get_bytes(BundleLink::KEY_SIZE);
    let work = store.new_work_folder()?;

    let result = (|| -> Result<BundleLink> {
        let total = manifest.total_length();
        let piece_size = BundleHeader::choose_piece_size(total);
        let hashes = encrypt_into(&SwarmStore::data_path(&work), &sources, &content_key, piece_size, total)?;

        let mut manifest_key = keys::manifest_key(&content_key);
        let sealed = aead::seal(&manifest_key, &manifest.to_bytes()?, &BundleHeader::binding(piece_size, total));
        rand::wipe(&mut manifest_key);

        let header = BundleHeader::create(piece_size, total, &sealed, &hashes)
            .ok_or_else(|| SwarmError::Invalid("the header does not add up".into()))?;
        let info_hash = *header.info_hash();
        store.adopt(&work, header)?;

        BundleLink::new(&info_hash, &content_key)
            .ok_or_else(|| SwarmError::Invalid("the link does not add up".into()))
    })();

    if result.is_err() {
        let _ = fs::remove_dir_all(&work);
    }
    rand::wipe(&mut content_key);
    result
}

/// Opens a complete bundle into a folder. Returns the file list. Every path is
/// checked once more against the folder itself: the list was checked while
/// parsing, but the disk is what must not be wronged.
pub fn extract(bundle: &Arc<StoredBundle>, content_key: &[u8], target_folder: impl AsRef<Path>) -> Result<BundleManifest> {
    if !bundle.is_complete() {
        return Err(SwarmError::Invalid("the bundle is not fully here yet".into()));
    }

    let manifest = bundle
        .header()
        .open_manifest(content_key)
        .ok_or_else(|| SwarmError::Crypto("the link's key does not open this bundle".into()))?;

    let root = absolute_lexical(target_folder.as_ref());
    fs::create_dir_all(&root)?;
    let prefix = with_trailing_sep(&root);

    let mut key = keys::stream_key(content_key);
    let mut iv = keys::stream_iv(content_key);

    let outcome = (|| -> Result<()> {
        let mut cipher = CtrStream::new(&key, &iv);
        let mut data = if bundle.header().total_length() == 0 {
            None
        } else {
            Some(fs::File::open(bundle.data_path())?)
        };

        let mut buffer = vec![0u8; COPY_BUFFER];

        for file in &manifest.files {
            let relative = file.path.replace('/', std::path::MAIN_SEPARATOR_STR);
            let target = absolute_lexical(&root.join(&relative));
            if !starts_with_ignore_case(&target, &prefix) {
                return Err(SwarmError::Invalid("a file path that leads out of the folder".into()));
            }

            if let Some(folder) = target.parent() {
                fs::create_dir_all(folder)?;
            }

            let mut output = fs::File::create(&target)?;
            let mut left = file.length;
            while left > 0 {
                let take = (buffer.len() as i64).min(left) as usize;
                read_exactly(data.as_mut(), &mut buffer[..take])?;
                cipher.xor_in_place(&mut buffer[..take]);
                output.write_all(&buffer[..take])?;
                left -= take as i64;
            }
        }

        rand::wipe(&mut buffer);
        Ok(())
    })();

    rand::wipe(&mut key);
    rand::wipe(&mut iv);
    outcome?;
    Ok(manifest)
}

/// The folder's files in a fixed order. Hidden and system ones stay home, the
/// same as from a shared folder: a `.git` or a `.ssh` that came along has no
/// business in somebody else's hands.
fn collect(root: &Path, folder: &Path, prefix: &str, manifest: &mut BundleManifest, sources: &mut Vec<PathBuf>) -> Result<()> {
    let mut files: Vec<PathBuf> = Vec::new();
    let mut children: Vec<PathBuf> = Vec::new();

    for entry in fs::read_dir(folder)? {
        let entry = entry?;
        let path = entry.path();
        let file_type = entry.file_type()?;

        if file_type.is_dir() {
            children.push(path);
        } else if file_type.is_file() {
            files.push(path);
        }
        // Symlinks to files are skipped here (neither dir nor file for
        // follow-purposes); directory links are filtered below.
    }

    // CompareOrdinal on the file name.
    files.sort_by(|a, b| file_name(a).cmp(&file_name(b)));
    children.sort_by(|a, b| file_name(a).cmp(&file_name(b)));

    for file in files {
        if is_hidden(&file) {
            continue;
        }
        let relative = relative_slash(root, &file);
        manifest.files.push(BundleFile::new(format!("{prefix}{relative}"), fs::metadata(&file)?.len() as i64));
        sources.push(file);
    }

    for child in children {
        if is_hidden(&child) {
            continue;
        }
        // A link to elsewhere is not followed: it could lead out of the folder
        // the owner meant to give, even in a loop.
        if is_reparse_point(&child) {
            continue;
        }
        collect(root, &child, prefix, manifest, sources)?;
    }

    Ok(())
}

fn is_hidden(path: &Path) -> bool {
    let name = file_name(path);
    if name.starts_with('.') {
        return true;
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        const HIDDEN: u32 = 0x2;
        const SYSTEM: u32 = 0x4;
        if let Ok(meta) = fs::symlink_metadata(path) {
            if meta.file_attributes() & (HIDDEN | SYSTEM) != 0 {
                return true;
            }
        }
    }
    false
}

fn is_reparse_point(path: &Path) -> bool {
    if let Ok(meta) = fs::symlink_metadata(path) {
        if meta.file_type().is_symlink() {
            return true;
        }
        #[cfg(windows)]
        {
            use std::os::windows::fs::MetadataExt;
            const REPARSE_POINT: u32 = 0x400;
            if meta.file_attributes() & REPARSE_POINT != 0 {
                return true;
            }
        }
    }
    false
}

/// Encrypts the files in a row into the data file and hashes each piece.
fn encrypt_into(data_path: &Path, sources: &[PathBuf], content_key: &[u8], piece_size: i32, total: i64) -> Result<Vec<[u8; 32]>> {
    let count = BundleHeader::pieces_for(total, piece_size) as usize;
    let mut hashes: Vec<[u8; 32]> = Vec::with_capacity(count);

    let mut key = keys::stream_key(content_key);
    let mut iv = keys::stream_iv(content_key);

    let result = (|| -> Result<Vec<[u8; 32]>> {
        let mut cipher = CtrStream::new(&key, &iv);
        let mut output = fs::File::create(data_path)?;

        let piece_size = piece_size as usize;
        let mut piece = vec![0u8; piece_size];
        let mut filled = 0usize;
        let mut written: i64 = 0;

        let flush = |piece: &mut [u8], length: usize, hashes: &mut Vec<[u8; 32]>, written: &mut i64, output: &mut fs::File, cipher: &mut CtrStream| -> Result<()> {
            if hashes.len() >= count {
                return Err(SwarmError::Io(std::io::Error::new(ErrorKind::Other, "a file grew while the bundle was being made")));
            }
            cipher.xor_in_place(&mut piece[..length]);
            let mut hash = [0u8; 32];
            hash.copy_from_slice(&Sha256::digest(&piece[..length]));
            hashes.push(hash);
            output.write_all(&piece[..length])?;
            *written += length as i64;
            Ok(())
        };

        for source in sources {
            let mut input = fs::File::open(source)?;
            loop {
                let got = input.read(&mut piece[filled..piece_size])?;
                if got == 0 {
                    break;
                }
                filled += got;
                if filled == piece_size {
                    flush(&mut piece, filled, &mut hashes, &mut written, &mut output, &mut cipher)?;
                    filled = 0;
                }
            }
        }

        if filled > 0 {
            flush(&mut piece, filled, &mut hashes, &mut written, &mut output, &mut cipher)?;
        }

        // A file that changed while it was read would leave the list and the
        // contents disagreeing — better no bundle.
        if written != total || hashes.len() != count {
            return Err(SwarmError::Io(std::io::Error::new(ErrorKind::Other, "a file changed while the bundle was being made")));
        }

        rand::wipe(&mut piece);
        Ok(hashes)
    })();

    rand::wipe(&mut key);
    rand::wipe(&mut iv);
    result
}

fn read_exactly(data: Option<&mut fs::File>, buffer: &mut [u8]) -> Result<()> {
    let file = data.ok_or_else(|| SwarmError::Io(std::io::Error::new(ErrorKind::Other, "the bundle's data ends early")))?;
    let mut read = 0usize;
    while read < buffer.len() {
        let got = file.read(&mut buffer[read..])?;
        if got == 0 {
            return Err(SwarmError::Io(std::io::Error::new(ErrorKind::Other, "the bundle's data ends early")));
        }
        read += got;
    }
    Ok(())
}

// ---- Path helpers ----------------------------------------------------------

fn file_name(path: &Path) -> String {
    path.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default()
}

/// The path of `file` relative to `root`, parts joined by `/`.
fn relative_slash(root: &Path, file: &Path) -> String {
    let rel = file.strip_prefix(root).unwrap_or(file);
    rel.components()
        .filter_map(|c| match c {
            Component::Normal(s) => Some(s.to_string_lossy().into_owned()),
            _ => None,
        })
        .collect::<Vec<_>>()
        .join("/")
}

/// Absolute path with `.` and `..` resolved lexically (no disk access), so a
/// not-yet-existing target can still be bounds-checked, like `Path.GetFullPath`.
fn absolute_lexical(path: &Path) -> PathBuf {
    let base = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir().map(|cwd| cwd.join(path)).unwrap_or_else(|_| path.to_path_buf())
    };

    let mut out = PathBuf::new();
    for component in base.components() {
        match component {
            Component::ParentDir => {
                out.pop();
            }
            Component::CurDir => {}
            other => out.push(other.as_os_str()),
        }
    }
    out
}

fn with_trailing_sep(path: &Path) -> String {
    let mut s = path.to_string_lossy().into_owned();
    if !s.ends_with(std::path::MAIN_SEPARATOR) {
        s.push(std::path::MAIN_SEPARATOR);
    }
    s
}

fn starts_with_ignore_case(path: &Path, prefix: &str) -> bool {
    // `get` rather than slicing: a cut inside a multi-byte letter (Cyrillic
    // paths) means "not inside", never a panic.
    let p = path.to_string_lossy();
    p.get(..prefix.len()).is_some_and(|head| head.eq_ignore_ascii_case(prefix))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_dir(name: &str) -> PathBuf {
        let mut p = std::env::temp_dir();
        p.push(format!("stalknet_build_{}_{}", std::process::id(), name));
        let _ = fs::remove_dir_all(&p);
        p
    }

    #[test]
    fn build_then_extract_a_folder() {
        let base = temp_dir("roundtrip");
        let src = base.join("src");
        let store_dir = base.join("store");
        let out = base.join("out");
        fs::create_dir_all(src.join("sub")).unwrap();
        fs::write(src.join("a.txt"), b"hello alpha").unwrap();
        fs::write(src.join("sub").join("b.bin"), vec![7u8; 100_000]).unwrap();

        let store = SwarmStore::new(&store_dir).unwrap();
        let link = build(&store, &src, BundleKind::Files).unwrap();

        let bundle = store.open(link.info_hash()).unwrap();
        assert!(bundle.is_complete());

        let manifest = extract(&bundle, link.content_key(), &out).unwrap();
        assert_eq!(manifest.kind, BundleKind::Files);

        // Folder kind keeps the folder's own name as the path prefix.
        let a = fs::read(out.join("src").join("a.txt")).unwrap();
        assert_eq!(a, b"hello alpha");
        let b = fs::read(out.join("src").join("sub").join("b.bin")).unwrap();
        assert_eq!(b, vec![7u8; 100_000]);

        let _ = fs::remove_dir_all(&base);
    }

    #[test]
    fn a_single_file_round_trips() {
        let base = temp_dir("singlefile");
        let file = base.join("note.txt");
        let store_dir = base.join("store");
        let out = base.join("out");
        fs::create_dir_all(&base).unwrap();
        fs::write(&file, b"a short note").unwrap();

        let store = SwarmStore::new(&store_dir).unwrap();
        let link = build(&store, &file, BundleKind::Files).unwrap();
        let bundle = store.open(link.info_hash()).unwrap();

        extract(&bundle, link.content_key(), &out).unwrap();
        assert_eq!(fs::read(out.join("note.txt")).unwrap(), b"a short note");
        let _ = fs::remove_dir_all(&base);
    }

    #[test]
    fn a_site_strips_the_root_name() {
        let base = temp_dir("site");
        let src = base.join("mysite");
        let store_dir = base.join("store");
        let out = base.join("out");
        fs::create_dir_all(&src).unwrap();
        fs::write(src.join("index.html"), b"<h1>hi</h1>").unwrap();

        let store = SwarmStore::new(&store_dir).unwrap();
        let link = build(&store, &src, BundleKind::Site).unwrap();
        let bundle = store.open(link.info_hash()).unwrap();
        let manifest = extract(&bundle, link.content_key(), &out).unwrap();

        assert_eq!(manifest.kind, BundleKind::Site);
        // Site paths start at the root: index.html lands directly in `out`.
        assert_eq!(fs::read(out.join("index.html")).unwrap(), b"<h1>hi</h1>");
        let _ = fs::remove_dir_all(&base);
    }

    #[test]
    fn a_wrong_key_does_not_open() {
        let base = temp_dir("wrongkey");
        let file = base.join("f.txt");
        let store_dir = base.join("store");
        fs::create_dir_all(&base).unwrap();
        fs::write(&file, b"secret").unwrap();

        let store = SwarmStore::new(&store_dir).unwrap();
        let link = build(&store, &file, BundleKind::Files).unwrap();
        let bundle = store.open(link.info_hash()).unwrap();

        let wrong = vec![0u8; BundleLink::KEY_SIZE];
        assert!(extract(&bundle, &wrong, base.join("out")).is_err());
        let _ = fs::remove_dir_all(&base);
    }
}
