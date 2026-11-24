//! The list of published folders and the serving of their contents (the C#
//! `ShareCatalog`). Cross-platform via `std::fs`.
//!
//! Two rules kept here at any price:
//!
//! 1. Reading goes on behalf of the guest who signed in (where the platform
//!    supports it — see [`AuthenticatedSession`]) rather than the node's owner.
//! 2. Only file names leave the machine. The full path does not.
//!
//! The hidden/system/dot-file filtering is reproduced on every platform:
//! dotfiles everywhere, and on Windows also the Hidden and System attributes.

use super::account_authenticator::AuthenticatedSession;
use super::shared_folder::{self, SharedFile, SharedFolder, ShareAccess, ShareOrigin};
use super::windows_share_reader;
use crate::text::t_args;
use crate::util::time::TICKS_AT_UNIX_EPOCH;
use std::collections::{HashMap, HashSet};
use std::io;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, UNIX_EPOCH};

/// Why access was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ShareResult {
    Ok,
    /// There is no such folder in the list.
    NoSuchFolder,
    /// The folder requires a sign-in, and no session was presented.
    LoginRequired,
    /// The OS refused: this account has no rights.
    Denied,
    /// The file name is invalid — an attempt to step outside the folder.
    BadName,
    /// The file or the folder disappeared from disk.
    Missing,
    /// Windows would not let us impersonate the guest.
    Impersonation,
}

/// The windows-shares list is re-read no more often than this (the C#
/// `SharesMaxAge`).
const SHARES_MAX_AGE: Duration = Duration::from_secs(15);

type Logger = Arc<dyn Fn(String) + Send + Sync>;

struct SharesCache {
    folders: Vec<SharedFolder>,
    read_at: Option<Instant>,
}

/// The catalogue of published folders.
pub struct ShareCatalog {
    manual: Mutex<HashMap<String, SharedFolder>>,
    follow_windows_shares: Mutex<bool>,
    logged: Mutex<Option<Logger>>,
    shares: Mutex<SharesCache>,
}

impl Default for ShareCatalog {
    fn default() -> Self {
        Self::new()
    }
}

impl ShareCatalog {
    pub fn new() -> ShareCatalog {
        ShareCatalog {
            manual: Mutex::new(HashMap::new()),
            follow_windows_shares: Mutex::new(true),
            logged: Mutex::new(None),
            shares: Mutex::new(SharesCache {
                folders: Vec::new(),
                read_at: None,
            }),
        }
    }

    /// Whether to take the list from the OS shares. On a system that has none the
    /// flag simply changes nothing: the catalogue then holds only what was added
    /// by hand.
    pub fn set_follow_windows_shares(&self, follow: bool) {
        *self.follow_windows_shares.lock().unwrap() = follow;
    }

    pub fn follows_windows_shares(&self) -> bool {
        *self.follow_windows_shares.lock().unwrap()
    }

    /// What to tell the node's owner. It never leaves the machine — only their own
    /// log, on their own machine.
    pub fn set_logged(&self, logger: Option<Logger>) {
        *self.logged.lock().unwrap() = logger;
    }

    /// Adds a folder besides those opened in the OS.
    pub fn add(&self, path: &str, alias: &str, access: ShareAccess) -> Result<(), &'static str> {
        let folder = SharedFolder::new(path, alias, access, ShareOrigin::Manual)?;
        self.manual.lock().unwrap().insert(folder.alias().to_string(), folder);
        Ok(())
    }

    pub fn remove(&self, alias: &str) {
        self.manual.lock().unwrap().remove(alias);
    }

    /// The current list: first the manual additions, then what is open in the OS.
    /// When the aliases coincide the manual entry wins — it is the one whose name
    /// and access mode the owner edited. Entries whose folder no longer exists are
    /// dropped.
    pub fn folders(&self) -> Vec<SharedFolder> {
        let mut result: Vec<SharedFolder> = Vec::new();
        let mut seen: HashSet<String> = HashSet::new();

        for folder in self.manual.lock().unwrap().values() {
            result.push(folder.clone());
            seen.insert(folder.alias().to_lowercase());
        }

        if self.follows_windows_shares() {
            for folder in self.windows_shares() {
                if seen.contains(&folder.alias().to_lowercase()) {
                    continue;
                }
                seen.insert(folder.alias().to_lowercase());
                result.push(folder);
            }
        }

        result.retain(|f| f.exists());
        result
    }

    fn windows_shares(&self) -> Vec<SharedFolder> {
        let mut cache = self.shares.lock().unwrap();
        let stale = match cache.read_at {
            None => true,
            Some(at) => at.elapsed() > SHARES_MAX_AGE,
        };
        if stale {
            cache.folders = windows_share_reader::enumerate();
            cache.read_at = Some(Instant::now());
        }
        cache.folders.clone()
    }

    pub fn find(&self, alias: &str) -> Option<SharedFolder> {
        if alias.is_empty() {
            return None;
        }
        self.folders()
            .into_iter()
            .find(|f| f.alias().eq_ignore_ascii_case(alias))
    }

    // ---- Serving the contents ------------------------------------------------

    /// Lists a folder's contents on the guest's behalf. For folders in
    /// `WindowsAccounts` mode a session is required.
    pub fn list(&self, alias: &str, session: Option<&AuthenticatedSession>) -> Result<Vec<SharedFile>, ShareResult> {
        let folder = self.find(alias).ok_or(ShareResult::NoSuchFolder)?;

        if folder.access() == ShareAccess::WindowsAccounts && session.is_none() {
            return Err(ShareResult::LoginRequired);
        }

        let path = folder.path().to_path_buf();
        let what = t_args("share.reading", &[folder.alias()]);
        self.run_as(session, &what, move || read_entries(&path))
    }

    /// Opens a file for reading on the guest's behalf. The handle is obtained under
    /// the guest's rights, and that is what gets checked.
    pub fn open_read(
        &self,
        alias: &str,
        file_name: &str,
        session: Option<&AuthenticatedSession>,
    ) -> Result<(std::fs::File, u64), ShareResult> {
        let folder = self.find(alias).ok_or(ShareResult::NoSuchFolder)?;

        if folder.access() == ShareAccess::WindowsAccounts && session.is_none() {
            return Err(ShareResult::LoginRequired);
        }

        let full = try_resolve(folder.path(), file_name).ok_or(ShareResult::BadName)?;
        let what = t_args("share.fetching", &[folder.alias()]);

        self.run_as(session, &what, move || {
            // What the list keeps out of sight must not be had by name either, or
            // the hiding was for show. The answer is the same as for an absent
            // file, so a refusal does not confirm that the file is there.
            let meta = std::fs::metadata(&full)?;
            let name = full.file_name().and_then(|n| n.to_str()).unwrap_or("");
            if is_hidden(name, attributes_of(&meta)) {
                return Err(io::Error::new(io::ErrorKind::NotFound, "hidden"));
            }
            let len = meta.len();
            let file = std::fs::File::open(&full)?;
            Ok((file, len))
        })
    }

    /// Performs the read under the right permissions and translates OS refusals
    /// into our codes. No error text is let out: it sometimes holds the full path,
    /// and that must not leave the machine.
    fn run_as<T>(
        &self,
        session: Option<&AuthenticatedSession>,
        what: &str,
        body: impl FnOnce() -> io::Result<T>,
    ) -> Result<T, ShareResult> {
        let outcome = match session {
            Some(s) => s.run(body),
            None => body(),
        };
        outcome.map_err(|e| self.blame(session, what, &e))
    }

    /// The guest gets one bare refusal code; the owner's log gets the reason.
    fn blame(&self, session: Option<&AuthenticatedSession>, what: &str, error: &io::Error) -> ShareResult {
        let result = classify(error);

        let who = match session {
            None => crate::text::t("share.who.owner"),
            Some(s) => t_args("share.who.named", &[s.user_name()]),
        };

        let message = if result == ShareResult::Impersonation {
            t_args("share.impersonation", &[what])
        } else {
            let kind = format!("{:?}", error.kind());
            let detail = error.to_string();
            t_args("share.failed", &[what, &who, &kind, &detail])
        };
        self.say(message);
        result
    }

    fn say(&self, message: String) {
        if let Some(handler) = self.logged.lock().unwrap().clone() {
            handler(message);
        }
    }
}

/// Reads a folder's entries, skipping the hidden ones. Directories first, then
/// files, as the C# `ReadEntries`.
fn read_entries(path: &Path) -> io::Result<Vec<SharedFile>> {
    let mut dirs: Vec<SharedFile> = Vec::new();
    let mut files: Vec<SharedFile> = Vec::new();

    for entry in std::fs::read_dir(path)? {
        let entry = entry?;
        let meta = match entry.metadata() {
            Ok(m) => m,
            Err(_) => continue,
        };
        let name = match entry.file_name().into_string() {
            Ok(n) => n,
            Err(_) => continue,
        };
        if is_hidden(&name, attributes_of(&meta)) {
            continue;
        }

        let ticks = ticks_of(&meta);
        if meta.is_dir() {
            dirs.push(SharedFile::new(name, 0, ticks, true));
        } else {
            files.push(SharedFile::new(name, meta.len() as i64, ticks, false));
        }
    }

    dirs.extend(files);
    Ok(dirs)
}

/// Hidden and system entries are not shown: the owner hid them for a reason.
/// Windows says it with an attribute, Unix with a leading dot — both are asked
/// about, on both systems.
fn is_hidden(name: &str, attributes: u32) -> bool {
    const FILE_ATTRIBUTE_HIDDEN: u32 = 0x2;
    const FILE_ATTRIBUTE_SYSTEM: u32 = 0x4;
    if attributes & (FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM) != 0 {
        return true;
    }
    name.starts_with('.')
}

/// The Windows file attributes of an entry; zero on other platforms (where only
/// the dotfile rule applies).
#[cfg(windows)]
fn attributes_of(meta: &std::fs::Metadata) -> u32 {
    use std::os::windows::fs::MetadataExt;
    meta.file_attributes()
}

#[cfg(not(windows))]
fn attributes_of(_meta: &std::fs::Metadata) -> u32 {
    0
}

/// The last-write time of an entry in .NET ticks.
fn ticks_of(meta: &std::fs::Metadata) -> i64 {
    meta.modified()
        .ok()
        .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
        .map(|d| TICKS_AT_UNIX_EPOCH + d.as_secs() as i64 * 10_000_000 + (d.subsec_nanos() / 100) as i64)
        .unwrap_or(TICKS_AT_UNIX_EPOCH)
}

/// Maps an I/O error to a refusal code (the C# `RunAs` catch arms).
fn classify(error: &io::Error) -> ShareResult {
    match error.kind() {
        io::ErrorKind::PermissionDenied => ShareResult::Denied,
        io::ErrorKind::NotFound => ShareResult::Missing,
        _ => {
            // 1346 — ERROR_BAD_IMPERSONATION_LEVEL. It has nothing to do with
            // files, yet it arrives as a read error.
            if error.raw_os_error() == Some(1346) {
                ShareResult::Impersonation
            } else {
                ShareResult::Missing
            }
        }
    }
}

/// Turns the name sent in into a path inside the folder — or refuses.
///
/// Only a bare name is let through: no separators, no drive, no parent step. The
/// resolution is lexical (no symlink following), matching the C# `Path.GetFullPath`
/// the check relies on, so the resulting path cannot climb out of the folder.
fn try_resolve(root: &Path, file_name: &str) -> Option<PathBuf> {
    if file_name.is_empty() {
        return None;
    }
    if file_name == "." || file_name == ".." {
        return None;
    }
    // Invalid / separator characters (a superset of the C# InvalidFileNameChars
    // relevant to escaping the folder).
    if file_name.chars().any(|c| matches!(c, '/' | '\\' | '\0' | ':' | '*' | '?' | '"' | '<' | '>' | '|') || (c as u32) < 0x20) {
        return None;
    }
    // Must be a pure file name — no path components.
    if Path::new(file_name).file_name().and_then(|n| n.to_str()) != Some(file_name) {
        return None;
    }

    let prefix = shared_folder::absolutize(root);
    let candidate = shared_folder::absolutize(&prefix.join(file_name));

    // Defence in depth: the candidate must sit strictly below the root.
    if !candidate.starts_with(&prefix) || candidate == prefix {
        return None;
    }
    Some(candidate)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn temp_dir(tag: &str) -> PathBuf {
        let mut dir = std::env::temp_dir();
        dir.push(format!("stalknet_catalog_{}_{}", tag, std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn write_file(dir: &Path, name: &str, contents: &[u8]) {
        let mut f = std::fs::File::create(dir.join(name)).unwrap();
        f.write_all(contents).unwrap();
    }

    #[test]
    fn dotfiles_are_filtered_everywhere() {
        let dir = temp_dir("dot");
        write_file(&dir, "visible.txt", b"hi");
        write_file(&dir, ".secret", b"nope");
        std::fs::create_dir_all(dir.join(".git")).unwrap();
        std::fs::create_dir_all(dir.join("Public")).unwrap();

        let files = read_entries(&dir).unwrap();
        let names: Vec<&str> = files.iter().map(|f| f.name()).collect();
        assert!(names.contains(&"visible.txt"));
        assert!(names.contains(&"Public"));
        assert!(!names.iter().any(|n| n.starts_with('.')));

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn safe_path_rejects_escapes() {
        let root = Path::new("/srv/share");
        assert!(try_resolve(root, "file.txt").is_some());
        assert!(try_resolve(root, "..").is_none());
        assert!(try_resolve(root, "../secret").is_none());
        assert!(try_resolve(root, "sub/file").is_none());
        assert!(try_resolve(root, "sub\\file").is_none());
        assert!(try_resolve(root, "").is_none());
        assert!(try_resolve(root, "a:b").is_none());
    }

    #[test]
    fn public_folder_lists_without_a_session() {
        let dir = temp_dir("pub");
        write_file(&dir, "a.txt", b"aaa");
        let catalog = ShareCatalog::new();
        catalog.set_follow_windows_shares(false);
        catalog.add(dir.to_str().unwrap(), "Pub", ShareAccess::Public).unwrap();

        let files = catalog.list("Pub", None).unwrap();
        assert_eq!(files.len(), 1);
        assert_eq!(files[0].name(), "a.txt");
        assert_eq!(files[0].size(), 3);

        // An account folder needs a session.
        catalog.add(dir.to_str().unwrap(), "Acc", ShareAccess::WindowsAccounts).unwrap();
        assert_eq!(catalog.list("Acc", None), Err(ShareResult::LoginRequired));
        assert_eq!(catalog.list("Nope", None), Err(ShareResult::NoSuchFolder));

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn open_read_refuses_bad_names_and_hidden() {
        let dir = temp_dir("open");
        write_file(&dir, "ok.bin", b"data");
        write_file(&dir, ".hidden", b"x");
        let catalog = ShareCatalog::new();
        catalog.set_follow_windows_shares(false);
        catalog.add(dir.to_str().unwrap(), "P", ShareAccess::Public).unwrap();

        let (_, size) = catalog.open_read("P", "ok.bin", None).unwrap();
        assert_eq!(size, 4);

        // `File` is not `PartialEq`, so match on the error arm.
        assert!(matches!(catalog.open_read("P", "../x", None), Err(ShareResult::BadName)));
        assert!(matches!(catalog.open_read("P", ".hidden", None), Err(ShareResult::Missing)));
        assert!(matches!(catalog.open_read("P", "absent", None), Err(ShareResult::Missing)));

        let _ = std::fs::remove_dir_all(&dir);
    }
}
