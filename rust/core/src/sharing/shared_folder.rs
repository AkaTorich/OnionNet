//! A folder published to the network, and a file inside it as the network sees
//! it (the C# `SharedFolder` and `SharedFile`).

use crate::text::{t, t_args};
use std::path::{Path, PathBuf};

/// Who may look into the folder over the network.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum ShareAccess {
    /// Sign-in with an account. The guest gives a name and a password, the node
    /// signs in under them and reads the folder on the guest's behalf — the
    /// permissions are checked by the operating system itself rather than by our
    /// code. The default mode.
    WindowsAccounts = 0,

    /// To anyone who knows the address. No password, read only.
    Public = 1,
}

impl ShareAccess {
    pub fn from_u8(value: u8) -> Option<ShareAccess> {
        match value {
            0 => Some(ShareAccess::WindowsAccounts),
            1 => Some(ShareAccess::Public),
            _ => None,
        }
    }
}

/// Where the folder was learned about.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ShareOrigin {
    /// From the OS shares — the very "Give access to".
    Windows,
    /// Added by hand inside StalkNet itself.
    Manual,
}

/// A folder published to the network.
///
/// Only the alias and the contents leave the machine. The full path on disk never
/// does: `D:\Work\Contracts` by itself tells more about the owner than all the
/// rest of the traffic.
#[derive(Debug, Clone)]
pub struct SharedFolder {
    path: PathBuf,
    alias: String,
    access: ShareAccess,
    origin: ShareOrigin,
    windows_share_name: Option<String>,
}

impl SharedFolder {
    /// Builds a folder. An empty path is rejected. The path is made absolute (by
    /// text, without following links — as the C# `Path.GetFullPath`).
    pub fn new(path: &str, alias: &str, access: ShareAccess, origin: ShareOrigin) -> Result<SharedFolder, &'static str> {
        if path.is_empty() {
            return Err("an empty path");
        }

        let full = absolutize(Path::new(path));
        let alias = if alias.is_empty() { default_alias(&full) } else { alias.to_string() };

        Ok(SharedFolder {
            path: full,
            alias,
            access,
            origin,
            windows_share_name: None,
        })
    }

    /// The path on disk. For local use only — it never leaves the machine.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// The name the folder is seen under on the network. Only it leaves the
    /// machine.
    pub fn alias(&self) -> &str {
        &self.alias
    }

    pub fn set_alias(&mut self, alias: String) {
        self.alias = alias;
    }

    pub fn access(&self) -> ShareAccess {
        self.access
    }

    pub fn set_access(&mut self, access: ShareAccess) {
        self.access = access;
    }

    pub fn origin(&self) -> ShareOrigin {
        self.origin
    }

    /// The name of the OS share, if the folder came from there.
    pub fn windows_share_name(&self) -> Option<&str> {
        self.windows_share_name.as_deref()
    }

    pub fn set_windows_share_name(&mut self, name: Option<String>) {
        self.windows_share_name = name;
    }

    pub fn exists(&self) -> bool {
        self.path.is_dir()
    }
}

impl std::fmt::Display for SharedFolder {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let access = t(match self.access {
            ShareAccess::Public => "folder.access.public",
            ShareAccess::WindowsAccounts => "folder.access.account",
        });
        write!(f, "{}", t_args("folder.summary", &[&self.alias, &access]))
    }
}

/// The folder's default network name: its last path component.
fn default_alias(path: &Path) -> String {
    match path.file_name().and_then(|n| n.to_str()) {
        Some(name) if !name.is_empty() => name.to_string(),
        _ => path.to_string_lossy().into_owned(),
    }
}

/// Makes a path absolute by text only. Unlike `std::fs::canonicalize`, it never
/// touches the filesystem and never follows a symbolic link, matching the C#
/// `Path.GetFullPath` the catalogue relies on for its safety check.
pub(crate) fn absolutize(path: &Path) -> PathBuf {
    if path.is_absolute() {
        normalize(path)
    } else {
        match std::env::current_dir() {
            Ok(cwd) => normalize(&cwd.join(path)),
            Err(_) => normalize(path),
        }
    }
}

/// Resolves `.` and `..` lexically, without touching the filesystem.
fn normalize(path: &Path) -> PathBuf {
    use std::path::Component;
    let mut out = PathBuf::new();
    for component in path.components() {
        match component {
            Component::ParentDir => {
                if !out.pop() {
                    out.push("..");
                }
            }
            Component::CurDir => {}
            other => out.push(other.as_os_str()),
        }
    }
    out
}

/// A file inside a published folder — as the network sees it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SharedFile {
    name: String,
    size: i64,
    /// The last-write time in .NET ticks (100-ns intervals since 0001-01-01).
    modified_ticks: i64,
    is_directory: bool,
}

impl SharedFile {
    pub fn new(name: String, size: i64, modified_ticks: i64, is_directory: bool) -> SharedFile {
        SharedFile {
            name,
            size,
            modified_ticks,
            is_directory,
        }
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn size(&self) -> i64 {
        self.size
    }

    pub fn modified_ticks(&self) -> i64 {
        self.modified_ticks
    }

    pub fn is_directory(&self) -> bool {
        self.is_directory
    }
}

impl std::fmt::Display for SharedFile {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.is_directory {
            write!(f, "[{}]", self.name)
        } else {
            write!(f, "{}", t_args("file.size", &[&self.name, &self.size.to_string()]))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_alias_is_the_last_component() {
        let folder = SharedFolder::new("/tmp/work/contracts", "", ShareAccess::Public, ShareOrigin::Manual).unwrap();
        assert_eq!(folder.alias(), "contracts");
    }

    #[test]
    fn explicit_alias_wins() {
        let folder = SharedFolder::new("/tmp/work", "Papers", ShareAccess::WindowsAccounts, ShareOrigin::Manual).unwrap();
        assert_eq!(folder.alias(), "Papers");
        assert_eq!(folder.access(), ShareAccess::WindowsAccounts);
    }

    #[test]
    fn empty_path_is_rejected() {
        assert!(SharedFolder::new("", "x", ShareAccess::Public, ShareOrigin::Manual).is_err());
    }

    #[test]
    fn normalize_strips_dot_segments() {
        let p = normalize(Path::new("/a/b/../c/./d"));
        assert_eq!(p, PathBuf::from("/a/c/d"));
    }
}
