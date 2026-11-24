//! The list of a bundle's files.
//!
//! It travels only inside the cipher: the names of files say about their owner
//! no less than the files themselves, and whoever hands the pieces out must not
//! read either. The contents are the files' bytes one after another in this
//! very order.
//!
//! A list that came from somebody else is checked hard while parsing. Its paths
//! become paths on our disk, and a path with `..` or a drive in it would write
//! a file wherever the stranger pleased.

use crate::swarm::{Result, SwarmError};

const FORMAT_VERSION: u8 = 1;

pub const MAX_FILES: usize = 100_000;
pub const MAX_PATH_BYTES: usize = 1024;
pub const MAX_NAME_BYTES: usize = 255;

/// What a bundle is.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum BundleKind {
    /// A file or a folder handed from one participant to another.
    Files = 0,
    /// A site: a folder of pages served by whoever opens its address.
    Site = 1,
}

impl BundleKind {
    pub fn from_u8(b: u8) -> Option<BundleKind> {
        match b {
            0 => Some(BundleKind::Files),
            1 => Some(BundleKind::Site),
            _ => None,
        }
    }
}

/// One file inside a bundle.
#[derive(Clone, Debug)]
pub struct BundleFile {
    /// The path inside the bundle, parts joined by `/`.
    pub path: String,
    pub length: i64,
}

impl BundleFile {
    pub fn new(path: impl Into<String>, length: i64) -> BundleFile {
        BundleFile {
            path: path.into(),
            length,
        }
    }
}

/// The list of a bundle's files.
#[derive(Clone, Debug)]
pub struct BundleManifest {
    pub kind: BundleKind,
    /// The bundle's name as it was shared: the file or the folder.
    pub name: String,
    pub files: Vec<BundleFile>,
}

impl BundleManifest {
    pub fn new(kind: BundleKind, name: impl Into<String>) -> BundleManifest {
        BundleManifest {
            kind,
            name: name.into(),
            files: Vec::new(),
        }
    }

    pub fn total_length(&self) -> i64 {
        let mut total: i64 = 0;
        for file in &self.files {
            total = total.wrapping_add(file.length);
        }
        total
    }

    /// Serialises the list. The layout:
    /// `version(1) | kind(1) | name | files count(4 LE) | (path | length(8 LE))*`,
    /// where a text field is `length(2 LE) || UTF-8 bytes`.
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        let mut out = Vec::new();
        out.push(FORMAT_VERSION);
        out.push(self.kind as u8);
        write_text(&mut out, &self.name, MAX_NAME_BYTES)?;
        out.extend_from_slice(&(self.files.len() as i32).to_le_bytes());

        for file in &self.files {
            write_text(&mut out, &file.path, MAX_PATH_BYTES)?;
            out.extend_from_slice(&file.length.to_le_bytes());
        }

        Ok(out)
    }

    /// Parses a list. Anything doubtful is a format error, not a file in a wrong
    /// place.
    pub fn parse(data: &[u8]) -> Result<BundleManifest> {
        let mut reader = Reader::new(data);

        if reader.u8()? != FORMAT_VERSION {
            return Err(fmt("an unknown file list version"));
        }

        let kind = BundleKind::from_u8(reader.u8()?).ok_or_else(|| fmt("an unknown bundle kind"))?;
        let name = read_text(&mut reader, MAX_NAME_BYTES)?;

        let mut manifest = BundleManifest::new(kind, name);

        let count = reader.i32()?;
        if count < 0 || count as usize > MAX_FILES {
            return Err(fmt("an impossible number of files"));
        }

        // OrdinalIgnoreCase in the C#; ASCII-lowercasing matches it for paths.
        let mut seen: std::collections::HashSet<String> = std::collections::HashSet::new();
        let mut total: i64 = 0;

        for _ in 0..count {
            let path = read_text(&mut reader, MAX_PATH_BYTES)?;
            let length = reader.i64()?;

            if !is_safe_path(&path) {
                return Err(fmt("a file path that leads out of the folder"));
            }
            if length < 0 {
                return Err(fmt("a negative file length"));
            }
            if !seen.insert(path.to_ascii_lowercase()) {
                return Err(fmt("the same file twice"));
            }

            total = total.checked_add(length).ok_or_else(|| fmt("the total length overflows"))?;
            if total < 0 {
                return Err(fmt("the total length overflows"));
            }

            manifest.files.push(BundleFile::new(path, length));
        }

        if !reader.at_end() {
            return Err(fmt("extra bytes after the file list"));
        }

        Ok(manifest)
    }
}

/// A path that stays inside the folder: relative, parts joined by `/`, no empty
/// parts, no `.` or `..`, nothing Windows forbids in a name, no reserved device
/// names.
pub fn is_safe_path(path: &str) -> bool {
    if path.is_empty() {
        return false;
    }
    if path.contains('\\') {
        return false;
    }

    for part in path.split('/') {
        if part.is_empty() || part == "." || part == ".." {
            return false;
        }
        if part.chars().any(is_invalid_name_char) {
            return false;
        }
        if part.contains(':') {
            return false;
        }

        // Windows strips dots and spaces at the end of a name, and "a." would
        // quietly become "a" — another file than meant.
        let last = part.chars().last().unwrap();
        if last == '.' || last == ' ' {
            return false;
        }

        if is_device_name(part) {
            return false;
        }
    }

    true
}

/// The characters Windows forbids in a file name: the control range and a fixed
/// set of punctuation, matching `Path.GetInvalidFileNameChars`.
fn is_invalid_name_char(c: char) -> bool {
    (c as u32) < 0x20 || matches!(c, '"' | '<' | '>' | '|' | ':' | '*' | '?' | '\\' | '/')
}

fn is_device_name(part: &str) -> bool {
    let stem = match part.find('.') {
        Some(dot) => &part[..dot],
        None => part,
    };

    matches!(
        stem.to_ascii_uppercase().as_str(),
        "CON" | "PRN" | "AUX" | "NUL"
            | "COM1" | "COM2" | "COM3" | "COM4" | "COM5"
            | "COM6" | "COM7" | "COM8" | "COM9"
            | "LPT1" | "LPT2" | "LPT3" | "LPT4" | "LPT5"
            | "LPT6" | "LPT7" | "LPT8" | "LPT9"
    )
}

fn write_text(out: &mut Vec<u8>, value: &str, max_bytes: usize) -> Result<()> {
    let bytes = value.as_bytes();
    if bytes.len() > max_bytes {
        return Err(SwarmError::Invalid(format!("a name is longer than {max_bytes} bytes")));
    }
    out.extend_from_slice(&(bytes.len() as u16).to_le_bytes());
    out.extend_from_slice(bytes);
    Ok(())
}

fn read_text(reader: &mut Reader, max_bytes: usize) -> Result<String> {
    let length = reader.u16()? as usize;
    if length > max_bytes {
        return Err(fmt("a name is too long"));
    }
    let bytes = reader.take(length)?;
    // C# Encoding.UTF8.GetString replaces bad sequences rather than failing.
    Ok(String::from_utf8_lossy(bytes).into_owned())
}

fn fmt(message: &str) -> SwarmError {
    SwarmError::Format(message.to_string())
}

/// A little-endian cursor over a byte slice, failing like `EndOfStreamException`.
pub(crate) struct Reader<'a> {
    data: &'a [u8],
    position: usize,
}

impl<'a> Reader<'a> {
    pub(crate) fn new(data: &'a [u8]) -> Reader<'a> {
        Reader { data, position: 0 }
    }

    pub(crate) fn at_end(&self) -> bool {
        self.position == self.data.len()
    }

    pub(crate) fn take(&mut self, count: usize) -> Result<&'a [u8]> {
        if self.position + count > self.data.len() {
            return Err(fmt("the data is cut short"));
        }
        let slice = &self.data[self.position..self.position + count];
        self.position += count;
        Ok(slice)
    }

    pub(crate) fn u8(&mut self) -> Result<u8> {
        Ok(self.take(1)?[0])
    }

    pub(crate) fn u16(&mut self) -> Result<u16> {
        let b = self.take(2)?;
        Ok(u16::from_le_bytes([b[0], b[1]]))
    }

    pub(crate) fn i32(&mut self) -> Result<i32> {
        let b = self.take(4)?;
        Ok(i32::from_le_bytes([b[0], b[1], b[2], b[3]]))
    }

    pub(crate) fn i64(&mut self) -> Result<i64> {
        let b = self.take(8)?;
        Ok(i64::from_le_bytes([b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]]))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn serialization_round_trip() {
        let mut m = BundleManifest::new(BundleKind::Files, "photos");
        m.files.push(BundleFile::new("photos/a.jpg", 10));
        m.files.push(BundleFile::new("photos/sub/b.png", 20));

        let bytes = m.to_bytes().unwrap();
        let parsed = BundleManifest::parse(&bytes).unwrap();

        assert_eq!(parsed.kind, BundleKind::Files);
        assert_eq!(parsed.name, "photos");
        assert_eq!(parsed.files.len(), 2);
        assert_eq!(parsed.files[0].path, "photos/a.jpg");
        assert_eq!(parsed.files[0].length, 10);
        assert_eq!(parsed.files[1].path, "photos/sub/b.png");
        assert_eq!(parsed.total_length(), 30);
    }

    #[test]
    fn rejects_unsafe_paths() {
        assert!(!is_safe_path("../secret"));
        assert!(!is_safe_path("a/../b"));
        assert!(!is_safe_path("C:/x"));
        assert!(!is_safe_path("a\\b"));
        assert!(!is_safe_path("con"));
        assert!(!is_safe_path("nul.txt"));
        assert!(!is_safe_path("trailing."));
        assert!(!is_safe_path("space "));
        assert!(!is_safe_path(""));
        assert!(!is_safe_path("a//b"));

        assert!(is_safe_path("photos/a.jpg"));
        assert!(is_safe_path("index.html"));
        assert!(is_safe_path("deep/path/file.txt"));
    }

    #[test]
    fn parse_rejects_unsafe_and_duplicate() {
        let mut m = BundleManifest::new(BundleKind::Files, "x");
        m.files.push(BundleFile::new("a", 1));
        m.files.push(BundleFile::new("A", 1)); // duplicate under OrdinalIgnoreCase
        let bytes = m.to_bytes().unwrap();
        assert!(BundleManifest::parse(&bytes).is_err());
    }

    #[test]
    fn parse_rejects_trailing_bytes() {
        let m = BundleManifest::new(BundleKind::Site, "s");
        let mut bytes = m.to_bytes().unwrap();
        bytes.push(0);
        assert!(BundleManifest::parse(&bytes).is_err());
    }
}
