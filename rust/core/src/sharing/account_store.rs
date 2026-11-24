//! The guests' accounts for the folders "by account", kept beside the identity
//! ("node.id" gives "node.accounts").
//!
//! One line per account: the name, the salt and the Argon2id hash of the
//! password, hex, separated by tabs. The password itself is never written.
//! Written aside and moved into place whole, so a crash leaves the old file.

use super::account_authenticator::{StoredPassword, PASSWORD_HASH_SIZE, PASSWORD_SALT_SIZE};
use std::path::{Path, PathBuf};

/// The accounts file beside an identity file.
pub fn path_for(identity_path: &Path) -> PathBuf {
    let mut p = identity_path.to_path_buf();
    p.set_extension("accounts");
    p
}

/// The kept accounts. A missing file is no accounts; a damaged line is skipped.
pub fn load(path: &Path) -> Vec<(String, StoredPassword)> {
    let text = match std::fs::read_to_string(path) {
        Ok(t) => t,
        Err(_) => return Vec::new(),
    };
    let mut out = Vec::new();
    for line in text.lines() {
        let mut parts = line.split('\t');
        let (name, salt, hash) = match (parts.next(), parts.next(), parts.next()) {
            (Some(n), Some(s), Some(h)) => (n, s, h),
            _ => continue,
        };
        let (salt, hash) = match (from_hex(salt), from_hex(hash)) {
            (Some(s), Some(h)) if s.len() == PASSWORD_SALT_SIZE && h.len() == PASSWORD_HASH_SIZE => (s, h),
            _ => continue,
        };
        if valid_name(name) {
            out.push((name.to_string(), StoredPassword { salt, hash }));
        }
    }
    out
}

/// Keeps the accounts.
pub fn save(path: &Path, accounts: &[(String, StoredPassword)]) -> std::io::Result<()> {
    let mut text = String::new();
    for (name, stored) in accounts {
        text.push_str(name);
        text.push('\t');
        text.push_str(&to_hex(&stored.salt));
        text.push('\t');
        text.push_str(&to_hex(&stored.hash));
        text.push('\n');
    }
    let mut part = path.as_os_str().to_owned();
    part.push(".part");
    std::fs::write(&part, text)?;
    std::fs::rename(&part, path)
}

/// A name the folder protocol can carry and the file can hold: 1–64 bytes,
/// no tabs, line breaks or other control characters.
pub fn valid_name(name: &str) -> bool {
    !name.trim().is_empty() && name.len() <= 64 && !name.chars().any(|c| c.is_control())
}

fn to_hex(data: &[u8]) -> String {
    data.iter().map(|b| format!("{b:02x}")).collect()
}

fn from_hex(text: &str) -> Option<Vec<u8>> {
    if text.len() % 2 != 0 || !text.is_ascii() {
        return None;
    }
    (0..text.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&text[i..i + 2], 16).ok())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kept_accounts_come_back_and_still_check() {
        let path = std::env::temp_dir().join(format!("stalknet-accounts-{}.accounts", std::process::id()));
        let alice = StoredPassword::new("open sesame");
        save(&path, &[("alice".to_string(), alice.clone())]).unwrap();

        let text = std::fs::read_to_string(&path).unwrap();
        assert!(!text.contains("open sesame"), "the password must not be written");

        let back = load(&path);
        assert_eq!(back, vec![("alice".to_string(), alice)]);
        assert!(back[0].1.matches("open sesame"));
        assert!(!back[0].1.matches("open barley"));
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn names_with_breaks_are_refused() {
        assert!(valid_name("guest"));
        assert!(!valid_name(""));
        assert!(!valid_name("a\tb"));
        assert!(!valid_name("a\nb"));
    }
}
