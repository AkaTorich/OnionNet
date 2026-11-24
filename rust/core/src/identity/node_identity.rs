//! A participant's identity: the signing key (who they are) and the onion key
//! (how to agree on a cipher with them).
//!
//! The folders have an identity of their own, in a file beside this one (see
//! [`folder_key_path`]). Two keys with nothing in common cannot be matched up,
//! so holding a folder address does not reveal the node's IP.
//!
//! On disk the file lies sealed under Argon2id: without the passphrase it is
//! useless, and guessing costs 64 MiB of memory per attempt. The file format is
//! identical to the C# `NodeIdentity`, so the two read each other's files.

use crate::crypto::ecc_p256::{AgreementKey, SigningKey};
use crate::crypto::{aead_aes_ctr_hmac as aead, argon2id, rand};
use crate::identity::onion_address::OnionAddress;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

const MAGIC_LENGTH: usize = 4;
const FORMAT_VERSION: u8 = 1;
const SALT_SIZE: usize = 16;
const SEAL_KEY_SIZE: usize = aead::KEY_SIZE; // 64
const PRIVATE_KEY_SIZE: usize = 96;

const MAGIC: &[u8; MAGIC_LENGTH] = b"ONID";
const PROTECTED_MAGIC: &[u8; MAGIC_LENGTH] = b"ONIW";
const PROTECTED_ENTROPY: &[u8] = b"stalknet-identity-windows-v1";

/// Ticks between 0001-01-01 and 1970-01-01, i.e. the .NET epoch offset in
/// 100-nanosecond intervals. Identity files store `DateTime.Ticks`, so the
/// Rust port converts to and from this representation to keep them compatible.
const TICKS_AT_UNIX_EPOCH: i64 = 621_355_968_000_000_000;

/// Upper bounds for unsealing — a forged header must not make the node allocate
/// gigabytes before the first check.
const MAX_MEMORY_KIB: u32 = 2 * 1024 * 1024; // 2 GiB
const MAX_ITERATIONS: u32 = 64;
const MAX_PARALLELISM: u32 = 64;

/// Why an identity operation failed.
#[derive(Debug)]
pub enum IdentityError {
    Io(std::io::Error),
    Format(String),
    /// Wrong passphrase, or the file is damaged / not ours.
    Crypto(String),
    /// Sealing by the Windows account exists only on Windows.
    Platform,
}

impl std::fmt::Display for IdentityError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            IdentityError::Io(e) => write!(f, "{e}"),
            IdentityError::Format(m) => write!(f, "{m}"),
            IdentityError::Crypto(m) => write!(f, "{m}"),
            IdentityError::Platform => write!(f, "sealing by the Windows account exists only on Windows"),
        }
    }
}
impl std::error::Error for IdentityError {}
impl From<std::io::Error> for IdentityError {
    fn from(e: std::io::Error) -> Self {
        IdentityError::Io(e)
    }
}

type Result<T> = std::result::Result<T, IdentityError>;

/// The Argon2id parameters the identity file is sealed with. They are kept in
/// the file header so an old file still opens after the settings change.
#[derive(Clone, Copy, Debug)]
pub struct KeySealParameters {
    pub memory_kib: u32,
    pub iterations: u32,
    pub parallelism: u32,
}

impl Default for KeySealParameters {
    /// 64 MiB and three passes.
    fn default() -> Self {
        KeySealParameters {
            memory_kib: 64 * 1024,
            iterations: 3,
            parallelism: 4,
        }
    }
}

impl KeySealParameters {
    /// A lighter set for tests and weak machines.
    pub fn light() -> Self {
        KeySealParameters {
            memory_kib: 8 * 1024,
            iterations: 2,
            parallelism: 2,
        }
    }

    fn validate(&self) -> Result<()> {
        if self.parallelism < 1 || self.parallelism > MAX_PARALLELISM {
            return Err(IdentityError::Crypto(format!(
                "invalid lane count in the identity file header: {}",
                self.parallelism
            )));
        }
        if self.iterations < 1 || self.iterations > MAX_ITERATIONS {
            return Err(IdentityError::Crypto(format!(
                "invalid pass count in the identity file header: {}",
                self.iterations
            )));
        }
        if self.memory_kib < 8 * self.parallelism || self.memory_kib > MAX_MEMORY_KIB {
            return Err(IdentityError::Crypto(format!(
                "invalid memory size in the identity file header: {} KiB",
                self.memory_kib
            )));
        }
        Ok(())
    }
}

#[derive(Clone)]
pub struct NodeIdentity {
    signing: SigningKey,
    onion: AgreementKey,
    nickname: String,
    created_ticks: i64,
    address: OnionAddress,
    public_signing_key: [u8; 64],
    public_onion_key: [u8; 64],
}

impl NodeIdentity {
    fn assemble(signing: SigningKey, onion: AgreementKey, nickname: String, created_ticks: i64) -> NodeIdentity {
        let public_signing_key = signing.export_public();
        let public_onion_key = onion.export_public();
        let address = OnionAddress::from_public_key(&public_signing_key)
            .expect("an exported P-256 key is always 64 bytes");
        NodeIdentity {
            signing,
            onion,
            nickname,
            created_ticks,
            address,
            public_signing_key,
            public_onion_key,
        }
    }

    pub fn nickname(&self) -> &str {
        &self.nickname
    }
    pub fn created_ticks(&self) -> i64 {
        self.created_ticks
    }
    pub fn address(&self) -> &OnionAddress {
        &self.address
    }
    pub fn public_signing_key(&self) -> &[u8; 64] {
        &self.public_signing_key
    }
    pub fn public_onion_key(&self) -> &[u8; 64] {
        &self.public_onion_key
    }
    pub fn fingerprint(&self) -> [u8; 20] {
        self.address.fingerprint()
    }

    /// The relay's long-term agreement key, for answering ntor handshakes.
    pub fn onion_key(&self) -> &AgreementKey {
        &self.onion
    }

    /// Signs arbitrary data with the identity's key.
    pub fn sign(&self, data: &[u8]) -> [u8; 64] {
        self.signing.sign(data)
    }

    /// Computes the shared secret with someone else's onion key.
    pub fn agree(&self, peer_onion_key: &[u8]) -> Option<[u8; 32]> {
        self.onion.agree(peer_onion_key).ok()
    }

    pub fn create(nickname: &str) -> Result<NodeIdentity> {
        if nickname.len() > 255 {
            return Err(IdentityError::Format(
                "a node name is no longer than 255 bytes in UTF-8".into(),
            ));
        }
        Ok(NodeIdentity::assemble(
            SigningKey::generate(),
            AgreementKey::generate(),
            nickname.to_string(),
            now_ticks(),
        ))
    }

    // ---- The folders' own key ----------------------------------------------

    /// Where the folders' key lies: beside the identity file, same name with
    /// `.folder` — `node.id` gives `node.folder`.
    pub fn folder_key_path(identity_path: &Path) -> PathBuf {
        let mut path = identity_path.to_path_buf();
        path.set_extension("folder");
        path
    }

    /// A new folder key for a new identity, sealed with the same passphrase. A
    /// file left by an earlier identity is written over.
    pub fn create_folder_key(identity_path: &Path, passphrase: &str) -> Result<NodeIdentity> {
        let key = NodeIdentity::create("")?;
        key.save(&NodeIdentity::folder_key_path(identity_path), passphrase)?;
        Ok(key)
    }

    /// Opens the folders' key; an identity made before there was one gets it
    /// now. A key that will not open is an error rather than a reason to make
    /// another — a new key is a new address.
    pub fn open_folder_key(identity_path: &Path, passphrase: &str) -> Result<NodeIdentity> {
        let path = NodeIdentity::folder_key_path(identity_path);
        if path.exists() {
            return NodeIdentity::load(&path, passphrase);
        }
        let key = NodeIdentity::create("")?;
        key.save(&path, passphrase)?;
        Ok(key)
    }

    // ---- Sealed by the Windows account, no passphrase ----------------------

    /// Whether the file is sealed by the Windows account — and opens with no
    /// passphrase.
    pub fn is_protected_file(path: &Path) -> bool {
        match fs::read(path) {
            Ok(bytes) => bytes.len() >= MAGIC_LENGTH && &bytes[..MAGIC_LENGTH] == PROTECTED_MAGIC,
            Err(_) => false,
        }
    }

    pub fn save_protected(&self, path: &Path) -> Result<()> {
        let plaintext = self.build_plaintext();
        let sealed = dpapi::protect(&plaintext, PROTECTED_ENTROPY)?;
        let mut file = Vec::with_capacity(MAGIC_LENGTH + 1 + sealed.len());
        file.extend_from_slice(PROTECTED_MAGIC);
        file.push(FORMAT_VERSION);
        file.extend_from_slice(&sealed);
        fs::write(path, &file)?;
        Ok(())
    }

    pub fn load_protected(path: &Path) -> Result<NodeIdentity> {
        let file = fs::read(path)?;
        if file.len() < MAGIC_LENGTH + 2 {
            return Err(IdentityError::Crypto("the identity file is damaged: it is too short".into()));
        }
        if &file[..MAGIC_LENGTH] != PROTECTED_MAGIC {
            return Err(IdentityError::Crypto("this file is not sealed by the Windows account".into()));
        }
        if file[MAGIC_LENGTH] != FORMAT_VERSION {
            return Err(IdentityError::Crypto(format!(
                "unknown identity file version: {}",
                file[MAGIC_LENGTH]
            )));
        }
        let plaintext = dpapi::unprotect(&file[MAGIC_LENGTH + 1..], PROTECTED_ENTROPY)?;
        NodeIdentity::parse_plaintext(&plaintext)
    }

    pub fn create_folder_key_protected(identity_path: &Path) -> Result<NodeIdentity> {
        let key = NodeIdentity::create("")?;
        key.save_protected(&NodeIdentity::folder_key_path(identity_path))?;
        Ok(key)
    }

    pub fn open_folder_key_protected(identity_path: &Path) -> Result<NodeIdentity> {
        let path = NodeIdentity::folder_key_path(identity_path);
        if path.exists() {
            return NodeIdentity::load_protected(&path);
        }
        let key = NodeIdentity::create("")?;
        key.save_protected(&path)?;
        Ok(key)
    }

    // ---- Writing to disk ---------------------------------------------------

    pub fn save(&self, path: &Path, passphrase: &str) -> Result<()> {
        self.save_with_params(path, passphrase, KeySealParameters::default())
    }

    pub fn save_with_params(&self, path: &Path, passphrase: &str, parameters: KeySealParameters) -> Result<()> {
        parameters.validate()?;

        let salt = rand::get_bytes(SALT_SIZE);
        let header = build_header(&parameters, &salt);
        let plaintext = self.build_plaintext();

        // The header goes in as associated data: swapping the Argon2
        // parameters for weaker ones breaks the tag rather than opening the
        // file more cheaply.
        let seal_key = derive_seal_key(passphrase, &salt, &parameters)?;
        let sealed = aead::seal(&seal_key, &plaintext, &header);

        let mut file = Vec::with_capacity(header.len() + sealed.len());
        file.extend_from_slice(&header);
        file.extend_from_slice(&sealed);
        fs::write(path, &file)?;
        Ok(())
    }

    pub fn load(path: &Path, passphrase: &str) -> Result<NodeIdentity> {
        let file = fs::read(path)?;

        let header_length = MAGIC_LENGTH + 1 + 4 + 4 + 1 + SALT_SIZE; // 30
        if file.len() < header_length + aead::OVERHEAD {
            return Err(IdentityError::Crypto("the identity file is damaged: it is too short".into()));
        }
        if &file[..MAGIC_LENGTH] != MAGIC {
            return Err(IdentityError::Crypto("this is not a StalkNet identity file".into()));
        }
        if file[MAGIC_LENGTH] != FORMAT_VERSION {
            return Err(IdentityError::Crypto(format!(
                "unknown identity file version: {}",
                file[MAGIC_LENGTH]
            )));
        }

        let parameters = KeySealParameters {
            memory_kib: read_le32(&file, MAGIC_LENGTH + 1),
            iterations: read_le32(&file, MAGIC_LENGTH + 5),
            parallelism: file[MAGIC_LENGTH + 9] as u32,
        };
        // Read before the passphrase is checked, so a forged header is bounded.
        parameters.validate()?;

        let salt = &file[MAGIC_LENGTH + 10..MAGIC_LENGTH + 10 + SALT_SIZE];
        let header = &file[..header_length];
        let sealed = &file[header_length..];

        let seal_key = derive_seal_key(passphrase, salt, &parameters)?;
        match aead::open(&seal_key, sealed, header) {
            Some(plaintext) => NodeIdentity::parse_plaintext(&plaintext),
            None => Err(IdentityError::Crypto(
                "wrong passphrase, or the identity file is damaged".into(),
            )),
        }
    }

    // ---- Parsing and assembling the body -----------------------------------

    fn build_plaintext(&self) -> Vec<u8> {
        let signing_private = self.signing.export_private();
        let onion_private = self.onion.export_private();
        let nickname = self.nickname.as_bytes();

        let mut plaintext = Vec::with_capacity(PRIVATE_KEY_SIZE * 2 + 8 + 1 + nickname.len());
        plaintext.extend_from_slice(&signing_private);
        plaintext.extend_from_slice(&onion_private);
        plaintext.extend_from_slice(&self.created_ticks.to_le_bytes());
        plaintext.push(nickname.len() as u8);
        plaintext.extend_from_slice(nickname);
        plaintext
    }

    fn parse_plaintext(plaintext: &[u8]) -> Result<NodeIdentity> {
        if plaintext.len() < PRIVATE_KEY_SIZE * 2 + 9 {
            return Err(IdentityError::Crypto("the identity file body is damaged".into()));
        }

        let signing_private = &plaintext[..PRIVATE_KEY_SIZE];
        let onion_private = &plaintext[PRIVATE_KEY_SIZE..PRIVATE_KEY_SIZE * 2];
        let mut position = PRIVATE_KEY_SIZE * 2;

        let mut ticks_bytes = [0u8; 8];
        ticks_bytes.copy_from_slice(&plaintext[position..position + 8]);
        let created_ticks = i64::from_le_bytes(ticks_bytes);
        position += 8;

        let nickname_length = plaintext[position] as usize;
        position += 1;
        if position + nickname_length > plaintext.len() {
            return Err(IdentityError::Crypto("the identity file body is damaged".into()));
        }
        let nickname = String::from_utf8_lossy(&plaintext[position..position + nickname_length]).into_owned();

        let signing = SigningKey::import_private(signing_private)
            .map_err(|e| IdentityError::Crypto(e.to_string()))?;
        let onion = AgreementKey::import_private(onion_private)
            .map_err(|e| IdentityError::Crypto(e.to_string()))?;

        Ok(NodeIdentity::assemble(signing, onion, nickname, created_ticks))
    }
}

fn build_header(parameters: &KeySealParameters, salt: &[u8]) -> Vec<u8> {
    let mut header = Vec::with_capacity(MAGIC_LENGTH + 1 + 4 + 4 + 1 + SALT_SIZE);
    header.extend_from_slice(MAGIC);
    header.push(FORMAT_VERSION);
    header.extend_from_slice(&parameters.memory_kib.to_le_bytes());
    header.extend_from_slice(&parameters.iterations.to_le_bytes());
    header.push(parameters.parallelism as u8);
    header.extend_from_slice(salt);
    header
}

fn derive_seal_key(passphrase: &str, salt: &[u8], parameters: &KeySealParameters) -> Result<Vec<u8>> {
    argon2id::derive_key(
        passphrase.as_bytes(),
        salt,
        parameters.parallelism,
        parameters.memory_kib,
        parameters.iterations,
        SEAL_KEY_SIZE,
        None,
        None,
    )
    .map_err(|e| IdentityError::Crypto(e.to_string()))
}

fn read_le32(data: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes([data[offset], data[offset + 1], data[offset + 2], data[offset + 3]])
}

fn now_ticks() -> i64 {
    match SystemTime::now().duration_since(UNIX_EPOCH) {
        Ok(d) => TICKS_AT_UNIX_EPOCH + d.as_secs() as i64 * 10_000_000 + (d.subsec_nanos() / 100) as i64,
        Err(_) => TICKS_AT_UNIX_EPOCH,
    }
}

// ---- DPAPI (Windows only) --------------------------------------------------

#[cfg(windows)]
mod dpapi {
    use super::{IdentityError, Result};
    use windows_sys::Win32::Foundation::LocalFree;
    use windows_sys::Win32::Security::Cryptography::{
        CryptProtectData, CryptUnprotectData, CRYPTPROTECT_UI_FORBIDDEN, CRYPT_INTEGER_BLOB,
    };

    fn blob(data: &[u8]) -> CRYPT_INTEGER_BLOB {
        CRYPT_INTEGER_BLOB {
            cbData: data.len() as u32,
            pbData: data.as_ptr() as *mut u8,
        }
    }

    unsafe fn take(out: CRYPT_INTEGER_BLOB) -> Vec<u8> {
        let slice = std::slice::from_raw_parts(out.pbData, out.cbData as usize);
        let owned = slice.to_vec();
        LocalFree(out.pbData as _);
        owned
    }

    pub fn protect(plaintext: &[u8], entropy: &[u8]) -> Result<Vec<u8>> {
        unsafe {
            let in_blob = blob(plaintext);
            let ent_blob = blob(entropy);
            let mut out = CRYPT_INTEGER_BLOB { cbData: 0, pbData: std::ptr::null_mut() };
            let ok = CryptProtectData(
                &in_blob,
                std::ptr::null(),
                &ent_blob,
                std::ptr::null(),
                std::ptr::null(),
                CRYPTPROTECT_UI_FORBIDDEN,
                &mut out,
            );
            if ok == 0 {
                return Err(IdentityError::Crypto("CryptProtectData failed".into()));
            }
            Ok(take(out))
        }
    }

    pub fn unprotect(sealed: &[u8], entropy: &[u8]) -> Result<Vec<u8>> {
        unsafe {
            let in_blob = blob(sealed);
            let ent_blob = blob(entropy);
            let mut out = CRYPT_INTEGER_BLOB { cbData: 0, pbData: std::ptr::null_mut() };
            // Another Windows user or another machine fails here — which is the point.
            let ok = CryptUnprotectData(
                &in_blob,
                std::ptr::null_mut(),
                &ent_blob,
                std::ptr::null(),
                std::ptr::null(),
                CRYPTPROTECT_UI_FORBIDDEN,
                &mut out,
            );
            if ok == 0 {
                return Err(IdentityError::Crypto(
                    "this identity belongs to another Windows account".into(),
                ));
            }
            Ok(take(out))
        }
    }
}

#[cfg(not(windows))]
mod dpapi {
    use super::{IdentityError, Result};
    pub fn protect(_plaintext: &[u8], _entropy: &[u8]) -> Result<Vec<u8>> {
        Err(IdentityError::Platform)
    }
    pub fn unprotect(_sealed: &[u8], _entropy: &[u8]) -> Result<Vec<u8>> {
        Err(IdentityError::Platform)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_path(name: &str) -> PathBuf {
        let mut p = std::env::temp_dir();
        p.push(format!("stalknet_test_{}_{}", std::process::id(), name));
        p
    }

    #[test]
    fn passphrase_round_trip() {
        let id = NodeIdentity::create("tester").unwrap();
        let path = temp_path("id.id");
        id.save_with_params(&path, "correct horse", KeySealParameters::light()).unwrap();

        let loaded = NodeIdentity::load(&path, "correct horse").unwrap();
        assert_eq!(id.public_signing_key(), loaded.public_signing_key());
        assert_eq!(id.public_onion_key(), loaded.public_onion_key());
        assert_eq!(id.nickname(), loaded.nickname());
        assert_eq!(id.address().text(), loaded.address().text());

        // The signing key survives: a signature made now verifies under the
        // reloaded public key.
        let sig = loaded.sign(b"payload");
        assert!(crate::crypto::ecc_p256::SigningKey::verify(id.public_signing_key(), b"payload", &sig));

        let _ = fs::remove_file(&path);
    }

    #[test]
    fn wrong_passphrase_is_rejected() {
        let id = NodeIdentity::create("x").unwrap();
        let path = temp_path("id2.id");
        id.save_with_params(&path, "right", KeySealParameters::light()).unwrap();
        assert!(NodeIdentity::load(&path, "wrong").is_err());
        let _ = fs::remove_file(&path);
    }

    #[test]
    fn folder_key_path_swaps_extension() {
        let p = NodeIdentity::folder_key_path(Path::new("C:/x/node.id"));
        assert!(p.to_string_lossy().ends_with("node.folder"));
    }
}
