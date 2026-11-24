//! AEAD out of plain primitives: AES-256 in CTR mode plus HMAC-SHA256, in the
//! encrypt-then-MAC arrangement. CTR is chosen so there is no padding at all —
//! a CBC-plus-MAC design would give a padding oracle.
//!
//! The sealed message format: `nonce(12) || ciphertext || tag(16)`.

use crate::crypto::rand;
use aes::cipher::{generic_array::GenericArray, BlockEncrypt, KeyInit};
use aes::Aes256;
use hmac::{Hmac, Mac};
use sha2::Sha256;
use zeroize::Zeroize;

type HmacSha256 = Hmac<Sha256>;

pub const KEY_SIZE: usize = 64; // 32 bytes for the cipher + 32 for the MAC
pub const NONCE_SIZE: usize = 12;
pub const TAG_SIZE: usize = 16;
pub const OVERHEAD: usize = NONCE_SIZE + TAG_SIZE;

/// A fresh 64-byte key.
pub fn generate_key() -> Vec<u8> {
    rand::get_bytes(KEY_SIZE)
}

/// Seals `plaintext` with a fresh random nonce.
pub fn seal(key: &[u8], plaintext: &[u8], associated_data: &[u8]) -> Vec<u8> {
    let nonce = rand::get_bytes(NONCE_SIZE);
    seal_with_nonce(key, &nonce, plaintext, associated_data)
}

/// Seals `plaintext` with a caller-supplied 12-byte nonce.
pub fn seal_with_nonce(key: &[u8], nonce: &[u8], plaintext: &[u8], associated_data: &[u8]) -> Vec<u8> {
    validate_key(key);
    assert_eq!(nonce.len(), NONCE_SIZE, "the nonce must be {NONCE_SIZE} bytes");

    let mut result = vec![0u8; NONCE_SIZE + plaintext.len() + TAG_SIZE];
    result[..NONCE_SIZE].copy_from_slice(nonce);
    result[NONCE_SIZE..NONCE_SIZE + plaintext.len()].copy_from_slice(plaintext);

    ctr_xor(key, 0, nonce, &mut result[NONCE_SIZE..NONCE_SIZE + plaintext.len()]);

    let tag = compute_tag(key, nonce, &result[NONCE_SIZE..NONCE_SIZE + plaintext.len()], associated_data);
    result[NONCE_SIZE + plaintext.len()..].copy_from_slice(&tag);

    result
}

/// Unwraps a message. Returns `None` if the tag does not check out — an error
/// path here would be a leak channel while handling someone else's traffic.
pub fn open(key: &[u8], sealed_message: &[u8], associated_data: &[u8]) -> Option<Vec<u8>> {
    validate_key(key);
    if sealed_message.len() < OVERHEAD {
        return None;
    }

    let cipher_length = sealed_message.len() - OVERHEAD;
    let nonce = &sealed_message[..NONCE_SIZE];
    let ciphertext = &sealed_message[NONCE_SIZE..NONCE_SIZE + cipher_length];
    let actual = &sealed_message[NONCE_SIZE + cipher_length..];

    let expected = compute_tag(key, nonce, ciphertext, associated_data);
    if !rand::constant_time_equals(&expected, actual) {
        return None;
    }

    let mut plaintext = ciphertext.to_vec();
    ctr_xor(key, 0, nonce, &mut plaintext);
    Some(plaintext)
}

fn validate_key(key: &[u8]) {
    assert_eq!(key.len(), KEY_SIZE, "the key must be {KEY_SIZE} bytes");
}

fn compute_tag(key: &[u8], nonce: &[u8], ciphertext: &[u8], associated_data: &[u8]) -> [u8; TAG_SIZE] {
    // `KeyInit` (from `aes::cipher`) and `Mac` both expose `new_from_slice`
    // here, so the HMAC construction is disambiguated explicitly.
    let mut mac = <HmacSha256 as Mac>::new_from_slice(&key[32..64]).expect("HMAC accepts any key length");
    mac.update(nonce);
    mac.update(associated_data);
    mac.update(ciphertext);

    // Lengths at the tail: without them "AAD||text" would split ambiguously.
    let mut lengths = [0u8; 16];
    lengths[..8].copy_from_slice(&(associated_data.len() as u64).to_le_bytes());
    lengths[8..].copy_from_slice(&(ciphertext.len() as u64).to_le_bytes());
    mac.update(&lengths);

    let full = mac.finalize().into_bytes();
    let mut tag = [0u8; TAG_SIZE];
    tag.copy_from_slice(&full[..TAG_SIZE]);
    tag
}

/// The AES-CTR keystream. The counter block: `nonce(12) || big-endian
/// counter(4)`, numbered from `block_offset` — so the stream can be continued
/// from any point.
fn ctr_xor(key: &[u8], block_offset: u32, nonce: &[u8], buffer: &mut [u8]) {
    let mut enc_key = [0u8; 32];
    enc_key.copy_from_slice(&key[..32]);
    let cipher = Aes256::new(GenericArray::from_slice(&enc_key));

    let mut counter_block = [0u8; 16];
    counter_block[..NONCE_SIZE].copy_from_slice(nonce);

    let mut produced = 0usize;
    let mut counter = block_offset;
    let length = buffer.len();

    while produced < length {
        counter_block[12] = (counter >> 24) as u8;
        counter_block[13] = (counter >> 16) as u8;
        counter_block[14] = (counter >> 8) as u8;
        counter_block[15] = counter as u8;

        let mut block = GenericArray::clone_from_slice(&counter_block);
        cipher.encrypt_block(&mut block);

        let take = 16.min(length - produced);
        for i in 0..take {
            buffer[produced + i] ^= block[i];
        }

        produced += take;
        counter = counter.wrapping_add(1);
    }

    enc_key.zeroize();
    counter_block.zeroize();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn seal_open_round_trip() {
        let key = generate_key();
        let msg = b"hidden service payload";
        let aad = b"context";
        let sealed = seal(&key, msg, aad);
        assert_eq!(sealed.len(), msg.len() + OVERHEAD);
        assert_eq!(open(&key, &sealed, aad).as_deref(), Some(&msg[..]));
    }

    #[test]
    fn wrong_aad_or_tamper_fails() {
        let key = generate_key();
        let sealed = seal(&key, b"payload", b"aad");
        assert!(open(&key, &sealed, b"other").is_none());

        let mut tampered = sealed.clone();
        tampered[NONCE_SIZE] ^= 1;
        assert!(open(&key, &tampered, b"aad").is_none());
    }

    #[test]
    fn empty_plaintext() {
        let key = generate_key();
        let sealed = seal(&key, b"", b"");
        assert_eq!(open(&key, &sealed, b"").as_deref(), Some(&b""[..]));
    }
}
