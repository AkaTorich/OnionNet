//! HKDF-SHA256 (RFC 5869).
//!
//! Spreads the single shared handshake secret into a set of keys: the forward
//! cipher key, the backward cipher key, two MAC keys. Implemented with `hmac`
//! and `sha2` so it matches the C# `Hkdf` (which uses `HMACSHA256`) exactly.

use hmac::{Hmac, Mac};
use sha2::Sha256;

type HmacSha256 = Hmac<Sha256>;

const HASH_LENGTH: usize = 32;

/// HKDF-Extract: PRK = HMAC-SHA256(salt, IKM). An empty salt becomes 32 zero
/// bytes, as in RFC 5869.
pub fn extract(salt: &[u8], input_key_material: &[u8]) -> Vec<u8> {
    let zero = [0u8; HASH_LENGTH];
    let salt = if salt.is_empty() { &zero[..] } else { salt };

    let mut mac = HmacSha256::new_from_slice(salt).expect("HMAC accepts any key length");
    mac.update(input_key_material);
    mac.finalize().into_bytes().to_vec()
}

/// HKDF-Expand to `output_length` bytes (at most 255 * 32).
pub fn expand(pseudo_random_key: &[u8], info: &[u8], output_length: usize) -> Vec<u8> {
    assert!(
        output_length <= 255 * HASH_LENGTH,
        "HKDF output is at most 255 blocks"
    );

    let mut output = vec![0u8; output_length];
    let mut previous: Vec<u8> = Vec::new();
    let mut position = 0usize;
    let mut counter: u8 = 1;

    while position < output_length {
        let mut mac =
            HmacSha256::new_from_slice(pseudo_random_key).expect("HMAC accepts any key length");
        mac.update(&previous);
        mac.update(info);
        mac.update(&[counter]);
        previous = mac.finalize().into_bytes().to_vec();

        let take = HASH_LENGTH.min(output_length - position);
        output[position..position + take].copy_from_slice(&previous[..take]);
        position += take;
        counter = counter.wrapping_add(1);
    }

    output
}

/// Extract and Expand in one call.
pub fn derive(salt: &[u8], input_key_material: &[u8], info: &[u8], output_length: usize) -> Vec<u8> {
    let prk = extract(salt, input_key_material);
    expand(&prk, info, output_length)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rfc5869_case1() {
        // RFC 5869 appendix A.1.
        let ikm = [0x0bu8; 22];
        let salt: Vec<u8> = (0x00u8..=0x0c).collect();
        let info: Vec<u8> = (0xf0u8..=0xf9).collect();

        let prk = extract(&salt, &ikm);
        let prk_hex: String = prk.iter().map(|b| format!("{:02x}", b)).collect();
        assert_eq!(
            prk_hex,
            "077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5"
        );

        let okm = expand(&prk, &info, 42);
        let okm_hex: String = okm.iter().map(|b| format!("{:02x}", b)).collect();
        assert_eq!(
            okm_hex,
            "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf\
             34007208d5b887185865"
        );
    }
}
