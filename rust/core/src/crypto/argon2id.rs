//! Argon2id (RFC 9106) — a memory-hard key derivation function.
//!
//! In the StalkNet network it has two roles:
//!   1. the node's long-term key is derived from the passphrase, so no secret
//!      lies on disk at all;
//!   2. registering a relay takes a memory-hard proof of work — faking a
//!      thousand nodes becomes expensive in memory rather than in time alone.
//!      This is the defence against a Sybil attack that real Tor does not have.
//!
//! The C# original hand-rolls the full RFC construction (.NET 4.8 has none).
//! Here it wraps the `argon2` crate, which is the same RFC 9106 Argon2id with
//! version 0x13, so the derived key matches the C# node byte for byte.

use argon2::{Algorithm, Argon2, AssociatedData, ParamsBuilder, Version};

/// Why a derivation failed. Mirrors the C# argument checks.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Argon2Error {
    SaltTooShort,
    BadParameter(&'static str),
    Internal(String),
}

impl std::fmt::Display for Argon2Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Argon2Error::SaltTooShort => write!(f, "the salt must be at least 8 bytes"),
            Argon2Error::BadParameter(p) => write!(f, "bad Argon2 parameter: {p}"),
            Argon2Error::Internal(e) => write!(f, "argon2: {e}"),
        }
    }
}

impl std::error::Error for Argon2Error {}

/// Derives a key of `output_length` bytes.
///
/// * `parallelism` — the number of lanes, `>= 1`.
/// * `memory_kib` — memory in kibibytes, `>= 8 * parallelism`.
/// * `iterations` — the number of passes, `>= 1`.
/// * `output_length` — the key length in bytes, `>= 4`.
/// * `secret` — an optional pepper (keyed hashing).
/// * `associated_data` — optional associated data.
#[allow(clippy::too_many_arguments)]
pub fn derive_key(
    password: &[u8],
    salt: &[u8],
    parallelism: u32,
    memory_kib: u32,
    iterations: u32,
    output_length: usize,
    secret: Option<&[u8]>,
    associated_data: Option<&[u8]>,
) -> Result<Vec<u8>, Argon2Error> {
    if salt.len() < 8 {
        return Err(Argon2Error::SaltTooShort);
    }
    if parallelism < 1 {
        return Err(Argon2Error::BadParameter("parallelism"));
    }
    if iterations < 1 {
        return Err(Argon2Error::BadParameter("iterations"));
    }
    if output_length < 4 {
        return Err(Argon2Error::BadParameter("output_length"));
    }
    if memory_kib < 8 * parallelism {
        return Err(Argon2Error::BadParameter("memory_kib"));
    }

    let mut builder = ParamsBuilder::new();
    builder
        .m_cost(memory_kib)
        .t_cost(iterations)
        .p_cost(parallelism)
        .output_len(output_length);
    if let Some(ad) = associated_data {
        if !ad.is_empty() {
            let ad = AssociatedData::try_from(ad).map_err(|e| Argon2Error::Internal(e.to_string()))?;
            builder.data(ad);
        }
    }
    let params = builder
        .build()
        .map_err(|e| Argon2Error::Internal(e.to_string()))?;

    let secret = secret.unwrap_or(&[]);
    let argon2 = Argon2::new_with_secret(secret, Algorithm::Argon2id, Version::V0x13, params)
        .map_err(|e| Argon2Error::Internal(e.to_string()))?;

    let mut out = vec![0u8; output_length];
    argon2
        .hash_password_into(password, salt, &mut out)
        .map_err(|e| Argon2Error::Internal(e.to_string()))?;
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rfc9106_test_vector() {
        // RFC 9106 section 5.3 Argon2id test vector:
        // password = 32 * 0x01, salt = 16 * 0x02, secret = 8 * 0x03,
        // ad = 12 * 0x04, p = 4, m = 32, t = 3, taglen = 32.
        let password = [0x01u8; 32];
        let salt = [0x02u8; 16];
        let secret = [0x03u8; 8];
        let ad = [0x04u8; 12];

        let tag = derive_key(&password, &salt, 4, 32, 3, 32, Some(&secret), Some(&ad)).unwrap();
        let hex: String = tag.iter().map(|b| format!("{:02x}", b)).collect();
        assert_eq!(
            hex,
            "0d640df58d78766c08c037a34a8b53c9d01ef0452d75b65eb52520e96b01e659"
        );
    }
}
