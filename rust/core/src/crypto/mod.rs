//! Cryptography (`StalkNet.Core/Crypto`).
//!
//! The C# original implements every primitive by hand because .NET Framework
//! 4.8 ships none of BLAKE2b, HKDF or Argon2id. The Rust rewrite uses the
//! reviewed RustCrypto crates instead; every one is RFC-compliant, so the
//! bytes on the wire are identical.

pub mod aead_aes_ctr_hmac;
pub mod argon2id;
pub mod blake2b;
pub mod chaining_mac;
pub mod ctr_stream;
pub mod ecc_p256;
pub mod hkdf;
pub mod rand;
