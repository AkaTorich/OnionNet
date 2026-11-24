//! ECDSA and ECDH over NIST P-256.
//!
//! Keys travel in a "raw" form so that on the wire and in a card a key takes
//! exactly 64 bytes and does not depend on any platform: a public key is
//! `X || Y`, a private key is `X || Y || d`, each coordinate a 32-byte
//! big-endian field element. The C# original wraps these into Windows CNG
//! blobs; that packaging never leaves the machine, so the Rust rewrite drops it
//! and keeps only the raw form, which is what both nodes actually exchange.
//!
//! * [`SigningKey`] — a node's signing key (ECDSA P-256). It signs relay cards
//!   and hidden-service announcements. A signature is always 64 bytes: `r || s`.
//! * [`AgreementKey`] — an agreement key (ECDH P-256). A static instance is a
//!   relay's "onion key", an ephemeral one is the client's half of the
//!   handshake. The shared secret is `SHA-256` of the shared point's `x`
//!   coordinate: both sides compute the same 32 bytes.

use p256::ecdsa::signature::{Signer, Verifier};
use p256::ecdsa::{Signature, SigningKey as EcdsaSigningKey, VerifyingKey};
use p256::elliptic_curve::sec1::ToEncodedPoint;
use p256::{EncodedPoint, PublicKey, SecretKey};
use sha2::{Digest, Sha256};

pub const FIELD_SIZE: usize = 32;
pub const PUBLIC_KEY_SIZE: usize = 64; // X || Y
pub const PRIVATE_KEY_SIZE: usize = 96; // X || Y || d
pub const SIGNATURE_SIZE: usize = 64; // r || s
pub const SHARED_SECRET_SIZE: usize = 32;

/// Raw-key conversion or import failed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyError(pub &'static str);

impl std::fmt::Display for KeyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}
impl std::error::Error for KeyError {}

/// A fresh non-zero scalar from OS randomness (rejection, as the field order is
/// not a power of two).
fn random_secret_key() -> SecretKey {
    loop {
        let bytes = crate::crypto::rand::get_bytes(FIELD_SIZE);
        if let Ok(sk) = SecretKey::from_slice(&bytes) {
            return sk;
        }
    }
}

/// `0x04 || X || Y` from raw `X || Y`, the uncompressed SEC1 point.
fn public_from_raw(raw: &[u8]) -> Result<PublicKey, KeyError> {
    if raw.len() != PUBLIC_KEY_SIZE {
        return Err(KeyError("a P-256 public key must be 64 bytes"));
    }
    let mut sec1 = [0u8; 1 + PUBLIC_KEY_SIZE];
    sec1[0] = 0x04;
    sec1[1..].copy_from_slice(raw);
    let point = EncodedPoint::from_bytes(sec1).map_err(|_| KeyError("not a valid P-256 point"))?;
    Option::<PublicKey>::from(PublicKey::from_encoded_point(&point))
        .ok_or(KeyError("point is not on the curve"))
}

use p256::elliptic_curve::sec1::FromEncodedPoint;

/// Raw `X || Y` (no SEC1 tag) from a public key.
fn public_to_raw(public: &PublicKey) -> [u8; PUBLIC_KEY_SIZE] {
    let point = public.to_encoded_point(false);
    let mut raw = [0u8; PUBLIC_KEY_SIZE];
    raw.copy_from_slice(&point.as_bytes()[1..]); // drop the 0x04 tag
    raw
}

/// Raw `X || Y || d` from a secret key.
fn private_to_raw(secret: &SecretKey) -> [u8; PRIVATE_KEY_SIZE] {
    let mut raw = [0u8; PRIVATE_KEY_SIZE];
    raw[..PUBLIC_KEY_SIZE].copy_from_slice(&public_to_raw(&secret.public_key()));
    raw[PUBLIC_KEY_SIZE..].copy_from_slice(&secret.to_bytes());
    raw
}

/// A node's signing key (ECDSA P-256).
#[derive(Clone)]
pub struct SigningKey {
    inner: EcdsaSigningKey,
}

impl SigningKey {
    pub fn generate() -> Self {
        let sk = random_secret_key();
        SigningKey {
            inner: EcdsaSigningKey::from(sk),
        }
    }

    /// Imports a 96-byte raw private key (`X || Y || d`); only `d` is used.
    pub fn import_private(raw: &[u8]) -> Result<Self, KeyError> {
        if raw.len() != PRIVATE_KEY_SIZE {
            return Err(KeyError("a private key must be 96 bytes"));
        }
        let inner = EcdsaSigningKey::from_slice(&raw[PUBLIC_KEY_SIZE..])
            .map_err(|_| KeyError("invalid P-256 scalar"))?;
        Ok(SigningKey { inner })
    }

    pub fn export_public(&self) -> [u8; PUBLIC_KEY_SIZE] {
        let vk = VerifyingKey::from(&self.inner);
        public_to_raw(&PublicKey::from(vk))
    }

    pub fn export_private(&self) -> [u8; PRIVATE_KEY_SIZE] {
        let sk = SecretKey::from(self.inner.clone());
        private_to_raw(&sk)
    }

    /// Signs `data` (hashed with SHA-256), returning `r || s`, 64 bytes.
    pub fn sign(&self, data: &[u8]) -> [u8; SIGNATURE_SIZE] {
        let sig: Signature = self.inner.sign(data);
        let bytes = sig.to_bytes();
        let mut out = [0u8; SIGNATURE_SIZE];
        out.copy_from_slice(&bytes);
        out
    }

    /// Verifies a 64-byte `r || s` signature against a 64-byte raw public key.
    /// A damaged or forged key means "did not check out", not a breakdown.
    pub fn verify(public_key: &[u8], data: &[u8], signature: &[u8]) -> bool {
        if signature.len() != SIGNATURE_SIZE || public_key.len() != PUBLIC_KEY_SIZE {
            return false;
        }
        let public = match public_from_raw(public_key) {
            Ok(p) => p,
            Err(_) => return false,
        };
        let sig = match Signature::from_slice(signature) {
            Ok(s) => s,
            Err(_) => return false,
        };
        VerifyingKey::from(public).verify(data, &sig).is_ok()
    }
}

/// An agreement key (ECDH P-256).
#[derive(Clone)]
pub struct AgreementKey {
    secret: SecretKey,
}

impl AgreementKey {
    pub fn generate() -> Self {
        AgreementKey {
            secret: random_secret_key(),
        }
    }

    pub fn import_private(raw: &[u8]) -> Result<Self, KeyError> {
        if raw.len() != PRIVATE_KEY_SIZE {
            return Err(KeyError("a private key must be 96 bytes"));
        }
        let secret = SecretKey::from_slice(&raw[PUBLIC_KEY_SIZE..])
            .map_err(|_| KeyError("invalid P-256 scalar"))?;
        Ok(AgreementKey { secret })
    }

    pub fn export_public(&self) -> [u8; PUBLIC_KEY_SIZE] {
        public_to_raw(&self.secret.public_key())
    }

    pub fn export_private(&self) -> [u8; PRIVATE_KEY_SIZE] {
        private_to_raw(&self.secret)
    }

    /// The shared secret with someone else's public key: `SHA-256(x)`, where
    /// `x` is the shared point's big-endian `x` coordinate. 32 bytes.
    pub fn agree(&self, peer_public_key: &[u8]) -> Result<[u8; SHARED_SECRET_SIZE], KeyError> {
        let peer = public_from_raw(peer_public_key)?;
        let shared = p256::ecdh::diffie_hellman(
            self.secret.to_nonzero_scalar(),
            peer.as_affine(),
        );
        let mut hasher = Sha256::new();
        hasher.update(shared.raw_secret_bytes());
        let digest = hasher.finalize();
        let mut out = [0u8; SHARED_SECRET_SIZE];
        out.copy_from_slice(&digest);
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sign_verify_round_trip() {
        let key = SigningKey::generate();
        let pk = key.export_public();
        let data = b"relay descriptor bytes";
        let sig = key.sign(data);
        assert!(SigningKey::verify(&pk, data, &sig));
        assert!(!SigningKey::verify(&pk, b"other", &sig));
    }

    #[test]
    fn signing_key_private_round_trip() {
        let key = SigningKey::generate();
        let raw = key.export_private();
        let restored = SigningKey::import_private(&raw).unwrap();
        assert_eq!(key.export_public(), restored.export_public());
        let data = b"abc";
        assert!(SigningKey::verify(&restored.export_public(), data, &key.sign(data)));
    }

    #[test]
    fn ecdh_agrees_both_ways() {
        let a = AgreementKey::generate();
        let b = AgreementKey::generate();
        let sa = a.agree(&b.export_public()).unwrap();
        let sb = b.agree(&a.export_public()).unwrap();
        assert_eq!(sa, sb);
        assert_eq!(sa.len(), SHARED_SECRET_SIZE);
    }

    #[test]
    fn ecdh_private_round_trip() {
        let a = AgreementKey::generate();
        let raw = a.export_private();
        let restored = AgreementKey::import_private(&raw).unwrap();
        assert_eq!(a.export_public(), restored.export_public());
    }
}
