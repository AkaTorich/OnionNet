//! A hidden service's announcement: through whom to reach it and with which key
//! to agree on a cipher with it.
//!
//! The service's address is not here and cannot be — only the fingerprints of
//! the introduction points. The announcement is signed with the service's key,
//! and the address grows out of that same key, so it cannot be forged. The wire
//! format matches the C# `ServiceDescriptor`.

use crate::crypto::ecc_p256::SigningKey;
use crate::crypto::rand;
use crate::identity::node_identity::NodeIdentity;
use crate::identity::onion_address::{self, OnionAddress, FINGERPRINT_SIZE};
use crate::text::t_args;
use crate::util::time::now_ticks;

const FORMAT_VERSION: u8 = 1;
const PUBLIC_KEY_SIZE: usize = 64;
const SIGNATURE_SIZE: usize = 64;
const MAX_INTRO_POINTS: usize = 8;

#[derive(Clone)]
pub struct ServiceDescriptor {
    pub signing_key: [u8; PUBLIC_KEY_SIZE],
    pub onion_key: [u8; PUBLIC_KEY_SIZE],
    pub intro_points: Vec<[u8; FINGERPRINT_SIZE]>,
    pub published_ticks: i64,
    signed_bytes: Option<Vec<u8>>,
}

impl ServiceDescriptor {
    pub fn fingerprint(&self) -> [u8; FINGERPRINT_SIZE] {
        onion_address::compute_fingerprint(&self.signing_key)
    }

    pub fn address(&self) -> OnionAddress {
        OnionAddress::from_public_key(&self.signing_key).expect("64-byte signing key")
    }

    pub fn signed_bytes(&self) -> Option<&[u8]> {
        self.signed_bytes.as_deref()
    }

    pub fn from_identity(identity: &NodeIdentity, intro_points: &[[u8; FINGERPRINT_SIZE]]) -> ServiceDescriptor {
        ServiceDescriptor {
            signing_key: *identity.public_signing_key(),
            onion_key: *identity.public_onion_key(),
            intro_points: intro_points.to_vec(),
            published_ticks: now_ticks(),
            signed_bytes: None,
        }
    }

    pub fn to_signed_bytes(&mut self, identity: &NodeIdentity) -> Result<Vec<u8>, String> {
        let body = self.to_body()?;
        let signature = identity.sign(&body);

        let mut result = Vec::with_capacity(4 + body.len() + SIGNATURE_SIZE);
        result.extend_from_slice(&(body.len() as u32).to_le_bytes());
        result.extend_from_slice(&body);
        result.extend_from_slice(&signature);
        self.signed_bytes = Some(result.clone());
        Ok(result)
    }

    fn to_body(&self) -> Result<Vec<u8>, String> {
        if self.intro_points.is_empty() {
            return Err("a service with no introduction points is unreachable".into());
        }
        if self.intro_points.len() > MAX_INTRO_POINTS {
            return Err(format!("more introduction points than {MAX_INTRO_POINTS}"));
        }

        let mut b = Vec::new();
        b.push(FORMAT_VERSION);
        b.extend_from_slice(&self.signing_key);
        b.extend_from_slice(&self.onion_key);
        b.extend_from_slice(&self.published_ticks.to_le_bytes());
        b.push(self.intro_points.len() as u8);
        for fp in &self.intro_points {
            b.extend_from_slice(fp);
        }
        Ok(b)
    }

    pub fn try_parse(data: &[u8]) -> Option<ServiceDescriptor> {
        if data.len() < 4 + SIGNATURE_SIZE {
            return None;
        }
        let body_length = u32::from_le_bytes([data[0], data[1], data[2], data[3]]) as usize;
        if 4 + body_length + SIGNATURE_SIZE != data.len() {
            return None;
        }
        let body = &data[4..4 + body_length];
        let signature = &data[4 + body_length..];

        let mut parsed = parse_body(body)?;
        if !SigningKey::verify(&parsed.signing_key, body, signature) {
            return None;
        }
        parsed.signed_bytes = Some(data.to_vec());
        Some(parsed)
    }

    /// Whether this is the service whose address we were looking for.
    pub fn matches(&self, address: &OnionAddress) -> bool {
        rand::constant_time_equals(&self.fingerprint(), &address.fingerprint())
    }
}

fn parse_body(body: &[u8]) -> Option<ServiceDescriptor> {
    // version(1) + signing(64) + onion(64) + ticks(8) + count(1) = 138 minimum
    if body.len() < 1 + PUBLIC_KEY_SIZE * 2 + 8 + 1 {
        return None;
    }
    if body[0] != FORMAT_VERSION {
        return None;
    }
    let mut pos = 1;
    let mut signing_key = [0u8; PUBLIC_KEY_SIZE];
    signing_key.copy_from_slice(&body[pos..pos + PUBLIC_KEY_SIZE]);
    pos += PUBLIC_KEY_SIZE;
    let mut onion_key = [0u8; PUBLIC_KEY_SIZE];
    onion_key.copy_from_slice(&body[pos..pos + PUBLIC_KEY_SIZE]);
    pos += PUBLIC_KEY_SIZE;

    let mut ticks = [0u8; 8];
    ticks.copy_from_slice(&body[pos..pos + 8]);
    let published_ticks = i64::from_le_bytes(ticks);
    pos += 8;

    let count = body[pos] as usize;
    pos += 1;
    if count == 0 || count > MAX_INTRO_POINTS {
        return None;
    }
    if body.len() != pos + count * FINGERPRINT_SIZE {
        return None; // extra or missing bytes
    }
    let mut intro_points = Vec::with_capacity(count);
    for _ in 0..count {
        let mut fp = [0u8; FINGERPRINT_SIZE];
        fp.copy_from_slice(&body[pos..pos + FINGERPRINT_SIZE]);
        intro_points.push(fp);
        pos += FINGERPRINT_SIZE;
    }

    Some(ServiceDescriptor {
        signing_key,
        onion_key,
        intro_points,
        published_ticks,
        signed_bytes: None,
    })
}

impl std::fmt::Display for ServiceDescriptor {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let addr = self.address();
        write!(f, "{}", t_args("hs.descriptor", &[addr.text(), &self.intro_points.len().to_string()]))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sign_parse_round_trip() {
        let id = NodeIdentity::create("svc").unwrap();
        let intros = [[1u8; FINGERPRINT_SIZE], [2u8; FINGERPRINT_SIZE]];
        let mut d = ServiceDescriptor::from_identity(&id, &intros);
        let signed = d.to_signed_bytes(&id).unwrap();

        let parsed = ServiceDescriptor::try_parse(&signed).unwrap();
        assert_eq!(parsed.signing_key, *id.public_signing_key());
        assert_eq!(parsed.intro_points, intros.to_vec());
        assert!(parsed.matches(&id.address().clone()));

        let mut broken = signed.clone();
        broken[5] ^= 0xff;
        assert!(ServiceDescriptor::try_parse(&broken).is_none());
    }
}
