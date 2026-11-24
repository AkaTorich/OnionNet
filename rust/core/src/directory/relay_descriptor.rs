//! A relay's card: where to look for it, which keys to speak to it with, and
//! the pass that let it in.
//!
//! The card is signed with the node's own key, so it cannot be rewritten on the
//! way. It carries a memory-hard Argon2id pass solved over the node's
//! fingerprint: there is nobody in the network to hand out entry, so every
//! participant checks the pass itself. The wire format matches the C#
//! `RelayDescriptor` byte for byte.

use crate::crypto::ecc_p256::SigningKey;
use crate::identity::node_identity::NodeIdentity;
use crate::identity::onion_address;
use crate::identity::sybil_proof;
use crate::text::t;
use std::sync::atomic::{AtomicU32, Ordering};

const MAX_NICKNAME_BYTES: usize = 64;
const MAX_HOST_BYTES: usize = 255;
const PUBLIC_KEY_SIZE: usize = 64;
const SIGNATURE_SIZE: usize = 64;
const PROOF_TAG: u8 = 2;

/// How hard a pass the network asks of a relay, in leading zero bits. Fourteen
/// bits is about sixteen thousand attempts at 8 MiB each — minutes once in the
/// life of a key for an honest relay, and the same again for every fake relay
/// somebody would raise to surround the users (the C# asked ten, which made a
/// fake relay cost seconds). The self-test lowers it, hence a settable global
/// rather than a constant.
static REQUIRED_PROOF_BITS: AtomicU32 = AtomicU32::new(14);

pub fn required_proof_bits() -> u32 {
    REQUIRED_PROOF_BITS.load(Ordering::Relaxed)
}

pub fn set_required_proof_bits(bits: u32) {
    REQUIRED_PROOF_BITS.store(bits, Ordering::Relaxed);
}

#[derive(Clone, Debug)]
pub struct RelayDescriptor {
    pub nickname: String,
    /// Where the relay is dialled.
    pub host: String,
    pub port: u16,
    /// The public signing key, 64 bytes. The fingerprint grows out of it.
    pub signing_key: [u8; PUBLIC_KEY_SIZE],
    /// The public onion key for the handshake, 64 bytes.
    pub onion_key: [u8; PUBLIC_KEY_SIZE],
    /// When the card was signed, as .NET ticks. A relay signs it afresh every
    /// hour; an old card is a gone relay.
    pub published_ticks: i64,
    /// Whether this node may be last in a circuit.
    pub allows_exit: bool,
    /// The pass: the nonce that makes the fingerprint's challenge come out with
    /// enough zero bits.
    pub proof: Option<[u8; sybil_proof::NONCE_SIZE]>,
    /// How many zero bits the pass was solved for.
    pub proof_bits: u8,
    /// The card exactly as its owner signed it, passed around rather than
    /// rebuilt (rebuilding would break the signature).
    signed_bytes: Option<Vec<u8>>,
}

impl RelayDescriptor {
    pub fn from_identity(identity: &NodeIdentity, host: &str, port: u16, allows_exit: bool) -> RelayDescriptor {
        RelayDescriptor {
            nickname: identity.nickname().to_string(),
            host: host.to_string(),
            port,
            signing_key: *identity.public_signing_key(),
            onion_key: *identity.public_onion_key(),
            published_ticks: now_ticks(),
            allows_exit,
            proof: None,
            proof_bits: 0,
            signed_bytes: None,
        }
    }

    pub fn fingerprint(&self) -> [u8; 20] {
        onion_address::compute_fingerprint(&self.signing_key)
    }

    pub fn signed_bytes(&self) -> Option<&[u8]> {
        self.signed_bytes.as_deref()
    }

    /// Attaches a solved pass to the card.
    pub fn set_proof(&mut self, nonce: [u8; sybil_proof::NONCE_SIZE], bits: u8) {
        self.proof = Some(nonce);
        self.proof_bits = bits;
    }

    // ---- The pass ----------------------------------------------------------

    /// The challenge a relay's pass is solved over: its fingerprint alone, with
    /// no period — the pass is for the key, once and for good.
    pub fn proof_challenge(fingerprint: &[u8]) -> [u8; sybil_proof::CHALLENGE_SIZE] {
        sybil_proof::build_challenge(fingerprint, 0)
    }

    /// Whether the card carries a pass hard enough for the network. One
    /// Argon2id run.
    pub fn has_valid_proof(&self) -> bool {
        let proof = match &self.proof {
            Some(p) => p,
            None => return false,
        };
        if (self.proof_bits as u32) < required_proof_bits() {
            return false;
        }
        sybil_proof::verify(
            &RelayDescriptor::proof_challenge(&self.fingerprint()),
            proof,
            self.proof_bits as u32,
        )
    }

    // ---- The wire ----------------------------------------------------------

    /// The body without the signature — what gets signed and checked.
    fn to_body(&self) -> Result<Vec<u8>, String> {
        self.validate()?;

        let mut b = Vec::new();
        write_string(&mut b, &self.nickname, MAX_NICKNAME_BYTES)?;
        write_string(&mut b, &self.host, MAX_HOST_BYTES)?;
        b.extend_from_slice(&self.port.to_le_bytes());
        b.extend_from_slice(&self.signing_key);
        b.extend_from_slice(&self.onion_key);
        b.extend_from_slice(&self.published_ticks.to_le_bytes());
        b.push(self.allows_exit as u8);

        if let Some(proof) = &self.proof {
            b.push(PROOF_TAG);
            b.push(self.proof_bits);
            b.extend_from_slice(proof);
        }

        Ok(b)
    }

    /// The body plus the author's signature. Also caches `signed_bytes`.
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

    /// Parses a card and checks the signature with the key declared inside it.
    /// A signature that does not check out is a refusal. The pass is checked
    /// separately — it costs an Argon2id run.
    pub fn try_parse(data: &[u8]) -> Option<RelayDescriptor> {
        if data.len() < 4 {
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

    fn validate(&self) -> Result<(), String> {
        if self.host.is_empty() {
            return Err("the descriptor has no address".into());
        }
        if self.port == 0 {
            return Err(format!("invalid port: {}", self.port));
        }
        if self.proof_bits > 64 {
            return Err("an impossible pass difficulty".into());
        }
        Ok(())
    }
}

impl std::fmt::Display for RelayDescriptor {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let name = if self.nickname.is_empty() {
            t("node.noname")
        } else {
            self.nickname.clone()
        };
        write!(f, "{} {}:{}", name, self.host, self.port)
    }
}

fn write_string(out: &mut Vec<u8>, value: &str, max_bytes: usize) -> Result<(), String> {
    let bytes = value.as_bytes();
    if bytes.len() > max_bytes {
        return Err(format!("the string is longer than {max_bytes} bytes"));
    }
    out.push(bytes.len() as u8);
    out.extend_from_slice(bytes);
    Ok(())
}

/// A little forward cursor over the body; every read is bounds-checked and
/// returns `None` past the end (standing in for C#'s `EndOfStreamException`).
struct Reader<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    fn new(data: &'a [u8]) -> Self {
        Reader { data, pos: 0 }
    }
    fn remaining(&self) -> usize {
        self.data.len() - self.pos
    }
    fn u8(&mut self) -> Option<u8> {
        let b = *self.data.get(self.pos)?;
        self.pos += 1;
        Some(b)
    }
    fn take(&mut self, n: usize) -> Option<&'a [u8]> {
        if self.remaining() < n {
            return None;
        }
        let s = &self.data[self.pos..self.pos + n];
        self.pos += n;
        Some(s)
    }
    fn u16_le(&mut self) -> Option<u16> {
        let s = self.take(2)?;
        Some(u16::from_le_bytes([s[0], s[1]]))
    }
    fn i64_le(&mut self) -> Option<i64> {
        let s = self.take(8)?;
        let mut a = [0u8; 8];
        a.copy_from_slice(s);
        Some(i64::from_le_bytes(a))
    }
    fn string(&mut self, max_bytes: usize) -> Option<String> {
        let length = self.u8()? as usize;
        if length > max_bytes {
            return None;
        }
        let bytes = self.take(length)?;
        Some(String::from_utf8_lossy(bytes).into_owned())
    }
}

fn parse_body(body: &[u8]) -> Option<RelayDescriptor> {
    let mut r = Reader::new(body);

    let nickname = r.string(MAX_NICKNAME_BYTES)?;
    let host = r.string(MAX_HOST_BYTES)?;
    let port = r.u16_le()?;

    let mut signing_key = [0u8; PUBLIC_KEY_SIZE];
    signing_key.copy_from_slice(r.take(PUBLIC_KEY_SIZE)?);
    let mut onion_key = [0u8; PUBLIC_KEY_SIZE];
    onion_key.copy_from_slice(r.take(PUBLIC_KEY_SIZE)?);

    let published_ticks = r.i64_le()?;
    let allows_exit = r.u8()? != 0;

    let mut proof = None;
    let mut proof_bits = 0u8;

    // The tail: tagged fields. A tag we do not know is a field from the future
    // — we stop there. The whole body is under the owner's signature.
    if r.remaining() > 0 && r.u8()? == PROOF_TAG {
        proof_bits = r.u8()?;
        let mut nonce = [0u8; sybil_proof::NONCE_SIZE];
        nonce.copy_from_slice(r.take(sybil_proof::NONCE_SIZE)?);
        proof = Some(nonce);
    }

    if host.is_empty() || port == 0 {
        return None; // a card with nowhere to dial
    }

    Some(RelayDescriptor {
        nickname,
        host,
        port,
        signing_key,
        onion_key,
        published_ticks,
        allows_exit,
        proof,
        proof_bits,
        signed_bytes: None,
    })
}

fn now_ticks() -> i64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    const TICKS_AT_UNIX_EPOCH: i64 = 621_355_968_000_000_000;
    match SystemTime::now().duration_since(UNIX_EPOCH) {
        Ok(d) => TICKS_AT_UNIX_EPOCH + d.as_secs() as i64 * 10_000_000 + (d.subsec_nanos() / 100) as i64,
        Err(_) => TICKS_AT_UNIX_EPOCH,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::NodeIdentity;

    #[test]
    fn sign_parse_round_trip_and_tamper() {
        let id = NodeIdentity::create("relay-1").unwrap();
        let mut desc = RelayDescriptor::from_identity(&id, "198.51.100.7", 9030, true);
        let signed = desc.to_signed_bytes(&id).unwrap();

        let parsed = RelayDescriptor::try_parse(&signed).expect("valid card parses");
        assert_eq!(parsed.host, "198.51.100.7");
        assert_eq!(parsed.port, 9030);
        assert!(parsed.allows_exit);
        assert_eq!(parsed.signing_key, *id.public_signing_key());
        assert_eq!(parsed.fingerprint(), id.fingerprint());

        // Flipping a body byte breaks the signature.
        let mut broken = signed.clone();
        broken[10] ^= 0xff;
        assert!(RelayDescriptor::try_parse(&broken).is_none());
    }

    #[test]
    fn proof_round_trips_through_the_wire() {
        set_required_proof_bits(4); // keep the test fast
        let id = NodeIdentity::create("").unwrap();
        let mut desc = RelayDescriptor::from_identity(&id, "203.0.113.1", 443, false);

        let challenge = RelayDescriptor::proof_challenge(&desc.fingerprint());
        let nonce = sybil_proof::solve(&challenge, 4, || false, |_, _| {}).unwrap();
        desc.set_proof(nonce, 4);
        assert!(desc.has_valid_proof());

        let signed = desc.to_signed_bytes(&id).unwrap();
        let parsed = RelayDescriptor::try_parse(&signed).unwrap();
        assert_eq!(parsed.proof, Some(nonce));
        assert_eq!(parsed.proof_bits, 4);
        assert!(parsed.has_valid_proof());

        set_required_proof_bits(14); // restore the default for other tests
    }
}
