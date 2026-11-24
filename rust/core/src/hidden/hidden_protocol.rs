//! Building and parsing hidden-service messages, and the invitation — the part
//! of it the introduction point must not read.

use crate::crypto::ecc_p256::{AgreementKey, SigningKey};
use crate::crypto::{aead_aes_ctr_hmac as aead, hkdf};
use crate::identity::node_identity::NodeIdentity;
use crate::identity::onion_address::FINGERPRINT_SIZE;
use crate::protocol::ntor::CLIENT_HANDSHAKE_SIZE;
use crate::text::t;

/// An introduction point's messages.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum IntroOp {
    Establish = 1,
    Introduce = 2,
    Forwarded = 3,
    Ack = 4,
}

/// A meeting point's messages.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum RendezvousOp {
    Establish = 1,
    Join = 2,
    Joined = 3,
    Ack = 4,
}

/// How a request to an introduction or meeting point ended.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum HiddenStatus {
    Ok = 0,
    BadRequest = 1,
    BadSignature = 2,
    NoService = 3,
    NoRendezvous = 4,
    Busy = 5,
    Taken = 6,
}

impl HiddenStatus {
    pub fn from_u8(b: u8) -> Option<HiddenStatus> {
        Some(match b {
            0 => HiddenStatus::Ok,
            1 => HiddenStatus::BadRequest,
            2 => HiddenStatus::BadSignature,
            3 => HiddenStatus::NoService,
            4 => HiddenStatus::NoRendezvous,
            5 => HiddenStatus::Busy,
            6 => HiddenStatus::Taken,
            _ => return None,
        })
    }

    pub fn explain(self) -> String {
        let key = match self {
            HiddenStatus::Ok => "hidden.status.ok",
            HiddenStatus::BadRequest => "hidden.status.badrequest",
            HiddenStatus::BadSignature => "hidden.status.badsignature",
            HiddenStatus::NoService => "hidden.status.noservice",
            HiddenStatus::NoRendezvous => "hidden.status.norendezvous",
            HiddenStatus::Busy => "hidden.status.busy",
            HiddenStatus::Taken => "hidden.status.taken",
        };
        t(key)
    }
}

/// A meeting token. Twenty random bytes are enough: they cannot be guessed.
pub const COOKIE_SIZE: usize = 20;

const PUBLIC_KEY_SIZE: usize = 64;
const ESTABLISH_CONTEXT: &str = "stalknet-establish-intro-v2";
const INVITE_CONTEXT: &str = "stalknet-introduce-v1";

// ---- Message wrappers ------------------------------------------------------

pub fn message(op: u8, body: &[u8]) -> Vec<u8> {
    let mut data = Vec::with_capacity(1 + body.len());
    data.push(op);
    data.extend_from_slice(body);
    data
}

pub fn ack(op: u8, status: HiddenStatus) -> Vec<u8> {
    vec![op, status as u8]
}

pub fn try_read(data: &[u8]) -> Option<(u8, Vec<u8>)> {
    if data.is_empty() {
        return None;
    }
    Some((data[0], data[1..].to_vec()))
}

// ---- Establish: the service proves its right to its address ----------------

// The signature names the introduction point it is for and the moment it was
// made. Signed over the key alone, it was the same everywhere and for ever: an
// introduction point that once saw it could register the service at others
// and swallow its invitations. Now it is good at one point, for minutes.

/// The Establish body: the service's key, the time (seconds since 1970, little
/// endian), the signature.
pub const ESTABLISH_BODY_SIZE: usize = PUBLIC_KEY_SIZE + 8 + 64;

/// How far the Establish time may stand from the introduction point's clock.
pub const ESTABLISH_WINDOW_SECS: u64 = 10 * 60;

fn establish_signed(service_signing_key: &[u8], intro_fingerprint: &[u8], seconds: u64) -> Vec<u8> {
    let mut body = Vec::with_capacity(ESTABLISH_CONTEXT.len() + PUBLIC_KEY_SIZE + FINGERPRINT_SIZE + 8);
    body.extend_from_slice(ESTABLISH_CONTEXT.as_bytes());
    body.extend_from_slice(service_signing_key);
    body.extend_from_slice(intro_fingerprint);
    body.extend_from_slice(&seconds.to_le_bytes());
    body
}

fn now_seconds() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// The Establish body a service proves its address is its own with, at the
/// introduction point with this fingerprint.
pub fn build_establish(service: &NodeIdentity, intro_fingerprint: &[u8]) -> Vec<u8> {
    let seconds = now_seconds();
    let key = service.public_signing_key();
    let signature = service.sign(&establish_signed(key, intro_fingerprint, seconds));
    let mut body = Vec::with_capacity(ESTABLISH_BODY_SIZE);
    body.extend_from_slice(key);
    body.extend_from_slice(&seconds.to_le_bytes());
    body.extend_from_slice(&signature);
    body
}

/// Checks an Establish body at the introduction point `own_fingerprint`.
/// Returns the service's signing key when the signature is for this point and
/// fresh; `None` otherwise.
pub fn verify_establish<'a>(body: &'a [u8], own_fingerprint: &[u8]) -> Option<&'a [u8]> {
    if body.len() != ESTABLISH_BODY_SIZE {
        return None;
    }
    let key = &body[..PUBLIC_KEY_SIZE];
    let mut seconds = [0u8; 8];
    seconds.copy_from_slice(&body[PUBLIC_KEY_SIZE..PUBLIC_KEY_SIZE + 8]);
    let seconds = u64::from_le_bytes(seconds);
    let signature = &body[PUBLIC_KEY_SIZE + 8..];

    if now_seconds().abs_diff(seconds) > ESTABLISH_WINDOW_SECS {
        return None;
    }
    if SigningKey::verify(key, &establish_signed(key, own_fingerprint, seconds), signature) {
        Some(key)
    } else {
        None
    }
}

// ---- The invitation: closed to the introduction point ----------------------

/// An opened invitation: where the client waits, under which token, with which
/// handshake.
pub struct Invite {
    pub rendezvous_fingerprint: [u8; FINGERPRINT_SIZE],
    pub cookie: [u8; COOKIE_SIZE],
    pub client_handshake: [u8; CLIENT_HANDSHAKE_SIZE],
}

/// Wraps an invitation so that only the service can read it. The format: an
/// ephemeral key (64) || the sealed body.
pub fn seal_invite(
    service_onion_key: &[u8],
    rendezvous_fingerprint: &[u8; FINGERPRINT_SIZE],
    cookie: &[u8; COOKIE_SIZE],
    client_handshake: &[u8; CLIENT_HANDSHAKE_SIZE],
) -> Result<Vec<u8>, &'static str> {
    let mut body = Vec::with_capacity(FINGERPRINT_SIZE + COOKIE_SIZE + CLIENT_HANDSHAKE_SIZE);
    body.extend_from_slice(rendezvous_fingerprint);
    body.extend_from_slice(cookie);
    body.extend_from_slice(client_handshake);

    let ephemeral = AgreementKey::generate();
    let ephemeral_public = ephemeral.export_public();
    let shared = ephemeral.agree(service_onion_key).map_err(|_| "invalid service onion key")?;
    let key = hkdf::derive(INVITE_CONTEXT.as_bytes(), &shared, &[], aead::KEY_SIZE);

    let sealed = aead::seal(&key, &body, &ephemeral_public);

    let mut result = Vec::with_capacity(PUBLIC_KEY_SIZE + sealed.len());
    result.extend_from_slice(&ephemeral_public);
    result.extend_from_slice(&sealed);
    Ok(result)
}

/// Unwraps an invitation. Returns `None` if it is not for us.
pub fn open_invite(service: &NodeIdentity, invite: &[u8]) -> Option<Invite> {
    if invite.len() <= PUBLIC_KEY_SIZE {
        return None;
    }
    let ephemeral_public = &invite[..PUBLIC_KEY_SIZE];
    let sealed = &invite[PUBLIC_KEY_SIZE..];

    let shared = service.agree(ephemeral_public)?;
    let key = hkdf::derive(INVITE_CONTEXT.as_bytes(), &shared, &[], aead::KEY_SIZE);
    let body = aead::open(&key, sealed, ephemeral_public)?;

    let expected = FINGERPRINT_SIZE + COOKIE_SIZE + CLIENT_HANDSHAKE_SIZE;
    if body.len() != expected {
        return None;
    }
    let mut rendezvous_fingerprint = [0u8; FINGERPRINT_SIZE];
    let mut cookie = [0u8; COOKIE_SIZE];
    let mut client_handshake = [0u8; CLIENT_HANDSHAKE_SIZE];
    let mut pos = 0;
    rendezvous_fingerprint.copy_from_slice(&body[pos..pos + FINGERPRINT_SIZE]);
    pos += FINGERPRINT_SIZE;
    cookie.copy_from_slice(&body[pos..pos + COOKIE_SIZE]);
    pos += COOKIE_SIZE;
    client_handshake.copy_from_slice(&body[pos..pos + CLIENT_HANDSHAKE_SIZE]);

    Some(Invite {
        rendezvous_fingerprint,
        cookie,
        client_handshake,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn establish_signature_round_trip() {
        let svc = NodeIdentity::create("svc").unwrap();
        let here = [1u8; FINGERPRINT_SIZE];
        let body = build_establish(&svc, &here);
        assert_eq!(verify_establish(&body, &here), Some(&svc.public_signing_key()[..]));

        // A damaged signature fails.
        let mut broken = body.clone();
        broken[ESTABLISH_BODY_SIZE - 1] ^= 1;
        assert!(verify_establish(&broken, &here).is_none());
    }

    #[test]
    fn establish_is_good_at_one_point_only() {
        // An introduction point that saw the body cannot use it at another one.
        let svc = NodeIdentity::create("svc").unwrap();
        let body = build_establish(&svc, &[1u8; FINGERPRINT_SIZE]);
        assert!(verify_establish(&body, &[2u8; FINGERPRINT_SIZE]).is_none());
    }

    #[test]
    fn establish_goes_stale() {
        // A body made long ago is refused even at its own point.
        let svc = NodeIdentity::create("svc").unwrap();
        let here = [1u8; FINGERPRINT_SIZE];
        let old = now_seconds() - ESTABLISH_WINDOW_SECS - 60;
        let key = svc.public_signing_key();
        let signature = svc.sign(&establish_signed(key, &here, old));
        let mut body = key.to_vec();
        body.extend_from_slice(&old.to_le_bytes());
        body.extend_from_slice(&signature);
        assert!(verify_establish(&body, &here).is_none());
    }

    #[test]
    fn invite_seals_only_for_the_service() {
        let service = NodeIdentity::create("").unwrap();
        let other = NodeIdentity::create("").unwrap();
        let fp = [9u8; FINGERPRINT_SIZE];
        let cookie = [7u8; COOKIE_SIZE];
        let hs = [3u8; CLIENT_HANDSHAKE_SIZE];

        let invite = seal_invite(service.public_onion_key(), &fp, &cookie, &hs).unwrap();
        let opened = open_invite(&service, &invite).expect("service opens it");
        assert_eq!(opened.rendezvous_fingerprint, fp);
        assert_eq!(opened.cookie, cookie);
        assert_eq!(opened.client_handshake, hs);

        // Another node cannot open it.
        assert!(open_invite(&other, &invite).is_none());
    }
}
