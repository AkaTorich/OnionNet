//! The ntor handshake, carried over to P-256.
//!
//! From the relay's signed card the client knows its fingerprint and its onion
//! key `B`. It takes an ephemeral pair `x`/`X` and mixes TWO shared secrets:
//! `x*Y` (ephemeral with ephemeral) and `x*B` (ephemeral with static).
//!
//! The first gives forward secrecy; the second proves the far end really is
//! that relay and not a man in the middle. The relay proves itself with an auth
//! tag rather than a signature: a signature would leave irrefutable proof on
//! the air that this node spoke to this client, while a tag can be checked only
//! by a party to the conversation.

use crate::crypto::ecc_p256::AgreementKey;
use crate::crypto::{hkdf, rand};
use hmac::{Hmac, Mac};
use sha2::Sha256;
use zeroize::Zeroize;

type HmacSha256 = Hmac<Sha256>;

const PROTOCOL_ID: &str = "stalknet-ntor-p256-v1";
const SERVER_LABEL: &str = "Server";

/// Node fingerprint length. Must equal `OnionAddress::FINGERPRINT_SIZE`.
pub const FINGERPRINT_SIZE: usize = 20;
pub const PUBLIC_KEY_SIZE: usize = 64;
pub const AUTH_SIZE: usize = 32;

pub const CLIENT_HANDSHAKE_SIZE: usize = FINGERPRINT_SIZE + PUBLIC_KEY_SIZE; // 84
pub const SERVER_HANDSHAKE_SIZE: usize = PUBLIC_KEY_SIZE + AUTH_SIZE; // 96
/// Must equal `HopKeys::MATERIAL_SIZE`.
pub const KEY_MATERIAL_SIZE: usize = 160;
pub const CHANNEL_BINDER_SIZE: usize = 32;

fn verify_key() -> Vec<u8> {
    format!("{PROTOCOL_ID}:verify").into_bytes()
}
fn mac_key() -> Vec<u8> {
    format!("{PROTOCOL_ID}:mac").into_bytes()
}
fn extract_salt() -> Vec<u8> {
    format!("{PROTOCOL_ID}:key_extract").into_bytes()
}
fn expand_info() -> Vec<u8> {
    format!("{PROTOCOL_ID}:key_expand").into_bytes()
}
/// The label for the channel seed — derived from the same shared secret but
/// under a different label, so it is unrelated to the keys. It exists so that a
/// proof of identity sent over one link cannot be moved to another.
fn link_bind_info() -> Vec<u8> {
    format!("{PROTOCOL_ID}:link_bind").into_bytes()
}

// ---- The client's side -----------------------------------------------------

/// An unfinished handshake. It holds the ephemeral key between sending Create
/// and the arrival of Created.
pub struct ClientHandshake {
    ephemeral: AgreementKey,
    fingerprint: [u8; FINGERPRINT_SIZE],
    onion_key: [u8; PUBLIC_KEY_SIZE],
    client_public: [u8; PUBLIC_KEY_SIZE],
    message: [u8; CLIENT_HANDSHAKE_SIZE],
}

impl ClientHandshake {
    /// The 84 bytes that go out in the Create cell.
    pub fn message(&self) -> &[u8; CLIENT_HANDSHAKE_SIZE] {
        &self.message
    }

    /// Parses the relay's answer. Returns 160 bytes of key material, or `None`
    /// if the relay did not prove itself.
    pub fn complete(&self, server_message: &[u8]) -> Option<Vec<u8>> {
        self.complete_with_binder(server_message).map(|(m, _)| m)
    }

    /// The same, but it also hands out the channel seed.
    pub fn complete_with_binder(&self, server_message: &[u8]) -> Option<(Vec<u8>, Vec<u8>)> {
        if server_message.len() != SERVER_HANDSHAKE_SIZE {
            return None;
        }
        let server_public = &server_message[..PUBLIC_KEY_SIZE];
        let received_auth = &server_message[PUBLIC_KEY_SIZE..];

        let mut ephemeral_shared = self.ephemeral.agree(server_public).ok()?;
        let mut static_shared = self.ephemeral.agree(&self.onion_key).ok()?;

        let mut secret_input = build_secret_input(
            &ephemeral_shared,
            &static_shared,
            &self.fingerprint,
            &self.onion_key,
            &self.client_public,
            server_public,
        );
        ephemeral_shared.zeroize();
        static_shared.zeroize();

        let expected_auth = compute_auth(
            &secret_input,
            &self.fingerprint,
            &self.onion_key,
            server_public,
            &self.client_public,
        );

        if !rand::constant_time_equals(&expected_auth, received_auth) {
            secret_input.zeroize();
            return None;
        }

        let material = hkdf::derive(&extract_salt(), &secret_input, &expand_info(), KEY_MATERIAL_SIZE);
        let binder = hkdf::derive(&extract_salt(), &secret_input, &link_bind_info(), CHANNEL_BINDER_SIZE);

        secret_input.zeroize();
        Some((material, binder))
    }
}

/// Starts a handshake with a relay whose fingerprint and onion key are already
/// known.
pub fn begin_client(relay_fingerprint: &[u8], relay_onion_key: &[u8]) -> Result<ClientHandshake, &'static str> {
    if relay_fingerprint.len() != FINGERPRINT_SIZE {
        return Err("the fingerprint must be 20 bytes");
    }
    if relay_onion_key.len() != PUBLIC_KEY_SIZE {
        return Err("the onion key must be 64 bytes");
    }

    let ephemeral = AgreementKey::generate();
    let client_public = ephemeral.export_public();

    let mut fingerprint = [0u8; FINGERPRINT_SIZE];
    fingerprint.copy_from_slice(relay_fingerprint);
    let mut onion_key = [0u8; PUBLIC_KEY_SIZE];
    onion_key.copy_from_slice(relay_onion_key);

    let mut message = [0u8; CLIENT_HANDSHAKE_SIZE];
    message[..FINGERPRINT_SIZE].copy_from_slice(&fingerprint);
    message[FINGERPRINT_SIZE..].copy_from_slice(&client_public);

    Ok(ClientHandshake {
        ephemeral,
        fingerprint,
        onion_key,
        client_public,
        message,
    })
}

// ---- The relay's side ------------------------------------------------------

/// A relay's answer to a client handshake.
pub struct ServerAnswer {
    pub server_message: [u8; SERVER_HANDSHAKE_SIZE],
    pub key_material: Vec<u8>,
    pub channel_binder: Vec<u8>,
}

/// Answers a client's handshake with the relay's fingerprint and static onion
/// key. Returns `None` if the request is addressed to somebody else or carries
/// an invalid point. `relay_onion` is the relay's long-term agreement key; its
/// public half must be the onion key published in the relay's card.
pub fn answer_server(
    relay_fingerprint: &[u8; FINGERPRINT_SIZE],
    relay_onion: &AgreementKey,
    client_message: &[u8],
) -> Option<ServerAnswer> {
    if client_message.len() != CLIENT_HANDSHAKE_SIZE {
        return None;
    }

    let claimed = &client_message[..FINGERPRINT_SIZE];
    // The client must name whom it is going to: otherwise a handshake could be
    // forwarded to another relay and its answer passed off as ours.
    if !rand::constant_time_equals(relay_fingerprint, claimed) {
        return None;
    }

    let client_public = &client_message[FINGERPRINT_SIZE..];
    let onion_key = relay_onion.export_public();

    let ephemeral = AgreementKey::generate();
    let server_public = ephemeral.export_public();

    let mut ephemeral_shared = ephemeral.agree(client_public).ok()?;
    let mut static_shared = relay_onion.agree(client_public).ok()?;

    let mut secret_input = build_secret_input(
        &ephemeral_shared,
        &static_shared,
        relay_fingerprint,
        &onion_key,
        client_public,
        &server_public,
    );
    ephemeral_shared.zeroize();
    static_shared.zeroize();

    let auth = compute_auth(&secret_input, relay_fingerprint, &onion_key, &server_public, client_public);

    let mut server_message = [0u8; SERVER_HANDSHAKE_SIZE];
    server_message[..PUBLIC_KEY_SIZE].copy_from_slice(&server_public);
    server_message[PUBLIC_KEY_SIZE..].copy_from_slice(&auth);

    let key_material = hkdf::derive(&extract_salt(), &secret_input, &expand_info(), KEY_MATERIAL_SIZE);
    let channel_binder = hkdf::derive(&extract_salt(), &secret_input, &link_bind_info(), CHANNEL_BINDER_SIZE);

    secret_input.zeroize();
    Some(ServerAnswer {
        server_message,
        key_material,
        channel_binder,
    })
}

// ---- The common part -------------------------------------------------------

/// `secret_input = x*Y | x*B | ID | B | X | Y | PROTOID`. Order and
/// completeness matter: everything the two sides agreed on goes in here, so
/// swapping any field on the way gives different keys.
fn build_secret_input(
    ephemeral_shared: &[u8],
    static_shared: &[u8],
    fingerprint: &[u8],
    onion_key: &[u8],
    client_public: &[u8],
    server_public: &[u8],
) -> Vec<u8> {
    let mut out = Vec::with_capacity(
        ephemeral_shared.len()
            + static_shared.len()
            + fingerprint.len()
            + onion_key.len()
            + client_public.len()
            + server_public.len()
            + PROTOCOL_ID.len(),
    );
    out.extend_from_slice(ephemeral_shared);
    out.extend_from_slice(static_shared);
    out.extend_from_slice(fingerprint);
    out.extend_from_slice(onion_key);
    out.extend_from_slice(client_public);
    out.extend_from_slice(server_public);
    out.extend_from_slice(PROTOCOL_ID.as_bytes());
    out
}

fn compute_auth(
    secret_input: &[u8],
    fingerprint: &[u8],
    onion_key: &[u8],
    server_public: &[u8],
    client_public: &[u8],
) -> [u8; AUTH_SIZE] {
    let verify = mac(&verify_key(), secret_input);

    let mut auth_input = Vec::new();
    auth_input.extend_from_slice(&verify);
    auth_input.extend_from_slice(fingerprint);
    auth_input.extend_from_slice(onion_key);
    auth_input.extend_from_slice(server_public);
    auth_input.extend_from_slice(client_public);
    auth_input.extend_from_slice(PROTOCOL_ID.as_bytes());
    auth_input.extend_from_slice(SERVER_LABEL.as_bytes());

    mac(&mac_key(), &auth_input)
}

fn mac(key: &[u8], data: &[u8]) -> [u8; AUTH_SIZE] {
    let mut m = HmacSha256::new_from_slice(key).expect("HMAC accepts any key length");
    m.update(data);
    let out = m.finalize().into_bytes();
    let mut tag = [0u8; AUTH_SIZE];
    tag.copy_from_slice(&out);
    tag
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn full_handshake_agrees_on_material() {
        let relay_onion = AgreementKey::generate();
        let onion_pub = relay_onion.export_public();
        let fingerprint = [0x11u8; FINGERPRINT_SIZE];

        let client = begin_client(&fingerprint, &onion_pub).unwrap();
        let answer = answer_server(&fingerprint, &relay_onion, client.message()).unwrap();

        let (material, binder) = client.complete_with_binder(&answer.server_message).unwrap();
        assert_eq!(material, answer.key_material);
        assert_eq!(binder, answer.channel_binder);
        assert_eq!(material.len(), KEY_MATERIAL_SIZE);
        assert_eq!(binder.len(), CHANNEL_BINDER_SIZE);
    }

    #[test]
    fn wrong_fingerprint_is_rejected() {
        let relay_onion = AgreementKey::generate();
        let client = begin_client(&[1u8; FINGERPRINT_SIZE], &relay_onion.export_public()).unwrap();
        // Relay's real fingerprint differs from the one the client addressed.
        assert!(answer_server(&[2u8; FINGERPRINT_SIZE], &relay_onion, client.message()).is_none());
    }

    #[test]
    fn forged_answer_fails_auth() {
        let relay_onion = AgreementKey::generate();
        let fingerprint = [7u8; FINGERPRINT_SIZE];
        let client = begin_client(&fingerprint, &relay_onion.export_public()).unwrap();
        let mut answer = answer_server(&fingerprint, &relay_onion, client.message()).unwrap();
        answer.server_message[PUBLIC_KEY_SIZE] ^= 0xff; // corrupt the auth tag
        assert!(client.complete(&answer.server_message).is_none());
    }
}
