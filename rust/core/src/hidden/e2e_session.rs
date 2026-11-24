//! The end-to-end cipher between a client and a hidden service.
//!
//! It sits on top of circuits that are already encrypted because TWO different
//! circuits meet at the meeting point, and the meeting point holds both ends.
//! Without this layer it would read everything the two sides say. The
//! arrangement is the link layer's: an AES-CTR keystream per direction plus a
//! tag chain. Messages vary in length, so the length goes into the tag.

use crate::crypto::chaining_mac::ChainingMac;
use crate::crypto::ctr_stream::CtrStream;
use crate::protocol::relay_cell::MAX_DATA_SIZE;

/// The end-to-end cipher tag (`ChannelLimits::EndToEndTag`).
pub const TAG_SIZE: usize = 16;
/// 160 bytes, like a hop's key material.
pub const MATERIAL_SIZE: usize = 160;
/// How many application bytes fit once the tag is counted
/// (`ChannelLimits::CellPayload - TagSize`, with `CellPayload = RelayCell::MAX_DATA_SIZE`).
pub const MAX_MESSAGE_SIZE: usize = MAX_DATA_SIZE - TAG_SIZE;

const CLIENT_KEY_OFFSET: usize = 0;
const CLIENT_IV_OFFSET: usize = 32;
const SERVICE_KEY_OFFSET: usize = 48;
const SERVICE_IV_OFFSET: usize = 80;
const CLIENT_MAC_OFFSET: usize = 96;
const SERVICE_MAC_OFFSET: usize = 128;

pub struct E2ESession {
    outbound: CtrStream,
    inbound: CtrStream,
    outbound_mac: ChainingMac,
    inbound_mac: ChainingMac,
}

impl E2ESession {
    /// Both sides get the same ntor material but take it apart mirrored: what is
    /// outgoing for the client is incoming for the service.
    pub fn create(material: &[u8], is_client: bool) -> E2ESession {
        assert_eq!(material.len(), MATERIAL_SIZE, "the session material is exactly {MATERIAL_SIZE} bytes");

        let client_key = &material[CLIENT_KEY_OFFSET..CLIENT_KEY_OFFSET + 32];
        let client_iv = &material[CLIENT_IV_OFFSET..CLIENT_IV_OFFSET + 16];
        let service_key = &material[SERVICE_KEY_OFFSET..SERVICE_KEY_OFFSET + 32];
        let service_iv = &material[SERVICE_IV_OFFSET..SERVICE_IV_OFFSET + 16];
        let client_mac = &material[CLIENT_MAC_OFFSET..CLIENT_MAC_OFFSET + 32];
        let service_mac = &material[SERVICE_MAC_OFFSET..SERVICE_MAC_OFFSET + 32];

        // The chaining MAC's nominal frame size is 1; messages vary, so each
        // computation carries its own length anyway.
        if is_client {
            E2ESession {
                outbound: CtrStream::new(client_key, client_iv),
                inbound: CtrStream::new(service_key, service_iv),
                outbound_mac: ChainingMac::new(client_mac, 1),
                inbound_mac: ChainingMac::new(service_mac, 1),
            }
        } else {
            E2ESession {
                outbound: CtrStream::new(service_key, service_iv),
                inbound: CtrStream::new(client_key, client_iv),
                outbound_mac: ChainingMac::new(service_mac, 1),
                inbound_mac: ChainingMac::new(client_mac, 1),
            }
        }
    }

    /// Wraps a message: ciphertext plus a tag.
    pub fn seal(&mut self, message: &[u8]) -> Vec<u8> {
        assert!(message.len() <= MAX_MESSAGE_SIZE, "a cell holds {MAX_MESSAGE_SIZE} bytes");

        let mut sealed = vec![0u8; message.len() + TAG_SIZE];
        sealed[..message.len()].copy_from_slice(message);
        self.outbound.xor_in_place(&mut sealed[..message.len()]);

        let tag = self.outbound_mac.compute(&sealed[..message.len()]);
        sealed[message.len()..].copy_from_slice(&tag[..TAG_SIZE]);
        self.outbound_mac.commit(&tag);

        sealed
    }

    /// Unwraps a message. `None` if the tag does not check out: somebody got
    /// into the conversation — most likely the meeting point.
    pub fn open(&mut self, sealed_message: &[u8]) -> Option<Vec<u8>> {
        if sealed_message.len() < TAG_SIZE {
            return None;
        }
        let length = sealed_message.len() - TAG_SIZE;
        let received = &sealed_message[length..];

        // The tag first, decryption after: nothing unverified may be parsed.
        if !self.inbound_mac.verify_and_commit(&sealed_message[..length], received) {
            return None;
        }
        let mut message = sealed_message[..length].to_vec();
        self.inbound.xor_in_place(&mut message);
        Some(message)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::rand;

    #[test]
    fn client_and_service_talk_both_ways() {
        let material = rand::get_bytes(MATERIAL_SIZE);
        let mut client = E2ESession::create(&material, true);
        let mut service = E2ESession::create(&material, false);

        let sealed = client.seal(b"hello service");
        assert_eq!(service.open(&sealed).as_deref(), Some(&b"hello service"[..]));

        let back = service.seal(b"hello client");
        assert_eq!(client.open(&back).as_deref(), Some(&b"hello client"[..]));
    }

    #[test]
    fn meeting_point_cannot_tamper() {
        let material = rand::get_bytes(MATERIAL_SIZE);
        let mut client = E2ESession::create(&material, true);
        let mut service = E2ESession::create(&material, false);
        let mut sealed = client.seal(b"secret");
        sealed[0] ^= 1;
        assert!(service.open(&sealed).is_none());
    }
}
