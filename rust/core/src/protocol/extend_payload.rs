//! The contents of an Extend cell: everything the last hop needs in order to
//! stretch the circuit to the next node.
//!
//! The layout: `address length(1) | address | port(2) | onion key(64) |
//! handshake(84)`. The next node's onion key sits here because the link between
//! relays is encrypted too; a separate fingerprint is not needed — it is
//! already inside the handshake.

use crate::protocol::ntor::CLIENT_HANDSHAKE_SIZE;

const ONION_KEY_SIZE: usize = 64;
const MIN_SIZE: usize = 1 + 2 + ONION_KEY_SIZE + CLIENT_HANDSHAKE_SIZE;

/// The length travels in a single byte, so 255 is the ceiling. The same 255 as
/// in a node's card and a stream request.
pub const MAX_HOST_BYTES: usize = 255;

pub struct ExtendTarget {
    pub host: String,
    pub port: u16,
    pub onion_key: [u8; ONION_KEY_SIZE],
    pub handshake: [u8; CLIENT_HANDSHAKE_SIZE],
}

pub fn build(host: &str, port: u16, onion_key: &[u8], handshake: &[u8]) -> Result<Vec<u8>, &'static str> {
    if onion_key.len() != ONION_KEY_SIZE {
        return Err("the onion key must be 64 bytes");
    }
    if handshake.len() != CLIENT_HANDSHAKE_SIZE {
        return Err("the handshake must be 84 bytes");
    }
    if port == 0 {
        return Err("port out of range");
    }
    let host_bytes = host.as_bytes();
    if host_bytes.is_empty() {
        return Err("the address is empty");
    }
    if host_bytes.len() > MAX_HOST_BYTES {
        return Err("the address must be no longer than 255 bytes");
    }

    let mut payload = Vec::with_capacity(1 + host_bytes.len() + 2 + ONION_KEY_SIZE + CLIENT_HANDSHAKE_SIZE);
    payload.push(host_bytes.len() as u8);
    payload.extend_from_slice(host_bytes);
    payload.push((port >> 8) as u8);
    payload.push(port as u8);
    payload.extend_from_slice(onion_key);
    payload.extend_from_slice(handshake);
    Ok(payload)
}

pub fn try_parse(payload: &[u8]) -> Option<ExtendTarget> {
    if payload.len() < MIN_SIZE {
        return None;
    }
    let host_length = payload[0] as usize;
    if host_length == 0 {
        return None;
    }
    let expected = 1 + host_length + 2 + ONION_KEY_SIZE + CLIENT_HANDSHAKE_SIZE;
    if payload.len() != expected {
        return None;
    }

    let mut position = 1;
    let host = String::from_utf8_lossy(&payload[position..position + host_length]).into_owned();
    position += host_length;

    let port = ((payload[position] as u16) << 8) | payload[position + 1] as u16;
    position += 2;
    if port == 0 {
        return None;
    }

    let mut onion_key = [0u8; ONION_KEY_SIZE];
    onion_key.copy_from_slice(&payload[position..position + ONION_KEY_SIZE]);
    position += ONION_KEY_SIZE;

    let mut handshake = [0u8; CLIENT_HANDSHAKE_SIZE];
    handshake.copy_from_slice(&payload[position..position + CLIENT_HANDSHAKE_SIZE]);

    Some(ExtendTarget {
        host,
        port,
        onion_key,
        handshake,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_parse_round_trip() {
        let onion = [3u8; ONION_KEY_SIZE];
        let hs = [4u8; CLIENT_HANDSHAKE_SIZE];
        let payload = build("relay.example", 9001, &onion, &hs).unwrap();
        let t = try_parse(&payload).unwrap();
        assert_eq!(t.host, "relay.example");
        assert_eq!(t.port, 9001);
        assert_eq!(t.onion_key, onion);
        assert_eq!(t.handshake, hs);
    }
}
