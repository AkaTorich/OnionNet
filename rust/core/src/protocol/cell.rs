//! A fixed-size cell — the unit of everything that travels over StalkNet.
//!
//! The size is fixed hard: 514 bytes always, whatever lies inside. Otherwise an
//! observer at the entrance and one at the exit would match flows by packet
//! length alone, and three hops of encryption would save no one.

use crate::crypto::rand;

pub const SIZE: usize = 514;
pub const PAYLOAD_SIZE: usize = 509;
const CIRCUIT_ID_SIZE: usize = 4;

/// What a cell means to the neighbouring node on the link.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum CellCommand {
    /// A dummy. Keeps the link warm and blurs the pattern of pauses.
    Padding = 0,
    /// The client asks for a circuit: the handshake is in the payload.
    Create = 1,
    /// The answer to Create.
    Created = 2,
    /// A cell inside a circuit, wrapped in layers.
    Relay = 3,
    /// The circuit is closing.
    Destroy = 4,
    // 5 and 6 carried the link cards of nodes behind a gatekeeper. There are
    // no gatekeepers any more; the numbers stay unused so an old cell is never
    // read as something new.
}

impl CellCommand {
    pub fn from_u8(b: u8) -> Option<CellCommand> {
        match b {
            0 => Some(CellCommand::Padding),
            1 => Some(CellCommand::Create),
            2 => Some(CellCommand::Created),
            3 => Some(CellCommand::Relay),
            4 => Some(CellCommand::Destroy),
            _ => None,
        }
    }
}

#[derive(Clone)]
pub struct Cell {
    pub circuit_id: u32,
    pub command: CellCommand,
    /// Exactly 509 bytes. The layers come off right here in place.
    pub payload: Vec<u8>,
}

impl Cell {
    pub fn new(circuit_id: u32, command: CellCommand, payload: Vec<u8>) -> Cell {
        assert_eq!(payload.len(), PAYLOAD_SIZE, "a cell payload is exactly {PAYLOAD_SIZE} bytes");
        Cell {
            circuit_id,
            command,
            payload,
        }
    }

    /// Builds a cell out of content shorter than a full payload, padding the
    /// rest with random bytes. Random, not zeros: under a CTR keystream known
    /// plaintext is a gift to whoever gets hold of a piece of the keystream.
    pub fn build(circuit_id: u32, command: CellCommand, content: &[u8]) -> Cell {
        assert!(content.len() <= PAYLOAD_SIZE, "the content does not fit into a cell");
        let mut payload = rand::get_bytes(PAYLOAD_SIZE);
        payload[..content.len()].copy_from_slice(content);
        Cell::new(circuit_id, command, payload)
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut raw = Vec::with_capacity(SIZE);
        raw.extend_from_slice(&self.circuit_id.to_be_bytes());
        raw.push(self.command as u8);
        raw.extend_from_slice(&self.payload);
        raw
    }

    pub fn try_parse(raw: &[u8], offset: usize) -> Option<Cell> {
        if offset + SIZE > raw.len() {
            return None;
        }
        let circuit_id = u32::from_be_bytes([
            raw[offset],
            raw[offset + 1],
            raw[offset + 2],
            raw[offset + 3],
        ]);
        let command = CellCommand::from_u8(raw[offset + CIRCUIT_ID_SIZE])?;
        let payload = raw[offset + CIRCUIT_ID_SIZE + 1..offset + SIZE].to_vec();
        Some(Cell::new(circuit_id, command, payload))
    }

    pub fn parse(raw: &[u8]) -> Option<Cell> {
        Cell::try_parse(raw, 0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips_through_bytes() {
        let cell = Cell::build(0xdeadbeef, CellCommand::Relay, b"hello");
        let raw = cell.to_bytes();
        assert_eq!(raw.len(), SIZE);
        let parsed = Cell::parse(&raw).unwrap();
        assert_eq!(parsed.circuit_id, 0xdeadbeef);
        assert_eq!(parsed.command, CellCommand::Relay);
        assert_eq!(&parsed.payload[..5], b"hello");
    }

    #[test]
    fn rejects_unknown_command() {
        let mut raw = Cell::build(1, CellCommand::Padding, b"").to_bytes();
        raw[4] = 99; // unknown command byte
        assert!(Cell::parse(&raw).is_none());
    }
}
