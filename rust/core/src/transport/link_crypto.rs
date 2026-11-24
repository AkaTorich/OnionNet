//! Encryption of the link between two neighbouring nodes — on top of the onion
//! layers rather than instead of them.
//!
//! A cell's circuit number and command stay in the clear otherwise; an observer
//! who sees two neighbouring links could stitch the hops together by matching
//! moments and numbers without breaking any cipher. The link layer hides that:
//! from outside only a procession of identical 530-byte frames is visible.
//!
//! The arrangement: the MAC over the ciphertext first, decryption after — the
//! other way round would mean parsing unauthenticated data.

use crate::crypto::chaining_mac::ChainingMac;
use crate::crypto::ctr_stream::CtrStream;
use crate::protocol::cell::{Cell, SIZE as CELL_SIZE};

pub const TAG_SIZE: usize = 16;
pub const FRAME_SIZE: usize = CELL_SIZE + TAG_SIZE; // 530
pub const MATERIAL_SIZE: usize = 160;

const INITIATOR_KEY_OFFSET: usize = 0;
const INITIATOR_IV_OFFSET: usize = 32;
const RESPONDER_KEY_OFFSET: usize = 48;
const RESPONDER_IV_OFFSET: usize = 80;
const INITIATOR_MAC_OFFSET: usize = 96;
const RESPONDER_MAC_OFFSET: usize = 128;

/// The sending half: one keystream and one tag chain. Kept apart from the
/// reading half so a long read never blocks a write.
pub struct LinkWriter {
    stream: CtrStream,
    mac: ChainingMac,
}

impl LinkWriter {
    /// Turns a cell into a link frame: 514 bytes of ciphertext plus a 16-byte tag.
    pub fn seal_cell(&mut self, cell: &Cell) -> Vec<u8> {
        let mut frame = vec![0u8; FRAME_SIZE];
        frame[..CELL_SIZE].copy_from_slice(&cell.to_bytes());

        self.stream.xor_in_place(&mut frame[..CELL_SIZE]);

        let tag = self.mac.compute(&frame[..CELL_SIZE]);
        frame[CELL_SIZE..].copy_from_slice(&tag[..TAG_SIZE]);
        self.mac.commit(&tag);

        frame
    }
}

/// The receiving half.
pub struct LinkReader {
    stream: CtrStream,
    mac: ChainingMac,
}

impl LinkReader {
    /// Parses a link frame. Returns `None` if the tag does not check out: that
    /// is either damage, a replay, or somebody in the stream.
    pub fn open_frame(&mut self, frame: &[u8]) -> Option<Cell> {
        if frame.len() != FRAME_SIZE {
            return None;
        }
        let received = &frame[CELL_SIZE..];
        let mut body = frame[..CELL_SIZE].to_vec();

        if !self.mac.verify_and_commit(&body, received) {
            return None;
        }
        self.stream.xor_in_place(&mut body);
        Cell::try_parse(&body, 0)
    }
}

pub struct LinkCrypto {
    writer: LinkWriter,
    reader: LinkReader,
}

impl LinkCrypto {
    /// Both sides get the same material but take it apart mirrored: what is
    /// outgoing for one is incoming for the other.
    pub fn create(material: &[u8], initiator: bool) -> LinkCrypto {
        assert_eq!(
            material.len(),
            MATERIAL_SIZE,
            "the link material is exactly {MATERIAL_SIZE} bytes"
        );

        let a_key = &material[INITIATOR_KEY_OFFSET..INITIATOR_KEY_OFFSET + 32];
        let a_iv = &material[INITIATOR_IV_OFFSET..INITIATOR_IV_OFFSET + 16];
        let b_key = &material[RESPONDER_KEY_OFFSET..RESPONDER_KEY_OFFSET + 32];
        let b_iv = &material[RESPONDER_IV_OFFSET..RESPONDER_IV_OFFSET + 16];
        let a_mac = &material[INITIATOR_MAC_OFFSET..INITIATOR_MAC_OFFSET + 32];
        let b_mac = &material[RESPONDER_MAC_OFFSET..RESPONDER_MAC_OFFSET + 32];

        // The initiator sends on A and receives on B; the responder mirrors it.
        let (out_key, out_iv, out_mac, in_key, in_iv, in_mac) = if initiator {
            (a_key, a_iv, a_mac, b_key, b_iv, b_mac)
        } else {
            (b_key, b_iv, b_mac, a_key, a_iv, a_mac)
        };

        LinkCrypto {
            writer: LinkWriter {
                stream: CtrStream::new(out_key, out_iv),
                mac: ChainingMac::new(out_mac, CELL_SIZE),
            },
            reader: LinkReader {
                stream: CtrStream::new(in_key, in_iv),
                mac: ChainingMac::new(in_mac, CELL_SIZE),
            },
        }
    }

    /// Turns a cell into a link frame.
    pub fn seal_cell(&mut self, cell: &Cell) -> Vec<u8> {
        self.writer.seal_cell(cell)
    }

    /// Parses a link frame; `None` if the tag does not check out.
    pub fn open_frame(&mut self, frame: &[u8]) -> Option<Cell> {
        self.reader.open_frame(frame)
    }

    /// Splits into the two halves, each guarded by its own lock in the channel.
    pub fn into_halves(self) -> (LinkWriter, LinkReader) {
        (self.writer, self.reader)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::rand;
    use crate::protocol::cell::CellCommand;

    #[test]
    fn two_sides_speak_over_the_link() {
        let material = rand::get_bytes(MATERIAL_SIZE);
        let mut initiator = LinkCrypto::create(&material, true);
        let mut responder = LinkCrypto::create(&material, false);

        let cell = Cell::build(7, CellCommand::Create, b"handshake");
        let frame = initiator.seal_cell(&cell);
        assert_eq!(frame.len(), FRAME_SIZE);

        let opened = responder.open_frame(&frame).expect("responder opens the frame");
        assert_eq!(opened.circuit_id, 7);
        assert_eq!(opened.command, CellCommand::Create);
        assert_eq!(&opened.payload[..9], b"handshake");
    }

    #[test]
    fn a_tampered_frame_is_rejected() {
        let material = rand::get_bytes(MATERIAL_SIZE);
        let mut initiator = LinkCrypto::create(&material, true);
        let mut responder = LinkCrypto::create(&material, false);

        let mut frame = initiator.seal_cell(&Cell::build(1, CellCommand::Relay, b"x"));
        frame[20] ^= 0xff;
        assert!(responder.open_frame(&frame).is_none());
    }
}
