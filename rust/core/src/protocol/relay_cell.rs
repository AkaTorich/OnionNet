//! The contents of a Relay cell once every layer is off — those very 509 bytes.
//!
//! The layout:
//!   `recogniser(2) | stream(2) | tag(6) | command(1) | length(2) | data(496)`
//!
//! The recogniser is zero only at the hop the cell is meant for. At every other
//! hop, once its layer comes off, there is pseudo-random rubbish there, and it
//! simply passes the cell on without understanding its contents.

use crate::crypto::rand;
use crate::protocol::cell::PAYLOAD_SIZE;

pub const HEADER_SIZE: usize = 13;
pub const MAX_DATA_SIZE: usize = PAYLOAD_SIZE - HEADER_SIZE; // 496

pub(crate) const RECOGNIZED_OFFSET: usize = 0;
pub(crate) const STREAM_ID_OFFSET: usize = 2;
pub(crate) const DIGEST_OFFSET: usize = 4;
pub(crate) const DIGEST_SIZE: usize = 6;
pub(crate) const COMMAND_OFFSET: usize = 10;
pub(crate) const LENGTH_OFFSET: usize = 11;
pub(crate) const DATA_OFFSET: usize = 13;

/// What a cell means to the hop it is addressed to.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum RelayCommand {
    Extend = 1,
    Extended = 2,
    Begin = 3,
    Connected = 4,
    Data = 5,
    End = 6,
    /// A junk cell: it evens the traffic out and the receiver throws it away.
    Drop = 7,
    Truncated = 8,
    /// The flow control window is opened a little.
    SendMe = 9,
    EstablishIntro = 10,
    Introduce = 11,
    EstablishRendezvous = 12,
    Rendezvous = 13,
    /// Open a stream to an address outside the network; the destination travels
    /// in the cell and the exit decides whether to go there.
    BeginTo = 14,
}

impl RelayCommand {
    pub fn from_u8(b: u8) -> Option<RelayCommand> {
        Some(match b {
            1 => RelayCommand::Extend,
            2 => RelayCommand::Extended,
            3 => RelayCommand::Begin,
            4 => RelayCommand::Connected,
            5 => RelayCommand::Data,
            6 => RelayCommand::End,
            7 => RelayCommand::Drop,
            8 => RelayCommand::Truncated,
            9 => RelayCommand::SendMe,
            10 => RelayCommand::EstablishIntro,
            11 => RelayCommand::Introduce,
            12 => RelayCommand::EstablishRendezvous,
            13 => RelayCommand::Rendezvous,
            14 => RelayCommand::BeginTo,
            _ => return None,
        })
    }
}

#[derive(Clone, Debug)]
pub struct RelayCell {
    pub command: RelayCommand,
    pub stream_id: u16,
    pub data: Vec<u8>,
}

impl RelayCell {
    pub fn new(command: RelayCommand, stream_id: u16, data: Vec<u8>) -> RelayCell {
        assert!(data.len() <= MAX_DATA_SIZE, "one cell holds {MAX_DATA_SIZE} bytes of data");
        RelayCell {
            command,
            stream_id,
            data,
        }
    }

    /// Unfolds into 509 bytes. The tag stays zero: the owner of the tag chain
    /// sets it right before encryption. The tail is random rubbish, not zeros.
    pub fn to_payload(&self) -> Vec<u8> {
        let mut payload = rand::get_bytes(PAYLOAD_SIZE);

        payload[RECOGNIZED_OFFSET] = 0;
        payload[RECOGNIZED_OFFSET + 1] = 0;

        payload[STREAM_ID_OFFSET] = (self.stream_id >> 8) as u8;
        payload[STREAM_ID_OFFSET + 1] = self.stream_id as u8;

        for i in 0..DIGEST_SIZE {
            payload[DIGEST_OFFSET + i] = 0;
        }

        payload[COMMAND_OFFSET] = self.command as u8;

        payload[LENGTH_OFFSET] = (self.data.len() >> 8) as u8;
        payload[LENGTH_OFFSET + 1] = self.data.len() as u8;

        payload[DATA_OFFSET..DATA_OFFSET + self.data.len()].copy_from_slice(&self.data);
        payload
    }

    /// Reads the contents out of 509 already verified bytes. Call only after
    /// the tag checks out, otherwise rubbish gets parsed.
    pub fn try_parse(payload: &[u8]) -> Option<RelayCell> {
        if payload.len() != PAYLOAD_SIZE {
            return None;
        }
        let command = RelayCommand::from_u8(payload[COMMAND_OFFSET])?;
        let length = ((payload[LENGTH_OFFSET] as usize) << 8) | payload[LENGTH_OFFSET + 1] as usize;
        if length > MAX_DATA_SIZE {
            return None;
        }
        let stream_id = ((payload[STREAM_ID_OFFSET] as u16) << 8) | payload[STREAM_ID_OFFSET + 1] as u16;
        let data = payload[DATA_OFFSET..DATA_OFFSET + length].to_vec();
        Some(RelayCell::new(command, stream_id, data))
    }

    /// Whether the recogniser is zero — the first, cheap sign of "this is for me".
    pub(crate) fn looks_recognized(payload: &[u8]) -> bool {
        payload[RECOGNIZED_OFFSET] == 0 && payload[RECOGNIZED_OFFSET + 1] == 0
    }
}
