//! Building and parsing the desk's messages: one message, one cell.
//!
//! These are the raw byte bodies a relay's desk exchanges. The stream layer
//! frames each one as a `RelayCommand::Data` cell on virtual port 1; here there
//! is only the message content, laid out exactly as the C# `PeerProtocol`.
//!
//! Note the two byte orders, kept as in the C#: request and response bodies are
//! written through a `BinaryWriter` and are therefore little-endian, while the
//! chunk header writes its index and length big-endian by hand.

use crate::protocol::relay_cell::MAX_DATA_SIZE;
use crate::text::t;

const REQUEST_HEADER: usize = 1;
const RESPONSE_HEADER: usize = 2;
const CHUNK_HEADER: usize = RESPONSE_HEADER + 4 + 2;

/// How many bytes of a bundle fit into one cell.
pub const CHUNK_SIZE: usize = MAX_DATA_SIZE - CHUNK_HEADER;

/// How many bytes of a card go in one offer message.
pub const OFFER_PIECE: usize = MAX_DATA_SIZE - REQUEST_HEADER - 4;

/// The ceiling on a card offered in pieces.
pub const MAX_OFFERED_CARD: usize = 2048;

/// What one node asks of a relay's desk.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum PeerOp {
    /// How big is the bundle of cards you know.
    Cards = 1,
    /// A piece of that bundle.
    CardsChunk = 2,
    /// A piece of my own card: take me into your list.
    Offer = 3,
    /// Keep a hidden address's announcement.
    PublishService = 4,
    /// A hidden address's announcement by its fingerprint.
    FetchService = 5,
    /// The hidden address with this fingerprint holds the bundle.
    Announce = 6,
    /// Who holds this bundle.
    Holders = 7,
    /// Keep a site's sealed record under the hash of its address.
    PublishSite = 8,
    /// A site's sealed record by the hash of its address.
    FetchSite = 9,
}

impl PeerOp {
    pub fn from_u8(b: u8) -> Option<PeerOp> {
        Some(match b {
            1 => PeerOp::Cards,
            2 => PeerOp::CardsChunk,
            3 => PeerOp::Offer,
            4 => PeerOp::PublishService,
            5 => PeerOp::FetchService,
            6 => PeerOp::Announce,
            7 => PeerOp::Holders,
            8 => PeerOp::PublishSite,
            9 => PeerOp::FetchSite,
            _ => return None,
        })
    }
}

/// How a request to a relay's desk ended.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum PeerStatus {
    Ok = 0,
    /// The card or the record was not parsed, or its signature does not check out.
    BadCard = 1,
    /// The request was not parsed.
    BadRequest = 2,
    /// The relay knows no cards yet.
    Empty = 3,
    /// Something broke on the relay's side.
    ServerError = 4,
    /// The relay's shelf for this kind of record is full.
    Full = 5,
    /// No announcement for that address is kept here.
    NoService = 6,
    /// The record is no newer than the one kept: that is a rollback.
    Stale = 7,
    /// No record for that site is kept here.
    NoSite = 8,
    /// The site's record is somebody else's: the write secret does not match.
    NotOwner = 9,
    /// The piece is taken — send the next one.
    More = 10,
}

impl PeerStatus {
    pub fn from_u8(b: u8) -> Option<PeerStatus> {
        Some(match b {
            0 => PeerStatus::Ok,
            1 => PeerStatus::BadCard,
            2 => PeerStatus::BadRequest,
            3 => PeerStatus::Empty,
            4 => PeerStatus::ServerError,
            5 => PeerStatus::Full,
            6 => PeerStatus::NoService,
            7 => PeerStatus::Stale,
            8 => PeerStatus::NoSite,
            9 => PeerStatus::NotOwner,
            10 => PeerStatus::More,
            _ => return None,
        })
    }
}

/// Builds a request message: the op byte, then whatever `body` writes.
///
/// Errors (like the C# `InvalidOperationException`) if the whole thing would not
/// fit into one cell.
pub fn request<F>(op: PeerOp, body: F) -> Result<Vec<u8>, String>
where
    F: FnOnce(&mut Vec<u8>),
{
    let mut data = Vec::new();
    data.push(op as u8);
    body(&mut data);
    if data.len() > MAX_DATA_SIZE {
        return Err("the request does not fit into a cell".into());
    }
    Ok(data)
}

/// Builds a response message: the op byte, the status byte, then `body`.
pub fn response<F>(op: PeerOp, status: PeerStatus, body: F) -> Result<Vec<u8>, String>
where
    F: FnOnce(&mut Vec<u8>),
{
    let mut data = Vec::new();
    data.push(op as u8);
    data.push(status as u8);
    body(&mut data);
    if data.len() > MAX_DATA_SIZE {
        return Err("the answer does not fit into a cell".into());
    }
    Ok(data)
}

/// Builds one bundle chunk. Index and length ride big-endian by hand, as in C#.
pub fn chunk(op: PeerOp, index: i32, source: &[u8], offset: usize, length: usize) -> Vec<u8> {
    assert!(length <= CHUNK_SIZE, "a chunk holds at most {CHUNK_SIZE} bytes");

    let mut data = vec![0u8; CHUNK_HEADER + length];
    data[0] = op as u8;
    data[1] = PeerStatus::Ok as u8;
    data[2] = (index >> 24) as u8;
    data[3] = (index >> 16) as u8;
    data[4] = (index >> 8) as u8;
    data[5] = index as u8;
    data[6] = (length >> 8) as u8;
    data[7] = length as u8;
    data[CHUNK_HEADER..].copy_from_slice(&source[offset..offset + length]);
    data
}

/// Reads a request message's op and the payload after it.
pub fn try_read_request(data: &[u8]) -> Option<(PeerOp, Vec<u8>)> {
    if data.len() < REQUEST_HEADER {
        return None;
    }
    let op = PeerOp::from_u8(data[0])?;
    Some((op, data[REQUEST_HEADER..].to_vec()))
}

/// Reads a response message's op, status and the payload after them.
pub fn try_read_response(data: &[u8]) -> Option<(PeerOp, PeerStatus, Vec<u8>)> {
    if data.len() < RESPONSE_HEADER {
        return None;
    }
    let op = PeerOp::from_u8(data[0])?;
    let status = PeerStatus::from_u8(data[1])?;
    Some((op, status, data[RESPONSE_HEADER..].to_vec()))
}

/// Reads one bundle chunk, checking the op and the `Ok` status in its header.
pub fn try_read_chunk(op: PeerOp, data: &[u8]) -> Option<(i32, Vec<u8>)> {
    if data.len() < CHUNK_HEADER {
        return None;
    }
    if data[0] != op as u8 || data[1] != PeerStatus::Ok as u8 {
        return None;
    }

    let index = ((data[2] as i32) << 24) | ((data[3] as i32) << 16) | ((data[4] as i32) << 8) | data[5] as i32;
    let length = ((data[6] as usize) << 8) | data[7] as usize;

    if index < 0 || length > CHUNK_SIZE || CHUNK_HEADER + length > data.len() {
        return None;
    }

    Some((index, data[CHUNK_HEADER..CHUNK_HEADER + length].to_vec()))
}

/// A human phrase for a status, from the shared string table.
pub fn explain(status: PeerStatus) -> String {
    match status {
        PeerStatus::Ok => t("peer.status.ok"),
        PeerStatus::BadCard => t("peer.status.badcard"),
        PeerStatus::BadRequest => t("peer.status.badrequest"),
        PeerStatus::Empty => t("peer.status.empty"),
        PeerStatus::Full => t("peer.status.full"),
        PeerStatus::NoService => t("peer.status.noservice"),
        PeerStatus::Stale => t("peer.status.stale"),
        PeerStatus::NoSite => t("peer.status.nosite"),
        PeerStatus::NotOwner => t("peer.status.notowner"),
        _ => t("peer.status.other"),
    }
}

/// A little forward cursor over a message payload; every read is bounds-checked
/// and returns `None` past the end, standing in for C#'s `EndOfStreamException`.
pub(crate) struct Cursor<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> Cursor<'a> {
    pub(crate) fn new(data: &'a [u8]) -> Self {
        Cursor { data, pos: 0 }
    }
    pub(crate) fn remaining(&self) -> usize {
        self.data.len() - self.pos
    }
    pub(crate) fn u8(&mut self) -> Option<u8> {
        let b = *self.data.get(self.pos)?;
        self.pos += 1;
        Some(b)
    }
    pub(crate) fn take(&mut self, n: usize) -> Option<&'a [u8]> {
        if self.remaining() < n {
            return None;
        }
        let s = &self.data[self.pos..self.pos + n];
        self.pos += n;
        Some(s)
    }
    /// Whatever is left, as the C# `ReadBytes(remaining)` does for an offer piece.
    pub(crate) fn rest(&mut self) -> &'a [u8] {
        let s = &self.data[self.pos..];
        self.pos = self.data.len();
        s
    }
    pub(crate) fn u16_le(&mut self) -> Option<u16> {
        let s = self.take(2)?;
        Some(u16::from_le_bytes([s[0], s[1]]))
    }
    pub(crate) fn i32_le(&mut self) -> Option<i32> {
        let s = self.take(4)?;
        Some(i32::from_le_bytes([s[0], s[1], s[2], s[3]]))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_round_trips() {
        let msg = request(PeerOp::FetchService, |w| w.extend_from_slice(&[1, 2, 3, 4])).unwrap();
        let (op, payload) = try_read_request(&msg).unwrap();
        assert_eq!(op, PeerOp::FetchService);
        assert_eq!(payload, vec![1, 2, 3, 4]);
    }

    #[test]
    fn response_round_trips() {
        let msg = response(PeerOp::Holders, PeerStatus::Ok, |w| {
            w.push(2);
            w.extend_from_slice(&[9; 40]);
        })
        .unwrap();
        let (op, status, payload) = try_read_response(&msg).unwrap();
        assert_eq!(op, PeerOp::Holders);
        assert_eq!(status, PeerStatus::Ok);
        assert_eq!(payload.len(), 1 + 40);
        assert_eq!(payload[0], 2);
    }

    #[test]
    fn chunk_round_trips_with_big_endian_header() {
        let source: Vec<u8> = (0..200u32).map(|i| i as u8).collect();
        let c = chunk(PeerOp::CardsChunk, 258, &source, 10, 50);
        // index 258 = 0x0102, written big-endian in bytes 2..6.
        assert_eq!(&c[2..6], &[0, 0, 1, 2]);
        let (index, content) = try_read_chunk(PeerOp::CardsChunk, &c).unwrap();
        assert_eq!(index, 258);
        assert_eq!(content, source[10..60].to_vec());
    }

    #[test]
    fn unknown_op_and_status_are_rejected() {
        assert!(try_read_request(&[0]).is_none());
        assert!(try_read_response(&[1, 200]).is_none());
        assert!(try_read_request(&[]).is_none());
    }

    #[test]
    fn chunk_size_and_offer_piece_match_the_csharp() {
        // RelayCell.MaxDataSize is 496; headers are 8 and 5.
        assert_eq!(CHUNK_SIZE, MAX_DATA_SIZE - 8);
        assert_eq!(OFFER_PIECE, MAX_DATA_SIZE - 5);
    }
}
