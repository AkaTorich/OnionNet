//! The messages of the piece exchange.
//!
//! Arranged as in the folder service: the operation, then for an answer the
//! status. Anything longer than a message — the header, the mark of pieces, a
//! piece — goes in numbered chunks, asked for by ranges of at most
//! `MAX_CHUNKS_PER_REQUEST`. The asker sets the pace: a holder never pushes more
//! than was asked for.
//!
//! Request and response integers are little-endian (the C# `BinaryWriter`); a
//! chunk's own index and length in the chunk header are big-endian, exactly as
//! the C# builds them by hand. Both are kept byte-for-byte.

/// What a peer asks a holder of a bundle for.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum SwarmOp {
    /// Pick the bundle by its info hash and learn what is here.
    Open = 1,
    /// A range of the "which pieces are here" mark.
    Bitfield = 2,
    /// A range of the header.
    Header = 3,
    /// A range of one piece.
    Piece = 4,
}

impl SwarmOp {
    pub fn from_u8(b: u8) -> Option<SwarmOp> {
        match b {
            1 => Some(SwarmOp::Open),
            2 => Some(SwarmOp::Bitfield),
            3 => Some(SwarmOp::Header),
            4 => Some(SwarmOp::Piece),
            _ => None,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum SwarmStatus {
    Ok = 0,
    /// There is no such bundle here.
    NoBundle = 1,
    /// That piece is not here (yet).
    NoPiece = 2,
    BadRequest = 3,
    /// No bundle was picked on this stream.
    NotOpen = 4,
    ServerError = 5,
}

impl SwarmStatus {
    pub fn from_u8(b: u8) -> Option<SwarmStatus> {
        match b {
            0 => Some(SwarmStatus::Ok),
            1 => Some(SwarmStatus::NoBundle),
            2 => Some(SwarmStatus::NoPiece),
            3 => Some(SwarmStatus::BadRequest),
            4 => Some(SwarmStatus::NotOpen),
            5 => Some(SwarmStatus::ServerError),
            _ => None,
        }
    }
}

const RESPONSE_HEADER: usize = 2;
const CHUNK_HEADER: usize = RESPONSE_HEADER + 4 + 2;

/// The largest application message the stream layer carries.
///
/// This is `ChannelLimits.MaxApplicationMessage` from the Streams layer, which
/// is being ported separately; it is inlined here as a constant so this module
/// does not depend on that one. `CellPayload(509) - EndToEndTag(16) -
/// MuxHeader(16) = 477`.
pub const MAX_MESSAGE_SIZE: usize = 477;

/// How many bytes of a chunk carry payload: `477 - 8 = 469`.
pub const CHUNK_SIZE: usize = MAX_MESSAGE_SIZE - CHUNK_HEADER;

pub const MAX_CHUNKS_PER_REQUEST: usize = 64;

pub fn chunks_for(length: i64) -> i32 {
    ((length + CHUNK_SIZE as i64 - 1) / CHUNK_SIZE as i64) as i32
}

/// A request message: `op | payload`.
pub fn request(op: SwarmOp, payload: &[u8]) -> Vec<u8> {
    let mut data = Vec::with_capacity(1 + payload.len());
    data.push(op as u8);
    data.extend_from_slice(payload);
    debug_assert!(data.len() <= MAX_MESSAGE_SIZE, "the message does not fit");
    data
}

/// A response message: `op | status | payload`.
pub fn response(op: SwarmOp, status: SwarmStatus, payload: &[u8]) -> Vec<u8> {
    let mut data = Vec::with_capacity(RESPONSE_HEADER + payload.len());
    data.push(op as u8);
    data.push(status as u8);
    data.extend_from_slice(payload);
    debug_assert!(data.len() <= MAX_MESSAGE_SIZE, "the message does not fit");
    data
}

/// One chunk: the operation, `Ok`, the chunk number (big-endian 4), the length
/// (big-endian 2), the bytes.
pub fn chunk(op: SwarmOp, index: i32, source: &[u8], offset: usize, length: usize) -> Vec<u8> {
    assert!(length <= CHUNK_SIZE, "a chunk is at most {CHUNK_SIZE} bytes");

    let mut data = vec![0u8; CHUNK_HEADER + length];
    data[0] = op as u8;
    data[1] = SwarmStatus::Ok as u8;
    data[2] = (index >> 24) as u8;
    data[3] = (index >> 16) as u8;
    data[4] = (index >> 8) as u8;
    data[5] = index as u8;
    data[6] = (length >> 8) as u8;
    data[7] = length as u8;
    data[CHUNK_HEADER..].copy_from_slice(&source[offset..offset + length]);
    data
}

/// Splits a request into its operation and the bytes after it.
pub fn try_read_request(data: &[u8]) -> Option<(SwarmOp, &[u8])> {
    if data.is_empty() {
        return None;
    }
    let op = SwarmOp::from_u8(data[0])?;
    Some((op, &data[1..]))
}

/// Splits a response into its operation, status and the bytes after them.
pub fn try_read_response(data: &[u8]) -> Option<(SwarmOp, SwarmStatus, &[u8])> {
    if data.len() < RESPONSE_HEADER {
        return None;
    }
    let op = SwarmOp::from_u8(data[0])?;
    let status = SwarmStatus::from_u8(data[1])?;
    Some((op, status, &data[RESPONSE_HEADER..]))
}

/// Reads a chunk's index and content, checking it is an `Ok` chunk for `op`.
pub fn try_read_chunk(op: SwarmOp, data: &[u8]) -> Option<(i32, &[u8])> {
    if data.len() < CHUNK_HEADER {
        return None;
    }
    if data[0] != op as u8 || data[1] != SwarmStatus::Ok as u8 {
        return None;
    }

    let index = ((data[2] as i32) << 24) | ((data[3] as i32) << 16) | ((data[4] as i32) << 8) | data[5] as i32;
    let length = ((data[6] as usize) << 8) | data[7] as usize;
    if index < 0 || length > CHUNK_SIZE || CHUNK_HEADER + length != data.len() {
        return None;
    }

    Some((index, &data[CHUNK_HEADER..]))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn chunk_sizes_match_the_csharp() {
        assert_eq!(MAX_MESSAGE_SIZE, 477);
        assert_eq!(CHUNK_SIZE, 469);
        assert_eq!(CHUNK_HEADER, 8);
    }

    #[test]
    fn request_response_round_trip() {
        let req = request(SwarmOp::Piece, &[1, 2, 3]);
        let (op, payload) = try_read_request(&req).unwrap();
        assert_eq!(op, SwarmOp::Piece);
        assert_eq!(payload, &[1, 2, 3]);

        let resp = response(SwarmOp::Open, SwarmStatus::NoBundle, &[9]);
        let (op, status, payload) = try_read_response(&resp).unwrap();
        assert_eq!(op, SwarmOp::Open);
        assert_eq!(status, SwarmStatus::NoBundle);
        assert_eq!(payload, &[9]);
    }

    #[test]
    fn chunk_round_trip_with_big_endian_header() {
        let source: Vec<u8> = (0u8..200).collect();
        let c = chunk(SwarmOp::Header, 0x010203, &source, 10, 50);
        // index big-endian in bytes 2..6
        assert_eq!(&c[2..6], &[0x00, 0x01, 0x02, 0x03]);
        assert_eq!(&c[6..8], &[0x00, 50]);
        let (index, content) = try_read_chunk(SwarmOp::Header, &c).unwrap();
        assert_eq!(index, 0x010203);
        assert_eq!(content, &source[10..60]);
    }

    #[test]
    fn chunks_for_rounds_up() {
        assert_eq!(chunks_for(0), 0);
        assert_eq!(chunks_for(1), 1);
        assert_eq!(chunks_for(CHUNK_SIZE as i64), 1);
        assert_eq!(chunks_for(CHUNK_SIZE as i64 + 1), 2);
    }
}
