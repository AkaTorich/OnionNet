//! Building and parsing the folder service's messages (the C# `FolderProtocol`).
//!
//! Everything must fit into one cell: the useful part of a message. Long answers
//! — a file list, contents — come as a batch of cells, each self-contained and
//! carrying its own number. The byte layout here is kept identical to the C#
//! original: little-endian for the `BinaryWriter` fields, and a hand-built
//! big-endian header for a file chunk.

use crate::streams::channel_limits;

/// What a guest asks the folder for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum FolderOp {
    /// Say hello and find out which folders are here.
    Hello = 1,
    /// Get the challenge for the Argon2id pass before signing in.
    Challenge = 2,
    /// Sign in with a Windows account.
    Login = 3,
    /// List a folder's contents.
    ListFiles = 4,
    /// Open a file for reading, learn its size.
    OpenFile = 5,
    /// Fetch a batch of pieces of an open file.
    ReadChunks = 6,
    /// Close the file.
    CloseFile = 7,
}

impl FolderOp {
    /// Mirrors the C# `Enum.IsDefined` guard: an undefined code is rejected.
    pub fn from_u8(value: u8) -> Option<FolderOp> {
        match value {
            1 => Some(FolderOp::Hello),
            2 => Some(FolderOp::Challenge),
            3 => Some(FolderOp::Login),
            4 => Some(FolderOp::ListFiles),
            5 => Some(FolderOp::OpenFile),
            6 => Some(FolderOp::ReadChunks),
            7 => Some(FolderOp::CloseFile),
            _ => None,
        }
    }
}

/// How the request ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum FolderStatus {
    Ok = 0,
    /// The folder requires signing in with an account.
    NeedLogin = 1,
    /// Windows refused this account.
    Denied = 2,
    /// There is no such folder.
    NoSuchFolder = 3,
    /// There is no such file, or it is gone.
    NoSuchFile = 4,
    /// The request was not parsed.
    BadRequest = 5,
    /// Too many failed sign-ins.
    Throttled = 6,
    /// The Argon2id pass was not attached, or it does not check out.
    BadProof = 7,
    /// Something broke on the owner's side.
    ServerError = 8,
    /// Too many open files in one session.
    TooManyFiles = 9,
}

impl FolderStatus {
    pub fn from_u8(value: u8) -> Option<FolderStatus> {
        match value {
            0 => Some(FolderStatus::Ok),
            1 => Some(FolderStatus::NeedLogin),
            2 => Some(FolderStatus::Denied),
            3 => Some(FolderStatus::NoSuchFolder),
            4 => Some(FolderStatus::NoSuchFile),
            5 => Some(FolderStatus::BadRequest),
            6 => Some(FolderStatus::Throttled),
            7 => Some(FolderStatus::BadProof),
            8 => Some(FolderStatus::ServerError),
            9 => Some(FolderStatus::TooManyFiles),
            _ => None,
        }
    }
}

const REQUEST_HEADER: usize = 1; // the operation code
const RESPONSE_HEADER: usize = 2; // the operation code + the status
const CHUNK_HEADER: usize = RESPONSE_HEADER + 4 + 2; // + the piece number + the length

/// The ceiling for one of the service's messages.
///
/// Sixteen bytes smaller than a cell on purpose: the same message may go not over
/// an ordinary stream but over an end-to-end channel to a hidden service, where
/// that much is taken by the end-to-end cipher's tag. One ceiling for both roads
/// is safer than two different ones and an everlasting risk of mixing them up.
pub const MAX_MESSAGE_SIZE: usize = channel_limits::MAX_APPLICATION_MESSAGE; // 477

/// How many bytes of a file fit into one message.
pub const CHUNK_SIZE: usize = MAX_MESSAGE_SIZE - CHUNK_HEADER; // 469

/// How many pieces may be asked for at once.
pub const MAX_CHUNKS_PER_REQUEST: u16 = 32;

/// One guest will not open more files at once than this.
pub const MAX_OPEN_FILES_PER_SESSION: usize = 8;

/// The limit on string length in messages — a guard against bloat.
pub const MAX_STRING_BYTES: usize = 255;

// ---- A little-endian writer, standing in for C# BinaryWriter -----------------

/// Builds a message body with the same byte order as the C# `BinaryWriter`
/// (little-endian for multi-byte integers, one byte for a bool).
#[derive(Default)]
pub struct MessageWriter {
    buf: Vec<u8>,
}

impl MessageWriter {
    pub fn new() -> MessageWriter {
        MessageWriter { buf: Vec::new() }
    }

    pub fn u8(&mut self, value: u8) {
        self.buf.push(value);
    }

    pub fn bool(&mut self, value: bool) {
        self.buf.push(if value { 1 } else { 0 });
    }

    pub fn u16_le(&mut self, value: u16) {
        self.buf.extend_from_slice(&value.to_le_bytes());
    }

    pub fn i32_le(&mut self, value: i32) {
        self.buf.extend_from_slice(&value.to_le_bytes());
    }

    pub fn u32_le(&mut self, value: u32) {
        self.buf.extend_from_slice(&value.to_le_bytes());
    }

    pub fn i64_le(&mut self, value: i64) {
        self.buf.extend_from_slice(&value.to_le_bytes());
    }

    pub fn bytes(&mut self, data: &[u8]) {
        self.buf.extend_from_slice(data);
    }

    /// A string with a one-byte length. Nothing in a message is longer than 255
    /// bytes; an over-long string is truncated on a character boundary rather
    /// than overflowing the length byte (the C# throws here, but every real
    /// caller keeps names within the limit).
    pub fn text(&mut self, value: &str) {
        let mut bytes = value.as_bytes();
        if bytes.len() > MAX_STRING_BYTES {
            let mut cut = MAX_STRING_BYTES;
            while cut > 0 && !value.is_char_boundary(cut) {
                cut -= 1;
            }
            bytes = &value.as_bytes()[..cut];
        }
        debug_assert!(bytes.len() <= MAX_STRING_BYTES);
        self.buf.push(bytes.len() as u8);
        self.buf.extend_from_slice(bytes);
    }

    pub fn into_vec(self) -> Vec<u8> {
        self.buf
    }
}

// ---- A reader, standing in for C# BinaryReader -------------------------------

/// Reads a message body in the C# `BinaryReader` byte order. Every read returns
/// `None` at end of input, which the callers map to a `BadRequest` — the C#
/// `EndOfStreamException` caught in `FolderService.Handle`.
pub struct MessageReader<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> MessageReader<'a> {
    pub fn new(data: &'a [u8]) -> MessageReader<'a> {
        MessageReader { data, pos: 0 }
    }

    pub fn u8(&mut self) -> Option<u8> {
        let b = *self.data.get(self.pos)?;
        self.pos += 1;
        Some(b)
    }

    pub fn bool(&mut self) -> Option<bool> {
        Some(self.u8()? != 0)
    }

    pub fn u16_le(&mut self) -> Option<u16> {
        let b = self.take(2)?;
        Some(u16::from_le_bytes([b[0], b[1]]))
    }

    pub fn i32_le(&mut self) -> Option<i32> {
        let b = self.take(4)?;
        Some(i32::from_le_bytes([b[0], b[1], b[2], b[3]]))
    }

    pub fn u32_le(&mut self) -> Option<u32> {
        let b = self.take(4)?;
        Some(u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
    }

    pub fn i64_le(&mut self) -> Option<i64> {
        let b = self.take(8)?;
        let mut a = [0u8; 8];
        a.copy_from_slice(b);
        Some(i64::from_le_bytes(a))
    }

    /// Exactly `n` bytes, or `None` if fewer remain (the C# `ReadBytes` plus its
    /// `bytes.Length != length` guard).
    pub fn take(&mut self, n: usize) -> Option<&'a [u8]> {
        let end = self.pos.checked_add(n)?;
        if end > self.data.len() {
            return None;
        }
        let slice = &self.data[self.pos..end];
        self.pos = end;
        Some(slice)
    }

    /// The remaining bytes, advancing to the end. Mirrors reading "whatever is
    /// left": the C# `ReadBytes(n)` returns however many bytes remain.
    pub fn rest(&mut self) -> &'a [u8] {
        let slice = &self.data[self.pos..];
        self.pos = self.data.len();
        slice
    }

    /// A one-byte-length-prefixed UTF-8 string.
    pub fn text(&mut self) -> Option<String> {
        let len = self.u8()? as usize;
        let bytes = self.take(len)?;
        Some(String::from_utf8_lossy(bytes).into_owned())
    }
}

// ---- Building ----------------------------------------------------------------

/// Builds a request: the op byte, then whatever `body` writes.
pub fn request<F: FnOnce(&mut MessageWriter)>(op: FolderOp, body: F) -> Vec<u8> {
    let mut w = MessageWriter::new();
    w.u8(op as u8);
    body(&mut w);
    let data = w.into_vec();
    debug_assert!(data.len() <= MAX_MESSAGE_SIZE, "the request does not fit into a message");
    data
}

/// Builds a response: the op byte, the status byte, then whatever `body` writes.
pub fn response<F: FnOnce(&mut MessageWriter)>(op: FolderOp, status: FolderStatus, body: F) -> Vec<u8> {
    let mut w = MessageWriter::new();
    w.u8(op as u8);
    w.u8(status as u8);
    body(&mut w);
    let data = w.into_vec();
    debug_assert!(data.len() <= MAX_MESSAGE_SIZE, "the answer does not fit into a message");
    data
}

/// A cell with a piece of a file: the piece number, the length, the bytes.
///
/// The header is laid out by hand in big-endian order, exactly as the C#
/// `Chunk`, independent of the little-endian `BinaryWriter`.
pub fn chunk(index: i32, source: &[u8], offset: usize, length: usize) -> Vec<u8> {
    assert!(length <= CHUNK_SIZE, "chunk length out of range");

    let index = index as u32;
    let mut data = vec![0u8; CHUNK_HEADER + length];
    data[0] = FolderOp::ReadChunks as u8;
    data[1] = FolderStatus::Ok as u8;
    data[2] = (index >> 24) as u8;
    data[3] = (index >> 16) as u8;
    data[4] = (index >> 8) as u8;
    data[5] = index as u8;
    data[6] = (length >> 8) as u8;
    data[7] = length as u8;
    data[CHUNK_HEADER..].copy_from_slice(&source[offset..offset + length]);
    data
}

// ---- Parsing -----------------------------------------------------------------

/// Parses a request: the op and the remaining payload. `None` on a malformed or
/// unknown op.
pub fn try_read_request(data: &[u8]) -> Option<(FolderOp, Vec<u8>)> {
    if data.len() < REQUEST_HEADER {
        return None;
    }
    let op = FolderOp::from_u8(data[0])?;
    Some((op, data[REQUEST_HEADER..].to_vec()))
}

/// Parses a response: the op, the status and the remaining payload.
pub fn try_read_response(data: &[u8]) -> Option<(FolderOp, FolderStatus, Vec<u8>)> {
    if data.len() < RESPONSE_HEADER {
        return None;
    }
    let op = FolderOp::from_u8(data[0])?;
    let status = FolderStatus::from_u8(data[1])?;
    Some((op, status, data[RESPONSE_HEADER..].to_vec()))
}

/// Parses a file chunk: the piece number and its content. `None` if the cell is
/// not an `Ok` `ReadChunks` chunk or is malformed.
pub fn try_read_chunk(data: &[u8]) -> Option<(i32, Vec<u8>)> {
    if data.len() < CHUNK_HEADER {
        return None;
    }
    if data[0] != FolderOp::ReadChunks as u8 || data[1] != FolderStatus::Ok as u8 {
        return None;
    }

    let index = ((data[2] as u32) << 24) | ((data[3] as u32) << 16) | ((data[4] as u32) << 8) | data[5] as u32;
    let index = index as i32;
    let length = ((data[6] as usize) << 8) | data[7] as usize;

    if index < 0 {
        return None;
    }
    if length > CHUNK_SIZE || CHUNK_HEADER + length > data.len() {
        return None;
    }

    Some((index, data[CHUNK_HEADER..CHUNK_HEADER + length].to_vec()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sizes_match_csharp() {
        assert_eq!(MAX_MESSAGE_SIZE, 477);
        assert_eq!(CHUNK_HEADER, 8);
        assert_eq!(CHUNK_SIZE, 469);
    }

    #[test]
    fn request_roundtrip() {
        let msg = request(FolderOp::Challenge, |w| w.text("Alice"));
        let (op, payload) = try_read_request(&msg).unwrap();
        assert_eq!(op, FolderOp::Challenge);
        let mut r = MessageReader::new(&payload);
        assert_eq!(r.text().unwrap(), "Alice");
    }

    #[test]
    fn response_roundtrip_all_field_types() {
        let msg = response(FolderOp::OpenFile, FolderStatus::Ok, |w| {
            w.u32_le(0xDEAD_BEEF);
            w.i64_le(-1234567890123);
            w.bool(true);
            w.u16_le(0x0102);
            w.i32_le(-5);
        });
        let (op, status, payload) = try_read_response(&msg).unwrap();
        assert_eq!(op, FolderOp::OpenFile);
        assert_eq!(status, FolderStatus::Ok);
        let mut r = MessageReader::new(&payload);
        assert_eq!(r.u32_le().unwrap(), 0xDEAD_BEEF);
        assert_eq!(r.i64_le().unwrap(), -1234567890123);
        assert!(r.bool().unwrap());
        assert_eq!(r.u16_le().unwrap(), 0x0102);
        assert_eq!(r.i32_le().unwrap(), -5);
        assert!(r.u8().is_none()); // nothing left
    }

    #[test]
    fn chunk_roundtrip_and_header_is_big_endian() {
        let src: Vec<u8> = (0..100u8).collect();
        let cell = chunk(0x01020304, &src, 10, 20);
        // Big-endian index in bytes 2..6.
        assert_eq!(&cell[2..6], &[0x01, 0x02, 0x03, 0x04]);
        // Big-endian length in bytes 6..8.
        assert_eq!(&cell[6..8], &[0x00, 20]);

        let (index, content) = try_read_chunk(&cell).unwrap();
        assert_eq!(index, 0x01020304);
        assert_eq!(content, &src[10..30]);
    }

    #[test]
    fn unknown_op_and_status_are_rejected() {
        assert!(try_read_request(&[99]).is_none());
        assert!(try_read_request(&[]).is_none());
        assert!(try_read_response(&[1, 99]).is_none()); // bad status
        assert!(try_read_response(&[99, 0]).is_none()); // bad op
    }

    #[test]
    fn chunk_rejects_non_chunk_cells() {
        let resp = response(FolderOp::ReadChunks, FolderStatus::NoSuchFile, |_| {});
        assert!(try_read_chunk(&resp).is_none());
    }

    #[test]
    fn text_truncates_over_long_names_safely() {
        let long = "a".repeat(300);
        let mut w = MessageWriter::new();
        w.text(&long);
        let data = w.into_vec();
        assert_eq!(data[0] as usize, MAX_STRING_BYTES);
        assert_eq!(data.len(), 1 + MAX_STRING_BYTES);
    }
}
