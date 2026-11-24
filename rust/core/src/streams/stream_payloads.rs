//! Building and parsing the stream's service cells, and the network's internal
//! ports.
//!
//! The internal ports are arranged like TCP: every node has its own port space
//! of `1..=65535`, and a request always goes to a "node, port" pair. The
//! difference is that a port here is virtual — it lives inside a circuit and
//! has nothing to do with which ports the machine has open to the outside. To
//! the outside a node has exactly one port open, the one the relay works on.
//!
//! The low numbers are reserved for the service protocols; everything else the
//! node's owner hands out themselves — usually proxying to their own local
//! services.

use crate::streams::stream_end_reason::StreamEndReason;
use crate::text::loc;
use std::fmt;

/// The reserved virtual ports of the StalkNet network.
pub mod well_known_ports {
    /// Every relay's own desk: it hands out the cards it knows, takes in cards
    /// offered to it and keeps the records the network files under keys closest
    /// to it.
    pub const PEERS: u16 = 1;

    /// Shared folders.
    pub const FOLDERS: u16 = 2;

    /// A hidden service's introduction point.
    pub const INTRO_POINT: u16 = 3;

    /// The meeting point of a client and a hidden service.
    pub const RENDEZVOUS: u16 = 4;

    /// Torrent pieces: whoever holds a bundle hands it out here.
    pub const SWARM: u16 = 5;

    /// The anonymous way out to the internet, reached through a hidden address.
    pub const EXIT: u16 = 6;

    /// From this number on, the ports are the owner's to hand out.
    pub const FIRST_USER_PORT: u16 = 1024;
}

/// The longest address that fits into one cell.
pub const MAX_HOST_BYTES: usize = 255;

/// What went wrong while building a `BeginTo` payload. Mirrors the C#
/// argument exceptions, which the single caller catches and turns into a
/// refused stream.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PayloadError {
    /// No address was given.
    EmptyHost,
    /// The port is zero or out of range.
    PortOutOfRange,
    /// The address is longer than [`MAX_HOST_BYTES`].
    HostTooLong,
}

impl fmt::Display for PayloadError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PayloadError::EmptyHost => write!(f, "no address was given"),
            PayloadError::PortOutOfRange => write!(f, "the port is out of range"),
            PayloadError::HostTooLong => write!(f, "the address is longer than {MAX_HOST_BYTES} bytes"),
        }
    }
}

impl std::error::Error for PayloadError {}

/// Begin: which internal port we are asking for.
pub fn begin(port: u16) -> Vec<u8> {
    vec![(port >> 8) as u8, port as u8]
}

/// Reads a `Begin` payload. `None` if it is malformed or names port zero.
pub fn try_read_begin(data: &[u8]) -> Option<u16> {
    if data.len() < 2 {
        return None;
    }
    let port = ((data[0] as u16) << 8) | data[1] as u16;
    if port == 0 {
        None
    } else {
        Some(port)
    }
}

/// Connected: the port is open, data may be sent.
pub fn connected(port: u16) -> Vec<u8> {
    begin(port)
}

/// BeginTo: where outside the network the guest is asking to go.
///
/// The layout is the same as in an Extend cell — address length (1), address,
/// port (2) — so that there is one way of writing an address in this protocol
/// rather than two.
pub fn begin_to(host: &str, port: u16) -> Result<Vec<u8>, PayloadError> {
    if host.is_empty() {
        return Err(PayloadError::EmptyHost);
    }
    if port == 0 {
        return Err(PayloadError::PortOutOfRange);
    }

    let host_bytes = host.as_bytes();
    if host_bytes.len() > MAX_HOST_BYTES {
        return Err(PayloadError::HostTooLong);
    }

    let mut payload = Vec::with_capacity(1 + host_bytes.len() + 2);
    payload.push(host_bytes.len() as u8);
    payload.extend_from_slice(host_bytes);
    payload.push((port >> 8) as u8);
    payload.push(port as u8);
    Ok(payload)
}

/// Reads a `BeginTo` payload. `None` if it is malformed, carries an empty or
/// blank host, or names port zero.
pub fn try_read_begin_to(data: &[u8]) -> Option<(String, u16)> {
    if data.len() < 4 {
        return None;
    }

    let length = data[0] as usize;
    if length == 0 || data.len() < 1 + length + 2 {
        return None;
    }

    let host = std::str::from_utf8(&data[1..1 + length]).ok()?.to_string();
    if host.trim().is_empty() {
        return None;
    }

    let port = ((data[1 + length] as u16) << 8) | data[1 + length + 1] as u16;
    if port == 0 {
        None
    } else {
        Some((host, port))
    }
}

/// End: one byte, the reason.
pub fn end(reason: StreamEndReason) -> Vec<u8> {
    vec![reason.as_u8()]
}

/// Reads an `End` payload. An empty or undefined value reads as
/// [`StreamEndReason::Done`], exactly as the C#.
pub fn read_end(data: &[u8]) -> StreamEndReason {
    if data.is_empty() {
        return StreamEndReason::Done;
    }
    StreamEndReason::from_u8(data[0]).unwrap_or(StreamEndReason::Done)
}

/// A short, human-readable reason for the log and the window.
pub fn explain(reason: StreamEndReason) -> String {
    let key = match reason {
        StreamEndReason::Done => "stream.end.done",
        StreamEndReason::PortClosed => "stream.end.portclosed",
        StreamEndReason::ConnectFailed => "stream.end.connectfailed",
        StreamEndReason::TooManyStreams => "stream.end.toomany",
        StreamEndReason::BadRequest => "stream.end.badrequest",
        StreamEndReason::ServerError => "stream.end.servererror",
        // CircuitGone and NotAllowed fall through to the generic phrase, as in C#.
        StreamEndReason::CircuitGone | StreamEndReason::NotAllowed => "stream.end.broken",
    };
    loc::t(key)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reserved_ports_are_fixed() {
        assert_eq!(well_known_ports::PEERS, 1);
        assert_eq!(well_known_ports::FOLDERS, 2);
        assert_eq!(well_known_ports::INTRO_POINT, 3);
        assert_eq!(well_known_ports::RENDEZVOUS, 4);
        assert_eq!(well_known_ports::SWARM, 5);
        assert_eq!(well_known_ports::EXIT, 6);
        assert_eq!(well_known_ports::FIRST_USER_PORT, 1024);
    }

    #[test]
    fn begin_round_trips() {
        for port in [1u16, 2, 6, 1024, 8080, 65535] {
            let bytes = begin(port);
            assert_eq!(bytes, vec![(port >> 8) as u8, port as u8]);
            assert_eq!(try_read_begin(&bytes), Some(port));
        }
    }

    #[test]
    fn begin_rejects_zero_and_short() {
        assert_eq!(try_read_begin(&begin(0)), None);
        assert_eq!(try_read_begin(&[7]), None);
        assert_eq!(try_read_begin(&[]), None);
    }

    #[test]
    fn connected_matches_begin() {
        assert_eq!(connected(6), begin(6));
    }

    #[test]
    fn begin_to_round_trips() {
        let payload = begin_to("example.com", 443).unwrap();
        // 1 (length) + 11 (host) + 2 (port)
        assert_eq!(payload.len(), 1 + "example.com".len() + 2);
        assert_eq!(payload[0] as usize, "example.com".len());
        let (host, port) = try_read_begin_to(&payload).unwrap();
        assert_eq!(host, "example.com");
        assert_eq!(port, 443);
    }

    #[test]
    fn begin_to_rejects_bad_input() {
        assert_eq!(begin_to("", 80), Err(PayloadError::EmptyHost));
        assert_eq!(begin_to("host", 0), Err(PayloadError::PortOutOfRange));
        let too_long = "a".repeat(MAX_HOST_BYTES + 1);
        assert_eq!(begin_to(&too_long, 80), Err(PayloadError::HostTooLong));
    }

    #[test]
    fn begin_to_parse_rejects_malformed() {
        assert_eq!(try_read_begin_to(&[0, 0, 0, 0]), None); // zero length
        assert_eq!(try_read_begin_to(&[5, b'h', b'i']), None); // truncated
    }

    #[test]
    fn end_round_trips() {
        for reason in [
            StreamEndReason::Done,
            StreamEndReason::PortClosed,
            StreamEndReason::ConnectFailed,
            StreamEndReason::TooManyStreams,
            StreamEndReason::BadRequest,
            StreamEndReason::ServerError,
            StreamEndReason::CircuitGone,
            StreamEndReason::NotAllowed,
        ] {
            assert_eq!(read_end(&end(reason)), reason);
        }
    }

    #[test]
    fn end_defaults_to_done() {
        assert_eq!(read_end(&[]), StreamEndReason::Done);
        assert_eq!(read_end(&[200]), StreamEndReason::Done);
    }
}
