//! Why a stream closed.
//!
//! The byte values are part of the wire protocol: they travel in the single
//! data byte of an `End` cell (see [`crate::streams::stream_payloads`]), so they
//! must stay identical to the C# `StreamEndReason`.

/// Why the stream closed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum StreamEndReason {
    /// An orderly finish.
    Done = 0,

    /// Nobody is listening on that port.
    PortClosed = 1,

    /// The service is there, but the connection failed.
    ConnectFailed = 2,

    /// Too many streams in one circuit.
    TooManyStreams = 3,

    /// The request was not parsed.
    BadRequest = 4,

    /// Something broke on the owner's side.
    ServerError = 5,

    /// The circuit broke.
    CircuitGone = 6,

    /// The exit node does not let anyone out to that address or port.
    NotAllowed = 7,
}

impl StreamEndReason {
    /// The byte that stands for this reason on the wire.
    pub fn as_u8(self) -> u8 {
        self as u8
    }

    /// The reason a byte stands for, or `None` if the byte is not a defined
    /// value (mirrors C# `Enum.IsDefined`).
    pub fn from_u8(b: u8) -> Option<StreamEndReason> {
        Some(match b {
            0 => StreamEndReason::Done,
            1 => StreamEndReason::PortClosed,
            2 => StreamEndReason::ConnectFailed,
            3 => StreamEndReason::TooManyStreams,
            4 => StreamEndReason::BadRequest,
            5 => StreamEndReason::ServerError,
            6 => StreamEndReason::CircuitGone,
            7 => StreamEndReason::NotAllowed,
            _ => return None,
        })
    }
}
