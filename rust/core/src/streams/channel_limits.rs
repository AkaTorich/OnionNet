//! How many bytes are left to an application protocol after every wrapper.
//!
//! It is computed once and in one place, deliberately. A message may go by two
//! different roads — an ordinary stream to a port on someone else's node, or
//! through a meeting point to a hidden service — and on the second road the
//! end-to-end cipher tag and the multiplexer header are added to it. If every
//! layer counted its own ceiling, sooner or later a message that fits one road
//! would not fit the other, and it would come to light at the most awkward
//! moment: while downloading a large file from someone else.
//!
//! So there is one ceiling — the narrowest possible — and it holds everywhere.

use crate::protocol::relay_cell::MAX_DATA_SIZE;

/// The useful part of a Relay cell.
pub const CELL_PAYLOAD: usize = MAX_DATA_SIZE; // 496

/// The end-to-end cipher tag between a client and a hidden service.
pub const END_TO_END_TAG: usize = 16;

/// The multiplexer header inside an end-to-end channel: the stream and the command.
pub const MUX_HEADER: usize = 3;

/// The ceiling for one application message. It fits either road.
pub const MAX_APPLICATION_MESSAGE: usize = CELL_PAYLOAD - END_TO_END_TAG - MUX_HEADER; // 477

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn window_math_matches_csharp() {
        assert_eq!(CELL_PAYLOAD, 496);
        assert_eq!(END_TO_END_TAG, 16);
        assert_eq!(MUX_HEADER, 3);
        assert_eq!(MAX_APPLICATION_MESSAGE, 477);
        assert_eq!(MAX_APPLICATION_MESSAGE, CELL_PAYLOAD - END_TO_END_TAG - MUX_HEADER);
    }
}
