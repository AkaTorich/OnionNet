//! A two-way exchange of messages — all an application protocol needs.
//!
//! Behind it lies either an ordinary stream to a port on someone else's node,
//! or an end-to-end channel to a hidden service through a meeting point. The
//! folder service works the same over both and never suspects the difference.
//!
//! (The C# `IMessageChannel`.)

use std::time::Duration;

/// A two-way exchange of messages.
///
/// The bound is `Send + Sync` because a channel is shared between the thread
/// that pours bytes into it and the thread that reads them back out, exactly as
/// the C# forwarders split the work across two threads.
pub trait MessageChannel: Send + Sync {
    /// Sends a message. Anything longer than one cell the implementation slices
    /// itself. A send on a closed channel is a quiet no-op, as the C# callers
    /// (which catch the exception and move on) effectively treat it.
    fn send(&self, message: &[u8]);

    /// Waits for the next message. Returns `None` if the channel closed or the
    /// wait ran out.
    fn receive(&self, timeout: Duration) -> Option<Vec<u8>>;

    fn is_open(&self) -> bool;

    fn close(&self);
}
