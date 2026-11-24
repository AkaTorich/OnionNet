//! What a stream can be asked of — inside the network and out of it.
//!
//! Behind [`StreamOpener`] stands either an ordinary circuit to a node or an
//! end-to-end channel to a hidden service. The port proxy works over both and
//! knows nothing of the difference — which is exactly why the port stack was
//! made a shared one.
//!
//! [`InternetOpener`] can be asked only of an ordinary circuit: a hidden
//! service is an address inside the network and has nowhere to let anyone out
//! to. Whether the exit node agrees is its own affair — here we only ask.
//!
//! (The C# `IStreamOpener` and `IInternetOpener`.)

use crate::streams::message_channel::MessageChannel;
use std::sync::Arc;

/// Something a stream to an internal port can be asked of.
pub trait StreamOpener: Send + Sync {
    /// Opens a stream to a port. Returns `None` if the port is closed.
    fn open(&self, port: u16) -> Option<Arc<dyn MessageChannel>>;

    fn is_alive(&self) -> bool;
}

/// Something a stream out of the network can be asked of.
pub trait InternetOpener: Send + Sync {
    /// Opens a stream to an address outside the network. Returns `None` if the
    /// exit node refused or did not answer.
    fn open_to(&self, host: &str, port: u16) -> Option<Arc<dyn MessageChannel>>;

    fn is_alive(&self) -> bool;
}
