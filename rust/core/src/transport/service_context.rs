//! The handle a node's service answers a client through, over the circuit.
//!
//! One instance lives exactly as long as the circuit and is the key to the
//! session state: whom the guest signed in as, which files they opened. What is
//! behind the circuit — who the client is, where they are from — is unknown
//! here and there is nowhere to learn it from. That is the point.

use crate::protocol::relay_cell::RelayCell;

pub trait ServiceContext: Send + Sync {
    /// Sends a cell towards the client. May be called any number of times.
    fn send(&self, cell: RelayCell);

    /// Whether the circuit is still alive. Answers to a dead circuit are
    /// dropped quietly.
    fn is_alive(&self) -> bool;
}
