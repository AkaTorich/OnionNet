//! Transport (`StalkNet.Core/Transport`): link encryption between neighbours,
//! the cell channel, the relay node and the circuit. Ported bottom-up.

pub mod cell_channel;
pub mod circuit;
pub mod link_crypto;
pub mod relay_node;
pub mod service_context;

pub use cell_channel::{CellChannel, ChannelError};
pub use circuit::{Circuit, CircuitError};
pub use link_crypto::LinkCrypto;
pub use relay_node::RelayNode;
pub use service_context::ServiceContext;
