//! The node runtime: the whole node in one place — identity, the relay, the
//! port stack, the desk, the hidden service, the way out. The window speaks to
//! this and knows nothing of cells and circuits. A port of `NodeController`.

pub mod node;

pub use node::{Node, NodeConfig, NodeStatus};
