//! Streams and the exit to the internet (`StalkNet.Core/Streams`).
//!
//! The port stack (TCP-like virtual ports inside a circuit), the SOCKS5 and
//! local-port doors for the programs on this machine, the self-rebuilding exit
//! tunnel, and the multiplexer that carries many streams over one circuit. The
//! wire formats — the SOCKS5 opcodes, the reserved virtual ports, the cell and
//! stream framing and the message ceilings — are kept identical to the C#.

pub mod channel_limits;
pub mod exit_policy;
pub mod exit_tunnel;
pub mod local_port_forwarder;
pub mod message_channel;
pub mod multiplexed_circuit;
pub mod port_stack;
pub mod socks_proxy;
pub mod stream_end_reason;
pub mod stream_opener;
pub mod stream_payloads;
pub mod tcp_port_service;

pub use channel_limits::{CELL_PAYLOAD, END_TO_END_TAG, MAX_APPLICATION_MESSAGE, MUX_HEADER};
pub use exit_policy::{is_own_network, ExitPolicy};
pub use exit_tunnel::ExitTunnel;
pub use local_port_forwarder::LocalPortForwarder;
pub use message_channel::MessageChannel;
pub use multiplexed_circuit::{ClientStream, MultiplexedCircuit};
pub use port_stack::{PortService, PortStack, ServerStream};
pub use socks_proxy::SocksProxy;
pub use stream_end_reason::StreamEndReason;
pub use stream_opener::{InternetOpener, StreamOpener};
pub use stream_payloads::{well_known_ports, PayloadError};
pub use tcp_port_service::TcpPortService;
