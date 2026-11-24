//! Hidden services (`StalkNet.Core/Hidden`): a service reachable at an address
//! that reveals nothing of where it runs. Ported bottom-up; the self-contained
//! pieces (the descriptor, the protocol messages, the end-to-end channel, the
//! circuit factory) land first, the orchestration once Peers and Streams are in.

pub mod circuit_factory;
pub mod e2e_channel;
pub mod e2e_session;
pub mod hidden_connection;
pub mod hidden_mux;
pub mod hidden_protocol;
pub mod hidden_service;
pub mod hidden_service_client;
pub mod intro_point_service;
pub mod rendezvous_service;
pub mod service_descriptor;

pub use circuit_factory::CircuitFactory;
pub use e2e_channel::E2EChannel;
pub use e2e_session::E2ESession;
pub use hidden_connection::HiddenConnection;
pub use hidden_mux::HiddenMux;
pub use hidden_protocol::{HiddenStatus, IntroOp, RendezvousOp};
pub use hidden_service::HiddenService;
pub use hidden_service_client::HiddenServiceError;
pub use intro_point_service::IntroPointService;
pub use rendezvous_service::RendezvousService;
pub use service_descriptor::ServiceDescriptor;
