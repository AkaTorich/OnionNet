//! The master-less network (`StalkNet.Core/Peers`).
//!
//! Nobody owns the relay list and nobody assigns where records live. Each node
//! gathers its own view of the relays from signed, proof-backed cards
//! ([`peer_view`]); who stores which record is the three relays closest by XOR to
//! the record's key ([`placement`]); and every relay runs a desk on virtual port
//! 1 ([`peer_service`]) that other nodes reach over a circuit ([`peer_client`]).
//! A relay's pass lives in `node.pass` beside its identity ([`relay_pass`]); the
//! view is kept across runs in `node.peers`.
//!
//! The layout mirrors the C# file split, and wire formats, virtual ports, record
//! kinds, time windows and constants are kept byte-identical.

pub mod holder_proof;
pub mod peer_client;
pub mod peer_protocol;
pub mod peer_service;
pub mod peer_view;
pub mod placement;
pub mod relay_pass;
pub mod store_pass;

pub use peer_client::{CircuitDeskLink, DeskLink, PeerClient};
pub use peer_protocol::{PeerOp, PeerStatus, CHUNK_SIZE, MAX_OFFERED_CARD, OFFER_PIECE};
pub use peer_service::{
    DeskSession, PeerDesk, PeerService, RecordParsers, ServiceFields, SiteFields, MAX_CARDS_PER_ANSWER, PEERS_PORT,
};
pub use peer_view::{CardVerdict, PeerView, FUTURE_TOLERANCE_TICKS, MAX_AGE_TICKS, MAX_CARDS};
pub use placement::{compare_distance, keepers, point, RecordKind, REPLICAS, SEARCHED};
pub use relay_pass::{obtain, path_for};
