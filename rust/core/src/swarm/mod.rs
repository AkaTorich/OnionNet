//! Encrypted, BitTorrent-style sharing (`StalkNet.Core/Swarm`).
//!
//! A bundle is a file or a folder cut into fixed-size pieces, each piece
//! encrypted and hashed. The header carries the hash of every piece and the
//! encrypted file list; the SHA-256 of the header is the bundle's info hash and
//! names it in the swarm. An `ont:` link carries the info hash and the content
//! key: whoever stores and hands out the pieces needs only the first and so
//! sees nothing but ciphertext.
//!
//! A site is the same machinery: its pages are a bundle, and a small record at
//! the storage nodes — filed under a hash of the site address and sealed with a
//! key grown from that address — points at the bundle that holds the current
//! version. The site is shown to an ordinary browser on `127.0.0.1`.
//!
//! The piece exchange answers on the torrent virtual port; an anonymous way out
//! to the internet answers on the exit virtual port, both reached through a
//! throwaway hidden address.
//!
//! The module mirrors the C# file split one-to-one. The byte layouts — the
//! header, the manifest, the `ont:` link, the protocol chunks, the site record
//! — are kept identical to the C# original, because they are on the wire and in
//! files. The pieces of plumbing that are being ported in other modules (the
//! relay service stack and the peer-storage records) are not depended on here;
//! what is needed from them is injected through the traits and closures each
//! submodule documents.

pub mod bundle_builder;
pub mod bundle_header;
pub mod bundle_link;
pub mod bundle_manifest;
pub mod exit_service;
pub mod local_site_server;
pub mod site_record;
pub mod swarm_download;
pub mod swarm_protocol;
pub mod swarm_service;
pub mod swarm_store;

pub use bundle_builder::{build, extract};
pub use bundle_header::BundleHeader;
pub use bundle_link::BundleLink;
pub use bundle_manifest::{BundleFile, BundleKind, BundleManifest};
pub use exit_service::{ExitRefusal, ExitService, ExitSession, ExitStream, HiddenExitOpener, StreamOpener};
pub use local_site_server::LocalSiteServer;
pub use site_record::SiteRecord;
pub use swarm_download::SwarmDownload;
pub use swarm_protocol::{SwarmOp, SwarmStatus};
pub use swarm_service::{MessageChannel, ReplyStream, SwarmPeer, SwarmService, SwarmSession};
pub use swarm_store::{StoredBundle, SwarmStore};

/// Why a swarm operation failed.
///
/// The C# code uses exceptions (`CryptographicException`, `FormatException`,
/// `InvalidOperationException`, `IOException`); the Rust port gathers them into
/// one error so call sites stay `Result`-shaped. The variants map onto those
/// exception kinds.
#[derive(Debug)]
pub enum SwarmError {
    /// A disk or network failure.
    Io(std::io::Error),
    /// Bytes that did not parse into what was expected.
    Format(String),
    /// The key did not open the bundle, or a signature did not check out.
    Crypto(String),
    /// The arguments themselves were wrong (e.g. a path that cannot travel).
    Invalid(String),
}

impl std::fmt::Display for SwarmError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SwarmError::Io(e) => write!(f, "{e}"),
            SwarmError::Format(m) => write!(f, "{m}"),
            SwarmError::Crypto(m) => write!(f, "{m}"),
            SwarmError::Invalid(m) => write!(f, "{m}"),
        }
    }
}

impl std::error::Error for SwarmError {}

impl From<std::io::Error> for SwarmError {
    fn from(e: std::io::Error) -> Self {
        SwarmError::Io(e)
    }
}

pub type Result<T> = std::result::Result<T, SwarmError>;
