//! Router port forwarding (`StalkNet.Core/Nat`).
//!
//! A faithful Rust rewrite of the C# `Nat` folder. It opens a port on the home
//! router the way a torrent client does on start, so that people can connect to
//! the node from outside.
//!
//! Two methods are tried in turn, exactly as the C# does: **NAT-PMP first** (it
//! is simpler and answers fast), then **UPnP IGD**. There is no guessing in
//! advance which one the router at hand understands, and routers usually
//! support just one.
//!
//! A port held by this machine's *own* old forward is reused or set again; a
//! port the router keeps for itself, or forwards to someone else, gets one
//! fallback external port ([`UpnpMapper::spare_port`]: `49152 + port % 16384`,
//! the same on every start). Other people's forwards are never touched.
//!
//! All SSDP, SOAP and HTTP for UPnP, and all NAT-PMP datagrams, are built and
//! parsed by hand over the standard library's [`std::net`] sockets, so the
//! bytes on the wire match the C# node exactly.
//!
//! # Logging
//!
//! The C# types raise a `Logged` event (`Action<string>`). Here that is a
//! [`LogFn`] callback installed with `set_logger`. The English phrases the C#
//! resolves through `StalkNet.Text.Loc` are inlined directly, since the `Text`
//! layer is not (yet) ported; the wording matches `Strings.En.cs`.

pub mod nat_pmp_mapper;
pub mod port_mapper;
pub mod port_mapping;
pub mod upnp_mapper;

pub use nat_pmp_mapper::NatPmpMapper;
pub use port_mapper::PortMapper;
pub use port_mapping::{MappingMethod, PortMapping};
pub use upnp_mapper::{UpnpEntry, UpnpMapper};

use std::fmt;
use std::sync::Arc;

/// A log sink shared between a mapper and its owner.
///
/// Stands in for the C# `event Action<string> Logged`. It is an [`Arc`] so a
/// [`PortMapper`] can hand the same sink to the NAT-PMP and UPnP mappers it
/// drives, and so the background renewal thread can hold a clone.
pub type LogFn = Arc<dyn Fn(&str) + Send + Sync>;

/// A handler for the "the forward changed" notification (C# `event
/// Action<PortMapping> Changed`).
pub type ChangedFn = Arc<dyn Fn(&PortMapping) + Send + Sync>;

/// What can go wrong at the public boundary of this module.
///
/// The C# code reports a bad port by throwing `ArgumentOutOfRangeException` and
/// otherwise signals failure by returning `null`; the Rust port keeps the
/// `Option` for "nothing happened" and reserves this enum for the genuine
/// programming error.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NatError {
    /// The requested port was outside `1..=65535`.
    InvalidPort(i32),
}

impl fmt::Display for NatError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            NatError::InvalidPort(port) => {
                write!(f, "port out of range: {port} (expected 1..=65535)")
            }
        }
    }
}

impl std::error::Error for NatError {}
