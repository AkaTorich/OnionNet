//! StalkNet core library.
//!
//! A faithful Rust rewrite of `StalkNet.Core` (C#, .NET Framework 4.8). The
//! module layout mirrors the original folders so the two can be read side by
//! side; the wire formats, byte orders and cryptographic constructions are kept
//! identical so a Rust node and a C# node speak the same network.
//!
//! Porting proceeds bottom-up. Modules land as they are ported; this file lists
//! what is already in the crate.

pub mod crypto;
pub mod directory;
pub mod discovery;
pub mod hidden;
pub mod identity;
pub mod nat;
pub mod peers;
pub mod protocol;
pub mod runtime;
pub mod sharing;
pub mod streams;
pub mod swarm;
pub mod text;
pub mod transport;
pub mod util;
