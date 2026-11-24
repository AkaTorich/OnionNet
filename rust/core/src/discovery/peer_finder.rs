//! The first relays, with nothing in hand.
//!
//! The torrent network's DHT:
//! every relay that stands on the internet announces itself there under the key
//! of the network's name, and whoever knows the name finds them the way a torrent
//! client finds peers, then asks each address for its card. A card is signed by
//! its relay and is checked; an address that hands out none is passed by. One
//! working relay is enough to start: it hands out the rest.
//!
//! The name is what tells one network from another. The same program run by
//! strangers under the default name would be found too - for a network of one's
//! own the name is worth changing in `node.cfg`.
//!
//! # Fetching a card
//!
//! The C# `PeerFinder.InTorrent` calls `CellChannel.RequestCard` to pull a
//! descriptor over the transport. That transport is not ported yet, so
//! [`in_torrent`] takes the fetcher as an argument: a closure
//! `Fn(&str, u16, Duration) -> Option<Vec<u8>>` the caller supplies once the
//! real `CellChannel` exists. It receives the address as a string, the port, and
//! the per-card wait, exactly the arguments the C# passed.

use std::collections::HashSet;
use std::net::SocketAddr;
use std::time::Duration;

use sha1::{Digest, Sha1};

use super::mainline_dht::MainlineDht;
use crate::directory::RelayDescriptor;

pub const DEFAULT_NETWORK: &str = "stalknet";

/// How long to wait for a single card over the transport.
const CARD_WAIT: Duration = Duration::from_secs(5);
/// At most this many addresses from the DHT are asked for a card.
const MAX_CARDS_ASKED: usize = 16;

/// The canonical form of a network name: trimmed and lowercased, the default if
/// blank.
pub fn normalize(network: &str) -> String {
    let trimmed = network.trim();
    if trimmed.is_empty() {
        DEFAULT_NETWORK.to_string()
    } else {
        trimmed.to_lowercase()
    }
}

/// The DHT key a network's relays are filed under: SHA-1 of its name, the DHT's
/// own size.
pub fn key_for(network: &str) -> [u8; 20] {
    let mut hasher = Sha1::new();
    hasher.update(b"stalknet-relays-v1:");
    hasher.update(normalize(network).as_bytes());

    let digest = hasher.finalize();
    let mut key = [0u8; 20];
    key.copy_from_slice(&digest);
    key
}

/// Cards of the relays found through the torrent network.
///
/// `fetch_card` stands in for `CellChannel.RequestCard`: given an address, a
/// port and a wait, it returns the raw signed card or `None`.
pub fn in_torrent<F>(
    network: &str,
    budget: Duration,
    seeds: Option<Vec<SocketAddr>>,
    fetch_card: F,
) -> Vec<RelayDescriptor>
where
    F: Fn(&str, u16, Duration) -> Option<Vec<u8>>,
{
    let mut found = Vec::new();
    let mut seen: HashSet<[u8; 20]> = HashSet::new();

    let addresses = {
        let mut dht = match MainlineDht::new() {
            Ok(d) => d,
            Err(_) => return found,
        };
        dht.set_seeds(seeds);
        dht.find_peers(&key_for(network), budget)
    };

    for address in addresses.iter().take(MAX_CARDS_ASKED) {
        let card = fetch_card(&address.ip().to_string(), address.port(), CARD_WAIT);
        if let Some(card) = card {
            if let Some(relay) = parse(&card) {
                if seen.insert(relay.fingerprint()) {
                    found.push(relay);
                }
            }
        }
    }

    found
}

/// Announces this machine's relay in the torrent network. Returns how many nodes
/// took it.
pub fn announce_in_torrent(network: &str, port: u16, budget: Duration, seeds: Option<Vec<SocketAddr>>) -> usize {
    let mut dht = match MainlineDht::new() {
        Ok(d) => d,
        Err(_) => return 0,
    };
    dht.set_seeds(seeds);
    dht.announce(&key_for(network), port, budget)
}

/// The card if it parses and its signature checks out; otherwise `None`. The
/// pass is the view's business.
pub fn parse(card: &[u8]) -> Option<RelayDescriptor> {
    if card.is_empty() {
        return None;
    }
    RelayDescriptor::try_parse(card)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalize_trims_lowercases_and_defaults() {
        assert_eq!(normalize("  StalkNet "), "stalknet");
        assert_eq!(normalize(""), DEFAULT_NETWORK);
        assert_eq!(normalize("   "), DEFAULT_NETWORK);
        assert_eq!(normalize("MyNet"), "mynet");
    }

    #[test]
    fn key_for_default_matches_sha1_vector() {
        // SHA-1("stalknet-relays-v1:stalknet"), the key the C# derives for the
        // default network.
        let expected: [u8; 20] = [
            0xc0, 0x14, 0xb8, 0x5d, 0xb6, 0x7b, 0x73, 0x71, 0x72, 0xf8, 0x20, 0x5b, 0xba, 0x0e, 0x47, 0x56,
            0x0c, 0x5b, 0x43, 0xc6,
        ];
        assert_eq!(key_for("stalknet"), expected);
        // The default name and a blank name derive the same key.
        assert_eq!(key_for(""), expected);
        assert_eq!(key_for("  STALKNET "), expected);
    }

    #[test]
    fn key_is_dht_sized() {
        assert_eq!(key_for("whatever").len(), 20);
    }

    #[test]
    fn parse_rejects_empty_and_garbage() {
        assert!(parse(&[]).is_none());
        assert!(parse(&[1, 2, 3]).is_none());
    }
}
