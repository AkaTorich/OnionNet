//! Discovery (`StalkNet.Core/Discovery`): finding the first relays with nothing
//! in hand - the BitTorrent mainline DHT and the peer finder over it. The
//! network is an internet one only; there is no home-network discovery.

pub mod bencode;
pub mod mainline_dht;
pub mod peer_finder;

pub use bencode::{decode, encode, BencodeError, BencodeValue, Dict};
pub use mainline_dht::{MainlineDht, BOOTSTRAP, ID_SIZE};
