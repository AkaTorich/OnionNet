//! The torrent network's DHT, as much of it as finding a directory takes: look
//! up who announced a key (`get_peers`) and announce ourselves under it
//! (`announce_peer`). The same distributed table every torrent client uses to
//! find peers without a tracker - millions of nodes, nobody's in particular.
//!
//! We only ask and never keep other people's records: the queries carry the
//! "read-only" mark of BEP 43, so nobody puts us in their routing tables. The
//! node id is random and new every time.
//!
//! What this costs in privacy, plainly: the DHT nodes we ask see our address and
//! the key we ask about. A directory that announces itself is listed under its
//! key for anyone who looks - that is the point. A participant only asks and is
//! listed nowhere.

use std::cell::RefCell;
use std::cmp::Ordering;
use std::collections::{HashMap, HashSet};
use std::io::ErrorKind;
use std::net::{IpAddr, Ipv4Addr, SocketAddr, ToSocketAddrs, UdpSocket};
use std::rc::Rc;
use std::sync::atomic::{AtomicBool, Ordering as AtomicOrdering};
use std::sync::mpsc::{self, Receiver, Sender};
use std::sync::Arc;
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use super::bencode::{self, BencodeValue, Dict};
use crate::crypto::rand;

/// The size of a node id and of a key, in bytes.
pub const ID_SIZE: usize = 20;

const ALPHA: usize = 8;
const CLOSEST: usize = 8;
const MAX_QUERIES: u32 = 300;
const QUERY_TIMEOUT: Duration = Duration::from_secs(2);

/// A lookup that found what it wanted lingers this long for more, then stops.
const AFTER_FOUND: Duration = Duration::from_secs(2);
/// No node nearer the key in this long - the lookup has reached its end.
const STALLED: Duration = Duration::from_secs(3);

/// Where a fresh client gets its first acquaintances - the torrent clients'
/// usual routers.
pub const BOOTSTRAP: [&str; 4] = [
    "router.bittorrent.com:6881",
    "dht.transmissionbt.com:6881",
    "router.utorrent.com:6881",
    "dht.libtorrent.org:25401",
];

type Node = Rc<RefCell<Candidate>>;

/// A single node we know of during a lookup.
struct Candidate {
    end_point: SocketAddr,
    id: Option<[u8; ID_SIZE]>,
    token: Option<Vec<u8>>,
    asked: bool,
    answered: bool,
    sent_utc: Instant,
}

impl Candidate {
    fn new(end_point: SocketAddr) -> Candidate {
        Candidate {
            end_point,
            id: None,
            token: None,
            asked: false,
            answered: false,
            sent_utc: Instant::now(),
        }
    }
}

/// An answer or error that the receive thread handed back, matched by its
/// transaction id (the raw bytes we put in `"t"`).
struct Response {
    tx: Vec<u8>,
    reply: Option<Dict>,
}

#[derive(Default)]
struct LookupResult {
    peers: Vec<SocketAddr>,
    with_tokens: Vec<Node>,
}

/// A read-only client of the BitTorrent mainline DHT.
pub struct MainlineDht {
    socket: UdpSocket,
    id: [u8; ID_SIZE],
    inbox: Receiver<Response>,
    stopping: Arc<AtomicBool>,
    recv_thread: Option<JoinHandle<()>>,
    /// Where to start; the torrent routers unless told otherwise. A test points
    /// it at a fake one.
    seeds: Option<Vec<SocketAddr>>,
    queries_sent: u32,
}

impl MainlineDht {
    pub fn new() -> std::io::Result<MainlineDht> {
        let socket = UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0))?;
        let recv_socket = socket.try_clone()?;
        recv_socket.set_read_timeout(Some(Duration::from_millis(500)))?;

        let (sender, inbox) = mpsc::channel();
        let stopping = Arc::new(AtomicBool::new(false));
        let thread_stopping = Arc::clone(&stopping);

        let mut id = [0u8; ID_SIZE];
        id.copy_from_slice(&rand::get_bytes(ID_SIZE));

        let recv_thread = thread::Builder::new()
            .name("stalknet-dht".into())
            .spawn(move || receive(recv_socket, sender, thread_stopping))
            .expect("spawning the DHT receive thread");

        Ok(MainlineDht {
            socket,
            id,
            inbox,
            stopping,
            recv_thread: Some(recv_thread),
            seeds: None,
            queries_sent: 0,
        })
    }

    /// Points the lookup at these seeds instead of the torrent routers.
    pub fn set_seeds(&mut self, seeds: Option<Vec<SocketAddr>>) {
        self.seeds = seeds;
    }

    pub fn queries_sent(&self) -> u32 {
        self.queries_sent
    }

    /// Who announced the key: addresses and ports, as the DHT holds them.
    pub fn find_peers(&mut self, key: &[u8], budget: Duration) -> Vec<SocketAddr> {
        self.lookup(key, budget, true).peers
    }

    /// Announces this machine under the key with the given TCP port. The address
    /// is the one the DHT nodes see our packets come from. Returns how many of
    /// the nodes closest to the key took the announcement.
    pub fn announce(&mut self, key: &[u8], port: u16, budget: Duration) -> usize {
        let found = self.lookup(key, budget, false);
        let mut accepted = 0usize;

        let mut pending: HashMap<Vec<u8>, Node> = HashMap::new();
        for node in &found.with_tokens {
            let (end_point, token) = {
                let c = node.borrow();
                (c.end_point, c.token.clone().unwrap_or_default())
            };
            let mut args = Dict::new();
            args.insert("id".into(), BencodeValue::Bytes(self.id.to_vec()));
            args.insert("info_hash".into(), BencodeValue::Bytes(key.to_vec()));
            args.insert("port".into(), BencodeValue::Int(port as i64));
            args.insert("token".into(), BencodeValue::Bytes(token));
            args.insert("implied_port".into(), BencodeValue::Int(0));
            let tx = self.send(end_point, "announce_peer", args);
            pending.insert(tx, Rc::clone(node));
        }

        let deadline = Instant::now() + QUERY_TIMEOUT + QUERY_TIMEOUT;
        while !pending.is_empty() {
            let left = deadline.saturating_duration_since(Instant::now());
            if left.is_zero() {
                break;
            }
            let response = match self.inbox.recv_timeout(left) {
                Ok(r) => r,
                Err(_) => break,
            };
            if pending.remove(&response.tx).is_some() && response.reply.is_some() {
                accepted += 1;
            }
        }

        accepted
    }

    // ---- The lookup ----------------------------------------------------------

    fn lookup(&mut self, key: &[u8], budget: Duration, stop_on_peers: bool) -> LookupResult {
        // A 20-byte key is expected; a wrong one finds nobody rather than panics.
        if key.len() != ID_SIZE {
            return LookupResult::default();
        }

        let mut result = LookupResult::default();
        let mut known: HashMap<SocketAddr, Node> = HashMap::new();
        let mut peers: HashSet<SocketAddr> = HashSet::new();
        let mut pending: HashMap<Vec<u8>, Node> = HashMap::new();

        for seed in self.seeds_or_default() {
            known.insert(seed, Rc::new(RefCell::new(Candidate::new(seed))));
        }

        let deadline = Instant::now() + budget;
        let mut first_peer: Option<Instant> = None;
        let mut last_nearer = Instant::now();
        let mut nearest: Option<[u8; ID_SIZE]> = None;

        while Instant::now() < deadline {
            // The real DHT never quite runs dry: there is always one more node a
            // little nearer. Without these two stops a lookup used its whole
            // budget even with the answer long in hand.
            if stop_on_peers {
                if let Some(found_at) = first_peer {
                    if found_at.elapsed() > AFTER_FOUND {
                        break;
                    }
                }
            }
            if nearest.is_some() && last_nearer.elapsed() > STALLED {
                break;
            }

            // Keep up to Alpha questions in the air, closest first.
            while pending.len() < ALPHA && self.queries_sent < MAX_QUERIES {
                let next = match next_to_ask(&known, key) {
                    Some(n) => n,
                    None => break,
                };
                let end_point = {
                    let mut c = next.borrow_mut();
                    c.asked = true;
                    c.sent_utc = Instant::now();
                    c.end_point
                };
                let mut args = Dict::new();
                args.insert("id".into(), BencodeValue::Bytes(self.id.to_vec()));
                args.insert("info_hash".into(), BencodeValue::Bytes(key.to_vec()));
                let tx = self.send(end_point, "get_peers", args);
                pending.insert(tx, next);
            }

            if pending.is_empty() {
                break;
            }
            if settled(&known, key) && pending.is_empty() {
                break;
            }

            let response = match self.inbox.recv_timeout(Duration::from_millis(300)) {
                Ok(r) => r,
                Err(_) => {
                    expire(&mut pending);
                    continue;
                }
            };

            let asked = match pending.remove(&response.tx) {
                Some(a) => a,
                None => continue,
            };
            let reply = match response.reply {
                Some(r) => r,
                None => continue,
            };

            {
                let mut a = asked.borrow_mut();
                if let Some(id) = reply.get("id").and_then(BencodeValue::as_bytes) {
                    if id.len() == ID_SIZE {
                        let mut id_array = [0u8; ID_SIZE];
                        id_array.copy_from_slice(id);
                        a.id = Some(id_array);
                        if nearest.is_none()
                            || compare_distance(&id_array, nearest.as_ref().unwrap(), key) == Ordering::Less
                        {
                            nearest = Some(id_array);
                            last_nearer = Instant::now();
                        }
                    }
                }
                a.answered = true;
                a.token = reply.get("token").and_then(BencodeValue::as_bytes).map(|b| b.to_vec());
            }

            if let Some(values) = reply.get("values").and_then(BencodeValue::as_list) {
                for value in values {
                    if let Some(bytes) = value.as_bytes() {
                        if let Some(peer) = compact(bytes, 0) {
                            if peers.insert(peer) {
                                result.peers.push(peer);
                                if first_peer.is_none() {
                                    first_peer = Some(Instant::now());
                                }
                            }
                        }
                    }
                }
            }

            if let Some(nodes) = reply.get("nodes").and_then(BencodeValue::as_bytes) {
                let mut at = 0usize;
                while at + 26 <= nodes.len() && known.len() < 2000 {
                    if let Some(end_point) = compact(nodes, at + ID_SIZE) {
                        if !known.contains_key(&end_point) {
                            let mut node_id = [0u8; ID_SIZE];
                            node_id.copy_from_slice(&nodes[at..at + ID_SIZE]);
                            let mut candidate = Candidate::new(end_point);
                            candidate.id = Some(node_id);
                            known.insert(end_point, Rc::new(RefCell::new(candidate)));
                        }
                    }
                    at += 26;
                }
            }

            expire(&mut pending);
            if settled(&known, key) && pending.is_empty() {
                break;
            }
        }

        let mut answered: Vec<Node> = known
            .values()
            .filter(|c| {
                let c = c.borrow();
                c.answered && c.id.is_some() && c.token.is_some()
            })
            .cloned()
            .collect();
        answered.sort_by(|a, b| {
            let a = a.borrow();
            let b = b.borrow();
            compare_distance(a.id.as_ref().unwrap(), b.id.as_ref().unwrap(), key)
        });
        for node in answered.into_iter().take(CLOSEST) {
            result.with_tokens.push(node);
        }

        result
    }

    // ---- The wire -----------------------------------------------------------

    fn send(&mut self, to: SocketAddr, query: &str, args: Dict) -> Vec<u8> {
        let tx = rand::get_bytes(4);

        let mut message = Dict::new();
        message.insert("t".into(), BencodeValue::Bytes(tx.clone()));
        message.insert("y".into(), BencodeValue::Str("q".into()));
        message.insert("q".into(), BencodeValue::Str(query.into()));
        message.insert("a".into(), BencodeValue::Dict(args));
        message.insert("ro".into(), BencodeValue::Int(1));

        let data = bencode::encode(&BencodeValue::Dict(message));
        let _ = self.socket.send_to(&data, to);

        self.queries_sent += 1;
        tx
    }

    fn seeds_or_default(&self) -> Vec<SocketAddr> {
        if let Some(seeds) = &self.seeds {
            return seeds.clone();
        }

        let mut seeds = Vec::new();
        for entry in BOOTSTRAP {
            let colon = match entry.rfind(':') {
                Some(c) => c,
                None => continue,
            };
            let host = &entry[..colon];
            let port: u16 = match entry[colon + 1..].parse() {
                Ok(p) => p,
                Err(_) => continue,
            };
            // A router that does not resolve today - the others will do.
            if let Ok(addresses) = (host, port).to_socket_addrs() {
                for address in addresses {
                    if address.is_ipv4() {
                        seeds.push(address);
                    }
                }
            }
        }
        seeds
    }
}

impl Drop for MainlineDht {
    fn drop(&mut self) {
        self.stopping.store(true, AtomicOrdering::SeqCst);
        if let Some(handle) = self.recv_thread.take() {
            let _ = handle.join();
        }
    }
}

// ---- Free helpers (the lookup's machinery) -----------------------------------

/// The next node to ask: the seeds first (id still unknown), then the closest
/// not yet asked.
fn next_to_ask(known: &HashMap<SocketAddr, Node>, key: &[u8]) -> Option<Node> {
    let mut best: Option<(Node, [u8; ID_SIZE])> = None;
    for candidate in known.values() {
        let (asked, id) = {
            let c = candidate.borrow();
            (c.asked, c.id)
        };
        if asked {
            continue;
        }
        match id {
            None => return Some(Rc::clone(candidate)),
            Some(id) => {
                let better = match &best {
                    None => true,
                    Some((_, best_id)) => compare_distance(&id, best_id, key) == Ordering::Less,
                };
                if better {
                    best = Some((Rc::clone(candidate), id));
                }
            }
        }
    }
    // Asking further than the closest that already answered gives nothing.
    best.map(|(node, _)| node)
}

/// The closest eight that answered are all asked, and nobody nearer waits.
fn settled(known: &HashMap<SocketAddr, Node>, key: &[u8]) -> bool {
    let mut answered: Vec<[u8; ID_SIZE]> = Vec::new();
    let mut nearest_unasked: Option<[u8; ID_SIZE]> = None;

    for candidate in known.values() {
        let c = candidate.borrow();
        match c.id {
            None => {
                if !c.asked {
                    return false;
                }
            }
            Some(id) => {
                if c.answered {
                    answered.push(id);
                } else if !c.asked {
                    let better = match nearest_unasked {
                        None => true,
                        Some(n) => compare_distance(&id, &n, key) == Ordering::Less,
                    };
                    if better {
                        nearest_unasked = Some(id);
                    }
                }
            }
        }
    }

    if answered.len() < CLOSEST {
        return nearest_unasked.is_none();
    }

    answered.sort_by(|a, b| compare_distance(a, b, key));
    match nearest_unasked {
        None => true,
        Some(n) => compare_distance(&n, &answered[CLOSEST - 1], key) == Ordering::Greater,
    }
}

fn expire(pending: &mut HashMap<Vec<u8>, Node>) {
    let now = Instant::now();
    let dead: Vec<Vec<u8>> = pending
        .iter()
        .filter(|(_, c)| now.duration_since(c.borrow().sent_utc) > QUERY_TIMEOUT)
        .map(|(tx, _)| tx.clone())
        .collect();
    for tx in dead {
        pending.remove(&tx);
    }
}

/// XOR-distance comparison of two ids against the key, most significant byte
/// first.
fn compare_distance(a: &[u8; ID_SIZE], b: &[u8; ID_SIZE], key: &[u8]) -> Ordering {
    for i in 0..ID_SIZE {
        let da = a[i] ^ key[i];
        let db = b[i] ^ key[i];
        if da != db {
            return if da < db { Ordering::Less } else { Ordering::Greater };
        }
    }
    Ordering::Equal
}

/// Six bytes: an IPv4 address and a port, the way the DHT packs them.
fn compact(data: &[u8], offset: usize) -> Option<SocketAddr> {
    if offset + 6 > data.len() {
        return None;
    }
    let address = Ipv4Addr::new(data[offset], data[offset + 1], data[offset + 2], data[offset + 3]);
    let port = ((data[offset + 4] as u16) << 8) | data[offset + 5] as u16;
    if port == 0 || data[offset] == 0 {
        return None;
    }
    Some(SocketAddr::new(IpAddr::V4(address), port))
}

fn receive(socket: UdpSocket, sender: Sender<Response>, stopping: Arc<AtomicBool>) {
    let mut buffer = [0u8; 65536];
    while !stopping.load(AtomicOrdering::SeqCst) {
        let read = match socket.recv_from(&mut buffer) {
            Ok((count, _from)) => count,
            Err(ref e) if e.kind() == ErrorKind::WouldBlock || e.kind() == ErrorKind::TimedOut => continue,
            Err(_) => {
                if stopping.load(AtomicOrdering::SeqCst) {
                    return;
                }
                continue;
            }
        };

        // Rubbish from somebody is dropped. Nothing may fly out of this thread.
        let message = match bencode::decode(&buffer[..read]) {
            Ok(BencodeValue::Dict(m)) => m,
            _ => continue,
        };

        let tx = match message.get("t").and_then(BencodeValue::as_bytes) {
            Some(bytes) => bytes.to_vec(),
            None => continue,
        };
        let kind = match message.get("y").and_then(BencodeValue::as_bytes) {
            Some(bytes) if bytes.len() == 1 => bytes[0],
            _ => continue,
        };

        // An answer or an error. Questions to us go unanswered: we are read-only
        // and keep nobody's records.
        if kind == b'r' {
            let reply = message.get("r").and_then(BencodeValue::as_dict).cloned();
            let _ = sender.send(Response { tx, reply });
        } else if kind == b'e' {
            let _ = sender.send(Response { tx, reply: None });
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn id(byte: u8) -> [u8; ID_SIZE] {
        [byte; ID_SIZE]
    }

    #[test]
    fn get_peers_message_encodes_in_sorted_order() {
        // Build the exact dict a get_peers query carries and check the wire.
        let mut args = Dict::new();
        args.insert("id".into(), BencodeValue::Bytes(vec![0xAA; ID_SIZE]));
        args.insert("info_hash".into(), BencodeValue::Bytes(vec![0xBB; ID_SIZE]));

        let mut message = Dict::new();
        message.insert("t".into(), BencodeValue::Bytes(vec![1, 2, 3, 4]));
        message.insert("y".into(), BencodeValue::Str("q".into()));
        message.insert("q".into(), BencodeValue::Str("get_peers".into()));
        message.insert("a".into(), BencodeValue::Dict(args));
        message.insert("ro".into(), BencodeValue::Int(1));

        let encoded = bencode::encode(&BencodeValue::Dict(message));

        // Round-trips, and the read-only mark and query name survive.
        let decoded = bencode::decode(&encoded).expect("decodes");
        let dict = decoded.as_dict().unwrap();
        assert_eq!(dict.get("ro").unwrap().as_int(), Some(1));
        assert_eq!(dict.get("q").unwrap().as_bytes(), Some(&b"get_peers"[..]));
        assert_eq!(dict.get("y").unwrap().as_bytes(), Some(&b"q"[..]));
        let a = dict.get("a").unwrap().as_dict().unwrap();
        assert_eq!(a.get("id").unwrap().as_bytes().unwrap().len(), ID_SIZE);

        // The dictionary's top-level keys appear in byte order: a, q, ro, t, y.
        let order: Vec<&str> = dict.keys().map(|k| k.as_str()).collect();
        assert_eq!(order, ["a", "q", "ro", "t", "y"]);
    }

    #[test]
    fn reply_with_nodes_parses() {
        // A get_peers reply dict: id + a token + one compact node.
        let mut node = Vec::new();
        node.extend_from_slice(&[0x11; ID_SIZE]); // node id
        node.extend_from_slice(&[203, 0, 113, 5, 0x1A, 0xE1]); // 203.0.113.5:6881

        let mut reply = Dict::new();
        reply.insert("id".into(), BencodeValue::Bytes(vec![0x22; ID_SIZE]));
        reply.insert("token".into(), BencodeValue::Bytes(vec![9, 9]));
        reply.insert("nodes".into(), BencodeValue::Bytes(node.clone()));

        let got_id = reply.get("id").and_then(BencodeValue::as_bytes).unwrap();
        assert_eq!(got_id.len(), ID_SIZE);

        let nodes = reply.get("nodes").and_then(BencodeValue::as_bytes).unwrap();
        let end_point = compact(nodes, ID_SIZE).expect("a compact node");
        assert_eq!(end_point, "203.0.113.5:6881".parse().unwrap());
    }

    #[test]
    fn compact_reads_address_and_port() {
        let data = [198, 51, 100, 7, 0x23, 0x28]; // 198.51.100.7:9000
        let end_point = compact(&data, 0).unwrap();
        assert_eq!(end_point, "198.51.100.7:9000".parse().unwrap());
    }

    #[test]
    fn compact_rejects_zero_port_and_zero_address() {
        assert!(compact(&[1, 2, 3, 4, 0, 0], 0).is_none()); // port 0
        assert!(compact(&[0, 2, 3, 4, 0x1A, 0xE1], 0).is_none()); // address starts 0
        assert!(compact(&[1, 2, 3], 0).is_none()); // too short
    }

    #[test]
    fn compare_distance_is_xor_ordering() {
        let key = id(0x00);
        // 0x01 is nearer the zero key than 0x02.
        assert_eq!(compare_distance(&id(0x01), &id(0x02), &key), Ordering::Less);
        assert_eq!(compare_distance(&id(0x02), &id(0x01), &key), Ordering::Greater);
        assert_eq!(compare_distance(&id(0x05), &id(0x05), &key), Ordering::Equal);
    }

    #[test]
    fn bootstrap_and_constants_match_the_csharp() {
        assert_eq!(ID_SIZE, 20);
        assert_eq!(BOOTSTRAP.len(), 4);
        assert_eq!(BOOTSTRAP[0], "router.bittorrent.com:6881");
        assert_eq!(BOOTSTRAP[3], "dht.libtorrent.org:25401");
    }
}
