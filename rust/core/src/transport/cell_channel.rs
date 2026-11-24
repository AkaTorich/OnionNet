//! The link between two neighbouring nodes: a TCP connection carrying encrypted
//! 530-byte frames and nothing besides them.
//!
//! The link knows nothing about circuits — it only carries cells. Who travels
//! over it and how many circuits are laid through it is decided a level above.
//! The handshake, the "who are you?" card request and the frame format match
//! the C# `CellChannel` byte for byte.

use crate::crypto::rand;
use crate::directory::relay_descriptor::RelayDescriptor;
use crate::identity::node_identity::NodeIdentity;
use crate::protocol::cell::Cell;
use crate::protocol::ntor;
use crate::transport::link_crypto::{LinkCrypto, LinkReader, LinkWriter, FRAME_SIZE};
use std::collections::HashSet;
use std::io::{self, Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::Mutex;
use std::time::Duration;

const PROTOCOL_VERSION: u8 = 1;
const MAGIC: &[u8; 4] = b"ONLK";
/// "Who are you?" — asked of a node found by its address alone. A relay answers
/// with its signed card; a non-relay closes without a word.
const CARD_MAGIC: &[u8; 4] = b"ONCD";
const MAX_CARD_SIZE: usize = 2048;

const CLIENT_HELLO_SIZE: usize = 4 + 1 + ntor::CLIENT_HANDSHAKE_SIZE; // 89
const SERVER_HELLO_SIZE: usize = 4 + 1 + 1 + ntor::SERVER_HANDSHAKE_SIZE; // 102

const STATUS_OK: u8 = 0;
const STATUS_UNKNOWN_RELAY: u8 = 1;

static NEXT_CHANNEL_ID: AtomicU32 = AtomicU32::new(0);

#[derive(Debug)]
pub enum ChannelError {
    Io(io::Error),
    Protocol(String),
    Closed,
}

impl std::fmt::Display for ChannelError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ChannelError::Io(e) => write!(f, "{e}"),
            ChannelError::Protocol(m) => write!(f, "{m}"),
            ChannelError::Closed => write!(f, "the link is closed"),
        }
    }
}
impl std::error::Error for ChannelError {}
impl From<io::Error> for ChannelError {
    fn from(e: io::Error) -> Self {
        ChannelError::Io(e)
    }
}

struct WriteSide {
    stream: TcpStream,
    crypto: LinkWriter,
}

struct ReadSide {
    stream: TcpStream,
    crypto: LinkReader,
}

pub struct CellChannel {
    id: u32,
    is_initiator: bool,
    link_binder: Vec<u8>,
    peer_fingerprint: Mutex<Option<Vec<u8>>>,
    peer_onion_key: Mutex<Option<Vec<u8>>>,
    peer_label: String,
    write: Mutex<Option<WriteSide>>,
    read: Mutex<Option<ReadSide>>,
    circuit_ids: Mutex<HashSet<u32>>,
    closed: AtomicBool,
}

impl CellChannel {
    pub fn id(&self) -> u32 {
        self.id
    }
    pub fn is_initiator(&self) -> bool {
        self.is_initiator
    }
    pub fn link_binder(&self) -> &[u8] {
        &self.link_binder
    }
    pub fn peer_label(&self) -> &str {
        &self.peer_label
    }
    pub fn is_closed(&self) -> bool {
        self.closed.load(Ordering::Acquire)
    }
    pub fn peer_fingerprint(&self) -> Option<Vec<u8>> {
        self.peer_fingerprint.lock().unwrap().clone()
    }
    pub fn peer_onion_key(&self) -> Option<Vec<u8>> {
        self.peer_onion_key.lock().unwrap().clone()
    }
    /// A link card fills in the caller's fingerprint on the receiving side.
    pub fn set_peer_identity(&self, fingerprint: Vec<u8>, onion_key: Vec<u8>) {
        *self.peer_fingerprint.lock().unwrap() = Some(fingerprint);
        *self.peer_onion_key.lock().unwrap() = Some(onion_key);
    }

    fn new(
        write_stream: TcpStream,
        read_stream: TcpStream,
        crypto: LinkCrypto,
        initiator: bool,
        peer_label: String,
    ) -> CellChannel {
        let (writer, reader) = crypto.into_halves();
        CellChannel {
            id: NEXT_CHANNEL_ID.fetch_add(1, Ordering::Relaxed) + 1,
            is_initiator: initiator,
            link_binder: Vec::new(),
            peer_fingerprint: Mutex::new(None),
            peer_onion_key: Mutex::new(None),
            peer_label,
            write: Mutex::new(Some(WriteSide {
                stream: write_stream,
                crypto: writer,
            })),
            read: Mutex::new(Some(ReadSide {
                stream: read_stream,
                crypto: reader,
            })),
            circuit_ids: Mutex::new(HashSet::new()),
            closed: AtomicBool::new(false),
        }
    }

    // ---- Bringing the link up ----------------------------------------------

    /// Connects to a relay and runs the link handshake. The neighbour's
    /// fingerprint and onion key must be known in advance.
    pub fn connect(
        host: &str,
        port: u16,
        peer_fingerprint: &[u8],
        peer_onion_key: &[u8],
        timeout: Duration,
        peer_label: Option<String>,
    ) -> Result<CellChannel, ChannelError> {
        let addr = (host, port)
            .to_socket_addrs()?
            .next()
            .ok_or_else(|| ChannelError::Protocol(format!("cannot resolve {host}:{port}")))?;
        let mut stream = TcpStream::connect_timeout(&addr, timeout)?;
        stream.set_nodelay(true).ok();
        stream.set_read_timeout(Some(timeout))?;
        stream.set_write_timeout(Some(timeout))?;

        let handshake = ntor::begin_client(peer_fingerprint, peer_onion_key)
            .map_err(|e| ChannelError::Protocol(e.into()))?;

        let mut hello = Vec::with_capacity(CLIENT_HELLO_SIZE);
        hello.extend_from_slice(MAGIC);
        hello.push(PROTOCOL_VERSION);
        hello.extend_from_slice(handshake.message());
        stream.write_all(&hello)?;
        stream.flush()?;

        let response = read_exactly(&mut stream, SERVER_HELLO_SIZE)?;
        if &response[..4] != MAGIC || response[4] != PROTOCOL_VERSION {
            return Err(ChannelError::Protocol(format!("{host}:{port} speaks a different protocol")));
        }
        if response[5] != STATUS_OK {
            return Err(ChannelError::Protocol(format!(
                "{host}:{port} did not own the fingerprint given"
            )));
        }

        let server_message = &response[6..6 + ntor::SERVER_HANDSHAKE_SIZE];
        let (material, binder) = handshake
            .complete_with_binder(server_message)
            .ok_or_else(|| ChannelError::Protocol(format!("{host}:{port} did not prove its onion key")))?;

        let crypto = LinkCrypto::create(&material, true);

        // A link lives long and stays quiet for stretches: no read timeout now.
        stream.set_read_timeout(None).ok();
        let read_stream = stream.try_clone()?;

        let mut channel = CellChannel::new(
            stream,
            read_stream,
            crypto,
            true,
            peer_label.unwrap_or_else(|| format!("{host}:{port}")),
        );
        channel.link_binder = binder;
        *channel.peer_fingerprint.get_mut().unwrap() = Some(peer_fingerprint.to_vec());
        *channel.peer_onion_key.get_mut().unwrap() = Some(peer_onion_key.to_vec());
        Ok(channel)
    }

    /// Connects to a relay by its descriptor.
    pub fn connect_to(peer: &RelayDescriptor, timeout: Duration) -> Result<CellChannel, ChannelError> {
        CellChannel::connect(
            &peer.host,
            peer.port,
            &peer.fingerprint(),
            &peer.onion_key,
            timeout,
            Some(peer.to_string()),
        )
    }

    /// Asks a node at an address for its card. Returns the card's bytes, or
    /// `None` if the node is no relay or did not answer. The card is checked by
    /// whoever asked; here it is only carried.
    pub fn request_card(host: &str, port: u16, timeout: Duration) -> Option<Vec<u8>> {
        let addr = (host, port).to_socket_addrs().ok()?.next()?;
        let mut stream = TcpStream::connect_timeout(&addr, timeout).ok()?;
        stream.set_read_timeout(Some(timeout)).ok()?;
        stream.set_write_timeout(Some(timeout)).ok()?;

        let mut ask = Vec::with_capacity(5);
        ask.extend_from_slice(CARD_MAGIC);
        ask.push(PROTOCOL_VERSION);
        stream.write_all(&ask).ok()?;
        stream.flush().ok()?;

        let head = read_exactly(&mut stream, 2).ok()?;
        let length = ((head[0] as usize) << 8) | head[1] as usize;
        if length == 0 || length > MAX_CARD_SIZE {
            return None;
        }
        read_exactly(&mut stream, length).ok()
    }

    /// Accepts an incoming connection and answers the link handshake. If the
    /// peer asks for a card instead, `card` is sent and `Err(Protocol)` is
    /// returned (no link follows), as the C# does.
    pub fn accept(
        mut stream: TcpStream,
        self_identity: &NodeIdentity,
        timeout: Duration,
        card: Option<&dyn Fn() -> Option<Vec<u8>>>,
    ) -> Result<CellChannel, ChannelError> {
        stream.set_nodelay(true).ok();
        stream.set_read_timeout(Some(timeout))?;
        stream.set_write_timeout(Some(timeout))?;

        let peer_label = stream
            .peer_addr()
            .map(|a| a.to_string())
            .unwrap_or_else(|_| "?".to_string());

        let head = read_exactly(&mut stream, 4)?;

        if &head[..] == CARD_MAGIC {
            read_exactly(&mut stream, 1)?; // version
            if let Some(provider) = card {
                if let Some(answer) = provider() {
                    if !answer.is_empty() && answer.len() <= MAX_CARD_SIZE {
                        let mut reply = Vec::with_capacity(2 + answer.len());
                        reply.push((answer.len() >> 8) as u8);
                        reply.push(answer.len() as u8);
                        reply.extend_from_slice(&answer);
                        stream.write_all(&reply).ok();
                        stream.flush().ok();
                    }
                }
            }
            return Err(ChannelError::Protocol("a card was asked for; no link follows".into()));
        }

        let mut hello = Vec::with_capacity(CLIENT_HELLO_SIZE);
        hello.extend_from_slice(&head);
        hello.extend_from_slice(&read_exactly(&mut stream, CLIENT_HELLO_SIZE - 4)?);

        if &hello[..4] != MAGIC || hello[4] != PROTOCOL_VERSION {
            return Err(ChannelError::Protocol("the incoming connection speaks a different protocol".into()));
        }

        let client_message = &hello[5..5 + ntor::CLIENT_HANDSHAKE_SIZE];
        let fingerprint = self_identity.fingerprint();
        let answer = ntor::answer_server(&fingerprint, self_identity.onion_key(), client_message);

        let mut response = vec![0u8; SERVER_HELLO_SIZE];
        response[..4].copy_from_slice(MAGIC);
        response[4] = PROTOCOL_VERSION;
        match &answer {
            Some(a) => {
                response[5] = STATUS_OK;
                response[6..].copy_from_slice(&a.server_message);
            }
            None => {
                response[5] = STATUS_UNKNOWN_RELAY;
                // A refusal must match an agreement in length.
                response[6..].copy_from_slice(&rand::get_bytes(ntor::SERVER_HANDSHAKE_SIZE));
            }
        }
        stream.write_all(&response)?;
        stream.flush()?;

        let answer = answer
            .ok_or_else(|| ChannelError::Protocol("the client knocked with a fingerprint that is not ours".into()))?;

        let crypto = LinkCrypto::create(&answer.key_material, false);
        stream.set_read_timeout(None).ok();
        let read_stream = stream.try_clone()?;

        let mut channel = CellChannel::new(stream, read_stream, crypto, false, peer_label);
        channel.link_binder = answer.channel_binder;
        Ok(channel)
    }

    // ---- Exchanging cells --------------------------------------------------

    pub fn write(&self, cell: &Cell) -> Result<(), ChannelError> {
        let mut guard = self.write.lock().unwrap();
        let side = guard.as_mut().ok_or(ChannelError::Closed)?;
        let frame = side.crypto.seal_cell(cell);
        side.stream.write_all(&frame)?;
        side.stream.flush()?;
        Ok(())
    }

    /// Reads a cell, but no longer than the time allowed. Returns `Ok(None)`
    /// both on an orderly close and on a timeout. `Err` only when a frame fails
    /// the integrity check — somebody got into the stream.
    pub fn read_timeout(&self, timeout: Duration) -> Result<Option<Cell>, ChannelError> {
        let mut guard = self.read.lock().unwrap();
        let side = match guard.as_mut() {
            Some(s) => s,
            None => return Ok(None),
        };
        if self.is_closed() {
            return Ok(None);
        }

        side.stream.set_read_timeout(Some(timeout)).ok();
        let frame = read_frame_opt(&mut side.stream);
        side.stream.set_read_timeout(None).ok();

        match frame {
            Some(frame) => match side.crypto.open_frame(&frame) {
                Some(cell) => Ok(Some(cell)),
                None => Err(ChannelError::Protocol(format!(
                    "a frame from {} failed the integrity check",
                    self.peer_label
                ))),
            },
            None => Ok(None),
        }
    }

    /// Reads the next cell, blocking until one arrives or the link closes.
    pub fn read(&self) -> Result<Option<Cell>, ChannelError> {
        let mut guard = self.read.lock().unwrap();
        let side = match guard.as_mut() {
            Some(s) => s,
            None => return Ok(None),
        };
        if self.is_closed() {
            return Ok(None);
        }
        match read_frame_opt(&mut side.stream) {
            Some(frame) => match side.crypto.open_frame(&frame) {
                Some(cell) => Ok(Some(cell)),
                None => Err(ChannelError::Protocol(format!(
                    "a frame from {} failed the integrity check",
                    self.peer_label
                ))),
            },
            None => Ok(None),
        }
    }

    // ---- Circuit numbers ---------------------------------------------------

    /// Hands out a free circuit number. Only the initiator of the connection
    /// hands them out, so the two sides cannot pick the same one.
    pub fn allocate_circuit_id(&self) -> Result<u32, ChannelError> {
        if !self.is_initiator {
            return Err(ChannelError::Protocol(
                "only the link's initiator hands out circuit numbers".into(),
            ));
        }
        let mut used = self.circuit_ids.lock().unwrap();
        for _ in 0..1000 {
            let b = rand::get_bytes(4);
            let id = u32::from_be_bytes([b[0], b[1], b[2], b[3]]);
            if id == 0 || used.contains(&id) {
                continue;
            }
            used.insert(id);
            return Ok(id);
        }
        Err(ChannelError::Protocol("no free circuit number could be found".into()))
    }

    pub fn release_circuit_id(&self, id: u32) {
        self.circuit_ids.lock().unwrap().remove(&id);
    }

    pub fn close(&self) {
        if self.closed.swap(true, Ordering::AcqRel) {
            return;
        }
        // A reading thread holds the read lock while it waits for data, so we
        // must not wait for that lock here. Shutting the socket down through
        // the write half (both halves share one socket) wakes the reader with
        // an end-of-stream; it then sees `closed` and lets go.
        if let Ok(mut w) = self.write.lock() {
            if let Some(side) = w.as_ref() {
                let _ = side.stream.shutdown(std::net::Shutdown::Both);
            }
            *w = None;
        }
        if let Ok(mut r) = self.read.try_lock() {
            *r = None;
        }
    }
}

impl Drop for CellChannel {
    fn drop(&mut self) {
        self.close();
    }
}

/// Reads exactly `count` bytes for the handshake; errors on EOF.
fn read_exactly(stream: &mut TcpStream, count: usize) -> io::Result<Vec<u8>> {
    let mut buffer = vec![0u8; count];
    stream.read_exact(&mut buffer)?;
    Ok(buffer)
}

/// Reads one full frame, or `None` on any orderly close, timeout or error — the
/// same way the C# `Read` swallows every read failure into `null`.
fn read_frame_opt(stream: &mut TcpStream) -> Option<Vec<u8>> {
    let mut buffer = vec![0u8; FRAME_SIZE];
    let mut filled = 0;
    while filled < FRAME_SIZE {
        match stream.read(&mut buffer[filled..]) {
            Ok(0) => return None,
            Ok(n) => filled += n,
            Err(ref e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(_) => return None,
        }
    }
    Some(buffer)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::cell::CellCommand;
    use std::net::TcpListener;
    use std::thread;

    #[test]
    fn full_link_handshake_and_cell_exchange_over_loopback() {
        let server_id = NodeIdentity::create("server").unwrap();
        let fingerprint = server_id.fingerprint();
        let onion = *server_id.public_onion_key();

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();

        let server = thread::spawn(move || {
            let (sock, _) = listener.accept().unwrap();
            let chan = CellChannel::accept(sock, &server_id, Duration::from_secs(5), None).unwrap();
            // Echo one cell back.
            let cell = chan.read().unwrap().unwrap();
            chan.write(&Cell::build(cell.circuit_id, CellCommand::Created, &cell.payload[..16])).unwrap();
        });

        let client = CellChannel::connect(
            &addr.ip().to_string(),
            addr.port(),
            &fingerprint,
            &onion,
            Duration::from_secs(5),
            None,
        )
        .unwrap();

        let cid = client.allocate_circuit_id().unwrap();
        client.write(&Cell::build(cid, CellCommand::Create, b"hello-link")).unwrap();
        let reply = client.read_timeout(Duration::from_secs(5)).unwrap().unwrap();
        assert_eq!(reply.circuit_id, cid);
        assert_eq!(reply.command, CellCommand::Created);
        assert_eq!(&reply.payload[..10], b"hello-link");

        server.join().unwrap();
    }

    #[test]
    fn wrong_fingerprint_is_refused() {
        let server_id = NodeIdentity::create("s").unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        thread::spawn(move || {
            if let Ok((sock, _)) = listener.accept() {
                let _ = CellChannel::accept(sock, &server_id, Duration::from_secs(5), None);
            }
        });

        // A random fingerprint that the server does not own.
        let bogus_fp = [9u8; 20];
        let bogus_onion = crate::crypto::ecc_p256::AgreementKey::generate().export_public();
        let result = CellChannel::connect(
            &addr.ip().to_string(),
            addr.port(),
            &bogus_fp,
            &bogus_onion,
            Duration::from_secs(5),
            None,
        );
        assert!(result.is_err());
    }
}
