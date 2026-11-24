//! A SOCKS5 door into the network for the programs on this machine.
//!
//! [`crate::streams::local_port_forwarder::LocalPortForwarder`] leads one local
//! port to one port on somebody else's node; here the program itself says where
//! it is going, and every connection goes its own way. That is what a browser
//! needs: it asks for a hundred addresses in an evening, and a hundred forwarded
//! ports would have to be set up by hand.
//!
//! The name is deliberately not resolved on this machine. SOCKS5 allows the
//! address to travel as a name, and it is sent onwards as a name: a DNS request
//! made here would tell the local network exactly where its owner is going, and
//! three hops of encryption would have been in vain.
//!
//! It listens on the loopback address only. A SOCKS proxy open to the local
//! network is an entrance into StalkNet for the neighbours, and an exit node's
//! owner would be answering for their traffic.
//!
//! Only CONNECT is served. BIND and UDP ASSOCIATE have nowhere to go here: the
//! network carries streams, not datagrams, and nothing in it listens on the
//! guest's behalf.

use crate::streams::channel_limits;
use crate::streams::message_channel::MessageChannel;
use crate::streams::stream_opener::InternetOpener;
use crate::text::loc;
use std::io::{Read, Write};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, AtomicU16, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::Duration;

const VERSION: u8 = 5;
const METHOD_NONE: u8 = 0x00;
const METHOD_UNSUPPORTED: u8 = 0xFF;

const COMMAND_CONNECT: u8 = 1;

const ADDRESS_IPV4: u8 = 1;
const ADDRESS_NAME: u8 = 3;
const ADDRESS_IPV6: u8 = 4;

const REPLY_OK: u8 = 0;
const REPLY_FAILURE: u8 = 1;
const REPLY_NOT_ALLOWED: u8 = 2;
const REPLY_COMMAND_UNSUPPORTED: u8 = 7;

const READ_TIMEOUT: Duration = Duration::from_secs(30);
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

/// Where the proxy's lines go.
pub type LogSink = Box<dyn Fn(&str) + Send + Sync>;

struct SocksShared {
    opener: Arc<dyn InternetOpener>,
    stopping: AtomicBool,
    active: AtomicUsize,
    served: AtomicUsize,
    logged: Mutex<Option<LogSink>>,
    local_port: AtomicU16,
    bound_addr: Mutex<Option<SocketAddr>>,
}

impl SocksShared {
    fn say(&self, message: &str) {
        if let Some(sink) = self.logged.lock().unwrap().as_ref() {
            sink(message);
        }
    }
}

pub struct SocksProxy {
    shared: Arc<SocksShared>,
    accept_handle: Mutex<Option<JoinHandle<()>>>,
}

impl SocksProxy {
    pub fn new(opener: Arc<dyn InternetOpener>, local_port: u16) -> SocksProxy {
        SocksProxy {
            shared: Arc::new(SocksShared {
                opener,
                stopping: AtomicBool::new(false),
                active: AtomicUsize::new(0),
                served: AtomicUsize::new(0),
                logged: Mutex::new(None),
                local_port: AtomicU16::new(local_port),
                bound_addr: Mutex::new(None),
            }),
            accept_handle: Mutex::new(None),
        }
    }

    /// The local port. After [`start`](Self::start) this holds the real number,
    /// if zero was asked for.
    pub fn local_port(&self) -> u16 {
        self.shared.local_port.load(Ordering::Acquire)
    }

    /// How many connections are being carried right now.
    pub fn active_connections(&self) -> usize {
        self.shared.active.load(Ordering::Acquire)
    }

    /// How many have been carried since the start — for the window.
    pub fn served_connections(&self) -> usize {
        self.shared.served.load(Ordering::Acquire)
    }

    pub fn set_logged(&self, sink: LogSink) {
        *self.shared.logged.lock().unwrap() = Some(sink);
    }

    pub fn start(&self) -> std::io::Result<()> {
        if self.accept_handle.lock().unwrap().is_some() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                "the proxy is already running",
            ));
        }

        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, self.local_port()))?;
        let local = listener.local_addr()?;
        self.shared.local_port.store(local.port(), Ordering::Release);
        *self.shared.bound_addr.lock().unwrap() = Some(local);

        let shared = self.shared.clone();
        let handle = thread::Builder::new()
            .name(format!("stalknet-socks-{}", local.port()))
            .spawn(move || accept_loop(shared, listener))
            .expect("spawn socks accept thread");
        *self.accept_handle.lock().unwrap() = Some(handle);
        Ok(())
    }

    fn dispose(&self) {
        if self.shared.stopping.swap(true, Ordering::AcqRel) {
            return;
        }
        // Wake the accept thread out of its blocking accept().
        if let Some(addr) = *self.shared.bound_addr.lock().unwrap() {
            let _ = TcpStream::connect_timeout(&addr, Duration::from_millis(200));
        }
        if let Some(handle) = self.accept_handle.lock().unwrap().take() {
            let _ = handle.join();
        }
    }
}

impl Drop for SocksProxy {
    fn drop(&mut self) {
        self.dispose();
    }
}

fn accept_loop(shared: Arc<SocksShared>, listener: TcpListener) {
    loop {
        if shared.stopping.load(Ordering::Acquire) {
            return;
        }
        match listener.accept() {
            Ok((client, _)) => {
                if shared.stopping.load(Ordering::Acquire) {
                    return;
                }
                let s = shared.clone();
                let _ = thread::Builder::new()
                    .name("stalknet-socks-bridge".into())
                    .spawn(move || serve(s, client));
            }
            Err(_) => return, // the listener was stopped
        }
    }
}

// ---- One connection ------------------------------------------------------

fn serve(shared: Arc<SocksShared>, client: TcpStream) {
    shared.active.fetch_add(1, Ordering::AcqRel);
    let _ = client.set_nodelay(true);
    let _ = client.set_read_timeout(Some(HANDSHAKE_TIMEOUT));

    let result = serve_inner(&shared, &client);
    // Whatever happened, the connection ends here.
    let _ = result;
    let _ = client.shutdown(std::net::Shutdown::Both);
    shared.active.fetch_sub(1, Ordering::AcqRel);
}

fn serve_inner(shared: &Arc<SocksShared>, client: &TcpStream) -> Option<()> {
    let mut network = client.try_clone().ok()?;

    if !greet(&mut network) {
        return None;
    }

    let (host, port) = match read_request(&mut network) {
        Some(request) => request,
        None => return None,
    };

    let stream = match shared.opener.open_to(&host, port) {
        Some(s) => s,
        None => {
            shared.say(&loc::t_args("socks.refused", &[&host, &port.to_string()]));
            answer(&mut network, REPLY_NOT_ALLOWED);
            return None;
        }
    };

    shared.served.fetch_add(1, Ordering::AcqRel);
    shared.say(&loc::t_args("socks.open", &[&host, &port.to_string()]));
    answer(&mut network, REPLY_OK);

    let _ = client.set_read_timeout(None);

    // One thread pours from the socket into the circuit; this one pours from the
    // circuit into the socket.
    let up_shared = shared.clone();
    let up_client = client.try_clone().ok()?;
    let up_stream = stream.clone();
    let upstream = thread::Builder::new()
        .name("stalknet-socks-up".into())
        .spawn(move || pump_to_circuit(up_shared, up_client, up_stream))
        .ok()?;

    while !shared.stopping.load(Ordering::Acquire) && stream.is_open() {
        match stream.receive(READ_TIMEOUT) {
            None => {
                if !stream.is_open() {
                    break;
                }
                continue; // just silence
            }
            Some(data) => {
                if data.is_empty() {
                    continue;
                }
                if network.write_all(&data).is_err() {
                    break;
                }
            }
        }
    }

    stream.close();
    // The other thread sits in a read on the program's socket; shut it so the
    // program sees the end now and that thread wakes, instead of both waiting
    // until the program happens to send something.
    let _ = client.shutdown(std::net::Shutdown::Both);
    let _ = upstream.join();
    Some(())
}

/// The first exchange: which ways of signing in we know. None.
fn greet<S: Read + Write>(network: &mut S) -> bool {
    let head = match read_n(network, 2) {
        Some(h) => h,
        None => return false,
    };
    if head[0] != VERSION {
        return false;
    }

    let methods = match read_n(network, head[1] as usize) {
        Some(m) => m,
        None => return false,
    };

    let none = methods.iter().any(|&m| m == METHOD_NONE);
    let selection = [VERSION, if none { METHOD_NONE } else { METHOD_UNSUPPORTED }];
    if network.write_all(&selection).is_err() {
        return false;
    }
    none
}

/// The request itself: where the program is going.
fn read_request<S: Read + Write>(network: &mut S) -> Option<(String, u16)> {
    let head = read_n(network, 4)?; // version, command, reserved, address kind
    if head[0] != VERSION {
        return None;
    }

    if head[1] != COMMAND_CONNECT {
        answer(network, REPLY_COMMAND_UNSUPPORTED);
        return None;
    }

    let host = match head[3] {
        ADDRESS_IPV4 => {
            let raw = read_n(network, 4)?;
            IpAddr::V4(Ipv4Addr::new(raw[0], raw[1], raw[2], raw[3])).to_string()
        }
        ADDRESS_IPV6 => {
            let raw = read_n(network, 16)?;
            let mut octets = [0u8; 16];
            octets.copy_from_slice(&raw);
            IpAddr::V6(Ipv6Addr::from(octets)).to_string()
        }
        ADDRESS_NAME => {
            let length = read_n(network, 1)?;
            if length[0] == 0 {
                return None;
            }
            let raw = read_n(network, length[0] as usize)?;
            // SOCKS5 names are ASCII; lossy decoding mirrors C# Encoding.ASCII.
            raw.iter().map(|&b| (b & 0x7f) as char).collect()
        }
        _ => {
            answer(network, REPLY_FAILURE);
            return None;
        }
    };

    let tail = read_n(network, 2)?;
    let port = ((tail[0] as u16) << 8) | tail[1] as u16;
    if port == 0 {
        None
    } else {
        Some((host, port))
    }
}

/// The answer to the request. The address in it is zeroes on purpose: the
/// program does not need to know which of our addresses the connection went out
/// of, and there is no honest answer anyway — it went out of somebody else's.
fn answer<W: Write>(network: &mut W, reply: u8) {
    let response = [VERSION, reply, 0, ADDRESS_IPV4, 0, 0, 0, 0, 0, 0];
    let _ = network.write_all(&response);
}

/// Reads exactly `count` bytes. `None` on a broken or closed connection,
/// mirroring the C# `Read` helper.
fn read_n<R: Read>(network: &mut R, count: usize) -> Option<Vec<u8>> {
    let mut buffer = vec![0u8; count];
    let mut got = 0;
    while got < count {
        match network.read(&mut buffer[got..]) {
            Ok(0) => return None,
            Ok(read) => got += read,
            Err(_) => return None,
        }
    }
    Some(buffer)
}

fn pump_to_circuit(shared: Arc<SocksShared>, mut client: TcpStream, stream: Arc<dyn MessageChannel>) {
    let mut buffer = vec![0u8; channel_limits::MAX_APPLICATION_MESSAGE];

    while !shared.stopping.load(Ordering::Acquire) && stream.is_open() {
        match client.read(&mut buffer) {
            Ok(0) | Err(_) => break,
            Ok(read) => stream.send(&buffer[..read]),
        }
    }
    stream.close();
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    /// A duplex double: reads come from `input`, writes land in `output`.
    struct Pipe {
        input: Cursor<Vec<u8>>,
        output: Vec<u8>,
    }

    impl Pipe {
        fn new(input: Vec<u8>) -> Pipe {
            Pipe {
                input: Cursor::new(input),
                output: Vec::new(),
            }
        }
    }

    impl Read for Pipe {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            self.input.read(buf)
        }
    }

    impl Write for Pipe {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.output.extend_from_slice(buf);
            Ok(buf.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn greet_accepts_no_auth() {
        // version 5, 1 method, method 0 (no auth)
        let mut pipe = Pipe::new(vec![5, 1, 0]);
        assert!(greet(&mut pipe));
        assert_eq!(pipe.output, vec![VERSION, METHOD_NONE]);
    }

    #[test]
    fn greet_rejects_when_no_acceptable_method() {
        // version 5, 1 method, method 2 (GSSAPI) — unsupported here
        let mut pipe = Pipe::new(vec![5, 1, 2]);
        assert!(!greet(&mut pipe));
        assert_eq!(pipe.output, vec![VERSION, METHOD_UNSUPPORTED]);
    }

    #[test]
    fn greet_rejects_wrong_version() {
        let mut pipe = Pipe::new(vec![4, 1, 0]);
        assert!(!greet(&mut pipe));
    }

    #[test]
    fn read_request_parses_a_domain_connect() {
        let host = b"example.com";
        let mut req = vec![VERSION, COMMAND_CONNECT, 0, ADDRESS_NAME, host.len() as u8];
        req.extend_from_slice(host);
        req.extend_from_slice(&[0x01, 0xBB]); // port 443
        let mut pipe = Pipe::new(req);

        let (parsed_host, port) = read_request(&mut pipe).unwrap();
        assert_eq!(parsed_host, "example.com");
        assert_eq!(port, 443);
    }

    #[test]
    fn read_request_parses_an_ipv4_connect() {
        let mut req = vec![VERSION, COMMAND_CONNECT, 0, ADDRESS_IPV4, 8, 8, 8, 8];
        req.extend_from_slice(&[0x00, 0x50]); // port 80
        let mut pipe = Pipe::new(req);

        let (host, port) = read_request(&mut pipe).unwrap();
        assert_eq!(host, "8.8.8.8");
        assert_eq!(port, 80);
    }

    #[test]
    fn read_request_refuses_non_connect() {
        // command 2 = BIND
        let req = vec![VERSION, 2, 0, ADDRESS_IPV4, 1, 2, 3, 4, 0, 80];
        let mut pipe = Pipe::new(req);
        assert!(read_request(&mut pipe).is_none());
        assert_eq!(pipe.output[1], REPLY_COMMAND_UNSUPPORTED);
    }

    #[test]
    fn read_request_rejects_port_zero() {
        let mut req = vec![VERSION, COMMAND_CONNECT, 0, ADDRESS_IPV4, 1, 1, 1, 1];
        req.extend_from_slice(&[0, 0]);
        let mut pipe = Pipe::new(req);
        assert!(read_request(&mut pipe).is_none());
    }

    #[test]
    fn answer_writes_zeroed_bound_address() {
        let mut pipe = Pipe::new(Vec::new());
        answer(&mut pipe, REPLY_OK);
        assert_eq!(pipe.output, vec![VERSION, REPLY_OK, 0, ADDRESS_IPV4, 0, 0, 0, 0, 0, 0]);
    }
}
