//! The way out to the internet behind a hidden address.
//!
//! An ordinary exit node stands in the network list, and everyone knows which
//! participant it is. This one is found through the storage nodes under an
//! address made for the occasion: the guest does not know whose machine lets
//! them out, the owner does not know whom they let out.
//!
//! What cannot be hidden: the sites outside see the address the traffic leaves
//! from, and whoever answers for that address answers for the traffic. So the
//! rule is the same as for an ordinary exit — off until the owner switches it on,
//! and never into the machine's own networks.
//!
//! The first message on a stream names where to: the port and the host. The
//! answer is one byte — zero, or the reason for the refusal. After that the
//! stream carries the connection's bytes both ways.
//!
//! ## Decoupling from the relay stack
//!
//! In the C# node the service is an `IPortService` bound to a `PortStack` and
//! the guest side leans on `IStreamOpener`. Those live in the Streams/relay
//! layer, ported separately, so here:
//!
//! * [`ExitStream`] is the server side of one stream the service answers through
//!   (the C# `ServerStream`).
//! * the "may I go to host:port, and to which address" decision is an injected
//!   closure — it stands in for `ExitPolicy.TryResolve`, whose port rules are not
//!   yet ported; the main thread wires it to the policy once that lands.
//! * [`StreamOpener`] is the guest's side (the C# `IStreamOpener`), and
//!   [`HiddenExitOpener`] drives it, returning a [`MessageChannel`] once the exit
//!   has accepted the destination.
//!
//! The exit virtual port is `6` (`WellKnownPorts.Exit`).

use crate::swarm::swarm_service::MessageChannel;
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

/// The anonymous way out to the internet (`WellKnownPorts.Exit` in the C#). The
/// relay layer binds the service here and the opener reaches for it.
pub const EXIT_PORT: u16 = 6;

/// The largest application message the stream layer carries (see
/// [`crate::swarm::swarm_protocol::MAX_MESSAGE_SIZE`]).
const MAX_APPLICATION_MESSAGE: usize = crate::swarm::swarm_protocol::MAX_MESSAGE_SIZE;

const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

/// Why the exit refused — the byte sent back mirrors `StreamEndReason`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum ExitRefusal {
    Done = 0,
    PortClosed = 1,
    ConnectFailed = 2,
    TooManyStreams = 3,
    BadRequest = 4,
    ServerError = 5,
    CircuitGone = 6,
    NotAllowed = 7,
}

/// The server side of one stream the exit answers through.
pub trait ExitStream: Send + Sync {
    fn send(&self, data: &[u8]);
    fn is_open(&self) -> bool;
    fn close(&self);
}

/// Per-stream state: whether the destination was named, and the open connection
/// outside once there is one.
pub struct Session {
    asked: bool,
    client: Option<TcpStream>,
}

pub type ExitSession = Arc<Mutex<Session>>;

type Resolver = dyn Fn(&str, u16) -> std::result::Result<SocketAddr, ExitRefusal> + Send + Sync;

pub struct ExitService {
    resolve: Arc<Resolver>,
    served: AtomicU64,
}

impl ExitService {
    /// `resolve` answers "may a guest go to this host and port, and to which
    /// address" — the injected stand-in for `ExitPolicy.TryResolve`.
    pub fn new<R>(resolve: R) -> ExitService
    where
        R: Fn(&str, u16) -> std::result::Result<SocketAddr, ExitRefusal> + Send + Sync + 'static,
    {
        ExitService {
            resolve: Arc::new(resolve),
            served: AtomicU64::new(0),
        }
    }

    /// How many connections went out — for the window.
    pub fn served(&self) -> u64 {
        self.served.load(Ordering::Relaxed)
    }

    /// A fresh session for a newly opened stream (the C# `OnOpen`).
    pub fn on_open(&self) -> ExitSession {
        Arc::new(Mutex::new(Session { asked: false, client: None }))
    }

    /// The request: what goes first on the stream. `None` for a bad host.
    pub fn request(host: &str, port: u16) -> Option<Vec<u8>> {
        let name = host.as_bytes();
        if name.is_empty() || name.len() > 255 {
            return None;
        }
        let mut out = Vec::with_capacity(4 + name.len());
        out.push(1);
        out.extend_from_slice(&port.to_le_bytes());
        out.push(name.len() as u8);
        out.extend_from_slice(name);
        Some(out)
    }

    pub fn on_data(&self, session: &ExitSession, data: &[u8], stream: Arc<dyn ExitStream>) {
        // Already connected: forward the client's bytes out.
        {
            let s = session.lock().unwrap();
            if let Some(client) = s.client.as_ref() {
                let write = (&mut &*client).write_all(data);
                drop(s);
                if write.is_err() {
                    shut(&stream, session);
                }
                return;
            }
            if s.asked {
                return;
            }
        }

        {
            let mut s = session.lock().unwrap();
            if s.asked {
                return;
            }
            s.asked = true;
        }

        let (host, port) = match try_read(data) {
            Some(v) => v,
            None => {
                refuse(&stream, ExitRefusal::BadRequest);
                return;
            }
        };

        let address = match (self.resolve)(&host, port) {
            Ok(a) => a,
            Err(refusal) => {
                refuse(&stream, refusal);
                return;
            }
        };

        let client = match TcpStream::connect_timeout(&address, CONNECT_TIMEOUT) {
            Ok(c) => c,
            Err(_) => {
                refuse(&stream, ExitRefusal::ConnectFailed);
                return;
            }
        };
        let _ = client.set_nodelay(true);

        // One handle stays in the session for the client's outbound bytes; the
        // pump thread reads the internet side through a second handle.
        let pump_handle = match client.try_clone() {
            Ok(c) => c,
            Err(_) => {
                refuse(&stream, ExitRefusal::ServerError);
                return;
            }
        };
        session.lock().unwrap().client = Some(client);

        self.served.fetch_add(1, Ordering::Relaxed);
        stream.send(&[0]);

        let stream_for_pump = stream.clone();
        let session_for_pump = session.clone();
        let _ = thread::Builder::new()
            .name("stalknet-exit".into())
            .spawn(move || pump(stream_for_pump, session_for_pump, pump_handle));
    }

    pub fn on_close(&self, session: &ExitSession) {
        let client = session.lock().unwrap().client.take();
        if let Some(client) = client {
            let _ = client.shutdown(std::net::Shutdown::Both);
        }
    }
}

fn pump(stream: Arc<dyn ExitStream>, session: ExitSession, mut client: TcpStream) {
    let mut buffer = vec![0u8; MAX_APPLICATION_MESSAGE];
    loop {
        if !stream.is_open() {
            break;
        }
        match client.read(&mut buffer) {
            Ok(0) | Err(_) => break,
            Ok(read) => stream.send(&buffer[..read]),
        }
    }
    shut(&stream, &session);
}

fn shut(stream: &Arc<dyn ExitStream>, session: &ExitSession) {
    stream.close();
    let client = session.lock().unwrap().client.take();
    if let Some(client) = client {
        let _ = client.shutdown(std::net::Shutdown::Both);
    }
}

fn refuse(stream: &Arc<dyn ExitStream>, reason: ExitRefusal) {
    let wire = if reason == ExitRefusal::Done {
        ExitRefusal::NotAllowed as u8
    } else {
        reason as u8
    };
    stream.send(&[wire]);
    stream.close();
}

fn try_read(data: &[u8]) -> Option<(String, u16)> {
    if data.len() < 5 || data[0] != 1 {
        return None;
    }
    let port = (data[1] as u16) | ((data[2] as u16) << 8);
    let length = data[3] as usize;
    if length == 0 || data.len() != 4 + length {
        return None;
    }
    let host = String::from_utf8_lossy(&data[4..4 + length]).into_owned();
    Some((host, port))
}

/// The guest's side: how a stream to the exit port is obtained.
pub trait StreamOpener {
    /// Opens a stream to the given virtual port on the hidden exit's node.
    fn open(&self, port: u16) -> Option<Box<dyn MessageChannel>>;
    /// Whether the underlying connection is still usable.
    fn is_alive(&self) -> bool;
}

/// The guest's side of a hidden exit: what the SOCKS door is led through.
pub struct HiddenExitOpener {
    connection: Box<dyn StreamOpener>,
    pub timeout: Duration,
}

impl HiddenExitOpener {
    pub fn new(connection: Box<dyn StreamOpener>) -> HiddenExitOpener {
        HiddenExitOpener {
            connection,
            timeout: Duration::from_secs(30),
        }
    }

    pub fn is_alive(&self) -> bool {
        self.connection.is_alive()
    }

    /// Opens a connection to `host:port` through the exit. `None` if the exit
    /// refused or could not be reached.
    pub fn open_to(&self, host: &str, port: u16) -> Option<Box<dyn MessageChannel>> {
        let channel = self.connection.open(EXIT_PORT)?;

        let request = ExitService::request(host, port)?;
        channel.send(&request);

        if let Some(answer) = channel.receive(self.timeout) {
            if answer.len() == 1 && answer[0] == 0 {
                return Some(channel);
            }
        }

        channel.close();
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::TcpListener;
    use std::sync::mpsc;

    struct ChannelStream {
        tx: mpsc::Sender<Vec<u8>>,
        open: Arc<std::sync::atomic::AtomicBool>,
    }
    impl ExitStream for ChannelStream {
        fn send(&self, data: &[u8]) {
            let _ = self.tx.send(data.to_vec());
        }
        fn is_open(&self) -> bool {
            self.open.load(Ordering::SeqCst)
        }
        fn close(&self) {
            self.open.store(false, Ordering::SeqCst);
        }
    }

    #[test]
    fn request_round_trips() {
        let req = ExitService::request("example.com", 443).unwrap();
        let (host, port) = try_read(&req).unwrap();
        assert_eq!(host, "example.com");
        assert_eq!(port, 443);
        assert!(ExitService::request("", 80).is_none());
    }

    #[test]
    fn a_bad_request_is_refused_not_allowed() {
        let service = ExitService::new(|_h, _p| Err(ExitRefusal::NotAllowed));
        let session = service.on_open();
        let (tx, rx) = mpsc::channel();
        let stream: Arc<dyn ExitStream> = Arc::new(ChannelStream {
            tx,
            open: Arc::new(std::sync::atomic::AtomicBool::new(true)),
        });

        // A malformed first message (data[0] != 1).
        service.on_data(&session, &[9, 9, 9, 9, 9], stream);
        let answer = rx.recv_timeout(Duration::from_secs(2)).unwrap();
        assert_eq!(answer, vec![ExitRefusal::BadRequest as u8]);
    }

    #[test]
    fn forwards_bytes_to_an_echo_server() {
        // A local echo server stands in for "the internet".
        let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let addr = listener.local_addr().unwrap();
        thread::spawn(move || {
            if let Ok((mut sock, _)) = listener.accept() {
                let mut buf = [0u8; 64];
                loop {
                    match sock.read(&mut buf) {
                        Ok(0) | Err(_) => break,
                        Ok(n) => {
                            if sock.write_all(&buf[..n]).is_err() {
                                break;
                            }
                        }
                    }
                }
            }
        });

        let service = ExitService::new(move |_h, _p| Ok(addr));
        let session = service.on_open();
        let (tx, rx) = mpsc::channel();
        let open = Arc::new(std::sync::atomic::AtomicBool::new(true));
        let stream: Arc<dyn ExitStream> = Arc::new(ChannelStream { tx, open: open.clone() });

        // Name the destination, then send a payload.
        let request = ExitService::request("anything", addr.port()).unwrap();
        service.on_data(&session, &request, stream.clone());

        let ok = rx.recv_timeout(Duration::from_secs(3)).unwrap();
        assert_eq!(ok, vec![0u8], "the exit accepts with a zero byte");

        service.on_data(&session, b"ping", stream.clone());
        let echoed = rx.recv_timeout(Duration::from_secs(3)).unwrap();
        assert_eq!(echoed, b"ping");

        open.store(false, Ordering::SeqCst);
        service.on_close(&session);
        assert_eq!(service.served(), 1);
    }
}
