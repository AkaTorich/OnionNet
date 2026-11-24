//! The client's outward proxy: it listens on a port on its own machine and
//! leads every connection into the network, to an internal port on someone
//! else's node.
//!
//! To an ordinary program it looks like the most ordinary local port: a browser,
//! a database client, anything — connects to 127.0.0.1 and never suspects that
//! three hops of encryption sit behind the port.
//!
//! We deliberately listen on the loopback address only: a proxy reachable from
//! the local network would turn the machine into an entrance to StalkNet for the
//! neighbours.

use crate::streams::channel_limits;
use crate::streams::message_channel::MessageChannel;
use crate::streams::stream_opener::StreamOpener;
use std::io::{Read, Write};
use std::net::{Ipv4Addr, SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, AtomicU16, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::Duration;

const READ_TIMEOUT: Duration = Duration::from_secs(30);

struct ForwarderShared {
    opener: Arc<dyn StreamOpener>,
    remote_port: u16,
    stopping: AtomicBool,
    active: AtomicUsize,
    local_port: AtomicU16,
    bound_addr: Mutex<Option<SocketAddr>>,
}

pub struct LocalPortForwarder {
    shared: Arc<ForwarderShared>,
    accept_handle: Mutex<Option<JoinHandle<()>>>,
}

impl LocalPortForwarder {
    pub fn new(opener: Arc<dyn StreamOpener>, local_port: u16, remote_port: u16) -> LocalPortForwarder {
        assert!(remote_port != 0, "remote port out of range");
        LocalPortForwarder {
            shared: Arc::new(ForwarderShared {
                opener,
                remote_port,
                stopping: AtomicBool::new(false),
                active: AtomicUsize::new(0),
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

    /// The internal port of the node at the far end of the circuit.
    pub fn remote_port(&self) -> u16 {
        self.shared.remote_port
    }

    /// How many connections are forwarded right now.
    pub fn active_connections(&self) -> usize {
        self.shared.active.load(Ordering::Acquire)
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
            .name(format!("stalknet-proxy-{}", local.port()))
            .spawn(move || accept_loop(shared, listener))
            .expect("spawn forwarder accept thread");
        *self.accept_handle.lock().unwrap() = Some(handle);
        Ok(())
    }

    fn dispose(&self) {
        if self.shared.stopping.swap(true, Ordering::AcqRel) {
            return;
        }
        if let Some(addr) = *self.shared.bound_addr.lock().unwrap() {
            let _ = TcpStream::connect_timeout(&addr, Duration::from_millis(200));
        }
        if let Some(handle) = self.accept_handle.lock().unwrap().take() {
            let _ = handle.join();
        }
    }
}

impl Drop for LocalPortForwarder {
    fn drop(&mut self) {
        self.dispose();
    }
}

fn accept_loop(shared: Arc<ForwarderShared>, listener: TcpListener) {
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
                    .name("stalknet-bridge".into())
                    .spawn(move || bridge(s, client));
            }
            Err(_) => return, // the listener was stopped
        }
    }
}

fn bridge(shared: Arc<ForwarderShared>, client: TcpStream) {
    shared.active.fetch_add(1, Ordering::AcqRel);
    let _ = client.set_nodelay(true);

    let stream = match shared.opener.open(shared.remote_port) {
        Some(s) => s,
        None => {
            let _ = client.shutdown(std::net::Shutdown::Both);
            shared.active.fetch_sub(1, Ordering::AcqRel);
            return;
        }
    };

    let outcome = bridge_inner(&shared, &client, &stream);
    let _ = outcome;

    stream.close();
    let _ = client.shutdown(std::net::Shutdown::Both);
    shared.active.fetch_sub(1, Ordering::AcqRel);
}

fn bridge_inner(
    shared: &Arc<ForwarderShared>,
    client: &TcpStream,
    stream: &Arc<dyn MessageChannel>,
) -> Option<()> {
    // One thread pours from the socket into the circuit; this one pours from the
    // circuit into the socket.
    let up_shared = shared.clone();
    let up_client = client.try_clone().ok()?;
    let up_stream = stream.clone();
    let upstream = thread::Builder::new()
        .name("stalknet-up".into())
        .spawn(move || pump_to_circuit(up_shared, up_client, up_stream))
        .ok()?;

    let mut network = client.try_clone().ok()?;
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

    // Wake the other thread out of its read on the program's socket, so the
    // program sees the end now rather than when it next sends something.
    stream.close();
    let _ = client.shutdown(std::net::Shutdown::Both);
    let _ = upstream.join();
    Some(())
}

fn pump_to_circuit(shared: Arc<ForwarderShared>, mut client: TcpStream, stream: Arc<dyn MessageChannel>) {
    let mut buffer = vec![0u8; channel_limits::MAX_APPLICATION_MESSAGE];

    while !shared.stopping.load(Ordering::Acquire) && stream.is_open() {
        match client.read(&mut buffer) {
            Ok(0) | Err(_) => break,
            Ok(read) => stream.send(&buffer[..read]),
        }
    }
    stream.close();
}
