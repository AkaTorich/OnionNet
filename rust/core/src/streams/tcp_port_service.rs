//! A service that forwards an internal network port to a local service on the
//! machine.
//!
//! Internal port 8080 on a node may lead to 127.0.0.1:8080 — or anywhere else,
//! that is the owner's call. Nothing is opened to the outside by it: from
//! outside the machine still shows only the relay's port, and the local service
//! goes on listening on the loopback address as before.
//!
//! There is deliberately no "connect wherever the guest says": the destination
//! is set by the owner when the port is offered. Otherwise the node would become
//! an open proxy into somebody's local network.

use crate::streams::channel_limits;
use crate::streams::port_stack::{PortService, ServerStream};
use crate::streams::stream_end_reason::StreamEndReason;
use std::io::{Read, Write};
use std::net::{Shutdown, TcpStream, ToSocketAddrs};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

const DEFAULT_CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

pub struct TcpPortService {
    host: String,
    port: u16,
    connect_timeout: Duration,
    stopping: Arc<AtomicBool>,
}

impl TcpPortService {
    pub fn new(host: &str, port: u16) -> TcpPortService {
        TcpPortService::with_timeout(host, port, DEFAULT_CONNECT_TIMEOUT)
    }

    pub fn with_timeout(host: &str, port: u16, connect_timeout: Duration) -> TcpPortService {
        assert!(!host.is_empty(), "no address was given");
        assert!(port != 0, "port out of range");
        TcpPortService {
            host: host.to_string(),
            port,
            connect_timeout,
            stopping: Arc::new(AtomicBool::new(false)),
        }
    }

    pub fn target(&self) -> String {
        format!("{}:{}", self.host, self.port)
    }

    /// Opens the local connection, within the connect timeout. `None` on failure.
    fn connect(&self) -> Option<TcpStream> {
        let addresses = (self.host.as_str(), self.port).to_socket_addrs().ok()?;
        for addr in addresses {
            if let Ok(client) = TcpStream::connect_timeout(&addr, self.connect_timeout) {
                return Some(client);
            }
        }
        None
    }
}

impl PortService for TcpPortService {
    fn on_open(&self, stream: Arc<ServerStream>) -> bool {
        if self.stopping.load(Ordering::Acquire) {
            return false;
        }

        let client = match self.connect() {
            Some(c) => c,
            None => return false,
        };
        let _ = client.set_nodelay(true);

        let reader_client = match client.try_clone() {
            Ok(c) => c,
            Err(_) => return false,
        };

        stream.set_state(Box::new(client));

        let stopping = self.stopping.clone();
        let reader_stream = stream.clone();
        let port = self.port;
        let _ = thread::Builder::new()
            .name(format!("stalknet-tcp-{port}"))
            .spawn(move || pump_to_network(reader_stream, reader_client, stopping));

        true
    }

    fn on_data(&self, stream: &Arc<ServerStream>, data: &[u8]) {
        if data.is_empty() {
            return;
        }

        let result = stream.with_state::<TcpStream, _>(|client| {
            let mut writer: &TcpStream = client;
            writer.write_all(data)
        });

        if let Some(Err(_)) = result {
            stream.close(StreamEndReason::Done);
            if let Some(client) = stream.take_state() {
                if let Ok(client) = client.downcast::<TcpStream>() {
                    let _ = client.shutdown(Shutdown::Both);
                }
            }
        }
    }

    fn on_close(&self, stream: &Arc<ServerStream>) {
        if let Some(client) = stream.take_state() {
            if let Ok(client) = client.downcast::<TcpStream>() {
                let _ = client.shutdown(Shutdown::Both);
            }
        }
    }
}

impl Drop for TcpPortService {
    fn drop(&mut self) {
        self.stopping.store(true, Ordering::Release);
    }
}

/// Moves everything the local service says into the circuit.
fn pump_to_network(stream: Arc<ServerStream>, mut client: TcpStream, stopping: Arc<AtomicBool>) {
    let mut buffer = vec![0u8; channel_limits::MAX_APPLICATION_MESSAGE];

    while !stopping.load(Ordering::Acquire) && stream.is_open() {
        match client.read(&mut buffer) {
            Ok(0) | Err(_) => break,
            Ok(read) => stream.send(&buffer[..read]),
        }
    }

    stream.close(StreamEndReason::Done);
    let _ = client.shutdown(Shutdown::Both);
}
