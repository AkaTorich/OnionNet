//! A finished circuit as the client sees it: the link to the guard plus the
//! keys of every hop.
//!
//! Only one link is open to the outside — to the first node. Everything else is
//! packed inside cells, and even the guard does not know how many nodes are
//! behind it. The handshake with the second and third node travels inside the
//! encrypted circuit, so the guard sees only "the client sent something onward".

use crate::crypto::rand;
use crate::directory::relay_descriptor::RelayDescriptor;
use crate::protocol::cell::{Cell, CellCommand};
use crate::protocol::client_circuit::ClientCircuit;
use crate::protocol::extend_payload;
use crate::protocol::ntor;
use crate::protocol::relay_cell::{RelayCell, RelayCommand};
use crate::transport::cell_channel::CellChannel;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Mutex;
use std::time::Duration;

const DEFAULT_TIMEOUT: Duration = Duration::from_secs(20);

/// How many circuits this participant built and still holds. Counted here
/// because a node knows only of other people's circuits that reached it from a
/// neighbour, while its own are built past it.
static LIVE: AtomicUsize = AtomicUsize::new(0);

pub fn live_count() -> usize {
    LIVE.load(Ordering::Relaxed)
}

/// A circuit could not be laid or held. `relay` names the node it broke down at,
/// so a single node's fault does not spoil the whole path's tally.
#[derive(Debug)]
pub struct CircuitError {
    pub message: String,
    pub relay: Option<RelayDescriptor>,
}

impl CircuitError {
    fn new(message: impl Into<String>) -> CircuitError {
        CircuitError {
            message: message.into(),
            relay: None,
        }
    }
    fn at(message: impl Into<String>, relay: &RelayDescriptor) -> CircuitError {
        CircuitError {
            message: message.into(),
            relay: Some(relay.clone()),
        }
    }
}

impl std::fmt::Display for CircuitError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.message)
    }
}
impl std::error::Error for CircuitError {}

pub struct Circuit {
    channel: CellChannel,
    crypto: Mutex<ClientCircuit>,
    circuit_id: u32,
    path: Vec<RelayDescriptor>,
    torn: AtomicBool,
}

impl Circuit {
    /// The circuit's nodes in order: the guard, the middles, the exit.
    pub fn path(&self) -> &[RelayDescriptor] {
        &self.path
    }
    pub fn length(&self) -> usize {
        self.path.len()
    }
    /// The number of the last hop — the usual addressee of application cells.
    pub fn exit_hop(&self) -> usize {
        self.path.len() - 1
    }

    pub fn build_default(path: Vec<RelayDescriptor>) -> Result<Circuit, CircuitError> {
        Circuit::build(path, DEFAULT_TIMEOUT)
    }

    /// Lays a circuit along the given path.
    pub fn build(path: Vec<RelayDescriptor>, timeout: Duration) -> Result<Circuit, CircuitError> {
        if path.is_empty() {
            return Err(CircuitError::new("the path is empty"));
        }

        let channel = CellChannel::connect_to(&path[0], timeout)
            .map_err(|e| CircuitError::at(format!("guard {} is unreachable: {e}", path[0]), &path[0]))?;

        let circuit_id = channel
            .allocate_circuit_id()
            .map_err(|e| CircuitError::at(format!("{e}"), &path[0]))?;

        let mut crypto = ClientCircuit::new();
        create_first_hop(&channel, circuit_id, &mut crypto, &path[0], timeout)?;
        for i in 1..path.len() {
            extend_to_next_hop(&channel, circuit_id, &mut crypto, &path[i], i, timeout)?;
        }

        LIVE.fetch_add(1, Ordering::Relaxed);
        Ok(Circuit {
            channel,
            crypto: Mutex::new(crypto),
            circuit_id,
            path,
            torn: AtomicBool::new(false),
        })
    }

    /// Sends a cell to the given hop. Wrapping and writing are one indivisible
    /// step: a hop has one keystream and one tag chain, and two cells assembled
    /// interleaved would part company for good.
    pub fn send_to(&self, cell: &RelayCell, hop_index: usize) -> Result<(), CircuitError> {
        self.ensure_alive()?;
        let mut crypto = self.crypto.lock().unwrap();
        let payload = crypto.wrap_outbound(cell, hop_index);
        self.channel
            .write(&Cell::new(self.circuit_id, CellCommand::Relay, payload))
            .map_err(|e| CircuitError::new(format!("{e}")))
    }

    /// Sends a cell to the last hop.
    pub fn send(&self, cell: &RelayCell) -> Result<(), CircuitError> {
        self.send_to(cell, self.exit_hop())
    }

    /// Waits for a cell from the circuit. `Ok(None)` if no answer came; the
    /// returned usize is the hop that sent it.
    pub fn receive(&self, timeout: Duration) -> Result<Option<(RelayCell, usize)>, CircuitError> {
        self.ensure_alive()?;
        let mut reply = match self.channel.read_timeout(timeout).map_err(|e| CircuitError::new(format!("{e}")))? {
            Some(c) => c,
            None => return Ok(None),
        };
        if reply.command == CellCommand::Destroy {
            self.torn.store(true, Ordering::Release);
            return Err(CircuitError::new("the circuit was destroyed by a node"));
        }
        if reply.command != CellCommand::Relay {
            return Ok(None);
        }
        let mut crypto = self.crypto.lock().unwrap();
        Ok(crypto.unwrap_inbound(&mut reply.payload).map(|(hop, cell)| (cell, hop)))
    }

    /// Sends to the last hop and waits for an answer from the same one.
    pub fn exchange(&self, request: &RelayCell, timeout: Duration) -> Result<Option<RelayCell>, CircuitError> {
        self.send_to(request, self.exit_hop())?;
        match self.receive(timeout)? {
            None => Ok(None),
            Some((answer, origin)) => {
                if origin != self.exit_hop() {
                    return Err(CircuitError::new(format!(
                        "the answer came from hop {origin}, while hop {} was expected",
                        self.exit_hop()
                    )));
                }
                Ok(Some(answer))
            }
        }
    }

    /// A junk cell: it evens the traffic out so pauses do not give the rhythm of
    /// work away.
    pub fn send_padding(&self) -> Result<(), CircuitError> {
        self.send_to(&RelayCell::new(RelayCommand::Drop, 0, rand::get_bytes(64)), self.exit_hop())
    }

    fn ensure_alive(&self) -> Result<(), CircuitError> {
        if self.torn.load(Ordering::Acquire) || self.channel.is_closed() {
            return Err(CircuitError::new("the circuit is no longer alive"));
        }
        Ok(())
    }
}

impl Drop for Circuit {
    fn drop(&mut self) {
        if !self.torn.swap(true, Ordering::AcqRel) && !self.channel.is_closed() {
            let _ = self.channel.write(&Cell::build(self.circuit_id, CellCommand::Destroy, &[]));
        }
        self.channel.close();
        LIVE.fetch_sub(1, Ordering::Relaxed);
    }
}

fn create_first_hop(
    channel: &CellChannel,
    circuit_id: u32,
    crypto: &mut ClientCircuit,
    guard: &RelayDescriptor,
    timeout: Duration,
) -> Result<(), CircuitError> {
    let handshake = ntor::begin_client(&guard.fingerprint(), &guard.onion_key)
        .map_err(|e| CircuitError::at(e.to_string(), guard))?;

    channel
        .write(&Cell::build(circuit_id, CellCommand::Create, handshake.message()))
        .map_err(|e| CircuitError::at(format!("{e}"), guard))?;

    let reply = channel
        .read_timeout(timeout)
        .map_err(|e| CircuitError::at(format!("{e}"), guard))?
        .ok_or_else(|| CircuitError::at(format!("guard {guard} did not answer Create"), guard))?;

    if reply.circuit_id != circuit_id {
        return Err(CircuitError::at("the guard answered on somebody else's circuit number", guard));
    }
    if reply.command == CellCommand::Destroy {
        return Err(CircuitError::at(format!("guard {guard} refused the circuit"), guard));
    }
    if reply.command != CellCommand::Created {
        return Err(CircuitError::at(format!("the guard sent {:?} instead of Created", reply.command), guard));
    }

    let server_message = &reply.payload[..ntor::SERVER_HANDSHAKE_SIZE];
    let material = handshake
        .complete(server_message)
        .ok_or_else(|| CircuitError::at(format!("guard {guard} did not prove its onion key"), guard))?;
    crypto.add_hop(&material);
    Ok(())
}

fn extend_to_next_hop(
    channel: &CellChannel,
    circuit_id: u32,
    crypto: &mut ClientCircuit,
    next: &RelayDescriptor,
    hop_number: usize,
    timeout: Duration,
) -> Result<(), CircuitError> {
    let handshake = ntor::begin_client(&next.fingerprint(), &next.onion_key)
        .map_err(|e| CircuitError::at(e.to_string(), next))?;

    let request = extend_payload::build(&next.host, next.port, &next.onion_key, handshake.message())
        .map_err(|e| CircuitError::at(e.to_string(), next))?;

    let last_hop = hop_number - 1;
    let payload = crypto.wrap_outbound(&RelayCell::new(RelayCommand::Extend, 0, request), last_hop);
    channel
        .write(&Cell::new(circuit_id, CellCommand::Relay, payload))
        .map_err(|e| CircuitError::at(format!("{e}"), next))?;

    let mut reply = channel
        .read_timeout(timeout)
        .map_err(|e| CircuitError::at(format!("{e}"), next))?
        .ok_or_else(|| CircuitError::at(format!("no answer to the extension to {next}"), next))?;

    if reply.command == CellCommand::Destroy {
        return Err(CircuitError::at(format!("the circuit was destroyed while extending to {next}"), next));
    }
    if reply.command != CellCommand::Relay {
        return Err(CircuitError::at(format!("while extending, {:?} arrived instead of Relay", reply.command), next));
    }

    let (origin, inner) = crypto
        .unwrap_inbound(&mut reply.payload)
        .ok_or_else(|| CircuitError::at("the answer to the extension came from the wrong hop", next))?;
    if origin != last_hop {
        return Err(CircuitError::at("the answer to the extension came from the wrong hop", next));
    }

    if inner.command == RelayCommand::Truncated {
        return Err(CircuitError::at(format!("node {last_hop} could not reach {next}"), next));
    }
    if inner.command != RelayCommand::Extended {
        return Err(CircuitError::at(format!("while extending, {:?} arrived instead of Extended", inner.command), next));
    }

    let material = handshake
        .complete(&inner.data)
        .ok_or_else(|| CircuitError::at(format!("node {next} did not prove its onion key"), next))?;
    crypto.add_hop(&material);
    Ok(())
}
