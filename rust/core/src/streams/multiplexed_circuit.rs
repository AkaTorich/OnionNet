//! A circuit with several streams at once.
//!
//! An ordinary [`Circuit`] works question-and-answer: you send and you wait.
//! For a port stack that is not enough — a file download, a relay's cards and a
//! proxied connection all travel over one circuit at the same time. So a
//! separate pump thread lives here: it sorts the arriving cells by stream
//! number, and the application code simply reads its own stream.
//!
//! The circuit stays one all the while: new streams build no new circuits and
//! start no new handshakes.

use crate::crypto::rand;
use crate::protocol::relay_cell::{RelayCell, RelayCommand, MAX_DATA_SIZE};
use crate::streams::message_channel::MessageChannel;
use crate::streams::stream_end_reason::StreamEndReason;
use crate::streams::stream_opener::{InternetOpener, StreamOpener};
use crate::streams::stream_payloads;
use crate::transport::circuit::Circuit;
use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Condvar, Mutex, Weak};
use std::thread::{self, JoinHandle};
use std::time::Duration;

/// How long the pump waits on a quiet circuit before looking around.
const PUMP_TIMEOUT: Duration = Duration::from_secs(1);

/// The default wait for the `Connected` answer when opening a stream.
const DEFAULT_OPEN_TIMEOUT: Duration = Duration::from_secs(20);

// --- A small blocking mailbox, standing in for C# BlockingCollection<byte[]> ---

struct Mailbox {
    state: Mutex<MailboxState>,
    cv: Condvar,
}

struct MailboxState {
    queue: VecDeque<Vec<u8>>,
    completed: bool,
}

impl Mailbox {
    fn new() -> Mailbox {
        Mailbox {
            state: Mutex::new(MailboxState {
                queue: VecDeque::new(),
                completed: false,
            }),
            cv: Condvar::new(),
        }
    }

    fn add(&self, item: Vec<u8>) {
        let mut s = self.state.lock().unwrap();
        if s.completed {
            return;
        }
        s.queue.push_back(item);
        self.cv.notify_one();
    }

    /// Waits up to `timeout` for an item. `None` on timeout or once the mailbox
    /// is completed and drained.
    fn take(&self, timeout: Duration) -> Option<Vec<u8>> {
        let mut s = self.state.lock().unwrap();
        loop {
            if let Some(item) = s.queue.pop_front() {
                return Some(item);
            }
            if s.completed {
                return None;
            }
            let (guard, wait) = self.cv.wait_timeout(s, timeout).unwrap();
            s = guard;
            if wait.timed_out() && s.queue.is_empty() {
                return None;
            }
        }
    }

    fn complete(&self) {
        let mut s = self.state.lock().unwrap();
        s.completed = true;
        self.cv.notify_all();
    }
}

// --- A one-shot "connected" event, standing in for ManualResetEventSlim ---

struct Gate {
    set: Mutex<bool>,
    cv: Condvar,
}

impl Gate {
    fn new() -> Gate {
        Gate {
            set: Mutex::new(false),
            cv: Condvar::new(),
        }
    }

    fn signal(&self) {
        let mut s = self.set.lock().unwrap();
        *s = true;
        self.cv.notify_all();
    }

    /// Waits up to `timeout` for the gate to be signalled; returns whether it was.
    fn wait(&self, timeout: Duration) -> bool {
        let s = self.set.lock().unwrap();
        if *s {
            return true;
        }
        let (guard, _) = self.cv.wait_timeout(s, timeout).unwrap();
        *guard
    }
}

/// A stream to an internal port on someone else's node — as seen by whoever
/// knocked.
///
/// It behaves like a TCP connection: it opened, carried some data, closed. Only
/// instead of a machine's address and port there is a circuit and a node's
/// internal port, and neither side knows where the other is.
pub struct ClientStream {
    owner: Weak<SharedCircuit>,
    stream_id: u16,
    port: u16,
    incoming: Mailbox,
    connected: Gate,
    closed: AtomicBool,
    end_reason: Mutex<StreamEndReason>,
}

impl ClientStream {
    fn new(owner: Weak<SharedCircuit>, stream_id: u16, port: u16) -> ClientStream {
        ClientStream {
            owner,
            stream_id,
            port,
            incoming: Mailbox::new(),
            connected: Gate::new(),
            closed: AtomicBool::new(false),
            end_reason: Mutex::new(StreamEndReason::Done),
        }
    }

    pub fn stream_id(&self) -> u16 {
        self.stream_id
    }

    pub fn port(&self) -> u16 {
        self.port
    }

    /// Why the stream closed. Meaningful only after it did.
    pub fn end_reason(&self) -> StreamEndReason {
        *self.end_reason.lock().unwrap()
    }

    fn wait_for_connected(&self, timeout: Duration) -> bool {
        self.connected.wait(timeout) && self.is_open()
    }

    fn mark_connected(&self) {
        self.connected.signal();
    }

    fn deliver(&self, data: Vec<u8>) {
        if self.closed.load(Ordering::Acquire) {
            return;
        }
        self.incoming.add(data);
    }

    fn mark_closed(&self, reason: StreamEndReason) {
        if self.closed.swap(true, Ordering::AcqRel) {
            return;
        }
        *self.end_reason.lock().unwrap() = reason;
        self.connected.signal(); // wake whoever waited for the connection
        self.incoming.complete();
    }
}

impl MessageChannel for ClientStream {
    /// Sends data. Anything longer than a cell it slices itself.
    fn send(&self, data: &[u8]) {
        if !self.is_open() {
            return; // the C# throws; here a send on a closed stream is a no-op
        }
        let owner = match self.owner.upgrade() {
            Some(o) => o,
            None => return,
        };

        if data.is_empty() {
            owner.send_on_stream(self.stream_id, Vec::new());
            return;
        }

        let mut offset = 0;
        while offset < data.len() {
            let take = std::cmp::min(MAX_DATA_SIZE, data.len() - offset);
            owner.send_on_stream(self.stream_id, data[offset..offset + take].to_vec());
            offset += take;
        }
    }

    fn receive(&self, timeout: Duration) -> Option<Vec<u8>> {
        self.incoming.take(timeout)
    }

    fn is_open(&self) -> bool {
        if self.closed.load(Ordering::Acquire) {
            return false;
        }
        self.owner.upgrade().map(|o| o.is_alive()).unwrap_or(false)
    }

    /// Closes the stream and tells the other side.
    fn close(&self) {
        if self.closed.load(Ordering::Acquire) {
            return;
        }
        match self.owner.upgrade() {
            Some(owner) => owner.close_stream(self, StreamEndReason::Done, true),
            None => self.mark_closed(StreamEndReason::CircuitGone),
        }
    }
}

// --- The shared state, held by the pump thread and the streams alike ---

struct State {
    streams: HashMap<u16, Arc<ClientStream>>,
    used_ids: HashSet<u16>,
}

struct SharedCircuit {
    circuit: Circuit,
    state: Mutex<State>,
    stopping: AtomicBool,
    open_timeout_ms: AtomicU64,
}

impl SharedCircuit {
    fn is_alive(&self) -> bool {
        !self.stopping.load(Ordering::Acquire)
    }

    fn open_timeout(&self) -> Duration {
        Duration::from_millis(self.open_timeout_ms.load(Ordering::Acquire))
    }

    fn send_on_stream(&self, stream_id: u16, data: Vec<u8>) {
        let _ = self.circuit.send(&RelayCell::new(RelayCommand::Data, stream_id, data));
    }

    fn close_stream(&self, stream: &ClientStream, reason: StreamEndReason, notify_peer: bool) {
        self.forget(stream.stream_id);
        stream.mark_closed(reason);

        if !notify_peer || self.stopping.load(Ordering::Acquire) {
            return;
        }
        let _ = self.circuit.send(&RelayCell::new(
            RelayCommand::End,
            stream.stream_id,
            stream_payloads::end(reason),
        ));
    }

    fn lookup(&self, stream_id: u16) -> Option<Arc<ClientStream>> {
        self.state.lock().unwrap().streams.get(&stream_id).cloned()
    }

    fn forget(&self, stream_id: u16) {
        let mut s = self.state.lock().unwrap();
        s.streams.remove(&stream_id);
        // Give the number back, or a long-lived circuit (the way out) runs out
        // of numbers after some tens of thousands of connections.
        s.used_ids.remove(&stream_id);
    }

    fn dispatch(&self, cell: RelayCell) {
        let stream = self.lookup(cell.stream_id);
        match cell.command {
            RelayCommand::Connected => {
                if let Some(s) = stream {
                    s.mark_connected();
                }
            }
            RelayCommand::Data => {
                if let Some(s) = stream {
                    s.deliver(cell.data);
                }
            }
            RelayCommand::End => {
                if let Some(s) = stream {
                    self.forget(cell.stream_id);
                    s.mark_closed(stream_payloads::read_end(&cell.data));
                }
            }
            RelayCommand::Drop => {}
            _ => {}
        }
    }

    fn tear_down_all(&self, reason: StreamEndReason) {
        let doomed: Vec<Arc<ClientStream>> = {
            let mut s = self.state.lock().unwrap();
            s.streams.drain().map(|(_, v)| v).collect()
        };
        for stream in doomed {
            stream.mark_closed(reason);
        }
    }

    /// Stream numbers are handed out at random rather than in order: from rising
    /// numbers the exit node could count how many connections the client opened
    /// altogether. `None` only if the (practically impossible) 65535-id space is
    /// exhausted.
    fn allocate_stream_id(&self) -> Option<u16> {
        let mut s = self.state.lock().unwrap();
        for _ in 0..1000 {
            let bytes = rand::get_bytes(2);
            let id = ((bytes[0] as u16) << 8) | bytes[1] as u16;
            if id == 0 || s.used_ids.contains(&id) {
                continue;
            }
            s.used_ids.insert(id);
            return Some(id);
        }
        None
    }
}

/// A circuit with several streams at once (the C# `MultiplexedCircuit`).
pub struct MultiplexedCircuit {
    shared: Arc<SharedCircuit>,
    pump: Mutex<Option<JoinHandle<()>>>,
}

impl MultiplexedCircuit {
    pub fn new(circuit: Circuit) -> MultiplexedCircuit {
        let shared = Arc::new(SharedCircuit {
            circuit,
            state: Mutex::new(State {
                streams: HashMap::new(),
                used_ids: HashSet::new(),
            }),
            stopping: AtomicBool::new(false),
            open_timeout_ms: AtomicU64::new(DEFAULT_OPEN_TIMEOUT.as_millis() as u64),
        });

        let pump_shared = shared.clone();
        let pump = thread::Builder::new()
            .name("stalknet-pump".into())
            .spawn(move || pump_loop(pump_shared))
            .expect("spawn pump thread");

        MultiplexedCircuit {
            shared,
            pump: Mutex::new(Some(pump)),
        }
    }

    /// How long to wait for the `Connected` answer when opening a stream.
    pub fn set_open_timeout(&self, timeout: Duration) {
        self.shared
            .open_timeout_ms
            .store(timeout.as_millis() as u64, Ordering::Release);
    }

    pub fn is_alive(&self) -> bool {
        self.shared.is_alive()
    }

    pub fn circuit(&self) -> &Circuit {
        &self.shared.circuit
    }

    /// How many streams are open right now.
    pub fn stream_count(&self) -> usize {
        self.shared.state.lock().unwrap().streams.len()
    }

    /// Opens a stream to an internal port on the circuit's exit node. Returns
    /// `None` if the port is closed or the node did not answer.
    pub fn open(&self, port: u16) -> Option<Arc<ClientStream>> {
        if port == 0 || self.shared.stopping.load(Ordering::Acquire) {
            return None;
        }

        let stream_id = self.shared.allocate_stream_id()?;
        let stream = Arc::new(ClientStream::new(Arc::downgrade(&self.shared), stream_id, port));
        self.shared
            .state
            .lock()
            .unwrap()
            .streams
            .insert(stream_id, stream.clone());

        let begin = RelayCell::new(RelayCommand::Begin, stream_id, stream_payloads::begin(port));
        if self.shared.circuit.send(&begin).is_err() {
            self.shared.forget(stream_id);
            return None;
        }

        if !stream.wait_for_connected(self.shared.open_timeout()) {
            self.shared.forget(stream_id);
            stream.mark_closed(StreamEndReason::ConnectFailed);
            return None;
        }

        Some(stream)
    }

    /// Opens a stream to an address outside the network — if the exit node
    /// agrees to let us out there.
    ///
    /// The destination goes into the cell, so it is known to the exit node and
    /// to nobody before it: the middle hops see only cells of the same size
    /// going by. Which is the whole arrangement — the exit knows where but not
    /// who, the guard knows who but not where.
    pub fn open_to(&self, host: &str, port: u16) -> Option<Arc<ClientStream>> {
        if host.trim().is_empty() || port == 0 {
            return None;
        }
        if self.shared.stopping.load(Ordering::Acquire) {
            return None;
        }

        let payload = stream_payloads::begin_to(host, port).ok()?;

        let stream_id = self.shared.allocate_stream_id()?;
        let stream = Arc::new(ClientStream::new(Arc::downgrade(&self.shared), stream_id, port));
        self.shared
            .state
            .lock()
            .unwrap()
            .streams
            .insert(stream_id, stream.clone());

        let begin_to = RelayCell::new(RelayCommand::BeginTo, stream_id, payload);
        if self.shared.circuit.send(&begin_to).is_err() {
            self.shared.forget(stream_id);
            return None;
        }

        if !stream.wait_for_connected(self.shared.open_timeout()) {
            self.shared.forget(stream_id);
            stream.mark_closed(StreamEndReason::ConnectFailed);
            return None;
        }

        Some(stream)
    }

    fn dispose(&self) {
        if self.shared.stopping.swap(true, Ordering::AcqRel) {
            return;
        }
        self.shared.tear_down_all(StreamEndReason::CircuitGone);

        // The pump is sitting on a `receive` with PUMP_TIMEOUT; once `stopping`
        // is set it exits at the next turn of the loop. (The C# tears the
        // circuit's socket down first to avoid this wait; the ported circuit
        // offers no public early-close, so a close may lag by up to PUMP_TIMEOUT.)
        if let Some(handle) = self.pump.lock().unwrap().take() {
            let _ = handle.join();
        }
    }
}

impl Drop for MultiplexedCircuit {
    fn drop(&mut self) {
        self.dispose();
    }
}

impl StreamOpener for MultiplexedCircuit {
    fn open(&self, port: u16) -> Option<Arc<dyn MessageChannel>> {
        self.open(port).map(|s| s as Arc<dyn MessageChannel>)
    }
    fn is_alive(&self) -> bool {
        self.is_alive()
    }
}

impl InternetOpener for MultiplexedCircuit {
    fn open_to(&self, host: &str, port: u16) -> Option<Arc<dyn MessageChannel>> {
        self.open_to(host, port).map(|s| s as Arc<dyn MessageChannel>)
    }
    fn is_alive(&self) -> bool {
        self.is_alive()
    }
}

fn pump_loop(shared: Arc<SharedCircuit>) {
    let exit = shared.circuit.exit_hop();
    while !shared.stopping.load(Ordering::Acquire) {
        match shared.circuit.receive(PUMP_TIMEOUT) {
            Err(_) => break,      // the circuit broke
            Ok(None) => continue, // just silence — keep waiting
            // Streams end at the last hop; a cell from a middle hop is not
            // theirs and must not be slipped into them.
            Ok(Some((cell, origin))) if origin == exit => shared.dispatch(cell),
            Ok(Some(_)) => {}
        }
    }
    // Whatever ended the loop, the circuit is dead now: say so, so the code
    // above (the way out, hidden connections) builds a fresh one.
    shared.stopping.store(true, Ordering::Release);
    shared.tear_down_all(StreamEndReason::CircuitGone);
}
