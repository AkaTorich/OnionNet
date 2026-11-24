//! Several streams inside one end-to-end channel.
//!
//! A meeting with a service costs six hops and two handshakes — setting up a new
//! one per connection would be wasteful. So inside an already open channel the
//! same port stack works as in an ordinary circuit: we address a "service,
//! internal port" pair, and the folders and the forwarded ports both travel over
//! one meeting.
//!
//! The header is three bytes: the stream number (`u16`, big-endian) and the
//! command. The shared message ceiling is lowered by exactly that much, see
//! [`crate::streams::channel_limits`]. The wire format matches the C#
//! `HiddenMux` byte for byte.

use crate::crypto::rand;
use crate::streams::channel_limits::{MAX_APPLICATION_MESSAGE, MUX_HEADER};
use crate::streams::message_channel::MessageChannel;
use crate::streams::port_stack::{PortService, PortStack, ServerStream};
use crate::streams::stream_opener::StreamOpener;
use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Condvar, Mutex, Weak};
use std::thread::{self, JoinHandle};
use std::time::Duration;

/// How long the pump waits on a quiet channel before looking around.
const PUMP_TIMEOUT: Duration = Duration::from_secs(1);

/// The default wait for the `Connected` answer when opening a stream.
const DEFAULT_OPEN_TIMEOUT: Duration = Duration::from_secs(30);

/// The multiplexer's commands inside an end-to-end channel.
///
/// (The C# `MuxCommand`.)
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
enum MuxCommand {
    Begin = 1,
    Connected = 2,
    Data = 3,
    End = 4,
}

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

    fn wait(&self, timeout: Duration) -> bool {
        let s = self.set.lock().unwrap();
        if *s {
            return true;
        }
        let (guard, _) = self.cv.wait_timeout(s, timeout).unwrap();
        *guard
    }
}

// --- The shared state, held by the pump thread and the streams alike ---

struct MuxState {
    /// Streams this side opened, keyed by id.
    streams: HashMap<u16, Arc<MuxStream>>,
    /// Streams the guest opened into our port stack, keyed by id.
    hosted: HashMap<u16, HostedEntry>,
    used_ids: HashSet<u16>,
}

/// What the service needs to route a hosted stream's data and close.
struct HostedEntry {
    service: Arc<dyn PortService>,
    server: Arc<ServerStream>,
}

struct MuxInner {
    channel: Arc<dyn MessageChannel>,
    stack: Option<Arc<PortStack>>,
    state: Mutex<MuxState>,
    stopping: AtomicBool,
    open_timeout_ms: AtomicU64,
}

impl MuxInner {
    fn is_alive(&self) -> bool {
        !self.stopping.load(Ordering::Acquire) && self.channel.is_open()
    }

    fn open_timeout(&self) -> Duration {
        Duration::from_millis(self.open_timeout_ms.load(Ordering::Acquire))
    }

    // ---- Framing -----------------------------------------------------------

    fn frame(id: u16, command: MuxCommand, body: &[u8]) -> Vec<u8> {
        let mut frame = Vec::with_capacity(MUX_HEADER + body.len());
        frame.push((id >> 8) as u8);
        frame.push(id as u8);
        frame.push(command as u8);
        frame.extend_from_slice(body);
        frame
    }

    fn send_data(&self, id: u16, data: &[u8]) {
        if !self.is_alive() {
            return;
        }
        // A frame that does not fit the end-to-end cell is dropped rather than
        // panicking — mirrors the C# ArgumentException, which no caller feeds.
        if data.len() > MAX_APPLICATION_MESSAGE {
            return;
        }
        self.channel.send(&Self::frame(id, MuxCommand::Data, data));
    }

    fn send_end(&self, id: u16) {
        if !self.is_alive() {
            return;
        }
        self.channel.send(&Self::frame(id, MuxCommand::End, &[]));
    }

    fn close_stream(&self, stream: &MuxStream) {
        self.forget(stream.id);
        stream.mark_closed();
        self.send_end(stream.id);
    }

    // ---- Opening (the guest's side) ----------------------------------------

    fn open(self: &Arc<Self>, port: u16) -> Option<Arc<MuxStream>> {
        if port == 0 || self.stopping.load(Ordering::Acquire) {
            return None;
        }

        let id = self.allocate_id()?;
        let stream = Arc::new(MuxStream::new(Arc::downgrade(self), id));
        self.state.lock().unwrap().streams.insert(id, stream.clone());

        self.channel.send(&Self::frame(
            id,
            MuxCommand::Begin,
            &[(port >> 8) as u8, port as u8],
        ));

        if !stream.wait_for_connected(self.open_timeout()) {
            self.forget(id);
            stream.mark_closed();
            return None;
        }

        Some(stream)
    }

    // ---- The pump ----------------------------------------------------------

    fn dispatch(self: &Arc<Self>, frame: Vec<u8>) {
        if frame.len() < MUX_HEADER {
            return;
        }
        let id = ((frame[0] as u16) << 8) | frame[1] as u16;
        let command = frame[2];
        let body = frame[MUX_HEADER..].to_vec();

        if command == MuxCommand::Begin as u8 {
            self.host_begin(id, &body);
        } else if command == MuxCommand::Connected as u8 {
            if let Some(stream) = self.lookup(id) {
                stream.mark_connected();
            }
        } else if command == MuxCommand::Data as u8 {
            if let Some(stream) = self.lookup(id) {
                stream.deliver(body);
            } else {
                self.host_data(id, &body);
            }
        } else if command == MuxCommand::End as u8 {
            if let Some(stream) = self.lookup(id) {
                self.forget(id);
                stream.mark_closed();
            } else {
                self.host_end(id);
            }
        }
    }

    // ---- The service's side: sorting into ports ----------------------------

    fn host_begin(self: &Arc<Self>, id: u16, body: &[u8]) {
        let stack = match &self.stack {
            Some(s) if body.len() >= 2 => s.clone(),
            _ => {
                self.send_end(id);
                return;
            }
        };

        let port = ((body[0] as u16) << 8) | body[1] as u16;

        let service = match stack.resolve(port) {
            Some(s) => s,
            None => {
                self.send_end(id);
                return;
            }
        };

        let hosted: Arc<dyn MessageChannel> = Arc::new(HostedStream {
            owner: Arc::downgrade(self),
            id,
        });
        let server = stack.create_detached(hosted, port);

        {
            let mut state = self.state.lock().unwrap();
            // A repeated Begin must not orphan the stream already under that
            // number; and one guest gets no more streams than a circuit does.
            if state.hosted.contains_key(&id) {
                return;
            }
            if state.hosted.len() >= PortStack::MAX_STREAMS_PER_CIRCUIT {
                drop(state);
                self.send_end(id);
                return;
            }
            state.hosted.insert(id, HostedEntry {
                service: service.clone(),
                server: server.clone(),
            });
        }

        if !service.on_open(server) {
            self.state.lock().unwrap().hosted.remove(&id);
            self.send_end(id);
            return;
        }

        self.channel.send(&Self::frame(id, MuxCommand::Connected, &[]));
    }

    fn host_data(&self, id: u16, body: &[u8]) {
        let entry = {
            let state = self.state.lock().unwrap();
            match state.hosted.get(&id) {
                Some(e) => (e.service.clone(), e.server.clone()),
                None => return,
            }
        };
        entry.0.on_data(&entry.1, body);
    }

    fn host_end(&self, id: u16) {
        let entry = {
            let mut state = self.state.lock().unwrap();
            match state.hosted.remove(&id) {
                Some(e) => e,
                None => return,
            }
        };
        entry.service.on_close(&entry.server);
    }

    // ---- Tables ------------------------------------------------------------

    fn lookup(&self, id: u16) -> Option<Arc<MuxStream>> {
        self.state.lock().unwrap().streams.get(&id).cloned()
    }

    fn forget(&self, id: u16) {
        let mut state = self.state.lock().unwrap();
        state.streams.remove(&id);
        // Give the number back, or a long-lived channel runs out of them.
        state.used_ids.remove(&id);
    }

    fn allocate_id(&self) -> Option<u16> {
        let mut state = self.state.lock().unwrap();
        for _ in 0..1000 {
            let bytes = rand::get_bytes(2);
            let id = ((bytes[0] as u16) << 8) | bytes[1] as u16;
            if id == 0 || state.used_ids.contains(&id) {
                continue;
            }
            state.used_ids.insert(id);
            return Some(id);
        }
        None
    }

    fn stream_count(&self) -> usize {
        let state = self.state.lock().unwrap();
        state.streams.len() + state.hosted.len()
    }

    /// Closes everything — our streams and the guest's hosted ones.
    fn tear_down(&self) {
        let (mine, theirs) = {
            let mut state = self.state.lock().unwrap();
            let mine: Vec<Arc<MuxStream>> = state.streams.drain().map(|(_, v)| v).collect();
            let theirs: Vec<HostedEntry> = state.hosted.drain().map(|(_, v)| v).collect();
            (mine, theirs)
        };

        for stream in mine {
            stream.mark_closed();
        }
        for entry in theirs {
            entry.service.on_close(&entry.server);
        }
    }
}

fn pump_loop(inner: Arc<MuxInner>) {
    while !inner.stopping.load(Ordering::Acquire) && inner.channel.is_open() {
        if let Some(frame) = inner.channel.receive(PUMP_TIMEOUT) {
            inner.dispatch(frame);
        }
    }
    inner.tear_down();
}

/// Several streams inside one end-to-end channel (the C# `HiddenMux`).
pub struct HiddenMux {
    inner: Arc<MuxInner>,
    pump: Mutex<Option<JoinHandle<()>>>,
}

impl HiddenMux {
    /// The guest's side: it opens streams to the service's ports.
    pub fn new(channel: Arc<dyn MessageChannel>) -> HiddenMux {
        HiddenMux::build(channel, None)
    }

    /// The service's side: it sorts the arriving streams into its own port
    /// stack. By that a hidden service serves exactly what an ordinary node
    /// serves.
    pub fn with_stack(channel: Arc<dyn MessageChannel>, stack: Arc<PortStack>) -> HiddenMux {
        HiddenMux::build(channel, Some(stack))
    }

    fn build(channel: Arc<dyn MessageChannel>, stack: Option<Arc<PortStack>>) -> HiddenMux {
        let inner = Arc::new(MuxInner {
            channel,
            stack,
            state: Mutex::new(MuxState {
                streams: HashMap::new(),
                hosted: HashMap::new(),
                used_ids: HashSet::new(),
            }),
            stopping: AtomicBool::new(false),
            open_timeout_ms: AtomicU64::new(DEFAULT_OPEN_TIMEOUT.as_millis() as u64),
        });

        let pump_inner = inner.clone();
        let pump = thread::Builder::new()
            .name("stalknet-hidden-mux".into())
            .spawn(move || pump_loop(pump_inner))
            .expect("spawn hidden-mux pump thread");

        HiddenMux {
            inner,
            pump: Mutex::new(Some(pump)),
        }
    }

    /// How long to wait for the `Connected` answer when opening a stream.
    pub fn set_open_timeout(&self, timeout: Duration) {
        self.inner
            .open_timeout_ms
            .store(timeout.as_millis() as u64, Ordering::Release);
    }

    pub fn is_alive(&self) -> bool {
        self.inner.is_alive()
    }

    /// How many streams travel over this channel right now.
    pub fn stream_count(&self) -> usize {
        self.inner.stream_count()
    }

    /// Opens a stream to an internal port of the service. `None` if the port is
    /// closed or the service did not answer in time.
    pub fn open(&self, port: u16) -> Option<Arc<dyn MessageChannel>> {
        self.inner.open(port).map(|s| s as Arc<dyn MessageChannel>)
    }

    fn dispose(&self) {
        if self.inner.stopping.swap(true, Ordering::AcqRel) {
            return;
        }
        self.inner.tear_down();
        // The pump sits on a `receive` with PUMP_TIMEOUT; once `stopping` is set
        // it exits at the next turn of the loop, so a close may lag by up to
        // PUMP_TIMEOUT.
        if let Some(handle) = self.pump.lock().unwrap().take() {
            let _ = handle.join();
        }
    }
}

impl Drop for HiddenMux {
    fn drop(&mut self) {
        self.dispose();
    }
}

impl StreamOpener for HiddenMux {
    fn open(&self, port: u16) -> Option<Arc<dyn MessageChannel>> {
        HiddenMux::open(self, port)
    }
    fn is_alive(&self) -> bool {
        self.inner.is_alive()
    }
}

/// A stream inside an end-to-end channel — as seen by whoever opened it.
struct MuxStream {
    owner: Weak<MuxInner>,
    id: u16,
    incoming: Mailbox,
    connected: Gate,
    closed: AtomicBool,
}

impl MuxStream {
    fn new(owner: Weak<MuxInner>, id: u16) -> MuxStream {
        MuxStream {
            owner,
            id,
            incoming: Mailbox::new(),
            connected: Gate::new(),
            closed: AtomicBool::new(false),
        }
    }

    fn owner_alive(&self) -> bool {
        self.owner.upgrade().map(|o| o.is_alive()).unwrap_or(false)
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

    fn mark_closed(&self) {
        if self.closed.swap(true, Ordering::AcqRel) {
            return;
        }
        self.connected.signal();
        self.incoming.complete();
    }
}

impl MessageChannel for MuxStream {
    fn send(&self, message: &[u8]) {
        if !self.is_open() {
            return; // the C# throws; here a send on a closed stream is a no-op
        }
        if let Some(owner) = self.owner.upgrade() {
            owner.send_data(self.id, message);
        }
    }

    fn receive(&self, timeout: Duration) -> Option<Vec<u8>> {
        self.incoming.take(timeout)
    }

    fn is_open(&self) -> bool {
        !self.closed.load(Ordering::Acquire) && self.owner_alive()
    }

    fn close(&self) {
        if self.closed.load(Ordering::Acquire) {
            return;
        }
        match self.owner.upgrade() {
            Some(owner) => owner.close_stream(self),
            None => self.mark_closed(),
        }
    }
}

/// A stream inside an end-to-end channel — as seen by the service. It lets the
/// detached `ServerStream` send into the channel; incoming data reaches the
/// service through the pump's `host_data`.
struct HostedStream {
    owner: Weak<MuxInner>,
    id: u16,
}

impl MessageChannel for HostedStream {
    fn send(&self, message: &[u8]) {
        if let Some(owner) = self.owner.upgrade() {
            owner.send_data(self.id, message);
        }
    }

    fn receive(&self, _timeout: Duration) -> Option<Vec<u8>> {
        None
    }

    fn is_open(&self) -> bool {
        self.owner.upgrade().map(|o| o.is_alive()).unwrap_or(false)
    }

    fn close(&self) {
        if let Some(owner) = self.owner.upgrade() {
            // The service closed it: drop the entry too, or the table fills up
            // and the guest can open nothing more.
            owner.state.lock().unwrap().hosted.remove(&self.id);
            owner.send_end(self.id);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ---- An in-memory MessageChannel pair --------------------------------

    struct Pipe {
        inbox: Mailbox,
        peer: Mutex<Option<Arc<Pipe>>>,
        open: Arc<AtomicBool>,
    }

    impl Pipe {
        fn duplex() -> (Arc<Pipe>, Arc<Pipe>) {
            let open = Arc::new(AtomicBool::new(true));
            let a = Arc::new(Pipe {
                inbox: Mailbox::new(),
                peer: Mutex::new(None),
                open: open.clone(),
            });
            let b = Arc::new(Pipe {
                inbox: Mailbox::new(),
                peer: Mutex::new(None),
                open,
            });
            *a.peer.lock().unwrap() = Some(b.clone());
            *b.peer.lock().unwrap() = Some(a.clone());
            (a, b)
        }
    }

    impl MessageChannel for Pipe {
        fn send(&self, message: &[u8]) {
            if !self.open.load(Ordering::Acquire) {
                return;
            }
            if let Some(peer) = self.peer.lock().unwrap().as_ref() {
                peer.inbox.add(message.to_vec());
            }
        }
        fn receive(&self, timeout: Duration) -> Option<Vec<u8>> {
            self.inbox.take(timeout)
        }
        fn is_open(&self) -> bool {
            self.open.load(Ordering::Acquire)
        }
        fn close(&self) {
            self.open.store(false, Ordering::Release);
            self.inbox.complete();
            if let Some(peer) = self.peer.lock().unwrap().as_ref() {
                peer.inbox.complete();
            }
        }
    }

    // ---- An echo service on an internal port -----------------------------

    struct EchoService;
    impl PortService for EchoService {
        fn on_open(&self, _stream: Arc<ServerStream>) -> bool {
            true
        }
        fn on_data(&self, stream: &Arc<ServerStream>, data: &[u8]) {
            stream.send(data);
        }
        fn on_close(&self, _stream: &Arc<ServerStream>) {}
    }

    #[test]
    fn frame_round_trip() {
        let frame = MuxInner::frame(0xABCD, MuxCommand::Data, b"payload");
        assert_eq!(frame[0], 0xAB);
        assert_eq!(frame[1], 0xCD);
        assert_eq!(frame[2], MuxCommand::Data as u8);
        assert_eq!(&frame[MUX_HEADER..], b"payload");

        // Parse it back the way `dispatch` does.
        let id = ((frame[0] as u16) << 8) | frame[1] as u16;
        assert_eq!(id, 0xABCD);
        assert_eq!(frame[2], 3);
        assert_eq!(&frame[MUX_HEADER..], b"payload");
    }

    #[test]
    fn client_opens_a_stream_a_service_routes_it() {
        let (client_end, service_end) = Pipe::duplex();

        let stack = PortStack::new();
        stack.bind(100, Arc::new(EchoService));

        let service_mux = HiddenMux::with_stack(service_end, stack);
        let client_mux = HiddenMux::new(client_end);
        client_mux.set_open_timeout(Duration::from_secs(5));

        let stream = client_mux.open(100).expect("the service accepts the stream");
        stream.send(b"ping");
        let echoed = stream.receive(Duration::from_secs(5));
        assert_eq!(echoed.as_deref(), Some(&b"ping"[..]));

        // A second message travels over the same meeting.
        stream.send(b"pong");
        assert_eq!(stream.receive(Duration::from_secs(5)).as_deref(), Some(&b"pong"[..]));

        assert_eq!(client_mux.stream_count(), 1);

        stream.close();
        drop(client_mux);
        drop(service_mux);
    }

    #[test]
    fn opening_a_closed_port_fails() {
        let (client_end, service_end) = Pipe::duplex();
        let stack = PortStack::new(); // nothing bound
        let service_mux = HiddenMux::with_stack(service_end, stack);
        let client_mux = HiddenMux::new(client_end);
        client_mux.set_open_timeout(Duration::from_secs(2));

        assert!(client_mux.open(777).is_none());

        drop(client_mux);
        drop(service_mux);
    }
}
