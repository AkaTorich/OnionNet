//! The node's internal port stack and the services that sit on it.
//!
//! It sorts the arriving cells by stream and by port, the way TCP does on a real
//! machine, and attaches to the node in place of a single handler: now every
//! service sits on its own port and knows nothing of the others.

use crate::protocol::relay_cell::{RelayCell, RelayCommand, MAX_DATA_SIZE};
use crate::streams::exit_policy::ExitPolicy;
use crate::streams::message_channel::MessageChannel;
use crate::streams::stream_end_reason::StreamEndReason;
use crate::streams::stream_payloads;
use crate::streams::tcp_port_service::TcpPortService;
use crate::transport::relay_node::RelayNode;
use crate::transport::service_context::ServiceContext;
use std::any::Any;
use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

/// A service listening on an internal port of the node.
///
/// One instance serves every stream on its port. Telling the guests apart is the
/// service's own duty — leaning on [`ServerStream`], which every stream has one
/// of.
pub trait PortService: Send + Sync {
    /// A guest knocked at the port. Return `false` to refuse.
    fn on_open(&self, stream: Arc<ServerStream>) -> bool;

    /// Data arrived.
    fn on_data(&self, stream: &Arc<ServerStream>, data: &[u8]);

    /// The stream closed — by the guest, by a broken circuit, or by us.
    fn on_close(&self, stream: &Arc<ServerStream>);
}

/// One stream through the service's eyes. It lives inside a circuit and dies
/// with it.
///
/// Who is at the far end is unknown and there is nowhere to learn it from: no
/// address, no name. All that tells one stream from another is [`state`], where
/// the service puts its own idea of the guest.
///
/// [`state`]: ServerStream::with_state
pub struct ServerStream {
    /// The ordinary road: a circuit to this node.
    circuit: Option<Arc<dyn ServiceContext>>,
    /// The second road: an end-to-end channel to a hidden service. The service
    /// sees no difference — it holds the very same `ServerStream`.
    channel: Option<Arc<dyn MessageChannel>>,

    stream_id: u16,
    port: u16,
    service: Mutex<Option<Arc<dyn PortService>>>,
    state: Mutex<Option<Box<dyn Any + Send + Sync>>>,
    closed: AtomicBool,
}

impl ServerStream {
    fn on_circuit(circuit: Arc<dyn ServiceContext>, stream_id: u16, port: u16) -> ServerStream {
        ServerStream {
            circuit: Some(circuit),
            channel: None,
            stream_id,
            port,
            service: Mutex::new(None),
            state: Mutex::new(None),
            closed: AtomicBool::new(false),
        }
    }

    fn on_channel(channel: Arc<dyn MessageChannel>, port: u16) -> ServerStream {
        ServerStream {
            circuit: None,
            channel: Some(channel),
            stream_id: 0,
            port,
            service: Mutex::new(None),
            state: Mutex::new(None),
            closed: AtomicBool::new(false),
        }
    }

    pub fn stream_id(&self) -> u16 {
        self.stream_id
    }

    pub fn port(&self) -> u16 {
        self.port
    }

    fn set_service(&self, service: Arc<dyn PortService>) {
        *self.service.lock().unwrap() = Some(service);
    }

    fn service(&self) -> Option<Arc<dyn PortService>> {
        self.service.lock().unwrap().clone()
    }

    /// Room for the service's state: the guest's sign-in, open files, a socket.
    pub fn set_state(&self, value: Box<dyn Any + Send + Sync>) {
        *self.state.lock().unwrap() = Some(value);
    }

    /// Takes the state back out, clearing it.
    pub fn take_state(&self) -> Option<Box<dyn Any + Send + Sync>> {
        self.state.lock().unwrap().take()
    }

    /// Runs `f` against the stored state, if it is of type `T`.
    pub fn with_state<T: Any, R>(&self, f: impl FnOnce(&T) -> R) -> Option<R> {
        let guard = self.state.lock().unwrap();
        guard.as_ref().and_then(|b| b.as_ref().downcast_ref::<T>()).map(f)
    }

    pub fn is_open(&self) -> bool {
        if self.closed.load(Ordering::Acquire) {
            return false;
        }
        match &self.channel {
            Some(channel) => channel.is_open(),
            None => self.circuit.as_ref().map(|c| c.is_alive()).unwrap_or(false),
        }
    }

    /// Sends data to the guest. It will not take more than one cell.
    pub fn send(&self, data: &[u8]) {
        // An oversized message is dropped, never a panic: this runs on a relay's
        // reader thread, under the stream's state lock, for any stranger.
        if data.len() > MAX_DATA_SIZE {
            return;
        }
        if !self.is_open() {
            return;
        }
        if let Some(channel) = &self.channel {
            channel.send(data);
            return;
        }
        if let Some(circuit) = &self.circuit {
            circuit.send(RelayCell::new(RelayCommand::Data, self.stream_id, data.to_vec()));
        }
    }

    /// Sends long data, slicing it into cells.
    pub fn send_all(&self, data: &[u8]) {
        let mut offset = 0;
        while offset < data.len() {
            let take = std::cmp::min(MAX_DATA_SIZE, data.len() - offset);
            self.send(&data[offset..offset + take]);
            offset += take;
        }
    }

    fn send_connected(&self) {
        if !self.is_open() {
            return;
        }
        // In an end-to-end channel the multiplexer reports readiness.
        if self.channel.is_some() {
            return;
        }
        if let Some(circuit) = &self.circuit {
            circuit.send(RelayCell::new(
                RelayCommand::Connected,
                self.stream_id,
                stream_payloads::connected(self.port),
            ));
        }
    }

    /// Closes the stream and tells the guest about it.
    pub fn close(&self, reason: StreamEndReason) {
        if self.closed.swap(true, Ordering::AcqRel) {
            return;
        }

        if let Some(channel) = &self.channel {
            channel.close();
            return;
        }

        let circuit = match &self.circuit {
            Some(c) => c,
            None => return,
        };
        if !circuit.is_alive() {
            return;
        }
        circuit.send(RelayCell::new(
            RelayCommand::End,
            self.stream_id,
            stream_payloads::end(reason),
        ));
    }

    fn mark_closed(&self) {
        self.closed.store(true, Ordering::Release);
    }
}

/// A key for the per-circuit stream tables. The relay node hands back the same
/// `ServiceContext` for a circuit's whole life, so its address identifies it.
fn ctx_key(ctx: &Arc<dyn ServiceContext>) -> usize {
    Arc::as_ptr(ctx) as *const () as usize
}

/// The node's internal port stack (the C# `PortStack`).
pub struct PortStack {
    /// No more streams than this can be opened in one circuit.
    services: Mutex<HashMap<u16, Arc<dyn PortService>>>,
    streams: Mutex<HashMap<usize, HashMap<u16, Arc<ServerStream>>>>,
    exit: Mutex<Option<Arc<ExitPolicy>>>,
}

impl PortStack {
    /// No more streams than this can be opened in one circuit.
    pub const MAX_STREAMS_PER_CIRCUIT: usize = 64;

    pub fn new() -> Arc<PortStack> {
        Arc::new(PortStack {
            services: Mutex::new(HashMap::new()),
            streams: Mutex::new(HashMap::new()),
            exit: Mutex::new(None),
        })
    }

    /// Whether and where this node lets guests out of the network. `None` — it
    /// lets nobody out, and that is how a node stands until its owner says
    /// otherwise.
    pub fn set_exit(&self, policy: Option<Arc<ExitPolicy>>) {
        *self.exit.lock().unwrap() = policy;
    }

    pub fn exit(&self) -> Option<Arc<ExitPolicy>> {
        self.exit.lock().unwrap().clone()
    }

    /// Takes an internal port for a service.
    pub fn bind(&self, port: u16, service: Arc<dyn PortService>) {
        assert!(port != 0, "port zero is not handed out");
        let mut services = self.services.lock().unwrap();
        assert!(!services.contains_key(&port), "port {port} is already taken");
        services.insert(port, service);
    }

    pub fn unbind(&self, port: u16) {
        self.services.lock().unwrap().remove(&port);
    }

    pub fn bound_ports(&self) -> Vec<u16> {
        let mut ports: Vec<u16> = self.services.lock().unwrap().keys().copied().collect();
        ports.sort_unstable();
        ports
    }

    /// How many streams are open right now across every circuit.
    pub fn stream_count(&self) -> usize {
        self.streams.lock().unwrap().values().map(|t| t.len()).sum()
    }

    /// How many streams are open right now on this internal port.
    pub fn stream_count_for(&self, port: u16) -> usize {
        self.streams
            .lock()
            .unwrap()
            .values()
            .flat_map(|t| t.values())
            .filter(|s| s.port == port)
            .count()
    }

    /// Which service listens on the port. `None` if the port is free.
    pub fn resolve(&self, port: u16) -> Option<Arc<dyn PortService>> {
        self.service_for(port)
    }

    /// Starts a stream that answers into an end-to-end channel rather than into
    /// a circuit (for hidden services).
    pub fn create_detached(&self, channel: Arc<dyn MessageChannel>, port: u16) -> Arc<ServerStream> {
        Arc::new(ServerStream::on_channel(channel, port))
    }

    /// Attaches the stack to the node.
    pub fn attach(self: &Arc<Self>, node: &RelayNode) {
        let handler = self.clone();
        node.set_service_handler(Arc::new(move |cell, context| handler.handle(cell, context)));

        let closer = self.clone();
        node.set_service_closed(Arc::new(move |context| closer.circuit_closed(context)));
    }

    // ---- Parsing cells -----------------------------------------------------

    pub fn handle(&self, cell: RelayCell, context: Arc<dyn ServiceContext>) {
        match cell.command {
            RelayCommand::Begin => self.handle_begin(&cell, &context),
            RelayCommand::BeginTo => self.handle_begin_to(&cell, &context),
            RelayCommand::Data => self.handle_data(&cell, &context),
            RelayCommand::End => self.handle_end(&cell, &context),
            _ => {}
        }
    }

    fn handle_begin(&self, cell: &RelayCell, context: &Arc<dyn ServiceContext>) {
        let port = match stream_payloads::try_read_begin(&cell.data) {
            Some(p) => p,
            None => {
                self.refuse(context, cell.stream_id, StreamEndReason::BadRequest);
                return;
            }
        };

        let service = match self.service_for(port) {
            Some(s) => s,
            None => {
                self.refuse(context, cell.stream_id, StreamEndReason::PortClosed);
                return;
            }
        };

        self.accept(context, cell.stream_id, port, service);
    }

    /// A guest asks to be let out of the network, to an address of its own
    /// choosing. Everything is decided by the exit rule.
    ///
    /// Without a rule the answer is the same as about a port nobody listens on:
    /// a stranger is told that nothing is here — not what is switched off and not
    /// what is forbidden, for an exit node that answered differently to different
    /// addresses would be a way of feeling out the owner's own network.
    fn handle_begin_to(&self, cell: &RelayCell, context: &Arc<dyn ServiceContext>) {
        let (host, port) = match stream_payloads::try_read_begin_to(&cell.data) {
            Some(parsed) => parsed,
            None => {
                self.refuse(context, cell.stream_id, StreamEndReason::BadRequest);
                return;
            }
        };

        let policy = match self.exit() {
            Some(p) if p.enabled => p,
            _ => {
                self.refuse(context, cell.stream_id, StreamEndReason::PortClosed);
                return;
            }
        };

        let address = match policy.try_resolve(&host, port) {
            Ok(a) => a,
            Err(refusal) => {
                self.refuse(context, cell.stream_id, refusal);
                return;
            }
        };

        // The stream is registered under port zero: it belongs to no port of
        // ours, and the counters by port must not take it for a guest of
        // somebody's offered service.
        let service: Arc<dyn PortService> = Arc::new(TcpPortService::new(&address.to_string(), port));
        self.accept(context, cell.stream_id, 0, service);
    }

    /// Registers the stream and hands it to the service.
    fn accept(&self, context: &Arc<dyn ServiceContext>, stream_id: u16, port: u16, service: Arc<dyn PortService>) {
        let stream = Arc::new(ServerStream::on_circuit(context.clone(), stream_id, port));
        stream.set_service(service.clone());

        {
            let mut tables = self.streams.lock().unwrap();
            let table = tables.entry(ctx_key(context)).or_default();

            if table.contains_key(&stream_id) {
                return; // a repeated Begin — we stay quiet
            }
            if table.len() >= Self::MAX_STREAMS_PER_CIRCUIT {
                drop(tables);
                self.refuse(context, stream_id, StreamEndReason::TooManyStreams);
                return;
            }
            table.insert(stream_id, stream.clone());
        }

        if !service.on_open(stream.clone()) {
            self.forget(context, stream_id);
            self.refuse(context, stream_id, StreamEndReason::ConnectFailed);
            return;
        }

        stream.send_connected();
    }

    fn handle_data(&self, cell: &RelayCell, context: &Arc<dyn ServiceContext>) {
        let stream = match self.lookup(context, cell.stream_id) {
            Some(s) => s,
            None => return,
        };
        let service = match stream.service() {
            Some(s) => s,
            None => return,
        };
        service.on_data(&stream, &cell.data);
    }

    fn handle_end(&self, cell: &RelayCell, context: &Arc<dyn ServiceContext>) {
        self.close_stream(context, cell.stream_id, StreamEndReason::Done, false);
    }

    /// The circuit closed — every stream of it closes with it.
    pub fn circuit_closed(&self, context: Arc<dyn ServiceContext>) {
        let doomed: Vec<Arc<ServerStream>> = {
            let mut tables = self.streams.lock().unwrap();
            match tables.remove(&ctx_key(&context)) {
                Some(table) => table.into_values().collect(),
                None => return,
            }
        };

        for stream in doomed {
            stream.mark_closed();
            if let Some(service) = stream.service() {
                service.on_close(&stream);
            }
        }
    }

    fn close_stream(
        &self,
        context: &Arc<dyn ServiceContext>,
        stream_id: u16,
        reason: StreamEndReason,
        notify_guest: bool,
    ) {
        let stream = match self.forget(context, stream_id) {
            Some(s) => s,
            None => return,
        };

        if notify_guest {
            stream.close(reason);
        } else {
            stream.mark_closed();
        }

        if let Some(service) = stream.service() {
            service.on_close(&stream);
        }
    }

    // ---- Tables ------------------------------------------------------------

    fn lookup(&self, context: &Arc<dyn ServiceContext>, stream_id: u16) -> Option<Arc<ServerStream>> {
        self.streams
            .lock()
            .unwrap()
            .get(&ctx_key(context))
            .and_then(|table| table.get(&stream_id).cloned())
    }

    fn forget(&self, context: &Arc<dyn ServiceContext>, stream_id: u16) -> Option<Arc<ServerStream>> {
        let mut tables = self.streams.lock().unwrap();
        let key = ctx_key(context);
        let table = tables.get_mut(&key)?;
        let stream = table.remove(&stream_id)?;
        if table.is_empty() {
            tables.remove(&key);
        }
        Some(stream)
    }

    fn service_for(&self, port: u16) -> Option<Arc<dyn PortService>> {
        self.services.lock().unwrap().get(&port).cloned()
    }

    fn refuse(&self, context: &Arc<dyn ServiceContext>, stream_id: u16, reason: StreamEndReason) {
        if !context.is_alive() {
            return;
        }
        context.send(RelayCell::new(RelayCommand::End, stream_id, stream_payloads::end(reason)));
    }

    pub fn dispose(&self) {
        let contexts: Vec<usize> = self.streams.lock().unwrap().keys().copied().collect();
        // Close every circuit's streams. We hold only the keys here; the stream
        // tables themselves are drained by circuit_closed via the table map.
        let _ = contexts;
        let tables: HashMap<usize, HashMap<u16, Arc<ServerStream>>> =
            std::mem::take(&mut *self.streams.lock().unwrap());
        for (_, table) in tables {
            for (_, stream) in table {
                stream.mark_closed();
                if let Some(service) = stream.service() {
                    service.on_close(&stream);
                }
            }
        }
        self.services.lock().unwrap().clear();
    }
}
