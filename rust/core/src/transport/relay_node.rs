//! A relay — a node other people's circuits pass through.
//!
//! All it can do: accept a handshake, take off its own layer, and either carry
//! out the command addressed to it or pass the cell to a neighbour. It knows
//! neither the length of the circuit, nor its own place in it, nor whether a
//! client or another relay stands in front of it. A node nobody can call from
//! outside runs with no listener at all — it builds circuits outward and that
//! is all.

use crate::directory::relay_descriptor::RelayDescriptor;
use crate::identity::node_identity::NodeIdentity;
use crate::identity::onion_address::FINGERPRINT_SIZE;
use crate::protocol::cell::{Cell, CellCommand};
use crate::protocol::extend_payload;
use crate::protocol::ntor;
use crate::protocol::relay_cell::{RelayCell, RelayCommand};
use crate::protocol::relay_hop::{Peeled, RelayHop};
use crate::streams::exit_policy;
use crate::transport::cell_channel::CellChannel;
use crate::transport::service_context::ServiceContext;
use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr, TcpListener, TcpStream, ToSocketAddrs};
use std::sync::atomic::{AtomicBool, AtomicU16, Ordering};
use std::sync::{Arc, Mutex, Weak};
use std::thread;
use std::time::Duration;

const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(15);
const MAX_ACCEPT_FAILURES: u32 = 32;

pub type ServiceHandler = Arc<dyn Fn(RelayCell, Arc<dyn ServiceContext>) + Send + Sync>;
pub type ServiceClosed = Arc<dyn Fn(Arc<dyn ServiceContext>) + Send + Sync>;
pub type CardFn = Arc<dyn Fn() -> Option<Vec<u8>> + Send + Sync>;
pub type ListLookup = Arc<dyn Fn(&[u8]) -> Option<RelayDescriptor> + Send + Sync>;

fn make_key(channel_id: u32, circuit_id: u32) -> i64 {
    ((channel_id as i64) << 32) | circuit_id as i64
}

#[derive(Default)]
struct Tables {
    by_previous: HashMap<i64, Arc<CircuitEntry>>,
    by_next: HashMap<i64, Arc<CircuitEntry>>,
    outbound: HashMap<String, Arc<CellChannel>>,
    channels: Vec<Arc<CellChannel>>,
}

struct Shared {
    identity: NodeIdentity,
    host: Mutex<String>,
    port: AtomicU16,
    public_port: AtomicU16,
    nickname: Mutex<Option<String>>,
    allows_exit: bool,
    accepts_incoming: AtomicBool,
    stopping: AtomicBool,
    faulted: AtomicBool,
    tables: Mutex<Tables>,
    bound_addr: Mutex<Option<SocketAddr>>,
    service_handler: Mutex<Option<ServiceHandler>>,
    service_closed: Mutex<Option<ServiceClosed>>,
    card: Mutex<Option<CardFn>>,
    list_lookup: Mutex<Option<ListLookup>>,
}

/// One passing circuit through the relay's eyes.
struct CircuitEntry {
    crypto: Mutex<Option<RelayHop>>,
    previous: Arc<CellChannel>,
    previous_id: u32,
    next: Mutex<Option<NextLink>>,
    extend_pending: AtomicBool,
    alive: AtomicBool,
    removed: AtomicBool,
    context: Mutex<Option<Arc<EntryContext>>>,
}

struct NextLink {
    channel: Arc<CellChannel>,
    id: u32,
}

impl CircuitEntry {
    fn next_snapshot(&self) -> Option<(Arc<CellChannel>, u32)> {
        self.next.lock().unwrap().as_ref().map(|n| (n.channel.clone(), n.id))
    }
}

/// The service handle for one circuit — the same one for its whole life.
struct EntryContext {
    shared: Weak<Shared>,
    entry: Weak<CircuitEntry>,
}

impl ServiceContext for EntryContext {
    fn send(&self, cell: RelayCell) {
        if let (Some(shared), Some(entry)) = (self.shared.upgrade(), self.entry.upgrade()) {
            if entry.alive.load(Ordering::Acquire) {
                shared.send_backward(&entry, cell);
            }
        }
    }
    fn is_alive(&self) -> bool {
        self.entry.upgrade().map(|e| e.alive.load(Ordering::Acquire)).unwrap_or(false)
    }
}

pub struct RelayNode {
    shared: Arc<Shared>,
    accept_handle: Mutex<Option<thread::JoinHandle<()>>>,
    started: AtomicBool,
}

impl RelayNode {
    pub fn new(identity: NodeIdentity, host: &str, port: u16, allows_exit: bool) -> RelayNode {
        RelayNode {
            shared: Arc::new(Shared {
                identity,
                host: Mutex::new(host.to_string()),
                port: AtomicU16::new(port),
                public_port: AtomicU16::new(0),
                nickname: Mutex::new(None),
                allows_exit,
                accepts_incoming: AtomicBool::new(true),
                stopping: AtomicBool::new(false),
                faulted: AtomicBool::new(false),
                tables: Mutex::new(Tables::default()),
                bound_addr: Mutex::new(None),
                service_handler: Mutex::new(None),
                service_closed: Mutex::new(None),
                card: Mutex::new(None),
                list_lookup: Mutex::new(None),
            }),
            accept_handle: Mutex::new(None),
            started: AtomicBool::new(false),
        }
    }

    pub fn identity(&self) -> &NodeIdentity {
        &self.shared.identity
    }
    pub fn host(&self) -> String {
        self.shared.host.lock().unwrap().clone()
    }
    pub fn set_host(&self, host: &str) {
        *self.shared.host.lock().unwrap() = host.to_string();
    }
    pub fn port(&self) -> u16 {
        self.shared.port.load(Ordering::Acquire)
    }
    pub fn set_public_port(&self, port: u16) {
        self.shared.public_port.store(port, Ordering::Release);
    }
    pub fn set_nickname(&self, nickname: Option<String>) {
        *self.shared.nickname.lock().unwrap() = nickname;
    }
    pub fn allows_exit(&self) -> bool {
        self.shared.allows_exit
    }
    pub fn set_accepts_incoming(&self, yes: bool) {
        self.shared.accepts_incoming.store(yes, Ordering::Release);
    }
    pub fn faulted(&self) -> bool {
        self.shared.faulted.load(Ordering::Acquire)
    }
    pub fn circuit_count(&self) -> usize {
        self.shared.tables.lock().unwrap().by_previous.len()
    }
    pub fn set_service_handler(&self, handler: ServiceHandler) {
        *self.shared.service_handler.lock().unwrap() = Some(handler);
    }
    pub fn set_service_closed(&self, closed: ServiceClosed) {
        *self.shared.service_closed.lock().unwrap() = Some(closed);
    }
    pub fn set_card(&self, card: CardFn) {
        *self.shared.card.lock().unwrap() = Some(card);
    }
    pub fn set_list_lookup(&self, lookup: ListLookup) {
        *self.shared.list_lookup.lock().unwrap() = Some(lookup);
    }

    /// Our card as it stands — unsigned; the owner signs it and adds the pass.
    pub fn descriptor(&self) -> RelayDescriptor {
        let s = &self.shared;
        let public_port = s.public_port.load(Ordering::Acquire);
        let port = if public_port > 0 { public_port } else { s.port.load(Ordering::Acquire) };
        let mut d = RelayDescriptor::from_identity(&s.identity, &s.host.lock().unwrap(), port, s.allows_exit);
        if let Some(n) = s.nickname.lock().unwrap().clone() {
            d.nickname = n;
        }
        d
    }

    pub fn start(&self) -> std::io::Result<()> {
        if self.started.swap(true, Ordering::AcqRel) {
            return Ok(());
        }
        if !self.shared.accepts_incoming.load(Ordering::Acquire) {
            return Ok(()); // a client: no listener, circuits built outward only
        }

        let port = self.shared.port.load(Ordering::Acquire);
        let listener = TcpListener::bind(("0.0.0.0", port))?;
        let local = listener.local_addr()?;
        self.shared.port.store(local.port(), Ordering::Release);
        *self.shared.bound_addr.lock().unwrap() = Some(local);

        let shared = self.shared.clone();
        let handle = thread::Builder::new()
            .name(format!("stalknet-accept-{}", local.port()))
            .spawn(move || accept_loop(shared, listener))
            .expect("spawn accept thread");
        *self.accept_handle.lock().unwrap() = Some(handle);
        Ok(())
    }

    pub fn stop(&self) {
        self.shared.stop();
        if let Some(handle) = self.accept_handle.lock().unwrap().take() {
            let _ = handle.join();
        }
    }
}

impl Drop for RelayNode {
    fn drop(&mut self) {
        self.shared.stop();
    }
}

fn accept_loop(shared: Arc<Shared>, listener: TcpListener) {
    let mut failures = 0u32;
    loop {
        if shared.stopping.load(Ordering::Acquire) {
            return;
        }
        match listener.accept() {
            Ok((stream, _)) => {
                if shared.stopping.load(Ordering::Acquire) {
                    return;
                }
                failures = 0;
                let s = shared.clone();
                let _ = thread::Builder::new()
                    .name("stalknet-link".into())
                    .spawn(move || serve_incoming(s, stream));
            }
            Err(_) => {
                if shared.stopping.load(Ordering::Acquire) {
                    return;
                }
                failures += 1;
                if failures > MAX_ACCEPT_FAILURES {
                    // Give up honestly: a node that can no longer accept anyone
                    // must not look like one that can.
                    shared.faulted.store(true, Ordering::Release);
                    shared.stop();
                    return;
                }
                thread::sleep(Duration::from_millis(200));
            }
        }
    }
}

fn serve_incoming(shared: Arc<Shared>, stream: TcpStream) {
    let card = shared.card.lock().unwrap().clone();
    let card_ref: Option<&dyn Fn() -> Option<Vec<u8>>> = card.as_deref().map(|c| c as &dyn Fn() -> Option<Vec<u8>>);
    let channel = match CellChannel::accept(stream, &shared.identity, HANDSHAKE_TIMEOUT, card_ref) {
        Ok(c) => Arc::new(c),
        Err(_) => return, // handshake failed or a card was asked for
    };
    shared.tables.lock().unwrap().channels.push(channel.clone());
    reader_loop(shared, channel);
}

fn reader_loop(shared: Arc<Shared>, channel: Arc<CellChannel>) {
    loop {
        if shared.stopping.load(Ordering::Acquire) {
            break;
        }
        match channel.read() {
            Ok(Some(cell)) => shared.handle_cell(&channel, cell),
            Ok(None) => break,
            Err(_) => break, // a break or a damaged frame — the link served its time
        }
    }
    shared.drop_channel(&channel);
}

impl Shared {
    fn stop(&self) {
        if self.stopping.swap(true, Ordering::AcqRel) {
            return;
        }
        // Wake the accept thread out of its blocking accept(). The listener is
        // bound to 0.0.0.0, which cannot be dialled on Windows: knock on the
        // loopback address at the same port instead.
        if let Some(addr) = *self.bound_addr.lock().unwrap() {
            let local = SocketAddr::from(([127, 0, 0, 1], addr.port()));
            let _ = TcpStream::connect_timeout(&local, Duration::from_secs(1));
        }

        let (channels, circuits) = {
            let mut t = self.tables.lock().unwrap();
            let channels: Vec<_> = t.channels.drain(..).collect();
            t.outbound.clear();
            let circuits: Vec<_> = t.by_previous.values().cloned().collect();
            t.by_previous.clear();
            t.by_next.clear();
            (channels, circuits)
        };
        for entry in circuits {
            entry.alive.store(false, Ordering::Release);
            *entry.crypto.lock().unwrap() = None;
        }
        for channel in channels {
            channel.close();
        }
    }

    fn handle_cell(self: &Arc<Self>, channel: &Arc<CellChannel>, cell: Cell) {
        match cell.command {
            CellCommand::Create => self.handle_create(channel, &cell),
            CellCommand::Created => self.handle_created(channel, &cell),
            CellCommand::Relay => self.handle_relay(channel, cell),
            CellCommand::Destroy => self.handle_destroy(channel, &cell),
            CellCommand::Padding => {}
        }
    }

    fn handle_create(&self, channel: &Arc<CellChannel>, cell: &Cell) {
        if cell.circuit_id == 0 {
            return; // number zero is reserved for the link's own service cells
        }
        let key = make_key(channel.id(), cell.circuit_id);
        {
            let t = self.tables.lock().unwrap();
            if t.by_previous.contains_key(&key) {
                return; // a repeated Create
            }
        }

        let client_message = &cell.payload[..ntor::CLIENT_HANDSHAKE_SIZE];
        let fingerprint = self.identity.fingerprint();
        let answer = ntor::answer_server(&fingerprint, self.identity.onion_key(), client_message);
        let answer = match answer {
            Some(a) => a,
            None => {
                safe_write(channel, &Cell::build(cell.circuit_id, CellCommand::Destroy, &[]));
                return;
            }
        };

        let entry = Arc::new(CircuitEntry {
            crypto: Mutex::new(Some(RelayHop::new(&answer.key_material))),
            previous: channel.clone(),
            previous_id: cell.circuit_id,
            next: Mutex::new(None),
            extend_pending: AtomicBool::new(false),
            alive: AtomicBool::new(true),
            removed: AtomicBool::new(false),
            context: Mutex::new(None),
        });
        self.tables.lock().unwrap().by_previous.insert(key, entry);

        safe_write(channel, &Cell::build(cell.circuit_id, CellCommand::Created, &answer.server_message));
    }

    fn handle_relay(self: &Arc<Self>, channel: &Arc<CellChannel>, mut cell: Cell) {
        if let Some(entry) = self.lookup(true, channel.id(), cell.circuit_id) {
            self.handle_forward(&entry, cell);
            return;
        }
        if let Some(entry) = self.lookup(false, channel.id(), cell.circuit_id) {
            // A cell from the far end: put our layer on and hand it back.
            let mut crypto = entry.crypto.lock().unwrap();
            if crypto.is_none() {
                return;
            }
            crypto.as_mut().unwrap().wrap_backward(&mut cell.payload);
            safe_write(&entry.previous, &Cell::new(entry.previous_id, CellCommand::Relay, cell.payload));
        }
    }

    fn handle_forward(self: &Arc<Self>, entry: &Arc<CircuitEntry>, mut cell: Cell) {
        let peeled = {
            let mut crypto = entry.crypto.lock().unwrap();
            match crypto.as_mut() {
                None => return, // taken down while the cell was on its way
                Some(hop) => hop.peel_forward(&mut cell.payload),
            }
        };

        match peeled {
            Peeled::PassOn => {
                if let Some((next, next_id)) = entry.next_snapshot() {
                    safe_write(&next, &Cell::new(next_id, CellCommand::Relay, cell.payload));
                }
            }
            Peeled::ForMe(inner) => match inner.command {
                RelayCommand::Extend => self.handle_extend(entry, &inner),
                RelayCommand::Drop => {}
                _ => self.handle_service(entry, inner),
            },
        }
    }

    fn handle_service(self: &Arc<Self>, entry: &Arc<CircuitEntry>, inner: RelayCell) {
        let handler = self.service_handler.lock().unwrap().clone();
        if let Some(handler) = handler {
            let context = self.context_for(entry);
            handler(inner, context);
        }
    }

    fn handle_extend(self: &Arc<Self>, entry: &Arc<CircuitEntry>, inner: &RelayCell) {
        if entry.next.lock().unwrap().is_some() {
            return; // already extended from here
        }
        let target = match extend_payload::try_parse(&inner.data) {
            Some(t) => t,
            None => return,
        };
        let fingerprint = &target.handshake[..FINGERPRINT_SIZE];

        let own_host = self.host.lock().unwrap().clone();
        let lookup = self.list_lookup.lock().unwrap().clone();
        let address = match may_dial(&target.host, target.port, fingerprint, lookup.as_deref(), &own_host) {
            Some(a) => a,
            None => {
                self.send_backward(entry, RelayCell::new(RelayCommand::Truncated, 0, Vec::new()));
                return;
            }
        };

        let next = match self.get_or_connect(&address.to_string(), target.port, fingerprint, &target.onion_key) {
            Some(c) => c,
            None => {
                self.send_backward(entry, RelayCell::new(RelayCommand::Truncated, 0, Vec::new()));
                return;
            }
        };

        let next_id = match next.allocate_circuit_id() {
            Ok(id) => id,
            Err(_) => {
                self.send_backward(entry, RelayCell::new(RelayCommand::Truncated, 0, Vec::new()));
                return;
            }
        };

        {
            let mut t = self.tables.lock().unwrap();
            if !entry.alive.load(Ordering::Acquire) {
                next.release_circuit_id(next_id);
                return;
            }
            *entry.next.lock().unwrap() = Some(NextLink {
                channel: next.clone(),
                id: next_id,
            });
            entry.extend_pending.store(true, Ordering::Release);
            t.by_next.insert(make_key(next.id(), next_id), entry.clone());
        }

        safe_write(&next, &Cell::build(next_id, CellCommand::Create, &target.handshake));
    }

    fn handle_created(&self, channel: &Arc<CellChannel>, cell: &Cell) {
        let entry = match self.lookup(false, channel.id(), cell.circuit_id) {
            Some(e) => e,
            None => return,
        };
        if !entry.extend_pending.swap(false, Ordering::AcqRel) {
            return;
        }
        let server_message = cell.payload[..ntor::SERVER_HANDSHAKE_SIZE].to_vec();
        self.send_backward(&entry, RelayCell::new(RelayCommand::Extended, 0, server_message));
    }

    fn handle_destroy(&self, channel: &Arc<CellChannel>, cell: &Cell) {
        if let Some(entry) = self.lookup(true, channel.id(), cell.circuit_id) {
            if let Some((next, next_id)) = entry.next_snapshot() {
                safe_write(&next, &Cell::build(next_id, CellCommand::Destroy, &[]));
            }
            self.forget(&entry);
            return;
        }
        if let Some(entry) = self.lookup(false, channel.id(), cell.circuit_id) {
            safe_write(&entry.previous, &Cell::build(entry.previous_id, CellCommand::Destroy, &[]));
            self.forget(&entry);
        }
    }

    /// Sends a cell of our own making towards the client. The crypto lock is
    /// held across originate and write so backward cells keep their order.
    fn send_backward(&self, entry: &Arc<CircuitEntry>, cell: RelayCell) {
        let mut crypto = entry.crypto.lock().unwrap();
        if let Some(hop) = crypto.as_mut() {
            let payload = hop.originate_backward(&cell);
            safe_write(&entry.previous, &Cell::new(entry.previous_id, CellCommand::Relay, payload));
        }
    }

    fn get_or_connect(
        self: &Arc<Self>,
        host: &str,
        port: u16,
        fingerprint: &[u8],
        onion_key: &[u8],
    ) -> Option<Arc<CellChannel>> {
        let key = format!("{host}:{port}");
        {
            let t = self.tables.lock().unwrap();
            if let Some(existing) = t.outbound.get(&key) {
                if !existing.is_closed() {
                    return Some(existing.clone());
                }
            }
        }

        let channel = Arc::new(
            CellChannel::connect(host, port, fingerprint, onion_key, HANDSHAKE_TIMEOUT, Some(key.clone())).ok()?,
        );

        {
            let mut t = self.tables.lock().unwrap();
            if let Some(existing) = t.outbound.get(&key) {
                if !existing.is_closed() {
                    channel.close();
                    return Some(existing.clone());
                }
            }
            t.outbound.insert(key.clone(), channel.clone());
            t.channels.push(channel.clone());
        }

        // A reader thread for the neighbour link.
        let shared = self.clone();
        let reader_channel = channel.clone();
        let _ = thread::Builder::new()
            .name(format!("stalknet-out-{key}"))
            .spawn(move || reader_loop(shared, reader_channel));

        Some(channel)
    }

    fn lookup(&self, previous: bool, channel_id: u32, circuit_id: u32) -> Option<Arc<CircuitEntry>> {
        let t = self.tables.lock().unwrap();
        let table = if previous { &t.by_previous } else { &t.by_next };
        table.get(&make_key(channel_id, circuit_id)).cloned()
    }

    fn drop_channel(&self, channel: &Arc<CellChannel>) {
        let mut orphaned: Vec<Arc<CircuitEntry>> = Vec::new();
        {
            let mut t = self.tables.lock().unwrap();
            t.channels.retain(|c| !Arc::ptr_eq(c, channel));
            let outbound_key = t
                .outbound
                .iter()
                .find(|(_, v)| Arc::ptr_eq(v, channel))
                .map(|(k, _)| k.clone());
            if let Some(k) = outbound_key {
                t.outbound.remove(&k);
            }
            collect_circuits(&mut t.by_previous, channel, &mut orphaned);
            collect_circuits(&mut t.by_next, channel, &mut orphaned);
        }

        for entry in &orphaned {
            if !Arc::ptr_eq(&entry.previous, channel) {
                safe_write(&entry.previous, &Cell::build(entry.previous_id, CellCommand::Destroy, &[]));
            }
            if let Some((next, next_id)) = entry.next_snapshot() {
                if !Arc::ptr_eq(&next, channel) {
                    safe_write(&next, &Cell::build(next_id, CellCommand::Destroy, &[]));
                }
            }
            self.forget(entry);
        }

        channel.close();
    }

    fn forget(&self, entry: &Arc<CircuitEntry>) {
        {
            let mut t = self.tables.lock().unwrap();
            if entry.removed.swap(true, Ordering::AcqRel) {
                return; // removed exactly once
            }
            t.by_previous.remove(&make_key(entry.previous.id(), entry.previous_id));
            if let Some(next) = entry.next.lock().unwrap().as_ref() {
                t.by_next.remove(&make_key(next.channel.id(), next.id));
                next.channel.release_circuit_id(next.id);
            }
        }
        entry.alive.store(false, Ordering::Release);

        let context = entry.context.lock().unwrap().clone();
        let closed = self.service_closed.lock().unwrap().clone();
        if let (Some(context), Some(closed)) = (context, closed) {
            closed(context);
        }

        *entry.crypto.lock().unwrap() = None;
    }

    fn context_for(self: &Arc<Self>, entry: &Arc<CircuitEntry>) -> Arc<dyn ServiceContext> {
        let mut slot = entry.context.lock().unwrap();
        if slot.is_none() {
            *slot = Some(Arc::new(EntryContext {
                shared: Arc::downgrade(self),
                entry: Arc::downgrade(entry),
            }));
        }
        let ctx: Arc<EntryContext> = slot.as_ref().unwrap().clone();
        ctx
    }
}

fn collect_circuits(
    table: &mut HashMap<i64, Arc<CircuitEntry>>,
    channel: &Arc<CellChannel>,
    destination: &mut Vec<Arc<CircuitEntry>>,
) {
    let doomed: Vec<i64> = table
        .iter()
        .filter(|(_, entry)| {
            Arc::ptr_eq(&entry.previous, channel)
                || entry
                    .next
                    .lock()
                    .unwrap()
                    .as_ref()
                    .map(|n| Arc::ptr_eq(&n.channel, channel))
                    .unwrap_or(false)
        })
        .map(|(k, _)| *k)
        .collect();
    for key in doomed {
        if let Some(entry) = table.remove(&key) {
            if !destination.iter().any(|e| Arc::ptr_eq(e, &entry)) {
                destination.push(entry);
            }
        }
    }
}

fn safe_write(channel: &Arc<CellChannel>, cell: &Cell) {
    if channel.write(cell).is_err() {
        channel.close();
    }
}

/// Whether a circuit may be extended to this address. The machine's own
/// networks are dialled only for a node the list holds at exactly that place;
/// outside addresses are dialled freely.
fn may_dial(
    host: &str,
    port: u16,
    fingerprint: &[u8],
    lookup: Option<&(dyn Fn(&[u8]) -> Option<RelayDescriptor> + Send + Sync)>,
    own_host: &str,
) -> Option<IpAddr> {
    if host.trim().is_empty() || port == 0 {
        return None;
    }
    let address = (host, port).to_socket_addrs().ok()?.map(|sa| sa.ip()).next()?;

    let own_matches = own_host.parse::<IpAddr>().map(|o| o == address).unwrap_or(false);
    let ours = exit_policy::is_own_network(address) || own_matches;
    if !ours {
        return Some(address);
    }
    let lookup = lookup?;
    let known = lookup(fingerprint)?;
    if known.port == port && known.host.eq_ignore_ascii_case(host) {
        Some(address)
    } else {
        None
    }
}
