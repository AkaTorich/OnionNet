//! The whole node in one place. A pragmatic port of `NodeController`: it signs
//! an identity in, starts the relay and the port stack with the peer desk,
//! introduction/meeting points and folder service, joins the master-less
//! network by discovery and gossip, keeps records with their keepers, raises a
//! hidden service, and opens a SOCKS way out.

use crate::directory::relay_descriptor::{self, RelayDescriptor};
use crate::directory::relay_list::RelayList;
use crate::directory::relay_reputation::RelayReputation;
use crate::discovery::peer_finder;
use crate::hidden::circuit_factory::CircuitFactory;
use crate::hidden::hidden_connection::HiddenConnection;
use crate::hidden::hidden_service::HiddenService;
use crate::hidden::service_descriptor::ServiceDescriptor;
use crate::identity::node_identity::NodeIdentity;
use crate::identity::onion_address::FINGERPRINT_SIZE;
use crate::identity::OnionAddress;
use crate::nat::port_mapper::PortMapper;
use crate::peers::peer_client::{DeskLink, PeerClient};
use crate::peers::peer_protocol::PeerStatus;
use crate::peers::peer_service::{DeskSession, PeerDesk, PeerService, RecordParsers, ServiceFields, SiteFields};
use crate::peers::peer_view::PeerView;
use crate::peers::placement::{self, RecordKind};
use crate::peers::relay_pass;
use crate::sharing::account_authenticator::MemoryAccountAuthenticator;
use crate::sharing::account_store;
use crate::sharing::folder_client::FolderClient;
use crate::sharing::folder_protocol::FolderStatus;
use crate::sharing::shared_folder::ShareAccess;
use crate::streams::exit_policy::{self, ExitPolicy};
use crate::streams::local_port_forwarder::LocalPortForwarder;
use crate::streams::exit_tunnel::ExitTunnel;
use crate::streams::message_channel::MessageChannel;
use crate::streams::multiplexed_circuit::{ClientStream, MultiplexedCircuit};
use crate::streams::port_stack::{PortService, PortStack, ServerStream};
use crate::streams::socks_proxy::SocksProxy;
use crate::streams::stream_opener::{InternetOpener, StreamOpener};
use crate::streams::stream_payloads::well_known_ports;
use crate::swarm::bundle_builder;
use crate::swarm::bundle_link::BundleLink;
use crate::swarm::swarm_download::SwarmDownload;
use crate::swarm::swarm_service::{
    MessageChannel as SwarmMessageChannel, ReplyStream, SwarmPeer, SwarmService, SwarmSession,
};
use crate::swarm::swarm_store::SwarmStore;
use crate::transport::circuit::Circuit;
use crate::transport::relay_node::RelayNode;
use crate::{crypto::rand, swarm::site_record::SiteRecord};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

#[path = "node_swarm.rs"]
mod node_swarm;
pub use node_swarm::BundleRow;

const TIMEOUT: Duration = Duration::from_secs(30);
const TORRENT_BUDGET: Duration = Duration::from_secs(25);
/// How long one torrent announcement may take, and how often it is repeated —
/// about as long as the DHT keeps an announcement.
const ANNOUNCE_BUDGET: Duration = Duration::from_secs(30);
const ANNOUNCE_EVERY: Duration = Duration::from_secs(20 * 60);
/// How many ports past the wanted one are tried when it is taken.
const PORT_ATTEMPTS: u16 = 20;
const PEERS_PORT: u16 = well_known_ports::PEERS;

pub type LogFn = Arc<dyn Fn(String) + Send + Sync>;

/// Settings the window hands in before the node starts.
#[derive(Clone)]
pub struct NodeConfig {
    pub network: String,
    /// The address others see us at — it goes into the card.
    pub public_host: String,
    pub auto_map_port: bool,
    /// Stay a relay even where nobody outside can reach us. Off: a relay
    /// nobody can reach would only break others' circuits, so it turns into a
    /// client once the network has others (the C# role choice). For tests on
    /// one machine.
    pub force_relay: bool,
}

impl Default for NodeConfig {
    fn default() -> Self {
        NodeConfig {
            network: peer_finder::DEFAULT_NETWORK.to_string(),
            public_host: "127.0.0.1".to_string(),
            auto_map_port: true,
            force_relay: false,
        }
    }
}

/// A snapshot of the node for the window.
#[derive(Clone, Default)]
pub struct NodeStatus {
    pub running: bool,
    pub relay: bool,
    pub host: String,
    pub port: u16,
    pub folder_address: String,
    pub nickname: String,
    pub relay_count: usize,
    pub kept_records: usize,
    pub own_circuits: usize,
    pub hidden_address: Option<String>,
    pub way_out_port: Option<u16>,
    /// Bundles are handed out under their own address right now.
    pub seeding: bool,
    /// This node lets others out as an anonymous exit right now.
    pub anonymous_exit: bool,
}

/// A relay in the node's list, for the window's table.
#[derive(Clone)]
pub struct RelayRow {
    pub nickname: String,
    pub address: String,
    pub fingerprint: String,
    pub allows_exit: bool,
    pub trusted: bool,
    pub is_self: bool,
}

/// One of our own shared folders.
#[derive(Clone)]
pub struct SharedRow {
    pub alias: String,
    pub public: bool,
}

/// A folder offered by a remote node we are visiting.
#[derive(Clone)]
pub struct RemoteFolderRow {
    pub alias: String,
    pub public: bool,
}

/// A file inside a remote folder.
#[derive(Clone)]
pub struct RemoteFileRow {
    pub name: String,
    pub size: i64,
}

/// The shared bits needed to reach keepers — cloned into the hidden service's
/// descriptor-changed callback so it can republish without the whole `Node`.
#[derive(Clone)]
struct Records {
    peer_view: Arc<PeerView>,
    reputation: Arc<RelayReputation>,
    self_fingerprint: Vec<u8>,
    is_relay: bool,
    own_desk: Option<Arc<PeerService>>,
    trusted_exits: Vec<Vec<u8>>,
    /// Every circuit starts at this one relay (see `pick_guard`).
    guard: Option<Vec<u8>>,
    /// Paid places at the keepers, by key fingerprint (see `pass_for`).
    passes: Arc<Mutex<std::collections::HashMap<Vec<u8>, Vec<u8>>>>,
    /// Two relays of one /16 never share a circuit — off only for relays on
    /// one machine (tests), where every address is 127.x.
    distinct_subnets: bool,
}

impl Records {
    fn others(&self) -> Vec<RelayDescriptor> {
        self.peer_view
            .snapshot()
            .relays()
            .iter()
            .filter(|r| !rand::constant_time_equals(&r.fingerprint(), &self.self_fingerprint))
            .cloned()
            .collect()
    }

    fn factory(&self) -> CircuitFactory {
        let view = self.peer_view.clone();
        let mut factory = CircuitFactory::with_source(
            Box::new(move || view.snapshot()),
            Some(self.self_fingerprint.clone()),
        );
        factory.require_distinct_subnets = self.distinct_subnets;
        factory.timeout = TIMEOUT;
        factory.reputation = Some(self.reputation.clone());
        factory.guard = self.guard.clone();
        factory
    }

    /// A circuit of at least two hops ending at `target`. Never a direct link:
    /// the target must not learn who is asking — whose announcement, which
    /// bundle's holders, whose folders. `None` when the network is too small.
    fn circuit_to(&self, target: &RelayDescriptor) -> Option<MultiplexedCircuit> {
        self.factory().build_to(target).ok()
    }

    /// For trading relay cards only: a circuit if one can be had, else a direct
    /// link. A card carries its relay's address anyway, and a network of two
    /// relays must still be able to meet.
    fn card_link_to(&self, target: &RelayDescriptor) -> Option<MultiplexedCircuit> {
        if let Some(mux) = self.circuit_to(target) {
            return Some(mux);
        }
        Circuit::build(vec![target.clone()], TIMEOUT).ok().map(MultiplexedCircuit::new)
    }

    fn keepers(&self, kind: RecordKind, key: &[u8], count: usize) -> Vec<RelayDescriptor> {
        let relays = if self.is_relay {
            self.peer_view.snapshot()
        } else {
            RelayList::from_relays(self.others())
        };
        placement::keepers(&relays, kind, key, count)
    }

    fn is_self(&self, relay: &RelayDescriptor) -> bool {
        rand::constant_time_equals(&relay.fingerprint(), &self.self_fingerprint)
    }

    /// Runs `work` at a keeper's desk: ours in place, anyone else's over a circuit.
    fn at_desk<R, F: FnOnce(&dyn PeerDesk) -> R>(&self, keeper: &RelayDescriptor, work: F) -> Option<R> {
        if self.is_self(keeper) {
            let desk = self.own_desk.as_ref()?;
            return Some(work(desk.as_ref()));
        }
        let mux = self.circuit_to(keeper)?;
        let stream = mux.open(PEERS_PORT)?;
        let client = PeerClient::new(ChannelDeskLink::new(stream));
        Some(work(&client))
    }

    /// The paid place at the keepers for a key (see `store_pass`): counted once
    /// per key, then remembered.
    fn pass_for(&self, fingerprint: &[u8]) -> Vec<u8> {
        if let Some(pass) = self.passes.lock().unwrap().get(fingerprint) {
            return pass.clone();
        }
        // Counted outside the lock: seconds of work.
        let pass = crate::peers::store_pass::solve(fingerprint);
        self.passes.lock().unwrap().insert(fingerprint.to_vec(), pass.clone());
        pass
    }

    fn publish_service(&self, descriptor: &ServiceDescriptor) -> Result<(), String> {
        let signed = descriptor.signed_bytes().ok_or("the announcement is not signed")?.to_vec();
        let pass = self.pass_for(&descriptor.fingerprint());
        let mut taken = 0;
        for keeper in self.keepers(RecordKind::Service, &descriptor.fingerprint(), placement::REPLICAS) {
            if let Some(status) = self.at_desk(&keeper, |d| d.publish_service(&signed, &pass)) {
                if status == PeerStatus::Ok {
                    taken += 1;
                }
            }
        }
        if taken == 0 {
            return Err("no keeper took the announcement".into());
        }
        Ok(())
    }

    fn find_service(&self, fingerprint: &[u8]) -> Option<ServiceDescriptor> {
        for keeper in self.keepers(RecordKind::Service, fingerprint, placement::SEARCHED) {
            if let Some((Some(bytes), _)) = self.at_desk(&keeper, |d| d.fetch_service(fingerprint)) {
                if let Some(desc) = ServiceDescriptor::try_parse(&bytes) {
                    return Some(desc);
                }
            }
        }
        None
    }

    /// Who holds the bundle: the answers of the nearest keepers, put together.
    fn find_holders(&self, info_hash: &[u8]) -> Vec<Vec<u8>> {
        let mut all = Vec::new();
        let mut seen: std::collections::HashSet<Vec<u8>> = std::collections::HashSet::new();
        let mut answered = 0;
        for keeper in self.keepers(RecordKind::Holders, info_hash, placement::SEARCHED) {
            if answered >= placement::REPLICAS {
                break;
            }
            if let Some(Some(list)) = self.at_desk(&keeper, |d| d.holders(info_hash)) {
                answered += 1;
                for h in list {
                    if seen.insert(h.clone()) {
                        all.push(h);
                    }
                }
            }
        }
        all
    }

    /// Tells the keepers that `holder` has the bundle, in its own signed word.
    fn announce(&self, info_hash: &[u8], holder: &NodeIdentity) {
        let pass = self.pass_for(&holder.fingerprint());
        let word = crate::peers::holder_proof::make(holder, info_hash, &pass);
        for keeper in self.keepers(RecordKind::Holders, info_hash, placement::REPLICAS) {
            let _ = self.at_desk(&keeper, |d| d.announce(info_hash, &word));
        }
    }

    /// Puts a site's record with its keepers.
    fn publish_site(&self, write_secret: &[u8], record: &[u8]) -> Result<(), String> {
        let parsed = SiteRecord::try_parse(record).ok_or("the site record is damaged")?;
        let lookup = parsed.lookup().to_vec();
        let pass = self.pass_for(&parsed.owner_fingerprint());
        let mut taken = 0;
        let mut refusal = None;
        for keeper in self.keepers(RecordKind::Site, &lookup, placement::REPLICAS) {
            match self.at_desk(&keeper, |d| d.publish_site(write_secret, record, &pass)) {
                Some(PeerStatus::Ok) => taken += 1,
                Some(other) => refusal = Some(other),
                None => {}
            }
        }
        if taken == 0 {
            return Err(match refusal {
                Some(status) => format!("the keepers refused the site: {status:?}"),
                None => "no keeper took the site".into(),
            });
        }
        Ok(())
    }

    /// A site's record from its keepers. `None` if nobody has it.
    fn fetch_site(&self, lookup: &[u8]) -> Option<Vec<u8>> {
        for keeper in self.keepers(RecordKind::Site, lookup, placement::SEARCHED) {
            if let Some((Some(bytes), _)) = self.at_desk(&keeper, |d| d.fetch_site(lookup)) {
                return Some(bytes);
            }
        }
        None
    }
}

// ---- Adapters between the modules -------------------------------------------

/// Binds the peer desk onto the port stack: each stream keeps a `DeskSession`,
/// and every request message gets one response.
struct DeskPort {
    desk: Arc<PeerService>,
}

impl PortService for DeskPort {
    fn on_open(&self, stream: Arc<ServerStream>) -> bool {
        stream.set_state(Box::new(Arc::new(Mutex::new(DeskSession::new()))));
        true
    }

    fn on_data(&self, stream: &Arc<ServerStream>, data: &[u8]) {
        let session = stream.with_state::<Arc<Mutex<DeskSession>>, _>(|s| s.clone());
        if let Some(session) = session {
            let answer = {
                let mut s = session.lock().unwrap();
                self.desk.on_data(&mut s, data)
            };
            if let Some(answer) = answer {
                stream.send(&answer);
            }
        }
    }

    fn on_close(&self, stream: &Arc<ServerStream>) {
        stream.take_state();
    }
}

/// The client side of a desk conversation over an opened mux stream.
struct ChannelDeskLink {
    stream: Arc<ClientStream>,
}

impl ChannelDeskLink {
    fn new(stream: Arc<ClientStream>) -> ChannelDeskLink {
        ChannelDeskLink { stream }
    }
}

impl DeskLink for ChannelDeskLink {
    fn is_open(&self) -> bool {
        self.stream.is_open()
    }
    fn exchange(&self, message: &[u8]) -> Option<Vec<u8>> {
        self.stream.send(message);
        self.stream.receive(TIMEOUT)
    }
}

/// Binds the swarm piece service onto the port stack (virtual port 5).
struct SwarmPort {
    service: Arc<SwarmService>,
}

impl PortService for SwarmPort {
    fn on_open(&self, stream: Arc<ServerStream>) -> bool {
        stream.set_state(Box::new(Arc::new(Mutex::new(self.service.on_open()))));
        true
    }
    fn on_data(&self, stream: &Arc<ServerStream>, data: &[u8]) {
        if let Some(session) = stream.with_state::<Arc<Mutex<SwarmSession>>, _>(|s| s.clone()) {
            let reply = SwarmReply { stream: stream.clone() };
            let mut s = session.lock().unwrap();
            self.service.on_data(&mut s, data, &reply);
        }
    }
    fn on_close(&self, stream: &Arc<ServerStream>) {
        stream.take_state();
    }
}

/// The server side of one swarm stream (adapts `ServerStream` to `ReplyStream`).
struct SwarmReply {
    stream: Arc<ServerStream>,
}

impl ReplyStream for SwarmReply {
    fn send(&self, data: &[u8]) {
        self.stream.send(data);
    }
    fn is_open(&self) -> bool {
        self.stream.is_open()
    }
}

// ---- The node --------------------------------------------------------------

struct Inner {
    config: NodeConfig,
    identity: Option<NodeIdentity>,
    folder_key: Option<Arc<NodeIdentity>>,
    identity_path: Option<PathBuf>,

    peer_view: Arc<PeerView>,
    reputation: Arc<RelayReputation>,
    catalog: Arc<crate::sharing::share_catalog::ShareCatalog>,
    swarm_store: Option<Arc<SwarmStore>>,

    relay_node: Option<Arc<RelayNode>>,
    stack: Option<Arc<PortStack>>,
    /// Folders and offered ports: reachable only through the folders' hidden
    /// address, never through the relay.
    private_stack: Option<Arc<PortStack>>,
    desk: Option<Arc<PeerService>>,
    hidden: Option<Arc<HiddenService>>,
    socks: Option<SocksProxy>,
    mapper: Option<PortMapper>,
    forwards: Vec<crate::streams::local_port_forwarder::LocalPortForwarder>,

    own_card: Arc<Mutex<Option<Vec<u8>>>>,
    pass: Option<(Vec<u8>, u32)>,
    is_relay: bool,
    exit: Arc<ExitPolicy>,
    announcement: Option<ServiceDescriptor>,
    trusted_exits: Vec<Vec<u8>>,

    /// How the node was last started — the role choice restarts it with these.
    started_port: u16,
    started_allow_exit: bool,
    /// The guests' accounts for the folders "by account".
    accounts: Arc<MemoryAccountAuthenticator>,
    /// The entry every circuit starts at (see `pick_guard`).
    guard: Option<Vec<u8>>,
    /// Paid places at the keepers, counted once per key for this run.
    store_passes: Arc<Mutex<std::collections::HashMap<Vec<u8>, Vec<u8>>>>,
    /// The torrent part: seeding, the anonymous exit, sites (node_swarm).
    swarm: node_swarm::SwarmState,
    /// Set to stop the twenty-minute torrent announcement.
    announce_stop: Option<Arc<AtomicBool>>,
}

/// An open visit to someone else's folders — over a circuit or a meeting point.
/// The circuit / hidden connection is held alongside the client so it stays up.
struct RemoteSession {
    client: FolderClient,
    _hidden: HiddenConnection,
}

impl Default for Inner {
    fn default() -> Self {
        Inner {
            config: NodeConfig::default(),
            identity: None,
            folder_key: None,
            identity_path: None,
            peer_view: Arc::new(PeerView::new()),
            reputation: Arc::new(RelayReputation::new()),
            catalog: Arc::new(crate::sharing::share_catalog::ShareCatalog::new()),
            swarm_store: None,
            relay_node: None,
            stack: None,
            private_stack: None,
            desk: None,
            hidden: None,
            socks: None,
            mapper: None,
            forwards: Vec::new(),
            own_card: Arc::new(Mutex::new(None)),
            pass: None,
            is_relay: false,
            exit: Arc::new(ExitPolicy::new()),
            announcement: None,
            trusted_exits: Vec::new(),
            announce_stop: None,
            accounts: Arc::new(MemoryAccountAuthenticator::new()),
            swarm: node_swarm::SwarmState::default(),
            guard: None,
            store_passes: Arc::new(Mutex::new(std::collections::HashMap::new())),
            started_port: 0,
            started_allow_exit: false,
        }
    }
}

pub struct Node {
    inner: Mutex<Inner>,
    log: Mutex<Option<LogFn>>,
    remote: Mutex<Option<RemoteSession>>,
    // Held while the relay pass is being solved, so it is computed only once
    // even if the pre-warm and the join race.
    pass_gate: Mutex<()>,
}

impl Default for Node {
    fn default() -> Self {
        Node::new()
    }
}

impl Node {
    pub fn new() -> Node {
        Node {
            inner: Mutex::new(Inner::default()),
            log: Mutex::new(None),
            remote: Mutex::new(None),
            pass_gate: Mutex::new(()),
        }
    }

    pub fn set_logger(&self, logger: LogFn) {
        *self.log.lock().unwrap() = Some(logger);
    }

    fn say(&self, message: impl Into<String>) {
        if let Some(log) = self.log.lock().unwrap().as_ref() {
            log(message.into());
        }
    }

    // ---- Identity ----------------------------------------------------------

    pub fn create_identity(&self, path: &str, passphrase: &str, nickname: &str) -> Result<(), String> {
        if passphrase.is_empty() {
            return Err("a passphrase is required".into());
        }
        let identity = NodeIdentity::create(nickname).map_err(|e| e.to_string())?;
        let p = Path::new(path);
        identity.save(p, passphrase).map_err(|e| e.to_string())?;
        let folder_key = NodeIdentity::create_folder_key(p, passphrase).map_err(|e| e.to_string())?;

        let mut inner = self.inner.lock().unwrap();
        inner.identity = Some(identity);
        inner.folder_key = Some(Arc::new(folder_key));
        inner.identity_path = Some(p.to_path_buf());
        load_accounts(&inner);
        self.say("identity created");
        Ok(())
    }

    /// Opens the identity at `path`, or — if there is none in this app's format
    /// — makes a fresh one there, with no passphrase. Nothing to type: the node
    /// always ends up with a working identity.
    pub fn open_or_create(&self, path: &str) -> Result<(), String> {
        let p = Path::new(path);
        let (identity, folder_key) = match NodeIdentity::load(p, "") {
            Ok(id) => {
                let fk = NodeIdentity::open_folder_key(p, "").map_err(|e| e.to_string())?;
                (id, fk)
            }
            Err(_) => {
                if let Some(parent) = p.parent() {
                    let _ = std::fs::create_dir_all(parent);
                }
                // A file that is there but will not open (damaged, locked, an
                // old format) is set aside, never overwritten: its keys may
                // still be wanted.
                if p.exists() {
                    let mut aside = p.as_os_str().to_owned();
                    aside.push(format!(".unreadable-{}", unix_seconds()));
                    std::fs::rename(p, &aside)
                        .map_err(|e| format!("the identity file will not open and cannot be set aside: {e}"))?;
                    self.say(format!("the identity file would not open; kept it as {}", Path::new(&aside).display()));
                }
                let id = NodeIdentity::create("").map_err(|e| e.to_string())?;
                id.save(p, "").map_err(|e| e.to_string())?;
                let fk = NodeIdentity::create_folder_key(p, "").map_err(|e| e.to_string())?;
                self.say("a fresh identity was created");
                (id, fk)
            }
        };

        let mut inner = self.inner.lock().unwrap();
        inner.identity = Some(identity);
        inner.folder_key = Some(Arc::new(folder_key));
        inner.identity_path = Some(p.to_path_buf());
        load_accounts(&inner);
        self.say("signed in");
        Ok(())
    }

    pub fn open_identity(&self, path: &str, passphrase: &str) -> Result<(), String> {
        let p = Path::new(path);
        let identity = NodeIdentity::load(p, passphrase).map_err(|e| e.to_string())?;
        let folder_key = NodeIdentity::open_folder_key(p, passphrase).map_err(|e| e.to_string())?;

        let mut inner = self.inner.lock().unwrap();
        inner.identity = Some(identity);
        inner.folder_key = Some(Arc::new(folder_key));
        inner.identity_path = Some(p.to_path_buf());
        load_accounts(&inner);
        self.say("identity opened");
        Ok(())
    }

    pub fn is_logged_in(&self) -> bool {
        self.inner.lock().unwrap().identity.is_some()
    }
    pub fn is_running(&self) -> bool {
        self.inner.lock().unwrap().relay_node.is_some()
    }

    pub fn set_config(&self, config: NodeConfig) {
        self.inner.lock().unwrap().config = config;
    }

    // ---- Start / stop ------------------------------------------------------

    pub fn start(&self, port: u16, allow_exit: bool, relay: bool) -> Result<(), String> {
        let mut inner = self.inner.lock().unwrap();
        if inner.identity.is_none() {
            return Err("sign in first".into());
        }
        if inner.relay_node.is_some() {
            return Err("the node is already running".into());
        }

        let host = inner.config.public_host.clone();

        // The wanted port, or the next free one: two nodes on one machine must
        // not fight over it (as the C# StartOnFreePort).
        let mut attempt: u16 = 0;
        let node = loop {
            let candidate = if port == 0 { 0 } else { port.saturating_add(attempt) };
            // A copy: the identity stays signed in, so STOP then START works
            // and a failed start does not lose it.
            let identity = inner.identity.clone().unwrap();
            let node = Arc::new(RelayNode::new(identity, &host, candidate, allow_exit));
            node.set_accepts_incoming(relay);

            // Dial into our own networks only where our list puts a relay.
            let view = inner.peer_view.clone();
            node.set_list_lookup(Arc::new(move |fp: &[u8]| view.find(fp)));

            if relay {
                let card = inner.own_card.clone();
                node.set_card(Arc::new(move || card.lock().unwrap().clone()));
            }

            match node.start() {
                Ok(()) => {
                    if attempt > 0 {
                        self.say(format!("port {port} was taken; started on {}", node.port()));
                    }
                    break node;
                }
                Err(e) if port != 0 && attempt < PORT_ATTEMPTS && e.kind() == std::io::ErrorKind::AddrInUse => {
                    attempt += 1;
                }
                Err(e) => return Err(e.to_string()),
            }
        };

        let stack = PortStack::new();
        let desk = PeerService::new(inner.peer_view.clone(), record_parsers());

        // The desk takes a home-network card only when it knows our own
        // address; without it every offer at home was refused (the C#
        // `OwnHost = () => PublicHost`). Weak: the desk must not keep the node.
        let weak = Arc::downgrade(&node);
        desk.set_own_host(Some(Arc::new(move || weak.upgrade().map(|n| n.host()))));
        let log = self.log.lock().unwrap().clone();
        desk.set_joined(Some(Arc::new(move |card: &RelayDescriptor| {
            if let Some(log) = &log {
                let name = if card.nickname.is_empty() { "a node" } else { card.nickname.as_str() };
                log(format!("{name} joined from {}:{}", card.host, card.port));
            }
        })));

        if relay {
            stack.bind(PEERS_PORT, Arc::new(DeskPort { desk: desk.clone() }));
            crate::hidden::intro_point_service::IntroPointService::new(&node.identity().fingerprint()).bind(&stack);
            crate::hidden::rendezvous_service::RendezvousService::new().bind(&stack);
        }

        // The folder service serves our catalog on the folders port.
        inner.catalog.set_follow_windows_shares(true);
        // The folders and the offered ports live on a private stack of their
        // own, served only through the folders' hidden address. On the relay's
        // stack they would answer anyone who asks the relay by its card — and
        // the card carries the relay's IP.
        let private_stack = PortStack::new();
        crate::sharing::folder_service::FolderService::with_authenticator(inner.catalog.clone(), inner.accounts.clone())
            .bind(&private_stack);

        // The swarm store (beside the identity). Its pieces are handed out under
        // an address of their own (see node_swarm), never on the relay's own
        // stack: there they would tie every bundle to this relay's card.
        let swarm_root = inner
            .identity_path
            .as_ref()
            .and_then(|p| p.parent().map(|d| d.join("node.swarm")))
            .unwrap_or_else(|| std::env::temp_dir().join("StalkNet").join("node.swarm"));
        if let Ok(store) = SwarmStore::new(&swarm_root) {
            inner.swarm_store = Some(Arc::new(store));
        }

        // A relay that agreed to be an exit lets other tunnels out; the
        // machine's own networks stay shut by the rule itself.
        let mut exit = ExitPolicy::new();
        exit.enabled = relay && allow_exit;
        inner.exit = Arc::new(exit);
        stack.set_exit(Some(inner.exit.clone()));
        stack.attach(&node);

        let actual_port = node.port();
        inner.started_port = port;
        inner.started_allow_exit = allow_exit;
        inner.is_relay = relay;
        inner.relay_node = Some(node);
        inner.stack = Some(stack);
        inner.private_stack = Some(private_stack);
        inner.desk = Some(desk);

        self.say(if relay {
            format!("relay up at {host}:{actual_port}")
        } else {
            "client up (no listener)".to_string()
        });

        let auto_map = inner.config.auto_map_port;
        let home_only = exit_policy::is_own_network(host.parse().unwrap_or(std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST)));
        drop(inner);

        if auto_map && relay && !home_only {
            self.map_port();
        }
        Ok(())
    }

    fn map_port(&self) {
        let (node, port) = {
            let inner = self.inner.lock().unwrap();
            match &inner.relay_node {
                Some(n) => (n.clone(), n.port()),
                None => return,
            }
        };
        // The NAT request runs without the lock held.
        let mut mapper = PortMapper::new();
        let result = mapper.map(port);
        if let Ok(Some(mapping)) = result {
            if mapping.is_reachable_from_internet() {
                if let Some(addr) = mapping.external_address() {
                    node.set_host(&addr.to_string());
                }
                let ext = mapping.external_port();
                node.set_public_port(if ext == port { 0 } else { ext });
                *self.inner.lock().unwrap().own_card.lock().unwrap() = None;
            }
        }
        self.inner.lock().unwrap().mapper = Some(mapper);
    }

    pub fn stop(&self) {
        *self.remote.lock().unwrap() = None;
        // The torrent's own addresses (seeding, the anonymous exit, open sites)
        // go down first; they take the node's lock themselves.
        self.stop_swarm();
        let mut inner = self.inner.lock().unwrap();
        self.close_way_out_locked(&mut inner);
        if let Some(h) = inner.hidden.take() {
            h.stop();
        }
        inner.announcement = None;
        if let Some(stop) = inner.announce_stop.take() {
            stop.store(true, Ordering::Release);
        }
        if let Some(mut mapper) = inner.mapper.take() {
            mapper.unmap();
        }
        let path = inner.identity_path.clone();
        if let Some(path) = &path {
            let _ = inner.peer_view.save(&peers_path(path));
        }
        inner.forwards.clear();
        inner.swarm_store = None;
        inner.stack = None;
        inner.private_stack = None;
        inner.desk = None;
        if let Some(node) = inner.relay_node.take() {
            node.stop();
        }
        *inner.own_card.lock().unwrap() = None;
        inner.is_relay = false;
        self.say("node stopped");
    }

    // ---- The card ----------------------------------------------------------

    /// Solves the relay pass ahead of time (right after sign-in), so joining
    /// the network later is quick. The pass is a one-time memory-hard proof of
    /// work tied to this identity; it is cached in `node.pass` and in memory.
    pub fn warm_pass(&self) {
        let (fingerprint, path, already) = {
            let inner = self.inner.lock().unwrap();
            match &inner.identity {
                Some(id) => (id.fingerprint(), inner.identity_path.clone(), inner.pass.is_some()),
                None => return,
            }
        };
        if already {
            return;
        }
        let _gate = self.pass_gate.lock().unwrap();
        if self.inner.lock().unwrap().pass.is_some() {
            return;
        }
        let bits = relay_descriptor::required_proof_bits();
        self.say(format!("preparing the relay pass ({bits} bits) in the background…"));
        if let Some(pass) = relay_pass::obtain(path.as_deref(), &fingerprint, bits, || false, |_, _| {}) {
            self.inner.lock().unwrap().pass = Some(pass);
            self.say("relay pass ready");
        }
    }

    fn ensure_card(&self) -> Option<Vec<u8>> {
        // Gather what we need under a short lock, then release it: the pass can
        // take a minute to solve, and holding the lock that long would freeze
        // every other call (and the window polling for status).
        let (node, path, have_pass) = {
            let inner = self.inner.lock().unwrap();
            if !inner.is_relay {
                return None;
            }
            if let Some(card) = inner.own_card.lock().unwrap().clone() {
                return Some(card);
            }
            (inner.relay_node.clone()?, inner.identity_path.clone(), inner.pass.clone())
        };

        let pass = match have_pass {
            Some(p) => p,
            None => {
                let _gate = self.pass_gate.lock().unwrap();
                // The pre-warm may have finished it while we waited for the gate.
                let ready = self.inner.lock().unwrap().pass.clone();
                match ready {
                    Some(p) => p,
                    None => {
                        let bits = relay_descriptor::required_proof_bits();
                        self.say(format!("counting the pass ({bits} bits) — this takes a moment…"));
                        let fp = node.identity().fingerprint();
                        let solved = relay_pass::obtain(path.as_deref(), &fp, bits, || false, |_, _| {})?;
                        self.say("pass ready");
                        self.inner.lock().unwrap().pass = Some(solved.clone());
                        solved
                    }
                }
            }
        };

        let (nonce, bits) = pass;
        let mut descriptor = node.descriptor();
        let mut proof = [0u8; 8];
        proof.copy_from_slice(&nonce);
        descriptor.set_proof(proof, bits as u8);
        let signed = descriptor.to_signed_bytes(node.identity()).ok()?;

        let view = {
            let inner = self.inner.lock().unwrap();
            *inner.own_card.lock().unwrap() = Some(signed.clone());
            inner.peer_view.clone()
        };
        view.offer_bytes(&signed);
        Some(signed)
    }

    // ---- Network -----------------------------------------------------------

    pub fn find_relays(&self, via_torrent: bool) -> Vec<RelayDescriptor> {
        let (path, network) = {
            let inner = self.inner.lock().unwrap();
            (inner.identity_path.clone(), inner.config.network.clone())
        };
        if let Some(path) = &path {
            let n = self.inner.lock().unwrap().peer_view.load(&peers_path(path));
            if n > 0 {
                self.say(format!("{n} cards kept from last run"));
            }
        }

        let mut found: Vec<RelayDescriptor> = Vec::new();
        if via_torrent {
            self.say(format!("looking in the torrent network under '{network}'…"));
            let fetched = peer_finder::in_torrent(&network, TORRENT_BUDGET, None, |host, port, wait| {
                crate::transport::cell_channel::CellChannel::request_card(host, port, wait)
            });
            for r in fetched {
                if !self.is_self(&r) {
                    found.push(r);
                }
            }
            self.say(format!("found {} in the torrent network", found.len()));
        }
        found
    }

    pub fn join_network(&self, found: &[RelayDescriptor]) -> usize {
        // The view is taken out first: checking a card's pass is an Argon2 run,
        // and it must not hold the node's lock.
        let view = self.inner.lock().unwrap().peer_view.clone();
        for r in found {
            if !self.is_self(r) {
                view.offer(r.clone());
            }
        }
        let card = self.ensure_card();
        self.start_announcing();
        let records = self.records();

        for relay in pick_some(&records.others(), 3) {
            self.pull_from(&records, &relay);
        }
        if let Some(card) = &card {
            for relay in pick_some(&records.others(), 3) {
                self.offer_to(&records, &relay, card);
            }
        }
        let count = records.others().len();
        // Two statements, not `if let … = self.inner.lock()…`: the guard of an
        // `if let` condition lives to the end of its block, and locking again
        // inside it deadlocked the node for good (the "window froze" bug).
        let (path, view) = {
            let inner = self.inner.lock().unwrap();
            (inner.identity_path.clone(), inner.peer_view.clone())
        };
        if let Some(path) = &path {
            let _ = view.save(&peers_path(path));
        }
        self.say(if count == 0 {
            "no one else in the network yet".to_string()
        } else {
            format!("joined; {count} relays known")
        });
        count
    }

    // ---- Being found -------------------------------------------------------

    /// A relay on the internet announces itself in the torrent network every
    /// twenty minutes (the C# StartBeacons, torrent half). Without this nobody
    /// can find the node at all.
    fn start_announcing(&self) {
        let mut inner = self.inner.lock().unwrap();
        if !inner.is_relay || inner.announce_stop.is_some() {
            return;
        }
        let node = match inner.relay_node.clone() {
            Some(n) => n,
            None => return,
        };

        // An address nobody outside can reach has nothing to do there.
        if !is_public(&node.host()) {
            self.say(format!(
                "{} is not an internet address: not announcing in the torrent network",
                node.host()
            ));
            return;
        }
        let stop = Arc::new(AtomicBool::new(false));
        inner.announce_stop = Some(stop.clone());
        let network = inner.config.network.clone();
        drop(inner);

        let log = self.log.lock().unwrap().clone();
        let _ = std::thread::Builder::new().name("stalknet-announce".into()).spawn(move || {
            while !stop.load(Ordering::Acquire) {
                // The port in the card: the router's outside port when it
                // mapped a different one, else our own.
                let port = node.descriptor().port;
                let taken = peer_finder::announce_in_torrent(&network, port, ANNOUNCE_BUDGET, None);
                if let Some(log) = &log {
                    log(format!("announced in the torrent network under '{network}': {taken} nodes took it"));
                }
                // Sleep in short steps so a STOP is noticed promptly.
                let mut slept = Duration::ZERO;
                while slept < ANNOUNCE_EVERY && !stop.load(Ordering::Acquire) {
                    std::thread::sleep(Duration::from_secs(1));
                    slept += Duration::from_secs(1);
                }
            }
        });
    }

    pub fn reconnect(&self, via_torrent: bool) -> usize {
        let found = self.find_relays(via_torrent);
        self.choose_role(&found);
        let known = self.join_network(&found);
        self.try_start_hidden();
        known
    }

    /// Relay or client (the C# ChooseRole). The very first node of a network is
    /// a relay: somebody has to begin. Once there are others, a relay at an
    /// address nobody outside can reach — no outside address in the settings,
    /// none handed out by the router — would only break their circuits: it
    /// stays a node of its own circuits, all of the network's use and none of
    /// the carrying.
    fn choose_role(&self, found: &[RelayDescriptor]) {
        let (node, force, port, allow_exit) = {
            let inner = self.inner.lock().unwrap();
            if !inner.is_relay {
                return;
            }
            match &inner.relay_node {
                Some(n) => (n.clone(), inner.config.force_relay, inner.started_port, inner.started_allow_exit),
                None => return,
            }
        };
        if force || is_public(&node.host()) {
            return;
        }
        let has_others = found.iter().any(|r| !self.is_self(r)) || !self.records().others().is_empty();
        if !has_others {
            return;
        }
        self.say(format!(
            "{} cannot be reached from the internet: this node carries no traffic for others, \
             it uses the network as a client (forward the port or enter the outside address to relay)",
            node.host()
        ));
        drop(node);
        self.stop();
        if let Err(e) = self.start(port, allow_exit, false) {
            self.say(format!("could not start again as a client: {e}"));
        }
    }

    /// The folders' hidden service needs other relays for its introduction
    /// points; the first node of a network has none yet. It is tried again with
    /// every exchange of cards until it comes up (the C# TryStartHidden).
    fn try_start_hidden(&self) {
        {
            let inner = self.inner.lock().unwrap();
            if inner.hidden.is_some() || inner.relay_node.is_none() {
                return;
            }
        }
        if self.records().others().is_empty() {
            return;
        }
        if let Err(e) = self.start_hidden_service(2) {
            self.say(format!("the folders' address is not up yet ({e}); trying again later"));
        }
    }

    fn pull_from(&self, records: &Records, relay: &RelayDescriptor) {
        if let Some(mux) = records.card_link_to(relay) {
            if let Some(stream) = mux.open(PEERS_PORT) {
                let client = PeerClient::new(ChannelDeskLink::new(stream));
                if let Some(cards) = client.cards() {
                    let view = self.inner.lock().unwrap().peer_view.clone();
                    let mut added = 0;
                    for signed in cards {
                        if matches!(view.offer_bytes(&signed), crate::peers::peer_view::CardVerdict::Added) {
                            added += 1;
                        }
                    }
                    if added > 0 {
                        self.say(format!("learned {added} cards"));
                    }
                }
            }
        }
    }

    fn offer_to(&self, records: &Records, relay: &RelayDescriptor, card: &[u8]) {
        let name = format!("{}:{}", relay.host, relay.port);
        let mux = match records.card_link_to(relay) {
            Some(m) => m,
            None => return self.say(format!("could not reach {name} to offer our card")),
        };
        let stream = match mux.open(PEERS_PORT) {
            Some(s) => s,
            None => return self.say(format!("{name} did not open its card desk")),
        };
        let client = PeerClient::new(ChannelDeskLink::new(stream));
        let status = client.offer(card);
        if status != PeerStatus::Ok {
            self.say(format!("{name} did not take our card: {status:?}"));
        }
    }

    // ---- Hidden service ----------------------------------------------------

    pub fn start_hidden_service(&self, intro_points: usize) -> Result<String, String> {
        let (folder_key, self_fp) = {
            let inner = self.inner.lock().unwrap();
            if inner.hidden.is_some() {
                return Err("the hidden service is already running".into());
            }
            let fk = inner.folder_key.clone().ok_or("sign in first")?;
            let node = inner.relay_node.clone().ok_or("start the node first")?;
            (fk, node.identity().fingerprint().to_vec())
        };

        let mut factory = {
            let inner = self.inner.lock().unwrap();
            let view = inner.peer_view.clone();
            let rep = inner.reputation.clone();
            let mut f = CircuitFactory::with_source(Box::new(move || view.snapshot()), Some(self_fp.clone()));
            f.require_distinct_subnets = false;
            f.timeout = TIMEOUT;
            f.reputation = Some(rep);
            f
        };
        let _ = &mut factory;

        let hidden = Arc::new(HiddenService::new(folder_key.clone(), factory));
        if let Some(stack) = self.inner.lock().unwrap().private_stack.clone() {
            hidden.set_stack(stack);
        }

        // Republish the announcement whenever an introduction point is replaced.
        let records = self.records();
        hidden.on_descriptor_changed(move |descriptor| {
            let _ = records.publish_service(&descriptor);
        });

        let descriptor = hidden.start(intro_points)?;
        // If nobody takes the announcement, take the service down again rather
        // than leave it running where nothing can stop it.
        if let Err(e) = self.records().publish_service(&descriptor) {
            hidden.stop();
            return Err(e);
        }

        let address = descriptor.address().text().to_string();
        let mut inner = self.inner.lock().unwrap();
        inner.hidden = Some(hidden);
        inner.announcement = Some(descriptor);
        self.say(format!("hidden service announced at {address}"));
        Ok(address)
    }

    pub fn stop_hidden_service(&self) {
        let mut inner = self.inner.lock().unwrap();
        if let Some(h) = inner.hidden.take() {
            h.stop();
            inner.announcement = None;
            self.say("hidden service stopped");
        }
    }

    // ---- The way out -------------------------------------------------------

    pub fn open_tunnel(&self, local_port: u16) -> Result<u16, String> {
        {
            let inner = self.inner.lock().unwrap();
            if let Some(socks) = &inner.socks {
                return Ok(socks.local_port());
            }
            if inner.relay_node.is_none() {
                return Err("start the node first".into());
            }
        }

        // The way out is only for those who let others out themselves: a relay
        // does it as an exit, any other node as an anonymous exit raised here
        // by itself. Whoever said "no exit" gets no way out either.
        if !self.lets_others_out() {
            let allow = self.inner.lock().unwrap().started_allow_exit;
            if !allow {
                return Err(
                    "the way out is only for those who let others out: tick \"Allow exit traffic\" and start again".into(),
                );
            }
            self.start_anonymous_exit()?;
        }

        let records = self.records();
        let own_exit = self.own_exit_fingerprint();
        let log = self.log.lock().unwrap().clone();
        let builder: crate::streams::exit_tunnel::TunnelBuilder = Box::new(move || {
            build_way_out(&records).or_else(|| {
                // No relay in the list lets traffic out: an anonymous exit.
                let opener = node_swarm::anonymous_way_out(&records, own_exit.as_deref());
                if opener.is_some() {
                    if let Some(log) = &log {
                        log("the way out goes through an anonymous exit".to_string());
                    }
                }
                opener
            })
        });
        let tunnel: Arc<dyn InternetOpener> = Arc::new(ExitTunnel::new(builder));

        // The port asked for, or the next free one.
        let mut attempt: u16 = 0;
        let proxy = loop {
            let candidate = if local_port == 0 { 0 } else { local_port.saturating_add(attempt) };
            let proxy = SocksProxy::new(tunnel.clone(), candidate);
            match proxy.start() {
                Ok(()) => break proxy,
                Err(e) if local_port != 0 && attempt < PORT_ATTEMPTS && e.kind() == std::io::ErrorKind::AddrInUse => {
                    attempt += 1;
                }
                Err(e) => return Err(e.to_string()),
            }
        };
        let actual = proxy.local_port();

        self.inner.lock().unwrap().socks = Some(proxy);
        self.say(format!("SOCKS way out open on 127.0.0.1:{actual}"));
        Ok(actual)
    }

    fn close_way_out_locked(&self, inner: &mut Inner) {
        inner.socks = None;
    }

    pub fn close_way_out(&self) {
        let mut inner = self.inner.lock().unwrap();
        self.close_way_out_locked(&mut inner);
    }

    // ---- Status ------------------------------------------------------------

    pub fn status(&self) -> NodeStatus {
        let inner = self.inner.lock().unwrap();
        let running = inner.relay_node.is_some();
        let (host, port, nickname) = match &inner.relay_node {
            Some(n) => (
                inner.config.public_host.clone(),
                n.port(),
                n.identity().nickname().to_string(),
            ),
            None => (inner.config.public_host.clone(), 0, String::new()),
        };
        let others = inner
            .peer_view
            .snapshot()
            .relays()
            .iter()
            .filter(|r| {
                inner
                    .relay_node
                    .as_ref()
                    .map(|n| !rand::constant_time_equals(&r.fingerprint(), &n.identity().fingerprint()))
                    .unwrap_or(true)
            })
            .count();
        let kept = inner
            .desk
            .as_ref()
            .map(|d| d.service_count() + d.swarm_count() + d.site_count())
            .unwrap_or(0);

        NodeStatus {
            running,
            relay: inner.is_relay,
            host,
            port,
            folder_address: inner
                .folder_key
                .as_ref()
                .map(|k| k.address().text().to_string())
                .unwrap_or_else(|| "-".to_string()),
            nickname,
            relay_count: others,
            kept_records: kept,
            own_circuits: crate::transport::circuit::live_count(),
            hidden_address: inner.announcement.as_ref().map(|a| a.address().text().to_string()),
            way_out_port: inner.socks.as_ref().map(|s| s.local_port()),
            seeding: inner.swarm.is_seeding(),
            anonymous_exit: inner.swarm.is_exit(),
        }
    }

    // ---- Keepalive gossip --------------------------------------------------

    /// One round of trading cards: renew ours, pull a couple, spread ours.
    pub fn gossip(&self) {
        if !self.is_running() {
            return;
        }
        let card = self.ensure_card();
        let records = self.records();
        for relay in pick_some(&records.others(), 2) {
            self.pull_from(&records, &relay);
        }
        if let Some(card) = &card {
            for relay in pick_some(&records.others(), 3) {
                self.offer_to(&records, &relay, card);
            }
        }
        self.try_start_hidden();
        self.renew_swarm();
    }

    // ---- Trusted exits -----------------------------------------------------

    pub fn set_trusted_exits(&self, hexes: &[String]) {
        let mut out = Vec::new();
        for h in hexes {
            if let Some(b) = hex_to_bytes(h) {
                if b.len() == FINGERPRINT_SIZE {
                    out.push(b);
                }
            }
        }
        self.inner.lock().unwrap().trusted_exits = out;
    }

    pub fn trusted_exits_hex(&self) -> Vec<String> {
        self.inner
            .lock()
            .unwrap()
            .trusted_exits
            .iter()
            .map(|b| bytes_to_hex(b))
            .collect()
    }

    // ---- The relay table ---------------------------------------------------

    pub fn relays(&self) -> Vec<RelayRow> {
        let inner = self.inner.lock().unwrap();
        let self_fp = inner.relay_node.as_ref().map(|n| n.identity().fingerprint().to_vec());
        let trusted = inner.trusted_exits.clone();
        inner
            .peer_view
            .snapshot()
            .relays()
            .iter()
            .map(|r| {
                let fp = r.fingerprint();
                RelayRow {
                    nickname: if r.nickname.is_empty() { "node".into() } else { r.nickname.clone() },
                    address: format!("{}:{}", r.host, r.port),
                    fingerprint: bytes_to_hex(&fp),
                    allows_exit: r.allows_exit,
                    trusted: trusted.iter().any(|t| t.as_slice() == fp),
                    is_self: self_fp.as_ref().map(|s| s.as_slice() == fp).unwrap_or(false),
                }
            })
            .collect()
    }

    // ---- Our own shared folders --------------------------------------------

    pub fn add_shared_folder(&self, path: &str, alias: &str, public: bool) -> Result<(), String> {
        let access = if public { ShareAccess::Public } else { ShareAccess::WindowsAccounts };
        self.inner
            .lock()
            .unwrap()
            .catalog
            .add(path, alias, access)
            .map_err(|e| e.to_string())
    }

    pub fn remove_shared_folder(&self, alias: &str) {
        self.inner.lock().unwrap().catalog.remove(alias);
    }

    pub fn shared_folders(&self) -> Vec<SharedRow> {
        self.inner
            .lock()
            .unwrap()
            .catalog
            .folders()
            .iter()
            .map(|f| SharedRow {
                alias: f.alias().to_string(),
                public: f.access() == ShareAccess::Public,
            })
            .collect()
    }

    // ---- Guests' accounts (folders "by account") ---------------------------

    /// Adds or replaces a guest account. The password is kept only as a salted
    /// Argon2id hash, in "node.accounts" beside the identity.
    pub fn add_account(&self, user_name: &str, password: &str) -> Result<(), String> {
        let user_name = user_name.trim();
        if !account_store::valid_name(user_name) {
            return Err("enter a name (up to 64 characters)".into());
        }
        if password.is_empty() {
            return Err("enter a password".into());
        }
        let (accounts, path) = {
            let inner = self.inner.lock().unwrap();
            (inner.accounts.clone(), inner.identity_path.clone().ok_or("sign in first")?)
        };
        // Hashing takes a moment: outside the node's lock.
        accounts.add_account(user_name, password);
        account_store::save(&account_store::path_for(&path), &accounts.stored()).map_err(|e| e.to_string())?;
        self.say(format!("account '{user_name}' saved"));
        Ok(())
    }

    pub fn remove_account(&self, user_name: &str) -> Result<(), String> {
        let (accounts, path) = {
            let inner = self.inner.lock().unwrap();
            (inner.accounts.clone(), inner.identity_path.clone().ok_or("sign in first")?)
        };
        accounts.remove_account(user_name);
        account_store::save(&account_store::path_for(&path), &accounts.stored()).map_err(|e| e.to_string())
    }

    pub fn accounts(&self) -> Vec<String> {
        self.inner.lock().unwrap().accounts.names()
    }

    // ---- Exposed ports -----------------------------------------------------

    pub fn expose_port(&self, internal: u16, local_host: &str, local_port: u16) -> Result<(), String> {
        let inner = self.inner.lock().unwrap();
        if local_port == 0 {
            return Err("enter the local port".into());
        }
        if local_host.trim().is_empty() {
            return Err("enter the local host".into());
        }
        if internal < well_known_ports::FIRST_USER_PORT {
            return Err(format!("ports under {} are reserved", well_known_ports::FIRST_USER_PORT));
        }
        // Offered on the private stack: reachable through the folders' hidden
        // address only, never through the relay's card.
        let stack = inner.private_stack.clone().ok_or("start the node first")?;
        // Binding a taken port panics in the stack, and a panic here, under the
        // node's lock, would leave every later call broken.
        if stack.bound_ports().contains(&internal) {
            return Err(format!("network port {internal} is already offered"));
        }
        stack.bind(
            internal,
            Arc::new(crate::streams::tcp_port_service::TcpPortService::new(local_host, local_port)),
        );
        Ok(())
    }

    pub fn hide_port(&self, internal: u16) {
        if let Some(stack) = self.inner.lock().unwrap().private_stack.clone() {
            stack.unbind(internal);
        }
    }

    pub fn exposed_ports(&self) -> Vec<u16> {
        match self.inner.lock().unwrap().private_stack.clone() {
            Some(stack) => stack
                .bound_ports()
                .into_iter()
                .filter(|p| *p >= well_known_ports::FIRST_USER_PORT)
                .collect(),
            None => Vec::new(),
        }
    }

    // ---- Visiting someone else's folders -----------------------------------

    pub fn open_hidden(&self, address: &str) -> Result<Vec<RemoteFolderRow>, String> {
        let addr = OnionAddress::try_parse(address).ok_or("not a valid StalkNet address")?;
        let records = self.records();
        let descriptor = records
            .find_service(&addr.fingerprint())
            .ok_or("the service was not found")?;
        let mut factory = records.factory();
        let conn = HiddenConnection::connect(&addr, &descriptor, &mut factory, TIMEOUT).map_err(|e| e.to_string())?;
        let client = FolderClient::connect(&conn).ok_or("the service shares no folders")?;
        let rows = folder_rows(&client)?;
        *self.remote.lock().unwrap() = Some(RemoteSession {
            client,
            _hidden: conn,
        });
        Ok(rows)
    }

    pub fn remote_login(&self, user: &str, password: &str) -> Result<(), String> {
        let guard = self.remote.lock().unwrap();
        let session = guard.as_ref().ok_or("no open folder session")?;
        match session.client.login(user, password) {
            FolderStatus::Ok => Ok(()),
            s => Err(format!("{s:?}")),
        }
    }

    pub fn remote_files(&self, alias: &str) -> Result<Vec<RemoteFileRow>, String> {
        let guard = self.remote.lock().unwrap();
        let session = guard.as_ref().ok_or("no open folder session")?;
        let files = session.client.list_files(alias).map_err(|s| format!("{s:?}"))?;
        Ok(files
            .iter()
            .map(|f| RemoteFileRow {
                name: f.name().to_string(),
                size: f.size(),
            })
            .collect())
    }

    pub fn remote_download(&self, alias: &str, file_name: &str, save_path: &str) -> Result<(), String> {
        let guard = self.remote.lock().unwrap();
        let session = guard.as_ref().ok_or("no open folder session")?;
        // The name comes from the other node: it must be a plain file name, so
        // "..\..\somewhere\x.exe" cannot write outside the chosen folder.
        let plain = Path::new(file_name)
            .file_name()
            .map(|n| n.to_string_lossy() == file_name && !file_name.contains(['/', '\\', ':']))
            .unwrap_or(false);
        if !plain {
            return Err("the other node gave a file name that is not a plain name".into());
        }
        let (id, size) = session.client.open_file(alias, file_name).map_err(|s| format!("{s:?}"))?;
        let mut file = std::fs::File::create(save_path).map_err(|e| e.to_string())?;
        match session.client.download(id, size, &mut file, |_, _| {}) {
            FolderStatus::Ok => Ok(()),
            s => {
                // A half-written file would pass for the whole one.
                drop(file);
                let _ = std::fs::remove_file(save_path);
                Err(format!("{s:?}"))
            }
        }
    }

    pub fn close_remote(&self) {
        *self.remote.lock().unwrap() = None;
    }

    // ---- Local forwards ----------------------------------------------------

    pub fn forward_hidden(&self, address: &str, remote_port: u16, local_port: u16) -> Result<u16, String> {
        let addr = OnionAddress::try_parse(address).ok_or("not a valid StalkNet address")?;
        let records = self.records();
        let descriptor = records
            .find_service(&addr.fingerprint())
            .ok_or("the service was not found")?;
        let mut factory = records.factory();
        let conn = HiddenConnection::connect(&addr, &descriptor, &mut factory, TIMEOUT).map_err(|e| e.to_string())?;
        let opener: Arc<dyn StreamOpener> = Arc::new(conn);
        self.start_forward(opener, remote_port, local_port)
    }

    fn start_forward(&self, opener: Arc<dyn StreamOpener>, remote_port: u16, local_port: u16) -> Result<u16, String> {
        if remote_port == 0 {
            return Err("enter the remote port".into());
        }
        let forwarder = LocalPortForwarder::new(opener, local_port, remote_port);
        forwarder.start().map_err(|e| e.to_string())?;
        let got = forwarder.local_port();
        self.inner.lock().unwrap().forwards.push(forwarder);
        Ok(got)
    }

    // ---- Helpers -----------------------------------------------------------

    fn records(&self) -> Records {
        let mut inner = self.inner.lock().unwrap();
        let self_fp = inner
            .relay_node
            .as_ref()
            .map(|n| n.identity().fingerprint().to_vec())
            .unwrap_or_default();
        let guard = pick_guard(&mut inner, &self_fp);
        let distinct_subnets = inner.relay_node.as_ref().map(|n| !is_loopback(&n.host())).unwrap_or(true);
        Records {
            peer_view: inner.peer_view.clone(),
            reputation: inner.reputation.clone(),
            self_fingerprint: self_fp,
            is_relay: inner.is_relay,
            own_desk: inner.desk.clone(),
            trusted_exits: inner.trusted_exits.clone(),
            guard,
            passes: inner.store_passes.clone(),
            distinct_subnets,
        }
    }

    fn is_self(&self, relay: &RelayDescriptor) -> bool {
        let inner = self.inner.lock().unwrap();
        match &inner.relay_node {
            Some(n) => rand::constant_time_equals(&relay.fingerprint(), &n.identity().fingerprint()),
            None => false,
        }
    }
}

/// A three-hop tunnel to the internet, the last hop an exit. Returns an opener
/// the SOCKS proxy sends connections through.
fn build_way_out(records: &Records) -> Option<Arc<dyn InternetOpener>> {
    use crate::directory::path_selector::PathSelector;
    let relays = records.peer_view.snapshot();

    let selector_with = |guard: Option<Vec<u8>>| {
        let mut selector = PathSelector::default();
        selector.length = 3;
        selector.minimum_length = 2;
        selector.self_fingerprint = Some(records.self_fingerprint.clone());
        selector.require_distinct_subnets = records.distinct_subnets;
        selector.require_exit_flag = true;
        selector.reputation = Some(records.reputation.clone());
        selector.guard_fingerprint = guard;
        if !records.trusted_exits.is_empty() {
            selector.trusted_exits = records.trusted_exits.clone();
        }
        selector
    };

    // Through our guard; if the exit drawn happens to be the guard itself, a
    // path without it (a circuit cannot pass one node twice).
    let path = match selector_with(records.guard.clone()).choose(&relays) {
        Ok(p) => p,
        Err(_) => selector_with(None).choose(&relays).ok()?,
    };
    let circuit = Circuit::build(path.clone(), TIMEOUT).ok()?;
    for relay in &path {
        records.reputation.record_success(&relay.fingerprint());
    }
    Some(Arc::new(MultiplexedCircuit::new(circuit)))
}

fn record_parsers() -> RecordParsers {
    RecordParsers {
        service: Arc::new(|bytes: &[u8]| {
            ServiceDescriptor::try_parse(bytes).map(|d| ServiceFields {
                fingerprint: {
                    let mut fp = [0u8; FINGERPRINT_SIZE];
                    fp.copy_from_slice(&d.fingerprint());
                    fp
                },
                published_ticks: d.published_ticks,
            })
        }),
        site: Arc::new(|bytes: &[u8]| {
            SiteRecord::try_parse(bytes).map(|r| SiteFields {
                owner_fingerprint: r.owner_fingerprint(),
                lookup: r.lookup().to_vec(),
                version: r.version(),
            })
        }),
    }
}

fn peers_path(identity_path: &Path) -> PathBuf {
    let mut p = identity_path.to_path_buf();
    p.set_extension("peers");
    p
}

fn pick_some(relays: &[RelayDescriptor], count: usize) -> Vec<RelayDescriptor> {
    let mut copy: Vec<RelayDescriptor> = relays.to_vec();
    // Fisher–Yates with the cryptographic source, as the C# PickSome.
    for i in (1..copy.len()).rev() {
        let j = rand::next((i + 1) as u32) as usize;
        copy.swap(i, j);
    }
    copy.truncate(count);
    copy
}

fn folder_rows(client: &FolderClient) -> Result<Vec<RemoteFolderRow>, String> {
    let folders = client.hello().map_err(|s| format!("{s:?}"))?;
    Ok(folders
        .iter()
        .map(|f| RemoteFolderRow {
            alias: f.alias().to_string(),
            public: f.access() == ShareAccess::Public,
        })
        .collect())
}

/// An address reachable from the internet: not loopback, not private, not
/// link-local. A name counts as one (the C# IsPublic).
fn is_public(host: &str) -> bool {
    let host = host.trim();
    if host.is_empty() {
        return false;
    }
    match host.parse::<std::net::IpAddr>() {
        Ok(address) => !exit_policy::is_own_network(address),
        Err(_) => true,
    }
}

/// The node's guard: one relay every circuit starts at, kept for good in
/// "node.guard" beside the identity. Were the first hop drawn afresh for every
/// circuit, sooner or later a hostile relay would draw it and see our address;
/// with one guard that happens once or never. A new one is drawn only when the
/// old one has left the network.
fn pick_guard(inner: &mut Inner, self_fp: &[u8]) -> Option<Vec<u8>> {
    if let Some(guard) = &inner.guard {
        if inner.peer_view.find(guard).is_some() {
            return Some(guard.clone());
        }
    }
    let path = inner.identity_path.as_ref().map(|p| {
        let mut g = p.clone();
        g.set_extension("guard");
        g
    });
    // The one kept from the last run, if it is still about.
    if inner.guard.is_none() {
        if let Some(kept) = path.as_ref().and_then(|p| std::fs::read_to_string(p).ok()).and_then(|t| hex_to_bytes(&t)) {
            if inner.peer_view.find(&kept).is_some() {
                inner.guard = Some(kept.clone());
                return Some(kept);
            }
        }
    }
    let candidates: Vec<RelayDescriptor> = inner
        .peer_view
        .snapshot()
        .relays()
        .iter()
        .filter(|r| !rand::constant_time_equals(&r.fingerprint(), self_fp))
        .cloned()
        .collect();
    if candidates.is_empty() {
        return None;
    }
    let chosen = candidates[rand::next(candidates.len() as u32) as usize].fingerprint().to_vec();
    if let Some(p) = &path {
        let _ = std::fs::write(p, bytes_to_hex(&chosen));
    }
    inner.guard = Some(chosen.clone());
    Some(chosen)
}

fn is_loopback(host: &str) -> bool {
    host.trim().parse::<std::net::IpAddr>().map(|a| a.is_loopback()).unwrap_or(false)
}

/// Puts the kept guest accounts (beside the identity) into the node's checker.
fn load_accounts(inner: &Inner) {
    if let Some(path) = &inner.identity_path {
        for (name, stored) in account_store::load(&account_store::path_for(path)) {
            inner.accounts.add_stored(&name, stored);
        }
    }
}

/// Seconds since 1970, for naming a set-aside file.
fn unix_seconds() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn bytes_to_hex(data: &[u8]) -> String {
    let mut s = String::with_capacity(data.len() * 2);
    for b in data {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

fn hex_to_bytes(hex: &str) -> Option<Vec<u8>> {
    let hex = hex.trim();
    // Non-ASCII text would be cut mid-letter below and panic.
    if hex.len() % 2 != 0 || !hex.is_ascii() {
        return None;
    }
    (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).ok())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// STOP then START must work again, and a start that fails (port taken)
    /// must not lose the signed-in identity.
    #[test]
    fn stop_then_start_keeps_the_identity() {
        let dir = std::env::temp_dir().join(format!("stalknet-node-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("node.id");

        let node = Node::new();
        node.open_or_create(&path.to_string_lossy()).unwrap();
        node.set_config(NodeConfig {
            network: "test".into(),
            public_host: "127.0.0.1".into(),
            auto_map_port: false,
            force_relay: true,
        });

        // A taken port: the node moves on to the next free one.
        let blocker = std::net::TcpListener::bind("0.0.0.0:0").unwrap();
        let busy = blocker.local_addr().unwrap().port();
        node.start(busy, false, true).unwrap();
        assert!(node.is_running());
        assert_ne!(node.status().port, busy);
        node.stop();
        assert!(node.is_logged_in());
        drop(blocker);

        node.start(0, false, true).unwrap();
        assert!(node.is_running());
        node.stop();
        assert!(!node.is_running());
        assert!(node.is_logged_in());
        node.start(0, false, true).unwrap();
        assert!(node.is_running());
        node.stop();

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Two nodes on one machine: the second is handed the first one's card (as
    /// the torrent network would) and both end up in each other's lists. Slow (each
    /// counts its relay pass), so it runs on request:
    /// `cargo test --release -- --ignored two_nodes_find_each_other`.
    #[test]
    #[ignore]
    fn two_nodes_find_each_other() {
        crate::directory::relay_descriptor::set_required_proof_bits(10); // keep it quick
        let base = std::env::temp_dir().join(format!("stalknet-two-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        let make = |name: &str| {
            let dir = base.join(name);
            std::fs::create_dir_all(&dir).unwrap();
            let node = Node::new();
            let tag = name.to_string();
            node.set_logger(Arc::new(move |line: String| eprintln!("[{tag}] {line}")));
            node.open_or_create(&dir.join("node.id").to_string_lossy()).unwrap();
            node.set_config(NodeConfig {
                network: "two-test".into(),
                public_host: "127.0.0.1".into(),
                auto_map_port: false,
                force_relay: true,
            });
            node
        };

        let first = make("a");
        first.start(0, false, true).unwrap();
        first.reconnect(false); // alone: makes its card

        // The first one's card, as the torrent network would hand it over.
        let first_fp = first.relays().into_iter().find(|r| r.is_self).unwrap().fingerprint;
        let first_card = first.inner.lock().unwrap().peer_view.find(&hex_to_bytes(&first_fp).unwrap()).unwrap();

        let second = make("b");
        second.start(0, false, true).unwrap();
        let known = second.join_network(&[first_card]);

        assert!(known >= 1, "the second node did not take the first");
        assert!(second.relays().iter().any(|r| r.fingerprint == first_fp));
        // The second offered its card to the first while joining; the first
        // calls it back before taking it, in the background.
        let deadline = std::time::Instant::now() + Duration::from_secs(30);
        while first.relays().len() < 2 && std::time::Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(200));
        }
        assert!(first.relays().len() >= 2, "the first node did not learn the second");

        second.stop();
        first.stop();
        let _ = std::fs::remove_dir_all(&base);
    }

    /// Three relays on this machine form a network, and everything is used for
    /// real: a bundle handed out by one and fetched by another through their
    /// hidden addresses, a site published and opened, a folder "by account"
    /// signed into over the folders' hidden address. Slow; on request:
    /// `cargo test --release -- --ignored network_end_to_end --nocapture`.
    #[test]
    #[ignore]
    fn network_end_to_end() {
        crate::directory::relay_descriptor::set_required_proof_bits(10); // keep it quick
        let base = std::env::temp_dir().join(format!("stalknet-e2e-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        let make = |name: &str| {
            let dir = base.join(name);
            std::fs::create_dir_all(&dir).unwrap();
            let node = Node::new();
            let tag = name.to_string();
            node.set_logger(Arc::new(move |line: String| eprintln!("[{tag}] {line}")));
            node.open_or_create(&dir.join("node.id").to_string_lossy()).unwrap();
            node.set_config(NodeConfig {
                network: "e2e".into(),
                public_host: "127.0.0.1".into(),
                auto_map_port: false,
                force_relay: true,
            });
            node.start(0, false, true).unwrap();
            node
        };
        let card_of = |node: &Node| {
            let fp = node.relays().into_iter().find(|r| r.is_self).unwrap().fingerprint;
            node.inner.lock().unwrap().peer_view.find(&hex_to_bytes(&fp).unwrap()).unwrap()
        };
        let wait_until = |what: &str, check: &dyn Fn() -> bool| {
            let deadline = std::time::Instant::now() + Duration::from_secs(60);
            while !check() {
                assert!(std::time::Instant::now() < deadline, "timed out waiting for: {what}");
                std::thread::sleep(Duration::from_millis(250));
            }
        };

        let a = make("a");
        a.reconnect(false);
        let b = make("b");
        b.join_network(&[card_of(&a)]);
        let c = make("c");
        c.join_network(&[card_of(&a), card_of(&b)]);
        // Everyone learns everyone: the cards travel by offers and gossip.
        for _ in 0..3 {
            a.gossip();
            b.gossip();
            c.gossip();
            if [&a, &b, &c].iter().all(|n| n.relays().len() >= 3) {
                break;
            }
        }
        wait_until("every node knows all three", &|| [&a, &b, &c].iter().all(|n| n.relays().len() >= 3));

        // ---- A bundle: shared by A, fetched by C ----
        let payload: Vec<u8> = (0..50_000u32).map(|i| (i * 7 % 251) as u8).collect();
        let source = base.join("shared.bin");
        std::fs::write(&source, &payload).unwrap();
        let link = a.share(&source.to_string_lossy()).expect("A shares the file");
        let into = base.join("fetched");
        let name = c.download(&link, &into.to_string_lossy()).expect("C downloads it");
        assert_eq!(std::fs::read(into.join(&name)).unwrap(), payload, "the file came whole");

        // ---- A site: published by A, opened by C ----
        let site = base.join("site");
        std::fs::create_dir_all(&site).unwrap();
        std::fs::write(site.join("index.html"), b"<h1>stalknet e2e</h1>").unwrap();
        let address = a.publish_site(&site.to_string_lossy()).expect("A publishes its site");
        let url = c.open_site(&address).expect("C opens it");
        let port: u16 = url.trim_end_matches('/').rsplit(':').next().unwrap().parse().unwrap();
        let mut http = std::net::TcpStream::connect(("127.0.0.1", port)).unwrap();
        use std::io::{Read, Write};
        http.write_all(b"GET / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n").unwrap();
        let mut page = String::new();
        http.read_to_string(&mut page).unwrap();
        assert!(page.contains("stalknet e2e"), "the site's page came: {page}");

        // ---- A folder by account, over A's folders' address ----
        let private = base.join("private");
        std::fs::create_dir_all(&private).unwrap();
        std::fs::write(private.join("secret.txt"), b"for guests only").unwrap();
        a.add_shared_folder(&private.to_string_lossy(), "Priv", false).unwrap();
        a.add_account("guest", "open sesame").unwrap();
        wait_until("A's folders' address is up", &|| a.status().hidden_address.is_some());
        let folders_address = a.status().hidden_address.unwrap();

        let folders = c.open_hidden(&folders_address).expect("C reaches A's folders");
        assert!(folders.iter().any(|f| f.alias == "Priv" && !f.public));
        assert!(c.remote_files("Priv").is_err(), "no files before signing in");
        assert!(c.remote_login("guest", "wrong").is_err(), "a wrong password is refused");
        c.remote_login("guest", "open sesame").expect("the right one opens it");
        let files = c.remote_files("Priv").unwrap();
        assert!(files.iter().any(|f| f.name == "secret.txt"));

        c.stop();
        b.stop();
        a.stop();
        let _ = std::fs::remove_dir_all(&base);
    }
}
