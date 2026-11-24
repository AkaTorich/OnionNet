//! A hidden service: the side whose address on the network is known while its
//! whereabouts are not.
//!
//! It works like this. The service opens long circuits to several nodes of other
//! people's and asks them to be its introduction points. Then it publishes an
//! announcement: here is my key, here are the fingerprints of my introduction
//! points. A client comes to an introduction point over a circuit of its own and
//! hands over a sealed invitation with a meeting point's address. The service
//! builds a third circuit to that meeting point, and there the two circuits are
//! stitched together.
//!
//! There is not one place in this arrangement where the addresses of both sides
//! come together.
//!
//! DECOUPLING FROM C#: this does NOT publish the descriptor itself. It raises the
//! `on_descriptor_changed` callback (the C# `DescriptorChanged` event); the caller
//! puts the announcement with its keepers. By that the service does not depend on
//! the Peers module.

use crate::crypto::rand;
use crate::directory::relay_descriptor::RelayDescriptor;
use crate::directory::relay_reputation::RelayReputation;
use crate::hidden::circuit_factory::CircuitFactory;
use crate::hidden::e2e_channel::E2EChannel;
use crate::hidden::e2e_session::E2ESession;
use crate::hidden::hidden_mux::HiddenMux;
use crate::hidden::hidden_protocol::{self as hp, HiddenStatus, IntroOp, RendezvousOp, COOKIE_SIZE};
use crate::hidden::service_descriptor::ServiceDescriptor;
use crate::identity::node_identity::NodeIdentity;
use crate::identity::onion_address::{OnionAddress, FINGERPRINT_SIZE};
use crate::protocol::ntor;
use crate::streams::message_channel::MessageChannel;
use crate::streams::multiplexed_circuit::{ClientStream, MultiplexedCircuit};
use crate::streams::port_stack::PortStack;
use crate::streams::stream_payloads::well_known_ports;
use crate::text::{t, t_args};
use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

const HANDSHAKE_WAIT: Duration = Duration::from_secs(30);
const IDLE_WAIT: Duration = Duration::from_secs(1);

/// How many nodes to walk through for one introduction point before giving up.
///
/// One attempt is not enough: the circuit to a candidate may break down at the
/// guard, which has nothing to do with the candidate itself. Giving up after the
/// first such break would leave the service unreachable until the watch's next
/// pass — and that is minutes.
pub const ATTEMPTS_PER_INTRO_POINT: usize = 4;

type DescriptorHandler = Arc<dyn Fn(ServiceDescriptor) + Send + Sync>;
type ChannelHandler = Arc<dyn Fn(E2EChannel) + Send + Sync>;
type LogHandler = Arc<dyn Fn(String) + Send + Sync>;

/// The long circuit to one introduction point.
struct IntroLink {
    relay: RelayDescriptor,
    circuit: Mutex<Option<MultiplexedCircuit>>,
    stream: Arc<ClientStream>,
}

impl IntroLink {
    fn new(relay: RelayDescriptor, circuit: MultiplexedCircuit, stream: Arc<ClientStream>) -> IntroLink {
        IntroLink {
            relay,
            circuit: Mutex::new(Some(circuit)),
            stream,
        }
    }

    fn dispose(&self) {
        self.stream.close();
        let _ = self.circuit.lock().unwrap().take(); // drops the circuit (tears it down)
    }
}

struct ServiceState {
    intros: Vec<Arc<IntroLink>>,
    sessions: Vec<HiddenMux>,
    quarantine: HashMap<String, Instant>,
    descriptor: Option<ServiceDescriptor>,
}

struct Inner {
    identity: Arc<NodeIdentity>,
    factory: Mutex<CircuitFactory>,
    state: Mutex<ServiceState>,

    stopping: AtomicBool,
    mending: AtomicBool,

    target_intro_points: AtomicUsize,
    replaced_intro_points: AtomicUsize,
    arrived_count: AtomicUsize,

    intro_backoff: Mutex<Duration>,
    maintenance_interval: Mutex<Duration>,

    stack: Mutex<Option<Arc<PortStack>>>,
    on_descriptor_changed: Mutex<Option<DescriptorHandler>>,
    on_client_arrived: Mutex<Option<ChannelHandler>>,
    logged: Mutex<Option<LogHandler>>,

    maint_flag: Mutex<bool>,
    maint_cv: Condvar,
}

/// Resets the "mending" flag however `maintain` leaves off.
struct MendGuard<'a>(&'a AtomicBool);
impl Drop for MendGuard<'_> {
    fn drop(&mut self) {
        self.0.store(false, Ordering::SeqCst);
    }
}

impl Inner {
    fn stopping(&self) -> bool {
        self.stopping.load(Ordering::Acquire)
    }

    fn with_factory<R>(&self, f: impl FnOnce(&mut CircuitFactory) -> R) -> R {
        let mut guard = self.factory.lock().unwrap();
        f(&mut guard)
    }

    fn reputation(&self) -> Option<Arc<RelayReputation>> {
        self.with_factory(|f| f.reputation.clone())
    }

    fn pick_random(&self, exclude: &[Vec<u8>]) -> Option<RelayDescriptor> {
        self.with_factory(|f| f.pick_random(exclude))
    }

    fn say(&self, message: String) {
        let handler = self.logged.lock().unwrap().clone();
        if let Some(handler) = handler {
            handler(message);
        }
    }

    fn current_intro_points(&self) -> Vec<[u8; FINGERPRINT_SIZE]> {
        self.state
            .lock()
            .unwrap()
            .intros
            .iter()
            .map(|link| link.relay.fingerprint())
            .collect()
    }

    // ---- Quarantine --------------------------------------------------------

    fn quarantined(&self) -> Vec<Vec<u8>> {
        let now = Instant::now();
        let backoff = *self.intro_backoff.lock().unwrap();
        let mut state = self.state.lock().unwrap();

        let mut result = Vec::new();
        let mut expired = Vec::new();
        for (key, when) in state.quarantine.iter() {
            if now.saturating_duration_since(*when) > backoff {
                expired.push(key.clone());
            } else {
                result.push(from_hex(key));
            }
        }
        for key in expired {
            state.quarantine.remove(&key);
        }
        result
    }

    fn quarantine(&self, fingerprint: &[u8]) {
        self.state
            .lock()
            .unwrap()
            .quarantine
            .insert(to_hex(fingerprint), Instant::now());
    }

    // ---- Publishing --------------------------------------------------------

    /// Rebuilds and signs the announcement for the current set of introduction
    /// points, and raises the publish callback.
    fn republish(&self, intro_points: Vec<[u8; FINGERPRINT_SIZE]>) -> Result<ServiceDescriptor, String> {
        let mut descriptor = ServiceDescriptor::from_identity(&self.identity, &intro_points);
        descriptor.to_signed_bytes(&self.identity)?;

        self.state.lock().unwrap().descriptor = Some(descriptor.clone());

        let handler = self.on_descriptor_changed.lock().unwrap().clone();
        if let Some(handler) = handler {
            handler(descriptor.clone());
        }

        Ok(descriptor)
    }

    // ---- Raising introduction points ---------------------------------------

    /// Raises one introduction point, walking through the candidates. Returns the
    /// node it worked out at, or `None`. Those tried are added to `taken` so they
    /// are not picked again.
    fn establish(self: &Arc<Inner>, taken: &mut Vec<Vec<u8>>) -> Option<RelayDescriptor> {
        for _ in 0..ATTEMPTS_PER_INTRO_POINT {
            if self.stopping() {
                return None;
            }

            // First we go around both the taken and those in quarantine.
            let mut avoid = taken.clone();
            avoid.extend(self.quarantined());

            let relay = match self.pick_random(&avoid) {
                Some(r) => Some(r),
                // If quarantine left nobody, we take from whoever is there. A
                // service without introduction points is worse than a service on
                // a less than perfect node.
                None => self.pick_random(taken),
            };
            let relay = relay?;

            taken.push(relay.fingerprint().to_vec());

            if self.try_establish(&relay) {
                return Some(relay);
            }

            self.quarantine(&relay.fingerprint());
        }

        None
    }

    fn try_establish(self: &Arc<Inner>, relay: &RelayDescriptor) -> bool {
        let circuit = match self.with_factory(|f| f.build_to(relay)) {
            Ok(c) => c,
            Err(e) => {
                // No miss is recorded here. The circuit may have broken down at
                // the guard on the way; the factory has already named the culprit.
                self.say(t_args("hs.intro.failed", &[&relay.nickname, &e.to_string()]));
                return false;
            }
        };

        let stream = match circuit.open(well_known_ports::INTRO_POINT) {
            Some(s) => s,
            None => {
                drop(circuit);
                // The circuit came up and the node answered; a refusal on the
                // port is its own, and the miss is its own.
                if let Some(rep) = self.reputation() {
                    rep.record_failure(&relay.fingerprint());
                }
                self.say(t_args("hs.intro.norun", &[&relay.nickname]));
                return false;
            }
        };

        // Signed for this introduction point only, and only for now.
        let body = hp::build_establish(&self.identity, &relay.fingerprint());
        stream.send(&hp::message(IntroOp::Establish as u8, &body));

        let answer = stream.receive(HANDSHAKE_WAIT);
        if !is_ok(&answer, IntroOp::Ack as u8) {
            drop(circuit);
            if let Some(rep) = self.reputation() {
                rep.record_failure(&relay.fingerprint());
            }
            self.say(t_args("hs.intro.refused", &[&relay.nickname]));
            return false;
        }

        let link = Arc::new(IntroLink::new(relay.clone(), circuit, stream));
        self.state.lock().unwrap().intros.push(link.clone());

        let me = self.clone();
        let listening = link.clone();
        thread::Builder::new()
            .name("stalknet-intro".into())
            .spawn(move || me.listen(listening))
            .expect("spawn intro listener thread");

        if let Some(rep) = self.reputation() {
            rep.record_success(&relay.fingerprint());
        }

        let last_length = self.with_factory(|f| f.last_length());
        self.say(t_args("hs.intro.ok", &[&relay.nickname, &last_length.to_string()]));
        true
    }

    /// Waits for invitations at one introduction point for its whole life.
    fn listen(self: Arc<Inner>, link: Arc<IntroLink>) {
        while !self.stopping() && link.stream.is_open() {
            let data = match link.stream.receive(IDLE_WAIT) {
                Some(d) => d,
                None => continue,
            };

            let (op, body) = match hp::try_read(&data) {
                Some(parsed) => parsed,
                None => continue,
            };
            if op != IntroOp::Forwarded as u8 {
                continue;
            }

            // The invitation is handled aside: while the third circuit is being
            // built, the introduction point must stay free for others.
            let me = self.clone();
            thread::Builder::new()
                .name("stalknet-meet".into())
                .spawn(move || me.meet(body))
                .expect("spawn meeting thread");
        }

        {
            let mut state = self.state.lock().unwrap();
            state.intros.retain(|l| !Arc::ptr_eq(l, &link));
        }

        // A broken introduction point is a miss for the node, and a weighty one.
        // But only if it was not us who tore it down.
        if !self.stopping() {
            if let Some(rep) = self.reputation() {
                rep.record_failure(&link.relay.fingerprint());
            }
            self.quarantine(&link.relay.fingerprint());
        }

        link.dispose();
    }

    /// Parses an invitation and goes to the meeting.
    fn meet(self: Arc<Inner>, invite: Vec<u8>) {
        let parsed = match hp::open_invite(&self.identity, &invite) {
            Some(p) => p,
            None => {
                self.say(t("hs.invite.bad"));
                return;
            }
        };

        let answer = match ntor::answer_server(
            &self.identity.fingerprint(),
            self.identity.onion_key(),
            &parsed.client_handshake,
        ) {
            Some(a) => a,
            None => {
                self.say(t("hs.handshake.bad"));
                return;
            }
        };

        let rendezvous = match self.with_factory(|f| f.find(&parsed.rendezvous_fingerprint)) {
            Some(r) => r,
            None => {
                self.say(t("hs.rendezvous.unknown"));
                return;
            }
        };

        let circuit = match self.with_factory(|f| f.build_to(&rendezvous)) {
            Ok(c) => c,
            Err(e) => {
                self.say(t_args("hs.meeting.failed", &[&e.to_string()]));
                return;
            }
        };

        let stream = match circuit.open(well_known_ports::RENDEZVOUS) {
            Some(s) => s,
            None => {
                self.say(t_args("hs.rendezvous.norun", &[&rendezvous.nickname]));
                drop(circuit);
                return;
            }
        };

        let mut body = Vec::with_capacity(COOKIE_SIZE + answer.server_message.len());
        body.extend_from_slice(&parsed.cookie);
        body.extend_from_slice(&answer.server_message);

        stream.send(&hp::message(RendezvousOp::Join as u8, &body));

        // There is no answer to Join: if the token matched, the meeting point
        // quietly stitches the two ends together, and the next message comes from
        // the client already under the end-to-end cipher.
        let mut material = answer.key_material;
        let session = E2ESession::create(&material, false);
        rand::wipe(&mut material);

        // Ownership of the circuit passes to the channel.
        let channel = E2EChannel::new(stream as Arc<dyn MessageChannel>, circuit, session, false);

        self.arrived_count.fetch_add(1, Ordering::SeqCst);
        self.say(t_args("hs.client.arrived", &[&rendezvous.nickname]));

        let handler = self.on_client_arrived.lock().unwrap().clone();
        if let Some(handler) = handler {
            handler(channel);
            return;
        }

        let stack = self.stack.lock().unwrap().clone();
        if let Some(stack) = stack {
            // The guest gets our ordinary port stack, only through the meeting
            // point. The multiplexer lives as long as the channel does.
            let mux = HiddenMux::with_stack(Arc::new(channel), stack);
            let mut state = self.state.lock().unwrap();
            // Guests that left are dropped here, or the list grows for the
            // service's whole life.
            state.sessions.retain(|s| s.is_alive());
            state.sessions.push(mux);
            return;
        }

        channel.close();
    }

    // ---- The watch ---------------------------------------------------------

    fn maintain(self: &Arc<Inner>) {
        if self.stopping() {
            return;
        }
        if self.mending.swap(true, Ordering::SeqCst) {
            return; // a pass is already running
        }
        let _guard = MendGuard(&self.mending);

        let current = self.current_intro_points();
        let target = self.target_intro_points.load(Ordering::SeqCst);
        if current.len() >= target {
            return;
        }
        let missing = target - current.len();

        self.say(t_args("hs.intro.short", &[&current.len().to_string(), &target.to_string()]));

        let mut taken: Vec<Vec<u8>> = current.iter().map(|fp| fp.to_vec()).collect();
        let mut raised = 0usize;
        for _ in 0..missing {
            if self.establish(&mut taken).is_some() {
                raised += 1;
            }
        }

        if raised == 0 {
            self.say(t("hs.intro.nomore"));
            return;
        }

        self.replaced_intro_points.fetch_add(raised, Ordering::SeqCst);

        match self.republish(self.current_intro_points()) {
            Ok(updated) => self.say(t_args("hs.announce.updated", &[&updated.intro_points.len().to_string()])),
            Err(e) => self.say(t_args("hs.watch.failed", &[&e])),
        }
    }

    fn maintenance_loop(self: Arc<Inner>, interval: Duration) {
        loop {
            {
                let flag = self.maint_flag.lock().unwrap();
                let (flag, _) = self
                    .maint_cv
                    .wait_timeout_while(flag, interval, |stop| !*stop)
                    .unwrap();
                if *flag {
                    break; // stop requested
                }
            }
            if self.stopping() {
                break;
            }
            Inner::maintain(&self);
        }
    }

    fn wake_maintenance(&self) {
        *self.maint_flag.lock().unwrap() = true;
        self.maint_cv.notify_all();
    }
}

/// A hidden service (the C# `HiddenService`).
pub struct HiddenService {
    inner: Arc<Inner>,
    maintenance: Mutex<Option<JoinHandle<()>>>,
}

impl HiddenService {
    pub fn new(identity: Arc<NodeIdentity>, factory: CircuitFactory) -> HiddenService {
        let inner = Arc::new(Inner {
            identity,
            factory: Mutex::new(factory),
            state: Mutex::new(ServiceState {
                intros: Vec::new(),
                sessions: Vec::new(),
                quarantine: HashMap::new(),
                descriptor: None,
            }),
            stopping: AtomicBool::new(false),
            mending: AtomicBool::new(false),
            target_intro_points: AtomicUsize::new(0),
            replaced_intro_points: AtomicUsize::new(0),
            arrived_count: AtomicUsize::new(0),
            intro_backoff: Mutex::new(Duration::from_secs(5 * 60)),
            maintenance_interval: Mutex::new(Duration::from_secs(2 * 60)),
            stack: Mutex::new(None),
            on_descriptor_changed: Mutex::new(None),
            on_client_arrived: Mutex::new(None),
            logged: Mutex::new(None),
            maint_flag: Mutex::new(false),
            maint_cv: Condvar::new(),
        });

        HiddenService {
            inner,
            maintenance: Mutex::new(None),
        }
    }

    // ---- Configuration -----------------------------------------------------

    /// The port stack the service serves to its guests — the same one an ordinary
    /// node has. Set it before, or instead of, an `on_client_arrived` handler.
    pub fn set_stack(&self, stack: Arc<PortStack>) {
        *self.inner.stack.lock().unwrap() = Some(stack);
    }

    /// The announcement changed — it has to be published again. The caller puts it
    /// with its keepers. (The C# `DescriptorChanged` event.)
    pub fn on_descriptor_changed(&self, handler: impl Fn(ServiceDescriptor) + Send + Sync + 'static) {
        *self.inner.on_descriptor_changed.lock().unwrap() = Some(Arc::new(handler));
    }

    /// A client arrived — here is the end-to-end channel to them. Needed only by
    /// whoever wants to talk to a guest around the port stack. When set, it takes
    /// precedence over the port stack.
    pub fn on_client_arrived(&self, handler: impl Fn(E2EChannel) + Send + Sync + 'static) {
        *self.inner.on_client_arrived.lock().unwrap() = Some(Arc::new(handler));
    }

    /// Messages about what is going on.
    pub fn on_logged(&self, handler: impl Fn(String) + Send + Sync + 'static) {
        *self.inner.logged.lock().unwrap() = Some(Arc::new(handler));
    }

    /// How often the introduction points are checked. Zero switches the watch
    /// off. Set before [`start`](Self::start).
    pub fn set_maintenance_interval(&self, interval: Duration) {
        *self.inner.maintenance_interval.lock().unwrap() = interval;
    }

    /// How long a node stands aside after failing as an introduction point.
    pub fn set_intro_backoff(&self, backoff: Duration) {
        *self.inner.intro_backoff.lock().unwrap() = backoff;
    }

    // ---- State -------------------------------------------------------------

    pub fn address(&self) -> OnionAddress {
        self.inner.identity.address().clone()
    }

    /// The current announcement with the fresh set of introduction points.
    pub fn descriptor(&self) -> Option<ServiceDescriptor> {
        self.inner.state.lock().unwrap().descriptor.clone()
    }

    /// How many introduction points the service tries to keep up.
    pub fn target_intro_points(&self) -> usize {
        self.inner.target_intro_points.load(Ordering::SeqCst)
    }

    /// How many introduction points had to be raised in place of dropped ones.
    pub fn replaced_intro_points(&self) -> usize {
        self.inner.replaced_intro_points.load(Ordering::SeqCst)
    }

    /// How many clients arrived over all the time.
    pub fn arrived_count(&self) -> usize {
        self.inner.arrived_count.load(Ordering::SeqCst)
    }

    /// How many introduction points are held right now.
    pub fn intro_point_count(&self) -> usize {
        self.inner.state.lock().unwrap().intros.len()
    }

    /// The fingerprints of the nodes holding our introduction points right now.
    pub fn current_intro_points(&self) -> Vec<[u8; FINGERPRINT_SIZE]> {
        self.inner.current_intro_points()
    }

    // ---- Lifecycle ---------------------------------------------------------

    /// Raises the introduction points and returns the signed announcement, which
    /// is left to be put with its keepers (via `on_descriptor_changed`, or the
    /// returned value).
    pub fn start(&self, intro_point_count: usize) -> Result<ServiceDescriptor, String> {
        if intro_point_count < 1 {
            return Err("at least one introduction point is needed".into());
        }

        let mut taken: Vec<Vec<u8>> = Vec::new();
        let mut chosen: Vec<[u8; FINGERPRINT_SIZE]> = Vec::new();

        for _ in 0..intro_point_count {
            match Inner::establish(&self.inner, &mut taken) {
                Some(relay) => chosen.push(relay.fingerprint()),
                None => break,
            }
        }

        if chosen.is_empty() {
            return Err("not one introduction point could be raised — without them the service is unreachable".into());
        }

        self.inner.target_intro_points.store(intro_point_count, Ordering::SeqCst);
        let chosen_count = chosen.len();
        let descriptor = self.inner.republish(chosen)?;

        self.inner.say(t_args(
            "hs.up",
            &[self.inner.identity.address().text(), &chosen_count.to_string()],
        ));

        let interval = *self.inner.maintenance_interval.lock().unwrap();
        if interval > Duration::ZERO {
            let inner = self.inner.clone();
            let handle = thread::Builder::new()
                .name("stalknet-hs-watch".into())
                .spawn(move || inner.maintenance_loop(interval))
                .expect("spawn maintenance thread");
            *self.maintenance.lock().unwrap() = Some(handle);
        }

        Ok(descriptor)
    }

    /// The watch over the introduction points: raise new ones in place of those
    /// that dropped off.
    pub fn maintain(&self) {
        Inner::maintain(&self.inner);
    }

    pub fn stop(&self) {
        if self.inner.stopping.swap(true, Ordering::SeqCst) {
            return;
        }

        self.inner.wake_maintenance();
        if let Some(handle) = self.maintenance.lock().unwrap().take() {
            let _ = handle.join();
        }

        let (links, sessions) = {
            let mut state = self.inner.state.lock().unwrap();
            (std::mem::take(&mut state.intros), std::mem::take(&mut state.sessions))
        };

        for session in sessions {
            drop(session); // HiddenMux's Drop disposes it
        }
        for link in links {
            link.dispose();
        }

        self.inner.say(t("hs.stopped"));
    }
}

impl Drop for HiddenService {
    fn drop(&mut self) {
        self.stop();
    }
}

fn is_ok(answer: &Option<Vec<u8>>, expected_op: u8) -> bool {
    match answer {
        Some(a) => a.len() >= 2 && a[0] == expected_op && a[1] == HiddenStatus::Ok as u8,
        None => false,
    }
}

fn to_hex(data: &[u8]) -> String {
    let mut s = String::with_capacity(data.len() * 2);
    for b in data {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

fn from_hex(hex: &str) -> Vec<u8> {
    (0..hex.len() / 2)
        .map(|i| u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16).unwrap_or(0))
        .collect()
}
