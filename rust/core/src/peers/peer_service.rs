//! A relay's desk, on internal (virtual) port 1 of every relay.
//!
//! It does three things for whoever comes over a circuit. It hands out the cards
//! it knows — that is how a newcomer learns the network and how the relays learn
//! each other. It takes in a relay's own card — and before believing it, calls
//! the relay back at the address written in it: a relay nobody can reach must not
//! get into anyone's paths. And it keeps the records whose keys lie closest to
//! its fingerprint: hidden addresses' announcements, who holds which bundle,
//! sites' sealed records.
//!
//! It keeps nothing it could read: an announcement is signed by its service, a
//! site's record is sealed under its address, a bundle is known only by its hash.
//! A desk can withhold a record — and so every record is put with three of them.
//!
//! ## Decoupling from not-yet-ported modules
//!
//! The C# `PeerService` is an `IPortService`: it is handed a `ServerStream` and
//! replies through it. That stream layer is not ported yet, so here the desk
//! works at the message level — [`PeerService::on_data`] takes one request
//! message and returns the response message to send back, and [`DeskSession`]
//! holds the per-stream state (a frozen bundle, a card arriving in pieces) that
//! the C# kept in `stream.State`. [`PeerService::serve`] is the thin binding that
//! frames the answer as a `RelayCommand::Data` cell and hands it to the circuit's
//! [`ServiceContext`].
//!
//! The C# desk stores `Hidden.ServiceDescriptor` and `Swarm.SiteRecord`, neither
//! of which is ported. Rather than depend on those modules, the desk keeps the
//! signed bytes as they arrive and is given two small parsers ([`RecordParsers`])
//! that pull out only the fields it indexes by. Each mirrors the matching C#
//! `TryParse`.

use crate::crypto::rand;
use crate::directory::relay_descriptor::RelayDescriptor;
use crate::identity::onion_address::FINGERPRINT_SIZE;
use crate::protocol::relay_cell::{RelayCell, RelayCommand};
use crate::transport::cell_channel::CellChannel;
use crate::transport::service_context::ServiceContext;
use sha2::{Digest, Sha256};
use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use super::peer_protocol::{self as proto, Cursor, PeerOp, PeerStatus};
use super::peer_view::{hex, CardVerdict, PeerView};

/// The virtual port every relay's desk listens on. Inlined from
/// `StalkNet.Streams.WellKnownPorts.Peers = 1` (StreamPayloads.cs) so `peers`
/// need not depend on the not-yet-ported Streams layer.
pub const PEERS_PORT: u16 = 1;

/// A bundle's info hash, 32 bytes — the key a swarm is announced under.
const INFO_HASH_SIZE: usize = 32;

/// `Swarm.SiteRecord.SecretSize` (SiteRecord.cs). The write secret guarding a
/// site record.
const SITE_SECRET_SIZE: usize = 32;

/// `Swarm.SiteRecord.LookupSize` (SiteRecord.cs). The hash of the address a site
/// record is filed under.
const SITE_LOOKUP_SIZE: usize = 32;

/// How many cards go in one answer. The rest the asker gets from others.
pub const MAX_CARDS_PER_ANSWER: usize = 1024;

const MAX_PENDING_OFFERS: usize = 64;
const MAX_SERVICES: usize = 8192;
const MAX_SWARMS: usize = 8192;
const MAX_HOLDERS_PER_SWARM: usize = 64;
const MAX_HOLDERS_PER_ANSWER: usize = 20;
const MAX_SITES: usize = 8192;

const CALL_BACK_WAIT: Duration = Duration::from_secs(5);

const DEFAULT_SERVICE_LIFETIME: Duration = Duration::from_secs(3 * 3600);
const DEFAULT_HOLDER_LIFETIME: Duration = Duration::from_secs(3600);
const DEFAULT_SITE_LIFETIME: Duration = Duration::from_secs(24 * 3600);

// ---- Injected record parsing ------------------------------------------------

/// The fields the desk indexes a hidden-service announcement by. Mirrors
/// `ServiceDescriptor.Fingerprint` and `.PublishedUtc`.
pub struct ServiceFields {
    pub fingerprint: [u8; FINGERPRINT_SIZE],
    /// `PublishedUtc.Ticks` — a newer announcement replaces an older one.
    pub published_ticks: i64,
}

/// The fields the desk indexes a site record by. Mirrors `SiteRecord.Lookup` and
/// `.Version`.
pub struct SiteFields {
    pub lookup: Vec<u8>,
    pub version: i64,
}

type ServiceParser = Arc<dyn Fn(&[u8]) -> Option<ServiceFields> + Send + Sync>;
type SiteParser = Arc<dyn Fn(&[u8]) -> Option<SiteFields> + Send + Sync>;

/// The parsers the desk needs for records whose C# types (`ServiceDescriptor`,
/// `SiteRecord`) are not yet ported. Injected at construction. When the `hidden`
/// and `swarm` modules land, bind these to their `try_parse`.
#[derive(Clone)]
pub struct RecordParsers {
    pub service: ServiceParser,
    pub site: SiteParser,
}

// ---- The desk's own interface ----------------------------------------------

/// The desk's work, whoever does it: a relay far away over a circuit (see
/// [`super::peer_client::PeerClient`]), or our own relay when the record falls to
/// it. This is the C# `IPeerDesk`, byte-oriented so it does not drag in the
/// not-yet-ported descriptor and record types: an announcement is its signed
/// bytes, a fetch returns the stored signed bytes.
pub trait PeerDesk {
    fn publish_service(&self, signed: &[u8]) -> PeerStatus;
    /// The stored announcement by its fingerprint. `None` with a status when
    /// nothing is returned.
    fn fetch_service(&self, fingerprint: &[u8]) -> (Option<Vec<u8>>, PeerStatus);
    /// `signed_holder` is the holder's signed word (see `holder_proof`).
    fn announce(&self, info_hash: &[u8], signed_holder: &[u8]) -> PeerStatus;
    /// Who holds the bundle. Empty if nobody, `None` if there was no answer.
    fn holders(&self, info_hash: &[u8]) -> Option<Vec<Vec<u8>>>;
    fn publish_site(&self, write_secret: &[u8], record: &[u8]) -> PeerStatus;
    fn fetch_site(&self, lookup: &[u8]) -> (Option<Vec<u8>>, PeerStatus);
}

// ---- Per-stream state -------------------------------------------------------

/// What one stream is in the middle of: a frozen bundle, a card arriving in
/// pieces. The C# `PeerService.StreamState`, held per `ServerStream`.
#[derive(Default)]
pub struct DeskSession {
    bundle: Option<Vec<u8>>,
    offer: Option<Vec<u8>>,
    offer_filled: usize,
}

impl DeskSession {
    pub fn new() -> DeskSession {
        DeskSession::default()
    }
}

// ---- Shelves and hooks ------------------------------------------------------

struct ServiceEntry {
    signed: Vec<u8>,
    published_ticks: i64,
    seen: SystemTime,
}

struct Holder {
    fingerprint: Vec<u8>,
    seen: SystemTime,
}

struct SiteEntry {
    secret_hash: [u8; 32],
    version: i64,
    record: Vec<u8>,
    seen: SystemTime,
}

#[derive(Default)]
struct Shelves {
    services: HashMap<String, ServiceEntry>,
    swarms: HashMap<String, HashMap<String, Holder>>,
    sites: HashMap<String, SiteEntry>,
}

struct Lifetimes {
    service: Duration,
    holder: Duration,
    site: Duration,
}

type CallBack = Arc<dyn Fn(&RelayDescriptor) -> bool + Send + Sync>;
type OwnHost = Arc<dyn Fn() -> Option<String> + Send + Sync>;
type Joined = Arc<dyn Fn(&RelayDescriptor) + Send + Sync>;

#[derive(Default)]
struct Hooks {
    /// Whether the relay in an offered card answers at its address with that
    /// card's key. `None` skips the check, as a null C# `CallBack` does.
    call_back: Option<CallBack>,
    /// Our own address as our card names it.
    own_host: Option<OwnHost>,
    /// A relay was taken into the list from its own offer.
    joined: Option<Joined>,
}

struct Offers {
    queue: VecDeque<RelayDescriptor>,
    checking: bool,
    disposed: bool,
}

pub struct PeerService {
    view: Arc<PeerView>,
    parsers: RecordParsers,
    shelves: Mutex<Shelves>,
    lifetimes: Mutex<Lifetimes>,
    hooks: Mutex<Hooks>,
    offers: Mutex<Offers>,
}

impl PeerService {
    /// A desk over the given view, with the parsers for the record types the
    /// `peers` module does not itself own. The call-back defaults to dialling the
    /// offered relay back (the C# `DialBack`).
    pub fn new(view: Arc<PeerView>, parsers: RecordParsers) -> Arc<PeerService> {
        Arc::new(PeerService {
            view,
            parsers,
            shelves: Mutex::new(Shelves::default()),
            lifetimes: Mutex::new(Lifetimes {
                service: DEFAULT_SERVICE_LIFETIME,
                holder: DEFAULT_HOLDER_LIFETIME,
                site: DEFAULT_SITE_LIFETIME,
            }),
            hooks: Mutex::new(Hooks {
                call_back: Some(Arc::new(dial_back)),
                own_host: None,
                joined: None,
            }),
            offers: Mutex::new(Offers {
                queue: VecDeque::new(),
                checking: false,
                disposed: false,
            }),
        })
    }

    // ---- Settings (the C# properties) --------------------------------------

    pub fn set_service_lifetime(&self, lifetime: Duration) {
        self.lifetimes.lock().unwrap().service = lifetime;
    }
    pub fn set_holder_lifetime(&self, lifetime: Duration) {
        self.lifetimes.lock().unwrap().holder = lifetime;
    }
    pub fn set_site_lifetime(&self, lifetime: Duration) {
        self.lifetimes.lock().unwrap().site = lifetime;
    }

    /// Replaces the dial-back check. `None` accepts every offer whose pass and
    /// reachability hold, as a null C# `CallBack` does.
    pub fn set_call_back(&self, call_back: Option<CallBack>) {
        self.hooks.lock().unwrap().call_back = call_back;
    }
    pub fn set_own_host(&self, own_host: Option<OwnHost>) {
        self.hooks.lock().unwrap().own_host = own_host;
    }
    pub fn set_joined(&self, joined: Option<Joined>) {
        self.hooks.lock().unwrap().joined = joined;
    }

    pub fn service_count(&self) -> usize {
        self.shelves.lock().unwrap().services.len()
    }
    pub fn swarm_count(&self) -> usize {
        self.shelves.lock().unwrap().swarms.len()
    }
    pub fn site_count(&self) -> usize {
        self.shelves.lock().unwrap().sites.len()
    }

    // ---- The port (C# IPortService) ----------------------------------------

    /// Handles one request message, returning the response message to send back
    /// on the stream (the stream layer frames it as a `RelayCommand::Data` cell
    /// on virtual port 1). `None` means send nothing. This is the C#
    /// `PeerService.OnData` and the `Reply` it drives.
    pub fn on_data(self: &Arc<Self>, session: &mut DeskSession, data: &[u8]) -> Option<Vec<u8>> {
        let (op, payload) = match proto::try_read_request(data) {
            Some(r) => r,
            None => return reply(PeerOp::Cards, PeerStatus::BadRequest, |_| {}),
        };

        match op {
            PeerOp::Cards => self.do_cards(session),
            PeerOp::CardsChunk => do_cards_chunk(session, &payload),
            PeerOp::Offer => self.do_offer(session, &payload),
            PeerOp::PublishService => self.do_publish_service(&payload),
            PeerOp::FetchService => self.do_fetch_service(&payload),
            PeerOp::Announce => self.do_announce(&payload),
            PeerOp::Holders => self.do_holders(&payload),
            PeerOp::PublishSite => self.do_publish_site(&payload),
            PeerOp::FetchSite => self.do_fetch_site(&payload),
        }
    }

    /// Frames `on_data`'s answer as a `Data` cell on `stream_id` and hands it to
    /// the circuit. Like the C# `Reply`, it drops the answer on a dead circuit.
    pub fn serve(self: &Arc<Self>, session: &mut DeskSession, stream_id: u16, data: &[u8], ctx: &dyn ServiceContext) {
        if let Some(answer) = self.on_data(session, data) {
            if ctx.is_alive() {
                ctx.send(RelayCell::new(RelayCommand::Data, stream_id, answer));
            }
        }
    }

    // ---- Cards -------------------------------------------------------------

    fn do_cards(self: &Arc<Self>, session: &mut DeskSession) -> Option<Vec<u8>> {
        let cards = self.view.signed_cards(MAX_CARDS_PER_ANSWER);
        if cards.is_empty() {
            return reply(PeerOp::Cards, PeerStatus::Empty, |_| {});
        }

        // The bundle is frozen for the whole download: otherwise its pieces would
        // come from different moments of the list.
        let mut bundle = Vec::new();
        bundle.extend_from_slice(&(cards.len() as u16).to_le_bytes());
        for card in &cards {
            bundle.extend_from_slice(&(card.len() as u16).to_le_bytes());
            bundle.extend_from_slice(card);
        }

        let total = bundle.len();
        let chunks = total.div_ceil(proto::CHUNK_SIZE);
        let count = cards.len();
        session.bundle = Some(bundle);

        reply(PeerOp::Cards, PeerStatus::Ok, |w| {
            w.extend_from_slice(&(total as i32).to_le_bytes());
            w.extend_from_slice(&(chunks as u16).to_le_bytes());
            w.extend_from_slice(&(count as u16).to_le_bytes());
        })
    }

    // ---- Records over the wire ---------------------------------------------

    fn do_publish_service(self: &Arc<Self>, payload: &[u8]) -> Option<Vec<u8>> {
        let mut r = Cursor::new(payload);
        let signed = match read_u16_prefixed(&mut r) {
            Some(s) => s,
            None => return reply(PeerOp::PublishService, PeerStatus::BadRequest, |_| {}),
        };
        let status = self.publish_service(&signed);
        reply(PeerOp::PublishService, status, |_| {})
    }

    fn do_fetch_service(self: &Arc<Self>, payload: &[u8]) -> Option<Vec<u8>> {
        let mut r = Cursor::new(payload);
        let fingerprint = match r.take(FINGERPRINT_SIZE) {
            Some(f) => f,
            None => return reply(PeerOp::FetchService, PeerStatus::BadRequest, |_| {}),
        };

        let (signed, status) = self.fetch_service(fingerprint);
        match signed {
            None => reply(PeerOp::FetchService, status, |_| {}),
            Some(signed) => reply(PeerOp::FetchService, PeerStatus::Ok, |w| {
                w.extend_from_slice(&(signed.len() as u16).to_le_bytes());
                w.extend_from_slice(&signed);
            }),
        }
    }

    fn do_announce(self: &Arc<Self>, payload: &[u8]) -> Option<Vec<u8>> {
        let mut r = Cursor::new(payload);
        let hash = r.take(INFO_HASH_SIZE);
        let holder = r.take(super::holder_proof::SIZE);
        match (hash, holder) {
            (Some(hash), Some(holder)) => reply(PeerOp::Announce, self.announce(hash, holder), |_| {}),
            _ => reply(PeerOp::Announce, PeerStatus::BadRequest, |_| {}),
        }
    }

    fn do_holders(self: &Arc<Self>, payload: &[u8]) -> Option<Vec<u8>> {
        let mut r = Cursor::new(payload);
        let hash = match r.take(INFO_HASH_SIZE) {
            Some(h) => h,
            None => return reply(PeerOp::Holders, PeerStatus::BadRequest, |_| {}),
        };

        let holders = self.holders_of(hash);
        reply(PeerOp::Holders, PeerStatus::Ok, |w| {
            w.push(holders.len() as u8);
            for holder in &holders {
                w.extend_from_slice(holder);
            }
        })
    }

    fn do_publish_site(self: &Arc<Self>, payload: &[u8]) -> Option<Vec<u8>> {
        let mut r = Cursor::new(payload);
        let secret = r.take(SITE_SECRET_SIZE).map(|s| s.to_vec());
        let record = read_u16_prefixed(&mut r);
        match (secret, record) {
            (Some(secret), Some(record)) => reply(PeerOp::PublishSite, self.publish_site(&secret, &record), |_| {}),
            _ => reply(PeerOp::PublishSite, PeerStatus::BadRequest, |_| {}),
        }
    }

    fn do_fetch_site(self: &Arc<Self>, payload: &[u8]) -> Option<Vec<u8>> {
        let mut r = Cursor::new(payload);
        let lookup = match r.take(SITE_LOOKUP_SIZE) {
            Some(l) => l,
            None => return reply(PeerOp::FetchSite, PeerStatus::BadRequest, |_| {}),
        };

        let (record, status) = self.fetch_site(lookup);
        match record {
            None => reply(PeerOp::FetchSite, status, |_| {}),
            Some(record) => reply(PeerOp::FetchSite, PeerStatus::Ok, |w| {
                w.extend_from_slice(&(record.len() as u16).to_le_bytes());
                w.extend_from_slice(&record);
            }),
        }
    }

    // ---- Offers (a relay's own card, in pieces) ----------------------------

    fn do_offer(self: &Arc<Self>, session: &mut DeskSession, payload: &[u8]) -> Option<Vec<u8>> {
        let mut r = Cursor::new(payload);
        let total = match r.u16_le() {
            Some(t) => t as usize,
            None => return reply(PeerOp::Offer, PeerStatus::BadRequest, |_| {}),
        };
        let offset = match r.u16_le() {
            Some(o) => o as usize,
            None => return reply(PeerOp::Offer, PeerStatus::BadRequest, |_| {}),
        };
        let piece = r.rest().to_vec();

        if total == 0 || total > proto::MAX_OFFERED_CARD || offset + piece.len() > total {
            return reply(PeerOp::Offer, PeerStatus::BadRequest, |_| {});
        }

        if offset == 0 {
            session.offer = Some(vec![0u8; total]);
            session.offer_filled = 0;
        }

        let fits = match &session.offer {
            Some(buf) => buf.len() == total && offset == session.offer_filled,
            None => false,
        };
        if !fits {
            return reply(PeerOp::Offer, PeerStatus::BadRequest, |_| {});
        }

        if let Some(buf) = session.offer.as_mut() {
            buf[offset..offset + piece.len()].copy_from_slice(&piece);
        }
        session.offer_filled += piece.len();

        if session.offer_filled < total {
            return reply(PeerOp::Offer, PeerStatus::More, |_| {});
        }

        let whole = session.offer.take().unwrap();
        match RelayDescriptor::try_parse(&whole) {
            Some(card) if PeerView::is_fresh(&card) => {
                self.enqueue(card);
                reply(PeerOp::Offer, PeerStatus::Ok, |_| {})
            }
            _ => reply(PeerOp::Offer, PeerStatus::BadCard, |_| {}),
        }
    }

    fn enqueue(self: &Arc<Self>, card: RelayDescriptor) {
        {
            let mut offers = self.offers.lock().unwrap();
            if offers.disposed || offers.queue.len() >= MAX_PENDING_OFFERS {
                return;
            }
            offers.queue.push_back(card);
            if offers.checking {
                return;
            }
            offers.checking = true;
        }

        let me = Arc::clone(self);
        std::thread::spawn(move || me.check_offers());
    }

    /// One offer at a time, so a flood of them costs a queue and no more.
    fn check_offers(&self) {
        loop {
            let card = {
                let mut offers = self.offers.lock().unwrap();
                if offers.disposed || offers.queue.is_empty() {
                    offers.checking = false;
                    return;
                }
                offers.queue.pop_front().unwrap()
            };
            self.consider(card);
        }
    }

    fn consider(&self, card: RelayDescriptor) {
        let known = self.view.find(&card.fingerprint());
        if let Some(known) = &known {
            if known.published_ticks >= card.published_ticks {
                return;
            }
        }

        if !self.reachable(&card.host) {
            return;
        }

        // The pass first: a call back costs the asker nothing, a pass costs it a
        // minute.
        if !self.view.pass_holds(&card) {
            return;
        }

        // A relay already known at the same place is just renewing its card — it
        // was called back when it first came.
        let same_place = match &known {
            Some(k) => k.port == card.port && k.host.eq_ignore_ascii_case(&card.host),
            None => false,
        };

        if !same_place {
            let call_back = self.hooks.lock().unwrap().call_back.clone();
            if let Some(cb) = call_back {
                if !cb(&card) {
                    return;
                }
            }
        }

        let joined = self.hooks.lock().unwrap().joined.clone();
        if self.view.offer(card.clone()) == CardVerdict::Added {
            if let Some(handler) = joined {
                handler(&card);
            }
        }
    }

    /// Whether an address could be reached from where we stand.
    fn reachable(&self, host: &str) -> bool {
        use std::net::IpAddr;
        use crate::streams::exit_policy::is_own_network;

        let address: IpAddr = match host.parse() {
            Ok(a) => a,
            Err(_) => return true, // a name, not a literal: assume reachable
        };
        if !is_own_network(address) {
            return true;
        }

        let own = self.hooks.lock().unwrap().own_host.clone();
        let own_host = own.and_then(|f| f());
        let ours: IpAddr = match own_host.as_deref().and_then(|h| h.parse().ok()) {
            Some(a) => a,
            None => return false,
        };

        // The network is an internet one: home addresses are never taken. Only
        // relays on one machine (tests) take the loopback from each other.
        ours.is_loopback() && address.is_loopback()
    }

    // ---- The shelves (the inherent, concrete logic) ------------------------

    fn holders_of(&self, info_hash: &[u8]) -> Vec<Vec<u8>> {
        let mut fresh: Vec<Vec<u8>> = Vec::new();
        let cutoff = {
            let life = self.lifetimes.lock().unwrap().holder;
            SystemTime::now().checked_sub(life)
        };

        {
            let shelves = self.shelves.lock().unwrap();
            if let Some(holders) = shelves.swarms.get(&hex(info_hash)) {
                for holder in holders.values() {
                    let is_fresh = match cutoff {
                        Some(cutoff) => holder.seen >= cutoff,
                        None => true,
                    };
                    if is_fresh {
                        fresh.push(holder.fingerprint.clone());
                    }
                }
            }
        }

        // A random handful: everyone asking gets a different lot, so the load
        // spreads instead of falling on the first few.
        for i in (1..fresh.len()).rev() {
            let j = rand::next((i + 1) as u32) as usize;
            fresh.swap(i, j);
        }
        if fresh.len() > MAX_HOLDERS_PER_ANSWER {
            fresh.truncate(MAX_HOLDERS_PER_ANSWER);
        }
        fresh
    }

    pub fn dispose(&self) {
        self.offers.lock().unwrap().disposed = true;
        self.offers.lock().unwrap().queue.clear();
        let mut shelves = self.shelves.lock().unwrap();
        shelves.services.clear();
        shelves.swarms.clear();
        shelves.sites.clear();
    }

    fn prune_services(&self, shelves: &mut Shelves) {
        if let Some(cutoff) = SystemTime::now().checked_sub(self.lifetimes.lock().unwrap().service) {
            shelves.services.retain(|_, e| e.seen >= cutoff);
        }
    }
    fn prune_sites(&self, shelves: &mut Shelves) {
        if let Some(cutoff) = SystemTime::now().checked_sub(self.lifetimes.lock().unwrap().site) {
            shelves.sites.retain(|_, e| e.seen >= cutoff);
        }
    }
    fn prune_swarms(&self, shelves: &mut Shelves) {
        let cutoff = match SystemTime::now().checked_sub(self.lifetimes.lock().unwrap().holder) {
            Some(c) => c,
            None => return,
        };
        shelves.swarms.retain(|_, holders| {
            holders.retain(|_, h| h.seen >= cutoff);
            !holders.is_empty()
        });
    }
}

impl PeerDesk for PeerService {
    /// Keeps an announcement. The same one again only refreshes it; an older one
    /// is a rollback and is refused.
    fn publish_service(&self, signed: &[u8]) -> PeerStatus {
        let fields = match (self.parsers.service)(signed) {
            Some(f) => f,
            None => return PeerStatus::BadCard,
        };

        let key = hex(&fields.fingerprint);
        let mut shelves = self.shelves.lock().unwrap();
        self.prune_services(&mut shelves);

        if let Some(entry) = shelves.services.get(&key) {
            if fields.published_ticks < entry.published_ticks {
                return PeerStatus::Stale;
            }
        } else if shelves.services.len() >= MAX_SERVICES {
            return PeerStatus::Full;
        }

        shelves.services.insert(
            key,
            ServiceEntry {
                signed: signed.to_vec(),
                published_ticks: fields.published_ticks,
                seen: SystemTime::now(),
            },
        );
        PeerStatus::Ok
    }

    fn fetch_service(&self, fingerprint: &[u8]) -> (Option<Vec<u8>>, PeerStatus) {
        let mut shelves = self.shelves.lock().unwrap();
        self.prune_services(&mut shelves);
        match shelves.services.get(&hex(fingerprint)) {
            Some(entry) => (Some(entry.signed.clone()), PeerStatus::Ok),
            None => (None, PeerStatus::NoService),
        }
    }

    fn announce(&self, info_hash: &[u8], signed_holder: &[u8]) -> PeerStatus {
        if info_hash.len() != INFO_HASH_SIZE || signed_holder.len() != super::holder_proof::SIZE {
            return PeerStatus::BadRequest;
        }
        // The holder is whoever signed the word — never a fingerprint taken on
        // trust.
        let holder = match super::holder_proof::verify(info_hash, signed_holder) {
            Some(fp) => fp,
            None => return PeerStatus::BadCard,
        };
        let holder = &holder[..];

        let mut shelves = self.shelves.lock().unwrap();
        let key = hex(info_hash);

        if !shelves.swarms.contains_key(&key) {
            if shelves.swarms.len() >= MAX_SWARMS {
                self.prune_swarms(&mut shelves);
            }
            if shelves.swarms.len() >= MAX_SWARMS {
                return PeerStatus::Full;
            }
            shelves.swarms.insert(key.clone(), HashMap::new());
        }

        let holders = shelves.swarms.get_mut(&key).unwrap();
        let who = hex(holder);
        if !holders.contains_key(&who) && holders.len() >= MAX_HOLDERS_PER_SWARM {
            // The oldest makes room: a fresh announcement is likelier alive.
            let oldest = holders.iter().min_by_key(|(_, h)| h.seen).map(|(k, _)| k.clone());
            if let Some(oldest) = oldest {
                holders.remove(&oldest);
            }
        }

        holders.insert(
            who,
            Holder {
                fingerprint: holder.to_vec(),
                seen: SystemTime::now(),
            },
        );
        PeerStatus::Ok
    }

    fn holders(&self, info_hash: &[u8]) -> Option<Vec<Vec<u8>>> {
        Some(self.holders_of(info_hash))
    }

    /// Keeps a site's record. Whoever first put a record under an address owns
    /// the place: a newer version is taken only with the same write secret, and
    /// the same version again only refreshes it.
    fn publish_site(&self, write_secret: &[u8], record: &[u8]) -> PeerStatus {
        if write_secret.len() != SITE_SECRET_SIZE {
            return PeerStatus::BadRequest;
        }

        let fields = match (self.parsers.site)(record) {
            Some(f) => f,
            None => return PeerStatus::BadCard,
        };

        let secret_hash: [u8; 32] = Sha256::digest(write_secret).into();

        let mut shelves = self.shelves.lock().unwrap();
        self.prune_sites(&mut shelves);

        let key = hex(&fields.lookup);
        if let Some(entry) = shelves.sites.get(&key) {
            if !rand::constant_time_equals(&entry.secret_hash, &secret_hash) {
                return PeerStatus::NotOwner;
            }
            if fields.version < entry.version {
                return PeerStatus::Stale;
            }
        } else if shelves.sites.len() >= MAX_SITES {
            return PeerStatus::Full;
        }

        shelves.sites.insert(
            key,
            SiteEntry {
                secret_hash,
                version: fields.version,
                record: record.to_vec(),
                seen: SystemTime::now(),
            },
        );
        PeerStatus::Ok
    }

    fn fetch_site(&self, lookup: &[u8]) -> (Option<Vec<u8>>, PeerStatus) {
        let mut shelves = self.shelves.lock().unwrap();
        self.prune_sites(&mut shelves);
        match shelves.sites.get(&hex(lookup)) {
            Some(entry) => (Some(entry.record.clone()), PeerStatus::Ok),
            None => (None, PeerStatus::NoSite),
        }
    }
}

// ---- A chunk request, and the one piece it names ----------------------------

/// Serves one chunk of the frozen bundle. A plain fn because it needs no desk
/// state beyond the session. The C# `DoCardsChunk`.
fn do_cards_chunk(session: &mut DeskSession, payload: &[u8]) -> Option<Vec<u8>> {
    let bundle = match &session.bundle {
        Some(b) => b,
        None => return reply(PeerOp::CardsChunk, PeerStatus::BadRequest, |_| {}),
    };

    let mut r = Cursor::new(payload);
    let index = match r.i32_le() {
        Some(i) => i,
        None => return reply(PeerOp::CardsChunk, PeerStatus::BadRequest, |_| {}),
    };

    let offset = index as i64 * proto::CHUNK_SIZE as i64;
    if index < 0 || offset >= bundle.len() as i64 {
        return reply(PeerOp::CardsChunk, PeerStatus::BadRequest, |_| {});
    }

    let offset = offset as usize;
    let length = std::cmp::min(proto::CHUNK_SIZE, bundle.len() - offset);
    Some(proto::chunk(PeerOp::CardsChunk, index, bundle, offset, length))
}

// ---- Small helpers ----------------------------------------------------------

/// Builds a reply message, or `None` if it somehow would not fit (the C# `Reply`
/// quietly sends nothing in that case — the size is bounded by construction).
fn reply<F: FnOnce(&mut Vec<u8>)>(op: PeerOp, status: PeerStatus, body: F) -> Option<Vec<u8>> {
    proto::response(op, status, body).ok()
}

/// Reads a `u16`-length-prefixed byte run, as the C# `ReadUInt16` + `ReadBytes`
/// with the `signed.Length != length` guard.
fn read_u16_prefixed(r: &mut Cursor) -> Option<Vec<u8>> {
    let length = r.u16_le()? as usize;
    r.take(length).map(|b| b.to_vec())
}

/// Calls the relay at its card's address and checks that the same key answers.
/// The C# `DialBack`, over the ported `CellChannel::request_card`.
pub fn dial_back(card: &RelayDescriptor) -> bool {
    match CellChannel::request_card(&card.host, card.port, CALL_BACK_WAIT) {
        Some(answer) => match RelayDescriptor::try_parse(&answer) {
            Some(there) => rand::constant_time_equals(&there.fingerprint(), &card.fingerprint()),
            None => false,
        },
        None => false,
    }
}

/// The current moment in .NET ticks, used by injected parsers that compare a
/// `published_ticks` against now if they wish. Kept here for convenience.
pub fn now_ticks() -> i64 {
    const TICKS_AT_UNIX_EPOCH: i64 = 621_355_968_000_000_000;
    match SystemTime::now().duration_since(UNIX_EPOCH) {
        Ok(d) => TICKS_AT_UNIX_EPOCH + d.as_secs() as i64 * 10_000_000 + (d.subsec_nanos() / 100) as i64,
        Err(_) => TICKS_AT_UNIX_EPOCH,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A test service parser: the "signed" bytes are `fingerprint(20) ||
    /// published_ticks(8 LE)`.
    fn test_parsers() -> RecordParsers {
        RecordParsers {
            service: Arc::new(|signed: &[u8]| {
                if signed.len() < FINGERPRINT_SIZE + 8 {
                    return None;
                }
                let mut fp = [0u8; FINGERPRINT_SIZE];
                fp.copy_from_slice(&signed[..FINGERPRINT_SIZE]);
                let mut t = [0u8; 8];
                t.copy_from_slice(&signed[FINGERPRINT_SIZE..FINGERPRINT_SIZE + 8]);
                Some(ServiceFields {
                    fingerprint: fp,
                    published_ticks: i64::from_le_bytes(t),
                })
            }),
            // A test site record: `lookup(32) || version(8 LE)`.
            site: Arc::new(|record: &[u8]| {
                if record.len() < SITE_LOOKUP_SIZE + 8 {
                    return None;
                }
                let mut v = [0u8; 8];
                v.copy_from_slice(&record[SITE_LOOKUP_SIZE..SITE_LOOKUP_SIZE + 8]);
                Some(SiteFields {
                    lookup: record[..SITE_LOOKUP_SIZE].to_vec(),
                    version: i64::from_le_bytes(v),
                })
            }),
        }
    }

    fn desk() -> Arc<PeerService> {
        PeerService::new(Arc::new(PeerView::new()), test_parsers())
    }

    #[test]
    fn service_publish_fetch_and_rollback() {
        let svc = desk();
        let fp = [7u8; FINGERPRINT_SIZE];
        let mut signed = fp.to_vec();
        signed.extend_from_slice(&100i64.to_le_bytes());

        assert_eq!(svc.publish_service(&signed), PeerStatus::Ok);
        let (got, status) = svc.fetch_service(&fp);
        assert_eq!(status, PeerStatus::Ok);
        assert_eq!(got.unwrap(), signed);

        // An older announcement is a rollback.
        let mut older = fp.to_vec();
        older.extend_from_slice(&50i64.to_le_bytes());
        assert_eq!(svc.publish_service(&older), PeerStatus::Stale);

        // An unknown fingerprint is not here.
        let (none, status) = svc.fetch_service(&[0u8; FINGERPRINT_SIZE]);
        assert!(none.is_none());
        assert_eq!(status, PeerStatus::NoService);
    }

    #[test]
    fn announce_and_holders() {
        let svc = desk();
        let hash = [3u8; INFO_HASH_SIZE];
        let key = crate::identity::node_identity::NodeIdentity::create("").unwrap();
        let word = crate::peers::holder_proof::make(&key, &hash);
        assert_eq!(svc.announce(&hash, &word), PeerStatus::Ok);

        let holders = svc.holders(&hash).unwrap();
        assert_eq!(holders.len(), 1);
        assert_eq!(holders[0], key.fingerprint().to_vec());

        // Bad sizes are refused, and a word for another bundle is no word.
        assert_eq!(svc.announce(&[0u8; 3], &word), PeerStatus::BadRequest);
        assert_eq!(svc.announce(&[4u8; INFO_HASH_SIZE], &word), PeerStatus::BadCard);
        // A bare fingerprint is not taken on trust any more.
        assert_eq!(svc.announce(&hash, &[9u8; FINGERPRINT_SIZE]), PeerStatus::BadRequest);
    }

    #[test]
    fn site_ownership_is_enforced() {
        let svc = desk();
        let secret_a = [1u8; SITE_SECRET_SIZE];
        let secret_b = [2u8; SITE_SECRET_SIZE];

        let mut record = [5u8; SITE_LOOKUP_SIZE].to_vec();
        record.extend_from_slice(&10i64.to_le_bytes());
        assert_eq!(svc.publish_site(&secret_a, &record), PeerStatus::Ok);

        // Another secret cannot overwrite it.
        let mut newer = [5u8; SITE_LOOKUP_SIZE].to_vec();
        newer.extend_from_slice(&20i64.to_le_bytes());
        assert_eq!(svc.publish_site(&secret_b, &newer), PeerStatus::NotOwner);

        // The owner may publish a newer version.
        assert_eq!(svc.publish_site(&secret_a, &newer), PeerStatus::Ok);

        let (record, status) = svc.fetch_site(&[5u8; SITE_LOOKUP_SIZE]);
        assert_eq!(status, PeerStatus::Ok);
        assert_eq!(record.unwrap(), newer);
    }

    #[test]
    fn bad_request_message_yields_bad_request() {
        let svc = desk();
        let mut session = DeskSession::new();
        // An empty message has no op byte.
        let answer = svc.on_data(&mut session, &[]).unwrap();
        let (_, status, _) = proto::try_read_response(&answer).unwrap();
        assert_eq!(status, PeerStatus::BadRequest);
    }
}
