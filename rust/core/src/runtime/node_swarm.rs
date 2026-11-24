//! The torrent part of the node (the C# `NodeController.Swarm`): bundles of
//! files and sites handed around the swarm, and the anonymous way out found
//! through it.
//!
//! Two hidden addresses of their own, made afresh on every start and thrown
//! away on stop: one hands bundles out, the other lets guests out. Neither is
//! the folders' address and neither is the relay's fingerprint. A holder's
//! address is known to anyone with the link, and an exit's address to anyone who
//! used it — and a user of an exit learns its IP from the sites it opened for
//! them. Under the folders' address or the relay's card all of that would tie
//! straight to the participant.

use super::*;
use crate::crypto::rand;
use crate::hidden::hidden_connection::HiddenConnection;
use crate::streams::stream_end_reason::StreamEndReason;
use crate::swarm::bundle_manifest::BundleKind;
use crate::swarm::exit_service::{ExitRefusal, ExitService, ExitSession, ExitStream};
use crate::swarm::local_site_server::LocalSiteServer;
use crate::swarm::site_record::SiteRecord;
use sha2::{Digest, Sha256};
use std::collections::HashMap;

/// The swarm every anonymous exit "holds": its keepers list the exits under it.
pub(super) fn exit_swarm() -> Vec<u8> {
    Sha256::digest(b"stalknet-anonymous-exit-v1").to_vec()
}

/// One extra hidden address with its own port stack (the swarm's, the exit's).
pub(super) struct SideService {
    key: Arc<NodeIdentity>,
    hidden: Arc<HiddenService>,
    _stack: Arc<PortStack>,
}

impl SideService {
    fn fingerprint(&self) -> Vec<u8> {
        self.key.fingerprint().to_vec()
    }
}

/// A bundle in the torrent table, the way the window shows it.
#[derive(Clone)]
pub struct BundleRow {
    pub name: String,
    pub kind: String,
    pub size: String,
    pub progress: String,
    pub link: String,
}

#[derive(Clone)]
pub(super) struct KnownBundle {
    link: BundleLink,
    name: String,
    kind: BundleKind,
}

/// The torrent part's state, kept in the node.
#[derive(Default)]
pub(super) struct SwarmState {
    seeding: Option<SideService>,
    seeding_service: Option<Arc<SwarmService>>,
    exit: Option<SideService>,
    exit_service: Option<Arc<ExitService>>,
    known: Vec<KnownBundle>,
    site_views: HashMap<String, LocalSiteServer>,
    site_record: Option<Vec<u8>>,
}

impl SwarmState {
    pub(super) fn is_seeding(&self) -> bool {
        self.seeding.is_some()
    }
    pub(super) fn is_exit(&self) -> bool {
        self.exit.is_some()
    }
}

// ---- Adapters ---------------------------------------------------------------

/// Binds the anonymous exit onto a port stack (virtual port 6).
struct ExitPort {
    service: Arc<ExitService>,
}

/// The exit's side of one stream.
struct ExitReply {
    stream: Arc<ServerStream>,
}

impl ExitStream for ExitReply {
    fn send(&self, data: &[u8]) {
        self.stream.send(data);
    }
    fn is_open(&self) -> bool {
        self.stream.is_open()
    }
    fn close(&self) {
        self.stream.close(StreamEndReason::Done);
    }
}

impl PortService for ExitPort {
    fn on_open(&self, stream: Arc<ServerStream>) -> bool {
        stream.set_state(Box::new(self.service.on_open()));
        true
    }
    fn on_data(&self, stream: &Arc<ServerStream>, data: &[u8]) {
        if let Some(session) = stream.with_state::<ExitSession, _>(|s| s.clone()) {
            let reply: Arc<dyn ExitStream> = Arc::new(ExitReply { stream: stream.clone() });
            self.service.on_data(&session, data, reply);
        }
    }
    fn on_close(&self, stream: &Arc<ServerStream>) {
        if let Some(session) = stream.with_state::<ExitSession, _>(|s| s.clone()) {
            self.service.on_close(&session);
        }
        stream.take_state();
    }
}

/// The downloader's side of one stream to a holder's hidden address. The
/// hidden connection is held so the meeting stays up while the stream is used.
struct HolderChannel {
    _connection: HiddenConnection,
    stream: Arc<dyn MessageChannel>,
}

impl SwarmMessageChannel for HolderChannel {
    fn send(&self, data: &[u8]) {
        self.stream.send(data);
    }
    fn receive(&self, timeout: Duration) -> Option<Vec<u8>> {
        self.stream.receive(timeout)
    }
    fn is_open(&self) -> bool {
        self.stream.is_open()
    }
    fn close(&self) {
        self.stream.close();
    }
}

/// The way out through an anonymous exit behind its hidden address: every
/// connection is a stream to the exit's port 6, the destination named first.
struct AnonymousExitOpener {
    connection: HiddenConnection,
}

impl InternetOpener for AnonymousExitOpener {
    fn open_to(&self, host: &str, port: u16) -> Option<Arc<dyn MessageChannel>> {
        let channel = self.connection.open(well_known_ports::EXIT)?;
        let request = ExitService::request(host, port)?;
        channel.send(&request);
        match channel.receive(TIMEOUT) {
            Some(answer) if answer.len() == 1 && answer[0] == 0 => Some(channel),
            _ => {
                channel.close();
                None
            }
        }
    }
    fn is_alive(&self) -> bool {
        self.connection.is_alive()
    }
}

// ---- Reaching hidden addresses by fingerprint -------------------------------

/// A meeting with a hidden address found by its fingerprint. `None` if it is
/// not announced or cannot be reached.
pub(super) fn connect_hidden(records: &Records, fingerprint: &[u8]) -> Option<HiddenConnection> {
    let descriptor = records.find_service(fingerprint)?;
    let mut factory = records.factory();
    HiddenConnection::connect(&descriptor.address(), &descriptor, &mut factory, TIMEOUT).ok()
}

/// A holder of a bundle, over its hidden address.
fn connect_holder(records: &Records, fingerprint: &[u8]) -> Option<SwarmPeer> {
    let connection = connect_hidden(records, fingerprint)?;
    let stream = connection.open(well_known_ports::SWARM)?;
    let mut peer = SwarmPeer::new(Box::new(HolderChannel { _connection: connection, stream }));
    peer.set_label(bytes_to_hex(&fingerprint[..fingerprint.len().min(6)]));
    Some(peer)
}

/// A way out through an anonymous exit found through the keepers — for when no
/// relay in the list lets traffic out. `own_exit` is left out: one does not
/// go out through oneself.
pub(super) fn anonymous_way_out(records: &Records, own_exit: Option<&[u8]>) -> Option<Arc<dyn InternetOpener>> {
    if records.others().is_empty() {
        return None;
    }
    let mut exits = records.find_holders(&exit_swarm());
    if let Some(own) = own_exit {
        exits.retain(|fp| !rand::constant_time_equals(fp, own));
    }
    for i in (1..exits.len()).rev() {
        let j = rand::next((i + 1) as u32) as usize;
        exits.swap(i, j);
    }
    for fingerprint in exits {
        if let Some(connection) = connect_hidden(records, &fingerprint) {
            return Some(Arc::new(AnonymousExitOpener { connection }));
        }
    }
    None
}

// ---- The node's torrent part -------------------------------------------------

impl Node {
    fn require_swarm_ready(&self) -> Result<(Arc<SwarmStore>, Records), String> {
        let store = {
            let inner = self.inner.lock().unwrap();
            if inner.relay_node.is_none() {
                return Err("start the node first".into());
            }
            inner.swarm_store.clone().ok_or("start the node first")?
        };
        let records = self.records();
        if records.others().is_empty() {
            return Err("no other relays known yet: the torrent needs the network".into());
        }
        Ok((store, records))
    }

    /// Raises one more hidden address on its own port stack and puts its
    /// announcement with its keepers, kept fresh as introduction points come
    /// and go.
    fn start_side_hidden(&self, stack: Arc<PortStack>) -> Result<SideService, String> {
        let key = Arc::new(NodeIdentity::create("").map_err(|e| e.to_string())?);
        let records = self.records();
        let hidden = Arc::new(HiddenService::new(key.clone(), records.factory()));
        hidden.set_stack(stack.clone());
        let republish = records.clone();
        hidden.on_descriptor_changed(move |descriptor| {
            let _ = republish.publish_service(&descriptor);
        });
        let descriptor = hidden.start(2)?;
        if let Err(e) = records.publish_service(&descriptor) {
            hidden.stop();
            return Err(e);
        }
        Ok(SideService { key, hidden, _stack: stack })
    }

    /// Raises the address bundles are handed out under, if it is not up, and
    /// announces everything the store holds whole.
    /// Returns the seeding address's key: holders sign their word with it.
    fn ensure_seeding(&self, store: &Arc<SwarmStore>) -> Result<Arc<NodeIdentity>, String> {
        if let Some(key) = self.inner.lock().unwrap().swarm.seeding.as_ref().map(|s| s.key.clone()) {
            return Ok(key);
        }
        let stack = PortStack::new();
        let service = Arc::new(SwarmService::new(store.clone()));
        stack.bind(well_known_ports::SWARM, Arc::new(SwarmPort { service: service.clone() }));
        let side = self.start_side_hidden(stack)?;
        let key = side.key.clone();
        {
            let mut inner = self.inner.lock().unwrap();
            inner.swarm.seeding = Some(side);
            inner.swarm.seeding_service = Some(service);
        }
        self.say("handing bundles out under an address of their own");

        let records = self.records();
        for bundle in store.complete() {
            records.announce(bundle.info_hash(), &key);
        }
        Ok(key)
    }

    fn remember(&self, link: &BundleLink, name: &str, kind: BundleKind) {
        let mut inner = self.inner.lock().unwrap();
        let text = link.text();
        inner.swarm.known.retain(|k| k.link.text() != text);
        inner.swarm.known.insert(0, KnownBundle { link: link.clone(), name: name.to_string(), kind });
    }

    /// Fetches a bundle from the swarm unless the store already holds it whole.
    fn fetch(&self, store: &Arc<SwarmStore>, link: &BundleLink) -> Result<Arc<crate::swarm::swarm_store::StoredBundle>, String> {
        let own = self.inner.lock().unwrap().swarm.seeding.as_ref().map(|s| s.fingerprint());
        let find_records = self.records();
        let conn_records = self.records();
        let info_hash = link.info_hash().to_vec();
        let ih = info_hash.clone();
        let mut download = SwarmDownload::new(
            store.clone(),
            info_hash,
            move || find_records.find_holders(&ih),
            move |fp: &[u8]| connect_holder(&conn_records, fp),
        );
        if let Some(own) = own {
            download.exclude = vec![own];
        }
        let log = self.log.lock().unwrap().clone();
        download.on_log(move |line| {
            if let Some(log) = &log {
                log(line);
            }
        });
        download.run(Arc::new(AtomicBool::new(false))).map_err(|e| e.to_string())
    }

    /// After a download: hand it out further. A failure here costs nothing of
    /// what was fetched.
    fn keep_seeding(&self, store: &Arc<SwarmStore>, info_hash: &[u8]) {
        match self.ensure_seeding(store) {
            Ok(key) => self.records().announce(info_hash, &key),
            Err(e) => self.say(format!("could not hand the bundle out further: {e}")),
        }
    }

    // ---- Bundles -----------------------------------------------------------

    /// Shares a file or a folder as an encrypted bundle; returns its link.
    pub fn share(&self, path: &str) -> Result<String, String> {
        let (store, records) = self.require_swarm_ready()?;
        let link = bundle_builder::build(&store, path, BundleKind::Files).map_err(|e| e.to_string())?;
        let name = Path::new(path.trim_end_matches(['/', '\\']))
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_else(|| path.to_string());
        self.remember(&link, &name, BundleKind::Files);
        let key = self.ensure_seeding(&store)?;
        records.announce(link.info_hash(), &key);
        self.say(format!("sharing {name}"));
        Ok(link.text())
    }

    /// Downloads a bundle by its link into `save_folder` and stays in the swarm
    /// with it. Returns the bundle's name.
    pub fn download(&self, link_text: &str, save_folder: &str) -> Result<String, String> {
        if save_folder.trim().is_empty() {
            return Err("choose a folder to save into".into());
        }
        let link = BundleLink::try_parse(link_text).ok_or("not a valid link")?;
        let (store, _) = self.require_swarm_ready()?;
        let stored = self.fetch(&store, &link)?;
        let manifest = bundle_builder::extract(&stored, link.content_key(), save_folder).map_err(|e| e.to_string())?;
        self.remember(&link, &manifest.name, manifest.kind);
        self.say(format!("downloaded {} into {save_folder}", manifest.name));
        self.keep_seeding(&store, link.info_hash());
        Ok(manifest.name)
    }

    /// The torrent table: what was shared and fetched this time.
    pub fn bundles(&self) -> Vec<BundleRow> {
        let (known, store) = {
            let inner = self.inner.lock().unwrap();
            (inner.swarm.known.clone(), inner.swarm_store.clone())
        };
        known
            .iter()
            .map(|item| {
                let bundle = store.as_ref().and_then(|s| s.open(item.link.info_hash()));
                BundleRow {
                    name: item.name.clone(),
                    kind: if item.kind == BundleKind::Site { "site".into() } else { "files".into() },
                    size: bundle.as_ref().map(|b| format_size(b.header().total_length())).unwrap_or_else(|| "-".into()),
                    progress: match &bundle {
                        None => "-".into(),
                        Some(b) if b.is_complete() => "whole".into(),
                        Some(b) => format!("{} / {}", b.have_count(), b.header().piece_count()),
                    },
                    link: item.link.text(),
                }
            })
            .collect()
    }

    // ---- Sites -------------------------------------------------------------

    /// Publishes a folder as our site under the folders' address. Every
    /// publication is a new version; whoever opens the address gets the newest.
    pub fn publish_site(&self, folder: &str) -> Result<String, String> {
        let (store, records) = self.require_swarm_ready()?;
        if !Path::new(folder).is_dir() {
            return Err("choose a folder".into());
        }
        let owner = self.inner.lock().unwrap().folder_key.clone().ok_or("sign in first")?;

        let link = bundle_builder::build(&store, folder, BundleKind::Site).map_err(|e| e.to_string())?;
        let name = Path::new(folder).file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default();
        self.remember(&link, &name, BundleKind::Site);
        let key = self.ensure_seeding(&store)?;
        records.announce(link.info_hash(), &key);

        let version = now_ticks();
        let record = SiteRecord::create(&owner, version, &link).to_bytes();
        let secret = SiteRecord::write_secret(&owner).ok_or("the folders' key cannot make a write secret")?;
        records.publish_site(&secret, &record)?;

        let _ = std::fs::write(store.root().join("site.record"), &record);
        self.inner.lock().unwrap().swarm.site_record = Some(record);
        let address = owner.address().text().to_string();
        self.say(format!("site published at {address}"));
        Ok(address)
    }

    /// Opens somebody's site: finds its record, fetches the current version
    /// from the swarm and shows it on a loopback address. Returns the address
    /// to open in the browser.
    pub fn open_site(&self, address_text: &str) -> Result<String, String> {
        let (store, records) = self.require_swarm_ready()?;
        let address = OnionAddress::try_parse(address_text.trim()).ok_or("not a valid StalkNet address")?;

        let bytes = records
            .fetch_site(&SiteRecord::lookup_for(&address.fingerprint()))
            .ok_or("no site is published at that address")?;
        // The record is checked twice: its owner's key must grow into this
        // address (in the parse) and the sealed part must open with it.
        let link = SiteRecord::try_parse(&bytes)
            .and_then(|r| r.try_open(&address))
            .ok_or("the site's record does not belong to that address")?;

        let stored = self.fetch(&store, &link)?;
        let folder = store.root().join("sites").join(BundleLink::hex(link.info_hash()));
        if !folder.is_dir() {
            // Opened aside and moved into place whole: a version cut short must
            // not be taken for a finished one later.
            let mut part = folder.as_os_str().to_owned();
            part.push(".part");
            let part = PathBuf::from(part);
            let _ = std::fs::remove_dir_all(&part);
            bundle_builder::extract(&stored, link.content_key(), &part).map_err(|e| e.to_string())?;
            std::fs::rename(&part, &folder).map_err(|e| e.to_string())?;
        }
        self.remember(&link, address.text(), BundleKind::Site);

        let key = address.text().to_string();
        let url = {
            let mut inner = self.inner.lock().unwrap();
            let same = inner.swarm.site_views.get(&key).map(|s| s.root() == folder.as_path()).unwrap_or(false);
            if !same {
                let mut server = LocalSiteServer::new(&folder);
                server.start().map_err(|e| e.to_string())?;
                inner.swarm.site_views.insert(key.clone(), server);
            }
            inner.swarm.site_views[&key].url()
        };
        self.say(format!("site {key} is open at {url}"));
        self.keep_seeding(&store, link.info_hash());
        Ok(url)
    }

    // ---- The anonymous way out ---------------------------------------------

    /// Lets guests out to the internet from this machine, behind an address
    /// made for the occasion. The traffic leaves from our own address, so this
    /// is only ever done on the owner's say-so. The rule is a separate one, not
    /// the node's own exit: that would put the exit in every relay list under
    /// our fingerprint. The machine's own networks stay closed all the same.
    pub fn start_anonymous_exit(&self) -> Result<(), String> {
        self.require_swarm_ready()?;
        if self.inner.lock().unwrap().swarm.exit.is_some() {
            return Ok(());
        }
        let mut policy = ExitPolicy::new();
        policy.enabled = true;
        let policy = Arc::new(policy);
        let service = Arc::new(ExitService::new(move |host: &str, port: u16| {
            match policy.try_resolve(host, port) {
                Ok(ip) => Ok(std::net::SocketAddr::new(ip, port)),
                Err(StreamEndReason::ConnectFailed) => Err(ExitRefusal::ConnectFailed),
                Err(_) => Err(ExitRefusal::NotAllowed),
            }
        }));
        let stack = PortStack::new();
        stack.bind(well_known_ports::EXIT, Arc::new(ExitPort { service: service.clone() }));
        let side = self.start_side_hidden(stack)?;
        let key = side.key.clone();
        {
            let mut inner = self.inner.lock().unwrap();
            inner.swarm.exit = Some(side);
            inner.swarm.exit_service = Some(service);
        }
        self.records().announce(&exit_swarm(), &key);
        self.say("letting others out to the internet, behind an address made for it");
        Ok(())
    }

    pub fn stop_anonymous_exit(&self) {
        let side = {
            let mut inner = self.inner.lock().unwrap();
            inner.swarm.exit_service = None;
            inner.swarm.exit.take()
        };
        if let Some(side) = side {
            side.hidden.stop();
            self.say("no longer letting others out");
            // Whoever stopped letting others out loses the way out as well.
            if !self.lets_others_out() && self.inner.lock().unwrap().socks.is_some() {
                self.say("the way out is only for those who let others out: closing it");
                self.close_way_out();
            }
        }
    }

    pub fn is_anonymous_exit(&self) -> bool {
        self.inner.lock().unwrap().swarm.exit.is_some()
    }

    /// The node lets others out: as a relay exit, or as an anonymous one.
    pub(super) fn lets_others_out(&self) -> bool {
        let inner = self.inner.lock().unwrap();
        (inner.relay_node.is_some() && inner.is_relay && inner.exit.enabled) || inner.swarm.exit.is_some()
    }

    pub(super) fn own_exit_fingerprint(&self) -> Option<Vec<u8>> {
        self.inner.lock().unwrap().swarm.exit.as_ref().map(|s| s.fingerprint())
    }

    // ---- Keeping it going --------------------------------------------------

    /// One pass of the reminder: the keepers forget whoever stays silent for an
    /// hour, so holders, the exit and the site are told again.
    pub(super) fn renew_swarm(&self) {
        let (store, seeding, exit, mut site) = {
            let inner = self.inner.lock().unwrap();
            (
                inner.swarm_store.clone(),
                inner.swarm.seeding.as_ref().map(|s| (s.key.clone(), s.hidden.descriptor())),
                inner.swarm.exit.as_ref().map(|s| (s.key.clone(), s.hidden.descriptor())),
                inner.swarm.site_record.clone(),
            )
        };
        let store = match store {
            Some(s) => s,
            None => return,
        };
        let records = self.records();

        // After a restart: whatever the store holds whole is handed out again.
        if seeding.is_none() && !store.complete().is_empty() && !records.others().is_empty() {
            if let Err(e) = self.ensure_seeding(&store) {
                self.say(format!("could not hand bundles out: {e}"));
            }
        } else if let Some((fp, descriptor)) = seeding {
            if let Some(d) = descriptor {
                let _ = records.publish_service(&d);
            }
            for bundle in store.complete() {
                records.announce(bundle.info_hash(), &fp);
            }
        }

        if let Some((fp, descriptor)) = exit {
            if let Some(d) = descriptor {
                let _ = records.publish_service(&d);
            }
            records.announce(&exit_swarm(), &fp);
        }

        if site.is_none() {
            site = std::fs::read(store.root().join("site.record")).ok();
            if site.is_some() {
                self.inner.lock().unwrap().swarm.site_record = site.clone();
            }
        }
        let owner = self.inner.lock().unwrap().folder_key.clone();
        if let (Some(record), Some(owner)) = (site, owner) {
            if let Some(secret) = SiteRecord::write_secret(&owner) {
                if let Err(e) = records.publish_site(&secret, &record) {
                    self.say(format!("could not renew the site: {e}"));
                }
            }
        }
    }

    /// Takes the torrent part down with the node.
    pub(super) fn stop_swarm(&self) {
        self.stop_anonymous_exit();
        let state = std::mem::take(&mut self.inner.lock().unwrap().swarm);
        if let Some(side) = state.seeding {
            side.hidden.stop();
        }
        for server in state.site_views.values() {
            server.stop();
        }
        // The list of bundles and the site record outlive a stop.
        let mut inner = self.inner.lock().unwrap();
        inner.swarm.known = state.known;
        inner.swarm.site_record = state.site_record;
    }
}

/// Ticks (100 ns since 0001-01-01), as the C# DateTime.UtcNow.Ticks.
fn now_ticks() -> i64 {
    const UNIX_EPOCH_TICKS: i64 = 621_355_968_000_000_000;
    let since = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default();
    UNIX_EPOCH_TICKS + since.as_nanos() as i64 / 100
}

fn format_size(bytes: i64) -> String {
    let b = bytes as f64;
    if bytes < 1024 {
        format!("{bytes} B")
    } else if bytes < 1024 * 1024 {
        format!("{:.1} KiB", b / 1024.0)
    } else if bytes < 1024 * 1024 * 1024 {
        format!("{:.1} MiB", b / (1024.0 * 1024.0))
    } else {
        format!("{:.2} GiB", b / (1024.0 * 1024.0 * 1024.0))
    }
}
