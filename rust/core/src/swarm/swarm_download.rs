//! Downloads a bundle from every holder at once.
//!
//! Each worker takes a holder of its own and asks it for pieces nobody else is
//! fetching. A piece is checked against its hash before it is taken; a holder
//! that sent a wrong one is dropped at once — not counted against, dropped: an
//! honest holder never sends a wrong piece.
//!
//! The holders are reached however the caller likes — through a meeting with a
//! hidden address or along a plain circuit. The download does not know which,
//! and that is the point. The two injected closures carry that freedom:
//!
//! * `find_holders` — who holds the bundle: the fingerprints of their hidden
//!   addresses. (In the C# node this queries the peer-storage records, which are
//!   ported separately; here it is a closure so this module does not depend on
//!   them.)
//! * `connect` — a stream to a holder's torrent port, wrapped as a [`SwarmPeer`].
//!   `None` means no luck with this holder.

use crate::crypto::rand;
use crate::swarm::swarm_service::SwarmPeer;
use crate::swarm::swarm_store::{StoredBundle, SwarmStore};
use crate::swarm::{Result, SwarmError};
use std::collections::{HashSet, VecDeque};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

type FindHolders = dyn Fn() -> Vec<Vec<u8>> + Send + Sync;
type Connect = dyn Fn(&[u8]) -> Option<SwarmPeer> + Send + Sync;
type LogFn = dyn Fn(String) + Send + Sync;
type ProgressFn = dyn Fn(i32, i32) + Send + Sync;

pub struct SwarmDownload {
    store: Arc<SwarmStore>,
    info_hash: Vec<u8>,
    find_holders: Arc<FindHolders>,
    connect: Arc<Connect>,

    /// How many holders are worked with at once.
    pub workers: usize,
    /// How many times the holders are looked up afresh if the first lot ran dry.
    pub rounds: usize,
    /// Fingerprints never to connect to — our own, first of all.
    pub exclude: Vec<Vec<u8>>,

    on_log: Option<Arc<LogFn>>,
    on_progress: Option<Arc<ProgressFn>>,
}

impl SwarmDownload {
    pub fn new<F, C>(store: Arc<SwarmStore>, info_hash: Vec<u8>, find_holders: F, connect: C) -> SwarmDownload
    where
        F: Fn() -> Vec<Vec<u8>> + Send + Sync + 'static,
        C: Fn(&[u8]) -> Option<SwarmPeer> + Send + Sync + 'static,
    {
        SwarmDownload {
            store,
            info_hash,
            find_holders: Arc::new(find_holders),
            connect: Arc::new(connect),
            workers: 3,
            rounds: 3,
            exclude: Vec::new(),
            on_log: None,
            on_progress: None,
        }
    }

    /// A callback for progress messages.
    pub fn on_log<F: Fn(String) + Send + Sync + 'static>(&mut self, handler: F) {
        self.on_log = Some(Arc::new(handler));
    }

    /// A callback with `(have, total)` pieces — for the window.
    pub fn on_progress<F: Fn(i32, i32) + Send + Sync + 'static>(&mut self, handler: F) {
        self.on_progress = Some(Arc::new(handler));
    }

    /// Runs until the bundle is whole. Fails if the holders ran out first, or if
    /// `cancel` was raised.
    pub fn run(&self, cancel: Arc<AtomicBool>) -> Result<Arc<StoredBundle>> {
        let start = self.store.open(&self.info_hash);
        if let Some(bundle) = &start {
            if bundle.is_complete() {
                return Ok(bundle.clone());
            }
        }

        let inner = Arc::new(Inner {
            store: self.store.clone(),
            info_hash: self.info_hash.clone(),
            connect: self.connect.clone(),
            on_log: self.on_log.clone(),
            on_progress: self.on_progress.clone(),
            cancel,
            state: Mutex::new(State {
                untried: VecDeque::new(),
                in_flight: HashSet::new(),
                bundle: start,
                header_busy: false,
            }),
        });

        for round in 0..self.rounds {
            if inner.cancel.load(Ordering::Relaxed) {
                return Err(SwarmError::Invalid("the download was cancelled".into()));
            }

            let holders = (self.find_holders)();
            {
                let mut state = inner.state.lock().unwrap();
                state.untried.clear();
                for holder in shuffle(holders) {
                    if !self.is_excluded(&holder) {
                        state.untried.push_back(holder);
                    }
                }
            }

            let untried_len = inner.state.lock().unwrap().untried.len();
            if untried_len == 0 {
                inner.say("swarm.noholders", &[]);
                if round + 1 < self.rounds {
                    thread::sleep(Duration::from_secs(5));
                }
                continue;
            }

            let count = self.workers.min(untried_len);
            let mut handles = Vec::with_capacity(count);
            for _ in 0..count {
                let worker = inner.clone();
                handles.push(thread::Builder::new().name("stalknet-swarm".into()).spawn(move || worker.work()).unwrap());
            }
            for handle in handles {
                let _ = handle.join();
            }

            if let Some(bundle) = &inner.state.lock().unwrap().bundle {
                if bundle.is_complete() {
                    return Ok(bundle.clone());
                }
            }
        }

        if inner.cancel.load(Ordering::Relaxed) {
            return Err(SwarmError::Invalid("the download was cancelled".into()));
        }

        let (have, total) = {
            let state = inner.state.lock().unwrap();
            match &state.bundle {
                Some(b) => (b.have_count(), b.header().piece_count()),
                None => (0, 0),
            }
        };
        Err(SwarmError::Invalid(crate::text::t_args(
            "swarm.failed",
            &[&have.to_string(), &total.to_string()],
        )))
    }

    fn is_excluded(&self, holder: &[u8]) -> bool {
        self.exclude.iter().any(|f| rand::constant_time_equals(f, holder))
    }
}

struct State {
    untried: VecDeque<Vec<u8>>,
    in_flight: HashSet<i32>,
    bundle: Option<Arc<StoredBundle>>,
    header_busy: bool,
}

struct Inner {
    store: Arc<SwarmStore>,
    info_hash: Vec<u8>,
    connect: Arc<Connect>,
    on_log: Option<Arc<LogFn>>,
    on_progress: Option<Arc<ProgressFn>>,
    cancel: Arc<AtomicBool>,
    state: Mutex<State>,
}

impl Inner {
    fn work(self: Arc<Self>) {
        while !self.cancel.load(Ordering::Relaxed) {
            if self.bundle_complete() {
                return;
            }

            let holder = {
                let mut state = self.state.lock().unwrap();
                match state.untried.pop_front() {
                    Some(h) => h,
                    None => return,
                }
            };

            let mut peer = match (self.connect)(&holder) {
                Some(p) => p,
                None => continue,
            };

            if !peer.open(&self.info_hash) {
                continue;
            }
            if !self.ensure_header(&mut peer) {
                continue;
            }
            self.drain(&peer);
        }
    }

    /// The header comes from whoever gets to it first; the rest wait for it.
    fn ensure_header(&self, peer: &mut SwarmPeer) -> bool {
        loop {
            if self.cancel.load(Ordering::Relaxed) {
                return false;
            }
            {
                let mut state = self.state.lock().unwrap();
                if state.bundle.is_some() {
                    return true;
                }
                if !state.header_busy {
                    state.header_busy = true;
                    break;
                }
            }
            thread::sleep(Duration::from_millis(200));
        }

        let header = peer.fetch_header();
        let bundle = header.and_then(|h| self.store.add_header(&self.info_hash, &h));

        match bundle {
            // A header that does not hash to the link is a lie: this holder is
            // dropped, and the next one tries.
            None => {
                self.say("swarm.header.bad", &[peer.label()]);
                self.state.lock().unwrap().header_busy = false;
                false
            }
            Some(bundle) => {
                {
                    let mut state = self.state.lock().unwrap();
                    state.bundle = Some(bundle);
                    state.header_busy = false;
                }
                self.report();
                true
            }
        }
    }

    /// Asks one holder for everything it has that is still missing.
    fn drain(&self, peer: &SwarmPeer) {
        let bundle = match self.state.lock().unwrap().bundle.clone() {
            Some(b) => b,
            None => return,
        };

        let has = match peer.fetch_bitfield() {
            Some(h) => h,
            None => return,
        };
        // The holder sized its bitfield by its own word; one shorter than the
        // bundle would be read past its end.
        let needed = (bundle.header().piece_count().max(0) as usize).div_ceil(8);
        if has.len() < needed {
            self.say("swarm.piece.bad", &[peer.label()]);
            return;
        }

        while !self.cancel.load(Ordering::Relaxed) && !bundle.is_complete() && peer.is_open() {
            let index = self.claim(&bundle, &has);
            if index < 0 {
                return;
            }

            let piece = peer.fetch_piece(index, bundle.header().piece_length(index));
            let proceed = match piece {
                None => false,
                Some(piece) => {
                    if !bundle.write_piece(index, &piece) {
                        self.say("swarm.piece.bad", &[peer.label()]);
                        false
                    } else {
                        self.report();
                        true
                    }
                }
            };

            self.state.lock().unwrap().in_flight.remove(&index);
            if !proceed {
                return;
            }
        }
    }

    /// A piece that is missing, that this holder has and that nobody is fetching.
    /// `-1` if none.
    fn claim(&self, bundle: &Arc<StoredBundle>, has: &[u8]) -> i32 {
        let count = bundle.header().piece_count();
        if count <= 0 {
            return -1;
        }
        let start = rand::next(count.max(1) as u32) as i64;

        let mut state = self.state.lock().unwrap();
        // From a random place, so that two downloaders of one bundle fetch
        // different pieces and can soon hand each other the rest.
        for step in 0..count as i64 {
            let i = ((start + step) % count as i64) as i32;
            if bundle.has(i) || state.in_flight.contains(&i) {
                continue;
            }
            let u = i as usize;
            if has[u >> 3] & (0x80u8 >> (u & 7)) == 0 {
                continue;
            }
            state.in_flight.insert(i);
            return i;
        }

        -1
    }

    fn bundle_complete(&self) -> bool {
        self.state
            .lock()
            .unwrap()
            .bundle
            .as_ref()
            .map(|b| b.is_complete())
            .unwrap_or(false)
    }

    fn report(&self) {
        if let Some(handler) = &self.on_progress {
            if let Some(bundle) = &self.state.lock().unwrap().bundle {
                handler(bundle.have_count(), bundle.header().piece_count());
            }
        }
    }

    fn say(&self, key: &str, args: &[&str]) {
        if let Some(handler) = &self.on_log {
            handler(crate::text::t_args(key, args));
        }
    }
}

fn shuffle(items: Vec<Vec<u8>>) -> Vec<Vec<u8>> {
    let mut copy = items;
    for i in (1..copy.len()).rev() {
        let j = rand::next(i as u32 + 1) as usize;
        copy.swap(i, j);
    }
    copy
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::aead_aes_ctr_hmac as aead;
    use crate::swarm::bundle_header::BundleHeader;
    use crate::swarm::swarm_service::{MessageChannel, ReplyStream, SwarmService, SwarmSession};
    use sha2::{Digest, Sha256};
    use std::collections::VecDeque as Fifo;
    use std::path::PathBuf;

    struct Recorder {
        sent: Mutex<Vec<Vec<u8>>>,
    }
    impl ReplyStream for Recorder {
        fn send(&self, data: &[u8]) {
            self.sent.lock().unwrap().push(data.to_vec());
        }
        fn is_open(&self) -> bool {
            true
        }
    }

    struct Loopback {
        service: Arc<SwarmService>,
        session: Mutex<SwarmSession>,
        inbox: Mutex<Fifo<Vec<u8>>>,
    }
    impl MessageChannel for Loopback {
        fn send(&self, data: &[u8]) {
            let recorder = Recorder { sent: Mutex::new(Vec::new()) };
            {
                let mut session = self.session.lock().unwrap();
                self.service.on_data(&mut session, data, &recorder);
            }
            let mut inbox = self.inbox.lock().unwrap();
            for m in recorder.sent.into_inner().unwrap() {
                inbox.push_back(m);
            }
        }
        fn receive(&self, _t: Duration) -> Option<Vec<u8>> {
            self.inbox.lock().unwrap().pop_front()
        }
        fn is_open(&self) -> bool {
            true
        }
        fn close(&self) {}
    }

    fn temp_dir(name: &str) -> PathBuf {
        let mut p = std::env::temp_dir();
        p.push(format!("stalknet_dl_{}_{}", std::process::id(), name));
        let _ = std::fs::remove_dir_all(&p);
        p
    }

    #[test]
    fn downloads_a_multi_piece_bundle_from_one_seeder() {
        // Seeder store, fully holding a three-piece bundle.
        let seeder_root = temp_dir("seeder");
        let seeder = Arc::new(SwarmStore::new(&seeder_root).unwrap());

        let piece_size = BundleHeader::MIN_PIECE_SIZE;
        let pieces: Vec<Vec<u8>> = (0..3u8).map(|k| vec![k.wrapping_add(1); piece_size as usize]).collect();
        let total = (piece_size as i64) * 3;
        let hashes: Vec<[u8; 32]> = pieces
            .iter()
            .map(|p| {
                let mut h = [0u8; 32];
                h.copy_from_slice(&Sha256::digest(p));
                h
            })
            .collect();
        let sealed = vec![0u8; aead::OVERHEAD];
        let header = BundleHeader::create(piece_size, total, &sealed, &hashes).unwrap();
        let info_hash = header.info_hash().to_vec();

        let bundle = seeder.add_header(&info_hash, header.bytes()).unwrap();
        for (i, p) in pieces.iter().enumerate() {
            assert!(bundle.write_piece(i as i32, p));
        }

        let service = Arc::new(SwarmService::new(seeder.clone()));

        // Downloader store, empty.
        let dl_root = temp_dir("downloader");
        let store = Arc::new(SwarmStore::new(&dl_root).unwrap());

        let service_for_connect = service.clone();
        let download = SwarmDownload::new(
            store.clone(),
            info_hash.clone(),
            || vec![vec![1u8; 20]], // one holder
            move |_holder| {
                let channel = Box::new(Loopback {
                    service: service_for_connect.clone(),
                    session: Mutex::new(service_for_connect.on_open()),
                    inbox: Mutex::new(Fifo::new()),
                });
                Some(SwarmPeer::new(channel))
            },
        );

        let result = download.run(Arc::new(AtomicBool::new(false))).unwrap();
        assert!(result.is_complete());
        assert_eq!(result.have_count(), 3);

        let _ = std::fs::remove_dir_all(&seeder_root);
        let _ = std::fs::remove_dir_all(&dl_root);
    }

    #[test]
    fn no_holders_fails() {
        let dl_root = temp_dir("noholders");
        let store = Arc::new(SwarmStore::new(&dl_root).unwrap());
        let mut download = SwarmDownload::new(store, vec![9u8; 32], Vec::new, |_| None);
        download.rounds = 1;
        assert!(download.run(Arc::new(AtomicBool::new(false))).is_err());
        let _ = std::fs::remove_dir_all(&dl_root);
    }
}
