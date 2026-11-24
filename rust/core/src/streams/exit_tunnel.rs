//! The way out to the internet that is always there.
//!
//! It holds one tunnel — a circuit of three relays whose last one lets traffic
//! out — and hands every new connection to it. When the tunnel breaks — a relay
//! on it went away, the exit stopped answering — the next connection simply gets
//! a new one, through other relays. Nobody has to press anything again.
//!
//! New connections move to a fresh tunnel every ten minutes, as in Tor: through
//! one tunnel for good, the exit would see every site a person opens and could
//! tie them all together. The old tunnel is not cut — a long download goes on
//! through it — it is kept aside until it dies or an hour is up.
//!
//! The tunnel itself is built by whoever made this one: the node knows the
//! relays and the rules of choosing them; here it is only kept alive. So the
//! builder is handed in as a closure and nothing of discovery or path selection
//! is wired in — which is what lets the tunnel be tested in isolation.

use crate::streams::message_channel::MessageChannel;
use crate::streams::stream_opener::InternetOpener;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// Builds a fresh tunnel on demand. `None` when one could not be laid.
pub type TunnelBuilder = Box<dyn Fn() -> Option<Arc<dyn InternetOpener>> + Send + Sync>;

/// A line for the log: why a tunnel could not be built.
pub type LogSink = Box<dyn Fn(&str) + Send + Sync>;

/// How long new connections go through one tunnel.
pub const ROTATE_AFTER: Duration = Duration::from_secs(10 * 60);
/// How long a tunnel set aside is kept for the connections still on it.
const RETIRED_FOR: Duration = Duration::from_secs(60 * 60);
const MAX_RETIRED: usize = 8;

type Dated = (Arc<dyn InternetOpener>, Instant);

pub struct ExitTunnel {
    build: TunnelBuilder,
    current: Mutex<Option<Dated>>,
    /// Old tunnels kept so connections on them are not cut.
    retired: Mutex<Vec<Dated>>,
    rotate_after: Duration,
    disposed: AtomicBool,
    logged: Mutex<Option<LogSink>>,
}

impl ExitTunnel {
    pub fn new(build: TunnelBuilder) -> ExitTunnel {
        ExitTunnel::with_rotation(build, ROTATE_AFTER)
    }

    pub fn with_rotation(build: TunnelBuilder, rotate_after: Duration) -> ExitTunnel {
        ExitTunnel {
            build,
            current: Mutex::new(None),
            retired: Mutex::new(Vec::new()),
            rotate_after,
            disposed: AtomicBool::new(false),
            logged: Mutex::new(None),
        }
    }

    /// Where lines about failed builds go.
    pub fn set_logged(&self, sink: LogSink) {
        *self.logged.lock().unwrap() = Some(sink);
    }

    /// The tunnel to use: the current one, or a new one if it died or its ten
    /// minutes are up.
    fn tunnel(&self) -> Option<Arc<dyn InternetOpener>> {
        let mut current = self.current.lock().unwrap();
        if let Some((t, since)) = current.as_ref() {
            if t.is_alive() && since.elapsed() < self.rotate_after {
                return Some(t.clone());
            }
        }

        // Its time is up but it lives: set aside, not cut. A dead one is let go.
        if let Some((t, since)) = current.take() {
            if t.is_alive() {
                let mut retired = self.retired.lock().unwrap();
                retired.push((t, since));
            }
        }
        {
            let mut retired = self.retired.lock().unwrap();
            retired.retain(|(t, since)| t.is_alive() && since.elapsed() < RETIRED_FOR);
            while retired.len() > MAX_RETIRED {
                retired.remove(0);
            }
        }

        match (self.build)() {
            Some(t) => {
                *current = Some((t.clone(), Instant::now()));
                Some(t)
            }
            None => {
                self.say("a new exit tunnel could not be built");
                None
            }
        }
    }

    fn say(&self, message: &str) {
        if let Some(sink) = self.logged.lock().unwrap().as_ref() {
            sink(message);
        }
    }

    fn dispose(&self) {
        self.disposed.store(true, Ordering::Release);
        *self.current.lock().unwrap() = None;
        self.retired.lock().unwrap().clear();
    }
}

impl InternetOpener for ExitTunnel {
    /// The way out stays open as long as it is not closed — the tunnel under it
    /// is renewed by itself.
    fn is_alive(&self) -> bool {
        !self.disposed.load(Ordering::Acquire)
    }

    fn open_to(&self, host: &str, port: u16) -> Option<Arc<dyn MessageChannel>> {
        // Twice at most: the tunnel may have died a moment ago, and that is no
        // reason to refuse the connection — but a destination the exit refuses is
        // refused by the next one just the same.
        for _ in 0..2 {
            if self.disposed.load(Ordering::Acquire) {
                return None;
            }

            let tunnel = self.tunnel()?;

            if let Some(stream) = tunnel.open_to(host, port) {
                return Some(stream);
            }

            // Still alive — the exit itself said no to this destination.
            if tunnel.is_alive() {
                return None;
            }
        }
        None
    }
}

impl Drop for ExitTunnel {
    fn drop(&mut self) {
        self.dispose();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::AtomicUsize;
    use std::time::Duration;

    /// A tunnel that answers a fixed number of times, then dies. When
    /// `stay_alive` is set it refuses instead (returns `None`) without dying —
    /// the "the exit itself said no" case.
    struct FakeTunnel {
        alive: AtomicBool,
        answers: AtomicUsize,
        stay_alive: bool,
    }

    impl InternetOpener for FakeTunnel {
        fn open_to(&self, _host: &str, _port: u16) -> Option<Arc<dyn MessageChannel>> {
            if self.answers.load(Ordering::SeqCst) == 0 {
                if !self.stay_alive {
                    self.alive.store(false, Ordering::SeqCst);
                }
                return None;
            }
            self.answers.fetch_sub(1, Ordering::SeqCst);
            Some(Arc::new(FakeChannel))
        }
        fn is_alive(&self) -> bool {
            self.alive.load(Ordering::SeqCst)
        }
    }

    struct FakeChannel;
    impl MessageChannel for FakeChannel {
        fn send(&self, _message: &[u8]) {}
        fn receive(&self, _timeout: Duration) -> Option<Vec<u8>> {
            None
        }
        fn is_open(&self) -> bool {
            true
        }
        fn close(&self) {}
    }

    #[test]
    fn rebuilds_after_a_tunnel_dies() {
        let builds = Arc::new(AtomicUsize::new(0));
        let b = builds.clone();
        let tunnel = ExitTunnel::new(Box::new(move || {
            b.fetch_add(1, Ordering::SeqCst);
            Some(Arc::new(FakeTunnel {
                alive: AtomicBool::new(true),
                answers: AtomicUsize::new(1), // one good answer, then dies
                stay_alive: false,
            }) as Arc<dyn InternetOpener>)
        }));

        // First two connections ride the first tunnel (answers = 1 -> two opens:
        // the first succeeds, the second kills it). The retry builds a second.
        assert!(tunnel.open_to("example.com", 80).is_some());
        assert!(tunnel.open_to("example.com", 80).is_some());
        assert!(builds.load(Ordering::SeqCst) >= 2);
    }

    #[test]
    fn refused_destination_is_not_retried_on_a_live_tunnel() {
        let builds = Arc::new(AtomicUsize::new(0));
        let b = builds.clone();
        let tunnel = ExitTunnel::new(Box::new(move || {
            b.fetch_add(1, Ordering::SeqCst);
            // Alive but refuses every destination (answers exhausted immediately,
            // yet stays alive).
            Some(Arc::new(FakeTunnel {
                alive: AtomicBool::new(true),
                answers: AtomicUsize::new(0),
                stay_alive: true,
            }) as Arc<dyn InternetOpener>)
        }));

        // The tunnel stays alive but says no: we must not build a second one.
        assert!(tunnel.open_to("blocked", 25).is_none());
        assert_eq!(builds.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn new_connections_move_to_a_fresh_tunnel_and_the_old_one_lives_on() {
        let built: Arc<Mutex<Vec<Arc<FakeTunnel>>>> = Arc::new(Mutex::new(Vec::new()));
        let b = built.clone();
        let tunnel = ExitTunnel::with_rotation(
            Box::new(move || {
                let t = Arc::new(FakeTunnel {
                    alive: AtomicBool::new(true),
                    answers: AtomicUsize::new(100),
                    stay_alive: true,
                });
                b.lock().unwrap().push(t.clone());
                Some(t as Arc<dyn InternetOpener>)
            }),
            Duration::from_millis(50),
        );

        assert!(tunnel.open_to("a.example", 443).is_some());
        std::thread::sleep(Duration::from_millis(80));
        assert!(tunnel.open_to("b.example", 443).is_some());

        let built = built.lock().unwrap();
        assert_eq!(built.len(), 2, "the second site went through a fresh tunnel");
        // The first one was set aside, not cut.
        assert!(built[0].is_alive());
        assert_eq!(tunnel.retired.lock().unwrap().len(), 1);
    }
}
