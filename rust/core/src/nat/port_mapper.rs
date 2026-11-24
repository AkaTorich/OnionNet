//! Automatic port forwarding in the router - what a torrent client does on
//! start, so that people can connect to you from outside.
//!
//! Both methods are tried in turn: NAT-PMP first (it is simpler and answers
//! fast), then UPnP. There is no guessing in advance which one the router at
//! hand understands, and routers usually support just one.
//!
//! The lease renews itself. A router forgets a forward when the lease runs out
//! or after a reboot, and without renewal the node would one day quietly vanish
//! from the network while still believing itself reachable. The renewal runs on
//! a background thread, mirroring the C# `System.Threading.Timer`.
//!
//! On stop the forward is removed. Leaving open ports behind on someone else's
//! router is impolite, and on your own it is simply dangerous - so [`Drop`]
//! removes it, as the C# `Dispose` does.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::thread::{self, JoinHandle};
use std::time::Duration;

use super::nat_pmp_mapper::NatPmpMapper;
use super::port_mapping::{MappingMethod, PortMapping};
use super::upnp_mapper::UpnpMapper;
use super::{ChangedFn, LogFn, NatError};

/// Drives NAT-PMP and UPnP, keeps the lease alive, and cleans up on drop.
pub struct PortMapper {
    inner: Arc<Mutex<Inner>>,
    renewal: Option<Renewal>,
    disposed: Arc<AtomicBool>,
}

struct Renewal {
    stop: Arc<(Mutex<bool>, Condvar)>,
    handle: Option<JoinHandle<()>>,
}

/// Everything the renewal thread and the owner share, under one lock.
struct Inner {
    nat_pmp: Option<NatPmpMapper>,
    upnp: Option<UpnpMapper>,
    port: u16,
    lease: Duration,
    current: Option<PortMapping>,
    renewals: u32,
    logger: Option<LogFn>,
    changed: Option<ChangedFn>,
}

impl Default for PortMapper {
    fn default() -> Self {
        Self::new()
    }
}

impl PortMapper {
    pub fn new() -> Self {
        PortMapper {
            inner: Arc::new(Mutex::new(Inner {
                nat_pmp: None,
                upnp: None,
                port: 0,
                lease: Duration::from_secs(60 * 60), // one hour
                current: None,
                renewals: 0,
                logger: None,
                changed: None,
            })),
            renewal: None,
            disposed: Arc::new(AtomicBool::new(false)),
        }
    }

    /// The lease term at the router. Renewal happens twice as often.
    pub fn lease(&self) -> Duration {
        self.inner.lock().unwrap().lease
    }

    pub fn set_lease(&mut self, lease: Duration) {
        self.inner.lock().unwrap().lease = lease;
    }

    /// What came of it. `None` if the forwarding failed.
    pub fn current(&self) -> Option<PortMapping> {
        self.inner.lock().unwrap().current.clone()
    }

    /// How many times the lease was renewed.
    pub fn renewals(&self) -> u32 {
        self.inner.lock().unwrap().renewals
    }

    pub fn is_mapped(&self) -> bool {
        self.inner.lock().unwrap().current.is_some()
    }

    /// The log sink (C# `event Action<string> Logged`). Set it before
    /// [`map`](Self::map); the sub-mappers capture it when they are first built.
    pub fn set_logger(&mut self, logger: LogFn) {
        self.inner.lock().unwrap().logger = Some(logger);
    }

    /// A renewal brought another outside address or port - after a router
    /// reboot, or a new address from the provider. Whoever printed the old ones
    /// on a card has to print it afresh.
    pub fn set_changed(&mut self, changed: ChangedFn) {
        self.inner.lock().unwrap().changed = Some(changed);
    }

    /// Forwards the port. Returns `Ok(None)` if neither method worked - that is
    /// not a breakage but an ordinary outcome: in many routers both UPnP and
    /// NAT-PMP are off, and we have no right to switch them on for the owner.
    pub fn map(&mut self, port: u16) -> Result<Option<PortMapping>, NatError> {
        if port == 0 {
            return Err(NatError::InvalidPort(port as i32));
        }

        let mapping = {
            let mut inner = self.inner.lock().unwrap();
            inner.port = port;
            inner.say(&format!("Forwarding port {port}..."));

            let mut mapping = inner.try_nat_pmp(port);
            if mapping.is_none() {
                mapping = inner.try_upnp(port);
            }

            match mapping {
                None => {
                    // A router that answered and refused is not one that stayed
                    // silent: the advice for the two is different.
                    let refused = inner.upnp.as_ref().map(|u| u.is_ready()).unwrap_or(false);
                    if refused {
                        inner.say("The router rejected the port mapping (see above).");
                    } else {
                        inner.say(
                            "Neither NAT-PMP nor UPnP responded. Forward the port manually \
                             or enable UPnP on the router.",
                        );
                    }
                    None
                }
                Some(mapping) => {
                    inner.current = Some(mapping.clone());
                    inner.say(&mapping.describe());

                    if !mapping.is_reachable_from_internet() && mapping.external_address().is_some()
                    {
                        inner.say(
                            "The port was forwarded, but the router's external address is private \
                             (double NAT). Ask your ISP for a public IP address.",
                        );
                    }
                    Some(mapping)
                }
            }
        };

        if mapping.is_some() {
            self.start_renewal();
        }

        Ok(mapping)
    }

    /// Removes the forward and stops renewing it.
    pub fn unmap(&mut self) {
        self.stop_renewal();
        let mut inner = self.inner.lock().unwrap();
        inner.unmap_locked();
    }

    // ---- Renewal -------------------------------------------------------------

    fn start_renewal(&mut self) {
        self.stop_renewal();

        let lifetime = {
            let inner = self.inner.lock().unwrap();
            inner
                .current
                .as_ref()
                .map(|c| c.lifetime())
                .unwrap_or(Duration::ZERO)
        };
        if lifetime <= Duration::ZERO {
            return; // an everlasting forward needs no renewal
        }

        // We renew twice as often as the term: one missed attempt then does not
        // leave the node without a forward, it only costs a second attempt.
        let interval = Duration::from_secs(std::cmp::max(30, lifetime.as_secs() / 2));

        {
            let inner = self.inner.lock().unwrap();
            inner.say(&format!(
                "The lease will be renewed every {} min.",
                interval.as_secs() / 60
            ));
        }

        let shared = Arc::clone(&self.inner);
        let stop = Arc::new((Mutex::new(false), Condvar::new()));
        let stop_thread = Arc::clone(&stop);

        let handle = thread::spawn(move || loop {
            let (lock, cvar) = &*stop_thread;
            let guard = lock.lock().unwrap();
            let (guard, timeout) = cvar.wait_timeout(guard, interval).unwrap();
            if *guard {
                break;
            }
            let timed_out = timeout.timed_out();
            drop(guard);

            if timed_out {
                let mut inner = shared.lock().unwrap();
                inner.renew_locked();
            }
        });

        self.renewal = Some(Renewal {
            stop,
            handle: Some(handle),
        });
    }

    fn stop_renewal(&mut self) {
        if let Some(mut renewal) = self.renewal.take() {
            {
                let (lock, cvar) = &*renewal.stop;
                *lock.lock().unwrap() = true;
                cvar.notify_all();
            }
            if let Some(handle) = renewal.handle.take() {
                let _ = handle.join();
            }
        }
    }
}

impl Inner {
    fn try_nat_pmp(&mut self, port: u16) -> Option<PortMapping> {
        if self.nat_pmp.is_none() {
            let mut mapper = NatPmpMapper::new();
            if let Some(logger) = self.logger.clone() {
                mapper.set_logger(logger);
            }
            self.nat_pmp = Some(mapper);
        }

        let lease = self.lease;
        self.nat_pmp.as_mut().unwrap().map(port, lease)
    }

    fn try_upnp(&mut self, port: u16) -> Option<PortMapping> {
        if self.upnp.is_none() {
            let mut mapper = UpnpMapper::new();
            if let Some(logger) = self.logger.clone() {
                mapper.set_logger(logger);
            }
            self.upnp = Some(mapper);
        }

        let lease = self.lease;
        self.upnp.as_mut().unwrap().map(port, lease)
    }

    fn unmap_locked(&mut self) {
        if self.current.is_none() {
            return;
        }

        let (method, external_port) = {
            let current = self.current.as_ref().unwrap();
            (current.method(), current.external_port())
        };
        let port = self.port;

        // NAT-PMP takes a forward down by our port, UPnP by the outside one.
        let removed = match method {
            MappingMethod::NatPmp => self.nat_pmp.as_mut().map(|m| m.unmap(port)).unwrap_or(false),
            _ => self
                .upnp
                .as_mut()
                .map(|m| m.unmap(external_port))
                .unwrap_or(false),
        };

        if removed {
            self.say(&format!("Port mapping {external_port} removed."));
        } else {
            self.say("Could not remove the port mapping - it will expire with the lease.");
        }

        self.current = None;
    }

    fn renew_locked(&mut self) {
        if self.current.is_none() {
            return;
        }

        let port = self.port;
        let (method, old_address, old_port) = {
            let current = self.current.as_ref().unwrap();
            (current.method(), current.external_address(), current.external_port())
        };

        let mut renewed = match method {
            MappingMethod::NatPmp => self.try_nat_pmp(port),
            _ => self.try_upnp(port),
        };

        if renewed.is_none() {
            self.say("Lease renewal failed - the router may have restarted. Retrying.");

            renewed = self.try_nat_pmp(port);
            if renewed.is_none() {
                renewed = self.try_upnp(port);
            }
            if renewed.is_none() {
                return;
            }
        }

        let renewed = renewed.unwrap();

        // The external address may have changed - with home connections that is
        // ordinary - and after a reboot the router may hand out another outside
        // port.
        let address_changed = old_address.is_some()
            && renewed.external_address().is_some()
            && old_address != renewed.external_address();
        let port_changed = old_port != renewed.external_port();

        if address_changed {
            self.say(&format!(
                "Public address changed: {} -> {}. The descriptor will be updated.",
                old_address.unwrap(),
                renewed.external_address().unwrap()
            ));
        }

        self.current = Some(renewed.clone());
        self.renewals += 1;

        if address_changed || port_changed {
            if let Some(handler) = self.changed.clone() {
                handler(&renewed);
            }
        }
    }

    fn say(&self, message: &str) {
        if let Some(logger) = &self.logger {
            logger(message);
        }
    }
}

impl Drop for PortMapper {
    fn drop(&mut self) {
        if self.disposed.swap(true, Ordering::SeqCst) {
            return;
        }
        self.unmap();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn renewal_interval_is_half_the_lease_but_never_below_30s() {
        // The C# rule: max(30, lifetime/2) seconds.
        let interval = |lifetime_secs: u64| {
            Duration::from_secs(std::cmp::max(30, lifetime_secs / 2))
        };
        assert_eq!(interval(3600), Duration::from_secs(1800));
        assert_eq!(interval(40), Duration::from_secs(30)); // 20 -> floored to 30
        assert_eq!(interval(120), Duration::from_secs(60));
    }

    #[test]
    fn a_fresh_mapper_has_a_one_hour_lease_and_no_mapping() {
        let mapper = PortMapper::new();
        assert_eq!(mapper.lease(), Duration::from_secs(3600));
        assert!(!mapper.is_mapped());
        assert!(mapper.current().is_none());
        assert_eq!(mapper.renewals(), 0);
    }

    #[test]
    fn zero_port_is_rejected() {
        let mut mapper = PortMapper::new();
        assert!(matches!(mapper.map(0), Err(NatError::InvalidPort(0))));
    }

    // Does real NAT-PMP/UPnP discovery against the live network: ~30s of
    // timeouts, and it holds the test binary open meanwhile. Run explicitly
    // with `cargo test -- --ignored`, not on every build.
    #[test]
    #[ignore]
    fn logger_receives_messages() {
        use std::sync::Mutex as StdMutex;
        let log: Arc<StdMutex<Vec<String>>> = Arc::new(StdMutex::new(Vec::new()));
        let sink = Arc::clone(&log);

        let mut mapper = PortMapper::new();
        mapper.set_logger(Arc::new(move |m: &str| sink.lock().unwrap().push(m.to_string())));

        // No router in the test environment: map returns Ok(None) and logs the
        // "looking" line plus a "nobody answered" line.
        let _ = mapper.map(6881);
        let messages = log.lock().unwrap();
        assert!(messages.iter().any(|m| m.contains("Forwarding port 6881")));
    }
}
