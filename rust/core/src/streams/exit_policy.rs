//! Where a node agrees to let a guest out of the network, and where it does not.
//!
//! Letting anyone out is switched off until the owner switches it on: traffic
//! leaves through the owner's own address, and whoever answers for that address
//! answers for the traffic. What is never allowed, on or off, is the machine's
//! own networks — loopback, the private ranges, link-local and the carrier's
//! shared range — or an exit node would be a door into the owner's home network.
//!
//! The full `try_resolve` with destination-port rules — resolving a name here
//! rather than at the connection, because a name may point wherever it likes,
//! including 127.0.0.1, and the check must be made against what the name
//! actually resolves to.

use crate::streams::stream_end_reason::StreamEndReason;
use crate::text::loc;
use std::fmt;
use std::net::{IpAddr, Ipv6Addr, ToSocketAddrs};
use std::sync::Mutex;

pub struct ExitPolicy {
    /// Whether the node lets guests out at all.
    pub enabled: bool,
    ports: Mutex<Vec<u16>>,
    /// The one loosening, for the self-test alone: a live check has nowhere to
    /// go but the loopback address. Never set in service.
    pub allow_private: bool,
}

impl Default for ExitPolicy {
    fn default() -> Self {
        ExitPolicy {
            enabled: false,
            ports: Mutex::new(Vec::new()),
            allow_private: false,
        }
    }
}

impl ExitPolicy {
    pub fn new() -> ExitPolicy {
        ExitPolicy::default()
    }

    /// Which destination ports are allowed. Empty — any of them.
    pub fn ports(&self) -> Vec<u16> {
        self.ports.lock().unwrap().clone()
    }

    pub fn allow_port(&self, port: u16) {
        assert!(port > 0, "port out of range");
        let mut ports = self.ports.lock().unwrap();
        if !ports.contains(&port) {
            ports.push(port);
        }
    }

    pub fn allow_any_port(&self) {
        self.ports.lock().unwrap().clear();
    }

    /// Works out where the guest is actually being let out to. Returns the
    /// address to connect to, or the reason for the refusal.
    ///
    /// Mirrors the C# `TryResolve`: the default refusal is
    /// [`StreamEndReason::NotAllowed`]; a name that does not resolve is a failed
    /// connection rather than a refusal, since there is nothing forbidden about
    /// it; and which of "our own network" or "a kind we do not speak" a rejected
    /// address was is never told to the guest — it would make an exit node into a
    /// scanner of the owner's network by the sound of its refusals.
    pub fn try_resolve(&self, host: &str, port: u16) -> Result<IpAddr, StreamEndReason> {
        if !self.enabled {
            return Err(StreamEndReason::NotAllowed);
        }
        if host.trim().is_empty() {
            return Err(StreamEndReason::BadRequest);
        }
        if port == 0 {
            return Err(StreamEndReason::BadRequest);
        }

        {
            let ports = self.ports.lock().unwrap();
            if !ports.is_empty() && !ports.contains(&port) {
                return Err(StreamEndReason::NotAllowed);
            }
        }

        let trimmed = host.trim();
        let candidates: Vec<IpAddr> = match trimmed.parse::<IpAddr>() {
            Ok(parsed) => vec![parsed],
            Err(_) => match (trimmed, port).to_socket_addrs() {
                // A name that does not resolve is a failed connection, not a
                // refusal.
                Ok(addrs) => addrs.map(|sa| sa.ip()).collect(),
                Err(_) => return Err(StreamEndReason::ConnectFailed),
            },
        };

        for candidate in &candidates {
            if !self.allow_private && is_own_network(*candidate) {
                continue;
            }
            return Ok(*candidate);
        }

        // Every address the name gave out is in our own networks (or there were
        // none at all).
        if candidates.is_empty() {
            Err(StreamEndReason::ConnectFailed)
        } else {
            Err(StreamEndReason::NotAllowed)
        }
    }
}

/// A short description for the log and for the window, in the window's language.
impl fmt::Display for ExitPolicy {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if !self.enabled {
            return write!(f, "{}", loc::t("exit.rule.off"));
        }
        let ports = self.ports.lock().unwrap();
        if ports.is_empty() {
            write!(f, "{}", loc::t("exit.rule.any"))
        } else {
            let joined = ports.iter().map(|p| p.to_string()).collect::<Vec<_>>().join(", ");
            write!(f, "{}", loc::t_args("exit.rule.ports", &[&joined]))
        }
    }
}

/// The addresses a guest is never let out to: they belong to the machine itself
/// or to the network it stands in.
pub fn is_own_network(address: IpAddr) -> bool {
    match address {
        IpAddr::V4(v4) => {
            if v4.is_loopback() {
                return true;
            }
            let b = v4.octets();
            b[0] == 0                                  // this network
                || b[0] == 10                          // 10.0.0.0/8
                || b[0] == 127                         // loopback
                || (b[0] == 169 && b[1] == 254)        // link-local
                || (b[0] == 172 && (16..=31).contains(&b[1])) // 172.16.0.0/12
                || (b[0] == 192 && b[1] == 168)        // 192.168.0.0/16
                || (b[0] == 100 && (64..=127).contains(&b[1])) // carrier NAT
                || (b[0] == 192 && b[1] == 0 && b[2] == 0)     // protocol assignments
                || b[0] >= 224 // multicast and above
        }
        IpAddr::V6(v6) => {
            if v6.is_loopback() || v6.is_multicast() {
                return true;
            }
            let seg = v6.segments();
            // Link-local fe80::/10.
            if (seg[0] & 0xffc0) == 0xfe80 {
                return true;
            }
            // Site-local fec0::/10 (deprecated but matched by the C#).
            if (seg[0] & 0xffc0) == 0xfec0 {
                return true;
            }
            // Unique local fc00::/7 — the IPv6 answer to 10.x.
            let first = v6.octets()[0];
            if (first & 0xfe) == 0xfc {
                return true;
            }
            if let Some(mapped) = v6.to_ipv4_mapped() {
                return is_own_network(IpAddr::V4(mapped));
            }
            v6 == Ipv6Addr::UNSPECIFIED
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn own_networks_are_recognised() {
        for ip in ["127.0.0.1", "10.1.2.3", "192.168.0.1", "172.16.5.5", "169.254.1.1", "100.64.0.1"] {
            assert!(is_own_network(ip.parse().unwrap()), "{ip} should be own-network");
        }
    }

    #[test]
    fn public_addresses_are_allowed() {
        for ip in ["8.8.8.8", "1.1.1.1", "203.0.113.9", "172.32.0.1"] {
            assert!(!is_own_network(ip.parse::<Ipv4Addr>().unwrap().into()), "{ip} should be public");
        }
    }

    #[test]
    fn disabled_policy_refuses_everything() {
        let policy = ExitPolicy::new();
        assert_eq!(policy.try_resolve("8.8.8.8", 443), Err(StreamEndReason::NotAllowed));
    }

    #[test]
    fn enabled_policy_lets_a_public_address_out() {
        let mut policy = ExitPolicy::new();
        policy.enabled = true;
        assert_eq!(policy.try_resolve("8.8.8.8", 443), Ok("8.8.8.8".parse().unwrap()));
    }

    #[test]
    fn own_network_is_refused_even_when_enabled() {
        let mut policy = ExitPolicy::new();
        policy.enabled = true;
        // A literal loopback/private address is in our own networks: refused.
        assert_eq!(policy.try_resolve("127.0.0.1", 80), Err(StreamEndReason::NotAllowed));
        assert_eq!(policy.try_resolve("192.168.1.1", 80), Err(StreamEndReason::NotAllowed));
    }

    #[test]
    fn allow_private_opens_the_loosening_for_the_self_test() {
        let mut policy = ExitPolicy::new();
        policy.enabled = true;
        policy.allow_private = true;
        assert_eq!(policy.try_resolve("127.0.0.1", 80), Ok("127.0.0.1".parse().unwrap()));
    }

    #[test]
    fn port_rules_gate_the_destination() {
        let mut policy = ExitPolicy::new();
        policy.enabled = true;
        policy.allow_port(443);
        // An allowed port goes through.
        assert_eq!(policy.try_resolve("8.8.8.8", 443), Ok("8.8.8.8".parse().unwrap()));
        // A port not on the list is refused.
        assert_eq!(policy.try_resolve("8.8.8.8", 80), Err(StreamEndReason::NotAllowed));
    }

    #[test]
    fn bad_request_for_blank_host_or_zero_port() {
        let mut policy = ExitPolicy::new();
        policy.enabled = true;
        assert_eq!(policy.try_resolve("   ", 80), Err(StreamEndReason::BadRequest));
        assert_eq!(policy.try_resolve("8.8.8.8", 0), Err(StreamEndReason::BadRequest));
    }

    #[test]
    fn description_follows_the_state() {
        let mut policy = ExitPolicy::new();
        assert_eq!(policy.to_string(), "disabled");
        policy.enabled = true;
        assert_eq!(policy.to_string(), "all ports");
        policy.allow_port(443);
        assert_eq!(policy.to_string(), "ports 443");
    }
}
