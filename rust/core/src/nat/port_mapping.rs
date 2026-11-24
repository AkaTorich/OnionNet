//! The outcome of a forward, and the facts known about this machine's network.
//!
//! Ports a Rust [`PortMapping`](crate::nat::PortMapping) to the C#
//! `PortMapping` / `NetworkFacts` pair. The `NetworkFacts` helpers need to
//! enumerate the machine's gateways and interfaces, which the standard library
//! does not expose; where that is so, the port falls back to a documented,
//! `std`-only shim (see each function).

use std::net::{Ipv4Addr, SocketAddr, UdpSocket};
use std::process::Command;
use std::time::{Duration, SystemTime};

/// Which method got the router to agree.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MappingMethod {
    None = 0,

    /// UPnP IGD - most home routers understand it.
    Upnp = 1,

    /// NAT-PMP - simpler and more dependable where it exists.
    NatPmp = 2,
}

/// What came of the forwarding.
///
/// Immutable once built, mirroring the C# type's private setters.
#[derive(Debug, Clone)]
pub struct PortMapping {
    method: MappingMethod,
    external_port: u16,
    internal_port: u16,
    external_address: Option<Ipv4Addr>,
    lifetime: Duration,
    gateway: String,
    created_utc: SystemTime,
}

impl PortMapping {
    pub fn new(
        method: MappingMethod,
        external_port: u16,
        internal_port: u16,
        external_address: Option<Ipv4Addr>,
        lifetime: Duration,
        gateway: String,
    ) -> Self {
        PortMapping {
            method,
            external_port,
            internal_port,
            external_address,
            lifetime,
            gateway,
            created_utc: SystemTime::now(),
        }
    }

    pub fn method(&self) -> MappingMethod {
        self.method
    }

    pub fn external_port(&self) -> u16 {
        self.external_port
    }

    pub fn internal_port(&self) -> u16 {
        self.internal_port
    }

    /// The address the router sees us at from outside. May be `None`.
    pub fn external_address(&self) -> Option<Ipv4Addr> {
        self.external_address
    }

    /// The lease term. Zero means "until the router reboots".
    pub fn lifetime(&self) -> Duration {
        self.lifetime
    }

    pub fn gateway(&self) -> &str {
        &self.gateway
    }

    pub fn created_utc(&self) -> SystemTime {
        self.created_utc
    }

    /// Whether the node is really visible from the internet.
    ///
    /// A router may honestly forward the port and return, as the external
    /// address... a private one again. That means another NAT stands behind it
    /// - usually the carrier's. The forward then opened a road only inside the
    /// carrier's network, and from outside the node is still unreachable.
    /// Staying quiet about it will not do: a person would wait for incoming
    /// connections that will never come.
    pub fn is_reachable_from_internet(&self) -> bool {
        match self.external_address {
            Some(address) => !network_facts::is_private(address),
            None => false,
        }
    }

    pub fn describe(&self) -> String {
        let method = if self.method == MappingMethod::Upnp {
            "UPnP"
        } else {
            "NAT-PMP"
        };

        let address = match self.external_address {
            Some(address) => address.to_string(),
            None => "address unknown".to_string(),
        };

        let mut text = format!(
            "{}: {}:{} -> local {} (router {})",
            method, address, self.external_port, self.internal_port, self.gateway
        );

        if self.lifetime > Duration::ZERO {
            text += &format!(", lease {} min", self.lifetime.as_secs() / 60);
        }

        if !self.is_reachable_from_internet() && self.external_address.is_some() {
            text += ". WARNING: the router reports a private address - double NAT, \
                     the node is not reachable from the internet.";
        }

        text
    }
}

/// What is known about this machine's network (C# `NetworkFacts`).
pub mod network_facts {
    use super::*;

    /// Whether the address is private. That includes `100.64.0.0/10` - the
    /// range carriers hand out behind their own NAT. A router that returns such
    /// an address as "external" gives a double NAT away completely.
    ///
    /// Only IPv4 is handled, as in the C# original (which returns `false` for
    /// any non-IPv4 family).
    pub fn is_private(address: Ipv4Addr) -> bool {
        let b = address.octets();

        if b[0] == 10 {
            return true; // 10.0.0.0/8
        }
        if b[0] == 127 {
            return true; // loopback
        }
        if b[0] == 172 && (16..=31).contains(&b[1]) {
            return true; // 172.16.0.0/12
        }
        if b[0] == 192 && b[1] == 168 {
            return true; // 192.168.0.0/16
        }
        if b[0] == 169 && b[1] == 254 {
            return true; // self-assigned
        }
        if b[0] == 100 && (64..=127).contains(&b[1]) {
            return true; // 100.64.0.0/10 - carrier NAT
        }

        false
    }

    /// The default gateways - the ones UPnP and NAT-PMP address.
    ///
    /// SHIM: the standard library cannot enumerate network adapters, so the
    /// default gateways are read from the operating system's routing table via
    /// a child process (`route print -4` on Windows, `ip -4 route show
    /// default` on Unix). The numeric routing table is locale-independent. The
    /// main thread may wish to replace this with the real adapter enumeration
    /// (`GetAdaptersAddresses`) once the glue layer exists.
    pub fn gateways() -> Vec<Ipv4Addr> {
        let mut result: Vec<Ipv4Addr> = Vec::new();
        let mut push = |address: Ipv4Addr| {
            if address == Ipv4Addr::UNSPECIFIED {
                return;
            }
            if !result.contains(&address) {
                result.push(address);
            }
        };

        if cfg!(windows) {
            // `route print -4` lists the IPv4 routing table. A default route
            // has destination 0.0.0.0 and mask 0.0.0.0; the third column is the
            // gateway. These data rows are numeric regardless of UI language.
            if let Ok(output) = Command::new("route").args(["print", "-4"]).output() {
                let text = String::from_utf8_lossy(&output.stdout);
                for line in text.lines() {
                    let fields: Vec<&str> = line.split_whitespace().collect();
                    if fields.len() >= 3 && fields[0] == "0.0.0.0" && fields[1] == "0.0.0.0" {
                        if let Ok(address) = fields[2].parse::<Ipv4Addr>() {
                            push(address);
                        }
                    }
                }
            }
        } else {
            // `ip -4 route show default` prints lines like
            // `default via 192.168.1.1 dev eth0 ...`.
            if let Ok(output) = Command::new("ip")
                .args(["-4", "route", "show", "default"])
                .output()
            {
                let text = String::from_utf8_lossy(&output.stdout);
                for line in text.lines() {
                    let fields: Vec<&str> = line.split_whitespace().collect();
                    if let Some(position) = fields.iter().position(|&f| f == "via") {
                        if let Some(address) = fields.get(position + 1) {
                            if let Ok(address) = address.parse::<Ipv4Addr>() {
                                push(address);
                            }
                        }
                    }
                }
            }
        }

        result
    }

    /// Whether the address belongs to one of this machine's adapters.
    ///
    /// SHIM: with no adapter enumeration in `std`, ownership is tested by
    /// trying to bind a UDP socket to the address - an address only binds if it
    /// is one of this machine's own. Loopback is accepted outright, as in the
    /// C# original.
    pub fn is_own_address(address: Ipv4Addr) -> bool {
        if address.is_loopback() {
            return true;
        }

        UdpSocket::bind((address, 0)).is_ok()
    }

    /// Our address on the way to the given one - the address the OS itself
    /// would send from. Nothing is sent: a UDP socket only picks a route when
    /// it is "connected". Without a target, or if no route is found, the plain
    /// guess from [`local_address`].
    pub fn local_address_towards(target: Option<Ipv4Addr>) -> Option<Ipv4Addr> {
        if let Some(target) = target {
            if let Ok(probe) = UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0)) {
                if probe.connect((target, 1900)).is_ok() {
                    if let Ok(SocketAddr::V4(local)) = probe.local_addr() {
                        let local = *local.ip();

                        // The loopback only counts when the router itself sits
                        // on it - which only the self-check's router does.
                        if local != Ipv4Addr::UNSPECIFIED
                            && (!local.is_loopback() || target.is_loopback())
                        {
                            return Some(local);
                        }
                    }
                }
            }
        }

        local_address()
    }

    /// Our address on the local network - the one to name to the router as the
    /// internal recipient. It is taken from the adapter that has the gateway:
    /// otherwise, on a machine with several networks, the forward would go to
    /// the wrong place.
    ///
    /// SHIM: `std` cannot pair an interface with its gateway, so the outbound
    /// local address is obtained by "connecting" (routing, without sending) a
    /// UDP socket towards each known gateway and reading back the local
    /// endpoint the OS chose - which is exactly the adapter facing that
    /// gateway.
    pub fn local_address() -> Option<Ipv4Addr> {
        for gateway in gateways() {
            if let Ok(probe) = UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0)) {
                if probe.connect((gateway, 9)).is_ok() {
                    if let Ok(SocketAddr::V4(local)) = probe.local_addr() {
                        let local = *local.ip();
                        if local != Ipv4Addr::UNSPECIFIED && !local.is_loopback() {
                            return Some(local);
                        }
                    }
                }
            }
        }

        None
    }
}

#[cfg(test)]
mod tests {
    use super::network_facts::is_private;
    use super::*;

    #[test]
    fn private_ranges_match_csharp() {
        assert!(is_private(Ipv4Addr::new(10, 0, 0, 1)));
        assert!(is_private(Ipv4Addr::new(127, 0, 0, 1)));
        assert!(is_private(Ipv4Addr::new(172, 16, 0, 1)));
        assert!(is_private(Ipv4Addr::new(172, 31, 255, 255)));
        assert!(is_private(Ipv4Addr::new(192, 168, 1, 1)));
        assert!(is_private(Ipv4Addr::new(169, 254, 0, 1)));
        assert!(is_private(Ipv4Addr::new(100, 64, 0, 1))); // carrier NAT
        assert!(is_private(Ipv4Addr::new(100, 127, 255, 255)));

        // Just outside the carrier-NAT block.
        assert!(!is_private(Ipv4Addr::new(100, 63, 0, 1)));
        assert!(!is_private(Ipv4Addr::new(100, 128, 0, 1)));
        // Ordinary public addresses.
        assert!(!is_private(Ipv4Addr::new(8, 8, 8, 8)));
        assert!(!is_private(Ipv4Addr::new(172, 15, 0, 1)));
        assert!(!is_private(Ipv4Addr::new(172, 32, 0, 1)));
    }

    #[test]
    fn reachable_only_with_a_public_external_address() {
        let public = PortMapping::new(
            MappingMethod::NatPmp,
            6881,
            6881,
            Some(Ipv4Addr::new(203, 0, 113, 7)),
            Duration::from_secs(3600),
            "192.168.1.1".to_string(),
        );
        assert!(public.is_reachable_from_internet());

        let double_nat = PortMapping::new(
            MappingMethod::NatPmp,
            6881,
            6881,
            Some(Ipv4Addr::new(100, 64, 0, 9)),
            Duration::from_secs(3600),
            "192.168.1.1".to_string(),
        );
        assert!(!double_nat.is_reachable_from_internet());
        assert!(double_nat.describe().contains("double NAT"));

        let unknown = PortMapping::new(
            MappingMethod::Upnp,
            6881,
            6881,
            None,
            Duration::ZERO,
            "192.168.1.1".to_string(),
        );
        assert!(!unknown.is_reachable_from_internet());
        assert!(unknown.describe().contains("address unknown"));
        // A zero lease prints no lease clause.
        assert!(!unknown.describe().contains("lease"));
    }
}
