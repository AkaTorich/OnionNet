//! Port forwarding over NAT-PMP - the second method torrent clients use.
//!
//! Where it exists it is simpler and more dependable than UPnP: instead of a
//! broadcast, XML parsing and SOAP, twelve bytes over UDP straight to the
//! gateway.
//!
//! It is needed as a fallback: some routers understand only NAT-PMP, some only
//! UPnP, and there is no guessing in advance which one turned up.
//!
//! The same caveat as with UPnP: the protocol cannot ask who is asking at all.
//! Any program on the local network can open a port.

use std::net::{Ipv4Addr, UdpSocket};
use std::time::Duration;

use super::port_mapping::{network_facts, MappingMethod, PortMapping};
use super::LogFn;

const GATEWAY_PORT: u16 = 5351;
const VERSION: u8 = 0;

const OP_PUBLIC_ADDRESS: u8 = 0;
const OP_MAP_TCP: u8 = 2;

/// Talks NAT-PMP to the default gateway.
pub struct NatPmpMapper {
    gateway: Option<Ipv4Addr>,
    timeout: Duration,
    logger: Option<LogFn>,
}

impl Default for NatPmpMapper {
    fn default() -> Self {
        Self::new()
    }
}

impl NatPmpMapper {
    pub fn new() -> Self {
        NatPmpMapper {
            gateway: None,
            timeout: Duration::from_secs(3),
            logger: None,
        }
    }

    pub fn timeout(&self) -> Duration {
        self.timeout
    }

    pub fn set_timeout(&mut self, timeout: Duration) {
        self.timeout = timeout;
    }

    pub fn gateway(&self) -> Option<String> {
        self.gateway.map(|g| g.to_string())
    }

    /// Installs the log sink (C# `event Action<string> Logged`).
    pub fn set_logger(&mut self, logger: LogFn) {
        self.logger = Some(logger);
    }

    /// Looks for a gateway that understands NAT-PMP. Asking for the address is
    /// the cheapest way to check: whoever answers, can.
    pub fn discover(&mut self) -> bool {
        for gateway in network_facts::gateways() {
            let request = [VERSION, OP_PUBLIC_ADDRESS];
            let response = match self.exchange(gateway, &request, 12) {
                Some(response) => response,
                None => continue,
            };

            if response[1] != 128 + OP_PUBLIC_ADDRESS {
                continue;
            }

            let result = ((response[2] as u16) << 8) | response[3] as u16;
            if result != 0 {
                self.say(&format!(
                    "NAT-PMP: gateway {gateway} rejected the request, code {result}."
                ));
                continue;
            }

            self.gateway = Some(gateway);
            self.say(&format!("NAT-PMP: gateway {gateway} responded."));
            return true;
        }

        // Silence has to be said out loud too: otherwise the log shows only the
        // UPnP refusal, and it looks as if NAT-PMP was never tried.
        self.say("NAT-PMP: no gateway responded.");
        false
    }

    /// Asks the gateway to forward `port`. Returns `None` on any failure - an
    /// ordinary outcome, not an error.
    pub fn map(&mut self, port: u16, lease: Duration) -> Option<PortMapping> {
        if self.gateway.is_none() && !self.discover() {
            return None;
        }
        let gateway = self.gateway?;

        let mut seconds = lease.as_secs() as i64;
        if seconds <= 0 {
            seconds = 3600; // NAT-PMP has no everlasting leases
        }

        let mut request = [0u8; 12];
        request[0] = VERSION;
        request[1] = OP_MAP_TCP;
        // [2..4] reserved, zeros
        write_u16(&mut request, 4, port); // our internal port
        write_u16(&mut request, 6, port); // the external one we want
        write_u32(&mut request, 8, seconds as u32);

        let response = match self.exchange(gateway, &request, 16) {
            Some(response) => response,
            None => {
                self.say("NAT-PMP: no response to the mapping request.");
                return None;
            }
        };

        if response[1] != 128 + OP_MAP_TCP {
            self.say("NAT-PMP: unexpected response.");
            return None;
        }

        let code = ((response[2] as u16) << 8) | response[3] as u16;
        if code != 0 {
            let explained = explain(code);
            self.say(&format!("NAT-PMP: rejected - {explained}"));
            return None;
        }

        let granted = ((response[10] as u16) << 8) | response[11] as u16;
        let lifetime = read_u32(&response, 12);

        let external = self.public_address();
        let gateway_text = self.gateway().unwrap_or_default();

        Some(PortMapping::new(
            MappingMethod::NatPmp,
            granted,
            port,
            external,
            Duration::from_secs(lifetime as u64),
            gateway_text,
        ))
    }

    /// Removes the forward: the same request with a zero lease.
    pub fn unmap(&mut self, port: u16) -> bool {
        let gateway = match self.gateway {
            Some(gateway) => gateway,
            None => return false,
        };

        let mut request = [0u8; 12];
        request[0] = VERSION;
        request[1] = OP_MAP_TCP;
        write_u16(&mut request, 4, port);
        write_u16(&mut request, 6, 0); // external port zero - remove it
        write_u32(&mut request, 8, 0); // lease zero - remove it

        match self.exchange(gateway, &request, 16) {
            Some(response) => response[2] == 0 && response[3] == 0,
            None => false,
        }
    }

    /// The address the gateway sees us at from outside.
    pub fn public_address(&self) -> Option<Ipv4Addr> {
        let gateway = self.gateway?;

        let response = self.exchange(gateway, &[VERSION, OP_PUBLIC_ADDRESS], 12)?;
        if response[1] != 128 + OP_PUBLIC_ADDRESS {
            return None;
        }
        if response[2] != 0 || response[3] != 0 {
            return None;
        }

        Some(Ipv4Addr::new(
            response[8],
            response[9],
            response[10],
            response[11],
        ))
    }

    // ---- Talking to the gateway ---------------------------------------------

    /// Sends one request and waits for one answer of at least `minimum_response`
    /// bytes. `None` when the gateway does not answer or does not speak NAT-PMP
    /// - ordinary, not a breakdown.
    fn exchange(&self, gateway: Ipv4Addr, request: &[u8], minimum_response: usize) -> Option<Vec<u8>> {
        let socket = UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0)).ok()?;
        socket.set_read_timeout(Some(self.timeout)).ok()?;
        socket.connect((gateway, GATEWAY_PORT)).ok()?;
        socket.send(request).ok()?;

        let mut buffer = [0u8; 1500];
        let read = socket.recv(&mut buffer).ok()?;

        if read < minimum_response {
            return None;
        }
        if buffer[0] != VERSION {
            return None;
        }

        Some(buffer[..read].to_vec())
    }
}

fn explain(code: u16) -> String {
    match code {
        1 => "unsupported protocol version".to_string(),
        2 => "not authorized (NAT-PMP disabled)".to_string(),
        3 => "network failure".to_string(),
        4 => "out of resources".to_string(),
        5 => "unsupported opcode".to_string(),
        other => format!("code {other}"),
    }
}

fn write_u16(buffer: &mut [u8], offset: usize, value: u16) {
    buffer[offset] = (value >> 8) as u8;
    buffer[offset + 1] = value as u8;
}

fn write_u32(buffer: &mut [u8], offset: usize, value: u32) {
    buffer[offset] = (value >> 24) as u8;
    buffer[offset + 1] = (value >> 16) as u8;
    buffer[offset + 2] = (value >> 8) as u8;
    buffer[offset + 3] = value as u8;
}

fn read_u32(buffer: &[u8], offset: usize) -> u32 {
    ((buffer[offset] as u32) << 24)
        | ((buffer[offset + 1] as u32) << 16)
        | ((buffer[offset + 2] as u32) << 8)
        | buffer[offset + 3] as u32
}

impl NatPmpMapper {
    fn say(&self, message: &str) {
        if let Some(logger) = &self.logger {
            logger(message);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn int_layout_round_trips_big_endian() {
        let mut buffer = [0u8; 12];
        write_u16(&mut buffer, 4, 6881);
        write_u16(&mut buffer, 6, 6881);
        write_u32(&mut buffer, 8, 3600);

        // 6881 = 0x1AE1, big-endian.
        assert_eq!(buffer[4], 0x1A);
        assert_eq!(buffer[5], 0xE1);
        assert_eq!(buffer[6], 0x1A);
        assert_eq!(buffer[7], 0xE1);
        // 3600 = 0x00000E10, big-endian.
        assert_eq!(&buffer[8..12], &[0x00, 0x00, 0x0E, 0x10]);
        assert_eq!(read_u32(&buffer, 8), 3600);
    }

    #[test]
    fn map_request_header_matches_protocol() {
        let mut request = [0u8; 12];
        request[0] = VERSION;
        request[1] = OP_MAP_TCP;
        assert_eq!(request[0], 0);
        assert_eq!(request[1], 2);
        // Reserved pair stays zero.
        assert_eq!(request[2], 0);
        assert_eq!(request[3], 0);
    }

    #[test]
    fn parses_a_mapping_response() {
        // A well-formed AddMapping answer: version 0, op 128+2, code 0,
        // seconds-since-start, internal 6881, external 6881, lifetime 3600.
        let mut response = [0u8; 16];
        response[0] = VERSION;
        response[1] = 128 + OP_MAP_TCP;
        // [2..4] result code 0
        // [4..8] seconds since start - ignored
        write_u16(&mut response, 8, 6881); // internal
        write_u16(&mut response, 10, 6881); // external (granted)
        write_u32(&mut response, 12, 3600); // lifetime

        assert_eq!(response[1], 130);
        let code = ((response[2] as u16) << 8) | response[3] as u16;
        assert_eq!(code, 0);
        let granted = ((response[10] as u16) << 8) | response[11] as u16;
        assert_eq!(granted, 6881);
        assert_eq!(read_u32(&response, 12), 3600);
    }

    #[test]
    fn public_address_parse_slices_the_right_bytes() {
        let mut response = [0u8; 12];
        response[0] = VERSION;
        response[1] = 128 + OP_PUBLIC_ADDRESS;
        response[8] = 203;
        response[9] = 0;
        response[10] = 113;
        response[11] = 7;
        let address = Ipv4Addr::new(response[8], response[9], response[10], response[11]);
        assert_eq!(address, Ipv4Addr::new(203, 0, 113, 7));
    }

    #[test]
    fn explain_matches_csharp_strings() {
        assert_eq!(explain(2), "not authorized (NAT-PMP disabled)");
        assert_eq!(explain(5), "unsupported opcode");
        assert_eq!(explain(9), "code 9");
    }
}
