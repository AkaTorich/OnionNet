//! Port forwarding over UPnP IGD - the same method torrent clients use. The
//! overwhelming majority of home routers understand it.
//!
//! It works in three steps: an SSDP broadcast over the local network looking
//! for the router, reading its description over HTTP, then the `AddPortMapping`
//! command over SOAP. All three are built and parsed here by hand over
//! [`std::net`] sockets - no HTTP, SOAP or XML library - so the bytes match the
//! C# original.
//!
//! Worth remembering: UPnP has no check at all on who is asking. Any program on
//! your local network can open any port on the router without asking anyone.
//! That is a property of the protocol itself rather than of our
//! implementation, and it is exactly why many routers have UPnP off by default
//! - and rightly so.

use std::fmt;
use std::io::{ErrorKind, Read, Write};
use std::net::{Ipv4Addr, SocketAddr, TcpStream, ToSocketAddrs, UdpSocket};
use std::time::{Duration, Instant};

use super::port_mapping::{network_facts, MappingMethod, PortMapping};
use super::LogFn;

const MULTICAST_ADDRESS: &str = "239.255.255.250";
const MULTICAST_PORT: u16 = 1900;
const DESCRIPTION: &str = "StalkNet";

const SEARCH_TARGETS: [&str; 3] = [
    "urn:schemas-upnp-org:device:InternetGatewayDevice:1",
    "urn:schemas-upnp-org:service:WANIPConnection:1",
    "urn:schemas-upnp-org:service:WANPPPConnection:1",
];

const SERVICE_TYPES: [&str; 3] = [
    "urn:schemas-upnp-org:service:WANIPConnection:2",
    "urn:schemas-upnp-org:service:WANIPConnection:1",
    "urn:schemas-upnp-org:service:WANPPPConnection:1",
];

// ---- When the port is taken ----------------------------------------------
const CONFLICT_CODE: &str = "718";
const PERMANENT_ONLY_CODE: &str = "725";

/// Talks UPnP IGD to the home router.
pub struct UpnpMapper {
    discovery_timeout: Duration,
    request_timeout: Duration,

    /// The address of the router found - to show to the owner.
    gateway: Option<String>,

    control_url: Option<String>,
    service_type: Option<String>,

    /// The error code of the router's last refusal; `None` after an answer that
    /// was not one.
    last_code: Option<String>,

    logger: Option<LogFn>,
}

impl Default for UpnpMapper {
    fn default() -> Self {
        Self::new()
    }
}

impl UpnpMapper {
    pub fn new() -> Self {
        UpnpMapper {
            discovery_timeout: Duration::from_secs(4),
            request_timeout: Duration::from_secs(8),
            gateway: None,
            control_url: None,
            service_type: None,
            last_code: None,
            logger: None,
        }
    }

    pub fn discovery_timeout(&self) -> Duration {
        self.discovery_timeout
    }

    pub fn set_discovery_timeout(&mut self, timeout: Duration) {
        self.discovery_timeout = timeout;
    }

    pub fn request_timeout(&self) -> Duration {
        self.request_timeout
    }

    pub fn set_request_timeout(&mut self, timeout: Duration) {
        self.request_timeout = timeout;
    }

    pub fn gateway(&self) -> Option<&str> {
        self.gateway.as_deref()
    }

    /// Installs the log sink (C# `event Action<string> Logged`).
    pub fn set_logger(&mut self, logger: LogFn) {
        self.logger = Some(logger);
    }

    pub fn is_ready(&self) -> bool {
        self.control_url.is_some()
    }

    /// The error code of the router's last refusal, for a report.
    pub fn last_code(&self) -> Option<&str> {
        self.last_code.as_deref()
    }

    /// Looks for the router. First by an ordinary broadcast, then by asking the
    /// gateway directly.
    ///
    /// The second attempt is not a whim: the multicast broadcast is cut again
    /// and again by the Windows firewall, which will not let the answers back
    /// to our socket. The router is alive all the while and answers a direct
    /// question perfectly well. Without that fallback UPnP "does not work" on
    /// half the machines where it in fact does.
    pub fn discover(&mut self) -> bool {
        for target in SEARCH_TARGETS {
            for location in self.search(target, None) {
                if self.try_read_device(&location) {
                    return true;
                }
            }
        }

        self.say("UPnP: no response to multicast discovery, querying the gateway directly.");

        for gateway in network_facts::gateways() {
            for target in SEARCH_TARGETS {
                for location in self.search(target, Some(gateway)) {
                    if self.try_read_device(&location) {
                        return true;
                    }
                }
            }
        }

        self.say("UPnP: no router found. UPnP is probably disabled on the router.");
        false
    }

    /// Asks the router to forward a port. The lease is given in seconds; zero
    /// means "until the router is rebooted".
    ///
    /// Outside, the same number as ours. A router that keeps that number for
    /// itself - it does happen, with no forward on it at all - gets asked for
    /// one spare outside port instead. The spare is worked out from our port,
    /// so it is the same on every run: no run leaves a new forward behind.
    pub fn map(&mut self, port: u16, lease: Duration) -> Option<PortMapping> {
        if !self.is_ready() && !self.discover() {
            return None;
        }

        let local = match self.router_facing_address() {
            Some(local) => local,
            None => {
                self.say("UPnP: cannot determine the local IP address.");
                return None;
            }
        };

        let mut seconds = lease.as_secs() as i64;
        let mut external = port;

        let (mut made, mut error) = self.try_add(port, port, local, &mut seconds);

        if !made && self.last_code.as_deref() == Some(CONFLICT_CODE) {
            external = Self::spare_port(port);
            self.say(&format!(
                "UPnP: using fallback external port {external} for local port {port}."
            ));
            let (made_again, error_again) = self.try_add(external, port, local, &mut seconds);
            made = made_again;
            error = error_again;
        }

        if !made {
            let error = error.unwrap_or_default();
            self.say(&format!("UPnP: mapping rejected - {error}"));
            return None;
        }

        let external_address = self.get_external_address();
        let gateway = self.gateway.clone().unwrap_or_default();

        Some(PortMapping::new(
            MappingMethod::Upnp,
            external,
            port,
            external_address,
            Duration::from_secs(seconds.max(0) as u64),
            gateway,
        ))
    }

    /// The one spare outside port for a port of ours: in the range left for
    /// private use, 49152-65535, where routers keep nothing of their own.
    pub fn spare_port(port: u16) -> u16 {
        49152 + port % 16384
    }

    /// Removes the forward of an outside port. A courtesy the router will thank
    /// us for.
    pub fn unmap(&mut self, external_port: u16) -> bool {
        if !self.is_ready() {
            return false;
        }

        let body = format!(
            "<NewRemoteHost></NewRemoteHost>\
             <NewExternalPort>{external_port}</NewExternalPort>\
             <NewProtocol>TCP</NewProtocol>"
        );

        self.try_invoke("DeletePortMapping", &body).0
    }

    /// Every forward the router holds, whoever made it. Only reads: for finding
    /// out who sits on a port.
    pub fn list_mappings(&mut self) -> Vec<UpnpEntry> {
        let mut entries = Vec::new();
        if !self.is_ready() && !self.discover() {
            return entries;
        }

        for index in 0..256 {
            let body = format!("<NewPortMappingIndex>{index}</NewPortMappingIndex>");
            let (ok, response) = self.try_invoke("GetGenericPortMappingEntry", &body);
            if !ok {
                break; // past the end: 713, or a router that says it otherwise
            }
            let response = match response {
                Some(response) => response,
                None => break,
            };

            match parse_entry(&response, None) {
                Some(entry) => entries.push(entry),
                None => break,
            }
        }

        entries
    }

    /// Who holds an outside port. Only reads. `None` if nobody, or if the
    /// router would not say.
    pub fn who_holds(&mut self, external_port: u16) -> Option<UpnpEntry> {
        if !self.is_ready() && !self.discover() {
            return None;
        }
        self.get_entry(external_port)
    }

    /// For the self-check: a router given straight away, with no looking for it.
    pub(crate) fn use_router(&mut self, control_url: &str, service_type: &str) {
        self.control_url = Some(control_url.to_string());
        self.service_type = Some(service_type.to_string());
        self.gateway = parse_http_url(control_url).map(|url| url.host);
    }

    // ---- When the port is taken ----------------------------------------------

    /// A port the router says is taken is looked up. A forward to this very
    /// address and port - left from an earlier run, which many routers will not
    /// overwrite - is simply ours and is taken as it stands. Ours to another
    /// address of this machine is taken down and made afresh. A forward to
    /// anyone else is left alone, and the owner is told whose.
    fn try_add(
        &mut self,
        external: u16,
        internal_port: u16,
        local: Ipv4Addr,
        seconds: &mut i64,
    ) -> (bool, Option<String>) {
        let (ok, mut error) = self.add_mapping(external, internal_port, local, *seconds);
        if ok {
            return (true, None);
        }

        // 725: the router accepts only everlasting leases. We ask for one - but
        // then the cleaning up is on us.
        if self.last_code.as_deref() == Some(PERMANENT_ONLY_CODE) && *seconds != 0 {
            self.say("UPnP: the router supports only permanent mappings, requesting one.");
            *seconds = 0;
            let (ok_permanent, error_permanent) = self.add_mapping(external, internal_port, local, 0);
            if ok_permanent {
                return (true, None);
            }
            error = error_permanent;
        }

        if self.last_code.as_deref() != Some(CONFLICT_CODE) {
            return (false, error);
        }

        let refusal = error.clone();
        let holder = self.get_entry(external);
        let asked = self.last_code.clone();

        match holder {
            None => {
                // 714: "no such forward" - the port is refused with nobody on
                // it, so the router keeps it for itself.
                if asked.as_deref() == Some("714") {
                    self.say(&format!("UPnP: port {external} is reserved by the router."));
                } else {
                    self.say(&format!("UPnP: port {external} is in use on the router."));
                }
            }
            Some(holder)
                if holder.client == Some(local)
                    && holder.internal_port == internal_port
                    && holder.enabled =>
            {
                self.say(&format!(
                    "UPnP: port {external} is already mapped to this computer - reusing it."
                ));
                if holder.lease_seconds >= 0 {
                    *seconds = holder.lease_seconds;
                }
                return (true, None);
            }
            Some(holder)
                if holder.description.as_deref() == Some(DESCRIPTION)
                    && holder.client.map(network_facts::is_own_address).unwrap_or(false) =>
            {
                // Ours from an earlier run, to another address of this same
                // machine or another port of it: taken down and made afresh. A
                // forward of ours to some other machine is never touched -
                // another node may be living there.
                let client = holder.client.map(|c| c.to_string()).unwrap_or_default();
                self.say(&format!(
                    "UPnP: port {external} has a stale StalkNet mapping to this computer ({client}:{}) - replacing it.",
                    holder.internal_port
                ));
                self.unmap(external);
                let (ok_fresh, error_fresh) = self.add_mapping(external, internal_port, local, *seconds);
                if ok_fresh {
                    return (true, None);
                }
                error = error_fresh;
            }
            Some(holder) => {
                let client = holder.client.map(|c| c.to_string()).unwrap_or_default();
                let description = match holder.description {
                    Some(ref d) if !d.is_empty() => d.clone(),
                    _ => "-".to_string(),
                };
                self.say(&format!(
                    "UPnP: port {external} is mapped to {client}:{} ({description}).",
                    holder.internal_port
                ));
            }
        }

        // Whatever was asked on the way, the port stays "taken".
        self.last_code = Some(CONFLICT_CODE.to_string());
        let error = refusal.or(error);
        (false, error)
    }

    /// Who the router forwards an outside port to. `None` if it would not say.
    fn get_entry(&mut self, external: u16) -> Option<UpnpEntry> {
        let body = format!(
            "<NewRemoteHost></NewRemoteHost>\
             <NewExternalPort>{external}</NewExternalPort>\
             <NewProtocol>TCP</NewProtocol>"
        );

        let (ok, response) = self.try_invoke("GetSpecificPortMappingEntry", &body);
        if !ok {
            return None;
        }
        parse_entry(&response?, Some(external))
    }

    /// Our address on the router's side. A machine with a VPN or a virtual
    /// network has several, and the first one with a gateway is not always the
    /// one facing this router; a forward to a foreign address is refused, or
    /// leads nowhere.
    fn router_facing_address(&self) -> Option<Ipv4Addr> {
        let router = self
            .control_url
            .as_deref()
            .and_then(parse_http_url)
            .and_then(|url| url.host.parse::<Ipv4Addr>().ok());

        network_facts::local_address_towards(router)
    }

    // ---- Looking for the router --------------------------------------------

    /// Broadcasts M-SEARCH. If an address is given it asks that address
    /// directly, otherwise it sends to the multicast address of the whole local
    /// network.
    fn search(&mut self, target: &str, direct: Option<Ipv4Addr>) -> Vec<String> {
        let mut found: Vec<String> = Vec::new();

        let host = match direct {
            None => format!("{MULTICAST_ADDRESS}:{MULTICAST_PORT}"),
            Some(direct) => format!("{direct}:{MULTICAST_PORT}"),
        };

        let request = format!(
            "M-SEARCH * HTTP/1.1\r\n\
             HOST: {host}\r\n\
             MAN: \"ssdp:discover\"\r\n\
             MX: 2\r\n\
             ST: {target}\r\n\r\n"
        );
        let payload = request.as_bytes();
        let local = network_facts::local_address();

        // We bind to our own address rather than to "any". On a machine with
        // several networks there is otherwise no guessing which one the
        // broadcast leaves by, and the answer arrives in the wrong place.
        //
        // SHIM: the C# sets SO_REUSEADDR, which `std` does not expose. Since we
        // bind to an ephemeral port (0) rather than to 1900, reuse is not
        // needed; and the outgoing multicast interface, which the C# sets
        // explicitly, `std` selects from the bound local address instead.
        let socket = match UdpSocket::bind((local.unwrap_or(Ipv4Addr::UNSPECIFIED), 0)) {
            Ok(socket) => socket,
            Err(e) => {
                self.say(&format!("UPnP: discovery failed - {e}"));
                return found;
            }
        };
        let _ = socket.set_read_timeout(Some(self.discovery_timeout));

        if direct.is_none() {
            // The default time to live is enough for exactly one network
            // segment; we set it with room to spare in case of a switch.
            let _ = socket.set_multicast_ttl_v4(4);
        }

        let endpoint: SocketAddr = match direct {
            None => SocketAddr::from((Ipv4Addr::new(239, 255, 255, 250), MULTICAST_PORT)),
            Some(direct) => SocketAddr::from((direct, MULTICAST_PORT)),
        };

        // We send it three times: UDP is easily lost, and a router will not get
        // a second attempt out of an impatient client.
        for _ in 0..3 {
            let _ = socket.send_to(payload, endpoint);
        }

        let deadline = Instant::now() + self.discovery_timeout;

        while Instant::now() < deadline {
            let mut buffer = [0u8; 2048];
            match socket.recv_from(&mut buffer) {
                Ok((read, from)) => {
                    let text = String::from_utf8_lossy(&buffer[..read]);
                    if let Some(location) = header_value(&text, "LOCATION") {
                        if !found.contains(&location) {
                            found.push(location);
                            self.gateway = Some(from.ip().to_string());
                        }
                    }
                }
                Err(_) => break, // the wait ran out
            }
        }

        found
    }

    fn try_read_device(&mut self, location: &str) -> bool {
        let xml = match http_get(location, self.request_timeout) {
            Some(xml) => xml,
            None => return false,
        };

        for wanted in SERVICE_TYPES {
            for service in all_elements(&xml, "service") {
                let service_type = match tag_text(&service, "serviceType") {
                    Some(service_type) => service_type,
                    None => continue,
                };
                if !service_type.eq_ignore_ascii_case(wanted) {
                    continue;
                }

                let control = match tag_text(&service, "controlURL") {
                    Some(control) if !control.is_empty() => control,
                    _ => continue,
                };

                self.control_url = Some(combine(location, &control));
                let label = service_type
                    .rsplit(':')
                    .next()
                    .unwrap_or(&service_type)
                    .to_string();
                self.service_type = Some(service_type);

                self.say(&format!("UPnP: router found, service {label}."));
                return true;
            }
        }

        false
    }

    // ---- Commands to the router ---------------------------------------------

    fn add_mapping(
        &mut self,
        external: u16,
        internal_port: u16,
        local: Ipv4Addr,
        lease: i64,
    ) -> (bool, Option<String>) {
        let body = format!(
            "<NewRemoteHost></NewRemoteHost>\
             <NewExternalPort>{external}</NewExternalPort>\
             <NewProtocol>TCP</NewProtocol>\
             <NewInternalPort>{internal_port}</NewInternalPort>\
             <NewInternalClient>{local}</NewInternalClient>\
             <NewEnabled>1</NewEnabled>\
             <NewPortMappingDescription>{DESCRIPTION}</NewPortMappingDescription>\
             <NewLeaseDuration>{lease}</NewLeaseDuration>"
        );

        let (ok, response) = self.try_invoke("AddPortMapping", &body);
        if ok {
            (true, None)
        } else {
            (false, response)
        }
    }

    fn get_external_address(&mut self) -> Option<Ipv4Addr> {
        let (ok, response) = self.try_invoke("GetExternalIPAddress", "");
        if !ok {
            return None;
        }
        tag_text(&response?, "NewExternalIPAddress").and_then(|s| s.parse::<Ipv4Addr>().ok())
    }

    /// Invokes a SOAP action. Returns `(true, body)` on an HTTP success, and
    /// `(false, text)` on a fault or transport error - where `text` is the
    /// summarised fault or the error message, mirroring the C# `out response`.
    fn try_invoke(&mut self, action: &str, body: &str) -> (bool, Option<String>) {
        self.last_code = None;
        let control = match &self.control_url {
            Some(control) => control.clone(),
            None => return (false, None),
        };
        let service = self.service_type.clone().unwrap_or_default();

        let envelope = format!(
            "<?xml version=\"1.0\"?>\
             <s:Envelope xmlns:s=\"http://schemas.xmlsoap.org/soap/envelope/\" \
             s:encodingStyle=\"http://schemas.xmlsoap.org/soap/encoding/\">\
             <s:Body><u:{action} xmlns:u=\"{service}\">{body}</u:{action}></s:Body></s:Envelope>"
        );
        let payload = envelope.into_bytes();
        let soap_action = format!("\"{service}#{action}\"");

        let headers = [
            ("Content-Type", "text/xml; charset=\"utf-8\""),
            ("SOAPACTION", soap_action.as_str()),
        ];

        match http_request("POST", &control, &headers, Some(&payload), self.request_timeout) {
            Ok((status, response)) if (200..300).contains(&status) => (true, Some(response)),
            Ok((_status, fault)) => {
                // The router explains a refusal in the answer's body rather
                // than in the HTTP code.
                let summary = self.summarise(&fault);
                (false, Some(summary))
            }
            Err(message) => (false, Some(message)),
        }
    }

    /// Pulls the code and the text out of a SOAP fault instead of dumping the
    /// whole XML. The code is kept: what to do next depends on it.
    fn summarise(&mut self, fault: &str) -> String {
        let code = tag_text(fault, "errorCode").unwrap_or_else(|| "?".to_string());
        self.last_code = Some(code.clone());
        let text = tag_text(fault, "errorDescription").unwrap_or_else(|| "no description".to_string());
        format!("error {code}, {text}")
    }

    fn say(&self, message: &str) {
        if let Some(logger) = &self.logger {
            logger(message);
        }
    }
}

/// One forward as the router lists it.
#[derive(Debug, Clone)]
pub struct UpnpEntry {
    pub external_port: u16,
    pub protocol: String,

    /// The machine the forward leads to. `None` if the router named something
    /// unreadable.
    pub client: Option<Ipv4Addr>,

    pub internal_port: u16,
    pub description: Option<String>,
    pub enabled: bool,

    /// Seconds left, zero for "until reboot", -1 if the router did not say.
    pub lease_seconds: i64,
}

impl fmt::Display for UpnpEntry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let client = match self.client {
            Some(client) => client.to_string(),
            None => "?".to_string(),
        };
        write!(
            f,
            "{} {} -> {}:{}  {}{}",
            self.protocol,
            self.external_port,
            client,
            self.internal_port,
            self.description.as_deref().unwrap_or(""),
            if self.enabled { "" } else { "  (off)" }
        )
    }
}

fn parse_entry(response: &str, external: Option<u16>) -> Option<UpnpEntry> {
    let external = match external {
        Some(external) => external,
        None => tag_text(response, "NewExternalPort")?.parse().ok()?,
    };

    let client = tag_text(response, "NewInternalClient").and_then(|s| s.parse::<Ipv4Addr>().ok());
    let internal_port = tag_text(response, "NewInternalPort")
        .and_then(|s| s.parse::<u16>().ok())
        .unwrap_or(0);
    let lease = tag_text(response, "NewLeaseDuration")
        .and_then(|s| s.parse::<i64>().ok())
        .unwrap_or(-1);

    Some(UpnpEntry {
        external_port: external,
        protocol: tag_text(response, "NewProtocol").unwrap_or_else(|| "TCP".to_string()),
        client,
        internal_port,
        description: tag_text(response, "NewPortMappingDescription"),
        enabled: tag_text(response, "NewEnabled").as_deref() != Some("0"),
        lease_seconds: lease,
    })
}

// ---- Hand-rolled HTTP over TCP -------------------------------------------

/// A parsed `http://` URL - all the IGD description and control URLs use.
struct HttpUrl {
    host: String,
    port: u16,
    path: String,
}

fn parse_http_url(url: &str) -> Option<HttpUrl> {
    let lower = url.to_ascii_lowercase();
    let rest = if let Some(rest) = lower.strip_prefix("http://") {
        &url[7..7 + rest.len()]
    } else {
        return None;
    };

    let (authority, path) = match rest.find('/') {
        Some(index) => (&rest[..index], rest[index..].to_string()),
        None => (rest, "/".to_string()),
    };

    let (host, port) = match authority.rfind(':') {
        Some(index) => (
            authority[..index].to_string(),
            authority[index + 1..].parse::<u16>().unwrap_or(80),
        ),
        None => (authority.to_string(), 80),
    };

    Some(HttpUrl { host, port, path })
}

fn authority(url: &HttpUrl) -> String {
    if url.port == 80 {
        url.host.clone()
    } else {
        format!("{}:{}", url.host, url.port)
    }
}

/// A control URL comes both absolute and relative.
fn combine(location: &str, control: &str) -> String {
    let lower = control.to_ascii_lowercase();
    if lower.starts_with("http://") || lower.starts_with("https://") {
        return control.to_string();
    }

    let base = match parse_http_url(location) {
        Some(base) => base,
        None => return control.to_string(),
    };

    if control.starts_with('/') {
        format!("http://{}{}", authority(&base), control)
    } else {
        let dir = match base.path.rfind('/') {
            Some(index) => &base.path[..=index],
            None => "/",
        };
        format!("http://{}{}{}", authority(&base), dir, control)
    }
}

fn http_get(url: &str, timeout: Duration) -> Option<String> {
    match http_request("GET", url, &[], None, timeout) {
        Ok((status, body)) if (200..300).contains(&status) => Some(body),
        _ => None,
    }
}

/// Sends one HTTP/1.1 request and reads the whole response. `Ok((status,
/// body))` for any complete answer, `Err(message)` for a transport failure.
///
/// `Connection: close` is requested so the body ends at EOF; a `chunked` body
/// is decoded, and any `Content-Length` is honoured.
fn http_request(
    method: &str,
    url: &str,
    headers: &[(&str, &str)],
    body: Option<&[u8]>,
    timeout: Duration,
) -> Result<(u16, String), String> {
    let url = parse_http_url(url).ok_or_else(|| format!("not an http url: {url}"))?;

    let address = (url.host.as_str(), url.port)
        .to_socket_addrs()
        .map_err(|e| e.to_string())?
        .next()
        .ok_or_else(|| format!("cannot resolve {}", url.host))?;

    let mut stream = TcpStream::connect_timeout(&address, timeout).map_err(|e| e.to_string())?;
    let _ = stream.set_read_timeout(Some(timeout));
    let _ = stream.set_write_timeout(Some(timeout));

    let mut request = format!("{method} {} HTTP/1.1\r\nHost: {}\r\n", url.path, authority(&url));
    for (name, value) in headers {
        request.push_str(&format!("{name}: {value}\r\n"));
    }
    if let Some(body) = body {
        request.push_str(&format!("Content-Length: {}\r\n", body.len()));
    }
    request.push_str("Connection: close\r\n\r\n");

    stream.write_all(request.as_bytes()).map_err(|e| e.to_string())?;
    if let Some(body) = body {
        stream.write_all(body).map_err(|e| e.to_string())?;
    }
    let _ = stream.flush();

    let mut raw = Vec::new();
    let mut buffer = [0u8; 4096];
    loop {
        match stream.read(&mut buffer) {
            Ok(0) => break,
            Ok(read) => {
                raw.extend_from_slice(&buffer[..read]);
                if raw.len() > 1 << 20 {
                    break; // a megabyte is far more than any IGD answer
                }
            }
            Err(e) if e.kind() == ErrorKind::WouldBlock || e.kind() == ErrorKind::TimedOut => break,
            Err(e) => return Err(e.to_string()),
        }
    }

    parse_http(&raw).ok_or_else(|| "malformed HTTP response".to_string())
}

fn parse_http(raw: &[u8]) -> Option<(u16, String)> {
    let separator = find_subslice(raw, b"\r\n\r\n")?;
    let header_text = String::from_utf8_lossy(&raw[..separator]);

    let mut lines = header_text.split("\r\n");
    let status_line = lines.next()?;
    let status: u16 = status_line.split_whitespace().nth(1)?.parse().ok()?;

    let mut chunked = false;
    for line in lines {
        if let Some((name, value)) = line.split_once(':') {
            if name.trim().eq_ignore_ascii_case("transfer-encoding")
                && value.to_ascii_lowercase().contains("chunked")
            {
                chunked = true;
            }
        }
    }

    let body = &raw[separator + 4..];
    let body = if chunked {
        decode_chunked(body)
    } else {
        body.to_vec()
    };

    Some((status, String::from_utf8_lossy(&body).into_owned()))
}

fn decode_chunked(mut body: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    loop {
        let line_end = match find_subslice(body, b"\r\n") {
            Some(index) => index,
            None => break,
        };
        let size_text = String::from_utf8_lossy(&body[..line_end]);
        let size_text = size_text.split(';').next().unwrap_or("").trim();
        let size = match usize::from_str_radix(size_text, 16) {
            Ok(size) => size,
            Err(_) => break,
        };
        if size == 0 {
            break;
        }
        let start = line_end + 2;
        // The size is whatever the other side wrote: a huge one must not wrap
        // around and cut the slice backwards.
        let end = match start.checked_add(size) {
            Some(end) => end,
            None => {
                out.extend_from_slice(&body[start..]);
                break;
            }
        };
        if end > body.len() {
            out.extend_from_slice(&body[start..]);
            break;
        }
        out.extend_from_slice(&body[start..end]);
        // Skip the trailing CRLF after the chunk data.
        body = if end + 2 <= body.len() {
            &body[end + 2..]
        } else {
            &[]
        };
    }
    out
}

fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || haystack.len() < needle.len() {
        return None;
    }
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

fn header_value(message: &str, header: &str) -> Option<String> {
    for line in message.split('\n') {
        let colon = match line.find(':') {
            Some(colon) if colon > 0 => colon,
            _ => continue,
        };
        if line[..colon].trim().eq_ignore_ascii_case(header) {
            return Some(line[colon + 1..].trim().to_string());
        }
    }
    None
}

// ---- Minimal XML reading --------------------------------------------------
//
// IGD responses carry no same-name nesting in the leaf fields read here, so a
// linear scan that matches local names (namespace prefix and case ignored) is
// enough; no XML library is pulled in.

/// The inner text of the first element whose local name equals `name`, trimmed.
fn tag_text(xml: &str, name: &str) -> Option<String> {
    let (inner_start, inner_end, _) = element_span(xml, name, 0)?;
    Some(xml[inner_start..inner_end].trim().to_string())
}

/// The inner XML of every element whose local name equals `name`.
fn all_elements(xml: &str, name: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut from = 0;
    while let Some((inner_start, inner_end, after)) = element_span(xml, name, from) {
        out.push(xml[inner_start..inner_end].to_string());
        from = after;
        if after <= inner_start {
            from = inner_start + 1; // guard against a stuck scan
        }
    }
    out
}

/// Finds the element whose local name equals `name` at or after `from` and
/// returns `(inner_start, inner_end, after_close)`.
fn element_span(xml: &str, name: &str, from: usize) -> Option<(usize, usize, usize)> {
    let mut index = from;
    loop {
        let open = xml[index..].find('<')? + index;
        let rest = &xml[open + 1..];

        if rest.starts_with('/') || rest.starts_with('!') || rest.starts_with('?') {
            index = open + 1;
            continue;
        }

        let token_end = rest
            .find(|c: char| c.is_whitespace() || c == '>' || c == '/')
            .unwrap_or(rest.len());
        let token = &rest[..token_end];
        let local = token.rsplit(':').next().unwrap_or(token);

        let close_angle = xml[open..].find('>')? + open;
        let self_closing = xml[open..close_angle].trim_end().ends_with('/');

        if local.eq_ignore_ascii_case(name) {
            if self_closing {
                return Some((close_angle, close_angle, close_angle + 1));
            }
            let inner_start = close_angle + 1;
            let close = find_close_tag(xml, name, inner_start)?;
            let close_end = xml[close..].find('>')? + close;
            return Some((inner_start, close, close_end + 1));
        }

        index = close_angle + 1;
    }
}

/// The byte offset of the closing tag `</...name>` (local name match), or
/// `None`.
fn find_close_tag(xml: &str, name: &str, from: usize) -> Option<usize> {
    let mut index = from;
    loop {
        let position = xml[index..].find("</")? + index;
        let rest = &xml[position + 2..];
        let token_end = rest
            .find(|c: char| c.is_whitespace() || c == '>')
            .unwrap_or(rest.len());
        let token = &rest[..token_end];
        let local = token.rsplit(':').next().unwrap_or(token);
        if local.eq_ignore_ascii_case(name) {
            return Some(position);
        }
        index = position + 2;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn spare_port_formula_matches_csharp() {
        // 49152 + port % 16384, and never above the private range.
        assert_eq!(UpnpMapper::spare_port(0), 49152);
        assert_eq!(UpnpMapper::spare_port(6881), 49152 + 6881 % 16384);
        assert_eq!(UpnpMapper::spare_port(16384), 49152);
        assert_eq!(UpnpMapper::spare_port(65535), 49152 + 65535 % 16384);
        for port in [1u16, 80, 443, 6881, 49152, 65535] {
            let spare = UpnpMapper::spare_port(port);
            assert!((49152..=65535).contains(&spare));
        }
    }

    #[test]
    fn reads_leaf_tags_ignoring_prefix_and_case() {
        let xml = "<root><u:NewExternalPort>6881</u:NewExternalPort>\
                   <NewInternalClient>192.168.1.5</NewInternalClient>\
                   <NewEnabled>1</NewEnabled></root>";
        assert_eq!(tag_text(xml, "NewExternalPort").as_deref(), Some("6881"));
        assert_eq!(
            tag_text(xml, "NewInternalClient").as_deref(),
            Some("192.168.1.5")
        );
        assert_eq!(tag_text(xml, "newenabled").as_deref(), Some("1"));
        assert_eq!(tag_text(xml, "Missing"), None);
    }

    #[test]
    fn parses_a_specific_mapping_entry() {
        let xml = "<?xml version=\"1.0\"?><s:Envelope><s:Body>\
            <u:GetSpecificPortMappingEntryResponse>\
            <NewInternalPort>6881</NewInternalPort>\
            <NewInternalClient>192.168.1.5</NewInternalClient>\
            <NewEnabled>1</NewEnabled>\
            <NewPortMappingDescription>StalkNet</NewPortMappingDescription>\
            <NewLeaseDuration>3600</NewLeaseDuration>\
            </u:GetSpecificPortMappingEntryResponse></s:Body></s:Envelope>";
        let entry = parse_entry(xml, Some(6881)).expect("entry parses");
        assert_eq!(entry.external_port, 6881);
        assert_eq!(entry.internal_port, 6881);
        assert_eq!(entry.client, Some(Ipv4Addr::new(192, 168, 1, 5)));
        assert_eq!(entry.description.as_deref(), Some("StalkNet"));
        assert!(entry.enabled);
        assert_eq!(entry.lease_seconds, 3600);
    }

    #[test]
    fn missing_lease_is_minus_one_and_missing_enabled_defaults_on() {
        let xml = "<r><NewInternalPort>80</NewInternalPort>\
                   <NewInternalClient>10.0.0.2</NewInternalClient></r>";
        let entry = parse_entry(xml, Some(80)).expect("entry parses");
        assert_eq!(entry.lease_seconds, -1);
        assert!(entry.enabled); // NewEnabled absent -> not "0" -> true
        assert_eq!(entry.protocol, "TCP");
    }

    #[test]
    fn enumerates_service_blocks() {
        let xml = "<device><serviceList>\
            <service><serviceType>urn:schemas-upnp-org:service:WANIPConnection:1</serviceType>\
            <controlURL>/ctl/IPConn</controlURL></service>\
            <service><serviceType>urn:schemas-upnp-org:service:Layer3Forwarding:1</serviceType>\
            <controlURL>/ctl/L3F</controlURL></service>\
            </serviceList></device>";
        let services = all_elements(xml, "service");
        assert_eq!(services.len(), 2);
        assert_eq!(
            tag_text(&services[0], "serviceType").as_deref(),
            Some("urn:schemas-upnp-org:service:WANIPConnection:1")
        );
        assert_eq!(tag_text(&services[0], "controlURL").as_deref(), Some("/ctl/IPConn"));
    }

    #[test]
    fn summarise_extracts_fault_code_and_text() {
        let fault = "<s:Fault><detail><UPnPError>\
            <errorCode>718</errorCode>\
            <errorDescription>ConflictInMappingEntry</errorDescription>\
            </UPnPError></detail></s:Fault>";
        let mut mapper = UpnpMapper::new();
        let summary = mapper.summarise(fault);
        assert_eq!(summary, "error 718, ConflictInMappingEntry");
        assert_eq!(mapper.last_code(), Some("718"));
    }

    #[test]
    fn combines_relative_and_absolute_control_urls() {
        assert_eq!(
            combine("http://192.168.1.1:5000/desc.xml", "/ctl/IPConn"),
            "http://192.168.1.1:5000/ctl/IPConn"
        );
        assert_eq!(
            combine("http://192.168.1.1:5000/dir/desc.xml", "IPConn"),
            "http://192.168.1.1:5000/dir/IPConn"
        );
        assert_eq!(
            combine("http://192.168.1.1/desc.xml", "http://other/ctl"),
            "http://other/ctl"
        );
    }

    #[test]
    fn parses_url_host_and_port() {
        let url = parse_http_url("http://192.168.1.1:5000/desc.xml").unwrap();
        assert_eq!(url.host, "192.168.1.1");
        assert_eq!(url.port, 5000);
        assert_eq!(url.path, "/desc.xml");

        let url = parse_http_url("http://10.0.0.1/root").unwrap();
        assert_eq!(url.port, 80);
        assert_eq!(url.path, "/root");

        assert!(parse_http_url("ftp://x/").is_none());
    }

    #[test]
    fn header_value_is_case_insensitive() {
        let message = "HTTP/1.1 200 OK\r\nLOCATION: http://192.168.1.1:5000/desc.xml\r\n\r\n";
        assert_eq!(
            header_value(message, "location").as_deref(),
            Some("http://192.168.1.1:5000/desc.xml")
        );
    }

    #[test]
    fn decodes_a_chunked_body() {
        let body = b"4\r\nWiki\r\n5\r\npedia\r\n0\r\n\r\n";
        assert_eq!(decode_chunked(body), b"Wikipedia");
    }

    #[test]
    fn parses_an_http_response_with_content_length() {
        let raw = b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello";
        let (status, body) = parse_http(raw).unwrap();
        assert_eq!(status, 200);
        assert_eq!(body, "hello");
    }
}
