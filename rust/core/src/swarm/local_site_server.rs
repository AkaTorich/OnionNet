//! Shows a downloaded site in an ordinary browser: a small web server on the
//! loopback address, files only, reading only.
//!
//! The danger here is the site itself. A page from a stranger that pulled a
//! picture from somebody's server outside would have the browser fetch it
//! directly — and hand that server the reader's real address, past the whole
//! network. So every answer carries a rule the browser enforces: nothing from
//! anywhere but this very site. Every site gets a port of its own, so two sites
//! are two strangers to the browser as well.

use std::io::{Read, Write};
use std::net::{Ipv4Addr, TcpListener, TcpStream};
use std::path::{Component, Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

const POLICY: &str = "default-src 'none'; img-src 'self' data:; media-src 'self'; style-src 'self' 'unsafe-inline'; \
font-src 'self'; script-src 'self'; connect-src 'self'; frame-src 'self'; \
form-action 'self'; base-uri 'self'; frame-ancestors 'self'";

pub struct LocalSiteServer {
    root: PathBuf,
    port: u16,
    stopping: Arc<AtomicBool>,
}

impl LocalSiteServer {
    pub fn new(root: impl AsRef<Path>) -> LocalSiteServer {
        LocalSiteServer {
            root: absolute_lexical(root.as_ref()),
            port: 0,
            stopping: Arc::new(AtomicBool::new(false)),
        }
    }

    pub fn port(&self) -> u16 {
        self.port
    }

    pub fn url(&self) -> String {
        format!("http://127.0.0.1:{}/", self.port)
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    pub fn start(&mut self) -> std::io::Result<()> {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))?;
        self.port = listener.local_addr()?.port();

        let root = self.root.clone();
        let stopping = self.stopping.clone();
        thread::Builder::new()
            .name(format!("stalknet-site-{}", self.port))
            .spawn(move || accept_loop(listener, root, stopping))?;
        Ok(())
    }

    /// Stops accepting connections. Idempotent; also called on drop.
    pub fn stop(&self) {
        if self.stopping.swap(true, Ordering::SeqCst) {
            return;
        }
        // Wake the accept loop out of its blocking `accept`.
        if self.port != 0 {
            let _ = TcpStream::connect((Ipv4Addr::LOCALHOST, self.port));
        }
    }
}

impl Drop for LocalSiteServer {
    fn drop(&mut self) {
        self.stop();
    }
}

fn accept_loop(listener: TcpListener, root: PathBuf, stopping: Arc<AtomicBool>) {
    while !stopping.load(Ordering::SeqCst) {
        let client = match listener.accept() {
            Ok((stream, _)) => stream,
            Err(_) => return,
        };
        if stopping.load(Ordering::SeqCst) {
            return;
        }
        let root = root.clone();
        let _ = thread::Builder::new()
            .name("stalknet-site-page".into())
            .spawn(move || serve(client, root));
    }
}

fn serve(mut client: TcpStream, root: PathBuf) {
    let _ = client.set_read_timeout(Some(Duration::from_secs(10)));
    let _ = client.set_write_timeout(Some(Duration::from_secs(30)));

    let request_line = match read_head(&mut client) {
        Some(line) => line,
        None => return,
    };

    let parts: Vec<&str> = request_line.split(' ').collect();
    if parts.len() < 3 || !parts[2].starts_with("HTTP/") {
        answer(&mut client, 400, "Bad Request", None, false);
        return;
    }

    let head = parts[0] == "HEAD";
    if parts[0] != "GET" && !head {
        answer(&mut client, 405, "Method Not Allowed", None, false);
        return;
    }

    let path = match resolve(&root, parts[1]) {
        Some(p) => p,
        None => {
            answer(&mut client, 404, "Not Found", None, head);
            return;
        }
    };

    let content_type = mime_type(&path);
    let bytes = match std::fs::read(&path) {
        Ok(b) => b,
        Err(_) => {
            // The browser went away, or the file vanished mid-answer.
            return;
        }
    };

    write_headers(&mut client, 200, "OK", content_type, bytes.len() as u64);
    if !head {
        let _ = client.write_all(&bytes);
    }
}

/// The file a request path leads to, or `None`. Never anything outside the
/// site's folder.
fn resolve(root: &Path, target: &str) -> Option<PathBuf> {
    let mut target = target;
    if let Some(cut) = target.find(['?', '#']) {
        target = &target[..cut];
    }
    if !target.starts_with('/') {
        return None;
    }

    let mut relative = percent_decode(target);
    relative = relative.trim_start_matches('/').to_string();

    if relative.is_empty() || relative.ends_with('/') {
        relative.push_str("index.html");
    }
    if relative.contains('\\') || relative.contains(':') || relative.contains('\0') {
        return None;
    }

    let full = absolute_lexical(&root.join(relative.replace('/', std::path::MAIN_SEPARATOR_STR)));

    let prefix = with_trailing_sep(root);
    let full_str = full.to_string_lossy();
    // `get` rather than slicing: a cut inside a multi-byte letter (Cyrillic
    // paths) must refuse, not panic.
    if !full_str.get(..prefix.len()).is_some_and(|head| head.eq_ignore_ascii_case(&prefix)) {
        return None;
    }

    let full = if full.is_dir() { full.join("index.html") } else { full };
    if full.is_file() {
        Some(full)
    } else {
        None
    }
}

/// Reads the request head up to the empty line. Only the first line matters.
fn read_head(stream: &mut TcpStream) -> Option<String> {
    let mut head: Vec<u8> = Vec::new();
    let mut one = [0u8; 1];

    while head.len() < 8192 {
        match stream.read(&mut one) {
            Ok(0) | Err(_) => return None,
            Ok(_) => {}
        }
        head.push(one[0]);

        let n = head.len();
        if n >= 4 && &head[n - 4..] == b"\r\n\r\n" {
            let text = String::from_utf8_lossy(&head);
            let end = text.find("\r\n")?;
            return Some(text[..end].to_string());
        }
    }

    None
}

fn answer(stream: &mut TcpStream, code: u16, reason: &str, body: Option<&str>, head: bool) {
    let body = body.map(|b| b.to_string()).unwrap_or_else(|| format!("{code} {reason}"));
    let bytes = body.into_bytes();
    write_headers(stream, code, reason, "text/plain; charset=utf-8", bytes.len() as u64);
    if !head {
        let _ = stream.write_all(&bytes);
    }
}

fn write_headers(stream: &mut TcpStream, code: u16, reason: &str, content_type: &str, length: u64) {
    let text = format!(
        "HTTP/1.1 {code} {reason}\r\n\
         Content-Type: {content_type}\r\n\
         Content-Length: {length}\r\n\
         Content-Security-Policy: {POLICY}\r\n\
         X-Content-Type-Options: nosniff\r\n\
         Referrer-Policy: no-referrer\r\n\
         Cache-Control: no-store\r\n\
         Connection: close\r\n\r\n"
    );
    let _ = stream.write_all(text.as_bytes());
}

fn mime_type(path: &Path) -> &'static str {
    let ext = path.extension().and_then(|e| e.to_str()).unwrap_or("").to_ascii_lowercase();
    match ext.as_str() {
        "html" | "htm" => "text/html; charset=utf-8",
        "css" => "text/css; charset=utf-8",
        "js" => "text/javascript; charset=utf-8",
        "json" => "application/json",
        "txt" => "text/plain; charset=utf-8",
        "xml" => "application/xml",
        "svg" => "image/svg+xml",
        "png" => "image/png",
        "jpg" | "jpeg" => "image/jpeg",
        "gif" => "image/gif",
        "webp" => "image/webp",
        "ico" => "image/x-icon",
        "pdf" => "application/pdf",
        "mp3" => "audio/mpeg",
        "ogg" => "audio/ogg",
        "wav" => "audio/wav",
        "mp4" => "video/mp4",
        "webm" => "video/webm",
        "woff" => "font/woff",
        "woff2" => "font/woff2",
        "ttf" => "font/ttf",
        "wasm" => "application/wasm",
        _ => "application/octet-stream",
    }
}

/// Decodes `%XX` escapes to bytes and reads them back as UTF-8, like
/// `Uri.UnescapeDataString` for a path.
fn percent_decode(text: &str) -> String {
    let bytes = text.as_bytes();
    let mut out: Vec<u8> = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            if let (Some(h), Some(l)) = (hex_val(bytes[i + 1]), hex_val(bytes[i + 2])) {
                out.push((h << 4) | l);
                i += 3;
                continue;
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn hex_val(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        b'A'..=b'F' => Some(c - b'A' + 10),
        _ => None,
    }
}

fn absolute_lexical(path: &Path) -> PathBuf {
    let base = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir().map(|cwd| cwd.join(path)).unwrap_or_else(|_| path.to_path_buf())
    };
    let mut out = PathBuf::new();
    for component in base.components() {
        match component {
            Component::ParentDir => {
                out.pop();
            }
            Component::CurDir => {}
            other => out.push(other.as_os_str()),
        }
    }
    out
}

fn with_trailing_sep(path: &Path) -> String {
    let mut s = path.to_string_lossy().into_owned();
    if !s.ends_with(std::path::MAIN_SEPARATOR) {
        s.push(std::path::MAIN_SEPARATOR);
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{BufRead, BufReader};

    fn temp_dir(name: &str) -> PathBuf {
        let mut p = std::env::temp_dir();
        p.push(format!("stalknet_site_{}_{}", std::process::id(), name));
        let _ = std::fs::remove_dir_all(&p);
        std::fs::create_dir_all(&p).unwrap();
        p
    }

    #[test]
    fn resolve_stays_inside_the_root() {
        let root = temp_dir("resolve");
        std::fs::write(root.join("index.html"), b"home").unwrap();
        std::fs::create_dir_all(root.join("assets")).unwrap();
        std::fs::write(root.join("assets").join("a.css"), b"body{}").unwrap();

        assert!(resolve(&root, "/").is_some()); // -> index.html
        assert!(resolve(&root, "/assets/a.css").is_some());
        assert!(resolve(&root, "/missing.txt").is_none());
        // Escapes and traversal are refused.
        assert!(resolve(&root, "/../secret").is_none());
        assert!(resolve(&root, "/..\\secret").is_none());
        assert!(resolve(&root, "bad").is_none()); // no leading slash

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn serves_a_file_over_http() {
        let root = temp_dir("http");
        std::fs::write(root.join("index.html"), b"<h1>hi</h1>").unwrap();

        let mut server = LocalSiteServer::new(&root);
        server.start().unwrap();
        let url_port = server.port();
        assert!(url_port != 0);

        let mut stream = TcpStream::connect((Ipv4Addr::LOCALHOST, url_port)).unwrap();
        stream.write_all(b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n").unwrap();

        let mut reader = BufReader::new(stream);
        let mut status = String::new();
        reader.read_line(&mut status).unwrap();
        assert!(status.starts_with("HTTP/1.1 200"), "got: {status}");

        let mut saw_csp = false;
        loop {
            let mut line = String::new();
            reader.read_line(&mut line).unwrap();
            if line == "\r\n" || line.is_empty() {
                break;
            }
            if line.starts_with("Content-Security-Policy:") {
                saw_csp = true;
            }
        }
        assert!(saw_csp, "the CSP header must be present");

        server.stop();
        let _ = std::fs::remove_dir_all(&root);
    }
}
