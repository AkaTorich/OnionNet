//! The shared folder service (the C# `FolderService`).
//!
//! It sits on the internal folders port and serves whoever knocked. The state is
//! tied to the stream rather than to a name or an address: two guests never see
//! each other's sign-in, even under the same account; once the stream closed the
//! sign-in went with it and the files closed.
//!
//! It is a [`PortService`], and it can also [`serve`](FolderService::serve) an
//! end-to-end [`MessageChannel`] to a hidden service with the very same protocol.

use super::account_authenticator::{default_authenticator, new_session_salt, AccountAuthenticator, AuthenticatedSession};
use super::auth_outcome::AuthOutcome;
use super::folder_protocol::{self as proto, FolderOp, FolderStatus, MessageReader, MessageWriter};
use super::login_proof;
use super::share_catalog::{ShareCatalog, ShareResult};
use super::shared_folder::SharedFile;
use crate::streams::message_channel::MessageChannel;
use crate::streams::port_stack::{PortService, PortStack, ServerStream};
use crate::streams::stream_payloads::well_known_ports;
use std::collections::HashMap;
use std::io::{Read, Seek, SeekFrom};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

/// How a request handler can fail: either the message did not parse (the C#
/// `EndOfStreamException` → `BadRequest`), or something broke (`ServerError`).
#[derive(Clone, Copy)]
enum Fail {
    BadRequest,
    ServerError,
}

/// Anything the service can answer back over: a port stream or an end-to-end
/// channel. The service notices no difference (the C# `IMessageChannel` plus its
/// `ServerStreamChannel` adapter).
trait Replier {
    fn send(&self, data: &[u8]);
    fn is_open(&self) -> bool;
}

impl Replier for ServerStream {
    fn send(&self, data: &[u8]) {
        ServerStream::send(self, data);
    }
    fn is_open(&self) -> bool {
        ServerStream::is_open(self)
    }
}

impl Replier for dyn MessageChannel {
    fn send(&self, data: &[u8]) {
        MessageChannel::send(self, data);
    }
    fn is_open(&self) -> bool {
        MessageChannel::is_open(self)
    }
}

/// What the service remembers about one guest on one stream.
struct GuestSession {
    windows: Option<AuthenticatedSession>,
    challenge: Option<Vec<u8>>,
    pending_user_name: Option<String>,
    files: HashMap<u32, std::fs::File>,
    next_file_id: u32,
}

impl GuestSession {
    fn new() -> GuestSession {
        GuestSession {
            windows: None,
            challenge: None,
            pending_user_name: None,
            files: HashMap::new(),
            next_file_id: 1,
        }
    }

    fn register(&mut self, file: std::fs::File) -> u32 {
        let id = self.next_file_id;
        self.next_file_id = self.next_file_id.wrapping_add(1);
        self.files.insert(id, file);
        id
    }
}

/// The folder service.
pub struct FolderService {
    catalog: Arc<ShareCatalog>,
    authenticator: Arc<dyn AccountAuthenticator>,
    session_count: AtomicUsize,
}

impl FolderService {
    /// A service over the given catalogue, with the platform's default account
    /// backend (the C# `FolderService(ShareCatalog)`).
    pub fn new(catalog: Arc<ShareCatalog>) -> Arc<FolderService> {
        Self::with_authenticator(catalog, default_authenticator())
    }

    /// A service with a chosen account backend — useful for tests and for a
    /// configured, portable deployment.
    pub fn with_authenticator(catalog: Arc<ShareCatalog>, authenticator: Arc<dyn AccountAuthenticator>) -> Arc<FolderService> {
        Arc::new(FolderService {
            catalog,
            authenticator,
            session_count: AtomicUsize::new(0),
        })
    }

    pub fn catalog(&self) -> &Arc<ShareCatalog> {
        &self.catalog
    }

    pub fn authenticator(&self) -> &Arc<dyn AccountAuthenticator> {
        &self.authenticator
    }

    /// How many guests are connected right now.
    pub fn session_count(&self) -> usize {
        self.session_count.load(Ordering::SeqCst)
    }

    /// Takes the standard folder port in the node's stack (the C# `Bind`).
    pub fn bind(self: &Arc<Self>, stack: &PortStack) {
        stack.bind(well_known_ports::FOLDERS, self.clone());
    }

    /// Serves an end-to-end channel to a hidden service. The same protocol as on
    /// the port. Blocks the thread until the channel closes (the C# `Serve`).
    pub fn serve(&self, channel: Arc<dyn MessageChannel>) {
        let session = Mutex::new(GuestSession::new());
        self.session_count.fetch_add(1, Ordering::SeqCst);

        while channel.is_open() {
            if let Some(data) = channel.receive(Duration::from_secs(1)) {
                let mut guard = session.lock().unwrap();
                self.handle(&*channel, &mut guard, &data);
            }
        }

        self.session_count.fetch_sub(1, Ordering::SeqCst);
        // The session's files close when it drops here.
    }

    // ---- The dispatch --------------------------------------------------------

    fn handle<R: Replier + ?Sized>(&self, replier: &R, session: &mut GuestSession, data: &[u8]) {
        let (op, payload) = match proto::try_read_request(data) {
            Some(parsed) => parsed,
            None => {
                reply(replier, FolderOp::Hello, FolderStatus::BadRequest, |_| {});
                return;
            }
        };

        let outcome = match op {
            FolderOp::Hello => self.do_hello(replier),
            FolderOp::Challenge => self.do_challenge(replier, session, &payload),
            FolderOp::Login => self.do_login(replier, session, &payload),
            FolderOp::ListFiles => self.do_list_files(replier, session, &payload),
            FolderOp::OpenFile => self.do_open_file(replier, session, &payload),
            FolderOp::ReadChunks => self.do_read_chunks(replier, session, &payload),
            FolderOp::CloseFile => self.do_close_file(replier, session, &payload),
        };

        if let Err(fail) = outcome {
            let status = match fail {
                Fail::BadRequest => FolderStatus::BadRequest,
                Fail::ServerError => FolderStatus::ServerError,
            };
            reply(replier, op, status, |_| {});
        }
    }

    // ---- Requests ------------------------------------------------------------

    fn do_hello<R: Replier + ?Sized>(&self, replier: &R) -> Result<(), Fail> {
        let folders = self.catalog.folders();
        // As many folders as fit into one message: a dozen long names would
        // overflow it, and an oversized answer never reaches the guest.
        let header = 2 + 1; // the answer header + the counter
        let mut size = header;
        let mut count = 0usize;
        for folder in folders.iter().take(32) {
            let entry = 1 + folder.alias().len().min(proto::MAX_STRING_BYTES) + 1;
            if size + entry > proto::MAX_MESSAGE_SIZE {
                break;
            }
            size += entry;
            count += 1;
        }
        reply(replier, FolderOp::Hello, FolderStatus::Ok, |w| {
            w.u8(count as u8);
            for folder in folders.iter().take(count) {
                w.text(folder.alias());
                w.u8(folder.access() as u8);
            }
        });
        Ok(())
    }

    fn do_challenge<R: Replier + ?Sized>(&self, replier: &R, session: &mut GuestSession, payload: &[u8]) -> Result<(), Fail> {
        let mut r = MessageReader::new(payload);
        let user_name = r.text().ok_or(Fail::BadRequest)?;

        let salt = new_session_salt();
        let challenge = self.authenticator.issue_challenge(&user_name, &salt);
        session.challenge = Some(challenge.clone());
        session.pending_user_name = Some(user_name);
        let difficulty = self.authenticator.proof_difficulty_bits();

        reply(replier, FolderOp::Challenge, FolderStatus::Ok, |w| {
            w.bytes(&salt);
            w.bytes(&challenge);
            w.u8(difficulty as u8);
        });
        Ok(())
    }

    fn do_login<R: Replier + ?Sized>(&self, replier: &R, session: &mut GuestSession, payload: &[u8]) -> Result<(), Fail> {
        let mut r = MessageReader::new(payload);
        let user_name = r.text().ok_or(Fail::BadRequest)?;
        let password = r.text().ok_or(Fail::BadRequest)?;
        // The C# ReadBytes returns however many are left (capped at the nonce
        // size); a short nonce then fails the proof rather than aborting the parse.
        let remaining = r.rest();
        let nonce = remaining[..remaining.len().min(login_proof::NONCE_SIZE)].to_vec();

        // The challenge must have been issued by us and for this very name.
        let challenge = session.challenge.clone();
        let matches = session
            .pending_user_name
            .as_deref()
            .map(|p| p.eq_ignore_ascii_case(&user_name))
            .unwrap_or(false);

        // The challenge is single-use whatever the outcome.
        session.challenge = None;
        session.pending_user_name = None;

        let challenge = match (challenge, matches) {
            (Some(c), true) => c,
            _ => {
                reply(replier, FolderOp::Login, FolderStatus::BadProof, |_| {});
                return Ok(());
            }
        };

        let (outcome, windows) = self
            .authenticator
            .try_authenticate(&user_name, &password, &challenge, &nonce);

        if outcome != AuthOutcome::Success {
            reply(replier, FolderOp::Login, translate_auth(outcome), |_| {});
            return Ok(());
        }

        let windows = windows.expect("a successful sign-in yields a session");
        let who = windows.user_name().to_string();
        session.windows = Some(windows);
        reply(replier, FolderOp::Login, FolderStatus::Ok, |w| w.text(&who));
        Ok(())
    }

    fn do_list_files<R: Replier + ?Sized>(&self, replier: &R, session: &mut GuestSession, payload: &[u8]) -> Result<(), Fail> {
        let mut r = MessageReader::new(payload);
        let alias = r.text().ok_or(Fail::BadRequest)?;

        match self.catalog.list(&alias, session.windows.as_ref()) {
            Ok(files) => {
                send_file_list(replier, &files);
                Ok(())
            }
            Err(result) => {
                reply(replier, FolderOp::ListFiles, translate_share(result), |_| {});
                Ok(())
            }
        }
    }

    fn do_open_file<R: Replier + ?Sized>(&self, replier: &R, session: &mut GuestSession, payload: &[u8]) -> Result<(), Fail> {
        let mut r = MessageReader::new(payload);
        let alias = r.text().ok_or(Fail::BadRequest)?;
        let file_name = r.text().ok_or(Fail::BadRequest)?;

        if session.files.len() >= proto::MAX_OPEN_FILES_PER_SESSION {
            reply(replier, FolderOp::OpenFile, FolderStatus::TooManyFiles, |_| {});
            return Ok(());
        }

        match self.catalog.open_read(&alias, &file_name, session.windows.as_ref()) {
            Ok((file, size)) => {
                let file_id = session.register(file);
                reply(replier, FolderOp::OpenFile, FolderStatus::Ok, |w| {
                    w.u32_le(file_id);
                    w.i64_le(size as i64);
                });
                Ok(())
            }
            Err(result) => {
                reply(replier, FolderOp::OpenFile, translate_share(result), |_| {});
                Ok(())
            }
        }
    }

    fn do_read_chunks<R: Replier + ?Sized>(&self, replier: &R, session: &mut GuestSession, payload: &[u8]) -> Result<(), Fail> {
        let mut r = MessageReader::new(payload);
        let file_id = r.u32_le().ok_or(Fail::BadRequest)?;
        let start_chunk = r.i32_le().ok_or(Fail::BadRequest)?;
        let count = r.u16_le().ok_or(Fail::BadRequest)?;

        let file = match session.files.get_mut(&file_id) {
            Some(f) => f,
            None => {
                reply(replier, FolderOp::ReadChunks, FolderStatus::NoSuchFile, |_| {});
                return Ok(());
            }
        };

        if start_chunk < 0 || count == 0 {
            reply(replier, FolderOp::ReadChunks, FolderStatus::BadRequest, |_| {});
            return Ok(());
        }

        let count = count.min(proto::MAX_CHUNKS_PER_REQUEST);
        let length = file.metadata().map_err(|_| Fail::ServerError)?.len() as i64;
        let offset = start_chunk as i64 * proto::CHUNK_SIZE as i64;
        if offset > length {
            reply(replier, FolderOp::ReadChunks, FolderStatus::BadRequest, |_| {});
            return Ok(());
        }

        file.seek(SeekFrom::Start(offset as u64)).map_err(|_| Fail::ServerError)?;

        let mut buffer = vec![0u8; proto::CHUNK_SIZE];
        for i in 0..count {
            if !replier.is_open() {
                return Ok(());
            }

            let read = read_fully(file, &mut buffer).map_err(|_| Fail::ServerError)?;
            if read == 0 {
                break;
            }

            replier.send(&proto::chunk(start_chunk + i as i32, &buffer, 0, read));
            if read < buffer.len() {
                break; // we reached the end of the file
            }
        }
        Ok(())
    }

    fn do_close_file<R: Replier + ?Sized>(&self, replier: &R, session: &mut GuestSession, payload: &[u8]) -> Result<(), Fail> {
        let mut r = MessageReader::new(payload);
        let file_id = r.u32_le().ok_or(Fail::BadRequest)?;
        session.files.remove(&file_id); // the file closes on drop
        reply(replier, FolderOp::CloseFile, FolderStatus::Ok, |_| {});
        Ok(())
    }
}

impl PortService for FolderService {
    fn on_open(&self, stream: Arc<ServerStream>) -> bool {
        stream.set_state(Box::new(Mutex::new(GuestSession::new())));
        self.session_count.fetch_add(1, Ordering::SeqCst);
        true
    }

    fn on_data(&self, stream: &Arc<ServerStream>, data: &[u8]) {
        stream.with_state::<Mutex<GuestSession>, ()>(|session| {
            let mut guard = session.lock().unwrap();
            self.handle(&**stream, &mut guard, data);
        });
    }

    fn on_close(&self, stream: &Arc<ServerStream>) {
        if stream.take_state().is_some() {
            self.session_count.fetch_sub(1, Ordering::SeqCst);
        }
        // The taken state (and its files) drops here.
    }
}

// ---- The file list, sliced into cells ----------------------------------------

/// The list may not fit into one cell, so it is sliced into batches. The last
/// cell is marked with a zero continuation flag (the C# `SendFileList`).
fn send_file_list<R: Replier + ?Sized>(replier: &R, files: &[SharedFile]) {
    let mut position = 0usize;

    loop {
        let header = 2 + 1 + 1; // the answer header + the flag + the counter
        let mut size = header;
        let batch_start = position;

        while position < files.len() {
            let name_bytes = files[position].name().as_bytes().len();
            let entry_size = 1 + name_bytes + 8 + 8 + 1;
            // A name longer than a cell's string limit, or that overflows the
            // cell, ends the batch.
            if name_bytes > proto::MAX_STRING_BYTES || size + entry_size > proto::MAX_MESSAGE_SIZE {
                break;
            }
            size += entry_size;
            position += 1;
        }

        // A single entry too large to fit anywhere is skipped.
        if position == batch_start && position < files.len() {
            position += 1;
            continue;
        }

        let more = position < files.len();
        let batch = &files[batch_start..position];
        reply(replier, FolderOp::ListFiles, FolderStatus::Ok, |w| {
            w.bool(more);
            w.u8(batch.len() as u8);
            for file in batch {
                w.text(file.name());
                w.i64_le(file.size());
                w.i64_le(file.modified_ticks());
                w.bool(file.is_directory());
            }
        });

        if !more {
            return;
        }
    }
}

// ---- Helpers -----------------------------------------------------------------

fn reply<R: Replier + ?Sized, F: FnOnce(&mut MessageWriter)>(replier: &R, op: FolderOp, status: FolderStatus, body: F) {
    if !replier.is_open() {
        return;
    }
    replier.send(&proto::response(op, status, body));
}

fn read_fully(file: &mut std::fs::File, buffer: &mut [u8]) -> std::io::Result<usize> {
    let mut filled = 0;
    while filled < buffer.len() {
        let read = file.read(&mut buffer[filled..])?;
        if read == 0 {
            break;
        }
        filled += read;
    }
    Ok(filled)
}

fn translate_share(result: ShareResult) -> FolderStatus {
    match result {
        ShareResult::Ok => FolderStatus::Ok,
        ShareResult::LoginRequired => FolderStatus::NeedLogin,
        ShareResult::Denied => FolderStatus::Denied,
        ShareResult::NoSuchFolder => FolderStatus::NoSuchFolder,
        ShareResult::BadName => FolderStatus::BadRequest,
        ShareResult::Missing => FolderStatus::NoSuchFile,
        // An unknown outcome must not pass itself off as "there is no such file".
        ShareResult::Impersonation => FolderStatus::ServerError,
    }
}

fn translate_auth(outcome: AuthOutcome) -> FolderStatus {
    match outcome {
        AuthOutcome::Success => FolderStatus::Ok,
        AuthOutcome::Throttled => FolderStatus::Throttled,
        AuthOutcome::BadProof => FolderStatus::BadProof,
        _ => FolderStatus::Denied,
    }
}
