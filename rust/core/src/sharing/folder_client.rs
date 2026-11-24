//! A guest of somebody else's folder (the C# `FolderClient` and `RemoteFolder`).
//!
//! It travels over a channel to the service at the far end. Every conversation
//! goes inside an already built circuit, so the folder's owner will not learn who
//! came, and the nodes in between will not learn what for. It works over any
//! [`MessageChannel`]: an ordinary stream to a node's folders port, or an
//! end-to-end channel to a hidden service. It notices no difference.

use super::folder_protocol::{self as proto, FolderOp, FolderStatus, MessageReader};
use super::login_proof;
use super::shared_folder::{ShareAccess, SharedFile};
use crate::streams::message_channel::MessageChannel;
use crate::streams::stream_opener::StreamOpener;
use crate::streams::stream_payloads::well_known_ports;
use crate::text::{t, t_args};
use std::io::Write;
use std::sync::{Arc, Mutex};
use std::time::Duration;

const DEFAULT_TIMEOUT: Duration = Duration::from_secs(30);

/// Somebody else's folder as it is seen over the network.
#[derive(Debug, Clone)]
pub struct RemoteFolder {
    alias: String,
    access: ShareAccess,
}

impl RemoteFolder {
    pub fn new(alias: String, access: ShareAccess) -> RemoteFolder {
        RemoteFolder { alias, access }
    }

    pub fn alias(&self) -> &str {
        &self.alias
    }

    pub fn access(&self) -> ShareAccess {
        self.access
    }
}

impl std::fmt::Display for RemoteFolder {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let access = t(match self.access {
            ShareAccess::Public => "folder.remote.public",
            ShareAccess::WindowsAccounts => "folder.remote.login",
        });
        write!(f, "{}", t_args("folder.summary", &[&self.alias, &access]))
    }
}

/// A guest of somebody else's folder.
pub struct FolderClient {
    stream: Arc<dyn MessageChannel>,
    timeout: Mutex<Duration>,
    logged_in_as: Mutex<Option<String>>,
}

impl FolderClient {
    /// Over any channel: an ordinary stream to a node's port, or an end-to-end
    /// channel to a hidden service.
    pub fn new(channel: Arc<dyn MessageChannel>) -> FolderClient {
        FolderClient {
            stream: channel,
            timeout: Mutex::new(DEFAULT_TIMEOUT),
            logged_in_as: Mutex::new(None),
        }
    }

    /// Opens a stream to the standard folders port and wraps it in a client. The
    /// C# `Connect(MultiplexedCircuit)`, here over any [`StreamOpener`]. `None` if
    /// the port is closed.
    pub fn connect(opener: &dyn StreamOpener) -> Option<FolderClient> {
        let channel = opener.open(well_known_ports::FOLDERS)?;
        Some(FolderClient::new(channel))
    }

    pub fn is_open(&self) -> bool {
        self.stream.is_open()
    }

    pub fn close(&self) {
        self.stream.close();
    }

    pub fn timeout(&self) -> Duration {
        *self.timeout.lock().unwrap()
    }

    pub fn set_timeout(&self, timeout: Duration) {
        *self.timeout.lock().unwrap() = timeout;
    }

    /// Whom we managed to sign in as. `None` until a sign-in is made.
    pub fn logged_in_as(&self) -> Option<String> {
        self.logged_in_as.lock().unwrap().clone()
    }

    // ---- Introductions -------------------------------------------------------

    /// Asks which folders are open here.
    pub fn hello(&self) -> Result<Vec<RemoteFolder>, FolderStatus> {
        let (status, payload) = self.ask(FolderOp::Hello, |_| {}).ok_or(FolderStatus::ServerError)?;
        if status != FolderStatus::Ok {
            return Err(status);
        }

        let mut r = MessageReader::new(&payload);
        let count = r.u8().ok_or(FolderStatus::ServerError)?;
        let mut folders = Vec::with_capacity(count as usize);
        for _ in 0..count {
            let alias = r.text().ok_or(FolderStatus::ServerError)?;
            let access = ShareAccess::from_u8(r.u8().ok_or(FolderStatus::ServerError)?).unwrap_or(ShareAccess::WindowsAccounts);
            folders.push(RemoteFolder::new(alias, access));
        }
        Ok(folders)
    }

    // ---- Signing in ----------------------------------------------------------

    /// Signs in with an account of the folder's owner.
    ///
    /// First we take a challenge and solve the Argon2id pass — deliberately slow,
    /// but then guessing at the password costs memory on every attempt. The
    /// password travels inside the already encrypted channel and surfaces only on
    /// the owner's machine.
    pub fn login(&self, user_name: &str, password: &str) -> FolderStatus {
        let (status, payload) = match self.ask(FolderOp::Challenge, |w| w.text(user_name)) {
            Some(answer) => answer,
            None => return FolderStatus::ServerError,
        };
        if status != FolderStatus::Ok {
            return status;
        }

        let (challenge, difficulty) = {
            let mut r = MessageReader::new(&payload);
            if r.take(16).is_none() {
                // the session salt, only the owner needs it
                return FolderStatus::ServerError;
            }
            let challenge = match r.take(login_proof::CHALLENGE_SIZE) {
                Some(c) => c.to_vec(),
                None => return FolderStatus::ServerError,
            };
            let difficulty = match r.u8() {
                Some(d) => d as u32,
                None => return FolderStatus::ServerError,
            };
            (challenge, difficulty)
        };

        let nonce = match login_proof::solve(&challenge, difficulty) {
            Some(n) => n,
            None => return FolderStatus::BadProof,
        };

        let (status, payload) = match self.ask(FolderOp::Login, |w| {
            w.text(user_name);
            w.text(password);
            w.bytes(&nonce);
        }) {
            Some(answer) => answer,
            None => return FolderStatus::ServerError,
        };
        if status != FolderStatus::Ok {
            return status;
        }

        let mut r = MessageReader::new(&payload);
        if let Some(name) = r.text() {
            *self.logged_in_as.lock().unwrap() = Some(name);
        }
        FolderStatus::Ok
    }

    // ---- Contents ------------------------------------------------------------

    pub fn list_files(&self, alias: &str) -> Result<Vec<SharedFile>, FolderStatus> {
        let (status, payload) = self
            .ask(FolderOp::ListFiles, |w| w.text(alias))
            .ok_or(FolderStatus::ServerError)?;
        if status != FolderStatus::Ok {
            return Err(status);
        }

        let mut collected = Vec::new();
        let mut more = read_file_batch(&payload, &mut collected).ok_or(FolderStatus::ServerError)?;

        // A long list comes as a batch of cells — we read the rest.
        while more {
            let next = self.stream.receive(self.timeout()).ok_or(FolderStatus::ServerError)?;
            let (op, status, payload) = proto::try_read_response(&next).ok_or(FolderStatus::ServerError)?;
            if op != FolderOp::ListFiles || status != FolderStatus::Ok {
                return Err(status);
            }
            more = read_file_batch(&payload, &mut collected).ok_or(FolderStatus::ServerError)?;
        }

        Ok(collected)
    }

    // ---- Files ---------------------------------------------------------------

    pub fn open_file(&self, alias: &str, file_name: &str) -> Result<(u32, u64), FolderStatus> {
        let (status, payload) = self
            .ask(FolderOp::OpenFile, |w| {
                w.text(alias);
                w.text(file_name);
            })
            .ok_or(FolderStatus::ServerError)?;
        if status != FolderStatus::Ok {
            return Err(status);
        }

        let mut r = MessageReader::new(&payload);
        let file_id = r.u32_le().ok_or(FolderStatus::ServerError)?;
        let size = r.i64_le().ok_or(FolderStatus::ServerError)?;
        Ok((file_id, size.max(0) as u64))
    }

    /// Downloads an open file into a sink. The pieces are asked for in batches:
    /// one round trip per thirty-two pieces, over a real circuit of three nodes a
    /// far cheaper trade than a round trip per half-kilobyte.
    pub fn download<W: Write, P: FnMut(u64, u64)>(
        &self,
        file_id: u32,
        size: u64,
        destination: &mut W,
        mut progress: P,
    ) -> FolderStatus {
        let chunk_size = proto::CHUNK_SIZE as u64;
        let total_chunks = size.div_ceil(chunk_size);
        let mut received: u64 = 0;
        let mut next_chunk: u64 = 0;

        while next_chunk < total_chunks {
            let want = (proto::MAX_CHUNKS_PER_REQUEST as u64).min(total_chunks - next_chunk) as u16;
            let start = next_chunk as i32;

            self.stream.send(&proto::request(FolderOp::ReadChunks, |w| {
                w.u32_le(file_id);
                w.i32_le(start);
                w.u16_le(want);
            }));

            for _ in 0..want {
                let cell = match self.stream.receive(self.timeout()) {
                    Some(c) => c,
                    None => return FolderStatus::ServerError,
                };

                match proto::try_read_chunk(&cell) {
                    Some((index, content)) => {
                        if index as i64 != next_chunk as i64 {
                            return FolderStatus::ServerError;
                        }
                        if destination.write_all(&content).is_err() {
                            return FolderStatus::ServerError;
                        }
                        received += content.len() as u64;
                        next_chunk += 1;
                        progress(received, size);

                        if content.len() < proto::CHUNK_SIZE {
                            return FolderStatus::Ok; // we reached the end of the file
                        }
                    }
                    None => {
                        // A refusal came instead of a piece — we parse it.
                        if let Some((_, status, _)) = proto::try_read_response(&cell) {
                            return status;
                        }
                        return FolderStatus::ServerError;
                    }
                }
            }
        }

        FolderStatus::Ok
    }

    pub fn close_file(&self, file_id: u32) -> FolderStatus {
        match self.ask(FolderOp::CloseFile, |w| w.u32_le(file_id)) {
            Some((status, _)) => status,
            None => FolderStatus::ServerError,
        }
    }

    /// Opens, downloads and closes a file in one call.
    pub fn fetch<W: Write, P: FnMut(u64, u64)>(
        &self,
        alias: &str,
        file_name: &str,
        destination: &mut W,
        progress: P,
    ) -> FolderStatus {
        let (file_id, size) = match self.open_file(alias, file_name) {
            Ok(opened) => opened,
            Err(status) => return status,
        };

        let status = self.download(file_id, size, destination, progress);
        let _ = self.close_file(file_id);
        status
    }

    // ---- The exchange --------------------------------------------------------

    fn ask<F: FnOnce(&mut proto::MessageWriter)>(&self, op: FolderOp, body: F) -> Option<(FolderStatus, Vec<u8>)> {
        if !self.stream.is_open() {
            return None;
        }
        self.stream.send(&proto::request(op, body));

        let answer = self.stream.receive(self.timeout())?;
        let (answered_op, status, payload) = proto::try_read_response(&answer)?;
        if answered_op != op {
            return None;
        }
        Some((status, payload))
    }

    /// A refusal in plain words (the C# `Explain`).
    pub fn explain(status: FolderStatus) -> String {
        match status {
            FolderStatus::Ok => t("folder.status.ok"),
            FolderStatus::NeedLogin => t("folder.status.needlogin"),
            FolderStatus::Denied => t("folder.status.denied"),
            FolderStatus::NoSuchFolder => t("folder.status.nofolder"),
            FolderStatus::NoSuchFile => t("folder.status.nofile"),
            FolderStatus::BadRequest => t("folder.status.badrequest"),
            FolderStatus::Throttled => t("folder.status.throttled"),
            FolderStatus::BadProof => t("folder.status.badproof"),
            FolderStatus::TooManyFiles => t("folder.status.toomanyfiles"),
            _ => t("folder.status.other"),
        }
    }
}

/// Reads one batch of the file list, appending to `destination`. Returns whether
/// more batches follow, or `None` if the batch was malformed. The C#
/// `ReadFileBatch`.
fn read_file_batch(payload: &[u8], destination: &mut Vec<SharedFile>) -> Option<bool> {
    let mut r = MessageReader::new(payload);
    let more = r.bool()?;
    let count = r.u8()?;

    for _ in 0..count {
        let name = r.text()?;
        let size = r.i64_le()?;
        let ticks = r.i64_le()?;
        let is_directory = r.bool()?;
        destination.push(SharedFile::new(name, size, ticks, is_directory));
    }

    Some(more)
}
