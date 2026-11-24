//! Shared folders (`StalkNet.Core/Sharing`).
//!
//! A node may publish folders to the network. A guest reaches the folder service
//! over a circuit ([`FolderClient`] ↔ [`FolderService`]), optionally signing in
//! with a local OS account; the service lists and streams the contents while
//! hidden, system and dot files are never shown or sent. The folder-protocol wire
//! format and the memory-hard login-proof construction are kept byte-identical to
//! the C# original.
//!
//! The layout mirrors the C# file split. The platform-specific pieces — signing
//! in against a real OS account, reading the machine's SMB shares, and the shell
//! context-menu item — live behind `#[cfg(windows)]` (and a cargo feature) with a
//! portable fallback or a graceful no-op everywhere else, so the crate builds on
//! Windows, Linux and macOS alike.

pub mod account_authenticator;
pub mod account_store;
pub mod auth_outcome;
pub mod explorer_integration;
pub mod folder_client;
pub mod folder_protocol;
pub mod folder_service;
pub mod login_proof;
pub mod share_catalog;
pub mod shared_folder;
pub mod windows_share_reader;

pub use account_authenticator::{
    default_authenticator, new_session_salt, AccountAuthenticator, AuthenticatedSession, MemoryAccountAuthenticator,
};
pub use auth_outcome::AuthOutcome;
pub use folder_client::{FolderClient, RemoteFolder};
pub use folder_protocol::{
    FolderOp, FolderStatus, MessageReader, MessageWriter, CHUNK_SIZE, MAX_CHUNKS_PER_REQUEST, MAX_MESSAGE_SIZE,
    MAX_OPEN_FILES_PER_SESSION, MAX_STRING_BYTES,
};
pub use folder_service::FolderService;
pub use login_proof::{
    build_challenge, solve, solve_cancellable, verify, CHALLENGE_SIZE, DEFAULT_DIFFICULTY_BITS, NONCE_SIZE,
};
pub use share_catalog::{ShareCatalog, ShareResult};
pub use shared_folder::{ShareAccess, ShareOrigin, SharedFile, SharedFolder};

#[cfg(test)]
mod loopback_tests {
    use super::*;
    use crate::streams::message_channel::MessageChannel;
    use std::collections::VecDeque;
    use std::io::Write;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::{Arc, Condvar, Mutex};
    use std::time::Duration;

    // ---- An in-memory MessageChannel pair -----------------------------------

    struct Inbox {
        queue: Mutex<VecDeque<Vec<u8>>>,
        cv: Condvar,
    }

    impl Inbox {
        fn new() -> Arc<Inbox> {
            Arc::new(Inbox {
                queue: Mutex::new(VecDeque::new()),
                cv: Condvar::new(),
            })
        }
    }

    struct PipeEnd {
        inbox: Arc<Inbox>,
        outbox: Arc<Inbox>,
        open: Arc<AtomicBool>,
    }

    impl MessageChannel for PipeEnd {
        fn send(&self, message: &[u8]) {
            if !self.open.load(Ordering::Acquire) {
                return;
            }
            self.outbox.queue.lock().unwrap().push_back(message.to_vec());
            self.outbox.cv.notify_one();
        }

        fn receive(&self, timeout: Duration) -> Option<Vec<u8>> {
            let mut queue = self.inbox.queue.lock().unwrap();
            loop {
                if let Some(message) = queue.pop_front() {
                    return Some(message);
                }
                if !self.open.load(Ordering::Acquire) {
                    return None;
                }
                let (guard, result) = self.inbox.cv.wait_timeout(queue, timeout).unwrap();
                queue = guard;
                if result.timed_out() {
                    return queue.pop_front();
                }
            }
        }

        fn is_open(&self) -> bool {
            self.open.load(Ordering::Acquire)
        }

        fn close(&self) {
            self.open.store(false, Ordering::Release);
            self.inbox.cv.notify_all();
            self.outbox.cv.notify_all();
        }
    }

    fn pipe() -> (PipeEnd, PipeEnd) {
        let a = Inbox::new();
        let b = Inbox::new();
        let open = Arc::new(AtomicBool::new(true));
        (
            PipeEnd { inbox: a.clone(), outbox: b.clone(), open: open.clone() },
            PipeEnd { inbox: b, outbox: a, open },
        )
    }

    // ---- The scratch folder --------------------------------------------------

    fn scratch(tag: &str) -> PathBuf {
        let mut dir = std::env::temp_dir();
        dir.push(format!("stalknet_sharing_{}_{}", tag, std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn loopback_hello_list_and_download() {
        let dir = scratch("loop");
        // A file that spans several chunks, and a small one.
        let big: Vec<u8> = (0..(proto_chunk() * 3 + 7)).map(|i| (i % 251) as u8).collect();
        std::fs::File::create(dir.join("big.bin")).unwrap().write_all(&big).unwrap();
        std::fs::File::create(dir.join("small.txt")).unwrap().write_all(b"hello").unwrap();
        std::fs::File::create(dir.join(".hidden")).unwrap().write_all(b"no").unwrap();

        let catalog = Arc::new(ShareCatalog::new());
        catalog.set_follow_windows_shares(false);
        catalog.add(dir.to_str().unwrap(), "Pub", ShareAccess::Public).unwrap();

        let auth = Arc::new(MemoryAccountAuthenticator::new());
        auth.set_proof_difficulty_bits(0);
        let service = FolderService::with_authenticator(catalog, auth);

        let (server, client_end) = pipe();
        let server = Arc::new(server);
        let worker = {
            let service = service.clone();
            std::thread::spawn(move || service.serve(server))
        };

        let client = FolderClient::new(Arc::new(client_end));

        // Hello
        let folders = client.hello().unwrap();
        assert_eq!(folders.len(), 1);
        assert_eq!(folders[0].alias(), "Pub");
        assert_eq!(folders[0].access(), ShareAccess::Public);

        // List — the dotfile is filtered out.
        let files = client.list_files("Pub").unwrap();
        let mut names: Vec<&str> = files.iter().map(|f| f.name()).collect();
        names.sort();
        assert_eq!(names, vec!["big.bin", "small.txt"]);

        // Download the multi-chunk file and compare byte for byte.
        let mut got = Vec::new();
        let status = client.fetch("Pub", "big.bin", &mut got, |_, _| {});
        assert_eq!(status, FolderStatus::Ok);
        assert_eq!(got, big);

        // A hidden file cannot be had by name either.
        let mut sink = Vec::new();
        assert_eq!(client.fetch("Pub", ".hidden", &mut sink, |_, _| {}), FolderStatus::NoSuchFile);

        client.close();
        worker.join().unwrap();
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn loopback_login_then_read_account_folder() {
        let dir = scratch("login");
        std::fs::File::create(dir.join("doc.txt")).unwrap().write_all(b"private").unwrap();

        let catalog = Arc::new(ShareCatalog::new());
        catalog.set_follow_windows_shares(false);
        catalog.add(dir.to_str().unwrap(), "Acc", ShareAccess::WindowsAccounts).unwrap();

        let auth = Arc::new(MemoryAccountAuthenticator::new());
        auth.set_proof_difficulty_bits(0); // keep the test quick
        auth.add_account("guest", "secret");
        let service = FolderService::with_authenticator(catalog, auth);

        let (server, client_end) = pipe();
        let server = Arc::new(server);
        let worker = {
            let service = service.clone();
            std::thread::spawn(move || service.serve(server))
        };

        let client = FolderClient::new(Arc::new(client_end));

        // Without a sign-in the account folder refuses.
        assert_eq!(client.list_files("Acc"), Err(FolderStatus::NeedLogin));

        // A wrong password is refused.
        assert_eq!(client.login("guest", "wrong"), FolderStatus::Denied);

        // The right password signs in and the folder opens.
        assert_eq!(client.login("guest", "secret"), FolderStatus::Ok);
        assert_eq!(client.logged_in_as().as_deref(), Some("guest"));

        let files = client.list_files("Acc").unwrap();
        assert_eq!(files.len(), 1);
        assert_eq!(files[0].name(), "doc.txt");

        let mut got = Vec::new();
        assert_eq!(client.fetch("Acc", "doc.txt", &mut got, |_, _| {}), FolderStatus::Ok);
        assert_eq!(got, b"private");

        client.close();
        worker.join().unwrap();
        let _ = std::fs::remove_dir_all(&dir);
    }

    fn proto_chunk() -> usize {
        super::CHUNK_SIZE
    }
}
