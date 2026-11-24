//! Signing in to a shared folder with a local OS account (the C#
//! `AccountAuthenticator` / `AuthenticatedSession`).
//!
//! ## Cross-platform shape
//!
//! The C# original is Windows-only: it calls `LogonUser` to check the password
//! against a real Windows account and then reads the folder *impersonating* that
//! account, so the kernel checks the ACL. That part cannot be portable.
//!
//! So the behaviour is split behind a trait, [`AccountAuthenticator`]:
//!
//! * [`MemoryAccountAuthenticator`] — a portable, configured credential checker.
//!   It is the default everywhere except a Windows build with the real backend
//!   enabled, and it is the fallback on Windows too. It carries the same
//!   memory-hard proof check and the same failure throttle as the C#.
//! * A real Windows backend lives in the `windows_logon` submodule, gated behind
//!   `#[cfg(all(windows, feature = "windows_logon"))]`. It is **not** compiled by
//!   default because `LogonUser` needs a `windows-sys` namespace feature this
//!   crate does not yet enable (see the module's note and the port report).
//!
//! The memory-hard [`login_proof`](super::login_proof) crypto is wholly
//! platform-independent and is ported in full regardless of backend.

use super::auth_outcome::AuthOutcome;
use super::login_proof;
use crate::crypto::rand;
use std::collections::HashMap;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Mutex;
use std::sync::Arc;
use std::time::{Duration, Instant};

#[cfg(all(windows, feature = "windows_logon"))]
pub(crate) use windows_logon::TokenHandle;

/// A guest's open session: the identity a folder read runs on behalf of.
///
/// All reading of the folder goes through [`run`](AuthenticatedSession::run).
/// With the real Windows backend that runs the closure while *impersonating* the
/// signed-in account, so the kernel checks the real ACL — revoke access in
/// Explorer and the very next read is refused. With the portable backend there
/// is nobody to impersonate, so the closure runs with the process's own rights;
/// the password was still checked for real before the session was handed out.
pub struct AuthenticatedSession {
    user_name: String,
    /// The impersonation token, present only with the real Windows backend. When
    /// `None` the read runs as the process (the portable path, and the C#
    /// "host == guest" case).
    #[cfg(all(windows, feature = "windows_logon"))]
    token: Option<TokenHandle>,
}

impl AuthenticatedSession {
    /// A session with no impersonation — the read runs as the process.
    pub(crate) fn host(user_name: String) -> AuthenticatedSession {
        AuthenticatedSession {
            user_name,
            #[cfg(all(windows, feature = "windows_logon"))]
            token: None,
        }
    }

    /// Whom we signed in as.
    pub fn user_name(&self) -> &str {
        &self.user_name
    }

    /// Runs the read. With the Windows backend and a real token it impersonates;
    /// otherwise it runs the closure directly.
    pub fn run<R>(&self, f: impl FnOnce() -> R) -> R {
        #[cfg(all(windows, feature = "windows_logon"))]
        {
            if let Some(token) = &self.token {
                return token.impersonated(f);
            }
        }
        f()
    }
}

/// The session's random salt — the basis of the pass challenge. 16 bytes, as in
/// the C# `AccountAuthenticator.NewSessionSalt`.
pub fn new_session_salt() -> Vec<u8> {
    rand::get_bytes(16)
}

/// Checking a name-and-pass against a local OS account.
///
/// Mirrors the public surface the C# `FolderService` leans on: issue a challenge,
/// know the proof difficulty, and try to authenticate.
pub trait AccountAuthenticator: Send + Sync {
    /// The Argon2id pass difficulty. Zero switches the check off.
    fn proof_difficulty_bits(&self) -> u32;

    /// The challenge a guest must solve before a sign-in attempt.
    fn issue_challenge(&self, user_name: &str, session_salt: &[u8]) -> Vec<u8> {
        login_proof::build_challenge(user_name, session_salt)
    }

    /// Tries to sign in under the given account. On success it hands out a session
    /// to read the folder on the guest's behalf.
    fn try_authenticate(
        &self,
        user_name: &str,
        password: &str,
        challenge: &[u8],
        proof_nonce: &[u8],
    ) -> (AuthOutcome, Option<AuthenticatedSession>);

    /// How many failures are on a name's record — to show to the owner.
    fn failure_count(&self, _user_name: &str) -> u32 {
        0
    }
}

/// Returns the best available backend for this build: the real Windows one when
/// compiled in, otherwise the portable checker.
pub fn default_authenticator() -> Arc<dyn AccountAuthenticator> {
    #[cfg(all(windows, feature = "windows_logon"))]
    {
        Arc::new(windows_logon::WindowsAccountAuthenticator::new())
    }
    #[cfg(not(all(windows, feature = "windows_logon")))]
    {
        Arc::new(MemoryAccountAuthenticator::new())
    }
}

// ---- The failure throttle (shared by both backends) --------------------------

/// How many failures in a row we tolerate before locking for a while.
pub const DEFAULT_MAX_FAILURES: u32 = 5;
/// For how long we lock, and over what window the failures are counted.
pub const DEFAULT_LOCKOUT_WINDOW: Duration = Duration::from_secs(5 * 60);

struct FailureRecord {
    count: u32,
    since: Instant,
}

/// Our own counter rather than the OS lockout. That way harmless guessing from
/// outside does not lock the owner's real account across the whole machine — we
/// simply stop checking. The C# `AccountAuthenticator` failure bookkeeping.
struct Throttle {
    records: Mutex<HashMap<String, FailureRecord>>,
    max_failures: u32,
    window: Duration,
}

impl Throttle {
    fn new() -> Throttle {
        Throttle {
            records: Mutex::new(HashMap::new()),
            max_failures: DEFAULT_MAX_FAILURES,
            window: DEFAULT_LOCKOUT_WINDOW,
        }
    }

    fn is_throttled(&self, key: &str) -> bool {
        let mut records = self.records.lock().unwrap();
        match records.get(key) {
            None => false,
            Some(record) if record.since.elapsed() > self.window => {
                records.remove(key);
                false
            }
            Some(record) => record.count >= self.max_failures,
        }
    }

    fn register_failure(&self, key: &str) {
        let mut records = self.records.lock().unwrap();
        let fresh = match records.get(key) {
            Some(record) => record.since.elapsed() > self.window,
            None => true,
        };
        if fresh {
            records.insert(key.to_string(), FailureRecord { count: 0, since: Instant::now() });
        }
        let record = records.get_mut(key).unwrap();
        record.count += 1;
        record.since = Instant::now();
    }

    fn clear(&self, key: &str) {
        self.records.lock().unwrap().remove(key);
    }

    fn failure_count(&self, key: &str) -> u32 {
        let records = self.records.lock().unwrap();
        match records.get(key) {
            Some(record) if record.since.elapsed() <= self.window => record.count,
            _ => 0,
        }
    }
}

// ---- The portable backend ----------------------------------------------------

/// A configured, in-memory credential checker — the portable [`AccountAuthenticator`].
///
/// Accounts are added by hand (name and password). It keeps the memory-hard proof
/// check and the failure throttle exactly as the Windows backend does; the only
/// difference is that the password is checked against the configured table rather
/// than by the OS, and a granted session reads with the process's own rights.
pub struct MemoryAccountAuthenticator {
    /// Name (lowercase) → its password's salt and Argon2id hash. The password
    /// itself is kept nowhere.
    accounts: Mutex<HashMap<String, StoredPassword>>,
    difficulty: AtomicU32,
    throttle: Throttle,
}

/// A password as it is kept: a random salt and the Argon2id hash over it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StoredPassword {
    pub salt: Vec<u8>,
    pub hash: Vec<u8>,
}

/// The Argon2id settings for kept passwords (the OWASP minimum: 19 MiB, two
/// passes, one lane) — a stolen accounts file is slow to guess through.
const PASSWORD_MEMORY_KIB: u32 = 19 * 1024;
const PASSWORD_ITERATIONS: u32 = 2;
const PASSWORD_LANES: u32 = 1;
pub const PASSWORD_SALT_SIZE: usize = 16;
pub const PASSWORD_HASH_SIZE: usize = 32;

fn hash_password(password: &str, salt: &[u8]) -> Vec<u8> {
    crate::crypto::argon2id::derive_key(
        password.as_bytes(),
        salt,
        PASSWORD_LANES,
        PASSWORD_MEMORY_KIB,
        PASSWORD_ITERATIONS,
        PASSWORD_HASH_SIZE,
        None,
        None,
    )
    .unwrap_or_default()
}

impl StoredPassword {
    /// Salts and hashes a password.
    pub fn new(password: &str) -> StoredPassword {
        let salt = rand::get_bytes(PASSWORD_SALT_SIZE);
        let hash = hash_password(password, &salt);
        StoredPassword { salt, hash }
    }

    pub fn matches(&self, password: &str) -> bool {
        let candidate = hash_password(password, &self.salt);
        !candidate.is_empty() && rand::constant_time_equals(&candidate, &self.hash)
    }
}

impl Default for MemoryAccountAuthenticator {
    fn default() -> Self {
        Self::new()
    }
}

impl MemoryAccountAuthenticator {
    pub fn new() -> MemoryAccountAuthenticator {
        MemoryAccountAuthenticator {
            accounts: Mutex::new(HashMap::new()),
            difficulty: AtomicU32::new(login_proof::DEFAULT_DIFFICULTY_BITS),
            throttle: Throttle::new(),
        }
    }

    /// Adds (or replaces) an account. The name is matched case-insensitively;
    /// the password is salted and hashed, never kept as it is.
    pub fn add_account(&self, user_name: &str, password: &str) {
        let stored = StoredPassword::new(password);
        self.accounts.lock().unwrap().insert(user_name.to_lowercase(), stored);
    }

    /// Puts back an account as it was kept (from the accounts file).
    pub fn add_stored(&self, user_name: &str, stored: StoredPassword) {
        self.accounts.lock().unwrap().insert(user_name.to_lowercase(), stored);
    }

    pub fn remove_account(&self, user_name: &str) {
        self.accounts.lock().unwrap().remove(&user_name.to_lowercase());
    }

    /// Every account as kept, sorted by name — for saving.
    pub fn stored(&self) -> Vec<(String, StoredPassword)> {
        let mut all: Vec<(String, StoredPassword)> =
            self.accounts.lock().unwrap().iter().map(|(n, p)| (n.clone(), p.clone())).collect();
        all.sort_by(|a, b| a.0.cmp(&b.0));
        all
    }

    /// The account names, sorted.
    pub fn names(&self) -> Vec<String> {
        self.stored().into_iter().map(|(n, _)| n).collect()
    }

    /// Sets the Argon2id pass difficulty. Zero switches the check off.
    pub fn set_proof_difficulty_bits(&self, bits: u32) {
        self.difficulty.store(bits, Ordering::Relaxed);
    }
}

impl AccountAuthenticator for MemoryAccountAuthenticator {
    fn proof_difficulty_bits(&self) -> u32 {
        self.difficulty.load(Ordering::Relaxed)
    }

    fn try_authenticate(
        &self,
        user_name: &str,
        password: &str,
        challenge: &[u8],
        proof_nonce: &[u8],
    ) -> (AuthOutcome, Option<AuthenticatedSession>) {
        if user_name.is_empty() {
            return (AuthOutcome::BadCredentials, None);
        }

        // The pass is checked before the password: guessing must run into memory
        // before it ever reaches the real check.
        let difficulty = self.proof_difficulty_bits();
        if difficulty > 0 && !login_proof::verify(challenge, proof_nonce, difficulty) {
            return (AuthOutcome::BadProof, None);
        }

        let key = user_name.to_lowercase();
        if self.throttle.is_throttled(&key) {
            return (AuthOutcome::Throttled, None);
        }

        // The hash is worked out outside the lock: it takes a moment.
        let stored = self.accounts.lock().unwrap().get(&key).cloned();
        let ok = match stored {
            Some(stored) => stored.matches(password),
            None => false,
        };

        if ok {
            self.throttle.clear(&key);
            (AuthOutcome::Success, Some(AuthenticatedSession::host(user_name.to_string())))
        } else {
            self.throttle.register_failure(&key);
            (AuthOutcome::BadCredentials, None)
        }
    }

    fn failure_count(&self, user_name: &str) -> u32 {
        self.throttle.failure_count(&user_name.to_lowercase())
    }
}

/// A refusal in plain words — for the owner's log, not for the guest. The C#
/// `AccountAuthenticator.Explain`.
pub fn explain(outcome: AuthOutcome) -> String {
    use crate::text::t;
    match outcome {
        AuthOutcome::Success => t("auth.success"),
        AuthOutcome::BadCredentials => t("auth.badcredentials"),
        AuthOutcome::AccountUnusable => t("auth.unusable"),
        AuthOutcome::Throttled => t("auth.throttled"),
        AuthOutcome::BadProof => t("auth.badproof"),
        AuthOutcome::Unavailable => t("auth.unavailable"),
    }
}

// ---- The real Windows backend (gated, unverified until its features land) -----
//
// This module ports `AccountAuthenticator.Windows.cs`. It is compiled only under
// `#[cfg(all(windows, feature = "windows_logon"))]`, because it calls `LogonUser`
// and `ImpersonateLoggedOnUser`, which this crate does not yet depend on. To
// enable it the main thread must:
//   * add a crate feature `windows_logon`, and
//   * extend the `[target.'cfg(windows)'.dependencies] windows-sys` features with
//       "Win32_Security_Authentication_Identity"  (LogonUserW)
//       "Win32_Security"                          (ImpersonateLoggedOnUser, RevertToSelf)
//     ("Win32_Foundation" is already enabled, for CloseHandle / HANDLE).
//
// Unlike the C#, this port does NOT compare the guest SID against the host SID to
// skip impersonation; it always impersonates a real token. That is the strict,
// safe side the C# comment itself prefers ("an unnecessary impersonation is more
// honest than unnecessary access").
#[cfg(all(windows, feature = "windows_logon"))]
mod windows_logon {
    use super::*;
    use std::ffi::c_void;
    use windows_sys::Win32::Foundation::{CloseHandle, HANDLE};
    use windows_sys::Win32::Security::Authentication::Identity::LogonUserW;
    use windows_sys::Win32::Security::{ImpersonateLoggedOnUser, RevertToSelf};

    const LOGON32_LOGON_NETWORK: u32 = 3;
    const LOGON32_PROVIDER_DEFAULT: u32 = 0;

    const ERROR_LOGON_FAILURE: u32 = 1326;
    const ERROR_ACCOUNT_RESTRICTION: u32 = 1327;
    const ERROR_PASSWORD_EXPIRED: u32 = 1330;
    const ERROR_ACCOUNT_DISABLED: u32 = 1331;
    const ERROR_ACCOUNT_LOCKED_OUT: u32 = 1909;

    /// Owns a logon token and closes it on drop. `Send`/`Sync` because the handle
    /// is only ever used behind the session's `&self`, one call at a time.
    pub(crate) struct TokenHandle(HANDLE);

    unsafe impl Send for TokenHandle {}
    unsafe impl Sync for TokenHandle {}

    impl TokenHandle {
        /// Runs `f` while impersonating this token, reverting afterwards no matter
        /// what. If impersonation fails the read still runs (as the process),
        /// which the kernel will then refuse — the honest, strict outcome.
        pub(crate) fn impersonated<R>(&self, f: impl FnOnce() -> R) -> R {
            let ok = unsafe { ImpersonateLoggedOnUser(self.0) } != 0;
            let result = f();
            if ok {
                unsafe {
                    RevertToSelf();
                }
            }
            result
        }
    }

    impl Drop for TokenHandle {
        fn drop(&mut self) {
            unsafe {
                CloseHandle(self.0);
            }
        }
    }

    fn to_wide(value: &str) -> Vec<u16> {
        value.encode_utf16().chain(std::iter::once(0)).collect()
    }

    /// "MACHINE\\name" and "name" — both forms are accepted, the default domain is
    /// local ("."). The C# `SplitAccount`.
    fn split_account(user_name: &str) -> (String, String) {
        match user_name.find('\\') {
            Some(i) if i > 0 => (user_name[..i].to_string(), user_name[i + 1..].to_string()),
            _ => (".".to_string(), user_name.to_string()),
        }
    }

    fn translate_error(error: u32) -> AuthOutcome {
        match error {
            ERROR_LOGON_FAILURE => AuthOutcome::BadCredentials,
            ERROR_ACCOUNT_DISABLED | ERROR_ACCOUNT_RESTRICTION | ERROR_ACCOUNT_LOCKED_OUT | ERROR_PASSWORD_EXPIRED => {
                AuthOutcome::AccountUnusable
            }
            _ => AuthOutcome::Unavailable,
        }
    }

    /// The Windows backend: `LogonUser` checks the password, and a granted session
    /// reads the folder impersonating the account.
    pub(crate) struct WindowsAccountAuthenticator {
        difficulty: AtomicU32,
        throttle: Throttle,
    }

    impl WindowsAccountAuthenticator {
        pub(crate) fn new() -> WindowsAccountAuthenticator {
            WindowsAccountAuthenticator {
                difficulty: AtomicU32::new(login_proof::DEFAULT_DIFFICULTY_BITS),
                throttle: Throttle::new(),
            }
        }
    }

    impl AccountAuthenticator for WindowsAccountAuthenticator {
        fn proof_difficulty_bits(&self) -> u32 {
            self.difficulty.load(Ordering::Relaxed)
        }

        fn try_authenticate(
            &self,
            user_name: &str,
            password: &str,
            challenge: &[u8],
            proof_nonce: &[u8],
        ) -> (AuthOutcome, Option<AuthenticatedSession>) {
            if user_name.is_empty() {
                return (AuthOutcome::BadCredentials, None);
            }

            let difficulty = self.proof_difficulty_bits();
            if difficulty > 0 && !login_proof::verify(challenge, proof_nonce, difficulty) {
                return (AuthOutcome::BadProof, None);
            }

            let key = user_name.to_lowercase();
            if self.throttle.is_throttled(&key) {
                return (AuthOutcome::Throttled, None);
            }

            let (domain, account) = split_account(user_name);
            let account_w = to_wide(&account);
            let domain_w = to_wide(&domain);
            let password_w = to_wide(password);

            let mut token: HANDLE = 0;
            let ok = unsafe {
                LogonUserW(
                    account_w.as_ptr(),
                    domain_w.as_ptr(),
                    password_w.as_ptr(),
                    LOGON32_LOGON_NETWORK,
                    LOGON32_PROVIDER_DEFAULT,
                    &mut token as *mut HANDLE,
                )
            } != 0;

            if !ok {
                let error = unsafe { windows_sys::Win32::Foundation::GetLastError() };
                self.throttle.register_failure(&key);
                return (translate_error(error), None);
            }

            self.throttle.clear(&key);
            let session = AuthenticatedSession {
                user_name: user_name.to_string(),
                token: Some(TokenHandle(token)),
            };
            (AuthOutcome::Success, Some(session))
        }

        fn failure_count(&self, user_name: &str) -> u32 {
            self.throttle.failure_count(&user_name.to_lowercase())
        }
    }

    // Touch the unused import guard off for c_void in some toolchains.
    #[allow(dead_code)]
    fn _assert_void(_: *mut c_void) {}
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn session_salt_is_sixteen_bytes() {
        assert_eq!(new_session_salt().len(), 16);
    }

    #[test]
    fn memory_backend_signs_in_with_the_right_password() {
        let auth = MemoryAccountAuthenticator::new();
        auth.set_proof_difficulty_bits(0); // keep the test fast
        auth.add_account("Guest", "secret");

        let salt = new_session_salt();
        let challenge = auth.issue_challenge("guest", &salt);
        let nonce = login_proof::solve(&challenge, 0).unwrap();

        let (outcome, session) = auth.try_authenticate("guest", "secret", &challenge, &nonce);
        assert_eq!(outcome, AuthOutcome::Success);
        let session = session.unwrap();
        assert_eq!(session.user_name(), "guest");
        // The session runs a read directly on the portable backend.
        assert_eq!(session.run(|| 7), 7);
    }

    #[test]
    fn memory_backend_rejects_wrong_password_then_throttles() {
        let auth = MemoryAccountAuthenticator::new();
        auth.set_proof_difficulty_bits(0);
        auth.add_account("guest", "secret");
        let salt = new_session_salt();
        let challenge = auth.issue_challenge("guest", &salt);
        let nonce = vec![0u8; login_proof::NONCE_SIZE];

        for _ in 0..DEFAULT_MAX_FAILURES {
            let (outcome, _) = auth.try_authenticate("guest", "wrong", &challenge, &nonce);
            assert_eq!(outcome, AuthOutcome::BadCredentials);
        }
        assert_eq!(auth.failure_count("guest"), DEFAULT_MAX_FAILURES);

        // The next attempt is throttled, even with the right password.
        let (outcome, _) = auth.try_authenticate("guest", "secret", &challenge, &nonce);
        assert_eq!(outcome, AuthOutcome::Throttled);
    }

    #[test]
    fn bad_proof_is_caught_before_the_password() {
        let auth = MemoryAccountAuthenticator::new();
        auth.set_proof_difficulty_bits(8);
        auth.add_account("guest", "secret");
        let salt = new_session_salt();
        let challenge = auth.issue_challenge("guest", &salt);
        // A zero nonce almost certainly fails 8 bits of difficulty.
        let (outcome, _) = auth.try_authenticate("guest", "secret", &challenge, &[0u8; login_proof::NONCE_SIZE]);
        assert_eq!(outcome, AuthOutcome::BadProof);
    }

    #[test]
    fn unknown_account_is_bad_credentials() {
        let auth = MemoryAccountAuthenticator::new();
        auth.set_proof_difficulty_bits(0);
        let salt = new_session_salt();
        let challenge = auth.issue_challenge("nobody", &salt);
        let (outcome, session) = auth.try_authenticate("nobody", "x", &challenge, &[0u8; login_proof::NONCE_SIZE]);
        assert_eq!(outcome, AuthOutcome::BadCredentials);
        assert!(session.is_none());
    }
}
