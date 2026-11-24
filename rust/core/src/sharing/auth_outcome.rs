//! How a sign-in attempt ended (the C# `AuthOutcome`).

/// How the sign-in attempt ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum AuthOutcome {
    Success = 0,

    /// Wrong name or password. Deliberately not told apart: otherwise names
    /// could be guessed at.
    BadCredentials = 1,

    /// The account is disabled, or its sign-in is restricted by policy.
    AccountUnusable = 2,

    /// Too many failures in a row — wait a while.
    Throttled = 3,

    /// The Argon2id pass was not attached, or it does not check out.
    BadProof = 4,

    /// Sign-in by account is unavailable on this machine.
    Unavailable = 5,
}
