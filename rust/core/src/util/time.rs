//! .NET `DateTime.Ticks` conversions. Several on-disk and on-wire fields store
//! ticks (100-nanosecond intervals since 0001-01-01), so the Rust port speaks
//! the same representation.

use std::time::{SystemTime, UNIX_EPOCH};

/// Ticks between 0001-01-01 and 1970-01-01.
pub const TICKS_AT_UNIX_EPOCH: i64 = 621_355_968_000_000_000;

/// The current UTC time as .NET ticks.
pub fn now_ticks() -> i64 {
    match SystemTime::now().duration_since(UNIX_EPOCH) {
        Ok(d) => TICKS_AT_UNIX_EPOCH + d.as_secs() as i64 * 10_000_000 + (d.subsec_nanos() / 100) as i64,
        Err(_) => TICKS_AT_UNIX_EPOCH,
    }
}

/// Seconds elapsed since the given ticks (negative if in the future).
pub fn seconds_since(ticks: i64) -> f64 {
    (now_ticks() - ticks) as f64 / 10_000_000.0
}
