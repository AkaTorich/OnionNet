//! The single source of randomness, and constant-time comparisons.
//!
//! Everything that decides a security question takes its bytes only here. The
//! operating system's CSPRNG is the source (`getrandom`), exactly as the C#
//! code takes the OS provider.

use subtle::ConstantTimeEq;
use zeroize::Zeroize;

/// `count` fresh random bytes from the OS.
pub fn get_bytes(count: usize) -> Vec<u8> {
    let mut data = vec![0u8; count];
    if count > 0 {
        getrandom::getrandom(&mut data).expect("OS randomness is available");
    }
    data
}

/// Fills `buffer` with fresh random bytes.
pub fn fill(buffer: &mut [u8]) {
    if !buffer.is_empty() {
        getrandom::getrandom(buffer).expect("OS randomness is available");
    }
}

/// A uniform number in `[0, exclusive_upper_bound)` with no modulo bias.
///
/// The tail is rejected so the lower values do not come up more often. The
/// 32-bit word is read little-endian, as `BitConverter.ToUInt32` does on the
/// platforms the C# node runs on.
pub fn next(exclusive_upper_bound: u32) -> u32 {
    assert!(exclusive_upper_bound > 0, "upper bound must be positive");

    let limit = u32::MAX - (u32::MAX % exclusive_upper_bound);
    loop {
        let buffer = get_bytes(4);
        let value = u32::from_le_bytes([buffer[0], buffer[1], buffer[2], buffer[3]]);
        if value < limit {
            return value % exclusive_upper_bound;
        }
    }
}

/// Picks a random item from a non-empty slice.
pub fn pick<T>(items: &[T]) -> &T {
    assert!(!items.is_empty(), "the list is empty");
    &items[next(items.len() as u32) as usize]
}

/// Picks an item by weight: the larger the weight, the more often it comes up.
///
/// The randomness comes from here rather than a general-purpose PRNG: the
/// choice of circuit nodes must not be predictable. Zero and negative weights
/// never come up; if all weights are zero the choice is uniform.
pub fn pick_weighted<T, F>(items: &[T], mut weight: F) -> &T
where
    F: FnMut(&T) -> f64,
{
    assert!(!items.is_empty(), "the list is empty");
    if items.len() == 1 {
        return &items[0];
    }

    let mut weights = vec![0.0f64; items.len()];
    let mut total = 0.0f64;
    for (i, item) in items.iter().enumerate() {
        let mut value = weight(item);
        if value.is_nan() || value < 0.0 {
            value = 0.0;
        }
        weights[i] = value;
        total += value;
    }

    if total <= 0.0 {
        return &items[next(items.len() as u32) as usize];
    }

    let point = next_double() * total;
    let mut running = 0.0f64;
    for (i, w) in weights.iter().enumerate() {
        running += w;
        if point < running {
            return &items[i];
        }
    }

    &items[items.len() - 1]
}

/// A uniform number in `[0, 1)` on cryptographic randomness.
///
/// Fifty-three bits — exactly the mantissa of an `f64`. The eight bytes are
/// folded big-endian, as the C# loop does.
pub fn next_double() -> f64 {
    let bytes = get_bytes(8);
    let mut value: u64 = 0;
    for b in bytes {
        value = (value << 8) | b as u64;
    }
    (value >> 11) as f64 * (1.0 / 9007199254740992.0)
}

/// A constant-time comparison: it does not reveal how many leading bytes matched.
pub fn constant_time_equals(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.ct_eq(b).into()
}

/// Overwrites a buffer with zeros.
pub fn wipe(data: &mut [u8]) {
    data.zeroize();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn next_is_in_range() {
        for _ in 0..1000 {
            assert!(next(7) < 7);
        }
    }

    #[test]
    fn next_double_in_unit_interval() {
        for _ in 0..1000 {
            let x = next_double();
            assert!((0.0..1.0).contains(&x));
        }
    }

    #[test]
    fn constant_time_equals_matches() {
        assert!(constant_time_equals(b"abc", b"abc"));
        assert!(!constant_time_equals(b"abc", b"abd"));
        assert!(!constant_time_equals(b"abc", b"ab"));
    }
}
