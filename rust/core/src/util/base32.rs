//! Base32 per RFC 4648, in lower case and without padding characters.
//!
//! Addresses are read out and dictated by living people, hence not Base64: in
//! lower case Base32 has no pairs that the eye confuses.

const ALPHABET: &[u8; 32] = b"abcdefghijklmnopqrstuvwxyz234567";

/// Encodes bytes as lower-case, unpadded Base32.
pub fn encode(data: &[u8]) -> String {
    if data.is_empty() {
        return String::new();
    }

    let mut out = String::with_capacity((data.len() * 8 + 4) / 5);
    let mut buffer: u32 = 0;
    let mut bits_left: i32 = 0;

    for &b in data {
        buffer = (buffer << 8) | b as u32;
        bits_left += 8;

        while bits_left >= 5 {
            out.push(ALPHABET[((buffer >> (bits_left - 5)) & 31) as usize] as char);
            bits_left -= 5;
        }
    }

    if bits_left > 0 {
        out.push(ALPHABET[((buffer << (5 - bits_left)) & 31) as usize] as char);
    }

    out
}

/// Decodes Base32, returning `None` when the string is not valid Base32.
pub fn try_decode(text: &str) -> Option<Vec<u8>> {
    let text = text.trim().to_ascii_lowercase();
    if text.is_empty() {
        return Some(Vec::new());
    }

    let mut result = vec![0u8; text.len() * 5 / 8];
    let mut position = 0usize;
    let mut buffer: u32 = 0;
    let mut bits_left: i32 = 0;

    for c in text.bytes() {
        let value = match ALPHABET.iter().position(|&a| a == c) {
            Some(v) => v as u32,
            None => return None,
        };

        buffer = (buffer << 5) | value;
        bits_left += 5;

        if bits_left >= 8 {
            result[position] = (buffer >> (bits_left - 8)) as u8;
            position += 1;
            bits_left -= 8;
        }
    }

    Some(result)
}

/// Decodes Base32, panicking in debug when the string is invalid.
///
/// The C# `Decode` throws `FormatException`; callers that must not fail use
/// [`try_decode`]. This mirrors the convenience overload.
pub fn decode(text: &str) -> Vec<u8> {
    try_decode(text).expect("the string is not valid Base32")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips() {
        for sample in [
            &b""[..],
            &b"f"[..],
            &b"fo"[..],
            &b"foo"[..],
            &b"foob"[..],
            &b"fooba"[..],
            &b"foobar"[..],
        ] {
            let encoded = encode(sample);
            let decoded = try_decode(&encoded).unwrap();
            assert_eq!(&decoded[..sample.len()], sample);
        }
    }

    #[test]
    fn rejects_padding_and_invalid() {
        assert!(try_decode("mzxw6===").is_none());
        assert!(try_decode("0189").is_none());
    }
}
