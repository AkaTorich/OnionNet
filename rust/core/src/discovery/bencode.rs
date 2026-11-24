//! The BitTorrent encoding: byte strings, whole numbers, lists and
//! dictionaries. Messages of the torrent network's DHT are written in it.
//!
//! On decode, strings come back as [`BencodeValue::Bytes`], numbers as
//! [`BencodeValue::Int`], lists as [`BencodeValue::List`], dictionaries as
//! [`BencodeValue::Dict`] (a `BTreeMap`, so its keys are already in byte order).
//! What arrives is a stranger's, so every length and depth is checked: a broken
//! message is a [`BencodeError`], never a wrong read.
//!
//! On encode, [`BencodeValue::Str`] is a convenience that writes exactly like a
//! [`BencodeValue::Bytes`] of the string's UTF-8 — the C# treated `string` and
//! `byte[]` the same way on the wire. Decoding never produces `Str`.

use std::collections::BTreeMap;
use std::fmt;

/// A dictionary: keys kept in byte order, as bencode requires.
pub type Dict = BTreeMap<String, BencodeValue>;

/// Maximum nesting the decoder will follow, matching the C# `MaxDepth`.
const MAX_DEPTH: i32 = 16;

/// A bencode value. `Str` is an encode-only convenience (see the module docs).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum BencodeValue {
    Bytes(Vec<u8>),
    /// Written as a byte string of the UTF-8; never produced by `decode`.
    Str(String),
    Int(i64),
    List(Vec<BencodeValue>),
    Dict(Dict),
}

impl BencodeValue {
    /// The bytes of a byte string (or of a `Str`), if this is one.
    pub fn as_bytes(&self) -> Option<&[u8]> {
        match self {
            BencodeValue::Bytes(b) => Some(b),
            BencodeValue::Str(s) => Some(s.as_bytes()),
            _ => None,
        }
    }

    /// The items of a list, if this is one.
    pub fn as_list(&self) -> Option<&[BencodeValue]> {
        match self {
            BencodeValue::List(items) => Some(items),
            _ => None,
        }
    }

    /// The entries of a dictionary, if this is one.
    pub fn as_dict(&self) -> Option<&Dict> {
        match self {
            BencodeValue::Dict(d) => Some(d),
            _ => None,
        }
    }

    /// The number, if this is one.
    pub fn as_int(&self) -> Option<i64> {
        match self {
            BencodeValue::Int(n) => Some(*n),
            _ => None,
        }
    }
}

/// A broken or incomplete bencode message (the C# `FormatException`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BencodeError(pub &'static str);

impl fmt::Display for BencodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.0)
    }
}

impl std::error::Error for BencodeError {}

/// Encodes a value into its bencode bytes.
pub fn encode(value: &BencodeValue) -> Vec<u8> {
    let mut out = Vec::new();
    write(&mut out, value);
    out
}

/// Decodes one bencode value; any trailing byte is an error.
pub fn decode(data: &[u8]) -> Result<BencodeValue, BencodeError> {
    let mut position = 0usize;
    let value = read(data, &mut position, 0)?;
    if position != data.len() {
        return Err(BencodeError("Extra bytes after the message."));
    }
    Ok(value)
}

fn write(out: &mut Vec<u8>, value: &BencodeValue) {
    match value {
        BencodeValue::Bytes(b) => write_bytes(out, b),
        BencodeValue::Str(s) => write_bytes(out, s.as_bytes()),
        BencodeValue::Int(n) => {
            out.push(b'i');
            out.extend_from_slice(n.to_string().as_bytes());
            out.push(b'e');
        }
        BencodeValue::List(items) => {
            out.push(b'l');
            for item in items {
                write(out, item);
            }
            out.push(b'e');
        }
        BencodeValue::Dict(map) => {
            // A `BTreeMap` already yields its keys in byte order - the rule.
            out.push(b'd');
            for (key, val) in map {
                write_bytes(out, key.as_bytes());
                write(out, val);
            }
            out.push(b'e');
        }
    }
}

fn write_bytes(out: &mut Vec<u8>, bytes: &[u8]) {
    out.extend_from_slice(bytes.len().to_string().as_bytes());
    out.push(b':');
    out.extend_from_slice(bytes);
}

fn read(data: &[u8], position: &mut usize, depth: i32) -> Result<BencodeValue, BencodeError> {
    if depth > MAX_DEPTH {
        return Err(BencodeError("Nested too deep."));
    }
    if *position >= data.len() {
        return Err(BencodeError("The message is cut short."));
    }

    let head = data[*position];

    if head == b'i' {
        *position += 1;
        let end = find(data, *position, b'e').ok_or(BencodeError("A broken number."))?;
        if end - *position > 20 || end == *position {
            return Err(BencodeError("A broken number."));
        }
        let text = std::str::from_utf8(&data[*position..end]).map_err(|_| BencodeError("A broken number."))?;
        let number: i64 = text.parse().map_err(|_| BencodeError("A broken number."))?;
        *position = end + 1;
        return Ok(BencodeValue::Int(number));
    }

    if head == b'l' {
        *position += 1;
        let mut list = Vec::new();
        loop {
            if *position >= data.len() {
                return Err(BencodeError("A list is cut short."));
            }
            if data[*position] == b'e' {
                *position += 1;
                return Ok(BencodeValue::List(list));
            }
            list.push(read(data, position, depth + 1)?);
        }
    }

    if head == b'd' {
        *position += 1;
        let mut dictionary = Dict::new();
        loop {
            if *position >= data.len() {
                return Err(BencodeError("A dictionary is cut short."));
            }
            if data[*position] == b'e' {
                *position += 1;
                return Ok(BencodeValue::Dict(dictionary));
            }
            let key = match read(data, position, depth + 1)? {
                BencodeValue::Bytes(bytes) => bytes,
                _ => return Err(BencodeError("A dictionary key that is not a string.")),
            };
            let value = read(data, position, depth + 1)?;
            dictionary.insert(String::from_utf8_lossy(&key).into_owned(), value);
        }
    }

    if head.is_ascii_digit() {
        let colon = find(data, *position, b':').ok_or(BencodeError("A broken string length."))?;
        if colon - *position > 9 {
            return Err(BencodeError("A broken string length."));
        }
        let text = std::str::from_utf8(&data[*position..colon]).map_err(|_| BencodeError("A broken string length."))?;
        let length: usize = text.parse().map_err(|_| BencodeError("A broken string length."))?;

        *position = colon + 1;
        if length > data.len() - *position {
            return Err(BencodeError("A string runs past the end."));
        }

        let bytes = data[*position..*position + length].to_vec();
        *position += length;
        return Ok(BencodeValue::Bytes(bytes));
    }

    Err(BencodeError("An unknown value type."))
}

/// The index of the first `needle` at or after `from`, as `Array.IndexOf` gives.
fn find(data: &[u8], from: usize, needle: u8) -> Option<usize> {
    data[from..].iter().position(|&b| b == needle).map(|i| from + i)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn round_trip(value: BencodeValue) {
        let encoded = encode(&value);
        let decoded = decode(&encoded).expect("decodes");
        assert_eq!(decoded, value);
    }

    #[test]
    fn integers_round_trip() {
        round_trip(BencodeValue::Int(0));
        round_trip(BencodeValue::Int(42));
        round_trip(BencodeValue::Int(-7));
        round_trip(BencodeValue::Int(i64::MAX));
        round_trip(BencodeValue::Int(i64::MIN));
        assert_eq!(encode(&BencodeValue::Int(42)), b"i42e");
        assert_eq!(encode(&BencodeValue::Int(-7)), b"i-7e");
    }

    #[test]
    fn byte_strings_round_trip() {
        round_trip(BencodeValue::Bytes(b"".to_vec()));
        round_trip(BencodeValue::Bytes(b"spam".to_vec()));
        round_trip(BencodeValue::Bytes(vec![0, 1, 2, 255, 254]));
        assert_eq!(encode(&BencodeValue::Bytes(b"spam".to_vec())), b"4:spam");
    }

    #[test]
    fn str_encodes_like_bytes() {
        assert_eq!(
            encode(&BencodeValue::Str("spam".into())),
            encode(&BencodeValue::Bytes(b"spam".to_vec()))
        );
    }

    #[test]
    fn lists_round_trip() {
        round_trip(BencodeValue::List(vec![
            BencodeValue::Int(1),
            BencodeValue::Bytes(b"a".to_vec()),
            BencodeValue::List(vec![BencodeValue::Int(2)]),
        ]));
        assert_eq!(
            encode(&BencodeValue::List(vec![
                BencodeValue::Bytes(b"spam".to_vec()),
                BencodeValue::Int(42)
            ])),
            b"l4:spami42ee"
        );
    }

    #[test]
    fn dicts_sort_keys_by_bytes() {
        let mut map = Dict::new();
        map.insert("y".into(), BencodeValue::Str("q".into()));
        map.insert("a".into(), BencodeValue::Int(1));
        map.insert("ro".into(), BencodeValue::Int(1));
        // Keys must come out sorted: "a", "ro", "y".
        assert_eq!(encode(&BencodeValue::Dict(map)), b"d1:ai1e2:roi1e1:y1:qe");
    }

    #[test]
    fn dict_round_trips() {
        let mut map = Dict::new();
        map.insert("id".into(), BencodeValue::Bytes(vec![1, 2, 3]));
        map.insert("info_hash".into(), BencodeValue::Bytes(vec![9, 8, 7]));
        round_trip(BencodeValue::Dict(map));
    }

    #[test]
    fn extra_bytes_rejected() {
        assert_eq!(decode(b"i1ei2e"), Err(BencodeError("Extra bytes after the message.")));
    }

    #[test]
    fn broken_messages_rejected() {
        assert!(decode(b"i").is_err());
        assert!(decode(b"ie").is_err());
        assert!(decode(b"i123456789012345678901e").is_err()); // > 20 digits
        assert!(decode(b"2:a").is_err()); // string runs past the end
        assert!(decode(b"l1:a").is_err()); // list cut short
        assert!(decode(b"di1ee").is_err()); // dictionary key not a string
        assert!(decode(b"x").is_err()); // unknown type
    }

    #[test]
    fn nesting_is_bounded() {
        // Opening 'l' bytes nested past MaxDepth must be refused before the
        // reader runs off the end.
        let deep = vec![b'l'; 18];
        assert_eq!(decode(&deep), Err(BencodeError("Nested too deep.")));
    }
}
