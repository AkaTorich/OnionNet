//! A relay's pass: solved once for its key and kept beside it.
//!
//! The pass is public — it goes into every card — so it is kept in an ordinary
//! file, `node.pass` beside `node.id`. Losing it costs only the minute of solving
//! it again. The file format (`'O' 'N' 'P' 'F' 1 | bits(1) | nonce(8)`) matches
//! the C# `RelayPass` byte for byte.

use crate::directory::relay_descriptor::RelayDescriptor;
use crate::identity::sybil_proof;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::Duration;

/// `'O' 'N' 'P' 'F' 1` — the magic of the kept `node.pass` file.
const MAGIC: [u8; 5] = [b'O', b'N', b'P', b'F', 1];

/// The pass file beside the identity: `node.id` gives `node.pass`.
pub fn path_for(identity_path: &Path) -> PathBuf {
    // `with_extension` replaces the final extension, matching the C#
    // `GetFileNameWithoutExtension(...) + ".pass"`.
    identity_path.with_extension("pass")
}

/// The kept pass if it is there, solved for this key and hard enough; otherwise a
/// new one, solved here and written down. Long — a minute or so at the network's
/// difficulty.
///
/// * `should_cancel` — polled during the solve; returning `true` aborts it.
/// * `progress` — called now and then with the attempt count and time elapsed.
///
/// Returns the pass nonce and the number of bits it was solved for, or `None` if
/// the solve was cancelled (the C# `OperationCanceledException`).
pub fn obtain<C, P>(
    identity_path: Option<&Path>,
    fingerprint: &[u8],
    bits: u32,
    should_cancel: C,
    progress: P,
) -> Option<(Vec<u8>, u32)>
where
    C: Fn() -> bool,
    P: FnMut(u64, Duration),
{
    let path = identity_path.map(path_for);
    let challenge = RelayDescriptor::proof_challenge(fingerprint);

    if let Some(path) = &path {
        if let Some((kept, kept_bits)) = try_read(path) {
            if kept_bits >= bits && sybil_proof::verify(&challenge, &kept, kept_bits) {
                return Some((kept, kept_bits));
            }
        }
    }

    let nonce = sybil_proof::solve(&challenge, bits, should_cancel, progress)?;

    if let Some(path) = &path {
        // A failure to write is no reason to refuse a freshly solved pass.
        let _ = write(path, &nonce, bits);
    }

    Some((nonce.to_vec(), bits))
}

/// Reads a kept pass: its bits and nonce, or `None` if the file is missing,
/// damaged or the wrong size.
fn try_read(path: &Path) -> Option<(Vec<u8>, u32)> {
    let data = fs::read(path).ok()?;
    if data.len() != MAGIC.len() + 1 + sybil_proof::NONCE_SIZE {
        return None;
    }
    if data[..MAGIC.len()] != MAGIC {
        return None;
    }

    let bits = data[MAGIC.len()] as u32;
    let nonce = data[MAGIC.len() + 1..].to_vec();
    Some((nonce, bits))
}

fn write(path: &Path, nonce: &[u8], bits: u32) -> std::io::Result<()> {
    let mut data = Vec::with_capacity(MAGIC.len() + 1 + nonce.len());
    data.extend_from_slice(&MAGIC);
    data.push(bits as u8);
    data.extend_from_slice(nonce);
    fs::write(path, &data)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn path_for_puts_the_pass_beside_the_identity() {
        assert_eq!(path_for(Path::new("/data/node.id")), PathBuf::from("/data/node.pass"));
        assert_eq!(path_for(Path::new("node.id")), PathBuf::from("node.pass"));
    }

    #[test]
    fn file_round_trips_and_is_reused() {
        let fingerprint = [11u8; 20];
        let dir = std::env::temp_dir();
        let id_path = dir.join(format!("stalknet-pass-{}.id", std::process::id()));

        // Solve once at a low difficulty and write the pass down.
        let (first, bits) = obtain(Some(&id_path), &fingerprint, 4, || false, |_, _| {}).unwrap();
        assert_eq!(bits, 4);
        assert!(path_for(&id_path).exists());

        // A second call reads the kept pass back rather than solving again.
        let (again, bits_again) = obtain(Some(&id_path), &fingerprint, 4, || false, |_, _| {}).unwrap();
        assert_eq!(bits_again, 4);
        assert_eq!(first, again);

        // What was kept verifies against the challenge.
        let challenge = RelayDescriptor::proof_challenge(&fingerprint);
        assert!(sybil_proof::verify(&challenge, &again, 4));

        let _ = fs::remove_file(path_for(&id_path));
    }

    #[test]
    fn cancellation_yields_none() {
        // A demand that can never be met, cancelled at once.
        let out = obtain(None, &[1u8; 20], 64, || true, |_, _| {});
        assert!(out.is_none());
    }
}
