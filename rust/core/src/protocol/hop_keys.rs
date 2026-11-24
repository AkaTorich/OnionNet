//! Everything a client and one hop know about each other after the handshake.
//!
//! "Forward" is from the client to the exit, "backward" is the way back. The
//! directions are kept fully apart: its own keystream key and its own tag chain
//! for each, so a cell that went one way cannot be reflected back. Both sides
//! derive the same set from the shared secret but use it mirrored.

use crate::crypto::ctr_stream::CtrStream;
use crate::protocol::relay_digest::RelayDigest;

pub const MATERIAL_SIZE: usize = 160;

const FORWARD_KEY_OFFSET: usize = 0;
const FORWARD_IV_OFFSET: usize = 32;
const BACKWARD_KEY_OFFSET: usize = 48;
const BACKWARD_IV_OFFSET: usize = 80;
const FORWARD_DIGEST_OFFSET: usize = 96;
const BACKWARD_DIGEST_OFFSET: usize = 128;

pub struct HopKeys {
    pub forward: CtrStream,
    pub backward: CtrStream,
    pub forward_digest: RelayDigest,
    pub backward_digest: RelayDigest,
}

impl HopKeys {
    pub fn from_material(material: &[u8]) -> HopKeys {
        assert_eq!(
            material.len(),
            MATERIAL_SIZE,
            "the key material is exactly {MATERIAL_SIZE} bytes"
        );
        HopKeys {
            forward: CtrStream::new(
                &material[FORWARD_KEY_OFFSET..FORWARD_KEY_OFFSET + 32],
                &material[FORWARD_IV_OFFSET..FORWARD_IV_OFFSET + 16],
            ),
            backward: CtrStream::new(
                &material[BACKWARD_KEY_OFFSET..BACKWARD_KEY_OFFSET + 32],
                &material[BACKWARD_IV_OFFSET..BACKWARD_IV_OFFSET + 16],
            ),
            forward_digest: RelayDigest::new(&material[FORWARD_DIGEST_OFFSET..FORWARD_DIGEST_OFFSET + 32]),
            backward_digest: RelayDigest::new(&material[BACKWARD_DIGEST_OFFSET..BACKWARD_DIGEST_OFFSET + 32]),
        }
    }
}
