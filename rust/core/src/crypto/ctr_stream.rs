//! A continuous AES-256-CTR keystream: one stream per direction per hop.
//!
//! Why a stream and not AEAD per cell: an AEAD tag would add 16 bytes per
//! layer, and the cell would swell at every hop. The packet size alone would
//! then tell how many nodes are still ahead. A counter stream keeps the cell at
//! exactly 509 bytes from the client to the exit.
//!
//! Integrity is provided by a separate chain of tags — see `RelayDigest`.
//!
//! The counter is the full 16-byte block as a 128-bit big-endian number,
//! incremented by one per block, exactly as the C# `CtrStream`. The raw AES
//! block cipher is used directly (ECB of the counter block) rather than a CTR
//! wrapper, so the keystream matches the original byte for byte.

use aes::cipher::{generic_array::GenericArray, BlockEncrypt, KeyInit};
use aes::Aes256;
use zeroize::Zeroize;

pub const KEY_SIZE: usize = 32;
pub const IV_SIZE: usize = 16;

const BLOCK_SIZE: usize = 16;

pub struct CtrStream {
    cipher: Aes256,
    counter: [u8; BLOCK_SIZE],
    key_stream: [u8; BLOCK_SIZE],
    // How many bytes of the current keystream block are already spent.
    key_stream_position: usize,
    bytes_produced: u64,
}

impl CtrStream {
    pub fn new(key: &[u8], iv: &[u8]) -> Self {
        assert_eq!(key.len(), KEY_SIZE, "the stream key must be {KEY_SIZE} bytes");
        assert_eq!(iv.len(), IV_SIZE, "the initial counter must be {IV_SIZE} bytes");

        let cipher = Aes256::new(GenericArray::from_slice(key));
        let mut counter = [0u8; BLOCK_SIZE];
        counter.copy_from_slice(iv);

        CtrStream {
            cipher,
            counter,
            key_stream: [0u8; BLOCK_SIZE],
            key_stream_position: BLOCK_SIZE,
            bytes_produced: 0,
        }
    }

    /// How many keystream bytes were given out — for diagnosing desync.
    pub fn bytes_produced(&self) -> u64 {
        self.bytes_produced
    }

    /// Applies the keystream straight onto the buffer. Encryption and
    /// decryption are the same operation, hence one method.
    pub fn xor_in_place(&mut self, buffer: &mut [u8]) {
        let count = buffer.len();
        let mut done = 0;
        while done < count {
            if self.key_stream_position == BLOCK_SIZE {
                self.key_stream.copy_from_slice(&self.counter);
                let mut block = GenericArray::clone_from_slice(&self.key_stream);
                self.cipher.encrypt_block(&mut block);
                self.key_stream.copy_from_slice(&block);
                self.increment_counter();
                self.key_stream_position = 0;
            }

            let take = (BLOCK_SIZE - self.key_stream_position).min(count - done);
            for i in 0..take {
                buffer[done + i] ^= self.key_stream[self.key_stream_position + i];
            }

            self.key_stream_position += take;
            done += take;
        }

        self.bytes_produced += count as u64;
    }

    /// The counter is a 128-bit big-endian number; it will never overflow.
    fn increment_counter(&mut self) {
        for i in (0..BLOCK_SIZE).rev() {
            self.counter[i] = self.counter[i].wrapping_add(1);
            if self.counter[i] != 0 {
                return;
            }
        }
    }
}

impl Drop for CtrStream {
    fn drop(&mut self) {
        self.counter.zeroize();
        self.key_stream.zeroize();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encrypt_then_decrypt_round_trips() {
        let key = [7u8; KEY_SIZE];
        let iv = [3u8; IV_SIZE];
        let plain = b"the quick brown fox jumps over the lazy dog, twice over".to_vec();

        let mut enc = CtrStream::new(&key, &iv);
        let mut buf = plain.clone();
        enc.xor_in_place(&mut buf);
        assert_ne!(buf, plain);

        let mut dec = CtrStream::new(&key, &iv);
        dec.xor_in_place(&mut buf);
        assert_eq!(buf, plain);
    }

    #[test]
    fn byte_at_a_time_matches_bulk() {
        let key = [1u8; KEY_SIZE];
        let iv = [0xffu8; IV_SIZE]; // forces a counter carry across the block
        let data = vec![0u8; 50];

        let mut bulk = CtrStream::new(&key, &iv);
        let mut a = data.clone();
        bulk.xor_in_place(&mut a);

        let mut drip = CtrStream::new(&key, &iv);
        let mut b = data.clone();
        for i in 0..b.len() {
            drip.xor_in_place(&mut b[i..i + 1]);
        }
        assert_eq!(a, b);
    }
}
