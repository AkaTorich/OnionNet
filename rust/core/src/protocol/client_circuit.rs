//! The cryptographic side of a circuit as the client sees it — the onion
//! itself. No networking here: this only puts layers on and takes them off.
//!
//! Hops are numbered from the client: 0 is the entry (the guard), the last is
//! the exit. The client holds every hop's keys, each hop holds only its own.

use crate::protocol::cell::PAYLOAD_SIZE;
use crate::protocol::hop_keys::HopKeys;
use crate::protocol::relay_cell::RelayCell;

#[derive(Default)]
pub struct ClientCircuit {
    hops: Vec<HopKeys>,
}

impl ClientCircuit {
    pub fn new() -> ClientCircuit {
        ClientCircuit { hops: Vec::new() }
    }

    pub fn hop_count(&self) -> usize {
        self.hops.len()
    }

    /// Adds a hop after another handshake completes.
    pub fn add_hop(&mut self, key_material: &[u8]) {
        self.hops.push(HopKeys::from_material(key_material));
    }

    /// Wraps a cell for the given hop and returns the finished 509 bytes. Only
    /// the addressee sets the tag; the cipher layers are laid on from it towards
    /// the client, so the guard's layer is outermost and comes off first.
    pub fn wrap_outbound(&mut self, cell: &RelayCell, hop_index: usize) -> Vec<u8> {
        assert!(hop_index < self.hops.len(), "hop index out of range");

        let mut payload = cell.to_payload();
        self.hops[hop_index].forward_digest.seal(&mut payload);

        for i in (0..=hop_index).rev() {
            self.hops[i].forward.xor_in_place(&mut payload);
        }
        payload
    }

    /// Takes the layers off an arriving cell. Returns the hop that sent it and
    /// the parsed cell, or `None` if no hop recognised it. Peeling goes from the
    /// guard inwards and stops at the first hop that recognises the cell: the
    /// further hops never saw it, and their keystream must not advance.
    pub fn unwrap_inbound(&mut self, payload: &mut [u8]) -> Option<(usize, RelayCell)> {
        assert_eq!(payload.len(), PAYLOAD_SIZE, "the payload must be {PAYLOAD_SIZE} bytes");

        for i in 0..self.hops.len() {
            self.hops[i].backward.xor_in_place(payload);

            if !RelayCell::looks_recognized(payload) {
                continue;
            }
            if !self.hops[i].backward_digest.verify_and_commit(payload) {
                continue;
            }
            return RelayCell::try_parse(payload).map(|cell| (i, cell));
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::relay_cell::RelayCommand;
    use crate::protocol::relay_hop::{Peeled, RelayHop};
    use crate::crypto::rand;

    #[test]
    fn client_and_three_hops_agree_through_the_onion() {
        // Each hop shares 160 bytes of material with the client.
        let materials: Vec<Vec<u8>> = (0..3).map(|_| rand::get_bytes(160)).collect();

        let mut client = ClientCircuit::new();
        let mut relays: Vec<RelayHop> = Vec::new();
        for m in &materials {
            client.add_hop(m);
            relays.push(RelayHop::new(m));
        }

        // Client sends a cell to hop 2 (the exit): wrap, then each relay peels
        // forward in turn; only hop 2 recognises it.
        let cell = RelayCell::new(RelayCommand::Data, 42, b"payload to exit".to_vec());
        let mut payload = client.wrap_outbound(&cell, 2);

        let mut delivered = None;
        for (i, relay) in relays.iter_mut().enumerate() {
            match relay.peel_forward(&mut payload) {
                Peeled::ForMe(c) => {
                    delivered = Some((i, c));
                    break;
                }
                Peeled::PassOn => {}
            }
        }
        let (idx, got) = delivered.expect("exit hop recognises the cell");
        assert_eq!(idx, 2);
        assert_eq!(got.command, RelayCommand::Data);
        assert_eq!(got.data, b"payload to exit");

        // Exit answers: it originates a backward cell, the inner relays wrap
        // their layers, the client unwraps and learns it came from hop 2.
        let answer = RelayCell::new(RelayCommand::Connected, 42, b"ok".to_vec());
        let mut back = relays[2].originate_backward(&answer);
        relays[1].wrap_backward(&mut back);
        relays[0].wrap_backward(&mut back);

        let (from, parsed) = client.unwrap_inbound(&mut back).expect("client recognises the reply");
        assert_eq!(from, 2);
        assert_eq!(parsed.command, RelayCommand::Connected);
        assert_eq!(parsed.data, b"ok");
    }
}
