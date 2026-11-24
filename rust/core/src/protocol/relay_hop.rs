//! What a relay knows about one circuit passing through it: exactly one layer,
//! its own. The relay knows neither the circuit's length nor its own place in
//! it; it takes off its layer, sees whether the cell is for it, and if not
//! passes it on without understanding a thing.

use crate::protocol::cell::PAYLOAD_SIZE;
use crate::protocol::hop_keys::HopKeys;
use crate::protocol::relay_cell::RelayCell;

/// The outcome of peeling one forward layer.
pub enum Peeled {
    /// The cell was addressed to us; here it is parsed.
    ForMe(RelayCell),
    /// Not for us. The payload is one layer lighter and ready to pass on.
    PassOn,
}

pub struct RelayHop {
    keys: HopKeys,
}

impl RelayHop {
    pub fn new(key_material: &[u8]) -> RelayHop {
        RelayHop {
            keys: HopKeys::from_material(key_material),
        }
    }

    /// Takes our layer off a cell travelling from the client.
    pub fn peel_forward(&mut self, payload: &mut [u8]) -> Peeled {
        assert_eq!(payload.len(), PAYLOAD_SIZE, "the payload must be {PAYLOAD_SIZE} bytes");

        self.keys.forward.xor_in_place(payload);

        if !RelayCell::looks_recognized(payload) {
            return Peeled::PassOn;
        }
        if !self.keys.forward_digest.verify_and_commit(payload) {
            return Peeled::PassOn;
        }
        match RelayCell::try_parse(payload) {
            Some(cell) => Peeled::ForMe(cell),
            None => Peeled::PassOn,
        }
    }

    /// Puts our layer onto a cell that came from the far end; its contents are
    /// unknown to us and stay unknown.
    pub fn wrap_backward(&mut self, payload: &mut [u8]) {
        assert_eq!(payload.len(), PAYLOAD_SIZE, "the payload must be {PAYLOAD_SIZE} bytes");
        self.keys.backward.xor_in_place(payload);
    }

    /// Builds a cell of our own for the client: the tag plus our layer.
    pub fn originate_backward(&mut self, cell: &RelayCell) -> Vec<u8> {
        let mut payload = cell.to_payload();
        self.keys.backward_digest.seal(&mut payload);
        self.keys.backward.xor_in_place(&mut payload);
        payload
    }
}
