//! The relays a node knows right now — what circuits are built out of.
//!
//! Nobody signs it as a whole and nobody hands it out: every node gathers its
//! own from the cards that came its way, and every card is signed by its own
//! relay and carries that relay's pass. Two nodes' lists differ a little, and
//! that is in order.

use crate::crypto::rand;
use crate::directory::relay_descriptor::RelayDescriptor;

#[derive(Default, Clone)]
pub struct RelayList {
    relays: Vec<RelayDescriptor>,
}

impl RelayList {
    pub fn new() -> RelayList {
        RelayList { relays: Vec::new() }
    }

    pub fn from_relays<I: IntoIterator<Item = RelayDescriptor>>(relays: I) -> RelayList {
        RelayList {
            relays: relays.into_iter().collect(),
        }
    }

    pub fn relays(&self) -> &[RelayDescriptor] {
        &self.relays
    }

    pub fn relays_mut(&mut self) -> &mut Vec<RelayDescriptor> {
        &mut self.relays
    }

    pub fn count(&self) -> usize {
        self.relays.len()
    }

    pub fn push(&mut self, relay: RelayDescriptor) {
        self.relays.push(relay);
    }

    /// The relays willing to be last in a circuit.
    pub fn exits(&self) -> Vec<&RelayDescriptor> {
        self.relays.iter().filter(|r| r.allows_exit).collect()
    }

    pub fn find(&self, fingerprint: &[u8]) -> Option<&RelayDescriptor> {
        self.relays
            .iter()
            .find(|r| rand::constant_time_equals(&r.fingerprint(), fingerprint))
    }
}
