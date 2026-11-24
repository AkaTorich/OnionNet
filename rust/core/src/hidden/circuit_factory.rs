//! Builds circuits to given nodes out of the node's own relay list.
//!
//! Pulled out on its own because a hidden service needs circuits constantly and
//! in different directions — to introduction points, to meeting points — under
//! the same path-selection rules. The list is asked for afresh each time: a
//! hidden service lives for hours while relays come and go.

use crate::crypto::rand;
use crate::directory::path_selector::{PathError, PathSelector};
use crate::directory::relay_descriptor::RelayDescriptor;
use crate::directory::relay_list::RelayList;
use crate::directory::relay_reputation::RelayReputation;
use crate::streams::multiplexed_circuit::MultiplexedCircuit;
use crate::transport::circuit::{Circuit, CircuitError};
use std::sync::Arc;
use std::time::Duration;

#[derive(Debug)]
pub enum FactoryError {
    Path(PathError),
    Circuit(CircuitError),
}

impl std::fmt::Display for FactoryError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            FactoryError::Path(e) => write!(f, "{e}"),
            FactoryError::Circuit(e) => write!(f, "{e}"),
        }
    }
}
impl std::error::Error for FactoryError {}

pub struct CircuitFactory {
    source: Box<dyn Fn() -> RelayList + Send + Sync>,
    pub self_fingerprint: Option<Vec<u8>>,
    pub length: usize,
    pub minimum_length: usize,
    pub require_distinct_subnets: bool,
    pub timeout: Duration,
    pub reputation: Option<Arc<RelayReputation>>,
    /// The node's long-lived entry ("guard"): every circuit starts there, so a
    /// hostile relay does not get its turn at seeing our address in time.
    pub guard: Option<Vec<u8>>,
    last_length: usize,
}

impl CircuitFactory {
    pub fn new(relays: RelayList, self_fingerprint: Option<Vec<u8>>) -> CircuitFactory {
        CircuitFactory::with_source(Box::new(move || relays.clone()), self_fingerprint)
    }

    /// A factory that asks for the list afresh every time.
    pub fn with_source(
        source: Box<dyn Fn() -> RelayList + Send + Sync>,
        self_fingerprint: Option<Vec<u8>>,
    ) -> CircuitFactory {
        CircuitFactory {
            source,
            self_fingerprint,
            length: 3,
            minimum_length: 2,
            require_distinct_subnets: false,
            timeout: Duration::from_secs(30),
            reputation: None,
            guard: None,
            last_length: 0,
        }
    }

    pub fn relays(&self) -> RelayList {
        (self.source)()
    }

    pub fn last_length(&self) -> usize {
        self.last_length
    }

    pub fn find(&self, fingerprint: &[u8]) -> Option<RelayDescriptor> {
        self.relays().find(fingerprint).cloned()
    }

    /// Builds a circuit whose last node is the given one.
    pub fn build_to(&mut self, exit: &RelayDescriptor) -> Result<MultiplexedCircuit, FactoryError> {
        let mut selector = PathSelector::default();
        selector.length = self.length;
        selector.minimum_length = self.minimum_length;
        selector.self_fingerprint = self.self_fingerprint.clone();
        selector.require_distinct_subnets = self.require_distinct_subnets;
        selector.trusted_exits = vec![exit.fingerprint().to_vec()];
        selector.reputation = self.reputation.clone();
        // The circuit ends at the relay's own service and lets nothing out: the
        // relay need not be an exit. The node was named outright, so if it is
        // our own, so be it — a refusal would give us away.
        selector.require_exit_flag = false;
        selector.allow_self_as_exit = true;

        let relays = self.relays();
        // The guard leads, unless it is the very node we go to (a circuit
        // cannot pass a node twice) or it has left the list.
        if let Some(guard) = &self.guard {
            if !rand::constant_time_equals(&exit.fingerprint(), guard) && relays.find(guard).is_some() {
                selector.guard_fingerprint = Some(guard.clone());
            }
        }
        let path = selector.choose(&relays).map_err(FactoryError::Path)?;
        self.last_length = path.len();

        match Circuit::build(path.clone(), self.timeout) {
            Ok(circuit) => {
                if let Some(rep) = &self.reputation {
                    for relay in &path {
                        rep.record_success(&relay.fingerprint());
                    }
                }
                Ok(MultiplexedCircuit::new(circuit))
            }
            Err(e) => {
                if let (Some(rep), Some(relay)) = (&self.reputation, &e.relay) {
                    rep.record_failure(&relay.fingerprint());
                }
                Err(FactoryError::Circuit(e))
            }
        }
    }

    /// The same, by the node's fingerprint.
    pub fn build_to_fingerprint(&mut self, fingerprint: &[u8]) -> Result<MultiplexedCircuit, FactoryError> {
        let exit = self
            .find(fingerprint)
            .ok_or_else(|| FactoryError::Path(PathError("no node with that fingerprint is in the network list".into())))?;
        self.build_to(&exit)
    }

    /// A random node of somebody else's — for an introduction or meeting point.
    /// Our own node and anything excluded are left out.
    pub fn pick_random(&self, exclude: &[Vec<u8>]) -> Option<RelayDescriptor> {
        let relays = self.relays();
        let candidates: Vec<&RelayDescriptor> = relays
            .relays()
            .iter()
            .filter(|r| {
                let fp = r.fingerprint();
                if let Some(self_fp) = &self.self_fingerprint {
                    if rand::constant_time_equals(&fp, self_fp) {
                        return false;
                    }
                }
                !exclude.iter().any(|e| rand::constant_time_equals(&fp, e))
            })
            .collect();

        if candidates.is_empty() {
            return None;
        }
        match &self.reputation {
            None => Some((*rand::pick(&candidates)).clone()),
            Some(rep) => {
                let alive = rep.sift(candidates, |r| r.fingerprint().to_vec());
                Some((*rand::pick_weighted(&alive, |r| rep.weight(&r.fingerprint()))).clone())
            }
        }
    }
}
