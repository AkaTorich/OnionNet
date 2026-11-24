//! Choosing a circuit's path out of the node list.
//!
//! The rules are no formality. Two nodes in one /16 subnet are most likely one
//! owner or one carrier who sees both ends at once. Our own node in our own
//! circuit is pointless: the first hop knows who we are anyway. The guard is
//! kept constant on purpose — a fresh entry node each time would eventually be
//! a hostile one, and then a stranger would learn our address.

use crate::crypto::rand;
use crate::directory::relay_descriptor::RelayDescriptor;
use crate::directory::relay_list::RelayList;
use crate::directory::relay_reputation::RelayReputation;
use std::net::Ipv4Addr;
use std::sync::Arc;

/// There is nothing to build a path out of.
#[derive(Debug, Clone)]
pub struct PathError(pub String);

impl std::fmt::Display for PathError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}
impl std::error::Error for PathError {}

pub struct PathSelector {
    /// The desired circuit length.
    pub length: usize,
    /// Shorter than this we do not build a circuit at all (one hop would reveal
    /// the client's address to the far end).
    pub minimum_length: usize,
    /// Whether to keep the hops in different /16 subnets.
    pub require_distinct_subnets: bool,
    /// Our own fingerprint — we do not take ourselves into a circuit.
    pub self_fingerprint: Option<Vec<u8>>,
    /// Allow our own node to be last in a circuit (a hidden service coming to a
    /// client-named meeting point that happens to be its own node).
    pub allow_self_as_exit: bool,
    /// The constant entry node. `None` — we pick at random.
    pub guard_fingerprint: Option<Vec<u8>>,
    /// Who not to take into the path as any hop.
    pub exclude_fingerprints: Vec<Vec<u8>>,
    /// Whether the last relay must be willing to let traffic out to the
    /// internet.
    pub require_exit_flag: bool,
    /// Nodes the owner allowed to be exits. Empty — any node with the exit flag.
    pub trusted_exits: Vec<Vec<u8>>,
    /// A private tally of the nodes. `None` — equal chances.
    pub reputation: Option<Arc<RelayReputation>>,

    last_chosen_length: usize,
    last_was_shortened: bool,
}

impl Default for PathSelector {
    fn default() -> Self {
        PathSelector {
            length: 3,
            minimum_length: 2,
            require_distinct_subnets: true,
            self_fingerprint: None,
            allow_self_as_exit: false,
            guard_fingerprint: None,
            exclude_fingerprints: Vec::new(),
            require_exit_flag: true,
            trusted_exits: Vec::new(),
            reputation: None,
            last_chosen_length: 0,
            last_was_shortened: false,
        }
    }
}

impl PathSelector {
    /// How many hops actually came out of the last choice.
    pub fn last_chosen_length(&self) -> usize {
        self.last_chosen_length
    }
    /// Whether the circuit had to be shortened for want of nodes.
    pub fn last_was_shortened(&self) -> bool {
        self.last_was_shortened
    }

    /// Chooses a path. The first node is the guard, the last is the exit.
    pub fn choose(&mut self, directory: &RelayList) -> Result<Vec<RelayDescriptor>, PathError> {
        if self.length < 1 {
            return Err(PathError("the circuit length is less than one node".into()));
        }

        let mut pool: Vec<&RelayDescriptor> = Vec::new();
        let mut exit_pool: Vec<&RelayDescriptor> = Vec::new();

        for relay in directory.relays() {
            let fp = relay.fingerprint();
            let is_self = match &self.self_fingerprint {
                Some(s) => rand::constant_time_equals(&fp, s),
                None => false,
            };
            if self.is_excluded(&fp) {
                continue;
            }
            if !is_self {
                pool.push(relay);
            }
            if !is_self || self.allow_self_as_exit {
                exit_pool.push(relay);
            }
        }

        if exit_pool.is_empty() {
            return Err(PathError("there is not a single usable node in the list".into()));
        }

        // The exit is chosen first: it is the most constrained.
        let exit = self
            .pick_exit(&exit_pool)
            .ok_or_else(|| PathError("there is not a single trusted exit node".into()))?;

        // How many nodes are left for the guard and the middle.
        let mut available = pool.len();
        if pool.iter().any(|r| same_relay(r, exit)) {
            available -= 1;
        }

        let effective = self.length.min(available + 1);
        self.last_was_shortened = effective < self.length;

        if effective < self.minimum_length {
            return Err(PathError(format!(
                "usable nodes: {}, while a circuit needs at least {}. Bring more nodes into the network.",
                available + 1,
                self.minimum_length
            )));
        }

        let mut chosen: Vec<&RelayDescriptor> = Vec::new();

        let guard = self
            .pick_guard(&pool, exit, effective)
            .ok_or_else(|| PathError("there is no suitable entry node".into()))?;
        chosen.push(guard);

        for _ in 0..effective.saturating_sub(2) {
            let middle = self.pick_distinct(&pool, &chosen, exit, effective).ok_or_else(|| {
                PathError(format!("the network has too few nodes for a circuit of length {effective}"))
            })?;
            chosen.push(middle);
        }

        if effective > 1 {
            chosen.push(exit);
        }

        self.last_chosen_length = chosen.len();
        Ok(chosen.into_iter().cloned().collect())
    }

    fn is_excluded(&self, fingerprint: &[u8]) -> bool {
        self.exclude_fingerprints
            .iter()
            .any(|banned| rand::constant_time_equals(fingerprint, banned))
    }

    fn pick_exit<'a>(&self, pool: &[&'a RelayDescriptor]) -> Option<&'a RelayDescriptor> {
        let candidates: Vec<&RelayDescriptor> = pool
            .iter()
            .copied()
            .filter(|r| !(self.require_exit_flag && !r.allows_exit))
            .filter(|r| self.is_trusted_exit(r))
            .collect();
        self.choose_weighted(candidates)
    }

    /// A choice weighted by the tally, if one is set.
    fn choose_weighted<'a>(&self, candidates: Vec<&'a RelayDescriptor>) -> Option<&'a RelayDescriptor> {
        if candidates.is_empty() {
            return None;
        }
        match &self.reputation {
            None => Some(*rand::pick(&candidates)),
            Some(rep) => {
                // First drop those that just refused flatly; weight only lowers
                // them, while a node that is down now brings the whole circuit
                // down whatever position it stands in.
                let alive = rep.sift(candidates, |r| r.fingerprint().to_vec());
                if alive.is_empty() {
                    return None;
                }
                Some(*rand::pick_weighted(&alive, |r| rep.weight(&r.fingerprint())))
            }
        }
    }

    fn is_trusted_exit(&self, relay: &RelayDescriptor) -> bool {
        if self.trusted_exits.is_empty() {
            return true;
        }
        let fp = relay.fingerprint();
        self.trusted_exits
            .iter()
            .any(|t| rand::constant_time_equals(&fp, t))
    }

    fn pick_guard<'a>(
        &self,
        pool: &[&'a RelayDescriptor],
        exit: &RelayDescriptor,
        effective: usize,
    ) -> Option<&'a RelayDescriptor> {
        if let Some(guard_fp) = &self.guard_fingerprint {
            for relay in pool {
                if !rand::constant_time_equals(&relay.fingerprint(), guard_fp) {
                    continue;
                }
                // The constant guard is unsuitable only if it also became the exit.
                if effective > 1 && same_relay(relay, exit) {
                    return None;
                }
                return Some(*relay);
            }
            return None;
        }
        self.pick_distinct(pool, &[], exit, effective)
    }

    fn pick_distinct<'a>(
        &self,
        pool: &[&'a RelayDescriptor],
        taken: &[&RelayDescriptor],
        exit: &RelayDescriptor,
        effective: usize,
    ) -> Option<&'a RelayDescriptor> {
        let mut candidates: Vec<&RelayDescriptor> = Vec::new();

        for relay in pool {
            if effective > 1 && same_relay(relay, exit) {
                continue;
            }
            let mut clash = false;
            for already in taken {
                if same_relay(relay, already) {
                    clash = true;
                    break;
                }
                if self.require_distinct_subnets && same_subnet(relay, already) {
                    clash = true;
                    break;
                }
            }
            if !clash && self.require_distinct_subnets && effective > 1 && same_subnet(relay, exit) {
                clash = true;
            }
            if clash {
                continue;
            }
            candidates.push(relay);
        }

        // The subnet requirement is a preference, not a prohibition: a small
        // network on one machine could build nothing otherwise.
        if candidates.is_empty() && self.require_distinct_subnets {
            for relay in pool {
                if effective > 1 && same_relay(relay, exit) {
                    continue;
                }
                let used = taken.iter().any(|a| same_relay(relay, a));
                if !used {
                    candidates.push(relay);
                }
            }
        }

        self.choose_weighted(candidates)
    }
}

fn same_relay(a: &RelayDescriptor, b: &RelayDescriptor) -> bool {
    rand::constant_time_equals(&a.fingerprint(), &b.fingerprint())
}

/// Whether it is one /16 subnet. Names that do not resolve to an IPv4 literal
/// are counted as different.
fn same_subnet(a: &RelayDescriptor, b: &RelayDescriptor) -> bool {
    let first = a.host.parse::<Ipv4Addr>();
    let second = b.host.parse::<Ipv4Addr>();
    match (first, second) {
        (Ok(x), Ok(y)) => {
            let xo = x.octets();
            let yo = y.octets();
            xo[0] == yo[0] && xo[1] == yo[1]
        }
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::NodeIdentity;

    fn relay(host: &str, exit: bool) -> RelayDescriptor {
        let id = NodeIdentity::create("").unwrap();
        RelayDescriptor::from_identity(&id, host, 9000, exit)
    }

    #[test]
    fn builds_a_three_hop_path_in_distinct_subnets() {
        let dir = RelayList::from_relays(vec![
            relay("10.0.0.1", true),
            relay("11.0.0.1", true),
            relay("12.0.0.1", true),
            relay("13.0.0.1", true),
        ]);
        let mut sel = PathSelector::default();
        let path = sel.choose(&dir).unwrap();
        assert_eq!(path.len(), 3);
        assert!(path.last().unwrap().allows_exit);
        // All three hops are distinct nodes.
        let fps: std::collections::HashSet<_> = path.iter().map(|r| r.fingerprint()).collect();
        assert_eq!(fps.len(), 3);
    }

    #[test]
    fn too_few_nodes_is_an_error() {
        let dir = RelayList::from_relays(vec![relay("10.0.0.1", true)]);
        let mut sel = PathSelector::default(); // minimum_length = 2
        assert!(sel.choose(&dir).is_err());
    }

    #[test]
    fn requires_an_exit_capable_last_hop() {
        let dir = RelayList::from_relays(vec![
            relay("10.0.0.1", false),
            relay("11.0.0.1", false),
            relay("12.0.0.1", false),
        ]);
        let mut sel = PathSelector::default();
        assert!(sel.choose(&dir).is_err());
    }
}
