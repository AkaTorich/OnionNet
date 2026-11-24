//! A private tally of the nodes: which of them raised circuits reliably and
//! which let us down.
//!
//! Three decisions, each deliberate:
//!
//! 1. The tally NEVER leaves the machine. A published reputation is a
//!    fingerprint of what you used and when.
//! 2. The weight has a floor: one failure does not drop a node for good, so the
//!    network does not ossify around a few "proven" ones and a client is never
//!    left with no path.
//! 3. Failures are forgotten with time: a node down yesterday is fit again
//!    today.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// A node never falls below this weight, however badly it lets us down.
pub const MINIMUM_WEIGHT: f64 = 0.05;

pub struct RelayReputation {
    inner: Mutex<Inner>,
    /// The time in which an event's weight halves.
    half_life: Duration,
    /// How long a node is kept out of circuits right after a refusal. A fresh
    /// refusal means not "pick it less often" but "do not pick it at all for a
    /// minute"; the first success lifts the ban early.
    blackout: Duration,
}

struct Inner {
    records: HashMap<Vec<u8>, Record>,
}

/// One node's tally, with forgetting.
struct Record {
    good: f64,
    bad: f64,
    /// When the node last refused.
    failed_at: Option<Instant>,
    updated: Instant,
}

impl Record {
    fn new() -> Record {
        Record {
            good: 0.0,
            bad: 0.0,
            failed_at: None,
            updated: Instant::now(),
        }
    }

    /// Weakens both pans with time: half the weight over the half-life.
    fn decay(&mut self, half_life: Duration) {
        if half_life.is_zero() {
            return;
        }
        let now = Instant::now();
        let elapsed = now.saturating_duration_since(self.updated).as_secs_f64();
        if elapsed <= 0.0 {
            return;
        }
        let factor = 0.5f64.powf(elapsed / half_life.as_secs_f64());
        self.good *= factor;
        self.bad *= factor;
        self.updated = now;
    }
}

impl Default for RelayReputation {
    fn default() -> Self {
        RelayReputation::new()
    }
}

impl RelayReputation {
    pub fn new() -> RelayReputation {
        RelayReputation {
            inner: Mutex::new(Inner {
                records: HashMap::new(),
            }),
            half_life: Duration::from_secs(30 * 60),
            blackout: Duration::from_secs(60),
        }
    }

    pub fn with_timings(half_life: Duration, blackout: Duration) -> RelayReputation {
        RelayReputation {
            inner: Mutex::new(Inner {
                records: HashMap::new(),
            }),
            half_life,
            blackout,
        }
    }

    /// How many nodes there is any word at all about.
    pub fn count(&self) -> usize {
        self.inner.lock().unwrap().records.len()
    }

    pub fn record_success(&self, fingerprint: &[u8]) {
        self.update(fingerprint, true);
    }

    pub fn record_failure(&self, fingerprint: &[u8]) {
        self.update(fingerprint, false);
    }

    /// Whether the node is serving a temporary ban after a fresh refusal.
    pub fn is_shunned(&self, fingerprint: &[u8]) -> bool {
        if self.blackout.is_zero() {
            return false;
        }
        let inner = self.inner.lock().unwrap();
        match inner.records.get(fingerprint) {
            Some(record) => match record.failed_at {
                Some(at) => at.elapsed() < self.blackout,
                None => false,
            },
            None => false,
        }
    }

    /// Sieves out those serving a ban. If nobody is left, returns the input: a
    /// circuit through a doubtful node beats no circuit at all.
    pub fn sift<T, F>(&self, items: Vec<T>, fingerprint: F) -> Vec<T>
    where
        F: Fn(&T) -> Vec<u8>,
    {
        if items.is_empty() {
            return items;
        }
        let kept: Vec<usize> = items
            .iter()
            .enumerate()
            .filter(|(_, it)| !self.is_shunned(&fingerprint(it)))
            .map(|(i, _)| i)
            .collect();
        if kept.is_empty() {
            return items;
        }
        if kept.len() == items.len() {
            return items;
        }
        let keep: std::collections::HashSet<usize> = kept.into_iter().collect();
        items
            .into_iter()
            .enumerate()
            .filter(|(i, _)| keep.contains(i))
            .map(|(_, it)| it)
            .collect()
    }

    /// A node's weight when a path is picked: from `MINIMUM_WEIGHT` to one. An
    /// unfamiliar node gets 0.5 — midway between the proven and the failed,
    /// because we honestly know nothing about it.
    pub fn weight(&self, fingerprint: &[u8]) -> f64 {
        let mut inner = self.inner.lock().unwrap();
        let record = match inner.records.get_mut(fingerprint) {
            Some(r) => r,
            None => return 0.5,
        };
        record.decay(self.half_life);

        // Laplace smoothing: one success and one failure are added to any tally.
        let weight = (record.good + 1.0) / (record.good + record.bad + 2.0);
        if weight < MINIMUM_WEIGHT {
            MINIMUM_WEIGHT
        } else {
            weight
        }
    }

    /// How many successes and failures a node has on record — to show the owner.
    pub fn try_describe(&self, fingerprint: &[u8]) -> Option<(f64, f64)> {
        let mut inner = self.inner.lock().unwrap();
        let record = inner.records.get_mut(fingerprint)?;
        record.decay(self.half_life);
        Some((record.good, record.bad))
    }

    pub fn forget(&self, fingerprint: &[u8]) {
        self.inner.lock().unwrap().records.remove(fingerprint);
    }

    pub fn clear(&self) {
        self.inner.lock().unwrap().records.clear();
    }

    fn update(&self, fingerprint: &[u8], success: bool) {
        let mut inner = self.inner.lock().unwrap();
        let record = inner
            .records
            .entry(fingerprint.to_vec())
            .or_insert_with(Record::new);
        record.decay(self.half_life);
        if success {
            record.good += 1.0;
            record.failed_at = None; // it answered — the ban is lifted early
        } else {
            record.bad += 1.0;
            record.failed_at = Some(Instant::now());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unknown_node_is_neutral() {
        let rep = RelayReputation::new();
        assert_eq!(rep.weight(b"unknown-fingerprint"), 0.5);
    }

    #[test]
    fn success_raises_failure_lowers_with_a_floor() {
        let rep = RelayReputation::new();
        let fp = b"node-a";
        for _ in 0..5 {
            rep.record_success(fp);
        }
        assert!(rep.weight(fp) > 0.5);

        let bad = b"node-b";
        for _ in 0..50 {
            rep.record_failure(bad);
        }
        assert!(rep.weight(bad) >= MINIMUM_WEIGHT);
        assert!(rep.weight(bad) < 0.2);
    }

    #[test]
    fn fresh_failure_shuns_then_success_lifts() {
        let rep = RelayReputation::new();
        let fp = b"node-c";
        rep.record_failure(fp);
        assert!(rep.is_shunned(fp));
        rep.record_success(fp);
        assert!(!rep.is_shunned(fp));
    }

    #[test]
    fn sift_drops_shunned_but_never_empties() {
        let rep = RelayReputation::new();
        rep.record_failure(b"x");
        let items = vec![b"x".to_vec(), b"y".to_vec()];
        let kept = rep.sift(items.clone(), |it| it.clone());
        assert_eq!(kept, vec![b"y".to_vec()]);

        // Everyone shunned → the original list comes back.
        rep.record_failure(b"y");
        let all = rep.sift(items.clone(), |it| it.clone());
        assert_eq!(all, items);
    }
}
