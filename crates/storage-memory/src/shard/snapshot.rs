//! State-history-based in-memory snapshot.
//!
//! Reads at the current tip are a direct `BTreeMap::get` on
//! `current_state`. Reads at a historical version V use a single
//! forward-scan on `state_history` to find the smallest entry `(K, v')`
//! with `v' > V`; its stored prior value is the value of K at V. If no
//! such entry exists, `current_state[K]` was stable since V and is the
//! answer.

use std::collections::BTreeMap;
use std::ops::Bound;

use hyperscale_storage::SubstateDatabase;
use hyperscale_types::SubstateKey;

/// Point-in-time snapshot of in-memory storage scoped to a specific
/// version within the retention window. Retention enforcement happens
/// at construction in `SimShardStorage::snapshot_at`.
pub struct SimSnapshot {
    pub(crate) current_state: BTreeMap<SubstateKey, Vec<u8>>,
    pub(crate) state_history: BTreeMap<(SubstateKey, u64), Option<Vec<u8>>>,
    /// Target version for all reads from this snapshot.
    pub(crate) version: u64,
    /// Current committed tip at snapshot-construction time. When
    /// `version >= current_version` we take the trivial branch
    /// (direct `current_state` read) for every operation.
    pub(crate) current_version: u64,
}

/// Value of `key` at `version`: the prior value of the smallest
/// state-history write after `version` (value-just-before that write,
/// which equals value-at-version since no writes happened between), or
/// the current value when no later write exists.
pub fn value_at_version(
    current_state: &BTreeMap<SubstateKey, Vec<u8>>,
    state_history: &BTreeMap<(SubstateKey, u64), Option<Vec<u8>>>,
    key: SubstateKey,
    version: u64,
    current_version: u64,
) -> Option<Vec<u8>> {
    let current = current_state.get(&key).cloned();

    if version >= current_version {
        return current;
    }

    let next = state_history
        .range((Bound::Included((key, version + 1)), Bound::Unbounded))
        .next();
    match next {
        Some(((k, _v_prime), prior)) if *k == key => prior.clone(),
        _ => current,
    }
}

impl SubstateDatabase for SimSnapshot {
    fn substate(&self, key: SubstateKey) -> Option<Vec<u8>> {
        value_at_version(
            &self.current_state,
            &self.state_history,
            key,
            self.version,
            self.current_version,
        )
    }
}
