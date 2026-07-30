//! Declared-key state locks + in-flight transaction counter.
//!
//! A key — a whole node, or one substate slot under it when key-granular
//! admission is on — is locked while any transaction that declares it is
//! `Committed`.
//! Two acquisition disciplines, chosen at construction by the
//! `share_declared_reads` mempool flag:
//!
//! - **Exclusive** (flag off): a node is either locked or not — insert is
//!   idempotent and release unconditional, and the declared mode is
//!   classification bookkeeping only.
//! - **Read-share** (flag on): per-node `(read_count, write_count)`.
//!   Readers stack, a write excludes everyone, and release decrements the
//!   holder's own mode; a node stays locked while either count is
//!   positive.
//!
//! [`LockTracker::lock_declared`] and [`LockTracker::unlock_declared`]
//! report the *transitions* — which nodes newly block (and whom) and
//! which are worth a promotion sweep — so the coordinator can drive the
//! ready-set cascade without knowing the discipline. The tracker also
//! owns **`in_flight_count`**, maintained incrementally on the
//! `Pending → Committed` and `Committed → Completed` transitions and read
//! by backpressure checks.

use std::collections::HashMap;

use hyperscale_types::DeclaredKey;

/// Whom a newly blocking key blocks in the ready set.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BlockScope {
    /// Every ready transaction touching the key.
    All,
    /// Only ready transactions declaring the key as a write — the key
    /// became read-locked, and readers keep sharing it.
    WritersOnly,
}

#[derive(Clone, Copy, Debug, Default)]
struct LockCounts {
    reads: usize,
    writes: usize,
}

pub struct LockTracker {
    share_reads: bool,
    locked: HashMap<DeclaredKey, LockCounts>,
    in_flight_count: usize,
}

impl LockTracker {
    /// A tracker under the discipline the mempool flag selects.
    pub fn with_read_share(share_reads: bool) -> Self {
        Self {
            share_reads,
            locked: HashMap::new(),
            in_flight_count: 0,
        }
    }

    /// Acquire locks for one committed transaction's declared sets.
    /// Returns the keys that newly block, each with the scope of whom
    /// each blocks — the coordinator's ready-set cascade input.
    pub fn lock_declared(
        &mut self,
        reads: impl IntoIterator<Item = DeclaredKey>,
        writes: impl IntoIterator<Item = DeclaredKey>,
    ) -> Vec<(DeclaredKey, BlockScope)> {
        if self.share_reads {
            let mut blocking = Vec::new();
            for key in reads {
                let counts = self.locked.entry(key).or_default();
                counts.reads += 1;
                if counts.reads == 1 && counts.writes == 0 {
                    blocking.push((key, BlockScope::WritersOnly));
                }
            }
            for key in writes {
                let counts = self.locked.entry(key).or_default();
                counts.writes += 1;
                if counts.writes == 1 {
                    blocking.push((key, BlockScope::All));
                }
            }
            blocking
        } else {
            // Exclusive: idempotent set-insert over the union; every newly
            // locked key blocks everyone. Writes marked for
            // classification.
            let mut blocking: Vec<(DeclaredKey, BlockScope)> = self
                .lock_keys(reads)
                .into_iter()
                .map(|key| (key, BlockScope::All))
                .collect();
            let write_keys: Vec<DeclaredKey> = writes.into_iter().collect();
            blocking.extend(
                self.lock_keys(write_keys.iter().copied())
                    .into_iter()
                    .map(|key| (key, BlockScope::All)),
            );
            self.mark_write_locked(write_keys);
            blocking
        }
    }

    /// Release one transaction's declared locks. Returns the keys worth a
    /// promotion sweep: those whose write lock cleared or that unlocked
    /// entirely. Absent or drained entries are ignored, so an unlock for
    /// keys never locked here (a remote shard's, or a double release) is
    /// harmless.
    pub fn unlock_declared(
        &mut self,
        reads: impl IntoIterator<Item = DeclaredKey>,
        writes: impl IntoIterator<Item = DeclaredKey>,
    ) -> Vec<DeclaredKey> {
        if self.share_reads {
            let mut promotable = Vec::new();
            for key in reads {
                if let Some(counts) = self.locked.get_mut(&key) {
                    counts.reads = counts.reads.saturating_sub(1);
                    if counts.reads == 0 && counts.writes == 0 {
                        self.locked.remove(&key);
                        promotable.push(key);
                    }
                }
            }
            for key in writes {
                if let Some(counts) = self.locked.get_mut(&key) {
                    counts.writes = counts.writes.saturating_sub(1);
                    if counts.writes == 0 {
                        if counts.reads == 0 {
                            self.locked.remove(&key);
                        }
                        promotable.push(key);
                    }
                }
            }
            promotable
        } else {
            let mut keys: Vec<DeclaredKey> = reads.into_iter().collect();
            keys.extend(writes);
            self.unlock_keys(keys)
        }
    }

    /// Mark each key in `keys` as locked, exclusive-style. Returns the
    /// subset that was not already locked — the coordinator uses this to
    /// block deferred txs that touch those keys.
    pub fn lock_keys(&mut self, keys: impl IntoIterator<Item = DeclaredKey>) -> Vec<DeclaredKey> {
        keys.into_iter()
            .filter(|key| match self.locked.entry(*key) {
                std::collections::hash_map::Entry::Occupied(_) => false,
                std::collections::hash_map::Entry::Vacant(entry) => {
                    entry.insert(LockCounts::default());
                    true
                }
            })
            .collect()
    }

    /// Mark each key in `keys` as unlocked, unconditionally. Returns the
    /// subset that was actually locked before this call — the coordinator
    /// uses this to promote deferred txs waiting on those keys.
    pub fn unlock_keys(&mut self, keys: impl IntoIterator<Item = DeclaredKey>) -> Vec<DeclaredKey> {
        keys.into_iter()
            .filter(|key| self.locked.remove(key).is_some())
            .collect()
    }

    /// Record that the holder of each (already locked) key declared it as
    /// a write. Exclusive-discipline classification bookkeeping; no effect
    /// on lock state.
    pub fn mark_write_locked(&mut self, keys: impl IntoIterator<Item = DeclaredKey>) {
        for key in keys {
            if let Some(counts) = self.locked.get_mut(&key) {
                counts.writes = counts.writes.max(1);
            }
        }
    }

    /// Whether some holder of `key` declared it as a write.
    pub fn is_write_locked(&self, key: &DeclaredKey) -> bool {
        self.locked.get(key).is_some_and(|counts| counts.writes > 0)
    }

    pub fn is_locked(&self, key: &DeclaredKey) -> bool {
        self.locked.contains_key(key)
    }

    pub fn locked_count(&self) -> usize {
        self.locked.len()
    }

    pub const fn inc_in_flight(&mut self) {
        self.in_flight_count += 1;
    }

    pub const fn dec_in_flight(&mut self) {
        self.in_flight_count = self.in_flight_count.saturating_sub(1);
    }

    /// Transactions currently holding state locks. Used for backpressure.
    pub const fn in_flight(&self) -> usize {
        self.in_flight_count
    }
}

#[cfg(test)]
mod tests {
    use hyperscale_types::test_utils::test_node;

    use super::*;

    fn key(seed: u8) -> DeclaredKey {
        DeclaredKey::node(test_node(seed))
    }

    #[test]
    fn fresh_tracker_is_empty() {
        let tracker = LockTracker::with_read_share(false);
        assert_eq!(tracker.locked_count(), 0);
        assert_eq!(tracker.in_flight(), 0);
        assert!(!tracker.is_locked(&key(1)));
    }

    #[test]
    fn lock_nodes_returns_only_newly_locked() {
        let mut tracker = LockTracker::with_read_share(false);
        let a = key(1);
        let b = key(2);

        let newly_locked = tracker.lock_keys([a, b]);
        assert_eq!(newly_locked.len(), 2);
        assert!(tracker.is_locked(&a));
        assert!(tracker.is_locked(&b));

        // Locking the same nodes again yields no newly-locked entries.
        let newly_locked = tracker.lock_keys([a, b]);
        assert!(newly_locked.is_empty());
        assert_eq!(tracker.locked_count(), 2);
    }

    #[test]
    fn lock_nodes_handles_partial_overlap() {
        let mut tracker = LockTracker::with_read_share(false);
        let a = key(1);
        let b = key(2);
        let c = key(3);

        tracker.lock_keys([a, b]);
        // Locking [b, c] should only report c as newly locked.
        let newly_locked = tracker.lock_keys([b, c]);
        assert_eq!(newly_locked, vec![c]);
        assert_eq!(tracker.locked_count(), 3);
    }

    #[test]
    fn unlock_nodes_returns_only_newly_unlocked() {
        let mut tracker = LockTracker::with_read_share(false);
        let a = key(1);
        let b = key(2);
        tracker.lock_keys([a, b]);

        let newly_unlocked = tracker.unlock_keys([a, b]);
        assert_eq!(newly_unlocked.len(), 2);
        assert!(!tracker.is_locked(&a));
        assert!(!tracker.is_locked(&b));

        // Unlocking again yields nothing.
        let newly_unlocked = tracker.unlock_keys([a, b]);
        assert!(newly_unlocked.is_empty());
    }

    #[test]
    fn unlock_ignores_never_locked_nodes() {
        let mut tracker = LockTracker::with_read_share(false);
        let locked = key(1);
        let unlocked = key(2);
        tracker.lock_keys([locked]);

        let newly_unlocked = tracker.unlock_keys([locked, unlocked]);
        assert_eq!(newly_unlocked, vec![locked]);
    }

    #[test]
    fn counter_increments_and_saturates_on_decrement() {
        let mut tracker = LockTracker::with_read_share(false);

        tracker.inc_in_flight();
        tracker.inc_in_flight();
        assert_eq!(tracker.in_flight(), 2);

        tracker.dec_in_flight();
        assert_eq!(tracker.in_flight(), 1);

        // Over-decrementing saturates at 0 rather than wrapping.
        tracker.dec_in_flight();
        tracker.dec_in_flight();
        tracker.dec_in_flight();
        assert_eq!(tracker.in_flight(), 0);
    }

    #[test]
    fn exclusive_lock_declared_blocks_everyone_and_marks_writes() {
        let mut tracker = LockTracker::with_read_share(false);
        let read = key(1);
        let write = key(2);

        let blocking = tracker.lock_declared([read], [write]);
        assert_eq!(
            blocking,
            vec![(read, BlockScope::All), (write, BlockScope::All)]
        );
        assert!(!tracker.is_write_locked(&read));
        assert!(tracker.is_write_locked(&write));

        let promotable = tracker.unlock_declared([read], [write]);
        assert_eq!(promotable, vec![read, write]);
        assert!(!tracker.is_locked(&read));
        assert!(!tracker.is_locked(&write));
    }

    #[test]
    fn shared_readers_stack_and_release_without_promotion_until_drained() {
        let mut tracker = LockTracker::with_read_share(true);
        let node = key(1);

        // First reader blocks writers; the second adds no new blocking.
        assert_eq!(
            tracker.lock_declared([node], []),
            vec![(node, BlockScope::WritersOnly)]
        );
        assert!(tracker.lock_declared([node], []).is_empty());
        assert!(tracker.is_locked(&node));
        assert!(!tracker.is_write_locked(&node));

        // Draining one reader promotes nothing; draining the last does.
        assert!(tracker.unlock_declared([node], []).is_empty());
        assert_eq!(tracker.unlock_declared([node], []), vec![node]);
        assert!(!tracker.is_locked(&node));
    }

    #[test]
    fn shared_write_excludes_and_its_release_promotes_even_over_readers() {
        let mut tracker = LockTracker::with_read_share(true);
        let node = key(1);

        tracker.lock_declared([node], []);
        // A write on a read-locked node (the commit pipeline admits this)
        // newly blocks everyone.
        assert_eq!(
            tracker.lock_declared([], [node]),
            vec![(node, BlockScope::All)]
        );
        assert!(tracker.is_write_locked(&node));

        // Releasing the write promotes readers even while a reader holds.
        assert_eq!(tracker.unlock_declared([], [node]), vec![node]);
        assert!(tracker.is_locked(&node));
        assert!(!tracker.is_write_locked(&node));
        assert_eq!(tracker.unlock_declared([node], []), vec![node]);
        assert!(!tracker.is_locked(&node));
    }

    #[test]
    fn shared_unlock_ignores_never_locked_nodes() {
        let mut tracker = LockTracker::with_read_share(true);
        assert!(tracker.unlock_declared([key(9)], [key(8)]).is_empty());
    }
}
