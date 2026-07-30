//! Node-level state locks + in-flight transaction counter.
//!
//! A node is locked while any transaction that declares it is `Committed`.
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

use hyperscale_types::NodeId;

/// Whom a newly blocking node blocks in the ready set.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BlockScope {
    /// Every ready transaction touching the node.
    All,
    /// Only ready transactions declaring the node as a write — the node
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
    locked: HashMap<NodeId, LockCounts>,
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
    /// Returns the nodes that newly block, each with the scope of whom it
    /// blocks — the coordinator's ready-set cascade input.
    pub fn lock_declared(
        &mut self,
        reads: impl IntoIterator<Item = NodeId>,
        writes: impl IntoIterator<Item = NodeId>,
    ) -> Vec<(NodeId, BlockScope)> {
        if self.share_reads {
            let mut blocking = Vec::new();
            for node in reads {
                let counts = self.locked.entry(node).or_default();
                counts.reads += 1;
                if counts.reads == 1 && counts.writes == 0 {
                    blocking.push((node, BlockScope::WritersOnly));
                }
            }
            for node in writes {
                let counts = self.locked.entry(node).or_default();
                counts.writes += 1;
                if counts.writes == 1 {
                    blocking.push((node, BlockScope::All));
                }
            }
            blocking
        } else {
            // Exclusive: idempotent set-insert over the union; every newly
            // locked node blocks everyone. Writes marked for
            // classification.
            let mut blocking: Vec<(NodeId, BlockScope)> = self
                .lock_nodes(reads)
                .into_iter()
                .map(|node| (node, BlockScope::All))
                .collect();
            let mut write_nodes = Vec::new();
            for node in writes {
                write_nodes.push(node);
            }
            blocking.extend(
                self.lock_nodes(write_nodes.iter().copied())
                    .into_iter()
                    .map(|node| (node, BlockScope::All)),
            );
            self.mark_write_locked(write_nodes);
            blocking
        }
    }

    /// Release one transaction's declared locks. Returns the nodes worth a
    /// promotion sweep: those whose write lock cleared or that unlocked
    /// entirely. Absent or drained entries are ignored, so an unlock for
    /// nodes never locked here (a remote shard's, or a double release) is
    /// harmless.
    pub fn unlock_declared(
        &mut self,
        reads: impl IntoIterator<Item = NodeId>,
        writes: impl IntoIterator<Item = NodeId>,
    ) -> Vec<NodeId> {
        if self.share_reads {
            let mut promotable = Vec::new();
            for node in reads {
                if let Some(counts) = self.locked.get_mut(&node) {
                    counts.reads = counts.reads.saturating_sub(1);
                    if counts.reads == 0 && counts.writes == 0 {
                        self.locked.remove(&node);
                        promotable.push(node);
                    }
                }
            }
            for node in writes {
                if let Some(counts) = self.locked.get_mut(&node) {
                    counts.writes = counts.writes.saturating_sub(1);
                    if counts.writes == 0 {
                        if counts.reads == 0 {
                            self.locked.remove(&node);
                        }
                        promotable.push(node);
                    }
                }
            }
            promotable
        } else {
            let mut nodes: Vec<NodeId> = reads.into_iter().collect();
            nodes.extend(writes);
            self.unlock_nodes(nodes)
        }
    }

    /// Mark each node in `nodes` as locked, exclusive-style. Returns the
    /// subset that was not already locked — the coordinator uses this to
    /// block deferred txs that touch those nodes.
    pub fn lock_nodes(&mut self, nodes: impl IntoIterator<Item = NodeId>) -> Vec<NodeId> {
        nodes
            .into_iter()
            .filter(|node| match self.locked.entry(*node) {
                std::collections::hash_map::Entry::Occupied(_) => false,
                std::collections::hash_map::Entry::Vacant(entry) => {
                    entry.insert(LockCounts::default());
                    true
                }
            })
            .collect()
    }

    /// Mark each node in `nodes` as unlocked, unconditionally. Returns the
    /// subset that was actually locked before this call — the coordinator
    /// uses this to promote deferred txs waiting on those nodes.
    pub fn unlock_nodes(&mut self, nodes: impl IntoIterator<Item = NodeId>) -> Vec<NodeId> {
        nodes
            .into_iter()
            .filter(|node| self.locked.remove(node).is_some())
            .collect()
    }

    /// Record that the holder of each (already locked) node declared it as
    /// a write. Exclusive-discipline classification bookkeeping; no effect
    /// on lock state.
    pub fn mark_write_locked(&mut self, nodes: impl IntoIterator<Item = NodeId>) {
        for node in nodes {
            if let Some(counts) = self.locked.get_mut(&node) {
                counts.writes = counts.writes.max(1);
            }
        }
    }

    /// Whether some holder of `node` declared it as a write.
    pub fn is_write_locked(&self, node: &NodeId) -> bool {
        self.locked
            .get(node)
            .is_some_and(|counts| counts.writes > 0)
    }

    pub fn is_locked(&self, node: &NodeId) -> bool {
        self.locked.contains_key(node)
    }

    pub fn locked_nodes_count(&self) -> usize {
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

    #[test]
    fn fresh_tracker_is_empty() {
        let tracker = LockTracker::with_read_share(false);
        assert_eq!(tracker.locked_nodes_count(), 0);
        assert_eq!(tracker.in_flight(), 0);
        assert!(!tracker.is_locked(&test_node(1)));
    }

    #[test]
    fn lock_nodes_returns_only_newly_locked() {
        let mut tracker = LockTracker::with_read_share(false);
        let a = test_node(1);
        let b = test_node(2);

        let newly_locked = tracker.lock_nodes([a, b]);
        assert_eq!(newly_locked.len(), 2);
        assert!(tracker.is_locked(&a));
        assert!(tracker.is_locked(&b));

        // Locking the same nodes again yields no newly-locked entries.
        let newly_locked = tracker.lock_nodes([a, b]);
        assert!(newly_locked.is_empty());
        assert_eq!(tracker.locked_nodes_count(), 2);
    }

    #[test]
    fn lock_nodes_handles_partial_overlap() {
        let mut tracker = LockTracker::with_read_share(false);
        let a = test_node(1);
        let b = test_node(2);
        let c = test_node(3);

        tracker.lock_nodes([a, b]);
        // Locking [b, c] should only report c as newly locked.
        let newly_locked = tracker.lock_nodes([b, c]);
        assert_eq!(newly_locked, vec![c]);
        assert_eq!(tracker.locked_nodes_count(), 3);
    }

    #[test]
    fn unlock_nodes_returns_only_newly_unlocked() {
        let mut tracker = LockTracker::with_read_share(false);
        let a = test_node(1);
        let b = test_node(2);
        tracker.lock_nodes([a, b]);

        let newly_unlocked = tracker.unlock_nodes([a, b]);
        assert_eq!(newly_unlocked.len(), 2);
        assert!(!tracker.is_locked(&a));
        assert!(!tracker.is_locked(&b));

        // Unlocking again yields nothing.
        let newly_unlocked = tracker.unlock_nodes([a, b]);
        assert!(newly_unlocked.is_empty());
    }

    #[test]
    fn unlock_ignores_never_locked_nodes() {
        let mut tracker = LockTracker::with_read_share(false);
        let locked = test_node(1);
        let unlocked = test_node(2);
        tracker.lock_nodes([locked]);

        let newly_unlocked = tracker.unlock_nodes([locked, unlocked]);
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
        let read = test_node(1);
        let write = test_node(2);

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
        let node = test_node(1);

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
        let node = test_node(1);

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
        assert!(
            tracker
                .unlock_declared([test_node(9)], [test_node(8)])
                .is_empty()
        );
    }
}
