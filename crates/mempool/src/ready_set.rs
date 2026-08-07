//! Pending-transaction ready/deferred tracking.
//!
//! Maintains the incremental ready set that backs O(1) proposal selection.
//! Every known Pending transaction is in exactly one of:
//!
//! - **ready** — no blocking nodes, eligible for inclusion in the next block.
//! - **deferred** — at least one declared node is locked by an in-flight
//!   transaction, or already claimed by another ready-set transaction.
//! - **neither** — never added, or explicitly removed.
//!
//! Conflicts key on [`DeclaredKey`] — the node-granular projection of
//! the declared sets. Three maintained reverse indices keep
//! add/remove/block/promote O(1) in the number of transactions touching
//! a given key:
//!
//! - `ready_txs_by_key`: key → ready hashes declaring it.
//! - `txs_deferred_by_key`: key → deferred hashes blocked by it.
//! - `deferred_by_keys`: hash → set of keys blocking it.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::sync::Arc;
use std::time::Duration;

use hyperscale_types::{DeclaredKey, LocalTimestamp, Transaction, TxHash, Verified};

use crate::lock_tracker::{BlockScope, LockTracker};

struct ReadyEntry {
    tx: Arc<Verified<Transaction>>,
    added_at: LocalTimestamp,
}

/// Aggregated deferral statistics: how often admission deferred, why, and
/// how long deferred transactions waited before promotion.
///
/// Waits are protocol-time deltas across events — one clock reading per
/// event, never a span within one.
///
/// A deferral is **read-read** when every blocking overlap is a declared
/// read held only by declared reads — exactly the deferrals a
/// read-compatible admission policy would admit. Any write on either side
/// classifies the event **write-involved**.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct DeferralStats {
    /// Transactions that entered the deferred set (admission or a lock
    /// landing on a ready claim), counted per entry event.
    pub deferral_events: u64,
    /// Deferral events whose every blocking overlap was read-read.
    pub read_read_deferrals: u64,
    /// Deferral events with a write on either side of some blocking
    /// overlap.
    pub write_involved_deferrals: u64,
    /// Deferred transactions later promoted to ready.
    pub promotions: u64,
    /// Total deferred-to-ready wait across all promotions.
    pub total_deferral_wait: Duration,
    /// The longest single deferred-to-ready wait.
    pub max_deferral_wait: Duration,
    /// High-water mark of any single node's deferred queue.
    pub peak_deferred_queue_depth: usize,
}

impl DeferralStats {
    /// Fold `other` into `self` — sums for the counters, maxima for the
    /// extremes — so per-node readouts aggregate across a cluster.
    pub fn absorb(&mut self, other: &Self) {
        self.deferral_events += other.deferral_events;
        self.read_read_deferrals += other.read_read_deferrals;
        self.write_involved_deferrals += other.write_involved_deferrals;
        self.promotions += other.promotions;
        self.total_deferral_wait += other.total_deferral_wait;
        self.max_deferral_wait = self.max_deferral_wait.max(other.max_deferral_wait);
        self.peak_deferred_queue_depth = self
            .peak_deferred_queue_depth
            .max(other.peak_deferred_queue_depth);
    }
}

pub struct ReadySet {
    share_reads: bool,
    ready: BTreeMap<TxHash, ReadyEntry>,
    deferred_by_keys: HashMap<TxHash, HashSet<DeclaredKey>>,
    txs_deferred_by_key: HashMap<DeclaredKey, HashSet<TxHash>>,
    ready_txs_by_key: HashMap<DeclaredKey, HashSet<TxHash>>,
    /// When each currently deferred tx first entered the deferred set;
    /// removed on promotion (recording the wait) or removal.
    deferred_since: HashMap<TxHash, LocalTimestamp>,
    stats: DeferralStats,
}

impl ReadySet {
    /// A ready set under the admission rule the mempool flag selects.
    pub fn with_read_share(share_reads: bool) -> Self {
        Self {
            share_reads,
            ready: BTreeMap::new(),
            deferred_by_keys: HashMap::new(),
            txs_deferred_by_key: HashMap::new(),
            ready_txs_by_key: HashMap::new(),
            deferred_since: HashMap::new(),
            stats: DeferralStats::default(),
        }
    }

    pub const fn deferral_stats(&self) -> DeferralStats {
        self.stats
    }

    fn declares_write(tx: &Transaction, key: &DeclaredKey) -> bool {
        tx.admission_write_keys().iter().any(|write| write == key)
    }

    /// Whether any ready-set claimant of `key` declared it as a write.
    fn ready_claim_is_write(&self, key: &DeclaredKey) -> bool {
        self.ready_txs_by_key
            .get(key)
            .into_iter()
            .flatten()
            .any(|hash| {
                self.ready
                    .get(hash)
                    .is_some_and(|entry| Self::declares_write(&entry.tx, key))
            })
    }

    fn record_deferral(&mut self, hash: TxHash, write_involved: bool, now: LocalTimestamp) {
        self.stats.deferral_events += 1;
        if write_involved {
            self.stats.write_involved_deferrals += 1;
        } else {
            self.stats.read_read_deferrals += 1;
        }
        self.deferred_since.entry(hash).or_insert(now);
    }

    fn note_queue_depth(&mut self, key: &DeclaredKey) {
        let depth = self.txs_deferred_by_key.get(key).map_or(0, HashSet::len);
        self.stats.peak_deferred_queue_depth = self.stats.peak_deferred_queue_depth.max(depth);
    }

    /// Add a transaction. If any declared node is currently locked or already
    /// claimed by another ready-set tx, the tx lands in the deferred set;
    /// otherwise it lands in the ready set. `locks` is read-only — the store
    /// does not mutate lock state. Idempotent: a hash already in either set
    /// is a no-op.
    ///
    /// `added_at` anchors the dwell filter (the pool admission time, also
    /// on re-adds after promotion); `now` is this event's clock reading,
    /// consumed by the deferral statistics only.
    pub fn add(
        &mut self,
        hash: TxHash,
        tx: Arc<Verified<Transaction>>,
        added_at: LocalTimestamp,
        now: LocalTimestamp,
        locks: &LockTracker,
    ) {
        if self.ready.contains_key(&hash) || self.deferred_by_keys.contains_key(&hash) {
            return;
        }

        // Exclusive admission: any lock or claim on a declared key
        // defers. Read-share admission: a declared write defers on any
        // lock or claim; a declared read defers only on a write lock or a
        // write claim — read-read overlap admits.
        let blocking_keys: HashSet<DeclaredKey> = tx
            .admission_keys()
            .into_iter()
            .filter(|key| {
                if self.share_reads && !Self::declares_write(&tx, key) {
                    locks.is_write_locked(key) || self.ready_claim_is_write(key)
                } else {
                    locks.is_locked(key) || self.ready_txs_by_key.contains_key(key)
                }
            })
            .collect();

        if !blocking_keys.is_empty() {
            let write_involved = blocking_keys.iter().any(|key| {
                Self::declares_write(&tx, key)
                    || locks.is_write_locked(key)
                    || self.ready_claim_is_write(key)
            });
            for key in &blocking_keys {
                self.txs_deferred_by_key
                    .entry(*key)
                    .or_default()
                    .insert(hash);
                self.note_queue_depth(key);
            }
            self.deferred_by_keys.insert(hash, blocking_keys);
            self.record_deferral(hash, write_involved, now);
            return;
        }

        if let Some(since) = self.deferred_since.remove(&hash) {
            let wait = now.saturating_sub(since);
            self.stats.promotions += 1;
            self.stats.total_deferral_wait += wait;
            self.stats.max_deferral_wait = self.stats.max_deferral_wait.max(wait);
        }
        for key in tx.admission_keys() {
            self.ready_txs_by_key.entry(key).or_default().insert(hash);
        }
        self.ready.insert(hash, ReadyEntry { tx, added_at });
    }

    /// Remove `hash` from whichever tracking structure it lives in. Returns
    /// the set of keys that were freed by removing a ready-set entry so the
    /// caller can cascade-promote deferred txs whose ready-set claim has now
    /// been released. Empty `Vec` when `hash` was deferred or absent.
    pub fn remove(&mut self, hash: &TxHash) -> Vec<DeclaredKey> {
        let mut freed_keys = Vec::new();
        if let Some(entry) = self.ready.remove(hash) {
            for key in entry.tx.admission_keys() {
                freed_keys.push(key);
                if let Some(txs) = self.ready_txs_by_key.get_mut(&key) {
                    txs.remove(hash);
                    if txs.is_empty() {
                        self.ready_txs_by_key.remove(&key);
                    }
                }
            }
        }

        if let Some(blocking_keys) = self.deferred_by_keys.remove(hash) {
            self.deferred_since.remove(hash);
            for key in blocking_keys {
                if let Some(deferred_txs) = self.txs_deferred_by_key.get_mut(&key) {
                    deferred_txs.remove(hash);
                    if deferred_txs.is_empty() {
                        self.txs_deferred_by_key.remove(&key);
                    }
                }
            }
        }

        freed_keys
    }

    /// Move ready-set txs touching `key` into the deferred set: every one
    /// under [`BlockScope::All`], only those declaring `key` as a write
    /// under [`BlockScope::WritersOnly`]. Called when `key` becomes
    /// locked; `write_locked` is the new holder's mode on `key` and `now`
    /// this event's clock reading, both consumed by the deferral
    /// statistics only.
    pub fn block_key(
        &mut self,
        key: DeclaredKey,
        scope: BlockScope,
        write_locked: bool,
        now: LocalTimestamp,
    ) {
        let Some(tx_hashes) = self.ready_txs_by_key.get(&key) else {
            return;
        };
        let to_block: Vec<TxHash> = tx_hashes
            .iter()
            .filter(|hash| match scope {
                BlockScope::All => true,
                BlockScope::WritersOnly => self
                    .ready
                    .get(hash)
                    .is_some_and(|entry| Self::declares_write(&entry.tx, &key)),
            })
            .copied()
            .collect();

        for hash in to_block {
            let Some(entry) = self.ready.remove(&hash) else {
                continue;
            };
            for other_key in entry.tx.admission_keys() {
                if let Some(txs) = self.ready_txs_by_key.get_mut(&other_key) {
                    txs.remove(&hash);
                    if txs.is_empty() {
                        self.ready_txs_by_key.remove(&other_key);
                    }
                }
            }
            let write_involved = write_locked || Self::declares_write(&entry.tx, &key);
            self.deferred_by_keys.entry(hash).or_default().insert(key);
            self.txs_deferred_by_key
                .entry(key)
                .or_default()
                .insert(hash);
            self.note_queue_depth(&key);
            self.record_deferral(hash, write_involved, now);
        }
    }

    /// Remove `key` from every deferred tx's blocker set. Returns the hashes
    /// whose last blocker was `key` — those are candidates for ready-set
    /// promotion. The caller must verify each hash is still a valid, Pending
    /// pool entry before re-adding it via [`add`](Self::add).
    pub fn promotable_for_key(&mut self, key: DeclaredKey) -> Vec<TxHash> {
        let Some(deferred_txs) = self.txs_deferred_by_key.remove(&key) else {
            return Vec::new();
        };

        let mut promotable = Vec::new();
        for tx_hash in deferred_txs {
            if let Some(blocking_keys) = self.deferred_by_keys.get_mut(&tx_hash) {
                blocking_keys.remove(&key);
                if blocking_keys.is_empty() {
                    self.deferred_by_keys.remove(&tx_hash);
                    promotable.push(tx_hash);
                }
            }
        }
        promotable
    }

    /// Iterate ready transactions in hash order, skipping entries whose dwell
    /// time is below `min_dwell`.
    pub fn iter_ready(
        &self,
        min_dwell: Duration,
        now: LocalTimestamp,
    ) -> impl Iterator<Item = Arc<Verified<Transaction>>> + '_ {
        self.ready
            .values()
            .filter(move |entry| now.saturating_sub(entry.added_at) >= min_dwell)
            .map(|entry| Arc::clone(&entry.tx))
    }

    pub fn ready_count(&self) -> usize {
        self.ready.len()
    }

    pub fn deferred_count(&self) -> usize {
        self.deferred_by_keys.len()
    }

    pub fn txs_deferred_by_key_len(&self) -> usize {
        self.txs_deferred_by_key.len()
    }

    pub fn ready_txs_by_key_len(&self) -> usize {
        self.ready_txs_by_key.len()
    }
}

#[cfg(test)]
mod tests {
    use hyperscale_types::test_utils::{test_prefix, test_transaction_with_prefixes};

    fn key(seed: u8) -> DeclaredKey {
        DeclaredKey::prefix(test_prefix(seed))
    }

    use super::*;

    fn tx_with(seed: u8, nodes: &[u8]) -> (TxHash, Arc<Verified<Transaction>>) {
        let prefixes: Vec<_> = nodes.iter().map(|n| test_prefix(*n)).collect();
        let tx = test_transaction_with_prefixes(&[seed], &prefixes, &prefixes);
        let hash = tx.hash();
        (hash, Arc::new(Verified::new_unchecked_for_test(tx)))
    }

    fn tx_rw(seed: u8, reads: &[u8], writes: &[u8]) -> (TxHash, Arc<Verified<Transaction>>) {
        let tx = test_transaction_with_prefixes(
            &[seed],
            &reads.iter().map(|n| test_prefix(*n)).collect::<Vec<_>>(),
            &writes.iter().map(|n| test_prefix(*n)).collect::<Vec<_>>(),
        );
        let hash = tx.hash();
        (hash, Arc::new(Verified::new_unchecked_for_test(tx)))
    }

    #[test]
    fn read_share_admits_read_read_overlap_and_defers_the_writer() {
        let mut rs = ReadySet::with_read_share(true);
        let locks = LockTracker::with_read_share(true);

        // Two readers of node 10 (each writing its own node) share the claim.
        let (h1, tx1) = tx_rw(1, &[10], &[1]);
        let (h2, tx2) = tx_rw(2, &[10], &[2]);
        rs.add(h1, tx1, LocalTimestamp::ZERO, LocalTimestamp::ZERO, &locks);
        rs.add(h2, tx2, LocalTimestamp::ZERO, LocalTimestamp::ZERO, &locks);
        assert_eq!(rs.ready_count(), 2);
        assert_eq!(rs.deferral_stats().deferral_events, 0);

        // A writer of node 10 defers on the read claims, classified
        // write-involved.
        let (h3, tx3) = tx_rw(3, &[], &[10]);
        rs.add(h3, tx3, LocalTimestamp::ZERO, LocalTimestamp::ZERO, &locks);
        assert_eq!(rs.ready_count(), 2);
        assert_eq!(rs.deferred_count(), 1);
        assert_eq!(rs.deferral_stats().write_involved_deferrals, 1);
        check_invariants(&rs).unwrap();
    }

    #[test]
    fn read_share_defers_readers_on_a_write_lock_and_promotes_on_release() {
        let mut rs = ReadySet::with_read_share(true);
        let mut locks = LockTracker::with_read_share(true);
        locks.lock_declared([], [key(10)]);

        let (h, tx) = tx_rw(1, &[10], &[1]);
        rs.add(
            h,
            Arc::clone(&tx),
            LocalTimestamp::ZERO,
            LocalTimestamp::ZERO,
            &locks,
        );
        assert_eq!(rs.deferred_count(), 1);
        assert_eq!(rs.deferral_stats().write_involved_deferrals, 1);

        let promotable_keys = locks.unlock_declared([], [key(10)]);
        assert_eq!(promotable_keys, vec![key(10)]);
        for node in promotable_keys {
            for hash in rs.promotable_for_key(node) {
                assert_eq!(hash, h);
                rs.add(
                    hash,
                    Arc::clone(&tx),
                    LocalTimestamp::ZERO,
                    LocalTimestamp::from_millis(70),
                    &locks,
                );
            }
        }
        assert_eq!(rs.ready_count(), 1);
        assert_eq!(rs.deferral_stats().promotions, 1);
        assert_eq!(
            rs.deferral_stats().total_deferral_wait,
            Duration::from_millis(70)
        );
        check_invariants(&rs).unwrap();
    }

    #[test]
    fn read_share_block_scope_writers_only_leaves_readers_ready() {
        let mut rs = ReadySet::with_read_share(true);
        let locks = LockTracker::with_read_share(true);

        let (h_reader, tx_reader) = tx_rw(1, &[10], &[1]);
        let (h_writer, tx_writer) = tx_rw(2, &[], &[10]);
        rs.add(
            h_reader,
            tx_reader,
            LocalTimestamp::ZERO,
            LocalTimestamp::ZERO,
            &locks,
        );
        // The writer defers on the reader's claim already; block the node
        // for writers when another reader's lock lands.
        rs.add(
            h_writer,
            tx_writer,
            LocalTimestamp::ZERO,
            LocalTimestamp::ZERO,
            &locks,
        );
        rs.block_key(
            key(10),
            BlockScope::WritersOnly,
            false,
            LocalTimestamp::ZERO,
        );
        // The reader keeps its ready seat; only writers are held back.
        assert_eq!(rs.ready_count(), 1);
        assert_eq!(rs.deferred_count(), 1);
        check_invariants(&rs).unwrap();
    }

    // ─── Invariant helpers ──────────────────────────────────────────────

    /// Central consistency check — also used by the property test. Returns
    /// a descriptive `Err` on violation so proptest prints meaningful output.
    fn check_invariants(rs: &ReadySet) -> Result<(), String> {
        // Ready and deferred are disjoint.
        for hash in rs.ready.keys() {
            if rs.deferred_by_keys.contains_key(hash) {
                return Err(format!("{hash:?} is in both ready and deferred"));
            }
        }

        // ready_txs_by_key reverse index is consistent with ready set.
        for (hash, entry) in &rs.ready {
            for key in entry.tx.admission_keys() {
                let Some(hashes) = rs.ready_txs_by_key.get(&key) else {
                    return Err(format!(
                        "ready tx {hash:?} declares key {key:?}, but reverse index missing"
                    ));
                };
                if !hashes.contains(hash) {
                    return Err(format!(
                        "ready tx {hash:?} declares key {key:?}, but reverse index entry missing"
                    ));
                }
            }
        }
        for (node, hashes) in &rs.ready_txs_by_key {
            if hashes.is_empty() {
                return Err(format!("empty ready_txs_by_node entry for {node:?}"));
            }
            for hash in hashes {
                let Some(entry) = rs.ready.get(hash) else {
                    return Err(format!(
                        "ready_txs_by_node[{node:?}] has {hash:?} but it's not in ready"
                    ));
                };
                if !entry.tx.admission_keys().iter().any(|k| k == node) {
                    return Err(format!(
                        "ready_txs_by_node[{node:?}] has {hash:?} which does not declare that key"
                    ));
                }
            }
        }

        // deferred_by_nodes / txs_deferred_by_node are consistent reverse
        // indices.
        for (hash, blockers) in &rs.deferred_by_keys {
            if blockers.is_empty() {
                return Err(format!("empty blocker set for deferred tx {hash:?}"));
            }
            for node in blockers {
                let Some(deferred) = rs.txs_deferred_by_key.get(node) else {
                    return Err(format!(
                        "deferred tx {hash:?} blocked by {node:?}, but reverse index missing"
                    ));
                };
                if !deferred.contains(hash) {
                    return Err(format!(
                        "deferred tx {hash:?} blocked by {node:?}, but reverse index entry missing"
                    ));
                }
            }
        }
        for (node, hashes) in &rs.txs_deferred_by_key {
            if hashes.is_empty() {
                return Err(format!("empty txs_deferred_by_node entry for {node:?}"));
            }
            for hash in hashes {
                let Some(blockers) = rs.deferred_by_keys.get(hash) else {
                    return Err(format!(
                        "txs_deferred_by_node[{node:?}] has {hash:?} but it's not deferred"
                    ));
                };
                if !blockers.contains(node) {
                    return Err(format!(
                        "txs_deferred_by_node[{node:?}] has {hash:?} but its blockers don't include that node"
                    ));
                }
            }
        }

        Ok(())
    }

    // ─── Unit tests ─────────────────────────────────────────────────────

    #[test]
    fn fresh_set_is_empty() {
        let rs = ReadySet::with_read_share(false);
        assert_eq!(rs.ready_count(), 0);
        assert_eq!(rs.deferred_count(), 0);
        assert_eq!(rs.ready_txs_by_key_len(), 0);
        assert_eq!(rs.txs_deferred_by_key_len(), 0);
        check_invariants(&rs).unwrap();
    }

    #[test]
    fn add_with_no_locks_lands_in_ready_set() {
        let mut rs = ReadySet::with_read_share(false);
        let locks = LockTracker::with_read_share(false);
        let (hash, tx) = tx_with(1, &[10]);

        rs.add(hash, tx, LocalTimestamp::ZERO, LocalTimestamp::ZERO, &locks);
        assert_eq!(rs.ready_count(), 1);
        assert_eq!(rs.deferred_count(), 0);
        check_invariants(&rs).unwrap();
    }

    #[test]
    fn add_with_locked_node_lands_in_deferred() {
        let mut rs = ReadySet::with_read_share(false);
        let mut locks = LockTracker::with_read_share(false);
        locks.lock_keys([key(10)]);

        let (hash, tx) = tx_with(1, &[10]);
        rs.add(hash, tx, LocalTimestamp::ZERO, LocalTimestamp::ZERO, &locks);
        assert_eq!(rs.ready_count(), 0);
        assert_eq!(rs.deferred_count(), 1);
        check_invariants(&rs).unwrap();
    }

    #[test]
    fn second_tx_touching_same_node_as_ready_tx_is_deferred() {
        let mut rs = ReadySet::with_read_share(false);
        let locks = LockTracker::with_read_share(false);
        let (h1, tx1) = tx_with(1, &[10]);
        let (h2, tx2) = tx_with(2, &[10]);

        rs.add(h1, tx1, LocalTimestamp::ZERO, LocalTimestamp::ZERO, &locks);
        rs.add(h2, tx2, LocalTimestamp::ZERO, LocalTimestamp::ZERO, &locks);
        assert_eq!(rs.ready_count(), 1);
        assert_eq!(rs.deferred_count(), 1);
        check_invariants(&rs).unwrap();
    }

    #[test]
    fn remove_ready_tx_frees_its_nodes() {
        let mut rs = ReadySet::with_read_share(false);
        let locks = LockTracker::with_read_share(false);
        let (h, tx) = tx_with(1, &[10, 20]);

        rs.add(h, tx, LocalTimestamp::ZERO, LocalTimestamp::ZERO, &locks);
        // `all_declared_nodes` iterates reads then writes; the fixture passes
        // the same nodes for both, so duplicates in `freed` are expected.
        // Only membership matters — the caller feeds each node through the
        // idempotent promote path.
        let freed = rs.remove(&h);
        assert!(freed.contains(&key(10)));
        assert!(freed.contains(&key(20)));
        check_invariants(&rs).unwrap();
    }

    #[test]
    fn remove_deferred_tx_returns_no_freed_nodes() {
        let mut rs = ReadySet::with_read_share(false);
        let mut locks = LockTracker::with_read_share(false);
        locks.lock_keys([key(10)]);
        let (h, tx) = tx_with(1, &[10]);

        rs.add(h, tx, LocalTimestamp::ZERO, LocalTimestamp::ZERO, &locks);
        let freed = rs.remove(&h);
        assert!(freed.is_empty());
        check_invariants(&rs).unwrap();
    }

    #[test]
    fn block_key_moves_ready_tx_to_deferred() {
        let mut rs = ReadySet::with_read_share(false);
        let locks = LockTracker::with_read_share(false);
        let (h, tx) = tx_with(1, &[10]);
        rs.add(h, tx, LocalTimestamp::ZERO, LocalTimestamp::ZERO, &locks);

        rs.block_key(key(10), BlockScope::All, false, LocalTimestamp::ZERO);
        assert_eq!(rs.ready_count(), 0);
        assert_eq!(rs.deferred_count(), 1);
        check_invariants(&rs).unwrap();
    }

    #[test]
    fn promotable_for_key_lists_only_last_blocker_txs() {
        let mut rs = ReadySet::with_read_share(false);
        let mut locks = LockTracker::with_read_share(false);
        locks.lock_keys([key(10), key(20)]);

        // Single-blocker tx: only blocked by node 10.
        let (h_single, tx_single) = tx_with(1, &[10]);
        rs.add(
            h_single,
            tx_single,
            LocalTimestamp::ZERO,
            LocalTimestamp::ZERO,
            &locks,
        );

        // Dual-blocker tx: blocked by both 10 and 20. Removing node 10 from
        // its blocker set should NOT mark it promotable (20 still blocks).
        let (h_dual, tx_dual) = tx_with(2, &[10, 20]);
        rs.add(
            h_dual,
            tx_dual,
            LocalTimestamp::ZERO,
            LocalTimestamp::ZERO,
            &locks,
        );

        let promotable = rs.promotable_for_key(key(10));
        assert_eq!(promotable, vec![h_single]);
        assert_eq!(rs.deferred_count(), 1);
        check_invariants(&rs).unwrap();
    }

    #[test]
    fn iter_ready_filters_below_dwell() {
        let mut rs = ReadySet::with_read_share(false);
        let locks = LockTracker::with_read_share(false);
        let (h, tx) = tx_with(1, &[10]);
        rs.add(
            h,
            tx,
            LocalTimestamp::from_millis(100),
            LocalTimestamp::from_millis(100),
            &locks,
        );

        assert!(
            rs.iter_ready(Duration::from_millis(200), LocalTimestamp::from_millis(250))
                .next()
                .is_none()
        );

        assert_eq!(
            rs.iter_ready(Duration::from_millis(100), LocalTimestamp::from_millis(250))
                .count(),
            1
        );
    }

    #[test]
    fn iter_ready_yields_hash_order() {
        let mut rs = ReadySet::with_read_share(false);
        let locks = LockTracker::with_read_share(false);
        // Two non-conflicting txs on different nodes.
        let (h1, tx1) = tx_with(1, &[10]);
        let (h2, tx2) = tx_with(2, &[20]);

        rs.add(h1, tx1, LocalTimestamp::ZERO, LocalTimestamp::ZERO, &locks);
        rs.add(h2, tx2, LocalTimestamp::ZERO, LocalTimestamp::ZERO, &locks);

        let order: Vec<_> = rs
            .iter_ready(Duration::ZERO, LocalTimestamp::from_millis(1_000))
            .map(|tx| tx.hash())
            .collect();
        let mut sorted = order.clone();
        sorted.sort();
        assert_eq!(order, sorted);
    }

    // ─── Property test ──────────────────────────────────────────────────

    use proptest::prelude::*;

    #[derive(Debug, Clone)]
    enum Op {
        Add(u8),       // tx index into the fixture pool
        Remove(u8),    // tx index
        BlockNode(u8), // node seed
        UnlockNode(u8),
    }

    fn op_strategy() -> impl Strategy<Value = Op> {
        prop_oneof![
            any::<u8>().prop_map(Op::Add),
            any::<u8>().prop_map(Op::Remove),
            any::<u8>().prop_map(Op::BlockNode),
            any::<u8>().prop_map(Op::UnlockNode),
        ]
    }

    /// Execute `op` against a coordinator-shaped wrapper that mirrors how
    /// `MempoolCoordinator` drives the store: unlock cascades re-add
    /// promotable txs, and remove cascades promote waiting deferred txs.
    fn apply(
        op: &Op,
        rs: &mut ReadySet,
        locks: &mut LockTracker,
        fixture: &[(TxHash, Arc<Verified<Transaction>>)],
    ) {
        let pool_len = fixture.len();
        match op {
            Op::Add(i) => {
                let (hash, tx) = &fixture[(*i as usize) % pool_len];
                rs.add(
                    *hash,
                    Arc::clone(tx),
                    LocalTimestamp::ZERO,
                    LocalTimestamp::ZERO,
                    locks,
                );
            }
            Op::Remove(i) => {
                let (hash, _) = &fixture[(*i as usize) % pool_len];
                let freed = rs.remove(hash);
                for freed_key in freed {
                    cascade_promote(rs, locks, fixture, freed_key);
                }
            }
            Op::BlockNode(n) => {
                let blocked = key(*n);
                if !locks.lock_keys([blocked]).is_empty() {
                    rs.block_key(blocked, BlockScope::All, false, LocalTimestamp::ZERO);
                }
            }
            Op::UnlockNode(n) => {
                let unlocked = key(*n);
                if !locks.unlock_keys([unlocked]).is_empty() {
                    cascade_promote(rs, locks, fixture, unlocked);
                }
            }
        }
    }

    fn cascade_promote(
        rs: &mut ReadySet,
        locks: &LockTracker,
        fixture: &[(TxHash, Arc<Verified<Transaction>>)],
        key: DeclaredKey,
    ) {
        let mut promotable = rs.promotable_for_key(key);
        promotable.sort();
        for hash in promotable {
            if let Some((_, tx)) = fixture.iter().find(|(h, _)| *h == hash) {
                rs.add(
                    hash,
                    Arc::clone(tx),
                    LocalTimestamp::ZERO,
                    LocalTimestamp::ZERO,
                    locks,
                );
            }
        }
    }

    proptest! {
        #![proptest_config(ProptestConfig { cases: 256, .. ProptestConfig::default() })]

        #[test]
        fn invariants_hold_under_arbitrary_op_sequences(
            ops in prop::collection::vec(op_strategy(), 0..40),
        ) {
            // Fixture: 8 txs over 4 declared-node seeds, heavy overlap so the
            // deferred path gets real exercise.
            let fixture: Vec<(TxHash, Arc<Verified<Transaction>>)> = (0..8)
                .map(|seed| tx_with(seed, &[0, 1, 2, 3][..=((seed as usize) % 4)]))
                .collect();

            let mut rs = ReadySet::with_read_share(false);
            let mut locks = LockTracker::with_read_share(false);

            for op in &ops {
                apply(op, &mut rs, &mut locks, &fixture);
                if let Err(e) = check_invariants(&rs) {
                    return Err(TestCaseError::Fail(
                        format!("invariant broken after {op:?}: {e}").into(),
                    ));
                }
            }
        }
    }
}
