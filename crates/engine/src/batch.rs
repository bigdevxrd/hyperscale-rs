//! What a wave's batch is executed against.
//!
//! The snapshot borrow, the per-wave context, and the cross-shard input
//! an [`Executor`](crate::Executor) reads besides the transactions
//! themselves — plus the cache walk that turns an already-computed
//! output into this shard's [`ExecutedTx`](crate::ExecutedTx).
//!
//! Storage is NOT owned by the executor — the runner provides it as a
//! method argument so the same executor can serve multiple snapshots
//! and so the runner can hoist a single snapshot across an entire
//! action batch.
//!
//! Execution is READ-ONLY: results are returned as `ExecutedTx` values
//! whose `DatabaseUpdates` the state machine caches and applies later,
//! when the wave's certificate is included in a committed block.

use std::sync::Arc;

use hyperscale_dispatch::Parallelism;
use hyperscale_storage::{
    DbPartitionKey, DbSortKey, DbSubstateValue, PartitionEntry, SubstateDatabase,
};
use hyperscale_types::{
    BlockHash, RevealChain, ShardId, ShardTrie, SubstateEntry, Transaction, Verified,
    WeightedTimestamp,
};

use crate::cache::{CachedSlot, ProcessExecutionCache, SlotStatus};
use crate::receipt::CachedOutput;

/// Type-erased borrow of the wave's state snapshot, so one batch entry
/// point serves every backend's snapshot type while the concrete type
/// stays generic at the call site.
pub struct DynSnapshot<'a>(pub &'a (dyn SubstateDatabase + Sync));

impl SubstateDatabase for DynSnapshot<'_> {
    fn get_raw_substate_by_db_key(
        &self,
        partition_key: &DbPartitionKey,
        sort_key: &DbSortKey,
    ) -> Option<DbSubstateValue> {
        self.0.get_raw_substate_by_db_key(partition_key, sort_key)
    }

    fn list_raw_values_from_db_key(
        &self,
        partition_key: &DbPartitionKey,
        from_sort_key: Option<&DbSortKey>,
    ) -> Box<dyn Iterator<Item = PartitionEntry> + '_> {
        self.0
            .list_raw_values_from_db_key(partition_key, from_sort_key)
    }
}

/// Per-wave inputs an engine's batch execution reads besides the
/// transactions themselves.
pub struct WaveBatchContext<'a> {
    /// Batch fan-out strategy, sourced from the dispatch backend.
    pub par: Parallelism,
    /// Process-scope cache of shard-invariant execution outputs.
    pub cache: &'a ProcessExecutionCache,
    /// The executing vnode's shard — the projection target.
    pub local_shard: ShardId,
    /// The active shard partition.
    pub shard_trie: &'a ShardTrie,
    /// The block whose wave this batch executes.
    pub block_hash: BlockHash,
    /// The wave-starting block's parent-QC weighted timestamp. For a
    /// single-shard batch this is the transaction clock of every member;
    /// cross-shard batches carry per-transaction clocks on their inputs.
    pub wave_start_ts: WeightedTimestamp,
    /// The wave-starting block's reveal chain. For a single-shard batch
    /// this is the randomness anchor of every member; cross-shard
    /// batches carry per-transaction anchors on their inputs.
    pub wave_start_reveal: RevealChain,
}

/// One cross-shard transaction as an engine consumes it: the
/// transaction plus what its remote counterparts shipped.
pub struct CrossShardTxInput<'a> {
    /// The transaction to execute.
    pub transaction: &'a Arc<Verified<Transaction>>,
    /// Verified provision entry lists, one per source shard contribution.
    pub provisions: &'a [Arc<Vec<SubstateEntry>>],
    /// The transaction clock: the payer-shard committing block's
    /// parent-QC weighted timestamp, identical on every participant.
    pub clock: WeightedTimestamp,
    /// The randomness anchor: the same block's reveal chain, likewise
    /// identical on every participant.
    pub randomness: RevealChain,
}

/// Shards this transaction reads or writes, routed via the active
/// `ShardTrie`.
///
/// Drives the execution cache's per-entry pending-shards set: the cache
/// narrows this to the host's hosted shards and decrements per-shard as
/// finalised waves arrive.
pub fn participating_shards<'a>(
    tx: &'a Transaction,
    shard_trie: &'a ShardTrie,
) -> impl Iterator<Item = ShardId> + 'a {
    tx.routing()
        .all_prefixes()
        .into_iter()
        .map(move |prefix| shard_trie.shard_for_prefix(prefix))
}

/// Plan derived for each position in a batch by classifying its
/// `ProcessExecutionCache` slot up-front. `Done` skips work; `Claimed`
/// runs `compute` and fills the slot; `Pending` blocks on another
/// worker's slot via `get_or_init` (the closure only fires if the
/// claimant abandoned the slot without setting a value).
enum Plan {
    Done(Arc<CachedOutput>),
    Claimed(CachedSlot),
    Pending(CachedSlot),
}

/// Two-phase cache acquisition for a batch of transactions.
///
/// Phase 1 classifies every position sequentially via `try_acquire` —
/// cheap `DashMap` lookups that publish all Claimed slots to other
/// concurrent batches before any compute starts. Phase 2 fans out via
/// `par.map`: `Done` returns the cached value, `Claimed` runs `compute`
/// and fills the slot, `Pending` blocks via `OnceLock::get_or_init`
/// (each blocked worker waits only on its own slot, so the wait
/// parallelises across the pool).
pub fn batch_compute_cached(
    par: Parallelism,
    cache: &ProcessExecutionCache,
    txs: &[Arc<Verified<Transaction>>],
    shard_trie: &ShardTrie,
    compute: impl Fn(usize) -> CachedOutput + Send + Sync,
) -> Vec<Arc<CachedOutput>> {
    let plans: Vec<(usize, Plan)> = txs
        .iter()
        .enumerate()
        .map(
            |(i, tx)| match cache.try_acquire(tx.hash(), participating_shards(tx, shard_trie)) {
                SlotStatus::Completed(v) => (i, Plan::Done(v)),
                SlotStatus::Claimed(slot) => (i, Plan::Claimed(slot)),
                SlotStatus::Pending(slot) => (i, Plan::Pending(slot)),
            },
        )
        .collect();

    par.map(plans, |(i, plan)| match plan {
        Plan::Done(v) => v,
        Plan::Claimed(slot) => {
            let value = Arc::new(compute(i));
            let _ = slot.set(Arc::clone(&value));
            value
        }
        Plan::Pending(slot) => Arc::clone(slot.get_or_init(|| Arc::new(compute(i)))),
    })
}
