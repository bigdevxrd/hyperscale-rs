//! What a wave's batch is executed against.
//!
//! The snapshot borrow, the per-wave context, and the cross-shard input
//! an [`Executor`](crate::Executor) reads besides the transactions
//! themselves.
//!
//! Storage is NOT owned by the executor — the runner provides it as a
//! method argument so the same executor can serve multiple snapshots
//! and so the runner can hoist a single snapshot across an entire
//! action batch.
//!
//! Execution is READ-ONLY: results are returned as `ExecutedTx` values
//! whose writes the state machine caches and applies later, when the
//! wave's certificate is included in a committed block.

use std::sync::Arc;

use hyperscale_dispatch::Parallelism;
use hyperscale_types::{
    BlockHash, RevealChain, ShardId, ShardTrie, SubstateEntry, Transaction, Verified,
    WeightedTimestamp,
};

/// Per-wave inputs an engine's batch execution reads besides the
/// transactions themselves.
pub struct WaveBatchContext<'a> {
    /// Batch fan-out strategy, sourced from the dispatch backend.
    pub par: Parallelism,
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
