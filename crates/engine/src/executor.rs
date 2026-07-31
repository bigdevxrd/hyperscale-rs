//! Synchronous Radix Engine executor.
//!
//! [`RadixExecutor`] runs transactions against a caller-supplied
//! snapshot and returns the shard-invariant [`CachedVmOutput`]. The
//! caller projects it into a per-shard [`ExecutedTx`] via
//! [`project_to_shard`](crate::project_to_shard) and typically
//! memoises the intermediate in
//! [`ProcessExecutionCache`](crate::ProcessExecutionCache).
//!
//! Storage is NOT owned by the executor — the runner provides it as a
//! method argument so the same executor can serve multiple snapshots
//! and so the runner can hoist a single snapshot across an entire
//! action batch.
//!
//! All methods are READ-ONLY: results are returned as [`ExecutedTx`]
//! values whose `DatabaseUpdates` the state machine caches and applies
//! later, when the wave's certificate is included in a committed block.

use std::collections::HashMap;
use std::sync::Arc;

use hyperscale_dispatch::Parallelism;
use hyperscale_metrics::record_transaction_executed;
use hyperscale_storage::{SubstateDatabase, SubstateStore};
use hyperscale_types::{
    BlockHash, BlockHeight, NodeId, RoutableTransaction, ShardId, ShardTrie, Stopwatch,
    SubstateEntry, Verified,
};
use radix_common::network::NetworkDefinition;
use radix_common::prelude::DbSubstateValue;
use radix_common::types::NodeId as RadixNodeId;
use radix_engine::transaction::{ExecutionConfig, execute_transaction};
use radix_engine::vm::DefaultVmModules;
use radix_substate_store_interface::interface::{DbPartitionKey, DbSortKey, PartitionEntry};
use radix_transactions::validation::TransactionValidator;
use tracing::field::Empty;
use tracing::{Level, Span, instrument};

use crate::cache::{CachedSlot, ProcessExecutionCache, SlotStatus};
use crate::output::ExecutedTx;
use crate::provisioned_snapshot::ProvisionedSnapshot;
use crate::receipt::{CachedVmOutput, compute_vm_output, project_to_shard};
use crate::sharding::{build_cross_shard_ownership, resolve_owned_nodes};

/// Fetch state entries for the given nodes from storage at a specific block height.
///
/// Reads substates at the given `block_height` using historical JMT traversal
/// and the leaf association table. Both data and proofs must come from the same
/// version to pass verification against the block header's `state_root`.
///
/// Returns `None` if the requested version is unavailable (GC'd or not yet
/// committed). Returns `Some(entries)` on success with pre-computed storage
/// keys for efficient cross-shard provisioning.
pub fn fetch_state_entries<S: SubstateStore>(
    storage: &S,
    nodes: &[NodeId],
    block_height: BlockHeight,
) -> Option<Vec<SubstateEntry>> {
    use radix_substate_store_interface::db_key_mapper::{DatabaseKeyMapper, SpreadPrefixKeyMapper};

    let mut entries = Vec::new();

    for node in nodes {
        // Compute the db_node_key once per node (expensive hash computation).
        let radix_node_id = RadixNodeId(node.0);
        let db_node_key = SpreadPrefixKeyMapper::to_db_node_key(&radix_node_id);

        let substates = storage.list_substates_for_node_at_height(node, block_height)?;

        for (partition_num, db_sort_key, value) in substates {
            // Storage key: db_node_key || partition_num || sort_key
            let mut storage_key = Vec::with_capacity(db_node_key.len() + 1 + db_sort_key.0.len());
            storage_key.extend_from_slice(&db_node_key);
            storage_key.push(partition_num);
            storage_key.extend_from_slice(&db_sort_key.0);

            entries.push(SubstateEntry::new(storage_key, Some(value)));
        }
    }

    Some(entries)
}

/// Shared executor caches to avoid rebuilding on clone.
///
/// Wrapped in [`Arc`] so cloning [`RadixExecutor`] is cheap.
struct ExecutorCaches {
    /// VM modules — recreating per transaction would dominate small-tx cost.
    vm_modules: DefaultVmModules,
    /// Execution config (pinned to the network's notarized-transaction profile).
    exec_config: ExecutionConfig,
    /// Transaction validator (latest config for the network).
    validator: TransactionValidator,
}

/// Synchronous Radix Engine executor for deterministic execution.
///
/// Storage is NOT owned by the executor; the runner passes it to each
/// method. State machines stay pure; I/O is delegated to runners.
///
/// # Cloning
///
/// Cloning is cheap — only the [`Arc`] around [`ExecutorCaches`] is bumped.
pub struct RadixExecutor {
    network: NetworkDefinition,
    caches: Arc<ExecutorCaches>,
}

impl RadixExecutor {
    /// Create a new executor for the given network.
    ///
    /// VM modules and execution config are cached to avoid per-transaction overhead.
    #[must_use]
    pub fn new(network: NetworkDefinition) -> Self {
        let vm_modules = DefaultVmModules::default();
        let exec_config = ExecutionConfig::for_notarized_transaction(network.clone());
        let validator = TransactionValidator::new_with_latest_config(&network);
        Self {
            network,
            caches: Arc::new(ExecutorCaches {
                vm_modules,
                exec_config,
                validator,
            }),
        }
    }

    /// Network definition this executor runs against.
    #[must_use]
    pub const fn network(&self) -> &NetworkDefinition {
        &self.network
    }

    /// Run the VM for a single-shard transaction and return the
    /// [`CachedVmOutput`] — the shard-invariant projection of the
    /// receipt. Caller pairs this with
    /// [`crate::project_to_shard`] to produce an [`ExecutedTx`] for
    /// each participating shard.
    ///
    /// Ownership is resolved locally against `snapshot`: every declared
    /// account of a single-shard transaction is owned by the executing
    /// shard, so the walk sees the full substate set.
    #[instrument(level = Level::DEBUG, skip_all, fields(latency_us = Empty))]
    pub fn compute_vm_output_single_shard<D: SubstateDatabase>(
        &self,
        snapshot: &D,
        tx: &RoutableTransaction,
    ) -> CachedVmOutput {
        let start = Stopwatch::start();
        if tx.is_vm() {
            // The wave dispatch routes VM sub-batches to the VM engine;
            // a VM body reaching the Radix engine fails deterministically
            // rather than panicking on the body accessor.
            return CachedVmOutput::validation_failed(tx.hash());
        }
        let Some(validated) = tx.get_or_validate(&self.caches.validator) else {
            return CachedVmOutput::validation_failed(tx.hash());
        };
        let executable = validated.clone().create_executable();
        record_transaction_executed();
        let receipt = execute_transaction(
            snapshot,
            &self.caches.vm_modules,
            &self.caches.exec_config,
            &executable,
        );
        let declared_nodes: Vec<NodeId> = tx
            .declared_reads()
            .iter()
            .chain(tx.declared_writes().iter())
            .copied()
            .collect();
        let ownership = resolve_owned_nodes(snapshot, &declared_nodes);
        let output = compute_vm_output(tx, &receipt, &ownership);
        Span::current().record(
            "latency_us",
            u64::try_from(start.elapsed().as_micros()).unwrap_or(u64::MAX),
        );
        output
    }

    /// Layers `provisions` on top of `snapshot` via [`ProvisionedSnapshot`]
    /// and executes against the merged view. Provisions carry pre-computed
    /// storage keys from the sending shard for O(log n) lookups without
    /// expensive hash work.
    ///
    /// `ownership` is the per-vnode merged `vault → owning_account` map
    /// the caller built via
    /// [`crate::sharding::build_cross_shard_ownership`] (provisions for
    /// remote-shard owners, local-snapshot resolve for local-shard owners).
    /// It is consumed here ONLY for `receipt_hash` (computed inside
    /// [`compute_vm_output`]); the returned [`CachedVmOutput`] does not
    /// store it, so callers re-pass their own ownership to
    /// [`crate::project_to_shard`].
    #[instrument(level = Level::DEBUG, skip_all, fields(
        provision_count = provisions.len(),
        latency_us = Empty,
    ))]
    #[allow(clippy::implicit_hasher)]
    pub fn compute_vm_output_cross_shard<D: SubstateDatabase>(
        &self,
        snapshot: &D,
        tx: &RoutableTransaction,
        provisions: &[Arc<Vec<SubstateEntry>>],
        ownership: &HashMap<NodeId, NodeId>,
    ) -> CachedVmOutput {
        let start = Stopwatch::start();
        let Some(validated) = tx.get_or_validate(&self.caches.validator) else {
            return CachedVmOutput::validation_failed(tx.hash());
        };
        let executable = validated.clone().create_executable();
        let entry_slices: Vec<&[SubstateEntry]> = provisions.iter().map(|p| p.as_slice()).collect();
        let provisioned = ProvisionedSnapshot::from_provisions(snapshot, &entry_slices);
        record_transaction_executed();
        let receipt = provisioned.execute(
            &executable,
            &self.caches.vm_modules,
            &self.caches.exec_config,
        );
        let output = compute_vm_output(tx, &receipt, ownership);
        Span::current().record(
            "latency_us",
            u64::try_from(start.elapsed().as_micros()).unwrap_or(u64::MAX),
        );
        output
    }
}

impl Clone for RadixExecutor {
    fn clone(&self) -> Self {
        Self {
            network: self.network.clone(),
            caches: Arc::clone(&self.caches),
        }
    }
}

/// Object-safe borrow of the wave's state snapshot, so the batch seam
/// stays dyn-dispatchable while the concrete snapshot type remains
/// generic at the call site.
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
}

/// One cross-shard transaction as an engine consumes it: the
/// transaction plus what its remote counterparts shipped.
pub struct CrossShardTxInput<'a> {
    /// The transaction to execute.
    pub transaction: &'a Arc<Verified<RoutableTransaction>>,
    /// Verified provision entry lists, one per source shard contribution.
    pub provisions: &'a [Arc<Vec<SubstateEntry>>],
    /// The merged `vault → owning_account` map for the Radix variant;
    /// structurally empty for VM transactions.
    pub ownership: &'a HashMap<NodeId, NodeId>,
}

/// One engine's execution of a wave's same-variant sub-batch.
///
/// The unit is the batch: the Radix implementation runs its
/// per-transaction loop over it, the VM implementation hands the whole
/// batch to its deterministic-parallel executor. Both return one
/// [`ExecutedTx`] per input transaction, in input order.
pub trait Executor: Send + Sync {
    /// Execute `transactions` against `snapshot` and project each result
    /// to the context's local shard.
    fn execute_wave_batch(
        &self,
        ctx: &WaveBatchContext<'_>,
        snapshot: &DynSnapshot<'_>,
        transactions: &[Arc<Verified<RoutableTransaction>>],
    ) -> Vec<ExecutedTx>;

    /// Execute a cross-shard sub-batch: `snapshot` carries local state,
    /// each request its remote provisions. One [`ExecutedTx`] per input,
    /// in input order, projected to the context's local shard.
    fn execute_cross_shard_batch(
        &self,
        ctx: &WaveBatchContext<'_>,
        snapshot: &DynSnapshot<'_>,
        requests: &[CrossShardTxInput<'_>],
    ) -> Vec<ExecutedTx>;
}

/// Shards this transaction reads or writes, routed via the active
/// `ShardTrie`.
///
/// Drives the execution cache's per-entry pending-shards set: the cache
/// narrows this to the host's hosted shards and decrements per-shard as
/// finalised waves arrive.
pub fn participating_shards<'a>(
    tx: &'a RoutableTransaction,
    shard_trie: &'a ShardTrie,
) -> impl Iterator<Item = ShardId> + 'a {
    tx.declared_reads()
        .iter()
        .chain(tx.declared_writes().iter())
        .map(move |n| shard_trie.shard_for(n))
}

/// Plan derived for each position in a batch by classifying its
/// `ProcessExecutionCache` slot up-front. `Done` skips work; `Claimed`
/// runs `compute` and fills the slot; `Pending` blocks on another
/// worker's slot via `get_or_init` (the closure only fires if the
/// claimant abandoned the slot without setting a value).
enum Plan {
    Done(Arc<CachedVmOutput>),
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
    txs: &[Arc<Verified<RoutableTransaction>>],
    shard_trie: &ShardTrie,
    compute: impl Fn(usize) -> CachedVmOutput + Send + Sync,
) -> Vec<Arc<CachedVmOutput>> {
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

impl Executor for RadixExecutor {
    fn execute_wave_batch(
        &self,
        ctx: &WaveBatchContext<'_>,
        snapshot: &DynSnapshot<'_>,
        transactions: &[Arc<Verified<RoutableTransaction>>],
    ) -> Vec<ExecutedTx> {
        let cached = batch_compute_cached(ctx.par, ctx.cache, transactions, ctx.shard_trie, |i| {
            self.compute_vm_output_single_shard(snapshot, &transactions[i])
        });
        transactions
            .iter()
            .zip(cached)
            .map(|(tx, cached)| {
                // Single-shard ownership is purely local: every declared
                // account lives on this shard. Computed per-call rather
                // than cached so the cache stays shard-invariant (matches
                // the cross-shard path).
                let declared: Vec<NodeId> = tx
                    .declared_reads()
                    .iter()
                    .chain(tx.declared_writes().iter())
                    .copied()
                    .collect();
                let ownership = resolve_owned_nodes(snapshot, &declared);
                project_to_shard(
                    &cached,
                    tx.hash(),
                    ctx.local_shard,
                    ctx.shard_trie,
                    &ownership,
                )
            })
            .collect()
    }

    fn execute_cross_shard_batch(
        &self,
        ctx: &WaveBatchContext<'_>,
        snapshot: &DynSnapshot<'_>,
        requests: &[CrossShardTxInput<'_>],
    ) -> Vec<ExecutedTx> {
        let txs: Vec<Arc<Verified<RoutableTransaction>>> =
            requests.iter().map(|r| Arc::clone(r.transaction)).collect();
        // Per-request merged ownership: provisions for remote-shard
        // owners, local-snapshot resolve for local ones. `Err` means the
        // transaction touches a vault claimed by accounts on both shards
        // — fast-abort so every committee produces the same `Failed`
        // outcome instead of executing a divergent VM view.
        let ownerships: Vec<Result<HashMap<NodeId, NodeId>, Vec<NodeId>>> = requests
            .iter()
            .map(|req| {
                let declared: Vec<NodeId> = req
                    .transaction
                    .declared_reads()
                    .iter()
                    .chain(req.transaction.declared_writes().iter())
                    .copied()
                    .collect();
                build_cross_shard_ownership(
                    snapshot,
                    &declared,
                    req.ownership,
                    ctx.local_shard,
                    ctx.shard_trie,
                )
            })
            .collect();
        let cached = batch_compute_cached(ctx.par, ctx.cache, &txs, ctx.shard_trie, |i| {
            let req = &requests[i];
            ownerships[i].as_ref().map_or_else(
                |_| CachedVmOutput::ownership_conflict_aborted(req.transaction.hash()),
                |ownership| {
                    self.compute_vm_output_cross_shard(
                        snapshot,
                        req.transaction,
                        req.provisions,
                        ownership,
                    )
                },
            )
        });
        let empty_ownership: HashMap<NodeId, NodeId> = HashMap::new();
        requests
            .iter()
            .zip(cached)
            .zip(ownerships.iter())
            .map(|((req, cached), ownership)| {
                let ownership = ownership.as_ref().unwrap_or(&empty_ownership);
                project_to_shard(
                    &cached,
                    req.transaction.hash(),
                    ctx.local_shard,
                    ctx.shard_trie,
                    ownership,
                )
            })
            .collect()
    }
}
