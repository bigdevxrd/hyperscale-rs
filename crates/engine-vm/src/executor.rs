//! The VM engine's wave-batch executor.
//!
//! `execute_wave_batch` runs one wave's VM sub-batch end to end: derive
//! each transaction's manifest and effect set through the bridge
//! (exactly the derivation admission ran), pre-read the declared cells
//! from the wave snapshot into an owned committed base, hand the batch
//! to `vm_kernel::execute_batch`, then fold the schedule-invariant
//! receipts into per-transaction absolute `database_updates` in
//! canonical order against the batch baseline — the same fold the
//! kernel's apply phase performs, checked against its end state before
//! anything is returned.
//!
//! Batch receipts are batch-dependent (reservation feasibility is judged
//! with the whole batch's holds in place), so VM outputs are never
//! memoized in the per-transaction `ProcessExecutionCache` — the same
//! transaction in a different block may abort differently.

use std::collections::{BTreeMap, HashMap};
use std::sync::Arc;

use blake3::hash as blake3_hash;
use hyperscale_effects_bridge::{BridgeStatics, ProtocolHasher, decode_tree, envelope_identity};
use hyperscale_engine::sharding::{compute_writes_root, sort_database_updates};
use hyperscale_engine::{
    CachedVmOutput, DynSnapshot, ExecutedTx, Executor, WaveBatchContext, project_to_shard,
};
use hyperscale_metrics::record_transaction_executed;
use hyperscale_storage::{DatabaseUpdate, DbSortKey, PartitionDatabaseUpdates, SubstateDatabase};
use hyperscale_types::state_key::{VM_PARTITION, vm_db_node_key};
use hyperscale_types::{
    BeaconWitnessRoot, EventRoot, ExecutionMetadata, FeeSummary, GlobalReceipt, Hash,
    OwnershipRoot, RoutableTransaction, TxHash, Verified, install_vm_statics,
};
use hyperscale_vm_effects::{
    Address, EffectSet, EffectTarget, Hash32, Manifest, ManifestHash, PrefixShardResolver, RoleId,
    SubstateKey, admit_tree, route_tree,
};
use hyperscale_vm_kernel::{
    Base, BatchTx, EnvInputs, ExecutionMode, Locality, Outcome, Receipt, TxHash as VmTxHash,
    decode_amount, encode_amount, execute_batch,
};
use indexmap::IndexMap;
use radix_common::math::Decimal;
use radix_common::prelude::DbSubstateValue;
use radix_substate_store_interface::interface::{DatabaseUpdates, DbPartitionKey};

use crate::backend::GuestBackend;
use crate::genesis::{VmWorld, genesis_world};
use crate::runner::{ManifestRunner, PreparedVmTx};

/// The protocol crypto hash behind the kernel's hashing host function
/// and fresh-ID derivation.
pub fn protocol_hash(data: &[u8]) -> [u8; 32] {
    *blake3_hash(data).as_bytes()
}

/// The batch's committed baseline: the declared cells pre-read from the
/// wave's JMT-backed snapshot at materialize time.
///
/// Cells only — ordered collections and locks are absent from the
/// current stdlib surface, and reservations never persist across
/// batches, so `holds` is empty by construction. Every kernel read flows
/// through a capability for a declared effect, so pre-reading exactly
/// the declared point targets is complete.
#[derive(Debug, Default)]
pub struct VmBase {
    pub cells: BTreeMap<SubstateKey, Vec<u8>>,
}

impl Base for VmBase {
    fn cell(&self, key: SubstateKey) -> Option<Vec<u8>> {
        self.cells.get(&key).cloned()
    }

    fn entries_in_range(
        &self,
        _owner: Address,
        _collection: RoleId,
        _lo: u128,
        _hi: u128,
        _limit: usize,
    ) -> Vec<(u128, Vec<u8>)> {
        Vec::new()
    }

    fn is_locked(&self, _key: SubstateKey) -> bool {
        false
    }

    fn holds(&self, _key: SubstateKey) -> BTreeMap<VmTxHash, u128> {
        BTreeMap::new()
    }

    fn into_any(self: Arc<Self>) -> Arc<dyn std::any::Any + Send + Sync> {
        self
    }
}

/// The VM engine: the genesis-static world, the compiled stdlib guests,
/// and the batch scheduling mode.
pub struct VmExecutor {
    world: VmWorld,
    backend: GuestBackend,
    mode: ExecutionMode,
}

impl VmExecutor {
    /// Build the engine for the genesis-funded `accounts` and install the
    /// process-wide VM statics (first installation wins, so co-hosted
    /// nodes sharing one genesis coexist).
    ///
    /// # Panics
    ///
    /// Panics if the committed stdlib artifact fails validation or
    /// compilation — a build defect surfaced at boot, not in a wave.
    #[must_use]
    pub fn new(accounts: &[([u8; 16], u128)], mode: ExecutionMode) -> Self {
        let world = genesis_world(accounts);
        install_vm_statics(Box::new(BridgeStatics {
            cache: world.cache.clone(),
            instances: world.instances.clone(),
        }));
        Self {
            world,
            backend: GuestBackend::new(),
            mode,
        }
    }

    /// Derive one transaction's manifest, effect set, and nullifiers —
    /// the same `decode → admit → route` admission ran; refusal here
    /// means the transaction bypassed admission and fails
    /// deterministically.
    fn prepare(
        &self,
        tx: &RoutableTransaction,
    ) -> Result<(Manifest, ManifestHash, EffectSet, Vec<SubstateKey>), String> {
        let vm = tx
            .vm()
            .ok_or_else(|| "Radix body in a VM sub-batch".to_string())?;
        let tree = decode_tree(&vm.tree).map_err(|error| error.to_string())?;
        let admitted = admit_tree(
            &tree,
            envelope_identity(vm),
            &self.world.cache,
            &self.world.instances,
            &ProtocolHasher,
        )
        .map_err(|error| format!("admission: {error}"))?;
        let routing = route_tree(
            &admitted,
            &self.world.cache,
            &self.world.instances,
            &ProtocolHasher,
            &PrefixShardResolver { bits: 0 },
        )
        .map_err(|error| format!("routing: {error}"))?;
        // Single-shard execution sees the transaction's full effect set;
        // the resolver's shard keys are irrelevant to its union.
        let mut declared = EffectSet::new();
        for effect in routing.per_shard.values().flat_map(EffectSet::iter) {
            declared
                .insert(effect)
                .map_err(|error| format!("effect set: {error:?}"))?;
        }
        let nullifiers = admitted
            .subintents
            .iter()
            .map(|record| record.nullifier)
            .collect();
        Ok((
            admitted.admitted.manifest,
            admitted.admitted.identity,
            declared,
            nullifiers,
        ))
    }
}

/// Read one declared cell from the wave snapshot by its exact flat key.
fn read_cell(snapshot: &DynSnapshot<'_>, key: SubstateKey) -> Option<DbSubstateValue> {
    snapshot.get_raw_substate_by_db_key(
        &DbPartitionKey {
            node_key: vm_db_node_key(key.owner.0),
            partition_num: VM_PARTITION,
        },
        &DbSortKey(key.local.0.to_vec()),
    )
}

/// Fold one receipt's delta into per-transaction absolute writes,
/// mirroring the kernel apply phase's operation order: exclusive cells,
/// then movements, then settles. `running` carries the batch's folded
/// state; the per-transaction map reads through it to the base.
///
/// # Panics
///
/// Panics on arithmetic the kernel's apply already vetted — a divergence
/// between this fold and kernel semantics, never a sender condition.
fn fold_delta(
    receipt: &Receipt,
    base: &VmBase,
    running: &mut BTreeMap<SubstateKey, Option<Vec<u8>>>,
    tx: VmTxHash,
) -> BTreeMap<SubstateKey, Option<Vec<u8>>> {
    assert!(
        receipt.delta.entries.is_empty(),
        "ordered-collection entries are outside the genesis stdlib surface"
    );
    let mut writes: BTreeMap<SubstateKey, Option<Vec<u8>>> = BTreeMap::new();
    let current = |writes: &BTreeMap<SubstateKey, Option<Vec<u8>>>,
                   running: &BTreeMap<SubstateKey, Option<Vec<u8>>>,
                   key: SubstateKey| {
        writes
            .get(&key)
            .or_else(|| running.get(&key))
            .cloned()
            .unwrap_or_else(|| base.cells.get(&key).cloned())
    };
    for (key, change) in &receipt.delta.cells {
        writes.insert(*key, change.clone());
    }
    for (key, movement) in &receipt.delta.movements {
        let before = current(&writes, running, *key)
            .map_or(Ok(0), |bytes| decode_amount(&bytes))
            .unwrap_or_else(|error| panic!("fold of {tx:?}: amount cell decode: {error}"));
        let after = before
            .checked_add(movement.credit)
            .and_then(|credited| credited.checked_sub(movement.debit))
            .unwrap_or_else(|| panic!("fold of {tx:?}: movement past the kernel-vetted floor"));
        writes.insert(*key, Some(encode_amount(after).to_vec()));
    }
    for (key, settled) in &receipt.delta.settles {
        let before = current(&writes, running, *key)
            .map_or(Ok(0), |bytes| decode_amount(&bytes))
            .unwrap_or_else(|error| panic!("fold of {tx:?}: amount cell decode: {error}"));
        let after = before
            .checked_sub(*settled)
            .unwrap_or_else(|| panic!("fold of {tx:?}: settle past the committed amount"));
        writes.insert(*key, Some(encode_amount(after).to_vec()));
    }
    for (key, change) in &writes {
        running.insert(*key, change.clone());
    }
    writes
}

/// Encode per-transaction absolute writes as VM-namespace
/// `DatabaseUpdates`.
fn writes_to_updates(writes: &BTreeMap<SubstateKey, Option<Vec<u8>>>) -> DatabaseUpdates {
    let mut updates = DatabaseUpdates::default();
    for (key, change) in writes {
        let node = updates
            .node_updates
            .entry(vm_db_node_key(key.owner.0))
            .or_default();
        let partition = node
            .partition_updates
            .entry(VM_PARTITION)
            .or_insert_with(|| PartitionDatabaseUpdates::Delta {
                substate_updates: IndexMap::new(),
            });
        let PartitionDatabaseUpdates::Delta { substate_updates } = partition else {
            unreachable!("VM updates are Delta-only by construction");
        };
        substate_updates.insert(
            DbSortKey(key.local.0.to_vec()),
            change
                .clone()
                .map_or(DatabaseUpdate::Delete, DatabaseUpdate::Set),
        );
    }
    updates
}

/// Fuel and the abort reason (if any) as node-local metadata.
fn vm_metadata(fuel: u64, error: Option<String>) -> ExecutionMetadata {
    ExecutionMetadata::new(
        FeeSummary {
            total_execution_cost: Some(Decimal::from(fuel)),
            total_royalty_cost: None,
            total_storage_cost: None,
            total_tipping_cost: None,
        },
        Vec::new(),
        error,
    )
}

/// Assemble one kernel receipt into the projected [`ExecutedTx`]: fold
/// its delta, root its writes, and run the shard projection. Aborts
/// carry their reason and fuel in the node-local metadata.
fn assemble_executed_tx(
    ctx: &WaveBatchContext<'_>,
    base: &VmBase,
    running: &mut BTreeMap<SubstateKey, Option<Vec<u8>>>,
    vm_tx: VmTxHash,
    receipt: &Receipt,
) -> ExecutedTx {
    let tx_hash = TxHash::from_raw(Hash::from_hash_bytes(&vm_tx.0.0));
    let cached = if matches!(receipt.outcome, Outcome::Completed { .. }) {
        let writes = fold_delta(receipt, base, running, vm_tx);
        let mut updates = writes_to_updates(&writes);
        sort_database_updates(&mut updates);
        let writes_root = compute_writes_root(&updates);
        let receipt_hash = GlobalReceipt::new(
            true,
            EventRoot::ZERO,
            BeaconWitnessRoot::ZERO,
            writes_root,
            OwnershipRoot::ZERO,
        )
        .receipt_hash();
        CachedVmOutput::vm_succeeded(updates, receipt_hash, vm_metadata(receipt.fuel, None))
    } else {
        let reason = match &receipt.outcome {
            Outcome::UserError { reason } | Outcome::ProtocolError { reason } => reason.clone(),
            Outcome::Infeasible { key, amount } => {
                format!("infeasible: {amount} uncovered on {key:?}")
            }
            Outcome::Completed { .. } => unreachable!("aborts only"),
        };
        CachedVmOutput::vm_failed(vm_metadata(receipt.fuel, Some(reason)))
    };
    project_to_shard(
        &cached,
        tx_hash,
        ctx.local_shard,
        ctx.shard_trie,
        &HashMap::new(),
    )
}

impl Executor for VmExecutor {
    fn execute_wave_batch(
        &self,
        ctx: &WaveBatchContext<'_>,
        snapshot: &DynSnapshot<'_>,
        transactions: &[Arc<Verified<RoutableTransaction>>],
    ) -> Vec<ExecutedTx> {
        if transactions.is_empty() {
            return Vec::new();
        }

        // Derive every transaction; refusals become deterministic
        // failures without touching the batch.
        let mut prepared: BTreeMap<VmTxHash, PreparedVmTx> = BTreeMap::new();
        let mut refused: BTreeMap<TxHash, String> = BTreeMap::new();
        for tx in transactions {
            let vm_tx = VmTxHash(Hash32(*tx.hash().as_bytes()));
            match self.prepare(tx) {
                Ok((manifest, identity, declared, nullifiers)) => {
                    record_transaction_executed();
                    prepared.insert(
                        vm_tx,
                        PreparedVmTx {
                            manifest,
                            identity,
                            declared,
                            nullifiers,
                        },
                    );
                }
                Err(reason) => {
                    tracing::warn!(tx_hash = ?tx.hash(), reason, "VM transaction refused at execution");
                    refused.insert(tx.hash(), reason);
                }
            }
        }

        // Pre-read the batch's declared cells from the wave snapshot —
        // the committed baseline every snapshot and judge read pins to.
        let mut cells: BTreeMap<SubstateKey, Vec<u8>> = BTreeMap::new();
        for entry in prepared.values() {
            for effect in entry.declared.iter() {
                if let EffectTarget::Point(key) = effect.target
                    && let Some(value) = read_cell(snapshot, key)
                {
                    cells.insert(key, value);
                }
            }
        }
        let base = Arc::new(VmBase { cells });

        let batch: Vec<BatchTx> = prepared
            .iter()
            .map(|(vm_tx, entry)| BatchTx {
                tx: *vm_tx,
                declared: entry.declared.clone(),
                nullifiers: entry.nullifiers.clone(),
            })
            .collect();
        let runner = ManifestRunner {
            backend: &self.backend,
            prepared: &prepared,
        };
        let env = EnvInputs {
            clock_ms: 0,
            randomness: *ctx.block_hash.as_bytes(),
        };
        let outcome = execute_batch(
            Arc::clone(&base) as Arc<dyn Base>,
            &batch,
            &runner,
            env,
            protocol_hash,
            self.mode,
            &Locality::All,
        )
        .unwrap_or_else(|error| panic!("BFT CRITICAL: VM batch execution failed: {error}"));

        // Fold receipts into per-transaction absolute updates in
        // canonical order, then check the folded end state against the
        // kernel's own applied store — the fold must be the same fold.
        let mut running: BTreeMap<SubstateKey, Option<Vec<u8>>> = BTreeMap::new();
        let mut folded: BTreeMap<VmTxHash, ExecutedTx> = BTreeMap::new();
        for (vm_tx, receipt) in &outcome.receipts {
            let executed = assemble_executed_tx(ctx, &base, &mut running, *vm_tx, receipt);
            folded.insert(*vm_tx, executed);
        }

        // The differential: every folded key's end value must equal the
        // kernel's applied store. A mismatch is a fold defect — receipts
        // silently diverging from kernel semantics — and must never ship.
        for (key, change) in &running {
            let applied = Base::cell(&outcome.store, *key);
            assert_eq!(
                change.as_ref(),
                applied.as_ref(),
                "BFT CRITICAL: VM fold diverged from the kernel apply at {key:?}"
            );
        }

        // Reassemble in input order.
        transactions
            .iter()
            .map(|tx| {
                let vm_tx = VmTxHash(Hash32(*tx.hash().as_bytes()));
                folded.get(&vm_tx).cloned().unwrap_or_else(|| {
                    let reason = refused
                        .get(&tx.hash())
                        .cloned()
                        .unwrap_or_else(|| "missing batch receipt".to_string());
                    let cached = CachedVmOutput::vm_failed(vm_metadata(0, Some(reason)));
                    project_to_shard(
                        &cached,
                        tx.hash(),
                        ctx.local_shard,
                        ctx.shard_trie,
                        &HashMap::new(),
                    )
                })
            })
            .collect()
    }
}
