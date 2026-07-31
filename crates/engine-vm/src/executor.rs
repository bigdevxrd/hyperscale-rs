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
    CachedVmOutput, CrossShardTxInput, DynSnapshot, ExecutedTx, Executor, WaveBatchContext,
    project_to_shard,
};
use hyperscale_metrics::record_transaction_executed;
use hyperscale_storage::{DatabaseUpdate, DbSortKey, PartitionDatabaseUpdates, SubstateDatabase};
use hyperscale_types::state_key::{VM_PARTITION, vm_db_node_key, vm_flat_key_parts};
use hyperscale_types::{
    BeaconWitnessRoot, ConsensusReceipt, EventRoot, ExecutionMetadata, FeeSummary, GlobalReceipt,
    Hash, OwnershipRoot, RoutableTransaction, SubstateEntry, TxHash, Verified, install_vm_statics,
};
use hyperscale_vm_effects::{
    Address, EffectSet, EffectTarget, Hash32, LocalKey, Manifest, ManifestHash,
    PrefixShardResolver, RoleId, SubstateKey, admit_tree, route_tree,
};
use hyperscale_vm_kernel::{
    Base, BatchTx, ExecutionMode, Locality, Outcome, Receipt, TxHash as VmTxHash, decode_amount,
    encode_amount, execute_batch,
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
    is_local: &dyn Fn(Address) -> bool,
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
        if !is_local(key.owner) {
            continue;
        }
        writes.insert(*key, change.clone());
    }
    for (key, movement) in &receipt.delta.movements {
        if !is_local(key.owner) {
            // The owning shard folds its own cells; here the movement is
            // the outbound record and never becomes an absolute write.
            continue;
        }
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
        if !is_local(key.owner) {
            continue;
        }
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
/// Apply the payer's fee burn on top of a transaction's kernel-mirroring
/// fold. The burn is part of the receipt's writes — and so of its
/// attested `writes_root` and the sync-replayable work items — while the
/// pre-fee `running` map stays the kernel differential's source: the
/// applied value of a fee-bearing cell is always
/// `saturating_sub(pre-fee value, cumulative fees)`.
fn apply_fee_burn(
    writes: &mut BTreeMap<SubstateKey, Option<Vec<u8>>>,
    running: &BTreeMap<SubstateKey, Option<Vec<u8>>>,
    base: &VmBase,
    fees_applied: &mut BTreeMap<SubstateKey, u128>,
    fee: Option<PayerFee>,
    fuel: u64,
) {
    // The transaction's own burn first: the attested actual — fuel, until
    // real pricing lands — capped at the signed ceiling.
    if let Some(payer) = fee {
        let burn = u128::from(fuel).min(payer.max_fee);
        if burn > 0 {
            *fees_applied.entry(payer.vault).or_insert(0) += burn;
        }
    }
    // Re-derive every fee-bearing cell this transaction's update set
    // covers from the pre-fee fold: later writes of a debited cell must
    // carry the cumulative burn, or their absolute updates would revert
    // earlier debits at commit.
    for (vault, fees) in fees_applied.iter() {
        let prefee = writes
            .get(vault)
            .cloned()
            .or_else(|| running.get(vault).cloned())
            .unwrap_or_else(|| base.cells.get(vault).cloned());
        let Some(bytes) = prefee else {
            continue;
        };
        let Ok(cell): Result<[u8; 16], _> = bytes.as_slice().try_into() else {
            continue;
        };
        let debited = u128::from_le_bytes(cell).saturating_sub(*fees);
        writes.insert(*vault, Some(debited.to_le_bytes().to_vec()));
    }
}

/// What this shard, as a transaction's fee payer, charges it: the vault,
/// the signed ceiling a success burns up to, and — for the cross-shard
/// legs a wave can abort after executing — the floor an abort settles.
#[derive(Clone, Copy)]
struct PayerFee {
    vault: SubstateKey,
    max_fee: u128,
    abort_floor: Option<u128>,
}

/// The fold's mutable state across a batch: the pre-fee kernel-mirror
/// map (the differential's source) and the cumulative fee burns layered
/// on top of it.
struct FoldState {
    running: BTreeMap<SubstateKey, Option<Vec<u8>>>,
    fees_applied: BTreeMap<SubstateKey, u128>,
}

/// Build the receipt an abort of this transaction settles: the payer's
/// vault debited by the class floor, and nothing else.
///
/// The value is read as of every canonically earlier transaction's
/// applied effect and fee, but without this transaction's own — an abort
/// discards those, so the burn must not be layered on top of them.
fn build_fee_receipt(
    ctx: &WaveBatchContext<'_>,
    base: &VmBase,
    fold: &FoldState,
    tx_hash: TxHash,
    vault: SubstateKey,
    floor: u128,
) -> Option<ConsensusReceipt> {
    let prefee = fold
        .running
        .get(&vault)
        .cloned()
        .unwrap_or_else(|| base.cells.get(&vault).cloned())?;
    let cell: [u8; 16] = prefee.as_slice().try_into().ok()?;
    let applied = u128::from_le_bytes(cell)
        .saturating_sub(fold.fees_applied.get(&vault).copied().unwrap_or(0));
    let debited = applied.saturating_sub(floor);

    let writes: BTreeMap<SubstateKey, Option<Vec<u8>>> =
        BTreeMap::from([(vault, Some(debited.to_le_bytes().to_vec()))]);
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
    let cached = CachedVmOutput::vm_succeeded(updates, receipt_hash, vm_metadata(0, None));
    Some(
        project_to_shard(
            &cached,
            tx_hash,
            ctx.local_shard,
            ctx.shard_trie,
            &HashMap::new(),
        )
        .consensus,
    )
}

fn assemble_executed_tx(
    ctx: &WaveBatchContext<'_>,
    base: &VmBase,
    fold: &mut FoldState,
    vm_tx: VmTxHash,
    receipt: &Receipt,
    fee: Option<PayerFee>,
    is_local: &dyn Fn(Address) -> bool,
) -> ExecutedTx {
    let tx_hash = TxHash::from_raw(Hash::from_hash_bytes(&vm_tx.0.0));
    // Built before this transaction's own burn folds in: an abort settles
    // the floor over the state its siblings left, not over its own.
    let fee_receipt = fee.and_then(|payer| {
        payer
            .abort_floor
            .and_then(|floor| build_fee_receipt(ctx, base, fold, tx_hash, payer.vault, floor))
    });
    let cached = if matches!(receipt.outcome, Outcome::Completed { .. }) {
        let mut writes = fold_delta(receipt, base, &mut fold.running, vm_tx, is_local);
        apply_fee_burn(
            &mut writes,
            &fold.running,
            base,
            &mut fold.fees_applied,
            fee,
            receipt.fuel,
        );
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
    let mut executed = project_to_shard(
        &cached,
        tx_hash,
        ctx.local_shard,
        ctx.shard_trie,
        &HashMap::new(),
    );
    executed.fee_receipt = fee_receipt;
    executed
}

impl VmExecutor {
    /// The batch pipeline both dispatch arms share: derive, pre-read the
    /// local baseline, layer provisioned remote cells, execute under the
    /// shard's locality, fold local keys, and project. `provisions` is
    /// empty and locality is total for the single-shard arm.
    #[allow(clippy::too_many_lines)] // one pipeline, stages in order
    fn run_batch(
        &self,
        ctx: &WaveBatchContext<'_>,
        snapshot: &DynSnapshot<'_>,
        transactions: &[Arc<Verified<RoutableTransaction>>],
        provisions_by_tx: &BTreeMap<VmTxHash, Vec<Arc<Vec<SubstateEntry>>>>,
        clock_by_tx: &BTreeMap<VmTxHash, u64>,
        cross_shard: bool,
    ) -> Vec<ExecutedTx> {
        if transactions.is_empty() {
            return Vec::new();
        }
        let locality = if cross_shard {
            let trie = ctx.shard_trie.clone();
            let local_shard = ctx.local_shard;
            Locality::Owned(Arc::new(move |owner: Address| {
                trie.shard_for_prefix(owner.0) == local_shard
            }))
        } else {
            Locality::All
        };
        let is_local = {
            let trie = ctx.shard_trie.clone();
            let local_shard = ctx.local_shard;
            move |owner: Address| !cross_shard || trie.shard_for_prefix(owner.0) == local_shard
        };

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

        // The committed baseline: provisioned remote cells first — a
        // key's owner prefix routes it to exactly one source, so nothing
        // arbitrates — then the locally owned declared cells from the
        // wave snapshot.
        let mut cells: BTreeMap<SubstateKey, Vec<u8>> = BTreeMap::new();
        for lists in provisions_by_tx.values() {
            for entries in lists {
                for entry in entries.iter() {
                    if let Some((owner, local)) = vm_flat_key_parts(&entry.storage_key)
                        && let Some(value) = entry.value.as_ref()
                    {
                        cells.insert(
                            SubstateKey {
                                owner: Address(owner),
                                local: LocalKey(local),
                            },
                            value.to_vec(),
                        );
                    }
                }
            }
        }
        for entry in prepared.values() {
            for effect in entry.declared.iter() {
                if let EffectTarget::Point(key) = effect.target
                    && is_local(key.owner)
                    && let Some(value) = read_cell(snapshot, key)
                {
                    cells.insert(key, value);
                }
            }
        }
        // Pinned snapshot values last: the read is version-pinned, so
        // the envelope's proven value overrides whatever the local
        // snapshot holds — every committee reads the same cell.
        for tx in transactions {
            if let Some(vm) = tx.vm() {
                for pin in &vm.snapshot_pins {
                    let key = SubstateKey {
                        owner: Address(pin.owner),
                        local: LocalKey(pin.local),
                    };
                    match &pin.value {
                        Some(value) => {
                            cells.insert(key, value.to_vec());
                        }
                        None => {
                            cells.remove(&key);
                        }
                    }
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
                clock_ms: clock_by_tx.get(vm_tx).copied().unwrap_or_default(),
            })
            .collect();
        let runner = ManifestRunner {
            backend: &self.backend,
            prepared: &prepared,
        };
        let outcome = execute_batch(
            Arc::clone(&base) as Arc<dyn Base>,
            &batch,
            &runner,
            *ctx.block_hash.as_bytes(),
            protocol_hash,
            self.mode,
            &locality,
        )
        .unwrap_or_else(|error| panic!("BFT CRITICAL: VM batch execution failed: {error}"));

        // Fold receipts into per-transaction absolute updates in
        // canonical order, then check the folded end state against the
        // kernel's own applied store — the fold must be the same fold.
        // The fee payers this shard settles: a completed transaction
        // burns its attested actual from its payer's vault, on the
        // payer's shard only.
        let fee_by_tx: BTreeMap<VmTxHash, PayerFee> = transactions
            .iter()
            .filter_map(|tx| {
                let vm = tx.vm()?;
                let (owner, local) = tx.vm_fee_vault()?;
                if !is_local(Address(owner)) {
                    return None;
                }
                Some((
                    VmTxHash(Hash32(*tx.hash().as_bytes())),
                    PayerFee {
                        vault: SubstateKey {
                            owner: Address(owner),
                            local: LocalKey(local),
                        },
                        max_fee: vm.max_fee,
                        // Only a cross-shard leg can be aborted after it
                        // executed, so only it needs the abort's receipt
                        // built in reserve.
                        abort_floor: cross_shard.then(|| vm.abort_floor()),
                    },
                ))
            })
            .collect();

        let mut fold = FoldState {
            running: BTreeMap::new(),
            fees_applied: BTreeMap::new(),
        };
        let mut folded: BTreeMap<VmTxHash, ExecutedTx> = BTreeMap::new();
        for (vm_tx, receipt) in &outcome.receipts {
            let executed = assemble_executed_tx(
                ctx,
                &base,
                &mut fold,
                *vm_tx,
                receipt,
                fee_by_tx.get(vm_tx).copied(),
                &is_local,
            );
            folded.insert(*vm_tx, executed);
        }

        // The differential: every folded key's end value must equal the
        // kernel's applied store. A mismatch is a fold defect — receipts
        // silently diverging from kernel semantics — and must never ship.
        for (key, change) in &fold.running {
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

impl Executor for VmExecutor {
    fn execute_wave_batch(
        &self,
        ctx: &WaveBatchContext<'_>,
        snapshot: &DynSnapshot<'_>,
        transactions: &[Arc<Verified<RoutableTransaction>>],
    ) -> Vec<ExecutedTx> {
        // A single-shard batch commits in one block, so every member's
        // transaction clock is the wave-start anchor.
        let clock_by_tx: BTreeMap<VmTxHash, u64> = transactions
            .iter()
            .map(|tx| {
                (
                    VmTxHash(Hash32(*tx.hash().as_bytes())),
                    ctx.wave_start_ts.as_millis(),
                )
            })
            .collect();
        self.run_batch(
            ctx,
            snapshot,
            transactions,
            &BTreeMap::new(),
            &clock_by_tx,
            false,
        )
    }

    fn execute_cross_shard_batch(
        &self,
        ctx: &WaveBatchContext<'_>,
        snapshot: &DynSnapshot<'_>,
        requests: &[CrossShardTxInput<'_>],
    ) -> Vec<ExecutedTx> {
        let transactions: Vec<Arc<Verified<RoutableTransaction>>> =
            requests.iter().map(|r| Arc::clone(r.transaction)).collect();
        let provisions_by_tx: BTreeMap<VmTxHash, Vec<Arc<Vec<SubstateEntry>>>> = requests
            .iter()
            .map(|r| {
                (
                    VmTxHash(Hash32(*r.transaction.hash().as_bytes())),
                    r.provisions.to_vec(),
                )
            })
            .collect();
        let clock_by_tx: BTreeMap<VmTxHash, u64> = requests
            .iter()
            .map(|r| {
                (
                    VmTxHash(Hash32(*r.transaction.hash().as_bytes())),
                    r.clock.as_millis(),
                )
            })
            .collect();
        self.run_batch(
            ctx,
            snapshot,
            &transactions,
            &provisions_by_tx,
            &clock_by_tx,
            true,
        )
    }
}
