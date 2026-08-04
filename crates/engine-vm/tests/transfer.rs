//! The VM engine end to end at the seam: signed transfer graphs through
//! derivation, the batch executor, and the movement fold, against a
//! genesis-seeded snapshot.

use std::collections::{BTreeMap, HashSet};
use std::sync::Arc;

use hyperscale_effects_bridge::vm_statics::package_key;
use hyperscale_effects_bridge::{
    ProtocolHasher, admit_package, attach_metadata, encode_tree, vm_account_address,
};
use hyperscale_engine::{
    DynSnapshot, ExecutedTx, Executor, Parallelism, ProcessExecutionCache, WaveBatchContext,
};
use hyperscale_engine_vm::genesis::{account_artifact, entropy_key, vault_key};
use hyperscale_engine_vm::{
    ExecutionMode, PreviewGrants, PreviewInputs, PreviewOutcome, PreviewReport, ResourceChange,
    VM_XRD, VmExecutor, vm_genesis_updates,
};
use hyperscale_storage::{
    DatabaseUpdate, DatabaseUpdates, DbSortKey, PartitionDatabaseUpdates, SubstateDatabase,
};
use hyperscale_types::state_key::{VM_PARTITION, vm_db_node_key};
use hyperscale_types::{
    BlockHash, ConsensusReceipt, Ed25519PrivateKey, Hash, RevealChain, RoutableTransaction,
    ShardId, ShardTrie, Verified, VmBody, VmTransaction, WeightedTimestamp,
    absorb_committed_vm_cells,
};
use hyperscale_vm_effects::{
    AbiParam, Address, Constraint, EdgeRef, EnvelopeTree, Expr, GraphArg, GraphNode, IntentDecl,
    ManifestGraph, Value, package_hash,
};
use hyperscale_vm_kernel::encode_amount;
use hyperscale_vm_stdlib::{ACCOUNT_COMPONENT, account_metadata};
use radix_common::prelude::DbSubstateValue;
use radix_substate_store_interface::interface::{DbPartitionKey, PartitionEntry};

const ALICE: [u8; 16] = [0x11; 16];
const BOB: [u8; 16] = [0x22; 16];

/// A snapshot over the flattened genesis updates.
struct MapDb(BTreeMap<(Vec<u8>, u8, Vec<u8>), Vec<u8>>);

impl MapDb {
    fn genesis(accounts: &[([u8; 16], u128)]) -> Self {
        let updates = vm_genesis_updates(accounts);
        let mut map = BTreeMap::new();
        for (node_key, node_updates) in &updates.node_updates {
            for (partition, partition_updates) in &node_updates.partition_updates {
                let PartitionDatabaseUpdates::Delta { substate_updates } = partition_updates else {
                    panic!("genesis VM updates are Delta-only");
                };
                for (sort_key, update) in substate_updates {
                    let DatabaseUpdate::Set(value) = update else {
                        panic!("genesis VM updates are Set-only");
                    };
                    map.insert(
                        (node_key.clone(), *partition, sort_key.0.clone()),
                        value.clone(),
                    );
                }
            }
        }
        Self(map)
    }
}

impl SubstateDatabase for MapDb {
    fn get_raw_substate_by_db_key(
        &self,
        partition_key: &DbPartitionKey,
        sort_key: &DbSortKey,
    ) -> Option<DbSubstateValue> {
        self.0
            .get(&(
                partition_key.node_key.clone(),
                partition_key.partition_num,
                sort_key.0.clone(),
            ))
            .cloned()
    }

    fn list_raw_values_from_db_key(
        &self,
        _partition_key: &DbPartitionKey,
        _from_sort_key: Option<&DbSortKey>,
    ) -> Box<dyn Iterator<Item = PartitionEntry> + '_> {
        Box::new(std::iter::empty())
    }
}

fn transfer_graph(from: [u8; 16], to: [u8; 16], amount: u128) -> ManifestGraph {
    ManifestGraph {
        nodes: vec![
            GraphNode {
                target: Address(from),
                method: "withdraw".into(),
                args: vec![
                    GraphArg::Literal(Value::Address(VM_XRD)),
                    GraphArg::Literal(Value::U128(amount)),
                ],
            },
            GraphNode {
                target: Address(to),
                method: "deposit".into(),
                args: vec![GraphArg::Edge {
                    edge: EdgeRef {
                        producer: 0,
                        output: 0,
                    },
                    constraints: vec![Constraint::ResourceIs(VM_XRD)],
                }],
            },
        ],
    }
}

fn signed_transfer(seed: u8, from: [u8; 16], to: [u8; 16], amount: u128) -> RoutableTransaction {
    signed_transfer_with_fee(seed, from, to, amount, 1_000_000)
}

fn signed_transfer_with_fee(
    seed: u8,
    from: [u8; 16],
    to: [u8; 16],
    amount: u128,
    max_fee: u128,
) -> RoutableTransaction {
    let key = Ed25519PrivateKey::from_bytes(&[seed; 32]).unwrap();
    let tree = EnvelopeTree {
        root: IntentDecl {
            graph: transfer_graph(from, to, amount),
            params: Vec::new(),
        },
        root_bindings: Vec::new(),
        subintents: Vec::new(),
    };
    let vm = VmTransaction {
        body: VmBody::Call(encode_tree(&tree).into()),
        subintent_sigs: Vec::new(),
        fee_payer: vm_account_address(&key.public_key().0),
        max_fee,
        gas_limit: 1_000_000,
        validity_start_ms: 0,
        validity_end_ms: u64::MAX,
        message: Vec::new().into(),
        signer: [0; 32],
        signature: [0; 64],
    }
    .sign(&key);
    RoutableTransaction::new_vm(vm)
}

/// The account address the fee-paying tests derive from their signing key.
fn fee_payer(seed: u8) -> [u8; 16] {
    let key = Ed25519PrivateKey::from_bytes(&[seed; 32]).unwrap();
    vm_account_address(&key.public_key().0)
}

/// Every account any test in this binary transacts with.
///
/// The VM statics are process-global and first-installed-wins, so every
/// executor here has to be built over one world: sharing a process, the
/// first `VmExecutor::new` fixes the instance registry for every test that
/// follows, and an address missing from it fails admission with `no
/// instance` rather than anything to do with the test's own subject. Per-test
/// balances are unaffected — those come from the snapshot `execute_on`
/// builds, which is separate from the world.
fn world_accounts() -> Vec<([u8; 16], u128)> {
    vec![
        (ALICE, 1_000),
        (BOB, 50),
        (fee_payer(7), 1_000),
        (fee_payer(11), 110),
    ]
}

fn execute(
    executor: &VmExecutor,
    transactions: &[Arc<Verified<RoutableTransaction>>],
) -> Vec<ExecutedTx> {
    execute_on(&[(ALICE, 1_000), (BOB, 50)], executor, transactions)
}

/// A signed single-node stamp: the account records the transaction's
/// randomness draw in its entropy leaf.
fn signed_stamp(seed: u8, owner: [u8; 16]) -> RoutableTransaction {
    let key = Ed25519PrivateKey::from_bytes(&[seed; 32]).unwrap();
    let tree = EnvelopeTree {
        root: IntentDecl {
            graph: ManifestGraph {
                nodes: vec![GraphNode {
                    target: Address(owner),
                    method: "stamp-entropy".into(),
                    args: vec![],
                }],
            },
            params: Vec::new(),
        },
        root_bindings: Vec::new(),
        subintents: Vec::new(),
    };
    let vm = VmTransaction {
        body: VmBody::Call(encode_tree(&tree).into()),
        subintent_sigs: Vec::new(),
        fee_payer: vm_account_address(&key.public_key().0),
        max_fee: 1_000_000,
        gas_limit: 1_000_000,
        validity_start_ms: 0,
        validity_end_ms: u64::MAX,
        message: Vec::new().into(),
        signer: [0; 32],
        signature: [0; 64],
    }
    .sign(&key);
    RoutableTransaction::new_vm(vm)
}

/// Execute `transactions` as a single-shard batch anchored on `reveal`.
fn execute_anchored(
    executor: &VmExecutor,
    reveal: RevealChain,
    transactions: &[Arc<Verified<RoutableTransaction>>],
) -> Vec<ExecutedTx> {
    let snapshot_store = MapDb::genesis(&[(ALICE, 1_000), (BOB, 50)]);
    let snapshot = DynSnapshot(&snapshot_store);
    let cache = ProcessExecutionCache::new(HashSet::from([ShardId::ROOT]));
    let trie = ShardTrie::single();
    let ctx = WaveBatchContext {
        par: Parallelism::Sequential,
        cache: &cache,
        local_shard: ShardId::ROOT,
        shard_trie: &trie,
        block_hash: BlockHash::from_raw(Hash::from_bytes(b"block")),
        wave_start_ts: WeightedTimestamp::from_millis(1_000),
        wave_start_reveal: reveal,
    };
    executor.execute_wave_batch(&ctx, &snapshot, transactions)
}

/// The entropy leaf a stamp wrote, if any.
fn entropy_cell(executed: &ExecutedTx, owner: [u8; 16]) -> Option<Vec<u8>> {
    let key = entropy_key(owner);
    let updates = executed.consensus.database_updates()?;
    let node = updates.node_updates.get(&vm_db_node_key(owner))?;
    let PartitionDatabaseUpdates::Delta { substate_updates } =
        node.partition_updates.get(&VM_PARTITION)?
    else {
        return None;
    };
    match substate_updates.get(&DbSortKey(key.local.0.to_vec()))? {
        DatabaseUpdate::Set(value) => Some(value.clone()),
        DatabaseUpdate::Delete => None,
    }
}

/// The stamp writes a draw fixed by the anchor: the same anchor gives the
/// same 32 bytes, a different anchor gives different ones — which is what
/// makes the payer block, and not the executing block, decide a
/// randomness-reading guest's receipt.
#[test]
fn a_stamp_writes_the_draw_its_anchor_fixes() {
    let executor = VmExecutor::new(&world_accounts(), ExecutionMode::Serial);
    let tx = Arc::new(Verified::<RoutableTransaction>::from_persisted(
        signed_stamp(9, ALICE),
    ));
    let anchor = RevealChain::from_raw(Hash::from_bytes(b"payer block"));

    let executed = execute_anchored(&executor, anchor, std::slice::from_ref(&tx));
    let stamped = entropy_cell(&executed[0], ALICE).expect("the stamp wrote the entropy leaf");
    assert_eq!(stamped.len(), 32);

    let again = execute_anchored(&executor, anchor, std::slice::from_ref(&tx));
    assert_eq!(
        entropy_cell(&again[0], ALICE),
        Some(stamped.clone()),
        "one anchor, one draw"
    );

    let elsewhere = execute_anchored(
        &executor,
        RevealChain::from_raw(Hash::from_bytes(b"another block")),
        std::slice::from_ref(&tx),
    );
    assert_ne!(
        entropy_cell(&elsewhere[0], ALICE),
        Some(stamped),
        "a different anchor is a different draw"
    );
}

fn execute_on(
    accounts: &[([u8; 16], u128)],
    executor: &VmExecutor,
    transactions: &[Arc<Verified<RoutableTransaction>>],
) -> Vec<ExecutedTx> {
    let snapshot_store = MapDb::genesis(accounts);
    let snapshot = DynSnapshot(&snapshot_store);
    let cache = ProcessExecutionCache::new(HashSet::from([ShardId::ROOT]));
    let trie = ShardTrie::single();
    let ctx = WaveBatchContext {
        par: Parallelism::Sequential,
        cache: &cache,
        local_shard: ShardId::ROOT,
        shard_trie: &trie,
        block_hash: BlockHash::from_raw(Hash::from_bytes(b"block")),
        wave_start_ts: WeightedTimestamp::from_millis(1_000),
        wave_start_reveal: RevealChain::ZERO,
    };
    executor.execute_wave_batch(&ctx, &snapshot, transactions)
}

/// The raw update a batch made to an account's native vault, if any.
fn vault_update(updates: &DatabaseUpdates, owner: [u8; 16]) -> Option<DatabaseUpdate> {
    let key = vault_key(owner, VM_XRD);
    let node = updates.node_updates.get(&vm_db_node_key(owner))?;
    let PartitionDatabaseUpdates::Delta { substate_updates } =
        node.partition_updates.get(&VM_PARTITION)?
    else {
        return None;
    };
    substate_updates
        .get(&DbSortKey(key.local.0.to_vec()))
        .cloned()
}

fn vault_cell(updates: &DatabaseUpdates, owner: [u8; 16]) -> Option<Vec<u8>> {
    match vault_update(updates, owner)? {
        DatabaseUpdate::Set(value) => Some(value),
        DatabaseUpdate::Delete => None,
    }
}

#[test]
fn a_transfer_folds_to_identity_keyed_absolute_updates() {
    let executor = VmExecutor::new(&world_accounts(), ExecutionMode::Serial);
    let tx = Arc::new(Verified::<RoutableTransaction>::from_persisted(
        signed_transfer(7, ALICE, BOB, 100),
    ));
    let executed = execute(&executor, &[tx]);
    assert_eq!(executed.len(), 1);
    let ConsensusReceipt::Succeeded {
        database_updates,
        owned_nodes,
        receipt_hash,
        ..
    } = &executed[0].consensus
    else {
        panic!("transfer must succeed: {:?}", executed[0].consensus);
    };
    assert!(owned_nodes.is_empty());
    assert_ne!(receipt_hash.as_raw(), &Hash::ZERO);
    // Withdraw settled 100 off the sender; deposit credited the
    // recipient. Absolute values, identity-keyed.
    assert_eq!(
        vault_cell(database_updates, ALICE),
        Some(encode_amount(900).to_vec())
    );
    assert_eq!(
        vault_cell(database_updates, BOB),
        Some(encode_amount(150).to_vec())
    );
}

#[test]
fn an_uncovered_withdrawal_aborts_and_the_batch_carries_on() {
    let executor = VmExecutor::new(&world_accounts(), ExecutionMode::Serial);
    let over = Arc::new(Verified::<RoutableTransaction>::from_persisted(
        signed_transfer(8, BOB, ALICE, 500),
    ));
    let fine = Arc::new(Verified::<RoutableTransaction>::from_persisted(
        signed_transfer(9, ALICE, BOB, 25),
    ));
    let executed = execute(&executor, &[Arc::clone(&over), Arc::clone(&fine)]);
    assert_eq!(executed.len(), 2);
    // Input order is preserved: the infeasible reservation aborts its
    // own transaction only.
    assert!(matches!(executed[0].consensus, ConsensusReceipt::Failed));
    let ConsensusReceipt::Succeeded {
        database_updates, ..
    } = &executed[1].consensus
    else {
        panic!("the covered transfer must succeed");
    };
    assert_eq!(
        vault_cell(database_updates, ALICE),
        Some(encode_amount(975).to_vec())
    );
    assert_eq!(
        vault_cell(database_updates, BOB),
        Some(encode_amount(75).to_vec())
    );
}

#[test]
fn serial_and_parallel_scheduling_produce_identical_receipts() {
    let serial = VmExecutor::new(&world_accounts(), ExecutionMode::Serial);
    let parallel = VmExecutor::new(&world_accounts(), ExecutionMode::Parallel);
    let txs: Vec<Arc<Verified<RoutableTransaction>>> = (0..4)
        .map(|i| {
            Arc::new(Verified::<RoutableTransaction>::from_persisted(
                signed_transfer(10 + i, ALICE, BOB, 10 + u128::from(i)),
            ))
        })
        .collect();
    let a = execute(&serial, &txs);
    let b = execute(&parallel, &txs);
    assert_eq!(a.len(), b.len());
    for (left, right) in a.iter().zip(&b) {
        assert_eq!(left.tx_hash, right.tx_hash);
        assert_eq!(left.consensus, right.consensus);
    }
}

/// A completed transfer burns its attested actual — fuel, capped at the
/// signed ceiling — from the payer's vault as part of the receipt's own
/// writes, so the burn rides the attested `writes_root` and the
/// sync-replayable work items.
/// An attempt that applies nothing still attests the declaration it made,
/// and a completed one attests strictly more.
///
/// This is the half of attested work that fuel alone misses. A shard that
/// executes a leg it does not own can burn almost no fuel while holding the
/// exclusivity its declaration claimed, so pricing on compute alone would
/// under-pay exactly the participants cross-shard compensation exists for.
/// Here the same shape is visible within one shard: the uncovered
/// withdrawal never applies an effect, and its work is still positive
/// because the declaration was admitted, routed, and locked regardless.
#[test]
fn an_unapplied_attempt_still_attests_its_declaration() {
    let executor = VmExecutor::new(&world_accounts(), ExecutionMode::Serial);
    let over = Arc::new(Verified::<RoutableTransaction>::from_persisted(
        signed_transfer(3, ALICE, BOB, 1_000_000),
    ));
    let executed = execute(&executor, &[over]);
    assert_eq!(executed.len(), 1);
    assert!(
        matches!(executed[0].consensus, ConsensusReceipt::Failed),
        "an uncovered withdrawal must not apply"
    );
    let unapplied = executed[0].attested_work;
    assert!(
        unapplied > 0,
        "an attempt that applied nothing still declared, routed, and locked"
    );

    // A completed transfer of the same shape attests the same declaration
    // plus the compute it actually consumed.
    let fine = Arc::new(Verified::<RoutableTransaction>::from_persisted(
        signed_transfer(4, ALICE, BOB, 100),
    ));
    let executed = execute(&executor, &[fine]);
    assert_eq!(executed.len(), 1);
    assert!(
        matches!(executed[0].consensus, ConsensusReceipt::Succeeded { .. }),
        "a covered transfer must apply"
    );
    assert!(
        executed[0].attested_work > unapplied,
        "a completed execution attests its compute on top of its declaration: \
         completed = {}, unapplied = {unapplied}",
        executed[0].attested_work,
    );
}

#[test]
fn a_completed_transfer_burns_the_fee_ceiling_from_its_payer() {
    let payer = fee_payer(7);
    let accounts = [(payer, 1_000), (BOB, 50)];
    let executor = VmExecutor::new(&world_accounts(), ExecutionMode::Serial);
    // A transfer's fuel far exceeds the tiny ceiling, so the burn is
    // exactly `max_fee` — the cap working.
    let tx = Arc::new(Verified::<RoutableTransaction>::from_persisted(
        signed_transfer_with_fee(7, payer, BOB, 100, 10),
    ));
    let executed = execute_on(&accounts, &executor, &[tx]);
    assert_eq!(executed.len(), 1);
    let ConsensusReceipt::Succeeded {
        database_updates, ..
    } = &executed[0].consensus
    else {
        panic!("transfer must succeed: {:?}", executed[0].consensus);
    };
    assert_eq!(
        vault_cell(database_updates, payer),
        Some(encode_amount(1_000 - 100 - 10).to_vec())
    );
    assert_eq!(
        vault_cell(database_updates, BOB),
        Some(encode_amount(150).to_vec())
    );
}

#[test]
fn a_payer_drained_by_its_own_fee_deletes_its_vault() {
    // The burn folds outside the kernel store, so it has to apply the
    // store's delete-on-zero rule itself — otherwise the commonest way a
    // vault empties leaves sixteen zero bytes behind, and a storage bond
    // that can never be refunded.
    let payer = fee_payer(11);
    // Exactly the transfer plus the ceiling: nothing survives the burn.
    let accounts = [(payer, 110), (BOB, 50)];
    let executor = VmExecutor::new(&world_accounts(), ExecutionMode::Serial);
    let tx = Arc::new(Verified::<RoutableTransaction>::from_persisted(
        signed_transfer_with_fee(11, payer, BOB, 100, 10),
    ));
    let executed = execute_on(&accounts, &executor, &[tx]);
    let ConsensusReceipt::Succeeded {
        database_updates, ..
    } = &executed[0].consensus
    else {
        panic!("transfer must succeed: {:?}", executed[0].consensus);
    };

    assert_eq!(
        vault_update(database_updates, payer),
        Some(DatabaseUpdate::Delete),
        "a drained payer vault is deleted, not zeroed"
    );
    // The recipient is untouched by the rule.
    assert_eq!(
        vault_cell(database_updates, BOB),
        Some(encode_amount(150).to_vec())
    );
}

/// An account whose prefix routes to the other half of a two-shard trie.
const FAR: [u8; 16] = [0x88; 16];

/// Execute one batch as `local_shard` under a two-leaf trie.
fn execute_on_shard(
    executor: &VmExecutor,
    local_shard: ShardId,
    transactions: &[Arc<Verified<RoutableTransaction>>],
) -> Vec<ExecutedTx> {
    let snapshot_store = MapDb::genesis(&[(ALICE, 1_000), (FAR, 50)]);
    let snapshot = DynSnapshot(&snapshot_store);
    let cache = ProcessExecutionCache::new(HashSet::from([local_shard]));
    let trie = ShardTrie::uniform(1);
    let ctx = WaveBatchContext {
        par: Parallelism::Sequential,
        cache: &cache,
        local_shard,
        shard_trie: &trie,
        block_hash: BlockHash::from_raw(Hash::from_bytes(b"block")),
        wave_start_ts: WeightedTimestamp::from_millis(1_000),
        wave_start_reveal: RevealChain::ZERO,
    };
    executor.execute_wave_batch(&ctx, &snapshot, transactions)
}

fn events_of(executed: &ExecutedTx) -> Vec<([u8; 16], u32)> {
    let ConsensusReceipt::Succeeded { vm_events, .. } = &executed.consensus else {
        panic!("transfer must succeed: {:?}", executed.consensus);
    };
    vm_events
        .iter()
        .map(|event| (event.emitter, event.event_type))
        .collect()
}

fn hash_of(executed: &ExecutedTx) -> Hash {
    let ConsensusReceipt::Succeeded { receipt_hash, .. } = &executed.consensus else {
        panic!("transfer must succeed");
    };
    *receipt_hash.as_raw()
}

/// A transfer's two legs emit from accounts on different shards. Each
/// shard's receipt keeps only the events its own instances emitted, while
/// the receipt hash — which covers the union — stays identical, so the
/// committees agree on what the transaction emitted without either shard
/// storing the other's events.
#[test]
fn an_event_lands_only_on_its_emitters_home_shard() {
    let world = vec![(ALICE, 1_000u128), (FAR, 50), (fee_payer(7), 1_000)];
    let executor = VmExecutor::new(&world, ExecutionMode::Serial);
    let trie = ShardTrie::uniform(1);
    let (near, far) = (trie.shard_for_prefix(ALICE), trie.shard_for_prefix(FAR));
    assert_ne!(near, far, "the two accounts must sit on different shards");

    let tx = Arc::new(Verified::<RoutableTransaction>::from_persisted(
        signed_transfer(7, ALICE, FAR, 100),
    ));
    let sender_side = execute_on_shard(&executor, near, std::slice::from_ref(&tx));
    let recipient_side = execute_on_shard(&executor, far, &[tx]);

    assert_eq!(events_of(&sender_side[0]), vec![(ALICE, 0)]);
    assert_eq!(events_of(&recipient_side[0]), vec![(FAR, 1)]);
    assert_eq!(
        hash_of(&sender_side[0]),
        hash_of(&recipient_side[0]),
        "the receipt hash covers the union, so it cannot differ by shard",
    );
}

/// A signed publish of `artifact`, paid for by `seed`'s account.
fn signed_publish(seed: u8, artifact: Vec<u8>) -> RoutableTransaction {
    let key = Ed25519PrivateKey::from_bytes(&[seed; 32]).unwrap();
    let vm = VmTransaction {
        body: VmBody::Publish(artifact.into()),
        subintent_sigs: Vec::new(),
        fee_payer: vm_account_address(&key.public_key().0),
        max_fee: 1_000_000,
        gas_limit: 1_000_000,
        validity_start_ms: 0,
        validity_end_ms: u64::MAX,
        message: Vec::new().into(),
        signer: [0; 32],
        signature: [0; 64],
    }
    .sign(&key);
    RoutableTransaction::new_vm(vm)
}

/// The raw update a batch made to a package's cell under `publisher`.
fn package_cell(
    updates: &DatabaseUpdates,
    publisher: [u8; 16],
    artifact: &[u8],
) -> Option<Vec<u8>> {
    let key = package_key(publisher, package_hash(&ProtocolHasher, artifact));
    let node = updates.node_updates.get(&vm_db_node_key(publisher))?;
    let PartitionDatabaseUpdates::Delta { substate_updates } =
        node.partition_updates.get(&VM_PARTITION)?
    else {
        return None;
    };
    match substate_updates.get(&DbSortKey(key.local.0.to_vec()))? {
        DatabaseUpdate::Set(value) => Some(value.clone()),
        DatabaseUpdate::Delete => None,
    }
}

#[test]
fn a_publish_writes_the_artifact_under_its_publisher() {
    let payer = fee_payer(7);
    let executor = VmExecutor::new(&world_accounts(), ExecutionMode::Serial);
    let artifact = account_artifact().to_vec();
    let tx = Arc::new(Verified::<RoutableTransaction>::from_persisted(
        signed_publish(7, artifact.clone()),
    ));
    // Funded well above the burn: at the placeholder rate of one unit
    // per artifact byte, publishing the stdlib guest costs more than the
    // balances the transfer fixtures use.
    let executed = execute_on(&[(payer, 1_000_000)], &executor, &[tx]);

    let ConsensusReceipt::Succeeded {
        database_updates, ..
    } = &executed[0].consensus
    else {
        panic!("a publish must succeed: {:?}", executed[0].consensus);
    };
    assert_eq!(
        package_cell(database_updates, payer, &artifact).as_deref(),
        Some(artifact.as_slice()),
        "the artifact lands whole in its content-addressed cell"
    );
    // The publisher paid: the vault carries the burn, and the fee is the
    // only other thing a publish writes.
    let paid = vault_cell(database_updates, payer).expect("the payer's vault was written");
    assert_eq!(
        paid,
        encode_amount(1_000_000 - artifact.len() as u128).to_vec(),
        "the publisher paid exactly what judging its artifact cost"
    );
    assert!(
        executed[0].attested_work > 0,
        "judging the artifact is attested work"
    );
}

/// The stdlib artifact's ABI bindings survive the round trip through the
/// metadata section, which is what makes the account guest callable
/// through them rather than through a table that knows its method names.
#[test]
fn the_stdlib_artifact_carries_resolvable_bindings() {
    let metadata = admit_package(account_artifact()).expect("the stdlib artifact admits");
    assert_eq!(
        metadata.methods["withdraw"].abi,
        vec![AbiParam::Handle(0), AbiParam::Derived(Expr::Arg(1))],
        "the binding decoded is the binding authored"
    );
    assert_eq!(
        metadata.methods["deposit"].abi,
        vec![AbiParam::Handle(0), AbiParam::Bucket(0)],
        "a bucket's amount is the one argument a signature cannot derive"
    );
}

#[test]
fn a_publish_that_is_not_a_package_never_reaches_execution() {
    // The whole publish verdict is a function of the artifact's bytes,
    // so it is reached at admission: derivation refuses, the transaction
    // is never included, and nobody pays for it or stores it.
    let junk = b"\0asm\x01\0\0\0".to_vec();
    assert!(
        admit_package(&junk).is_err(),
        "well-formed wasm framing is not a package"
    );
    assert!(
        admit_package(account_artifact()).is_ok(),
        "the stdlib artifact is one"
    );
}

#[test]
fn a_committed_publish_grows_the_cache_that_routing_reads() {
    let payer = fee_payer(7);
    let executor = VmExecutor::new(&world_accounts(), ExecutionMode::Serial);

    // A package the world has never seen: the stdlib artifact with its
    // metadata attached a second time under a different publisher would
    // be the same bytes, so vary the metadata to vary the address.
    let mut metadata = account_metadata();
    metadata.events.push("republished".into());
    let artifact = attach_metadata(ACCOUNT_COMPONENT, &metadata).expect("attaches");
    let package = package_hash(&ProtocolHasher, &artifact);

    let cache = executor.packages();
    assert!(
        cache.load().get(package).is_none(),
        "the package is unknown before its block commits"
    );

    let tx = Arc::new(Verified::<RoutableTransaction>::from_persisted(
        signed_publish(7, artifact),
    ));
    let executed = execute_on(&[(payer, 1_000_000)], &executor, &[tx]);
    let ConsensusReceipt::Succeeded { .. } = &executed[0].consensus else {
        panic!("the publish must succeed: {:?}", executed[0].consensus);
    };

    // Executing is not committing: the cache learns the package from the
    // committed receipt, which is what a synced replica also replays.
    assert!(
        cache.load().get(package).is_none(),
        "execution alone does not publish"
    );
    absorb_committed_vm_cells([&executed[0].consensus]);
    assert_eq!(
        cache.load().get(package),
        Some(&metadata),
        "the committed cell published exactly the metadata the artifact declares"
    );
}

#[test]
fn only_a_cell_that_addresses_its_own_contents_publishes() {
    // A package cell is self-identifying: its key is the content address
    // of the value it holds. Without that check, any committed cell
    // whose bytes happened to parse as an artifact would publish a
    // package — no publish transaction, no fee, no cell of its own.
    let executor = VmExecutor::new(&world_accounts(), ExecutionMode::Serial);
    let cache = executor.packages();

    let mut metadata = account_metadata();
    metadata.events.push("smuggled".into());
    let artifact = attach_metadata(ACCOUNT_COMPONENT, &metadata).expect("attaches");
    let package = package_hash(&ProtocolHasher, &artifact);
    let publisher = fee_payer(11);

    // The right bytes at the wrong key: a vault slot, not the content
    // address. Refused.
    let vault = vault_key(publisher, VM_XRD);
    cache.absorb_cell(publisher, vault.local.0, &artifact);
    assert!(
        cache.load().get(package).is_none(),
        "an artifact stored anywhere but its own address is not a package"
    );

    // The same bytes at the key their own hash builds. Published.
    let cell = package_key(publisher, package);
    cache.absorb_cell(publisher, cell.local.0, &artifact);
    assert_eq!(cache.load().get(package), Some(&metadata));
}

/// Preview `tx` against a genesis snapshot of `accounts`, committing
/// nothing.
fn preview_on(
    accounts: &[([u8; 16], u128)],
    executor: &VmExecutor,
    tx: &RoutableTransaction,
    grants: PreviewGrants,
) -> PreviewReport {
    let snapshot_store = MapDb::genesis(accounts);
    let snapshot = DynSnapshot(&snapshot_store);
    executor.preview(
        &snapshot,
        tx,
        PreviewInputs {
            clock: WeightedTimestamp::from_millis(1_000),
            randomness: RevealChain::ZERO,
            grants,
        },
    )
}

/// The reported change to `owner`'s native vault.
fn change_for(report: &PreviewReport, owner: [u8; 16]) -> ResourceChange {
    let key = vault_key(owner, VM_XRD);
    *report
        .changes
        .iter()
        .find(|change| change.key == key)
        .unwrap_or_else(|| panic!("no reported change for {owner:?}: {:?}", report.changes))
}

/// The preview fixture: a payer who funds the transfer and its fee, and a
/// recipient. The ceiling sits far below the fuel a transfer burns, so the
/// charge is the cap rather than the actual.
const PREVIEW_CEILING: u128 = 10;

struct PreviewFixture {
    payer: [u8; 16],
    accounts: Vec<([u8; 16], u128)>,
    tx: RoutableTransaction,
}

fn preview_fixture() -> PreviewFixture {
    let payer = fee_payer(7);
    PreviewFixture {
        payer,
        accounts: vec![(payer, 1_000), (BOB, 50)],
        tx: signed_transfer_with_fee(7, payer, BOB, 100, PREVIEW_CEILING),
    }
}

/// A preview reports the transfer's resource changes: what leaves the
/// sender's vault, what reaches the recipient's, and what the fee costs on
/// top — read off the receipt's settles and movements without committing
/// anything.
#[test]
fn a_preview_reports_the_resource_changes_a_transfer_would_make() {
    let PreviewFixture {
        payer,
        accounts,
        tx,
    } = preview_fixture();
    let executor = VmExecutor::new(&world_accounts(), ExecutionMode::Serial);
    let report = preview_on(&accounts, &executor, &tx, PreviewGrants::default());

    assert_eq!(report.outcome, PreviewOutcome::Completed);
    assert_eq!(report.fee, PREVIEW_CEILING, "a transfer's fuel exceeds it");
    assert_eq!(report.changes.len(), 2, "two vaults move: {report:?}");

    let sender = change_for(&report, payer);
    assert_eq!((sender.before, sender.after), (1_000, 1_000 - 100 - 10));
    assert_eq!(
        (sender.settled, sender.credit, sender.debit),
        (100, 0, 0),
        "a withdrawal leaves through its reservation's settle"
    );

    let recipient = change_for(&report, BOB);
    assert_eq!((recipient.before, recipient.after), (50, 150));
    assert_eq!(
        (recipient.credit, recipient.debit, recipient.settled),
        (100, 0, 0),
        "a deposit arrives as a commutative credit"
    );

    // Nothing moved: the same preview twice reports the same thing.
    assert_eq!(
        preview_on(&accounts, &executor, &tx, PreviewGrants::default()),
        report,
        "a preview commits nothing, so it is repeatable"
    );
}

/// The preview's arithmetic is the wave's arithmetic: what it says a
/// vault would hold is what the committed receipt writes there.
#[test]
fn a_preview_agrees_with_the_wave_that_would_commit_it() {
    let PreviewFixture {
        payer,
        accounts,
        tx,
    } = preview_fixture();
    let executor = VmExecutor::new(&world_accounts(), ExecutionMode::Serial);
    let report = preview_on(&accounts, &executor, &tx, PreviewGrants::default());

    let verified = Arc::new(Verified::<RoutableTransaction>::from_persisted(tx));
    let executed = execute_on(&accounts, &executor, &[verified]);
    let ConsensusReceipt::Succeeded {
        database_updates, ..
    } = &executed[0].consensus
    else {
        panic!("the transfer must succeed: {:?}", executed[0].consensus);
    };

    for owner in [payer, BOB] {
        assert_eq!(
            vault_cell(database_updates, owner),
            Some(encode_amount(change_for(&report, owner).after).to_vec()),
            "the preview's figure for {owner:?} is what the wave commits"
        );
    }
}

/// Free credit is the one grant a preview can carry today: the fee is
/// still priced and reported, but it never reaches the payer's vault, so
/// a wallet can price an envelope its payer could not cover.
#[test]
fn free_credit_reports_the_fee_without_charging_it() {
    let PreviewFixture {
        payer,
        accounts,
        tx,
    } = preview_fixture();
    let executor = VmExecutor::new(&world_accounts(), ExecutionMode::Serial);
    let charged = preview_on(&accounts, &executor, &tx, PreviewGrants::default());
    let credited = preview_on(
        &accounts,
        &executor,
        &tx,
        PreviewGrants { free_credit: true },
    );

    assert_eq!(credited.fee, charged.fee, "the fee is priced either way");
    assert_eq!(
        change_for(&credited, payer).after,
        change_for(&charged, payer).after + charged.fee,
        "credit keeps exactly the fee off the payer's vault"
    );
    assert_eq!(
        change_for(&credited, BOB),
        change_for(&charged, BOB),
        "a grant to the payer moves nobody else"
    );
}

/// An uncovered withdrawal previews as the abort it would be, priced at
/// the class floor: the sender lost a deterministic race rather than
/// making a mistake, so nothing but the floor leaves its vault.
#[test]
fn a_preview_prices_an_abort_at_its_class_floor() {
    let payer = fee_payer(7);
    let accounts = [(payer, 1_000), (BOB, 50)];
    let executor = VmExecutor::new(&world_accounts(), ExecutionMode::Serial);
    let tx = signed_transfer_with_fee(7, payer, BOB, 5_000, PREVIEW_CEILING);
    let report = preview_on(&accounts, &executor, &tx, PreviewGrants::default());

    let PreviewOutcome::Aborted { reason } = &report.outcome else {
        panic!("an uncovered withdrawal must abort: {:?}", report.outcome);
    };
    assert!(reason.contains("infeasible"), "reason = {reason}");
    assert_eq!(report.fee, PREVIEW_CEILING / 10, "the abort floor");
    assert_eq!(
        report.changes,
        vec![ResourceChange {
            key: vault_key(payer, VM_XRD),
            before: 1_000,
            after: 1_000 - PREVIEW_CEILING / 10,
            credit: 0,
            debit: 0,
            settled: 0,
        }],
        "an abort moves nothing but the floor"
    );
}

/// An envelope admission would refuse previews as refused, and costs
/// nothing: it could never enter a block, so nobody would pay for it.
#[test]
fn a_preview_refuses_what_admission_would_refuse() {
    let stranger = [0xAB; 16];
    assert!(
        !world_accounts().iter().any(|(a, _)| *a == stranger),
        "the address must be outside the world"
    );
    let executor = VmExecutor::new(&world_accounts(), ExecutionMode::Serial);
    let tx = signed_transfer_with_fee(7, stranger, BOB, 10, PREVIEW_CEILING);
    let report = preview_on(&[(BOB, 50)], &executor, &tx, PreviewGrants::default());

    assert!(
        matches!(report.outcome, PreviewOutcome::Refused { .. }),
        "outcome = {:?}",
        report.outcome
    );
    assert_eq!(report.fee, 0);
    assert!(report.changes.is_empty());
}

/// A publish previews too, and its price needs no state: judging an
/// artifact costs one unit per byte, which is the whole answer.
#[test]
fn a_preview_prices_a_publish_by_its_artifact() {
    let payer = fee_payer(7);
    let artifact = account_artifact().to_vec();
    let executor = VmExecutor::new(&world_accounts(), ExecutionMode::Serial);
    let tx = signed_publish(7, artifact.clone());
    let report = preview_on(
        &[(payer, 1_000_000)],
        &executor,
        &tx,
        PreviewGrants::default(),
    );

    assert_eq!(report.outcome, PreviewOutcome::Completed);
    assert_eq!(report.fee, artifact.len() as u128);
    let vault = change_for(&report, payer);
    assert_eq!(
        (vault.before, vault.after),
        (1_000_000, 1_000_000 - artifact.len() as u128)
    );

    // An artifact that is not a package is refused at admission, so it
    // never enters a block and costs its publisher nothing.
    let junk = signed_publish(7, b"\0asm\x01\0\0\0".to_vec());
    let refused = preview_on(
        &[(payer, 1_000_000)],
        &executor,
        &junk,
        PreviewGrants::default(),
    );
    assert!(matches!(refused.outcome, PreviewOutcome::Refused { .. }));
    assert_eq!(refused.fee, 0);
}

#[test]
fn a_committed_cell_that_is_not_a_package_is_ignored() {
    // The other half: ordinary traffic cannot grow the cache by
    // accident, whatever it writes.
    let executor = VmExecutor::new(&world_accounts(), ExecutionMode::Serial);
    let tx = Arc::new(Verified::<RoutableTransaction>::from_persisted(
        signed_transfer(7, ALICE, BOB, 100),
    ));
    let executed = execute(&executor, &[tx]);
    let bogus = package_hash(&ProtocolHasher, encode_amount(900).as_ref());
    absorb_committed_vm_cells([&executed[0].consensus]);
    assert!(
        executor.packages().load().get(bogus).is_none(),
        "vault writes are not packages"
    );
}
