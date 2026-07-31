//! The VM engine end to end at the seam: signed transfer graphs through
//! derivation, the batch executor, and the movement fold, against a
//! genesis-seeded snapshot.

use std::collections::{BTreeMap, HashSet};
use std::sync::Arc;

use hyperscale_effects_bridge::{encode_tree, vm_account_address};
use hyperscale_engine::{
    DynSnapshot, ExecutedTx, Executor, Parallelism, ProcessExecutionCache, WaveBatchContext,
};
use hyperscale_engine_vm::genesis::vault_key;
use hyperscale_engine_vm::{ExecutionMode, VM_XRD, VmExecutor, vm_genesis_updates};
use hyperscale_storage::{
    DatabaseUpdate, DatabaseUpdates, DbSortKey, PartitionDatabaseUpdates, SubstateDatabase,
};
use hyperscale_types::state_key::{VM_PARTITION, vm_db_node_key};
use hyperscale_types::{
    BlockHash, ConsensusReceipt, Ed25519PrivateKey, Hash, RevealChain, RoutableTransaction,
    ShardId, ShardTrie, Verified, VmTransaction, WeightedTimestamp,
};
use hyperscale_vm_effects::{
    Address, Constraint, EdgeRef, EnvelopeTree, GraphArg, GraphNode, IntentDecl, ManifestGraph,
    Value,
};
use hyperscale_vm_kernel::encode_amount;
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
        tree: encode_tree(&tree).into(),
        subintent_sigs: Vec::new(),
        fee_payer: vm_account_address(&key.public_key().0),
        max_fee,
        gas_limit: 1_000_000,
        snapshot_pins: Vec::new(),
        validity_start_ms: 0,
        validity_end_ms: u64::MAX,
        message: Vec::new().into(),
        signer: [0; 32],
        signature: [0; 64],
    }
    .sign(&key);
    RoutableTransaction::new_vm(vm)
}

fn execute(
    executor: &VmExecutor,
    transactions: &[Arc<Verified<RoutableTransaction>>],
) -> Vec<ExecutedTx> {
    execute_on(&[(ALICE, 1_000), (BOB, 50)], executor, transactions)
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
    let executor = VmExecutor::new(&[(ALICE, 1_000), (BOB, 50)], ExecutionMode::Serial);
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
    let executor = VmExecutor::new(&[(ALICE, 1_000), (BOB, 50)], ExecutionMode::Serial);
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
    let serial = VmExecutor::new(&[(ALICE, 1_000), (BOB, 50)], ExecutionMode::Serial);
    let parallel = VmExecutor::new(&[(ALICE, 1_000), (BOB, 50)], ExecutionMode::Parallel);
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
#[test]
fn a_completed_transfer_burns_the_fee_ceiling_from_its_payer() {
    let key = Ed25519PrivateKey::from_bytes(&[7u8; 32]).unwrap();
    let payer = vm_account_address(&key.public_key().0);
    let accounts = [(payer, 1_000), (BOB, 50)];
    let executor = VmExecutor::new(&accounts, ExecutionMode::Serial);
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
    let key = Ed25519PrivateKey::from_bytes(&[11u8; 32]).unwrap();
    let payer = vm_account_address(&key.public_key().0);
    // Exactly the transfer plus the ceiling: nothing survives the burn.
    let accounts = [(payer, 110), (BOB, 50)];
    let executor = VmExecutor::new(&accounts, ExecutionMode::Serial);
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
