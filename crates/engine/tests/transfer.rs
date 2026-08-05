//! The VM engine end to end at the seam: signed transfer graphs through
//! derivation, the batch executor, and the movement fold, against a
//! genesis-seeded snapshot.

use std::collections::{BTreeMap, HashSet};
use std::sync::Arc;

use hyperscale_effects_bridge::vm_statics::package_key;
use hyperscale_effects_bridge::{
    ProtocolHasher, account_address, admit_package, attach_metadata, encode_tree,
};
use hyperscale_engine::genesis::{account_artifact, entropy_key, vault_key};
use hyperscale_engine::{
    DynSnapshot, ExecutedTx, ExecutionMode, Executor, Parallelism, PreviewGrants, PreviewInputs,
    PreviewOutcome, PreviewReport, ProcessExecutionCache, ResourceChange, WaveBatchContext, XRD,
    genesis_updates,
};
use hyperscale_storage::{
    DatabaseUpdate, DatabaseUpdates, DbPartitionKey, DbSortKey, DbSubstateValue,
    PartitionDatabaseUpdates, PartitionEntry, SubstateDatabase,
};
use hyperscale_types::state_key::{VM_PARTITION, vm_db_node_key};
use hyperscale_types::{
    BlockHash, ConsensusReceipt, Ed25519PrivateKey, Hash, RevealChain, ShardId, ShardTrie,
    Transaction, TransactionBody, TransactionEnvelope, Verified, WeightedTimestamp,
    absorb_committed_cells,
};
use hyperscale_vm_effects::{
    AbiParam, Address, Constraint, EdgeRef, EnvelopeTree, Expr, GraphArg, GraphNode, IntentDecl,
    ManifestGraph, Value, package_hash,
};
use hyperscale_vm_kernel::encode_amount;
use hyperscale_vm_stdlib::{ACCOUNT_COMPONENT, account_metadata};

/// The two accounts the transfer cases move funds between, as signing
/// seeds rather than as literal addresses: a withdrawing node admits only
/// the signature its target's address derives from, so an account that
/// spends has to be one a key here derives.
const ALICE_SEED: u8 = 41;
const BOB_SEED: u8 = 42;

/// The ceiling the plain transfer cases name, and — being under what a
/// transfer costs — the fee they are charged exactly.
///
/// Small enough to stay legible in the balance assertions, which matters
/// now that a withdrawal's own account is also the one paying: the payer
/// is the signer, and the signer is whoever the withdrawing node names.
const TRANSFER_FEE: u128 = 100;

fn alice() -> [u8; 16] {
    fee_payer(ALICE_SEED)
}

fn bob() -> [u8; 16] {
    fee_payer(BOB_SEED)
}

/// A snapshot over the flattened genesis updates.
struct MapDb(BTreeMap<(Vec<u8>, u8, Vec<u8>), Vec<u8>>);

impl MapDb {
    fn genesis(accounts: &[([u8; 16], u128)]) -> Self {
        let updates = genesis_updates(accounts, &[]);
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

impl MapDb {
    /// Apply a receipt's committed updates, as the commit path would.
    fn apply(&mut self, updates: &DatabaseUpdates) {
        for (node_key, node_updates) in &updates.node_updates {
            let PartitionDatabaseUpdates::Delta { substate_updates } = node_updates
                .partition_updates
                .get(&VM_PARTITION)
                .expect("VM updates land in the VM partition")
            else {
                panic!("VM updates are Delta-only");
            };
            for (sort_key, update) in substate_updates {
                let key = (node_key.clone(), VM_PARTITION, sort_key.0.clone());
                match update {
                    DatabaseUpdate::Set(value) => {
                        self.0.insert(key, value.clone());
                    }
                    DatabaseUpdate::Delete => {
                        self.0.remove(&key);
                    }
                }
            }
        }
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
                    GraphArg::Literal(Value::Address(XRD)),
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
                    constraints: vec![Constraint::ResourceIs(XRD)],
                }],
            },
        ],
    }
}

fn signed_transfer(seed: u8, from: [u8; 16], to: [u8; 16], amount: u128) -> Transaction {
    signed_transfer_with_fee(seed, from, to, amount, TRANSFER_FEE)
}

/// A transfer whose recipient signs a floor the withdrawal cannot meet.
fn signed_transfer_under_bound(
    seed: u8,
    from: [u8; 16],
    to: [u8; 16],
    amount: u128,
    min: u128,
    max_fee: u128,
) -> Transaction {
    let key = Ed25519PrivateKey::from_bytes(&[seed; 32]).unwrap();
    let mut graph = transfer_graph(from, to, amount);
    let GraphArg::Edge { constraints, .. } = &mut graph.nodes[1].args[0] else {
        panic!("the deposit consumes an edge");
    };
    constraints.push(Constraint::MinAmount(min));
    let tree = EnvelopeTree {
        root: IntentDecl {
            graph,
            params: Vec::new(),
        },
        root_bindings: Vec::new(),
        subintents: Vec::new(),
    };
    let vm = TransactionEnvelope {
        body: TransactionBody::Call(encode_tree(&tree).into()),
        subintent_sigs: Vec::new(),
        fee_payer: account_address(&key.public_key().0),
        max_fee,
        gas_limit: 1_000_000,
        validity_start_ms: 0,
        validity_end_ms: u64::MAX,
        message: Vec::new().into(),
        signer: [0; 32],
        signature: [0; 64],
    }
    .sign(&key);
    Transaction::new(vm)
}

fn signed_transfer_with_fee(
    seed: u8,
    from: [u8; 16],
    to: [u8; 16],
    amount: u128,
    max_fee: u128,
) -> Transaction {
    let key = Ed25519PrivateKey::from_bytes(&[seed; 32]).unwrap();
    let tree = EnvelopeTree {
        root: IntentDecl {
            graph: transfer_graph(from, to, amount),
            params: Vec::new(),
        },
        root_bindings: Vec::new(),
        subintents: Vec::new(),
    };
    let vm = TransactionEnvelope {
        body: TransactionBody::Call(encode_tree(&tree).into()),
        subintent_sigs: Vec::new(),
        fee_payer: account_address(&key.public_key().0),
        max_fee,
        gas_limit: 1_000_000,
        validity_start_ms: 0,
        validity_end_ms: u64::MAX,
        message: Vec::new().into(),
        signer: [0; 32],
        signature: [0; 64],
    }
    .sign(&key);
    Transaction::new(vm)
}

/// The account address the fee-paying tests derive from their signing key.
fn fee_payer(seed: u8) -> [u8; 16] {
    let key = Ed25519PrivateKey::from_bytes(&[seed; 32]).unwrap();
    account_address(&key.public_key().0)
}

/// Every account any test in this binary transacts with.
///
/// The VM statics are process-global and first-installed-wins, so every
/// executor here has to be built over one world: sharing a process, the
/// first `Executor::new` fixes the instance registry for every test that
/// follows, and an address missing from it fails admission with `no
/// instance` rather than anything to do with the test's own subject. Per-test
/// balances are unaffected — those come from the snapshot `execute_on`
/// builds, which is separate from the world.
fn world_accounts() -> Vec<([u8; 16], u128)> {
    vec![
        (alice(), 1_000),
        (bob(), 50),
        (fee_payer(7), 1_000),
        (fee_payer(11), 110),
        (fee_payer(23), 1_000),
        (fee_payer(31), 1_000),
        (fee_payer(32), 1_000),
    ]
}

fn execute(executor: &Executor, transactions: &[Arc<Verified<Transaction>>]) -> Vec<ExecutedTx> {
    execute_on(&[(alice(), 1_000), (bob(), 50)], executor, transactions)
}

/// A signed single-node stamp: the account records the transaction's
/// randomness draw in its entropy leaf.
fn signed_stamp(seed: u8, owner: [u8; 16]) -> Transaction {
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
    let vm = TransactionEnvelope {
        body: TransactionBody::Call(encode_tree(&tree).into()),
        subintent_sigs: Vec::new(),
        fee_payer: account_address(&key.public_key().0),
        max_fee: 1_000_000,
        gas_limit: 1_000_000,
        validity_start_ms: 0,
        validity_end_ms: u64::MAX,
        message: Vec::new().into(),
        signer: [0; 32],
        signature: [0; 64],
    }
    .sign(&key);
    Transaction::new(vm)
}

/// Execute `transactions` as a single-shard batch anchored on `reveal`.
fn execute_anchored(
    executor: &Executor,
    reveal: RevealChain,
    transactions: &[Arc<Verified<Transaction>>],
) -> Vec<ExecutedTx> {
    let snapshot_store = MapDb::genesis(&[(alice(), 1_000), (bob(), 50)]);
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
    let executor = Executor::new(&world_accounts(), ExecutionMode::Serial);
    let tx = Arc::new(Verified::<Transaction>::from_persisted(signed_stamp(
        ALICE_SEED,
        alice(),
    )));
    let anchor = RevealChain::from_raw(Hash::from_bytes(b"payer block"));

    let executed = execute_anchored(&executor, anchor, std::slice::from_ref(&tx));
    let stamped = entropy_cell(&executed[0], alice()).expect("the stamp wrote the entropy leaf");
    assert_eq!(stamped.len(), 32);

    let again = execute_anchored(&executor, anchor, std::slice::from_ref(&tx));
    assert_eq!(
        entropy_cell(&again[0], alice()),
        Some(stamped.clone()),
        "one anchor, one draw"
    );

    let elsewhere = execute_anchored(
        &executor,
        RevealChain::from_raw(Hash::from_bytes(b"another block")),
        std::slice::from_ref(&tx),
    );
    assert_ne!(
        entropy_cell(&elsewhere[0], alice()),
        Some(stamped),
        "a different anchor is a different draw"
    );
}

/// Two independent payments into one account, each in its own batch.
///
/// The recipient's vault is a `delta` on both sides, which the mode
/// lattice calls compatible — so nothing defers the second behind the
/// first, and the two may legitimately be included in different blocks.
/// What each receipt then carries is an *absolute* value for the cell,
/// derived from whatever baseline its batch read.
///
/// Threaded, that is right: the second batch reads the first's applied
/// credit and writes the sum. Against a shared baseline it is not: both
/// batches read the same starting balance, both write the same absolute,
/// and whichever settles last silently discards the other's credit.
///
/// The second half characterises a live defect rather than blessing it —
/// a payment included while an earlier one is committed but not yet
/// settled reads exactly that shared baseline.
#[test]
fn a_batch_baseline_decides_whether_two_payments_both_land() {
    let payer_a = fee_payer(31);
    let payer_b = fee_payer(32);
    let hot = bob();
    let accounts = [(payer_a, 1_000), (payer_b, 1_000), (hot, 10)];
    let executor = Executor::new(&world_accounts(), ExecutionMode::Serial);

    let pay = |seed: u8, from: [u8; 16]| {
        Arc::new(Verified::<Transaction>::from_persisted(
            signed_transfer_with_fee(seed, from, hot, 100, 10),
        ))
    };

    // Threaded: each batch reads what the previous one committed.
    let mut store = MapDb::genesis(&accounts);
    let mut threaded = Vec::new();
    for (seed, from) in [(31u8, payer_a), (32, payer_b)] {
        let executed = execute_batch_on(&store, &executor, &[pay(seed, from)]);
        let updates = executed[0]
            .consensus
            .database_updates()
            .expect("a completed payment commits updates");
        threaded.push(vault_cell(updates, hot));
        store.apply(updates);
    }
    assert_eq!(
        threaded,
        vec![
            Some(encode_amount(110).to_vec()),
            Some(encode_amount(210).to_vec())
        ],
        "each payment must land on top of the last"
    );

    // Unthreaded: both batches read the genesis baseline, as two blocks
    // committed inside one unsettled window would.
    let genesis = MapDb::genesis(&accounts);
    let shared: Vec<Option<Vec<u8>>> = [(31u8, payer_a), (32, payer_b)]
        .into_iter()
        .map(|(seed, from)| {
            let executed = execute_batch_on(&genesis, &executor, &[pay(seed, from)]);
            vault_cell(
                executed[0]
                    .consensus
                    .database_updates()
                    .expect("a completed payment commits updates"),
                hot,
            )
        })
        .collect();
    assert_eq!(
        shared,
        vec![
            Some(encode_amount(110).to_vec()),
            Some(encode_amount(110).to_vec())
        ],
        "two batches on one baseline each write the same absolute — applying \
         both leaves one credit, not two"
    );
}

fn execute_on(
    accounts: &[([u8; 16], u128)],
    executor: &Executor,
    transactions: &[Arc<Verified<Transaction>>],
) -> Vec<ExecutedTx> {
    execute_batch_on(&MapDb::genesis(accounts), executor, transactions)
}

/// Execute one batch against an explicit store, so a caller can thread
/// committed state between batches the way the commit path does.
fn execute_batch_on(
    snapshot_store: &MapDb,
    executor: &Executor,
    transactions: &[Arc<Verified<Transaction>>],
) -> Vec<ExecutedTx> {
    let snapshot = DynSnapshot(snapshot_store);
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
    let key = vault_key(owner, XRD);
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
    let executor = Executor::new(&world_accounts(), ExecutionMode::Serial);
    let tx = Arc::new(Verified::<Transaction>::from_persisted(signed_transfer(
        ALICE_SEED,
        alice(),
        bob(),
        100,
    )));
    let executed = execute(&executor, &[tx]);
    assert_eq!(executed.len(), 1);
    let ConsensusReceipt::Succeeded {
        database_updates,
        receipt_hash,
        ..
    } = &executed[0].consensus
    else {
        panic!("transfer must succeed: {:?}", executed[0].consensus);
    };
    assert_ne!(receipt_hash.as_raw(), &Hash::ZERO);
    // Withdraw settled 100 off the sender and the fee another 100 —
    // the sender signs, so the sender pays. Deposit credited the
    // recipient. Absolute values, identity-keyed.
    assert_eq!(
        vault_cell(database_updates, alice()),
        Some(encode_amount(1_000 - 100 - TRANSFER_FEE).to_vec())
    );
    assert_eq!(
        vault_cell(database_updates, bob()),
        Some(encode_amount(150).to_vec())
    );
}

#[test]
fn an_uncovered_withdrawal_aborts_and_the_batch_carries_on() {
    let executor = Executor::new(&world_accounts(), ExecutionMode::Serial);
    let over = Arc::new(Verified::<Transaction>::from_persisted(signed_transfer(
        BOB_SEED,
        bob(),
        alice(),
        500,
    )));
    let fine = Arc::new(Verified::<Transaction>::from_persisted(signed_transfer(
        ALICE_SEED,
        alice(),
        bob(),
        25,
    )));
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
        vault_cell(database_updates, alice()),
        Some(encode_amount(1_000 - 25 - TRANSFER_FEE).to_vec())
    );
    assert_eq!(
        vault_cell(database_updates, bob()),
        Some(encode_amount(75).to_vec())
    );
}

#[test]
fn serial_and_parallel_scheduling_produce_identical_receipts() {
    let serial = Executor::new(&world_accounts(), ExecutionMode::Serial);
    let parallel = Executor::new(&world_accounts(), ExecutionMode::Parallel);
    let txs: Vec<Arc<Verified<Transaction>>> = (0..4u128)
        .map(|i| {
            Arc::new(Verified::<Transaction>::from_persisted(signed_transfer(
                ALICE_SEED,
                alice(),
                bob(),
                10 + i,
            )))
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
    let executor = Executor::new(&world_accounts(), ExecutionMode::Serial);
    let over = Arc::new(Verified::<Transaction>::from_persisted(signed_transfer(
        ALICE_SEED,
        alice(),
        bob(),
        1_000_000,
    )));
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
    let fine = Arc::new(Verified::<Transaction>::from_persisted(signed_transfer(
        ALICE_SEED,
        alice(),
        bob(),
        100,
    )));
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
    let accounts = [(payer, 1_000), (bob(), 50)];
    let executor = Executor::new(&world_accounts(), ExecutionMode::Serial);
    // A transfer's fuel far exceeds the tiny ceiling, so the burn is
    // exactly `max_fee` — the cap working.
    let tx = Arc::new(Verified::<Transaction>::from_persisted(
        signed_transfer_with_fee(7, payer, bob(), 100, 10),
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
        vault_cell(database_updates, bob()),
        Some(encode_amount(150).to_vec())
    );
}

/// A missed edge bound is an infeasibility, not a defect: the sender
/// declared what it would accept and the world moved between signing and
/// execution, so nothing but the class floor leaves its vault.
#[test]
fn a_missed_edge_bound_charges_its_payer_the_floor() {
    let payer = fee_payer(23);
    let funded = 1_000;
    let accounts = [(payer, funded), (bob(), 50)];
    let executor = Executor::new(&world_accounts(), ExecutionMode::Serial);
    // The withdrawal is covered and the guest is honest — it returns the
    // 100 it reserved. What fails is the recipient's signed floor.
    let tx = signed_transfer_under_bound(23, payer, bob(), 100, 150, 1_000);
    let floor = tx.body().abort_floor();
    let executed = execute_on(
        &accounts,
        &executor,
        &[Arc::new(Verified::<Transaction>::from_persisted(tx))],
    );
    assert_eq!(executed.len(), 1);
    assert!(
        matches!(executed[0].consensus, ConsensusReceipt::Failed),
        "a missed bound must not apply: {:?}",
        executed[0].consensus
    );

    // The charge stands in for the receipt the execution never produced,
    // which is what keeps state moving through receipts alone.
    let Some(ConsensusReceipt::Succeeded {
        database_updates, ..
    }) = executed[0].fee_receipt.as_ref()
    else {
        panic!("a charged abort settles a fee receipt");
    };
    assert_eq!(
        vault_cell(database_updates, payer),
        Some(encode_amount(funded - floor).to_vec()),
        "the floor and nothing else"
    );
    assert_eq!(
        vault_cell(database_updates, bob()),
        None,
        "the transfer's own effects are discarded"
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
    let accounts = [(payer, 110), (bob(), 50)];
    let executor = Executor::new(&world_accounts(), ExecutionMode::Serial);
    let tx = Arc::new(Verified::<Transaction>::from_persisted(
        signed_transfer_with_fee(11, payer, bob(), 100, 10),
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
        vault_cell(database_updates, bob()),
        Some(encode_amount(150).to_vec())
    );
}

/// An account whose prefix routes to the other half of a two-shard trie
/// from [`alice`], derived by flipping the bit that trie splits on so the
/// pair straddles it whatever address derivation produces.
fn far() -> [u8; 16] {
    let mut prefix = alice();
    prefix[0] ^= 0x80;
    prefix
}

/// Execute one batch as `local_shard` under a two-leaf trie.
fn execute_on_shard(
    executor: &Executor,
    local_shard: ShardId,
    transactions: &[Arc<Verified<Transaction>>],
) -> Vec<ExecutedTx> {
    let snapshot_store = MapDb::genesis(&[(alice(), 1_000), (far(), 50)]);
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
    let ConsensusReceipt::Succeeded { events, .. } = &executed.consensus else {
        panic!("transfer must succeed: {:?}", executed.consensus);
    };
    events
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
    let world = vec![(alice(), 1_000u128), (far(), 50), (fee_payer(7), 1_000)];
    let executor = Executor::new(&world, ExecutionMode::Serial);
    let trie = ShardTrie::uniform(1);
    let (near_shard, far_shard) = (trie.shard_for_prefix(alice()), trie.shard_for_prefix(far()));
    assert_ne!(
        near_shard, far_shard,
        "the two accounts must sit on different shards"
    );

    let tx = Arc::new(Verified::<Transaction>::from_persisted(signed_transfer(
        ALICE_SEED,
        alice(),
        far(),
        100,
    )));
    let sender_side = execute_on_shard(&executor, near_shard, std::slice::from_ref(&tx));
    let recipient_side = execute_on_shard(&executor, far_shard, &[tx]);

    assert_eq!(events_of(&sender_side[0]), vec![(alice(), 0)]);
    assert_eq!(events_of(&recipient_side[0]), vec![(far(), 1)]);
    assert_eq!(
        hash_of(&sender_side[0]),
        hash_of(&recipient_side[0]),
        "the receipt hash covers the union, so it cannot differ by shard",
    );
}

/// A signed publish of `artifact`, paid for by `seed`'s account.
fn signed_publish(seed: u8, artifact: Vec<u8>) -> Transaction {
    let key = Ed25519PrivateKey::from_bytes(&[seed; 32]).unwrap();
    let vm = TransactionEnvelope {
        body: TransactionBody::Publish(artifact.into()),
        subintent_sigs: Vec::new(),
        fee_payer: account_address(&key.public_key().0),
        max_fee: 1_000_000,
        gas_limit: 1_000_000,
        validity_start_ms: 0,
        validity_end_ms: u64::MAX,
        message: Vec::new().into(),
        signer: [0; 32],
        signature: [0; 64],
    }
    .sign(&key);
    Transaction::new(vm)
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
    let executor = Executor::new(&world_accounts(), ExecutionMode::Serial);
    let artifact = account_artifact().to_vec();
    let tx = Arc::new(Verified::<Transaction>::from_persisted(signed_publish(
        7,
        artifact.clone(),
    )));
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
    let executor = Executor::new(&world_accounts(), ExecutionMode::Serial);

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

    let tx = Arc::new(Verified::<Transaction>::from_persisted(signed_publish(
        7, artifact,
    )));
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
    absorb_committed_cells([&executed[0].consensus]);
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
    let executor = Executor::new(&world_accounts(), ExecutionMode::Serial);
    let cache = executor.packages();

    let mut metadata = account_metadata();
    metadata.events.push("smuggled".into());
    let artifact = attach_metadata(ACCOUNT_COMPONENT, &metadata).expect("attaches");
    let package = package_hash(&ProtocolHasher, &artifact);
    let publisher = fee_payer(11);

    // The right bytes at the wrong key: a vault slot, not the content
    // address. Refused.
    let vault = vault_key(publisher, XRD);
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
    executor: &Executor,
    tx: &Transaction,
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
    let key = vault_key(owner, XRD);
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
    tx: Transaction,
}

fn preview_fixture() -> PreviewFixture {
    let payer = fee_payer(7);
    PreviewFixture {
        payer,
        accounts: vec![(payer, 1_000), (bob(), 50)],
        tx: signed_transfer_with_fee(7, payer, bob(), 100, PREVIEW_CEILING),
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
    let executor = Executor::new(&world_accounts(), ExecutionMode::Serial);
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

    let recipient = change_for(&report, bob());
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
    let executor = Executor::new(&world_accounts(), ExecutionMode::Serial);
    let report = preview_on(&accounts, &executor, &tx, PreviewGrants::default());

    let verified = Arc::new(Verified::<Transaction>::from_persisted(tx));
    let executed = execute_on(&accounts, &executor, &[verified]);
    let ConsensusReceipt::Succeeded {
        database_updates, ..
    } = &executed[0].consensus
    else {
        panic!("the transfer must succeed: {:?}", executed[0].consensus);
    };

    for owner in [payer, bob()] {
        assert_eq!(
            vault_cell(database_updates, owner),
            Some(encode_amount(change_for(&report, owner).after).to_vec()),
            "the preview's figure for {owner:?} is what the wave commits"
        );
    }
}

/// Free credit: the fee is still priced and reported, but it never
/// reaches the payer's vault, so a wallet can price an envelope its payer
/// could not cover.
#[test]
fn free_credit_reports_the_fee_without_charging_it() {
    let PreviewFixture {
        payer,
        accounts,
        tx,
    } = preview_fixture();
    let executor = Executor::new(&world_accounts(), ExecutionMode::Serial);
    let charged = preview_on(&accounts, &executor, &tx, PreviewGrants::default());
    let credited = preview_on(
        &accounts,
        &executor,
        &tx,
        PreviewGrants {
            free_credit: true,
            ..PreviewGrants::default()
        },
    );

    assert_eq!(credited.fee, charged.fee, "the fee is priced either way");
    assert_eq!(
        change_for(&credited, payer).after,
        change_for(&charged, payer).after + charged.fee,
        "credit keeps exactly the fee off the payer's vault"
    );
    assert_eq!(
        change_for(&credited, bob()),
        change_for(&charged, bob()),
        "a grant to the payer moves nobody else"
    );
}

/// An uncovered withdrawal previews as the abort it would be, priced at
/// the class floor: the sender lost a deterministic race rather than
/// making a mistake, so nothing but the floor leaves its vault.
#[test]
fn a_preview_prices_an_abort_at_its_class_floor() {
    let payer = fee_payer(7);
    let accounts = [(payer, 1_000), (bob(), 50)];
    let executor = Executor::new(&world_accounts(), ExecutionMode::Serial);
    let tx = signed_transfer_with_fee(7, payer, bob(), 5_000, PREVIEW_CEILING);
    let report = preview_on(&accounts, &executor, &tx, PreviewGrants::default());

    let PreviewOutcome::Aborted { reason } = &report.outcome else {
        panic!("an uncovered withdrawal must abort: {:?}", report.outcome);
    };
    assert!(reason.contains("infeasible"), "reason = {reason}");
    assert_eq!(report.fee, PREVIEW_CEILING / 10, "the abort floor");
    assert_eq!(
        report.changes,
        vec![ResourceChange {
            key: vault_key(payer, XRD),
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
    let executor = Executor::new(&world_accounts(), ExecutionMode::Serial);
    let tx = signed_transfer_with_fee(7, stranger, bob(), 10, PREVIEW_CEILING);
    let report = preview_on(&[(bob(), 50)], &executor, &tx, PreviewGrants::default());

    assert!(
        matches!(report.outcome, PreviewOutcome::Refused { .. }),
        "outcome = {:?}",
        report.outcome
    );
    assert_eq!(report.fee, 0);
    assert!(report.changes.is_empty());
}

/// A preview holds a node to its target's authority like the chain does,
/// and the grant is what a wallet reaches for when it wants an answer
/// about an envelope its counterparties have not signed yet.
///
/// Without it, a wallet composing a two-party trade would be told
/// "refused" and have nothing to show the user. With it, the report is
/// what the composition would do once signed — which is exactly the
/// question being asked.
#[test]
fn a_preview_holds_a_node_to_its_targets_authority_unless_granted() {
    let payer = fee_payer(7);
    let accounts = [(payer, 1_000), (alice(), 1_000), (bob(), 50)];
    let executor = Executor::new(&world_accounts(), ExecutionMode::Serial);
    // Signed by 7, withdrawing from Alice: the shape the gate refuses.
    let tx = signed_transfer_with_fee(7, alice(), bob(), 100, PREVIEW_CEILING);

    let refused = preview_on(&accounts, &executor, &tx, PreviewGrants::default());
    assert!(
        matches!(refused.outcome, PreviewOutcome::Refused { .. }),
        "outcome = {:?}",
        refused.outcome
    );
    assert_eq!(refused.fee, 0);

    let granted = preview_on(
        &accounts,
        &executor,
        &tx,
        PreviewGrants {
            assume_target_auth: true,
            ..PreviewGrants::default()
        },
    );
    assert_eq!(granted.outcome, PreviewOutcome::Completed);
    assert_eq!(change_for(&granted, alice()).debit, 0);
    assert_eq!(change_for(&granted, alice()).settled, 100);
    assert_eq!(change_for(&granted, bob()).credit, 100);
}

/// A publish previews too, and its price needs no state: judging an
/// artifact costs one unit per byte, which is the whole answer.
#[test]
fn a_preview_prices_a_publish_by_its_artifact() {
    let payer = fee_payer(7);
    let artifact = account_artifact().to_vec();
    let executor = Executor::new(&world_accounts(), ExecutionMode::Serial);
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
    let executor = Executor::new(&world_accounts(), ExecutionMode::Serial);
    let tx = Arc::new(Verified::<Transaction>::from_persisted(signed_transfer(
        ALICE_SEED,
        alice(),
        bob(),
        100,
    )));
    let executed = execute(&executor, &[tx]);
    let bogus = package_hash(&ProtocolHasher, encode_amount(900).as_ref());
    absorb_committed_cells([&executed[0].consensus]);
    assert!(
        executor.packages().load().get(bogus).is_none(),
        "vault writes are not packages"
    );
}
