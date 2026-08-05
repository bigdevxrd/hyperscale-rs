//! Portable transaction builders.
//!
//! These construct a [`RoutableTransaction`] from explicit inputs and so are
//! harness-agnostic; account discovery and the submit routing live in the
//! adaptors. A scenario submits the result via [`Cluster::submit`].
//!
//! [`Cluster::submit`]: crate::Cluster::submit

use std::time::Duration;

use hyperscale_effects_bridge::{ProtocolHasher, attach_metadata, encode_tree};
use hyperscale_engine_vm::genesis::stake_unit;
use hyperscale_engine_vm::{VM_XRD, vm_account_address};
use hyperscale_types::{
    ConsensusPublicKey, ConsensusSignature, Ed25519PrivateKey, Epoch, MIN_STAKE_FLOOR,
    NetworkParams, NodeId, RoutableTransaction, ShardId, ShardTrie, StakePoolId, StakePoolSeat,
    TimestampRange, ValidatorId, VmBody, VmSubintentSig, VmTransaction, WeightedTimestamp,
    build_transfer_tx as build_transfer, ed25519_keypair_from_seed, uniform_shard_for_node,
};
use hyperscale_vm_effects::{
    Address, Constraint, EdgeRef, EnvelopeTree, GraphArg, GraphNode, IntentDecl, ManifestGraph,
    Subintent, Value, YieldBinding, YieldParam,
};
use hyperscale_vm_stdlib::{ACCOUNT_COMPONENT, account_metadata};
use radix_common::math::Decimal;
use radix_common::network::NetworkDefinition;
use radix_common::types::ComponentAddress;

/// A deterministic Ed25519 signer from a one-byte seed. A faucet transaction's
/// fee comes from the faucet, so any key notarizes it.
#[must_use]
pub fn signer_from_seed(seed: u8) -> Ed25519PrivateKey {
    ed25519_keypair_from_seed(&[seed; 32])
}

/// The preallocated account address for the [`signer_from_seed`] of `seed` —
/// the account that signer controls, so a genesis that funds this address can
/// be spent by that key.
#[must_use]
pub fn account_from_seed(seed: u8) -> ComponentAddress {
    ComponentAddress::preallocated_account_from_public_key(&signer_from_seed(seed).public_key())
}

/// The splitting shard of the grown surviving-sibling shape — `leaf(1, 0)`, the
/// heavier child the engine bootstrap concentrates substates into, which crosses
/// the voted-down threshold and terminates.
pub const STRADDLER_SPLITTER: ShardId = ShardId::leaf(1, 0);

/// The surviving sibling — `leaf(1, 1)`, the lighter child that stays under the
/// threshold. Straddler payers live here; their cross-shard waves name the
/// terminating splitter.
pub const STRADDLER_SURVIVOR: ShardId = ShardId::leaf(1, 1);

/// Bulk accounts funded into the splitter to reinforce the engine bootstrap's
/// natural low-prefix skew, so the splitter clears the voted-down threshold and
/// the survivor stays under it.
const STRADDLER_BULK: usize = 20;

/// Straddler pairs submitted across the splitter's grow — enough to span its
/// terminal cut: the earliest settle on it before it crosses, the latest name a
/// splitter that has already terminated.
pub const STRADDLER_COUNT: usize = 8;

/// The surviving shard of the depth-2 merge-straddler topology — `leaf(2, 0)`.
///
/// The heaviest engine-bootstrap quarter, bulk-funded over `merge_bytes` so its
/// sibling pair never merges. Straddler payers live here; their cross-shard
/// waves name the terminating merge-left child.
pub const MERGE_STRADDLER_SURVIVOR: ShardId = ShardId::leaf(2, 0);

/// The merge-left child — `leaf(2, 2)`.
///
/// Light enough to fall under `merge_bytes` and collapse into `leaf(1, 1)` with
/// its sibling. Straddler recipients live here, so the survivor's wave names the
/// shard that terminates at the merge.
pub const MERGE_STRADDLER_LEFT: ShardId = ShardId::leaf(2, 2);

/// The merge-right child — `leaf(2, 3)`, the lightest quarter, which merges with
/// [`MERGE_STRADDLER_LEFT`] into their parent `leaf(1, 1)`.
pub const MERGE_STRADDLER_RIGHT: ShardId = ShardId::leaf(2, 3);

/// Bulk accounts funded into the lighter surviving quarter `leaf(2, 1)`.
///
/// The engine bootstrap leaves `leaf(2, 1)` (~89k) below `merge_bytes`, so
/// without this it would emit an unpairable merge against its heavy sibling
/// `leaf(2, 0)` (~522k) and churn the schedule. Lifting it to ~403k keeps the
/// whole surviving pair above the threshold while the lighter merging pair stays
/// under it. The `u8`-seeded [`account_in_n`] tops out at 255 keys; this draws
/// from the wide `u64` seed space of [`bulk_fund_into`].
const MERGE_SURVIVOR_BULK: usize = 500;

/// Merge-straddler pairs submitted across the merge.
///
/// Each payer in the survivor `leaf(2, 0)`, each recipient in the merging
/// `leaf(2, 2)`. Submitted in two waves — the first settles before the
/// merge-left terminal, the second straddles it.
pub const MERGE_STRADDLER_COUNT: usize = 4;

/// Seed of the merge-straddler vote payer.
///
/// The simulation adaptor reaches the four-shard topology by growing the root
/// (the harness genesis is always single-shard) and then voting `split_bytes` up
/// so only the light pair merges. That vote is a fee-paying system action; this
/// account is funded at genesis so the adaptor's pre-grow vote can lock its fee.
/// On production the genesis seats four shards directly, so the account is just
/// an unused funded balance.
const MERGE_VOTE_PAYER_SEED: u8 = 200;

/// The merge-straddler vote payer's signing key — funded by
/// [`merge_straddler_setup`] for the simulation adaptor's pre-grow vote.
#[must_use]
pub fn merge_vote_payer() -> Ed25519PrivateKey {
    signer_from_seed(MERGE_VOTE_PAYER_SEED)
}

/// The merge-vote payer's account, for genesis funding by cluster
/// builders that re-vote the reshape threshold after growing.
#[must_use]
pub fn merge_vote_payer_account() -> ComponentAddress {
    account_from_seed(MERGE_VOTE_PAYER_SEED)
}

/// Seed of the witness scenarios' fee payer.
///
/// The beacon-witness scenarios (staking, validator registration, governance
/// votes) pay every system action from one genesis-funded account. Both adaptors
/// install [`witness_genesis_balances`] at genesis so the payer can lock fees on
/// either harness.
const WITNESS_PAYER_SEED: u8 = 42;

/// The witness scenarios' fee-paying signing key.
#[must_use]
pub fn witness_payer() -> Ed25519PrivateKey {
    signer_from_seed(WITNESS_PAYER_SEED)
}

/// Genesis funding for the witness scenarios.
///
/// Funds the witness payer's account well above the fee any single system action
/// locks. Both adaptors install these so the witness bodies run identically on
/// either harness.
#[must_use]
pub fn witness_genesis_balances() -> Vec<(ComponentAddress, Decimal)> {
    vec![(
        account_from_seed(WITNESS_PAYER_SEED),
        Decimal::from(100_000),
    )]
}

/// Genesis funding for the halted-shard recovery scenario.
///
/// Both children of the root are bulk-funded into the stable band — above
/// the derived merge floor, below the split threshold, summing over it —
/// so the root splits exactly once and the grown pair holds: neither
/// child re-splits or asserts a merge half while the halt and its
/// recovery play out (a pending reshape would exempt the halted shard
/// from detection).
#[must_use]
pub fn halt_recovery_genesis_balances() -> Vec<(ComponentAddress, Decimal)> {
    let mut balances = vec![(
        account_from_seed(MERGE_VOTE_PAYER_SEED),
        Decimal::from(100_000),
    )];
    bulk_fund_into(ShardId::leaf(1, 0), 2, STRADDLER_BULK, &mut balances);
    bulk_fund_into(ShardId::leaf(1, 1), 2, STRADDLER_BULK, &mut balances);
    balances
}

/// Probe pairs per submission batch of the halted-shard straddler scenario.
///
/// Two transfers sourced on the surviving sibling into the halting shard,
/// one sourced on the halting shard itself, so both wave directions cross
/// each phase of the freeze.
pub const HALT_STRADDLER_BATCH: usize = 3;

/// The genesis funding and probe transfers for the halted-shard straddler
/// scenario.
///
/// The stable-band bulk of [`halt_recovery_genesis_balances`] plus three
/// probe batches (submitted before the fault installs, at the freeze edge,
/// and against the frozen shard) and a post-recovery transfer per
/// direction. One definition the adaptors and the scenario body share, so
/// the funded accounts cannot drift from the transfers spent against them.
pub struct HaltStraddlerSetup {
    /// Genesis XRD ballast: the halt-recovery stable-band bulk plus one
    /// account per probe leg per child.
    pub balances: Vec<(ComponentAddress, Decimal)>,
    /// Genesis VM accounts: every probe leg's payer and recipient.
    pub vm_accounts: Vec<([u8; 16], u128)>,
    /// Probe transfers in submission order, [`HALT_STRADDLER_BATCH`] per
    /// batch: `(payer key, payer account, recipient account)`.
    pub straddlers: Vec<(Ed25519PrivateKey, [u8; 16], [u8; 16])>,
    /// Transfers submitted after the recovery record clears, one per
    /// direction — the recovered shard's cross-shard rail must serve both.
    pub post_recovery: Vec<(Ed25519PrivateKey, [u8; 16], [u8; 16])>,
}

/// Probe legs the halted-shard straddler scenario submits: three batches
/// plus a post-recovery transfer per direction.
const HALT_STRADDLER_LEGS: usize = HALT_STRADDLER_BATCH * 3 + 2;

/// Build the halted-shard straddler genesis funding and probe transfers.
///
/// The halting `leaf(1, 0)` and surviving `leaf(1, 1)` keep the
/// [`halt_recovery_genesis_balances`] stable-band bulk; the probe accounts
/// ride on top, small enough to leave both children inside the band.
#[must_use]
pub fn halt_straddler_setup() -> HaltStraddlerSetup {
    let halting = ShardId::leaf(1, 0);
    let surviving = ShardId::leaf(1, 1);

    let mut balances = halt_recovery_genesis_balances();
    // The vote payer's seed is excluded from the ballast draw — it already
    // carries the grow vote's nonce sequence.
    let mut ballast_taken = vec![MERGE_VOTE_PAYER_SEED];
    for shard in [halting, surviving] {
        ballast(
            shard,
            2,
            HALT_STRADDLER_LEGS,
            &mut ballast_taken,
            &mut balances,
        );
    }

    let mut vm_accounts = Vec::new();
    let mut taken = Vec::new();
    let mut leg = |from, to| vm_leg(from, to, 2, &mut taken, &mut vm_accounts);

    let mut straddlers = Vec::new();
    for _ in 0..3 {
        straddlers.push(leg(surviving, halting));
        straddlers.push(leg(surviving, halting));
        straddlers.push(leg(halting, surviving));
    }
    let post_recovery = vec![leg(surviving, halting), leg(halting, surviving)];
    HaltStraddlerSetup {
        balances,
        vm_accounts,
        straddlers,
        post_recovery,
    }
}

/// The genesis funding and straddler transfers for the merge-straddler scenario.
///
/// Mirrors [`SplitStraddlerSetup`] but for a four-shard topology: the surviving
/// quarter pair (`leaf(2, 0)`/`leaf(2, 1)`) is bulk-funded over `merge_bytes`,
/// the merging pair (`leaf(2, 2)`/`leaf(2, 3)`) is left under it, and the
/// straddlers run from the survivor into the merging left child. The funding is
/// installed at the single-shard genesis and partitions across the quarters as
/// the cluster grows.
pub struct MergeStraddlerSetup {
    /// Genesis XRD ballast: the survivor pair funded over `merge_bytes`, the
    /// merging pair left under it.
    pub balances: Vec<(ComponentAddress, Decimal)>,
    /// Genesis VM accounts: the straddler payers in the survivor, their
    /// recipients in the merging left child.
    pub vm_accounts: Vec<([u8; 16], u128)>,
    /// Straddler transfers: `(payer key, payer account in the survivor,
    /// recipient in the merging left child)`.
    pub straddlers: Vec<(Ed25519PrivateKey, [u8; 16], [u8; 16])>,
}

/// The genesis funding and straddler transfers for the split-straddler scenario.
///
/// One definition both adaptors and the scenario body derive from, so the funded
/// accounts can't drift from the transfers spent against them.
pub struct SplitStraddlerSetup {
    /// Genesis XRD ballast, skewed toward the splitter so only it crosses the
    /// voted-down threshold.
    pub balances: Vec<(ComponentAddress, Decimal)>,
    /// Genesis VM accounts: the straddler payers in the survivor, their
    /// recipients in the splitter.
    pub vm_accounts: Vec<([u8; 16], u128)>,
    /// Straddler transfers: `(payer key, payer account in survivor, recipient in
    /// splitter)`.
    pub straddlers: Vec<(Ed25519PrivateKey, [u8; 16], [u8; 16])>,
    /// The leg whose payer sits in the *terminating* splitter, so the
    /// reservation it engages is held by a shard that dies before the wave
    /// can resolve: `(payer key, payer in the splitter's left child,
    /// recipient in the survivor)`.
    pub terminating: (Ed25519PrivateKey, [u8; 16], [u8; 16]),
    /// A recipient in the terminating payer's successor child, so the
    /// post-terminal probe stays intra-shard.
    pub successor_recipient: [u8; 16],
    /// An unencumbered payer in the same shard as [`Self::terminating`]'s,
    /// funded normally. Submitted beside the encumbered probe at the same
    /// instant, it separates "this shard is refusing everything" from "this
    /// shard is refusing this payer".
    pub control: (Ed25519PrivateKey, [u8; 16]),
}

/// The successor child the terminating payer's cells land in when the
/// splitter splits.
pub const STRADDLER_SUCCESSOR: ShardId = ShardId::leaf(2, 0);

/// What the terminating payer holds at genesis.
///
/// Above one signed fee ceiling and below two, so a reservation surviving
/// its shard's terminal would leave the payer unable to cover a second
/// transaction — which is exactly the encumbrance the probe looks for.
pub const TERMINATING_PAYER_FUNDING: u128 = VM_MAX_FEE + VM_MAX_FEE / 2;

const _: () = assert!(
    TERMINATING_PAYER_FUNDING > VM_MAX_FEE && TERMINATING_PAYER_FUNDING < 2 * VM_MAX_FEE,
    "the terminating payer must cover exactly one fee ceiling: one transaction      admits, a second while the first is in flight cannot",
);

/// A deterministic seeded account routing to `shard` under the `num_shards`-wide
/// uniform trie, skipping seeds already `taken`.
fn account_in_n(
    shard: ShardId,
    num_shards: u64,
    taken: &mut Vec<u8>,
) -> (Ed25519PrivateKey, ComponentAddress) {
    for seed in 1u8..=u8::MAX {
        if taken.contains(&seed) {
            continue;
        }
        let key = ed25519_keypair_from_seed(&[seed; 32]);
        let address = ComponentAddress::preallocated_account_from_public_key(&key.public_key());
        let node = NodeId::from_radix(address.into_node_id());
        if uniform_shard_for_node(&node, num_shards) == shard {
            taken.push(seed);
            return (key, address);
        }
    }
    panic!("no account seed routes to {shard:?}");
}

/// Push `count` funded accounts routing to `shard` onto `balances`.
///
/// Ballast is funded for its committed bytes and nothing else: nothing spends
/// it, and the reshape thresholds a straddler scenario votes in are bracketed
/// against the totals it produces. It retires with the Radix genesis.
fn ballast(
    shard: ShardId,
    num_shards: u64,
    count: usize,
    taken: &mut Vec<u8>,
    balances: &mut Vec<(ComponentAddress, Decimal)>,
) {
    for _ in 0..count {
        let (_, account) = account_in_n(shard, num_shards, taken);
        balances.push((account, Decimal::from(10_000)));
    }
}

/// The first seeded account routing to `shard` under a `num_shards`-wide
/// uniform trie, with its signing key — for tests that pin a payer or payee
/// to a specific leaf.
#[must_use]
pub fn account_routing_to(
    shard: ShardId,
    num_shards: u64,
) -> (Ed25519PrivateKey, ComponentAddress) {
    account_in_n(shard, num_shards, &mut Vec::new())
}

/// The first `count` seeded accounts routing to `shard` under a
/// `num_shards`-wide uniform trie, with signing keys. `taken` threads seed
/// exclusions across calls, so successive account sets stay disjoint.
#[must_use]
pub fn accounts_routing_to(
    shard: ShardId,
    num_shards: u64,
    count: usize,
    taken: &mut Vec<u8>,
) -> Vec<(Ed25519PrivateKey, ComponentAddress)> {
    (0..count)
        .map(|_| account_in_n(shard, num_shards, taken))
        .collect()
}

/// Seed base for the contention scenarios' payers; each sender occupies
/// one seed so no two payments share a payer account.
const CONTENTION_SENDER_BASE: u8 = 120;

/// Seed base for the contention scenarios' payees, disjoint from every
/// sender seed.
const CONTENTION_RECIPIENT_BASE: u8 = 200;

/// Contention sender `index`: its signing key and account. Funded at
/// genesis via [`contention_genesis_balances`].
#[must_use]
pub fn contention_sender(index: u8) -> (Ed25519PrivateKey, ComponentAddress) {
    let seed = CONTENTION_SENDER_BASE + index;
    (signer_from_seed(seed), account_from_seed(seed))
}

/// Contention recipient `index`: a payee account. Never funded — deposits
/// instantiate it.
#[must_use]
pub fn contention_recipient(index: u8) -> ComponentAddress {
    account_from_seed(CONTENTION_RECIPIENT_BASE + index)
}

/// Genesis funding for the contention scenarios: `senders` payers, plus
/// `recipients` payees.
///
/// Shared payees must exist at genesis — a virtual account instantiated
/// by concurrent conflicting commits (the pipeline admits up to the
/// two-chain window of them before locks engage) is torn by their
/// interleaved creation write sets and faults on every later open.
#[must_use]
pub fn contention_genesis_balances(
    senders: u8,
    recipients: u8,
) -> Vec<(ComponentAddress, Decimal)> {
    (0..senders)
        .map(|index| (contention_sender(index).1, Decimal::from(10_000)))
        .chain((0..recipients).map(|index| (contention_recipient(index), Decimal::from(10))))
        .collect()
}

/// Genesis funding for the cross-shard contention scenarios: `senders`
/// payers routed to the left child shard of a two-shard trie.
///
/// The scenarios regenerate the same accounts with an identical `taken`
/// walk.
#[must_use]
pub fn cross_contention_genesis_balances(senders: usize) -> Vec<(ComponentAddress, Decimal)> {
    let mut taken = Vec::new();
    accounts_routing_to(ShardId::leaf(1, 0), 2, senders, &mut taken)
        .into_iter()
        .map(|(_, account)| (account, Decimal::from(10_000)))
        .collect()
}

/// Push `count` funded accounts routing to `shard` under a `num_shards`-wide
/// trie onto `balances`, drawing from the wide `u64` seed space so a single
/// shard's prefix can be funded far past the `u8`-seeded [`account_in_n`] ceiling
/// — needed to lift a light quarter above `merge_bytes` so it stays a live leaf.
fn bulk_fund_into(
    shard: ShardId,
    num_shards: u64,
    count: usize,
    balances: &mut Vec<(ComponentAddress, Decimal)>,
) {
    let mut found = 0;
    let mut seed: u64 = 1;
    while found < count {
        let mut bytes = [0u8; 32];
        bytes[..8].copy_from_slice(&seed.to_le_bytes());
        let key = ed25519_keypair_from_seed(&bytes);
        let address = ComponentAddress::preallocated_account_from_public_key(&key.public_key());
        let node = NodeId::from_radix(address.into_node_id());
        if uniform_shard_for_node(&node, num_shards) == shard {
            balances.push((address, Decimal::from(10_000)));
            found += 1;
        }
        seed += 1;
    }
}

/// Build the split-straddler genesis funding and straddler transfers.
///
/// The splitter (`leaf(1, 0)`) is funded over the voted-down threshold, the
/// survivor (`leaf(1, 1)`) under it, so only the splitter crosses and
/// terminates. The skew comes from the [`ballast`] — accounts funded for their
/// committed bytes and nothing else — while the straddlers themselves are VM
/// transfers from a survivor payer into a splitter recipient.
#[must_use]
pub fn split_straddler_setup() -> SplitStraddlerSetup {
    let mut taken = vec![MERGE_VOTE_PAYER_SEED];
    // The threshold vote is a fee-paying system action, so its payer's Radix
    // account is funded here rather than left to whichever seed the ballast
    // draw happened to reach.
    let mut balances = vec![(merge_vote_payer_account(), Decimal::from(100_000))];
    ballast(
        STRADDLER_SPLITTER,
        2,
        STRADDLER_BULK,
        &mut taken,
        &mut balances,
    );
    // One ballast pair per straddler, splitter and survivor alike: the
    // threshold the vote installs is bracketed against these byte totals.
    ballast(
        STRADDLER_SURVIVOR,
        2,
        STRADDLER_COUNT,
        &mut taken,
        &mut balances,
    );
    ballast(
        STRADDLER_SPLITTER,
        2,
        STRADDLER_COUNT,
        &mut taken,
        &mut balances,
    );

    let mut vm_accounts = Vec::new();
    let mut vm_taken = Vec::new();
    let straddlers = (0..STRADDLER_COUNT)
        .map(|_| {
            vm_leg(
                STRADDLER_SURVIVOR,
                STRADDLER_SPLITTER,
                2,
                &mut vm_taken,
                &mut vm_accounts,
            )
        })
        .collect();

    // The terminating payer is ground into the splitter's *left child*, so
    // the successor holding its cells after the split is known up front
    // rather than derived from a trie the scenario would have to rebuild.
    let (terminating_key, terminating_payer) =
        vm_account_routing_to_n(STRADDLER_SUCCESSOR, 4, &mut vm_taken);
    let (_, terminating_recipient) = vm_account_routing_to(STRADDLER_SURVIVOR, &mut vm_taken);
    let (_, successor_recipient) = vm_account_routing_to_n(STRADDLER_SUCCESSOR, 4, &mut vm_taken);
    let (control_key, control_payer) =
        vm_account_routing_to_n(STRADDLER_SUCCESSOR, 4, &mut vm_taken);
    vm_accounts.push((terminating_payer, TERMINATING_PAYER_FUNDING));
    vm_accounts.push((terminating_recipient, 10));
    vm_accounts.push((successor_recipient, 10));
    vm_accounts.push((control_payer, 10_000));

    SplitStraddlerSetup {
        balances,
        vm_accounts,
        straddlers,
        terminating: (terminating_key, terminating_payer, terminating_recipient),
        successor_recipient,
        control: (control_key, control_payer),
    }
}

/// Build the merge-straddler genesis funding and straddler transfers.
///
/// Across the four-shard topology the surviving quarters (`leaf(2, 0)`/`leaf(2,
/// 1)`) are bulk-funded over the derived `merge_bytes` so neither auto-merges,
/// while the lighter merging pair (`leaf(2, 2)`/`leaf(2, 3)`) stays under it and
/// collapses into `leaf(1, 1)`. Straddler payers sit in the survivor
/// `leaf(2, 0)` and recipients in the merging `leaf(2, 2)`, so each cross-shard
/// wave names the shard that terminates at the merge.
#[must_use]
pub fn merge_straddler_setup() -> MergeStraddlerSetup {
    let num_shards = 4;
    let mut taken = Vec::new();
    let mut balances = vec![(
        account_from_seed(MERGE_VOTE_PAYER_SEED),
        Decimal::from(100_000),
    )];

    // Lift the naturally light survivor quarter `leaf(2, 1)` above `merge_bytes`:
    // its heavy sibling `leaf(2, 0)` already clears it, but `leaf(2, 1)` would
    // otherwise emit an unpairable merge and churn the schedule.
    bulk_fund_into(
        ShardId::leaf(2, 1),
        num_shards,
        MERGE_SURVIVOR_BULK,
        &mut balances,
    );

    // One ballast pair per straddler, survivor and merging child alike: the
    // derived `merge_bytes` is bracketed against these byte totals.
    ballast(
        MERGE_STRADDLER_SURVIVOR,
        num_shards,
        MERGE_STRADDLER_COUNT,
        &mut taken,
        &mut balances,
    );
    ballast(
        MERGE_STRADDLER_LEFT,
        num_shards,
        MERGE_STRADDLER_COUNT,
        &mut taken,
        &mut balances,
    );

    let mut vm_accounts = Vec::new();
    let mut vm_taken = Vec::new();
    let straddlers = (0..MERGE_STRADDLER_COUNT)
        .map(|_| {
            vm_leg(
                MERGE_STRADDLER_SURVIVOR,
                MERGE_STRADDLER_LEFT,
                num_shards,
                &mut vm_taken,
                &mut vm_accounts,
            )
        })
        .collect();
    MergeStraddlerSetup {
        balances,
        vm_accounts,
        straddlers,
    }
}

/// Genesis XRD balances that seat a funded account in each child span of the
/// first root split: seed `31` lands in the left child, seed `30` in the right.
///
/// Both adaptors install these at genesis from this one definition so the
/// cross-shard scenarios spend `account_from_seed(31)` and `account_from_seed(30)`
/// across the two children identically on either harness — the funding can't
/// drift between sim and production.
#[must_use]
pub fn straddler_genesis_balances() -> Vec<(ComponentAddress, Decimal)> {
    vec![
        (account_from_seed(31), Decimal::from(10_000)),
        (account_from_seed(30), Decimal::from(10_000)),
    ]
}

/// The cross-shard accounts (`31` left, `30` right) plus two extra funded
/// accounts (`40`, `41`) for single-shard control transfers.
///
/// The inter-shard partition scenario needs control accounts *disjoint* from the
/// cross-shard pair: a self-transfer on `31` or `30` would collide with the
/// in-flight cross-shard wave's reserved writes and stall behind it, so the
/// controls run on `40` / `41` instead and settle purely intra-shard.
#[must_use]
pub fn intershard_partition_genesis_balances() -> Vec<(ComponentAddress, Decimal)> {
    vec![
        (account_from_seed(31), Decimal::from(10_000)),
        (account_from_seed(30), Decimal::from(10_000)),
        (account_from_seed(40), Decimal::from(10_000)),
        (account_from_seed(41), Decimal::from(10_000)),
    ]
}

/// A validity window bracketing `now`.
///
/// Opens 5 s before and closes 150 s after, well under Radix's ~5-minute
/// ceiling, so a transaction built with this window stays valid across a
/// reshape that shuffles placement meanwhile.
#[must_use]
pub fn validity_around(now: Duration) -> TimestampRange {
    TimestampRange::new(
        WeightedTimestamp::ZERO.plus(now.saturating_sub(Duration::from_secs(5))),
        WeightedTimestamp::ZERO.plus(now + VALIDITY_FORWARD),
    )
}

/// How far forward [`validity_around`] opens a window.
///
/// Wall-clock rather than epoch-shaped, and both a transaction's
/// inclusion deadline and — for a cross-shard VM payer — the point past
/// which it gives up waiting for engagement echoes.
const VALIDITY_FORWARD: Duration = Duration::from_secs(150);

/// The VM account owned by [`signer_from_seed`]'s key for `seed`.
#[must_use]
pub fn vm_account_from_seed(seed: u8) -> [u8; 16] {
    vm_account_address(&signer_from_seed(seed).public_key().0)
}

/// VM contention sender `index`: its signing key and account, on the same
/// seed lane as [`contention_sender`] — the VM address space is disjoint
/// from the Radix one, so the lanes never collide.
#[must_use]
pub fn vm_sender(index: u8) -> (Ed25519PrivateKey, [u8; 16]) {
    let seed = CONTENTION_SENDER_BASE + index;
    (signer_from_seed(seed), vm_account_from_seed(seed))
}

/// VM contention recipient `index`.
#[must_use]
pub fn vm_recipient(index: u8) -> [u8; 16] {
    vm_account_from_seed(CONTENTION_RECIPIENT_BASE + index)
}

/// Genesis VM accounts for the VM scenarios: `senders` funded payers plus
/// `recipients` payees.
///
/// Recipients must be genesis accounts too — an instance the registry
/// does not know cannot be a deposit target, so there is no
/// instantiate-on-deposit path to race (the account-creation flow is
/// later-phase scope).
#[must_use]
pub fn vm_genesis_accounts(senders: u8, recipients: u8) -> Vec<([u8; 16], u128)> {
    (0..senders)
        .map(|index| (vm_sender(index).1, 10_000u128))
        .chain((0..recipients).map(|index| (vm_recipient(index), 10)))
        .collect()
}

/// One payment to each of `recipients`, all from `from` in a single
/// transaction.
///
/// A withdrawal per recipient rather than one split between them: each
/// leg is an independent reservation on the payer's own vault, which is
/// what a fan-out actually contends on, and the payer's shard is the one
/// cell every leg shares.
///
/// # Panics
///
/// Panics on a recipient list long enough to overflow a node index,
/// which is orders past the manifest node cap admission enforces.
#[must_use]
pub fn build_vm_fan_out_tx(
    payer: &Ed25519PrivateKey,
    from: [u8; 16],
    recipients: &[[u8; 16]],
    amount: u128,
    validity: TimestampRange,
) -> RoutableTransaction {
    let mut nodes = Vec::with_capacity(recipients.len() * 2);
    for (index, to) in recipients.iter().enumerate() {
        let producer = u32::try_from(nodes.len()).expect("fan-out node count fits");
        nodes.push(GraphNode {
            target: Address(from),
            method: "withdraw".into(),
            args: vec![
                GraphArg::Literal(Value::Address(VM_XRD)),
                GraphArg::Literal(Value::U128(amount + index as u128)),
            ],
        });
        nodes.push(GraphNode {
            target: Address(*to),
            method: "deposit".into(),
            args: vec![GraphArg::Edge {
                edge: EdgeRef {
                    producer,
                    output: 0,
                },
                constraints: vec![Constraint::ResourceIs(VM_XRD)],
            }],
        });
    }
    RoutableTransaction::new_vm(vm_envelope(ManifestGraph { nodes }, payer, validity))
}

/// The accounts the participant sweep fans out across: one payer on the
/// first leaf and one payee on each leaf, under a `num_shards`-wide trie.
///
/// The sweep walks the same grind, so what it names is what genesis
/// funded.
#[must_use]
pub fn vm_participant_sweep_accounts(num_shards: u64) -> Vec<(Ed25519PrivateKey, [u8; 16])> {
    let depth = num_shards.trailing_zeros();
    let mut taken = Vec::new();
    let mut accounts = vm_accounts_routing_to(ShardId::leaf(depth, 0), num_shards, 1, &mut taken);
    for leaf in 0..num_shards {
        accounts.extend(vm_accounts_routing_to(
            ShardId::leaf(depth, leaf),
            num_shards,
            1,
            &mut taken,
        ));
    }
    accounts
}

/// Genesis funding for [`vm_participant_sweep_accounts`].
#[must_use]
pub fn vm_participant_sweep_genesis_accounts(num_shards: u64) -> Vec<([u8; 16], u128)> {
    vm_participant_sweep_accounts(num_shards)
        .into_iter()
        .map(|(_, account)| (account, 10_000u128))
        .collect()
}

/// The conflicting pair the livelock probe submits: one account on each
/// child of the root split.
///
/// Ground onto opposite children so the two transfers are genuinely
/// cross-shard and share their whole account set — each is the other's
/// mirror, which is the shape that would livelock if conflicting waves
/// could starve each other.
#[must_use]
pub fn vm_livelock_pair() -> Vec<(Ed25519PrivateKey, [u8; 16])> {
    let mut taken = Vec::new();
    vec![
        vm_account_routing_to(ShardId::leaf(1, 0), &mut taken),
        vm_account_routing_to(ShardId::leaf(1, 1), &mut taken),
    ]
}

/// Genesis funding for [`vm_livelock_pair`]: both sides pay and receive,
/// so both need a payer's balance.
#[must_use]
pub fn vm_livelock_genesis_accounts() -> Vec<([u8; 16], u128)> {
    vm_livelock_pair()
        .into_iter()
        .map(|(_, account)| (account, 10_000u128))
        .collect()
}

/// The transaction a scenario submits when it needs real traffic and does
/// not care what the traffic does.
///
/// A transfer between the first genesis-funded sender and recipient, so
/// any cluster funding [`vm_genesis_accounts`] can carry it. Scenarios
/// use it to keep a committee busy, to give a drop rule something to
/// drop, or to have one settlement to watch — none of which depends on
/// the payment itself.
#[must_use]
pub fn build_probe_transfer_tx(validity: TimestampRange) -> RoutableTransaction {
    let (payer, from) = vm_sender(0);
    build_vm_transfer_tx(&payer, from, vm_recipient(0), PROBE_PAYMENT, validity)
}

/// What [`build_probe_transfer_tx`] moves: enough to be a real credit,
/// far under the sender's genesis funding so a scenario can submit
/// several.
pub const PROBE_PAYMENT: u128 = 100;

/// `count` VM accounts routing to `shard` under a `num_shards`-wide trie,
/// each drawing a fresh seed.
#[must_use]
pub fn vm_accounts_routing_to(
    shard: ShardId,
    num_shards: u64,
    count: usize,
    taken: &mut Vec<u8>,
) -> Vec<(Ed25519PrivateKey, [u8; 16])> {
    (0..count)
        .map(|_| vm_account_routing_to_n(shard, num_shards, taken))
        .collect()
}

/// How many senders the cross-shard fraction sweep runs with. Named so
/// the world's registration and the scenario's own funding cannot drift.
pub const CROSS_FRACTION_SENDERS: usize = 16;

/// Genesis VM funding for the cross-shard fraction sweep: `senders`
/// payers on the left child, and a payee for each on whichever child the
/// sweep sends it to.
///
/// Every account a transfer names has to exist at genesis — an instance
/// the registry does not know cannot be a deposit target — so the walk
/// here is the sweep's own, in the same order.
#[must_use]
pub fn vm_cross_fraction_genesis_accounts(senders: usize) -> Vec<([u8; 16], u128)> {
    let (left, right) = (ShardId::leaf(1, 0), ShardId::leaf(1, 1));
    let mut taken = Vec::new();
    let mut accounts: Vec<([u8; 16], u128)> = vm_accounts_routing_to(left, 2, senders, &mut taken)
        .into_iter()
        .map(|(_, account)| (account, 10_000u128))
        .collect();
    // Both recipient walks in full, so any cross fraction the sweep is
    // run at finds its payees funded.
    for shard in [left, right] {
        accounts.extend(
            vm_accounts_routing_to(shard, 2, senders, &mut taken)
                .into_iter()
                .map(|(_, account)| (account, 10u128)),
        );
    }
    accounts
}

/// Grind a signing key whose VM account routes to `shard` under the
/// depth-1 partition. Seeds in `taken` are skipped, so successive calls
/// yield distinct accounts.
///
/// # Panics
///
/// Panics on a shard that is not a depth-1 leaf.
#[must_use]
pub fn vm_account_routing_to(shard: ShardId, taken: &mut Vec<u8>) -> (Ed25519PrivateKey, [u8; 16]) {
    assert!(
        shard == ShardId::leaf(1, 0) || shard == ShardId::leaf(1, 1),
        "depth-1 grinding only"
    );
    vm_account_routing_to_n(shard, 2, taken)
}

/// Grind a signing key whose VM account routes to `shard` under the
/// `num_shards`-wide uniform partition, skipping seeds already `taken`.
///
/// A VM account's 16-byte address *is* its placement — the trie walks the
/// prefix bits directly rather than hashing — so grinding is a scan for a
/// seed whose address lands in the wanted leaf.
///
/// # Panics
///
/// Panics if no seed in the `u8` space routes to `shard`.
#[must_use]
pub fn vm_account_routing_to_n(
    shard: ShardId,
    num_shards: u64,
    taken: &mut Vec<u8>,
) -> (Ed25519PrivateKey, [u8; 16]) {
    let trie = ShardTrie::uniform_from_count(num_shards);
    for seed in 1..=u8::MAX {
        if taken.contains(&seed) {
            continue;
        }
        let address = vm_account_from_seed(seed);
        if trie.shard_for_prefix(address) == shard {
            taken.push(seed);
            return (signer_from_seed(seed), address);
        }
    }
    panic!("no VM account seed routes to {shard:?}");
}

/// The shard owning `address` under the `num_shards`-wide uniform
/// partition. A VM account's address *is* its placement, so this is the
/// trie walk over the address bits and nothing else.
///
/// # Panics
///
/// Panics if `num_shards` is not a power of two.
#[must_use]
pub fn vm_account_shard(address: [u8; 16], num_shards: u64) -> ShardId {
    ShardTrie::uniform_from_count(num_shards).shard_for_prefix(address)
}

/// Grind a straddler leg: a payer in `from_shard` and a recipient in
/// `to_shard`, both funded — the payer to cover the payment and its fee
/// ceiling, the recipient with dust so the deposit has a live instance to
/// land in.
fn vm_leg(
    from_shard: ShardId,
    to_shard: ShardId,
    num_shards: u64,
    taken: &mut Vec<u8>,
    accounts: &mut Vec<([u8; 16], u128)>,
) -> (Ed25519PrivateKey, [u8; 16], [u8; 16]) {
    let (payer_key, payer) = vm_account_routing_to_n(from_shard, num_shards, taken);
    let (_, recipient) = vm_account_routing_to_n(to_shard, num_shards, taken);
    accounts.push((payer, 10_000));
    accounts.push((recipient, 10));
    (payer_key, payer, recipient)
}

/// The cross-shard VM cast: the payer's key and account on `leaf(1, 0)`
/// and the recipient's account on `leaf(1, 1)`.
#[must_use]
pub fn vm_cross_shard_cast() -> (Ed25519PrivateKey, [u8; 16], [u8; 16]) {
    let (payer, from, key, _) = vm_cross_shard_keys();
    (payer, from, vm_account_address(&key.public_key().0))
}

/// [`vm_cross_shard_cast`] with the recipient's key as well: what a
/// scenario needs when the far side has to authorise something of its
/// own rather than only be paid.
#[must_use]
pub fn vm_cross_shard_keys() -> (Ed25519PrivateKey, [u8; 16], Ed25519PrivateKey, [u8; 16]) {
    let mut taken = Vec::new();
    let (payer, from) = vm_account_routing_to(ShardId::leaf(1, 0), &mut taken);
    let (recipient, to) = vm_account_routing_to(ShardId::leaf(1, 1), &mut taken);
    (payer, from, recipient, to)
}

/// Genesis funding for the cross-shard VM cast: the payer funded, the
/// recipient registered with dust (deposit targets must exist at
/// genesis — no instantiate-on-deposit path exists).
#[must_use]
pub fn vm_cross_shard_genesis_accounts() -> Vec<([u8; 16], u128)> {
    let (_payer, from, to) = vm_cross_shard_cast();
    vec![(from, 10_000), (to, 10)]
}

/// The nullifier race's cast: two composers who each fund a request, and
/// the account that signed it.
///
/// Distinct seeds from every other VM scenario's, so the shared statics
/// registry admits them all without collision.
#[must_use]
pub fn vm_nullifier_race_cast() -> (Ed25519PrivateKey, Ed25519PrivateKey, Ed25519PrivateKey) {
    (
        signer_from_seed(191),
        signer_from_seed(192),
        signer_from_seed(193),
    )
}

/// Genesis funding for the nullifier race: both composers covered for
/// the payment and its fee ceiling, the requesting account holding dust.
#[must_use]
pub fn vm_nullifier_race_genesis_accounts() -> Vec<([u8; 16], u128)> {
    let (first, second, requester) = vm_nullifier_race_cast();
    vec![
        (vm_account_address(&first.public_key().0), 10_000),
        (vm_account_address(&second.public_key().0), 10_000),
        (vm_account_address(&requester.public_key().0), 10),
    ]
}

/// The cross-shard fault family's cast, over the depth-1 split.
///
/// One funded account in each child, so a transfer runs in either
/// direction over the pair, plus an intra-shard control pair per child.
/// The controls must be disjoint from the crossing pair: a transfer
/// between the crossing accounts would declare the same vault cells as
/// the in-flight cross-shard wave and queue behind it instead of proving
/// the shard still settles locally.
pub struct CrossShardFaultCast {
    /// The payer and account in `leaf(1, 0)`.
    pub left: (Ed25519PrivateKey, [u8; 16]),
    /// The payer and account in `leaf(1, 1)`.
    pub right: (Ed25519PrivateKey, [u8; 16]),
    /// One intra-shard control per child: `(payer key, payer, recipient)`,
    /// both accounts in the same child.
    pub controls: Vec<(Ed25519PrivateKey, [u8; 16], [u8; 16])>,
}

/// Build the cross-shard fault family's cast.
#[must_use]
pub fn cross_shard_fault_cast() -> CrossShardFaultCast {
    let mut taken = Vec::new();
    let left = vm_account_routing_to(ShardId::leaf(1, 0), &mut taken);
    let right = vm_account_routing_to(ShardId::leaf(1, 1), &mut taken);
    let controls = [ShardId::leaf(1, 0), ShardId::leaf(1, 1)]
        .into_iter()
        .map(|shard| {
            let (key, payer) = vm_account_routing_to(shard, &mut taken);
            let (_, recipient) = vm_account_routing_to(shard, &mut taken);
            (key, payer, recipient)
        })
        .collect();
    CrossShardFaultCast {
        left,
        right,
        controls,
    }
}

/// Genesis VM accounts for the cross-shard fault family.
///
/// Every account is funded: the crossing pair pays in both directions, so
/// each is a payer as well as a recipient, and a control recipient must
/// exist before a deposit can land in it.
#[must_use]
pub fn cross_shard_fault_genesis_accounts() -> Vec<([u8; 16], u128)> {
    let cast = cross_shard_fault_cast();
    let mut accounts = vec![(cast.left.1, 10_000), (cast.right.1, 10_000)];
    for (_, payer, recipient) in &cast.controls {
        accounts.push((*payer, 10_000));
        accounts.push((*recipient, 10));
    }
    accounts
}

/// Genesis funding for the insolvent-payer scenario: the same cast as
/// [`vm_cross_shard_genesis_accounts`], but the payer holds dust — below
/// any transfer's signed fee ceiling.
#[must_use]
pub fn vm_insolvent_genesis_accounts() -> Vec<([u8; 16], u128)> {
    let (_payer, from, to) = vm_cross_shard_cast();
    vec![(from, 10), (to, 10)]
}

/// Build a cross-shard entropy stamp: both accounts record the
/// transaction's randomness draw in their own entropy leaf, so the two
/// shards' stamps are equal exactly when they executed under one draw.
///
/// Each stamp is an exclusive write, so each shard owes the other the
/// prior value of the leaf it owns — the read-set-provisioned shape, in
/// both directions.
///
/// The two stamps sit in two intents because they write two accounts'
/// leaves: a stamp is gated on its target's own authority, so the
/// right-hand account signs its own. That is the composition it takes to
/// touch a second party at all, and it costs the scenario nothing —
/// admission still folds one manifest and one draw still covers both.
#[must_use]
pub fn build_vm_stamp_tx(
    payer: &Ed25519PrivateKey,
    left: [u8; 16],
    right_key: &Ed25519PrivateKey,
    validity: TimestampRange,
) -> RoutableTransaction {
    let stamp = |owner: [u8; 16]| IntentDecl {
        graph: ManifestGraph {
            nodes: vec![GraphNode {
                target: Address(owner),
                method: "stamp-entropy".into(),
                args: vec![],
            }],
        },
        params: Vec::new(),
    };
    let right = stamp(vm_account_address(&right_key.public_key().0));
    let tree = EnvelopeTree {
        root: stamp(left),
        root_bindings: Vec::new(),
        subintents: vec![Subintent {
            decl: right.clone(),
            signer: Address(vm_account_address(&right_key.public_key().0)),
            bindings: Vec::new(),
        }],
    };
    let signed = right_key.sign(right.hash(&ProtocolHasher).0.0);
    let vm = VmTransaction {
        body: VmBody::Call(encode_tree(&tree).into()),
        subintent_sigs: vec![VmSubintentSig {
            public_key: right_key.public_key().0,
            signature: signed.0,
        }],
        fee_payer: vm_account_address(&payer.public_key().0),
        max_fee: VM_MAX_FEE,
        gas_limit: 1_000_000,
        validity_start_ms: validity.start_timestamp_inclusive.as_millis(),
        validity_end_ms: validity.end_timestamp_exclusive.as_millis(),
        message: Vec::new().into(),
        signer: [0; 32],
        signature: [0; 64],
    }
    .sign(payer);
    RoutableTransaction::new_vm(vm)
}

/// Build a VM transfer: the account guest's withdraw+deposit graph over
/// [`VM_XRD`], wrapped in a single-intent envelope signed by `payer`.
///
/// The transaction hash covers the whole signed envelope — validity
/// window included — so distinct submissions differ in signed content;
/// byte-identical envelopes are one transaction, which is the hash-dedup
/// replay protection working as designed.
#[must_use]
pub fn build_vm_transfer_tx(
    payer: &Ed25519PrivateKey,
    from: [u8; 16],
    to: [u8; 16],
    amount: u128,
    validity: TimestampRange,
) -> RoutableTransaction {
    let graph = ManifestGraph {
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
    };
    RoutableTransaction::new_vm(vm_envelope(graph, payer, validity))
}

/// Every VM account address any scenario in this crate transacts with.
///
/// The VM statics are process-global and first-installed-wins, so a test
/// binary sharing one process must install a world covering every scenario
/// it will run — otherwise the first cluster built fixes the instance
/// registry and every later scenario's addresses fail admission with `no
/// instance`, which reads as a defect in whatever that scenario was
/// testing. Balances here are placeholders: `genesis_world` registers
/// addresses and ignores amounts, and each cluster still seeds its own
/// funding from its own fixture — which matters, because the insolvent
/// scenario deliberately funds an address the cross-shard one funds richly.
#[must_use]
pub fn vm_world_accounts() -> Vec<([u8; 16], u128)> {
    let mut all = vm_genesis_accounts(24, 6);
    all.extend(vm_storm_genesis_accounts());
    all.extend(vm_cross_shard_genesis_accounts());
    all.extend(vm_insolvent_genesis_accounts());
    all.extend(vm_nullifier_race_genesis_accounts());
    all.extend(split_straddler_setup().vm_accounts);
    all.extend(merge_straddler_setup().vm_accounts);
    all.extend(halt_straddler_setup().vm_accounts);
    all.extend(cross_shard_fault_genesis_accounts());
    all.extend(vm_staking_genesis_accounts());
    all.extend(vm_livelock_genesis_accounts());
    all.extend(vm_cross_fraction_genesis_accounts(CROSS_FRACTION_SENDERS));
    all.sort_unstable_by_key(|(address, _)| *address);
    all.dedup_by_key(|(address, _)| *address);
    all
}

/// Every stake pool any scenario in this crate seats.
///
/// The companion to [`vm_world_accounts`], for the same reason: a pool is
/// an instance the statics must resolve, so a shared-process binary whose
/// first cluster seats none would leave every later delegation failing
/// admission with `no instance`. Seating a pool writes no genesis state
/// and a pool nobody delegates to emits nothing, so recognising one
/// everywhere costs a registry entry.
#[must_use]
pub fn vm_world_pools() -> Vec<StakePoolSeat> {
    vm_staking_pools()
}

/// The publishers a deploy storm spams from: one per depth-1 shard, so
/// the storm lands on both committees at once.
#[must_use]
pub fn vm_storm_publishers() -> Vec<(Ed25519PrivateKey, [u8; 16])> {
    let mut taken = Vec::new();
    vec![
        vm_account_routing_to(ShardId::leaf(1, 0), &mut taken),
        vm_account_routing_to(ShardId::leaf(1, 1), &mut taken),
    ]
}

/// Genesis funding for the storm publishers.
///
/// Publishing is priced per artifact byte, so a publisher needs orders
/// more than a payment sender: the balances the transfer scenarios use
/// would not cover one deploy.
#[must_use]
pub fn vm_storm_genesis_accounts() -> Vec<([u8; 16], u128)> {
    vm_storm_publishers()
        .into_iter()
        .map(|(_, address)| (address, VM_STORM_FUNDING))
        .collect()
}

/// What a storm publisher is funded with, and the ceiling each publish
/// signs. Placeholder pricing, sized to cover the stdlib-shaped artifact
/// the storm deploys.
pub const VM_STORM_FUNDING: u128 = 100_000_000;
const VM_PUBLISH_MAX_FEE: u128 = 1_000_000;

/// The `nonce`-th distinct publishable artifact.
///
/// The stdlib guest carrying a metadata section that differs only in one
/// event name, so every variant is a different content address and
/// therefore a different package — which is what makes a storm a storm
/// rather than one publish repeated idempotently.
///
/// # Panics
///
/// Panics if the metadata does not attach, which would be a defect in
/// the codec rather than a runtime condition.
#[must_use]
pub fn vm_storm_artifact(nonce: u16) -> Vec<u8> {
    let mut metadata = account_metadata();
    metadata.events.push(format!("storm-{nonce}"));
    attach_metadata(ACCOUNT_COMPONENT, &metadata).expect("storm metadata attaches")
}

/// Build a signed publish of `artifact`, paid for by `payer` from their
/// own account — the publisher and the payer are the same signer.
#[must_use]
pub fn build_vm_publish_tx(
    payer: &Ed25519PrivateKey,
    artifact: Vec<u8>,
    validity: TimestampRange,
) -> RoutableTransaction {
    RoutableTransaction::new_vm(
        VmTransaction {
            body: VmBody::Publish(artifact.into()),
            subintent_sigs: Vec::new(),
            fee_payer: vm_account_address(&payer.public_key().0),
            max_fee: VM_PUBLISH_MAX_FEE,
            gas_limit: 1_000_000,
            validity_start_ms: validity.start_timestamp_inclusive.as_millis(),
            validity_end_ms: validity.end_timestamp_exclusive.as_millis(),
            message: Vec::new().into(),
            signer: [0; 32],
            signature: [0; 64],
        }
        .sign(payer),
    )
}

/// The stake pool the VM staking scenario delegates to.
///
/// An address no key derives, like the genesis publisher's: a pool is
/// seated by the network rather than created by a signer.
pub const VM_STAKE_POOL: [u8; 16] = [0x50; 16];

/// The identifier the beacon folds [`VM_STAKE_POOL`] under.
///
/// Distinct from the genesis pool every seated validator belongs to, so a
/// delegation through the VM is the only source of this pool's stake and
/// the assertion cannot be satisfied by anything else.
pub const VM_STAKE_POOL_ID: StakePoolId = StakePoolId::new(7777);

/// The delegator's signing key and account.
#[must_use]
pub fn vm_delegator() -> (Ed25519PrivateKey, [u8; 16]) {
    let key = signer_from_seed(180);
    let account = vm_account_address(&key.public_key().0);
    (key, account)
}

/// What the delegator holds at genesis.
///
/// The beacon's stake floor is denominated in whole tokens and the
/// witness scenarios move multiples of it, so the delegator has to hold
/// stake-scale funds rather than the token amounts the transfer
/// scenarios use. Sized above every delegation any scenario makes plus
/// their fees.
pub const VM_DELEGATOR_FUNDING: u128 = 40 * MIN_STAKE_FLOOR.attos();

/// Genesis VM accounts for the staking scenarios.
///
/// The delegator is funded well above its delegations and their fee
/// ceilings; the operator is funded for the fees its own actions cost —
/// an operator action moves no funds, but it still pays to be included.
#[must_use]
pub fn vm_staking_genesis_accounts() -> Vec<([u8; 16], u128)> {
    vec![
        (vm_delegator().1, VM_DELEGATOR_FUNDING),
        (vm_pool_operator().1, VM_MAX_FEE * 64),
    ]
}

/// A second seated pool, for the scenarios whose claim needs two pools
/// that disagree.
pub const VM_SECOND_POOL: [u8; 16] = [0x51; 16];

/// The identifier the beacon folds [`VM_SECOND_POOL`] under.
pub const VM_SECOND_POOL_ID: StakePoolId = StakePoolId::new(7778);

/// The contract for the pool every genesis validator belongs to.
///
/// Beacon genesis creates that pool and its members; seating an instance
/// for it is what gives it an operator, which is how a deployment retires
/// a founding validator. Nothing else about the pool changes — its stake
/// and its membership are still genesis's.
pub const VM_GENESIS_POOL: [u8; 16] = [0x52; 16];

/// The identifier beacon genesis creates the founding pool under.
pub const VM_GENESIS_POOL_ID: StakePoolId = StakePoolId::new(0);

/// The pools a staking cluster seats.
///
/// Both name the same operator, which is an entity running two pools
/// rather than a shortcut: what a pool's operator field admits is
/// exercised where it can be isolated, and here the interesting question
/// is what two *pools* may say about each other.
#[must_use]
pub fn vm_staking_pools() -> Vec<StakePoolSeat> {
    let operator = vm_pool_operator().1;
    vec![
        StakePoolSeat {
            address: VM_STAKE_POOL,
            id: VM_STAKE_POOL_ID,
            operator,
            founding: Vec::new(),
        },
        StakePoolSeat {
            address: VM_SECOND_POOL,
            id: VM_SECOND_POOL_ID,
            operator,
            founding: Vec::new(),
        },
        // The founding pool's members are the beacon's to name, and
        // genesis fills them in from its own folded state.
        StakePoolSeat {
            address: VM_GENESIS_POOL,
            id: VM_GENESIS_POOL_ID,
            operator,
            founding: Vec::new(),
        },
    ]
}

/// Retire `validator`, which `pool` must operate.
#[must_use]
pub fn build_vm_deactivate_tx(
    operator: &Ed25519PrivateKey,
    pool: [u8; 16],
    validator: ValidatorId,
    validity: TimestampRange,
) -> RoutableTransaction {
    build_vm_operator_tx(
        operator,
        pool,
        "deactivate-validator",
        vec![GraphArg::Literal(Value::U64(validator.inner()))],
        validity,
    )
}

/// Register `validator` against `pool`, carrying the consensus key it
/// will be known by and the proof it holds that key.
///
/// Signed by the pool's operator, which is the whole of the action's
/// authority: the manifest names a method only that principal may call,
/// and admission refuses the envelope otherwise.
#[must_use]
pub fn build_vm_register_tx(
    operator: &Ed25519PrivateKey,
    pool: [u8; 16],
    validator: ValidatorId,
    pubkey: &ConsensusPublicKey,
    possession_proof: &ConsensusSignature,
    validity: TimestampRange,
) -> RoutableTransaction {
    build_vm_operator_tx(
        operator,
        pool,
        "register-validator",
        vec![
            GraphArg::Literal(Value::U64(validator.inner())),
            GraphArg::Literal(Value::Bytes(pubkey.as_bytes().to_vec())),
            GraphArg::Literal(Value::Bytes(possession_proof.as_bytes().to_vec())),
        ],
        validity,
    )
}

/// One operator action on `pool`: a single node, no funds, and the
/// operator's own signature as its authority.
#[must_use]
pub fn build_vm_operator_tx(
    operator: &Ed25519PrivateKey,
    pool: [u8; 16],
    method: &str,
    args: Vec<GraphArg>,
    validity: TimestampRange,
) -> RoutableTransaction {
    let graph = ManifestGraph {
        nodes: vec![GraphNode {
            target: Address(pool),
            method: method.into(),
            args,
        }],
    };
    RoutableTransaction::new_vm(vm_envelope(graph, operator, validity))
}

/// Return `amount` worth of stake units to `pool`, moving that much of
/// the delegator's position into the pool's unbonding total.
///
/// The units are withdrawn from the delegator's own account like any
/// other balance — a staking position is an ordinary fungible holding,
/// so unwinding one is an ordinary withdrawal.
#[must_use]
pub fn build_vm_unstake_tx(
    delegator: &Ed25519PrivateKey,
    from: [u8; 16],
    pool: [u8; 16],
    amount: u128,
    validity: TimestampRange,
) -> RoutableTransaction {
    let graph = ManifestGraph {
        nodes: vec![
            GraphNode {
                target: Address(from),
                method: "withdraw".into(),
                args: vec![
                    GraphArg::Literal(Value::Address(stake_unit(pool))),
                    GraphArg::Literal(Value::U128(amount)),
                ],
            },
            GraphNode {
                target: Address(pool),
                method: "unstake".into(),
                args: vec![GraphArg::Edge {
                    edge: EdgeRef {
                        producer: 0,
                        output: 0,
                    },
                    constraints: vec![Constraint::ResourceIs(stake_unit(pool))],
                }],
            },
        ],
    };
    RoutableTransaction::new_vm(vm_envelope(graph, delegator, validity))
}

/// The principal the staking scenario's pool admits on its operator
/// surface, and the key that satisfies it.
#[must_use]
pub fn vm_pool_operator() -> (Ed25519PrivateKey, [u8; 16]) {
    let key = signer_from_seed(181);
    let account = vm_account_address(&key.public_key().0);
    (key, account)
}

/// Build a delegation: withdraw `amount` from the delegator's native
/// vault, stake it into the pool, and bank the units the pool issues.
///
/// The units are an ordinary fungible balance in the delegator's own
/// account, which is what makes a staking position something a holder can
/// hold rather than a record only the pool can read.
#[must_use]
pub fn build_vm_stake_tx(
    delegator: &Ed25519PrivateKey,
    from: [u8; 16],
    pool: [u8; 16],
    amount: u128,
    validity: TimestampRange,
) -> RoutableTransaction {
    let graph = ManifestGraph {
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
                target: Address(pool),
                method: "stake".into(),
                args: vec![GraphArg::Edge {
                    edge: EdgeRef {
                        producer: 0,
                        output: 0,
                    },
                    constraints: vec![Constraint::ResourceIs(VM_XRD)],
                }],
            },
            GraphNode {
                target: Address(from),
                method: "deposit".into(),
                args: vec![GraphArg::Edge {
                    edge: EdgeRef {
                        producer: 1,
                        output: 0,
                    },
                    constraints: vec![Constraint::ResourceIs(stake_unit(pool))],
                }],
            },
        ],
    };
    RoutableTransaction::new_vm(vm_envelope(graph, delegator, validity))
}

/// The one-time payment request `signer` puts their name to: whoever
/// hands them at least `amount` XRD, they will bank it.
///
/// A declaration and nothing else — no envelope, no fee terms, no
/// composer. Its hash is a function of this content alone, which is what
/// lets the signer sign it before any composer exists and lets two
/// composers bind the identical declaration afterwards.
#[must_use]
pub fn vm_payment_request(signer: [u8; 16], amount: u128) -> IntentDecl {
    IntentDecl {
        graph: ManifestGraph {
            nodes: vec![GraphNode {
                target: Address(signer),
                method: "deposit".into(),
                args: vec![GraphArg::Param(0)],
            }],
        },
        params: vec![YieldParam {
            resource: VM_XRD,
            constraints: vec![Constraint::MinAmount(amount)],
        }],
    }
}

/// Compose `request` — signed by `signer_key`, whose account is the
/// request's target — into a transaction that fills it from `from`.
///
/// The composer withdraws the funds and yields them to the request; the
/// request deposits them. Committing spends the request's nullifier
/// under its signer's prefix, so two compositions carrying one request
/// contend on that key and exactly one settles.
///
/// # Panics
///
/// Panics if the composed envelope does not derive, which would be a
/// defect in the builder rather than a runtime condition.
#[must_use]
pub fn build_vm_composed_tx(
    composer: &Ed25519PrivateKey,
    from: [u8; 16],
    signer_key: &Ed25519PrivateKey,
    request: &IntentDecl,
    amount: u128,
    validity: TimestampRange,
) -> RoutableTransaction {
    let tree = EnvelopeTree {
        root: IntentDecl {
            graph: ManifestGraph {
                nodes: vec![GraphNode {
                    target: Address(from),
                    method: "withdraw".into(),
                    args: vec![
                        GraphArg::Literal(Value::Address(VM_XRD)),
                        GraphArg::Literal(Value::U128(amount)),
                    ],
                }],
            },
            params: Vec::new(),
        },
        root_bindings: Vec::new(),
        subintents: vec![Subintent {
            decl: request.clone(),
            signer: Address(vm_account_address(&signer_key.public_key().0)),
            bindings: vec![YieldBinding {
                intent: 0,
                edge: EdgeRef {
                    producer: 0,
                    output: 0,
                },
            }],
        }],
    };
    // The signer signs its own declaration's hash, which no part of the
    // envelope enters — the composer binds it afterwards and signs the
    // whole, subintent signatures included.
    let signed = signer_key.sign(request.hash(&ProtocolHasher).0.0);
    let vm = VmTransaction {
        body: VmBody::Call(encode_tree(&tree).into()),
        subintent_sigs: vec![VmSubintentSig {
            public_key: signer_key.public_key().0,
            signature: signed.0,
        }],
        fee_payer: vm_account_address(&composer.public_key().0),
        max_fee: 1_000,
        gas_limit: 1_000_000,
        validity_start_ms: validity.start_timestamp_inclusive.as_millis(),
        validity_end_ms: validity.end_timestamp_exclusive.as_millis(),
        message: Vec::new().into(),
        signer: [0; 32],
        signature: [0; 64],
    }
    .sign(composer);
    RoutableTransaction::new_vm(vm)
}

/// The fee ceiling every built call envelope signs.
///
/// A placeholder — the constants are phase 6 scope, the structure is signed
/// now — but a load-bearing one: the payer shard's reservation check demands
/// the ceiling be coverable, so it must sit below the funded balances, and a
/// scenario probing for a stale reservation sizes its funding against it.
pub const VM_MAX_FEE: u128 = 1_000;

/// Wrap a single-intent graph in a signed envelope with placeholder fee
/// terms.
fn vm_envelope(
    graph: ManifestGraph,
    payer: &Ed25519PrivateKey,
    validity: TimestampRange,
) -> VmTransaction {
    let tree = EnvelopeTree {
        root: IntentDecl {
            graph,
            params: Vec::new(),
        },
        root_bindings: Vec::new(),
        subintents: Vec::new(),
    };
    VmTransaction {
        body: VmBody::Call(encode_tree(&tree).into()),
        subintent_sigs: Vec::new(),
        fee_payer: vm_account_address(&payer.public_key().0),
        max_fee: VM_MAX_FEE,
        gas_limit: 1_000_000,
        validity_start_ms: validity.start_timestamp_inclusive.as_millis(),
        validity_end_ms: validity.end_timestamp_exclusive.as_millis(),
        message: Vec::new().into(),
        signer: [0; 32],
        signature: [0; 64],
    }
    .sign(payer)
}

/// Build a withdraw-from-`from`, deposit-to-`to` XRD transfer, signed and
/// notarized by `payer` and valid across `validity`.
///
/// # Panics
///
/// Panics if signing or the routability conversion fails — both fire only on a
/// malformed manifest (programmer error).
#[must_use]
pub fn build_transfer_tx(
    payer: &Ed25519PrivateKey,
    from: ComponentAddress,
    to: ComponentAddress,
    amount: Decimal,
    network: &NetworkDefinition,
    nonce: u32,
    validity: TimestampRange,
) -> RoutableTransaction {
    build_transfer(payer, from, to, amount, network, nonce, validity).expect("transfer builds")
}

/// Cast the founding pool's vote to retune the reshape `split_bytes`,
/// activating at `activate_at`.
///
/// The founding pool holds every genesis validator's stake, so one vote
/// is a majority. Raising `split_bytes` lifts the derived `merge_bytes`
/// above a grown topology's children so they fall under the merge
/// threshold.
///
/// Every governed parameter travels, not just the one being changed: a
/// vote is a whole proposal, and the tally buckets by the exact pair, so
/// a vote that omitted the others would be voting to reset them.
#[must_use]
pub fn build_reshape_threshold_vote_tx(
    operator: &Ed25519PrivateKey,
    split_bytes: u64,
    activate_at: Epoch,
    validity: TimestampRange,
) -> RoutableTransaction {
    build_vm_operator_tx(
        operator,
        VM_GENESIS_POOL,
        "cast-param-vote",
        vec![
            GraphArg::Literal(Value::U64(split_bytes)),
            GraphArg::Literal(Value::U64(NetworkParams::default().impound_epochs)),
            GraphArg::Literal(Value::U64(activate_at.inner())),
        ],
        validity,
    )
}
