//! Beacon-witness scenarios.
//!
//! Each scenario drives a real system transaction — a `lock_fee` no-op carrying
//! a [`BeaconWitnessEvent`] — from submission through the shard commit, the
//! shard's beacon-witness root, and the beacon fold, then asserts the folded
//! [`BeaconState`]. No witness is injected: every action travels the same rail an
//! operator's staking, registration, or governance transaction would, so the
//! same body validates the witness rail on both harnesses.
//!
//! The deposited and withdrawn amounts are asserted by the transaction message
//! (the stop-gap trust model), so a pool can be funded past genesis capacity
//! regardless of the payer's balance.
//!
//! [`BeaconState`]: hyperscale_types::BeaconState

use std::sync::Arc;

use hyperscale_types::{
    BeaconWitnessEvent, ConsensusPublicKey, MIN_STAKE_FLOOR, RoutableTransaction, Stake,
    StakePoolId, TransactionDecision, TransactionStatus, UNBONDING_WINDOW_EPOCHS, ValidatorId,
    ValidatorStatus, validator_possession_proof_sign,
};
use radix_common::network::NetworkDefinition;

use crate::support::query::{
    pool_effective_stake, pool_total_stake, validator_pubkey, validator_status,
};
use crate::support::tx::{
    VM_STAKE_POOL, VM_STAKE_POOL_ID, build_vm_stake_tx, build_vm_unstake_tx, build_witness_tx,
    validity_around, vm_delegator, witness_payer,
};
use crate::support::wait::{await_beacon_epoch, await_tx_terminal};
use crate::support::{Cluster, epochs};

/// The single genesis stake pool every genesis validator belongs to.
const GENESIS_POOL: StakePoolId = StakePoolId::new(0);

/// Warm the cluster until the beacon folds its first epoch — the precondition a
/// system action needs to land on a live shard and witness through.
fn warm_up<C: Cluster>(c: &mut C) {
    assert!(
        await_beacon_epoch(c, 1, epochs(6)),
        "beacon never folded its first epoch",
    );
}

/// Build and submit a system action from the witness payer at `nonce`.
fn submit_action<C: Cluster>(c: &mut C, nonce: u32, event: &BeaconWitnessEvent) {
    let tx = build_witness_tx(
        &witness_payer(),
        event,
        &NetworkDefinition::simulator(),
        nonce,
        validity_around(c.now()),
    );
    c.submit(Arc::new(tx));
}

/// A well-formed consensus pubkey for a registration, derived under the
/// cluster's own scheme. No host runs the registered validator, so any
/// deterministic key serves.
fn dummy_pubkey(c: &impl Cluster, seed: u8) -> ConsensusPublicKey {
    c.signer_from_seed(&[seed; 32]).public_key()
}

/// A `RegisterValidator` event for `dummy_pubkey(seed)` under
/// `validator_id`, carrying a genuine proof-of-possession — the fold
/// rejects a registration whose proof does not verify, so the signing
/// scheme must be the cluster's own.
fn dummy_registration(
    c: &impl Cluster,
    seed: u8,
    pool_id: StakePoolId,
    validator_id: ValidatorId,
) -> BeaconWitnessEvent {
    let keypair = c.signer_from_seed(&[seed; 32]);
    BeaconWitnessEvent::RegisterValidator {
        pool_id,
        validator_id,
        pubkey: keypair.public_key(),
        possession_proof: validator_possession_proof_sign(
            keypair.as_ref(),
            &NetworkDefinition::simulator(),
            validator_id,
        )
        .expect("sign"),
    }
}

/// A delegation through a stake pool contract folds into the beacon
/// state — the control plane's whole rail, driven by contract code.
///
/// The Radix scenarios above assert a witness a *keyholder signed*: the
/// action rides a no-op transaction's plaintext message, so the beacon
/// takes the sender's word for it. This one asserts a witness a *contract
/// emitted*: the delegator's funds actually move into the pool's vault,
/// the pool's code records what happened, and the beacon folds that.
/// Nothing is asserted about the amount by the transaction — the amount
/// is the delta that occurred.
///
/// Every layer between is the one the Radix path already used: the same
/// receipt field, the same witness leaves, the same windowed root on the
/// boundary header, the same fold. Only the source changed, which is what
/// makes this the assertion that the source is all that changed.
///
/// # Panics
///
/// Panics if the delegation never commits, or the beacon never folds it
/// within budget.
pub fn vm_delegation_folds_into_beacon_state(c: &mut impl Cluster) {
    warm_up(c);

    let pool = VM_STAKE_POOL_ID;
    assert_eq!(
        pool_total_stake(c, pool),
        None,
        "the pool must have no stake before anyone delegates to it",
    );

    let (key, delegator) = vm_delegator();
    let tx = build_vm_stake_tx(
        &key,
        delegator,
        VM_STAKE_POOL,
        DELEGATION,
        validity_around(c.now()),
    );
    let hash = tx.hash();
    c.submit(Arc::new(tx));

    let status = await_tx_terminal(c, hash, epochs(8));
    assert!(
        matches!(
            status,
            Some(TransactionStatus::Completed(TransactionDecision::Accept))
        ),
        "the delegation must commit before it can be witnessed; status = {status:?}",
    );

    // The pool's stake is the delegation, in the units the beacon counts:
    // a VM amount cell is attos, which is what `Stake` is denominated in,
    // so nothing rescales on the way through.
    assert!(
        c.run_until(epochs(10), |c| pool_total_stake(c, pool)
            == Some(Stake::from_attos(DELEGATION))),
        "the beacon never folded the delegation; pool stake = {:?}",
        pool_total_stake(c, pool),
    );
}

/// What the staking scenario delegates. Large enough that the folded
/// stake cannot be confused with a rounding artefact and small enough to
/// sit well inside the delegator's genesis funding.
const DELEGATION: u128 = 250_000;

/// Registering a validator against a funded pool seats it in the pool.
///
/// # Panics
///
/// Panics if the deposit or the registration never folds within budget.
pub fn register_validator_pools_a_node(c: &mut impl Cluster) {
    warm_up(c);

    // Fund a fresh pool well above min_stake so it can support a validator.
    let pool = StakePoolId::new(7777);
    let newcomer = ValidatorId::new(1000);
    submit_action(
        c,
        1,
        &BeaconWitnessEvent::StakeDeposit {
            pool_id: pool,
            amount: Stake::from_whole_tokens(10_000_000),
        },
    );
    assert!(
        c.run_until(epochs(8), |c| pool_total_stake(c, pool).is_some()),
        "deposit never folded",
    );

    submit_action(c, 2, &dummy_registration(c, 9, pool, newcomer));
    assert!(
        c.run_until(epochs(8), |c| validator_status(c, newcomer)
            == Some(ValidatorStatus::Pooled)),
        "registered validator never reached the pool",
    );
}

/// A registration against a pool below one `min_stake` is rejected on the
/// capacity gate, leaving no validator record.
///
/// # Panics
///
/// Panics if the deposit never folds, or if the under-capacity registration
/// creates a validator record.
pub fn register_without_capacity_is_rejected(c: &mut impl Cluster) {
    warm_up(c);

    // The pool exists but holds less than one min_stake, so it can support no
    // validator — the registration must be rejected on the capacity gate.
    let pool = StakePoolId::new(8888);
    let newcomer = ValidatorId::new(2000);
    submit_action(
        c,
        1,
        &BeaconWitnessEvent::StakeDeposit {
            pool_id: pool,
            amount: Stake::from_whole_tokens(500_000),
        },
    );
    assert!(
        c.run_until(epochs(8), |c| pool_total_stake(c, pool).is_some()),
        "deposit never folded",
    );

    submit_action(c, 2, &dummy_registration(c, 11, pool, newcomer));
    // Run long enough that the registration has committed and folded; an
    // accepted one would surface within a couple of epochs.
    c.run_until(epochs(5), |_| false);
    assert_eq!(
        validator_status(c, newcomer),
        None,
        "under-capacity registration must not create a validator record",
    );
}

/// Returning part of a staking position drops the pool's effective stake
/// immediately while its total stake holds until the unbond matures.
///
/// The position is an ordinary fungible balance, so unwinding one is an
/// ordinary withdrawal from the delegator's own account handed back to
/// the pool — and what the beacon folds is the pool's own account of
/// what left, not an amount the transaction asserted.
///
/// # Panics
///
/// Panics if the delegation or the return never folds, or if total stake
/// drops before the unbond matures.
pub fn stake_withdraw_drops_effective_stake(c: &mut impl Cluster) {
    warm_up(c);

    let pool = VM_STAKE_POOL_ID;
    let delegated = MIN_STAKE_FLOOR.attos() * 5;
    let returned = MIN_STAKE_FLOOR.attos() * 2;
    let remaining = Stake::from_attos(delegated - returned);
    let (key, delegator) = vm_delegator();

    submit_committed(
        c,
        build_vm_stake_tx(
            &key,
            delegator,
            VM_STAKE_POOL,
            delegated,
            validity_around(c.now()),
        ),
    );
    assert!(
        c.run_until(epochs(8), |c| pool_total_stake(c, pool)
            == Some(Stake::from_attos(delegated))),
        "the delegation never folded; pool stake = {:?}",
        pool_total_stake(c, pool),
    );

    submit_committed(
        c,
        build_vm_unstake_tx(
            &key,
            delegator,
            VM_STAKE_POOL,
            returned,
            validity_around(c.now()),
        ),
    );
    assert!(
        c.run_until(epochs(8), |c| pool_effective_stake(c, pool)
            == Some(remaining)),
        "the return never dropped effective stake; effective = {:?}",
        pool_effective_stake(c, pool),
    );
    // `total_stake` holds through the unbonding window; only `effective_stake`
    // drops immediately.
    assert_eq!(
        pool_total_stake(c, pool),
        Some(Stake::from_attos(delegated)),
        "total stake must hold until the withdrawal unbonds",
    );
}

/// Submit `tx` and wait for it to commit, failing on any other outcome.
///
/// A witness only exists if its transaction settled, so a scenario that
/// waited on the fold alone would report "the beacon never folded it"
/// for a transaction that never ran.
fn submit_committed<C: Cluster>(c: &mut C, tx: RoutableTransaction) {
    let hash = tx.hash();
    c.submit(Arc::new(tx));
    let status = await_tx_terminal(c, hash, epochs(8));
    assert!(
        matches!(
            status,
            Some(TransactionStatus::Completed(TransactionDecision::Accept))
        ),
        "the action must commit before it can be witnessed; status = {status:?}",
    );
}

/// A pooled validator draws onto the shard once a committee slot frees.
///
/// # Panics
///
/// Panics if any lifecycle stage misses its budget.
pub fn registered_validator_activates_onto_a_shard(c: &mut impl Cluster) {
    warm_up(c);

    let newcomer = ValidatorId::new(1000);

    // Grow the genesis pool past its capacity so it can support another node.
    submit_action(
        c,
        1,
        &BeaconWitnessEvent::StakeDeposit {
            pool_id: GENESIS_POOL,
            amount: Stake::from_whole_tokens(10_000_000),
        },
    );
    assert!(
        c.run_until(epochs(8), |c| pool_total_stake(c, GENESIS_POOL)
            .is_some_and(|s| s >= Stake::from_whole_tokens(13_000_000))),
        "capacity deposit never folded",
    );

    // Register a new validator; with the committee full it parks in the pool.
    submit_action(c, 2, &dummy_registration(c, 9, GENESIS_POOL, newcomer));
    assert!(
        c.run_until(epochs(8), |c| validator_status(c, newcomer)
            == Some(ValidatorStatus::Pooled)),
        "newcomer never reached the pool",
    );

    // Retire a genesis validator; the freed committee slot draws the only pooled
    // validator — the newcomer — onto the shard. It enters `OnShard { ready:
    // false }`; the ready flip follows later via the shard's `Ready` witness,
    // which this host-less validator never drives, so the placement is the
    // activation milestone.
    submit_action(
        c,
        3,
        &BeaconWitnessEvent::DeactivateValidator {
            pool_id: GENESIS_POOL,
            validator_id: ValidatorId::new(0),
        },
    );
    assert!(
        c.run_until(epochs(8), |c| matches!(
            validator_status(c, newcomer),
            Some(ValidatorStatus::OnShard { .. })
        )),
        "newcomer never drew onto the shard after a slot freed",
    );
}

/// A matured withdrawal ejects an over-capacity validator; a later deposit
/// reactivates it once capacity returns.
///
/// Requires a committee with enough slack to keep quorum while a member ejects
/// (the harness seats a seven-validator committee).
///
/// # Panics
///
/// Panics if the ejection or the reactivation misses its budget.
pub fn withdrawal_ejects_a_validator_that_a_deposit_reactivates(c: &mut impl Cluster) {
    // The highest-id genesis validator is the first the over-capacity sweep
    // ejects, so it is the one to watch.
    let victim = ValidatorId::new(6);
    assert!(
        c.run_until(epochs(6), |c| matches!(
            validator_status(c, victim),
            Some(ValidatorStatus::OnShard { .. } | ValidatorStatus::Pooled)
        )),
        "victim should start active",
    );

    // The withdrawal blocks new support immediately but only releases stake —
    // and forces the over-capacity ejection — once it unbonds, an
    // UNBONDING_WINDOW_EPOCHS later.
    submit_action(
        c,
        1,
        &BeaconWitnessEvent::StakeWithdraw {
            pool_id: GENESIS_POOL,
            amount: Stake::from_whole_tokens(1_500_000),
        },
    );
    let unbond_budget = u32::try_from(UNBONDING_WINDOW_EPOCHS).expect("unbonding window fits u32");
    assert!(
        c.run_until(epochs(unbond_budget + 10), |c| validator_status(c, victim)
            == Some(ValidatorStatus::InsufficientStake)),
        "the matured withdrawal never ejected the over-capacity validator",
    );

    // Top the pool back up; `auto_reactivate` promotes the ejected validator
    // back into service once capacity returns.
    submit_action(
        c,
        2,
        &BeaconWitnessEvent::StakeDeposit {
            pool_id: GENESIS_POOL,
            amount: Stake::from_whole_tokens(3_000_000),
        },
    );
    assert!(
        c.run_until(epochs(8), |c| matches!(
            validator_status(c, victim),
            Some(ValidatorStatus::Pooled | ValidatorStatus::OnShard { .. })
        )),
        "the deposit never reactivated the ejected validator",
    );
}

/// Re-registering a live validator id is a no-op: the record keeps its first
/// key, since the id is dead for the life of the chain.
///
/// # Panics
///
/// Panics if the first registration never folds, or if the re-registration
/// overwrites the existing record.
pub fn re_registration_of_a_live_validator_is_a_no_op(c: &mut impl Cluster) {
    warm_up(c);

    let pool = StakePoolId::new(7777);
    let id = ValidatorId::new(1000);
    let first = dummy_pubkey(c, 9);

    submit_action(
        c,
        1,
        &BeaconWitnessEvent::StakeDeposit {
            pool_id: pool,
            amount: Stake::from_whole_tokens(10_000_000),
        },
    );
    assert!(
        c.run_until(epochs(8), |c| pool_total_stake(c, pool).is_some()),
        "deposit never folded",
    );

    submit_action(c, 2, &dummy_registration(c, 9, pool, id));
    assert!(
        c.run_until(epochs(8), |c| validator_pubkey(c, id) == Some(first)),
        "validator never registered",
    );

    // Re-register the same id with a different key; the id is dead for the life
    // of the chain, so the record keeps its first key.
    submit_action(c, 3, &dummy_registration(c, 99, pool, id));
    c.run_until(epochs(5), |_| false);
    assert_eq!(
        validator_pubkey(c, id),
        Some(first),
        "re-registration must not overwrite the existing record",
    );
}

/// Pool capacity caps registrations: four registrations against a pool funded
/// for three take exactly three.
///
/// # Panics
///
/// Panics if the deposit or registrations never fold, or if more than three
/// take.
pub fn pool_capacity_caps_registrations(c: &mut impl Cluster) {
    warm_up(c);

    // Fund the pool for exactly three validators at the 1M floor.
    let pool = StakePoolId::new(7777);
    let candidates = [
        ValidatorId::new(1000),
        ValidatorId::new(1001),
        ValidatorId::new(1002),
        ValidatorId::new(1003),
    ];
    submit_action(
        c,
        1,
        &BeaconWitnessEvent::StakeDeposit {
            pool_id: pool,
            amount: Stake::from_whole_tokens(3_000_000),
        },
    );
    assert!(
        c.run_until(epochs(8), |c| pool_total_stake(c, pool).is_some()),
        "deposit never folded",
    );

    // Four registrations against capacity three: exactly three take.
    for (i, id) in candidates.iter().enumerate() {
        let offset = u8::try_from(i).expect("candidate index fits u8");
        submit_action(
            c,
            u32::from(offset) + 2,
            &dummy_registration(c, 20 + offset, pool, *id),
        );
    }
    assert!(
        c.run_until(epochs(8), |c| candidates
            .iter()
            .filter(|id| validator_status(c, **id).is_some())
            .count()
            >= 3),
        "registrations never folded",
    );
    // Let any fourth attempt commit; the cap must hold at three.
    c.run_until(epochs(4), |_| false);
    let registered = candidates
        .iter()
        .filter(|id| validator_status(c, **id).is_some())
        .count();
    assert_eq!(
        registered, 3,
        "pool capacity must cap registrations at three",
    );
}
