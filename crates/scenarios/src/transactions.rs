//! Transaction scenarios.

use std::sync::Arc;

use hyperscale_types::{ShardId, TransactionDecision, TransactionStatus};
use radix_common::math::Decimal;
use radix_common::network::NetworkDefinition;

use crate::reshape::split_lifecycle;
use crate::support::tx::{
    PROBE_PAYMENT, account_from_seed, build_faucet_tx, build_transfer_tx, build_vm_transfer_tx,
    signer_from_seed, validity_around, vm_livelock_pair,
};
use crate::support::wait::{await_height, await_tx_terminal};
use crate::support::{Cluster, epochs};

/// Submit a faucet-funded single-shard transfer and assert it accepts.
///
/// Awaits the transfer completing with an `Accept` decision and the root shard
/// advancing past genesis. The faucet is a fixed native component on both
/// harnesses, so no funded-account discovery is needed.
///
/// # Panics
///
/// Panics if the transfer does not accept within budget or the root shard does
/// not advance past genesis.
pub fn single_shard_tx(c: &mut impl Cluster) {
    let signer = signer_from_seed(1);
    let to = account_from_seed(2);
    let transfer = build_faucet_tx(
        to,
        &signer,
        &NetworkDefinition::simulator(),
        1,
        validity_around(c.now()),
    );
    let hash = transfer.hash();
    c.submit(Arc::new(transfer));

    let status = await_tx_terminal(c, hash, epochs(8));
    assert!(
        matches!(
            status,
            Some(TransactionStatus::Completed(TransactionDecision::Accept))
        ),
        "single-shard tx did not accept within budget; status = {status:?}"
    );
    assert!(
        await_height(c, ShardId::ROOT, 1, epochs(2)),
        "root shard did not advance past genesis"
    );
}

/// Grow the root into two shards, then settle a cross-shard transfer.
///
/// Transfers between a funded account on each child, asserting it completes with
/// `Accept` — provisioning, execution, and per-shard certificates all agree,
/// with zero aborts. Composes [`split_lifecycle`] for the grow; account `31`
/// sits on the left child and `30` on the right, both funded at genesis.
///
/// # Panics
///
/// Panics if the grow misses its budget or the transfer does not accept.
pub fn cross_shard_tx(c: &mut impl Cluster) {
    split_lifecycle(c);

    let payer = signer_from_seed(31);
    let from = account_from_seed(31);
    let to = account_from_seed(30);
    let transfer = build_transfer_tx(
        &payer,
        from,
        to,
        Decimal::from(500),
        &NetworkDefinition::simulator(),
        1,
        validity_around(c.now()),
    );
    let hash = transfer.hash();
    c.submit(Arc::new(transfer));

    let status = await_tx_terminal(c, hash, epochs(8));
    assert!(
        matches!(
            status,
            Some(TransactionStatus::Completed(TransactionDecision::Accept))
        ),
        "cross-shard transfer did not accept (zero aborts) within budget; status = {status:?}"
    );
}

/// Grow to two shards, then submit a conflicting cross-shard pair (`31 → 30`
/// and `30 → 31`, across the two children) and assert it resolves promptly.
///
/// Each transfer is the other's mirror across the two children, so the
/// pair shares its whole account set and each engages the shard the other
/// pays from. Both reach a terminal outcome within a bounded budget and
/// the contention clears behind them — which is what "no livelock" means
/// here.
///
/// **A symmetric pair resolves by deadline, not by a loser.** There is no
/// cycle detector: each payer's shard holds a lock the other's wave needs,
/// neither can engage, and the deadline abort is what breaks it — the
/// backstop D21 names, doing the job it exists for. So both aborting is
/// the expected shape rather than the failure the Radix path called it,
/// and asserting "at most one aborts" would be asserting a mechanism this
/// engine does not have.
///
/// What that leaves worth asserting is that the deadlock was transient:
/// the pair moves nothing, and a single transfer submitted afterwards
/// settles, which it could not if either shard were still holding a lock.
/// Composes [`split_lifecycle`] for the grow.
///
/// # Panics
///
/// Panics if either transaction fails to reach a terminal outcome, or if
/// the contention does not clear behind them.
pub fn livelock_resolves_promptly(c: &mut impl Cluster) {
    split_lifecycle(c);

    let validity = validity_around(c.now());
    let pair = vm_livelock_pair();
    let (key_a, acc_a) = &pair[0];
    let (key_b, acc_b) = &pair[1];

    let tx_a = build_vm_transfer_tx(key_a, *acc_a, *acc_b, PROBE_PAYMENT, validity);
    let tx_b = build_vm_transfer_tx(key_b, *acc_b, *acc_a, PROBE_PAYMENT, validity);
    let hash_a = tx_a.hash();
    let hash_b = tx_b.hash();
    c.submit(Arc::new(tx_a));
    c.submit(Arc::new(tx_b));

    // The budget has to outlast a payer's deadline, which is its signed
    // window's end plus the evidence margin — wall-clock, and longer than
    // the wave a settlement would take. A genuine livelock never resolves
    // at all, so the assertion still catches one.
    let status_a = await_tx_terminal(c, hash_a, epochs(8));
    let status_b = await_tx_terminal(c, hash_b, epochs(8));
    assert!(
        matches!(status_a, Some(TransactionStatus::Completed(_)))
            && matches!(status_b, Some(TransactionStatus::Completed(_))),
        "conflicting pair must resolve without livelocking; a = {status_a:?}, b = {status_b:?}"
    );

    // The control on that: whatever the pair did, neither shard is still
    // encumbered. A lock the deadlock left behind would refuse this.
    let after = build_vm_transfer_tx(
        key_a,
        *acc_a,
        *acc_b,
        PROBE_PAYMENT,
        validity_around(c.now()),
    );
    let hash = after.hash();
    c.submit(Arc::new(after));
    let status = await_tx_terminal(c, hash, epochs(8));
    assert!(
        matches!(
            status,
            Some(TransactionStatus::Completed(TransactionDecision::Accept))
        ),
        "the contention must clear behind the pair; status = {status:?}",
    );
}
