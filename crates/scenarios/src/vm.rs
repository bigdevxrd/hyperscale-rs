//! The single-shard catalogue on the VM engine.
//!
//! Every scenario drives signed manifest graphs — the account guest's
//! withdraw+deposit — through the live pipeline: gossip, derived-key
//! admission, proposal, wave execution on the VM batch executor,
//! receipts, commit. The bodies are portable over [`Cluster`]; the
//! kernel-level invariants (handle capabilities, snapshot semantics,
//! schedule invariance) are pinned in the vm repo's differential suite —
//! here the assertions are consensus-shaped: acceptance, deterministic
//! aborts, ordering, and committed state roots.

use std::collections::BTreeSet;
use std::sync::Arc;

use hyperscale_effects_bridge::ProtocolHasher;
use hyperscale_effects_bridge::vm_statics::package_key;
use hyperscale_engine_vm::genesis::{entropy_key, vault_key};
use hyperscale_engine_vm::{
    PreviewGrants, PreviewOutcome, PreviewReport, ResourceChange, VM_XRD, vm_account_address,
};
use hyperscale_types::{
    BlockHeight, NetworkDefinition, ShardId, TransactionDecision, TransactionStatus, TxHash,
};
use hyperscale_vm_effects::package_hash;

use crate::contention::{ContentionReport, Lcg, settle_and_report, zipf_cdf};
use crate::support::faultable::FaultableCluster;
use crate::support::tx::{
    build_faucet_tx, build_vm_composed_tx, build_vm_publish_tx, build_vm_stamp_tx,
    build_vm_transfer_tx, contention_recipient, signer_from_seed, validity_around,
    vm_cross_shard_cast, vm_nullifier_race_cast, vm_payment_request, vm_recipient, vm_sender,
    vm_storm_artifact, vm_storm_publishers,
};
use crate::support::wait::{await_height, await_tx_terminal};
use crate::support::{Cluster, epochs};

/// Per-payment amount of the VM contention scenarios.
const PAYMENT: u128 = 5;

/// The payment a nullifier race contends over.
const REQUEST: u128 = 100;

/// Two compositions carrying one signed subintent: exactly one commits.
///
/// The request is a declaration and nothing else — its hash covers its
/// own graph and parameters, no envelope — so both composers bind the
/// identical one and both derive the same nullifier key under its
/// signer's prefix. That shared declared write is what puts them in one
/// conflict group, where the spent check sees the winner's cell.
///
/// The loser is charged as a lost race rather than as a defect: canonical
/// order picked the winner, and nothing a composer could read at signing
/// time would have told it which way.
///
/// # Panics
///
/// Panics if both compositions settle the same way, if the request is
/// filled more than once, or if either payer is charged the wrong class.
pub fn vm_nullifier_race_admits_exactly_one(c: &mut impl Cluster) {
    let shard = ShardId::ROOT;
    let (first_key, second_key, requester_key) = vm_nullifier_race_cast();
    let first = vm_account_address(&first_key.public_key().0);
    let second = vm_account_address(&second_key.public_key().0);
    let requester = vm_account_address(&requester_key.public_key().0);

    let before = [
        vm_vault_balance(c, shard, first),
        vm_vault_balance(c, shard, second),
        vm_vault_balance(c, shard, requester),
    ];

    let request = vm_payment_request(requester, REQUEST);
    let window = validity_around(c.now());
    let mut hashes = Vec::new();
    let mut floors = Vec::new();
    for (composer, from) in [(&first_key, first), (&second_key, second)] {
        let tx = build_vm_composed_tx(composer, from, &requester_key, &request, REQUEST, window);
        floors.push(tx.vm().expect("a VM envelope").abort_floor());
        hashes.push(tx.hash());
        c.submit(Arc::new(tx));
    }

    let verdicts: Vec<Option<TransactionStatus>> = hashes
        .iter()
        .map(|hash| await_tx_terminal(c, *hash, epochs(8)))
        .collect();
    let accepted = verdicts
        .iter()
        .filter(|status| {
            matches!(
                status,
                Some(TransactionStatus::Completed(TransactionDecision::Accept))
            )
        })
        .count();
    assert_eq!(
        accepted, 1,
        "exactly one composition may fill a once-only request; verdicts = {verdicts:?}"
    );

    // The request was filled once, so the requester banked one payment.
    let after_requester = vm_vault_balance(c, shard, requester);
    assert_eq!(
        after_requester - before[2],
        REQUEST,
        "the request must be filled exactly once"
    );

    // The winner paid the payment and its fee; the loser paid the class
    // floor and nothing more.
    let won = matches!(
        verdicts[0],
        Some(TransactionStatus::Completed(TransactionDecision::Accept))
    );
    let (winner_spent, loser_spent) = if won {
        (
            before[0] - vm_vault_balance(c, shard, first),
            before[1] - vm_vault_balance(c, shard, second),
        )
    } else {
        (
            before[1] - vm_vault_balance(c, shard, second),
            before[0] - vm_vault_balance(c, shard, first),
        )
    };
    assert!(
        winner_spent > REQUEST,
        "the winner paid the request plus a fee; spent = {winner_spent}"
    );
    assert_eq!(
        loser_spent, floors[0],
        "a lost race settles the class floor, not the ceiling"
    );
}

/// Submit one VM transfer between genesis-funded VM accounts and assert
/// it accepts and lands state.
///
/// The committed state root must move off its pre-submission value: the
/// transfer's identity-keyed vault cells (INV-VM-4's leaf form) entered
/// the shard's JMT on every replica, or the commit could not have
/// certified.
///
/// # Panics
///
/// Panics if the transfer does not accept within budget, the root shard
/// does not advance, or the state root does not move.
pub fn vm_single_transfer(c: &mut impl Cluster) {
    let (payer, from) = vm_sender(0);
    let to = vm_recipient(0);
    let before = c.committed_state_root(ShardId::ROOT);
    let transfer = build_vm_transfer_tx(&payer, from, to, 100, validity_around(c.now()));
    let hash = transfer.hash();
    c.submit(Arc::new(transfer));

    let status = await_tx_terminal(c, hash, epochs(8));
    assert!(
        matches!(
            status,
            Some(TransactionStatus::Completed(TransactionDecision::Accept))
        ),
        "VM transfer did not accept within budget; status = {status:?}"
    );
    assert!(
        await_height(c, ShardId::ROOT, 1, epochs(2)),
        "root shard did not advance past genesis"
    );
    let after = c.committed_state_root(ShardId::ROOT);
    assert!(
        after.is_some() && after != before,
        "the committed state root must reflect the transfer's vault cells; \
         before = {before:?}, after = {after:?}"
    );
}

/// An uncovered VM withdrawal aborts deterministically on every replica
/// and the chain carries on — the consensus half of INV-VM-1.
///
/// The over-withdrawal's reservation is infeasible against committed
/// state, so every replica derives the identical `Failed` receipt and
/// the block certifies; a covered transfer from the same payer then
/// accepts, showing the abort wedged nothing. (The kernel half — an
/// undeclared substate has no handle, a forged handle traps — is pinned
/// by the vm repo's differential corpus.)
///
/// # Panics
///
/// Panics if the over-withdrawal does not reject, or the follow-up does
/// not accept.
pub fn vm_abort_converges(c: &mut impl Cluster) {
    let (payer, from) = vm_sender(0);
    let to = vm_recipient(0);

    let over = build_vm_transfer_tx(&payer, from, to, 1_000_000, validity_around(c.now()));
    let over_hash = over.hash();
    c.submit(Arc::new(over));
    let status = await_tx_terminal(c, over_hash, epochs(8));
    assert!(
        matches!(
            status,
            Some(TransactionStatus::Completed(TransactionDecision::Reject))
        ),
        "an uncovered VM withdrawal must reject deterministically; status = {status:?}"
    );

    let fine = build_vm_transfer_tx(&payer, from, to, 50, validity_around(c.now()));
    let fine_hash = fine.hash();
    c.submit(Arc::new(fine));
    let status = await_tx_terminal(c, fine_hash, epochs(8));
    assert!(
        matches!(
            status,
            Some(TransactionStatus::Completed(TransactionDecision::Accept))
        ),
        "a covered VM transfer must accept after an abort; status = {status:?}"
    );
}

/// A dependent VM transfer reads its own block's attested baseline.
///
/// The second transfer spends more than its payer's genesis balance and
/// is covered only by the first transfer's committed deposit. It accepts
/// only if its wave's reads pin to the state its block attests — which
/// includes the funding commit — never a stale baseline; and it cannot
/// read further forward either, since nothing beyond its baseline
/// exists. (Submitted after the funding settles: concurrent submission
/// would leave the pair's serialization order to admission, making the
/// dependent leg's verdict scheduling-dependent by design.)
///
/// # Panics
///
/// Panics if either transfer misses its budget, the dependent transfer
/// does not accept, or the commit order is not strictly increasing.
pub fn vm_reads_the_committed_baseline(c: &mut impl Cluster) {
    let (alice_key, alice) = vm_sender(0);
    let (bob_key, bob) = vm_sender(1);
    let carol = vm_recipient(0);

    // Bob holds 10_000 at genesis; after Alice's 5_000 deposit he can
    // cover 12_000.
    let first = build_vm_transfer_tx(&alice_key, alice, bob, 5_000, validity_around(c.now()));
    let first_hash = first.hash();
    c.submit(Arc::new(first));
    let status = await_tx_terminal(c, first_hash, epochs(10));
    assert!(
        matches!(
            status,
            Some(TransactionStatus::Completed(TransactionDecision::Accept))
        ),
        "funding transfer must accept; status = {status:?}"
    );

    let second = build_vm_transfer_tx(&bob_key, bob, carol, 12_000, validity_around(c.now()));
    let second_hash = second.hash();
    c.submit(Arc::new(second));
    let status = await_tx_terminal(c, second_hash, epochs(10));
    assert!(
        matches!(
            status,
            Some(TransactionStatus::Completed(TransactionDecision::Accept))
        ),
        "dependent transfer must accept against the committed baseline; status = {status:?}"
    );

    let (first_committed, _) = c.chain_fate(ShardId::ROOT, first_hash);
    let (second_committed, _) = c.chain_fate(ShardId::ROOT, second_hash);
    let (first_committed, second_committed) = (
        first_committed.expect("accepted transfer has a commit height"),
        second_committed.expect("accepted transfer has a commit height"),
    );
    assert!(
        second_committed > first_committed,
        "the dependent transfer must commit after its funding \
         ({second_committed:?} vs {first_committed:?})"
    );
}

/// Zipf-skewed VM payments: `senders` transfers into `recipients` payees
/// drawn from a Zipf(`skew`) distribution — the catalogue's contention
/// shape on the VM engine.
///
/// # Panics
///
/// Panics if any payment misses its budget or does not accept.
pub fn vm_zipf_payments(
    c: &mut impl Cluster,
    senders: u8,
    recipients: u8,
    skew: f64,
) -> ContentionReport {
    let cdf = zipf_cdf(recipients as usize, skew);
    let mut rng = Lcg(0x5eed_c0de ^ u64::from(senders) << 8 ^ u64::from(recipients));
    let mut submissions = Vec::with_capacity(senders as usize);
    for index in 0..senders {
        let (payer, from) = vm_sender(index);
        let draw = rng.unit();
        let rank = cdf.iter().position(|&c| draw < c).unwrap_or(cdf.len() - 1);
        let to = vm_recipient(u8::try_from(rank).expect("recipient rank fits"));
        let tx = build_vm_transfer_tx(&payer, from, to, PAYMENT, validity_around(c.now()));
        submissions.push((tx.hash(), c.now()));
        c.submit(Arc::new(tx));
    }
    settle_and_report(c, &submissions, epochs(10))
}

/// One hot VM recipient driven to the admission serialization ceiling.
///
/// Every payer deposits to the same vault cell; its substate-granular
/// write key serializes the batch at admission (the delta mode's
/// commutativity is a later admission lever, not exercised here), so no
/// two payments commit at one height.
///
/// # Panics
///
/// Panics if any payment misses its budget, does not accept, or two hot
/// payments commit at one height.
pub fn vm_hot_recipient(c: &mut impl Cluster, senders: u8) -> (ContentionReport, u64) {
    let hot = vm_recipient(0);
    let before = vm_vault_balance(c, ShardId::ROOT, hot);
    let mut submissions = Vec::with_capacity(senders as usize);
    for index in 0..senders {
        let (payer, from) = vm_sender(index);
        let tx = build_vm_transfer_tx(&payer, from, hot, PAYMENT, validity_around(c.now()));
        submissions.push((tx.hash(), c.now()));
        c.submit(Arc::new(tx));
    }
    let report = settle_and_report(c, &submissions, epochs(16));

    let mut heights = Vec::with_capacity(submissions.len());
    for (hash, _) in &submissions {
        let (committed, _) = c.chain_fate(ShardId::ROOT, *hash);
        heights.push(committed.expect("accepted payment has a commit height"));
    }
    heights.sort_unstable();
    let span = heights
        .last()
        .map_or(0, |last| last.inner() - heights[0].inner() + 1);
    let distinct = {
        let mut deduped = heights.clone();
        deduped.dedup();
        deduped.len()
    };
    assert_eq!(
        distinct,
        heights.len(),
        "two hot VM payments committed at one height — the serialization bound is broken",
    );

    // Every payment has to be *in* the hot vault. Counting commit
    // heights says they were serialized; only the balance says none was
    // overwritten by another executing against the same baseline —
    // `settle_and_report` has already asserted all of them accepted.
    let settled = u128::try_from(report.submitted).expect("bounded");
    assert_eq!(
        vm_vault_balance(c, ShardId::ROOT, hot) - before,
        settled * PAYMENT,
        "the hot vault must hold every accepted payment: {settled} settled",
    );
    (report, span)
}

/// A cross-shard VM transfer settles through the payer-first holdback.
///
/// The reserve leg lives on the payer's shard and the delta leg on the
/// recipient's; neither leg provisions state (both are commutative), so
/// the payer's wave records an empty dependency set and
/// dispatches immediately. The recipient engages only on the transaction
/// commit proof — the payer's empty-entry bundle, consumable once the
/// payer's block commit-proves — so its commit trails the payer's by one
/// cross-shard hop, and its wave's requirement is satisfied by the
/// bundle committing beside the transaction. Settlement is then the EC
/// exchange.
///
/// # Panics
///
/// Panics if the transfer misses its budget, does not accept, or either
/// shard's chain never commits it.
pub fn vm_cross_shard_transfer(c: &mut impl Cluster) {
    let (payer, from, to) = vm_cross_shard_cast();
    let tx = build_vm_transfer_tx(&payer, from, to, 100, validity_around(c.now()));
    let hash = tx.hash();
    c.submit(Arc::new(tx));

    let status = await_tx_terminal(c, hash, epochs(16));
    assert!(
        matches!(
            status,
            Some(TransactionStatus::Completed(TransactionDecision::Accept))
        ),
        "cross-shard VM transfer did not accept; status = {status:?}"
    );
    // Atomic settlement: both legs' chains carry the transaction.
    let (left, _) = c.chain_fate(ShardId::leaf(1, 0), hash);
    let (right, _) = c.chain_fate(ShardId::leaf(1, 1), hash);
    assert!(left.is_some(), "payer shard never committed the transfer");
    assert!(
        right.is_some(),
        "recipient shard never committed the transfer"
    );
}

/// A multi-shard transaction's events land only on their emitters' home
/// receipts.
///
/// The withdrawal emits from the payer's account and the deposit from the
/// recipient's, and the two accounts sit on different shards. Each shard
/// stores its own event and not the other's, while the receipt hash both
/// committees agree on covers the union — so attribution splits the
/// storage without splitting the agreement.
///
/// # Panics
///
/// Panics if the transfer does not accept, if either shard never holds a
/// receipt for it, or if either shard stores an event whose emitter lives
/// on the other.
pub fn vm_events_land_on_their_emitters_home_shard(c: &mut impl Cluster) {
    let (payer, from, to) = vm_cross_shard_cast();
    let tx = build_vm_transfer_tx(&payer, from, to, 100, validity_around(c.now()));
    let hash = tx.hash();
    c.submit(Arc::new(tx));

    let status = await_tx_terminal(c, hash, epochs(16));
    assert!(
        matches!(
            status,
            Some(TransactionStatus::Completed(TransactionDecision::Accept))
        ),
        "cross-shard VM transfer did not accept; status = {status:?}"
    );

    let (sender_shard, recipient_shard) = (ShardId::leaf(1, 0), ShardId::leaf(1, 1));
    // Receipts persist a beat behind the decision, so wait for both.
    let stored = c.run_until(epochs(8), |c| {
        c.vm_events(sender_shard, hash).is_some() && c.vm_events(recipient_shard, hash).is_some()
    });
    assert!(stored, "both shards must hold a receipt for the transfer");

    let sender_events = c.vm_events(sender_shard, hash).expect("payer receipt");
    let recipient_events = c
        .vm_events(recipient_shard, hash)
        .expect("recipient receipt");
    assert_eq!(
        sender_events
            .iter()
            .map(|event| event.emitter)
            .collect::<Vec<_>>(),
        vec![from],
        "the payer shard stores its own emission and nothing else"
    );
    assert_eq!(
        recipient_events
            .iter()
            .map(|event| event.emitter)
            .collect::<Vec<_>>(),
        vec![to],
        "the recipient shard stores its own emission and nothing else"
    );
}

/// Both shards' attested load reaches the beacon, including the
/// counterpart's — the shard the fee never paid.
///
/// Fees never move cross-shard, and this exercises the whole of what
/// replaces them. A cross-shard transfer
/// burns its fee at the payer's shard alone, so the counterpart executes
/// its leg for nothing; the work it did is instead attested as gas on its
/// own receipts, carried on its own headers, and folded onto its own
/// boundary record, where the emission weighting reads it. The assertion
/// that carries the rule is the counterpart's mark moving at all.
///
/// The byte level is checked for stability rather than for conservation
/// across a reshape: bonds do not exist yet, so INV-VM-7's own clause has
/// nothing to conserve. What is checkable today is that the channel
/// neither invents nor loses state — a quiesced network's recorded levels
/// do not drift.
///
/// # Panics
///
/// Panics if the transfer does not accept, if either shard's mark or byte
/// level never reaches the beacon within budget, if the counterpart
/// attests no work for the leg it executed, or if a recorded byte level
/// moves while nothing is executing.
pub fn vm_attested_load_reaches_the_beacon(c: &mut impl Cluster) {
    let left = ShardId::leaf(1, 0);
    let right = ShardId::leaf(1, 1);

    let (payer, from, to) = vm_cross_shard_cast();
    let tx = build_vm_transfer_tx(&payer, from, to, 100, validity_around(c.now()));
    let hash = tx.hash();
    c.submit(Arc::new(tx));
    let status = await_tx_terminal(c, hash, epochs(16));
    assert!(
        matches!(
            status,
            Some(TransactionStatus::Completed(TransactionDecision::Accept))
        ),
        "cross-shard VM transfer did not accept; status = {status:?}"
    );

    // Wait for both shards to fold a crossing carrying a non-zero mark.
    let both_attested = |c: &_| {
        recorded_gas(c, left).is_some_and(|g| g > 0)
            && recorded_gas(c, right).is_some_and(|g| g > 0)
    };
    assert!(
        c.run_until(epochs(24), both_attested),
        "attested work never reached the beacon: left = {:?}, right = {:?}",
        recorded_gas(c, left),
        recorded_gas(c, right),
    );

    // The counterpart burned no fee and still attested its work — without
    // this the emission weighting would pay it only the participation
    // floor, and cross-shard execution would be unfunded.
    let counterpart_gas = recorded_gas(c, right).expect("counterpart record present");
    assert!(
        counterpart_gas > 0,
        "the counterpart shard attested no work for a leg it executed"
    );

    // The byte levels are recorded, and a quiesced network does not drift:
    // nothing executes, so no state appears or vanishes on either record.
    let settled = |c: &_| recorded_bytes(c, left).is_some() && recorded_bytes(c, right).is_some();
    assert!(
        c.run_until(epochs(8), settled),
        "byte levels never reached the beacon"
    );
    let before = (recorded_bytes(c, left), recorded_bytes(c, right));
    // Burn the budget with nothing to wait for: the condition never holds,
    // so this runs the cluster on for the whole span and returns false.
    c.run_until(epochs(8), |_| false);
    let after = (recorded_bytes(c, left), recorded_bytes(c, right));
    assert_eq!(
        before, after,
        "recorded byte levels drifted with nothing executing"
    );
}

/// A transaction that never applied an effect still attests the work its
/// shard did for it.
///
/// This is what moving the quantity off the receipt buys. A receipt records
/// effects, so an attempt that produced none has nothing to carry — and a
/// failure or an abort is exactly when a shard has already paid for
/// admission, routing, and locking. The outcome exists for every verdict,
/// so the work rides there and the shard is credited for the attempt.
///
/// # Panics
///
/// Panics if the uncovered withdrawal does not reject, or if the shard's
/// attested mark fails to move across a block whose only transaction
/// applied nothing.
pub fn vm_a_failed_attempt_still_attests_work(c: &mut impl Cluster) {
    let shard = ShardId::ROOT;
    let (payer, from) = vm_sender(0);
    let to = vm_recipient(0);

    // Settle any earlier traffic so the mark below moves only for the
    // failure this scenario submits.
    assert!(
        c.run_until(epochs(4), |c| recorded_gas(c, shard).is_some()),
        "the beacon never folded a crossing for the shard"
    );
    let before = recorded_gas(c, shard).expect("a folded crossing");

    let over = build_vm_transfer_tx(&payer, from, to, 1_000_000, validity_around(c.now()));
    let over_hash = over.hash();
    c.submit(Arc::new(over));
    let status = await_tx_terminal(c, over_hash, epochs(8));
    assert!(
        matches!(
            status,
            Some(TransactionStatus::Completed(TransactionDecision::Reject))
        ),
        "an uncovered VM withdrawal must reject deterministically; status = {status:?}"
    );

    // The attempt applied nothing, so under the old shape — work carried on
    // the receipt — there was no receipt to carry it and the mark stood
    // still.
    assert!(
        c.run_until(epochs(24), |c| recorded_gas(c, shard)
            .is_some_and(|now| now > before)),
        "a failed attempt attested no work: mark stuck at {before}"
    );
}

/// The gas mark on `shard`'s boundary record, if the beacon has folded a
/// crossing for it.
fn recorded_gas<C: Cluster>(c: &C, shard: ShardId) -> Option<u64> {
    c.beacon_state()
        .and_then(|state| state.boundaries.get(&shard).map(|b| b.attested_work))
}

/// The stored-byte level on `shard`'s boundary record.
fn recorded_bytes<C: Cluster>(c: &C, shard: ShardId) -> Option<u64> {
    c.beacon_state()
        .and_then(|state| state.boundaries.get(&shard).map(|b| b.substate_bytes))
}

/// A randomness-reading transaction derives one draw on both shards.
///
/// Both accounts stamp the transaction's draw into their own entropy
/// leaf, one leaf per shard, so the two stamps agree exactly when the two
/// committees executed the transaction under one value. The draw is
/// anchored on the payer block — the block that committed the
/// transaction on the payer's shard, whose reveal chain rides the
/// engagement bundle — so agreement holds by construction rather than by
/// the two shards happening to commit in step. Each stamp is an
/// exclusive write, so this is also the read-set-provisioned shape in
/// both directions: each shard executes on the other's shipped prior.
///
/// # Panics
///
/// Panics if the stamp misses its budget, does not accept, either
/// shard's chain never commits it, either leaf is unstamped, or the two
/// stamps differ.
pub fn vm_randomness_draw_agrees_across_shards<C: Cluster>(c: &mut C) {
    let (payer, left_owner, right_owner) = vm_cross_shard_cast();
    let tx = build_vm_stamp_tx(&payer, left_owner, right_owner, validity_around(c.now()));
    let hash = tx.hash();
    c.submit(Arc::new(tx));

    let status = await_tx_terminal(c, hash, epochs(16));
    assert!(
        matches!(
            status,
            Some(TransactionStatus::Completed(TransactionDecision::Accept))
        ),
        "cross-shard VM stamp did not accept; status = {status:?}"
    );
    let (left_fate, _) = c.chain_fate(ShardId::leaf(1, 0), hash);
    let (right_fate, _) = c.chain_fate(ShardId::leaf(1, 1), hash);
    assert!(left_fate.is_some(), "payer shard never committed the stamp");
    assert!(
        right_fate.is_some(),
        "counterpart shard never committed the stamp"
    );

    // The stamps are read off each shard's own committed state, which
    // trails the settling block by the persistence step.
    let read = |c: &C, shard: ShardId, owner: [u8; 16]| -> Option<Vec<u8>> {
        let key = entropy_key(owner);
        c.vm_substate(shard, key.owner.0, key.local.0)
    };
    assert!(
        c.run_until(epochs(4), |c| read(c, ShardId::leaf(1, 0), left_owner)
            .is_some()
            && read(c, ShardId::leaf(1, 1), right_owner).is_some()),
        "both entropy leaves must carry a stamp"
    );
    let left = read(c, ShardId::leaf(1, 0), left_owner).expect("stamped");
    let right = read(c, ShardId::leaf(1, 1), right_owner).expect("stamped");
    assert_eq!(left.len(), 32, "a stamp is the 32-byte draw");
    assert_eq!(
        left, right,
        "the two shards executed the transaction under different draws"
    );
}

/// An insolvent payer's transaction engages nothing anywhere.
///
/// The payer's balance cannot cover the signed fee ceiling, so the
/// reservation is uncoverable: no payer-shard proposer selects the
/// transaction, and the reservation verification refuses any block that
/// carries it — it never commits at the payer shard, so no bundle ever
/// flows and no counterpart engages a lock. The transaction expires in
/// the mempool while both chains carry on.
///
/// # Panics
///
/// Panics if either chain stalls, the transaction completes, or either
/// shard's chain ever includes it.
pub fn vm_insolvent_payer_engages_nothing(c: &mut impl Cluster) {
    let (payer, from, to) = vm_cross_shard_cast();
    let tx = build_vm_transfer_tx(&payer, from, to, 5, validity_around(c.now()));
    let hash = tx.hash();
    c.submit(Arc::new(tx));

    // Both chains keep advancing while the transaction goes nowhere.
    assert!(
        await_height(c, ShardId::leaf(1, 0), 3, epochs(6)),
        "payer shard chain must keep advancing"
    );
    assert!(
        await_height(c, ShardId::leaf(1, 1), 3, epochs(6)),
        "counterpart shard chain must keep advancing"
    );
    let status = c.tx_status(hash);
    assert!(
        !matches!(status, Some(TransactionStatus::Completed(_))),
        "an uncoverable reservation must never complete; status = {status:?}"
    );
    let (payer_inclusion, _) = c.chain_fate(ShardId::leaf(1, 0), hash);
    assert!(
        payer_inclusion.is_none(),
        "the insolvent payer's transaction must never commit at the payer shard"
    );
    let (counterpart_inclusion, _) = c.chain_fate(ShardId::leaf(1, 1), hash);
    assert!(
        counterpart_inclusion.is_none(),
        "the counterpart must not engage an insolvent payer's transaction"
    );
}

/// Radix and VM traffic interleaved on one chain: both engines' receipts
/// merge through the per-variant wave dispatch and every transaction
/// accepts.
///
/// # Panics
///
/// Panics if any transaction misses its budget or does not accept.
pub fn mixed_engine_blocks(c: &mut impl Cluster, pairs: u8) {
    let network = NetworkDefinition::simulator();
    let mut hashes = Vec::with_capacity(2 * pairs as usize);
    for index in 0..pairs {
        let (vm_payer, vm_from) = vm_sender(index);
        let vm_tx = build_vm_transfer_tx(
            &vm_payer,
            vm_from,
            vm_recipient(0),
            PAYMENT + u128::from(index),
            validity_around(c.now()),
        );
        let radix_signer = signer_from_seed(index + 1);
        let radix_tx = build_faucet_tx(
            contention_recipient(index),
            &radix_signer,
            &network,
            u32::from(index),
            validity_around(c.now()),
        );
        hashes.push(vm_tx.hash());
        hashes.push(radix_tx.hash());
        c.submit(Arc::new(vm_tx));
        c.submit(Arc::new(radix_tx));
    }
    for (index, hash) in hashes.iter().enumerate() {
        let status = await_tx_terminal(c, *hash, epochs(10));
        assert!(
            matches!(
                status,
                Some(TransactionStatus::Completed(TransactionDecision::Accept))
            ),
            "mixed-engine transaction #{index} did not accept; status = {status:?}"
        );
    }
}

/// A payer whose counterpart never engages settles the abort floor and
/// nothing else.
///
/// Cutting both channels the payer's bundle travels — the gossip
/// broadcast and the fetch that backs it up — makes the counterpart's
/// absence structural: engagement demands that evidence, so the
/// transaction can never enter a block there. The payer's own leg is
/// dependency-free, so it commits, reserves, and executes at once, then
/// waits. It speaks once: with no engagement echo and the window closed,
/// its single statement is the abort. The transaction's effects are
/// discarded, so the recipient is never credited and the transferred
/// amount never leaves; what leaves is the class floor, settled through
/// the fee receipt the abort names.
///
/// # Panics
///
/// Panics if the harness cannot read the payer's vault, the payer never
/// commits, the bundle is never suppressed, the transaction fails to
/// reach a terminal abort, the counterpart engages, or the payer's
/// balance moves by anything other than the floor.
pub fn vm_abort_floor_settles_on_deadline(c: &mut impl FaultableCluster) {
    let payer_shard = ShardId::leaf(1, 0);
    let counterpart = ShardId::leaf(1, 1);
    let (payer, from, to) = vm_cross_shard_cast();
    let before = vm_vault_balance(c, payer_shard, from);

    // Both channels the bundle travels. The fetch rule names the
    // *request* type: the fault engine tags a request and its response
    // alike, so dropping the response id would never match.
    let broadcast_dropped = c.drop_type("provisions.broadcast");
    let fetch_dropped = c.drop_type("provision.request");

    let tx = build_vm_transfer_tx(&payer, from, to, 100, validity_around(c.now()));
    let hash = tx.hash();
    let floor = tx.vm().expect("a VM envelope").abort_floor();
    c.submit(Arc::new(tx));

    assert!(
        c.run_until(epochs(8), |c| c.chain_fate(payer_shard, hash).0.is_some()),
        "the payer shard must commit and reserve for the transaction"
    );

    let verdict = await_tx_terminal(c, hash, epochs(90));
    assert!(
        matches!(
            verdict,
            Some(TransactionStatus::Completed(TransactionDecision::Aborted))
        ),
        "an unechoed cross-shard VM transaction must abort at the deadline; \
         verdict = {verdict:?}",
    );
    assert!(
        broadcast_dropped.fired() > 0 && fetch_dropped.fired() > 0,
        "both bundle channels must actually have been exercised and cut"
    );
    let (counterpart_inclusion, _) = c.chain_fate(counterpart, hash);
    assert!(
        counterpart_inclusion.is_none(),
        "the counterpart must never have engaged the transaction",
    );

    // The floor left the payer's vault; the transfer did not.
    let after = vm_vault_balance(c, payer_shard, from);
    assert_eq!(
        before.saturating_sub(after),
        floor,
        "the abort must burn exactly the class floor: before = {before}, after = {after}",
    );
}

/// A transaction that fails still pays, and what it pays depends on whose
/// fault the failure was.
///
/// Failing must never be the cheaper way to buy execution. An uncovered
/// withdrawal loses a deterministic race it could not have foreseen — the
/// sender declared honestly and another transaction got there first — so
/// it settles the class floor, not the ceiling. What matters is that it
/// settles something: the same attempt used to cost nothing at all, which
/// made trapping strictly cheaper than succeeding for identical work.
///
/// # Panics
///
/// Panics if the uncovered withdrawal does not reject, if the covered
/// transfer that follows does not accept, or if the rejected attempt
/// moves the payer's vault by anything other than the floor.
pub fn vm_failure_charges_its_payer(c: &mut impl Cluster) {
    let shard = ShardId::ROOT;
    let (payer, from) = vm_sender(0);
    let to = vm_recipient(0);

    let before = vm_vault_balance(c, shard, from);
    let over = build_vm_transfer_tx(&payer, from, to, 1_000_000, validity_around(c.now()));
    let floor = over.vm().expect("a VM envelope").abort_floor();
    let over_hash = over.hash();
    c.submit(Arc::new(over));
    let status = await_tx_terminal(c, over_hash, epochs(8));
    assert!(
        matches!(
            status,
            Some(TransactionStatus::Completed(TransactionDecision::Reject))
        ),
        "an uncovered VM withdrawal must reject deterministically; status = {status:?}"
    );

    let after = vm_vault_balance(c, shard, from);
    assert_eq!(
        before.saturating_sub(after),
        floor,
        "a rejected attempt must settle exactly the class floor: \
         before = {before}, after = {after}, floor = {floor}"
    );

    // The charge is the only thing that moved: the payer can still spend.
    let fine = build_vm_transfer_tx(&payer, from, to, 50, validity_around(c.now()));
    let fine_hash = fine.hash();
    c.submit(Arc::new(fine));
    let status = await_tx_terminal(c, fine_hash, epochs(8));
    assert!(
        matches!(
            status,
            Some(TransactionStatus::Completed(TransactionDecision::Accept))
        ),
        "a covered VM transfer must accept after a charged failure; status = {status:?}"
    );
}

/// The committed balance of a VM account's native vault, read through the
/// harness's client-proven snapshot seam.
fn vm_vault_balance(c: &impl Cluster, shard: ShardId, owner: [u8; 16]) -> u128 {
    let vault = vault_key(owner, VM_XRD);
    c.vm_substate(shard, vault.owner.0, vault.local.0)
        .map_or(0, |bytes| {
            let cell: [u8; 16] = bytes.as_slice().try_into().expect("an amount cell");
            u128::from_le_bytes(cell)
        })
}

/// The reported change to `owner`'s native vault.
fn preview_change(report: &PreviewReport, owner: [u8; 16]) -> ResourceChange {
    let vault = vault_key(owner, VM_XRD);
    *report
        .changes
        .iter()
        .find(|change| change.key == vault)
        .unwrap_or_else(|| panic!("no reported change for {owner:?}: {:?}", report.changes))
}

/// A wallet's question before it signs, answered off the tip: what would
/// this transfer move, and what would it cost?
///
/// Preview is engine-side and consensus-free, and the scenario holds it
/// to both halves of that. The candidate is never submitted while it is
/// being previewed — the chain advances past it and has never heard of
/// it, and the payer's committed balance is exactly where it was — and
/// then the same envelope is committed for real, where the balances it
/// lands on are the figures the report named. A preview that reported
/// plausible numbers nobody ever checked against a commit would be
/// decoration.
///
/// Free credit is the one grant a preview carries today: it prices the
/// fee without charging it, which is what lets a wallet cost an envelope
/// its payer could not cover.
///
/// # Panics
///
/// Panics if the root shard serves no preview, if the report disagrees
/// with the committed baseline or with what the transfer commits, if the
/// preview leaks the transaction into the chain, or if the transfer does
/// not accept.
pub fn vm_preview_reports_resource_changes(c: &mut impl Cluster) {
    const AMOUNT: u128 = 100;
    let (payer, from) = vm_sender(0);
    let to = vm_recipient(0);

    // A preview reads the chain's own attested clock and reveal, so it
    // wants a chain that has spoken at least once.
    assert!(
        await_height(c, ShardId::ROOT, 1, epochs(2)),
        "root shard did not advance past genesis"
    );
    let sender_before = vm_vault_balance(c, ShardId::ROOT, from);
    let recipient_before = vm_vault_balance(c, ShardId::ROOT, to);

    let candidate = build_vm_transfer_tx(&payer, from, to, AMOUNT, validity_around(c.now()));
    let hash = candidate.hash();
    let report = c
        .vm_preview(ShardId::ROOT, &candidate, PreviewGrants::default())
        .expect("the root shard serves a preview");

    assert_eq!(
        report.outcome,
        PreviewOutcome::Completed,
        "a covered transfer previews as completed"
    );
    assert!(report.fee > 0, "a transfer costs its payer something");

    let sender = preview_change(&report, from);
    assert_eq!(
        (sender.before, sender.settled, sender.after),
        (sender_before, AMOUNT, sender_before - AMOUNT - report.fee),
        "the sender pays the transfer through its reservation's settle, plus the fee"
    );
    let recipient = preview_change(&report, to);
    assert_eq!(
        (recipient.before, recipient.credit, recipient.after),
        (recipient_before, AMOUNT, recipient_before + AMOUNT),
        "the recipient is credited the transfer and charged nothing"
    );

    let credited = c
        .vm_preview(
            ShardId::ROOT,
            &candidate,
            PreviewGrants { free_credit: true },
        )
        .expect("the root shard serves a preview");
    assert_eq!(credited.fee, report.fee, "the fee is priced either way");
    assert_eq!(
        preview_change(&credited, from).after,
        sender.after + report.fee,
        "free credit keeps exactly the fee off the payer's vault"
    );

    // Nothing was submitted, gossiped, or committed: the chain advances
    // past the preview without ever holding the transaction.
    let ahead = c
        .committed_height(ShardId::ROOT)
        .map_or(2, |h| h.inner() + 2);
    assert!(
        await_height(c, ShardId::ROOT, ahead, epochs(4)),
        "the root shard did not advance past the preview"
    );
    assert!(
        c.tx_status(hash).is_none(),
        "a preview must not submit the transaction it previewed"
    );
    assert_eq!(
        c.chain_fate(ShardId::ROOT, hash),
        (None, None),
        "a preview must reach no chain"
    );
    assert_eq!(
        vm_vault_balance(c, ShardId::ROOT, from),
        sender_before,
        "a preview writes nothing"
    );

    // The same envelope for real: the report was the truth about it.
    c.submit(Arc::new(candidate));
    let status = await_tx_terminal(c, hash, epochs(8));
    assert!(
        matches!(
            status,
            Some(TransactionStatus::Completed(TransactionDecision::Accept))
        ),
        "the previewed transfer did not accept; status = {status:?}"
    );
    assert_eq!(
        vm_vault_balance(c, ShardId::ROOT, from),
        sender.after,
        "the commit landed on the figure the preview named for the sender"
    );
    assert_eq!(
        vm_vault_balance(c, ShardId::ROOT, to),
        recipient.after,
        "the commit landed on the figure the preview named for the recipient"
    );
}

/// An adversarial deploy storm rides out: throughput degrades, no shard
/// stalls.
///
/// Every publisher spams distinct packages at its own shard at once, so
/// both committees are simultaneously carrying the heaviest transaction
/// the protocol admits — a full artifact each, validated at admission and
/// written whole into state. This is the probe the commit-fed cache has
/// to survive: if publishing could wedge a committee, or if the cache
/// feed could make a shard's commit path fall behind its consensus, this
/// is where it would show.
///
/// The assertion is deliberately about liveness rather than latency.
/// Every publish reaching a terminal decision is itself the anti-stall
/// proof — a wedged committee settles nothing — and both shards' heights
/// advancing past the storm says the chains never stopped.
///
/// # Panics
///
/// Panics if any publish fails to settle, if a publish did not commit on
/// its publisher's shard, or if either shard's chain failed to advance.
pub fn vm_deploy_storm_rides_out(c: &mut impl Cluster) {
    const PER_PUBLISHER: u16 = 6;

    let publishers = vm_storm_publishers();
    let shards = [ShardId::leaf(1, 0), ShardId::leaf(1, 1)];
    let before: Vec<Option<BlockHeight>> = shards
        .iter()
        .map(|shard| c.committed_height(*shard))
        .collect();

    let validity = validity_around(c.now());
    let mut submitted: Vec<(TxHash, ShardId)> = Vec::new();
    let mut cells: Vec<(ShardId, [u8; 16], [u8; 16])> = Vec::new();
    for (index, (key, publisher)) in (0u16..).zip(publishers.iter()) {
        for nonce in 0..PER_PUBLISHER {
            // Distinct per publisher as well as per nonce, so the two
            // shards never race to publish one content address.
            let artifact = vm_storm_artifact(nonce + index * 1_000);
            let cell = package_key(*publisher, package_hash(&ProtocolHasher, &artifact));
            let tx = build_vm_publish_tx(key, artifact, validity);
            let shard = shards[usize::from(index)];
            submitted.push((tx.hash(), shard));
            cells.push((shard, cell.owner.0, cell.local.0));
            c.submit(Arc::new(tx));
        }
    }
    assert_eq!(
        cells
            .iter()
            .map(|(_, owner, local)| (*owner, *local))
            .collect::<BTreeSet<_>>()
            .len(),
        cells.len(),
        "the storm must deploy distinct packages, or it is one publish repeated"
    );

    for (hash, shard) in &submitted {
        let status = await_tx_terminal(c, *hash, epochs(24));
        assert!(
            matches!(
                status,
                Some(TransactionStatus::Completed(TransactionDecision::Accept))
            ),
            "a publish in the storm did not accept; status = {status:?}"
        );
        let (fate, _) = c.chain_fate(*shard, *hash);
        assert!(
            fate.is_some(),
            "the publisher's shard never committed its own publish"
        );
    }

    // Every package the storm deployed is in state, which is what makes
    // the distinctness above load-bearing: idempotent duplicates would
    // collapse into one cell and the storm would be a single publish.
    for (shard, owner, local) in &cells {
        assert!(
            c.vm_substate(*shard, *owner, *local).is_some(),
            "{shard:?} does not hold the package cell the storm published"
        );
    }

    for (shard, height) in shards.iter().zip(before) {
        let after = c.committed_height(*shard);
        assert!(
            after > height,
            "{shard:?} did not advance through the storm: {height:?} -> {after:?}"
        );
    }
}
