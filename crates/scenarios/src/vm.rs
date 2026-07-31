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

use std::sync::Arc;

use hyperscale_engine_vm::VM_XRD;
use hyperscale_engine_vm::genesis::vault_key;
use hyperscale_types::{NetworkDefinition, ShardId, TransactionDecision, TransactionStatus};

use crate::contention::{ContentionReport, Lcg, settle_and_report, zipf_cdf};
use crate::support::faultable::FaultableCluster;
use crate::support::tx::{
    VM_SNAPSHOT_GUARD_BALANCE, build_faucet_tx, build_vm_guarded_transfer_tx, build_vm_transfer_tx,
    contention_recipient, signer_from_seed, validity_around, vm_cross_shard_cast, vm_recipient,
    vm_sender, vm_snapshot_cast,
};
use crate::support::wait::{await_height, await_tx_terminal};
use crate::support::{Cluster, epochs};

/// Per-payment amount of the VM contention scenarios.
const PAYMENT: u128 = 5;

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

/// A dependent VM transfer reads its own block's attested baseline — the
/// consensus form of INV-VM-3's snapshot pinning.
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
pub fn vm_snapshot_reads_committed_baseline(c: &mut impl Cluster) {
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

/// A transaction whose only remote touch is a bounded snapshot read
/// settles its local leg while the guarded shard commits nothing.
///
/// With fresh reads the only shared admission class and snapshot targets
/// taking no key at all, the guarded shard drops out of participation
/// structurally: no lock, no wave slot, nothing to commit. The envelope
/// carries the guarded cell's client-proven pin — key, value, and JMT
/// inclusion proof under the guarded shard's committed root — so every
/// replica of the executing committee reads the signed cell.
///
/// # Panics
///
/// Panics if the harness cannot serve the pin, the transfer does not
/// accept, the local shard never commits it, the guarded shard's chain
/// carries it, or the guarded shard's state root moves.
pub fn vm_snapshot_only_commits_nothing(c: &mut impl Cluster) {
    let (payer, from, to, guard) = vm_snapshot_cast();
    let remote = ShardId::leaf(1, 1);
    let vault = vault_key(guard, VM_XRD);
    let pin = c
        .vm_snapshot_pin(remote, vault.owner.0, vault.local.0)
        .expect("the harness serves client-proven snapshot reads");
    assert_eq!(
        pin.value.as_deref().map(Vec::as_slice),
        Some(VM_SNAPSHOT_GUARD_BALANCE.to_le_bytes().as_slice()),
        "the pin must carry the guarded vault's genesis balance"
    );
    let root_before = c.committed_state_root(remote);

    let tx = build_vm_guarded_transfer_tx(
        &payer,
        from,
        to,
        100,
        guard,
        VM_SNAPSHOT_GUARD_BALANCE - 100,
        8,
        pin,
        validity_around(c.now()),
    );
    let hash = tx.hash();
    c.submit(Arc::new(tx));

    let status = await_tx_terminal(c, hash, epochs(16));
    assert!(
        matches!(
            status,
            Some(TransactionStatus::Completed(TransactionDecision::Accept))
        ),
        "guarded VM transfer did not accept; status = {status:?}"
    );
    let (local, _) = c.chain_fate(ShardId::leaf(1, 0), hash);
    assert!(
        local.is_some(),
        "the local shard never committed the guarded transfer"
    );
    // The guarded shard is structurally not a participant: its chain
    // never carries the transaction and its state never moves.
    let (remote_inclusion, _) = c.chain_fate(remote, hash);
    assert!(
        remote_inclusion.is_none(),
        "the guarded shard must not carry the transaction"
    );
    let root_after = c.committed_state_root(remote);
    assert_eq!(
        root_before, root_after,
        "the guarded shard must commit nothing"
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

/// The committed balance of a VM account's native vault, read through the
/// harness's client-proven snapshot seam.
fn vm_vault_balance(c: &impl Cluster, shard: ShardId, owner: [u8; 16]) -> u128 {
    let vault = vault_key(owner, VM_XRD);
    let pin = c
        .vm_snapshot_pin(shard, vault.owner.0, vault.local.0)
        .expect("the harness serves client-proven reads");
    pin.value.as_ref().map_or(0, |bytes| {
        let cell: [u8; 16] = bytes.as_slice().try_into().expect("an amount cell");
        u128::from_le_bytes(cell)
    })
}
