//! Block-proposal helpers used by the shard consensus-driven dispatch arms.
//!
//! Both the post-dispatch proposal-retry hook and the QC-formed path build
//! proposals from the same triple — ready txs from mempool, finalized waves
//! from execution, queued provisions — so the gather logic lives once here.

use std::sync::Arc;

use hyperscale_core::Action;
use hyperscale_types::{
    FinalizedWave, MAX_TXS_PER_BLOCK, Provisions, TopologySchedule, TopologySnapshot, Transaction,
    Verifiable, Verified,
};

use super::ShardParticipation;

/// Inputs gathered for building a block proposal.
pub(in crate::state) struct ProposalInputs {
    pub ready_txs: Vec<Arc<Verified<Transaction>>>,
    pub finalized_waves: Vec<Arc<Verifiable<FinalizedWave>>>,
    pub provisions: Vec<Arc<Verifiable<Provisions>>>,
}

impl ShardParticipation {
    /// Gather all inputs needed for a block proposal.
    ///
    /// Used by both `on_proposal_timer` and `on_qc_formed` to avoid duplicating
    /// the ready-transaction + abort intents + certificates gathering logic.
    pub(in crate::state) fn gather_proposal_inputs(
        &self,
        sched: &TopologySchedule,
        pending_txs: usize,
        pending_certs: usize,
    ) -> ProposalInputs {
        // Request extra transactions from the mempool to compensate for QC-chain
        // duplicates that will be filtered by shard consensus during proposal building.
        let max_txs = MAX_TXS_PER_BLOCK + self.shard_coordinator.dedup_overhead();
        // Reshape-boundary quiesce: in a shard's final epoch before it
        // terminates at a split or merge, stop selecting transactions that
        // can't settle before the cut. `None` in steady state, so the
        // mempool filter is inert.
        let quiesce = self.shard_coordinator.quiesce_cut(sched);
        let ready_txs = self.mempool_coordinator.ready_transactions(
            max_txs,
            pending_txs,
            pending_certs,
            self.now,
            quiesce,
        );
        let finalized_waves = self.execution_coordinator.get_finalized_waves();
        let queued = self.provisions_coordinator.queued_provisions(self.now);

        // The engagement gate: a non-payer shard proposes a cross-shard
        // transaction only beside its payer bundle — this proposal's
        // own provisions — or after an earlier block absorbed it. The
        // bundle is the transaction commit proof (verified against a
        // commit-proven payer header), so locks engage only on committed
        // payer evidence; a mis-paired inclusion is backstopped by the
        // dispatch gate's required-set check.
        let topology = sched.head();
        // A transaction takes its mempool lock when its block commits,
        // and this selects while earlier blocks are still uncommitted —
        // the pipeline is deeper than the lock window, so the ready set
        // alone would let two conflicting transactions into two blocks
        // and both would execute against the same baseline. The window
        // the lock set does not yet cover is read back out of chain
        // content and excluded here.
        let in_flight = self.shard_coordinator.in_flight_admission_keys();
        let ready_txs = ready_txs
            .into_iter()
            .filter(|tx| {
                in_flight.is_empty()
                    || !tx
                        .admission_keys()
                        .iter()
                        .any(|key| in_flight.contains(key))
            })
            .filter(|tx| self.engagement_held(tx, topology, &queued))
            .collect();

        // Provisions coordinator stores `Verified` internally; lift each
        // batch into the `Verifiable` transport shape so the marker
        // survives across the proposal-build action.
        let provisions = queued
            .into_iter()
            .map(|v| Arc::new((*v).clone().into()))
            .collect();

        ProposalInputs {
            ready_txs,
            finalized_waves,
            provisions,
        }
    }

    /// Whether the engagement evidence for `tx` is in hand: not a
    /// transaction, single-shard, our shard is the payer's, the payer's
    /// bundle rides in `queued`, or an earlier block already absorbed it.
    fn engagement_held(
        &self,
        tx: &Arc<Verified<Transaction>>,
        topology: &TopologySnapshot,
        queued: &[Arc<Verified<Provisions>>],
    ) -> bool {
        if topology.is_single_shard_transaction(tx.as_ref()) {
            return true;
        }
        let payer_shard = topology
            .shard_trie()
            .shard_for_prefix(tx.body().fee_payer.0);
        if payer_shard == self.local_shard {
            return true;
        }
        let tx_hash = tx.hash();
        self.execution_coordinator
            .has_provisions_from(tx_hash, payer_shard)
            || queued.iter().any(|bundle| {
                bundle.source_shard() == payer_shard
                    && bundle
                        .transactions()
                        .iter()
                        .any(|entry| entry.tx_hash == tx_hash)
            })
    }

    /// Shared proposal logic for the post-dispatch retry hook and the
    /// QC-formed path.
    pub(in crate::state) fn try_event_driven_proposal(
        &mut self,
        sched: &TopologySchedule,
    ) -> Vec<Action> {
        let (pending_txs, pending_certs) = self.shard_coordinator.pending_block_counts();
        let inputs = self.gather_proposal_inputs(sched, pending_txs, pending_certs);

        self.shard_coordinator.try_propose(
            sched,
            &inputs.ready_txs,
            inputs.finalized_waves,
            inputs.provisions,
        )
    }
}
