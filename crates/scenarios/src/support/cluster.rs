//! The [`Cluster`] trait: the harness-agnostic surface a scenario drives.

use std::sync::Arc;
use std::time::Duration;

use hyperscale_crypto_bls::BlsSigner;
use hyperscale_mempool::DeferralStats;
use hyperscale_types::{
    BeaconState, BlockHeight, RoutableTransaction, ShardId, Signer, StateRoot, TransactionDecision,
    TransactionStatus, TxHash, VmEvent, VmSnapshotPin,
};

use super::Budget;

/// A running cluster of assembled nodes, observed and driven by a scenario.
///
/// Implemented twice — `SimCluster` over the in-process `SimulationRunner`
/// (logical clock) and `ProdCluster` over the production QUIC + `RocksDB` cluster
/// (wall-clock). The trait is the *intersection* of what both can do: a submit
/// rail, a clock-advancing [`run_until`](Cluster::run_until), and a handful of
/// synchronous observations. Anything derivable from these — beacon epoch,
/// split admission, anchor roots — lives in [`crate::query`] / [`crate::wait`]
/// as free combinators rather than as trait methods, so the two adaptors share
/// one definition and cannot silently diverge.
///
/// `run_until` takes `impl Fn(&Self) -> bool`, so the trait is not object-safe;
/// scenarios are generic (`fn scenario(c: &mut impl Cluster)`). The borrow is
/// sequential — the immutable closure borrow never overlaps the `&mut self`
/// advance inside `run_until`.
pub trait Cluster {
    /// Submit a transaction, routed to whichever host serves its source shard.
    fn submit(&mut self, tx: Arc<RoutableTransaction>);

    /// Advance the cluster until `cond` holds or `budget` epochs elapse;
    /// return whether `cond` held.
    ///
    /// Sim drives its logical clock (and pumps reshape); production blocks on a
    /// poll loop while reshape advances organically via the supervisor.
    fn run_until(&mut self, budget: Budget, cond: impl Fn(&Self) -> bool) -> bool;

    /// Elapsed time since genesis on the cluster's own clock — for building
    /// transaction validity windows. Sim returns its logical now; production
    /// returns wall-clock since start.
    fn now(&self) -> Duration;

    /// The highest committed block height on `shard`, if any host serves it.
    fn committed_height(&self, shard: ShardId) -> Option<BlockHeight>;

    /// The committed state root at `shard`'s tip, if any host serves it.
    fn committed_state_root(&self, shard: ShardId) -> Option<StateRoot>;

    /// Whether any host currently serves `shard`.
    fn serves_shard(&self, shard: ShardId) -> bool;

    /// The latest committed beacon state across the cluster (highest epoch).
    fn beacon_state(&self) -> Option<Arc<BeaconState>>;

    /// Upper bound on the wall-clock cost for a submitted governance vote to
    /// fold into the beacon: transaction inclusion, an epoch-boundary crossing
    /// carrying the vote leaf, and a beacon quorum observing that crossing.
    /// The cascade is priced by the harness's clock, not by epoch count — the
    /// default covers a logical-clock harness that delivers every hop in
    /// simulated milliseconds; a real-network cluster overrides with the
    /// seconds-per-hop cost it actually pays. Scenarios divide this by the
    /// epoch length to size epoch-denominated vote leads.
    fn vote_fold_budget_ms(&self) -> u64 {
        5_000
    }

    /// Derive a deterministic signer under the cluster's own crypto
    /// scheme — for fixtures that mint keys outside the hosted set
    /// (e.g. validator-registration witnesses, whose possession proofs
    /// the beacon fold verifies with the cluster's verifier). Defaults
    /// to BLS, the production scheme; the sim harness overrides per its
    /// configured scheme.
    fn signer_from_seed(&self, seed: &[u8; 32]) -> Arc<dyn Signer> {
        Arc::new(BlsSigner::from_seed(seed))
    }

    /// Aggregated mempool deferral statistics across every hosted vnode,
    /// when the harness can observe them synchronously. `None` on a
    /// harness whose node state is not reachable from the driving thread;
    /// scenarios treat the readout as optional.
    fn deferral_stats(&self) -> Option<DeferralStats> {
        None
    }

    /// The client-proven form of a bounded snapshot read: the cell's
    /// value and its JMT inclusion proof under `shard`'s latest committed
    /// root — what a wallet assembles before signing an envelope with a
    /// snapshot leg. `None` when no hosted store can serve the read.
    fn vm_snapshot_pin(
        &self,
        shard: ShardId,
        owner: [u8; 16],
        local: [u8; 16],
    ) -> Option<VmSnapshotPin> {
        let _ = (shard, owner, local);
        None
    }

    /// The VM events `shard`'s own copy of `tx`'s receipt carries.
    ///
    /// An event is stored where its emitter lives, so this differs by
    /// shard for a multi-shard transaction by design. `None` when no
    /// hosted store on `shard` holds the receipt.
    fn vm_events(&self, shard: ShardId, tx: TxHash) -> Option<Vec<VmEvent>> {
        let _ = (shard, tx);
        None
    }

    /// The status of `tx`, if any hosted mempool or execution still tracks it.
    fn tx_status(&self, tx: TxHash) -> Option<TransactionStatus>;

    /// Where `tx` landed on `shard`: the height it committed at (if any), and
    /// the height plus decision of its execution outcome (if any).
    fn chain_fate(
        &self,
        shard: ShardId,
        tx: TxHash,
    ) -> (
        Option<BlockHeight>,
        Option<(BlockHeight, TransactionDecision)>,
    );
}
