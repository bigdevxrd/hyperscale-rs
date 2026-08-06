//! Signing message for validator "ready on shard" signals.

use hyperscale_hbor::Hbor;

use crate::signing::NetworkId;
use crate::{ShardId, ValidatorId, WeightedTimestamp};

/// What a [`ReadySignal`](crate::ReadySignal) signature covers.
///
/// Signed by the validator and broadcast to their shard committee. The
/// `shard` binding names the shard whose synced state the signal attests,
/// so a signal from a validator's prior reshape seat cannot be re-credited
/// to a seat on a different shard. The proposer includes valid
/// dwell-eligible signals in the next block's manifest; verifiers rebuild
/// this message to check the signature before admitting the signal to
/// their local pool. The weighted-time window bounds replay surface — a
/// signal hoarded past `wt_window_end` no longer validates.
#[derive(Debug, Clone, PartialEq, Eq, Hbor)]
#[hbor(signing_domain = "HYPERSCALE_READY_SIGNAL_v1", signing_context = NetworkId)]
pub struct ReadySignalMessage {
    /// The validator declaring readiness.
    pub validator_id: ValidatorId,
    /// The shard whose synced state the signal attests.
    pub shard: ShardId,
    /// Start of the weighted-time validity window.
    pub wt_window_start: WeightedTimestamp,
    /// End of the weighted-time validity window.
    pub wt_window_end: WeightedTimestamp,
}
