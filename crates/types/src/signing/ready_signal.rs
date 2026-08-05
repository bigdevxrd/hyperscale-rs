//! Signing message for validator "ready on shard" signals.

use hyperscale_hbor::Hbor;

use crate::{NetworkDefinition, ShardId, ValidatorId, WeightedTimestamp};

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
#[hbor(signing_domain = "HYPERSCALE_READY_SIGNAL_v1")]
pub struct ReadySignalMessage {
    /// Network the signal binds to.
    pub network_id: u8,
    /// The validator declaring readiness.
    pub validator_id: ValidatorId,
    /// The shard whose synced state the signal attests.
    pub shard: ShardId,
    /// Start of the weighted-time validity window.
    pub wt_window_start: WeightedTimestamp,
    /// End of the weighted-time validity window.
    pub wt_window_end: WeightedTimestamp,
}

impl ReadySignalMessage {
    /// Assemble the message a ready signal signs.
    #[must_use]
    pub const fn new(
        network: &NetworkDefinition,
        validator_id: ValidatorId,
        shard: ShardId,
        wt_window_start: WeightedTimestamp,
        wt_window_end: WeightedTimestamp,
    ) -> Self {
        Self {
            network_id: network.id,
            validator_id,
            shard,
            wt_window_start,
            wt_window_end,
        }
    }
}

#[cfg(test)]
mod tests {
    use hyperscale_hbor::HborSigned;

    use super::*;

    fn net() -> NetworkDefinition {
        NetworkDefinition::simulator()
    }

    #[test]
    fn ready_signal_message_differs_by_window() {
        let mk = |end: u64| {
            ReadySignalMessage::new(
                &net(),
                ValidatorId::new(7),
                ShardId::ROOT,
                WeightedTimestamp::from_millis(0),
                WeightedTimestamp::from_millis(end),
            )
            .signing_bytes()
            .unwrap()
        };
        assert_ne!(mk(1), mk(2));
    }

    #[test]
    fn ready_signal_message_differs_by_shard() {
        let (left, right) = ShardId::ROOT.children();
        let mk = |shard: ShardId| {
            ReadySignalMessage::new(
                &net(),
                ValidatorId::new(7),
                shard,
                WeightedTimestamp::from_millis(0),
                WeightedTimestamp::from_millis(1),
            )
            .signing_bytes()
            .unwrap()
        };
        assert_ne!(mk(left), mk(right));
    }
}
