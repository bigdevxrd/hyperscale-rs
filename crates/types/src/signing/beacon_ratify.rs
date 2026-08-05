//! Signing message for beacon epoch-ratification votes.
//!
//! Each active validator ratifies a beacon block for an epoch by signing
//! `(anchor_hash, epoch, round, phase, block_hash)`. A prevote and a
//! precommit at the same round sign different bytes, so neither can stand
//! in for the other; a quorum of precommits over the same tuple
//! aggregates into a [`RatifyCert`](crate::RatifyCert) committing the
//! block.
//!
//! The signing domain keeps a ratify sig from being confused with a PC
//! vote, a VRF reveal, or any other consensus message reusing the same
//! key material.

use hyperscale_hbor::Hbor;

use crate::{BeaconBlockHash, Epoch, NetworkDefinition, RatifyPhase, RatifyRound};

/// What a ratify vote's signature covers — also the message behind the
/// aggregate signature on the assembled
/// [`RatifyCert`](crate::RatifyCert).
#[derive(Debug, Clone, PartialEq, Eq, Hbor)]
#[hbor(signing_domain = "HYPERSCALE_RATIFY_VOTE_v1")]
pub struct RatifyVoteMessage {
    /// Network the vote binds to.
    pub network_id: u8,
    /// The commit-anchor hash the ratification round runs under.
    pub anchor_hash: BeaconBlockHash,
    /// The epoch being ratified.
    pub epoch: Epoch,
    /// Ratification round.
    pub round: RatifyRound,
    /// Prevote or precommit — the phase byte is load-bearing: without it
    /// a single signature could count toward both a polka and a commit.
    pub phase: RatifyPhase,
    /// The beacon block being ratified.
    pub block_hash: BeaconBlockHash,
}

impl RatifyVoteMessage {
    /// Assemble the message a ratify vote signs.
    #[must_use]
    pub const fn new(
        network: &NetworkDefinition,
        anchor_hash: BeaconBlockHash,
        epoch: Epoch,
        round: RatifyRound,
        phase: RatifyPhase,
        block_hash: BeaconBlockHash,
    ) -> Self {
        Self {
            network_id: network.id,
            anchor_hash,
            epoch,
            round,
            phase,
            block_hash,
        }
    }
}

#[cfg(test)]
mod tests {
    use hyperscale_hbor::HborSigned;

    use super::*;
    use crate::Hash;

    fn net() -> NetworkDefinition {
        NetworkDefinition::simulator()
    }

    fn anchor() -> BeaconBlockHash {
        BeaconBlockHash::from_raw(Hash::from_bytes(b"anchor"))
    }

    fn block() -> BeaconBlockHash {
        BeaconBlockHash::from_raw(Hash::from_bytes(b"block"))
    }

    /// A prevote and a precommit over the same tuple sign different
    /// bytes.
    #[test]
    fn ratify_vote_message_differs_across_phases() {
        let mk = |phase| {
            RatifyVoteMessage::new(
                &net(),
                anchor(),
                Epoch::new(5),
                RatifyRound::INITIAL,
                phase,
                block(),
            )
            .signing_bytes()
            .unwrap()
        };
        assert_ne!(mk(RatifyPhase::Prevote), mk(RatifyPhase::Precommit));
    }

    #[test]
    fn ratify_vote_message_differs_across_rounds() {
        let mk = |round| {
            RatifyVoteMessage::new(
                &net(),
                anchor(),
                Epoch::new(5),
                round,
                RatifyPhase::Prevote,
                block(),
            )
            .signing_bytes()
            .unwrap()
        };
        assert_ne!(mk(RatifyRound::new(1)), mk(RatifyRound::new(2)));
    }

    #[test]
    fn ratify_vote_message_differs_across_networks() {
        let mk = |n: &NetworkDefinition| {
            RatifyVoteMessage::new(
                n,
                anchor(),
                Epoch::new(5),
                RatifyRound::INITIAL,
                RatifyPhase::Prevote,
                block(),
            )
            .signing_bytes()
            .unwrap()
        };
        assert_ne!(
            mk(&NetworkDefinition::mainnet()),
            mk(&NetworkDefinition::stokenet())
        );
    }
}
