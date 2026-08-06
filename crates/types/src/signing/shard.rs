//! Signing messages for shard consensus.

use hyperscale_hbor::Hbor;

use crate::{BlockHash, BlockHeight, NetworkDefinition, Round, ShardId};

/// What a block vote's signature covers.
///
/// Used for individual block vote signatures, QC aggregated signature
/// verification, and view-change `highest_qc` verification.
/// `parent_block_hash` is bound in so the QC's committable-block selector
/// (the two-chain rule) is authenticated by the quorum, not merely
/// trusted.
#[derive(Debug, Clone, PartialEq, Eq, Hbor)]
#[hbor(signing_domain = "BLOCK_VOTE")]
pub struct BlockVoteMessage {
    /// Network the vote binds to — cross-network replay protection.
    pub network_id: u8,
    /// Shard whose consensus the vote belongs to.
    pub shard_group: ShardId,
    /// Height of the block being voted on.
    pub height: BlockHeight,
    /// Consensus round of the vote.
    pub round: Round,
    /// The block being voted on.
    pub block_hash: BlockHash,
    /// The voted block's parent.
    pub parent_block_hash: BlockHash,
}

impl BlockVoteMessage {
    /// Assemble the message a block vote signs.
    #[must_use]
    pub const fn new(
        network: &NetworkDefinition,
        shard_group: ShardId,
        height: BlockHeight,
        round: Round,
        block_hash: BlockHash,
        parent_block_hash: BlockHash,
    ) -> Self {
        Self {
            network_id: network.id,
            shard_group,
            height,
            round,
            block_hash,
            parent_block_hash,
        }
    }
}

/// What a block header proposal's signature covers.
///
/// Signed by the proposer when broadcasting block header proposals;
/// verified before admitting the proposal into shard consensus. A domain
/// of its own so a proposal signature can't stand in for a vote.
#[derive(Debug, Clone, PartialEq, Eq, Hbor)]
#[hbor(signing_domain = "BLOCK_HEADER")]
pub struct BlockHeaderMessage {
    /// Network the proposal binds to.
    pub network_id: u8,
    /// Shard whose consensus the proposal belongs to.
    pub shard_group: ShardId,
    /// Height of the proposed block.
    pub height: BlockHeight,
    /// Consensus round of the proposal.
    pub round: Round,
    /// The proposed block.
    pub block_hash: BlockHash,
}

impl BlockHeaderMessage {
    /// Assemble the message a block header proposal signs.
    #[must_use]
    pub const fn new(
        network: &NetworkDefinition,
        shard_group: ShardId,
        height: BlockHeight,
        round: Round,
        block_hash: BlockHash,
    ) -> Self {
        Self {
            network_id: network.id,
            shard_group,
            height,
            round,
            block_hash,
        }
    }
}

/// What a shard consensus timeout's signature covers.
///
/// Only `(shard, round)` — the timeout also carries the signer's
/// `high_qc`, but a QC is self-authenticating (it is its own 2f+1
/// aggregate), so its round need not be bound here.
#[derive(Debug, Clone, PartialEq, Eq, Hbor)]
#[hbor(signing_domain = "TIMEOUT")]
pub struct TimeoutMessage {
    /// Network the timeout binds to.
    pub network_id: u8,
    /// Shard whose round timed out.
    pub shard_group: ShardId,
    /// The round that timed out.
    pub round: Round,
}

impl TimeoutMessage {
    /// Assemble the message a timeout share signs.
    #[must_use]
    pub const fn new(network: &NetworkDefinition, shard_group: ShardId, round: Round) -> Self {
        Self {
            network_id: network.id,
            shard_group,
            round,
        }
    }
}

/// What a committed block header gossip's signature covers.
///
/// Signed by the sender when broadcasting committed block headers
/// globally; verified before admitting them to the state machine.
#[derive(Debug, Clone, PartialEq, Eq, Hbor)]
#[hbor(signing_domain = "COMMITTED_BLOCK_HEADER")]
pub struct CertifiedBlockHeaderMessage {
    /// Network the gossip binds to.
    pub network_id: u8,
    /// Shard the committed block belongs to.
    pub shard_id: ShardId,
    /// Height of the committed block.
    pub height: BlockHeight,
    /// The committed block.
    pub block_hash: BlockHash,
}

impl CertifiedBlockHeaderMessage {
    /// Assemble the message a committed-header broadcast signs.
    #[must_use]
    pub const fn new(
        network: &NetworkDefinition,
        shard_id: ShardId,
        height: BlockHeight,
        block_hash: BlockHash,
    ) -> Self {
        Self {
            network_id: network.id,
            shard_id,
            height,
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

    #[test]
    fn block_vote_message_binds_parent_block_hash() {
        let block = BlockHash::from_raw(Hash::from_bytes(b"test_block"));
        let parent_a = BlockHash::from_raw(Hash::from_bytes(b"parent_a"));
        let parent_b = BlockHash::from_raw(Hash::from_bytes(b"parent_b"));

        // Same block, different parent → different message. This is what
        // stops a proposer forging a QC's parent_block_hash to point at a
        // sibling block.
        let mk = |parent: BlockHash| {
            BlockVoteMessage::new(
                &net(),
                ShardId::ROOT,
                BlockHeight::new(10),
                Round::INITIAL,
                block,
                parent,
            )
            .signing_bytes()
            .unwrap()
        };
        assert_ne!(mk(parent_a), mk(parent_b));
    }
}
