//! Signing messages for execution votes and certificate gossip.

use blake3::Hasher;
use hyperscale_hbor::Hbor;

use crate::{
    ExecutionCertificate, ExecutionVote, GlobalReceiptRoot, Hash, NetworkDefinition, ShardId,
    WaveId, WeightedTimestamp,
};

/// What an execution vote's signature covers.
///
/// Used for both individual [`ExecutionVote`] signatures and
/// [`ExecutionCertificate`] aggregated signature verification. The
/// `wave_id` is self-contained (shard + block height + remote shards), so
/// no separate block hash is needed.
#[derive(Debug, Clone, PartialEq, Eq, Hbor)]
#[hbor(signing_domain = "EXEC_VOTE")]
pub struct ExecVoteMessage {
    /// Network the vote binds to — cross-network replay protection.
    pub network_id: u8,
    /// BFT-authenticated anchor the vote was cast at.
    pub vote_anchor_ts: WeightedTimestamp,
    /// The wave being voted on.
    pub wave_id: WaveId,
    /// Shard casting the vote.
    pub shard_group: ShardId,
    /// Merkle root over per-tx outcome leaves.
    pub global_receipt_root: GlobalReceiptRoot,
    /// Number of transactions in the wave.
    pub tx_count: u32,
}

impl ExecVoteMessage {
    /// Assemble the message an execution vote signs.
    #[must_use]
    pub const fn new(
        network: &NetworkDefinition,
        vote_anchor_ts: WeightedTimestamp,
        wave_id: WaveId,
        shard_group: ShardId,
        global_receipt_root: GlobalReceiptRoot,
        tx_count: u32,
    ) -> Self {
        Self {
            network_id: network.id,
            vote_anchor_ts,
            wave_id,
            shard_group,
            global_receipt_root,
            tx_count,
        }
    }
}

/// What an execution-vote batch gossip signature covers: the shard plus a
/// digest of the batch's receipt roots.
#[derive(Debug, Clone, PartialEq, Eq, Hbor)]
#[hbor(signing_domain = "EXEC_VOTE_BATCH")]
pub struct ExecVoteBatchMessage {
    /// Network the batch binds to.
    pub network_id: u8,
    /// Shard the votes belong to.
    pub shard_group: ShardId,
    /// Digest over the batch's `global_receipt_root`s, in batch order.
    pub roots_digest: Hash,
}

impl ExecVoteBatchMessage {
    /// Assemble the message an execution-vote batch signs.
    #[must_use]
    pub fn new<'a, I>(network: &NetworkDefinition, shard_group: ShardId, votes: I) -> Self
    where
        I: IntoIterator<Item = &'a ExecutionVote>,
    {
        let mut hasher = Hasher::new();
        for v in votes {
            hasher.update(v.global_receipt_root().as_raw().as_bytes());
        }
        Self {
            network_id: network.id,
            shard_group,
            roots_digest: Hash::from_hash_bytes(hasher.finalize().as_bytes()),
        }
    }
}

/// What an execution-certificate batch gossip signature covers — same
/// shape as [`ExecVoteBatchMessage`] under its own domain.
#[derive(Debug, Clone, PartialEq, Eq, Hbor)]
#[hbor(signing_domain = "EXEC_CERT_BATCH")]
pub struct ExecCertBatchMessage {
    /// Network the batch binds to.
    pub network_id: u8,
    /// Shard the certificates belong to.
    pub shard_group: ShardId,
    /// Digest over the batch's `global_receipt_root`s, in batch order.
    pub roots_digest: Hash,
}

impl ExecCertBatchMessage {
    /// Assemble the message an execution-certificate batch signs.
    #[must_use]
    pub fn new(
        network: &NetworkDefinition,
        shard_group: ShardId,
        certificates: &[ExecutionCertificate],
    ) -> Self {
        let mut hasher = Hasher::new();
        for c in certificates {
            hasher.update(c.global_receipt_root().as_raw().as_bytes());
        }
        Self {
            network_id: network.id,
            shard_group,
            roots_digest: Hash::from_hash_bytes(hasher.finalize().as_bytes()),
        }
    }
}
