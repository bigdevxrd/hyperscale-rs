//! Signing messages for execution votes and certificate gossip.

use blake3::Hasher;
use hyperscale_hbor::Hbor;

use crate::signing::NetworkId;
use crate::{
    ExecutionCertificate, ExecutionVote, GlobalReceiptRoot, Hash, ShardId, WaveId,
    WeightedTimestamp,
};

/// What an execution vote's signature covers.
///
/// Used for both individual [`ExecutionVote`] signatures and
/// [`ExecutionCertificate`] aggregated signature verification. The
/// `wave_id` is self-contained (shard + block height + remote shards), so
/// no separate block hash is needed.
#[derive(Debug, Clone, PartialEq, Eq, Hbor)]
#[hbor(signing_domain = "EXEC_VOTE", signing_context = NetworkId)]
pub struct ExecVoteMessage {
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

/// What an execution-vote batch gossip signature covers: the shard plus a
/// digest of the batch's receipt roots.
#[derive(Debug, Clone, PartialEq, Eq, Hbor)]
#[hbor(signing_domain = "EXEC_VOTE_BATCH", signing_context = NetworkId)]
pub struct ExecVoteBatchMessage {
    /// Shard the votes belong to.
    pub shard_group: ShardId,
    /// Digest over the batch's `global_receipt_root`s, in batch order.
    pub roots_digest: Hash,
}

impl ExecVoteBatchMessage {
    /// Assemble the message an execution-vote batch signs.
    #[must_use]
    pub fn new<'a, I>(shard_group: ShardId, votes: I) -> Self
    where
        I: IntoIterator<Item = &'a ExecutionVote>,
    {
        let mut hasher = Hasher::new();
        for v in votes {
            hasher.update(v.global_receipt_root().as_raw().as_bytes());
        }
        Self {
            shard_group,
            roots_digest: Hash::from_hash_bytes(hasher.finalize().as_bytes()),
        }
    }
}

/// What an execution-certificate batch gossip signature covers — same
/// shape as [`ExecVoteBatchMessage`] under its own domain.
#[derive(Debug, Clone, PartialEq, Eq, Hbor)]
#[hbor(signing_domain = "EXEC_CERT_BATCH", signing_context = NetworkId)]
pub struct ExecCertBatchMessage {
    /// Shard the certificates belong to.
    pub shard_group: ShardId,
    /// Digest over the batch's `global_receipt_root`s, in batch order.
    pub roots_digest: Hash,
}

impl ExecCertBatchMessage {
    /// Assemble the message an execution-certificate batch signs.
    #[must_use]
    pub fn new(shard_group: ShardId, certificates: &[ExecutionCertificate]) -> Self {
        let mut hasher = Hasher::new();
        for c in certificates {
            hasher.update(c.global_receipt_root().as_raw().as_bytes());
        }
        Self {
            shard_group,
            roots_digest: Hash::from_hash_bytes(hasher.finalize().as_bytes()),
        }
    }
}
