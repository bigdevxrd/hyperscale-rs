//! Signing message for cross-shard state provisions gossip.

use blake3::Hasher;
use hyperscale_hbor::Hbor;

use crate::{BlockHeight, Hash, NetworkDefinition, Provisions, ShardId};

/// What a state-provisions gossip signature covers: the route, the source
/// height, and a digest of the transaction hashes in the bundle.
///
/// Cheap to reconstruct at verification while binding the signature to the
/// specific bundle contents, so unauthenticated provision spam is rejected
/// before expensive merkle proof verification.
#[derive(Debug, Clone, PartialEq, Eq, Hbor)]
#[hbor(signing_domain = "STATE_PROVISION_BATCH")]
pub struct StateProvisionsMessage {
    /// Network the bundle binds to.
    pub network_id: u8,
    /// Shard the bundle was produced on.
    pub source_shard: ShardId,
    /// Shard the bundle serves.
    pub target_shard: ShardId,
    /// Source block height the bundle belongs to.
    pub block_height: BlockHeight,
    /// Digest over the bundle's transaction hashes, in bundle order.
    pub tx_digest: Hash,
}

impl StateProvisionsMessage {
    /// Assemble the message a provisions broadcast signs.
    #[must_use]
    pub fn new(network: &NetworkDefinition, provisions: &Provisions) -> Self {
        let mut hasher = Hasher::new();
        for tx in provisions.transactions() {
            hasher.update(tx.tx_hash.as_bytes());
        }
        Self {
            network_id: network.id,
            source_shard: provisions.source_shard(),
            target_shard: provisions.target_shard(),
            block_height: provisions.block_height(),
            tx_digest: Hash::from_hash_bytes(hasher.finalize().as_bytes()),
        }
    }
}
