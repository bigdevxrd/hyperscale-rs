//! Snap-sync state range response.

use hyperscale_hbor::Hbor;
use hyperscale_vm_types::MAX_CELL_VALUE_LEN;

use crate::{MerkleInclusionProof, MessageClass, NetworkMessage, SubstateKey};

/// Cap on the leaves a single state range chunk can carry.
///
/// Bounds the response decode and the server's per-chunk enumeration;
/// a joiner paginates with `more` + cursor continuation, so the cap
/// sizes chunks, not the total transfer.
pub const MAX_LEAVES_PER_STATE_RANGE: usize = 1_024;

/// One leaf of a state range: the substate pair it represents.
///
/// The verifier trusts none of it bare: the key's own 32 bytes are the
/// JMT leaf key and must prove into the shard's attested `state_root`
/// via the chunk's range proof, and the proof's claimed value hash must
/// equal the hash of `value`.
#[derive(Debug, Clone, PartialEq, Eq, Hbor)]
pub struct StateRangeLeaf {
    /// The substate's key — its JMT leaf key by identity.
    pub key: SubstateKey,
    /// The raw substate value, bounded like a provisioned entry's.
    #[hbor(max = MAX_CELL_VALUE_LEN)]
    pub value: Vec<u8>,
}

/// A served chunk of a shard's state at a pinned boundary: leaves in
/// ascending hashed-key order plus the completeness-checked range proof
/// over them.
#[derive(Debug, Clone, PartialEq, Eq, Hbor)]
pub struct StateRangeChunk {
    /// Substate entries, strictly ascending by key.
    #[hbor(max = MAX_LEAVES_PER_STATE_RANGE)]
    pub leaves: Vec<StateRangeLeaf>,
    /// Whether leaves beyond the last returned remain in the requested
    /// range — the chunk is complete only through its last leaf, and the
    /// joiner resumes immediately after it.
    pub more: bool,
    /// Encoded range proof (`MultiProof` wire format) for the chunk,
    /// verified against the shard's beacon-attested boundary
    /// `state_root`.
    pub proof: MerkleInclusionProof,
}

/// Response to a
/// [`GetStateRangeRequest`](crate::network::request::GetStateRangeRequest).
#[derive(Debug, Clone, PartialEq, Eq, Hbor)]
pub struct GetStateRangeResponse {
    /// The served chunk, or `None` when this peer cannot serve the
    /// requested boundary (never pinned, or evicted from its ring) —
    /// the requester should try a different peer.
    pub chunk: Option<StateRangeChunk>,
}

impl NetworkMessage for GetStateRangeResponse {
    fn message_type_id() -> &'static str {
        "state_range.response"
    }

    fn class() -> MessageClass {
        MessageClass::Bulk
    }
}

#[cfg(test)]
mod tests {
    use hyperscale_hbor::{from_slice as hbor_from_slice, to_vec as hbor_to_vec};

    use super::*;

    #[test]
    fn test_hbor_roundtrip_unavailable() {
        let response = GetStateRangeResponse { chunk: None };

        let encoded = hbor_to_vec(&response).unwrap();
        let decoded: GetStateRangeResponse = hbor_from_slice(&encoded).unwrap();
        assert_eq!(response, decoded);
    }

    #[test]
    fn test_hbor_roundtrip_chunk() {
        let leaf = StateRangeLeaf {
            key: SubstateKey::from_bytes([7u8; 32]),
            value: vec![9u8; 128],
        };
        let response = GetStateRangeResponse {
            chunk: Some(StateRangeChunk {
                leaves: vec![leaf],
                more: true,
                proof: MerkleInclusionProof::new(vec![1, 2, 3]),
            }),
        };

        let encoded = hbor_to_vec(&response).unwrap();
        let decoded: GetStateRangeResponse = hbor_from_slice(&encoded).unwrap();
        assert_eq!(response, decoded);
    }
}
