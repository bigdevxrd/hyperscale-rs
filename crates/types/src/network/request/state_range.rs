//! Snap-sync state range request.

use hyperscale_hbor::Hbor;

use crate::network::response::GetStateRangeResponse;
use crate::{BlockHeight, Hash, MessageClass, NetworkMessage, Request};

/// Request a verified range of a shard's committed state at a pinned
/// epoch boundary.
///
/// Sent by a joining vnode bootstrapping the target shard's state
/// against its beacon-attested boundary anchor. The server reads from
/// the boundary pinned at `height` and answers leaves in hashed-key
/// order over `[start, end]`, with a completeness-checked range proof
/// against the boundary's `state_root`.
#[derive(Debug, Clone, PartialEq, Eq, Hbor)]
pub struct GetStateRangeRequest {
    /// The pinned boundary height — the anchor's block height, read from
    /// the projected `TopologySnapshot`.
    pub height: BlockHeight,
    /// First hashed JMT key of the requested range (inclusive).
    pub start: Hash,
    /// Last hashed JMT key of the requested range (inclusive).
    pub end: Hash,
    /// Requested leaf cap for this chunk. The server clamps to
    /// [`MAX_LEAVES_PER_STATE_RANGE`](crate::network::response::MAX_LEAVES_PER_STATE_RANGE)
    /// and may return fewer (byte budget); `more` signals continuation.
    pub limit: u32,
}

impl NetworkMessage for GetStateRangeRequest {
    fn message_type_id() -> &'static str {
        "state_range.request"
    }

    fn class() -> MessageClass {
        MessageClass::Bulk
    }
}

impl Request for GetStateRangeRequest {
    type Response = GetStateRangeResponse;

    fn is_empty_response(response: &Self::Response) -> bool {
        response.chunk.is_none()
    }
}

#[cfg(test)]
mod tests {
    use hyperscale_hbor::{from_slice as hbor_from_slice, to_vec as hbor_to_vec};

    use super::*;

    #[test]
    fn test_hbor_roundtrip() {
        let request = GetStateRangeRequest {
            height: BlockHeight::new(42),
            start: Hash::from_bytes(b"start"),
            end: Hash::from_bytes(b"end"),
            limit: 512,
        };

        let encoded = hbor_to_vec(&request).unwrap();
        let decoded: GetStateRangeRequest = hbor_from_slice(&encoded).unwrap();
        assert_eq!(request, decoded);
    }
}
