//! Settled-waves window request for the split-boundary fence.
//!
//! After a shard `P` terminates at a split, a surviving counterpart must
//! decide, for any cross-shard wave still referencing `P`, whether `P`
//! actually settled that wave in its chain at or before the terminal block
//! `B`. It reads `P`'s beacon-attested `settled_waves_root` from its own
//! fold and fetches the whole window settled-wave list in one shot: the
//! complete set `S_P` of the **cross-shard** waves `P` settled over
//! `[B − RETENTION_HORIZON, B]` (single-shard waves are never queried, so
//! they are excluded). The requester accepts the list iff its recomputed
//! root equals the attested one, so a withheld wave changes the root and the
//! absence of any wave from the verified-complete set is sound (see
//! [`GetSettledWavesResponse`]).

use hyperscale_hbor::Hbor;

use crate::network::response::GetSettledWavesResponse;
use crate::{BlockHash, BlockHeight, MessageClass, NetworkMessage, Request};

/// Request a terminated shard's complete settled-wave window list,
/// anchored at its terminal block.
#[derive(Debug, Clone, PartialEq, Eq, Hbor)]
pub struct GetSettledWavesRequest {
    /// Height of the terminal block `B` the window ends at.
    pub terminal_height: BlockHeight,
    /// Expected hash of `B` — the beacon-attested terminal the requester
    /// reads from its fold. The server resolves `B` by height and answers
    /// `not_found` on a hash mismatch.
    pub terminal_block_hash: BlockHash,
}

impl GetSettledWavesRequest {
    /// Request the settled-wave window ending at terminal block
    /// `(terminal_height, terminal_block_hash)`.
    #[must_use]
    pub const fn new(terminal_height: BlockHeight, terminal_block_hash: BlockHash) -> Self {
        Self {
            terminal_height,
            terminal_block_hash,
        }
    }
}

impl NetworkMessage for GetSettledWavesRequest {
    fn message_type_id() -> &'static str {
        "settled_waves.request"
    }

    fn class() -> MessageClass {
        MessageClass::Bulk
    }
}

impl Request for GetSettledWavesRequest {
    type Response = GetSettledWavesResponse;

    fn is_empty_response(response: &Self::Response) -> bool {
        response.waves.is_none()
    }
}

#[cfg(test)]
mod tests {
    use hyperscale_hbor::{from_slice as hbor_from_slice, to_vec as hbor_to_vec};

    use super::*;
    use crate::Hash;

    #[test]
    fn test_hbor_roundtrip() {
        let request = GetSettledWavesRequest::new(
            BlockHeight::new(98),
            BlockHash::from_raw(Hash::from_bytes(b"terminal")),
        );
        let encoded = hbor_to_vec(&request).unwrap();
        let decoded: GetSettledWavesRequest = hbor_from_slice(&encoded).unwrap();
        assert_eq!(request, decoded);
    }
}
