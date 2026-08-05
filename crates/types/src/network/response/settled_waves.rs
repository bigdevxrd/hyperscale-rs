//! Settled-waves window response for the split-boundary fence.

use hyperscale_hbor::Hbor;

use crate::{MAX_FINALIZED_TX_PER_BLOCK, MessageClass, NetworkMessage, WaveId};

/// The complete settled-wave window list of a terminated shard.
///
/// `waves` is `S_P` in full: every **cross-shard** wave-id `P` settled in
/// `[B − RETENTION_HORIZON, B]`. Single-shard waves are excluded — they are
/// never the subject of a counterpart's fence query — so the list is
/// proportional to cross-shard traffic, not total throughput. Verified, not
/// trusted bare — the requester recomputes `settled_waves_root_from_ids(waves)`
/// and accepts only when it equals the beacon-attested `settled_waves_root`.
/// Because the root commits the whole set, a server can neither hide a
/// settled wave (a missing leaf changes the root) nor fabricate one, so the
/// verified-complete set makes the absence of any wave from it sound.
#[derive(Debug, Clone, PartialEq, Eq, Hbor)]
pub struct GetSettledWavesResponse {
    /// The terminated shard's complete settled-wave window list, or `None`
    /// when this peer doesn't hold the terminal block — the requester
    /// rotates to another terminal-committee member.
    #[hbor(max = MAX_FINALIZED_TX_PER_BLOCK)]
    pub waves: Option<Vec<WaveId>>,
}

/// The window-list cap, checked at the wire boundary.
impl GetSettledWavesResponse {
    /// A complete window list for the terminated shard.
    #[must_use]
    pub const fn found(waves: Vec<WaveId>) -> Self {
        Self { waves: Some(waves) }
    }

    /// This peer can't serve the requested terminal block.
    #[must_use]
    pub const fn not_found() -> Self {
        Self { waves: None }
    }
}

impl NetworkMessage for GetSettledWavesResponse {
    fn message_type_id() -> &'static str {
        "settled_waves.response"
    }

    fn class() -> MessageClass {
        MessageClass::Bulk
    }
}

#[cfg(test)]
mod tests {
    use hyperscale_hbor::{from_slice as hbor_from_slice, to_vec as hbor_to_vec};

    use super::*;
    use crate::{BlockHeight, ShardId};

    #[test]
    fn test_hbor_roundtrip_not_found() {
        let response = GetSettledWavesResponse::not_found();
        let encoded = hbor_to_vec(&response).unwrap();
        let decoded: GetSettledWavesResponse = hbor_from_slice(&encoded).unwrap();
        assert_eq!(response, decoded);
    }

    #[test]
    fn test_hbor_roundtrip_found() {
        let wave = WaveId::new(
            ShardId::ROOT,
            BlockHeight::new(7),
            std::iter::empty().collect(),
        );
        let response = GetSettledWavesResponse::found(vec![wave]);
        let encoded = hbor_to_vec(&response).unwrap();
        let decoded: GetSettledWavesResponse = hbor_from_slice(&encoded).unwrap();
        assert_eq!(response, decoded);
    }
}
