//! Finalized wave fetch response (intra-shard DA).

use std::sync::Arc;

use hyperscale_hbor::Hbor;

use crate::{FinalizedWave, MessageClass, NetworkMessage};

/// Cap on finalized waves returned in a single response at decode time.
///
/// Matches the per-collection cap used by [`hyperscale_types::Block`].
/// The fetch dispatcher chunks finalized-wave requests at 4 ids per call,
/// so legitimate responses sit in single digits; everything beyond is
/// rejected before any per-wave decode work.
const MAX_FINALIZED_WAVES_PER_RESPONSE: usize = 10_000;

/// Response to a finalized wave fetch request.
///
/// Contains the requested finalized waves that the responder has.
/// Missing waves are simply not included in the response.
#[derive(Debug, Clone, Hbor)]
pub struct GetFinalizedWavesResponse {
    /// The requested finalized waves that were found.
    ///
    /// `Arc`-wrapped because both the server-side cache and every
    /// downstream consumer hold `FinalizedWave` behind `Arc` already.
    #[hbor(max = MAX_FINALIZED_WAVES_PER_RESPONSE)]
    pub waves: Vec<Arc<FinalizedWave>>,
}

impl GetFinalizedWavesResponse {
    /// Build a response carrying the supplied finalized waves.
    ///
    /// # Panics
    ///
    /// Panics if `waves.len() > MAX_FINALIZED_WAVES_PER_RESPONSE`.
    #[must_use]
    pub const fn new(waves: Vec<Arc<FinalizedWave>>) -> Self {
        Self { waves }
    }

    /// Build an empty response (responder had none of the requested waves).
    #[must_use]
    pub const fn empty() -> Self {
        Self { waves: Vec::new() }
    }
}

impl NetworkMessage for GetFinalizedWavesResponse {
    fn message_type_id() -> &'static str {
        "finalized_wave.response"
    }

    fn class() -> MessageClass {
        MessageClass::BlockCompletion
    }
}

#[cfg(test)]
mod tests {
    use hyperscale_hbor::{
        DecodeError, from_slice as hbor_from_slice, to_vec as hbor_to_vec, varint,
    };

    use super::*;

    #[test]
    fn decode_rejects_oversized_waves_count() {
        // Hand-roll a response whose waves length prefix exceeds the cap.
        // The cap fires before any per-wave decode work is attempted.
        let mut buf = Vec::new();
        varint::write(&mut buf, MAX_FINALIZED_WAVES_PER_RESPONSE + 1).unwrap();
        buf.extend(std::iter::repeat_n(
            0u8,
            (MAX_FINALIZED_WAVES_PER_RESPONSE + 1) * 256,
        ));
        let err = hbor_from_slice::<GetFinalizedWavesResponse>(&buf).unwrap_err();
        assert!(matches!(
            err,
            DecodeError::BoundExceeded { max, actual }
                if max == MAX_FINALIZED_WAVES_PER_RESPONSE
                    && actual == MAX_FINALIZED_WAVES_PER_RESPONSE + 1
        ));
    }

    #[test]
    fn empty_response_roundtrips() {
        let original = GetFinalizedWavesResponse::empty();
        let bytes = hbor_to_vec(&original).unwrap();
        let decoded: GetFinalizedWavesResponse = hbor_from_slice(&bytes).unwrap();
        assert!(decoded.waves.is_empty());
    }
}
