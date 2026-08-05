//! Execution certificate fetch request for fallback recovery.

use hyperscale_hbor::Hbor;

use crate::network::response::GetExecutionCertsResponse;
use crate::{MessageClass, NetworkMessage, Request, WaveId};

/// Request to fetch missing execution certificates from a source shard.
///
/// Sent by target shards when a remote block's wave leader fails to deliver
/// execution certs within the timeout window. Any node in the source shard
/// that has the cert cached can serve this request. The source-block height
/// for the storage fallback is derived from `wave_ids[0].block_height` —
/// every `WaveId` carries it and all ids in a single request share the
/// same source block by construction.
#[derive(Debug, Clone, PartialEq, Eq, Hbor)]
pub struct GetExecutionCertsRequest {
    /// Which waves' certs are missing.
    pub wave_ids: Vec<WaveId>,
}

impl NetworkMessage for GetExecutionCertsRequest {
    fn message_type_id() -> &'static str {
        "execution_cert.request"
    }

    fn class() -> MessageClass {
        MessageClass::CrossShardProgress
    }
}

impl Request for GetExecutionCertsRequest {
    type Response = GetExecutionCertsResponse;

    fn is_empty_response(response: &Self::Response) -> bool {
        response.certificates.as_ref().is_none_or(Vec::is_empty)
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use hyperscale_hbor::{from_slice as hbor_from_slice, to_vec as hbor_to_vec};

    use super::*;
    use crate::{BlockHeight, ShardId};

    #[test]
    fn test_hbor_roundtrip() {
        let request = GetExecutionCertsRequest {
            wave_ids: vec![WaveId::new(
                ShardId::leaf(2, 0),
                BlockHeight::new(42),
                BTreeSet::from([ShardId::leaf(2, 1), ShardId::leaf(2, 2)]),
            )],
        };

        let encoded = hbor_to_vec(&request).unwrap();
        let decoded: GetExecutionCertsRequest = hbor_from_slice(&encoded).unwrap();
        assert_eq!(request, decoded);
    }
}
