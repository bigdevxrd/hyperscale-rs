//! Transaction fetch request.

use hyperscale_hbor::Hbor;

use crate::network::response::GetTransactionsResponse;
use crate::{MessageClass, NetworkMessage, Request, TxHash};

/// Request to fetch transactions by hash.
///
/// Used when a validator is missing transactions referenced by a pending
/// block (or by any other consumer waiting on tx data). The responder
/// resolves each hash from local state — no scope information is needed.
#[derive(Debug, Clone, PartialEq, Eq, Hbor)]
pub struct GetTransactionsRequest {
    /// Hashes of the transactions being requested.
    pub tx_hashes: Vec<TxHash>,
}

impl GetTransactionsRequest {
    /// Create a new transaction fetch request.
    #[must_use]
    pub const fn new(tx_hashes: Vec<TxHash>) -> Self {
        Self { tx_hashes }
    }

    /// Get the number of transactions being requested.
    #[must_use]
    pub const fn count(&self) -> usize {
        self.tx_hashes.len()
    }
}

// Network message implementation
impl NetworkMessage for GetTransactionsRequest {
    fn message_type_id() -> &'static str {
        "transaction.request"
    }

    fn class() -> MessageClass {
        MessageClass::BlockCompletion
    }
}

/// Type-safe request/response pairing.
impl Request for GetTransactionsRequest {
    type Response = GetTransactionsResponse;

    fn is_empty_response(response: &Self::Response) -> bool {
        response.transactions.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use hyperscale_hbor::{from_slice as hbor_from_slice, to_vec as hbor_to_vec};

    use super::*;
    use crate::Hash;

    #[test]
    fn test_get_transactions_request() {
        let tx_hashes = vec![
            TxHash::from(Hash::from_bytes(b"tx1")),
            TxHash::from(Hash::from_bytes(b"tx2")),
            TxHash::from(Hash::from_bytes(b"tx3")),
        ];

        let request = GetTransactionsRequest::new(tx_hashes.clone());
        assert_eq!(request.tx_hashes, tx_hashes);
        assert_eq!(request.count(), 3);
    }

    #[test]
    fn test_hbor_roundtrip() {
        let request = GetTransactionsRequest::new(vec![TxHash::from(Hash::from_bytes(b"tx1"))]);
        let bytes = hbor_to_vec(&request).unwrap();
        let decoded: GetTransactionsRequest = hbor_from_slice(&bytes).unwrap();
        assert_eq!(request, decoded);
    }
}
