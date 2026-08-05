//! Merkle inclusion proof for cross-shard provisioning.

use hyperscale_hbor::Hbor;

use crate::MAX_MERKLE_PROOF_LEN;
use crate::bounded::BoundedBytes;

/// Merkle multiproof authenticating substates' inclusion in the JMT state tree.
///
/// Opaque bytes containing an encoded `hyperscale_jmt::MultiProof`. Encoding,
/// decoding and verification are handled by the storage crate, which owns
/// the adapter between the JMT crate and on-wire types.
///
/// The proof contains:
/// - Per-claimed-key termination metadata (leaf / empty-subtree / leaf-mismatch)
/// - Sibling hashes for bottom-up verification
#[derive(Debug, Clone, PartialEq, Eq, Hbor)]
#[hbor(transparent)]
pub struct MerkleInclusionProof(pub BoundedBytes<MAX_MERKLE_PROOF_LEN>);

impl MerkleInclusionProof {
    /// Create a new proof from raw bytes.
    #[must_use]
    pub fn new(bytes: Vec<u8>) -> Self {
        Self(BoundedBytes::from(bytes))
    }

    /// Get the raw proof bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Create a dummy (empty) proof for testing.
    #[cfg(any(test, feature = "test-utils"))]
    #[must_use]
    pub const fn dummy() -> Self {
        Self(BoundedBytes::new())
    }
}

#[cfg(test)]
mod tests {
    use hyperscale_hbor::{
        DecodeError, from_slice as hbor_from_slice, to_vec as hbor_to_vec, varint,
    };

    use super::*;

    #[test]
    fn roundtrip_preserves_bytes() {
        let proof = MerkleInclusionProof::new(vec![0xab; 1024]);
        let bytes = hbor_to_vec(&proof).unwrap();
        let decoded: MerkleInclusionProof = hbor_from_slice(&bytes).unwrap();
        assert_eq!(decoded, proof);
    }

    #[test]
    fn decode_rejects_oversized_proof() {
        let mut buf = Vec::new();
        varint::write(&mut buf, MAX_MERKLE_PROOF_LEN + 1).unwrap();
        buf.extend(std::iter::repeat_n(0u8, MAX_MERKLE_PROOF_LEN + 1));
        let err = hbor_from_slice::<MerkleInclusionProof>(&buf).unwrap_err();
        assert!(matches!(
            err,
            DecodeError::BoundExceeded { max, actual }
                if max == MAX_MERKLE_PROOF_LEN && actual == MAX_MERKLE_PROOF_LEN + 1
        ));
    }
}
