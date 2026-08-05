//! Pre-computed-key substate entries shipped between shards as provisions.

use sbor::prelude::*;

#[cfg(any(test, feature = "test-utils"))]
use crate::state_key::vm_flat_key;
use crate::{BoundedBytes, Hash, MAX_STATE_ENTRY_KEY_LEN, MAX_STATE_ENTRY_VALUE_LEN};

/// A state entry with pre-computed storage key for fast engine lookup.
///
/// This type stores the pre-computed storage key that can be used directly for
/// database lookups without any key transformation at the receiving shard.
///
/// The storage key format is: `db_node_key(50) + partition_num(1) + sort_key(var)`
/// where `db_node_key` is the `SpreadPrefixKeyMapper` hash (expensive to compute).
#[derive(Debug, Clone, PartialEq, Eq, BasicSbor)]
pub struct SubstateEntry {
    /// Pre-computed full storage key (ready for direct DB lookup).
    /// Format: `db_node_key` (50 bytes) + partition (1 byte) + `sort_key`
    pub storage_key: BoundedBytes<MAX_STATE_ENTRY_KEY_LEN>,

    /// SBOR-encoded substate value (None if deleted/doesn't exist).
    pub value: Option<BoundedBytes<MAX_STATE_ENTRY_VALUE_LEN>>,
}

impl SubstateEntry {
    /// Create a new DB state entry with pre-computed storage key.
    #[must_use]
    pub fn new(storage_key: Vec<u8>, value: Option<Vec<u8>>) -> Self {
        Self {
            storage_key: storage_key.into(),
            value: value.map(Into::into),
        }
    }

    /// Compute hash of this entry for signing/verification.
    #[must_use]
    pub fn hash(&self) -> Hash {
        let mut data = Vec::with_capacity(self.storage_key.len() + 32);
        data.extend_from_slice(&self.storage_key);

        match &self.value {
            Some(value_bytes) => {
                let value_hash = Hash::from_bytes(value_bytes);
                data.extend_from_slice(value_hash.as_bytes());
            }
            None => {
                data.extend_from_slice(&[0u8; 32]); // ZERO hash for deletion
            }
        }

        Hash::from_bytes(&data)
    }

    /// Create a test entry from a node ID (for testing only).
    ///
    /// Builds the flat storage key from the owner prefix and a local half
    /// zero-padded from `local`, so a fixture names a cell by a short seed
    /// and still produces a key every decoding path accepts.
    #[cfg(any(test, feature = "test-utils"))]
    #[must_use]
    pub fn test_entry(owner: [u8; 16], local: &[u8], value: Option<Vec<u8>>) -> Self {
        let mut half = [0u8; 16];
        let n = local.len().min(16);
        half[..n].copy_from_slice(&local[..n]);
        Self::new(vm_flat_key(owner, half), value)
    }
}
#[cfg(test)]
mod tests {
    use sbor::{
        BASIC_SBOR_V1_MAX_DEPTH, BASIC_SBOR_V1_PAYLOAD_PREFIX, DecodeError, Encoder as _,
        NoCustomValueKind, ValueKind, VecEncoder, basic_decode, basic_encode,
    };

    use super::*;

    #[test]
    fn test_substate_entry_hash() {
        let entry = SubstateEntry::test_entry([1u8; 16], b"key", Some(b"value".to_vec()));

        let hash1 = entry.hash();
        let hash2 = entry.hash();
        assert_eq!(hash1, hash2);
    }

    #[test]
    fn sbor_roundtrip_some_value() {
        let entry = SubstateEntry::test_entry([7u8; 16], b"sort", Some(vec![9u8; 128]));
        let bytes = basic_encode(&entry).unwrap();
        let decoded: SubstateEntry = basic_decode(&bytes).unwrap();
        assert_eq!(decoded, entry);
    }

    #[test]
    fn sbor_roundtrip_none_value() {
        let entry = SubstateEntry::test_entry([7u8; 16], b"sort", None);
        let bytes = basic_encode(&entry).unwrap();
        let decoded: SubstateEntry = basic_decode(&bytes).unwrap();
        assert_eq!(decoded, entry);
    }

    /// Encode an oversized `storage_key` directly (without going through
    /// `SubstateEntry::Encode`) and verify decode rejects it before allocation.
    #[test]
    fn decode_rejects_oversized_storage_key() {
        let mut buf = Vec::with_capacity(64);
        let mut enc = VecEncoder::<NoCustomValueKind>::new(&mut buf, BASIC_SBOR_V1_MAX_DEPTH);
        enc.write_payload_prefix(BASIC_SBOR_V1_PAYLOAD_PREFIX)
            .unwrap();
        enc.write_value_kind(ValueKind::Tuple).unwrap();
        enc.write_size(2).unwrap();
        enc.write_value_kind(ValueKind::Array).unwrap();
        enc.write_value_kind(ValueKind::U8).unwrap();
        enc.write_size(MAX_STATE_ENTRY_KEY_LEN + 1).unwrap();
        let err = basic_decode::<SubstateEntry>(&buf).unwrap_err();
        assert!(matches!(
            err,
            DecodeError::UnexpectedSize {
                expected: MAX_STATE_ENTRY_KEY_LEN,
                actual,
            } if actual == MAX_STATE_ENTRY_KEY_LEN + 1
        ));
    }

    /// Same shape as above, but for the `Some(value)` byte-vector field.
    #[test]
    fn decode_rejects_oversized_value() {
        let mut buf = Vec::with_capacity(64);
        let mut enc = VecEncoder::<NoCustomValueKind>::new(&mut buf, BASIC_SBOR_V1_MAX_DEPTH);
        enc.write_payload_prefix(BASIC_SBOR_V1_PAYLOAD_PREFIX)
            .unwrap();
        enc.write_value_kind(ValueKind::Tuple).unwrap();
        enc.write_size(2).unwrap();
        // Empty storage_key is fine; the bound check we want fires on `value`.
        enc.encode(&Vec::<u8>::new()).unwrap();
        enc.write_value_kind(ValueKind::Enum).unwrap();
        enc.write_discriminator(1).unwrap();
        enc.write_size(1).unwrap();
        enc.write_value_kind(ValueKind::Array).unwrap();
        enc.write_value_kind(ValueKind::U8).unwrap();
        enc.write_size(MAX_STATE_ENTRY_VALUE_LEN + 1).unwrap();
        let err = basic_decode::<SubstateEntry>(&buf).unwrap_err();
        assert!(matches!(
            err,
            DecodeError::UnexpectedSize {
                expected: MAX_STATE_ENTRY_VALUE_LEN,
                actual,
            } if actual == MAX_STATE_ENTRY_VALUE_LEN + 1
        ));
    }
}
