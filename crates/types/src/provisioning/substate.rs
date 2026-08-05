//! Pre-computed-key substate entries shipped between shards as provisions.

use hyperscale_hbor::Hbor;

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
#[derive(Debug, Clone, PartialEq, Eq, Hbor)]
pub struct SubstateEntry {
    /// Pre-computed full storage key (ready for direct DB lookup).
    /// Format: `db_node_key` (50 bytes) + partition (1 byte) + `sort_key`
    pub storage_key: BoundedBytes<MAX_STATE_ENTRY_KEY_LEN>,

    /// HBOR-encoded substate value (None if deleted/doesn't exist).
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
    use hyperscale_hbor::{
        DecodeError, from_slice as hbor_from_slice, to_vec as hbor_to_vec, varint,
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
    fn hbor_roundtrip_some_value() {
        let entry = SubstateEntry::test_entry([7u8; 16], b"sort", Some(vec![9u8; 128]));
        let bytes = hbor_to_vec(&entry).unwrap();
        let decoded: SubstateEntry = hbor_from_slice(&bytes).unwrap();
        assert_eq!(decoded, entry);
    }

    #[test]
    fn hbor_roundtrip_none_value() {
        let entry = SubstateEntry::test_entry([7u8; 16], b"sort", None);
        let bytes = hbor_to_vec(&entry).unwrap();
        let decoded: SubstateEntry = hbor_from_slice(&bytes).unwrap();
        assert_eq!(decoded, entry);
    }

    /// Encode an oversized `storage_key` directly (without going through
    /// `SubstateEntry::Encode`) and verify decode rejects it before allocation.
    #[test]
    fn decode_rejects_oversized_storage_key() {
        let mut buf = Vec::new();
        varint::write(&mut buf, MAX_STATE_ENTRY_KEY_LEN + 1).unwrap();
        buf.extend(std::iter::repeat_n(0u8, MAX_STATE_ENTRY_KEY_LEN + 2));
        let err = hbor_from_slice::<SubstateEntry>(&buf).unwrap_err();
        assert!(matches!(
            err,
            DecodeError::BoundExceeded { max, actual }
                if max == MAX_STATE_ENTRY_KEY_LEN && actual == MAX_STATE_ENTRY_KEY_LEN + 1
        ));
    }

    /// Same shape as above, but for the `Some(value)` byte-vector field.
    #[test]
    fn decode_rejects_oversized_value() {
        // Empty storage_key is fine; the bound check we want fires on `value`.
        let mut buf = hbor_to_vec(&Vec::<u8>::new()).unwrap();
        buf.push(1); // Some
        varint::write(&mut buf, MAX_STATE_ENTRY_VALUE_LEN + 1).unwrap();
        buf.extend(std::iter::repeat_n(0u8, MAX_STATE_ENTRY_VALUE_LEN + 1));
        let err = hbor_from_slice::<SubstateEntry>(&buf).unwrap_err();
        assert!(matches!(
            err,
            DecodeError::BoundExceeded { max, actual }
                if max == MAX_STATE_ENTRY_VALUE_LEN && actual == MAX_STATE_ENTRY_VALUE_LEN + 1
        ));
    }
}
