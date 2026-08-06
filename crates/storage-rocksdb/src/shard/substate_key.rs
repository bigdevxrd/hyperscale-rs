//! Substate key encoding for `RocksDB`.
//!
//! The `state` column family keys on a [`SubstateKey`]'s own 32 leaf
//! bytes — owner prefix, then local half. Both halves are fixed-width,
//! so the concatenation preserves lexicographic ordering for prefix
//! scans and decodes back without a length prefix.

use hyperscale_types::SubstateKey;

use crate::typed_cf::{DbCodec, DbEncode};

/// Codec for substate keys: the key's 32 leaf bytes, by identity.
#[derive(Default)]
pub struct SubstateKeyCodec;

impl DbEncode<SubstateKey> for SubstateKeyCodec {
    fn encode_to(&self, value: &SubstateKey, buf: &mut Vec<u8>) {
        buf.extend_from_slice(&value.to_bytes());
    }
}

impl DbCodec<SubstateKey> for SubstateKeyCodec {
    fn decode(&self, bytes: &[u8]) -> SubstateKey {
        let key: [u8; 32] = bytes.try_into().expect("a substate key is 32 bytes");
        SubstateKey::from_bytes(key)
    }
}
