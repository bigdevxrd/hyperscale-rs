//! Canonical state hashing.
//!
//! A substate's JMT leaf key is the key's own 32 bytes
//! ([`SubstateKey::to_bytes`](crate::SubstateKey::to_bytes)) — no
//! hashing, no owner map — so the storage backend and the cross-shard
//! provision proof verifier share the value hashing defined here and
//! nothing else.

use blake3::hash as blake3_hash;

/// Hash a substate value to the 32-byte value hash held in its JMT leaf.
#[must_use]
pub fn jmt_value_hash(value: &[u8]) -> [u8; 32] {
    *blake3_hash(value).as_bytes()
}
