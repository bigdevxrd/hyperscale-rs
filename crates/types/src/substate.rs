//! The substate-store vocabulary: how a block's writes are described.
//!
//! A [`DatabaseUpdates`] is the canonical description of everything a
//! receipt changes, keyed the way storage lays it out — by entity, then
//! partition, then sort key. It rides in `ConsensusReceipt`, so it is
//! wire vocabulary as much as storage vocabulary, which is why it lives
//! here rather than in `hyperscale-storage`.
//!
//! Every map is an [`IndexMap`]: iteration is insertion order, so an
//! encoding is deterministic for a given construction order, and any
//! value hashed across replicas is sorted first (see the engine's
//! `sort_database_updates`).

use hyperscale_hbor::error::{DecodeError as HborDecodeError, EncodeError as HborEncodeError};
use hyperscale_hbor::{
    Decoder as HborDecoder, Encoder as HborEncoder, Hbor, HborDecode, HborEncode, HborWidth,
};
use indexmap::IndexMap;

/// A raw substate value, as stored.
pub type DbSubstateValue = Vec<u8>;

/// A key-value entry within one partition.
pub type PartitionEntry = (DbSortKey, DbSubstateValue);

/// A database-level key of an entire partition.
#[derive(Debug, Clone, Hash, PartialEq, Eq, Ord, PartialOrd, Hbor)]
pub struct DbPartitionKey {
    /// The entity this partition belongs to — a flat key's `tag || owner`.
    pub node_key: Vec<u8>,
    /// Which partition of that entity.
    pub partition_num: u8,
}

/// A database-level key of a substate within a known partition.
#[derive(Debug, Clone, Hash, PartialEq, Eq, Ord, PartialOrd, Hbor)]
pub struct DbSortKey(pub Vec<u8>);

/// An update of a single substate's value.
#[derive(Debug, Clone, Hash, PartialEq, Eq, PartialOrd, Ord, Hbor)]
pub enum DatabaseUpdate {
    /// Write this value, creating the substate if absent.
    Set(DbSubstateValue),
    /// Remove the substate.
    Delete,
}

/// A canonical description of all database updates to be applied.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct DatabaseUpdates {
    /// Entity-level updates.
    pub node_updates: IndexMap<Vec<u8>, NodeDatabaseUpdates>,
}

/// A canonical description of one entity's updates.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct NodeDatabaseUpdates {
    /// Partition-level updates.
    pub partition_updates: IndexMap<u8, PartitionDatabaseUpdates>,
}

/// A canonical description of one partition's updates.
///
/// Receipts carry [`Self::Delta`] only — a `Reset` is refused at decode,
/// because reconstructing the keys it drops needs state the decoder does
/// not have. See `ConsensusReceipt`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PartitionDatabaseUpdates {
    /// A delta change, touching just the named substates.
    Delta {
        /// Per-substate updates within this partition.
        substate_updates: IndexMap<DbSortKey, DatabaseUpdate>,
    },

    /// A reset: drop every substate of the partition and replace them.
    Reset {
        /// The partition's complete post-state.
        new_substate_values: IndexMap<DbSortKey, DbSubstateValue>,
    },
}

// ── Codecs ──
//
// Manual, because every map here is an `IndexMap` whose iteration order is
// semantic: an encoding preserves arrival order and rejects duplicate keys,
// so there is exactly one byte string per value where the value includes
// its order. The sorted-before-hashing discipline lives with the producers
// (the engine's `sort_database_updates`), not in the codec.

fn encode_index_map<K: HborEncode, V: HborEncode>(
    encoder: &mut HborEncoder<'_>,
    map: &IndexMap<K, V>,
) -> Result<(), HborEncodeError> {
    encoder.write_len(map.len())?;
    encoder.descend(|encoder| {
        for (key, value) in map {
            key.encode(encoder)?;
            value.encode(encoder)?;
        }
        Ok(())
    })
}

fn decode_index_map<K, V>(decoder: &mut HborDecoder<'_>) -> Result<IndexMap<K, V>, HborDecodeError>
where
    K: HborDecode + core::hash::Hash + Eq,
    V: HborDecode,
{
    let len = decoder.read_len(K::MIN_ENCODED_LEN + V::MIN_ENCODED_LEN)?;
    let mut out = IndexMap::with_capacity(len.min(1024));
    decoder.descend(|decoder| {
        for _ in 0..len {
            let key = K::decode(decoder)?;
            let value = V::decode(decoder)?;
            if out.insert(key, value).is_some() {
                return Err(HborDecodeError::FailedValidation(
                    "an update map names a key twice",
                ));
            }
        }
        Ok(())
    })?;
    Ok(out)
}

impl HborWidth for DatabaseUpdates {
    const MIN_ENCODED_LEN: usize = 1;
}

impl HborEncode for DatabaseUpdates {
    fn encode(&self, encoder: &mut HborEncoder<'_>) -> Result<(), HborEncodeError> {
        encode_index_map(encoder, &self.node_updates)
    }
}

impl HborDecode for DatabaseUpdates {
    fn decode(decoder: &mut HborDecoder<'_>) -> Result<Self, HborDecodeError> {
        Ok(Self {
            node_updates: decode_index_map(decoder)?,
        })
    }
}

impl HborWidth for NodeDatabaseUpdates {
    const MIN_ENCODED_LEN: usize = 1;
}

impl HborEncode for NodeDatabaseUpdates {
    fn encode(&self, encoder: &mut HborEncoder<'_>) -> Result<(), HborEncodeError> {
        encode_index_map(encoder, &self.partition_updates)
    }
}

impl HborDecode for NodeDatabaseUpdates {
    fn decode(decoder: &mut HborDecoder<'_>) -> Result<Self, HborDecodeError> {
        Ok(Self {
            partition_updates: decode_index_map(decoder)?,
        })
    }
}

impl HborWidth for PartitionDatabaseUpdates {
    const MIN_ENCODED_LEN: usize = 2;
}

impl HborEncode for PartitionDatabaseUpdates {
    fn encode(&self, encoder: &mut HborEncoder<'_>) -> Result<(), HborEncodeError> {
        match self {
            Self::Delta { substate_updates } => {
                encoder.write_u8(0);
                encode_index_map(encoder, substate_updates)
            }
            Self::Reset {
                new_substate_values,
            } => {
                encoder.write_u8(1);
                encode_index_map(encoder, new_substate_values)
            }
        }
    }
}

impl HborDecode for PartitionDatabaseUpdates {
    fn decode(decoder: &mut HborDecoder<'_>) -> Result<Self, HborDecodeError> {
        match decoder.read_u8()? {
            0 => Ok(Self::Delta {
                substate_updates: decode_index_map(decoder)?,
            }),
            1 => Ok(Self::Reset {
                new_substate_values: decode_index_map(decoder)?,
            }),
            other => Err(HborDecodeError::InvalidDiscriminant(other)),
        }
    }
}
