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

use indexmap::IndexMap;
use sbor::BasicSbor;

/// A raw substate value, as stored.
pub type DbSubstateValue = Vec<u8>;

/// A key-value entry within one partition.
pub type PartitionEntry = (DbSortKey, DbSubstateValue);

/// A database-level key of an entire partition.
#[derive(Debug, Clone, Hash, PartialEq, Eq, Ord, PartialOrd, BasicSbor)]
pub struct DbPartitionKey {
    /// The entity this partition belongs to — a flat key's `tag || owner`.
    pub node_key: Vec<u8>,
    /// Which partition of that entity.
    pub partition_num: u8,
}

/// A database-level key of a substate within a known partition.
#[derive(Debug, Clone, Hash, PartialEq, Eq, Ord, PartialOrd, BasicSbor)]
pub struct DbSortKey(pub Vec<u8>);

/// An update of a single substate's value.
#[derive(Debug, Clone, Hash, PartialEq, Eq, PartialOrd, Ord, BasicSbor)]
pub enum DatabaseUpdate {
    /// Write this value, creating the substate if absent.
    Set(DbSubstateValue),
    /// Remove the substate.
    Delete,
}

/// A canonical description of all database updates to be applied.
#[derive(Debug, Clone, PartialEq, Eq, Default, BasicSbor)]
pub struct DatabaseUpdates {
    /// Entity-level updates.
    pub node_updates: IndexMap<Vec<u8>, NodeDatabaseUpdates>,
}

/// A canonical description of one entity's updates.
#[derive(Debug, Clone, PartialEq, Eq, Default, BasicSbor)]
pub struct NodeDatabaseUpdates {
    /// Partition-level updates.
    pub partition_updates: IndexMap<u8, PartitionDatabaseUpdates>,
}

/// A canonical description of one partition's updates.
///
/// Receipts carry [`Self::Delta`] only — a `Reset` is refused at decode,
/// because reconstructing the keys it drops needs state the decoder does
/// not have. See `ConsensusReceipt`.
#[derive(Debug, Clone, PartialEq, Eq, BasicSbor)]
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
