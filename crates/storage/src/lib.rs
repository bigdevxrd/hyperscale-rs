//! Storage traits and shared types.
//!
//! This crate defines the storage abstraction used by runners to persist substate state,
//! along with shared types and utilities that both in-memory and `RocksDB` storage
//! implementations need.
//!
//! # Design
//!
//! Storage is an implementation detail of runners, not the state machine.
//! The state machine emits `Action::ExecuteTransactions` and receives
//! `ProtocolEvent::ExecutionBatchCompleted` - it never touches storage directly.
//!
//! Runners own storage and pass it to the executor:
//! - `SimulationRunner` uses in-memory storage (`SimShardStorage`)
//! - `ProductionRunner` uses `RocksDB` (`RocksDbShardStorage`)
//!
//! # Jellyfish Merkle Tree (JMT)
//!
//! The `tree` module provides the binary Blake3 JMT state tree adapter.
//! Storage backends implement `jmt::TreeReader` to provide tree access —
//! both `RocksDB` and `SimShardStorage` hook into the same trait.

#![warn(missing_docs)]

pub mod beacon;
pub mod lock_recover;
pub mod shard;
pub mod tree;

#[cfg(any(test, feature = "test-utils"))]
pub mod test_helpers;

pub use beacon::chain_reader::BeaconChainReader;
pub use beacon::chain_writer::BeaconChainWriter;
pub use beacon::ratify_registers::RatifyRegisterStore;
pub use beacon::storage::BeaconStorage;
use hyperscale_jmt::TreeReader;
pub use shard::boundary::{
    AdoptSource, BOUNDARY_RETAIN, BoundaryStore, ImportCursor, ImportLeaf, ImportProgress,
    ResolveLeaf, WitnessSeed,
};
pub use shard::chain_reader::{BlockForSync, ShardChainReader};
pub use shard::chain_writer::ShardChainWriter;
pub use shard::genesis::GenesisCommit;
pub use shard::overlay::{SubstateDbLookup, SubstateLookup};
pub use shard::pending_chain::{BaseReadCache, ChainEntry, PendingChain, SubstateView};
pub use shard::recovered_state::RecoveredState;
pub use shard::store::{SubstateStore, VersionedStore};
pub use shard::vote_registers::SafeVoteRegisterStore;
pub use shard::writes::{
    filter_updates_to_prefix, merge_database_updates, merge_into, merge_updates_from_receipts,
};
pub use tree::{CollectedWrites, JmtSnapshot, LeafSubstateKeyAssociation};

/// Umbrella bound for storage backends threaded as a generic `S` through
/// node-side machinery (the `IoLoop` and its delegated action handler).
///
/// Use this only at sites that *thread* storage generically — i.e. the
/// `IoLoop<S>` impls and entry points that must satisfy every capability
/// `IoLoop` ultimately needs. For narrower scopes (block commit, shard consensus
/// proposal building, provision handlers), bound on the specific traits
/// directly so the signature reflects what the function actually touches.
pub trait ShardStorage:
    ShardChainWriter
    + SubstateStore
    + VersionedStore
    + ShardChainReader
    + TreeReader
    + BoundaryStore
    + SafeVoteRegisterStore
    + Send
    + Sync
    + 'static
{
}

impl<S> ShardStorage for S where
    S: ShardChainWriter
        + SubstateStore
        + VersionedStore
        + ShardChainReader
        + TreeReader
        + BoundaryStore
        + SafeVoteRegisterStore
        + Send
        + Sync
        + 'static
{
}

/// An empty `SubstateDatabase` for use in tests and single-shard contexts
/// where no storage reads are needed.
#[must_use]
pub fn empty_substate_database() -> impl SubstateDatabase {
    struct Empty;
    impl SubstateDatabase for Empty {
        fn get_raw_substate_by_db_key(
            &self,
            _partition_key: &DbPartitionKey,
            _sort_key: &DbSortKey,
        ) -> Option<Vec<u8>> {
            None
        }
        fn list_raw_values_from_db_key(
            &self,
            _partition_key: &DbPartitionKey,
            _from_sort_key: Option<&DbSortKey>,
        ) -> Box<dyn Iterator<Item = (DbSortKey, Vec<u8>)> + '_> {
            Box::new(std::iter::empty())
        }
    }
    Empty
}

// The substate vocabulary lives in `types` because a receipt carries it;
// re-exported here so storage implementations need one import.
pub use hyperscale_types::substate::{
    DatabaseUpdate, DatabaseUpdates, DbPartitionKey, DbSortKey, DbSubstateValue,
    NodeDatabaseUpdates, PartitionDatabaseUpdates, PartitionEntry,
};

/// Read access to a substate store.
///
/// Object-safe: the execution seam borrows one as `dyn SubstateDatabase`
/// so a single batch entry point serves every backend's snapshot type.
pub trait SubstateDatabase {
    /// The value at `(partition_key, sort_key)`, or `None` if absent.
    fn get_raw_substate_by_db_key(
        &self,
        partition_key: &DbPartitionKey,
        sort_key: &DbSortKey,
    ) -> Option<DbSubstateValue>;

    /// Every entry of `partition_key`, in ascending sort-key order,
    /// starting at `from_sort_key` (or its immediate successor when that
    /// exact key is absent).
    fn list_raw_values_from_db_key(
        &self,
        partition_key: &DbPartitionKey,
        from_sort_key: Option<&DbSortKey>,
    ) -> Box<dyn Iterator<Item = PartitionEntry> + '_>;
}

/// Write access to a substate store. Test and genesis paths commit
/// through it directly; the live path goes through `ShardChainWriter`.
pub trait CommittableSubstateDatabase {
    /// Apply `database_updates` to the store.
    fn commit(&mut self, database_updates: &DatabaseUpdates);
}
