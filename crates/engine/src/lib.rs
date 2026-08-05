//! Engine integration.
//!
//! Synchronous transaction execution shared by the production runner
//! and the deterministic simulator. The executor does NOT own storage:
//! the runner owns it and passes a snapshot per call.
//!
//! State machines emit `Action::ExecuteTransactions`; the runner drives
//! an [`Executor`] over the wave's batch, which projects the
//! shard-invariant [`CachedVmOutput`] into the local shard's
//! [`ExecutedTx`] via [`project_to_shard`]. The process-scope
//! [`ProcessExecutionCache`] short-circuits execution when same-shard
//! vnodes (or hosted participating shards) replay an already-executed
//! transaction.

#![warn(missing_docs)]

mod cache;
mod executor;
mod genesis;
mod genesis_cache;
mod output;
mod receipt;

/// Shard assignment and write filtering for `DatabaseUpdates`.
pub mod sharding;

pub use cache::{CachedSlot, ProcessExecutionCache, SlotStatus};
pub use executor::{
    CrossShardTxInput, DynSnapshot, Executor, WaveBatchContext, batch_compute_cached,
    fetch_state_entries, participating_shards,
};
pub use genesis::GenesisConfig;
pub use genesis_cache::prepared_genesis;
// Re-export the fan-out strategy `WaveBatchContext` carries, so seam
// implementations and their tests need no separate dispatch dependency.
pub use hyperscale_dispatch::Parallelism;
pub use output::ExecutedTx;
pub use radix_common::network::NetworkDefinition;
pub use receipt::{CachedVmOutput, project_to_shard};
