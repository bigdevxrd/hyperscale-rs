//! Mempool state machine.
//!
//! A pure, synchronous state machine driving the transaction mempool.
//! The [`MempoolCoordinator`] composes:
//!
//! - [`TxStore`] of pending transactions keyed by hash.
//! - Ready set for incrementally-maintained pending-tx selection.
//! - Lock tracker for node-level state locks and in-flight counters.
//! - Tombstone store + evicted-body cache for terminal-state dedup.
//! - `ExpectedTxs` sub-machine that backfills cross-shard transactions
//!   referenced by remote provisions before source-shard gossip arrives.
//!
//! Callers drive the coordinator via `on_submit_transaction`,
//! `on_transaction_gossip`, `on_block_committed`, and related lifecycle
//! methods; all I/O is deferred to the caller via returned `Action`s.

mod coordinator;
mod expected_txs;
mod lock_tracker;
mod ready_set;
mod tombstones;
mod tx_store;

pub use coordinator::{
    DEFAULT_MIN_DWELL_TIME, DEFAULT_QUIESCE_CROSS_SHARD_MARGIN,
    DEFAULT_QUIESCE_SINGLE_SHARD_MARGIN, LockContentionStats, MempoolConfig, MempoolCoordinator,
    MempoolMemoryStats, RoutingObserver,
};
pub use ready_set::DeferralStats;
pub use tx_store::TxStore;
