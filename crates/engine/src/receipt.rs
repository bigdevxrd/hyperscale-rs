//! The shard-invariant execution output and its per-shard projection.
//!
//! Receipt projection runs in two stages:
//!
//! - the engine turns its own receipt into a [`CachedOutput`] — every
//!   field is shard-invariant for a given transaction. This is the
//!   cacheable stage.
//! - [`project_to_shard`] consumes the cached output and a target shard
//!   to produce the final [`ExecutedTx`]. Only the `database_updates`
//!   slice, the events, and the beacon facts are shard-specific.

use hyperscale_types::{
    BeaconWitnessEvent, ConsensusReceipt, Event, ExecutionMetadata, GlobalReceiptHash, ShardId,
    ShardTrie, TxHash, has_partition_reset,
};
use radix_substate_store_interface::interface::DatabaseUpdates;

use crate::output::ExecutedTx;
use crate::sharding::{filter_updates_for_shard, sort_database_updates};

/// Shard-invariant projection of an execution receipt.
///
/// Carries everything needed to assemble an [`ExecutedTx`] for any
/// participating shard. The transaction's effective state is canonical
/// across participating shards by way of provisioning, so every field
/// here is identical on every shard that executes the same transaction.
/// Per-shard `database_updates` is *not* cached — it's re-derived per
/// call from `raw_updates` via [`project_to_shard`].
pub struct CachedOutput {
    metadata: ExecutionMetadata,
    body: CachedOutputBody,
}

#[allow(clippy::large_enum_variant)] // Succeeded is the common case; boxing penalises every hit
enum CachedOutputBody {
    /// A per-transaction abort, or a transaction that never reached the
    /// engine.
    Failed,
    /// A committed success: the folded absolute updates and the receipt
    /// hash over their canonical encoding.
    Succeeded {
        raw_updates: DatabaseUpdates,
        /// Events in emission order, unfiltered: the projection picks
        /// each shard's own by the emitter's home, and the event root
        /// covers the whole union.
        events: Vec<Event>,
        receipt_hash: GlobalReceiptHash,
        /// Beacon facts lifted from a recognised stake pool's events,
        /// each beside the emitter that produced it.
        ///
        /// A pair rather than an anchor node, because an emitter is a
        /// substate prefix: which shard keeps the fact is the same
        /// question — and the same answer — as which shard keeps the
        /// event it was read from.
        witnesses: Vec<([u8; 16], BeaconWitnessEvent)>,
        /// Fuel the engine consumed. Shard-invariant here and filtered to
        /// nothing by projection: every participant that ran this batch
        /// consumed the same amount, and locality scoping shows up as a
        /// different batch rather than a different number.
        gas_consumed: u64,
    },
}

impl CachedOutput {
    /// The success output: the folded absolute updates and the receipt
    /// hash over their canonical encoding. Keys carry their shard
    /// placement in the owner prefix, so no declared node set or
    /// ownership map exists.
    #[must_use]
    pub const fn succeeded(
        raw_updates: DatabaseUpdates,
        receipt_hash: GlobalReceiptHash,
        metadata: ExecutionMetadata,
        gas_consumed: u64,
        events: Vec<Event>,
        witnesses: Vec<([u8; 16], BeaconWitnessEvent)>,
    ) -> Self {
        Self {
            metadata,
            body: CachedOutputBody::Succeeded {
                raw_updates,
                events,
                receipt_hash,
                witnesses,
                gas_consumed,
            },
        }
    }

    /// The failure output — a per-transaction abort whose diagnostics
    /// ride the node-local metadata.
    #[must_use]
    pub const fn failed(metadata: ExecutionMetadata) -> Self {
        Self {
            metadata,
            body: CachedOutputBody::Failed,
        }
    }
}

#[cfg(test)]
impl CachedOutput {
    /// Build a `Failed` output for cache-mechanics tests. The body
    /// content doesn't matter for cache-identity assertions.
    pub(crate) fn failed_for_tests() -> Self {
        Self {
            metadata: ExecutionMetadata::empty(),
            body: CachedOutputBody::Failed,
        }
    }
}

/// Build an [`ExecutedTx`] for `local_shard` from a [`CachedOutput`].
///
/// Runs the per-shard step: `filter_updates_for_shard` over the cached
/// `raw_updates`, then assembles the `ExecutedTx`. The filter output is
/// sorted before hashing so `ConsensusReceipt::local_receipt_hash` is
/// order-stable.
///
/// # Panics
///
/// Panics if a partition Reset survives shard filtering — receipt
/// updates must be Delta-only (see
/// [`has_partition_reset`](hyperscale_types::has_partition_reset)).
#[must_use]
pub fn project_to_shard(
    cached: &CachedOutput,
    tx_hash: TxHash,
    local_shard: ShardId,
    shard_trie: &ShardTrie,
) -> ExecutedTx {
    match &cached.body {
        CachedOutputBody::Failed => {
            ExecutedTx::new(tx_hash, ConsensusReceipt::Failed, cached.metadata.clone())
        }
        CachedOutputBody::Succeeded {
            raw_updates,
            events,
            receipt_hash,
            witnesses,
            gas_consumed,
        } => {
            let mut database_updates =
                filter_updates_for_shard(raw_updates, local_shard, shard_trie);
            // Receipt updates must be Delta-only: storage applies them
            // without enumerating pre-existing partition keys, so a Reset
            // surviving shard filtering would silently diverge the live and
            // sync JMT roots (see `hyperscale_types::has_partition_reset`).
            assert!(
                !has_partition_reset(&database_updates),
                "partition Reset survived shard filtering for tx {tx_hash:?} — receipt updates must be Delta-only",
            );
            // Canonicalise key order so `ConsensusReceipt::local_receipt_hash`
            // (which SBOR-encodes the IndexMap directly) is order-stable
            // across validators regardless of `raw_updates` insertion order.
            sort_database_updates(&mut database_updates);
            // A fact's emitter is a substate prefix, so the shard that
            // keeps the fact is the one that keeps the event it was read
            // from — the same rule applied a few lines below, and the
            // whole of what decides which shard reports a fact. The
            // beacon folds each one exactly once because exactly one
            // shard owns its emitter.
            let beacon_witness_events: Vec<BeaconWitnessEvent> = witnesses
                .iter()
                .filter(|(emitter, _)| shard_trie.shard_for_prefix(*emitter) == local_shard)
                .map(|(_, event)| event.clone())
                .collect();
            // An event is stored where its emitter lives, so each shard
            // keeps its own and the rest are another shard's to hold. The
            // receipt hash covers the whole union, so dropping them here
            // costs no agreement.
            let events: Vec<Event> = events
                .iter()
                .filter(|event| shard_trie.shard_for_prefix(event.emitter) == local_shard)
                .cloned()
                .collect();
            let consensus = ConsensusReceipt::Succeeded {
                receipt_hash: *receipt_hash,
                database_updates,
                beacon_witness_events,
                events,
            };
            let mut executed = ExecutedTx::new(tx_hash, consensus, cached.metadata.clone());
            executed.attested_work = *gas_consumed;
            executed
        }
    }
}
