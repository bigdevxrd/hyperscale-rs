//! The bridge-backed routing-overlay observer: the wiring-layer
//! implementation of the mempool's port.

use hyperscale_effects_bridge::{declared_effects, routing_digest};
use hyperscale_mempool::RoutingObserver;
use hyperscale_metrics::record_routing_digest;
use hyperscale_types::{RoutableTransaction, TopologySnapshot};

/// The observer the wiring layer injects when the routing overlay is on.
///
/// Derives the per-shard effect sets and their routing digest for every
/// newly admitted transaction and records the digest through the metrics
/// facade. Observability only — the digest never feeds a consensus value
/// or an admission decision.
#[derive(Clone, Copy, Debug, Default)]
pub struct BridgeRoutingObserver;

impl RoutingObserver for BridgeRoutingObserver {
    fn on_admitted(&self, tx: &RoutableTransaction, topology: &TopologySnapshot) {
        let digest = routing_digest(&declared_effects(tx, topology));
        record_routing_digest(digest.0);
        tracing::trace!(tx_hash = ?tx.hash(), digest = ?digest, "routing overlay digest");
    }
}
