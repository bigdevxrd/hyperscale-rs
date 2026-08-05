//! Cross-shard agreement receipt (Tier 1).

use hyperscale_hbor::Hbor;

use crate::{BeaconWitnessRoot, EventRoot, GlobalReceiptHash, Hash, OwnershipRoot, WritesRoot};

/// Cross-shard agreement receipt — ensures validators on different shards
/// executing the same transaction reach the same outcome.
///
/// Contains `writes_root` (merkle root of declared-only, system-filtered global
/// writes — NOT shard-filtered) so cross-shard agreement covers state changes,
/// not just outcome + events.
///
/// This hash is what validators sign over in execution votes.
/// Ephemeral — never written to storage, only lives for EC aggregation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Hbor)]
pub struct GlobalReceipt {
    success: bool,
    event_root: EventRoot,
    beacon_witness_root: BeaconWitnessRoot,
    writes_root: WritesRoot,
    ownership_root: OwnershipRoot,
}

impl GlobalReceipt {
    /// Build a `GlobalReceipt` from its parts.
    #[must_use]
    pub const fn new(
        success: bool,
        event_root: EventRoot,
        beacon_witness_root: BeaconWitnessRoot,
        writes_root: WritesRoot,
        ownership_root: OwnershipRoot,
    ) -> Self {
        Self {
            success,
            event_root,
            beacon_witness_root,
            writes_root,
            ownership_root,
        }
    }

    /// Whether the engine committed (`true`) or rejected (`false`) the transaction.
    #[must_use]
    pub const fn success(&self) -> bool {
        self.success
    }

    /// Merkle root of application event hashes.
    #[must_use]
    pub const fn event_root(&self) -> EventRoot {
        self.event_root
    }

    /// Merkle root over the per-tx beacon-witness events.
    ///
    /// Folded into [`Self::receipt_hash`] so cross-shard agreement covers
    /// the beacon-witness event stream too. `BeaconWitnessRoot::ZERO`
    /// until the engine surfaces real events from execution.
    #[must_use]
    pub const fn beacon_witness_root(&self) -> BeaconWitnessRoot {
        self.beacon_witness_root
    }

    /// Merkle root of declared-only, system-filtered global database writes.
    ///
    /// Computed from `filter_updates_for_global_receipt()` — includes writes for
    /// ALL shards (not shard-filtered), but excludes system entities and undeclared
    /// writes. This ensures cross-shard validators agree on the same state changes
    /// for declared accounts.
    #[must_use]
    pub const fn writes_root(&self) -> WritesRoot {
        self.writes_root
    }

    /// Commitment over the transaction's `(internal_node, owning_global_ancestor)`
    /// ownership map (globally filtered, shard-invariant).
    ///
    /// Folded into [`Self::receipt_hash`] so the execution committee agrees
    /// on the ownership used to owner-prefix internal nodes' JMT leaves
    /// before a wave finalizes — a Byzantine source can't slip in a keying
    /// the committee never voted on.
    #[must_use]
    pub const fn ownership_root(&self) -> OwnershipRoot {
        self.ownership_root
    }

    /// Compute the global receipt hash.
    ///
    /// This is the value signed over in execution votes and stored on certificates.
    #[must_use]
    pub fn receipt_hash(&self) -> GlobalReceiptHash {
        let outcome_byte = if self.success { [1u8] } else { [0u8] };
        GlobalReceiptHash::from_raw(Hash::from_parts(&[
            &outcome_byte,
            self.event_root.as_raw().as_bytes(),
            self.beacon_witness_root.as_raw().as_bytes(),
            self.writes_root.as_raw().as_bytes(),
            self.ownership_root.as_raw().as_bytes(),
        ]))
    }
}
