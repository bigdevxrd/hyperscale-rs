//! Receipt model for transaction execution results.
//!
//! | Tier | Type | Contents | Cross-shard identical? |
//! |------|------|----------|------------------------|
//! | **Global**    | [`GlobalReceipt`](global::GlobalReceipt)         | success bit + `event_root` + `beacon_witness_root` + `writes_root` | Yes |
//! | **Consensus** | [`ConsensusReceipt`](consensus::ConsensusReceipt) | variant tag + (Succeeded:) shard-filtered writes + events + beacon-witness events + precomputed `receipt_hash` | No |
//! | **Metadata**  | [`ExecutionMetadata`](metadata::ExecutionMetadata) | fees, logs, errors | No (local-only) |
//! | **Stored**    | [`StoredReceipt`](stored::StoredReceipt)         | `tx_hash` + consensus + optional metadata | n/a (storage shape) |
//!
//! `GlobalReceipt::receipt_hash()` is signed over in execution votes/certificates.
//! Per-shard state correctness is enforced by `state_root` in the block header,
//! with per-tx attribution via `local_receipt_root` (`ConsensusReceipt::local_receipt_hash`).

pub mod consensus;
pub mod global;
pub mod metadata;
pub mod stored;

#[cfg(test)]
mod tests {
    use crate::test_utils::test_event_type_identifier;
    use crate::{
        ApplicationEvent, BeaconWitnessRoot, BoundedVec, ConsensusReceipt, DatabaseUpdates,
        EventData, EventRoot, GlobalReceipt, GlobalReceiptHash, Hash, OwnershipRoot, WritesRoot,
    };

    fn make_event(seed: u8) -> ApplicationEvent {
        ApplicationEvent {
            type_id: test_event_type_identifier(seed),
            data: EventData(vec![seed, seed + 1]),
        }
    }

    fn make_succeeded(events: Vec<ApplicationEvent>) -> ConsensusReceipt {
        ConsensusReceipt::Succeeded {
            receipt_hash: GlobalReceiptHash::ZERO,
            database_updates: DatabaseUpdates::default(),
            owned_nodes: BoundedVec::new(),
            application_events: events,
            beacon_witness_events: Vec::new(),
        }
    }

    #[test]
    fn test_global_receipt_hash_changes_with_outcome() {
        let success = GlobalReceipt::new(
            true,
            EventRoot::ZERO,
            BeaconWitnessRoot::ZERO,
            WritesRoot::ZERO,
            OwnershipRoot::ZERO,
        );
        let failure = GlobalReceipt::new(
            false,
            EventRoot::ZERO,
            BeaconWitnessRoot::ZERO,
            WritesRoot::ZERO,
            OwnershipRoot::ZERO,
        );
        assert_ne!(success.receipt_hash(), failure.receipt_hash());
    }

    #[test]
    fn test_global_receipt_hash_changes_with_writes_root() {
        let a = GlobalReceipt::new(
            true,
            EventRoot::ZERO,
            BeaconWitnessRoot::ZERO,
            WritesRoot::ZERO,
            OwnershipRoot::ZERO,
        );
        let b = GlobalReceipt::new(
            true,
            EventRoot::ZERO,
            BeaconWitnessRoot::ZERO,
            WritesRoot::from_raw(Hash::from_bytes(b"different")),
            OwnershipRoot::ZERO,
        );
        assert_ne!(a.receipt_hash(), b.receipt_hash());
    }

    #[test]
    fn test_global_receipt_hash_changes_with_beacon_witness_root() {
        let a = GlobalReceipt::new(
            true,
            EventRoot::ZERO,
            BeaconWitnessRoot::ZERO,
            WritesRoot::ZERO,
            OwnershipRoot::ZERO,
        );
        let b = GlobalReceipt::new(
            true,
            EventRoot::ZERO,
            BeaconWitnessRoot::from_raw(Hash::from_bytes(b"witness")),
            WritesRoot::ZERO,
            OwnershipRoot::ZERO,
        );
        assert_ne!(a.receipt_hash(), b.receipt_hash());
    }

    #[test]
    fn test_global_receipt_hash_changes_with_ownership_root() {
        let a = GlobalReceipt::new(
            true,
            EventRoot::ZERO,
            BeaconWitnessRoot::ZERO,
            WritesRoot::ZERO,
            OwnershipRoot::ZERO,
        );
        let b = GlobalReceipt::new(
            true,
            EventRoot::ZERO,
            BeaconWitnessRoot::ZERO,
            WritesRoot::ZERO,
            OwnershipRoot::from_raw(Hash::from_bytes(b"ownership")),
        );
        assert_ne!(a.receipt_hash(), b.receipt_hash());
    }

    #[test]
    fn test_application_event_hash_deterministic() {
        let event = make_event(42);
        assert_eq!(event.hash(), event.hash());

        let same_event = ApplicationEvent {
            type_id: test_event_type_identifier(42),
            data: EventData(vec![42, 43]),
        };
        assert_eq!(event.hash(), same_event.hash());
    }

    #[test]
    fn test_local_receipt_hash_deterministic() {
        let receipt = make_succeeded(vec![make_event(1)]);
        assert_eq!(receipt.local_receipt_hash(), receipt.local_receipt_hash());
    }

    #[test]
    fn test_local_receipt_hash_changes_with_outcome() {
        let succeeded = make_succeeded(vec![]);
        let failed = ConsensusReceipt::Failed;
        assert_ne!(succeeded.local_receipt_hash(), failed.local_receipt_hash());
    }

    #[test]
    fn test_local_receipt_hash_changes_with_events() {
        let receipt_a = make_succeeded(vec![make_event(1)]);
        let receipt_b = make_succeeded(vec![make_event(1), make_event(2)]);
        assert_ne!(
            receipt_a.local_receipt_hash(),
            receipt_b.local_receipt_hash()
        );
    }
}
