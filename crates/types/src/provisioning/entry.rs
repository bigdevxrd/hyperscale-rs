//! Per-transaction state entries within a provision.

use sbor::prelude::*;

use crate::{BoundedVec, MAX_STATE_ENTRIES_PER_TX, SubstateEntry, TxHash};

/// Per-transaction state entries within a provision.
///
/// Identifies which transaction and what state it touched on the source
/// shard. Nothing names what the receiver needs: the receiver derives
/// that from the envelope, so a bundle carries values and nothing else.
#[derive(Debug, Clone, PartialEq, Eq, BasicSbor)]
pub struct ProvisionEntry {
    /// Hash of the transaction.
    pub tx_hash: TxHash,

    /// The state entries this transaction touched on the source shard.
    /// Empty for an engagement echo — a counterpart with nothing to serve
    /// still owes the payer its commitment of the transaction.
    pub entries: BoundedVec<SubstateEntry, MAX_STATE_ENTRIES_PER_TX>,
}

impl ProvisionEntry {
    /// Build a `ProvisionEntry`, canonicalising `entries` by storage key.
    ///
    /// Both transports (gossip emit and fetch serve) construct entries
    /// from the same logical inputs but through different iteration
    /// paths; canonicalising here rather than at each call site means a
    /// future ordering leak can't slip past one caller.
    #[must_use]
    pub fn new(tx_hash: TxHash, mut entries: Vec<SubstateEntry>) -> Self {
        entries.sort_by(|a, b| a.storage_key.cmp(&b.storage_key));
        Self {
            tx_hash,
            entries: entries.into(),
        }
    }
}

#[cfg(test)]
mod tests {
    use sbor::{
        BASIC_SBOR_V1_MAX_DEPTH, BASIC_SBOR_V1_PAYLOAD_PREFIX, DecodeError, Encoder as _,
        NoCustomValueKind, ValueKind, VecEncoder, basic_decode, basic_encode,
    };

    use super::*;
    use crate::Hash;

    fn sample_entry(seed: u8) -> SubstateEntry {
        SubstateEntry::test_entry([seed; 16], b"sort", Some(vec![seed]))
    }

    #[test]
    fn sbor_roundtrip() {
        let entry = ProvisionEntry::new(
            TxHash::from_raw(Hash::from_bytes(b"tx")),
            vec![sample_entry(1), sample_entry(2)],
        );
        let bytes = basic_encode(&entry).unwrap();
        let decoded: ProvisionEntry = basic_decode(&bytes).unwrap();
        assert_eq!(decoded, entry);
    }

    /// Both transports build an entry from the same logical read set but
    /// walk it in different orders; a bundle is only comparable across
    /// them if construction canonicalises.
    #[test]
    fn construction_canonicalises_entry_order() {
        let tx_hash = TxHash::from_raw(Hash::from_bytes(b"tx"));
        let forward = ProvisionEntry::new(tx_hash, vec![sample_entry(1), sample_entry(2)]);
        let reverse = ProvisionEntry::new(tx_hash, vec![sample_entry(2), sample_entry(1)]);
        assert_eq!(forward, reverse);
        assert_eq!(
            basic_encode(&forward).unwrap(),
            basic_encode(&reverse).unwrap()
        );
    }

    #[test]
    fn decode_rejects_oversized_entries() {
        let mut buf = Vec::with_capacity(64);
        let mut enc = VecEncoder::<NoCustomValueKind>::new(&mut buf, BASIC_SBOR_V1_MAX_DEPTH);
        enc.write_payload_prefix(BASIC_SBOR_V1_PAYLOAD_PREFIX)
            .unwrap();
        enc.write_value_kind(ValueKind::Tuple).unwrap();
        enc.write_size(2).unwrap();
        enc.encode(&TxHash::from_raw(Hash::from_bytes(b"tx")))
            .unwrap();
        enc.write_value_kind(ValueKind::Array).unwrap();
        enc.write_value_kind(SubstateEntry::value_kind()).unwrap();
        enc.write_size(MAX_STATE_ENTRIES_PER_TX + 1).unwrap();
        let err = basic_decode::<ProvisionEntry>(&buf).unwrap_err();
        assert!(matches!(
            err,
            DecodeError::UnexpectedSize {
                expected: MAX_STATE_ENTRIES_PER_TX,
                actual,
            } if actual == MAX_STATE_ENTRIES_PER_TX + 1
        ));
    }

    #[test]
    fn decode_rejects_the_node_set_shape() {
        // Hand-roll the prior wire layout — entries plus target and owned
        // node lists — to confirm a peer can't keep shipping node sets the
        // receiver now derives for itself.
        let mut buf = Vec::with_capacity(64);
        let mut enc = VecEncoder::<NoCustomValueKind>::new(&mut buf, BASIC_SBOR_V1_MAX_DEPTH);
        enc.write_payload_prefix(BASIC_SBOR_V1_PAYLOAD_PREFIX)
            .unwrap();
        enc.write_value_kind(ValueKind::Tuple).unwrap();
        enc.write_size(4).unwrap();
        enc.encode(&TxHash::from_raw(Hash::from_bytes(b"tx")))
            .unwrap();
        let err = basic_decode::<ProvisionEntry>(&buf).unwrap_err();
        assert!(matches!(
            err,
            DecodeError::UnexpectedSize {
                expected: 2,
                actual: 4
            }
        ));
    }
}
