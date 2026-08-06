//! Merging and filtering [`StateWrites`].

use hyperscale_jmt::NibblePath;
use hyperscale_types::{StateWrites, StoredReceipt};

/// Extract and merge the writes from stored receipts.
///
/// Canonical projection from receipts to JMT/substate-write input.
/// Failed receipts contribute nothing (`ConsensusReceipt::writes`
/// returns `None`). Later receipts win per cell, matching the receipts'
/// commit order.
#[must_use]
pub fn merge_writes_from_receipts(receipts: &[StoredReceipt]) -> StateWrites {
    let mut merged = StateWrites::default();
    for receipt in receipts {
        if let Some(writes) = receipt.consensus.writes() {
            merged.cells.extend(
                writes
                    .cells
                    .iter()
                    .map(|(key, change)| (*key, change.clone())),
            );
        }
    }
    merged
}

/// Merge writes in order; later entries win per cell.
#[must_use]
pub fn merge_state_writes(list: &[&StateWrites]) -> StateWrites {
    let mut merged = StateWrites::default();
    for writes in list {
        merged.cells.extend(
            writes
                .cells
                .iter()
                .map(|(key, change)| (*key, change.clone())),
        );
    }
    merged
}

/// Restrict `writes` to the cells whose JMT leaves fall under `prefix` —
/// the subset of a followed chain's block writes that belongs to a store
/// rooted there.
///
/// A substate key's leading bits are its owner prefix — the identity
/// leaf's routing half — so every cell of one owner shares the prefix
/// decision.
#[must_use]
pub fn filter_writes_to_prefix(writes: &StateWrites, prefix: &NibblePath) -> StateWrites {
    let mut filtered = StateWrites::default();
    for (key, change) in &writes.cells {
        if key_under_prefix(&key.to_bytes(), prefix) {
            filtered.cells.insert(*key, change.clone());
        }
    }
    filtered
}

/// Whether `key`'s leading bits equal `prefix` — the subtree-membership
/// test shard prefixes partition the keyspace by.
fn key_under_prefix(key: &[u8; 32], prefix: &NibblePath) -> bool {
    (0..prefix.len()).all(|i| {
        let key_bit = (key[usize::from(i / 8)] >> (7 - (i % 8))) & 1;
        prefix.bits_at(i, 1) == key_bit
    })
}

#[cfg(test)]
mod tests {
    use hyperscale_jmt::NibblePath;
    use hyperscale_types::{Address, LocalKey, SubstateKey};

    use super::*;

    fn writes_for(owner: [u8; 16], value: u8) -> StateWrites {
        let mut writes = StateWrites::default();
        writes.cells.insert(
            SubstateKey {
                owner: Address(owner),
                local: LocalKey([1; 16]),
            },
            Some(vec![value]),
        );
        writes
    }

    #[test]
    fn later_writes_win_per_cell() {
        let merged = merge_state_writes(&[&writes_for([1; 16], 1), &writes_for([1; 16], 2)]);
        assert_eq!(merged.cells.len(), 1);
        assert_eq!(merged.cells.values().next().unwrap(), &Some(vec![2]));
    }

    #[test]
    fn prefix_filter_splits_on_the_leading_bit() {
        let low = writes_for([0x00; 16], 1);
        let high = writes_for([0xFF; 16], 2);
        let merged = merge_state_writes(&[&low, &high]);

        let mut left = NibblePath::empty();
        left.push_bits(0, 1);
        let mut right = NibblePath::empty();
        right.push_bits(1, 1);
        assert_eq!(filter_writes_to_prefix(&merged, &left), low);
        assert_eq!(filter_writes_to_prefix(&merged, &right), high);
        assert_eq!(
            filter_writes_to_prefix(&merged, &NibblePath::empty()),
            merged
        );
    }
}
