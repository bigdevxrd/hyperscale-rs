//! Storage key encoding — the byte-level contract between storage backends
//! and overlay implementations (e.g., provision overlays in the engine).
//!
//! Key layout: `[node_key][partition_num (1B)][sort_key]`
//!
//! Both the `RocksDB` backend and the engine's provision overlay use these
//! functions to produce compatible keys.

use crate::{DbPartitionKey, DbSortKey};

/// Convert Radix partition key + sort key to a flat storage key.
#[must_use]
pub fn to_storage_key(partition_key: &DbPartitionKey, sort_key: &DbSortKey) -> Vec<u8> {
    let mut key = Vec::with_capacity(partition_key.node_key.len() + 1 + sort_key.0.len());
    key.extend_from_slice(&partition_key.node_key);
    key.push(partition_key.partition_num);
    key.extend_from_slice(&sort_key.0);
    key
}

/// Build storage key prefix for a partition (for range scans / overlays).
#[must_use]
pub fn partition_prefix(partition_key: &DbPartitionKey) -> Vec<u8> {
    let mut prefix = Vec::with_capacity(partition_key.node_key.len() + 1);
    prefix.extend_from_slice(&partition_key.node_key);
    prefix.push(partition_key.partition_num);
    prefix
}

/// Compute the exclusive end key for a prefix scan.
///
/// Returns `None` if the prefix is all `0xFF` bytes (no valid exclusive upper bound).
#[must_use]
pub fn next_prefix(prefix: &[u8]) -> Option<Vec<u8>> {
    debug_assert!(!prefix.is_empty(), "next_prefix called with empty prefix");
    let mut next = prefix.to_vec();
    for i in (0..next.len()).rev() {
        if next[i] < 255 {
            next[i] += 1;
            return Some(next);
        }
        next[i] = 0;
    }
    None
}
