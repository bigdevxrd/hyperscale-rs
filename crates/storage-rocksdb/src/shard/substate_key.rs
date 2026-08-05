//! Substate key encoding for `RocksDB`.
//!
//! Constructs the composite byte keys used in the `state` and
//! `state_history` column families. These are RocksDB-specific — the
//! memory storage backend uses native structured keys instead.
//!
//! Key layout: `[node_key][partition_num (1B)][sort_key]`, the flat
//! storage key. Both halves are fixed-width, so the concatenation both
//! preserves lexicographic ordering for prefix scans and decodes back
//! without a length prefix.

use hyperscale_types::state_key::{VM_PARTITION, vm_db_node_key, vm_flat_key_parts};
use radix_substate_store_interface::interface::{DbPartitionKey, DbSortKey};

use crate::typed_cf::{DbCodec, DbEncode};

/// Codec for composite substate keys: `node_key ++ partition_num ++ sort_key`.
#[derive(Default)]
pub struct SubstateKeyCodec;

impl DbEncode<(DbPartitionKey, DbSortKey)> for SubstateKeyCodec {
    fn encode_to(&self, value: &(DbPartitionKey, DbSortKey), buf: &mut Vec<u8>) {
        buf.extend_from_slice(&value.0.node_key);
        buf.push(value.0.partition_num);
        buf.extend_from_slice(&value.1.0);
    }
}

impl DbCodec<(DbPartitionKey, DbSortKey)> for SubstateKeyCodec {
    fn decode(&self, bytes: &[u8]) -> (DbPartitionKey, DbSortKey) {
        let (owner, local) = vm_flat_key_parts(bytes).expect("invalid storage key");
        (
            DbPartitionKey {
                node_key: vm_db_node_key(owner),
                partition_num: VM_PARTITION,
            },
            DbSortKey(local.to_vec()),
        )
    }
}

/// Build storage key prefix for a partition (for range scans).
pub fn partition_prefix(partition_key: &DbPartitionKey) -> Vec<u8> {
    let mut prefix = Vec::with_capacity(partition_key.node_key.len() + 1);
    prefix.extend_from_slice(&partition_key.node_key);
    prefix.push(partition_key.partition_num);
    prefix
}

/// Build the full storage-key prefix for a specific (partition, `sort_key`).
/// Used by the versioned substates CF to scan the version history of a
/// single substate (the per-substate key suffix is an 8-byte big-endian
/// version appended by the versioned CF's codec).
pub fn substate_prefix(partition_key: &DbPartitionKey, sort_key: &DbSortKey) -> Vec<u8> {
    let mut prefix = Vec::with_capacity(partition_key.node_key.len() + 1 + sort_key.0.len());
    prefix.extend_from_slice(&partition_key.node_key);
    prefix.push(partition_key.partition_num);
    prefix.extend_from_slice(&sort_key.0);
    prefix
}
