//! Shard assignment and write filtering for `DatabaseUpdates`.
//!
//! An entity key carries its owner prefix — the identity leaf's routing
//! half — so shard assignment is a prefix walk over the shard trie and
//! nothing else. Genesis replicates the stdlib package to every shard's
//! substate store for read availability, but each shard's prefix-rooted
//! JMT must contain only its own subtree, so what a shard commits is
//! filtered here first.
//!
//! This module also carries the canonicalisation a `writes_root` needs:
//! `DatabaseUpdates` is built from `IndexMap`s whose order reflects
//! execution touch order, so the root is taken over a key-sorted clone
//! and is a pure function of content.

use hyperscale_storage::{DatabaseUpdates, PartitionDatabaseUpdates};
use hyperscale_types::state_key::vm_db_node_key_owner;
use hyperscale_types::{ShardId, ShardTrie, WritesRoot};
use radix_common::prelude::basic_encode;

/// Filter genesis `DatabaseUpdates` to the entities whose owner prefix
/// routes to `local_shard`, for building that shard's prefix-rooted JMT.
///
/// The stdlib package is replicated to every shard's substate store for
/// read availability, but the prefix-rooted JMT must contain only this
/// shard's subtree — so the committed `state_root` is exactly the global
/// tree's node at the shard prefix. Single-shard deployments root at the
/// empty prefix, where every entity routes to the one shard and this is
/// the identity filter.
#[must_use]
pub fn filter_genesis_updates_for_shard(
    merged: &DatabaseUpdates,
    local_shard: ShardId,
    shard_trie: &ShardTrie,
) -> DatabaseUpdates {
    filter_updates_for_shard(merged, local_shard, shard_trie)
}

// ============================================================================
// Stage 2: Shard Filtering
// ============================================================================

/// Filter `DatabaseUpdates` for a single shard.
///
/// An entity key carries its owner prefix — the identity leaves' routing
/// half — so shard assignment is a prefix walk and nothing else.
#[must_use]
pub fn filter_updates_for_shard(
    updates: &DatabaseUpdates,
    local_shard: ShardId,
    shard_trie: &ShardTrie,
) -> DatabaseUpdates {
    let mut filtered = DatabaseUpdates::default();
    for (db_node_key, node_updates) in &updates.node_updates {
        let Some(owner) = vm_db_node_key_owner(db_node_key) else {
            continue;
        };
        if shard_trie.shard_for_prefix(owner) == local_shard {
            filtered
                .node_updates
                .insert(db_node_key.clone(), node_updates.clone());
        }
    }
    filtered
}

/// Compute the `writes_root` for a `GlobalReceipt` from filtered `DatabaseUpdates`.
///
/// `DatabaseUpdates` is built from `IndexMap`s at every level — Radix's
/// `StateUpdates` documents itself as "not 100% canonical form" because the
/// `by_node` order reflects engine touch order rather than a content-derived
/// order. To make `writes_root` a pure function of the *content* of the
/// updates (independent of how the maps were populated), we sort all
/// `IndexMap`s by key before SBOR-encoding.
///
/// # Panics
///
/// Panics if SBOR encoding of [`DatabaseUpdates`] fails. The Radix SBOR encoder
/// is infallible for these structures, so this is unreachable in practice.
#[must_use]
pub fn compute_writes_root(updates: &DatabaseUpdates) -> WritesRoot {
    use hyperscale_types::{Hash, WritesRoot};

    if updates.node_updates.is_empty() {
        return WritesRoot::ZERO;
    }

    let mut canonical = updates.clone();
    sort_database_updates(&mut canonical);
    let encoded = basic_encode(&canonical).expect("DatabaseUpdates encoding should not fail");
    WritesRoot::from_raw(Hash::from_bytes(&encoded))
}

/// Sort every `IndexMap` inside `updates` by key, in-place.
pub fn sort_database_updates(updates: &mut DatabaseUpdates) {
    updates.node_updates.sort_keys();
    for node_updates in updates.node_updates.values_mut() {
        node_updates.partition_updates.sort_keys();
        for partition_updates in node_updates.partition_updates.values_mut() {
            match partition_updates {
                PartitionDatabaseUpdates::Delta { substate_updates } => {
                    substate_updates.sort_keys();
                }
                PartitionDatabaseUpdates::Reset {
                    new_substate_values,
                } => {
                    new_substate_values.sort_keys();
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use hyperscale_storage::{
        DatabaseUpdate, DatabaseUpdates, DbSortKey, NodeDatabaseUpdates, PartitionDatabaseUpdates,
    };
    use hyperscale_types::state_key::{VM_PARTITION, vm_db_node_key};
    use hyperscale_types::{ShardTrie, WritesRoot};

    use super::*;

    /// A `DatabaseUpdates` holding one cell under `owner`.
    fn set_update(owner: [u8; 16], local: [u8; 16], value: Vec<u8>) -> DatabaseUpdates {
        let mut updates = DatabaseUpdates::default();
        let nu = updates
            .node_updates
            .entry(vm_db_node_key(owner))
            .or_insert_with(NodeDatabaseUpdates::default);
        nu.partition_updates.insert(
            VM_PARTITION,
            PartitionDatabaseUpdates::Delta {
                substate_updates: std::iter::once((
                    DbSortKey(local.to_vec()),
                    DatabaseUpdate::Set(value),
                ))
                .collect(),
            },
        );
        updates
    }

    fn merge(mut a: DatabaseUpdates, b: DatabaseUpdates) -> DatabaseUpdates {
        for (k, v) in b.node_updates {
            a.node_updates.insert(k, v);
        }
        a
    }

    // ── compute_writes_root ──────────────────────────────────────────────────

    #[test]
    fn compute_writes_root_empty_is_zero() {
        assert_eq!(
            compute_writes_root(&DatabaseUpdates::default()),
            WritesRoot::ZERO
        );
    }

    #[test]
    fn compute_writes_root_is_insertion_order_independent() {
        // The cross-shard agreement contract requires that two validators which
        // build the same logical `DatabaseUpdates` produce the same root
        // regardless of how their underlying `IndexMap`s were populated. If
        // this fails, validators executing the same transaction can disagree
        // on `writes_root` and break global-receipt consensus.
        let (a, b) = ([1u8; 16], [2u8; 16]);
        let forward = merge(
            set_update(a, [0; 16], vec![1]),
            set_update(b, [0; 16], vec![1]),
        );
        let reverse = merge(
            set_update(b, [0; 16], vec![1]),
            set_update(a, [0; 16], vec![1]),
        );
        assert_eq!(compute_writes_root(&forward), compute_writes_root(&reverse));
    }

    #[test]
    fn compute_writes_root_distinguishes_inputs() {
        let a = set_update([1u8; 16], [0; 16], vec![1]);
        let b = set_update([2u8; 16], [0; 16], vec![1]);
        assert_ne!(compute_writes_root(&a), compute_writes_root(&b));
    }

    // ── filter_updates_for_shard ─────────────────────────────────────────────

    #[test]
    fn filter_for_shard_keeps_only_this_shard_prefixes() {
        let trie = ShardTrie::uniform_from_count(2);
        let left = [0x00; 16];
        let right = [0xFF; 16];
        assert_ne!(trie.shard_for_prefix(left), trie.shard_for_prefix(right));
        let updates = merge(
            set_update(left, [1; 16], vec![1]),
            set_update(right, [1; 16], vec![2]),
        );

        let filtered = filter_updates_for_shard(&updates, trie.shard_for_prefix(left), &trie);
        assert_eq!(filtered.node_updates.len(), 1);
        assert_eq!(
            vm_db_node_key_owner(filtered.node_updates.keys().next().unwrap()),
            Some(left)
        );
    }

    #[test]
    fn filter_for_shard_drops_keys_outside_the_namespace() {
        // An entity key that carries no owner prefix routes nowhere, so
        // the filter drops it rather than committing it to every shard.
        let mut updates = set_update([1u8; 16], [0; 16], vec![1]);
        let value = updates
            .node_updates
            .shift_remove_index(0)
            .expect("one entry")
            .1;
        updates.node_updates.insert(vec![0xAA; 50], value);

        let filtered =
            filter_updates_for_shard(&updates, ShardId::ROOT, &ShardTrie::uniform_from_count(1));
        assert!(filtered.node_updates.is_empty());
    }
}
