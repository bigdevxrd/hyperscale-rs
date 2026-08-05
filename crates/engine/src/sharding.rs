//! Shard assignment and write filtering for Radix Engine DatabaseUpdates.
//!
//! # The Problem
//!
//! The Radix Engine's object model doesn't align with our sharding model:
//!
//! - **Accounts** (`0x51`) are global entities assigned to shards by hash.
//! - **Vaults** (`0x58`) are internal entities whose NodeIds are random hashes
//!   (`hash(creating_tx_hash, counter)`) with NO structural relationship to their
//!   owning account. A vault's `outer_object` points to its **resource manager**
//!   (`0x5d`), not the account — because vaults are "inner objects" of the
//!   resource blueprint, not the account blueprint.
//! - A simple XRD transfer writes to vault nodes only — the account node itself
//!   is read-only (the KV store entry holding the `Own(vault_id)` doesn't change).
//! - The account→vault relationship is stored as `Own(vault_id)` in the account's
//!   KV store. There is NO back-pointer from vault to account.
//!
//! This means:
//! 1. We can't determine a vault's shard from its NodeId alone.
//! 2. We can't walk UP from vault to account (no back-pointer exists).
//! 3. We must walk DOWN from declared accounts to discover their vaults.
//!
//! # Current Scope: Proof of Concept for Simple Transfers
//!
//! This implementation handles the basic case where:
//! - Transactions are simple account-to-account transfers.
//! - The transaction manifest declares the involved **account NodeIds** as
//!   `declared_reads`/`declared_writes`.
//! - Each account's vaults are discovered by scanning account substates for
//!   SBOR-encoded `Own(NodeId)` references.
//!
//! **This is NOT a general solution.** A full implementation would require:
//! - **Transaction preview/simulation** before submission to discover the
//!   complete read/write set (all NodeIds actually touched by the Radix Engine,
//!   including vaults, KV stores, proofs, buckets, etc.).
//! - The preview would provide vault NodeIds directly, eliminating the need
//!   for the walk-down heuristic.
//! - Complex transactions (DEX swaps, multi-component calls) touch entities
//!   beyond simple account vaults and would need preview to correctly declare
//!   their full dependency set.
//!
//! # Approach
//!
//! Filtering happens in two stages:
//!
//! **Stage 1: Ownership resolution** (`resolve_owned_nodes`)
//! Scans declared accounts' substates to discover which vault NodeIds they own.
//! Uses SBOR byte scanning to find `Own(NodeId)` references (tag `0x90` + 30 bytes).
//! Builds a map from each internal NodeId to its owning account.
//!
//! **Stage 2: Shard filtering** (`filter_updates_for_shard`)
//! Applies three filters:
//! - System entities (ConsensusManager, TransactionTracker, Validator) are dropped.
//! - Nodes not owned by any declared account are dropped (prevents non-deterministic
//!   writes from undeclared entities like fee vaults).
//! - Nodes assigned to other shards (based on owning account's hash) are dropped.
//!
//! # Why filter undeclared writes?
//!
//! The mempool prevents concurrent access to declared accounts. But the Radix
//! Engine also writes to undeclared entities (e.g. fee/royalty vaults owned by
//! the resource manager). These writes are invisible to the mempool's conflict
//! detection. If two transactions both touch the same fee vault, validators
//! that execute at different committed heights see different vault balances,
//! producing different DatabaseUpdates and divergent state roots.

use hyperscale_storage::{DatabaseUpdates, PartitionDatabaseUpdates};
pub use hyperscale_types::state_key::db_node_key_to_node_id;
use hyperscale_types::state_key::vm_db_node_key_owner;
use hyperscale_types::{NodeId, ShardId, ShardTrie, WritesRoot};
use radix_common::prelude::basic_encode;
use radix_common::types::NodeId as RadixNodeId;

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

// ============================================================================
// Utilities
// ============================================================================

/// Compute the `SpreadPrefixKeyMapper` `db_node_key` for a `NodeId`.
///
/// Returns the 50-byte key: 20-byte hash prefix + 30-byte `NodeId`.
#[must_use]
pub fn node_entity_key(node_id: &NodeId) -> Vec<u8> {
    use radix_substate_store_interface::db_key_mapper::{DatabaseKeyMapper, SpreadPrefixKeyMapper};
    let radix_node_id = RadixNodeId(node_id.0);
    SpreadPrefixKeyMapper::to_db_node_key(&radix_node_id)
}

#[cfg(test)]
mod tests {
    use hyperscale_storage::{
        DatabaseUpdate, DatabaseUpdates, DbSortKey, NodeDatabaseUpdates, PartitionDatabaseUpdates,
    };
    use hyperscale_types::state_key::{VM_PARTITION, vm_db_node_key};
    use hyperscale_types::{NodeId, ShardTrie, WritesRoot};
    use radix_substate_store_interface::db_key_mapper::{DatabaseKeyMapper, SpreadPrefixKeyMapper};

    use super::*;

    // ── Helpers ──────────────────────────────────────────────────────────────

    fn id_with_type(type_byte: u8, seed: u8) -> NodeId {
        let mut id = [seed; 30];
        id[0] = type_byte;
        NodeId(id)
    }

    fn account_id(seed: u8) -> NodeId {
        // 0x51 is a global account entity type — not in SYSTEM_ENTITY_TYPES
        // and not in INTERNAL_ENTITY_TYPES, matching production usage.
        id_with_type(0x51, seed)
    }

    fn fungible_vault_id(seed: u8) -> NodeId {
        id_with_type(0x58, seed)
    }

    fn make_set_update(
        node: NodeId,
        partition: u8,
        sort: Vec<u8>,
        value: Vec<u8>,
    ) -> DatabaseUpdates {
        let radix_node_id = RadixNodeId(node.0);
        let db_node_key = SpreadPrefixKeyMapper::to_db_node_key(&radix_node_id);
        let mut updates = DatabaseUpdates::default();
        let nu = updates
            .node_updates
            .entry(db_node_key)
            .or_insert_with(NodeDatabaseUpdates::default);
        nu.partition_updates.insert(
            partition,
            PartitionDatabaseUpdates::Delta {
                substate_updates: std::iter::once((DbSortKey(sort), DatabaseUpdate::Set(value)))
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

    // ── db_node_key_to_node_id ───────────────────────────────────────────────

    #[test]
    fn db_node_key_short_returns_none() {
        assert!(db_node_key_to_node_id(&[]).is_none());
        assert!(db_node_key_to_node_id(&[0u8; 49]).is_none());
    }

    #[test]
    fn db_node_key_round_trips_through_node_entity_key() {
        let node = fungible_vault_id(42);
        let key = node_entity_key(&node);
        assert_eq!(key.len(), 50);
        assert_eq!(db_node_key_to_node_id(&key), Some(node));
    }

    // ── is_internal_entity ───────────────────────────────────────────────────

    #[test]
    fn node_entity_key_has_node_id_suffix() {
        let node = fungible_vault_id(7);
        let key = node_entity_key(&node);
        assert_eq!(key.len(), 50);
        assert_eq!(&key[20..], &node.0);
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
        let a = account_id(1);
        let b = account_id(2);
        let forward = merge(
            make_set_update(a, 64, vec![0], vec![1]),
            make_set_update(b, 64, vec![0], vec![1]),
        );
        let reverse = merge(
            make_set_update(b, 64, vec![0], vec![1]),
            make_set_update(a, 64, vec![0], vec![1]),
        );
        assert_eq!(compute_writes_root(&forward), compute_writes_root(&reverse));
    }

    #[test]
    fn compute_writes_root_distinguishes_inputs() {
        let a = make_set_update(account_id(1), 64, vec![0], vec![1]);
        let b = make_set_update(account_id(2), 64, vec![0], vec![1]);
        assert_ne!(compute_writes_root(&a), compute_writes_root(&b));
    }

    // ── filter_updates_for_shard ─────────────────────────────────────────────

    /// A `DatabaseUpdates` holding one cell under `owner`.
    fn vm_set_update(owner: [u8; 16], local: [u8; 16], value: Vec<u8>) -> DatabaseUpdates {
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

    #[test]
    fn filter_for_shard_keeps_only_this_shard_prefixes() {
        let trie = ShardTrie::uniform_from_count(2);
        let left = [0x00; 16];
        let right = [0xFF; 16];
        assert_ne!(trie.shard_for_prefix(left), trie.shard_for_prefix(right));
        let updates = merge(
            vm_set_update(left, [1; 16], vec![1]),
            vm_set_update(right, [1; 16], vec![2]),
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
        // A Radix entity key survives genesis but is nobody's receipt
        // update, and the filter is the place that says so.
        let updates = make_set_update(account_id(1), 64, vec![0], vec![1]);
        let filtered =
            filter_updates_for_shard(&updates, ShardId::ROOT, &ShardTrie::uniform_from_count(1));
        assert!(filtered.node_updates.is_empty());
    }
}
