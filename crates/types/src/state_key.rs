//! Canonical state-keying.
//!
//! The single definition of how a substate's flat storage key becomes a JMT
//! leaf, and how a `db_node_key` prefix decodes back to its [`NodeId`]. The
//! storage backend (JMT construction and merkle proof generation) and the
//! cross-shard provision proof verifier both derive leaves through these
//! functions, so the proving and verifying sides commit to one identical key,
//! value, and `NodeId` byte layout.
//!
//! Two key namespaces share the store. Radix keys are
//! `SpreadPrefixKeyMapper`-encoded (`db_node_key || partition || sort_key`)
//! and hash to their leaves. VM keys are
//! `VM_KEY_TAG || owner(16) || VM_PARTITION || local(16)` and read as the
//! identity leaf `[owner | local]` — no hashing, no owner map. A VM flat key
//! is exactly [`VM_FLAT_KEY_LEN`] bytes and a Radix key at least
//! [`DB_NODE_KEY_LEN`] + 1, so the namespaces are disjoint by length.

use blake3::hash as blake3_hash;

use crate::NodeId;

/// First byte of every VM storage key, keeping the VM namespace disjoint
/// from the Radix keys genesis still writes.
pub const VM_KEY_TAG: u8 = 0x56;

/// Length of the `SpreadPrefixKeyMapper` hash prefix that precedes the `NodeId`
/// in a `db_node_key`.
pub const DB_NODE_KEY_HASH_PREFIX_LEN: usize = 20;

/// Length of a `NodeId` in bytes.
pub const NODE_ID_LEN: usize = 30;

/// Length of a full `db_node_key`: hash prefix followed by the `NodeId`.
pub const DB_NODE_KEY_LEN: usize = DB_NODE_KEY_HASH_PREFIX_LEN + NODE_ID_LEN;

/// Length of a VM `db_node_key`: [`VM_KEY_TAG`] followed by the 16-byte
/// owner prefix.
pub const VM_DB_NODE_KEY_LEN: usize = 1 + 16;

/// Length of a full VM flat key: `db_node_key`, the partition byte, and the
/// 16-byte local half.
///
/// Fixed — both halves of a VM substate key are exactly 16 bytes, which is
/// what keeps the namespace disjoint from Radix keys by length alone.
pub const VM_FLAT_KEY_LEN: usize = VM_DB_NODE_KEY_LEN + 1 + 16;

/// The single partition of a VM owner's namespace.
pub const VM_PARTITION: u8 = 0x00;

/// Decode cap on a raw substate storage key.
///
/// Applied by every wire object carrying one (provisioned
/// `SubstateEntry`s and snap-sync `StateRangeLeaf`s alike) — one limit,
/// so anything that can be committed can also be provisioned and
/// served.
///
/// Real keys are `db_node_key` (50 bytes) + partition (1) + `sort_key`
/// (≤ a few hundred bytes for any realistic substate). 4 KiB is well
/// above any legitimate Radix substate key and rejects obviously
/// oversized arrivals before allocation.
pub const MAX_STATE_ENTRY_KEY_LEN: usize = 4 * 1024;

/// Decode cap on a raw substate value, shared by the same wire objects
/// as [`MAX_STATE_ENTRY_KEY_LEN`].
///
/// Bounds the SBOR `Vec<u8>` pre-allocation a peer can force on a single
/// `value` field, and sets the largest thing state can hold in one cell.
/// Twice [`crate::MAX_TX_BYTES_LEN`], so anything a transaction can carry
/// still fits a cell with the framing around it — which is what lets a
/// published package artifact be one value rather than a chunked set.
pub const MAX_STATE_ENTRY_VALUE_LEN: usize = 2 * 1024 * 1024;

/// The VM `db_node_key` for `owner`: `VM_KEY_TAG || owner`.
#[must_use]
pub fn vm_db_node_key(owner: [u8; 16]) -> Vec<u8> {
    let mut key = Vec::with_capacity(VM_DB_NODE_KEY_LEN);
    key.push(VM_KEY_TAG);
    key.extend_from_slice(&owner);
    key
}

/// The full VM flat storage key for one substate:
/// `VM_KEY_TAG || owner || VM_PARTITION || local`.
#[must_use]
pub fn vm_flat_key(owner: [u8; 16], local: [u8; 16]) -> Vec<u8> {
    let mut key = Vec::with_capacity(VM_FLAT_KEY_LEN);
    key.push(VM_KEY_TAG);
    key.extend_from_slice(&owner);
    key.push(VM_PARTITION);
    key.extend_from_slice(&local);
    key
}

/// Decode a VM flat key into its `(owner, local)` halves, or `None` when the
/// key is not exactly VM-shaped (wrong length, tag, or partition byte).
///
/// The namespace discriminator: every keying path branches on this before
/// falling through to the Radix arm.
#[must_use]
pub fn vm_flat_key_parts(storage_key: &[u8]) -> Option<([u8; 16], [u8; 16])> {
    if storage_key.len() != VM_FLAT_KEY_LEN
        || storage_key[0] != VM_KEY_TAG
        || storage_key[VM_DB_NODE_KEY_LEN] != VM_PARTITION
    {
        return None;
    }
    let owner = storage_key[1..VM_DB_NODE_KEY_LEN].try_into().ok()?;
    let local = storage_key[VM_DB_NODE_KEY_LEN + 1..].try_into().ok()?;
    Some((owner, local))
}

/// The owner prefix of a VM `db_node_key` (an entity key as carried in
/// `DatabaseUpdates`), or `None` when the key is not exactly VM-shaped.
#[must_use]
pub fn vm_db_node_key_owner(db_node_key: &[u8]) -> Option<[u8; 16]> {
    if db_node_key.len() != VM_DB_NODE_KEY_LEN || db_node_key[0] != VM_KEY_TAG {
        return None;
    }
    db_node_key[1..].try_into().ok()
}

/// The identity JMT leaf key of a VM substate: `[owner | local]`.
///
/// No hashing — the leaf key *is* the substate key, so an owned object's leaf
/// equals its creation owner by construction (INV-VM-4) and every VM owner's
/// footprint is a contiguous JMT subtree under the shard prefix the owner's
/// own bits name (`ShardTrie::shard_for_prefix` and leaf placement agree with
/// no translation).
#[must_use]
pub fn vm_leaf_key(owner: [u8; 16], local: [u8; 16]) -> [u8; 32] {
    let mut key = [0u8; 32];
    key[..16].copy_from_slice(&owner);
    key[16..].copy_from_slice(&local);
    key
}

/// Hash a flat storage key (`db_node_key || partition_num || sort_key`) to its
/// 32-byte JMT leaf key.
///
/// A VM flat key ([`vm_flat_key`]) maps by identity — [`vm_leaf_key`] of its
/// halves; the `owner` argument applies only to the Radix arm (a VM key embeds
/// its owner and never appears in an ownership map).
///
/// A Radix key is owner-major: the high 16 bytes are `blake3(routing_node)`, where
/// `routing_node` is `owner` for an internal/owned node (vault, KV store) and
/// the node itself for a globally-addressed entity (`owner == None`). The low
/// 16 bytes are `blake3(storage_key)` over the *whole* key, which embeds the
/// node's own id and so disambiguates sibling internal nodes that share an
/// owner prefix. Every substate of one owner — the account and the vaults/KV
/// stores it owns — shares the high half, so an account's full footprint forms
/// a contiguous JMT subtree under one shard prefix.
///
/// Internal nodes have random `NodeId`s unrelated to their owner; without
/// owner-prefixing they would scatter across shard prefixes and break the
/// prefix-subtree invariant. The owner is the node's global ancestor, resolved
/// from the ownership map the executor already computes (and ships in the
/// receipt) — see [`crate::ConsensusReceipt`].
///
/// A non-VM `storage_key` must begin with a `db_node_key` — every key the
/// engine commits and every key proof generation reads is
/// `SpreadPrefixKeyMapper` encoded, so this holds by construction. The one
/// path taking untrusted keys (provision proof verification) rejects
/// malformed entries before keying.
///
/// # Panics
///
/// Panics if `storage_key` is neither VM-shaped nor at least a `db_node_key`
/// long.
#[must_use]
pub fn jmt_leaf_key(storage_key: &[u8], owner: Option<NodeId>) -> [u8; 32] {
    if let Some((vm_owner, local)) = vm_flat_key_parts(storage_key) {
        return vm_leaf_key(vm_owner, local);
    }
    let node_id = db_node_key_to_node_id(storage_key)
        .expect("jmt_leaf_key requires a VM flat key or db_node_key-prefixed storage key");
    let routing_node = owner.unwrap_or(node_id);
    let node_hash = node_routing_hash(&routing_node);
    let substate_hash = blake3_hash(storage_key);
    let mut key = [0u8; 32];
    key[..16].copy_from_slice(&node_hash[..16]);
    key[16..].copy_from_slice(&substate_hash.as_bytes()[..16]);
    key
}

/// The owner-major routing hash whose leading bytes form a leaf key's
/// high half — the bits a shard prefix routes and partitions on.
///
/// Every substate of one routing node (the entity itself, or the global
/// owner of an internal node) shares it, so "which shard prefix does
/// this entity's state sit under" is a test against this hash alone.
#[must_use]
pub fn node_routing_hash(routing_node: &NodeId) -> [u8; 32] {
    *blake3_hash(&routing_node.0).as_bytes()
}

/// Hash a substate value to the 32-byte value hash held in its JMT leaf.
#[must_use]
pub fn jmt_value_hash(value: &[u8]) -> [u8; 32] {
    *blake3_hash(value).as_bytes()
}

/// Whether `leaf_key` binds `storage_key`.
///
/// For a Radix key: the leaf's low half equals `blake3(storage_key)`'s. The
/// high (owner-routing) half is positional — attested by whatever proof the
/// leaf arrives under — so a verifier without the ownership map checks
/// exactly the low half to tie a shipped raw key to a proven leaf (snap-sync
/// chunk verification).
///
/// For a VM flat key both halves derive from the key itself, so the whole
/// identity leaf is checked.
#[must_use]
pub fn leaf_key_binds_storage_key(leaf_key: &[u8; 32], storage_key: &[u8]) -> bool {
    if let Some((owner, local)) = vm_flat_key_parts(storage_key) {
        return *leaf_key == vm_leaf_key(owner, local);
    }
    leaf_key[16..] == blake3_hash(storage_key).as_bytes()[..16]
}

/// Decode the [`NodeId`] embedded in a `db_node_key` (or any storage key that
/// begins with one). Returns `None` when the slice is shorter than a full
/// `db_node_key`.
///
/// Layout: `[hash prefix: DB_NODE_KEY_HASH_PREFIX_LEN][NodeId: NODE_ID_LEN]`.
#[must_use]
pub fn db_node_key_to_node_id(db_node_key: &[u8]) -> Option<NodeId> {
    if db_node_key.len() < DB_NODE_KEY_LEN {
        return None;
    }
    let mut id = [0u8; NODE_ID_LEN];
    id.copy_from_slice(&db_node_key[DB_NODE_KEY_HASH_PREFIX_LEN..DB_NODE_KEY_LEN]);
    Some(NodeId(id))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a well-formed storage key: zeroed hash prefix, then the node id,
    /// then a partition byte and sort key.
    fn storage_key(node: NodeId, partition: u8, sort: &[u8]) -> Vec<u8> {
        let mut key = vec![0u8; DB_NODE_KEY_HASH_PREFIX_LEN];
        key.extend_from_slice(&node.0);
        key.push(partition);
        key.extend_from_slice(sort);
        key
    }

    #[test]
    fn db_node_key_to_node_id_extracts_embedded_id() {
        let node = NodeId([7u8; NODE_ID_LEN]);
        assert_eq!(
            db_node_key_to_node_id(&storage_key(node, 0, b"sort")),
            Some(node)
        );
    }

    #[test]
    fn db_node_key_to_node_id_rejects_short_key() {
        assert_eq!(db_node_key_to_node_id(&[]), None);
        assert_eq!(db_node_key_to_node_id(&[0u8; DB_NODE_KEY_LEN - 1]), None);
    }

    #[test]
    fn jmt_leaf_key_is_node_major() {
        let a = NodeId([1u8; NODE_ID_LEN]);
        let b = NodeId([2u8; NODE_ID_LEN]);
        let a0 = jmt_leaf_key(&storage_key(a, 0, b"x"), None);
        let a1 = jmt_leaf_key(&storage_key(a, 7, b"yy"), None);
        // Two substates of one node share the node-major prefix but differ in
        // the substate half.
        assert_eq!(a0[..16], a1[..16]);
        assert_ne!(a0[16..], a1[16..]);
        // A different node lands under a different prefix.
        let b0 = jmt_leaf_key(&storage_key(b, 0, b"x"), None);
        assert_ne!(a0[..16], b0[..16]);
    }

    #[test]
    fn jmt_leaf_key_is_deterministic() {
        let key = storage_key(NodeId([9u8; NODE_ID_LEN]), 3, b"sort");
        assert_eq!(jmt_leaf_key(&key, None), jmt_leaf_key(&key, None));
    }

    #[test]
    fn owner_prefixing_folds_internal_node_under_owner() {
        let owner = NodeId([1u8; NODE_ID_LEN]);
        let vault = NodeId([200u8; NODE_ID_LEN]);
        // The account's own substate (owner = self) and the vault keyed under
        // its owner share the high-half owner prefix.
        let account_key = jmt_leaf_key(&storage_key(owner, 0, b"x"), None);
        let vault_key = jmt_leaf_key(&storage_key(vault, 0, b"x"), Some(owner));
        assert_eq!(account_key[..16], vault_key[..16]);
        // Unprefixed, the vault would land under its own (unrelated) prefix.
        let vault_unprefixed = jmt_leaf_key(&storage_key(vault, 0, b"x"), None);
        assert_ne!(account_key[..16], vault_unprefixed[..16]);
    }

    #[test]
    fn vm_flat_key_roundtrips_its_parts() {
        let owner = [0xA5u8; 16];
        let local = [0x3Cu8; 16];
        let key = vm_flat_key(owner, local);
        assert_eq!(key.len(), VM_FLAT_KEY_LEN);
        assert_eq!(vm_flat_key_parts(&key), Some((owner, local)));
        assert_eq!(vm_db_node_key_owner(&vm_db_node_key(owner)), Some(owner));
    }

    #[test]
    fn vm_flat_key_parts_rejects_non_vm_shapes() {
        let good = vm_flat_key([1u8; 16], [2u8; 16]);

        let mut wrong_tag = good.clone();
        wrong_tag[0] ^= 1;
        assert_eq!(vm_flat_key_parts(&wrong_tag), None);

        let mut wrong_partition = good.clone();
        wrong_partition[VM_DB_NODE_KEY_LEN] = 1;
        assert_eq!(vm_flat_key_parts(&wrong_partition), None);

        let mut wrong_len = good.clone();
        wrong_len.push(0);
        assert_eq!(vm_flat_key_parts(&wrong_len), None);
        assert_eq!(vm_flat_key_parts(&good[..VM_FLAT_KEY_LEN - 1]), None);

        // A Radix key never parses as VM-shaped, whatever its first byte.
        let mut radix = storage_key(NodeId([3u8; NODE_ID_LEN]), 0, b"sort");
        radix[0] = VM_KEY_TAG;
        assert_eq!(vm_flat_key_parts(&radix), None);

        assert_eq!(vm_db_node_key_owner(&good), None); // full key, not entity key
        assert_eq!(vm_db_node_key_owner(&wrong_tag[..VM_DB_NODE_KEY_LEN]), None);
    }

    #[test]
    fn jmt_leaf_key_vm_arm_is_the_identity() {
        let owner = [0xA5u8; 16];
        let local = [0x3Cu8; 16];
        let leaf = jmt_leaf_key(&vm_flat_key(owner, local), None);
        assert_eq!(leaf, vm_leaf_key(owner, local));
        assert_eq!(leaf[..16], owner);
        assert_eq!(leaf[16..], local);
    }

    #[test]
    fn vm_leaves_of_one_owner_share_the_owner_half() {
        let owner = [0x11u8; 16];
        let a = jmt_leaf_key(&vm_flat_key(owner, [1u8; 16]), None);
        let b = jmt_leaf_key(&vm_flat_key(owner, [2u8; 16]), None);
        assert_eq!(a[..16], b[..16]);
        assert_ne!(a[16..], b[16..]);
        let other = jmt_leaf_key(&vm_flat_key([0x22u8; 16], [1u8; 16]), None);
        assert_ne!(a[..16], other[..16]);
    }

    #[test]
    fn leaf_key_binds_vm_storage_key_on_both_halves() {
        let key = vm_flat_key([0x11u8; 16], [0x22u8; 16]);
        let leaf = jmt_leaf_key(&key, None);
        assert!(leaf_key_binds_storage_key(&leaf, &key));

        let mut wrong_owner = leaf;
        wrong_owner[0] ^= 1;
        assert!(!leaf_key_binds_storage_key(&wrong_owner, &key));

        let mut wrong_local = leaf;
        wrong_local[16] ^= 1;
        assert!(!leaf_key_binds_storage_key(&wrong_local, &key));
    }

    #[test]
    #[should_panic(expected = "db_node_key")]
    fn jmt_leaf_key_rejects_a_mistagged_vm_length_key() {
        let mut key = vm_flat_key([1u8; 16], [2u8; 16]);
        key[0] ^= 1;
        let _ = jmt_leaf_key(&key, None);
    }

    #[test]
    fn sibling_internal_nodes_share_prefix_but_disambiguate() {
        // Two vaults owned by the same account share the owner prefix yet must
        // not collide even when their substate (partition + sort key) matches —
        // the low half hashes the full key, which embeds each vault's own id.
        let owner = NodeId([1u8; NODE_ID_LEN]);
        let v1 = NodeId([10u8; NODE_ID_LEN]);
        let v2 = NodeId([20u8; NODE_ID_LEN]);
        let k1 = jmt_leaf_key(&storage_key(v1, 0, b"balance"), Some(owner));
        let k2 = jmt_leaf_key(&storage_key(v2, 0, b"balance"), Some(owner));
        assert_eq!(k1[..16], k2[..16]);
        assert_ne!(k1, k2);
    }
}
