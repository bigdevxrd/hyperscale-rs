//! Canonical state-keying.
//!
//! The single definition of how a substate's flat storage key becomes a JMT
//! leaf. The storage backend (JMT construction and merkle proof generation)
//! and the cross-shard provision proof verifier both derive leaves through
//! these functions, so the proving and verifying sides commit to one
//! identical key and value byte layout.
//!
//! A flat key is `VM_KEY_TAG || owner(16) || VM_PARTITION || local(16)`,
//! exactly [`VM_FLAT_KEY_LEN`] bytes, and reads as the identity leaf
//! `[owner | local]` — no hashing, no owner map.

use blake3::hash as blake3_hash;

use crate::NodeId;

/// First byte of every storage key — the tag a decoder checks before
/// splitting a key into its halves.
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

/// The 32-byte JMT leaf key of a flat storage key.
///
/// Identity: the key's owner and local halves *are* the leaf key, so an
/// owned object's leaf equals its creation owner by construction
/// (INV-VM-4) and every owner's footprint is a contiguous JMT subtree
/// under the shard prefix the owner's own bits name.
///
/// # Panics
///
/// Panics on a key that is not flat-shaped. Every key the engine commits
/// is; the one path taking untrusted keys (provision proof verification)
/// decodes through [`vm_flat_key_parts`] and refuses before keying.
#[must_use]
pub fn jmt_leaf_key(storage_key: &[u8]) -> [u8; 32] {
    let (owner, local) =
        vm_flat_key_parts(storage_key).expect("jmt_leaf_key requires a flat storage key");
    vm_leaf_key(owner, local)
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
/// Both halves of the leaf derive from the key itself, so the whole
/// identity leaf is checked — which is what ties a peer-shipped raw key
/// to a proven leaf (snap-sync chunk verification). A key that is not
/// flat-shaped binds nothing.
#[must_use]
pub fn leaf_key_binds_storage_key(leaf_key: &[u8; 32], storage_key: &[u8]) -> bool {
    vm_flat_key_parts(storage_key)
        .is_some_and(|(owner, local)| *leaf_key == vm_leaf_key(owner, local))
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
    fn jmt_leaf_key_is_owner_major() {
        let a = [1u8; 16];
        let b = [2u8; 16];
        let a0 = jmt_leaf_key(&vm_flat_key(a, [0u8; 16]));
        let a1 = jmt_leaf_key(&vm_flat_key(a, [7u8; 16]));
        // Two substates of one owner share the owner-major prefix but
        // differ in the local half.
        assert_eq!(a0[..16], a1[..16]);
        assert_ne!(a0[16..], a1[16..]);
        // A different owner lands under a different prefix.
        let b0 = jmt_leaf_key(&vm_flat_key(b, [0u8; 16]));
        assert_ne!(a0[..16], b0[..16]);
    }

    #[test]
    fn jmt_leaf_key_is_the_identity_of_its_halves() {
        let (owner, local) = ([9u8; 16], [3u8; 16]);
        let key = vm_flat_key(owner, local);
        assert_eq!(jmt_leaf_key(&key), vm_leaf_key(owner, local));
        assert_eq!(jmt_leaf_key(&key), jmt_leaf_key(&key));
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
        let leaf = jmt_leaf_key(&vm_flat_key(owner, local));
        assert_eq!(leaf, vm_leaf_key(owner, local));
        assert_eq!(leaf[..16], owner);
        assert_eq!(leaf[16..], local);
    }

    #[test]
    fn vm_leaves_of_one_owner_share_the_owner_half() {
        let owner = [0x11u8; 16];
        let a = jmt_leaf_key(&vm_flat_key(owner, [1u8; 16]));
        let b = jmt_leaf_key(&vm_flat_key(owner, [2u8; 16]));
        assert_eq!(a[..16], b[..16]);
        assert_ne!(a[16..], b[16..]);
        let other = jmt_leaf_key(&vm_flat_key([0x22u8; 16], [1u8; 16]));
        assert_ne!(a[..16], other[..16]);
    }

    #[test]
    fn leaf_key_binds_vm_storage_key_on_both_halves() {
        let key = vm_flat_key([0x11u8; 16], [0x22u8; 16]);
        let leaf = jmt_leaf_key(&key);
        assert!(leaf_key_binds_storage_key(&leaf, &key));

        let mut wrong_owner = leaf;
        wrong_owner[0] ^= 1;
        assert!(!leaf_key_binds_storage_key(&wrong_owner, &key));

        let mut wrong_local = leaf;
        wrong_local[16] ^= 1;
        assert!(!leaf_key_binds_storage_key(&wrong_local, &key));
    }

    /// A peer-shipped key that is not flat-shaped binds no leaf at all —
    /// snap-sync chunk verification refuses it rather than testing it
    /// against a partial rule.
    #[test]
    fn a_mistagged_key_binds_nothing() {
        let key = vm_flat_key([0x11u8; 16], [0x22u8; 16]);
        let leaf = jmt_leaf_key(&key);

        let mut mistagged = key.clone();
        mistagged[0] ^= 1;
        assert!(!leaf_key_binds_storage_key(&leaf, &mistagged));
        assert!(!leaf_key_binds_storage_key(&leaf, &key[..key.len() - 1]));
        assert!(!leaf_key_binds_storage_key(&leaf, &[]));
    }

    #[test]
    #[should_panic(expected = "flat storage key")]
    fn jmt_leaf_key_rejects_a_mistagged_key() {
        let mut key = vm_flat_key([1u8; 16], [2u8; 16]);
        key[0] ^= 1;
        let _ = jmt_leaf_key(&key);
    }
}
