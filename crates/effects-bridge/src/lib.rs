//! The workspace's binding to the VM effect vocabulary.
//!
//! Two pieces. [`ProtocolHasher`] puts the protocol hash — blake3 — behind
//! the `vm_effects` hashing seam: domain-separated and length-framed, so a
//! part boundary is always semantic. [`declared_effects`] adapts a
//! transaction's wire declarations to per-shard effect sets: declared
//! reads become `read`-mode and declared writes `write`-mode point
//! effects, under a deterministic `NodeId` to [`Address`] projection
//! through the same hasher, grouped by the topology's shard routing.
//!
//! Wire declarations are node-granular and worktop-conservative, so the
//! derived sets bound a transaction's true effects from above — the
//! fidelity limit of this adapter. Its output is observational: recorded
//! and asserted for determinism via [`routing_digest`], never a consensus
//! artifact or an admission input.

pub mod artifact;
pub mod staking;
pub mod vm_metadata;
pub mod vm_statics;
mod wire;

use std::collections::BTreeMap;

pub use artifact::{METADATA_SECTION, admit_package, attach_metadata, extract_metadata};
use blake3::Hasher as Blake3;
use hyperscale_types::{NodeId, RoutableTransaction, ShardId, TopologySnapshot};
use hyperscale_vm_effects::{
    Address, Effect, EffectSet, EffectTarget, Hash32, Hasher, LocalKey, Mode, SubstateKey,
};
pub use staking::{PoolRegistry, witness_from_event};
pub use vm_metadata::{MAX_PACKAGE_METADATA_BYTES, decode_metadata, encode_metadata};
pub use vm_statics::{
    BridgeStatics, VM_XRD, decode_tree, encode_tree, entropy_key, envelope_identity, vault_key,
    vm_account_address,
};

const DOMAIN_NODE_ADDRESS: &[u8] = b"hyperscale/effects-bridge/node-address";
const DOMAIN_ROUTING_DIGEST: &[u8] = b"hyperscale/effects-bridge/routing-digest";

/// The protocol hash behind the `vm_effects` hashing seam: blake3 over the
/// length-framed domain and parts. Pure, and framed so that moving bytes
/// across a part boundary always changes the digest.
#[derive(Clone, Copy, Debug, Default)]
pub struct ProtocolHasher;

impl Hasher for ProtocolHasher {
    fn hash(&self, domain: &[u8], parts: &[&[u8]]) -> Hash32 {
        let mut hasher = Blake3::new();
        hasher.update(&(domain.len() as u64).to_le_bytes());
        hasher.update(domain);
        for part in parts {
            hasher.update(&(part.len() as u64).to_le_bytes());
            hasher.update(part);
        }
        Hash32(*hasher.finalize().as_bytes())
    }
}

/// The point key standing for one whole declared node: the node's bytes
/// projected to an owner address through the protocol hash, with the zero
/// local slot marking node granularity — wire declarations carry no finer
/// key.
fn node_key(node: &NodeId) -> SubstateKey {
    let digest = ProtocolHasher.hash(DOMAIN_NODE_ADDRESS, &[&node.0]);
    let mut owner = [0u8; 16];
    owner.copy_from_slice(&digest.0[..16]);
    SubstateKey {
        owner: Address(owner),
        local: LocalKey([0; 16]),
    }
}

/// Per-shard effect sets for a transaction's wire declarations.
///
/// Each declared read is a `read`-mode point effect and each declared
/// write a `write`-mode point effect, filed under the shard the topology
/// routes the node to. A pure function of the declarations and the
/// topology.
///
/// # Panics
///
/// Never: read and write effects cannot overflow a reserve fold.
#[must_use]
pub fn declared_effects(
    tx: &RoutableTransaction,
    topology: &TopologySnapshot,
) -> BTreeMap<ShardId, EffectSet> {
    let mut by_shard: BTreeMap<ShardId, EffectSet> = BTreeMap::new();
    for (nodes, mode) in [
        (tx.declared_reads(), Mode::Read),
        (tx.declared_writes(), Mode::Write),
    ] {
        for node in nodes.iter() {
            by_shard
                .entry(topology.shard_for_node_id(node))
                .or_default()
                .insert(Effect {
                    target: EffectTarget::Point(node_key(node)),
                    mode,
                })
                .expect("read and write effects never fold reserve amounts");
        }
    }
    by_shard
}

/// A deterministic digest over per-shard effect sets.
///
/// Equal maps digest equally on every node, and any change of shard,
/// target, or mode changes the digest — the property the determinism
/// suite asserts. One framed part per shard, each a fixed-width encoding
/// of the shard id and its canonically ordered effects.
#[must_use]
pub fn routing_digest(effects: &BTreeMap<ShardId, EffectSet>) -> Hash32 {
    let sections: Vec<Vec<u8>> = effects
        .iter()
        .map(|(shard, set)| {
            let mut bytes = Vec::new();
            bytes.extend_from_slice(&shard.depth().to_le_bytes());
            bytes.extend_from_slice(&shard.path().to_le_bytes());
            for effect in set.iter() {
                encode_effect(&mut bytes, &effect);
            }
            bytes
        })
        .collect();
    let parts: Vec<&[u8]> = sections.iter().map(Vec::as_slice).collect();
    ProtocolHasher.hash(DOMAIN_ROUTING_DIGEST, &parts)
}

/// Fixed-width, tag-prefixed encoding of one effect; unambiguous by
/// construction, so the digest needs no further framing within a shard
/// section.
fn encode_effect(bytes: &mut Vec<u8>, effect: &Effect) {
    match effect.target {
        EffectTarget::Point(key) => {
            bytes.push(0);
            bytes.extend_from_slice(&key.owner.0);
            bytes.extend_from_slice(&key.local.0);
        }
        EffectTarget::Entry {
            owner,
            collection,
            order,
        } => {
            bytes.push(1);
            bytes.extend_from_slice(&owner.0);
            bytes.extend_from_slice(&collection.0.to_le_bytes());
            bytes.extend_from_slice(&order.to_le_bytes());
        }
        EffectTarget::Range {
            owner,
            collection,
            lo,
            hi,
            cap,
        } => {
            bytes.push(2);
            bytes.extend_from_slice(&owner.0);
            bytes.extend_from_slice(&collection.0.to_le_bytes());
            bytes.extend_from_slice(&lo.to_le_bytes());
            bytes.extend_from_slice(&hi.to_le_bytes());
            bytes.extend_from_slice(&cap.to_le_bytes());
        }
    }
    match effect.mode {
        Mode::Read => bytes.push(0),
        Mode::Locked => bytes.push(1),
        Mode::Delta => bytes.push(3),
        Mode::Reserve { amount } => {
            bytes.push(4);
            bytes.extend_from_slice(&amount.to_le_bytes());
        }
        Mode::Write => bytes.push(5),
    }
}

#[cfg(test)]
mod tests {
    use hyperscale_types::test_utils::{TestCommittee, test_node, test_transaction_with_nodes};
    use hyperscale_types::{NodeId, TopologySnapshot};
    use hyperscale_vm_effects::{Effect, EffectSet, EffectTarget, Hasher, Mode};

    use super::{ProtocolHasher, declared_effects, node_key, routing_digest};

    fn two_shard_topology() -> TopologySnapshot {
        TestCommittee::new(4, 7).topology_snapshot(2)
    }

    #[test]
    fn the_protocol_hasher_is_deterministic_framed_and_domain_separated() {
        let a = ProtocolHasher.hash(b"d", &[b"ab", b"c"]);
        assert_eq!(a, ProtocolHasher.hash(b"d", &[b"ab", b"c"]));
        // Part boundaries are semantic.
        assert_ne!(a, ProtocolHasher.hash(b"d", &[b"a", b"bc"]));
        assert_ne!(a, ProtocolHasher.hash(b"d", &[b"abc"]));
        // Domains separate.
        assert_ne!(a, ProtocolHasher.hash(b"e", &[b"ab", b"c"]));
    }

    #[test]
    fn effects_map_modes_and_group_by_the_topology_shard() {
        let topology = two_shard_topology();
        let reads = vec![test_node(0), test_node(1)];
        let writes = vec![test_node(10)];
        let tx = test_transaction_with_nodes(&[1, 2, 3], reads.clone(), writes.clone());

        let effects = declared_effects(&tx, &topology);
        let declared: Vec<(&NodeId, Mode)> = reads
            .iter()
            .map(|node| (node, Mode::Read))
            .chain(writes.iter().map(|node| (node, Mode::Write)))
            .collect();
        for (node, mode) in declared {
            let shard = topology.shard_for_node_id(node);
            assert!(
                effects[&shard].contains(&Effect {
                    target: EffectTarget::Point(node_key(node)),
                    mode,
                }),
                "{node:?} missing from {shard:?} as {mode:?}"
            );
        }
        assert_eq!(effects.values().map(EffectSet::len).sum::<usize>(), 3);
    }

    #[test]
    fn the_adapter_and_digest_are_deterministic() {
        let topology = two_shard_topology();
        let build = || {
            let tx = test_transaction_with_nodes(
                &[4, 5, 6],
                vec![test_node(2), test_node(3)],
                vec![test_node(20), test_node(21)],
            );
            declared_effects(&tx, &topology)
        };
        let (first, second) = (build(), build());
        assert_eq!(first, second);
        assert_eq!(routing_digest(&first), routing_digest(&second));
    }

    #[test]
    fn the_digest_separates_node_mode_and_shard() {
        let topology = two_shard_topology();
        let digest_of = |reads: Vec<NodeId>, writes: Vec<NodeId>| {
            let tx = test_transaction_with_nodes(&[9, 9, 9], reads, writes);
            routing_digest(&declared_effects(&tx, &topology))
        };
        let baseline = digest_of(vec![test_node(0)], vec![test_node(10)]);
        // A different node changes the digest.
        assert_ne!(baseline, digest_of(vec![test_node(1)], vec![test_node(10)]));
        // The same node under the opposite mode changes the digest.
        assert_ne!(baseline, digest_of(vec![test_node(10)], vec![test_node(0)]));
        // Dropping a declaration changes the digest.
        assert_ne!(baseline, digest_of(vec![test_node(0)], vec![]));
    }
}
