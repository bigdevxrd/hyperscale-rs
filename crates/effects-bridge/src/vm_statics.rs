//! The VM transaction's static derivation: the graph wire codec and the
//! [`VmStatics`] implementation admission verifies through.
//!
//! The graph travels as canonical basic-SBOR of the mirror types below —
//! the vocabulary crate deliberately has no wire encoding, so this module
//! owns it. Derivation is `decode → admit → route` over the process's
//! genesis-static metadata, projected into the workspace's admission
//! vocabulary: substate-granular keys for point effects, owner-granular
//! keys for collection effects (entries and ranges conflict at their
//! owner — conservative, never unsound), reads and snapshots in the
//! shared class, every other mode exclusive.

use std::collections::BTreeSet;

use hyperscale_types::{DeclaredKey, VmRouting, VmStatics, VmStaticsError};
use hyperscale_vm_effects::{
    Address, Constraint, EdgeRef, EffectSet, EffectTarget, GraphArg, GraphNode, InstanceRegistry,
    LocalKey, ManifestGraph, MetadataCache, Mode, PrefixShardResolver, SubstateKey, Value, admit,
    route,
};
use sbor::prelude::*;

use crate::ProtocolHasher;

/// Wire mirror of [`Value`].
#[derive(Clone, Debug, PartialEq, Eq, BasicSbor)]
enum WireValue {
    U64(u64),
    U128(u128),
    Bytes(Vec<u8>),
    Address([u8; 16]),
    Key([u8; 16], [u8; 16]),
    Bucket([u8; 16]),
    Tuple(Vec<Self>),
    List(Vec<Self>),
}

/// Wire mirror of [`Constraint`].
#[derive(Clone, Debug, PartialEq, Eq, BasicSbor)]
enum WireConstraint {
    MinAmount(u128),
    MaxAmount(u128),
    ResourceIs([u8; 16]),
}

/// Wire mirror of [`GraphArg`].
#[derive(Clone, Debug, PartialEq, Eq, BasicSbor)]
enum WireArg {
    Literal(WireValue),
    Edge {
        producer: u32,
        output: u32,
        constraints: Vec<WireConstraint>,
    },
}

/// Wire mirror of [`GraphNode`].
#[derive(Clone, Debug, PartialEq, Eq, BasicSbor)]
struct WireNode {
    target: [u8; 16],
    method: String,
    args: Vec<WireArg>,
}

/// Wire mirror of [`ManifestGraph`].
#[derive(Clone, Debug, PartialEq, Eq, BasicSbor)]
struct WireGraph {
    nodes: Vec<WireNode>,
}

fn wire_value(value: &Value) -> WireValue {
    match value {
        Value::U64(x) => WireValue::U64(*x),
        Value::U128(x) => WireValue::U128(*x),
        Value::Bytes(bytes) => WireValue::Bytes(bytes.clone()),
        Value::Address(address) => WireValue::Address(address.0),
        Value::Key(key) => WireValue::Key(key.owner.0, key.local.0),
        Value::Bucket { resource } => WireValue::Bucket(resource.0),
        Value::Tuple(fields) => WireValue::Tuple(fields.iter().map(wire_value).collect()),
        Value::List(items) => WireValue::List(items.iter().map(wire_value).collect()),
    }
}

fn value(wire: WireValue) -> Value {
    match wire {
        WireValue::U64(x) => Value::U64(x),
        WireValue::U128(x) => Value::U128(x),
        WireValue::Bytes(bytes) => Value::Bytes(bytes),
        WireValue::Address(address) => Value::Address(Address(address)),
        WireValue::Key(owner, local) => Value::Key(SubstateKey {
            owner: Address(owner),
            local: LocalKey(local),
        }),
        WireValue::Bucket(resource) => Value::Bucket {
            resource: Address(resource),
        },
        WireValue::Tuple(fields) => Value::Tuple(fields.into_iter().map(value).collect()),
        WireValue::List(items) => Value::List(items.into_iter().map(value).collect()),
    }
}

/// Encode a manifest graph into its canonical wire bytes.
///
/// # Panics
///
/// Never in practice: the mirror types are closed basic-SBOR shapes.
#[must_use]
pub fn encode_graph(graph: &ManifestGraph) -> Vec<u8> {
    let wire = WireGraph {
        nodes: graph
            .nodes
            .iter()
            .map(|node| WireNode {
                target: node.target.0,
                method: node.method.clone(),
                args: node
                    .args
                    .iter()
                    .map(|arg| match arg {
                        GraphArg::Literal(literal) => WireArg::Literal(wire_value(literal)),
                        GraphArg::Edge { edge, constraints } => WireArg::Edge {
                            producer: edge.producer,
                            output: edge.output,
                            constraints: constraints
                                .iter()
                                .map(|constraint| match constraint {
                                    Constraint::MinAmount(amount) => {
                                        WireConstraint::MinAmount(*amount)
                                    }
                                    Constraint::MaxAmount(amount) => {
                                        WireConstraint::MaxAmount(*amount)
                                    }
                                    Constraint::ResourceIs(resource) => {
                                        WireConstraint::ResourceIs(resource.0)
                                    }
                                })
                                .collect(),
                        },
                    })
                    .collect(),
            })
            .collect(),
    };
    basic_encode(&wire).expect("graph wire encode is infallible")
}

/// Decode wire bytes into a manifest graph.
///
/// # Errors
///
/// [`VmStaticsError`] on malformed bytes.
pub fn decode_graph(bytes: &[u8]) -> Result<ManifestGraph, VmStaticsError> {
    let wire: WireGraph =
        basic_decode(bytes).map_err(|error| VmStaticsError(format!("graph decode: {error:?}")))?;
    Ok(ManifestGraph {
        nodes: wire
            .nodes
            .into_iter()
            .map(|node| GraphNode {
                target: Address(node.target),
                method: node.method,
                args: node
                    .args
                    .into_iter()
                    .map(|arg| match arg {
                        WireArg::Literal(literal) => GraphArg::Literal(value(literal)),
                        WireArg::Edge {
                            producer,
                            output,
                            constraints,
                        } => GraphArg::Edge {
                            edge: EdgeRef { producer, output },
                            constraints: constraints
                                .into_iter()
                                .map(|constraint| match constraint {
                                    WireConstraint::MinAmount(amount) => {
                                        Constraint::MinAmount(amount)
                                    }
                                    WireConstraint::MaxAmount(amount) => {
                                        Constraint::MaxAmount(amount)
                                    }
                                    WireConstraint::ResourceIs(resource) => {
                                        Constraint::ResourceIs(Address(resource))
                                    }
                                })
                                .collect(),
                        },
                    })
                    .collect(),
            })
            .collect(),
    })
}

/// The admission key for one effect target: substate-granular for points,
/// owner-granular for collection targets.
const fn admission_key(target: &EffectTarget) -> DeclaredKey {
    match target {
        EffectTarget::Point(key) => DeclaredKey::substate(key.owner.0, key.local.0),
        EffectTarget::Entry { owner, .. } | EffectTarget::Range { owner, .. } => {
            DeclaredKey::prefix(owner.0)
        }
    }
}

fn key_owner(key: &DeclaredKey) -> [u8; 16] {
    match key {
        DeclaredKey::Prefix { owner, .. } => *owner,
        DeclaredKey::Node { .. } => unreachable!("VM derivation emits prefix keys only"),
    }
}

/// The bridge's [`VmStatics`]: `decode → admit → route` over the
/// process's genesis-static metadata.
pub struct BridgeStatics {
    /// Published package metadata, genesis-static this phase.
    pub cache: MetadataCache,
    /// Instance registrations, genesis-static this phase.
    pub instances: InstanceRegistry,
}

impl VmStatics for BridgeStatics {
    fn derive(&self, graph: &[u8]) -> Result<VmRouting, VmStaticsError> {
        let graph = decode_graph(graph)?;
        let admitted = admit(&graph, &self.cache, &self.instances, &ProtocolHasher)
            .map_err(|error| VmStaticsError(format!("admission: {error}")))?;
        let routing = route(
            &admitted.manifest,
            admitted.identity,
            &self.cache,
            &self.instances,
            &ProtocolHasher,
            &PrefixShardResolver { bits: 0 },
        )
        .map_err(|error| VmStaticsError(format!("routing: {error}")))?;

        let mut read_keys = BTreeSet::new();
        let mut write_keys = BTreeSet::new();
        for effect in routing.per_shard.values().flat_map(EffectSet::iter) {
            let key = admission_key(&effect.target);
            match effect.mode {
                Mode::Read | Mode::Snapshot { .. } => {
                    read_keys.insert(key);
                }
                Mode::Delta | Mode::Reserve { .. } | Mode::Write => {
                    write_keys.insert(key);
                }
            }
        }
        let prefixes = |keys: &BTreeSet<DeclaredKey>| -> Vec<[u8; 16]> {
            keys.iter()
                .map(key_owner)
                .collect::<BTreeSet<_>>()
                .into_iter()
                .collect()
        };
        Ok(VmRouting {
            read_prefixes: prefixes(&read_keys),
            write_prefixes: prefixes(&write_keys),
            read_keys: read_keys.into_iter().collect(),
            write_keys: write_keys.into_iter().collect(),
        })
    }
}

#[cfg(test)]
mod tests {
    use hyperscale_vm_effects::stdlib::{VAULT, account_metadata};
    use hyperscale_vm_effects::{Hasher, InstanceMeta, PackageHash, child_key};

    use super::*;

    const ALICE: Address = Address([0x10; 16]);
    const BOB: Address = Address([0x20; 16]);
    const USDC: Address = Address([0xE1; 16]);

    fn statics() -> BridgeStatics {
        let package = PackageHash(ProtocolHasher.hash(b"package", &[b"account"]));
        let mut cache = MetadataCache::new();
        cache.publish(package, account_metadata());
        let mut instances = InstanceRegistry::new();
        for address in [ALICE, BOB] {
            instances.register(
                address,
                InstanceMeta {
                    package,
                    config: vec![],
                },
            );
        }
        BridgeStatics { cache, instances }
    }

    fn transfer_graph() -> ManifestGraph {
        ManifestGraph {
            nodes: vec![
                GraphNode {
                    target: ALICE,
                    method: "withdraw".into(),
                    args: vec![
                        GraphArg::Literal(Value::Address(USDC)),
                        GraphArg::Literal(Value::U128(100)),
                    ],
                },
                GraphNode {
                    target: BOB,
                    method: "deposit".into(),
                    args: vec![GraphArg::Edge {
                        edge: EdgeRef {
                            producer: 0,
                            output: 0,
                        },
                        constraints: vec![Constraint::ResourceIs(USDC)],
                    }],
                },
            ],
        }
    }

    #[test]
    fn the_graph_codec_round_trips() {
        let graph = transfer_graph();
        let decoded = decode_graph(&encode_graph(&graph)).unwrap();
        assert_eq!(decoded, graph);
        assert!(decode_graph(&[0xFF, 0x00]).is_err());
    }

    #[test]
    fn a_transfer_derives_substate_keys_and_owner_prefixes() {
        let routing = statics()
            .derive(&encode_graph(&transfer_graph()))
            .expect("derives");

        // Reserve at the sender's vault and deltas at the recipient's:
        // all exclusive-class, substate-granular, under the two owners.
        let vault = |owner: Address| {
            child_key(
                &ProtocolHasher,
                owner,
                VAULT,
                &[Value::Address(USDC).canonical_bytes()],
            )
        };
        let sender_vault = vault(ALICE);
        assert!(
            routing
                .write_keys
                .contains(&DeclaredKey::substate(ALICE.0, sender_vault.local.0))
        );
        assert!(routing.read_keys.is_empty());
        assert_eq!(routing.write_prefixes, vec![ALICE.0, BOB.0]);
        assert_eq!(routing.all_prefixes(), vec![ALICE.0, BOB.0]);
    }

    #[test]
    fn an_inadmissible_graph_is_refused() {
        // The produced bucket is never consumed: linearity refuses it.
        let mut dangling = transfer_graph();
        dangling.nodes.truncate(1);
        assert!(statics().derive(&encode_graph(&dangling)).is_err());
    }
}
