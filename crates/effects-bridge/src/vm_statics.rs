//! The VM envelope's static derivation: the tree wire codec and the
//! [`VmStatics`] implementation admission verifies through.
//!
//! The envelope tree travels as canonical basic-SBOR of the mirror types
//! below — the vocabulary crate deliberately has no wire encoding, so
//! this module owns it. Derivation is `decode → admit → route` over the
//! process's genesis-static metadata, rooted at the envelope's signing
//! hash, projected into the workspace's admission vocabulary:
//! substate-granular keys for point effects, owner-granular keys for
//! collection effects (entries and ranges conflict at their owner —
//! conservative, never unsound), reads and snapshots in the shared
//! class, every other mode exclusive. Subintent nullifier creation
//! writes ride the routed sets, so admission conflicts on them like any
//! other exclusive key.

use std::collections::BTreeSet;

use hyperscale_types::{
    DeclaredKey, VmDerived, VmRouting, VmStatics, VmStaticsError, VmTransaction,
};
use hyperscale_vm_effects::stdlib::{ENTROPY, VAULT};
use hyperscale_vm_effects::{
    Address, Constraint, EdgeRef, EffectSet, EffectTarget, EnvelopeTree, GraphArg, GraphNode,
    Hash32, InstanceRegistry, IntentDecl, ManifestGraph, ManifestHash, MetadataCache, Mode,
    PackageHash, PrefixShardResolver, RoleId, Subintent, SubstateKey, Value, YieldBinding,
    YieldParam, admit_tree, child_key, package_hash, route_tree,
};
use sbor::prelude::*;

use crate::ProtocolHasher;
use crate::artifact::admit_package;
use crate::wire::{WireValue, value, wire_value};

const DOMAIN_VM_ACCOUNT: &[u8] = b"hyperscale/engine-vm/account-address";

/// The native fee/transfer resource of the VM namespace.
pub const VM_XRD: Address = Address([0x58; 16]);

/// The vault cell for `resource` under `owner` — the same child key the
/// stdlib account metadata's effect clauses compute.
#[must_use]
pub fn vault_key(owner: [u8; 16], resource: Address) -> SubstateKey {
    child_key(
        &ProtocolHasher,
        Address(owner),
        VAULT,
        &[Value::Address(resource).canonical_bytes()],
    )
}

/// An account's entropy leaf: where the stdlib's `stamp-entropy` records
/// the transaction's randomness draw. Mirrors the effect signature the
/// method declares.
#[must_use]
pub fn entropy_key(owner: [u8; 16]) -> SubstateKey {
    child_key(&ProtocolHasher, Address(owner), ENTROPY, &[])
}

/// The role a published package's artifact sits under, in the reserved
/// band the vocabulary's nullifier role occupies the top of.
///
/// A package cell lives under its publisher's own prefix, and no
/// package's metadata can declare an effect on this role — the account
/// signatures name vault, claims, config and entropy — so the cell is
/// reachable by the publish path and by nothing else.
pub const PACKAGE_ROLE: RoleId = RoleId(0xFFFE);

/// Where `publisher`'s copy of the package addressed by `package` lives.
///
/// Keyed by content address under the publisher, so republishing the
/// same artifact is the same cell — which is what makes publishing
/// idempotent rather than a conflict.
#[must_use]
pub fn package_key(publisher: [u8; 16], package: PackageHash) -> SubstateKey {
    child_key(
        &ProtocolHasher,
        Address(publisher),
        PACKAGE_ROLE,
        &[package.0.0.to_vec()],
    )
}

/// The VM account address owned by an ed25519 public key: the protocol
/// hash of the key, truncated to the owner-prefix width.
///
/// Deterministic — genesis funding, transaction builders, and admission
/// all derive the same address from the same key.
#[must_use]
pub fn vm_account_address(public_key: &[u8; 32]) -> [u8; 16] {
    use hyperscale_vm_effects::Hasher as _;
    let digest = ProtocolHasher.hash(DOMAIN_VM_ACCOUNT, &[public_key]);
    let mut address = [0u8; 16];
    address.copy_from_slice(&digest.0[..16]);
    address
}

/// Wire mirror of [`Constraint`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, BasicSbor)]
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
    Param(u32),
}

/// Wire mirror of [`GraphNode`].
#[derive(Clone, Debug, PartialEq, Eq, BasicSbor)]
struct WireNode {
    target: [u8; 16],
    method: String,
    args: Vec<WireArg>,
}

/// Wire mirror of [`IntentDecl`]: a graph plus its declared yield
/// parameters.
#[derive(Clone, Debug, PartialEq, Eq, BasicSbor)]
struct WireIntent {
    nodes: Vec<WireNode>,
    params: Vec<WireParam>,
}

/// Wire mirror of [`YieldParam`].
#[derive(Clone, Debug, PartialEq, Eq, BasicSbor)]
struct WireParam {
    resource: [u8; 16],
    constraints: Vec<WireConstraint>,
}

/// Wire mirror of [`YieldBinding`].
#[derive(Clone, Debug, PartialEq, Eq, BasicSbor)]
struct WireBinding {
    intent: u32,
    producer: u32,
    output: u32,
}

/// Wire mirror of [`Subintent`].
#[derive(Clone, Debug, PartialEq, Eq, BasicSbor)]
struct WireSubintent {
    decl: WireIntent,
    signer: [u8; 16],
    bindings: Vec<WireBinding>,
}

/// Wire mirror of [`EnvelopeTree`].
#[derive(Clone, Debug, PartialEq, Eq, BasicSbor)]
struct WireTree {
    root: WireIntent,
    root_bindings: Vec<WireBinding>,
    subintents: Vec<WireSubintent>,
}

const fn wire_constraint(constraint: &Constraint) -> WireConstraint {
    match constraint {
        Constraint::MinAmount(amount) => WireConstraint::MinAmount(*amount),
        Constraint::MaxAmount(amount) => WireConstraint::MaxAmount(*amount),
        Constraint::ResourceIs(resource) => WireConstraint::ResourceIs(resource.0),
    }
}

const fn constraint(wire: WireConstraint) -> Constraint {
    match wire {
        WireConstraint::MinAmount(amount) => Constraint::MinAmount(amount),
        WireConstraint::MaxAmount(amount) => Constraint::MaxAmount(amount),
        WireConstraint::ResourceIs(resource) => Constraint::ResourceIs(Address(resource)),
    }
}

fn wire_intent(decl: &IntentDecl) -> WireIntent {
    WireIntent {
        nodes: decl
            .graph
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
                            constraints: constraints.iter().map(wire_constraint).collect(),
                        },
                        GraphArg::Param(param) => WireArg::Param(*param),
                    })
                    .collect(),
            })
            .collect(),
        params: decl
            .params
            .iter()
            .map(|param| WireParam {
                resource: param.resource.0,
                constraints: param.constraints.iter().map(wire_constraint).collect(),
            })
            .collect(),
    }
}

fn intent(wire: WireIntent) -> IntentDecl {
    IntentDecl {
        graph: ManifestGraph {
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
                                constraints: constraints.into_iter().map(constraint).collect(),
                            },
                            WireArg::Param(param) => GraphArg::Param(param),
                        })
                        .collect(),
                })
                .collect(),
        },
        params: wire
            .params
            .into_iter()
            .map(|param| YieldParam {
                resource: Address(param.resource),
                constraints: param.constraints.into_iter().map(constraint).collect(),
            })
            .collect(),
    }
}

fn wire_bindings(bindings: &[YieldBinding]) -> Vec<WireBinding> {
    bindings
        .iter()
        .map(|binding| WireBinding {
            intent: binding.intent,
            producer: binding.edge.producer,
            output: binding.edge.output,
        })
        .collect()
}

fn bindings(wire: Vec<WireBinding>) -> Vec<YieldBinding> {
    wire.into_iter()
        .map(|binding| YieldBinding {
            intent: binding.intent,
            edge: EdgeRef {
                producer: binding.producer,
                output: binding.output,
            },
        })
        .collect()
}

/// Encode an envelope tree into its canonical wire bytes.
///
/// # Panics
///
/// Never in practice: the mirror types are closed basic-SBOR shapes.
#[must_use]
pub fn encode_tree(tree: &EnvelopeTree) -> Vec<u8> {
    let wire = WireTree {
        root: wire_intent(&tree.root),
        root_bindings: wire_bindings(&tree.root_bindings),
        subintents: tree
            .subintents
            .iter()
            .map(|subintent| WireSubintent {
                decl: wire_intent(&subintent.decl),
                signer: subintent.signer.0,
                bindings: wire_bindings(&subintent.bindings),
            })
            .collect(),
    };
    basic_encode(&wire).expect("tree wire encode is infallible")
}

/// Decode wire bytes into an envelope tree.
///
/// # Errors
///
/// [`VmStaticsError`] on malformed bytes.
pub fn decode_tree(bytes: &[u8]) -> Result<EnvelopeTree, VmStaticsError> {
    let wire: WireTree =
        basic_decode(bytes).map_err(|error| VmStaticsError(format!("tree decode: {error:?}")))?;
    Ok(EnvelopeTree {
        root: intent(wire.root),
        root_bindings: bindings(wire.root_bindings),
        subintents: wire
            .subintents
            .into_iter()
            .map(|subintent| Subintent {
                decl: intent(subintent.decl),
                signer: Address(subintent.signer),
                bindings: bindings(subintent.bindings),
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

/// The envelope's identity: its signing hash through the workspace's
/// protocol hash, as the vocabulary's hash type.
#[must_use]
pub fn envelope_identity(vm: &VmTransaction) -> ManifestHash {
    ManifestHash(Hash32(*vm.signing_hash().as_bytes()))
}

/// The bridge's [`VmStatics`]: `decode → admit → route` over the
/// process's genesis-static metadata.
pub struct BridgeStatics {
    /// Published package metadata, genesis-static this phase.
    pub cache: MetadataCache,
    /// Instance registrations, genesis-static this phase.
    pub instances: InstanceRegistry,
}

impl BridgeStatics {
    /// A publish's routing: an exclusive write on the package cell, and
    /// one on the publisher's fee vault.
    ///
    /// The vault is declared even though no signature asks for it. A
    /// completed transaction burns its fee there, and declaring it is
    /// what makes two publishes by one payer conflict — without it they
    /// share a block and settle two burns against one cell, which is the
    /// exposure a call transaction avoids only because its own withdraw
    /// happens to name the same vault.
    fn derive_publish(vm: &VmTransaction, artifact: &[u8]) -> Result<VmDerived, VmStaticsError> {
        if !vm.subintent_sigs.is_empty() || !vm.snapshot_pins.is_empty() {
            return Err(VmStaticsError(
                "a publish carries no subintents and no snapshot pins".into(),
            ));
        }
        // The artifact has to describe itself before it is addressed:
        // what the address covers is code and signatures together, so an
        // artifact that declares nothing is not a package.
        admit_package(artifact)?;

        let publisher = vm.fee_payer;
        let package = package_hash(&ProtocolHasher, artifact);
        let cell = package_key(publisher, package);
        let vault = vault_key(publisher, VM_XRD);
        let mut write_keys = vec![
            DeclaredKey::substate(cell.owner.0, cell.local.0),
            DeclaredKey::substate(vault.owner.0, vault.local.0),
        ];
        write_keys.sort_unstable();
        write_keys.dedup();

        Ok(VmDerived {
            routing: VmRouting {
                read_prefixes: Vec::new(),
                write_prefixes: vec![publisher],
                provision_prefixes: Vec::new(),
                read_keys: Vec::new(),
                write_keys,
                provision_keys: Vec::new(),
            },
            subintent_hashes: Vec::new(),
            snapshot_targets: Vec::new(),
            fee_vault_local: vault.local.0,
        })
    }
}

impl VmStatics for BridgeStatics {
    fn derive(&self, vm: &VmTransaction) -> Result<VmDerived, VmStaticsError> {
        // The payer is the composer, and this is what makes that true.
        // Every fee rule debits the account this field names — the
        // reservation a payer shard enforces as block validity, the
        // burn a completed transaction writes, the floor an abort
        // settles — and the composer's signature is the only authority
        // in the envelope. An unbound payer field is therefore a debit
        // on an account that authorised nothing, spendable by anyone
        // who knows its address.
        if vm_account_address(&vm.signer) != vm.fee_payer {
            return Err(VmStaticsError(
                "fee payer is not the composer's own account".into(),
            ));
        }
        if let Some(artifact) = vm.artifact() {
            return Self::derive_publish(vm, artifact);
        }
        let tree = decode_tree(vm.call_tree().unwrap_or_default())?;
        if vm.subintent_sigs.len() != tree.subintents.len() {
            return Err(VmStaticsError(format!(
                "envelope binds {} subintents but carries {} signatures",
                tree.subintents.len(),
                vm.subintent_sigs.len()
            )));
        }
        // Bind every declared signer address to its public key; the
        // signatures themselves verify at the transaction gate, over the
        // declaration hashes returned here.
        for (index, (sig, subintent)) in vm.subintent_sigs.iter().zip(&tree.subintents).enumerate()
        {
            if vm_account_address(&sig.public_key) != subintent.signer.0 {
                return Err(VmStaticsError(format!(
                    "subintent {index} signer address does not match its public key"
                )));
            }
        }
        let admitted = admit_tree(
            &tree,
            envelope_identity(vm),
            &self.cache,
            &self.instances,
            &ProtocolHasher,
        )
        .map_err(|error| VmStaticsError(format!("admission: {error}")))?;
        let routing = route_tree(
            &admitted,
            &self.cache,
            &self.instances,
            &ProtocolHasher,
            &PrefixShardResolver { bits: 0 },
        )
        .map_err(|error| VmStaticsError(format!("routing: {error}")))?;

        // Fresh reads share, mutations exclude, and snapshot reads are
        // lock-free and client-proven — they take no admission key and
        // make no participant. The provision set is the read set:
        // fresh reads plus read-modify-write priors, the values a
        // counterpart shard cannot execute without.
        let mut read_keys = BTreeSet::new();
        let mut write_keys = BTreeSet::new();
        let mut provision_keys = BTreeSet::new();
        for effect in routing.per_shard.values().flat_map(EffectSet::iter) {
            let key = admission_key(&effect.target);
            match effect.mode {
                Mode::Read => {
                    read_keys.insert(key);
                    provision_keys.insert(key);
                }
                Mode::Write => {
                    write_keys.insert(key);
                    provision_keys.insert(key);
                }
                Mode::Delta | Mode::Reserve { .. } => {
                    write_keys.insert(key);
                }
                Mode::Snapshot { .. } => {}
            }
        }
        let prefixes = |keys: &BTreeSet<DeclaredKey>| -> Vec<[u8; 16]> {
            keys.iter()
                .map(key_owner)
                .collect::<BTreeSet<_>>()
                .into_iter()
                .collect()
        };
        Ok(VmDerived {
            routing: VmRouting {
                read_prefixes: prefixes(&read_keys),
                write_prefixes: prefixes(&write_keys),
                provision_prefixes: prefixes(&provision_keys),
                read_keys: read_keys.into_iter().collect(),
                write_keys: write_keys.into_iter().collect(),
                provision_keys: provision_keys.into_iter().collect(),
            },
            subintent_hashes: admitted
                .subintents
                .iter()
                .map(|record| record.subintent.0.0)
                .collect(),
            snapshot_targets: routing
                .snapshot_obligations
                .iter()
                .map(|obligation| match obligation.target {
                    EffectTarget::Point(key) => Ok((key.owner.0, key.local.0)),
                    EffectTarget::Entry { .. } | EffectTarget::Range { .. } => Err(VmStaticsError(
                        "collection snapshot obligations are unsupported".into(),
                    )),
                })
                .collect::<Result<_, _>>()?,
            fee_vault_local: vault_key(vm.fee_payer, VM_XRD).local.0,
        })
    }
}

#[cfg(test)]
mod tests {
    use hyperscale_types::{Ed25519PrivateKey, VmBody, VmSubintentSig};
    use hyperscale_vm_effects::stdlib::{VAULT, account_metadata};
    use hyperscale_vm_effects::{
        Hasher, InstanceMeta, PackageHash, SubintentHash, child_key, nullifier_key,
    };

    use super::*;

    const RES_X: Address = Address([0xE1; 16]);
    const RES_Y: Address = Address([0xE2; 16]);

    fn key(seed: u8) -> Ed25519PrivateKey {
        Ed25519PrivateKey::from_bytes(&[seed; 32]).unwrap()
    }

    fn composer_addr() -> Address {
        Address(vm_account_address(&key(7).public_key().0))
    }

    fn bob_addr() -> Address {
        Address(vm_account_address(&key(9).public_key().0))
    }

    fn statics() -> BridgeStatics {
        let package = PackageHash(ProtocolHasher.hash(b"package", &[b"account"]));
        let mut cache = MetadataCache::new();
        cache.publish(package, account_metadata());
        let mut instances = InstanceRegistry::new();
        for address in [composer_addr(), bob_addr()] {
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

    fn withdraw(target: Address, resource: Address, amount: u128) -> GraphNode {
        GraphNode {
            target,
            method: "withdraw".into(),
            args: vec![
                GraphArg::Literal(Value::Address(resource)),
                GraphArg::Literal(Value::U128(amount)),
            ],
        }
    }

    fn deposit_edge(target: Address, producer: u32, resource: Address) -> GraphNode {
        GraphNode {
            target,
            method: "deposit".into(),
            args: vec![GraphArg::Edge {
                edge: EdgeRef {
                    producer,
                    output: 0,
                },
                constraints: vec![Constraint::ResourceIs(resource)],
            }],
        }
    }

    fn deposit_param(target: Address, param: u32) -> GraphNode {
        GraphNode {
            target,
            method: "deposit".into(),
            args: vec![GraphArg::Param(param)],
        }
    }

    fn single_intent_tree(nodes: Vec<GraphNode>) -> EnvelopeTree {
        EnvelopeTree {
            root: IntentDecl {
                graph: ManifestGraph { nodes },
                params: Vec::new(),
            },
            root_bindings: Vec::new(),
            subintents: Vec::new(),
        }
    }

    /// The two-signer composition: the composer pays X for the
    /// subintent's Y.
    fn composed_tree() -> EnvelopeTree {
        EnvelopeTree {
            root: IntentDecl {
                graph: ManifestGraph {
                    nodes: vec![
                        withdraw(composer_addr(), RES_X, 100),
                        deposit_param(composer_addr(), 0),
                    ],
                },
                params: vec![YieldParam {
                    resource: RES_Y,
                    constraints: vec![Constraint::MinAmount(10)],
                }],
            },
            root_bindings: vec![YieldBinding {
                intent: 1,
                edge: EdgeRef {
                    producer: 0,
                    output: 0,
                },
            }],
            subintents: vec![Subintent {
                decl: IntentDecl {
                    graph: ManifestGraph {
                        nodes: vec![
                            withdraw(bob_addr(), RES_Y, 10),
                            deposit_param(bob_addr(), 0),
                        ],
                    },
                    params: vec![YieldParam {
                        resource: RES_X,
                        constraints: vec![Constraint::MinAmount(100)],
                    }],
                },
                signer: bob_addr(),
                bindings: vec![YieldBinding {
                    intent: 0,
                    edge: EdgeRef {
                        producer: 0,
                        output: 0,
                    },
                }],
            }],
        }
    }

    fn envelope(tree: &EnvelopeTree, subintent_keys: &[&Ed25519PrivateKey]) -> VmTransaction {
        let subintent_sigs = tree
            .subintents
            .iter()
            .zip(subintent_keys)
            .map(|(subintent, signer)| {
                let hash = subintent.decl.hash(&ProtocolHasher);
                VmSubintentSig {
                    public_key: signer.public_key().0,
                    signature: signer.sign(hash.0.0).0,
                }
            })
            .collect();
        VmTransaction {
            body: VmBody::Call(encode_tree(tree).into()),
            subintent_sigs,
            fee_payer: composer_addr().0,
            max_fee: 1_000,
            gas_limit: 1_000_000,
            snapshot_pins: Vec::new(),
            validity_start_ms: 0,
            validity_end_ms: 1_000_000,
            message: Vec::new().into(),
            signer: [0; 32],
            signature: [0; 64],
        }
        .sign(&key(7))
    }

    #[test]
    fn the_tree_codec_round_trips() {
        let tree = composed_tree();
        let decoded = decode_tree(&encode_tree(&tree)).unwrap();
        assert_eq!(decoded, tree);
        assert!(decode_tree(&[0xFF, 0x00]).is_err());
    }

    #[test]
    fn a_transfer_derives_substate_keys_and_owner_prefixes() {
        let tree = single_intent_tree(vec![
            withdraw(composer_addr(), RES_X, 100),
            deposit_edge(bob_addr(), 0, RES_X),
        ]);
        let derived = statics().derive(&envelope(&tree, &[])).expect("derives");

        // Reserve at the sender's vault and deltas at the recipient's:
        // all exclusive-class, substate-granular, under the two owners.
        let sender_vault = child_key(
            &ProtocolHasher,
            composer_addr(),
            VAULT,
            &[Value::Address(RES_X).canonical_bytes()],
        );
        assert!(derived.routing.write_keys.contains(&DeclaredKey::substate(
            composer_addr().0,
            sender_vault.local.0
        )));
        assert!(derived.routing.read_keys.is_empty());
        // A commutative-only transfer provisions nothing at all.
        assert!(derived.routing.provision_keys.is_empty());
        assert!(derived.routing.provision_prefixes.is_empty());
        assert!(derived.subintent_hashes.is_empty());
        let mut owners = vec![composer_addr().0, bob_addr().0];
        owners.sort_unstable();
        assert_eq!(derived.routing.write_prefixes, owners);
    }

    #[test]
    fn a_composed_envelope_derives_the_nullifier_write() {
        let tree = composed_tree();
        let bob = key(9);
        let derived = statics()
            .derive(&envelope(&tree, &[&bob]))
            .expect("derives");

        let hash = tree.subintents[0].decl.hash(&ProtocolHasher);
        assert_eq!(derived.subintent_hashes, vec![hash.0.0]);
        let nullifier = nullifier_key(&ProtocolHasher, bob_addr(), hash);
        assert!(
            derived
                .routing
                .write_keys
                .contains(&DeclaredKey::substate(bob_addr().0, nullifier.local.0))
        );
    }

    #[test]
    fn a_fee_payer_the_composer_does_not_own_is_refused() {
        // The whole fee path debits whatever this field names, and the
        // composer's signature is the only authority in the envelope —
        // so naming someone else's account has to be refused before any
        // of it runs, or that account is spendable by a stranger.
        let tree = single_intent_tree(vec![
            withdraw(composer_addr(), RES_X, 100),
            deposit_edge(bob_addr(), 0, RES_X),
        ]);
        let mut stolen = envelope(&tree, &[]);
        stolen.fee_payer = bob_addr().0;
        let stolen = stolen.sign(&key(7));

        assert!(stolen.signature_is_valid(), "the composer signed it");
        let refused = statics().derive(&stolen).expect_err("refuses");
        assert!(refused.0.contains("fee payer"), "{}", refused.0);

        // The composer paying from their own account is the admitted
        // case, so the check bites on ownership and not on fees at all.
        assert!(statics().derive(&envelope(&tree, &[])).is_ok());
    }

    #[test]
    fn a_mismatched_subintent_signer_is_refused() {
        // The tree binds BOB's address, but the carried key is another's.
        let tree = composed_tree();
        let impostor = key(11);
        let refused = statics().derive(&envelope(&tree, &[&impostor]));
        assert!(refused.is_err());

        // A missing signature list is a distinct refusal.
        let mut unsigned = envelope(&tree, &[&key(9)]);
        unsigned.subintent_sigs.clear();
        assert!(statics().derive(&unsigned).is_err());
    }

    #[test]
    fn an_inadmissible_tree_is_refused() {
        // The produced bucket is never consumed: linearity refuses it.
        let tree = single_intent_tree(vec![withdraw(composer_addr(), RES_X, 100)]);
        assert!(statics().derive(&envelope(&tree, &[])).is_err());
    }

    #[test]
    fn a_nullifier_hash_needs_a_subintent_hash_type() {
        // Pin the record type wiring: the routed hash is the declaration
        // hash, reconstructible from the decoded tree alone.
        let tree = composed_tree();
        let decoded = decode_tree(&encode_tree(&tree)).unwrap();
        assert_eq!(
            decoded.subintents[0].decl.hash(&ProtocolHasher),
            tree.subintents[0].decl.hash(&ProtocolHasher)
        );
        let _typed: SubintentHash = tree.subintents[0].decl.hash(&ProtocolHasher);
    }
}
