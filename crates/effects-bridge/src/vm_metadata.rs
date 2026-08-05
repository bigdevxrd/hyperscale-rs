//! Package metadata's wire codec: the canonical encoding a published
//! artifact carries in its metadata section.
//!
//! The effect vocabulary is wire-free, so every encoding of it belongs
//! here beside the envelope tree's, which is what makes the format the
//! workspace's to freeze. The shape it freezes is the whole signature
//! tree: a method's declared accessibility, its parameter kinds, its
//! output resource expressions, its effect clauses down through nested
//! `for-each` bodies, its static call sites, and the package's event
//! table.
//!
//! Decode is canonical and bounded. Canonical because the format admits
//! exactly one byte string per value: SBOR's own sizes are minimal
//! LEB128, the payload's end is checked, and the method table travels as
//! a vector this module reads under a strictly ascending name order
//! rather than as a map a peer could permute or repeat. Bounded because
//! the byte cap makes decode linear in its input — SBOR is self-framing,
//! so no collection can claim more elements than the input has bytes —
//! while the vocabulary's own nesting bounds cover the depths a few
//! hundred bytes could still reach. Above those sit the two caps that
//! carry meaning rather than safety: a clause tree no evaluation could
//! ever declare, and an event table longer than the index the kernel
//! accepts.

use hyperscale_types::{MAX_TX_BYTES_LEN, MAX_VM_EVENT_TYPES, VmStaticsError};
use hyperscale_vm_effects::{
    AbiParam, Accessibility, CallSite, Clause, Expr, MAX_CLAUSE_DEPTH, MAX_EFFECTS_PER_SIGNATURE,
    MAX_EXPR_DEPTH, MAX_VALUE_DEPTH, MethodSignature, ModeExpr, PackageMetadata, ParamType, RoleId,
    TargetExpr,
};
use sbor::prelude::*;
use sbor::{basic_decode_with_depth_limit, basic_encode_with_depth_limit};

use crate::wire::{WireValue, value, wire_value};

/// The bound on an encoded metadata section.
///
/// A section rides inside a published artifact and the artifact inside a
/// transaction, so the code it describes has to fit beside it; a quarter
/// of the transaction budget is the share this side claims. The cap is
/// also what makes decode linear: SBOR frames every collection with its
/// length and every element costs at least a byte, so no claimed count
/// can outrun the input.
pub const MAX_PACKAGE_METADATA_BYTES: usize = MAX_TX_BYTES_LEN / 4;

/// The SBOR nesting limit this codec encodes and decodes at.
///
/// Every nested field counts one level, so the vocabulary's depth bounds
/// do not translate one for one: a clause layer costs two levels — the
/// body vector and its element — an expression layer up to two, for a
/// child key's material vector and its element, and a value layer two for
/// the same reason. The fixed prefix is the remainder: the metadata
/// record, its method table, a method, its clause list, a target and a
/// mode. The limit admits everything [`check_metadata`] accepts; the
/// checks are what decide.
const MAX_SBOR_DEPTH: usize = 16 + 2 * (MAX_CLAUSE_DEPTH + MAX_EXPR_DEPTH + MAX_VALUE_DEPTH);

/// Wire mirror of [`ParamType`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, BasicSbor)]
enum WireParamType {
    U64,
    U128,
    Bytes,
    Address,
    Bucket,
}

/// Wire mirror of [`Expr`].
#[derive(Clone, Debug, PartialEq, Eq, BasicSbor)]
enum WireExpr {
    Literal(WireValue),
    Arg(u32),
    Config(u32),
    Binding(u32),
    SelfAddr,
    Field(Box<Self>, u32),
    ResourceOf(Box<Self>),
    Lookup {
        map: Box<Self>,
        key: Box<Self>,
    },
    ChildKey {
        owner: Box<Self>,
        role: u16,
        material: Vec<Self>,
    },
    FreshId {
        slot: u32,
    },
    FreshKey {
        slot: u32,
    },
    Pack {
        hi: Box<Self>,
        lo: Box<Self>,
    },
}

/// Wire mirror of [`ModeExpr`].
#[derive(Clone, Debug, PartialEq, Eq, BasicSbor)]
enum WireMode {
    Read,
    Locked,
    Delta,
    Reserve(WireExpr),
    Write,
}

/// Wire mirror of [`TargetExpr`].
#[derive(Clone, Debug, PartialEq, Eq, BasicSbor)]
enum WireTarget {
    Point(WireExpr),
    Entry {
        owner: WireExpr,
        collection: u16,
        order: WireExpr,
    },
    Range {
        owner: WireExpr,
        collection: u16,
        lo: WireExpr,
        hi: WireExpr,
        cap: u32,
    },
}

/// Wire mirror of [`Clause`].
#[derive(Clone, Debug, PartialEq, Eq, BasicSbor)]
enum WireClause {
    Effect { target: WireTarget, mode: WireMode },
    ForEach { list: WireExpr, body: Vec<Self> },
}

/// Wire mirror of [`CallSite`].
#[derive(Clone, Debug, PartialEq, Eq, BasicSbor)]
struct WireCall {
    target: WireExpr,
    method: String,
    args: Vec<WireExpr>,
}

/// Wire mirror of [`AbiParam`].
#[derive(Clone, Debug, PartialEq, Eq, BasicSbor)]
enum WireAbiParam {
    Handle(u32),
    Bucket(u32),
    Derived(WireExpr),
}

/// Wire mirror of [`Accessibility`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, BasicSbor)]
enum WireAccessibility {
    Public,
    RequiresTargetAuth,
}

/// Wire mirror of [`MethodSignature`], carrying the name it is filed
/// under: the table is a vector so its order is part of the encoding.
#[derive(Clone, Debug, PartialEq, Eq, BasicSbor)]
struct WireMethod {
    name: String,
    accessibility: WireAccessibility,
    params: Vec<WireParamType>,
    abi: Vec<WireAbiParam>,
    outputs: Vec<WireExpr>,
    effects: Vec<WireClause>,
    calls: Vec<WireCall>,
}

/// Wire mirror of [`PackageMetadata`].
#[derive(Clone, Debug, PartialEq, Eq, BasicSbor)]
struct WireMetadata {
    methods: Vec<WireMethod>,
    events: Vec<String>,
}

const fn wire_param(param: ParamType) -> WireParamType {
    match param {
        ParamType::U64 => WireParamType::U64,
        ParamType::U128 => WireParamType::U128,
        ParamType::Bytes => WireParamType::Bytes,
        ParamType::Address => WireParamType::Address,
        ParamType::Bucket => WireParamType::Bucket,
    }
}

const fn param(wire: WireParamType) -> ParamType {
    match wire {
        WireParamType::U64 => ParamType::U64,
        WireParamType::U128 => ParamType::U128,
        WireParamType::Bytes => ParamType::Bytes,
        WireParamType::Address => ParamType::Address,
        WireParamType::Bucket => ParamType::Bucket,
    }
}

fn wire_expr(expr: &Expr) -> WireExpr {
    match expr {
        Expr::Literal(literal) => WireExpr::Literal(wire_value(literal)),
        Expr::Arg(index) => WireExpr::Arg(*index),
        Expr::Config(index) => WireExpr::Config(*index),
        Expr::Binding(index) => WireExpr::Binding(*index),
        Expr::SelfAddr => WireExpr::SelfAddr,
        Expr::Field(tuple, index) => WireExpr::Field(Box::new(wire_expr(tuple)), *index),
        Expr::ResourceOf(bucket) => WireExpr::ResourceOf(Box::new(wire_expr(bucket))),
        Expr::Lookup { map, key } => WireExpr::Lookup {
            map: Box::new(wire_expr(map)),
            key: Box::new(wire_expr(key)),
        },
        Expr::ChildKey {
            owner,
            role,
            material,
        } => WireExpr::ChildKey {
            owner: Box::new(wire_expr(owner)),
            role: role.0,
            material: material.iter().map(wire_expr).collect(),
        },
        Expr::FreshId { slot } => WireExpr::FreshId { slot: *slot },
        Expr::FreshKey { slot } => WireExpr::FreshKey { slot: *slot },
        Expr::Pack { hi, lo } => WireExpr::Pack {
            hi: Box::new(wire_expr(hi)),
            lo: Box::new(wire_expr(lo)),
        },
    }
}

fn expr(wire: WireExpr) -> Expr {
    match wire {
        WireExpr::Literal(literal) => Expr::Literal(value(literal)),
        WireExpr::Arg(index) => Expr::Arg(index),
        WireExpr::Config(index) => Expr::Config(index),
        WireExpr::Binding(index) => Expr::Binding(index),
        WireExpr::SelfAddr => Expr::SelfAddr,
        WireExpr::Field(tuple, index) => Expr::Field(Box::new(expr(*tuple)), index),
        WireExpr::ResourceOf(bucket) => Expr::ResourceOf(Box::new(expr(*bucket))),
        WireExpr::Lookup { map, key } => Expr::Lookup {
            map: Box::new(expr(*map)),
            key: Box::new(expr(*key)),
        },
        WireExpr::ChildKey {
            owner,
            role,
            material,
        } => Expr::ChildKey {
            owner: Box::new(expr(*owner)),
            role: RoleId(role),
            material: material.into_iter().map(expr).collect(),
        },
        WireExpr::FreshId { slot } => Expr::FreshId { slot },
        WireExpr::FreshKey { slot } => Expr::FreshKey { slot },
        WireExpr::Pack { hi, lo } => Expr::Pack {
            hi: Box::new(expr(*hi)),
            lo: Box::new(expr(*lo)),
        },
    }
}

fn wire_target(target: &TargetExpr) -> WireTarget {
    match target {
        TargetExpr::Point(key) => WireTarget::Point(wire_expr(key)),
        TargetExpr::Entry {
            owner,
            collection,
            order,
        } => WireTarget::Entry {
            owner: wire_expr(owner),
            collection: collection.0,
            order: wire_expr(order),
        },
        TargetExpr::Range {
            owner,
            collection,
            lo,
            hi,
            cap,
        } => WireTarget::Range {
            owner: wire_expr(owner),
            collection: collection.0,
            lo: wire_expr(lo),
            hi: wire_expr(hi),
            cap: *cap,
        },
    }
}

fn target(wire: WireTarget) -> TargetExpr {
    match wire {
        WireTarget::Point(key) => TargetExpr::Point(expr(key)),
        WireTarget::Entry {
            owner,
            collection,
            order,
        } => TargetExpr::Entry {
            owner: expr(owner),
            collection: RoleId(collection),
            order: expr(order),
        },
        WireTarget::Range {
            owner,
            collection,
            lo,
            hi,
            cap,
        } => TargetExpr::Range {
            owner: expr(owner),
            collection: RoleId(collection),
            lo: expr(lo),
            hi: expr(hi),
            cap,
        },
    }
}

const fn wire_accessibility(accessibility: Accessibility) -> WireAccessibility {
    match accessibility {
        Accessibility::Public => WireAccessibility::Public,
        Accessibility::RequiresTargetAuth => WireAccessibility::RequiresTargetAuth,
    }
}

const fn accessibility(wire: WireAccessibility) -> Accessibility {
    match wire {
        WireAccessibility::Public => Accessibility::Public,
        WireAccessibility::RequiresTargetAuth => Accessibility::RequiresTargetAuth,
    }
}

fn wire_abi_param(binding: &AbiParam) -> WireAbiParam {
    match binding {
        AbiParam::Handle(clause) => WireAbiParam::Handle(*clause),
        AbiParam::Bucket(param) => WireAbiParam::Bucket(*param),
        AbiParam::Derived(expr) => WireAbiParam::Derived(wire_expr(expr)),
    }
}

fn abi_param(wire: WireAbiParam) -> AbiParam {
    match wire {
        WireAbiParam::Handle(clause) => AbiParam::Handle(clause),
        WireAbiParam::Bucket(param) => AbiParam::Bucket(param),
        WireAbiParam::Derived(wire) => AbiParam::Derived(expr(wire)),
    }
}

fn wire_mode(mode: &ModeExpr) -> WireMode {
    match mode {
        ModeExpr::Read => WireMode::Read,
        ModeExpr::Locked => WireMode::Locked,
        ModeExpr::Delta => WireMode::Delta,
        ModeExpr::Reserve(amount) => WireMode::Reserve(wire_expr(amount)),
        ModeExpr::Write => WireMode::Write,
    }
}

fn mode(wire: WireMode) -> ModeExpr {
    match wire {
        WireMode::Read => ModeExpr::Read,
        WireMode::Locked => ModeExpr::Locked,
        WireMode::Delta => ModeExpr::Delta,
        WireMode::Reserve(amount) => ModeExpr::Reserve(expr(amount)),
        WireMode::Write => ModeExpr::Write,
    }
}

fn wire_clause(clause: &Clause) -> WireClause {
    match clause {
        Clause::Effect { target, mode } => WireClause::Effect {
            target: wire_target(target),
            mode: wire_mode(mode),
        },
        Clause::ForEach { list, body } => WireClause::ForEach {
            list: wire_expr(list),
            body: body.iter().map(wire_clause).collect(),
        },
    }
}

fn clause(wire: WireClause) -> Clause {
    match wire {
        WireClause::Effect {
            target: wire_target,
            mode: wire_mode,
        } => Clause::Effect {
            target: target(wire_target),
            mode: mode(wire_mode),
        },
        WireClause::ForEach { list, body } => Clause::ForEach {
            list: expr(list),
            body: body.into_iter().map(clause).collect(),
        },
    }
}

fn wire_call(call: &CallSite) -> WireCall {
    WireCall {
        target: wire_expr(&call.target),
        method: call.method.clone(),
        args: call.args.iter().map(wire_expr).collect(),
    }
}

fn call(wire: WireCall) -> CallSite {
    CallSite {
        target: expr(wire.target),
        method: wire.method,
        args: wire.args.into_iter().map(expr).collect(),
    }
}

fn wire_metadata(metadata: &PackageMetadata) -> WireMetadata {
    WireMetadata {
        methods: metadata
            .methods
            .iter()
            .map(|(name, signature)| WireMethod {
                name: name.clone(),
                accessibility: wire_accessibility(signature.accessibility),
                params: signature.params.iter().copied().map(wire_param).collect(),
                abi: signature.abi.iter().map(wire_abi_param).collect(),
                outputs: signature.outputs.iter().map(wire_expr).collect(),
                effects: signature.effects.iter().map(wire_clause).collect(),
                calls: signature.calls.iter().map(wire_call).collect(),
            })
            .collect(),
        events: metadata.events.clone(),
    }
}

/// Encode package metadata into its canonical section bytes.
///
/// # Errors
///
/// [`VmStaticsError`] if the metadata is past a bound decode enforces, so
/// that whatever this returns decodes back to an equal value.
pub fn encode_metadata(metadata: &PackageMetadata) -> Result<Vec<u8>, VmStaticsError> {
    check_metadata(metadata)?;
    let bytes = basic_encode_with_depth_limit(&wire_metadata(metadata), MAX_SBOR_DEPTH)
        .map_err(|error| VmStaticsError(format!("metadata encode: {error:?}")))?;
    if bytes.len() > MAX_PACKAGE_METADATA_BYTES {
        return Err(VmStaticsError(format!(
            "metadata encodes to {} bytes, past the {MAX_PACKAGE_METADATA_BYTES} cap",
            bytes.len()
        )));
    }
    Ok(bytes)
}

/// Decode a metadata section's canonical bytes.
///
/// # Errors
///
/// [`VmStaticsError`] on an oversized section, malformed or non-canonical
/// bytes, or a structure past a bound the vocabulary fixes.
pub fn decode_metadata(bytes: &[u8]) -> Result<PackageMetadata, VmStaticsError> {
    if bytes.len() > MAX_PACKAGE_METADATA_BYTES {
        return Err(VmStaticsError(format!(
            "metadata section is {} bytes, past the {MAX_PACKAGE_METADATA_BYTES} cap",
            bytes.len()
        )));
    }
    let wire: WireMetadata = basic_decode_with_depth_limit(bytes, MAX_SBOR_DEPTH)
        .map_err(|error| VmStaticsError(format!("metadata decode: {error:?}")))?;

    let mut metadata = PackageMetadata {
        methods: BTreeMap::new(),
        events: wire.events,
    };
    let mut previous: Option<String> = None;
    for method in wire.methods {
        if previous.as_ref().is_some_and(|prior| *prior >= method.name) {
            return Err(VmStaticsError(format!(
                "method table is not in ascending name order at {:?}",
                method.name
            )));
        }
        previous = Some(method.name.clone());
        metadata.methods.insert(
            method.name,
            MethodSignature {
                accessibility: accessibility(method.accessibility),
                params: method.params.into_iter().map(param).collect(),
                abi: method.abi.into_iter().map(abi_param).collect(),
                outputs: method.outputs.into_iter().map(expr).collect(),
                effects: method.effects.into_iter().map(clause).collect(),
                calls: method.calls.into_iter().map(call).collect(),
            },
        );
    }
    check_metadata(&metadata)?;
    Ok(metadata)
}

/// Reject metadata past a bound the vocabulary fixes.
///
/// The depth walks mirror the evaluator's own recursion — same starting
/// depth, same comparison — so a signature this accepts is one evaluation
/// will not refuse on structure alone.
fn check_metadata(metadata: &PackageMetadata) -> Result<(), VmStaticsError> {
    if metadata.events.len() > MAX_VM_EVENT_TYPES as usize {
        return Err(VmStaticsError(format!(
            "event table names {} types, past the {MAX_VM_EVENT_TYPES} an event index can reach",
            metadata.events.len()
        )));
    }
    for (name, signature) in &metadata.methods {
        check_signature(signature)
            .map_err(|error| VmStaticsError(format!("method {name:?}: {}", error.0)))?;
    }
    Ok(())
}

fn check_signature(signature: &MethodSignature) -> Result<(), VmStaticsError> {
    for output in &signature.outputs {
        check_expr(output, 0)?;
    }
    for call in &signature.calls {
        check_expr(&call.target, 0)?;
        for arg in &call.args {
            check_expr(arg, 0)?;
        }
    }
    let mut declared = 0usize;
    check_clauses(&signature.effects, 0, &mut declared)
}

fn check_clauses(
    clauses: &[Clause],
    depth: usize,
    declared: &mut usize,
) -> Result<(), VmStaticsError> {
    if depth > MAX_CLAUSE_DEPTH {
        return Err(VmStaticsError(format!(
            "for-each clauses nest deeper than {MAX_CLAUSE_DEPTH}"
        )));
    }
    for clause in clauses {
        match clause {
            Clause::Effect { target, mode } => {
                *declared += 1;
                if *declared > MAX_EFFECTS_PER_SIGNATURE {
                    return Err(VmStaticsError(format!(
                        "signature declares more than {MAX_EFFECTS_PER_SIGNATURE} effects"
                    )));
                }
                check_target(target)?;
                check_mode(mode)?;
            }
            Clause::ForEach { list, body } => {
                check_expr(list, 0)?;
                check_clauses(body, depth + 1, declared)?;
            }
        }
    }
    Ok(())
}

fn check_target(target: &TargetExpr) -> Result<(), VmStaticsError> {
    match target {
        TargetExpr::Point(key) => check_expr(key, 0),
        TargetExpr::Entry { owner, order, .. } => {
            check_expr(owner, 0)?;
            check_expr(order, 0)
        }
        TargetExpr::Range { owner, lo, hi, .. } => {
            check_expr(owner, 0)?;
            check_expr(lo, 0)?;
            check_expr(hi, 0)
        }
    }
}

fn check_mode(mode: &ModeExpr) -> Result<(), VmStaticsError> {
    match mode {
        ModeExpr::Read | ModeExpr::Delta | ModeExpr::Write | ModeExpr::Locked => Ok(()),
        ModeExpr::Reserve(amount) => check_expr(amount, 0),
    }
}

fn check_expr(expr: &Expr, depth: usize) -> Result<(), VmStaticsError> {
    if depth > MAX_EXPR_DEPTH {
        return Err(VmStaticsError(format!(
            "expression nests deeper than {MAX_EXPR_DEPTH}"
        )));
    }
    let deeper = depth + 1;
    match expr {
        Expr::Literal(literal) => {
            if literal.depth() > MAX_VALUE_DEPTH {
                return Err(VmStaticsError(format!(
                    "literal nests deeper than {MAX_VALUE_DEPTH}"
                )));
            }
            Ok(())
        }
        Expr::Arg(_)
        | Expr::Config(_)
        | Expr::Binding(_)
        | Expr::SelfAddr
        | Expr::FreshId { .. }
        | Expr::FreshKey { .. } => Ok(()),
        Expr::Field(inner, _) | Expr::ResourceOf(inner) => check_expr(inner, deeper),
        Expr::Lookup {
            map: first,
            key: second,
        }
        | Expr::Pack {
            hi: first,
            lo: second,
        } => {
            check_expr(first, deeper)?;
            check_expr(second, deeper)
        }
        Expr::ChildKey {
            owner, material, ..
        } => {
            check_expr(owner, deeper)?;
            for part in material {
                check_expr(part, deeper)?;
            }
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use hyperscale_vm_effects::stdlib::{
        VAULT, account_metadata, amm_metadata, book_metadata, splitter_metadata,
    };
    use hyperscale_vm_effects::{Address, LocalKey, SubstateKey, Value};

    use super::*;

    fn stdlib() -> Vec<(&'static str, PackageMetadata)> {
        vec![
            ("account", account_metadata()),
            ("amm", amm_metadata()),
            ("book", book_metadata()),
            ("splitter", splitter_metadata()),
        ]
    }

    /// A signature whose only effect points at `expr`.
    fn signature_over(expr: Expr) -> MethodSignature {
        MethodSignature {
            effects: vec![Clause::Effect {
                target: TargetExpr::Point(expr),
                mode: ModeExpr::Write,
            }],
            ..MethodSignature::default()
        }
    }

    fn one_method(signature: MethodSignature) -> PackageMetadata {
        let mut metadata = PackageMetadata::default();
        metadata.methods.insert("m".into(), signature);
        metadata
    }

    /// The section bytes for metadata the bound checks would refuse —
    /// what a hostile publisher writes, and the only input that puts the
    /// decode-side bounds under test.
    fn encode_unchecked(metadata: &PackageMetadata) -> Vec<u8> {
        basic_encode_with_depth_limit(&wire_metadata(metadata), MAX_SBOR_DEPTH)
            .expect("the wire mirror encodes within the codec's own nesting limit")
    }

    /// Both sides of a bound: the admitted structure round trips, and the
    /// one past it is refused by encode and by decode alike.
    fn assert_bounded(admitted: &PackageMetadata, refused: &PackageMetadata) {
        let bytes = encode_metadata(admitted).expect("the admitted structure encodes");
        assert_eq!(&decode_metadata(&bytes).expect("decodes"), admitted);
        assert!(
            encode_metadata(refused).is_err(),
            "encode accepted a structure past the bound"
        );
        assert!(
            decode_metadata(&encode_unchecked(refused)).is_err(),
            "decode accepted a structure past the bound"
        );
    }

    /// A left-nested projection chain, the shape the evaluator's own depth
    /// test uses.
    fn nested_projection(depth: usize) -> Expr {
        let mut expr = Expr::Arg(0);
        for _ in 0..depth {
            expr = Expr::Field(Box::new(expr), 0);
        }
        expr
    }

    fn nested_foreach(depth: usize) -> Clause {
        let mut clause = Clause::Effect {
            target: TargetExpr::Point(Expr::SelfAddr),
            mode: ModeExpr::Read,
        };
        for _ in 0..depth {
            clause = Clause::ForEach {
                list: Expr::Arg(0),
                body: vec![clause],
            };
        }
        clause
    }

    #[test]
    fn the_stdlib_metadata_round_trips() {
        for (package, metadata) in stdlib() {
            let bytes = encode_metadata(&metadata).expect("encodes");
            let decoded = decode_metadata(&bytes).expect("decodes");
            assert_eq!(decoded, metadata, "{package} metadata round trip");
            assert_eq!(
                encode_metadata(&decoded).expect("re-encodes"),
                bytes,
                "{package} metadata re-encodes identically"
            );
        }
    }

    #[test]
    fn every_authored_shape_survives_the_codec() {
        // The stdlib does not author every variant, so the coverage the
        // round-trip test cannot give comes from one method that does:
        // each expression form, each target form, each mode, a nested
        // for-each body, a call site, and a deep literal.
        let signature = MethodSignature {
            accessibility: Accessibility::RequiresTargetAuth,
            abi: Vec::new(),
            params: vec![
                ParamType::U64,
                ParamType::U128,
                ParamType::Bytes,
                ParamType::Address,
                ParamType::Bucket,
            ],
            outputs: vec![
                Expr::Config(2),
                Expr::ResourceOf(Box::new(Expr::Arg(4))),
                Expr::Literal(Value::Tuple(vec![
                    Value::U64(1),
                    Value::List(vec![Value::Bytes(vec![7, 8, 9])]),
                    Value::Key(SubstateKey {
                        owner: Address([3; 16]),
                        local: LocalKey([4; 16]),
                    }),
                    Value::Bucket {
                        resource: Address([5; 16]),
                    },
                    Value::U128(u128::MAX),
                    Value::Address(Address([6; 16])),
                ])),
            ],
            effects: vec![
                Clause::Effect {
                    target: TargetExpr::Point(Expr::ChildKey {
                        owner: Box::new(Expr::SelfAddr),
                        role: VAULT,
                        material: vec![Expr::Arg(3), Expr::FreshKey { slot: 1 }],
                    }),
                    mode: ModeExpr::Reserve(Expr::Arg(1)),
                },
                Clause::Effect {
                    target: TargetExpr::Entry {
                        owner: Expr::Field(Box::new(Expr::Config(0)), 2),
                        collection: RoleId(9),
                        order: Expr::Pack {
                            hi: Box::new(Expr::Arg(0)),
                            lo: Box::new(Expr::FreshId { slot: 3 }),
                        },
                    },
                    mode: ModeExpr::Locked,
                },
                Clause::Effect {
                    target: TargetExpr::Range {
                        owner: Expr::SelfAddr,
                        collection: RoleId(4),
                        lo: Expr::Literal(Value::U128(0)),
                        hi: Expr::Literal(Value::U128(u128::MAX)),
                        cap: 64,
                    },
                    mode: ModeExpr::Locked,
                },
                Clause::ForEach {
                    list: Expr::Arg(2),
                    body: vec![Clause::ForEach {
                        list: Expr::Binding(0),
                        body: vec![Clause::Effect {
                            target: TargetExpr::Point(Expr::Lookup {
                                map: Box::new(Expr::Binding(1)),
                                key: Box::new(Expr::Binding(0)),
                            }),
                            mode: ModeExpr::Delta,
                        }],
                    }],
                },
                Clause::Effect {
                    target: TargetExpr::Point(Expr::SelfAddr),
                    mode: ModeExpr::Read,
                },
            ],
            calls: vec![CallSite {
                target: Expr::Config(1),
                method: "deposit".into(),
                args: vec![Expr::Arg(4), Expr::Literal(Value::U64(11))],
            }],
        };
        let mut metadata = one_method(signature);
        metadata
            .methods
            .insert("another".into(), MethodSignature::default());
        metadata.events = vec!["withdrawn".into(), "deposited".into()];

        let bytes = encode_metadata(&metadata).expect("encodes");
        assert_eq!(decode_metadata(&bytes).expect("decodes"), metadata);
    }

    #[test]
    fn any_byte_change_fails_or_changes_the_value() {
        for (package, metadata) in stdlib() {
            let bytes = encode_metadata(&metadata).expect("encodes");
            for index in 0..bytes.len() {
                for mask in [0x01u8, 0x40, 0x80, 0xFF] {
                    let mut mutated = bytes.clone();
                    mutated[index] ^= mask;
                    if let Ok(decoded) = decode_metadata(&mutated) {
                        assert_ne!(
                            decoded, metadata,
                            "{package}: byte {index} ^ {mask:#04x} decoded to the same value"
                        );
                    }
                }
            }
        }
    }

    #[test]
    fn truncated_and_extended_payloads_are_refused() {
        let bytes = encode_metadata(&account_metadata()).expect("encodes");
        for cut in 0..bytes.len() {
            assert!(
                decode_metadata(&bytes[..cut]).is_err(),
                "a payload truncated to {cut} bytes decoded"
            );
        }
        let mut trailing = bytes;
        trailing.push(0);
        assert!(
            decode_metadata(&trailing).is_err(),
            "trailing byte accepted"
        );
        assert!(decode_metadata(&[]).is_err());
        assert!(decode_metadata(&[0xFF, 0x00]).is_err());
    }

    #[test]
    fn the_method_table_decodes_only_in_ascending_name_order() {
        // The table travels as a vector, so permuting it or repeating a
        // name is a distinct byte string that must not decode to a value
        // the map would silently normalise.
        let mut metadata = PackageMetadata::default();
        for name in ["a", "b"] {
            metadata
                .methods
                .insert(name.into(), MethodSignature::default());
        }
        let bytes = encode_metadata(&metadata).expect("encodes");

        let rewrite = |methods: Vec<WireMethod>| {
            basic_encode_with_depth_limit(
                &WireMetadata {
                    methods,
                    events: Vec::new(),
                },
                MAX_SBOR_DEPTH,
            )
            .expect("wire encodes")
        };
        let entry = |name: &str| WireMethod {
            accessibility: WireAccessibility::Public,
            abi: Vec::new(),
            name: name.into(),
            params: Vec::new(),
            outputs: Vec::new(),
            effects: Vec::new(),
            calls: Vec::new(),
        };
        assert_eq!(rewrite(vec![entry("a"), entry("b")]), bytes);
        assert!(decode_metadata(&rewrite(vec![entry("b"), entry("a")])).is_err());
        assert!(decode_metadata(&rewrite(vec![entry("a"), entry("a")])).is_err());
    }

    #[test]
    fn the_deepest_admissible_metadata_still_encodes() {
        // Every nesting bound at its limit at once, along the costliest
        // path: clause bodies, child-key material, and a tuple literal
        // each cost two SBOR levels a layer. If the codec's own nesting
        // limit ever stops covering the bounds it is derived from, this
        // is what says so — the checks would accept a structure the
        // encoder could not write.
        let mut literal = Value::U64(0);
        for _ in 1..MAX_VALUE_DEPTH {
            literal = Value::Tuple(vec![literal]);
        }
        let mut deepest = Expr::Literal(literal);
        for _ in 0..MAX_EXPR_DEPTH {
            deepest = Expr::ChildKey {
                owner: Box::new(Expr::SelfAddr),
                role: VAULT,
                material: vec![deepest],
            };
        }
        let mut clause = Clause::Effect {
            target: TargetExpr::Range {
                owner: Expr::SelfAddr,
                collection: RoleId(4),
                lo: deepest.clone(),
                hi: deepest,
                cap: 1,
            },
            mode: ModeExpr::Locked,
        };
        for _ in 0..MAX_CLAUSE_DEPTH {
            clause = Clause::ForEach {
                list: Expr::Arg(0),
                body: vec![clause],
            };
        }
        let metadata = one_method(MethodSignature {
            effects: vec![clause],
            ..MethodSignature::default()
        });

        let bytes = encode_metadata(&metadata).expect("the deepest admissible metadata encodes");
        assert_eq!(decode_metadata(&bytes).expect("decodes"), metadata);
    }

    #[test]
    fn expression_nesting_is_bounded_where_the_evaluator_bounds_it() {
        assert_bounded(
            &one_method(signature_over(nested_projection(MAX_EXPR_DEPTH))),
            &one_method(signature_over(nested_projection(MAX_EXPR_DEPTH + 1))),
        );
    }

    #[test]
    fn clause_nesting_is_bounded_where_the_evaluator_bounds_it() {
        assert_bounded(
            &one_method(MethodSignature {
                effects: vec![nested_foreach(MAX_CLAUSE_DEPTH)],
                ..MethodSignature::default()
            }),
            &one_method(MethodSignature {
                effects: vec![nested_foreach(MAX_CLAUSE_DEPTH + 1)],
                ..MethodSignature::default()
            }),
        );
    }

    #[test]
    fn a_clause_tree_wider_than_a_signature_can_declare_is_refused() {
        let effect = Clause::Effect {
            target: TargetExpr::Point(Expr::SelfAddr),
            mode: ModeExpr::Read,
        };
        let with = |count: usize| {
            one_method(MethodSignature {
                effects: vec![effect.clone(); count],
                ..MethodSignature::default()
            })
        };
        assert_bounded(
            &with(MAX_EFFECTS_PER_SIGNATURE),
            &with(MAX_EFFECTS_PER_SIGNATURE + 1),
        );
    }

    #[test]
    fn literal_nesting_is_bounded_where_admission_bounds_it() {
        let literal = |depth: usize| {
            let mut value = Value::U64(0);
            for _ in 1..depth {
                value = Value::Tuple(vec![value]);
            }
            Expr::Literal(value)
        };
        assert_bounded(
            &one_method(signature_over(literal(MAX_VALUE_DEPTH))),
            &one_method(signature_over(literal(MAX_VALUE_DEPTH + 1))),
        );
    }

    #[test]
    fn an_event_table_past_the_index_the_kernel_accepts_is_refused() {
        let table = |len: usize| PackageMetadata {
            methods: BTreeMap::new(),
            events: vec![String::new(); len],
        };
        assert_bounded(
            &table(MAX_VM_EVENT_TYPES as usize),
            &table(MAX_VM_EVENT_TYPES as usize + 1),
        );
    }

    #[test]
    fn an_oversized_section_is_refused_before_it_is_parsed() {
        // Well formed but past the cap: an event table spending more
        // than the section budget, refused on length before the decoder
        // reads a byte of it.
        let over = PackageMetadata {
            methods: BTreeMap::new(),
            events: vec!["e".repeat(1024); MAX_VM_EVENT_TYPES as usize],
        };
        let bytes = encode_unchecked(&over);
        assert!(bytes.len() > MAX_PACKAGE_METADATA_BYTES);
        assert!(decode_metadata(&bytes).is_err());
        assert!(encode_metadata(&over).is_err());

        assert!(decode_metadata(&vec![0u8; MAX_PACKAGE_METADATA_BYTES + 1]).is_err());
    }
}
