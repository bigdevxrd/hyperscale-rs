//! Envelope builders shared by the harnesses and the load generators.
//!
//! The account guest's transfer graph and the signed envelope around it.
//! Both live here rather than beside a caller because the tree encoding
//! and the account address derivation do, and a transfer built one way in
//! a scenario and another way in a load generator is a transfer nobody
//! can compare.

use hyperscale_types::{
    Ed25519PrivateKey, RoutableTransaction, TimestampRange, VmBody, VmTransaction,
};
use hyperscale_vm_effects::{
    Address, Constraint, EdgeRef, EnvelopeTree, GraphArg, GraphNode, IntentDecl, ManifestGraph,
    Value,
};

use crate::vm_statics::{VM_XRD, encode_tree, vm_account_address};

/// The execution gas limit every built envelope signs. Placeholder
/// pricing — well above what a transfer draws, so the ceiling is never
/// what a load generator hits first.
pub const DEFAULT_GAS_LIMIT: u64 = 1_000_000;

/// The withdraw-then-deposit graph moving `amount` of the native
/// resource from `from` to `to`.
#[must_use]
pub fn transfer_graph(from: [u8; 16], to: [u8; 16], amount: u128) -> ManifestGraph {
    ManifestGraph {
        nodes: vec![
            GraphNode {
                target: Address(from),
                method: "withdraw".into(),
                args: vec![
                    GraphArg::Literal(Value::Address(VM_XRD)),
                    GraphArg::Literal(Value::U128(amount)),
                ],
            },
            GraphNode {
                target: Address(to),
                method: "deposit".into(),
                args: vec![GraphArg::Edge {
                    edge: EdgeRef {
                        producer: 0,
                        output: 0,
                    },
                    constraints: vec![Constraint::ResourceIs(VM_XRD)],
                }],
            },
        ],
    }
}

/// Wrap `graph` in a single-intent envelope signed by `payer`.
///
/// `message` rides the envelope's signed content, so a caller submitting
/// the same graph repeatedly inside one validity window varies it to keep
/// the submissions distinct transactions rather than one deduplicated by
/// hash.
#[must_use]
pub fn sign_call(
    graph: ManifestGraph,
    payer: &Ed25519PrivateKey,
    max_fee: u128,
    validity: TimestampRange,
    message: Vec<u8>,
) -> VmTransaction {
    let tree = EnvelopeTree {
        root: IntentDecl {
            graph,
            params: Vec::new(),
        },
        root_bindings: Vec::new(),
        subintents: Vec::new(),
    };
    VmTransaction {
        body: VmBody::Call(encode_tree(&tree).into()),
        subintent_sigs: Vec::new(),
        fee_payer: vm_account_address(&payer.public_key().0),
        max_fee,
        gas_limit: DEFAULT_GAS_LIMIT,
        validity_start_ms: validity.start_timestamp_inclusive.as_millis(),
        validity_end_ms: validity.end_timestamp_exclusive.as_millis(),
        message: message.into(),
        signer: [0; 32],
        signature: [0; 64],
    }
    .sign(payer)
}

/// Build a signed native-resource transfer from `from` to `to`.
///
/// `payer` must control `from`: only the withdrawing account's authority
/// is gated, so one signature composes the whole transfer.
#[must_use]
pub fn build_transfer_tx(
    payer: &Ed25519PrivateKey,
    from: [u8; 16],
    to: [u8; 16],
    amount: u128,
    max_fee: u128,
    validity: TimestampRange,
    message: Vec<u8>,
) -> RoutableTransaction {
    RoutableTransaction::new(sign_call(
        transfer_graph(from, to, amount),
        payer,
        max_fee,
        validity,
        message,
    ))
}
