//! The engine seam's guest runner: one transaction's manifest walked
//! node by node, each node invoking its guest export with the session's
//! capability handles and the edge cells produced upstream.
//!
//! The genesis stdlib surface is the account guest; its exports are the
//! invocation shapes wired here. Anything else fails as a deterministic
//! user error — admission over the genesis-static metadata cannot
//! produce it.

use std::collections::BTreeMap;

use hyperscale_vm_effects::{Declaration, Manifest, ManifestHash, NodeInput, SubstateKey, Value};
use hyperscale_vm_kernel::{
    Capability, GuestRunner, KernelSession, Outcome, RunResult, TxHash as VmTxHash, encode_amount,
};

use crate::backend::{GuestBackend, Invocation};
use crate::genesis::{entropy_key, vault_key};

/// One derived transaction, keyed for the runner by its kernel hash.
pub struct PreparedVmTx {
    /// The flattened manifest the runner walks — envelope trees lower
    /// into it, so the runner never sees intent structure; each edge
    /// input carries its resolved resource type and flattened source.
    pub manifest: Manifest,
    /// The admitted identity (fresh-ID root); unused by the account
    /// surface but part of the derivation the executor caches.
    #[allow(dead_code)] // consumed once the stdlib surface grows fresh-ID methods
    pub identity: ManifestHash,
    /// The routed declaration, both views: the folded set scheduling
    /// reads, and the clause order materialization walks.
    pub declaration: Declaration,
    /// The subintent nullifier keys the batch entry enforces.
    pub nullifiers: Vec<SubstateKey>,
}

pub struct ManifestRunner<'a> {
    pub backend: &'a GuestBackend,
    pub prepared: &'a BTreeMap<VmTxHash, PreparedVmTx>,
}

fn rep_of(session: &KernelSession, wanted: &Capability) -> Option<u32> {
    session
        .capabilities()
        .iter()
        .position(|capability| capability == wanted)
        .and_then(|position| u32::try_from(position).ok())
}

/// A node invocation's success: the session back, the node's output
/// cells, and the fuel consumed.
type NodeSuccess = (KernelSession, Vec<Vec<u8>>, u64);

/// A node invocation's failure: the session back, the deterministic
/// reason, and the fuel consumed before the abort. Boxed — the session
/// is large and the failure path is cold.
type NodeFailure = Box<(KernelSession, String, u64)>;

fn fail(session: KernelSession, reason: impl Into<String>, fuel: u64) -> NodeFailure {
    Box::new((session, reason.into(), fuel))
}

impl ManifestRunner<'_> {
    /// Invoke one node's export. `Err` carries the session back with a
    /// deterministic reason; the whole transaction aborts as a user
    /// error.
    #[allow(clippy::too_many_lines)] // one arm per stdlib method
    fn invoke_node(
        &self,
        entry: &PreparedVmTx,
        index: usize,
        outputs: &[Vec<Vec<u8>>],
        mut session: KernelSession,
    ) -> Result<NodeSuccess, NodeFailure> {
        let node = &entry.manifest.nodes[index];
        // The node names its target, and an emission is attributed to it —
        // the session holds one capability table for the whole transaction
        // and cannot tell whose call is running.
        session.enter_invocation(node.target);
        match node.method.as_str() {
            "withdraw" => {
                let (
                    NodeInput::Literal(Value::Address(resource)),
                    NodeInput::Literal(Value::U128(amount)),
                ) = (&node.inputs[0], &node.inputs[1])
                else {
                    return Err(fail(session, "withdraw argument shape", 0));
                };
                let vault = vault_key(node.target.0, *resource);
                let Some(rep) = rep_of(&session, &Capability::Reserve(vault)) else {
                    return Err(fail(session, "missing reserve capability", 0));
                };
                let invoked = self.backend.invoke(
                    session,
                    &Invocation::Withdraw {
                        vault_rep: rep,
                        amount: &encode_amount(*amount),
                    },
                );
                match invoked.result {
                    Ok(Some(bucket)) => Ok((invoked.session, vec![bucket], invoked.fuel)),
                    Ok(None) => Err(fail(
                        invoked.session,
                        "withdraw returned nothing",
                        invoked.fuel,
                    )),
                    Err(reason) => Err(fail(invoked.session, reason, invoked.fuel)),
                }
            }
            "deposit" => {
                let NodeInput::Edge {
                    source, resource, ..
                } = &node.inputs[0]
                else {
                    return Err(fail(session, "deposit argument shape", 0));
                };
                // The lowered edge names only its producer; the account
                // surface's producers are single-output.
                let Some(bucket) = outputs
                    .get(*source as usize)
                    .and_then(|node_outputs| node_outputs.first())
                    .cloned()
                else {
                    return Err(fail(session, "dangling edge", 0));
                };
                let vault = vault_key(node.target.0, *resource);
                let Some(rep) = rep_of(&session, &Capability::Delta(vault)) else {
                    return Err(fail(session, "missing delta capability", 0));
                };
                let invoked = self.backend.invoke(
                    session,
                    &Invocation::Deposit {
                        vault_rep: rep,
                        bucket: &bucket,
                    },
                );
                match invoked.result {
                    Ok(_) => Ok((invoked.session, Vec::new(), invoked.fuel)),
                    Err(reason) => Err(fail(invoked.session, reason, invoked.fuel)),
                }
            }
            "assert-balance" => {
                let (
                    NodeInput::Literal(Value::Address(resource)),
                    NodeInput::Literal(Value::U128(min)),
                    NodeInput::Literal(Value::U64(_window)),
                ) = (&node.inputs[0], &node.inputs[1], &node.inputs[2])
                else {
                    return Err(fail(session, "assert-balance argument shape", 0));
                };
                let vault = vault_key(node.target.0, *resource);
                let Some(rep) = rep_of(&session, &Capability::Locked(vault)) else {
                    return Err(fail(session, "missing snapshot capability", 0));
                };
                let invoked = self.backend.invoke(
                    session,
                    &Invocation::AssertBalance {
                        vault_rep: rep,
                        min: &encode_amount(*min),
                    },
                );
                match invoked.result {
                    Ok(_) => Ok((invoked.session, Vec::new(), invoked.fuel)),
                    Err(reason) => Err(fail(invoked.session, reason, invoked.fuel)),
                }
            }
            "stamp-entropy" => {
                let leaf = entropy_key(node.target.0);
                let Some(rep) = rep_of(&session, &Capability::Write(leaf)) else {
                    return Err(fail(session, "missing write capability", 0));
                };
                let invoked = self
                    .backend
                    .invoke(session, &Invocation::StampEntropy { leaf_rep: rep });
                match invoked.result {
                    Ok(_) => Ok((invoked.session, Vec::new(), invoked.fuel)),
                    Err(reason) => Err(fail(invoked.session, reason, invoked.fuel)),
                }
            }
            other => Err(fail(session, format!("unsupported method: {other}"), 0)),
        }
    }
}

impl GuestRunner for ManifestRunner<'_> {
    fn run(&self, tx: VmTxHash, mut session: KernelSession) -> RunResult {
        let Some(entry) = self.prepared.get(&tx) else {
            return RunResult {
                session,
                outcome: Outcome::UserError {
                    reason: "unprepared transaction".to_string(),
                },
                fuel: 0,
            };
        };
        let mut outputs: Vec<Vec<Vec<u8>>> = Vec::with_capacity(entry.manifest.nodes.len());
        let mut fuel = 0u64;
        for index in 0..entry.manifest.nodes.len() {
            match self.invoke_node(entry, index, &outputs, session) {
                Ok((returned, node_outputs, consumed)) => {
                    session = returned;
                    session.leave_invocation();
                    fuel += consumed;
                    outputs.push(node_outputs);
                }
                Err(failure) => {
                    let (returned, reason, consumed) = *failure;
                    return RunResult {
                        session: returned,
                        outcome: Outcome::UserError { reason },
                        fuel: fuel + consumed,
                    };
                }
            }
        }
        RunResult {
            session,
            outcome: Outcome::Completed { value: None },
            fuel,
        }
    }
}
