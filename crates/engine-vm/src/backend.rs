//! The guest invocation backend: the blessed engine on native targets,
//! the reference interpreter on wasm32.
//!
//! One instantiation per guest call — the execution model fuel parity is
//! pinned against — with the session threaded in and out through the
//! host state. Traps come back as deterministic reason strings; the
//! session always survives for the kernel's rollback.

use hyperscale_vm_kernel::KernelSession;

use crate::host::HostState;

/// Per-invocation fuel budget. Exhaustion is a deterministic trap: the
/// metering schedule is pinned by the blessed engine's configuration and
/// mirrored by the reference interpreter.
pub const FUEL: u64 = 10_000_000;

/// One account-guest invocation.
pub enum Invocation<'a> {
    /// `withdraw(vault: borrow<reserve-cell>, amount: list<u8>) -> list<u8>`.
    Withdraw {
        /// Capability index of the vault's reserve handle.
        vault_rep: u32,
        /// The requested amount's encoded bytes.
        amount: &'a [u8],
    },
    /// `deposit(vault: borrow<delta-cell>, amount: list<u8>)`.
    Deposit {
        /// Capability index of the vault's delta handle.
        vault_rep: u32,
        /// The bucket bytes flowing in.
        bucket: &'a [u8],
    },
    /// `assert-balance(vault: borrow<snap-cell>, min: list<u8>)`.
    AssertBalance {
        /// Capability index of the vault's snapshot handle.
        vault_rep: u32,
        /// The required minimum's encoded bytes.
        min: &'a [u8],
    },
    /// `stamp-entropy(leaf: borrow<write-cell>)`.
    StampEntropy {
        /// Capability index of the entropy leaf's write handle.
        leaf_rep: u32,
    },
}

/// What one invocation produced: the session back from the engine, the
/// fuel consumed, and either the export's output bytes or a trap reason.
pub struct InvokeOutcome {
    pub session: KernelSession,
    pub fuel: u64,
    pub result: Result<Option<Vec<u8>>, String>,
}

#[cfg(not(target_arch = "wasm32"))]
mod native {
    use hyperscale_vm_runtime::{
        DeltaCell, ReserveCell, SnapCell, WriteCell, add_kernel_to_linker, blessed_engine,
        validate_component,
    };
    use wasmtime::component::{Component, InstancePre, Linker, Resource};
    use wasmtime::{Engine, Store};

    use super::{FUEL, HostState, Invocation, InvokeOutcome, KernelSession};
    use crate::genesis::account_artifact;

    /// The compiled account guest, pre-linked for cheap instantiation.
    pub struct GuestBackend {
        engine: Engine,
        account: InstancePre<HostState>,
    }

    impl GuestBackend {
        /// Compile the genesis packages on the blessed engine.
        ///
        /// The artifact compiled is the one the package address covers,
        /// metadata section included: what the chain stores is what the
        /// engine runs.
        ///
        /// # Panics
        ///
        /// Panics if the stdlib artifact fails profile validation or
        /// compilation — a build defect, not a runtime condition.
        pub fn new() -> Self {
            let engine = blessed_engine().expect("blessed engine configuration is pinned");
            let artifact = account_artifact();
            validate_component(artifact).expect("the stdlib account artifact clears the profile");
            let component =
                Component::new(&engine, artifact).expect("the stdlib account artifact compiles");
            let mut linker = Linker::<HostState>::new(&engine);
            add_kernel_to_linker(&mut linker).expect("kernel world wiring");
            let account = linker
                .instantiate_pre(&component)
                .expect("account component links against the kernel world");
            Self { engine, account }
        }

        pub fn invoke(&self, session: KernelSession, call: &Invocation<'_>) -> InvokeOutcome {
            let mut store = Store::new(&self.engine, HostState(session));
            store.set_fuel(FUEL).expect("fuel metering is enabled");
            let instance = match self.account.instantiate(&mut store) {
                Ok(instance) => instance,
                Err(error) => {
                    return InvokeOutcome {
                        session: store.into_data().0,
                        fuel: 0,
                        result: Err(format!("instantiate: {error:#}")),
                    };
                }
            };
            let result = match call {
                Invocation::Withdraw { vault_rep, amount } => instance
                    .get_typed_func::<(Resource<ReserveCell>, &[u8]), (Vec<u8>,)>(
                        &mut store, "withdraw",
                    )
                    .map_err(|error| format!("typed export: {error:#}"))
                    .and_then(|func| {
                        func.call(&mut store, (Resource::new_borrow(*vault_rep), amount))
                            .map_err(|trap| format!("{trap:#}"))
                            .map(|(bucket,)| Some(bucket))
                    }),
                Invocation::Deposit { vault_rep, bucket } => instance
                    .get_typed_func::<(Resource<DeltaCell>, &[u8]), ()>(&mut store, "deposit")
                    .map_err(|error| format!("typed export: {error:#}"))
                    .and_then(|func| {
                        func.call(&mut store, (Resource::new_borrow(*vault_rep), bucket))
                            .map_err(|trap| format!("{trap:#}"))
                            .map(|()| None)
                    }),
                Invocation::AssertBalance { vault_rep, min } => instance
                    .get_typed_func::<(Resource<SnapCell>, &[u8]), ()>(&mut store, "assert-balance")
                    .map_err(|error| format!("typed export: {error:#}"))
                    .and_then(|func| {
                        func.call(&mut store, (Resource::new_borrow(*vault_rep), min))
                            .map_err(|trap| format!("{trap:#}"))
                            .map(|()| None)
                    }),
                Invocation::StampEntropy { leaf_rep } => instance
                    .get_typed_func::<(Resource<WriteCell>,), ()>(&mut store, "stamp-entropy")
                    .map_err(|error| format!("typed export: {error:#}"))
                    .and_then(|func| {
                        func.call(&mut store, (Resource::new_borrow(*leaf_rep),))
                            .map_err(|trap| format!("{trap:#}"))
                            .map(|()| None)
                    }),
            };
            let fuel = FUEL - store.get_fuel().expect("fuel metering is enabled");
            InvokeOutcome {
                session: store.into_data().0,
                fuel,
                result,
            }
        }
    }
}

#[cfg(not(target_arch = "wasm32"))]
pub use native::GuestBackend;

#[cfg(target_arch = "wasm32")]
mod reference {
    use hyperscale_vm_ref::{CVal, RefComponent, RefComponentInstance, ResourceKind};

    use super::{HostState, Invocation, InvokeOutcome, KernelSession};
    use crate::genesis::account_artifact;

    /// The decoded account guest under the reference interpreter.
    pub struct GuestBackend {
        account: RefComponent,
    }

    impl GuestBackend {
        /// Decode the genesis packages.
        ///
        /// # Panics
        ///
        /// Panics if the stdlib artifact fails to decode — a build
        /// defect, not a runtime condition.
        pub fn new() -> Self {
            Self {
                account: RefComponent::decode(account_artifact())
                    .expect("the stdlib account artifact decodes"),
            }
        }

        pub fn invoke(&self, session: KernelSession, call: &Invocation<'_>) -> InvokeOutcome {
            let (export, args, has_output) = match call {
                Invocation::Withdraw { vault_rep, amount } => (
                    "withdraw",
                    vec![
                        CVal::Borrow(*vault_rep, ResourceKind::ReserveCell),
                        CVal::Bytes(amount.to_vec()),
                    ],
                    true,
                ),
                Invocation::Deposit { vault_rep, bucket } => (
                    "deposit",
                    vec![
                        CVal::Borrow(*vault_rep, ResourceKind::DeltaCell),
                        CVal::Bytes(bucket.to_vec()),
                    ],
                    false,
                ),
                Invocation::AssertBalance { vault_rep, min } => (
                    "assert-balance",
                    vec![
                        CVal::Borrow(*vault_rep, ResourceKind::SnapCell),
                        CVal::Bytes(min.to_vec()),
                    ],
                    false,
                ),
                Invocation::StampEntropy { leaf_rep } => (
                    "stamp-entropy",
                    vec![CVal::Borrow(*leaf_rep, ResourceKind::WriteCell)],
                    false,
                ),
            };
            let mut instance = RefComponentInstance::instantiate(&self.account, HostState(session))
                .expect("the validated genesis component instantiates");
            let outcome = instance.invoke(export, &args);
            let fuel = instance.fuel_consumed();
            let session = instance.into_host().0;
            let result = match outcome {
                Ok(Ok(values)) => match (has_output, values.as_slice()) {
                    (false, []) => Ok(None),
                    (true, [CVal::Bytes(bytes)]) => Ok(Some(bytes.clone())),
                    other => Err(format!("unexpected result shape: {other:?}")),
                },
                Ok(Err(trap)) => Err(format!("{trap:?}")),
                Err(error) => Err(format!("invoke: {error:?}")),
            };
            InvokeOutcome {
                session,
                fuel,
                result,
            }
        }
    }
}

#[cfg(target_arch = "wasm32")]
pub use reference::GuestBackend;
