//! VM engine integration: the wave-batch executor over `vm-kernel`.
//!
//! [`VmExecutor`] implements the engine crate's batch seam for the VM
//! variant: derivation through the effects bridge, an owned committed
//! base pre-read from the wave's JMT-backed snapshot, the kernel's
//! deterministic-parallel batch executor, and the movement fold that
//! turns schedule-invariant receipts into per-transaction absolute
//! `database_updates`. Guests run on the blessed wasmtime engine
//! natively and on the reference interpreter on wasm32; the vm repo's
//! differential suite pins byte-identical receipts and fuel across both.
//!
//! [`genesis`] seeds the stdlib world: the account package published
//! under its artifact hash, funded accounts registered as its instances,
//! and their balances as identity-keyed vault cells.

#![warn(missing_docs)]

mod backend;
mod executor;
mod host;
mod runner;

/// VM genesis seeding: the stdlib world and funded-account cells.
pub mod genesis;

pub use executor::VmExecutor;
pub use genesis::{VM_XRD, VmWorld, genesis_world, vm_account_address, vm_genesis_updates};
pub use hyperscale_vm_kernel::ExecutionMode;
