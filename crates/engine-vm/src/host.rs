//! The kernel session as the guest runtime's host.
//!
//! Thin delegation so one [`KernelSession`] drives the blessed engine
//! (native) and the reference interpreter (wasm32) with identical
//! semantics and identical refusal messages.

use hyperscale_vm_kernel::KernelSession;

/// Wraps a session for use as a wasmtime store data or a `vm-ref` host.
#[derive(Debug)]
pub struct HostState(pub KernelSession);

macro_rules! delegate {
    ($trait_path:path) => {
        impl $trait_path for HostState {
            fn read_cell(&mut self, rep: u32) -> Result<Vec<u8>, String> {
                self.0.read_cell(rep).map_err(|t| t.to_string())
            }
            fn snap_cell(&mut self, rep: u32) -> Result<Vec<u8>, String> {
                self.0.snap_cell(rep).map_err(|t| t.to_string())
            }
            fn write_cell_get(&mut self, rep: u32) -> Result<Vec<u8>, String> {
                self.0.write_cell_get(rep).map_err(|t| t.to_string())
            }
            fn write_cell_set(&mut self, rep: u32, value: Vec<u8>) -> Result<(), String> {
                self.0.write_cell_set(rep, value).map_err(|t| t.to_string())
            }
            fn delta_add(&mut self, rep: u32, amount: &[u8]) -> Result<(), String> {
                self.0.delta_add(rep, amount).map_err(|t| t.to_string())
            }
            fn delta_sub(&mut self, rep: u32, amount: &[u8]) -> Result<(), String> {
                self.0.delta_sub(rep, amount).map_err(|t| t.to_string())
            }
            fn reserve_amount(&mut self, rep: u32) -> Result<Vec<u8>, String> {
                self.0.reserve_amount(rep).map_err(|t| t.to_string())
            }
            fn range_count(&mut self, rep: u32) -> Result<u32, String> {
                self.0.range_count(rep).map_err(|t| t.to_string())
            }
            fn range_order(&mut self, rep: u32, index: u32) -> Result<Vec<u8>, String> {
                self.0.range_order(rep, index).map_err(|t| t.to_string())
            }
            fn range_entry(&mut self, rep: u32, index: u32) -> Result<Vec<u8>, String> {
                self.0.range_entry(rep, index).map_err(|t| t.to_string())
            }
            fn range_set(&mut self, rep: u32, index: u32, value: Vec<u8>) -> Result<(), String> {
                self.0
                    .range_set(rep, index, value)
                    .map_err(|t| t.to_string())
            }
            fn range_insert(
                &mut self,
                rep: u32,
                order: &[u8],
                value: Vec<u8>,
            ) -> Result<(), String> {
                self.0
                    .range_insert(rep, order, value)
                    .map_err(|t| t.to_string())
            }
            fn range_remove(&mut self, rep: u32, index: u32) -> Result<(), String> {
                self.0.range_remove(rep, index).map_err(|t| t.to_string())
            }
            fn clock_ms(&self) -> u64 {
                self.0.clock_ms()
            }
            fn randomness(&self) -> [u8; 32] {
                self.0.randomness()
            }
            fn hash(&self, data: &[u8]) -> [u8; 32] {
                self.0.hash(data)
            }
            fn emit(&mut self, event_type: u32, payload: Vec<u8>) -> Result<(), String> {
                self.0.emit(event_type, payload).map_err(|t| t.to_string())
            }
        }
    };
}

#[cfg(target_arch = "wasm32")]
use hyperscale_vm_ref::RefKernelHost;
#[cfg(not(target_arch = "wasm32"))]
use hyperscale_vm_runtime::KernelHost;

#[cfg(not(target_arch = "wasm32"))]
delegate!(KernelHost);

#[cfg(target_arch = "wasm32")]
delegate!(RefKernelHost);
