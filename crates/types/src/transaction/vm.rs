//! [`VmTransaction`] — the VM engine's signed transaction body.
//!
//! The body carries a manifest graph as canonical bytes plus the sender's
//! ed25519 signature over them. The graph vocabulary lives behind the
//! effects bridge: this crate treats the graph as opaque signed content,
//! and admission decodes, admits, and derives effect sets through the
//! bridge's registered [`VmStatics`](crate::VmStatics).

use std::sync::OnceLock;

use blake3::Hasher as Blake3;
use radix_common::crypto::{Ed25519PrivateKey, Ed25519PublicKey, Ed25519Signature, verify_ed25519};
use sbor::prelude::*;
use thiserror::Error;

use crate::{BoundedBytes, DeclaredKey, Hash, MAX_TX_BYTES_LEN};

/// Domain separator for the VM transaction signing hash.
const SIGNING_DOMAIN: &[u8] = b"hyperscale-vm-transaction-v0";

/// A VM transaction: the canonical bytes of a manifest graph and the
/// sender's signature over their domain-separated hash.
#[derive(Debug, Clone, PartialEq, Eq, BasicSbor)]
pub struct VmTransaction {
    /// The manifest graph, canonically encoded; the effects bridge owns
    /// the encoding.
    pub graph: BoundedBytes<MAX_TX_BYTES_LEN>,
    /// The sender's ed25519 public key.
    pub signer: [u8; 32],
    /// The sender's signature over [`VmTransaction::signing_hash`].
    pub signature: [u8; 64],
}

impl VmTransaction {
    /// The domain-separated hash the sender signs.
    #[must_use]
    pub fn signing_hash(graph: &[u8]) -> Hash {
        let mut hasher = Blake3::new();
        hasher.update(SIGNING_DOMAIN);
        hasher.update(graph);
        Hash::from_hash_bytes(hasher.finalize().as_bytes())
    }

    /// Sign `graph` with `key`.
    #[must_use]
    pub fn new_signed(graph: Vec<u8>, key: &Ed25519PrivateKey) -> Self {
        let hash = Self::signing_hash(&graph);
        let signature = key.sign(hash.as_bytes());
        Self {
            graph: graph.into(),
            signer: key.public_key().0,
            signature: signature.0,
        }
    }

    /// Whether the signature covers the graph under the signer's key.
    #[must_use]
    pub fn signature_is_valid(&self) -> bool {
        let hash = Self::signing_hash(&self.graph);
        verify_ed25519(
            hash.as_bytes(),
            &Ed25519PublicKey(self.signer),
            &Ed25519Signature(self.signature),
        )
    }
}

/// A VM transaction's derived routing identity.
///
/// Admission conflict keys and the owner prefixes that place it on
/// shards. A pure function of the graph and genesis-static metadata
/// (INV-VM-2) — derived locally at every node, never carried on the
/// wire.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VmRouting {
    /// Conflict keys for the shared-access modes (reads, snapshots).
    pub read_keys: Vec<DeclaredKey>,
    /// Conflict keys for every other mode (writes, deltas, reserves).
    pub write_keys: Vec<DeclaredKey>,
    /// Owner prefixes behind `read_keys`, deduplicated ascending.
    pub read_prefixes: Vec<[u8; 16]>,
    /// Owner prefixes behind `write_keys`, deduplicated ascending.
    pub write_prefixes: Vec<[u8; 16]>,
}

impl VmRouting {
    /// Every owner prefix the transaction touches, ascending, deduplicated.
    #[must_use]
    pub fn all_prefixes(&self) -> Vec<[u8; 16]> {
        let mut prefixes: Vec<[u8; 16]> = self
            .read_prefixes
            .iter()
            .chain(self.write_prefixes.iter())
            .copied()
            .collect();
        prefixes.sort_unstable();
        prefixes.dedup();
        prefixes
    }
}

/// Why VM static derivation refused a graph. Deterministic: every node
/// reaches the identical verdict for the same bytes.
#[derive(Debug, Clone, Error, PartialEq, Eq)]
#[error("vm static derivation failed: {0}")]
pub struct VmStaticsError(pub String);

/// The seam VM admission derives through.
///
/// Decode the graph, admit it, and route its effect sets into the
/// workspace vocabulary. The effects bridge implements it over the
/// genesis-static metadata; node wiring installs it at boot.
pub trait VmStatics: Send + Sync {
    /// Derive the routing identity of the graph, or refuse it.
    ///
    /// # Errors
    ///
    /// [`VmStaticsError`] on an undecodable or inadmissible graph.
    fn derive(&self, graph: &[u8]) -> Result<VmRouting, VmStaticsError>;
}

static VM_STATICS: OnceLock<Box<dyn VmStatics>> = OnceLock::new();

/// Install the process-wide VM statics implementation. The first
/// installation wins; later calls are ignored, so tests and node boot can
/// both install without coordination.
pub fn install_vm_statics(statics: Box<dyn VmStatics>) {
    let _ = VM_STATICS.set(statics);
}

/// Whether a VM statics implementation is installed.
#[must_use]
pub fn vm_statics_installed() -> bool {
    VM_STATICS.get().is_some()
}

/// The installed statics.
///
/// # Panics
///
/// If none is installed — VM transactions cannot exist in a process that
/// never wired the derivation seam.
pub fn vm_statics() -> &'static dyn VmStatics {
    VM_STATICS
        .get()
        .expect("VM statics not installed; node wiring installs the effects-bridge derivation")
        .as_ref()
}
