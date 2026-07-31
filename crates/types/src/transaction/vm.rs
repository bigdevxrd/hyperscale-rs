//! [`VmTransaction`] — the VM engine's signed transaction envelope.
//!
//! The envelope carries the bound tree — the composer's root graph plus
//! every signed subintent — as canonical bytes, beside the signing-time
//! choices no node can derive: the fee payer, the fee ceiling and gas
//! limit, snapshot version pins, the validity window, and a capped
//! optional message. The composer signs the whole envelope, and the
//! transaction hash covers it, so distinct submissions differ in signed
//! content. The tree vocabulary lives behind the effects bridge: this
//! crate treats the tree as opaque signed content, and admission
//! decodes, admits, and derives effect sets through the bridge's
//! registered [`VmStatics`](crate::VmStatics).

use std::sync::OnceLock;

use blake3::Hasher as Blake3;
use hyperscale_jmt::{Blake3Hasher, MultiProof, Tree};
use radix_common::crypto::{Ed25519PrivateKey, Ed25519PublicKey, Ed25519Signature, verify_ed25519};
use sbor::prelude::*;
use thiserror::Error;

use crate::provisioning::proof::MerkleInclusionProof;
use crate::state_key::{jmt_value_hash, vm_leaf_key};
use crate::{
    BoundedBytes, DeclaredKey, Hash, MAX_STATE_ENTRY_VALUE_LEN, MAX_TX_BYTES_LEN, ShardId,
    TimestampRange, WeightedTimestamp,
};

/// Domain separator for the VM envelope signing hash.
const SIGNING_DOMAIN: &[u8] = b"hyperscale-vm-envelope-v1";

/// The cap on a VM envelope's optional message, in bytes.
pub const MAX_VM_MESSAGE_LEN: usize = 1024;

/// One bound subintent's signature: the signer's key and their ed25519
/// signature over the subintent's declaration hash, in tree order.
#[derive(Debug, Clone, PartialEq, Eq, BasicSbor)]
pub struct VmSubintentSig {
    /// The subintent signer's ed25519 public key; its derived account
    /// address must match the signer the tree binds.
    pub public_key: [u8; 32],
    /// The signature over the subintent's declaration hash.
    pub signature: [u8; 64],
}

/// A signed snapshot version pin: the client-proven form of a bounded
/// snapshot read.
///
/// The pin names an attested `(shard, height, version)` and carries the
/// read's identity leaf — key, value, and a JMT inclusion proof against
/// `root`. [`VmSnapshotPin::verify_inclusion`] checks the proof at the
/// transaction gate; binding `root` to the shard's actual attested root
/// for that height rides the remote-header channel where attested roots
/// live.
#[derive(Debug, Clone, PartialEq, Eq, BasicSbor)]
pub struct VmSnapshotPin {
    /// The shard whose attested root the pin names.
    pub shard: ShardId,
    /// The pinned block height.
    pub height: u64,
    /// The pinned state version.
    pub version: u64,
    /// The state root the proof verifies against.
    pub root: [u8; 32],
    /// The pinned key's owner half.
    pub owner: [u8; 16],
    /// The pinned key's local half.
    pub local: [u8; 16],
    /// The pinned value; `None` proves absence.
    pub value: Option<BoundedBytes<MAX_STATE_ENTRY_VALUE_LEN>>,
    /// The JMT inclusion proof of the identity leaf under `root`.
    pub proof: MerkleInclusionProof,
}

impl VmSnapshotPin {
    /// Whether the proof binds `(owner, local) → value` under `root`.
    #[must_use]
    pub fn verify_inclusion(&self) -> bool {
        let Ok(proof) = MultiProof::decode(self.proof.as_bytes()) else {
            return false;
        };
        let leaf = vm_leaf_key(self.owner, self.local);
        let value_hash = self.value.as_ref().map(|value| jmt_value_hash(value));
        <Tree<Blake3Hasher, 1>>::verify(&proof, self.root, &[(leaf, value_hash)]).is_ok()
    }
}

/// A VM transaction: the bound envelope tree and the signing-time
/// choices, under the composer's signature.
#[derive(Debug, Clone, PartialEq, Eq, BasicSbor)]
pub struct VmTransaction {
    /// The bound envelope tree, canonically encoded; the effects bridge
    /// owns the encoding.
    pub tree: BoundedBytes<MAX_TX_BYTES_LEN>,
    /// One signature per bound subintent, in tree order.
    pub subintent_sigs: Vec<VmSubintentSig>,
    /// The fee-paying account — the composer's.
    pub fee_payer: [u8; 16],
    /// The signed fee ceiling, in fee units.
    pub max_fee: u128,
    /// The signed execution gas limit.
    pub gas_limit: u64,
    /// Signed snapshot version pins, one per snapshot leg.
    pub snapshot_pins: Vec<VmSnapshotPin>,
    /// The signed validity window's inclusive start, in weighted-time
    /// milliseconds. The wire `validity_range` must mirror the window.
    pub validity_start_ms: u64,
    /// The signed validity window's exclusive end.
    pub validity_end_ms: u64,
    /// An optional message, capped at [`MAX_VM_MESSAGE_LEN`].
    pub message: BoundedBytes<MAX_VM_MESSAGE_LEN>,
    /// The composer's ed25519 public key.
    pub signer: [u8; 32],
    /// The composer's signature over [`VmTransaction::signing_hash`].
    pub signature: [u8; 64],
}

impl VmTransaction {
    /// The domain-separated hash of the envelope's signed content —
    /// everything but the composer's own key and signature. This is
    /// also the identity fresh derivations root at: distinct signed
    /// envelopes never mint the same fresh key.
    #[must_use]
    pub fn signing_hash(&self) -> Hash {
        let mut hasher = Blake3::new();
        let frame = |hasher: &mut Blake3, bytes: &[u8]| {
            hasher.update(&(bytes.len() as u64).to_le_bytes());
            hasher.update(bytes);
        };
        hasher.update(SIGNING_DOMAIN);
        frame(&mut hasher, &self.tree);
        hasher.update(&(self.subintent_sigs.len() as u64).to_le_bytes());
        for sig in &self.subintent_sigs {
            hasher.update(&sig.public_key);
            hasher.update(&sig.signature);
        }
        hasher.update(&self.fee_payer);
        hasher.update(&self.max_fee.to_le_bytes());
        hasher.update(&self.gas_limit.to_le_bytes());
        hasher.update(&(self.snapshot_pins.len() as u64).to_le_bytes());
        for pin in &self.snapshot_pins {
            hasher.update(&pin.shard.depth().to_le_bytes());
            hasher.update(&pin.shard.path().to_le_bytes());
            hasher.update(&pin.height.to_le_bytes());
            hasher.update(&pin.version.to_le_bytes());
            hasher.update(&pin.root);
            hasher.update(&pin.owner);
            hasher.update(&pin.local);
            match &pin.value {
                Some(value) => frame(&mut hasher, value),
                None => {
                    hasher.update(&u64::MAX.to_le_bytes());
                }
            }
            frame(&mut hasher, pin.proof.as_bytes());
        }
        hasher.update(&self.validity_start_ms.to_le_bytes());
        hasher.update(&self.validity_end_ms.to_le_bytes());
        frame(&mut hasher, &self.message);
        Hash::from_hash_bytes(hasher.finalize().as_bytes())
    }

    /// Sign the envelope's content with the composer's key, filling the
    /// signer and signature fields.
    #[must_use]
    pub fn sign(mut self, key: &Ed25519PrivateKey) -> Self {
        let hash = self.signing_hash();
        self.signer = key.public_key().0;
        self.signature = key.sign(hash.as_bytes()).0;
        self
    }

    /// Whether the composer's signature covers the envelope content
    /// under the signer's key.
    #[must_use]
    pub fn signature_is_valid(&self) -> bool {
        let hash = self.signing_hash();
        verify_ed25519(
            hash.as_bytes(),
            &Ed25519PublicKey(self.signer),
            &Ed25519Signature(self.signature),
        )
    }

    /// The signed validity window as the wire's range form.
    #[must_use]
    pub const fn validity_window(&self) -> TimestampRange {
        TimestampRange::new(
            WeightedTimestamp::from_millis(self.validity_start_ms),
            WeightedTimestamp::from_millis(self.validity_end_ms),
        )
    }
}

/// A VM transaction's derived routing identity.
///
/// Admission conflict keys and the owner prefixes that place it on
/// shards. A pure function of the envelope and genesis-static metadata
/// (INV-VM-2) — derived locally at every node, never carried on the
/// wire. Nullifier creation writes are in the write keys: committing a
/// subintent is an exclusive write at its canonical nullifier address.
/// Snapshot reads appear nowhere here: they are lock-free and
/// client-proven, so a snapshot-only shard is not a participant at all.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VmRouting {
    /// Conflict keys for fresh reads — the shared admission class.
    pub read_keys: Vec<DeclaredKey>,
    /// Conflict keys for every mutation (writes, deltas, reserves).
    pub write_keys: Vec<DeclaredKey>,
    /// Owner prefixes behind `read_keys`, deduplicated ascending.
    pub read_prefixes: Vec<[u8; 16]>,
    /// Owner prefixes behind `write_keys`, deduplicated ascending.
    pub write_prefixes: Vec<[u8; 16]>,
    /// The keys whose committed values counterpart shards must carry:
    /// fresh reads plus read-modify-write priors. Deltas, blind writes,
    /// and reserves provision nothing.
    pub provision_keys: Vec<DeclaredKey>,
    /// Owner prefixes behind `provision_keys`, deduplicated ascending —
    /// the wave's provision dependency set routes on these.
    pub provision_prefixes: Vec<[u8; 16]>,
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

/// Everything the bridge derives from a VM envelope.
///
/// The routing identity plus the declaration hash each subintent
/// signature must cover, in tree order. Derivation has already checked
/// that every bound signer address is the one the matching public key
/// derives.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VmDerived {
    /// The routing identity.
    pub routing: VmRouting,
    /// One declaration hash per bound subintent, in tree order.
    pub subintent_hashes: Vec<[u8; 32]>,
    /// Every bounded-window snapshot target, as `(owner, local)` halves —
    /// each must be covered by a verified pin in the envelope.
    pub snapshot_targets: Vec<([u8; 16], [u8; 16])>,
    /// The local half of the fee payer's native-resource vault cell —
    /// the substate the payer shard's reservation check reads and the
    /// fee settlement debits. The owner half is the envelope's
    /// `fee_payer`.
    pub fee_vault_local: [u8; 16],
}

/// Why VM static derivation refused an envelope. Deterministic: every
/// node reaches the identical verdict for the same bytes.
#[derive(Debug, Clone, Error, PartialEq, Eq)]
#[error("vm static derivation failed: {0}")]
pub struct VmStaticsError(pub String);

/// The seam VM admission derives through.
///
/// Decode the envelope tree, admit it, and route its effect sets into
/// the workspace vocabulary. The effects bridge implements it over the
/// genesis-static metadata; node wiring installs it at boot.
pub trait VmStatics: Send + Sync {
    /// Derive the envelope's routing identity and subintent claims, or
    /// refuse it.
    ///
    /// # Errors
    ///
    /// [`VmStaticsError`] on an undecodable or inadmissible envelope,
    /// a subintent signature list that does not match the tree, or a
    /// bound signer address the matching public key does not derive.
    fn derive(&self, vm: &VmTransaction) -> Result<VmDerived, VmStaticsError>;
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

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use hyperscale_jmt::{LeafValue, MemoryStore, NodeKey};

    use super::*;
    use crate::state_key::{jmt_leaf_key, vm_flat_key};

    type Jmt = Tree<Blake3Hasher, 1>;

    /// Build a one-cell VM state and a pin proving it: the identity leaf
    /// under a real JMT root, exactly what a wallet assembles.
    fn proven_pin(owner: [u8; 16], local: [u8; 16], value: &[u8]) -> VmSnapshotPin {
        let store = MemoryStore::new();
        let storage_key = vm_flat_key(owner, local);
        let leaf = jmt_leaf_key(&storage_key, None);
        let updates: BTreeMap<[u8; 32], Option<LeafValue>> = [(
            leaf,
            Some(LeafValue::new(jmt_value_hash(value), value.len() as u64)),
        )]
        .into();
        let result = Jmt::apply_updates(&store, None, 1, &updates).unwrap();
        let mut store = store;
        let root = result.root_hash;
        store.apply(&result);
        let proof = Jmt::prove(&store, &NodeKey::root(1), &[leaf]).unwrap();
        VmSnapshotPin {
            shard: ShardId::leaf(1, 1),
            height: 7,
            version: 7,
            root,
            owner,
            local,
            value: Some(value.to_vec().into()),
            proof: MerkleInclusionProof::new(proof.encode()),
        }
    }

    #[test]
    fn a_proven_pin_verifies_and_tampering_refuses() {
        let pin = proven_pin([0x11; 16], [0x22; 16], b"pinned-cell");
        assert!(pin.verify_inclusion());

        let mut wrong_value = pin.clone();
        wrong_value.value = Some(b"other".to_vec().into());
        assert!(!wrong_value.verify_inclusion());

        let mut wrong_key = pin.clone();
        wrong_key.local = [0x23; 16];
        assert!(!wrong_key.verify_inclusion());

        let mut wrong_root = pin.clone();
        wrong_root.root[0] ^= 1;
        assert!(!wrong_root.verify_inclusion());

        let mut garbage_proof = pin;
        garbage_proof.proof = MerkleInclusionProof::new(vec![0xFF; 8]);
        assert!(!garbage_proof.verify_inclusion());
    }
}
