//! `RoutableTransaction` — wraps a Radix `UserTransaction` with shard-routing metadata.
//!
//! [`RoutableTransaction`] is the raw wire form. Its verified form is
//! `Verified<RoutableTransaction>`; predicate at
//! [`impl Verify<&RoutableTransactionContext<'_>>`](Verify::verify) below.

use std::fmt::{self, Debug, Formatter};
use std::sync::OnceLock;

use blake3::Hasher;
use radix_common::data::manifest::{manifest_decode, manifest_encode};
use radix_transactions::model::{UserTransaction, ValidatedUserTransaction};
use radix_transactions::validation::TransactionValidator;
use sbor::prelude::*;
use thiserror::Error;

use crate::transaction::vm::vm_statics;
use crate::{
    BoundedBytes, BoundedVec, DeclaredKey, Hash, MAX_DECLARED_NODES_PER_TX, MAX_TX_BYTES_LEN,
    NodeId, ShardTrie, TimestampRange, TxHash, Verified, Verify, VmRouting, VmStaticsError,
    VmTransaction, uniform_shard_for_node,
};

/// First byte of a VM-variant body.
///
/// Distinct from manifest-SBOR's payload prefix, so the two engines' wire
/// bodies are disjoint by construction: a Radix body is raw
/// manifest-encoded `UserTransaction` bytes, and a VM body is this tag
/// followed by the basic-SBOR encoding of [`VmTransaction`].
pub const VM_BODY_TAG: u8 = 0x56;

/// A transaction's decoded body: wholly one engine's, by construction —
/// cross-engine composition is inexpressible.
#[derive(Debug, Clone)]
#[allow(clippy::large_enum_variant)] // one cache slot per transaction; the Radix body sat inline before
pub enum TransactionBody {
    /// A Radix `UserTransaction`.
    Radix(UserTransaction),
    /// A VM signed manifest graph.
    Vm(VmTransaction),
}

/// A transaction with routing information.
///
/// Wraps a Radix `UserTransaction` with routing metadata for sharding.
///
/// `serialized_bytes` is the canonical wire form. The `transaction` view
/// (a deserialized `UserTransaction`) is kept around because basic-SBOR
/// can't reach into manifest-SBOR's custom value kinds — the bytes are
/// the SBOR-universe bridge. Other cached fields (`hash`, `validated`,
/// `cached_sbor`) are skipped on the wire and lazily populated from
/// `serialized_bytes`.
#[derive(BasicSbor)]
pub struct RoutableTransaction {
    /// Manifest-encoded `UserTransaction` bytes — the canonical wire form.
    serialized_bytes: BoundedBytes<MAX_TX_BYTES_LEN>,

    declared_reads: BoundedVec<NodeId, MAX_DECLARED_NODES_PER_TX>,
    declared_writes: BoundedVec<NodeId, MAX_DECLARED_NODES_PER_TX>,
    validity_range: TimestampRange,

    /// Deserialized body, populated by `body()` on first access from
    /// `serialized_bytes`. Constructors pre-populate. Not on the wire.
    #[sbor(skip)]
    body: OnceLock<TransactionBody>,

    /// The VM variant's derived routing identity, populated at
    /// verification (or lazily for committed transactions). Never
    /// populated for the Radix variant. Not on the wire — derivation is
    /// local by construction.
    #[sbor(skip)]
    vm_routing: OnceLock<VmRouting>,

    /// Content hash, populated on first call to `hash()` via
    /// `blake3(&serialized_bytes)`. `::new` pre-populates. Not on the
    /// wire — recomputed at each end so a peer can't ship `(hash=X,
    /// tx_bytes=Y)` and have us key the bogus body by X.
    #[sbor(skip)]
    hash: OnceLock<Hash>,

    /// Cached signature-validated transaction. Populated lazily by
    /// `get_or_validate(validator)`. `Option` carries validation
    /// success/failure (the latter shouldn't happen for RPC-validated
    /// txs).
    #[sbor(skip)]
    validated: OnceLock<Option<ValidatedUserTransaction>>,

    /// Pre-encoded SBOR bytes of the full `RoutableTransaction`,
    /// populated lazily by `cached_sbor_bytes()`. Lets the commit thread
    /// hand bytes to `cf_put_raw` without re-encoding.
    #[sbor(skip)]
    cached_sbor: OnceLock<Vec<u8>>,
}

// Manual PartialEq/Eq - compare by hash for efficiency
impl PartialEq for RoutableTransaction {
    fn eq(&self, other: &Self) -> bool {
        self.hash() == other.hash()
    }
}

impl Eq for RoutableTransaction {}

// Manual Clone - OnceLock doesn't implement Clone. Every populated cache
// is copied so the clone doesn't pay first-access cost twice; in
// particular `validated` rides across clones so the signature validation a
// fresh tx incurs at admission is amortized over every later raw clone
// (wave-state extract, mempool block-commit lift, proposal build).
impl Clone for RoutableTransaction {
    fn clone(&self) -> Self {
        let body = OnceLock::new();
        if let Some(t) = self.body.get() {
            let _ = body.set(t.clone());
        }
        let vm_routing = OnceLock::new();
        if let Some(r) = self.vm_routing.get() {
            let _ = vm_routing.set(r.clone());
        }
        let hash = OnceLock::new();
        if let Some(h) = self.hash.get() {
            let _ = hash.set(*h);
        }
        let validated = OnceLock::new();
        if let Some(v) = self.validated.get() {
            let _ = validated.set(v.clone());
        }
        let cached_sbor = OnceLock::new();
        if let Some(b) = self.cached_sbor.get() {
            let _ = cached_sbor.set(b.clone());
        }
        Self {
            serialized_bytes: self.serialized_bytes.clone(),
            declared_reads: self.declared_reads.clone(),
            declared_writes: self.declared_writes.clone(),
            validity_range: self.validity_range,
            body,
            vm_routing,
            hash,
            validated,
            cached_sbor,
        }
    }
}

// Manual Debug — skip the validated and cached_sbor fields.
impl Debug for RoutableTransaction {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("RoutableTransaction")
            .field("hash", &self.hash())
            .field("declared_reads", &self.declared_reads)
            .field("declared_writes", &self.declared_writes)
            .field("validity_range", &self.validity_range)
            .finish_non_exhaustive()
    }
}

impl RoutableTransaction {
    /// `NodeIds` that this transaction reads from.
    #[must_use]
    pub const fn declared_reads(&self) -> &BoundedVec<NodeId, MAX_DECLARED_NODES_PER_TX> {
        &self.declared_reads
    }

    /// `NodeIds` that this transaction writes to.
    #[must_use]
    pub const fn declared_writes(&self) -> &BoundedVec<NodeId, MAX_DECLARED_NODES_PER_TX> {
        &self.declared_writes
    }

    /// The admission conflict keys for this transaction's reads, derived
    /// at the call site — the node-granular projection of
    /// `declared_reads` for the Radix variant, the routed effect sets'
    /// shared-mode keys for the VM variant. Nothing key-granular is
    /// carried on the wire.
    #[must_use]
    pub fn admission_read_keys(&self) -> Vec<DeclaredKey> {
        self.vm_routing().map_or_else(
            || {
                self.declared_reads
                    .iter()
                    .copied()
                    .map(DeclaredKey::node)
                    .collect()
            },
            |routing| routing.read_keys.clone(),
        )
    }

    /// The admission conflict keys for this transaction's writes; see
    /// [`Self::admission_read_keys`].
    #[must_use]
    pub fn admission_write_keys(&self) -> Vec<DeclaredKey> {
        self.vm_routing().map_or_else(
            || {
                self.declared_writes
                    .iter()
                    .copied()
                    .map(DeclaredKey::node)
                    .collect()
            },
            |routing| routing.write_keys.clone(),
        )
    }

    /// Every admission conflict key, reads then writes.
    #[must_use]
    pub fn admission_keys(&self) -> Vec<DeclaredKey> {
        let mut keys = self.admission_read_keys();
        keys.extend(self.admission_write_keys());
        keys
    }

    /// Half-open `WeightedTimestamp` range during which this tx may be
    /// included in a block. Anchored on the parent QC's `weighted_timestamp`
    /// at every check site. Signer-chosen, chain-enforced.
    #[must_use]
    pub const fn validity_range(&self) -> TimestampRange {
        self.validity_range
    }

    /// Create a new routable transaction from a `UserTransaction`.
    ///
    /// `validity_range` must be supplied explicitly — there is no chain-side
    /// default. The signer chooses the bounds; the chain enforces them.
    ///
    /// # Panics
    ///
    /// Panics if the `UserTransaction` cannot be SBOR-encoded — that
    /// indicates a programmer error since `UserTransaction` is a closed
    /// SBOR type and its encoding is infallible in practice.
    #[must_use]
    pub fn new(
        transaction: UserTransaction,
        declared_reads: Vec<NodeId>,
        declared_writes: Vec<NodeId>,
        validity_range: TimestampRange,
    ) -> Self {
        let payload = manifest_encode(&transaction).expect("transaction should be encodable");
        let mut hasher = Hasher::new();
        hasher.update(&payload);
        let hash = Hash::from_hash_bytes(hasher.finalize().as_bytes());

        let body_lock = OnceLock::new();
        let _ = body_lock.set(TransactionBody::Radix(transaction));
        let hash_lock = OnceLock::new();
        let _ = hash_lock.set(hash);

        Self {
            serialized_bytes: payload.into(),
            declared_reads: declared_reads.into(),
            declared_writes: declared_writes.into(),
            validity_range,
            body: body_lock,
            vm_routing: OnceLock::new(),
            hash: hash_lock,
            validated: OnceLock::new(),
            cached_sbor: OnceLock::new(),
        }
    }

    /// Create a routable transaction from a VM transaction. The declared
    /// node fields stay empty — the VM variant's admission keys and shard
    /// sets are derived from its effect sets, never carried.
    ///
    /// # Panics
    ///
    /// Panics if the `VmTransaction` cannot be SBOR-encoded; it is a
    /// closed basic-SBOR type, so encoding is infallible in practice.
    #[must_use]
    pub fn new_vm(vm: VmTransaction, validity_range: TimestampRange) -> Self {
        let mut payload = vec![VM_BODY_TAG];
        payload.extend(basic_encode(&vm).expect("VmTransaction SBOR encode is infallible"));
        let mut hasher = Hasher::new();
        hasher.update(&payload);
        let hash = Hash::from_hash_bytes(hasher.finalize().as_bytes());

        let body_lock = OnceLock::new();
        let _ = body_lock.set(TransactionBody::Vm(vm));
        let hash_lock = OnceLock::new();
        let _ = hash_lock.set(hash);

        Self {
            serialized_bytes: payload.into(),
            declared_reads: Vec::new().into(),
            declared_writes: Vec::new().into(),
            validity_range,
            body: body_lock,
            vm_routing: OnceLock::new(),
            hash: hash_lock,
            validated: OnceLock::new(),
            cached_sbor: OnceLock::new(),
        }
    }

    /// Get the transaction hash (content-addressed).
    ///
    /// Computes `blake3(serialized_bytes)` on first call and caches the
    /// result. `::new` pre-populates the cache.
    pub fn hash(&self) -> TxHash {
        TxHash::from_raw(*self.hash.get_or_init(|| {
            let mut hasher = Hasher::new();
            hasher.update(&self.serialized_bytes);
            Hash::from_hash_bytes(hasher.finalize().as_bytes())
        }))
    }

    /// Whether this is a VM-variant transaction, read off the wire tag
    /// without decoding.
    #[must_use]
    pub fn is_vm(&self) -> bool {
        self.serialized_bytes.first() == Some(&VM_BODY_TAG)
    }

    /// Decode the body, or refuse malformed bytes. The fallible path for
    /// wire input; [`Self::body`] is the post-verification accessor.
    ///
    /// # Errors
    ///
    /// [`RoutableTransactionVerifyError::UndecodableBody`] when the bytes
    /// decode under neither variant's encoding.
    pub fn try_body(&self) -> Result<&TransactionBody, RoutableTransactionVerifyError> {
        if let Some(body) = self.body.get() {
            return Ok(body);
        }
        let decoded = if self.is_vm() {
            basic_decode::<VmTransaction>(&self.serialized_bytes[1..])
                .map(TransactionBody::Vm)
                .map_err(|_| RoutableTransactionVerifyError::UndecodableBody)?
        } else {
            manifest_decode::<UserTransaction>(&self.serialized_bytes)
                .map(TransactionBody::Radix)
                .map_err(|_| RoutableTransactionVerifyError::UndecodableBody)?
        };
        Ok(self.body.get_or_init(|| decoded))
    }

    /// The decoded body. Constructors pre-populate it; wire-decoded
    /// transactions populate it at verification.
    ///
    /// # Panics
    ///
    /// Panics if `serialized_bytes` decode under neither variant.
    /// Wire-decoded transactions are verified (which decodes fallibly)
    /// before this is invoked.
    pub fn body(&self) -> &TransactionBody {
        self.try_body()
            .expect("RoutableTransaction.serialized_bytes failed body decode")
    }

    /// Get a reference to the underlying Radix transaction.
    ///
    /// # Panics
    ///
    /// As [`Self::body`]; additionally if this is a VM-variant
    /// transaction — callers on the Radix path gate by variant first.
    pub fn transaction(&self) -> &UserTransaction {
        match self.body() {
            TransactionBody::Radix(transaction) => transaction,
            TransactionBody::Vm(_) => {
                panic!("transaction() called on a VM-variant RoutableTransaction")
            }
        }
    }

    /// The VM body, when this is a VM-variant transaction.
    #[must_use]
    pub fn vm(&self) -> Option<&VmTransaction> {
        match self.body() {
            TransactionBody::Vm(vm) => Some(vm),
            TransactionBody::Radix(_) => None,
        }
    }

    /// The VM variant's derived routing identity; `None` for the Radix
    /// variant.
    ///
    /// Derives through the installed [`crate::VmStatics`] on first access
    /// and caches per transaction.
    ///
    /// # Panics
    ///
    /// Panics if derivation refuses the graph — unreachable for verified
    /// or committed transactions, whose graphs already derived cleanly at
    /// admission — or if no statics are installed.
    #[must_use]
    pub fn vm_routing(&self) -> Option<&VmRouting> {
        match self.body() {
            TransactionBody::Radix(_) => None,
            TransactionBody::Vm(_) => Some(self.try_vm_routing().unwrap_or_else(|error| {
                panic!("VM routing derivation failed on an admitted transaction: {error}")
            })),
        }
    }

    /// Derive (or fetch the cached) VM routing identity, fallibly — the
    /// verification path.
    ///
    /// # Errors
    ///
    /// [`VmStaticsError`] from the installed derivation.
    ///
    /// # Panics
    ///
    /// Panics if called on the Radix variant.
    pub fn try_vm_routing(&self) -> Result<&VmRouting, VmStaticsError> {
        if let Some(routing) = self.vm_routing.get() {
            return Ok(routing);
        }
        let vm = self.vm().expect("try_vm_routing on a Radix transaction");
        let routing = vm_statics().derive(&vm.graph)?;
        Ok(self.vm_routing.get_or_init(|| routing))
    }

    /// Get or create a validated transaction.
    ///
    /// The first call validates the transaction and caches the result.
    /// Subsequent calls return the cached value, avoiding re-validation.
    ///
    /// Returns None if validation fails (should not happen for transactions
    /// that passed RPC validation).
    pub fn get_or_validate(
        &self,
        validator: &TransactionValidator,
    ) -> Option<&ValidatedUserTransaction> {
        self.validated
            .get_or_init(|| {
                self.transaction()
                    .clone()
                    .prepare_and_validate(validator)
                    .ok()
            })
            .as_ref()
    }

    /// Check if this transaction has already been validated and cached.
    pub fn is_validated(&self) -> bool {
        self.validated.get().is_some()
    }

    /// Get the cached serialized transaction bytes.
    ///
    /// These are the manifest-encoded bytes of the underlying
    /// `UserTransaction`. Use this for:
    /// - Computing transaction merkle roots (avoids re-serialization)
    /// - Network encoding (bytes are ready to use)
    pub fn serialized_bytes(&self) -> &[u8] {
        &self.serialized_bytes
    }

    /// Get the transaction as manifest-encoded bytes.
    ///
    /// Returns a clone of the cached serialized bytes. For read-only access,
    /// prefer `serialized_bytes()`.
    pub fn transaction_bytes(&self) -> Vec<u8> {
        self.serialized_bytes.0.clone()
    }

    /// Pre-serialized SBOR bytes of the full `RoutableTransaction`.
    /// Computed on first call and cached.
    ///
    /// # Panics
    ///
    /// Panics if SBOR encoding fails — that's a programmer error since
    /// every field is `BasicSbor` and the type itself is closed.
    pub fn cached_sbor_bytes(&self) -> &[u8] {
        self.cached_sbor.get_or_init(|| {
            basic_encode(self).expect("RoutableTransaction SBOR encode is infallible")
        })
    }

    /// Check if this transaction is cross-shard under a uniform `num_shards`-way
    /// partition. For the live partition use
    /// [`TopologySnapshot::is_cross_shard_transaction`], which routes against the
    /// active [`ShardTrie`]; this by-count form is for genesis and offline tooling.
    pub fn is_cross_shard(&self, num_shards: u64) -> bool {
        if let Some(routing) = self.vm_routing() {
            let trie = ShardTrie::uniform_from_count(num_shards);
            let mut shards = routing
                .write_prefixes
                .iter()
                .map(|prefix| trie.shard_for_prefix(*prefix));
            let Some(first) = shards.next() else {
                return false;
            };
            return shards.any(|shard| shard != first);
        }
        if self.declared_writes.is_empty() {
            return false;
        }

        let first_shard = uniform_shard_for_node(&self.declared_writes[0], num_shards);
        self.declared_writes
            .iter()
            .skip(1)
            .any(|node| uniform_shard_for_node(node, num_shards) != first_shard)
    }

    /// All `NodeIds` this transaction declares access to.
    pub fn all_declared_nodes(&self) -> impl Iterator<Item = &NodeId> {
        self.declared_reads
            .iter()
            .chain(self.declared_writes.iter())
    }
}

/// Inputs the [`RoutableTransaction`] verifier reads against.
///
/// Borrows the [`TransactionValidator`] (typically owned by the engine /
/// executor caches) without consuming it; multiple verifications can
/// share the same validator.
#[derive(Debug, Copy, Clone)]
pub struct RoutableTransactionContext<'a> {
    /// Radix-side validator running signature + structural checks.
    pub validator: &'a TransactionValidator,
}

/// Failure modes of [`RoutableTransaction`] verification.
#[derive(Debug, Clone, Error, PartialEq, Eq)]
pub enum RoutableTransactionVerifyError {
    /// Radix's [`TransactionValidator::prepare_and_validate`] rejected
    /// the transaction (bad signature, malformed payload, or version
    /// mismatch).
    #[error("transaction failed Radix prepare_and_validate")]
    InvalidUserTransaction,
    /// The body bytes decode under neither variant's encoding.
    #[error("transaction body bytes are undecodable")]
    UndecodableBody,
    /// The VM body's ed25519 signature does not cover its graph.
    #[error("vm transaction signature is invalid")]
    InvalidVmSignature,
    /// VM static derivation refused the graph.
    #[error(transparent)]
    VmDerivation(#[from] VmStaticsError),
}

/// Construction asserts the variant's own predicate:
///
/// - **Radix**: the `UserTransaction` passes Radix's
///   [`TransactionValidator::prepare_and_validate`] — sender signature
///   valid, well-formed for the active protocol version.
/// - **Vm**: the body decodes, its ed25519 signature covers the graph,
///   and the graph admits and routes under the installed
///   [`crate::VmStatics`] (which caches the derived identity on the
///   transaction).
///
/// Construction goes through one of two gates:
///
/// - [`<RoutableTransaction as Verify>::verify`](Verify::verify) — runs
///   the variant's predicate.
/// - [`Verified::<RoutableTransaction>::new_unchecked`] — re-wraps a
///   transaction whose predicate already held via an out-of-band trust
///   source (storage-recovery, where the value was validated before
///   persistence; equivalent-attestation paths). Every call site
///   carries a `// SAFETY:` comment naming the trust source.
impl Verify<&RoutableTransactionContext<'_>> for RoutableTransaction {
    type Error = RoutableTransactionVerifyError;

    fn verify(&self, ctx: &RoutableTransactionContext<'_>) -> Result<Verified<Self>, Self::Error> {
        match self.try_body()? {
            TransactionBody::Radix(_) => {
                if self.get_or_validate(ctx.validator).is_none() {
                    return Err(RoutableTransactionVerifyError::InvalidUserTransaction);
                }
            }
            TransactionBody::Vm(vm) => {
                if !vm.signature_is_valid() {
                    return Err(RoutableTransactionVerifyError::InvalidVmSignature);
                }
                self.try_vm_routing()?;
            }
        }
        Ok(Verified::new_unchecked(self.clone()))
    }
}

impl Verified<RoutableTransaction> {
    /// Re-wrap a `RoutableTransaction` whose trust derives from inclusion
    /// in a committed block.
    ///
    /// Trust chain (BFT-transitive):
    /// 1. The tx is contained in a `CertifiedBlock`.
    /// 2. `CertifiedBlock` carries a QC attesting ≥2f+1 voting power.
    /// 3. Voters refuse to vote on blocks whose `Block.transactions`
    ///    entries are not all `Verifiable::Verified` — see
    ///    `validate_block_for_vote` in `crates/shard`.
    /// 4. Therefore every tx in a committed block was admission-validated
    ///    by at least one honest voter through the standard `Verify` gate.
    ///
    /// Callers: mempool reload from a committed block, storage
    /// rehydration into block containers, and any other path that
    /// surfaces a raw `RoutableTransaction` whose container is itself
    /// the trust anchor.
    #[must_use]
    pub const fn from_persisted(tx: RoutableTransaction) -> Self {
        Self::new_unchecked(tx)
    }
}

#[cfg(test)]
mod tests {
    use sbor::{
        BASIC_SBOR_V1_MAX_DEPTH, BASIC_SBOR_V1_PAYLOAD_PREFIX, DecodeError, Encoder as _,
        NoCustomValueKind, ValueKind, VecEncoder, basic_decode, basic_encode,
    };

    use super::*;
    use crate::test_utils::{test_node, test_transaction_with_nodes, test_validity_range};
    use crate::{Ed25519PrivateKey, VmStatics, install_vm_statics};

    struct StubStatics;

    impl VmStatics for StubStatics {
        fn derive(&self, graph: &[u8]) -> Result<VmRouting, VmStaticsError> {
            if graph == b"inadmissible" {
                return Err(VmStaticsError("stub refusal".into()));
            }
            Ok(VmRouting {
                read_keys: vec![DeclaredKey::prefix([0x11; 16])],
                write_keys: vec![DeclaredKey::substate([0x22; 16], [0x01; 16])],
                read_prefixes: vec![[0x11; 16]],
                write_prefixes: vec![[0x22; 16]],
            })
        }
    }

    fn vm_fixture(graph: &[u8]) -> RoutableTransaction {
        install_vm_statics(Box::new(StubStatics));
        let key = Ed25519PrivateKey::from_bytes(&[7u8; 32]).unwrap();
        let vm = VmTransaction::new_signed(graph.to_vec(), &key);
        RoutableTransaction::new_vm(vm, test_validity_range())
    }

    #[test]
    fn vm_roundtrip_preserves_hash_and_variant() {
        let tx = vm_fixture(b"graph bytes");
        assert!(tx.is_vm());
        let bytes = basic_encode(&tx).unwrap();
        let decoded: RoutableTransaction = basic_decode(&bytes).unwrap();
        assert_eq!(decoded.hash(), tx.hash());
        assert!(decoded.is_vm());
        assert!(matches!(decoded.try_body(), Ok(TransactionBody::Vm(_))));
    }

    #[test]
    fn vm_admission_keys_derive_through_the_installed_statics() {
        let tx = vm_fixture(b"graph bytes");
        assert_eq!(
            tx.admission_read_keys(),
            vec![DeclaredKey::prefix([0x11; 16])]
        );
        assert_eq!(
            tx.admission_write_keys(),
            vec![DeclaredKey::substate([0x22; 16], [0x01; 16])]
        );
        assert!(!tx.is_cross_shard(1));
    }

    #[test]
    fn vm_verification_checks_signature_and_derivation() {
        use radix_transactions::validation::TransactionValidator;
        let validator = TransactionValidator::new_for_latest_simulator();
        let ctx = RoutableTransactionContext {
            validator: &validator,
        };

        let good = vm_fixture(b"graph bytes");
        assert!(good.verify(&ctx).is_ok());

        // A tampered signature refuses.
        let mut vm = good.vm().unwrap().clone();
        vm.signature[0] ^= 1;
        let bad_signature = RoutableTransaction::new_vm(vm, test_validity_range());
        assert_eq!(
            bad_signature.verify(&ctx).unwrap_err(),
            RoutableTransactionVerifyError::InvalidVmSignature
        );

        // A refused graph surfaces the derivation error.
        let inadmissible = vm_fixture(b"inadmissible");
        assert!(matches!(
            inadmissible.verify(&ctx).unwrap_err(),
            RoutableTransactionVerifyError::VmDerivation(_)
        ));

        // Garbage after the tag is an undecodable body, not a panic.
        let mut wire = basic_encode(&vm_fixture(b"graph bytes")).unwrap();
        let decoded: RoutableTransaction = basic_decode(&wire).unwrap();
        drop(decoded);
        let tx = vm_fixture(b"graph bytes");
        let mut bytes = tx.serialized_bytes().to_vec();
        bytes.truncate(3);
        wire.clear();
        let garbage = RoutableTransaction {
            serialized_bytes: bytes.into(),
            declared_reads: Vec::new().into(),
            declared_writes: Vec::new().into(),
            validity_range: test_validity_range(),
            body: OnceLock::new(),
            vm_routing: OnceLock::new(),
            hash: OnceLock::new(),
            validated: OnceLock::new(),
            cached_sbor: OnceLock::new(),
        };
        assert_eq!(
            garbage.verify(&ctx).unwrap_err(),
            RoutableTransactionVerifyError::UndecodableBody
        );
    }

    #[test]
    fn roundtrip_preserves_content_hash() {
        let tx = test_transaction_with_nodes(&[1, 2, 3], vec![test_node(1)], vec![test_node(2)]);
        let original_hash = tx.hash();
        let bytes = basic_encode(&tx).unwrap();
        let decoded: RoutableTransaction = basic_decode(&bytes).unwrap();
        assert_eq!(decoded.hash(), original_hash);
        assert_eq!(decoded.serialized_bytes(), tx.serialized_bytes());
    }

    #[test]
    fn decoded_hash_is_blake3_of_tx_bytes_not_wire_value() {
        // The hash isn't on the wire; decode pulls only `serialized_bytes`
        // and the lazy `hash()` call computes blake3 over those bytes.
        let tx = test_transaction_with_nodes(&[7, 8, 9], vec![test_node(3)], vec![test_node(4)]);
        let bytes = basic_encode(&tx).unwrap();
        let decoded: RoutableTransaction = basic_decode(&bytes).unwrap();
        let mut hasher = Hasher::new();
        hasher.update(decoded.serialized_bytes());
        let expected = TxHash::from_raw(Hash::from_hash_bytes(hasher.finalize().as_bytes()));
        assert_eq!(decoded.hash(), expected);
    }

    #[test]
    fn decode_rejects_oversized_tx_bytes() {
        // Hand-roll a 4-field payload whose `tx_bytes` length prefix
        // exceeds MAX_TX_BYTES_LEN. The `BoundedBytes` decoder must
        // error before allocating the full Vec.
        let mut buf = Vec::with_capacity(32);
        {
            let mut enc = VecEncoder::<NoCustomValueKind>::new(&mut buf, BASIC_SBOR_V1_MAX_DEPTH);
            enc.write_payload_prefix(BASIC_SBOR_V1_PAYLOAD_PREFIX)
                .unwrap();
            enc.write_value_kind(ValueKind::Tuple).unwrap();
            enc.write_size(4).unwrap();
            enc.write_value_kind(ValueKind::Array).unwrap();
            enc.write_value_kind(ValueKind::U8).unwrap();
            enc.write_size(MAX_TX_BYTES_LEN + 1).unwrap();
        }
        let err = basic_decode::<RoutableTransaction>(&buf).unwrap_err();
        assert!(matches!(
            err,
            DecodeError::UnexpectedSize { expected, actual }
                if expected == MAX_TX_BYTES_LEN && actual == MAX_TX_BYTES_LEN + 1
        ));
    }

    #[test]
    fn decode_rejects_oversized_declared_reads() {
        // Hand-roll a 4-field payload: a real (decodable) tx_bytes
        // followed by a declared_reads array whose length exceeds the
        // cap. The `BoundedVec` decoder fires before consuming any
        // element bytes.
        let real = test_transaction_with_nodes(&[1], vec![test_node(1)], vec![test_node(1)]);
        let mut buf = Vec::with_capacity(real.serialized_bytes().len() + 16);
        {
            let mut enc = VecEncoder::<NoCustomValueKind>::new(&mut buf, BASIC_SBOR_V1_MAX_DEPTH);
            enc.write_payload_prefix(BASIC_SBOR_V1_PAYLOAD_PREFIX)
                .unwrap();
            enc.write_value_kind(ValueKind::Tuple).unwrap();
            enc.write_size(4).unwrap();
            enc.encode(&real.serialized_bytes().to_vec()).unwrap();
            enc.write_value_kind(ValueKind::Array).unwrap();
            enc.write_value_kind(NodeId::value_kind()).unwrap();
            enc.write_size(MAX_DECLARED_NODES_PER_TX + 1).unwrap();
        }
        let err = basic_decode::<RoutableTransaction>(&buf).unwrap_err();
        assert!(matches!(
            err,
            DecodeError::UnexpectedSize { expected, actual }
                if expected == MAX_DECLARED_NODES_PER_TX && actual == MAX_DECLARED_NODES_PER_TX + 1
        ));
    }

    #[test]
    fn decode_rejects_old_5_field_shape() {
        // Hand-roll the prior wire layout (with a leading hash field) to
        // confirm a peer can't keep shipping the spoofable shape.
        let tx = test_transaction_with_nodes(&[1, 2, 3], vec![test_node(1)], vec![test_node(2)]);
        let mut buf = Vec::with_capacity(256);
        {
            let mut enc = VecEncoder::<NoCustomValueKind>::new(&mut buf, BASIC_SBOR_V1_MAX_DEPTH);
            enc.write_payload_prefix(BASIC_SBOR_V1_PAYLOAD_PREFIX)
                .unwrap();
            enc.write_value_kind(ValueKind::Tuple).unwrap();
            enc.write_size(5).unwrap();
            // Forged hash (peer-chosen, would diverge from real tx hash).
            let bogus_hash = [0xAAu8; 32];
            enc.encode(&bogus_hash).unwrap();
            enc.encode(&tx.serialized_bytes().to_vec()).unwrap();
            enc.encode(&tx.declared_reads).unwrap();
            enc.encode(&tx.declared_writes).unwrap();
            enc.encode(&tx.validity_range).unwrap();
        }
        let err = basic_decode::<RoutableTransaction>(&buf).unwrap_err();
        assert!(matches!(
            err,
            DecodeError::UnexpectedSize {
                expected: 4,
                actual: 5
            }
        ));
    }
}
