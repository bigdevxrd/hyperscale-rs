//! The workspace's binding to the VM effect vocabulary.
//!
//! [`ProtocolHasher`] puts the protocol hash — blake3 — behind the
//! `vm_effects` hashing seam: domain-separated and length-framed, so a
//! part boundary is always semantic. [`BridgeStatics`] derives a signed
//! envelope's admission keys, participant prefixes and subintent claims
//! through it; [`admit_package`] judges a publish; [`PoolRegistry`] reads
//! a recognised pool's events as beacon facts.

pub mod artifact;
pub mod builder;
pub mod staking;
pub mod vm_metadata;
pub mod vm_statics;
mod wire;

pub use artifact::{METADATA_SECTION, admit_package, attach_metadata, extract_metadata};
use blake3::Hasher as Blake3;
pub use builder::{DEFAULT_GAS_LIMIT, build_transfer_tx, sign_call, transfer_graph};
use hyperscale_vm_effects::{Hash32, Hasher};
pub use staking::{PoolRegistry, witness_from_event};
pub use vm_metadata::{MAX_PACKAGE_METADATA_BYTES, decode_metadata, encode_metadata};
pub use vm_statics::{
    BridgeStatics, XRD, account_address, check_target_authority, decode_tree, encode_tree,
    entropy_key, envelope_identity, validator_key, vault_key,
};

/// The protocol hash behind the `vm_effects` hashing seam: blake3 over the
/// length-framed domain and parts. Pure, and framed so that moving bytes
/// across a part boundary always changes the digest.
#[derive(Clone, Copy, Debug, Default)]
pub struct ProtocolHasher;

impl Hasher for ProtocolHasher {
    fn hash(&self, domain: &[u8], parts: &[&[u8]]) -> Hash32 {
        let mut hasher = Blake3::new();
        hasher.update(&(domain.len() as u64).to_le_bytes());
        hasher.update(domain);
        for part in parts {
            hasher.update(&(part.len() as u64).to_le_bytes());
            hasher.update(part);
        }
        Hash32(*hasher.finalize().as_bytes())
    }
}

#[cfg(test)]
mod tests {
    use hyperscale_vm_effects::Hasher;

    use super::ProtocolHasher;

    #[test]
    fn the_protocol_hasher_is_deterministic_framed_and_domain_separated() {
        let a = ProtocolHasher.hash(b"d", &[b"ab", b"c"]);
        assert_eq!(a, ProtocolHasher.hash(b"d", &[b"ab", b"c"]));
        // Part boundaries are semantic.
        assert_ne!(a, ProtocolHasher.hash(b"d", &[b"a", b"bc"]));
        assert_ne!(a, ProtocolHasher.hash(b"d", &[b"abc"]));
        // Domains separate.
        assert_ne!(a, ProtocolHasher.hash(b"e", &[b"ab", b"c"]));
    }
}
