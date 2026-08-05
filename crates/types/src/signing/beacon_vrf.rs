//! Signing message for beacon-chain VRF reveals.
//!
//! Each committee member signs `(network, epoch)` to produce an
//! epoch-bound VRF reveal. The 96-byte signature is the
//! [`VrfProof`](crate::VrfProof); its digest is the
//! [`VrfOutput`](crate::VrfOutput) mixed into beacon randomness.
//!
//! The VRF property — uniquely determined by `(secret_key, message)` —
//! follows from signatures being deterministic in min-pk mode. The
//! signing domain keeps a VRF reveal from being confused with a PC vote
//! or a block header sig, both of which reuse the same consensus keys.

pub use hyperscale_crypto::vrf_output_from_proof;
use hyperscale_crypto::{SignError, Signer, Verifier};
use hyperscale_hbor::Hbor;

use crate::signing::signed_bytes;
use crate::{ConsensusPublicKey, Epoch, NetworkDefinition, VrfProof};

/// What a VRF reveal covers: the epoch, under the network.
#[derive(Debug, Clone, PartialEq, Eq, Hbor)]
#[hbor(signing_domain = "HYPERSCALE_PC_VRF_v1")]
pub struct VrfRevealMessage {
    /// Network the reveal binds to.
    pub network_id: u8,
    /// The epoch whose randomness the reveal contributes to.
    pub epoch: Epoch,
}

impl VrfRevealMessage {
    /// Assemble the message a VRF reveal signs.
    #[must_use]
    pub const fn new(network: &NetworkDefinition, epoch: Epoch) -> Self {
        Self {
            network_id: network.id,
            epoch,
        }
    }
}

/// Sign `(network, epoch)` and return the VRF proof. The output is
/// [`vrf_output_from_proof`] of the result — a pure function of the
/// proof, never stored separately.
///
/// Deterministic — [`Signer::vrf_sign`] guarantees the proof is a
/// function of `(key, message)` only, so the same `(signer, network,
/// epoch)` always produces the same proof.
///
/// # Errors
///
/// Propagates [`SignError`] when the signer cannot sign.
pub fn vrf_sign(
    signer: &dyn Signer,
    network: &NetworkDefinition,
    epoch: Epoch,
) -> Result<VrfProof, SignError> {
    let msg = signed_bytes(&VrfRevealMessage::new(network, epoch));
    signer.vrf_sign(&msg)
}

/// Verify that `proof` was produced by `pk` over `(network, epoch)`.
///
/// The VRF output is a pure function of the proof
/// ([`vrf_output_from_proof`]), so there is nothing to grind and only one
/// check: the proof, as a signature, verifies against `pk` over the
/// reveal message at `(network, epoch)`.
#[must_use]
pub fn vrf_verify(
    verifier: &dyn Verifier,
    pk: &ConsensusPublicKey,
    network: &NetworkDefinition,
    epoch: Epoch,
    proof: &VrfProof,
) -> bool {
    let msg = signed_bytes(&VrfRevealMessage::new(network, epoch));
    verifier.verify_vrf(pk, &msg, proof)
}

#[cfg(test)]
mod tests {
    use hyperscale_crypto_bls::{BlsVerifier, signer_from_u64_seed};

    use super::*;

    fn net() -> NetworkDefinition {
        NetworkDefinition::simulator()
    }

    #[test]
    fn vrf_sign_verify_round_trip() {
        let signer = signer_from_u64_seed(3);
        let proof = vrf_sign(&signer, &net(), Epoch::new(42)).expect("sign");
        assert!(vrf_verify(
            &BlsVerifier,
            &signer.public_key(),
            &net(),
            Epoch::new(42),
            &proof
        ));
    }

    /// Deterministic: same inputs → same proof across replicas.
    #[test]
    fn vrf_sign_is_deterministic() {
        let signer = signer_from_u64_seed(7);
        let a = vrf_sign(&signer, &net(), Epoch::new(100)).expect("sign");
        let b = vrf_sign(&signer, &net(), Epoch::new(100)).expect("sign");
        assert_eq!(a, b);
    }

    /// A reveal from party A doesn't verify under party B's pubkey.
    #[test]
    fn vrf_verify_rejects_cross_party() {
        let signer_a = signer_from_u64_seed(3);
        let signer_b = signer_from_u64_seed(4);
        let proof = vrf_sign(&signer_a, &net(), Epoch::new(42)).expect("sign");
        assert!(!vrf_verify(
            &BlsVerifier,
            &signer_b.public_key(),
            &net(),
            Epoch::new(42),
            &proof
        ));
    }

    /// A reveal for epoch N doesn't verify against epoch M ≠ N — the
    /// epoch is bound into the signing message.
    #[test]
    fn vrf_verify_rejects_wrong_epoch() {
        let signer = signer_from_u64_seed(3);
        let proof = vrf_sign(&signer, &net(), Epoch::new(42)).expect("sign");
        assert!(!vrf_verify(
            &BlsVerifier,
            &signer.public_key(),
            &net(),
            Epoch::new(43),
            &proof
        ));
    }

    /// Cross-network replay protection at the verify layer: a reveal
    /// signed under mainnet doesn't verify against stokenet even when
    /// the epoch matches.
    #[test]
    fn vrf_verify_rejects_cross_network() {
        let signer = signer_from_u64_seed(3);
        let proof = vrf_sign(&signer, &NetworkDefinition::mainnet(), Epoch::new(42)).expect("sign");
        assert!(!vrf_verify(
            &BlsVerifier,
            &signer.public_key(),
            &NetworkDefinition::stokenet(),
            Epoch::new(42),
            &proof,
        ));
    }

    /// Tampered proof (signature invalid) must reject. The output can't
    /// be tampered independently — it's derived from the proof — so the
    /// proof's signature check is the whole predicate.
    #[test]
    fn vrf_verify_rejects_tampered_proof() {
        let signer = signer_from_u64_seed(3);
        let proof = vrf_sign(&signer, &net(), Epoch::new(42)).expect("sign");
        let mut bytes = *proof.as_bytes();
        bytes[0] ^= 1;
        let proof = VrfProof::new(bytes);
        assert!(!vrf_verify(
            &BlsVerifier,
            &signer.public_key(),
            &net(),
            Epoch::new(42),
            &proof
        ));
    }
}
