//! Signing message for validator proof-of-possession at registration.

use hyperscale_crypto::{SignError, Signer, Verifier};
use hyperscale_hbor::Hbor;

use crate::signing::signed_bytes;
use crate::{ConsensusPublicKey, ConsensusSignature, NetworkDefinition, ValidatorId};

/// What a proof-of-possession signature covers: the registering
/// validator's id and the public key itself, so a registration cannot
/// adopt a key its owner never offered for that identity.
#[derive(Debug, Clone, PartialEq, Eq, Hbor)]
#[hbor(signing_domain = "HYPERSCALE_VALIDATOR_POSSESSION_PROOF_v1")]
pub struct ValidatorPossessionProofMessage {
    /// Network the registration binds to.
    pub network_id: u8,
    /// The registering validator.
    pub validator_id: ValidatorId,
    /// The consensus public key being registered.
    pub pubkey: ConsensusPublicKey,
}

impl ValidatorPossessionProofMessage {
    /// Assemble the message a possession proof signs.
    #[must_use]
    pub const fn new(
        network: &NetworkDefinition,
        validator_id: ValidatorId,
        pubkey: ConsensusPublicKey,
    ) -> Self {
        Self {
            network_id: network.id,
            validator_id,
            pubkey,
        }
    }
}

/// Sign the possession proof for `validator_id` with `signer`'s own key.
///
/// # Errors
///
/// Propagates [`SignError`] when the signer cannot sign.
pub fn validator_possession_proof_sign(
    signer: &dyn Signer,
    network: &NetworkDefinition,
    validator_id: ValidatorId,
) -> Result<ConsensusSignature, SignError> {
    let msg = signed_bytes(&ValidatorPossessionProofMessage::new(
        network,
        validator_id,
        signer.public_key(),
    ));
    signer.sign(&msg)
}

/// Verify `possession_proof` was produced by `pubkey` over
/// `(network, validator_id, pubkey)`.
#[must_use]
pub fn validator_possession_proof_verify(
    verifier: &dyn Verifier,
    network: &NetworkDefinition,
    validator_id: ValidatorId,
    pubkey: &ConsensusPublicKey,
    possession_proof: &ConsensusSignature,
) -> bool {
    let msg = signed_bytes(&ValidatorPossessionProofMessage::new(
        network,
        validator_id,
        *pubkey,
    ));
    verifier.verify(pubkey, &msg, possession_proof)
}

#[cfg(test)]
mod tests {
    use hyperscale_crypto_bls::{BlsVerifier, signer_from_u64_seed as signer};

    use super::*;

    fn net() -> NetworkDefinition {
        NetworkDefinition::simulator()
    }

    #[test]
    fn possession_proof_round_trips() {
        let s = signer(1);
        let proof = validator_possession_proof_sign(&s, &net(), ValidatorId::new(7)).unwrap();
        assert!(validator_possession_proof_verify(
            &BlsVerifier,
            &net(),
            ValidatorId::new(7),
            &s.public_key(),
            &proof
        ));
    }

    #[test]
    fn possession_proof_binds_validator_id() {
        let s = signer(1);
        let proof = validator_possession_proof_sign(&s, &net(), ValidatorId::new(7)).unwrap();
        assert!(!validator_possession_proof_verify(
            &BlsVerifier,
            &net(),
            ValidatorId::new(8),
            &s.public_key(),
            &proof
        ));
    }

    #[test]
    fn possession_proof_rejects_foreign_key() {
        let a = signer(1);
        let b = signer(2);
        let proof = validator_possession_proof_sign(&a, &net(), ValidatorId::new(7)).unwrap();
        assert!(!validator_possession_proof_verify(
            &BlsVerifier,
            &net(),
            ValidatorId::new(7),
            &b.public_key(),
            &proof
        ));
    }
}
