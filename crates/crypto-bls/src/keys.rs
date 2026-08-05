//! BLS keypair generation.

use rand::{Rng, rng};

use crate::bls12381::PrivateKey;

/// Generate a new random BLS12-381 keypair.
///
/// A random 32-byte seed through the same derivation as
/// [`bls_keypair_from_seed`].
#[must_use]
pub fn generate_bls_keypair() -> PrivateKey {
    let mut ikm = [0u8; 32];
    rng().fill_bytes(&mut ikm);
    bls_keypair_from_seed(&ikm)
}

/// Generate a BLS12-381 keypair from a seed (deterministic, for testing/simulation).
///
/// Hashes the full seed to a valid BLS scalar, so any 32 bytes name a
/// key — a seed that is not itself a valid scalar included.
#[must_use]
pub fn bls_keypair_from_seed(seed: &[u8; 32]) -> PrivateKey {
    PrivateKey::from_ikm(seed)
}

/// Deterministic seeded-key fixtures shared across the workspace's test
/// suites, so the same integer names the same key in every crate.
#[cfg(any(test, feature = "test-utils"))]
mod fixtures {
    use hyperscale_crypto::{ConsensusPublicKey, Signer};

    use crate::BlsSigner;

    /// Derive a signer from a small integer, widened into the seed space
    /// as little-endian bytes in the low 8 positions with the rest zero.
    #[must_use]
    pub fn signer_from_u64_seed(seed: u64) -> BlsSigner {
        let mut bytes = [0u8; 32];
        bytes[..8].copy_from_slice(&seed.to_le_bytes());
        BlsSigner::from_seed(&bytes)
    }

    /// Public key of [`signer_from_u64_seed`] for the same integer.
    #[must_use]
    pub fn public_key_from_u64_seed(seed: u64) -> ConsensusPublicKey {
        signer_from_u64_seed(seed).public_key()
    }
}

#[cfg(any(test, feature = "test-utils"))]
pub use fixtures::{public_key_from_u64_seed, signer_from_u64_seed};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bls_keypair_from_seed_is_deterministic_and_seed_sensitive() {
        let seed = [42u8; 32];
        assert_eq!(
            bls_keypair_from_seed(&seed).public_key(),
            bls_keypair_from_seed(&seed).public_key()
        );

        // Seeds differing only past the first 8 bytes must still produce
        // distinct keys (the full seed feeds key derivation).
        let mut seed_a = [0u8; 32];
        seed_a[30] = 0x30;
        seed_a[31] = 0x39;
        let mut seed_b = [0u8; 32];
        seed_b[30] = 0x30;
        seed_b[31] = 0x3a;
        assert_ne!(
            bls_keypair_from_seed(&seed_a).public_key(),
            bls_keypair_from_seed(&seed_b).public_key()
        );
    }
}
