//! Signing message for validator address announcement gossip.

use blake3::Hasher;
use hyperscale_hbor::Hbor;

use crate::{Hash, NetworkDefinition};

/// What a validator address announcement's signature covers: the
/// announcement sequence number plus a digest of the peer id and
/// addresses.
///
/// The digest keeps the signed message fixed-width while binding the
/// signature to the specific announcement contents.
#[derive(Debug, Clone, PartialEq, Eq, Hbor)]
#[hbor(signing_domain = "VALIDATOR_ADDRESS")]
pub struct ValidatorAddressMessage {
    /// Network the announcement binds to.
    pub network_id: u8,
    /// Monotonic announcement sequence — receivers keep the highest.
    pub sequence: u64,
    /// Digest over the length-framed peer id and addresses.
    pub content_digest: Hash,
}

impl ValidatorAddressMessage {
    /// Assemble the message an address announcement signs.
    #[must_use]
    pub fn new(
        network: &NetworkDefinition,
        peer_id_bytes: &[u8],
        addresses: &[Vec<u8>],
        sequence: u64,
    ) -> Self {
        let mut hasher = Hasher::new();
        hasher.update(&frame_len(peer_id_bytes.len()));
        hasher.update(peer_id_bytes);
        for addr in addresses {
            hasher.update(&frame_len(addr.len()));
            hasher.update(addr);
        }
        Self {
            network_id: network.id,
            sequence,
            content_digest: Hash::from_hash_bytes(hasher.finalize().as_bytes()),
        }
    }
}

fn frame_len(len: usize) -> [u8; 8] {
    u64::try_from(len).expect("length fits u64").to_le_bytes()
}
