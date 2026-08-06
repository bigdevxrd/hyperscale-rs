//! Signing message for validator-bind `PeerId` authentication.

use hyperscale_hbor::Hbor;

use crate::signing::NetworkId;

/// Length of the challenge nonce a validator-bind signature covers.
pub const VALIDATOR_BIND_NONCE_LEN: usize = 32;

/// What a validator-bind handshake signature covers: the peer id being
/// bound plus the challenger's nonce, so a bind signature cannot be
/// replayed for a different peer or a different challenge.
#[derive(Debug, Clone, PartialEq, Eq, Hbor)]
#[hbor(signing_domain = "VALIDATOR_BIND", signing_context = NetworkId)]
pub struct ValidatorBindMessage {
    /// The libp2p peer id being bound to the validator key.
    pub peer_id: Vec<u8>,
    /// The challenger's nonce.
    pub nonce: [u8; VALIDATOR_BIND_NONCE_LEN],
}
