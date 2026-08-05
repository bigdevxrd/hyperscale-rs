//! Signing messages for every signature the consensus protocol gathers.
//!
//! Each signable artifact pairs with a message struct deriving
//! `#[hbor(signing_domain = "...")]`: the bytes a signature covers are
//! [`HborSigned::signing_bytes`](hyperscale_hbor::HborSigned) — the
//! framed domain, then the canonical encoding of the fields. Domain
//! separation prevents cross-protocol replay; injectivity of the
//! canonical encoding makes every field binding, with no per-message
//! framing argument.

use hyperscale_hbor::HborSigned;

/// The bytes a signature over `message` covers.
///
/// Every signing message is a small closed struct, so encoding cannot
/// hit a length or depth cap; the panic is unreachable.
///
/// # Panics
///
/// Panics if encoding the message fails, which the message shapes rule
/// out.
#[must_use]
pub fn signed_bytes<M: HborSigned>(message: &M) -> Vec<u8> {
    message
        .signing_bytes()
        .expect("signing messages are small closed structs")
}

mod beacon_pc;
mod beacon_ratify;
mod beacon_vrf;
mod execution;
mod provisions;
mod ready_signal;
mod shard;
mod shard_reveal;
mod validator_address;
mod validator_bind;
mod validator_possession_proof;

pub use beacon_pc::{
    PcRound, PcScope, PcVoteMessage, SpcEmptyViewMessage, SpcRelayKind, SpcRelayMessage,
};
pub use beacon_ratify::RatifyVoteMessage;
pub use beacon_vrf::{VrfRevealMessage, vrf_output_from_proof, vrf_sign, vrf_verify};
pub use execution::{ExecCertBatchMessage, ExecVoteBatchMessage, ExecVoteMessage};
pub use provisions::StateProvisionsMessage;
pub use ready_signal::ReadySignalMessage;
pub use shard::{
    BlockHeaderMessage, BlockVoteMessage, CertifiedBlockHeaderMessage, TimeoutMessage,
};
pub use shard_reveal::{ShardRevealMessage, shard_reveal_sign, shard_reveal_verify};
pub use validator_address::ValidatorAddressMessage;
pub use validator_bind::{VALIDATOR_BIND_NONCE_LEN, ValidatorBindMessage};
pub use validator_possession_proof::{
    ValidatorPossessionProofMessage, validator_possession_proof_sign,
    validator_possession_proof_verify,
};
