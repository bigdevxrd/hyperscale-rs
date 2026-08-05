//! Transaction types for consensus.
//!
//! - [`wire`]: [`Transaction`], the carried form of a signed envelope.
//! - [`status`]: [`TransactionDecision`], [`TransactionStatus`], [`TransactionError`],
//!   and the RPC-string parser.
//! - [`declared_key`]: the substate-granular admission key.
//! - [`limits`]: per-transaction wire-limit constants.
//! - [`vm`]: [`TransactionEnvelope`], the signed envelope itself, and the
//!   derivation seam that routes it.

pub mod declared_key;
pub mod limits;
pub mod status;
pub mod vm;
pub mod wire;
