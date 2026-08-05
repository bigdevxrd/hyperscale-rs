//! Transaction types for consensus.
//!
//! - [`routable`]: [`RoutableTransaction`], the network-routing wrapper
//!   around a signed manifest envelope.
//! - [`status`]: [`TransactionDecision`], [`TransactionStatus`], [`TransactionError`],
//!   and the RPC-string parser.
//! - [`declared_key`]: the substate-granular admission key.
//! - [`limits`]: per-transaction wire-limit constants.
//! - [`vm`]: the signed envelope and the derivation seam that routes it.

pub mod declared_key;
pub mod limits;
pub mod routable;
pub mod status;
pub mod vm;
