//! Per-transaction wire limits.
//!
//! Hard caps applied at decode time on peer-supplied transaction
//! payloads. Bound the SBOR `Vec<u8>` / `Vec<NodeId>` pre-allocation a
//! single transaction can claim — independent of how many transactions
//! a block carries (which is governed by [`crate::shard::limits`]).

/// Cap on a transaction's envelope bytes at decode time.
///
/// Bounds the payload a peer can pre-allocate via the SBOR `Vec<u8>`
/// fast path. Realistic transactions sit far below this; it exists to
/// reject obviously malformed or oversized payloads early instead of
/// admitting them and stressing mempool / commit pipelines.
///
/// It is also the ceiling on a published package: an artifact travels
/// inside the transaction that publishes it and lands in a single
/// substate, so this bound and [`crate::MAX_STATE_ENTRY_VALUE_LEN`]
/// together are why no artifact is ever split across cells.
pub const MAX_TX_BYTES_LEN: usize = 1024 * 1024;
