//! Per-provision wire limits.
//!
//! Hard caps applied at decode time on peer-supplied provision payloads.
//! Bound the wire pre-allocation a single merkle proof or per-tx entry
//! list can claim — independent of how many transactions a block
//! carries (which is governed by [`crate::shard::limits`]). Caps on the
//! substate key and value bytes themselves live with the canonical key
//! layout in [`crate::state_key`].

/// Cap on a serialized merkle proof at decode time.
///
/// The proof grows roughly with `claim_count × tree_depth × hash_size`.
/// With JMT decode-time caps of `10_000` claims and `100_000` sibling
/// hashes (32 bytes each), legitimate proofs sit well under 4 MiB; we
/// cap a touch above for headroom.
pub const MAX_MERKLE_PROOF_LEN: usize = 4 * 1024 * 1024;

/// Cap on `ProvisionEntry.entries` length at decode time.
///
/// Each entry is one substate cell the transaction's read set names on
/// the source shard. `16_384` leaves comfortable headroom for any
/// realistic transaction and rejects obviously oversized arrivals before
/// allocation.
pub const MAX_STATE_ENTRIES_PER_TX: usize = 16_384;
