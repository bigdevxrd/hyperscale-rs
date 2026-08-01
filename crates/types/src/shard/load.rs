//! The shard's attested load, as a block header states it.

use sbor::prelude::*;

/// What a block attests about its shard's load: the compute the chain has
/// consumed and the state it holds.
///
/// Both scalars are header content, so a consumer reads them off a header
/// it already holds — the beacon off the boundary header it sources each
/// epoch, a joining node off the block it joined at — and every replica
/// recomputes them before voting. The pair is deliberately two shapes:
///
/// - [`cumulative_gas`](Self::cumulative_gas) is a **flow**, carried as a
///   running total over the chain's whole history. A consumer wanting one
///   epoch's consumption differences it against the total it last
///   recorded, which makes the quantity monotone and its application
///   idempotent: a missed boundary crossing is absorbed by the next one
///   instead of lost. Carrying the total rather than the increment is
///   also what lets a node that joined mid-chain continue the count —
///   the block it synced to states the running total, so nothing has to
///   reconstruct it from history the joiner does not have.
/// - [`substate_bytes`](Self::substate_bytes) is a **level**, the byte
///   total behind the block's parent state. A consumer records it as-is,
///   and a missed crossing simply leaves the value unrefreshed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, BasicSbor)]
pub struct ShardLoad {
    /// Gas this chain has consumed over its whole history, through the
    /// certificates the block itself carries.
    ///
    /// Accumulation saturates rather than wrapping. Wrapping would break
    /// the monotonicity a differencing consumer relies on, and it has no
    /// honest reading: the epoch it straddles would come out as zero
    /// consumption or as the whole counter's width.
    pub cumulative_gas: u64,
    /// Committed substate byte total behind the block's parent state —
    /// the same quantity the reshape predicate evaluates.
    ///
    /// `None` under exactly the condition that takes that predicate out
    /// of play: the block's ancestry crosses a halt recovery's
    /// sync-admitted suffix, where the total is unknowable until the
    /// suffix commits. Every replica that can vote on the block resolves
    /// the same absence, so the claim stays agreed.
    pub substate_bytes: Option<u64>,
}

impl ShardLoad {
    /// Nothing consumed and no resolved byte total.
    ///
    /// Every structural genesis header's load: a chain starts its own gas
    /// count at zero — including a split child or a merged parent, which
    /// inherit state but not their predecessor's consumption — and a
    /// genesis block has no parent state to have a total behind.
    pub const ZERO: Self = Self {
        cumulative_gas: 0,
        substate_bytes: None,
    };

    /// This load advanced by `gas` and re-anchored on `substate_bytes`.
    ///
    /// The successor relation the proposer applies and every verifier
    /// recomputes, so neither side can drift on the arithmetic.
    #[must_use]
    pub const fn advance(self, gas: u64, substate_bytes: Option<u64>) -> Self {
        Self {
            cumulative_gas: self.cumulative_gas.saturating_add(gas),
            substate_bytes,
        }
    }

    /// Gas consumed between `self` and the later `next`.
    ///
    /// Saturating in the same direction the counter runs: a successor
    /// total below this one cannot happen on one chain, and answering
    /// zero keeps a fold that meets one from crediting a wrap.
    #[must_use]
    pub const fn gas_since(self, next: Self) -> u64 {
        next.cumulative_gas.saturating_sub(self.cumulative_gas)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn advance_accumulates_gas_and_replaces_the_byte_level() {
        let start = ShardLoad::ZERO;
        let next = start.advance(70, Some(4_096));
        assert_eq!(next.cumulative_gas, 70);
        assert_eq!(next.substate_bytes, Some(4_096));

        // Gas accumulates; the byte total is a level, so it replaces.
        let later = next.advance(30, Some(8_192));
        assert_eq!(later.cumulative_gas, 100);
        assert_eq!(later.substate_bytes, Some(8_192));

        // An unresolved byte total does not disturb the running gas.
        let unresolved = later.advance(5, None);
        assert_eq!(unresolved.cumulative_gas, 105);
        assert_eq!(unresolved.substate_bytes, None);
    }

    #[test]
    fn gas_since_differences_the_running_total() {
        let earlier = ShardLoad::ZERO.advance(400, None);
        let later = earlier.advance(90, None);
        assert_eq!(earlier.gas_since(later), 90);

        // Idempotent against the total already recorded.
        assert_eq!(later.gas_since(later), 0);

        // A total below the recorded one credits nothing rather than wrapping.
        assert_eq!(later.gas_since(earlier), 0);
    }

    #[test]
    fn saturating_accumulation_does_not_wrap() {
        let brim = ShardLoad::ZERO.advance(u64::MAX, None);
        assert_eq!(brim.advance(1_000, None).cumulative_gas, u64::MAX);
    }

    #[test]
    fn sbor_round_trip_covers_both_byte_total_arms() {
        for load in [
            ShardLoad::ZERO,
            ShardLoad::ZERO.advance(1, Some(0)),
            ShardLoad::ZERO.advance(u64::MAX, Some(u64::MAX)),
        ] {
            let bytes = basic_encode(&load).unwrap();
            assert_eq!(basic_decode::<ShardLoad>(&bytes).unwrap(), load);
        }
    }
}
