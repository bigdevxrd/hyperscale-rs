//! Genesis bootstrap configuration.
//!
//! [`GenesisConfig`] is the canonical input to genesis: the accounts a
//! deployment funds and the stake pools its beacon folds facts for.
//! Everything genesis writes derives from it, so two nodes with the same
//! config install byte-identical state.

use hyperscale_types::StakePoolSeat;

/// Configuration for genesis bootstrapping.
#[derive(Debug, Clone, Default)]
pub struct GenesisConfig {
    /// Funded accounts: owner prefix and initial balance. Seeded as
    /// identity-keyed vault cells and registered as account-package
    /// instances in the process's VM statics; the raw prefix keeps this
    /// crate free of the VM vocabulary.
    pub accounts: Vec<([u8; 16], u128)>,

    /// Stake pools the beacon folds facts for: the pool instance's owner
    /// prefix and the identifier it is folded under. Seated as stake pool
    /// package instances in the process's VM statics, which is what makes
    /// their emitted events beacon facts — running the package never
    /// does, because anyone may run the package.
    pub pools: Vec<StakePoolSeat>,
}
