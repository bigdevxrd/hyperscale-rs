//! Substate lookup trait for resolving unchanged substate values.
//!
//! Used by [`JmtSnapshot::from_collected_writes`] to resolve `Unchanged`
//! associations: when a JMT leaf is recreated due to tree restructuring
//! (not an actual value change), the actual substate value must be looked
//! up from the database.

use hyperscale_types::SubstateKey;

use crate::SubstateDatabase;

/// Trait for looking up substate values during JMT snapshot construction.
///
/// Used to look up unchanged substate values when collecting historical
/// leaf-to-substate associations. The lookup is needed to record what
/// value a JMT leaf node points to, even when that value hasn't changed.
pub trait SubstateLookup {
    /// Look up a substate value by its key.
    fn lookup_substate(&self, key: SubstateKey) -> Option<Vec<u8>>;
}

/// Adapter to use a `&dyn SubstateDatabase` as a [`SubstateLookup`].
///
/// This is needed because Rust can't coerce `dyn SubstateDatabase` to
/// `dyn SubstateLookup` even with a blanket impl.
pub struct SubstateDbLookup<'a>(pub &'a (dyn SubstateDatabase + Sync));

impl SubstateLookup for SubstateDbLookup<'_> {
    fn lookup_substate(&self, key: SubstateKey) -> Option<Vec<u8>> {
        self.0.substate(key)
    }
}
