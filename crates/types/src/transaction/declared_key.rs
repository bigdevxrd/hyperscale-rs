//! [`DeclaredKey`]: the substate-granular admission key.
//!
//! A declared key names an access target in the engine's identity space.
//! It is the mempool's conflict-key domain and is always derived locally
//! from effect metadata. Nothing key-granular travels on the wire; every
//! effect set is derived from the manifest and published metadata on each
//! node.

use hyperscale_hbor::Hbor;

use crate::{Address, CollectionId, LocalKey, SubstateKey};

/// One declared access target: an owner prefix, one substate cell — the
/// cell variant is exactly the state leaf key — or one ordered-collection
/// interval.
///
/// Two keys conflict only when equal — an owner-granular key and a cell
/// under the same owner are distinct keys, so a producer narrowing its
/// declarations must narrow them consistently.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Hbor)]
pub enum DeclaredKey {
    /// Owner-granular: every cell under the owner's prefix.
    Prefix(Address),
    /// One substate cell.
    Cell(SubstateKey),
    /// One ordered-collection interval.
    Range(DeclaredRange),
}

/// A declared collection interval.
///
/// The entries of `[lo, hi]` in the owner's collection, at most `cap`
/// of them — the same bound the range capability enforces at execution,
/// so a provision serves exactly what an executor may touch.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Hbor)]
pub struct DeclaredRange {
    /// The collection's owner; fixes the interval's shard.
    pub owner: Address,
    /// The collection under the owner.
    pub collection: CollectionId,
    /// Inclusive lower order-key bound.
    pub lo: u128,
    /// Inclusive upper order-key bound.
    pub hi: u128,
    /// The declared entry cap.
    pub cap: u32,
}

impl DeclaredKey {
    /// The substate-granular key for a leaf `[owner | local]`.
    #[must_use]
    pub const fn substate(owner: Address, local: [u8; 16]) -> Self {
        Self::Cell(SubstateKey {
            owner,
            local: LocalKey(local),
        })
    }

    /// The owner-granular key for a prefix.
    #[must_use]
    pub const fn prefix(owner: Address) -> Self {
        Self::Prefix(owner)
    }

    /// The owning address — the routing half every variant carries.
    #[must_use]
    pub const fn owner(&self) -> Address {
        match self {
            Self::Prefix(owner) => *owner,
            Self::Cell(key) => key.owner,
            Self::Range(range) => range.owner,
        }
    }

    /// The cell key, when the target is one substate cell.
    #[must_use]
    pub const fn cell(&self) -> Option<SubstateKey> {
        match self {
            Self::Prefix(_) | Self::Range(_) => None,
            Self::Cell(key) => Some(*key),
        }
    }

    /// The collection interval, when the target is one.
    #[must_use]
    pub const fn range(&self) -> Option<DeclaredRange> {
        match self {
            Self::Prefix(_) | Self::Cell(_) => None,
            Self::Range(range) => Some(*range),
        }
    }
}
