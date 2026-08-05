//! [`DeclaredKey`]: the substate-granular admission key.
//!
//! A declared key names an access target in the engine's identity space.
//! It is the mempool's conflict-key domain and is always derived locally
//! from effect metadata. Nothing key-granular travels on the wire; every
//! effect set is derived from the manifest and published metadata on each
//! node.

use sbor::prelude::*;

/// One declared access target: an owner prefix, optionally narrowed to
/// one substate's local half — together exactly the state leaf key.
///
/// Two keys conflict only when equal — an owner-granular key
/// (`local: None`) and a slot under the same owner are distinct keys, so
/// a producer narrowing its declarations must narrow them consistently.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, BasicSbor)]
pub struct DeclaredKey {
    /// The owning address: the leaf key's owner half.
    pub owner: [u8; 16],
    /// The substate's local half, when declared finer than
    /// owner-granular.
    pub local: Option<[u8; 16]>,
}

impl DeclaredKey {
    /// The substate-granular key for a leaf `[owner | local]`.
    #[must_use]
    pub const fn substate(owner: [u8; 16], local: [u8; 16]) -> Self {
        Self {
            owner,
            local: Some(local),
        }
    }

    /// The owner-granular key for a prefix.
    #[must_use]
    pub const fn prefix(owner: [u8; 16]) -> Self {
        Self { owner, local: None }
    }
}
