//! [`DeclaredKey`]: the substate-granular admission key.
//!
//! A declared key names either a whole node (`local: None`) or one
//! substate slot within it. It is the mempool's conflict-key domain and
//! is always derived locally — from the node-granular analysis today,
//! from effect metadata once deployed packages carry it. Nothing
//! key-granular travels on the wire; the end state derives every effect
//! set from the manifest and published metadata on each node.

use sbor::prelude::*;

use crate::NodeId;

/// One declared access target: a node, optionally narrowed to a single
/// 16-byte local slot under it.
///
/// Two keys conflict only when equal — a node-granular key
/// (`local: None`) and a slot under the same node are distinct keys, so a
/// producer narrowing its declarations must narrow them consistently.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, BasicSbor)]
pub struct DeclaredKey {
    /// The declared node.
    pub node: NodeId,
    /// The slot within the node, when declared finer than node-granular.
    pub local: Option<[u8; 16]>,
}

impl DeclaredKey {
    /// The node-granular key for `node`.
    #[must_use]
    pub const fn node(node: NodeId) -> Self {
        Self { node, local: None }
    }
}
