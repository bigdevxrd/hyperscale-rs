//! [`DeclaredKey`]: the substate-granular admission key.
//!
//! A declared key names an access target in one of the two engines'
//! identity spaces. It is the mempool's conflict-key domain and is always
//! derived locally — from the node-granular analysis for Radix
//! transactions, from effect metadata for VM transactions. Nothing
//! key-granular travels on the wire; the end state derives every effect
//! set from the manifest and published metadata on each node.

use sbor::prelude::*;

use crate::NodeId;

/// One declared access target.
///
/// Two keys conflict only when equal — a node-granular key
/// (`local: None`) and a slot under the same node are distinct keys, so a
/// producer narrowing its declarations must narrow them consistently. The
/// two variants are distinct key spaces by construction: a Radix node and
/// a VM owner prefix never collide, mirroring the two engines' disjoint
/// state placement.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, BasicSbor)]
pub enum DeclaredKey {
    /// A Radix node, optionally narrowed to a single 16-byte local slot
    /// under it.
    Node {
        /// The declared node.
        node: NodeId,
        /// The slot within the node, when declared finer than
        /// node-granular.
        local: Option<[u8; 16]>,
    },
    /// A VM owner prefix, optionally narrowed to one substate's local
    /// half — together exactly the state leaf key.
    Prefix {
        /// The owning address: the leaf key's owner half.
        owner: [u8; 16],
        /// The substate's local half, when declared finer than
        /// owner-granular.
        local: Option<[u8; 16]>,
    },
}

impl DeclaredKey {
    /// The node-granular key for `node`.
    #[must_use]
    pub const fn node(node: NodeId) -> Self {
        Self::Node { node, local: None }
    }

    /// The substate-granular key for a VM leaf `[owner | local]`.
    #[must_use]
    pub const fn substate(owner: [u8; 16], local: [u8; 16]) -> Self {
        Self::Prefix {
            owner,
            local: Some(local),
        }
    }

    /// The owner-granular key for a VM prefix.
    #[must_use]
    pub const fn prefix(owner: [u8; 16]) -> Self {
        Self::Prefix { owner, local: None }
    }
}
