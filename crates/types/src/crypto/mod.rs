//! Cryptographic types and helpers for the transaction path.
//!
//! [`ed25519`] is the signature scheme itself; [`keys`] is keypair
//! generation over it.

pub mod ed25519;
pub mod keys;

pub use ed25519::{Ed25519PrivateKey, Ed25519PublicKey, Ed25519Signature, verify_ed25519};
