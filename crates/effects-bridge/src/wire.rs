//! The wire mirror of the effect vocabulary's [`Value`].
//!
//! The vocabulary crate is deliberately wire-free, so every encoding of it
//! is the workspace's to freeze. `Value` appears in two of them — envelope
//! tree literals and package-metadata literals — and both bind to this
//! mirror, so the vocabulary type has exactly one encoding and a new
//! variant cannot land in one format and not the other.

use hyperscale_vm_effects::{Address, LocalKey, SubstateKey, Value};
use sbor::prelude::*;

/// Wire mirror of [`Value`].
#[derive(Clone, Debug, PartialEq, Eq, BasicSbor)]
pub enum WireValue {
    U64(u64),
    U128(u128),
    Bytes(Vec<u8>),
    Address([u8; 16]),
    Key([u8; 16], [u8; 16]),
    Bucket([u8; 16]),
    Tuple(Vec<Self>),
    List(Vec<Self>),
}

pub fn wire_value(value: &Value) -> WireValue {
    match value {
        Value::U64(x) => WireValue::U64(*x),
        Value::U128(x) => WireValue::U128(*x),
        Value::Bytes(bytes) => WireValue::Bytes(bytes.clone()),
        Value::Address(address) => WireValue::Address(address.0),
        Value::Key(key) => WireValue::Key(key.owner.0, key.local.0),
        Value::Bucket { resource } => WireValue::Bucket(resource.0),
        Value::Tuple(fields) => WireValue::Tuple(fields.iter().map(wire_value).collect()),
        Value::List(items) => WireValue::List(items.iter().map(wire_value).collect()),
    }
}

pub fn value(wire: WireValue) -> Value {
    match wire {
        WireValue::U64(x) => Value::U64(x),
        WireValue::U128(x) => Value::U128(x),
        WireValue::Bytes(bytes) => Value::Bytes(bytes),
        WireValue::Address(address) => Value::Address(Address(address)),
        WireValue::Key(owner, local) => Value::Key(SubstateKey {
            owner: Address(owner),
            local: LocalKey(local),
        }),
        WireValue::Bucket(resource) => Value::Bucket {
            resource: Address(resource),
        },
        WireValue::Tuple(fields) => Value::Tuple(fields.into_iter().map(value).collect()),
        WireValue::List(items) => Value::List(items.into_iter().map(value).collect()),
    }
}
