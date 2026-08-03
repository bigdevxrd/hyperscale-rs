//! The VM engine's event record: what a transaction said happened.
//!
//! An event names its emitting instance, the emitting package's event
//! type, and an opaque payload. The kernel stamps the emitter from the
//! invocation, so the address is a fact about which instance ran rather
//! than a claim the guest could make — and that address is what decides
//! which shard's receipt stores the event.
//!
//! The type is an index into the emitting package's event table. Packages
//! are content-addressed and immutable, so an index can only ever mean
//! one thing; resolving it is the consumer's business, and nothing on the
//! execution path reads it.

use sbor::{Categorize, Decode, DecodeError, Decoder, Encode, NoCustomValueKind, ValueKind};

use crate::Hash;
use crate::sbor_codec::decode_bounded_bytes;

/// Cap on one event payload's bytes at decode time.
///
/// Mirrors the kernel's own per-event cap, which traps rather than
/// truncating, so a payload past this bound cannot have been produced by
/// an honest execution.
pub const MAX_VM_EVENT_PAYLOAD_LEN: usize = 4 * 1024;

/// Cap on the events one transaction may carry at decode time.
///
/// Mirrors the kernel's per-transaction cap, and bounds how many a peer
/// can claim before iteration begins.
pub const MAX_VM_EVENTS_PER_TX: usize = 256;

/// Cap on the event types one package's table may name.
///
/// Mirrors the kernel's bound on an emitted index: an entry past it names
/// a type no execution could ever emit, so metadata claiming one is
/// malformed rather than merely wasteful.
pub const MAX_VM_EVENT_TYPES: u32 = 1024;

/// One event a VM transaction emitted.
#[derive(Clone, Debug, PartialEq, Eq, Categorize, Encode)]
pub struct VmEvent {
    /// The instance that emitted it, as the leaf key's owner half.
    pub emitter: [u8; 16],
    /// The index into the emitting package's event table.
    pub event_type: u32,
    /// The event's opaque payload.
    pub payload: Vec<u8>,
}

impl VmEvent {
    /// This event's leaf hash in the transaction's event root.
    #[must_use]
    pub fn hash(&self) -> Hash {
        Hash::from_parts(&[&self.emitter, &self.event_type.to_le_bytes(), &self.payload])
    }
}

impl<D: Decoder<NoCustomValueKind>> Decode<NoCustomValueKind, D> for VmEvent {
    fn decode_body_with_value_kind(
        decoder: &mut D,
        value_kind: ValueKind<NoCustomValueKind>,
    ) -> Result<Self, DecodeError> {
        decoder.check_preloaded_value_kind(value_kind, ValueKind::Tuple)?;
        decoder.read_and_check_size(3)?;
        let emitter = decoder.decode::<[u8; 16]>()?;
        let event_type = decoder.decode::<u32>()?;
        let payload = decode_bounded_bytes(decoder, MAX_VM_EVENT_PAYLOAD_LEN)?;
        Ok(Self {
            emitter,
            event_type,
            payload,
        })
    }
}
