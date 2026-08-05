//! Length-capped collection wrappers for wire types.
//!
//! Each `Bounded*` wrapper encodes byte-identically to its inner collection
//! but rejects peer-claimed lengths above `MAX` on decode, before the
//! elements are read. The cap lives in the type, so readers see the bound at
//! the field declaration without scrolling into a manual decode impl.
//!
//! `HashMap`/`HashSet` have no codec impls at all — their iteration order is
//! undefined, so a wire field simply cannot name them.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt::{self, Display, Formatter};
use std::ops::Deref;

/// Returned by the `try_from_*` constructors on `Bounded*` types when an
/// input exceeds the type's `MAX`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BoundedLengthError {
    /// The compile-time maximum.
    pub max: usize,
    /// The actual length of the rejected input.
    pub actual: usize,
}

impl Display for BoundedLengthError {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "bounded value overflow: max {}, got {}",
            self.max, self.actual
        )
    }
}

impl std::error::Error for BoundedLengthError {}

// ============================================================================
// Bounded newtype wrappers
// ============================================================================
//
// All wrappers `Deref` to the inner collection so call-site reads
// (`bytes.len()`, `vec.iter()`, etc.) work unchanged. Wrappers do *not*
// implement `DerefMut` — bound-violating mutations should require
// reaching into the public tuple field on purpose, and the encode-time
// check catches the bypass either way.
//
// Bound enforcement is layered: `From<Inner>` panics on overflow,
// inherent `try_from_*` methods return `BoundedLengthError`, and encode
// fails with `EncodeError::BoundExceeded` if the value somehow grew past
// `MAX` between construction and the wire (e.g. via direct `.0` access).
// Decode rejects oversized peer payloads before reading the elements.

/// `Vec<u8>` with a compile-time max-length cap on decode.
#[derive(Debug, Clone, Default, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct BoundedBytes<const MAX: usize>(pub Vec<u8>);

impl<const MAX: usize> BoundedBytes<MAX> {
    /// Construct an empty `BoundedBytes`.
    #[must_use]
    pub const fn new() -> Self {
        Self(Vec::new())
    }

    /// Consume the wrapper and return the inner `Vec<u8>`.
    #[must_use]
    pub fn into_inner(self) -> Vec<u8> {
        self.0
    }

    /// Fallible counterpart of `From<Vec<u8>>` — returns `Err` instead of
    /// panicking when `value.len() > MAX`.
    ///
    /// # Errors
    ///
    /// Returns [`BoundedLengthError`] when the input exceeds `MAX`.
    pub fn try_from_vec(value: Vec<u8>) -> Result<Self, BoundedLengthError> {
        if value.len() > MAX {
            return Err(BoundedLengthError {
                max: MAX,
                actual: value.len(),
            });
        }
        Ok(Self(value))
    }
}

impl<const MAX: usize> From<Vec<u8>> for BoundedBytes<MAX> {
    /// Panics if `value.len() > MAX`. Use [`Self::try_from_vec`] for
    /// fallible construction from untrusted input.
    fn from(value: Vec<u8>) -> Self {
        assert!(
            value.len() <= MAX,
            "BoundedBytes<{MAX}> overflow: got {} bytes",
            value.len()
        );
        Self(value)
    }
}

impl<const MAX: usize> Deref for BoundedBytes<MAX> {
    type Target = Vec<u8>;
    fn deref(&self) -> &Vec<u8> {
        &self.0
    }
}

/// `String` with a compile-time max-length cap on decode (in bytes).
#[derive(Debug, Clone, Default, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct BoundedString<const MAX: usize>(pub String);

impl<const MAX: usize> BoundedString<MAX> {
    /// Construct an empty `BoundedString`.
    #[must_use]
    pub const fn new() -> Self {
        Self(String::new())
    }

    /// Consume the wrapper and return the inner `String`.
    #[must_use]
    pub fn into_inner(self) -> String {
        self.0
    }

    /// Fallible counterpart of `From<String>` — returns `Err` when the
    /// input exceeds `MAX` bytes.
    ///
    /// # Errors
    ///
    /// Returns [`BoundedLengthError`] when `value.len() > MAX`.
    pub fn try_from_string(value: String) -> Result<Self, BoundedLengthError> {
        if value.len() > MAX {
            return Err(BoundedLengthError {
                max: MAX,
                actual: value.len(),
            });
        }
        Ok(Self(value))
    }
}

impl<const MAX: usize> From<String> for BoundedString<MAX> {
    /// Panics if `value.len() > MAX`. Use [`Self::try_from_string`] for
    /// fallible construction from untrusted input.
    fn from(value: String) -> Self {
        assert!(
            value.len() <= MAX,
            "BoundedString<{MAX}> overflow: got {} bytes",
            value.len()
        );
        Self(value)
    }
}

impl<const MAX: usize> Deref for BoundedString<MAX> {
    type Target = String;
    fn deref(&self) -> &String {
        &self.0
    }
}

/// `Vec<T>` with a compile-time max-length cap on decode.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct BoundedVec<T, const MAX: usize>(pub Vec<T>);

// Manual `Default` so the impl doesn't pick up a spurious `T: Default`
// bound from the derive — an empty `Vec<T>` is constructible regardless
// of `T`, and downstream wire types whose element type isn't `Default`
// (e.g. `BoundedVec<TxHash, _>`) need this to derive `Default` themselves.
impl<T, const MAX: usize> Default for BoundedVec<T, MAX> {
    fn default() -> Self {
        Self::new()
    }
}

impl<T, const MAX: usize> BoundedVec<T, MAX> {
    /// Construct an empty `BoundedVec`.
    #[must_use]
    pub const fn new() -> Self {
        Self(Vec::new())
    }

    /// Number of elements held. Mirrors [`Vec::len`] but is callable from
    /// `const fn` (the [`Deref`]-routed `.len()` is not).
    #[must_use]
    pub const fn len(&self) -> usize {
        self.0.len()
    }

    /// Whether the wrapper is empty. `const`-callable counterpart of
    /// `Vec::is_empty` reachable via `Deref`.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Consume the wrapper and return the inner `Vec<T>`.
    #[must_use]
    pub fn into_inner(self) -> Vec<T> {
        self.0
    }

    /// Fallible counterpart of `From<Vec<T>>` — returns `Err` when the
    /// input exceeds `MAX` elements.
    ///
    /// # Errors
    ///
    /// Returns [`BoundedLengthError`] when `value.len() > MAX`.
    pub fn try_from_vec(value: Vec<T>) -> Result<Self, BoundedLengthError> {
        if value.len() > MAX {
            return Err(BoundedLengthError {
                max: MAX,
                actual: value.len(),
            });
        }
        Ok(Self(value))
    }

    /// Append an element to the back of the inner `Vec`.
    ///
    /// # Panics
    ///
    /// Panics if pushing would exceed `MAX`. Use [`Self::try_push`] for
    /// fallible append.
    pub fn push(&mut self, value: T) {
        assert!(
            self.0.len() < MAX,
            "BoundedVec<_, {MAX}> overflow on push: already at {} elements",
            self.0.len()
        );
        self.0.push(value);
    }

    /// Fallible counterpart of [`Self::push`] — returns the rejected
    /// element back to the caller when the wrapper is at capacity.
    ///
    /// # Errors
    ///
    /// Returns the input `value` unchanged when `self.len() == MAX`.
    pub fn try_push(&mut self, value: T) -> Result<(), T> {
        if self.0.len() >= MAX {
            return Err(value);
        }
        self.0.push(value);
        Ok(())
    }
}

impl<T, const MAX: usize> From<Vec<T>> for BoundedVec<T, MAX> {
    /// Panics if `value.len() > MAX`. Use [`Self::try_from_vec`] for
    /// fallible construction from untrusted input.
    fn from(value: Vec<T>) -> Self {
        assert!(
            value.len() <= MAX,
            "BoundedVec<_, {MAX}> overflow: got {} elements",
            value.len()
        );
        Self(value)
    }
}

impl<T, const MAX: usize> Deref for BoundedVec<T, MAX> {
    type Target = Vec<T>;
    fn deref(&self) -> &Vec<T> {
        &self.0
    }
}

/// `BTreeSet<T>` with a compile-time max-length cap on decode.
#[derive(Debug, Clone, Default, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct BoundedBTreeSet<T, const MAX: usize>(pub BTreeSet<T>);

impl<T: Ord, const MAX: usize> BoundedBTreeSet<T, MAX> {
    /// Construct an empty `BoundedBTreeSet`.
    #[must_use]
    pub const fn new() -> Self {
        Self(BTreeSet::new())
    }

    /// Consume the wrapper and return the inner `BTreeSet<T>`.
    #[must_use]
    pub fn into_inner(self) -> BTreeSet<T> {
        self.0
    }

    /// Fallible counterpart of `From<BTreeSet<T>>` — returns `Err` when
    /// the input exceeds `MAX` elements.
    ///
    /// # Errors
    ///
    /// Returns [`BoundedLengthError`] when `value.len() > MAX`.
    pub fn try_from_btree_set(value: BTreeSet<T>) -> Result<Self, BoundedLengthError> {
        if value.len() > MAX {
            return Err(BoundedLengthError {
                max: MAX,
                actual: value.len(),
            });
        }
        Ok(Self(value))
    }
}

impl<T: Ord, const MAX: usize> From<BTreeSet<T>> for BoundedBTreeSet<T, MAX> {
    /// Panics if `value.len() > MAX`. Use [`Self::try_from_btree_set`] for
    /// fallible construction from untrusted input.
    fn from(value: BTreeSet<T>) -> Self {
        assert!(
            value.len() <= MAX,
            "BoundedBTreeSet<_, {MAX}> overflow: got {} elements",
            value.len()
        );
        Self(value)
    }
}

impl<T, const MAX: usize> Deref for BoundedBTreeSet<T, MAX> {
    type Target = BTreeSet<T>;
    fn deref(&self) -> &BTreeSet<T> {
        &self.0
    }
}

/// `BTreeMap<K, V>` with a compile-time max-entry-count cap on decode.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct BoundedBTreeMap<K, V, const MAX: usize>(pub BTreeMap<K, V>);

// Manual `Default` so the impl doesn't pick up spurious `K: Default + Ord`
// or `V: Default` bounds from the derive — an empty `BTreeMap` is
// constructible regardless. Mirrors `BoundedVec`'s rationale.
impl<K, V, const MAX: usize> Default for BoundedBTreeMap<K, V, MAX> {
    fn default() -> Self {
        Self(BTreeMap::new())
    }
}

impl<K: Ord, V, const MAX: usize> BoundedBTreeMap<K, V, MAX> {
    /// Construct an empty `BoundedBTreeMap`.
    #[must_use]
    pub const fn new() -> Self {
        Self(BTreeMap::new())
    }

    /// Consume the wrapper and return the inner `BTreeMap<K, V>`.
    #[must_use]
    pub fn into_inner(self) -> BTreeMap<K, V> {
        self.0
    }

    /// Fallible counterpart of `From<BTreeMap<K, V>>` — returns `Err`
    /// when the input exceeds `MAX` entries.
    ///
    /// # Errors
    ///
    /// Returns [`BoundedLengthError`] when `value.len() > MAX`.
    pub fn try_from_btree_map(value: BTreeMap<K, V>) -> Result<Self, BoundedLengthError> {
        if value.len() > MAX {
            return Err(BoundedLengthError {
                max: MAX,
                actual: value.len(),
            });
        }
        Ok(Self(value))
    }
}

impl<K: Ord, V, const MAX: usize> From<BTreeMap<K, V>> for BoundedBTreeMap<K, V, MAX> {
    /// Panics if `value.len() > MAX`. Use [`Self::try_from_btree_map`] for
    /// fallible construction from untrusted input.
    fn from(value: BTreeMap<K, V>) -> Self {
        assert!(
            value.len() <= MAX,
            "BoundedBTreeMap<_, _, {MAX}> overflow: got {} entries",
            value.len()
        );
        Self(value)
    }
}

impl<K, V, const MAX: usize> Deref for BoundedBTreeMap<K, V, MAX> {
    type Target = BTreeMap<K, V>;
    fn deref(&self) -> &BTreeMap<K, V> {
        &self.0
    }
}

// ── Codec impls ──
//
// Each wrapper encodes byte-identically to its inner collection and rejects
// a peer-claimed length past `MAX` before allocation, through
// `hyperscale_hbor::bounded`. A plain collection field with `#[hbor(max)]`
// expresses the same bound without a wrapper type; these exist for the
// field sites that still name them.

use hyperscale_hbor::error::{DecodeError as HborDecodeError, EncodeError as HborEncodeError};
use hyperscale_hbor::{
    Decoder as HborDecoder, Encoder as HborEncoder, HborDecode, HborEncode, HborWidth,
    bounded as hbor_bounded,
};

impl<const MAX: usize> HborWidth for BoundedBytes<MAX> {
    const MIN_ENCODED_LEN: usize = 1;
}

impl<const MAX: usize> HborEncode for BoundedBytes<MAX> {
    fn encode(&self, encoder: &mut HborEncoder<'_>) -> Result<(), HborEncodeError> {
        hbor_bounded::check_encoded_len("BoundedBytes", self.0.len(), MAX)?;
        encoder.descend(|encoder| hbor_bounded::encode_bytes(encoder, &self.0))
    }
}

impl<const MAX: usize> HborDecode for BoundedBytes<MAX> {
    fn decode(decoder: &mut HborDecoder<'_>) -> Result<Self, HborDecodeError> {
        Ok(Self(decoder.descend(|decoder| {
            hbor_bounded::decode_bounded_bytes(decoder, MAX)
        })?))
    }
}

impl<const MAX: usize> HborWidth for BoundedString<MAX> {
    const MIN_ENCODED_LEN: usize = 1;
}

impl<const MAX: usize> HborEncode for BoundedString<MAX> {
    fn encode(&self, encoder: &mut HborEncoder<'_>) -> Result<(), HborEncodeError> {
        hbor_bounded::check_encoded_len("BoundedString", self.0.len(), MAX)?;
        encoder.nested(&self.0)
    }
}

impl<const MAX: usize> HborDecode for BoundedString<MAX> {
    fn decode(decoder: &mut HborDecoder<'_>) -> Result<Self, HborDecodeError> {
        Ok(Self(decoder.descend(|decoder| {
            hbor_bounded::decode_bounded_string(decoder, MAX)
        })?))
    }
}

impl<T, const MAX: usize> HborWidth for BoundedVec<T, MAX> {
    const MIN_ENCODED_LEN: usize = 1;
}

impl<T: HborEncode, const MAX: usize> HborEncode for BoundedVec<T, MAX> {
    fn encode(&self, encoder: &mut HborEncoder<'_>) -> Result<(), HborEncodeError> {
        hbor_bounded::check_encoded_len("BoundedVec", self.0.len(), MAX)?;
        encoder.nested(&self.0)
    }
}

impl<T: HborDecode, const MAX: usize> HborDecode for BoundedVec<T, MAX> {
    fn decode(decoder: &mut HborDecoder<'_>) -> Result<Self, HborDecodeError> {
        Ok(Self(decoder.descend(|decoder| {
            hbor_bounded::decode_bounded_vec(decoder, MAX)
        })?))
    }
}

impl<T, const MAX: usize> HborWidth for BoundedBTreeSet<T, MAX> {
    const MIN_ENCODED_LEN: usize = 1;
}

impl<T: HborEncode, const MAX: usize> HborEncode for BoundedBTreeSet<T, MAX> {
    fn encode(&self, encoder: &mut HborEncoder<'_>) -> Result<(), HborEncodeError> {
        hbor_bounded::check_encoded_len("BoundedBTreeSet", self.0.len(), MAX)?;
        encoder.nested(&self.0)
    }
}

impl<T: HborDecode + Ord, const MAX: usize> HborDecode for BoundedBTreeSet<T, MAX> {
    fn decode(decoder: &mut HborDecoder<'_>) -> Result<Self, HborDecodeError> {
        Ok(Self(decoder.descend(|decoder| {
            hbor_bounded::decode_bounded_btree_set(decoder, MAX)
        })?))
    }
}

impl<K, V, const MAX: usize> HborWidth for BoundedBTreeMap<K, V, MAX> {
    const MIN_ENCODED_LEN: usize = 1;
}

impl<K: HborEncode, V: HborEncode, const MAX: usize> HborEncode for BoundedBTreeMap<K, V, MAX> {
    fn encode(&self, encoder: &mut HborEncoder<'_>) -> Result<(), HborEncodeError> {
        hbor_bounded::check_encoded_len("BoundedBTreeMap", self.0.len(), MAX)?;
        encoder.nested(&self.0)
    }
}

impl<K: HborDecode + Ord, V: HborDecode, const MAX: usize> HborDecode
    for BoundedBTreeMap<K, V, MAX>
{
    fn decode(decoder: &mut HborDecoder<'_>) -> Result<Self, HborDecodeError> {
        Ok(Self(decoder.descend(|decoder| {
            hbor_bounded::decode_bounded_btree_map(decoder, MAX)
        })?))
    }
}

#[cfg(test)]
mod tests {
    use hyperscale_hbor::{
        DecodeError, EncodeError, from_slice as hbor_from_slice, to_vec as hbor_to_vec,
    };

    use super::*;

    #[test]
    fn bounded_bytes_roundtrip_and_reject_oversize() {
        let inner = vec![1u8, 2, 3, 4];
        let value = BoundedBytes::<8>(inner.clone());
        let bytes = hbor_to_vec(&value).unwrap();
        let decoded: BoundedBytes<8> = hbor_from_slice(&bytes).unwrap();
        assert_eq!(decoded.0, inner);

        // Same wire bytes refused by a tighter bound.
        let err = hbor_from_slice::<BoundedBytes<2>>(&bytes).unwrap_err();
        assert!(matches!(
            err,
            DecodeError::BoundExceeded { max: 2, actual: 4 }
        ));
    }

    #[test]
    fn bounded_string_roundtrip_and_reject_oversize() {
        let inner = "hello".to_string();
        let value = BoundedString::<8>(inner.clone());
        let bytes = hbor_to_vec(&value).unwrap();
        let decoded: BoundedString<8> = hbor_from_slice(&bytes).unwrap();
        assert_eq!(decoded.0, inner);

        let err = hbor_from_slice::<BoundedString<2>>(&bytes).unwrap_err();
        assert!(matches!(
            err,
            DecodeError::BoundExceeded { max: 2, actual: 5 }
        ));
    }

    #[test]
    fn bounded_vec_roundtrip_and_reject_oversize() {
        let inner = vec![10u32, 20, 30];
        let value = BoundedVec::<u32, 8>(inner.clone());
        let bytes = hbor_to_vec(&value).unwrap();
        let decoded: BoundedVec<u32, 8> = hbor_from_slice(&bytes).unwrap();
        assert_eq!(decoded.0, inner);

        let err = hbor_from_slice::<BoundedVec<u32, 2>>(&bytes).unwrap_err();
        assert!(matches!(
            err,
            DecodeError::BoundExceeded { max: 2, actual: 3 }
        ));
    }

    #[test]
    fn bounded_btree_set_roundtrip_and_reject_oversize() {
        let inner: BTreeSet<u16> = [1u16, 2, 3].into_iter().collect();
        let value = BoundedBTreeSet::<u16, 8>(inner.clone());
        let bytes = hbor_to_vec(&value).unwrap();
        let decoded: BoundedBTreeSet<u16, 8> = hbor_from_slice(&bytes).unwrap();
        assert_eq!(decoded.0, inner);

        let err = hbor_from_slice::<BoundedBTreeSet<u16, 2>>(&bytes).unwrap_err();
        assert!(matches!(
            err,
            DecodeError::BoundExceeded { max: 2, actual: 3 }
        ));
    }

    #[test]
    fn bounded_btree_map_roundtrip_and_reject_oversize() {
        let inner: BTreeMap<u16, u32> = [(1u16, 10u32), (2, 20), (3, 30)].into_iter().collect();
        let value = BoundedBTreeMap::<u16, u32, 8>(inner.clone());
        let bytes = hbor_to_vec(&value).unwrap();
        let decoded: BoundedBTreeMap<u16, u32, 8> = hbor_from_slice(&bytes).unwrap();
        assert_eq!(decoded.0, inner);

        // Same wire bytes refused by a tighter bound.
        let err = hbor_from_slice::<BoundedBTreeMap<u16, u32, 2>>(&bytes).unwrap_err();
        assert!(matches!(
            err,
            DecodeError::BoundExceeded { max: 2, actual: 3 }
        ));
    }

    /// Confirms wire-identity with the unwrapped `BTreeMap` — wrapping a
    /// field can't shift any merkle root.
    #[test]
    fn bounded_btree_map_wire_matches_btree_map() {
        let inner: BTreeMap<u16, u32> = [(1u16, 10u32), (2, 20)].into_iter().collect();
        let bounded = BoundedBTreeMap::<u16, u32, 32>(inner.clone());
        assert_eq!(hbor_to_vec(&bounded).unwrap(), hbor_to_vec(&inner).unwrap());
    }

    #[test]
    #[should_panic(expected = "BoundedBTreeMap<_, _, 2> overflow")]
    fn bounded_btree_map_from_panics_on_overflow() {
        let huge: BTreeMap<u16, u8> = (0..3u16).map(|i| (i, 0u8)).collect();
        let _ = BoundedBTreeMap::<u16, u8, 2>::from(huge);
    }

    #[test]
    fn bounded_btree_map_try_from_returns_err_on_overflow() {
        let huge: BTreeMap<u16, u8> = (0..5u16).map(|i| (i, 0u8)).collect();
        let err = BoundedBTreeMap::<u16, u8, 2>::try_from_btree_map(huge).unwrap_err();
        assert_eq!(err, BoundedLengthError { max: 2, actual: 5 });
    }

    #[test]
    fn bounded_btree_map_encode_rejects_oversize_when_field_bypassed() {
        let huge: BTreeMap<u16, u8> = (0..5u16).map(|i| (i, 0u8)).collect();
        let smuggled = BoundedBTreeMap::<u16, u8, 2>(huge);
        let err = hbor_to_vec(&smuggled).unwrap_err();
        assert!(matches!(
            err,
            EncodeError::BoundExceeded {
                actual: 5,
                max: 2,
                ..
            }
        ));
    }

    /// Confirms that wire bytes from a bounded wrapper are byte-identical
    /// to the equivalent unwrapped collection — wrapping a field can't
    /// change any merkle root.
    #[test]
    fn bounded_bytes_wire_matches_vec_u8() {
        let raw = vec![7u8; 16];
        let bounded = BoundedBytes::<32>(raw.clone());
        assert_eq!(hbor_to_vec(&bounded).unwrap(), hbor_to_vec(&raw).unwrap());
    }

    #[test]
    #[should_panic(expected = "BoundedBytes<2> overflow")]
    fn bounded_bytes_from_panics_on_overflow() {
        let _ = BoundedBytes::<2>::from(vec![0u8; 3]);
    }

    #[test]
    fn bounded_bytes_try_from_vec_returns_err_on_overflow() {
        let err = BoundedBytes::<2>::try_from_vec(vec![0u8; 5]).unwrap_err();
        assert_eq!(err, BoundedLengthError { max: 2, actual: 5 });
    }

    /// Bypasses construction by reaching into the public tuple field, then
    /// asserts that `Encode` still refuses to ship oversized bytes.
    #[test]
    fn bounded_bytes_encode_rejects_oversize_when_field_bypassed() {
        let smuggled = BoundedBytes::<2>(vec![0u8; 5]);
        let err = hbor_to_vec(&smuggled).unwrap_err();
        assert!(matches!(
            err,
            EncodeError::BoundExceeded {
                actual: 5,
                max: 2,
                ..
            }
        ));
    }

    #[test]
    #[should_panic(expected = "BoundedString<2> overflow")]
    fn bounded_string_from_panics_on_overflow() {
        let _ = BoundedString::<2>::from("abc".to_string());
    }

    #[test]
    fn bounded_string_try_from_string_returns_err_on_overflow() {
        let err = BoundedString::<2>::try_from_string("abcd".to_string()).unwrap_err();
        assert_eq!(err, BoundedLengthError { max: 2, actual: 4 });
    }

    #[test]
    fn bounded_string_encode_rejects_oversize_when_field_bypassed() {
        let smuggled = BoundedString::<2>("abcd".to_string());
        let err = hbor_to_vec(&smuggled).unwrap_err();
        assert!(matches!(
            err,
            EncodeError::BoundExceeded {
                actual: 4,
                max: 2,
                ..
            }
        ));
    }

    #[test]
    #[should_panic(expected = "BoundedVec<_, 2> overflow")]
    fn bounded_vec_from_panics_on_overflow() {
        let _ = BoundedVec::<u32, 2>::from(vec![1u32, 2, 3]);
    }

    #[test]
    fn bounded_vec_try_from_vec_returns_err_on_overflow() {
        let err = BoundedVec::<u32, 2>::try_from_vec(vec![1u32, 2, 3, 4]).unwrap_err();
        assert_eq!(err, BoundedLengthError { max: 2, actual: 4 });
    }

    #[test]
    fn bounded_vec_encode_rejects_oversize_when_field_bypassed() {
        let smuggled = BoundedVec::<u32, 2>(vec![1u32, 2, 3, 4]);
        let err = hbor_to_vec(&smuggled).unwrap_err();
        assert!(matches!(
            err,
            EncodeError::BoundExceeded {
                actual: 4,
                max: 2,
                ..
            }
        ));
    }

    #[test]
    #[should_panic(expected = "BoundedBTreeSet<_, 2> overflow")]
    fn bounded_btree_set_from_panics_on_overflow() {
        let huge: BTreeSet<u16> = (0..3).collect();
        let _ = BoundedBTreeSet::<u16, 2>::from(huge);
    }

    #[test]
    fn bounded_btree_set_try_from_btree_set_returns_err_on_overflow() {
        let huge: BTreeSet<u16> = (0..5).collect();
        let err = BoundedBTreeSet::<u16, 2>::try_from_btree_set(huge).unwrap_err();
        assert_eq!(err, BoundedLengthError { max: 2, actual: 5 });
    }

    #[test]
    fn bounded_btree_set_encode_rejects_oversize_when_field_bypassed() {
        let huge: BTreeSet<u16> = (0..5).collect();
        let smuggled = BoundedBTreeSet::<u16, 2>(huge);
        let err = hbor_to_vec(&smuggled).unwrap_err();
        assert!(matches!(
            err,
            EncodeError::BoundExceeded {
                actual: 5,
                max: 2,
                ..
            }
        ));
    }
}
