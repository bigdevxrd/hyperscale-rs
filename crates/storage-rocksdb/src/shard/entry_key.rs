//! Key encodings for the ordered-collection entry index.
//!
//! The `entries` column family keys on the entry's identity — owner
//! address, collection, then the order key big-endian — so one
//! collection's entries are contiguous and iterate in ascending order.
//! The history companion appends a big-endian version suffix, enabling
//! the same forward seek historical cell reads use.

use hyperscale_types::{Address, CollectionId, EntryKey};
use rocksdb::{DB, DBRawIteratorWithThreadMode};

use crate::typed_cf::{DbCodec, DbEncode};

/// The encoded width of an entry's identity: owner, collection, order.
pub const ENTRY_KEY_LEN: usize = 32 + 16 + 16;

const VERSION_LEN: usize = 8;

/// Codec for entry-index keys: `owner ++ collection ++ order_BE_16B`.
#[derive(Default)]
pub struct EntryKeyCodec;

impl EntryKeyCodec {
    fn decode_parts(bytes: &[u8]) -> EntryKey {
        let owner: [u8; 32] = bytes[..32].try_into().expect("owner half");
        let collection: [u8; 16] = bytes[32..48].try_into().expect("collection half");
        let order = u128::from_be_bytes(bytes[48..64].try_into().expect("order half"));
        EntryKey {
            owner: Address::from_bytes(owner).expect("a stored entry key names an address"),
            collection: CollectionId(collection),
            order,
        }
    }
}

impl DbEncode<EntryKey> for EntryKeyCodec {
    fn encode_to(&self, value: &EntryKey, buf: &mut Vec<u8>) {
        buf.extend_from_slice(&value.owner.to_bytes());
        buf.extend_from_slice(&value.collection.0);
        buf.extend_from_slice(&value.order.to_be_bytes());
    }
}

impl DbCodec<EntryKey> for EntryKeyCodec {
    fn decode(&self, bytes: &[u8]) -> EntryKey {
        assert_eq!(bytes.len(), ENTRY_KEY_LEN, "an entry key is 64 bytes");
        Self::decode_parts(bytes)
    }
}

/// Codec for versioned entry-index keys: the entry key followed by
/// `write_version_BE_8B`, so versions sort ascending within one entry.
#[derive(Default)]
pub struct VersionedEntryKeyCodec;

impl DbEncode<(EntryKey, u64)> for VersionedEntryKeyCodec {
    fn encode_to(&self, value: &(EntryKey, u64), buf: &mut Vec<u8>) {
        let (key, version) = value;
        EntryKeyCodec.encode_to(key, buf);
        buf.extend_from_slice(&version.to_be_bytes());
    }
}

impl DbCodec<(EntryKey, u64)> for VersionedEntryKeyCodec {
    fn decode(&self, bytes: &[u8]) -> (EntryKey, u64) {
        assert_eq!(
            bytes.len(),
            ENTRY_KEY_LEN + VERSION_LEN,
            "a versioned entry key is 72 bytes"
        );
        let key = EntryKeyCodec::decode_parts(&bytes[..ENTRY_KEY_LEN]);
        let version = u64::from_be_bytes(bytes[ENTRY_KEY_LEN..].try_into().expect("version half"));
        (key, version)
    }
}

/// The encoded interval covering `[lo, hi]` of one collection: the
/// half-open raw-key range every entry (and, with the version suffix,
/// every versioned row) of the interval falls in.
#[must_use]
pub fn entry_range_bounds(
    owner: Address,
    collection: CollectionId,
    lo: u128,
    hi: u128,
) -> (Vec<u8>, Vec<u8>) {
    let mut start = Vec::with_capacity(ENTRY_KEY_LEN);
    EntryKeyCodec.encode_to(
        &EntryKey {
            owner,
            collection,
            order: lo,
        },
        &mut start,
    );
    // One past the last versioned row of `hi`: the order suffix is
    // followed by version bytes, so "hi's prefix then 0xFF padding"
    // bounds both the plain and the versioned encodings.
    let mut end = Vec::with_capacity(ENTRY_KEY_LEN + VERSION_LEN);
    EntryKeyCodec.encode_to(
        &EntryKey {
            owner,
            collection,
            order: hi,
        },
        &mut end,
    );
    end.extend_from_slice(&[0xFF; VERSION_LEN]);
    end.push(0xFF);
    (start, end)
}

/// Walk `iter` over `[lo, hi]` of one collection, ascending by order
/// key, yielding at most `limit` rows — `None` walks the whole interval,
/// the base a historical read's overlay corrects afterwards.
///
/// The one decoder of the entries CF's iteration order: every
/// tip-shaped range read goes through here, so the seek-start,
/// bound-end, and limit rules cannot drift between readers.
pub fn scan_entries(
    mut iter: DBRawIteratorWithThreadMode<'_, DB>,
    owner: Address,
    collection: CollectionId,
    lo: u128,
    hi: u128,
    limit: Option<usize>,
) -> Vec<(u128, Vec<u8>)> {
    let (start, end) = entry_range_bounds(owner, collection, lo, hi);
    let mut hits = Vec::new();
    iter.seek(&start);
    while iter.valid() && limit.is_none_or(|cap| hits.len() < cap) {
        let Some(raw_key) = iter.key() else { break };
        if raw_key >= end.as_slice() {
            break;
        }
        let key = EntryKeyCodec.decode(raw_key);
        hits.push((key.order, iter.value().unwrap_or_default().to_vec()));
        iter.next();
    }
    hits
}

#[cfg(test)]
mod tests {
    use hyperscale_types::AddressClass;

    use super::*;

    fn entry(order: u128) -> EntryKey {
        EntryKey {
            owner: Address::new([7; 31], AddressClass::Component),
            collection: CollectionId([4; 16]),
            order,
        }
    }

    #[test]
    fn round_trips_and_orders_by_order_key() {
        let key = entry(300);
        assert_eq!(EntryKeyCodec.decode(&EntryKeyCodec.encode(&key)), key);
        assert!(EntryKeyCodec.encode(&entry(2)) < EntryKeyCodec.encode(&entry(300)));

        let versioned = (key, 42u64);
        assert_eq!(
            VersionedEntryKeyCodec.decode(&VersionedEntryKeyCodec.encode(&versioned)),
            versioned
        );
        assert!(
            VersionedEntryKeyCodec.encode(&(key, 1)) < VersionedEntryKeyCodec.encode(&(key, 2))
        );
    }

    #[test]
    fn range_bounds_cover_plain_and_versioned_rows() {
        let (start, end) = entry_range_bounds(entry(0).owner, entry(0).collection, 2, 300);
        for order in [2u128, 100, 300] {
            let plain = EntryKeyCodec.encode(&entry(order));
            assert!(start <= plain && plain < end, "plain row at {order}");
            let versioned = VersionedEntryKeyCodec.encode(&(entry(order), u64::MAX));
            assert!(
                start <= versioned && versioned < end,
                "versioned at {order}"
            );
        }
        assert!(EntryKeyCodec.encode(&entry(1)) < start);
        assert!(EntryKeyCodec.encode(&entry(301)) >= end);
    }
}
