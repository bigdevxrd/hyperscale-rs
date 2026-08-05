//! Fee summary, log levels, and node-local execution metadata.

use sbor::prelude::*;

use crate::{BoundedString, BoundedVec};

/// Cap on `ExecutionMetadata.log_messages` count at decode time. Receipts
/// emit a handful of log lines per tx; 1024 is far above any legitimate
/// workload.
pub const MAX_LOG_MESSAGES_PER_TX: usize = 1024;

/// Cap on a single engine-produced diagnostic string at decode time —
/// applies to both each `log_messages` entry and `error_message`. Engine
/// diagnostics are short; 4 KiB rejects obviously oversized arrivals
/// before any per-byte allocation.
pub const MAX_DIAGNOSTIC_STRING_LEN: usize = 4 * 1024;

/// Fee metrics from transaction execution.
///
/// Costs are denominated in attos (10⁻¹⁸ whole tokens), the same scale
/// [`Stake`](crate::Stake) uses. Each is `Some` for receipts the engine
/// actually produced and `None` for synthetic-failure records
/// ([`ExecutionMetadata::empty`]) where the executor never reached the
/// guest and has no fees to report.
#[allow(missing_docs)] // the field names are the documentation
#[derive(Debug, Clone, PartialEq, Eq, BasicSbor)]
pub struct FeeSummary {
    pub total_execution_cost: Option<u128>,
    pub total_royalty_cost: Option<u128>,
    pub total_storage_cost: Option<u128>,
    pub total_tipping_cost: Option<u128>,
}

/// Log severity level from transaction execution. Variants follow the
/// standard `tracing` severity ordering.
#[allow(missing_docs)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, sbor::prelude::BasicSbor)]
pub enum LogLevel {
    Error,
    Warn,
    Info,
    Debug,
    Trace,
}

/// Node-local execution metadata — fees, logs, error messages.
///
/// Not consensus-critical. Only available when this node executed the
/// transaction locally (not available for synced receipts).
///
/// Written atomically with block commit but on a separate pruning cycle
/// (can be pruned earlier than the consensus receipt since not needed for state verification).
#[derive(Debug, Clone, PartialEq, Eq, BasicSbor)]
pub struct ExecutionMetadata {
    /// Fee breakdown reported by the engine.
    pub fee_summary: FeeSummary,
    /// Engine log lines emitted during execution.
    pub log_messages:
        BoundedVec<(LogLevel, BoundedString<MAX_DIAGNOSTIC_STRING_LEN>), MAX_LOG_MESSAGES_PER_TX>,
    /// Engine error message when `outcome == Failure`.
    pub error_message: Option<BoundedString<MAX_DIAGNOSTIC_STRING_LEN>>,
}

impl ExecutionMetadata {
    /// Build from raw `Vec`/`String` inputs, wrapping each into its
    /// bounded type.
    ///
    /// # Panics
    ///
    /// Panics if `log_messages.len() > MAX_LOG_MESSAGES_PER_TX`, if any
    /// `log_messages` entry's string exceeds `MAX_DIAGNOSTIC_STRING_LEN`,
    /// or if `error_message` exceeds `MAX_DIAGNOSTIC_STRING_LEN`.
    #[must_use]
    pub fn new(
        fee_summary: FeeSummary,
        log_messages: Vec<(LogLevel, String)>,
        error_message: Option<String>,
    ) -> Self {
        Self {
            fee_summary,
            log_messages: log_messages
                .into_iter()
                .map(|(level, msg)| (level, BoundedString::from(msg)))
                .collect::<Vec<_>>()
                .into(),
            error_message: error_message.map(BoundedString::from),
        }
    }

    /// All-zero metadata: empty fees, no logs, no error.
    ///
    /// Used by the engine's synthetic-failure path (`ExecutedTx::failure`
    /// in the `hyperscale_engine` crate) when the executor never reached
    /// the guest and so has no diagnostic to report. Real failed receipts
    /// carry `error_message`, `log_messages` and `fee_summary` from the
    /// kernel's own receipt.
    #[must_use]
    pub const fn empty() -> Self {
        Self {
            fee_summary: FeeSummary {
                total_execution_cost: None,
                total_royalty_cost: None,
                total_storage_cost: None,
                total_tipping_cost: None,
            },
            log_messages: BoundedVec::new(),
            error_message: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use sbor::{
        BASIC_SBOR_V1_MAX_DEPTH, BASIC_SBOR_V1_PAYLOAD_PREFIX, DecodeError, Encoder as _,
        NoCustomValueKind, ValueKind, VecEncoder, basic_decode, basic_encode,
    };

    use super::*;
    use crate::Stake;

    #[test]
    fn fee_summary_roundtrip_some() {
        let fs = FeeSummary {
            total_execution_cost: Some(123),
            total_royalty_cost: Some(Stake::ATTOS_PER_WHOLE),
            total_storage_cost: Some(0),
            total_tipping_cost: Some(0),
        };
        let bytes = basic_encode(&fs).unwrap();
        let decoded: FeeSummary = basic_decode(&bytes).unwrap();
        assert_eq!(decoded, fs);
    }

    #[test]
    fn fee_summary_roundtrip_none_for_synthetic_failure() {
        let fs = FeeSummary {
            total_execution_cost: None,
            total_royalty_cost: None,
            total_storage_cost: None,
            total_tipping_cost: None,
        };
        let bytes = basic_encode(&fs).unwrap();
        let decoded: FeeSummary = basic_decode(&bytes).unwrap();
        assert_eq!(decoded, fs);
    }

    fn sample_metadata() -> ExecutionMetadata {
        ExecutionMetadata::new(
            FeeSummary {
                total_execution_cost: None,
                total_royalty_cost: None,
                total_storage_cost: None,
                total_tipping_cost: None,
            },
            vec![
                (LogLevel::Info, "started".to_string()),
                (LogLevel::Error, "boom".to_string()),
            ],
            Some("explanatory text".to_string()),
        )
    }

    #[test]
    fn execution_metadata_roundtrip() {
        let meta = sample_metadata();
        let bytes = basic_encode(&meta).unwrap();
        let decoded: ExecutionMetadata = basic_decode(&bytes).unwrap();
        assert_eq!(decoded, meta);
    }

    #[test]
    fn execution_metadata_roundtrip_empty() {
        let meta = ExecutionMetadata::empty();
        let bytes = basic_encode(&meta).unwrap();
        let decoded: ExecutionMetadata = basic_decode(&bytes).unwrap();
        assert_eq!(decoded, meta);
    }

    /// Hand-roll metadata whose `log_messages` count exceeds the cap and
    /// verify decode rejects it before iterating.
    #[test]
    fn execution_metadata_decode_rejects_oversized_log_messages_count() {
        let mut buf = Vec::with_capacity(64);
        let mut enc = VecEncoder::<NoCustomValueKind>::new(&mut buf, BASIC_SBOR_V1_MAX_DEPTH);
        enc.write_payload_prefix(BASIC_SBOR_V1_PAYLOAD_PREFIX)
            .unwrap();
        enc.write_value_kind(ValueKind::Tuple).unwrap();
        enc.write_size(3).unwrap();
        enc.encode(&FeeSummary {
            total_execution_cost: None,
            total_royalty_cost: None,
            total_storage_cost: None,
            total_tipping_cost: None,
        })
        .unwrap();
        enc.write_value_kind(ValueKind::Array).unwrap();
        enc.write_value_kind(ValueKind::Tuple).unwrap();
        enc.write_size(MAX_LOG_MESSAGES_PER_TX + 1).unwrap();
        let err = basic_decode::<ExecutionMetadata>(&buf).unwrap_err();
        assert!(matches!(
            err,
            DecodeError::UnexpectedSize {
                expected: MAX_LOG_MESSAGES_PER_TX,
                actual,
            } if actual == MAX_LOG_MESSAGES_PER_TX + 1
        ));
    }

    /// Hand-roll metadata with a single oversized log-message string and
    /// verify decode rejects it before allocating the string buffer.
    #[test]
    fn execution_metadata_decode_rejects_oversized_log_message_string() {
        let mut buf = Vec::with_capacity(128);
        let mut enc = VecEncoder::<NoCustomValueKind>::new(&mut buf, BASIC_SBOR_V1_MAX_DEPTH);
        enc.write_payload_prefix(BASIC_SBOR_V1_PAYLOAD_PREFIX)
            .unwrap();
        enc.write_value_kind(ValueKind::Tuple).unwrap();
        enc.write_size(3).unwrap();
        enc.encode(&FeeSummary {
            total_execution_cost: None,
            total_royalty_cost: None,
            total_storage_cost: None,
            total_tipping_cost: None,
        })
        .unwrap();
        // log_messages: Vec<(LogLevel, String)> with one entry whose string
        // is oversized.
        enc.write_value_kind(ValueKind::Array).unwrap();
        enc.write_value_kind(ValueKind::Tuple).unwrap();
        enc.write_size(1).unwrap();
        enc.write_size(2).unwrap();
        enc.encode(&LogLevel::Info).unwrap();
        enc.write_value_kind(ValueKind::String).unwrap();
        enc.write_size(MAX_DIAGNOSTIC_STRING_LEN + 1).unwrap();
        let err = basic_decode::<ExecutionMetadata>(&buf).unwrap_err();
        assert!(matches!(
            err,
            DecodeError::UnexpectedSize {
                expected: MAX_DIAGNOSTIC_STRING_LEN,
                actual,
            } if actual == MAX_DIAGNOSTIC_STRING_LEN + 1
        ));
    }

    /// Hand-roll metadata with an oversized `error_message` string and
    /// verify decode rejects it before allocating the string buffer.
    #[test]
    fn execution_metadata_decode_rejects_oversized_error_message() {
        let mut buf = Vec::with_capacity(128);
        let mut enc = VecEncoder::<NoCustomValueKind>::new(&mut buf, BASIC_SBOR_V1_MAX_DEPTH);
        enc.write_payload_prefix(BASIC_SBOR_V1_PAYLOAD_PREFIX)
            .unwrap();
        enc.write_value_kind(ValueKind::Tuple).unwrap();
        enc.write_size(3).unwrap();
        enc.encode(&FeeSummary {
            total_execution_cost: None,
            total_royalty_cost: None,
            total_storage_cost: None,
            total_tipping_cost: None,
        })
        .unwrap();
        // log_messages: empty.
        enc.encode(&Vec::<(LogLevel, String)>::new()).unwrap();
        // error_message: Option::Some<String> with oversized length.
        enc.write_value_kind(ValueKind::Enum).unwrap();
        enc.write_discriminator(1).unwrap();
        enc.write_size(1).unwrap();
        enc.write_value_kind(ValueKind::String).unwrap();
        enc.write_size(MAX_DIAGNOSTIC_STRING_LEN + 1).unwrap();
        let err = basic_decode::<ExecutionMetadata>(&buf).unwrap_err();
        assert!(matches!(
            err,
            DecodeError::UnexpectedSize {
                expected: MAX_DIAGNOSTIC_STRING_LEN,
                actual,
            } if actual == MAX_DIAGNOSTIC_STRING_LEN + 1
        ));
    }
}
