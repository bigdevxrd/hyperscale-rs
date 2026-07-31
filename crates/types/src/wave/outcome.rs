//! Per-tx execution outcome ([`TxOutcome`]) and the [`ExecutionOutcome`] enum
//! carried inside execution certificates.

use sbor::prelude::*;

use crate::{GlobalReceiptHash, TxHash};

/// Per-transaction execution outcome within a wave.
///
/// Carried inside execution certificates so remote shards can extract
/// individual transaction results for cross-shard finalization.
#[derive(Debug, Clone, PartialEq, Eq, BasicSbor)]
pub struct TxOutcome {
    tx_hash: TxHash,
    outcome: ExecutionOutcome,
    /// Set when this shard aborts a transaction it pays for: the hash of
    /// the fee receipt the abort settles.
    ///
    /// An aborted transaction's own effects never apply — that is what
    /// makes a cross-shard abort atomic — but the payer still owes the
    /// class floor, and state moves only through receipts. The fee
    /// receipt is the reconciliation: it carries the floor debit and
    /// nothing else, and naming its hash here puts it under the signed
    /// receipt root like any other receipt's content.
    fee_receipt: Option<GlobalReceiptHash>,
}

impl TxOutcome {
    /// Create a new `TxOutcome` settling no fee receipt.
    #[must_use]
    pub const fn new(tx_hash: TxHash, outcome: ExecutionOutcome) -> Self {
        Self {
            tx_hash,
            outcome,
            fee_receipt: None,
        }
    }

    /// Create an aborted `TxOutcome` that settles the payer's floor
    /// through the named fee receipt.
    #[must_use]
    pub const fn aborted_with_fee(tx_hash: TxHash, fee_receipt: GlobalReceiptHash) -> Self {
        Self {
            tx_hash,
            outcome: ExecutionOutcome::Aborted,
            fee_receipt: Some(fee_receipt),
        }
    }

    /// The fee receipt this outcome settles, if any.
    #[must_use]
    pub const fn fee_receipt(&self) -> Option<GlobalReceiptHash> {
        self.fee_receipt
    }

    /// Transaction hash.
    #[must_use]
    pub const fn tx_hash(&self) -> TxHash {
        self.tx_hash
    }

    /// The execution outcome for this transaction.
    #[must_use]
    pub const fn outcome(&self) -> &ExecutionOutcome {
        &self.outcome
    }

    /// Consume the outcome and return its parts.
    #[must_use]
    pub const fn into_parts(self) -> (TxHash, ExecutionOutcome) {
        (self.tx_hash, self.outcome)
    }

    /// Whether this outcome is an abort.
    #[must_use]
    pub const fn is_aborted(&self) -> bool {
        matches!(self.outcome, ExecutionOutcome::Aborted)
    }
}

/// The outcome of executing a transaction on a single shard.
///
/// The variant tag IS the outcome — there is no separate `success: bool`
/// flag. Failed transactions carry no `receipt_hash` on the wire (the
/// canonical [`FAILED_RECEIPT_HASH`](crate::FAILED_RECEIPT_HASH) is
/// derivable at hash time).
#[derive(Debug, Clone, PartialEq, Eq, BasicSbor)]
pub enum ExecutionOutcome {
    /// Engine committed the transaction; state changes applied.
    Succeeded {
        /// Hash of the global receipt produced by this execution.
        receipt_hash: GlobalReceiptHash,
    },
    /// Engine rejected the transaction; no state changes applied.
    /// Carries no payload — every failure is consensus-equivalent.
    Failed,
    /// Transaction aborted before execution could complete.
    Aborted,
}

impl ExecutionOutcome {
    /// Whether the transaction was aborted.
    #[must_use]
    pub const fn is_aborted(&self) -> bool {
        matches!(self, Self::Aborted)
    }
}
