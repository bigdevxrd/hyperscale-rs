//! Building the XRD transfer every client sends.
//!
//! The manifest shape — lock a fee on the payer, withdraw, deposit the whole
//! worktop or abort — is the same whether a load generator, a behavioral
//! scenario, or the browser demo is sending it. Only the surrounding policy
//! differs (where the nonce comes from, whether a failure aborts the run or
//! is logged and skipped), so this returns a `Result` and leaves that to the
//! caller.

use radix_common::constants::XRD;
use radix_common::crypto::Ed25519PrivateKey;
use radix_common::math::Decimal;
use radix_common::network::NetworkDefinition;
use radix_common::types::ComponentAddress;
use radix_transactions::builder::ManifestBuilder;

use super::notarize::sign_and_notarize;
use crate::transaction::constructors::routable_from_notarized_v1;
use crate::{RoutableTransaction, TimestampRange, TransactionError};

/// The fee the payer locks. Comfortably covers a transfer at current costing;
/// the surplus refunds, so overshooting is free and underestimating aborts.
const TRANSFER_FEE: u32 = 10;

/// Build a signed, notarized XRD transfer from `from` to `to`, routable and
/// valid across `validity`.
///
/// `payer` must control `from`: it both signs the withdrawal and notarizes.
///
/// # Errors
///
/// Returns [`TransactionError`] if signing or notarization fails, which in
/// practice means a malformed manifest.
pub fn build_transfer_tx(
    payer: &Ed25519PrivateKey,
    from: ComponentAddress,
    to: ComponentAddress,
    amount: Decimal,
    network: &NetworkDefinition,
    nonce: u32,
    validity: TimestampRange,
) -> Result<RoutableTransaction, TransactionError> {
    let manifest = ManifestBuilder::new()
        .lock_fee(from, Decimal::from(TRANSFER_FEE))
        .withdraw_from_account(from, XRD, amount)
        .try_deposit_entire_worktop_or_abort(to, None)
        .build();
    let notarized = sign_and_notarize(manifest, network, nonce, payer)?;
    routable_from_notarized_v1(notarized, validity)
}

/// Build a signed, notarized XRD fan-out: one withdrawal from `from`,
/// `amount` deposited to each of `recipients`.
///
/// Every recipient account joins the transaction's declared set, so the
/// participant count — and with it the number of shards the transaction
/// touches — scales with the recipient list.
///
/// `payer` must control `from`: it both signs the withdrawal and notarizes.
///
/// # Errors
///
/// Returns [`TransactionError`] if signing or notarization fails, which in
/// practice means a malformed manifest.
///
/// # Panics
///
/// Panics if `recipients` is empty.
pub fn build_fan_out_transfer_tx(
    payer: &Ed25519PrivateKey,
    from: ComponentAddress,
    recipients: &[ComponentAddress],
    amount: Decimal,
    network: &NetworkDefinition,
    nonce: u32,
    validity: TimestampRange,
) -> Result<RoutableTransaction, TransactionError> {
    assert!(!recipients.is_empty(), "fan-out needs a recipient");
    let total = amount
        * Decimal::from(u64::try_from(recipients.len()).expect("recipient count fits in u64"));
    let mut builder = ManifestBuilder::new()
        .lock_fee(from, Decimal::from(TRANSFER_FEE))
        .withdraw_from_account(from, XRD, total);
    for (index, recipient) in recipients.iter().enumerate() {
        let bucket = format!("fan_out_{index}");
        builder = builder
            .take_from_worktop(XRD, amount, &bucket)
            .try_deposit_or_abort(*recipient, None, bucket);
    }
    let notarized = sign_and_notarize(builder.build(), network, nonce, payer)?;
    routable_from_notarized_v1(notarized, validity)
}
