//! Shared provision construction.
//!
//! Both the gossip emit path ([`fetch_and_broadcast_provision`]) and the
//! fetch serve path (`serve_provision_request` in the node crate) flow
//! through [`build_provisions`]. Keeping a single function means a
//! receiver absorbs byte-identical bundles regardless of which transport
//! delivered them — any future field-ordering leak gets caught in one
//! place rather than drifting between two near-identical loops.
//!
//! [`fetch_and_broadcast_provision`]: crate::action_handlers::fetch_and_broadcast_provision

use std::sync::Arc;

use hyperscale_core::ProvisionsRequest;
use hyperscale_jmt::TreeReader as JmtTreeReader;
use hyperscale_storage::{SubstateStore, SubstateView, VersionedStore};
use hyperscale_types::state_key::vm_flat_key;
use hyperscale_types::{
    BlockHeight, MerkleInclusionProof, ProvisionEntry, Provisions, RevealChain, ShardId,
    SubstateEntry, TxHash, WeightedTimestamp,
};
use tracing::warn;

/// Build a `Provisions` bundle for a single source → target shard pair.
///
/// Returns `None` if the JMT version at `source_block_height` is no
/// longer available for the cell reads or proof generation — callers
/// treat this as "block not found" and surface a fetch-side retry.
/// Returns `Some(Provisions { ... transactions: empty })` when no request
/// targets `target_shard`; receivers handle empty transactions in the
/// verify path.
///
/// `requests` may name several target shards. Only those naming
/// `target_shard` participate in this build.
pub fn build_provisions<S>(
    view: &SubstateView<S>,
    source_shard: ShardId,
    target_shard: ShardId,
    source_block_height: BlockHeight,
    source_block_ts: WeightedTimestamp,
    source_block_reveal: RevealChain,
    requests: &[ProvisionsRequest],
) -> Option<Arc<Provisions>>
where
    S: SubstateStore + VersionedStore + JmtTreeReader + Sync,
{
    let mut staged: Vec<(TxHash, Vec<SubstateEntry>)> = Vec::with_capacity(requests.len());
    let mut all_storage_keys: Vec<Vec<u8>> = Vec::new();

    for req in requests {
        if !req.targets.contains(&target_shard) {
            continue;
        }

        // Read the exact flat keys of the transaction's local read set at
        // the source height. No ownership walk — identity keying made
        // ownership maps structurally absent — and nothing naming what the
        // receiver needs: it re-derives that from the envelope. A keyless
        // request still stages its transaction: the payer shard's
        // empty-entry bundle is the engagement evidence.
        let mut entries = Vec::with_capacity(req.local_keys.len());
        for (owner, local) in &req.local_keys {
            let Some(value) = view.get_substate_at_height(*owner, *local, source_block_height)
            else {
                warn!(
                    source_shard = source_shard.inner(),
                    target_shard = target_shard.inner(),
                    block_height = source_block_height.inner(),
                    tx_hash = %req.tx_hash,
                    "build_provisions: height unavailable for flat key"
                );
                return None;
            };
            if let Some(value) = value {
                let storage_key = vm_flat_key(*owner, *local);
                all_storage_keys.push(storage_key.clone());
                entries.push(SubstateEntry::new(storage_key, Some(value)));
            }
        }
        staged.push((req.tx_hash, entries));
    }

    let proof = if all_storage_keys.is_empty() {
        MerkleInclusionProof::new(Vec::new())
    } else {
        view.generate_merkle_proofs_overlay(&all_storage_keys, source_block_height)?
    };

    let transactions = staged
        .into_iter()
        .map(|(tx_hash, entries)| ProvisionEntry::new(tx_hash, entries))
        .collect();

    Some(Arc::new(Provisions::new(
        source_shard,
        target_shard,
        source_block_height,
        source_block_ts,
        source_block_reveal,
        proof,
        transactions,
    )))
}
