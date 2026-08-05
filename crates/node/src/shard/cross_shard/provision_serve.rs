//! Inbound provision-request handling for cross-shard fetches.

use std::sync::Arc;

use hyperscale_core::ProvisionsRequest;
use hyperscale_metrics::record_fetch_response_sent;
use hyperscale_provisions::build_provisions;
use hyperscale_storage::{PendingChain, ShardStorage};
use hyperscale_types::network::request::GetProvisionsRequest;
use hyperscale_types::network::response::GetProvisionResponse;
use hyperscale_types::{ShardId, ShardTrie};
use tracing::warn;

/// Serve an inbound provision request from a target shard needing our state.
///
/// Reads the source block through [`PendingChain`] so heights still inside
/// the shard-committed / JMT-persisted window are reachable; reconstructs
/// per-tx [`ProvisionsRequest`]s from the block's declared reads + writes;
/// then hands them to [`build_provisions`], which is the same function the
/// gossip emit path runs. Receivers therefore absorb byte-identical
/// `entries`, `target_nodes`, and `owned_nodes` regardless of which
/// transport delivered the provision — without this, fetched-provision
/// recipients would have empty `owned_nodes` maps and diverge on
/// `filter_updates_for_shard` downstream, breaking `local_receipt_root`
/// agreement.
///
/// Takes `local_shard` and the active `ShardTrie` instead of
/// `&TopologyCoordinator` to avoid a topology dependency in the I/O layer.
/// The caller loads the trie at serve time so routing always resolves
/// against the current partition.
pub fn serve_provision_request<S: ShardStorage>(
    pending_chain: &Arc<PendingChain<S>>,
    local_shard: ShardId,
    shard_trie: &ShardTrie,
    req: &GetProvisionsRequest,
) -> GetProvisionResponse {
    let Some(certified) = pending_chain.certified_block(req.block_height) else {
        warn!(
            block_height = req.block_height.inner(),
            "Provision request: block not found"
        );
        return GetProvisionResponse { provisions: None };
    };
    let block = certified.block();

    let mut requests: Vec<ProvisionsRequest> = Vec::new();
    for tx in block.transactions().iter() {
        // The same read-set keys the gossip emit path serves, re-derived
        // from the envelope.
        let routing = tx.routing();
        let local_keys: Vec<([u8; 16], [u8; 16])> = routing
            .provision_keys
            .iter()
            .filter_map(|key| {
                key.local
                    .filter(|_| shard_trie.shard_for_prefix(key.owner) == local_shard)
                    .map(|local| (key.owner, local))
            })
            .collect();
        let targets_requester = routing
            .all_prefixes()
            .iter()
            .any(|prefix| shard_trie.shard_for_prefix(*prefix) == req.target_shard);
        // The payer shard serves its bundle even with nothing owned
        // — the engagement evidence — and a counterpart with
        // nothing owned serves its empty bundle to the payer alone:
        // the engagement echo. Both mirror the emit path.
        let payer_shard = shard_trie.shard_for_prefix(tx.body().fee_payer.0);
        if local_keys.is_empty() && payer_shard != local_shard {
            if payer_shard != req.target_shard {
                continue;
            }
        } else if !targets_requester {
            continue;
        }
        requests.push(ProvisionsRequest {
            tx_hash: tx.hash(),
            targets: vec![req.target_shard],
            local_keys,
        });
    }

    let view = pending_chain.view_at_committed_tip();
    let provisions = build_provisions(
        &view,
        local_shard,
        req.target_shard,
        req.block_height,
        block.header().parent_qc().weighted_timestamp(),
        block.header().reveal_chain(),
        &requests,
    );

    if let Some(p) = &provisions {
        record_fetch_response_sent("provision", p.transactions().len());
    }
    GetProvisionResponse { provisions }
}
