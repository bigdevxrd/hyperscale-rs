//! Pure execution functions invoked from the node's delegated-action dispatcher.
//!
//! These functions implement the asynchronous side of the execution
//! state machine: signature verification, execution-vote aggregation into
//! [`ExecutionCertificate`]s, transaction execution against a
//! [`SubstateView`], and cross-shard provisioning requests. They are
//! kept free of node/runner concerns so the dispatcher only handles
//! event plumbing — sharing the handlers between production and
//! simulation keeps execution behavior identical across both backends.

use std::sync::Arc;

use hyperscale_core::{Action, ActionContext, CrossShardExecutionRequest, ProtocolEvent};
use hyperscale_engine::{CrossShardTxInput, DynSnapshot, Executor as _, WaveBatchContext};
use hyperscale_metrics::record_execution_latency;
use hyperscale_network::Network;
use hyperscale_storage::{ShardStorage, SubstateStore, SubstateView};
use hyperscale_types::network::notification::{
    ExecutionCertificatesNotification, ExecutionVotesNotification,
};
use hyperscale_types::{
    ExecutionCertificate, ExecutionCertificateContext, ExecutionVote, FinalizedWaveContext,
    Stopwatch, StoredReceipt, Verifiable, Verified, exec_cert_batch_message,
    exec_vote_batch_message,
};

// ============================================================================
// Wave-based execution voting handlers
// ============================================================================

/// Outcomes flow through `ctx.notify`. Variants owned by other coordinator
/// crates hit `unreachable!()` — node's dispatcher routes by variant prefix.
///
/// # Panics
///
/// Panics if the dispatcher routes a variant owned by another crate, or if
/// the executor breaks its "one result per input transaction" contract.
#[allow(clippy::too_many_lines)] // single dispatch over execution-owned Action variants
pub fn handle_action<S, N>(action: Action, ctx: &ActionContext<'_, S, N>)
where
    S: ShardStorage,
    N: Network,
{
    match action {
        Action::AggregateExecutionCertificate {
            wave_id,
            global_receipt_root,
            votes,
            committee,
        } => {
            let certificate = Verified::<ExecutionCertificate>::aggregate(
                ctx.verifier,
                &wave_id,
                global_receipt_root,
                &votes,
                &committee,
            );
            ctx.notify_protocol(ProtocolEvent::ExecutionCertificateAggregated {
                wave_id,
                certificate: Arc::new(certificate),
            });
        }
        Action::VerifyAndAggregateExecutionVotes {
            wave_id,
            block_hash,
            votes,
        } => {
            let verified_votes = Verified::<ExecutionVote>::verify_batch(
                ctx.verifier,
                ctx.topology_snapshot.network(),
                votes,
            );
            ctx.notify_protocol(ProtocolEvent::ExecutionVotesVerifiedAndAggregated {
                wave_id,
                block_hash,
                verified_votes,
            });
        }
        Action::VerifyExecutionCertificateSignature {
            certificate,
            public_keys,
            ..
        } => {
            let ctx_ec = ExecutionCertificateContext {
                verifier: ctx.verifier,
                network: ctx.topology_snapshot.network(),
                public_keys: &public_keys,
            };
            let result = certificate
                .upgrade(&ctx_ec)
                .map(Arc::new)
                .map_err(|(raw, err)| (Arc::new(raw), err));
            ctx.notify_protocol(ProtocolEvent::ExecutionCertificateSignatureVerified { result });
        }
        Action::VerifyFinalizedWave {
            wave,
            ec_public_keys,
        } => {
            let fw_ctx = FinalizedWaveContext {
                verifier: ctx.verifier,
                network: ctx.topology_snapshot.network(),
                ec_public_keys: &ec_public_keys,
            };
            let result = Arc::unwrap_or_clone(wave)
                .upgrade(&fw_ctx)
                .map(Arc::new)
                .map_err(|(raw, err)| (Arc::new(raw), err));
            ctx.notify_protocol(ProtocolEvent::FinalizedWaveVerified { result });
        }
        Action::ExecuteTransactions {
            wave_id,
            block_hash,
            block_height,
            transactions,
            wave_start_ts,
            state_root: _,
        } => {
            let start = Stopwatch::start();
            let shard_trie = ctx.topology_snapshot.shard_trie();
            let view = ctx.pending_chain.view_at(block_hash, block_height);
            let view_snap = <SubstateView<_> as SubstateStore>::snapshot(&*view);
            let snapshot = DynSnapshot(&view_snap);
            let wave_ctx = WaveBatchContext {
                par: ctx.par,
                cache: ctx.execution_cache.as_ref(),
                local_shard: ctx.shard,
                shard_trie,
                block_hash,
                wave_start_ts,
            };
            // Engine dispatch is typed: the block splits into per-variant
            // sub-batches, each engine executes its own, and the receipts
            // merge back in canonical transaction-hash order.
            let (vm_txs, radix_txs): (Vec<_>, Vec<_>) = transactions
                .iter()
                .map(Arc::clone)
                .partition(|tx| tx.is_vm());
            let mut executed = ctx
                .executor
                .execute_wave_batch(&wave_ctx, &snapshot, &radix_txs);
            executed.extend(
                ctx.vm_executor
                    .execute_wave_batch(&wave_ctx, &snapshot, &vm_txs),
            );
            executed.sort_by_key(|tx| tx.tx_hash);
            let (tx_outcomes, results): (Vec<_>, Vec<_>) = executed
                .into_iter()
                .map(|executed| (executed.outcome(), StoredReceipt::from(executed)))
                .unzip();
            record_execution_latency(start.elapsed().as_secs_f64());
            ctx.notify_protocol(ProtocolEvent::ExecutionBatchCompleted {
                wave_id,
                results,
                tx_outcomes,
            });
        }
        Action::ExecuteCrossShardTransactions {
            wave_id,
            block_hash,
            block_height,
            requests,
            wave_start_ts,
        } => {
            fn inputs<'a>(reqs: &[&'a CrossShardExecutionRequest]) -> Vec<CrossShardTxInput<'a>> {
                reqs.iter()
                    .map(|r| CrossShardTxInput {
                        transaction: &r.transaction,
                        provisions: &r.provisions,
                        ownership: &r.ownership,
                        clock: r.clock,
                    })
                    .collect()
            }
            let start = Stopwatch::start();
            let shard_trie = ctx.topology_snapshot.shard_trie();
            let view = ctx.pending_chain.view_at(block_hash, block_height);
            let view_snap = <SubstateView<_> as SubstateStore>::snapshot(&*view);
            let snapshot = DynSnapshot(&view_snap);
            let wave_ctx = WaveBatchContext {
                par: ctx.par,
                cache: ctx.execution_cache.as_ref(),
                local_shard: ctx.shard,
                shard_trie,
                block_hash,
                wave_start_ts,
            };
            // Engine dispatch is typed, exactly like the single-shard arm:
            // per-variant sub-batches, receipts merged back in canonical
            // transaction-hash order.
            let (vm_requests, radix_requests): (Vec<_>, Vec<_>) = requests
                .iter()
                .partition::<Vec<_>, _>(|r| r.transaction.is_vm());
            let mut executed = ctx.executor.execute_cross_shard_batch(
                &wave_ctx,
                &snapshot,
                &inputs(&radix_requests),
            );
            executed.extend(ctx.vm_executor.execute_cross_shard_batch(
                &wave_ctx,
                &snapshot,
                &inputs(&vm_requests),
            ));
            executed.sort_by_key(|tx| tx.tx_hash);
            let (tx_outcomes, results): (Vec<_>, Vec<_>) = executed
                .into_iter()
                .map(|executed| (executed.outcome(), StoredReceipt::from(executed)))
                .unzip();
            record_execution_latency(start.elapsed().as_secs_f64());
            ctx.notify_protocol(ProtocolEvent::ExecutionBatchCompleted {
                wave_id,
                results,
                tx_outcomes,
            });
        }

        // ── Sign + broadcast actions ──────────────────────────────────────
        Action::SignAndSendExecutionVote {
            block_hash,
            block_height,
            vote_anchor_ts,
            wave_id,
            global_receipt_root: _,
            tx_outcomes,
            leader,
        } => {
            let local_shard = ctx.shard;
            let validator_id = ctx.me;
            let network = ctx.topology_snapshot.network();

            let Ok(verified) = Verified::<ExecutionVote>::sign_local(
                network,
                block_hash,
                block_height,
                vote_anchor_ts,
                wave_id,
                local_shard,
                tx_outcomes,
                validator_id,
                ctx.signer.as_ref(),
            ) else {
                tracing::error!(?block_hash, "cannot sign execution vote; abstaining");
                return;
            };

            // Send vote to the wave leader (unicast). When the leader is a
            // colocated vnode the local-dispatch fast path preserves the
            // `Verifiable::Verified` marker, letting the handler skip
            // re-verification of our own signature.
            if leader != validator_id {
                let batch_msg =
                    exec_vote_batch_message(network, local_shard, std::iter::once(&*verified));
                let Ok(batch_sig) = ctx.signer.sign(&batch_msg) else {
                    tracing::error!(
                        ?block_hash,
                        "cannot sign execution vote batch; skipping send"
                    );
                    return;
                };
                let batch = ExecutionVotesNotification::new(
                    vec![Verifiable::from(verified.clone())],
                    validator_id,
                    batch_sig,
                );
                ctx.network.notify(&[leader], &batch);
            }

            // Feed own vote to state machine only if we are the leader.
            if leader == validator_id {
                ctx.notify_protocol(ProtocolEvent::VerifiedExecutionVoteReceived {
                    vote: verified,
                });
            }
        }

        Action::BroadcastExecutionCertificate {
            shard: _,
            certificate,
            recipients,
        } => {
            let cert = Arc::unwrap_or_clone(certificate).into_inner();
            let msg = exec_cert_batch_message(
                ctx.topology_snapshot.network(),
                cert.shard_id(),
                std::slice::from_ref(&cert),
            );
            let Ok(sig) = ctx.signer.sign(&msg) else {
                tracing::error!("cannot sign execution certificate batch; skipping broadcast");
                return;
            };
            let batch = ExecutionCertificatesNotification::new(vec![cert], ctx.me, sig);
            ctx.network.notify(&recipients, &batch);
        }

        _ => unreachable!("hyperscale_execution::handle_action called with non-execution action"),
    }
}
