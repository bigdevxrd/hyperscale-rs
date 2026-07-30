//! Routing-overlay determinism, plumbing form: digests recomputed from
//! each node's committed chain agree node for node.
//!
//! Every node in the harness derives the overlay at mempool ingest (the
//! `routing_overlay` flag is on in the simulation runner), but ingest
//! order differs per node — gossip arrival is jittered — so the live
//! derivation can't be compared directly. The committed chain can: it is
//! consensus-identical across nodes, and recomputing the digest for every
//! committed transaction through each node's own topology snapshot pins
//! the adapter as a pure function of `(declarations, topology)` — any
//! iteration-order or instance-dependent nondeterminism in the adapter or
//! the digest encoding diverges here.

use std::sync::Arc;
use std::time::Duration;

use hyperscale_effects_bridge::{declared_effects, routing_digest};
use hyperscale_node::shard::{HostEvent, ProcessScopedInput};
use hyperscale_simulation::{SimConfig, SimulationRunner};
use hyperscale_storage::shard::chain_reader::ShardChainReader;
use hyperscale_types::test_utils::test_transaction;
use hyperscale_types::{BlockHeight, ShardId};

#[test]
fn routing_digests_recomputed_from_committed_chains_agree() {
    let config = SimConfig {
        shard_size: 4,
        jitter_fraction: 0.1,
        ..Default::default()
    };
    let mut runner = SimulationRunner::new(&config, 977);
    runner.initialize_genesis();

    // Mixed traffic: distinct declared node sets, submitted across
    // different entry nodes so gossip (not just local submission) feeds
    // every mempool.
    for (i, delay_ms) in [50u64, 51, 52, 60, 61].into_iter().enumerate() {
        let seed = u8::try_from(i).unwrap() + 1;
        let entry = u32::try_from(i).unwrap() % 4;
        runner.schedule_initial_event(
            entry,
            Duration::from_millis(delay_ms),
            HostEvent::process(ProcessScopedInput::SubmitTransaction {
                tx: Arc::new(test_transaction(seed)),
            }),
        );
    }
    runner.run_until(Duration::from_secs(10));

    let per_node: Vec<Vec<[u8; 32]>> = (0..4u32)
        .map(|i| {
            let state = runner.first_vnode_state(i).expect("vnode state");
            let topology = state.topology_snapshot();
            let tip = state.shard_coordinator().committed_height();
            let storage = runner
                .hosts_shard(i, ShardId::ROOT)
                .expect("host serves the root shard");
            let mut digests = Vec::new();
            let mut height = BlockHeight::new(1);
            while height <= tip {
                if let Some(certified) = storage.get_block(height) {
                    for tx in certified.block().transactions().iter() {
                        digests.push(routing_digest(&declared_effects(tx, topology)).0);
                    }
                }
                height = height.next();
            }
            digests
        })
        .collect();

    assert!(
        !per_node[0].is_empty(),
        "the run must commit transactions for the comparison to mean anything",
    );
    for (node, digests) in per_node.iter().enumerate().skip(1) {
        assert_eq!(
            &per_node[0], digests,
            "node {node} recomputed different routing digests from its committed chain",
        );
    }
}
