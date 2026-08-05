//! A pool seated by the second cluster in a process is still a pool.
//!
//! The VM statics install once per process and the first installer wins,
//! so a binary running several clusters shares one instance registry —
//! and a pool instance lives in that registry like every other address.
//! A first cluster that seats no pools would otherwise fix a registry
//! that has never heard of the pool, and every later delegation would be
//! refused at admission for naming an instance that does not resolve.
//!
//! That failure reads as a defect in whatever the later scenario was
//! testing, which is why it gets a probe of its own rather than a note.
//! The cluster built first here deliberately seats nothing.

use std::time::Duration;

use hyperscale_scenarios::tx::staking_genesis_accounts;
use hyperscale_scenarios::{ScenarioConfig, delegation_folds_into_beacon_state};

mod support;

use support::SimCluster;

/// Single-shard, four-validator, resharding disarmed: the stable ground
/// the witness scenarios fold against.
const fn witness_config() -> ScenarioConfig {
    ScenarioConfig {
        shard_size: 4,
        vnodes_per_host: 1,
        pool_surplus: 0,
        num_shards: 1,
        split_bytes: u64::MAX,
        latency: Duration::from_millis(150),
    }
}

#[test]
fn a_pool_seated_after_the_statics_are_installed_still_folds() {
    // Built and dropped for its side effect alone: constructing a cluster
    // installs the process statics, and this one seats no pools.
    let _pool_less = SimCluster::new(&witness_config(), 0x9001);

    let mut cluster =
        SimCluster::with_accounts(&witness_config(), 0x57AC, &staking_genesis_accounts());
    delegation_folds_into_beacon_state(&mut cluster);
}
