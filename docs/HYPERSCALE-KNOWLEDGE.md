# Hyperscale-rs Knowledge Base

## What Is hyperscale-rs

A Rust implementation of the Hyperscale consensus protocol for the Radix network. Community-driven project ("try to break it") building a sharded BFT consensus layer based on HotStuff-2.

**Current state**: Work in progress. Core consensus, execution, networking, and storage layers are implemented. Deterministic simulation testing framework is functional. Not production-ready.

**Repos**:
- Upstream: https://github.com/hyperscalers/hyperscale-rs
- Fork: https://github.com/bigdevxrd/hyperscale-rs

## Architecture Overview

### Workspace Structure
28 crates in a Rust workspace monorepo. Key layers:

- **Consensus** (`bft`): Two-chain commit based on HotStuff-2 with optimistic pipelining — proposers propose immediately after QC formation rather than waiting for full commit
- **Execution** (`execution`, `engine`): Transaction execution with cross-shard coordination via wave-based voting (not 2PC). Radix Engine integration for smart contracts
- **Networking** (`network`, `network-libp2p`, `network-memory`): Trait-based networking with libp2p production transport (gossipsub + QUIC/TCP) and deterministic in-memory transport for simulation
- **Storage** (`storage`, `storage-rocksdb`, `storage-memory`): Jellyfish Verkle Tree for state roots, RocksDB for production, persistent data structures for simulation
- **Coordination** (`livelock`, `provisions`, `mempool`): Cross-shard deadlock prevention, centralized provision coordination, transaction pool management
- **Node** (`node`, `production`): Composes sub-state machines into the main node; production runner with async event loop and RPC

### Key Binaries
- `hyperscale-validator` — production validator node
- `hyperscale-keygen` — validator key generation
- `hyperscale-sim` — deterministic simulation runner

### Design Principles
- Pure consensus layer: no I/O, no locks, no async in the core state machine
- Deterministic simulation as first-class testing strategy
- Trait-based abstractions for swappable backends (storage, network, dispatch)

## Build Requirements

- **Rust**: stable (2021 edition), installed via rustup
- **System packages**: clang, lld, pkg-config, protobuf-compiler, libssl-dev, libc6-dev, git, build-essential
- **Git submodules**: required for vendor dependencies (`git clone --recurse-submodules`)
- **External deps**: libp2p 0.56, RocksDB 0.24, tokio, Radix Engine (pinned at rev 7d0b9a0 from hyperscalers fork)
- **Build command**: `cargo build --release`

## Deployment Target

**Guild VPS**: 72.62.195.141 (SSH alias: `guild-vps`)
- Guild bot already lives at `/opt/guild/`
- Hyperscale installs to `/opt/hyperscale/`
- See `deploy/DEPLOY-GUIDE.md` for full instructions

## Related Projects

- **guild-saas**: Guild management SaaS platform
- **auto-trader-xrd**: Automated trading bot for Radix DEXes
- **radix-community-projects**: Community project hub

## Agent SDK Research

Radix currently has **zero agent SDK coverage**. No official or community SDK exists for building autonomous agents on Radix. The guild-saas project could be the first to fill this gap by providing agent-oriented tooling for the Radix ecosystem.

### rdx-cli@0.2.0 and x402 Payment Flows
- `rdx-cli` version 0.2.0 includes subintent commands for agent payment flows
- x402 payment protocol enables HTTP-native payment flows using Radix subintents
- Subintent architecture allows agents to compose atomic multi-step transactions

## DeFi Concepts

### Deviation vs Slippage
These terms are often confused but are distinct:
- **Deviation**: Difference between the *quoted price* and an *external price source* (e.g., oracle). Measured *before* trade execution. Indicates how far the pool price has moved from a reference price.
- **Slippage**: Difference between the *expected execution price* and the *actual execution price*. Measured *during/after* trade execution. Caused by trade size relative to pool liquidity.

### Auto-Trader Deviation Fix
The auto-trader was previously rejecting trades when deviation exceeded a threshold. The fix changes this from **rejection mode** to **price adjustment mode** — instead of refusing the trade, the bot adjusts its limit price to account for the deviation, allowing trades to proceed within acceptable bounds.
