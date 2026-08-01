//! Building blocks for the realistic-delivery evaluation: instead of the 
//! ideal in-order delivery that the throughput benchmarks measure, 
//! we simulate what a real network does to the packet
//! stream and drive the real receiver with the result.
//!
//! The pipeline is: simulated sender ([`sender`]) -> network disturbance
//! model ([`network`]) -> `ReceiverKeyManager` -> per-packet cost +
//! keying-loss stats. This module holds the reusable, unit-tested stages;
//! the benchmarking itself lives in the `realistic_receiver` bench.
//! Everything here is deterministic, so every run is reproducible.

pub mod network;
pub mod sender;
