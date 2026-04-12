# SRTP Encryption Throughput Results

Benchmark: `srtp_throughput_criterion.rs`, which measures SRTP encryption throughput.

## Specs

- **Chip**: Apple M2 (4 Performance + 4 Efficiency cores)
- **RAM**: 16 GB
- **OS**: macOS Tahoe 26.3.1 

## Target bitrate

2.4 Gbps ≈ the bitrate of an uncompressed 1080p60 video stream. 
This is the rate at which SRTP packets would arrive and need to be encrypted, 
so we measure whether `protect()` can keep up with this pace.

## Results

| Payload size               | Mean time/pkt | Std dev  | Throughput | Speedup |
|----------------------------|---------------|----------|------------|---------|
| 1424 B (ST 2110 standard)  | 385.3 ns      | 0.7 ns   | 30.1 Gbps  | x12.6   |
| 8924 B (ST 2110 jumbo)     | 1177.7 ns     | 6.5 ns   | 60.8 Gbps  | x25.3   |

Speedup = measured throughput / target bitrate

With standard-MTU packets (1424 B), encryption is x12.6 faster than the
2.4 Gbps target. With jumbo frames (8924 B) the speedup doubles to x25.3
(because the per-packet fixed costs are amortized over a larger payload).
In both cases, SRTP encryption is far from a bottleneck for real-time 1080p60 video.

## Criterion report

A full HTML report is available at `criterion_srtp_throughput/report/index.html`.

## Reproduction

```
cargo bench --package mls-srtp-core --bench srtp_throughput_criterion
python3 crates/mls-srtp-core/benches/results/summarize_throughput.py
```
