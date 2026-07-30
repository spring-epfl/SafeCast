# SRTP Encryption Throughput Results

Benchmark: `srtp_throughput_criterion.rs`, which measures SRTP protect
(encrypt) and unprotect (decrypt) throughput.

## Specs

- **Chip**: Apple M2 (4 Performance + 4 Efficiency cores)
- **RAM**: 16 GB
- **OS**: macOS Tahoe 26.3.1 

## Target bitrate

2.4 Gbps ≈ the bitrate of an uncompressed 1080p60 video stream. 
This is the rate at which SRTP packets would arrive and need to be encrypted, 
so we measure whether `protect()` can keep up with this pace.

## Results

| Payload size               | Operation | Mean time/pkt | Std dev | Throughput | Speedup |
|----------------------------|-----------|---------------|---------|------------|---------|
| 1424 B (ST 2110 standard)  | protect   | 252.2 ns      | 2.6 ns  | 46.1 Gbps  | x19.2   |
| 1424 B (ST 2110 standard)  | unprotect | 294.3 ns      | 15.7 ns | 39.5 Gbps  | x16.4   |
| 8924 B (ST 2110 jumbo)     | protect   | 1038.4 ns     | 14.8 ns | 69.0 Gbps  | x28.7   |
| 8924 B (ST 2110 jumbo)     | unprotect | 1179.6 ns     | 15.6 ns | 60.7 Gbps  | x25.3   |

Speedup = measured throughput / target bitrate.
Throughput = `(payload + 12 B RTP header + 16 B GCM tag) × 8 bits / mean_time`.

With standard-MTU packets (1424 B), encryption is x19.2 faster than the
2.4 Gbps target. With jumbo frames (8924 B) the speedup grows to x28.7
(because the per-packet fixed costs are amortized over a larger payload;
see `../payload_scaling/results.md` for the fixed-vs-per-byte breakdown).
In both cases, SRTP encryption is far from a bottleneck for real-time
1080p60 video.

## Reproduction

```
cargo bench --package mls-srtp-core --bench srtp_throughput_criterion
```
