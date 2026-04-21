# MLS-SRTP Operations Benchmark Results

Results from `srtp_operations.rs`, which benchmarks four MLS-SRTP
operations using Criterion: encryption (`protect`), decryption (`unprotect`),
replay protection, and MLS key export.

Both benchmarks include RTP packet handling overhead to reflect realistic
end-to-end costs: the encrypt benchmark includes packet construction and
serialization (`make_rtp_packet()` + `to_bytes()`), and the decrypt benchmark
includes RTP parsing after decryption (`from_bytes()`).

## Payload sizes

All payload sizes are chosen to match real-world RTP traffic.

**Audio** uses the default 20 ms packetization interval (RFC 3551). Bitrates
follow the Opus "sweet spots" from RFC 7587 §3.1.1.

**Video** payloads are H.264 FU-A fragments sized to fit within the common
1500-byte Ethernet MTU (RFC 8088 §3.1.3). After IP (20 B), UDP (8 B), and
RTP (12 B) headers, the maximum RTP payload is ~1460 bytes.

**ST 2110** payload sizes are derived from the SMPTE ST 2110-10 UDP datagram
size classes, after subtracting protocol headers (UDP 8 B + RTP 12 B + GCM tag 16 B).

| Size     | Use Case                  | Derivation                          |
|----------|---------------------------|-------------------------------------|
| 40 B     | Wideband speech           | Opus 20 ms @ 16 kbit/s (RFC 7587)  |
| 160 B    | Fullband mono music       | Opus 20 ms @ 64 kbit/s (RFC 7587)  |
| 800 B    | Video fragment (small)    | H.264 FU-A within MTU               |
| 1200 B   | Video fragment (near-MTU) | H.264 FU-A within MTU               |
| 1424 B   | ST 2110 standard          | 1460 - 8 UDP - 12 RTP - 16 GCM tag |
| 8924 B   | ST 2110 jumbo             | 8960 - 8 UDP - 12 RTP - 16 GCM tag |

## SRTP encryption (protect)

| Payload  | Latency  | Throughput  | Throughput (Gbps)   |
|----------|----------|-------------|---------------------|
| 40 B     | 358 ns   | 181 MiB/s   | 1.52 Gbps           |
| 160 B    | 371 ns   | 483 MiB/s   | 4.05 Gbps           |
| 800 B    | 482 ns   | 1.60 GiB/s  | 13.74 Gbps          |
| 1200 B   | 537 ns   | 2.13 GiB/s  | 18.29 Gbps          |
| 1424 B   | 562 ns   | 2.41 GiB/s  | 20.67 Gbps          |
| 8924 B   | 1660 ns  | 5.02 GiB/s  | 43.11 Gbps          |

Throughput (MiB/s, GiB/s) is reported by Criterion based on the SRTP packet
size (12 B header + payload + 16 B GCM tag). The Gbps column is calculated as
`(12 B header + payload + 16 B GCM tag) × 8 bits / latency`.

Latency ranges from 358 ns (40 B speech) to 1.66 µs (8924 B jumbo).
For audio, 358 ns is 0.002% of a 20 ms frame interval.
At the ST 2110 standard MTU payload size (1424 B), a single core achieves
20.67 Gbps, which is 8.6x the 2.4 Gbps throughput for uncompressed 1080p60.

## SRTP decryption (unprotect)

| Payload  | Latency  | Throughput  | Throughput (Gbps)   |
|----------|----------|-------------|---------------------|
| 40 B     | 450 ns   | 144 MiB/s   | 1.21 Gbps           |
| 160 B    | 483 ns   | 371 MiB/s   | 3.11 Gbps           |
| 800 B    | 701 ns   | 1.10 GiB/s  | 9.45 Gbps           |
| 1200 B   | 712 ns   | 1.61 GiB/s  | 13.80 Gbps          |
| 1424 B   | 723 ns   | 1.87 GiB/s  | 16.07 Gbps          |
| 8924 B   | 1467 ns  | 5.68 GiB/s  | 48.82 Gbps          |

Throughput (MiB/s, GiB/s) is reported by Criterion based on the SRTP packet
size (12 B header + payload + 16 B GCM tag). The Gbps column is calculated as
`(12 B header + payload + 16 B GCM tag) × 8 bits / latency`.

Decryption is ~20-35% slower than encryption across all payload sizes.
AES-GCM itself is symmetric (both sides compute GHASH + AES-CTR).
The replay protection benchmark below shows that the replay window check
costs only ~3.6 ns, so it does not explain the difference. 
TODO: investigate

## MLS key export

| Operation                        | Latency  |
|----------------------------------|----------|
| `export_secret` x2 (key + salt)  | 4.17 µs  |

This derives the 16-byte SRTP master key and 12-byte master salt from the
MLS exporter secret using HKDF. It runs once per MLS epoch change (when
group membership changes), not per packet. 
At 4.17 µs, it is negligible in practice.

## SRTP replay protection

| Payload  | Latency  |
|----------|----------|
| 40 B     | 3.64 ns  |
| 160 B    | 3.56 ns  |
| 800 B    | 3.58 ns  |
| 1200 B   | 3.55 ns  |
| 1424 B   | 3.55 ns  |
| 8924 B   | 3.55 ns  |

Measures how fast libsrtp rejects a replayed (duplicate) packet. SRTP
maintains a sliding replay window (RFC 3711 §3.3.2) that tracks recently
seen sequence numbers. When a duplicate arrives, it is rejected via a
bitmask lookup before any decryption occurs.

The cost is ~3.6 ns and constant across all payload sizes, confirming that
the rejection happens before touching the payload. At 3.6 ns per check,
replay protection adds negligible overhead to the receiver path.

## Packet overhead

SRTP with AES-128-GCM adds a constant 16-byte authentication tag per packet
(RFC 7714 §12). The 12-byte RTP header is authenticated but not encrypted.

| Payload  | RTP Size | SRTP Size | Size Increase |
|----------|----------|-----------|---------------|
| 40 B     | 52 B     | 68 B      | +30.8%        |
| 160 B    | 172 B    | 188 B     | +9.3%         |
| 800 B    | 812 B    | 828 B     | +2.0%         |
| 1200 B   | 1212 B   | 1228 B    | +1.3%         |
| 1424 B   | 1436 B   | 1452 B    | +1.1%         |
| 8924 B   | 8936 B   | 8952 B    | +0.2%         |

The 16-byte tag is a fixed cost, so overhead is most significant for small
audio packets (30.8% for 40 B speech) and negligible for large video
payloads (0.2% for 8924 B jumbo frames).

## Reproduction

```
cargo bench --package mls-srtp-core --bench mls_srtp_operations
```
