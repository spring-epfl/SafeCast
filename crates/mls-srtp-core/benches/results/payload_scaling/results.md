# Payload Scaling Investigation

> These measurements were taken on an older build, before
> later fixes and improvements to our SRTP setup. The methodology and the
> qualitative conclusion (a large fixed per-packet cost dominates small
> payloads) still hold. TODO: re-run `srtp_scaling` and `aes_gcm_baseline`
> and update the numbers.

## Motivation

The throughput benchmark showed that larger payloads yield higher throughput
(30.1 Gbps at 1424 B vs 60.8 Gbps at 8924 B). This investigation quantifies
why: how much of the per-packet time is a fixed cost vs. a per-byte cost,
and where does the fixed cost come from?

## Method

Two benchmarks, each tested across 13 payload sizes (16 B to 16384 B):

1. **`srtp_scaling.rs`** — measures SRTP `protect()`.

2. **`aes_gcm_baseline.rs`** — measures AES-GCM via OpenSSL directly.

A linear regression `time = fixed + per_byte × payload_size` is fitted to each dataset.

## Benchmark data

### SRTP `protect()` (from `srtp_scaling`)

| Payload |  Mean time | Throughput |
|--------:|-----------:|-----------:|
|    16 B |  252.07 ns |   1.4 Gbps |
|    32 B |  255.25 ns |   1.5 Gbps |
|    64 B |  256.71 ns |   2.9 Gbps |
|   128 B |  273.15 ns |   4.6 Gbps |
|   256 B |  288.65 ns |   7.9 Gbps |
|   512 B |  305.98 ns |  14.1 Gbps |
|  1024 B |  361.32 ns |  23.3 Gbps |
|  1424 B |  400.16 ns |  29.1 Gbps |
|  2048 B |  466.45 ns |  35.5 Gbps |
|  4096 B |  686.95 ns |  48.0 Gbps |
|  8192 B | 1110.80 ns |  59.1 Gbps |
|  8924 B | 1192.50 ns |  60.0 Gbps |
| 16384 B | 1968.70 ns |  66.7 Gbps |

### Raw AES-GCM (from `aes_gcm_baseline`)

| Payload |  Mean time | Throughput |
|--------:|-----------:|-----------:|
|    16 B |   91.78 ns |   2.8 Gbps |
|    32 B |   93.81 ns |   4.1 Gbps |
|    64 B |   97.58 ns |   6.6 Gbps |
|   128 B |  106.85 ns |  10.8 Gbps |
|   256 B |  129.58 ns |  16.8 Gbps |
|   512 B |  146.91 ns |  28.7 Gbps |
|  1024 B |  201.11 ns |  41.3 Gbps |
|  1424 B |  242.17 ns |  47.5 Gbps |
|  2048 B |  307.41 ns |  53.6 Gbps |
|  4096 B |  520.73 ns |  63.2 Gbps |
|  8192 B |  947.51 ns |  69.2 Gbps |
|  8924 B | 1070.50 ns |  66.9 Gbps |
| 16384 B | 1801.80 ns |  72.9 Gbps |

Throughput = `(payload + 12 B RTP header + 16 B GCM tag) × 8 bits / mean_time`.

## Linear regression

A linear model is fitted to each dataset using least squares regression:

```
time(payload_size) = fixed_cost + time_per_byte × payload_size
```

| Method               | fixed_cost (ns) | time_per_byte (ns) | Asymptotic throughput |
|----------------------|----------------:|-------------------:|----------------------:|
| Raw AES-GCM          |            94.3 |             0.1051 |             76.1 Gbps |
| SRTP `protect()`     |           254.2 |             0.1047 |             76.4 Gbps |

**Asymptotic throughput** = the theoretical maximum throughput if the payload were
infinitely large (so the fixed cost becomes negligible). Derived as follows:

```
throughput (bytes/ns) = payload_size / time
                      = payload_size / (fixed_cost + time_per_byte × payload_size)
```

As `payload_size -> ∞`, the `fixed_cost` term becomes negligible:

```
                      = payload_size / (time_per_byte × payload_size)
                      = 1 / time_per_byte                               [bytes/ns]
```

This gives bytes per nanosecond. To convert to gigabits per second (Gbps):

```
1 byte/ns = 1 byte / 10⁻⁹ s = 10⁹ bytes/s = 1 GB/s (GBps) = 8 Gbps
```

So we just multiply by 8:

```
throughput (Gbps) = 8 / time_per_byte = 8 / 0.1051 = 76.1 Gbps
```

## Fixed cost breakdown

The per-byte cost is identical (~0.105 ns/byte), confirming it is pure
AES-GCM encryption. Only the fixed cost differs.

| Component                                   |   Cost |
|---------------------------------------------|-------:|
| Raw AES-GCM per-packet overhead             |  94 ns |
| SRTP overhead on top of raw GCM             | 160 ns |
| **Total SRTP `protect()` fixed cost**       | 254 ns |

**Raw AES-GCM (94 ns)**: the per-packet cost of AES-128-GCM via OpenSSL.
This covers loading the new 12-byte IV/nonce into the cipher context, 
feeding the 12-byte RTP header as authenticated-but-not-encrypted data, and
computing the final 16-byte authentication tag from the GHASH state

**SRTP overhead (160 ns)**: everything libsrtp2 does on top of raw GCM: stream
lookup by SSRC, key usage limit check, replay window update, IV construction
(SSRC + packet index XOR salt), plus the Rust FFI.

## Conclusion

Throughput increases with payload size because the 254 ns fixed cost is amortized
over more bytes:

**16 B payload:**

```
fixed_cost_share = fixed_cost / total_time = 254 / 252 = 99%
throughput = (16 + 12 + 16) × 8 / 252 = 1.4 Gbps
```

Almost all the time is spent on the fixed cost; the actual AES-GCM
encryption of 16 bytes is negligible (0.1047 × 16 = 1.7 ns).

**16384 B payload:**

```
fixed_cost_share = fixed_cost / total_time = 254 / 1969 = 13%
throughput = (16384 + 12 + 16) × 8 / 1969 = 66.7 Gbps
```

The fixed cost is only 13% of the total time. The remaining 87% is the
AES-GCM encryption itself (0.1047 × 16384 = 1715 ns), so the throughput
approaches the asymptotic AES-GCM ceiling of ~76 Gbps.

## Reproduction

```
cargo bench --package mls-srtp-core --bench srtp_scaling
cargo bench --package mls-srtp-core --bench aes_gcm_baseline
python3 fixed_cost_breakdown.py
```
