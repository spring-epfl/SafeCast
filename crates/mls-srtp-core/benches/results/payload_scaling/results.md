# Payload Scaling Investigation

## Motivation

The throughput benchmark showed that larger payloads yield higher throughput
(46.1 Gbps at 1424 B vs 69.0 Gbps at 8924 B). This investigation quantifies
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
|    16 B |  104.3 ns  |   3.4 Gbps |
|    32 B |  107.0 ns  |   4.5 Gbps |
|    64 B |  110.2 ns  |   6.7 Gbps |
|   128 B |  118.7 ns  |  10.5 Gbps |
|   256 B |  143.2 ns  |  15.9 Gbps |
|   512 B |  160.8 ns  |  26.9 Gbps |
|  1024 B |  214.6 ns  |  39.2 Gbps |
|  1424 B |  261.6 ns  |  44.4 Gbps |
|  2048 B |  318.7 ns  |  52.1 Gbps |
|  4096 B |  531.9 ns  |  62.0 Gbps |
|  8192 B |  957.9 ns  |  68.7 Gbps |
|  8924 B | 1036.8 ns  |  69.1 Gbps |
| 16384 B | 1808.7 ns  |  72.6 Gbps |

### Raw AES-GCM (from `aes_gcm_baseline`)

| Payload |  Mean time | Throughput |
|--------:|-----------:|-----------:|
|    16 B |   91.0 ns  |   3.9 Gbps |
|    32 B |   94.2 ns  |   5.1 Gbps |
|    64 B |  106.3 ns  |   6.9 Gbps |
|   128 B |  108.7 ns  |  11.5 Gbps |
|   256 B |  129.6 ns  |  17.5 Gbps |
|   512 B |  146.4 ns  |  29.5 Gbps |
|  1024 B |  200.1 ns  |  42.1 Gbps |
|  1424 B |  241.1 ns  |  48.2 Gbps |
|  2048 B |  306.6 ns  |  54.2 Gbps |
|  4096 B |  531.6 ns  |  62.1 Gbps |
|  8192 B |  951.8 ns  |  69.1 Gbps |
|  8924 B | 1024.8 ns  |  69.9 Gbps |
| 16384 B | 1794.8 ns  |  73.2 Gbps |

Throughput = `(payload + 12 B RTP header + 16 B GCM tag) × 8 bits / mean_time`.

## Linear regression

A linear model is fitted to each dataset using least squares regression:

```
time(payload_size) = fixed_cost + time_per_byte × payload_size
```

| Method               | fixed_cost (ns) | time_per_byte (ns) | Asymptotic throughput |
|----------------------|----------------:|-------------------:|----------------------:|
| Raw AES-GCM          |            95.8 |             0.1040 |             76.9 Gbps |
| SRTP `protect()`     |           107.4 |             0.1039 |             77.0 Gbps |

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
throughput (Gbps) = 8 / time_per_byte = 8 / 0.1040 = 76.9 Gbps
```

## Fixed cost breakdown

The per-byte cost is identical (~0.104 ns/byte), confirming it is pure
AES-GCM encryption. Only the fixed cost differs.

| Component                                   |    Cost |
|---------------------------------------------|--------:|
| Raw AES-GCM per-packet overhead             | 95.8 ns |
| SRTP overhead on top of raw GCM             | 11.6 ns |
| **Total SRTP `protect()` fixed cost**       |  107 ns |

**Raw AES-GCM (95.8 ns)**: the per-packet cost of AES-128-GCM via OpenSSL.
This covers loading the new 12-byte IV/nonce into the cipher context,
feeding the 12-byte RTP header as authenticated-but-not-encrypted data, and
computing the final 16-byte authentication tag from the GHASH state.

**SRTP overhead (11.6 ns)**: everything libsrtp2 does on top of raw GCM: stream
lookup by SSRC, key usage limit check, replay window update, IV construction
(SSRC + packet index XOR salt), plus the Rust FFI.

## Conclusion

Throughput increases with payload size because the 107 ns fixed cost is amortized
over more bytes:

**16 B payload:**

```
fixed_cost_share = fixed_cost / total_time = 107 / 104 ≈ 100%
throughput = (16 + 12 + 16) × 8 / 104.3 = 3.4 Gbps
```

Almost all the time is spent on the fixed cost; the actual AES-GCM
encryption of 16 bytes is negligible (0.1039 × 16 = 1.7 ns).

**16384 B payload:**

```
fixed_cost_share = fixed_cost / total_time = 107 / 1809 = 6%
throughput = (16384 + 12 + 16) × 8 / 1808.7 = 72.6 Gbps
```

The fixed cost is only 6% of the total time. The remaining 94% is the
AES-GCM encryption itself (0.1039 × 16384 = 1702 ns), so the throughput
approaches the asymptotic AES-GCM ceiling of ~77 Gbps.

## Reproduction

```
cargo bench --package mls-srtp-core --bench srtp_scaling
cargo bench --package mls-srtp-core --bench aes_gcm_baseline

# copy the Criterion estimates this analysis reads:
for sz in 16 32 64 128 256 512 1024 1424 2048 4096 8192 8924 16384; do
  mkdir -p payload_scaling_data/protect/$sz/new raw_aes_gcm_data/encrypt/$sz/new
  cp <repo>/target/criterion/payload_scaling/protect/$sz/new/estimates.json payload_scaling_data/protect/$sz/new/
  cp <repo>/target/criterion/raw_aes_gcm/encrypt/$sz/new/estimates.json raw_aes_gcm_data/encrypt/$sz/new/
done

python3 fixed_cost_breakdown.py
```
