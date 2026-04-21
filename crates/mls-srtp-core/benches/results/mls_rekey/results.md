# MLS Rekey Benchmark Results

Results from `rekey.rs`, which benchmarks the MLS rekeying pipeline using
Criterion. A rekey is a self-update commit that advances the group to a new
epoch with fresh key material and triggers SRTP key rotation.

All benchmarks are parameterized by the following group sizes: 
2, 10, 50, 200, 500.

## Create rekey commit (sender)

| Members | Latency   |
|---------|-----------|
| 2       | 257 µs    |
| 10      | 574 µs    |
| 50      | 1.04 ms   |
| 200     | 2.58 ms   |
| 500     | 5.37 ms   |

The sender creates a commit that rotates its own key material. It
generates a fresh key pair and computes new secrets for each internal
node on the path from its leaf to the root of the ratchet tree. Each
internal node in the tree has a public/private key pair, and the sender
encrypts each new secret under the sibling node's public key so that
members on the other side of the tree can decrypt it. This requires
O(log n) public-key encryptions.

## Process rekey commit (receiver)

| Members | Latency   |
|---------|-----------|
| 2       | 254 µs    |
| 10      | 434 µs    |
| 50      | 788 µs    |
| 200     | 2.07 ms   |
| 500     | 4.30 ms   |

The receiver processes the incoming commit: it decrypts the path secret
intended for it (one public-key decryption), updates its local copy of
the ratchet tree, and derives the new group epoch secret that all members
now share.

## SRTP key export

| Members | Latency   |
|---------|-----------|
| 2       | 4.29 µs   |
| 10      | 4.20 µs   |
| 50      | 4.19 µs   |
| 200     | 4.19 µs   |
| 500     | 4.19 µs   |

Two calls to `export_secret` (master key + master salt) via HKDF. Constant
across group sizes since the exporter operates on the epoch secret, not the
tree. At ~4.2 µs, this is negligible compared to commit processing.

## Sender rekey pipeline (commit + export)

| Members | Latency   |
|---------|-----------|
| 2       | 262 µs    |
| 10      | 586 µs    |
| 50      | 1.04 ms   |
| 200     | 2.58 ms   |
| 500     | 5.36 ms   |

Total sender-side cost per epoch change.

## Receiver rekey pipeline (process + export)

| Members | Latency   |
|---------|-----------|
| 2       | 255 µs    |
| 10      | 434 µs    |
| 50      | 813 µs    |
| 200     | 2.06 ms   |
| 500     | 4.32 ms   |

Total receiver-side cost per epoch change.

## Discussion

For large broadcast groups (200-500 members), rekeying takes 2-5 ms. This
is fast enough for periodic rekeys (during for example ad breaks), but
would become a concern if rekeys were triggered at high
frequency.

The SRTP key export (~4.2 µs) is independent of group size and adds
negligible overhead to the rekey pipeline.

## Reproduction

```
cargo bench --package mls-srtp-core --bench rekey
```
