# MLS Rekey Benchmark Results

Results from `rekey.rs`, which benchmarks the MLS rekeying pipeline using
Criterion. A rekey is a self-update commit that advances the group to a new
epoch with fresh key material and triggers SRTP key rotation.

All benchmarks are parameterized by the following group sizes:
2, 10, 50, 200, 500, 1000, 5000.

The raw Criterion data lives in `../criterion/rekey/`; fig5 is generated
from it by `figures_from_benches.ipynb`. The component-level breakdown of
these pipelines (propose, build, stage, merge, ...) is a separate
benchmark: `rekey_breakdown.rs`, with data in `../criterion/rekey_breakdown/`
(fig6).

## Sender rekey pipeline (commit + export)

| Members | Latency   |
|---------|-----------|
| 2       | 271 µs    |
| 10      | 555 µs    |
| 50      | 1.06 ms   |
| 200     | 2.69 ms   |
| 500     | 5.47 ms   |
| 1000    | 10.2 ms   |
| 5000    | 56.7 ms   |

Total sender-side cost per epoch change. The sender creates a commit that
rotates its own key material: it generates a fresh key pair and computes new
secrets for each internal node on the path from its leaf to the root of the
ratchet tree. Each internal node in the tree has a public/private key pair,
and the sender encrypts each new secret under the sibling node's public key
so that members on the other side of the tree can decrypt it. This requires
O(log n) public-key encryptions. The pipeline ends with the SRTP key export
from the new epoch secret.

## Receiver rekey pipeline (process + export)

| Members | Latency   |
|---------|-----------|
| 2       | 267 µs    |
| 10      | 441 µs    |
| 50      | 810 µs    |
| 200     | 2.11 ms   |
| 500     | 4.31 ms   |
| 1000    | 8.18 ms   |
| 5000    | 47.4 ms   |

Total receiver-side cost per epoch change. The receiver processes the
incoming commit: it decrypts the path secret intended for it (one public-key
decryption), updates its local copy of the ratchet tree, and derives the new
group epoch secret that all members now share, then exports the SRTP keys.

## SRTP key export

The export step (two calls to `export_secret` via HKDF for master key +
master salt) is constant at ~4.2 µs across group sizes, since the exporter
operates on the epoch secret, not the tree. It adds negligible overhead to
the rekey pipeline; see `../key_derivation/results.md` for details.

## Discussion

For large broadcast groups (200-500 members), rekeying takes 2-5 ms; at
5000 members it reaches ~50-57 ms. This is fast enough for periodic rekeys
(during for example ad breaks), but would become a concern if rekeys were
triggered at high frequency.

## Reproduction

```
cargo bench --package mls-srtp-core --bench rekey
```
