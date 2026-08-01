# MLS-SRTP

This repository is a research prototype and evaluation of a system for
end-to-end encrypted real-time media transported over IP multicast. The design combines two
building blocks:

- **Group key management**, provided by **MLS** (Messaging Layer Security): MLS
  maintains a shared group secret, and rekeys efficiently whenever a
  participant joins, leaves, or is removed, even at large scale. Each such change
  advances the group to a new epoch (the span during which the group's secret stays fixed).
- **Transport protection**, provided by **SRTP** (Secure RTP): SRTP encrypts and
  authenticates the media, using the key provided by MLS.

On top of the bridge between the two components, this repository adds and
evaluates fine-grained, within-epoch keying. Finer keying shrinks how much media 
a single compromised key exposes, at the cost of extra key-derivation work 
(and hence lower achievable throughput).

This trade-off, along with the cost of MLS rekeying and SRTP encryption/decryption, 
is benchmarked in this repository (see the Benchmarks section below). 
A Jupyter notebook (`figures_from_benches.ipynb`) then turns the raw results into figures.

![MLS-SRTP overview](figures/mls_srtp_overview.png)

Each MLS epoch exports one seed per sender (`MLS-Exporter(SSRC)`), which an SRTP
key ratchet expands via HKDF into a chain of generation keys `key_0, key_1, ...`.
The sender advances the ratchet as it emits packets. The receiver, 
which may see packets reordered or delayed, instead recomputes each packet's `g` 
from RTP header fields alone (the timestamp for frame-level keying, the sequence number for per-packet). 
Hence, it can pick the matching key without any signaling over the wire. 
As jitter can make a packet from an earlier generation arrive after the receiver 
has already moved on, the receiver caches the last few generation keys in a sliding window, 
so those late packets still decrypt. Once a generation falls behind the window its key is deleted, 
and it is that deletion that provides forward secrecy.

## Repository structure

- `crates/mls-srtp-core/` -- Core library: MLS group management, SRTP key
  derivation, the keying-granularity schemes (epoch/frame/packet), the
  reorder-capable receiver, and the network simulation.
- `crates/mls-srtp-core/benches/` -- All benchmarks (see the table below).
- `crates/mls-srtp-core/benches/results/` -- Benchmark data and write-ups:
  `criterion/` holds the raw Criterion JSON the Jupyter notebook reads, `memory_usage/`
  and `realistic_receiver/` hold the other benchmarks' data, and `writeups/`
  holds a write-up for some of the benchmarks.
- `demo/` -- A minimal Authentication Service (`auth-service`), a
  creator/sender/receiver client (`mls-srtp-client`), and the script that
  launches the whole pipeline (`run_demo.sh`).
- `openmls/` -- Copy of OpenMLS (with local modifications, see below).
- `vendor/srtp`, `vendor/srtp2-sys` -- Copies of the Rust libsrtp
  bindings (with local modifications, see below).
- `figures/` -- Generated benchmark figures (PDF/PNG) and implementation overview diagrams.
- `figures_from_benches.ipynb` -- Jupyter notebook that generates all figures
  from the benchmark results.
- `run_end_to_end.sh` -- Runs all benchmarks, copies results, and executes the
  notebook to regenerate every figure.

## Setup

You need a Rust toolchain and OpenSSL.

1. **Rust**. Install via [rustup](https://rustup.rs):
   ```bash
   curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
   ```

2. **OpenSSL.** This repo bundles the libsrtp C library and compiles it from
   source as part of `cargo build`. That compilation needs OpenSSL's development
   files:
   ```bash
   brew install openssl@3        # macOS
   sudo apt install libssl-dev   # Debian / Ubuntu
   ```

3. **Python 3.** Only needed to regenerate the figures from the notebook.
   Requires `jupyter` and `nbconvert`:
   ```bash
   pip install jupyter nbconvert
   ```

Once Rust and OpenSSL are in place, `cargo build` compiles everything.

## Benchmarks

Run all benchmarks and regenerate every figure in one go:
```bash
./run_end_to_end.sh
```

Or run a single benchmark:
```bash
cargo bench --package mls-srtp-core --bench <name>
```

| Benchmark | What it measures | Output |
| --- | --- | --- |
| `srtp_throughput` | SRTP encryption/decryption throughput and latency across different payload sizes | Fig 1, 2; Table 1 |
| `pep_throughput` | PEP (CTR / CTR+CMAC-64) throughput, for comparison | Fig 3, 4 |
| `rekey` | MLS rekey latency (sender + receiver) across group sizes | Fig 5 |
| `rekey_breakdown` | MLS rekey cost breakdown | Fig 6 |
| `memory_usage` | Per-member memory across group sizes | Fig 7 |
| `srtp_rtcp_interleaving` | RTP throughput with periodic SRTCP interleaved | Fig 8 |
| `granularity_throughput_ideal` | Epoch/frame/packet keying under ideal in-order delivery | Fig 9, 10 |
| `realistic_receiver` | The three granularities on the reorder-capable receiver under a disturbed network | Fig 11-17 |
| `key_derivation` | MLS key export + SRTP KDF latency | Table 3 |
| `replay_protection` | Cost of rejecting a replayed packet | Table 1 (replay row) |
| `ratchet_step` | The cost paid per ratchet step: deriving and installing new keys | `writeups/ratchet_step.md` |
| `srtp_scaling` + `aes_gcm_baseline` | SRTP time vs raw AES-GCM | `writeups/fixed_cost_breakdown.md` |

"Fig N" is the file `figures/figN_*.png`/`.pdf`; "Table N" is printed inside the
notebook (`figures_from_benches.ipynb`). The write-ups live in
`crates/mls-srtp-core/benches/results/writeups/`.

The `realistic_receiver` benchmark evaluates the receiver under simulated network conditions:

![Realistic receiver benchmark pipeline](figures/bench_pipeline.png)

A simulated sender produces a paced, encrypted video stream. A network model
then disturbs the stream (jitter, loss, and reordering from an ST 2022-7
dual-path merge, all driven by one RNG seed). The receiver decrypts the packets 
in that arrival order, looking up or deriving the generation key for each packet. 
Each run yields throughput and latency percentiles (only the decryption calls
are timed), plus the keying loss: the fraction of packets that could not be decrypted 
because they were so late that their key had already been deleted from the receiver's cache. 
The sender's parameters (payload size and granularity), the network's disturbance
parameters, and the receiver's limits are all configurable CLI flags. The
receiver has three such limits: the key window K (how many recent generation
keys it caches), the seek cap (the most keys one packet may force it to derive
at once, so we protect against DoS attacks), and the replay window 
(how far back a duplicate packet is still detected).

## Demo

```bash
./demo/run_demo.sh      # 1 sender + 1 receiver
./demo/run_demo.sh 3    # 1 sender + 3 receivers
```

The demo launches the full pipeline as separate processes: an Authentication
Service (credential registry), the OpenMLS Delivery Service, a group creator, a
sender, and N receivers. The creator discovers peers via the DS, verifies their
credentials against the AS, creates the MLS group, and delivers Welcome messages.
Sender and receivers join, independently verify all group members against the AS,
export per-sender SRTP keys from the MLS epoch secret, and exchange
SRTP-protected RTP packets over IP multicast.

## Tests

```bash
cargo test --package mls-srtp-core
```

## Local modifications to dependencies

- **`openmls/`** (copy of [openmls/openmls](https://github.com/openmls/openmls)):
  - `openmls/openmls/src/group/mls_group/processing.rs`: changed
    `process_unverified_message` visibility from `pub(crate)` to `pub`, so the
    rekey breakdown benchmark can measure the receiver's most expensive step on its
    own: verifying the commit signature and the public-key decryption of the new
    path secrets.
  - `openmls/delivery-service/ds/src/main.rs`: fixed `send_welcome` to queue the Welcome
    for every matching client instead of returning after the first match (otherwise, 
    with multiple joiners in one commit, all but one joiner would wait forever).
- **`vendor/srtp`** (copy of the [srtp](https://crates.io/crates/srtp) crate):
  adds `Session::inplace_rekey`, which swaps only the key bytes of an existing
  stream without tearing down and rebuilding the whole stream (libsrtp's
  `srtp_update` rebuilds everything).
- **`vendor/srtp2-sys`** (copy of the [srtp2-sys](https://crates.io/crates/srtp2-sys)
  crate): bundles libsrtp v2.8.0 instead of v2.3.0 (v2.3.0 had a SET_TAG bug
  costing ~120 ns on every `protect()`, see
  `crates/mls-srtp-core/benches/encrypt_decrypt_asymmetry/`). We also add
  `srtp_inplace_rekey` to the bundled libsrtp, which `inplace_rekey` wraps.
