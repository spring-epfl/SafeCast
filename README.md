# SafeCast: End-to-End Encrypted Real-Time Media over IP Multicast

SafeCast is a research prototype and evaluation of a system for
end-to-end encrypted real-time media transported over IP multicast. The design combines two
building blocks:

- **Group key management**, provided by **MLS** (Messaging Layer Security): MLS
  maintains a shared group secret, and rekeys efficiently whenever a
  participant joins, leaves, or is removed, even at large scale. Each such change
  advances the group to a new epoch (the span during which the group's secret stays fixed).
- **Transport protection**, provided by **SRTP** (Secure RTP): SRTP encrypts and
  authenticates the media, using the key provided by MLS.

On top of the bridge between the two components, this repository adds and
evaluates fine-grained **within-epoch keying**. Finer keying shrinks how much media 
a single compromised key exposes, at the cost of extra key-derivation work 
(and hence lower achievable throughput).

It also adds and evaluates optional per-sender **source authentication**:
the shared group key only proves that *some* member sent a packet, so any
member could forge traffic as any other. The classic fix, signing every
packet, is too slow at media packet rates. This gap is instead closed 
by adapting the **TESLA** protocol to our setting. In TESLA, the sender tags every packet 
with a fast MAC under a key that only the sender knows, and reveals 
that key a few milliseconds later. Receivers hold each packet
briefly and check its tag once the key is out. A valid tag then proves
the packet came from the sender, because when the packet arrived, nobody
else could have known the key it was tagged with.

This trade-off, along with the cost of MLS rekeying and SRTP encryption/decryption, 
is benchmarked in this repository (see [Benchmarks](#benchmarks)). 
A Jupyter notebook (`GENERATE_FIGURES.ipynb`) then turns the raw results into figures.

![SafeCast overview](figures/safecast_overview.png)

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

The bottom row of the figure is the source-authentication layer. Time is sliced into short
intervals, and the sender holds a secret hash chain `K_0 <- K_1 <- ... <- K_N` with one
key per interval. Each encrypted packet gets a tag under the current interval's key `K_i`
and carries, in the clear, the interval number `i` and the key `K_{i-d}` whose secrecy 
has just expired. That disclosure is how receivers learn the keys, `d` intervals later. 
The receiver accepts a packet only if its clock says `K_i` cannot have been
disclosed yet, and holds it. Once `K_i` arrives, one hash proves the key genuine
(`hash(K_i) = K_{i-1}`, rooted in the signed starting point `K_0`), and the
held packets' tags are checked with it. Before the stream starts, the sender
publishes `K_0` and the interval timetable in a single message, signed with its
MLS signing key. Verifying that signature is how a receiver knows whose
chain it is checking.

## Repository structure

```
SafeCast/
├── src/                          The core library
│   ├── keying/                   MLS group management and key export, the
│   │                             per-stream key ratchet, and the keying
│   │                             granularities (epoch/frame/packet)
│   ├── transport/                RTP packet handling and SRTP sessions
│   ├── receiver/                 Reorder-capable receiver: caches the last K
│   │                             generation keys so late packets still decrypt
│   ├── simulation/               Simulated sender + network disturbance model
│   │                             (jitter, loss, ST 2022-7 dual-path merge)
│   └── tesla/                    TESLA per-sender source authentication
├── benches/                      All benchmarks (see the table below)
│   └── results/                  Benchmark data the notebook reads:
│       ├── criterion/            - raw Criterion JSON
│       ├── memory_usage/         - memory measurements
│       ├── realistic_receiver/   - disturbed-network results
│       ├── tesla_throughput/     - TESLA cost results
│       └── writeups/             - write-ups for some benchmarks
├── tests/                        Integration tests of the core library
├── demo/                         Live multicast demo
│   ├── auth-service/             - minimal Authentication Service
│   ├── safecast-client/          - creator/sender/receiver client
│   └── run_demo.sh               - launches the whole pipeline
├── third_party/                  Patched copies of dependencies (see below):
│   ├── openmls/                  - OpenMLS (incl. the Delivery Service)
│   ├── srtp/                     - safe Rust API wrapping srtp2-sys
│   └── srtp2-sys/                - the libsrtp C library
├── figures/                      Generated figures + overview diagrams
├── GENERATE_FIGURES.ipynb    Jupyter notebook: benchmark results -> all figures
└── REPRODUCE.sh             Runs all benchmarks + executes notebook to regenerate figures
```

## Setup

You need a Rust toolchain and OpenSSL.

1. Rust: Install via [rustup](https://rustup.rs):
   ```bash
   curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
   ```

2. OpenSSL: This repo bundles the libsrtp C library and compiles it from
   source as part of `cargo build`. That compilation needs OpenSSL's development
   files:
   ```bash
   brew install openssl@3        # macOS
   sudo apt install libssl-dev   # Debian / Ubuntu
   ```

3. Python dependencies: Only needed to regenerate the figures from the notebook.
   ```bash
   pip install -r requirements.txt
   ```

Once Rust and OpenSSL are in place, `cargo build` compiles everything.

## Benchmarks

Run all benchmarks and regenerate every figure in one go:
```bash
./REPRODUCE.sh
```
The full run takes about 2.5 hours.

Or run a single benchmark:
```bash
cargo bench --package safecast-core --bench <name>
```

| Benchmark | What it measures | Output |
| --- | --- | --- |
| `srtp_throughput` | SRTP encryption/decryption throughput and latency across different payload sizes | Figures 1, 2; Table 1 |
| `pep_throughput` | PEP (CTR / CTR+CMAC-64) throughput, for comparison | Figures 3, 4 |
| `rekey` | MLS rekey latency (sender + receiver) across group sizes | Figures 5 |
| `rekey_breakdown` | MLS rekey cost breakdown | Figure 6 |
| `memory_usage` | Per-member memory across group sizes | Figure 7 |
| `srtp_rtcp_interleaving` | RTP throughput with periodic SRTCP interleaved | Figure 8 |
| `granularity_throughput_ideal` | Epoch/frame/packet keying under ideal in-order delivery | Figures 9, 10 |
| `realistic_receiver` | The three granularities on the reorder-capable receiver under a disturbed network | Figures 11-17 |
| `key_derivation` | MLS key export + SRTP KDF latency | Table 3 |
| `replay_protection` | Cost of rejecting a replayed packet | Table 1 (replay row) |
| `ratchet_step` | The cost paid per ratchet step: deriving and installing new keys | `writeups/ratchet_step.md` |
| `srtp_scaling` + `aes_gcm_baseline` | SRTP time vs raw AES-GCM | `writeups/fixed_cost_breakdown.md` |
| `tesla_throughput` | TESLA per-sender authentication cost on top of SRTP, both directions | Figures 18, 19 |

"Figure N" is the file `figures/figN_*.png`/`.pdf`; "Table N" is printed inside the
notebook (`GENERATE_FIGURES.ipynb`). The write-ups live in
`benches/results/writeups/`.

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
cargo test --package safecast-core
```

## Modifications to dependencies

- **`third_party/openmls/`** (copy of [openmls/openmls](https://github.com/openmls/openmls)):
  - `third_party/openmls/openmls/src/group/mls_group/processing.rs`: changed
    `process_unverified_message` visibility from `pub(crate)` to `pub`, so the
    rekey breakdown benchmark can measure the receiver's most expensive step on its
    own: verifying the commit signature and the public-key decryption of the new
    path secrets.
  - `third_party/openmls/delivery-service/ds/src/main.rs`: fixed `send_welcome` to queue the Welcome
    for every matching client instead of returning after the first match (otherwise, 
    with multiple joiners in one commit, all but one joiner would wait forever).
- **`third_party/srtp`** (copy of the [srtp](https://crates.io/crates/srtp) crate):
  adds `Session::inplace_rekey`, which swaps only the key bytes of an existing
  stream without tearing down and rebuilding the whole stream (libsrtp's
  `srtp_update` rebuilds everything).
- **`third_party/srtp2-sys`** (copy of the [srtp2-sys](https://crates.io/crates/srtp2-sys)
  crate): bundles libsrtp v2.8.0 instead of v2.3.0 (v2.3.0 had a SET_TAG bug
  costing ~120 ns on every `protect()`, see
  `benches/encrypt_decrypt_asymmetry/`). We also add
  `srtp_inplace_rekey` to the bundled libsrtp, which `inplace_rekey` wraps.
