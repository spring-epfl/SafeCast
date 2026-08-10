# Ratchet Step Microbenchmark Results

Results from `ratchet_step.rs`, which measures the fixed per-generation cost of
fine-grained keying in isolation. A "generation" is the span of a stream that
shares one SRTP key: one packet at packet-level and one frame at frame-level. Per
generation the cost is two ratchet HKDF-Expands (deriving that generation's
AES-128-GCM SRTP key+salt, and advancing the chain), plus the AES-128-GCM key
setup that installs that new key into the cipher. This cost is independent of payload size and is paid once per generation (per frame at frame-level, per packet at packet-level).

## Results

| Operation                | Mean time | What it is                                   |
|--------------------------|-----------|----------------------------------------------|
| `ratchet_key_salt`       | 186 ns    | 1 HKDF-Expand: derive SRTP key+salt          |
| `ratchet_chain_step`     | 206 ns    | 1 HKDF-Expand: advance `S_g -> S_{g+1}`      |
| `gcm_key_setup`          | 281 ns    | AES-128 key schedule + GHASH H subkey        |

Per-generation fixed cost = ratchet (186 + 206 = 392 ns) + key install (281 ns) ≈ 673 ns.

To install each generation's key, our in-place rekey swaps the new key into one
reused AES-128-GCM cipher object. Default libsrtp has no such call: its only rekey
path, `srtp_update`, takes a whole new policy as input (which might change the cipher
algorithm, the MKI count, or the replay-window size), and hence rebuilds the entire
stream. This is overkill when only the key bytes differ, as in our case. Concretely, 
the steps we skip are: reallocating the cipher object (a field of the
torn-down stream), re-running the master-to-session key derivation once per master key
(one per MKI), and clearing the replay window's record of recently-seen packets.

## Prediction (to confirm in separate benchmarks)

- **Frame-level:** 673 ns amortized over a frame's packets. A 1080p60 frame at
  the standard MTU (1424 B) is ~3-4k packets, so ~0.2 ns/packet: negligible.
- **Packet-level:** 673 ns added to every packet, on top of the 252 ns default
  encryption time at standard MTU (measured by `srtp_throughput.rs`).
  That is ~252 -> ~925 ns/packet, roughly 3.7x, meaning a drop of standard-MTU encrypt throughput from ~46 Gbps
  to ~12.5 Gbps. At standard MTU, the projected packet-level throughput is only modestly above a 4K@60FPS 10.3 Gbps stream, leaving little headroom. At the jumbo MTU (8924 B), the same 673 ns sits on top of a 1037 ns encryption time -> only a ~1.65x increase in per-packet time. Hence, packet-level throughput drops from ~69 Gbps to ~42 Gbps. The 673 ns is a fixed per-packet cost, so it weighs far less against a jumbo packet's longer encryption (~1037 ns) than against a standard packet's (~252 ns), letting jumbo comfortably cover 4K and 8K@50FPS.

These are analytical projections from the fixed cost. The real
throughput for all three granularities is measured separately.

## Reproduction

```
cargo bench --package safecast-core --bench ratchet_step
```
