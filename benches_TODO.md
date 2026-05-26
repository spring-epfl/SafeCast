# Benchmark TODOs

## SRTP operations

- [x] **Throughput:** sustained `protect()` throughput for ST 2110-10 payload sizes
  (standard 1424 B and jumbo 8924 B) against for example a 2.4 Gbps uncompressed 1080p60 target.
  ---> `results/criterion_srtp_throughput/results.md`

- [x] **Encryption + authentication:** per-packet AES-128-GCM `protect()` and
  `unprotect()` cost across different payload sizes.
  ---> `results/mls_srtp_operations/results.md`

- [x] **Key derivation:** SRTP key derivation function that produces session-level
  cipher and salt keys from the master key (with AES-GCM there is no separate
  authentication key, since GCM handles authentication internally). This runs once
  at session start (and can be configured to refresh periodically via `key_derivation_rate`),
  not per packet. Expected to be negligible.
  ---> `results/key_derivation/results.md`

- [x] **Replay protection (receiver side):** the receiver maintains a sliding window
  (default size 64) that tracks which packet indices have already been received.
  On each packet, the receiver extracts the index and checks whether it falls within
  the window and has already been seen. This is a simple bit-check operation and
  should be negligible.
  ---> `results/mls_srtp_operations/results.md`

- [x] **Memory usage** for different group sizes.
  ---> `results/memory_usage.json`

## MLS operations

- [ ] **MLS join cost:** time for a new member to join a group (i.e., welcome
  processing time), varying group size (2, 10, 50, 200, 500, 1000, 5000 members).

- [x] **MLS rekey cost:** time to perform a group rekey (i.e., commit processing
  time) for different group sizes.
  ---> `results/mls_rekey/results.md`

- [x] **Rekey cost breakdown:** break down the rekey pipeline into its individual components inside the create/process commit and inside the SRTP key export, across group sizes. Maybe a stacked bar chart would be a nice representation here.
  ---> `results/criterion/rekey_breakdown/`

- [x] **Memory usage** for different group sizes.
  ---> `results/memory_usage.json`

## Real-world/hardware

- [ ] **AES-GCM FPGA evaluation:** using AES-GCM FPGAs for performance evaluation.
  SRTP does very little per-packet work on top of AES-GCM (just IV formation),
  so FPGA-accelerated AES-GCM throughput would be a representative measurement
  of real hardware-offloaded SRTP performance.

## Extras

- [ ] **Cycles-per-byte benchmark for SRTP vs. PEP.** In addition to reporting throughput in Gbps, 
  we could report cycles per byte (cpb) for SRTP and PEP. This metric counts
  how many CPU clock cycles are needed to process one byte of data,
  and is the standard way cryptographic primitives are compared (e.g., on the
  [eBACS benchmarking site](https://bench.cr.yp.to/)). Unlike throughput in
  Gbps, cpb is much less directly tied to clock speed: the same algorithm on the same
  microarchitecture (e.g., Apple M2 or AMD Zen 4) 
  gives the same cpb whether the chip is clocked at 700 MHz or 3.5 GHz.
  For example, if an encryption algorithm takes 200 ns when
  the chip runs at 3.49 GHz, that is 698 cycles. If the chip throttles to 3.2 GHz,
  it might take 218 ns. While this is a different wall-clock time, it is
  still 698 cycles.

  The difficulty is that measuring cpb is not straightforward on our M2 Mac.
  The `criterion-cycles-per-byte` crate relies on low-level CPU cycle counters
  such as `rdtsc`, which are x86-specific. On aarch64-apple-darwin, the crate
  does not compile at all
  ([GitHub issue](https://github.com/criterion-rs/criterion-cycles-per-byte/issues/6)).
  Apple Silicon does have hardware cycle counters, but macOS does not expose them
  in the same simple way.

  The goal is to implement a small custom Criterion measurement backend that reads cycle
  counts via Apple's `thread_selfcounts` API. A similar approach was proposed for
  [Google Benchmark](https://github.com/google/benchmark/pull/1404), but does not
  seem to have been integrated into any Rust benchmarking crate.

- [x] **RTCP encryption overhead.** In a real session, each
  participant encrypts media packets (SRTP `protect()`) and periodically
  encrypts control packets (SRTCP `protect_rtcp()`). RTCP is sent
  infrequently (~every 5 s per RFC 3550 §6.2) and packets are small,
  so the per-packet cost is negligible compared to media encryption. 
  The real question is whether interleaving occasional SRTCP
  operations with the RTP stream causes measurable interference.
  This could be quantified with a benchmark that runs an
  SRTP `protect()` loop and injects an SRTCP `protect_rtcp()` call every
  N packets\* and compares the sustained RTP throughput with and without the RTCP
  interleaving. The expected result is no measurable difference,
  as the RTCP interval is long. 
  
  \* for N, taking for example ST 2110-10 uncompressed 1080p60
  (4:2:2 10-bit, 2.58 Gbps) => at the standard MTU payload size (1424 B)
  this is ~226,500 pps, so N ≈ 1,130,000 per 5 s RTCP interval.

  For the RTCP packet size we can use 100 bytes. RFC 3550 does not define a fixed RTCP size, but real-world captures show packets in this range: a [ShareTechnote](https://www.sharetechnote.com/html/IMS_SIP_RTP_RTCP.html) example shows a 72-byte RTCP packet, while the [Wireshark](https://wiki.wireshark.org/RTCP) RTCP sample contains a 100-byte packet.


- [ ] **SRTP cipher comparison.** Benchmarking protect/unprotect across the three
  SRTP cipher families to quantify the cost of authenticated encryption
  vs. authentication-only vs. encrypt-then-MAC:

  - AEAD_AES_128_GCM (RFC 7714): authenticated encryption,
    used in our current setup.

  - AES_CM_128_HMAC_SHA1_80 (RFC 3711 §5): the mandatory-to-implement
    SRTP profile. Encrypt-then-MAC: AES-128 in counter mode for
    confidentiality (RFC 3711 §5.1), then HMAC-SHA1 truncated to 80 bits
    for authentication (RFC 3711 §5.2). Two separate passes over the data.

  - NULL_HMAC_SHA1_80 (RFC 3711 §5): same as above but without encryption (RFC 3711 §5.1).

- [ ] **Sender-side inbound SRTCP state memory.** the `srtp` crate supports SRTCP via
  `session.protect_rtcp()` & `session.unprotect_rtcp()`. RTCP packets
  are typically small (tens of bytes) and
  sent infrequently (~every 5 seconds per RFC 3550 §6.2), so the
  per-packet cost is unlikely to be a bottleneck. However, in large
  multicast groups, the sender must maintain cryptographic state for
  each receiver's RTCP stream, which could affect memory. RFC 3711:
  "In large multicast with one sender, the same considerations as for
  the small group multicast hold.  The biggest issue in this scenario
  is the additional load placed at the sender side, due to the state
  (cryptographic contexts) that has to be maintained for each receiver,
  sending back RTCP Receiver Reports. At minimum, a replay window
  might need to be maintained for each RTCP source."

- [ ] **Reduce code duplication across benchmarks.** Several benchmark files
  duplicate the same MLS group setup, RTP header construction, timing functions, etc.
  We should extract shared helpers (e.g., `setup_mls_group()`,
  `make_rtp_buffer()`, constants like `GCM_TAG_LEN` and for the MTU sizes) into a common
  `benches/bench_utils.rs` module.
