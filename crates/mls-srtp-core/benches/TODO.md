# Benchmark TODOs

## SRTP operations

- [x] **Throughput:** sustained `protect()` throughput for ST 2110-10 payload sizes
  (standard 1424 B and jumbo 8924 B) against for example a 2.4 Gbps uncompressed 1080p60 target.

- [x] **Encryption + authentication:** per-packet AES-128-GCM `protect()` and
  `unprotect()` cost across different payload sizes.

- [ ] **Key derivation:** SRTP key derivation function that produces session-level
  cipher and salt keys from the master key (with AES-GCM there is no separate
  authentication key, since GCM handles authentication internally). This runs once
  at session start (and can be configured to refresh periodically via `key_derivation_rate`),
  not per packet. Expected to be negligible.

- [ ] **Replay protection (receiver side):** the receiver maintains a sliding window
  (default size 64) that tracks which packet indices have already been received.
  On each packet, the receiver extracts the index and checks whether it falls within
  the window and has already been seen. This is a simple bit-check operation and
  should be negligible.

- [ ] **Memory usage** for different group sizes.

## MLS operations

- [ ] **MLS join cost:** time for a new member to join a group (i.e., welcome
  processing time), varying group size (2, 10, 50, 200, 500, 1000, 5000 members).

- [x] **MLS rekey cost:** time to perform a group rekey (i.e., commit processing
  time) for different group sizes.

- [ ] **Memory usage** for different group sizes.

## Real-world/hardware

- [ ] **AES-GCM FPGA evaluation:** using AES-GCM FPGAs for performance evaluation.
  SRTP does very little per-packet work on top of AES-GCM (just IV formation),
  so FPGA-accelerated AES-GCM throughput would be a representative measurement
  of real hardware-offloaded SRTP performance.

## Extras

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

- [ ] **Sender-side inbound SRTCP state memory:** the `srtp` crate supports SRTCP via
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
