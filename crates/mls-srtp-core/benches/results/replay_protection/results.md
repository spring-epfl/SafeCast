# SRTP Replay-Protection Benchmark Results

Results from `replay_protection.rs`: the cost of libsrtp rejecting a
duplicate (replayed) SRTP packet via its replay window (RFC 3711 §3.3.2).
The rejection happens before any decryption: header parse, stream lookup,
replay-window bitmask check, error return.

**Machine:** Apple M2 (8 cores), 16 GB, macOS 26.3.1. Single-threaded,
Criterion `iter_batched` with fixed 256-clone batches: every iteration gets
a fresh clone of the ciphertext as untimed setup, and only the rejecting
`unprotect` call is timed.

**Why the fresh clone per iteration matters.** The `srtp` crate empties the
buffer on any failed `unprotect` (`buf.set_len(0)` on the error path), so a
rejected buffer cannot be fed in again: the second attempt would measure
"reject a zero-length buffer"
(https://github.com/cisco/libsrtp/blob/6e23ad8d971209e152ef4aa5349be9969e108d14/srtp/srtp.c#L313).

## reject_replay

| Payload                    | mean ns | std ns |
|----------------------------|---------|--------|
| 40 B (audio speech)        |    7.02 |   0.07 |
| 160 B (audio music)        |    7.12 |   0.36 |
| 800 B (video fragment)     |    7.21 |   0.15 |
| 1200 B (video fragment)    |    7.35 |   0.13 |
| 1424 B (ST 2110 standard)  |    7.33 |   0.11 |
| 8924 B (ST 2110 jumbo)     |    7.18 |   0.14 |

## Reading the numbers

- The rejection cost is size-independent, as it must be: the path never
  touches the payload. All six sizes agree within ~0.3 ns.
- A replay rejection costs ~7 ns, so about 2.5% of a 1424 B decrypt
  (~290 ns).
- What that means practically: suppose an attacker floods the receiver
  with duplicate packets, each costing 7 ns to reject. How bad can it get?
  The flood is limited by the network: a 100 Gbps link (typical ST 2110
  facility fabric) carries at most ~8.5 million packets of 1424 B per
  second. Rejecting all of them costs 8,500,000 x 7 ns = ~60 ms of work
  per second, so the receiver is ~6% busy. Even a fully saturated
  100 Gbps link of duplicates leaves the receiver largely unbothered.