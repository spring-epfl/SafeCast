# Key Derivation Benchmark Results

Results from `key_derivation.rs`, which benchmarks the two-stage key
derivation pipeline that turns an MLS epoch secret into SRTP session keys:
MLS key export (HKDF) followed by the SRTP KDF (AES-128-CTR).

Both stages run once at session setup and again on each MLS epoch change
(rekey). Neither runs per packet.

## MLS key export

Two calls to the MLS exporter via HKDF derive the 16-byte SRTP master key
and 12-byte master salt from the epoch secret. 
This is discussed in `mls_rekey/results.md`: the cost is
constant across group sizes at ~4.2 µs.

## SRTP KDF

| Operation                                    | Latency  |
|----------------------------------------------|----------|
| 4 x AES-128-CTR keystream (RFC 3711 §4.3.1)  | 874 ns   |

The SRTP KDF derives four session keys from the master key material:
RTP cipher key (16 B), RTP salt (12 B), RTCP cipher key (16 B), and
RTCP salt (12 B). Benchmarked via a C FFI call to code extracted from
libsrtp2's `srtp_stream_init_keys()`.

## Full pipeline (MLS export + SRTP KDF)

| Operation              | Latency  |
|------------------------|----------|
| export + KDF combined  | 5.12 µs  |

The MLS exporter dominates at ~80% of the total cost. At 5.12 µs per
epoch change, key derivation is negligible compared to the MLS commit
processing that triggers it (271 µs for a 2-member group).

## Reproduction

```
cargo bench --package mls-srtp-core --bench key_derivation
```
