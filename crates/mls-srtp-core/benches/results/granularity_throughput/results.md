# Granularity Throughput Benchmark Results
Results from `granularity_throughput_ideal.rs`: data-plane `protect` (encrypt) and `unprotect` (decrypt) throughput for the three keying granularities (epoch-only / frame-level / packet-level) across a payload sweep.
**Machine:** Apple M2 (8 cores), 16 GB, macOS 26.3.1. Single-threaded, Criterion `iter_custom` timing only the SRTP call (which, for frame/packet, includes the ratchet + in-place rekey when a generation boundary is crossed). 10 s measurement per point.
**Reading the numbers.** Throughput is *per-core, single-stream*, derived from per-packet latency (the workload is serial: one SSRC's packets are produced in order, in real time). It is a conservative floor; aggregate multi-core throughput is a separate question not measured here. Gbps is over the SRTP packet (12 B RTP header + payload + 16 B GCM tag). All numbers are computed from the Criterion estimates in `../criterion/granularity_protect/` and `../criterion/granularity_unprotect/`.
## How the granularities differ
- **epoch-only:** never rekeys within the epoch (baseline, just `protect`).
- **frame-level:** rekeys once per frame (on RTP-timestamp change), so one rekey is amortized over all packets of that frame.
- **packet-level:** rekeys every packet.

Frame model: packets per frame = FRAME_BYTES / payload, with FRAME_BYTES = one uncompressed 1080p 10-bit 4:2:2 frame (1920x1080x2.5 = 5,184,000 B).
## protect (encrypt)
| Payload (B) | epoch ns | frame ns | packet ns | epoch Gbps | packet Gbps | rekey tax ns | packet/epoch |
|---|---|---|---|---|---|---|---|
| 16 | 106 | 107 | 834 | 3.33 | 0.42 | 729 | 7.89x |
| 32 | 109 | 109 | 839 | 4.41 | 0.57 | 730 | 7.70x |
| 40 | 110 | 110 | 842 | 4.95 | 0.65 | 732 | 7.66x |
| 64 | 111 | 110 | 844 | 6.66 | 0.87 | 733 | 7.64x |
| 128 | 119 | 120 | 853 | 10.48 | 1.46 | 734 | 7.16x |
| 160 (speech) | 130 | 129 | 864 | 11.57 | 1.74 | 734 | 6.65x |
| 256 | 142 | 143 | 878 | 16.02 | 2.59 | 737 | 6.19x |
| 512 | 165 | 160 | 915 | 26.24 | 4.72 | 750 | 5.56x |
| 800 (video) | 187 | 188 | 916 | 35.38 | 7.23 | 729 | 4.89x |
| 1024 | 213 | 218 | 961 | 39.43 | 8.76 | 747 | 4.50x |
| 1200 (video) | 229 | 231 | 956 | 42.92 | 10.28 | 727 | 4.18x |
| 1424 (ST2110 std) | 259 | 254 | 995 | 44.81 | 11.68 | 736 | 3.84x |
| 2048 | 320 | 322 | 1055 | 51.92 | 15.75 | 735 | 3.30x |
| 4096 | 533 | 543 | 1275 | 61.88 | 25.88 | 742 | 2.39x |
| 8924 (ST2110 jumbo) | 1037 | 1040 | 1772 | 69.05 | 40.41 | 735 | 1.71x |

## unprotect (decrypt)
| Payload (B) | epoch ns | frame ns | packet ns | epoch Gbps | packet Gbps | rekey tax ns | packet/epoch |
|---|---|---|---|---|---|---|---|
| 16 | 129 | 128 | 873 | 2.73 | 0.40 | 744 | 6.77x |
| 32 | 129 | 129 | 901 | 3.73 | 0.53 | 772 | 7.00x |
| 40 | 131 | 131 | 886 | 4.15 | 0.61 | 755 | 6.75x |
| 64 | 128 | 128 | 883 | 5.74 | 0.83 | 754 | 6.89x |
| 128 | 138 | 137 | 898 | 9.07 | 1.39 | 760 | 6.52x |
| 160 (speech) | 145 | 146 | 897 | 10.37 | 1.68 | 752 | 6.18x |
| 256 | 162 | 163 | 903 | 13.99 | 2.52 | 741 | 5.56x |
| 512 | 196 | 198 | 930 | 22.02 | 4.64 | 734 | 4.74x |
| 800 (video) | 227 | 230 | 997 | 29.14 | 6.65 | 769 | 4.39x |
| 1024 | 244 | 248 | 990 | 34.52 | 8.50 | 746 | 4.06x |
| 1200 (video) | 267 | 268 | 998 | 36.86 | 9.84 | 732 | 3.75x |
| 1424 (ST2110 std) | 291 | 301 | 1047 | 39.93 | 11.10 | 756 | 3.60x |
| 2048 | 366 | 358 | 1092 | 45.34 | 15.21 | 726 | 2.98x |
| 4096 | 573 | 579 | 1354 | 57.61 | 24.36 | 782 | 2.36x |
| 8924 (ST2110 jumbo) | 1171 | 1175 | 1933 | 61.18 | 37.06 | 762 | 1.65x |

## Key findings
**1. Frame-level is essentially free.** Across every size frame-level matches epoch-only within measurement noise (the per-frame rekey is amortized over thousands of packets). The two curves are interchangeable.

**2. Packet-level adds a flat per-packet tax.** The rekey (ratchet's two HKDF-Expands + the AES key install) costs a near-constant ~735 ns/packet on encrypt (range 727-750 ns) and ~752 ns/packet on decrypt, independent of payload size - consistent with the ratchet_step microbenchmark.

**3. The tax is a per-packet cost, so it bites hardest on small packets.** Because the rekey is fixed while the crypto scales with size, packet-level is 7.9x slower than epoch at 16 B but only 1.7x at 8924 B. The cost is driven by packets-per-second, not bitrate.

## Crossover: can packet-level keep up with a video stream?
Required ST 2110-20 media bitrates (uncompressed 10-bit 4:2:2, 60 fps) vs the smallest payload size at which **packet-level** sustains them (epoch-only and frame-level sustain all of these at any size in the sweep where the stream's own packet size lands):

| Format | Required Gbps | packet-level OK from (encrypt) | packet-level OK from (decrypt) |
|---|---|---|---|
| 720p60 | 1.11 | >= 128 B | >= 128 B |
| 1080p60 | 2.49 | >= 256 B | >= 256 B |
| 2160p60 (4K) | 9.95 | >= 1200 (video) B | >= 1424 (ST2110 std) B |
| 4320p60 (8K) | 39.81 | >= 8924 B (jumbo only) | never sustained in sweep (37.1 Gbps at jumbo) |

**Interpretation.** Packet-level comfortably sustains 1080p60 and 4K60 at realistic MTU-sized packets, but only because those packets are large; shrink the packets (more packets/sec) and packet-level falls behind first. 8K60 sits at the edge of a single core for packet-level (needs jumbo frames, and decrypt barely misses it), while epoch-only and frame-level clear it with headroom. So the price of per-packet forward secrecy is real only at the high end (8K, or unusually small packets); for everything up to 4K60 it is affordable on one core, and frame-level forward secrecy is effectively free everywhere.
