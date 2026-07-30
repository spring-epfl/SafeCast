# Granularity Throughput Benchmark Results
Results from `granularity_throughput_ideal.rs`: data-plane `protect` (encrypt) and `unprotect` (decrypt) throughput for the three keying granularities (epoch-only / frame-level / packet-level) across a payload sweep.
**Machine:** Apple M2 (8 cores), 16 GB, macOS 26.3.1. Single-threaded, Criterion `iter_custom` timing only the SRTP call (which, for frame/packet, includes the ratchet + in-place rekey when a generation boundary is crossed). 10 s measurement per point.
**Reading the numbers.** Throughput is *per-core, single-stream*, derived from per-packet latency (the workload is serial: one SSRC's packets are produced in order, in real time). It is a conservative floor; aggregate multi-core throughput is a separate question not measured here. Gbps is over the SRTP packet (12 B RTP header + payload + 16 B GCM tag).
## How the granularities differ
- **epoch-only:** never rekeys within the epoch (baseline, just `protect`).
- **frame-level:** rekeys once per frame (on RTP-timestamp change), so one rekey is amortized over all packets of that frame.
- **packet-level:** rekeys every packet.

Frame model: packets per frame = FRAME_BYTES / payload, with FRAME_BYTES = one uncompressed 1080p 10-bit 4:2:2 frame (1920x1080x2.5 = 5,184,000 B).
## protect (encrypt)
| Payload (B) | epoch ns | frame ns | packet ns | epoch Gbps | packet Gbps | rekey tax ns | packet/epoch |
|---|---|---|---|---|---|---|---|
| 16 | 106 | 108 | 830 | 3.33 | 0.42 | 724 | 7.85x |
| 32 | 109 | 111 | 833 | 4.41 | 0.58 | 724 | 7.64x |
| 40 | 111 | 111 | 831 | 4.92 | 0.65 | 720 | 7.51x |
| 64 | 112 | 110 | 848 | 6.57 | 0.87 | 736 | 7.57x |
| 128 | 121 | 121 | 862 | 10.33 | 1.45 | 741 | 7.14x |
| 160 (speech) | 129 | 131 | 858 | 11.68 | 1.75 | 730 | 6.67x |
| 256 | 143 | 144 | 873 | 15.90 | 2.60 | 730 | 6.11x |
| 512 | 162 | 161 | 891 | 26.60 | 4.85 | 729 | 5.49x |
| 800 (video) | 189 | 189 | 912 | 35.09 | 7.27 | 723 | 4.83x |
| 1024 | 217 | 215 | 947 | 38.77 | 8.89 | 730 | 4.36x |
| 1200 (video) | 231 | 231 | 951 | 42.50 | 10.33 | 719 | 4.11x |
| 1424 (ST2110 std) | 255 | 255 | 975 | 45.56 | 11.92 | 720 | 3.82x |
| 2048 | 323 | 321 | 1066 | 51.48 | 15.58 | 743 | 3.30x |
| 4096 | 534 | 536 | 1259 | 61.80 | 26.20 | 725 | 2.36x |
| 8924 (ST2110 jumbo) | 1038 | 1042 | 1762 | 68.99 | 40.64 | 724 | 1.70x |

## unprotect (decrypt)
| Payload (B) | epoch ns | frame ns | packet ns | epoch Gbps | packet Gbps | rekey tax ns | packet/epoch |
|---|---|---|---|---|---|---|---|
| 16 | 128 | 129 | 874 | 2.75 | 0.40 | 746 | 6.82x |
| 32 | 130 | 130 | 877 | 3.70 | 0.55 | 747 | 6.77x |
| 40 | 131 | 132 | 878 | 4.15 | 0.62 | 747 | 6.70x |
| 64 | 128 | 129 | 883 | 5.73 | 0.83 | 755 | 6.88x |
| 128 | 137 | 138 | 897 | 9.09 | 1.39 | 759 | 6.53x |
| 160 (speech) | 147 | 147 | 913 | 10.23 | 1.65 | 766 | 6.21x |
| 256 | 163 | 164 | 903 | 13.92 | 2.52 | 740 | 5.53x |
| 512 | 198 | 199 | 929 | 21.78 | 4.65 | 730 | 4.68x |
| 800 (video) | 229 | 232 | 961 | 28.91 | 6.89 | 732 | 4.19x |
| 1024 | 248 | 255 | 986 | 33.95 | 8.54 | 738 | 3.98x |
| 1200 (video) | 268 | 274 | 1000 | 36.65 | 9.82 | 732 | 3.73x |
| 1424 (ST2110 std) | 295 | 301 | 1031 | 39.35 | 11.27 | 736 | 3.49x |
| 2048 | 356 | 360 | 1111 | 46.70 | 14.95 | 755 | 3.12x |
| 4096 | 596 | 583 | 1350 | 55.33 | 24.45 | 753 | 2.26x |
| 8924 (ST2110 jumbo) | 1178 | 1176 | 1902 | 60.77 | 37.66 | 723 | 1.61x |

## Key findings
**1. Frame-level is essentially free.** Across every size frame-level matches epoch-only within measurement noise (the per-frame rekey is amortized over thousands of packets). The two curves are interchangeable.

**2. Packet-level adds a flat per-packet tax.** The rekey (ratchet's two HKDF-Expands + the AES key install) costs a near-constant ~728 ns/packet on encrypt (range 719-743 ns) and ~744 ns/packet on decrypt, independent of payload size - consistent with the M1 ratchet-step microbenchmark.

**3. The tax is a per-packet cost, so it bites hardest on small packets.** Because the rekey is fixed while the crypto scales with size, packet-level is 7.8x slower than epoch at 16 B but only 1.7x at 8924 B. The cost is driven by packets-per-second, not bitrate.

## Crossover: can packet-level keep up with a video stream?
Required ST 2110-20 media bitrates (uncompressed 10-bit 4:2:2, 60 fps) vs the smallest payload size at which **packet-level** sustains them (epoch-only and frame-level sustain all of these at any size in the sweep where the stream's own packet size lands):

| Format | Required Gbps | packet-level OK from (encrypt) | packet-level OK from (decrypt) |
|---|---|---|---|
| 720p60 | 1.11 | >= 128 B | >= 128 B |
| 1080p60 | 2.49 | >= 256 B | >= 256 B |
| 2160p60 (4K) | 9.95 | >= 1200 (video) B | >= 1424 (ST2110 std) B |
| 4320p60 (8K) | 39.81 | >= 8924 B (jumbo only) | never sustained in sweep (37.7 Gbps at jumbo) |

**Interpretation.** Packet-level comfortably sustains 1080p60 and 4K60 at realistic MTU-sized packets, but only because those packets are large; shrink the packets (more packets/sec) and packet-level falls behind first. 8K60 sits at the edge of a single core for packet-level (needs jumbo frames, and decrypt barely misses it), while epoch-only and frame-level clear it with headroom. So the price of per-packet forward secrecy is real only at the high end (8K, or unusually small packets); for everything up to 4K60 it is affordable on one core, and frame-level forward secrecy is effectively free everywhere.
