#!/usr/bin/env python3

### Comparing SRTP protect() vs raw AES-128-GCM to isolate the fixed cost.

# SRTP protect() data (from srtp_scaling benchmark)
srtp_data = [
    (16,    252.07),
    (32,    255.25),
    (64,    256.71),
    (128,   273.15),
    (256,   288.65),
    (512,   305.98),
    (1024,  361.32),
    (1424,  400.16),
    (2048,  466.45),
    (4096,  686.95),
    (8192,  1110.8),
    (8924,  1192.5),
    (16384, 1968.7),
]

# Raw AES-128-GCM data (from aes_gcm_baseline benchmark)
raw_gcm_data = [
    (16,    91.78),
    (32,    93.81),
    (64,    97.58),
    (128,   106.85),
    (256,   129.58),
    (512,   146.91),
    (1024,  201.11),
    (1424,  242.17),
    (2048,  307.41),
    (4096,  520.73),
    (8192,  947.51),
    (8924,  1070.5),
    (16384, 1801.8),
]

# Linear regression to find fixed and per-byte costs for both datasets.
def linreg(data):
    n = len(data)
    sx = sum(p for p, _ in data)
    sy = sum(t for _, t in data)
    sxy = sum(p * t for p, t in data)
    sxx = sum(p * p for p, _ in data)
    slope = (n * sxy - sx * sy) / (n * sxx - sx * sx)
    intercept = (sy - slope * sx) / n
    return intercept, slope

s_fix, s_byte = linreg(srtp_data)
r_fix, r_byte = linreg(raw_gcm_data)

print("=" * 75)
print("Linear model: time = fixed + per_byte x payload_size")
print("=" * 75)
print(f"  {'Method':<25}  {'Fixed (ns)':>12}  {'Per-byte (ns)':>14}  {'Max throughput':>14}")
print(f"  {'-'*25}  {'-'*12}  {'-'*14}  {'-'*14}")
print(f"  {'Raw AES-GCM':<25}  {r_fix:>10.1f}    {r_byte:>12.4f}    {8/r_byte:>10.1f} Gbps")
print(f"  {'SRTP protect()':<25}  {s_fix:>10.1f}    {s_byte:>12.4f}    {8/s_byte:>10.1f} Gbps")

print()
print("=" * 75)
print("Cost breakdown")
print("=" * 75)
print()
print(f"  Raw AES-GCM fixed cost:      {r_fix:.1f} ns")
print(f"    = loading the new 12-byte IV into the cipher context")
print(f"      + feeding the 12-byte RTP header as authenticated-but-not-encrypted data")
print(f"      + computing the 16-byte authentication tag from the GHASH state")
print()
print(f"  SRTP overhead over raw GCM:  {s_fix - r_fix:.1f} ns")
print(f"    = looking up the SRTP stream by SSRC")
print(f"      + replay protection check")
print(f"      + constructing the IV from SSRC, packet index, and salt")
print(f"      + Rust-to-C FFI")
print()
print(f"  Per-byte costs are nearly identical: {r_byte:.4f} vs {s_byte:.4f} ns/byte")
print(f"    -> confirms the per-byte cost is pure AES-GCM encryption")

print()
print("=" * 75)
print("Side-by-side comparison")
print("=" * 75)
print(f"  {'Payload':>8}  |  {'Raw GCM':>10}  |  {'SRTP':>10}  |  {'SRTP overhead':>14}")
print(f"  {'':>8}  |  {'(ns)':>10}  |  {'(ns)':>10}  |  {'(ns)':>14}")
print(f"  {'-'*8}--+--{'-'*10}--+--{'-'*10}--+--{'-'*14}")

for (sz, st), (_, rt) in zip(srtp_data, raw_gcm_data):
    diff = st - rt
    print(f"  {sz:>6} B  |  {rt:>10.1f}  |  {st:>10.1f}  |  {diff:>+14.1f}")
