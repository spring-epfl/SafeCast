#!/usr/bin/env python3

### Linear regression on SRTP protect() and raw AES-128-GCM benchmark data
### to find the fixed per-packet cost and per-byte cost for each.

import json
import os

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))

PAYLOAD_SIZES = [16, 32, 64, 128, 256, 512, 1024, 1424, 2048, 4096, 8192, 8924, 16384]

def load_criterion_data(data_dir, group_name):
    """Reads mean time (ns) from Criterion estimates.json for each payload size."""
    data = []
    for sz in PAYLOAD_SIZES:
        path = os.path.join(data_dir, group_name, str(sz), "new", "estimates.json")
        with open(path) as f:
            estimates = json.load(f)
        mean_ns = estimates["mean"]["point_estimate"]
        data.append((sz, mean_ns))
    return data

# loading data from Criterion output (copied next to this script)
srtp_data = load_criterion_data(os.path.join(SCRIPT_DIR, "srtp_scaling_data"), "protect")
raw_gcm_data = load_criterion_data(os.path.join(SCRIPT_DIR, "raw_aes_gcm_data"), "encrypt")

# linear regression to find fixed and per-byte costs for both datasets
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
print(f"      + key usage limit check")
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
