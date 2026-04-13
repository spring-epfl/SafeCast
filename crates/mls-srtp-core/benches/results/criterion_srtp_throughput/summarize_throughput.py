#!/usr/bin/env python3
"""
Reads Criterion JSON output from the srtp_throughput benchmark and prints
a summary with throughput in Gbps and speedup relative to a target bitrate.

Usage:
    python3 crates/mls-srtp-core/benches/results/criterion_srtp_throughput/summarize_throughput.py
    python3 crates/mls-srtp-core/benches/results/criterion_srtp_throughput/summarize_throughput.py --target-gbps 2.4
"""

from __future__ import annotations

import argparse
import json
import os
import sys

CRITERION_DIR = os.path.join(
    os.path.dirname(os.path.abspath(__file__)),
    "..", "..", "..", "..", "..",
    "target",
    "criterion",
    "srtp_throughput",
    "protect",
)


def load_benchmark(bench_dir: str) -> dict | None:
    """Loads benchmark.json and estimates.json from a Criterion result directory."""
    new_dir = os.path.join(bench_dir, "new")
    bench_path = os.path.join(new_dir, "benchmark.json")
    est_path = os.path.join(new_dir, "estimates.json")
    if not os.path.exists(bench_path) or not os.path.exists(est_path):
        return None
    with open(bench_path) as f:
        bench = json.load(f)
    with open(est_path) as f:
        estimates = json.load(f)
    return {
        "label": bench["value_str"],
        "srtp_bytes": bench["throughput"]["Bytes"],
        "mean_ns": estimates["mean"]["point_estimate"],
        "std_ns": estimates["std_dev"]["point_estimate"],
    }


def format_bits(bps: float) -> str:
    if bps >= 1e9:
        return f"{bps / 1e9:.3f} Gbps"
    elif bps >= 1e6:
        return f"{bps / 1e6:.3f} Mbps"
    else:
        return f"{bps / 1e3:.3f} kbps"


def main() -> int:
    parser = argparse.ArgumentParser(description="Summarize srtp_throughput Criterion results")
    parser.add_argument(
        "--target-gbps",
        type=float,
        default=2.4,
        help="target bitrate in Gbps (default: 2.4)",
    )
    args = parser.parse_args()

    if not os.path.isdir(CRITERION_DIR):
        print(
            "no Criterion results found. Run the benchmark first:\n"
            "  cargo bench --package mls-srtp-core --bench srtp_throughput",
            file=sys.stderr,
        )
        return 1

    # discovering all benchmark subdirectories
    entries = sorted(
        d for d in os.listdir(CRITERION_DIR)
        if os.path.isdir(os.path.join(CRITERION_DIR, d)) and d != "report"
    )

    if not entries:
        print("no benchmark results found", file=sys.stderr)
        return 1

    target_bps = args.target_gbps * 1e9

    print(f"═══ Summary (target: {args.target_gbps:.1f} Gbps) ═══")

    for entry in entries:
        data = load_benchmark(os.path.join(CRITERION_DIR, entry))
        if data is None:
            print(f"  {entry}: no data")
            continue

        # throughput = srtp_bytes * 8 bits / mean_ns nanoseconds
        # gives bits per nanosecond, we multiply by 1e9 to get bits per second
        throughput_bps = (data["srtp_bytes"] * 8) / data["mean_ns"] * 1e9
        speedup = throughput_bps / target_bps

        print(
            f"  {data['label']}: {format_bits(throughput_bps)} "
            f"| speedup x{speedup:.2f} "
            f"(mean {data['mean_ns']:.1f} ns/pkt, std {data['std_ns']:.1f} ns)"
        )

    return 0


if __name__ == "__main__":
    sys.exit(main())
