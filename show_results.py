#!/usr/bin/env python3
"""
Display auto-mode JSON result files as formatted tables.

Usage:
  python show_results.py results/32/openssl-O3/rsa_decrypt/*.json
  python show_results.py results/32/**/*.json
  python show_results.py results/32/**/*.json --summary
"""

import argparse
import json
import glob
import os
import sys


def load_results(paths):
    """Load JSON result files, expanding globs."""
    results = []
    for p in paths:
        expanded = glob.glob(p, recursive=True)
        if not expanded:
            expanded = [p]
        for fp in expanded:
            try:
                with open(fp) as f:
                    data = json.load(f)
                data["_file"] = fp
                results.append(data)
            except (json.JSONDecodeError, OSError) as e:
                print(f"Warning: skipping {fp}: {e}", file=sys.stderr)
    return results


def print_detail(data):
    """Print detailed table for a single result."""
    lib = data.get("library", "?")
    prim = data.get("primitive", "?")
    opt = data.get("optimization", "")
    nature = data.get("nature", "?")
    platform = data.get("platform", "?")
    timeout = data.get("timeout", "?")
    keylen = data.get("keylen", "?")

    label = f"{lib}-{opt}" if opt else lib
    print(f"{'═'*62}")
    print(f"  {label} / {prim}  (nature={nature}, platform={platform})")
    print(f"  timeout={timeout}s  keylen={keylen}")
    print(f"{'═'*62}")

    iterations = data.get("iterations", [])
    if iterations:
        print(f"  {'Phase':<20s} {'Alerts':>8s} {'Unique':>8s} {'Stubs':>8s} {'BN Hook':>8s}  Log")
        print(f"  {'─'*78}")
        for it in iterations:
            phase = it.get("phase", "?")
            alerts = it.get("alerts", 0)
            unique = it.get("unique_alerts", 0)
            stubs = it.get("stubs", 0)
            hooked_bn = it.get("hooked_bn", 0)
            log = os.path.basename(it.get("log_file", ""))
            print(f"  {phase:<20s} {alerts:>8d} {unique:>8d} {stubs:>8d} {hooked_bn:>8d}  {log}")

    merged = data.get("unique_alerts", {})
    if merged:
        print(f"  {'─'*78}")
        print(f"  {'Merged Unique':}")
        for key in ["no_stub", "allstubs", "progressive", "final"]:
            val = merged.get(key)
            if val is not None:
                label_map = {
                    "no_stub": "No Stub (iter 0)",
                    "allstubs": "All Stubs",
                    "progressive": "Progressive (all)",
                    "final": "Final",
                }
                print(f"    {label_map.get(key, key):<25s} {val:>8d}")
    print()


def print_summary(results):
    """Print a summary table across all results."""
    if not results:
        return

    # Group by library
    by_library = {}
    for data in results:
        lib = data.get("library", "?")
        if lib not in by_library:
            by_library[lib] = []
        by_library[lib].append(data)

    # Collect all optimizations
    all_opts = sorted(set(d.get("optimization", "") for d in results))
    if not all_opts or all_opts == [""]:
        all_opts = [""]

    phases = ["no_stub", "allstubs", "progressive", "final"]
    phase_labels = {
        "no_stub": "NoStub",
        "allstubs": "AllStub",
        "progressive": "Prog",
        "final": "Final",
    }

    for lib in sorted(by_library):
        lib_results = by_library[lib]
        primitives = sorted(set(d.get("primitive", "?") for d in lib_results))

        # Build column headers
        col_headers = []
        for opt in all_opts:
            opt_label = opt if opt else "def"
            for p in phases:
                col_headers.append(f"{opt_label}-{phase_labels[p]}")

        col_w = max(len(h) for h in col_headers)
        col_w = max(col_w, 6)
        prim_w = max((len(p) for p in primitives), default=10)
        prim_w = max(prim_w, len("Primitive"))

        print(f"{'═'*62}")
        print(f"  SUMMARY: {lib}  (unique alerts)")
        print(f"{'═'*62}")

        header = f"  {'Primitive':<{prim_w}}"
        for h in col_headers:
            header += f"  {h:>{col_w}}"
        print(header)
        print(f"  {'─' * (len(header) - 2)}")

        for prim in primitives:
            row = f"  {prim:<{prim_w}}"
            for opt in all_opts:
                # Find matching result
                match = None
                for d in lib_results:
                    if d.get("primitive") == prim and d.get("optimization", "") == opt:
                        match = d
                        break
                merged = match.get("unique_alerts", {}) if match else {}
                for p in phases:
                    val = merged.get(p)
                    cell = str(val) if val is not None else "-"
                    row += f"  {cell:>{col_w}}"
            print(row)

        print(f"  {'─' * (len(header) - 2)}")
        print()


def main():
    parser = argparse.ArgumentParser(
        description="Display auto-mode JSON result files as formatted tables"
    )
    parser.add_argument("files", nargs="+", help="JSON result files (globs supported)")
    parser.add_argument("--summary", action="store_true",
                        help="Show summary table only (one row per primitive)")
    args = parser.parse_args()

    results = load_results(args.files)
    if not results:
        print("No result files found.", file=sys.stderr)
        sys.exit(1)

    # Sort by library, optimization, primitive
    results.sort(key=lambda d: (
        d.get("library", ""),
        d.get("optimization", ""),
        d.get("primitive", ""),
    ))

    if args.summary:
        print_summary(results)
    else:
        for data in results:
            print_detail(data)
        if len(results) > 1:
            print_summary(results)


if __name__ == "__main__":
    main()
