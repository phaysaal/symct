#!/usr/bin/env python3

"""Run all available benchmark tests as a smoke test."""

import argparse
import os
import re
import subprocess
import sys
import time
from collections import defaultdict

# Algorithm -> nature prefix mapping
NATURE_MAP = {
    "rsa_decrypt":  "rsa",
    "rsa_sign":     "rsa",
    "rsa_keygen":   "rsa_keygen",
    "ecdsa_sign":   "ecdsa",
    "ecdsa_keygen": "ec_keygen",
    "eddsa_sign":   "eddsa",
    "eddsa_keygen": "ed_keygen",
}


def parse_library_dir(dirname):
    """Parse 'openssl-O2' into ('openssl', 'O2') or 'bearssl-O0' into ('bearssl', 'O0')."""
    parts = dirname.split("-", 1)
    if len(parts) == 2:
        return parts[0], parts[1]
    return parts[0], ""


def find_all_tests(root):
    """Scan benchmark directory and match with available nature configs."""
    benchmark_dir = os.path.join(root, "benchmark", "32")
    binsec_dir = os.path.join(root, "binsec", "32")
    tests = []

    if not os.path.exists(benchmark_dir):
        return tests

    for lib_dir in sorted(os.listdir(benchmark_dir)):
        lib_path = os.path.join(benchmark_dir, lib_dir)
        if not os.path.isdir(lib_path):
            continue

        library, optimization = parse_library_dir(lib_dir)

        for algo in sorted(os.listdir(lib_path)):
            src_path = os.path.join(lib_path, algo, "src")
            if not os.path.isdir(src_path):
                continue

            prefix = NATURE_MAP.get(algo)
            if not prefix:
                continue

            nature = f"{prefix}_{library}"
            ini_path = os.path.join(binsec_dir, f"{nature}.ini")

            if not os.path.exists(ini_path):
                continue

            tests.append({
                "library": library,
                "algorithm": algo,
                "nature": nature,
                "optimization": optimization,
                "label": f"{lib_dir}/{algo}",
            })

    return tests


LEAK_RE = re.compile(
    r'\[checkct:result\]\s+Instruction\s+(0x[0-9a-fA-F]+)\s+has\s+(.+?)\s+leak\s+\(([0-9.]+)s\)'
)


def parse_leaks(log_file):
    """Parse a binsec log file for leak lines. Returns list of (address, leak_type)."""
    leaks = []
    try:
        with open(log_file, 'r') as f:
            for line in f:
                m = LEAK_RE.search(line)
                if m:
                    leaks.append((m.group(1), m.group(2)))
    except (OSError, IOError):
        pass
    return leaks


def get_log_path(test, root, platform="32"):
    """Construct the expected log file path for a test."""
    library_str = test["library"]
    if test["optimization"]:
        library_str = f"{test['library']}-{test['optimization']}"
    return os.path.join(
        root, "results", platform, library_str,
        test["algorithm"], f"{test['nature']}_0.log"
    )


def print_leak_summary(tests, root, results):
    """Parse logs and print a leak analysis summary."""
    # Categorize tests
    completed = []
    failures = []
    for t, (label, success, elapsed, cmd_str) in zip(tests, results):
        if success:
            completed.append(t)
        else:
            # Check if a log file exists (ran but failed vs build failure)
            log_path = get_log_path(t, root)
            if os.path.exists(log_path) and os.path.getsize(log_path) > 0:
                completed.append(t)
            else:
                failures.append(t)

    # Parse leaks from all completed tests
    # Track by library and algorithm
    leaks_by_library = defaultdict(lambda: defaultdict(int))
    leaks_by_algorithm = defaultdict(lambda: defaultdict(int))
    total_leaks = 0

    # Collect all libraries and algorithms seen
    all_libraries = sorted(set(t["library"] for t in tests))
    all_algorithms = sorted(set(t["algorithm"] for t in tests))

    for t in completed:
        log_path = get_log_path(t, root)
        leaks = parse_leaks(log_path)
        for addr, leak_type in leaks:
            leaks_by_library[t["library"]][leak_type] += 1
            leaks_by_algorithm[t["algorithm"]][leak_type] += 1
            total_leaks += 1

    # Collect all leak types seen
    all_leak_types = sorted(set(
        lt for counts in list(leaks_by_library.values()) + list(leaks_by_algorithm.values())
        for lt in counts
    ))
    if not all_leak_types:
        all_leak_types = ["control flow", "memory access"]

    # Print summary
    print()
    print("=" * 62)
    print("LEAK ANALYSIS SUMMARY")
    print("=" * 62)
    print(f"Primitives checked: {len(tests)}")
    print(f"  - Completed (reached timeout or finished): {len(completed)}")
    print(f"  - Build/run failures: {len(failures)}")

    print()
    print("Leaks by library:")
    for lib in all_libraries:
        counts = leaks_by_library[lib]
        parts = [f"{counts.get(lt, 0)} {lt}" for lt in all_leak_types]
        lib_total = sum(counts.values())
        print(f"  {lib:12s}: {', '.join(parts)}  ({lib_total} total)")

    print()
    print("Leaks by algorithm:")
    for algo in all_algorithms:
        counts = leaks_by_algorithm[algo]
        if not counts:
            continue
        parts = [f"{counts.get(lt, 0)} {lt}" for lt in all_leak_types]
        print(f"  {algo:14s}: {', '.join(parts)}")

    print()
    print(f"Total: {total_leaks} leaks across {len(tests)} primitives")
    print("=" * 62)


def run_test(test, root, timeout, memlimit):
    """Run a single test and return (label, success, elapsed)."""
    cmd = [
        sys.executable, os.path.join(root, "runbench.py"),
        test["library"], test["algorithm"], test["nature"],
        "--root", root,
        "--bn",
        "--timeout", str(timeout),
        "--memlimit", str(memlimit),
    ]

    if test["optimization"]:
        cmd += ["--optimization", test["optimization"]]

    cmd_str = " ".join(cmd)
    start = time.time()

    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout + 60)
        elapsed = time.time() - start
        return test["label"], result.returncode == 0, elapsed, cmd_str
    except subprocess.TimeoutExpired:
        elapsed = time.time() - start
        return test["label"], False, elapsed, cmd_str


def main():
    parser = argparse.ArgumentParser(description="Run all benchmark tests")
    parser.add_argument("--timeout", type=int, default=120, help="Timeout per test in seconds (default: 120)")
    parser.add_argument("--memlimit", type=int, default=16384, help="Memory limit in MB (default: 16384)")
    parser.add_argument("--root", type=str, default=".", help="Project root directory")
    parser.add_argument("--library", type=str, action="append", default=None,
                        help="Filter by library (e.g. --library wolfssl). Comma-separated or repeated.")
    parser.add_argument("--dry-run", action="store_true", help="List tests without running")
    args = parser.parse_args()

    root = os.path.abspath(args.root)
    tests = find_all_tests(root)

    if args.library:
        # Flatten comma-separated values: --library wolfssl,openssl --library bearssl
        allowed = set()
        for item in args.library:
            for lib in item.split(","):
                lib = lib.strip()
                if lib:
                    allowed.add(lib)
        tests = [t for t in tests if t["library"] in allowed]

    if not tests:
        print("[ERROR] No tests found", file=sys.stderr)
        sys.exit(1)

    print(f"[INFO] Found {len(tests)} tests (timeout={args.timeout}s, memlimit={args.memlimit}MB)")
    print("=" * 60)

    if args.dry_run:
        for t in tests:
            opt = f" --optimization {t['optimization']}" if t["optimization"] else ""
            print(f"  {t['label']:40s} -> {t['nature']}{opt}")
        return

    passed = 0
    failed = 0
    results = []

    for i, t in enumerate(tests):
        label = t["label"]
        print(f"[{i+1}/{len(tests)}] {label} ... ", end="", flush=True)

        label, success, elapsed, cmd_str = run_test(t, root, args.timeout, args.memlimit)

        if success:
            print(f"OK ({elapsed:.0f}s)")
            passed += 1
        else:
            print(f"FAIL ({elapsed:.0f}s)")
            failed += 1

        results.append((label, success, elapsed, cmd_str))

    print("=" * 60)
    print(f"[SUMMARY] {passed} passed, {failed} failed, {len(tests)} total")

    if failed > 0:
        print("\nFailed tests:")
        for label, success, elapsed, cmd_str in results:
            if not success:
                print(f"  - {label}")
                print(f"    {cmd_str}")

    print_leak_summary(tests, root, results)

    if failed > 0:
        sys.exit(1)


if __name__ == "__main__":
    main()
