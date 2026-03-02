#!/usr/bin/env python3

"""Run all available benchmark tests as a smoke test."""

import argparse
import os
import subprocess
import sys
import time

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
    parser.add_argument("--dry-run", action="store_true", help="List tests without running")
    args = parser.parse_args()

    root = os.path.abspath(args.root)
    tests = find_all_tests(root)

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
        sys.exit(1)


if __name__ == "__main__":
    main()
