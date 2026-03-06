#!/usr/bin/env python3

"""Run all available benchmark tests as a smoke test."""

import argparse
import gzip
import os
import re
import subprocess
import sys
import time
from collections import defaultdict

# Algorithm -> nature prefix mapping
NATURE_MAP = {
    "rsa_decrypt":  "rsa",
    "rsa_decrypt_oaep": "rsa",
    "rsa_sign":     "rsa",
    "rsa_keygen":   "rsa_keygen",
    "ecdsa_sign":   "ecdsa",
    "ecdsa_keygen": "ec_keygen",
    "eddsa_sign":   "eddsa",
    "eddsa_keygen": "ed_keygen",
}

# Algorithm -> progressive directory name mapping
# The progressive dir lives under binsec/<platform>/<library>/<progressive>/
PROGRESSIVE_MAP = {
    "rsa_decrypt":      "rsa",
    "rsa_decrypt_oaep": "rsa",
    "rsa_sign":         "rsa",
    "rsa_keygen":       "keygen",
    "ecdsa_sign":       "ecdsa",
    "ecdsa_keygen":     "keygen",
    "eddsa_sign":       "eddsa",
    "eddsa_keygen":     "keygen",
}

# Library-specific overrides for PROGRESSIVE_MAP
PROGRESSIVE_OVERRIDES = {
    ("ecdsa_keygen", "mbedtls"): "eckeygen",
}


def get_progressive_dir(algo, library):
    """Return the progressive directory name for a given algorithm and library."""
    override = PROGRESSIVE_OVERRIDES.get((algo, library))
    if override:
        return override
    return PROGRESSIVE_MAP.get(algo, "")


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
    """Parse a binsec log file for leak lines. Returns list of (address, leak_type).

    Handles both plain and gzip-compressed (.gz) log files.
    """
    leaks = []
    # Try .gz version if plain file doesn't exist
    if not os.path.exists(log_file) and os.path.exists(log_file + ".gz"):
        log_file = log_file + ".gz"
    try:
        opener = gzip.open if log_file.endswith(".gz") else open
        with opener(log_file, 'rt') as f:
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


def print_leak_summary(tests, root, results, merged_files=None, individual_leaks=None):
    """Parse logs and print a leak analysis summary with file paths."""
    if merged_files is None:
        merged_files = {}
    if individual_leaks is None:
        individual_leaks = {}

    # Categorize tests
    completed = []
    failures = []
    for t, (label, success, elapsed, cmd_str) in zip(tests, results):
        if success:
            completed.append(t)
        else:
            # Check if a log file exists (ran but failed vs build failure)
            log_path = get_log_path(t, root)
            gz_path = log_path + ".gz"
            if (os.path.exists(log_path) and os.path.getsize(log_path) > 0) or \
               (os.path.exists(gz_path) and os.path.getsize(gz_path) > 0):
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

    # Track per-test leak counts for file listing
    test_leak_counts = {}

    for t in completed:
        log_path = get_log_path(t, root)
        leaks = parse_leaks(log_path)
        test_leak_counts[t["label"]] = len(leaks)
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

    # Print merged report paths per library
    if merged_files:
        print()
        print("Merged source-level reports (unique alerts per library):")
        for lib in all_libraries:
            if lib in merged_files:
                print(f"  {lib:12s}: {merged_files[lib]}")

    # Print detailed file listing
    print()
    print("Detailed output files:")
    for t in tests:
        label = t["label"]
        log_path = get_log_path(t, root)
        # Show .gz path if compressed
        display_path = log_path + ".gz" if not os.path.exists(log_path) and os.path.exists(log_path + ".gz") else log_path
        n_leaks = test_leak_counts.get(label, 0)
        if os.path.exists(display_path):
            leaks_path = individual_leaks.get(label)
            if leaks_path:
                print(f"  {label:40s}  log: {display_path}")
                print(f"  {'':40s}  leaks: {leaks_path}  ({n_leaks} leaks)")
            elif n_leaks > 0:
                print(f"  {label:40s}  log: {display_path}  ({n_leaks} leaks)")
            else:
                print(f"  {label:40s}  log: {display_path}")

    print("=" * 62)


def get_binary_path(test, root, platform="32"):
    """Construct the debug binary path (non-.core) for a test."""
    library_str = test["library"]
    if test["optimization"]:
        library_str = f"{test['library']}-{test['optimization']}"
    algo = test["algorithm"]
    return os.path.join(
        root, "benchmark", platform, library_str, algo, "bin",
        f"{algo}_{library_str}_{platform}"
    )


def compress_log(log_file):
    """Compress a log file with gzip in a background process. Returns the Popen object."""
    gz_path = log_file + ".gz"
    try:
        proc = subprocess.Popen(
            ["gzip", "-f", log_file],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
        return proc
    except Exception as e:
        print(f"  [WARN] gzip failed for {os.path.basename(log_file)}: {e}", file=sys.stderr)
        return None


def run_callstack2source(log_file, binary_path, output_file):
    """Run callstack2source.py to generate a .leaks report from a binsec log."""
    script_dir = os.path.dirname(os.path.abspath(__file__))
    callstack2source = os.path.join(script_dir, "callstack2source.py")

    try:
        result = subprocess.run(
            [sys.executable, callstack2source, log_file, binary_path, output_file],
            capture_output=True, text=True,
        )
        if result.returncode == 0:
            return True
        else:
            print(f"  [WARN] callstack2source failed for {os.path.basename(log_file)}", file=sys.stderr)
            return False
    except Exception as e:
        print(f"  [WARN] callstack2source error: {e}", file=sys.stderr)
        return False


def run_merge_reports(leaks_files, output_file):
    """Run merge_reports.py --uniq-source to deduplicate .leaks files."""
    script_dir = os.path.dirname(os.path.abspath(__file__))
    merge_reports = os.path.join(script_dir, "merge_reports.py")

    try:
        result = subprocess.run(
            [sys.executable, merge_reports, '--uniq-source', '-o', output_file] + leaks_files,
            capture_output=True, text=True,
        )
        if result.returncode == 0:
            return True
        else:
            print(f"  [WARN] merge_reports failed", file=sys.stderr)
            return False
    except Exception as e:
        print(f"  [WARN] merge_reports error: {e}", file=sys.stderr)
        return False


def run_test(test, root, timeout, memlimit, progressive=None):
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

    if progressive is not None:
        prog_dir = progressive if progressive else get_progressive_dir(test["algorithm"], test["library"])
        if prog_dir:
            cmd += ["--progressive", prog_dir]

    cmd_str = " ".join(cmd)
    start = time.time()

    try:
        result = subprocess.run(cmd, timeout=timeout + 60)
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
    parser.add_argument("--report", type=str, default="reports",
                        help="Directory for .leaks reports and per-library merged reports (default: reports/)")
    parser.add_argument("--progressive", type=str, nargs="?", const="", default=None,
                        help="Enable progressive mode. Optionally specify a directory override.")
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
            prog = ""
            if args.progressive is not None:
                prog_dir = args.progressive if args.progressive else get_progressive_dir(t["algorithm"], t["library"])
                if prog_dir:
                    prog = f" --progressive {prog_dir}"
            print(f"  {t['label']:40s} -> {t['nature']}{opt}{prog}")
        return

    report_dir = args.report
    if report_dir:
        os.makedirs(report_dir, exist_ok=True)

    passed = 0
    failed = 0
    results = []
    individual_leaks = {}  # label -> leaks_file
    leaks_by_lib_opt = defaultdict(list)  # (library, opt) -> [leaks_file, ...]
    leaks_by_library = defaultdict(list)  # library -> [leaks_file, ...]
    compress_procs = []  # background gzip processes
    merged_files = {}  # library -> merged_file

    def get_lib_opt(test):
        """Return (library, optimization) tuple for a test."""
        return (test["library"], test["optimization"])

    def merge_lib_opt(library, opt, files):
        """Merge .leaks files for a (library, opt) group and print unique leak count."""
        opt_dir = os.path.join(report_dir, opt) if opt else report_dir
        lib_str = f"{library}-{opt}" if opt else library
        merged_file = os.path.join(opt_dir, f"{lib_str}_merged.leaks")
        print(f"  [MERGE] {lib_str}: {len(files)} files -> {os.path.relpath(merged_file)}")
        if run_merge_reports(files, merged_file):
            # Count unique leaks in merged file
            try:
                with open(merged_file, 'r') as f:
                    n_unique = sum(1 for line in f if line.startswith("Leak "))
                print(f"  [MERGE] {lib_str}: {n_unique} unique leak(s)")
            except (OSError, IOError):
                pass
            return merged_file
        return None

    for i, t in enumerate(tests):
        label = t["label"]
        prog_info = ""
        if args.progressive is not None:
            prog_dir = args.progressive if args.progressive else get_progressive_dir(t["algorithm"], t["library"])
            if prog_dir:
                prog_info = f" [progressive={prog_dir}]"
        print(f"[{i+1}/{len(tests)}] {label}{prog_info}")

        label, success, elapsed, cmd_str = run_test(t, root, args.timeout, args.memlimit, args.progressive)

        if success:
            print(f"  -> OK ({elapsed:.0f}s)")
            passed += 1
        else:
            print(f"  -> FAIL ({elapsed:.0f}s)")
            failed += 1

        results.append((label, success, elapsed, cmd_str))

        # Run callstack2source and compress log right after each test
        log_path = get_log_path(t, root)
        if os.path.exists(log_path) and os.path.getsize(log_path) > 0:
            leaks = parse_leaks(log_path)
            if leaks and report_dir:
                binary_path = get_binary_path(t, root)
                if os.path.exists(binary_path):
                    lib_str = t["library"]
                    opt = t["optimization"]
                    if opt:
                        lib_str = f"{t['library']}-{opt}"
                    opt_dir = os.path.join(report_dir, opt) if opt else report_dir
                    os.makedirs(opt_dir, exist_ok=True)
                    leaks_file = os.path.join(
                        opt_dir, f"{lib_str}_{t['algorithm']}.leaks"
                    )
                    print(f"  [REPORT] {t['label']} -> {os.path.relpath(leaks_file)}")
                    if run_callstack2source(log_path, binary_path, leaks_file):
                        individual_leaks[t["label"]] = leaks_file
                        leaks_by_lib_opt[get_lib_opt(t)].append(leaks_file)
                        leaks_by_library[t["library"]].append(leaks_file)

            # Compress log in background
            proc = compress_log(log_path)
            if proc:
                compress_procs.append((t["label"], proc, log_path))

        # Check if next test is a different (library, opt) group — merge current group
        if report_dir:
            next_lib_opt = get_lib_opt(tests[i + 1]) if i + 1 < len(tests) else None
            cur_lib_opt = get_lib_opt(t)
            if next_lib_opt != cur_lib_opt and leaks_by_lib_opt[cur_lib_opt]:
                merge_lib_opt(t["library"], t["optimization"], leaks_by_lib_opt[cur_lib_opt])

    # Wait for all background gzip processes
    if compress_procs:
        print("\n[COMPRESS] Waiting for log compression to finish...")
        for label, proc, log_path in compress_procs:
            proc.wait()
        print(f"[COMPRESS] {len(compress_procs)} logs compressed")

    print("=" * 60)
    print(f"[SUMMARY] {passed} passed, {failed} failed, {len(tests)} total")

    if failed > 0:
        print("\nFailed tests:")
        for label, success, elapsed, cmd_str in results:
            if not success:
                print(f"  - {label}")
                print(f"    {cmd_str}")

    # Final merge: per library across all optimizations
    if report_dir:
        for library, files in sorted(leaks_by_library.items()):
            if not files:
                continue
            merged_file = os.path.join(report_dir, f"{library}_merged.leaks")
            print(f"  [MERGE] {library} (all opts): {len(files)} files -> {os.path.relpath(merged_file)}")
            if run_merge_reports(files, merged_file):
                merged_files[library] = merged_file

    print_leak_summary(tests, root, results, merged_files, individual_leaks)

    if failed > 0:
        sys.exit(1)


if __name__ == "__main__":
    main()
