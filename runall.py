#!/usr/bin/env python3

"""Run all available benchmark tests as a smoke test."""

import argparse
import glob as glob_mod
import gzip
import json
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


def count_log_lines(path):
    """Count lines in a log file (handles .gz)."""
    try:
        if path.endswith(".gz"):
            with gzip.open(path, 'rt', errors='replace') as f:
                return sum(1 for _ in f)
        else:
            with open(path, 'r', errors='replace') as f:
                return sum(1 for _ in f)
    except Exception:
        return 0


def has_complete_logs(test, root, platform="32", min_lines=1000):
    """Check if a test already has complete auto-mode logs (auto_0 + auto_final, each >min_lines)."""
    cats = categorize_logs(test, root, platform)
    # Need at least auto_0 and auto_final
    if not cats['no_stub'] or not cats['final']:
        return False
    if count_log_lines(cats['no_stub']) < min_lines:
        return False
    if count_log_lines(cats['final']) < min_lines:
        return False
    return True


def get_log_path(test, root, platform="32"):
    """Construct the expected log file path for a test."""
    library_str = test["library"]
    if test["optimization"]:
        library_str = f"{test['library']}-{test['optimization']}"
    return os.path.join(
        root, "results", platform, library_str,
        test["algorithm"], f"{test['nature']}_0.log"
    )


def get_log_dir(test, root, platform="32"):
    """Return the log directory for a test."""
    library_str = test["library"]
    if test["optimization"]:
        library_str = f"{test['library']}-{test['optimization']}"
    return os.path.join(root, "results", platform, library_str, test["algorithm"])


def get_all_log_paths(test, root, platform="32"):
    """Find all log files for a test (plain _0.log and auto mode _auto_*.log).

    Returns list of existing log file paths, preferring uncompressed over .gz.
    """
    log_dir = get_log_dir(test, root, platform)
    if not os.path.isdir(log_dir):
        return []
    nature = test["nature"]
    paths = []
    for pattern in [f"{nature}_0.log", f"{nature}_auto_*.log"]:
        paths.extend(glob_mod.glob(os.path.join(log_dir, pattern)))
    # Also check .gz versions
    for pattern in [f"{nature}_0.log.gz", f"{nature}_auto_*.log.gz"]:
        for gz in glob_mod.glob(os.path.join(log_dir, pattern)):
            plain = gz[:-3]
            if plain not in paths:
                paths.append(gz)
    return sorted(paths)


def categorize_logs(test, root, platform="32"):
    """Categorize log files for a test into auto mode phases.

    Returns dict with keys:
        'no_stub': path to auto_0 log (initial run, no stubs)
        'stub_iterations': list of auto_1..auto_N logs (stub iterations)
        'last_stub': path to last stub iteration log (auto_N)
        'allstubs': path to auto_allstubs log (all keylen-compatible stubs)
        'final': path to auto_final log (final run, no stubs, extended timeout)
        'plain': path to non-auto _0.log (if not using auto mode)
    All values are None/[] if not found.
    """
    log_dir = get_log_dir(test, root, platform)
    nature = test["nature"]
    result = {'no_stub': None, 'stub_iterations': [], 'last_stub': None, 'allstubs': None, 'final': None, 'plain': None}

    if not os.path.isdir(log_dir):
        return result

    def find(pattern):
        """Find log file, checking plain then .gz."""
        matches = glob_mod.glob(os.path.join(log_dir, pattern))
        if matches:
            return sorted(matches)
        # Try .gz
        gz_matches = glob_mod.glob(os.path.join(log_dir, pattern + ".gz"))
        return sorted(gz_matches) if gz_matches else []

    # Plain (non-auto) log
    plain = find(f"{nature}_0.log")
    if plain:
        result['plain'] = plain[0]

    # Auto mode logs
    auto_0 = find(f"{nature}_auto_0.log")
    if auto_0:
        result['no_stub'] = auto_0[0]

    # Stub iterations: auto_1, auto_2, ...
    all_auto = find(f"{nature}_auto_[0-9]*.log")
    # Filter out auto_0 — those are no-stub
    stub_iters = []
    for p in all_auto:
        base = os.path.basename(p).replace('.gz', '')
        # Extract iteration number from <nature>_auto_<N>.log
        m = re.search(r'_auto_(\d+)\.log', base)
        if m and int(m.group(1)) > 0:
            stub_iters.append(p)
    stub_iters.sort()
    result['stub_iterations'] = stub_iters
    if stub_iters:
        result['last_stub'] = stub_iters[-1]

    # All-stubs run
    allstubs = find(f"{nature}_auto_allstubs.log")
    if allstubs:
        result['allstubs'] = allstubs[0]

    # Final run
    final = find(f"{nature}_auto_final.log")
    if final:
        result['final'] = final[0]

    return result


def count_leaks_in_file(leaks_file):
    """Count unique entries in a .leaks report file.

    Handles both raw callstack2source output (VIOLATION #N) and
    merge_reports output (UNIQUE #N).
    """
    try:
        with open(leaks_file, 'r') as f:
            return sum(1 for line in f if re.match(r'^(VIOLATION|UNIQUE) #\d+', line))
    except (OSError, IOError):
        return 0


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
            # Check if any log file exists (ran but failed vs build failure)
            log_paths = get_all_log_paths(t, root)
            if log_paths:
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
        test_leaks = []
        for log_path in get_all_log_paths(t, root):
            test_leaks.extend(parse_leaks(log_path))
        test_leak_counts[t["label"]] = len(test_leaks)
        for addr, leak_type in test_leaks:
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
        log_paths = get_all_log_paths(t, root)
        n_leaks = test_leak_counts.get(label, 0)
        if log_paths:
            leaks_path = individual_leaks.get(label)
            log_display = log_paths[0] if len(log_paths) == 1 else f"{log_paths[0]} (+{len(log_paths)-1} more)"
            if leaks_path:
                print(f"  {label:40s}  log: {log_display}")
                print(f"  {'':40s}  leaks: {leaks_path}  ({n_leaks} leaks)")
            elif n_leaks > 0:
                print(f"  {label:40s}  log: {log_display}  ({n_leaks} leaks)")
            else:
                print(f"  {label:40s}  log: {log_display}")

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


def print_leak_tables(table_data, tests):
    """Print a per-library table with rows=primitives, columns=opt x phase."""
    all_libraries = sorted(set(t["library"] for t in tests))
    all_algorithms = sorted(set(t["algorithm"] for t in tests))
    all_opts = sorted(set(t["optimization"] for t in tests if t["optimization"]))
    if not all_opts:
        all_opts = [""]

    phases = [('no_stub', 'No Stub'), ('progressive', 'Progressive'), ('all_stub', 'All Stub'), ('allstubs', 'All Stubs'), ('final', 'Final')]

    for library in all_libraries:
        # Check if this library has any data
        lib_algos = sorted(set(algo for (lib, algo) in table_data if lib == library))
        if not lib_algos:
            continue

        # Build column headers
        col_headers = []
        for opt in all_opts:
            opt_label = opt if opt else "default"
            for _, phase_label in phases:
                col_headers.append(f"{opt_label}-{phase_label}")

        # Determine column widths
        algo_width = max(len(a) for a in lib_algos)
        algo_width = max(algo_width, len("Algorithm"))
        col_width = max(len(h) for h in col_headers)
        col_width = max(col_width, 4)

        print()
        print("=" * 62)
        print(f"LEAK TABLE: {library}")
        print("=" * 62)

        # Header row
        header = f"{'Algorithm':<{algo_width}}"
        for h in col_headers:
            header += f"  {h:>{col_width}}"
        print(header)
        print("-" * len(header))

        # Data rows
        for algo in lib_algos:
            row = f"{algo:<{algo_width}}"
            for opt in all_opts:
                for phase_key, _ in phases:
                    val = table_data.get((library, algo), {}).get((opt, phase_key))
                    cell = str(val) if val is not None else "-"
                    row += f"  {cell:>{col_width}}"
            print(row)

        print("-" * len(header))
        print()


def load_json_result(test, root, platform="32"):
    """Load the JSON result file for a test, if it exists."""
    library_str = test["library"]
    if test["optimization"]:
        library_str = f"{test['library']}-{test['optimization']}"
    json_dir = os.path.join(root, "results", platform, library_str, test["algorithm"])
    if not os.path.isdir(json_dir):
        return None
    # Find the .json file
    for f in os.listdir(json_dir):
        if f.endswith('.json'):
            try:
                with open(os.path.join(json_dir, f)) as jf:
                    return json.load(jf)
            except (json.JSONDecodeError, OSError):
                pass
    return None


def print_stub_tables(tests, root):
    """Print a per-library stub table with rows=primitives, columns=opt x phase.

    Reads stub counts from JSON result files produced by runbench.py.
    """
    all_libraries = sorted(set(t["library"] for t in tests))
    all_opts = sorted(set(t["optimization"] for t in tests if t["optimization"]))
    if not all_opts:
        all_opts = [""]

    # Collect stub data from JSON files
    # stub_data[(library, algo)][(opt, phase)] = stub_count
    # hook_data[(library, algo)][(opt, phase)] = hooked_bn_count
    stub_data = defaultdict(dict)
    hook_data = defaultdict(dict)
    has_data = False

    for t in tests:
        jdata = load_json_result(t, root)
        if not jdata:
            continue
        lib = t["library"]
        algo = t["algorithm"]
        opt = t["optimization"]
        for it in jdata.get("iterations", []):
            phase = it.get("phase", "")
            stubs = it.get("stubs", 0)
            hooked_bn = it.get("hooked_bn", 0)
            stub_data[(lib, algo)][(opt, phase)] = stubs
            hook_data[(lib, algo)][(opt, phase)] = hooked_bn
            if stubs > 0 or hooked_bn > 0:
                has_data = True

    if not has_data:
        return

    phases = [('no_stub', 'No Stub'), ('allstubs', 'All Stubs'), ('final', 'Final')]
    # Also include stub_N phases dynamically
    all_phases_seen = set()
    for key_dict in stub_data.values():
        for (opt, phase) in key_dict:
            all_phases_seen.add(phase)

    # Build ordered phase list: no_stub, stub_1, stub_2, ..., allstubs, final
    stub_phases = sorted([p for p in all_phases_seen if p.startswith("stub_")],
                         key=lambda x: int(x.split("_")[1]))
    phases = [('no_stub', 'No Stub')]
    for sp in stub_phases:
        phases.append((sp, sp.replace("_", " ").title()))
    phases.append(('allstubs', 'All Stubs'))
    phases.append(('final', 'Final'))

    for library in all_libraries:
        lib_algos = sorted(set(algo for (lib, algo) in stub_data if lib == library))
        if not lib_algos:
            continue

        col_headers = []
        for opt in all_opts:
            opt_label = opt if opt else "default"
            for _, phase_label in phases:
                col_headers.append(f"{opt_label}-{phase_label}")

        algo_width = max(len(a) for a in lib_algos)
        algo_width = max(algo_width, len("Algorithm"))
        col_width = max(len(h) for h in col_headers)
        col_width = max(col_width, 4)

        print()
        print("=" * 62)
        print(f"STUB TABLE: {library}  (functions stubbed)")
        print("=" * 62)

        header = f"{'Algorithm':<{algo_width}}"
        for h in col_headers:
            header += f"  {h:>{col_width}}"
        print(header)
        print("-" * len(header))

        for algo in lib_algos:
            row = f"{algo:<{algo_width}}"
            for opt in all_opts:
                for phase_key, _ in phases:
                    val = stub_data.get((library, algo), {}).get((opt, phase_key))
                    cell = str(val) if val is not None else "-"
                    row += f"  {cell:>{col_width}}"
            print(row)

        print("-" * len(header))
        print()

        # BN Hook table
        print("=" * 62)
        print(f"BN HOOK TABLE: {library}  (BN functions actually applied)")
        print("=" * 62)

        print(header.replace("Algorithm", "Algorithm"))  # reuse same header
        print("-" * len(header))

        for algo in lib_algos:
            row = f"{algo:<{algo_width}}"
            for opt in all_opts:
                for phase_key, _ in phases:
                    val = hook_data.get((library, algo), {}).get((opt, phase_key))
                    cell = str(val) if val is not None else "-"
                    row += f"  {cell:>{col_width}}"
            print(row)

        print("-" * len(header))
        print()


def run_test(test, root, timeout, memlimit, progressive=None, auto=True, group=0, tree=False):
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

    if tree:
        cmd += ["--tree"]
    elif auto:
        cmd += ["--auto"]

    if group > 0:
        cmd += ["--group", str(group)]

    if progressive is not None:
        prog_dir = progressive if progressive else get_progressive_dir(test["algorithm"], test["library"])
        if prog_dir:
            cmd += ["--progressive", prog_dir]

    cmd_str = " ".join(cmd)
    start = time.time()
    # Auto mode runs multiple iterations; allow generous subprocess timeout
    subprocess_timeout = (timeout * 20 + 120) if auto else (timeout + 60)

    env = os.environ.copy()
    env["PYTHONUNBUFFERED"] = "1"

    try:
        result = subprocess.run(cmd, timeout=subprocess_timeout, env=env)
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
    parser.add_argument("--optimization", type=str, action="append", default=None,
                        help="Filter by optimization (e.g. --optimization O0). Comma-separated or repeated.")
    parser.add_argument("--report", type=str, default="reports",
                        help="Directory for .leaks reports and per-library merged reports (default: reports/)")
    parser.add_argument("--progressive", type=str, nargs="?", const="", default=None,
                        help="Enable progressive mode. Optionally specify a directory override.")
    parser.add_argument("--auto", action="store_true", default=True,
                        help="Enable auto mode for iterative stub discovery (default: on)")
    parser.add_argument("--no-auto", action="store_false", dest="auto",
                        help="Disable auto mode")
    parser.add_argument("--tree", action="store_true",
                        help="Tree mode: start with all stubs, progressively unstub")
    parser.add_argument("--group", type=int, default=0,
                        help="In auto mode, add at most K new stub files per iteration (0 = all at once)")
    parser.add_argument("--dry-run", action="store_true", help="List tests without running")
    parser.add_argument("--missing", action="store_true",
                        help="Skip tests whose result logs already exist and have >1000 lines; reuse existing logs for reporting")
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

    if args.optimization:
        allowed_opts = set()
        for item in args.optimization:
            for opt in item.split(","):
                opt = opt.strip()
                if opt:
                    allowed_opts.add(opt)
        tests = [t for t in tests if t["optimization"] in allowed_opts]

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

    wall_start = time.time()
    passed = 0
    failed = 0
    results = []
    individual_leaks = {}  # label -> leaks_file
    leaks_by_lib_opt = defaultdict(list)  # (library, opt) -> [leaks_file, ...]
    leaks_by_library = defaultdict(list)  # library -> [leaks_file, ...]
    compress_procs = []  # background gzip processes
    merged_files = {}  # library -> merged_file

    # table_data[(library, algorithm)][(opt, phase)] = unique leak count
    # phases: 'no_stub', 'progressive', 'all_stub', 'allstubs', 'final'
    table_data = defaultdict(dict)

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
            n_unique = count_leaks_in_file(merged_file)
            print(f"  [MERGE] {lib_str}: {n_unique} unique leak(s)")
            return merged_file
        return None

    def make_leaks_file(log_path, test, suffix=""):
        """Run callstack2source on a log and return the .leaks path, or None."""
        if not log_path or not os.path.exists(log_path):
            return None
        if os.path.getsize(log_path) == 0 if not log_path.endswith(".gz") else False:
            return None
        leaks = parse_leaks(log_path)
        if not leaks:
            return None
        binary_path = get_binary_path(test, root)
        if not os.path.exists(binary_path):
            return None
        lib_str = test["library"]
        opt = test["optimization"]
        if opt:
            lib_str = f"{test['library']}-{opt}"
        opt_dir = os.path.join(report_dir, opt) if opt else report_dir
        os.makedirs(opt_dir, exist_ok=True)
        log_base = os.path.splitext(os.path.basename(log_path))[0]
        if log_base.endswith(".log"):
            log_base = log_base[:-4]  # strip extra .log from .log.gz
        leaks_file = os.path.join(
            opt_dir, f"{lib_str}_{test['algorithm']}_{log_base}{suffix}.leaks"
        )
        print(f"  [REPORT] {test['label']} -> {os.path.relpath(leaks_file)}")
        if run_callstack2source(log_path, binary_path, leaks_file):
            return leaks_file
        return None

    def merge_and_count(files, output_path):
        """Merge .leaks files and return unique leak count. Returns count or None."""
        if not files:
            return None
        if len(files) == 1:
            # Single file: just merge (dedup within it) and count
            if run_merge_reports(files, output_path):
                return count_leaks_in_file(output_path)
            return None
        if run_merge_reports(files, output_path):
            return count_leaks_in_file(output_path)
        return None

    skipped = 0
    last_lib = None
    for i, t in enumerate(tests):
        cur_lib = f"{t['library']}-{t['optimization']}" if t["optimization"] else t["library"]
        if cur_lib != last_lib:
            print(f"\n{'─'*60}\n  {cur_lib}\n{'─'*60}")
            last_lib = cur_lib
        label = t["label"]
        prog_info = ""
        if args.progressive is not None:
            prog_dir = args.progressive if args.progressive else get_progressive_dir(t["algorithm"], t["library"])
            if prog_dir:
                prog_info = f" [progressive={prog_dir}]"
        print(f"[{i+1}/{len(tests)}] {label}{prog_info}")

        # --missing: skip if complete logs already exist
        if args.missing and has_complete_logs(t, root):
            print(f"  -> SKIP (logs already exist)")
            skipped += 1
            passed += 1
            results.append((label, True, 0, "skipped"))
        else:
            label, success, elapsed, cmd_str = run_test(t, root, args.timeout, args.memlimit, args.progressive, args.auto, args.group, args.tree)

            if success:
                print(f"  -> OK ({elapsed:.0f}s)")
                passed += 1
            else:
                print(f"  -> FAIL ({elapsed:.0f}s)")
                failed += 1

            results.append((label, success, elapsed, cmd_str))

        if not report_dir:
            continue

        # Categorize logs and generate .leaks files per phase
        cats = categorize_logs(t, root)
        lib_str = t["library"]
        opt = t["optimization"]
        if opt:
            lib_str = f"{t['library']}-{opt}"
        opt_dir = os.path.join(report_dir, opt) if opt else report_dir
        os.makedirs(opt_dir, exist_ok=True)

        all_leaks_files = []  # all .leaks for this primitive

        # 1. No Stub (auto_0): generate .leaks, merge (dedup), count
        no_stub_leaks = make_leaks_file(cats['no_stub'], t)
        if no_stub_leaks:
            merged_path = os.path.join(opt_dir, f"{lib_str}_{t['algorithm']}_no_stub_merged.leaks")
            n = merge_and_count([no_stub_leaks], merged_path)
            if n is not None:
                table_data[(t["library"], t["algorithm"])][(opt, 'no_stub')] = n
                print(f"  [NO STUB] {n} unique leak(s)")
            all_leaks_files.append(no_stub_leaks)
        elif cats['no_stub']:
            # Log exists but make_leaks_file failed — use raw count
            raw = len(parse_leaks(cats['no_stub']))
            table_data[(t["library"], t["algorithm"])][(opt, 'no_stub')] = raw
            if raw > 0:
                print(f"  [NO STUB] {raw} leak(s) (raw, .leaks generation failed)")

        # 2. Stub iterations (auto_1..auto_N-1): generate .leaks for each
        stub_leaks_files = []
        for log_path in cats['stub_iterations']:
            lf = make_leaks_file(log_path, t)
            if lf:
                stub_leaks_files.append(lf)
                all_leaks_files.append(lf)

        # 3. All Stub (auto_N-1, last stub iteration with all accumulated stubs)
        if cats['last_stub']:
            last_leaks = parse_leaks(cats['last_stub'])
            n_last = len(last_leaks)
            table_data[(t["library"], t["algorithm"])][(opt, 'all_stub')] = n_last
            print(f"  [ALL STUB] {n_last} leak(s) (raw)")
            # If there's a .leaks file for it, use merge-dedup count
            if stub_leaks_files:
                last_stub_file = stub_leaks_files[-1]
                merged_path = os.path.join(opt_dir, f"{lib_str}_{t['algorithm']}_all_stub_merged.leaks")
                n = merge_and_count([last_stub_file], merged_path)
                if n is not None:
                    table_data[(t["library"], t["algorithm"])][(opt, 'all_stub')] = n
                    print(f"  [ALL STUB] {n} unique leak(s)")
        elif cats['stub_iterations']:
            # Last stub iteration — use raw count
            raw = len(parse_leaks(cats['last_stub'])) if cats['last_stub'] else 0
            table_data[(t["library"], t["algorithm"])][(opt, 'all_stub')] = raw
            if raw > 0:
                print(f"  [ALL STUB] {raw} leak(s) (raw, .leaks generation failed)")

        # 4. Progressive (all iterations merged: auto_0 + auto_1 + ... + auto_N-1)
        progressive_files = []
        if no_stub_leaks:
            progressive_files.append(no_stub_leaks)
        progressive_files.extend(stub_leaks_files)
        if progressive_files:
            merged_path = os.path.join(opt_dir, f"{lib_str}_{t['algorithm']}_progressive_merged.leaks")
            n = merge_and_count(progressive_files, merged_path)
            if n is not None:
                table_data[(t["library"], t["algorithm"])][(opt, 'progressive')] = n
                print(f"  [PROGRESSIVE] {n} unique leak(s)")
        elif cats['no_stub'] or cats['stub_iterations']:
            # Logs exist but no .leaks produced — sum raw counts
            raw_total = 0
            if cats['no_stub']:
                raw_total += len(parse_leaks(cats['no_stub']))
            for lp in cats['stub_iterations']:
                raw_total += len(parse_leaks(lp))
            table_data[(t["library"], t["algorithm"])][(opt, 'progressive')] = raw_total

        # 5. All-stubs run (auto_allstubs): generate .leaks, merge (dedup), count
        allstubs_leaks = make_leaks_file(cats['allstubs'], t)
        if allstubs_leaks:
            merged_path = os.path.join(opt_dir, f"{lib_str}_{t['algorithm']}_allstubs_merged.leaks")
            n = merge_and_count([allstubs_leaks], merged_path)
            if n is not None:
                table_data[(t["library"], t["algorithm"])][(opt, 'allstubs')] = n
                print(f"  [ALL STUBS] {n} unique leak(s)")
            all_leaks_files.append(allstubs_leaks)
        elif cats['allstubs']:
            raw = len(parse_leaks(cats['allstubs']))
            table_data[(t["library"], t["algorithm"])][(opt, 'allstubs')] = raw
            if raw > 0:
                print(f"  [ALL STUBS] {raw} leak(s) (raw, .leaks generation failed)")

        # 6. Final run (auto_final): generate .leaks, merge (dedup), count
        final_leaks = make_leaks_file(cats['final'], t)
        if final_leaks:
            merged_path = os.path.join(opt_dir, f"{lib_str}_{t['algorithm']}_final_merged.leaks")
            n = merge_and_count([final_leaks], merged_path)
            if n is not None:
                table_data[(t["library"], t["algorithm"])][(opt, 'final')] = n
                print(f"  [FINAL] {n} unique leak(s)")
            all_leaks_files.append(final_leaks)
        elif cats['final']:
            raw = len(parse_leaks(cats['final']))
            table_data[(t["library"], t["algorithm"])][(opt, 'final')] = raw
            if raw > 0:
                print(f"  [FINAL] {raw} leak(s) (raw, .leaks generation failed)")

        # Also handle plain (non-auto) log if present and no auto logs found
        if not cats['no_stub'] and not cats['final'] and cats['plain']:
            plain_leaks = make_leaks_file(cats['plain'], t)
            if plain_leaks:
                merged_path = os.path.join(opt_dir, f"{lib_str}_{t['algorithm']}_plain_merged.leaks")
                n = merge_and_count([plain_leaks], merged_path)
                if n is not None:
                    table_data[(t["library"], t["algorithm"])][(opt, 'no_stub')] = n
                all_leaks_files.append(plain_leaks)

        # Track for per-library merges
        if all_leaks_files:
            individual_leaks[t["label"]] = all_leaks_files[-1]
            leaks_by_lib_opt[get_lib_opt(t)].extend(all_leaks_files)
            leaks_by_library[t["library"]].extend(all_leaks_files)

        # Compress all log files in background
        for log_path in get_all_log_paths(t, root):
            if log_path.endswith(".gz"):
                continue
            proc = compress_log(log_path)
            if proc:
                compress_procs.append((t["label"], proc, log_path))

        # Check if next test is a different (library, opt) group — merge current group
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
    skip_info = f", {skipped} skipped" if skipped else ""
    print(f"[SUMMARY] {passed} passed, {failed} failed, {len(tests)} total{skip_info}")

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

    # Print per-library leak tables
    if table_data:
        print_leak_tables(table_data, tests)

    # Print per-library stub tables from JSON results
    print_stub_tables(tests, root)

    wall_elapsed = time.time() - wall_start
    hours, rem = divmod(int(wall_elapsed), 3600)
    mins, secs = divmod(rem, 60)
    print(f"\n[TIME] Total wall time: {hours}h {mins}m {secs}s ({wall_elapsed:.0f}s)")

    if failed > 0:
        sys.exit(1)


if __name__ == "__main__":
    main()
