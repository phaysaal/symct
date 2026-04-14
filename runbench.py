#!/usr/bin/env python3

import argparse
import json
import os
import re
import resource
import subprocess
import sys
from enum import Enum
from typing import List, Tuple, Optional

# ============================================================================ 
# Enums
# ============================================================================ 

class RandomMode(Enum):
    RANDOM = "rand"
    CONSTANT = "const"

    def __str__(self):
        return self.value

class Library(Enum):
    OPENSSL = "openssl"
    BEARSSL = "bearssl"
    WOLFSSL = "wolfssl"
    MBEDTLS = "mbedtls"

    def __str__(self):
        return self.value

class Platform(Enum):
    X86 = "32"
    X86_64 = "64"
    ARM64 = "arm64"
    
    def __str__(self):
        return self.value

# ============================================================================ 
# Argument Parsing
# ============================================================================ 

def parse_args():
    parser = argparse.ArgumentParser(description="Benchmark Test Driver")

    parser.add_argument("library", type=str, choices=[l.value for l in Library], help="Library to test")
    parser.add_argument("algorithm", type=str, help="Algorithm name")
    parser.add_argument("nature", type=str, help="Test type/nature")
    parser.add_argument("--keylen", type=int, default=2048, help="Key length")
    
    # Changed root to optional flag with default '.'
    parser.add_argument("--root", type=str, default=".", help="Root directory")
    
    parser.add_argument("--startfrom", type=str, default="core", help="Starting point (core, main, etc.)")
    parser.add_argument("--timeout", type=int, default=1800, help="Timeout in seconds")
    parser.add_argument("--no-details", action="store_true", help="Disable debug output")
    parser.add_argument("--random", type=str, choices=[r.value for r in RandomMode], default=RandomMode.CONSTANT.value, help="Randomization mode (default: const)")
    parser.add_argument("--extra", type=str, default="", help="Extra arguments")
    parser.add_argument("--tag", type=str, default="", help="Tag for log files")
    
    # Removed --batch flag
    
    parser.add_argument("--batch-file", type=str, default="", help="Run tests from a file with different test configurations")
    parser.add_argument("--platform", type=str, choices=[p.value for p in Platform], default=Platform.X86.value, help="Platform (32 or 64)")
    parser.add_argument("--bn", action="store_true", help="Enable Bignumber mode")
    parser.add_argument("--progressive", type=str, default="", help="Progressive mode configuration")
    parser.add_argument("--only", type=str, default="", help="Run only specific progressive step")
    parser.add_argument("--combinations", action="store_true", help="Run all combinations")
    parser.add_argument("--optimization", type=str, default="", help="Optimization level/flag")
    parser.add_argument("--report", type=str, default="", help="Directory for callstack2source report files")
    parser.add_argument("--build", action="store_true", help="Build the benchmark before running")
    parser.add_argument("--memlimit", type=int, default=16384, help="Memory limit in MB (default: 16384 = 16GB, 0 = unlimited)")
    parser.add_argument("--auto", action="store_true", help="Auto mode: iteratively discover and add bignum stubs")
    parser.add_argument("--newprimeall", action="store_true", help="In auto mode, use the Terminal Leakers strategy (stub all terminal leakers)")
    parser.add_argument("--newprimeone", action="store_true", help="In auto mode, use the Terminal Leakers strategy (stub one terminal leaker per iteration)")
    parser.add_argument("--no-final", action="store_true", help="Skip the final run without stubs")
    parser.add_argument("--no-all", action="store_true", help="Skip the run with all available stubs")
    parser.add_argument("--resume-from", type=int, default=0, metavar="N",
                        help="In auto mode, skip to iteration N by replaying existing logs for iterations 0..N-1")
    parser.add_argument("--tree", action="store_true", help="Tree mode: start with all stubs, progressively unstub to find leak sources")
    parser.add_argument("--dead-erase", action="store_true", help="In tree mode, auto-generate empty stubs for dead regions (no leaks, no BN) to speed up subsequent runs")
    parser.add_argument("--group", type=int, default=0, help="In auto mode, add at most K new stub files per iteration (0 = all at once)")
    parser.add_argument("--report-diff", action="store_true", help="Show per-iteration leak diff report (new/removed leaks between iterations)")
    parser.add_argument("--end-report", action="store_true", help="Print end-of-run summary report")
    parser.add_argument("--parallel", action="store_true", help="In progressive mode, run all iterations in parallel")
    parser.add_argument("--clean", action="store_true", help="Delete existing results and reports for this primitive before running")

    return parser.parse_args()

# ============================================================================ 
# Main Entry Point
# ============================================================================ 

def main():
    if '--analyze-log' in sys.argv:
        _analyze_log_cmd()
        return
    args = parse_args()
    if not drive_test(args):
        sys.exit(1)


def _analyze_log_cmd():
    """Standalone log analysis: parse and display the analysis/decision report
    for one or more existing BINSEC log files without running BINSEC."""
    parser = argparse.ArgumentParser(
        description="Analyze existing BINSEC log file(s) — show analysis and stub-decision report",
        prog=f"{os.path.basename(sys.argv[0])} --analyze-log",
    )
    parser.add_argument("--analyze-log", metavar="LOG", nargs="+", required=True,
                        help="Path(s) to BINSEC log file(s) to analyze")
    parser.add_argument("--library", required=True,
                        choices=[l.value for l in Library],
                        help="Library (openssl, bearssl, wolfssl, mbedtls)")
    parser.add_argument("--platform", default=Platform.X86.value,
                        choices=[p.value for p in Platform])
    parser.add_argument("--root", default=".",
                        help="Root directory (for locating binsec/ stub files)")
    parser.add_argument("--keylen", type=int, default=0,
                        help="Key length for stub compatibility filtering (0 = any)")
    parser.add_argument("--iteration", type=int, default=None,
                        help="Override iteration number (auto-detected from filename if omitted)")
    parser.add_argument("--newprimeall", action="store_true",
                        help="Show analysis as NewPrimeAll strategy")
    parser.add_argument("--newprimeone", action="store_true",
                        help="Show analysis as NewPrimeOne strategy")
    args = parser.parse_args()

    # Build a minimal Namespace that satisfies _auto_iter_report
    import argparse as _ap
    fake_args = _ap.Namespace(
        library=args.library,
        platform=args.platform,
        root=os.path.abspath(args.root),
        group=0,
        report_diff=False,
        dead_erase=False,
        optimization="",
        timeout=0,
        newprimeall=args.newprimeall,
        newprimeone=args.newprimeone,
        end_report=False,
    )
    script_root = f"{fake_args.root}/binsec/"

    for log_file in args.analyze_log:
        if not os.path.exists(log_file):
            print(f"Error: log file not found: {log_file}", file=sys.stderr)
            continue

        # Auto-detect iteration from filename (e.g. rsa_openssl_auto_2.log → 2)
        iteration = args.iteration
        if iteration is None:
            m = re.search(r'_auto_(\d+)', os.path.basename(log_file))
            iteration = int(m.group(1)) if m else 0

        print(f"\n{'='*60}")
        print(f"[ANALYZE] {os.path.relpath(log_file)}  (iteration {iteration})")
        print(f"{'='*60}")

        _auto_iter_report(
            iteration, log_file,
            binary_path=None,
            accumulated_stubs=set(),
            args=fake_args,
            script_root=script_root,
            resolved_keylen=args.keylen,
            generate_leaks=False,
        )

# ============================================================================ 
# Test Driver Functions
# ============================================================================ 

def drive_test(args):
    if args.tree:
        return tree_test(args)
    elif args.auto:
        return auto_test(args)
    elif args.batch_file:
        return batch_file_test(args)
    else:
        return single_test(args)

def batch_file_test(args):
    try:
        with open(args.batch_file, 'r') as f:
            lines = f.readlines()
    except Exception as e:
        sys.exit(f"Could not open batch file: {args.batch_file}. Error: {e}")

    print(f"[INFO] Running tests from batch file: {args.batch_file}")
    print("----------------------------------------")

    all_ok = True
    for line_num, line in enumerate(lines):
        line = line.strip()

        if not line or line.startswith('#'):
            continue

        # Create a new namespace for the test to avoid modifying the original args
        new_args = argparse.Namespace(**vars(args))
        new_args.nature = line

        print(f"\n[TEST] {line_num + 1}: {line}")
        if not single_test(new_args):
            all_ok = False
        print(f"[DONE] {line}")

    print("\n----------------------------------------")
    print("[OK] All tests from batch file completed")
    return all_ok

def single_test(args):
    # Build paths and configuration strings
    script_root = f"{args.root}/binsec/"

    base_ini = f"{script_root}{args.platform}/core.ini" if args.startfrom == "core" else \
               f"{script_root}{args.platform}/{args.startfrom}"

    library_str = args.library if not args.optimization else f"{args.library}-{args.optimization}"

    base_dir = f"{script_root}{args.platform}/{args.library}"

    base_stubs = ""
    if args.bn:
        files = list_files(base_dir)
        if files:
            base_stubs = "," + ",".join(files)

    # Load keylen config and resolve
    keylen_config = load_keylen_config(args.root)
    resolved_keylen = args.keylen
    
    try:
        # Structure: library -> algorithm -> platform -> keylen
        if args.library in keylen_config:
            lib_conf = keylen_config[args.library]
            if args.algorithm in lib_conf:
                alg_conf = lib_conf[args.algorithm]
                if args.platform in alg_conf:
                    resolved_keylen = alg_conf[args.platform]
    except Exception:
        pass

    bn_option = ""
    if args.bn:
        bn_option = f"-bn -bn-backend {args.library} -bn-keylen {resolved_keylen} "

    base_root_ini = base_ini if args.nature == "dry" else \
                    f"{base_ini},{script_root}{args.platform}/{args.nature}.ini"

    random_file = ""
    random_dir = f"{script_root}{args.platform}/{args.library}/random"
    if os.path.exists(random_dir):
        if args.random == RandomMode.RANDOM.value:
            random_file = f",{random_dir}/rand.ini"
        else:
            random_file = f",{random_dir}/const.ini"

    algorithm = args.algorithm
    nature = args.nature

    gs_path = ""
    if args.platform == Platform.X86.value:
        gs_path = f",{args.root}/benchmark/{args.platform}/{library_str}/{algorithm}/bin/gs.ini"

    extra = f",{args.extra}" if args.extra else ""
    
    tag = args.tag if not args.tag else f"_{args.tag}"

    dbg = 0 if args.no_details else 2

    # callstack2source needs [sse:debug] traces to resolve addresses
    if args.report and dbg < 2:
        dbg = 2

    # Determine binary path
    if args.startfrom == "core":
        binary_path = f"{args.root}/benchmark/{args.platform}/{library_str}/{algorithm}/bin/{algorithm}_{library_str}_{args.platform}.core"
        debug_binary = binary_path[:-5]
    else:
        binary_path = f"{args.root}/benchmark/{args.platform}/{library_str}/{algorithm}/bin/{algorithm}_{library_str}_{args.platform}"
        debug_binary = binary_path

    # Auto-build if starting from core or --build is specified
    if args.build or args.startfrom == "core":
        if not prepare_benchmark(args.root, args.platform, library_str, args.algorithm):
            print(f"[ERROR] Failed to prepare benchmark, aborting", file=sys.stderr)
            return False

    # Create output directory
    output_path = f"{args.root}/results/{args.platform}/{library_str}/{algorithm}"
    os.makedirs(output_path, exist_ok=True)

    # Build combinations of bn scripts
    bn_dir = f"{script_root}{args.platform}/{args.library}/{args.progressive}/"
    
    bn_stubs_list = []
    if args.bn:
        bn_stubs_list = list_files(bn_dir)

    all_combs = []
    if args.combinations:
        all_combs = all_combinations(bn_stubs_list)
    elif not args.progressive:
        all_combs = [("0", bn_stubs_list)]
    else:
        all_combs = progressive_list(bn_dir, args.progressive, args.only)

    if args.progressive:
        step_names = [name for name, _ in all_combs]
        print(f"[PROGRESSIVE] mode={args.progressive} steps={len(all_combs)} [{', '.join(step_names)}]")

    # Prepare report directory if requested
    report_dir = args.report
    if report_dir:
        os.makedirs(report_dir, exist_ok=True)
    leaks_files = []
    iteration_stats = []
    iteration_leak_sites = []
    iteration_leak_times = []
    success = True

    # Build all run configurations
    total_combs = len(all_combs)
    run_configs = []  # list of (name, cmd_parts, log_file, stubs_list)
    for idx, (name, c) in enumerate(all_combs, 1):
        bn_scripts = ""
        if c:
            bn_scripts = "," + ",".join(c)

        script_files = f"{base_root_ini},{script_root}{args.platform}/mem.ini{random_file}{gs_path}{extra}{base_stubs}{bn_scripts}"

        script_list = f"_{name}"
        log_file = f"{args.root}/results/{args.platform}/{library_str}/{algorithm}/{nature}{script_list}{tag}.log"

        run_cmd = (
            f"binsec -sse -checkct {bn_option}-sse-missing-symbol warn -sse-script {script_files} "
            f"-sse-debug-level {dbg} -sse-depth 1000000000 "
            f"-fml-solver-timeout 600 -sse-timeout {args.timeout} {binary_path} "
            f"-smt-solver bitwuzla:smtlib"
        )

        parts = run_cmd.split()
        if parts:
            run_configs.append((name, idx, parts, log_file, c))

    # Run tests — parallel or sequential
    if args.parallel and len(run_configs) > 1:
        print(f"[PARALLEL] Launching {len(run_configs)} tests simultaneously")
        procs = []
        for name, idx, parts, log_file, c in run_configs:
            print(f"  [LAUNCH {idx}/{total_combs}] step={name} -> {os.path.relpath(log_file)}")
            preexec = make_memlimit_fn(args.memlimit) if args.memlimit > 0 else None
            lf = open(log_file, 'w')
            proc = subprocess.Popen(
                parts, stdout=lf, stderr=lf, preexec_fn=preexec
            )
            procs.append((name, idx, proc, lf, log_file, c))

        # Wait for all to finish
        print(f"[PARALLEL] Waiting for all {len(procs)} tests to complete...")
        for name, idx, proc, lf, log_file, c in procs:
            proc.wait()
            lf.close()
            status = "OK" if proc.returncode == 0 else "FAIL"
            if proc.returncode == -9:
                status = "KILLED (OOM)"
            elif proc.returncode != 0:
                success = False
            print(f"  [{status}] step={name} -> {os.path.relpath(log_file)}")

        # Collect log files in order
        completed = [(name, idx, log_file, c) for name, idx, _, _, log_file, c in procs]
    else:
        # Sequential execution
        completed = []
        for name, idx, parts, log_file, c in run_configs:
            program = parts[0]
            run_args = parts[1:]

            if args.progressive:
                print(f"[STEP {idx}/{total_combs}] progressive={args.progressive} step={name}")
            print(f"[CASE] {','.join(c) if c else '(no stubs)'}")
            if not run_and_log(program, run_args, log_file, algorithm, nature, tag, args.memlimit, gzip_after=not args.end_report):
                success = False
            completed.append((name, idx, log_file, c))

    # Post-processing: generate reports and collect stats
    for name, idx, log_file, c in completed:
        n_alerts = count_leaks_in_log(log_file)
        n_unique = 0
        leaks_file = None
        if report_dir:
            debug_binary = binary_path
            if debug_binary.endswith('.core'):
                debug_binary = debug_binary[:-5]
            log_basename = os.path.basename(log_file)
            leaks_basename = log_basename.replace('.log', '.leaks')
            leaks_file = os.path.join(report_dir, leaks_basename)
            run_callstack2source(log_file, debug_binary, leaks_file)
            leaks_files.append(leaks_file)
            n = count_unique_in_leaks([leaks_file])
            if n is not None:
                n_unique = n

        phase_name = name if args.progressive else f"run_{idx}"
        stubs_count = count_stubbed_functions(set(c)) if c else 0
        hooked_bn = get_hooked_bn_functions(log_file, args.library) if args.bn else set()

        iteration_stats.append({
            "phase": phase_name,
            "alerts": n_alerts,
            "unique_alerts": n_unique,
            "stubs": stubs_count,
            "hooked_bn": len(hooked_bn),
            "hooked_bn_funcs": sorted(hooked_bn),
        })

        if args.report_diff and leaks_file and os.path.exists(leaks_file):
            sites = extract_unique_leak_sites([leaks_file])
            times = extract_leak_sites_with_time(leaks_file)
            iteration_leak_sites.append(sites if sites else set())
            iteration_leak_times.append(times if times else {})
        else:
            iteration_leak_sites.append(set())
            iteration_leak_times.append({})

    # Merge reports if progressive mode
    if report_dir and args.progressive and len(leaks_files) > 1:
        merged_name = f"{args.library}_{algorithm}_{args.platform}{tag}.leaks"
        merged_file = os.path.join(report_dir, merged_name)
        run_merge_reports(leaks_files, merged_file)

    if args.end_report:
        # Summary table
        if iteration_stats and len(iteration_stats) > 1:
            print(f"\n{'='*60}")
            print(f"[PROGRESSIVE] Summary")
            print(f"{'='*60}")
            print(f"  {'Phase':<20s} {'Alerts':>8s} {'Uniq Src':>8s} {'Stubs':>8s} {'BN Hook':>8s}  BN Functions Applied")
            print(f"  {'-'*100}")
            for s in iteration_stats:
                bn_list = ", ".join(s.get('hooked_bn_funcs', []))
                print(f"  {s['phase']:<20s} {s['alerts']:>8d} {s['unique_alerts']:>8d} {s['stubs']:>8d} {s['hooked_bn']:>8d}  {bn_list}")

        # Diff report
        if args.report_diff and iteration_leak_sites:
            print_diff_report(iteration_stats, iteration_leak_sites, iteration_leak_times)

        # LaTeX tables
        if iteration_stats and len(iteration_stats) > 1:
            latex_title = f"{args.library} {algorithm} {args.optimization or ''} (progressive)"
            print_latex_table(iteration_stats, latex_title)
            if args.report_diff and iteration_leak_sites:
                print_latex_diff_table(iteration_stats, iteration_leak_sites, latex_title)

    return success

# ============================================================================
# Auto Mode — Iterative Bignum Stub Discovery
# ============================================================================

# Bignum function prefixes per library
BN_PREFIXES = {
    "openssl": ["BN_", "bn_"],
    "bearssl": ["br_i31_", "br_i15_"],
    "wolfssl": ["sp_"],
    "mbedtls": ["mbedtls_mpi_"],
}

# Auto mode stub resolution thresholds (easy to tweak)
AUTO_P1_DOMINANCE_THRESHOLD = 0.25  # P1: leaking BN function must have >=25% subtree share
AUTO_P3_SUBTREE_THRESHOLD   = 0.10  # P3: stub deepest BN function with >=10% subtree share
AUTO_DISPLAY_MIN_PCT        = 0.05  # report: show functions with subtree cost >= 5% of total

FUNC_ANNOTATION_RE = re.compile(r'#\s*<([a-zA-Z0-9_]+)>')
AUTO_LEAK_RE = re.compile(
    r'\[checkct:result\]\s+Instruction\s+0x[0-9a-fA-F]+\s+has\s+.+?\s+leak'
)
AUTO_LEAK_ADDR_RE = re.compile(
    r'\[checkct:result\]\s+Instruction\s+(0x[0-9a-fA-F]+)\s+has\s+(.+?\s+leak)'
)
REPLACE_DIRECTIVE_RE = re.compile(r'replace\s+<([a-zA-Z0-9_]+)>')
POPBV_SIZE_RE = re.compile(r'popBV\s+\w+<(\d+)>')
HOOK_AT_RE = re.compile(r'hook at <([a-zA-Z0-9_]+)>')


def count_leaks_in_log(log_file):
    """Count leak lines in a binsec log file (handles .gz)."""
    import gzip as _gzip
    if not os.path.exists(log_file) and os.path.exists(log_file + ".gz"):
        log_file = log_file + ".gz"
    count = 0
    try:
        opener = _gzip.open if log_file.endswith(".gz") else open
        with opener(log_file, 'rt') as f:
            for line in f:
                if AUTO_LEAK_RE.search(line):
                    count += 1
    except (OSError, IOError):
        pass
    return count


def get_hooked_bn_functions(log_file, library):
    """Extract unique BN function names that were actually hooked in a binsec log."""
    import gzip as _gzip
    hooked = set()
    # Try .gz version if plain file doesn't exist
    if not os.path.exists(log_file) and os.path.exists(log_file + ".gz"):
        log_file = log_file + ".gz"
    try:
        opener = _gzip.open if log_file.endswith(".gz") else open
        with opener(log_file, 'rt') as f:
            for line in f:
                m = HOOK_AT_RE.search(line)
                if m:
                    func = m.group(1)
                    if is_bn_function(func, library):
                        hooked.add(func)
    except (OSError, IOError):
        pass
    return hooked


def count_stubbed_functions(stub_files):
    """Count total number of functions replaced by a set of stub .ini files."""
    funcs = set()
    for fpath in stub_files:
        try:
            with open(fpath) as f:
                funcs.update(REPLACE_DIRECTIVE_RE.findall(f.read()))
        except (OSError, IOError):
            pass
    return len(funcs)


def get_unique_leak_addrs(log_file):
    """Extract unique (address, leak_type) pairs from a binsec log file (handles .gz)."""
    import gzip as _gzip
    if not os.path.exists(log_file) and os.path.exists(log_file + ".gz"):
        log_file = log_file + ".gz"
    addrs = set()
    try:
        opener = _gzip.open if log_file.endswith(".gz") else open
        with opener(log_file, 'rt') as f:
            for line in f:
                m = AUTO_LEAK_ADDR_RE.search(line)
                if m:
                    addrs.add((m.group(1), m.group(2).strip()))
    except (OSError, IOError):
        pass
    return addrs


def generate_leaks_file(log_file, binary_path, output_leaks):
    """Run callstack2source on a log file to produce a .leaks file.

    Returns True on success, False on failure.
    """
    callstack2source = os.path.join(os.path.dirname(os.path.abspath(__file__)), "callstack2source.py")
    try:
        r = subprocess.run(
            [sys.executable, callstack2source, log_file, binary_path, output_leaks],
            capture_output=True, text=True, timeout=120
        )
        return r.returncode == 0
    except Exception:
        return False


def generate_uniq_file(leaks_file, output_uniq):
    """Run merge_reports --uniq-source on a .leaks file to produce a .uniq file."""
    merge_reports = os.path.join(os.path.dirname(os.path.abspath(__file__)), "merge_reports.py")
    try:
        r = subprocess.run(
            [sys.executable, merge_reports, '--uniq-source', '-o', output_uniq, leaks_file],
            capture_output=True, text=True, timeout=60
        )
        return r.returncode == 0
    except Exception:
        return False


def count_unique_in_leaks(leaks_files):
    """Run merge_reports --uniq-source on .leaks files and return unique count.

    Returns unique source-level alert count, or None on failure.
    """
    merge_reports_script = os.path.join(os.path.dirname(os.path.abspath(__file__)), "merge_reports.py")
    import tempfile
    try:
        with tempfile.NamedTemporaryFile(suffix='.merged', delete=False, mode='w') as tmp:
            tmp_path = tmp.name
        valid_files = [f for f in leaks_files if os.path.exists(f) and os.path.getsize(f) > 0]
        if not valid_files:
            return 0
        r = subprocess.run(
            [sys.executable, merge_reports_script, '--uniq-source', '-o', tmp_path] + valid_files,
            capture_output=True, text=True, timeout=60
        )
        if r.returncode != 0:
            return None
        count = 0
        with open(tmp_path, 'r') as f:
            for line in f:
                if re.match(r'^UNIQUE #\d+', line):
                    count += 1
        return count
    except Exception:
        return None
    finally:
        try:
            os.unlink(tmp_path)
        except OSError:
            pass


def print_diff_report(iteration_stats, iteration_leak_sites, iteration_leak_times=None):
    """Print a per-iteration diff report showing added/removed leaks.

    Args:
        iteration_stats: list of dicts with 'phase', 'unique_alerts', etc.
        iteration_leak_sites: list of sets of leak site strings (parallel to iteration_stats)
        iteration_leak_times: list of dicts mapping site -> earliest_time (parallel, optional)
    """
    if iteration_leak_times is None:
        iteration_leak_times = [{} for _ in iteration_stats]

    print(f"\n{'='*80}")
    print(f"LEAK DIFF REPORT")
    print(f"{'='*80}")
    print(f"  {'Phase':<35s} {'Uniq':>5s}  {'Delta':>12s}")
    print(f"  {'-'*55}")

    prev_sites = set()
    for i, (stat, sites) in enumerate(zip(iteration_stats, iteration_leak_sites)):
        phase = stat['phase']
        n = len(sites) if sites else stat.get('unique_alerts', 0)

        if i == 0 or not prev_sites:
            delta_str = ""
        else:
            removed = prev_sites - sites
            added = sites - prev_sites
            delta_str = f"(-{len(removed)},+{len(added)})"

        print(f"  {phase:<35s} {n:>5d}  {delta_str:>12s}")

        prev_sites = sites if sites else prev_sites

    print(f"  {'-'*55}")

    # Detailed list of all changes
    print(f"\n  Detailed changes per iteration:")
    prev_sites = set()
    for i, (stat, sites, times) in enumerate(zip(iteration_stats, iteration_leak_sites, iteration_leak_times)):
        if i == 0:
            if sites:
                print(f"\n  [{stat['phase']}] Initial leaks ({len(sites)}):")
                for s in sorted(sites):
                    t = times.get(s)
                    time_str = f" @ {t:.3f}s" if t is not None else ""
                    print(f"    {s}{time_str}")
            prev_sites = sites if sites else set()
            continue

        removed = prev_sites - sites if sites else set()
        added = sites - prev_sites if sites else set()

        if removed or added:
            print(f"\n  [{stat['phase']}] vs [{iteration_stats[i-1]['phase']}]:")
            for s in sorted(removed):
                print(f"    - {s}")
            for s in sorted(added):
                t = times.get(s)
                time_str = f" @ {t:.3f}s" if t is not None else ""
                print(f"    + {s}{time_str}")

        prev_sites = sites if sites else prev_sites

    # Total unique across all iterations
    all_sites = set()
    all_times = {}
    for sites, times in zip(iteration_leak_sites, iteration_leak_times):
        if sites:
            all_sites |= sites
            for s, t in times.items():
                if s not in all_times or t < all_times[s]:
                    all_times[s] = t

    print(f"\n  Total unique alerts across all iterations: {len(all_sites)}")
    if all_sites:
        for s in sorted(all_sites):
            t = all_times.get(s)
            time_str = f" @ {t:.3f}s" if t is not None else ""
            print(f"    {s}{time_str}")

    print(f"  {'='*75}")


def print_latex_table(iteration_stats, title=""):
    """Print a LaTeX-formatted summary table."""
    def escape_latex(s):
        return s.replace('_', r'\_').replace('%', r'\%').replace('&', r'\&').replace('#', r'\#')

    print(f"\n% LaTeX table{' — ' + title if title else ''}")
    print(r"\begin{table}[htbp]")
    print(r"\centering")
    print(r"\caption{" + escape_latex(title) + "}")
    print(r"\begin{tabular}{l r r r r l}")
    print(r"\hline")
    print(r"\textbf{Phase} & \textbf{Alerts} & \textbf{Uniq Src} & \textbf{Stubs} & \textbf{BN Hook} & \textbf{BN Functions} \\")
    print(r"\hline")
    for s in iteration_stats:
        phase = escape_latex(s.get('phase', ''))
        alerts = s.get('alerts', 0)
        unique = s.get('unique_alerts', 0)
        stubs = s.get('stubs', 0)
        hooked = s.get('hooked_bn', 0)
        bn_funcs = ", ".join(s.get('hooked_bn_funcs', []))
        bn_funcs = escape_latex(bn_funcs)
        if len(bn_funcs) > 60:
            bn_funcs = bn_funcs[:57] + "..."
        dead = " $\\dagger$" if s.get('dead') else ""
        print(f"{phase}{dead} & {alerts} & {unique} & {stubs} & {hooked} & {bn_funcs} \\\\")
    print(r"\hline")
    print(r"\end{tabular}")
    print(r"\end{table}")


def print_latex_diff_table(iteration_stats, iteration_leak_sites, title=""):
    """Print a LaTeX-formatted diff table."""
    def escape_latex(s):
        return s.replace('_', r'\_').replace('%', r'\%').replace('&', r'\&').replace('#', r'\#')

    print(f"\n% LaTeX diff table{' — ' + title if title else ''}")
    print(r"\begin{table}[htbp]")
    print(r"\centering")
    print(r"\caption{Leak diff: " + escape_latex(title) + "}")
    print(r"\begin{tabular}{l r r}")
    print(r"\hline")
    print(r"\textbf{Phase} & \textbf{Unique} & \textbf{Delta} \\")
    print(r"\hline")

    prev_sites = set()
    for i, (stat, sites) in enumerate(zip(iteration_stats, iteration_leak_sites)):
        phase = escape_latex(stat.get('phase', ''))
        n = len(sites) if sites else stat.get('unique_alerts', 0)
        if i == 0 or not prev_sites:
            delta = ""
        else:
            removed = prev_sites - sites
            added = sites - prev_sites
            delta = f"$(-{len(removed)},+{len(added)})$"
        print(f"{phase} & {n} & {delta} \\\\")
        prev_sites = sites if sites else prev_sites

    print(r"\hline")
    print(r"\end{tabular}")
    print(r"\end{table}")


def _clean_hierarchy_line(line):
    """Clean a hierarchy line: strip address, tree chars, whitespace."""
    cleaned = re.sub(r'\[0x[0-9a-fA-F]+\]\s*', '', line)
    cleaned = re.sub(r'\s*<--.*$', '', cleaned)
    cleaned = re.sub(r'^[\s└─│├]+', '', cleaned).strip()
    return cleaned


def _is_resolved(cleaned):
    """Check if a cleaned hierarchy line has a resolved source (not ?? or empty)."""
    stripped = re.sub(r'[└─│\s\t]', '', cleaned)
    return stripped and stripped != '??' and '(' in cleaned


def extract_leak_sites_with_time(leaks_file):
    """Parse a single .leaks file and extract leak sites with their time.

    If the leak site is '??', walks up the call hierarchy to find the
    last resolved caller.

    Returns a dict mapping site_key -> earliest_time (float seconds).
    site_key is "[leak_type] func (file:line)".
    """
    sites = {}
    if not leaks_file or not os.path.exists(leaks_file):
        return sites

    try:
        with open(leaks_file, 'r') as f:
            lines = f.readlines()
    except (OSError, IOError):
        return sites

    i = 0
    while i < len(lines):
        line = lines[i].rstrip('\n')
        if re.match(r'^VIOLATION #\d+', line):
            leak_type = ""
            leak_time = 0.0
            site = None
            hierarchy_lines = []
            in_hierarchy = False
            i += 1
            while i < len(lines):
                l = lines[i].rstrip('\n')
                if re.match(r'^VIOLATION #\d+', l) or l.startswith('=' * 40):
                    break
                # Extract leak type
                m = re.match(r'^Leak Type:\s+(.+)$', l)
                if m:
                    leak_type = m.group(1).strip()
                # Extract time
                m = re.match(r'^Time:\s+([\d.]+)s', l)
                if m:
                    leak_time = float(m.group(1))
                # Track hierarchy lines
                if l.startswith('CALL HIERARCHY:'):
                    in_hierarchy = True
                    i += 1  # skip dash line
                    i += 1
                    continue
                if in_hierarchy:
                    if l.strip() == '' or l.startswith('-' * 40):
                        in_hierarchy = False
                    else:
                        hierarchy_lines.append(l)
                # Extract leak site from hierarchy
                if '<--' in l and 'leak' in l:
                    cleaned = _clean_hierarchy_line(l)
                    if _is_resolved(cleaned):
                        site = f"[{leak_type}] {cleaned}"
                    else:
                        # ?? — walk up hierarchy to find last resolved caller
                        for hl in reversed(hierarchy_lines[:-1]):
                            parent = _clean_hierarchy_line(hl)
                            if _is_resolved(parent):
                                site = f"[{leak_type}] {parent}"
                                break
                        if not site:
                            site = f"[{leak_type}] {cleaned}"
                i += 1

            if site:
                if site not in sites or leak_time < sites[site]:
                    sites[site] = leak_time
            continue
        i += 1

    return sites


def extract_unique_leak_sites(leaks_files):
    """Run merge_reports --uniq-source on .leaks files and extract unique leak site strings.

    Returns a set of strings like "func (file:line)" for each unique leak, or None on failure.
    """
    merge_reports_script = os.path.join(os.path.dirname(os.path.abspath(__file__)), "merge_reports.py")
    import tempfile
    try:
        with tempfile.NamedTemporaryFile(suffix='.merged', delete=False, mode='w') as tmp:
            tmp_path = tmp.name
        valid_files = [f for f in leaks_files if os.path.exists(f) and os.path.getsize(f) > 0]
        if not valid_files:
            return set()
        r = subprocess.run(
            [sys.executable, merge_reports_script, '--uniq-source', '-o', tmp_path] + valid_files,
            capture_output=True, text=True, timeout=60
        )
        if r.returncode != 0:
            return None

        # Parse the merged output to extract leak sites
        sites = set()
        with open(tmp_path, 'r') as f:
            lines = f.readlines()
        i = 0
        while i < len(lines):
            line = lines[i].rstrip('\n')
            if re.match(r'^UNIQUE #\d+', line):
                # Extract leak type from header: "UNIQUE #N  (type leak)"
                leak_type = ""
                m = re.match(r'^UNIQUE #\d+\s+\((.+?)\s+leak\)', line)
                if m:
                    leak_type = m.group(1)
                # Skip the dash separator line after the header
                i += 1
                if i < len(lines) and lines[i].rstrip('\n').startswith('-' * 40):
                    i += 1
                # Collect hierarchy lines and find leak site
                hier_lines = []
                while i < len(lines):
                    l = lines[i].rstrip('\n')
                    # Stop at next entry or section boundary
                    if re.match(r'^UNIQUE #\d+', l) or l.startswith('=' * 40):
                        break
                    if l.strip():
                        hier_lines.append(l)
                    if '<--' in l and 'leak' in l:
                        cleaned = _clean_hierarchy_line(l)
                        if _is_resolved(cleaned):
                            sites.add(f"[{leak_type}] {cleaned}")
                        else:
                            # ?? — walk up hierarchy to find last resolved caller
                            found = False
                            for hl in reversed(hier_lines[:-1]):
                                parent = _clean_hierarchy_line(hl)
                                if _is_resolved(parent):
                                    sites.add(f"[{leak_type}] {parent}")
                                    found = True
                                    break
                            if not found:
                                sites.add(f"[{leak_type}] {cleaned}")
                        break
                    i += 1
            i += 1
        return sites

    except Exception:
        return None
    finally:
        try:
            os.unlink(tmp_path)
        except OSError:
            pass


def is_bn_function(func_name, library):
    """Check if a function name matches bignum prefixes for the given library."""
    prefixes = BN_PREFIXES.get(library, [])
    return any(func_name.startswith(p) for p in prefixes)


CALL_STACK_ADDR_RE = re.compile(
    r'\[checkct:result\]\s+#\d+\s+(0x[0-9a-fA-F]+)'
)
ADDR_ANNOTATION_RE = re.compile(
    r'\[sse:debug\]\s+0x([0-9a-fA-F]+)\s.*#\s*<([a-zA-Z0-9_]+)>'
)
RET_RE          = re.compile(r'\[sse:debug\]\s+0x[0-9a-fA-F]+\s+ret\b')
HOOK_AT_RE      = re.compile(r'\[sse:debug\]\s+0x[0-9a-fA-F]+\s+hook at\s+<([a-zA-Z0-9_]+)>')
CUT_PATH_RE     = re.compile(r'\[sse:debug\]\s+Cut path')
COMPLETED_CUT_RE = re.compile(r'completed/cut paths\s+(\d+)')


def compute_subtree_costs(lines):
    """Compute per-function subtree analysis cost from log line spans.

    Single-path logs (completed/cut paths == 0):
      Use implicit-return heuristic: when annotation transitions to an ancestor
      already on the stack, pop all intermediate frames and charge them up to
      the current line.  This handles pop+ret, tail calls, and other patterns
      that don't emit an explicit annotated ret.

    Multi-path logs (completed/cut paths > 0):
      Phase 1 — before the first 'Cut path' line: same as single-path
        (we are still tracing the first path; annotation-to-ancestor is a real
        return).
      Phase 2 — after the first 'Cut path' line: annotation-to-ancestor is
        NOT treated as a return (BINSEC is replaying a different branch from
        somewhere inside the already-popped call tree).  Instead, if F is not
        on the stack we simply re-push it (new path entry); if it is already
        on the stack we do nothing.

    In both modes:
      - `ret # <F>`: pop F and every frame above it, charging each.
      - `hook at <F>`: never pushed (stub or debug hook, not a real frame).
      - End-of-log: charge all remaining frames total_lines - entry_line.

    Cost is accumulated (+=) over all invocations / path explorations.

    Returns dict: func_name -> total subtree cost across all invocations.
    """
    from collections import defaultdict

    # Determine whether this log contains multiple paths.
    multi_path = False
    for line in lines:
        m = COMPLETED_CUT_RE.search(line)
        if m:
            multi_path = int(m.group(1)) > 0
            break

    costs = defaultdict(int)
    stack = []           # list of (func_name, entry_lineno)
    stack_funcs = set()  # O(1) membership test
    total = len(lines)
    after_first_cut = False  # only relevant when multi_path=True

    for lineno, line in enumerate(lines):
        if '[sse:debug]' not in line:
            continue

        # Track phase boundary for multi-path logs.
        if multi_path and not after_first_cut and CUT_PATH_RE.search(line):
            after_first_cut = True

        is_ret  = bool(RET_RE.search(line))
        is_hook = bool(HOOK_AT_RE.search(line))

        # Extract function annotation — ADDR_ANNOTATION_RE covers all cases
        # including `ret # <func>` and `hook at <func> # <func>`.
        func_name = None
        m = ADDR_ANNOTATION_RE.search(line)
        if m:
            func_name = m.group(2)
        elif not is_ret:
            m2 = FUNC_ANNOTATION_RE.search(line)
            if m2:
                func_name = m2.group(1)

        if is_ret and func_name:
            # Explicit annotated ret: pop F and everything above it, charging
            # each frame up to the current line.
            for k in range(len(stack) - 1, -1, -1):
                if stack[k][0] == func_name:
                    for j in range(len(stack) - 1, k, -1):
                        costs[stack[j][0]] += lineno - stack[j][1]
                    costs[func_name] += lineno - stack[k][1]
                    del stack[k:]
                    stack_funcs = {f for f, _ in stack}
                    break
            # If F not found on stack: a ret for an already-closed frame
            # (path 2 returning a function popped in path 1) — ignore.

        elif is_hook:
            # hook at <Z>: BINSEC stub or debug hook — never push.
            pass

        elif func_name:
            if func_name in stack_funcs:
                # F is already live on the stack.
                if not (multi_path and after_first_cut):
                    # Single-path / phase-1: annotation returning to ancestor
                    # means the intermediate frames have implicitly returned.
                    for k in range(len(stack) - 1, -1, -1):
                        if stack[k][0] == func_name:
                            for j in range(len(stack) - 1, k, -1):
                                costs[stack[j][0]] += lineno - stack[j][1]
                            del stack[k + 1:]
                            stack_funcs = {f for f, _ in stack}
                            break
                # else phase-2: F is already on the stack from a prior path
                # exploration; nothing to do.
            else:
                # F not on stack: new call (phase 1) or new path entry (phase 2).
                stack.append((func_name, lineno))
                stack_funcs.add(func_name)

    # Charge all invocations still open at end of log.
    for func_name, entry_lineno in stack:
        costs[func_name] += total - entry_lineno

    return dict(costs)


def parse_log_for_auto(log_file, library):
    """Parse a binsec log for auto mode analysis.

    Returns:
        func_line_counts: dict mapping function name -> number of [sse:debug] lines
                          (annotation-based, no double-counting across functions)
        subtree_costs:    dict mapping function name -> subtree analysis cost
                          (line span M-N per invocation, includes all nested calls)
        leak_call_chains: list of lists of function names (deepest first) for each leak
        call_graph: dict mapping caller -> {callee: transition_count}
    """
    from collections import defaultdict
    func_line_counts = defaultdict(int)
    leak_call_chains = []
    addr_to_func = {}  # hex address (int) -> function name
    # Track function transitions for call graph
    transitions = defaultdict(int)  # (from_func, to_func) -> count
    first_transition = {}  # (from_func, to_func) -> order of first occurrence
    transition_order = 0
    last_func = None

    lines = []
    try:
        with open(log_file, 'r') as f:
            lines = f.readlines()
    except (OSError, IOError):
        return func_line_counts, {}, leak_call_chains, {}

    # First pass: build addr_to_func mapping, func_line_counts, and transitions
    for line in lines:
        if '[sse:debug]' in line:
            m = ADDR_ANNOTATION_RE.search(line)
            if m:
                addr = int(m.group(1), 16)
                func_name = m.group(2)
                func_line_counts[func_name] += 1
                addr_to_func[addr] = func_name
            else:
                m2 = FUNC_ANNOTATION_RE.search(line)
                if m2:
                    func_name = m2.group(1)
                    func_line_counts[func_name] += 1
                else:
                    func_name = None

            if func_name:
                if last_func and last_func != func_name:
                    pair = (last_func, func_name)
                    transitions[pair] += 1
                    if pair not in first_transition:
                        first_transition[pair] = transition_order
                        transition_order += 1
                last_func = func_name

    # Build call graph from transitions
    # If A->B and B->A both exist, it's a call/return pair.
    # Use per-pair first transition direction: whichever direction was seen
    # first in the trace is the call direction (caller -> callee).
    call_graph = defaultdict(lambda: defaultdict(int))  # caller -> {callee: count}
    seen_pairs = set()
    for (a, b), ab_count in transitions.items():
        ba_count = transitions.get((b, a), 0)
        if ba_count > 0:
            pair = tuple(sorted([a, b]))
            if pair in seen_pairs:
                continue
            seen_pairs.add(pair)
            # The first transition direction determines caller -> callee
            if first_transition.get((a, b), float('inf')) < first_transition.get((b, a), float('inf')):
                call_graph[a][b] += ab_count
            else:
                call_graph[b][a] += ba_count

    # Second pass: parse leak lines and their call stacks
    i = 0
    while i < len(lines):
        line = lines[i]
        if AUTO_LEAK_RE.search(line):
            # Extract the leaking instruction's own address
            leak_m = AUTO_LEAK_ADDR_RE.search(line)
            leak_addr = int(leak_m.group(1), 16) if leak_m else None

            # Collect call stack addresses from following lines
            call_addrs = []
            j = i + 1
            while j < len(lines):
                sline = lines[j]
                if '[checkct:result] CT call stack' in sline:
                    j += 1
                    continue
                sm = CALL_STACK_ADDR_RE.search(sline)
                if sm:
                    call_addrs.append(int(sm.group(1), 16))
                    j += 1
                else:
                    break

            # Resolve call stack addresses to function names (deepest first = #0 first)
            chain = []
            for addr in call_addrs:
                func = addr_to_func.get(addr)
                if func and (not chain or chain[-1] != func):
                    chain.append(func)

            # Prepend the actual leaking function (from the leaking instruction address)
            # The call stack only contains return addresses (callers), not the function
            # where the leak occurs, so we add it explicitly at the front.
            if leak_addr is not None:
                leak_func = addr_to_func.get(leak_addr)
                if leak_func and (not chain or chain[0] != leak_func):
                    chain.insert(0, leak_func)

            leak_call_chains.append(chain)
            i = j
        else:
            i += 1

    subtree_costs = compute_subtree_costs(lines)
    return func_line_counts, subtree_costs, leak_call_chains, dict(call_graph)


def resolve_auto_stubs(leak_call_chains, func_line_counts, subtree_costs,
                       func_to_file, library, newprimeall=False, newprimeone=False):
    """Three-tier stub resolution for auto mode.

    Terminal Leaker Strategies (overrides P1/P2):
    - newprimeall: identify all terminal leakers C = A - B and stub them all.
    - newprimeone: same as above but stub only the single highest-cost leaker from C.
    where A = set of leaking BN functions (leaf of at least one chain)
          B = set of BN functions that call ANY function in set A.

    Standard Tiers:
    P1 (dominant leaking BN): Among leaking BN functions with a stub, if any
       has subtree cost >= AUTO_P1_DOMINANCE_THRESHOLD of total traced lines,
       stub the most dominant one.
    P2 (any leaking BN): If none meet the dominance threshold but leaking BN
       functions exist, stub the one with the highest subtree cost.
    P3 (complexity fallback): If no leaking function is a BN function, find all
       stubbable BN functions whose subtree cost >= AUTO_P3_SUBTREE_THRESHOLD
       and stub the one with the MINIMUM subtree cost (deepest in the call tree).
       Stubbing the deepest costly function is more targeted: it eliminates that
       function's subtree while keeping its callers visible for further analysis.

    All tiers use subtree_costs for ranking.

    Returns:
        strategy: "P1", "P2", "P3", or "NewPrimeAll"/"NewPrimeOne", or None
        resolved: dict of func -> stub_file
        info: list of (func, pct, role) for display ("leaking-dominant",
              "leaking", or "complexity")
        excluded: list of functions excluded from A (A intersect B)
    """
    total_lines = sum(func_line_counts.values())
    if total_lines == 0:
        return None, {}, [], []

    # Identify sets for NewPrime strategies
    if newprimeall or newprimeone:
        # A = set of the "nearest" stubbable BN functions for each leak chain
        # B = set of BN functions that call ANY function in set A within those chains
        A = set()
        B = set()
        for chain in leak_call_chains:
            # Find the first stubbable BN function in this chain
            target_idx = -1
            for i, func in enumerate(chain):
                if is_bn_function(func, library) and func in func_to_file:
                    target_idx = i
                    A.add(func)
                    break
            
            # If we found a target BN function, add ALL BN functions further up 
            # the chain to Set B. This ensures that 'C = A - B' identifies 
            # only the "lowest" stubbable BN functions in the hierarchy.
            if target_idx != -1:
                for i in range(target_idx + 1, len(chain)):
                    caller = chain[i]
                    if is_bn_function(caller, library) and caller in func_to_file:
                        B.add(caller)

        # C = terminal leakers
        C = A - B
        excluded = sorted(list(A & B))

        if C:
            if newprimeall:
                resolved = {f: func_to_file[f] for f in C}
                info = [
                    (f, subtree_costs.get(f, func_line_counts.get(f, 0)) / total_lines, "newprime-all")
                    for f in sorted(C, key=lambda f: subtree_costs.get(f, func_line_counts.get(f, 0)), reverse=True)
                ]
                return "NewPrimeAll", resolved, info, excluded
            else: # newprimeone
                best = max(C, key=lambda f: subtree_costs.get(f, func_line_counts.get(f, 0)))
                pct = subtree_costs.get(best, func_line_counts.get(best, 0)) / total_lines
                resolved = {best: func_to_file[best]}
                info = [(best, pct, "newprime-one")]
                return "NewPrimeOne", resolved, info, excluded

    # For each leak chain, walk from the leaking function outward to find the
    # nearest BN function that has a stub.  This handles cases like bin2bn
    # (non-BN by prefix) whose nearest BN caller BN_bin2bn does have a stub.
    # Use subtree cost for ranking: it reflects how much analysis is eliminated.
    leaking_bn = {}  # bn_func -> subtree_cost
    for chain in leak_call_chains:
        for f in chain:
            if is_bn_function(f, library) and f in func_to_file:
                cost = subtree_costs.get(f, func_line_counts.get(f, 0))
                if f not in leaking_bn or cost > leaking_bn[f]:
                    leaking_bn[f] = cost
                break  # nearest BN in this chain is sufficient

    # P1: leaking BN functions that are also dominant (>= threshold by subtree cost)
    if leaking_bn:
        dominant = {
            f: cost for f, cost in leaking_bn.items()
            if cost / total_lines >= AUTO_P1_DOMINANCE_THRESHOLD
        }
        if dominant:
            best = max(dominant, key=lambda f: dominant[f])
            pct = dominant[best] / total_lines
            resolved = {best: func_to_file[best]}
            info = [(best, pct, "leaking-dominant")]
            return "P1", resolved, info, []

    # P2: stub all leaking BN functions (skipped if newprime mode is active)
    if leaking_bn and not (newprimeall or newprimeone):
        resolved = {f: func_to_file[f] for f in leaking_bn}
        info = [
            (f, leaking_bn[f] / total_lines, "leaking")
            for f in sorted(leaking_bn, key=lambda f: leaking_bn[f], reverse=True)
        ]
        return "P2", resolved, info, []

    # P3: complexity fallback — stub the single deepest (lowest subtree cost)
    # BN function that still exceeds the threshold.  Picking the minimum
    # subtree cost avoids hiding an outer caller that we still want to see.
    candidates = {}
    for f in func_line_counts:
        if not is_bn_function(f, library) or f not in func_to_file:
            continue
        cost = subtree_costs.get(f, func_line_counts.get(f, 0))
        if cost / total_lines >= AUTO_P3_SUBTREE_THRESHOLD:
            candidates[f] = cost

    if candidates:
        best = min(candidates, key=lambda f: candidates[f])
        pct = candidates[best] / total_lines
        return "P3", {best: func_to_file[best]}, [(best, pct, "complexity")], []

    return None, {}, [], []


def find_stub_files_for_auto(binsec_root, library, platform, target_funcs, keylen=0):
    """For each target function, find the first .ini file that replaces it.

    Searches all subdirectories of binsec/<platform>/<library>/ (except random/).

    If keylen > 0 and a file contains popBV with a bitvector size, only accept
    the file if the size matches keylen. Files without popBV are always accepted.

    Returns:
        func_to_file: dict mapping function name -> file path
    """
    lib_dir = os.path.join(binsec_root, platform, library)
    if not os.path.isdir(lib_dir):
        return {}

    func_to_file = {}  # func_name -> file_path

    for dirpath, dirnames, filenames in sorted(os.walk(lib_dir)):
        # Skip random directory
        if os.path.basename(dirpath) == "random":
            dirnames.clear()
            continue

        for fname in sorted(filenames):
            if not fname.endswith('.ini'):
                continue
            fpath = os.path.join(dirpath, fname)
            try:
                with open(fpath) as f:
                    content = f.read()
            except (OSError, IOError):
                continue

            # Check keylen compatibility via popBV bitvector sizes
            if keylen > 0:
                popbv_sizes = set(int(s) for s in POPBV_SIZE_RE.findall(content))
                if popbv_sizes and keylen not in popbv_sizes:
                    continue

            replaced_funcs = set(REPLACE_DIRECTIVE_RE.findall(content))
            for func in replaced_funcs:
                if func in target_funcs and func not in func_to_file:
                    func_to_file[func] = fpath

    return func_to_file


def find_dead_region_funcs(log_file, library, existing_stubs):
    """Find functions in the trace that are dead regions — no leaks in their subtree.

    A function is a dead region candidate if:
    - It appears in the trace (was explored)
    - It is NOT a BN function
    - It is NOT already stubbed (not in hook at lines)
    - No leaks were found at any address within it or its callees

    Returns set of function names suitable for empty stub generation.
    """
    import gzip as _gzip
    from collections import defaultdict

    if not os.path.exists(log_file) and os.path.exists(log_file + ".gz"):
        log_file = log_file + ".gz"

    func_line_counts = defaultdict(int)
    leak_funcs = set()  # functions that directly have leaks
    hooked_funcs = set()  # functions that were stubbed (hook at)
    call_graph = defaultdict(set)  # caller -> set of callees
    last_func = None

    try:
        opener = _gzip.open if log_file.endswith(".gz") else open
        with opener(log_file, 'rt') as f:
            for line in f:
                if '[sse:debug]' in line:
                    m = ADDR_ANNOTATION_RE.search(line)
                    if m:
                        func_name = m.group(2)
                        func_line_counts[func_name] += 1
                        if last_func and last_func != func_name:
                            call_graph[last_func].add(func_name)
                        last_func = func_name
                    else:
                        m2 = FUNC_ANNOTATION_RE.search(line)
                        if m2:
                            func_name = m2.group(1)
                            func_line_counts[func_name] += 1
                            if last_func and last_func != func_name:
                                call_graph[last_func].add(func_name)
                            last_func = func_name

                if AUTO_LEAK_RE.search(line):
                    # The leak is at the current function
                    if last_func:
                        leak_funcs.add(last_func)

                m = HOOK_AT_RE.search(line)
                if m:
                    hooked_funcs.add(m.group(1))
    except (OSError, IOError):
        return set()

    # Build set of functions with leaks in subtree (transitive closure)
    # A function has "tainted subtree" if it or any of its callees (recursively) has a leak
    tainted = set(leak_funcs)
    changed = True
    while changed:
        changed = False
        for caller, callees in call_graph.items():
            if caller not in tainted and any(c in tainted for c in callees):
                tainted.add(caller)
                changed = True

    # Get names of all functions replaced by existing stubs
    existing_stub_funcs = set()
    for fpath in existing_stubs:
        try:
            with open(fpath) as f:
                existing_stub_funcs.update(REPLACE_DIRECTIVE_RE.findall(f.read()))
        except (OSError, IOError):
            pass

    # Dead region: explored, not BN, not already stubbed, not tainted
    dead = set()
    for func in func_line_counts:
        if func in tainted:
            continue
        if is_bn_function(func, library):
            continue
        if func in hooked_funcs:
            continue
        if func in existing_stub_funcs:
            continue
        # Must have significant trace presence (skip tiny functions)
        if func_line_counts[func] < 100:
            continue
        dead.add(func)

    return dead


def generate_empty_stubs(func_names, output_dir, prefix="dead"):
    """Generate empty stub .ini files for the given functions.

    Creates one file per function: replace <func>(_) by return 0 end

    Returns set of generated file paths.
    """
    os.makedirs(output_dir, exist_ok=True)
    generated = set()
    for func in sorted(func_names):
        stub_path = os.path.join(output_dir, f"{prefix}_{func}.ini")
        with open(stub_path, 'w') as f:
            f.write(f"replace <{func}>(_) by\n")
            f.write(f"        return 0\n")
            f.write(f"end\n")
        generated.add(stub_path)
    return generated


def build_stub_func_map(stub_files):
    """Build a mapping of function_name -> stub_file_path for a set of stub files."""
    func_to_file = {}
    for fpath in stub_files:
        try:
            with open(fpath) as f:
                content = f.read()
            for func in REPLACE_DIRECTIVE_RE.findall(content):
                if func not in func_to_file:
                    func_to_file[func] = fpath
        except (OSError, IOError):
            pass
    return func_to_file


def find_all_keylen_stubs(binsec_root, library, platform, keylen=0):
    """Find ALL .ini stub files for a library that are keylen-compatible.

    Deduplicates files that replace the same set of functions — only the
    first file found (alphabetical walk order) is kept per unique function set.

    Returns set of file paths.
    """
    lib_dir = os.path.join(binsec_root, platform, library)
    if not os.path.isdir(lib_dir):
        return set()

    stub_files = set()
    seen_func_sets = {}  # frozenset of replaced funcs -> first file path
    for dirpath, dirnames, filenames in sorted(os.walk(lib_dir)):
        if os.path.basename(dirpath) == "random":
            dirnames.clear()
            continue
        for fname in sorted(filenames):
            if not fname.endswith('.ini'):
                continue
            fpath = os.path.join(dirpath, fname)
            try:
                with open(fpath) as f:
                    content = f.read()
            except (OSError, IOError):
                continue
            # Must have at least one replace directive
            replaced_funcs = frozenset(REPLACE_DIRECTIVE_RE.findall(content))
            if not replaced_funcs:
                continue
            # Check keylen compatibility
            if keylen > 0:
                popbv_sizes = set(int(s) for s in POPBV_SIZE_RE.findall(content))
                if popbv_sizes and keylen not in popbv_sizes:
                    continue
            # Deduplicate: keep first file per unique function set
            if replaced_funcs not in seen_func_sets:
                seen_func_sets[replaced_funcs] = fpath
                stub_files.add(fpath)

    return stub_files


def tree_test(args):
    """Tree mode: start with all stubs, progressively unstub to find leak sources."""
    script_root = f"{args.root}/binsec/"

    base_ini = f"{script_root}{args.platform}/core.ini" if args.startfrom == "core" else \
               f"{script_root}{args.platform}/{args.startfrom}"

    library_str = args.library if not args.optimization else f"{args.library}-{args.optimization}"

    base_dir = f"{script_root}{args.platform}/{args.library}"

    # Base library stubs (loaded when bn is enabled)
    base_stub_files = list_files(base_dir)
    base_stubs = ("," + ",".join(base_stub_files)) if base_stub_files else ""

    # Load keylen config and resolve
    keylen_config = load_keylen_config(args.root)
    resolved_keylen = args.keylen
    try:
        if args.library in keylen_config:
            lib_conf = keylen_config[args.library]
            if args.algorithm in lib_conf:
                alg_conf = lib_conf[args.algorithm]
                if args.platform in alg_conf:
                    resolved_keylen = alg_conf[args.platform]
    except Exception:
        pass

    bn_option = f"-bn -bn-backend {args.library} -bn-keylen {resolved_keylen} "

    base_root_ini = base_ini if args.nature == "dry" else \
                    f"{base_ini},{script_root}{args.platform}/{args.nature}.ini"

    random_file = ""
    random_dir = f"{script_root}{args.platform}/{args.library}/random"
    if os.path.exists(random_dir):
        if args.random == RandomMode.RANDOM.value:
            random_file = f",{random_dir}/rand.ini"
        else:
            random_file = f",{random_dir}/const.ini"

    algorithm = args.algorithm
    nature = args.nature

    gs_path = ""
    if args.platform == Platform.X86.value:
        gs_path = f",{args.root}/benchmark/{args.platform}/{library_str}/{algorithm}/bin/gs.ini"

    extra = f",{args.extra}" if args.extra else ""
    tag = args.tag if not args.tag else f"_{args.tag}"

    dbg = 0 if args.no_details else 2
    if args.report and dbg < 2:
        dbg = 2

    # Determine binary path
    if args.startfrom == "core":
        binary_path = f"{args.root}/benchmark/{args.platform}/{library_str}/{algorithm}/bin/{algorithm}_{library_str}_{args.platform}.core"
        debug_binary = binary_path[:-5]
    else:
        binary_path = f"{args.root}/benchmark/{args.platform}/{library_str}/{algorithm}/bin/{algorithm}_{library_str}_{args.platform}"
        debug_binary = binary_path

    # Auto-build
    if args.build or args.startfrom == "core":
        if not prepare_benchmark(args.root, args.platform, library_str, args.algorithm):
            print(f"[ERROR] Failed to prepare benchmark, aborting", file=sys.stderr)
            return False

    # Create output directory
    output_path = f"{args.root}/results/{args.platform}/{library_str}/{algorithm}"
    os.makedirs(output_path, exist_ok=True)

    # Clean if requested
    if args.clean:
        import glob as _glob
        for f in _glob.glob(os.path.join(output_path, "*")):
            os.remove(f)
            print(f"[CLEAN] Removed {os.path.relpath(f, args.root)}")
        if args.report:
            report_base = args.report
        else:
            report_base = os.path.join(args.root, "reports")
        if args.optimization:
            report_dir = os.path.join(report_base, args.optimization)
        else:
            report_dir = report_base
        if os.path.isdir(report_dir):
            pattern = os.path.join(report_dir, f"{library_str}_{algorithm}*")
            for f in _glob.glob(pattern):
                os.remove(f)
                print(f"[CLEAN] Removed {os.path.relpath(f, args.root)}")

    # Find all keylen-compatible stubs
    all_stubs = find_all_keylen_stubs(script_root, args.library, args.platform, resolved_keylen)
    func_to_file = build_stub_func_map(all_stubs)

    # Reverse map: file -> set of functions
    file_to_funcs = {}
    for func, fpath in func_to_file.items():
        if fpath not in file_to_funcs:
            file_to_funcs[fpath] = set()
        file_to_funcs[fpath].add(func)

    success = True
    iteration_stats = []
    iteration_leaks_files = []
    iteration_leak_sites = []  # list of sets of leak site strings per iteration (for diff report)
    iteration_leak_times = []  # list of dicts mapping site -> earliest_time (parallel)
    dead_stub_files = set()  # auto-generated empty stubs for dead regions
    dead_stub_dir = os.path.join(output_path, "dead_stubs")
    all_dead_funcs = set()  # all functions we've generated dead stubs for

    def run_tree_iteration(label, stub_files, log_name):
        """Run binsec with given stub files. Returns (n_alerts, n_unique, hooked_bn, log_file, leaks_path)."""
        # Include dead region stubs
        combined_stubs = stub_files | dead_stub_files
        stub_scripts = ("," + ",".join(sorted(combined_stubs))) if combined_stubs else ""
        script_files = (
            f"{base_root_ini},{script_root}{args.platform}/mem.ini"
            f"{random_file}{gs_path}{extra}{base_stubs}{stub_scripts}"
        )
        log_file = f"{output_path}/{nature}_tree_{log_name}{tag}.log"

        run_cmd = (
            f"binsec -sse -checkct {bn_option}-sse-missing-symbol warn -sse-script {script_files} "
            f"-sse-debug-level {dbg} -sse-depth 1000000000 "
            f"-fml-solver-timeout 600 -sse-timeout {args.timeout} {binary_path} "
            f"-smt-solver bitwuzla:smtlib"
        )

        parts = run_cmd.split()
        if not parts:
            return 0, 0, set(), log_file, None

        program = parts[0]
        run_args = parts[1:]

        print(f"[CASE] tree {label}")
        nonlocal success
        if not run_and_log(program, run_args, log_file, algorithm, nature, tag, args.memlimit, gzip_after=not args.end_report):
            success = False

        n_alerts = count_leaks_in_log(log_file)
        hooked_bn = get_hooked_bn_functions(log_file, args.library)

        # Generate .leaks and count unique
        n_unique = 0
        leaks_path = log_file.replace('.log', '.leaks')
        if generate_leaks_file(log_file, debug_binary, leaks_path):
            generate_uniq_file(leaks_path, leaks_path + ".uniq")
            n = count_unique_in_leaks([leaks_path])
            if n is not None:
                n_unique = n
            iteration_leaks_files.append(leaks_path)
        elif n_alerts > 0:
            n_unique = len(get_unique_leak_addrs(log_file))
            leaks_path = None

        return n_alerts, n_unique, hooked_bn, log_file, leaks_path

    # ── Phase 0: All stubs ──
    print(f"\n{'='*60}")
    print(f"[TREE] Phase 0: All stubs ({len(all_stubs)} files, {count_stubbed_functions(all_stubs)} functions)")
    print(f"{'='*60}")

    n_alerts, n_unique, hooked_bn, log_file, leaks_path = run_tree_iteration(
        "allstubs", all_stubs, "allstubs"
    )

    print(f"  [BN HOOKS] {len(hooked_bn)} BN functions applied:")
    for f in sorted(hooked_bn):
        print(f"    {f}")

    iteration_stats.append({
        "phase": "allstubs",
        "removed": None,
        "parent": None,
        "alerts": n_alerts,
        "unique_alerts": n_unique,
        "stubs": count_stubbed_functions(all_stubs),
        "hooked_bn": len(hooked_bn),
        "hooked_bn_funcs": sorted(hooked_bn),
        "log_file": os.path.relpath(log_file, args.root),
    })
    if args.report_diff and leaks_path and os.path.exists(leaks_path):
        sites = extract_unique_leak_sites([leaks_path])
        iteration_leak_sites.append(sites if sites else set())
    else:
        iteration_leak_sites.append(set())

    # Dead-erase: generate empty stubs for dead regions after allstubs run
    if args.dead_erase:
        dead_funcs = find_dead_region_funcs(log_file, args.library, all_stubs)
        if dead_funcs:
            new_dead = dead_funcs - all_dead_funcs
            if new_dead:
                gen = generate_empty_stubs(new_dead, dead_stub_dir)
                dead_stub_files.update(gen)
                all_dead_funcs.update(new_dead)
                print(f"  [DEAD-ERASE] Generated {len(new_dead)} empty stubs for dead regions:")
                for f in sorted(new_dead):
                    print(f"    {f}")

    # ── Progressive unstubbing ──
    # Queue: list of (func_to_remove, parent_phase, current_stub_set)
    # Start with all hooked BN functions from phase 0
    current_stubs = set(all_stubs)
    unstub_queue = []
    seen_funcs = set()  # all BN functions we've already queued for removal
    dead_funcs = set()  # functions whose removal produced no leaks and no new hooks

    # Sort by function name for deterministic order
    for func in sorted(hooked_bn):
        if func in func_to_file:
            unstub_queue.append((func, "allstubs", set(current_stubs)))
            seen_funcs.add(func)

    step = 0
    while unstub_queue:
        func_to_remove, parent, stubs_snapshot = unstub_queue.pop(0)
        step += 1

        # Find the stub file for this function and remove it
        stub_file = func_to_file.get(func_to_remove)
        if not stub_file or stub_file not in stubs_snapshot:
            print(f"\n[TREE] Step {step}: {func_to_remove} — no stub file to remove, skipping")
            continue

        new_stubs = stubs_snapshot - {stub_file}
        removed_funcs = file_to_funcs.get(stub_file, {func_to_remove})

        # Re-add stubs for dead functions to keep execution fast
        for df in dead_funcs:
            df_file = func_to_file.get(df)
            if df_file and df_file not in new_stubs:
                new_stubs.add(df_file)

        print(f"\n{'='*60}")
        print(f"[TREE] Step {step}: Remove {func_to_remove}")
        print(f"  Parent: {parent}")
        print(f"  Stub file: {os.path.relpath(stub_file, args.root)}")
        if len(removed_funcs) > 1:
            print(f"  Also removes: {', '.join(sorted(removed_funcs - {func_to_remove}))}")
        print(f"  Remaining stubs: {len(new_stubs)} files")
        if dead_funcs:
            print(f"  Dead branches re-stubbed: {len(dead_funcs)}")
        print(f"{'='*60}")

        phase_name = f"remove_{func_to_remove}"
        n_alerts, n_unique, hooked_bn, log_file, leaks_path = run_tree_iteration(
            f"step {step} (remove {func_to_remove})", new_stubs, f"s{step}_{func_to_remove}"
        )

        if hooked_bn:
            print(f"  [BN HOOKS] {len(hooked_bn)} BN functions applied:")
            for f in sorted(hooked_bn):
                print(f"    {f}")

        # Find newly exposed BN functions (hooked now but not seen before)
        new_bn = hooked_bn - seen_funcs
        is_dead = (n_alerts == 0 and len(new_bn) == 0)

        if is_dead:
            print(f"  [DEAD BRANCH] No leaks, no new BN hooks — pruning")
            dead_funcs.add(func_to_remove)
        elif new_bn:
            print(f"  [NEW BN] {len(new_bn)} newly exposed:")
            for f in sorted(new_bn):
                print(f"    {f}")
            # Add them to the queue with current stubs as snapshot
            for f in sorted(new_bn):
                if f in func_to_file:
                    unstub_queue.append((f, phase_name, set(new_stubs)))
                    seen_funcs.add(f)
                else:
                    print(f"    {f} — no stub available, cannot unstub further")

        iteration_stats.append({
            "phase": phase_name,
            "removed": func_to_remove,
            "parent": parent,
            "alerts": n_alerts,
            "unique_alerts": n_unique,
            "stubs": count_stubbed_functions(new_stubs),
            "hooked_bn": len(hooked_bn),
            "hooked_bn_funcs": sorted(hooked_bn),
            "dead": is_dead,
            "log_file": os.path.relpath(log_file, args.root),
        })
        if args.report_diff and leaks_path and os.path.exists(leaks_path):
            sites = extract_unique_leak_sites([leaks_path])
            times = extract_leak_sites_with_time(leaks_path)
            iteration_leak_sites.append(sites if sites else set())
            iteration_leak_times.append(times if times else {})
        else:
            iteration_leak_sites.append(set())
            iteration_leak_times.append({})

        # Dead-erase after each step
        if args.dead_erase and not is_dead:
            dead_funcs_step = find_dead_region_funcs(log_file, args.library, new_stubs | dead_stub_files)
            new_dead = dead_funcs_step - all_dead_funcs
            if new_dead:
                gen = generate_empty_stubs(new_dead, dead_stub_dir)
                dead_stub_files.update(gen)
                all_dead_funcs.update(new_dead)
                print(f"  [DEAD-ERASE] Generated {len(new_dead)} new empty stubs:")
                for f in sorted(new_dead):
                    print(f"    {f}")

    if args.dead_erase and all_dead_funcs:
        print(f"\n[DEAD-ERASE] Total: {len(all_dead_funcs)} dead region stubs generated")

    # ── Final run: no stubs, extended timeout ──
    is_keygen = "keygen" in algorithm
    total_runs = step + 1  # allstubs + N steps
    final_timeout = args.timeout * (total_runs + 1)
    final_bn = bn_option if is_keygen else ""
    final_base_stubs = base_stubs if is_keygen else ""

    bn_label = "with BN" if is_keygen else "no BN"
    print(f"\n{'='*60}")
    print(f"[TREE] Final run ({bn_label}, no stubs, timeout={final_timeout}s)")
    print(f"{'='*60}")

    script_files = (
        f"{base_root_ini},{script_root}{args.platform}/mem.ini"
        f"{random_file}{gs_path}{extra}{final_base_stubs}"
    )
    log_file = f"{output_path}/{nature}_tree_final{tag}.log"
    run_cmd = (
        f"binsec -sse -checkct {final_bn}-sse-missing-symbol warn -sse-script {script_files} "
        f"-sse-debug-level {dbg} -sse-depth 1000000000 "
        f"-fml-solver-timeout 600 -sse-timeout {final_timeout} {binary_path} "
        f"-smt-solver bitwuzla:smtlib"
    )
    parts = run_cmd.split()
    if parts:
        program = parts[0]
        run_args = parts[1:]
        print(f"[CASE] tree final")
        if not run_and_log(program, run_args, log_file, algorithm, nature, tag, args.memlimit, gzip_after=not args.end_report):
            success = False

        n_alerts = count_leaks_in_log(log_file)
        leaks_path = log_file.replace('.log', '.leaks')
        n_unique = 0
        if generate_leaks_file(log_file, debug_binary, leaks_path):
            generate_uniq_file(leaks_path, leaks_path + ".uniq")
            n = count_unique_in_leaks([leaks_path])
            if n is not None:
                n_unique = n
            iteration_leaks_files.append(leaks_path)
        elif n_alerts > 0:
            n_unique = len(get_unique_leak_addrs(log_file))
        hooked_bn = get_hooked_bn_functions(log_file, args.library)

        iteration_stats.append({
            "phase": "final",
            "removed": None,
            "parent": None,
            "alerts": n_alerts,
            "unique_alerts": n_unique,
            "stubs": 0,
            "hooked_bn": len(hooked_bn),
            "hooked_bn_funcs": sorted(hooked_bn),
            "log_file": os.path.relpath(log_file, args.root),
        })
        if args.report_diff and leaks_path and os.path.exists(leaks_path):
            sites = extract_unique_leak_sites([leaks_path])
            times = extract_leak_sites_with_time(leaks_path)
            iteration_leak_sites.append(sites if sites else set())
            iteration_leak_times.append(times if times else {})
        else:
            iteration_leak_sites.append(set())
            iteration_leak_times.append({})
        if hooked_bn:
            print(f"  [BN HOOKS] {len(hooked_bn)} BN functions applied:")
            for f in sorted(hooked_bn):
                print(f"    {f}")

    if args.end_report:
        # ── Summary ──
        print(f"\n{'='*60}")
        print(f"[TREE] Summary")
        print(f"{'='*60}")
        print(f"  {'Phase':<40s} {'Alerts':>8s} {'Uniq Src':>8s} {'Stubs':>8s} {'BN Hook':>8s}")
        print(f"  {'-'*76}")
        for s in iteration_stats:
            phase = s['phase']
            if s.get('parent'):
                phase = f"  {phase} (from {s['parent']})"
            dead_mark = " [DEAD]" if s.get('dead') else ""
            print(f"  {phase:<40s} {s['alerts']:>8d} {s['unique_alerts']:>8d} {s['stubs']:>8d} {s['hooked_bn']:>8d}{dead_mark}")
            bn_funcs = s.get('hooked_bn_funcs', [])
            if bn_funcs:
                print(f"    BN applied: {', '.join(bn_funcs)}")
        if dead_funcs:
            print(f"\n  Dead branches ({len(dead_funcs)}): {', '.join(sorted(dead_funcs))}")

        # Diff report
        if args.report_diff and iteration_leak_sites:
            print_diff_report(iteration_stats, iteration_leak_sites, iteration_leak_times)

        # LaTeX tables
        latex_title = f"{args.library} {algorithm} {args.optimization or ''} (tree)"
        print_latex_table(iteration_stats, latex_title)
        if args.report_diff and iteration_leak_sites:
            print_latex_diff_table(iteration_stats, iteration_leak_sites, latex_title)

    # ── Merged unique alerts across all runs ──
    merged_total = count_unique_in_leaks(iteration_leaks_files)
    if merged_total is None:
        merged_total = 0

    print(f"\n  {'='*76}")
    print(f"  Total unique source-level alerts (merged): {merged_total}")

    if merged_total > 0 and iteration_leaks_files:
        # Run merge_reports to get the actual unique alerts and print them
        merge_reports_script = os.path.join(os.path.dirname(os.path.abspath(__file__)), "merge_reports.py")
        import tempfile
        try:
            with tempfile.NamedTemporaryFile(suffix='.merged', delete=False, mode='w') as tmp:
                tmp_path = tmp.name
            valid_files = [f for f in iteration_leaks_files if os.path.exists(f) and os.path.getsize(f) > 0]
            if valid_files:
                r = subprocess.run(
                    [sys.executable, merge_reports_script, '--uniq-source', '-o', tmp_path] + valid_files,
                    capture_output=True, text=True, timeout=60
                )
                if r.returncode == 0:
                    with open(tmp_path, 'r') as f:
                        in_entry = False
                        for line in f:
                            line = line.rstrip('\n')
                            if re.match(r'^UNIQUE #\d+', line):
                                in_entry = True
                                print(f"  {line}")
                            elif in_entry:
                                if line.startswith('-' * 40) or line.startswith('=' * 40):
                                    in_entry = False
                                elif line.strip() == '':
                                    in_entry = False
                                    print()
                                else:
                                    # Print just the leak site line (with <--)
                                    if '<--' in line:
                                        cleaned = re.sub(r'\[0x[0-9a-fA-F]+\]\s*', '', line)
                                        cleaned = re.sub(r'^[\s└─│├]+', '', cleaned).strip()
                                        print(f"    -> {cleaned}")
                                        in_entry = False
        except Exception:
            pass
        finally:
            try:
                os.unlink(tmp_path)
            except OSError:
                pass

    print(f"  {'='*76}")

    # ── Write JSON ──
    json_data = {
        "library": args.library,
        "primitive": algorithm,
        "optimization": args.optimization or "",
        "nature": nature,
        "platform": args.platform,
        "timeout": args.timeout,
        "keylen": resolved_keylen,
        "mode": "tree",
        "dead_erase": args.dead_erase,
        "dead_region_funcs": sorted(all_dead_funcs) if all_dead_funcs else [],
        "iterations": iteration_stats,
        "total_unique_alerts": merged_total,
    }
    json_file = os.path.join(
        output_path,
        f"{nature}_{library_str}_{algorithm}_tree{tag}.json"
    )
    with open(json_file, 'w') as jf:
        json.dump(json_data, jf, indent=2)
    print(f"\n[TREE] Results written to {os.path.relpath(json_file, args.root)}")

    return success


def _auto_iter_report(iteration, log_file, binary_path, accumulated_stubs,
                      args, script_root, resolved_keylen, generate_leaks=True):
    """Analyze one auto-mode iteration log: print evidence and compute next stubs.

    Parameters
    ----------
    iteration     : iteration index (0 = no-stub baseline)
    log_file      : path to the BINSEC log for this iteration
    binary_path   : path to the binary (for callstack2source)
    accumulated_stubs : set of stub file paths already added before this iteration
    args          : parsed CLI args (library, platform, group, report_diff, root, …)
    script_root   : binsec/ root path
    resolved_keylen : key length for stub compatibility filtering
    generate_leaks : if True, run callstack2source to create the .leaks file;
                     if False, use an existing .leaks file if present (replay mode)

    Returns
    -------
    stats         : dict ready for iteration_stats.append()
    leaks_path    : path to .leaks file (may not exist)
    leak_sites    : set of unique leak site strings (for diff report)
    leak_times    : dict of site -> earliest time (for diff report)
    new_files     : set of stub file paths to add before the NEXT iteration
    func_to_file  : func -> stub file mapping (for further reporting)
    func_counts   : func -> annotation line count mapping
    subtree_costs : func -> subtree analysis cost mapping
    """
    library = args.library

    func_counts, subtree_costs, leak_call_chains, _ = parse_log_for_auto(log_file, library)
    n_alerts = count_leaks_in_log(log_file)

    leaks_path = log_file.replace('.log', '.leaks')
    n_unique = 0
    if generate_leaks:
        if generate_leaks_file(log_file, binary_path, leaks_path):
            generate_uniq_file(leaks_path, leaks_path + ".uniq")
            n = count_unique_in_leaks([leaks_path])
            if n is not None:
                n_unique = n
        else:
            n_unique = len(get_unique_leak_addrs(log_file))
    elif os.path.exists(leaks_path):
        n = count_unique_in_leaks([leaks_path])
        if n is not None:
            n_unique = n

    hooked_bn = get_hooked_bn_functions(log_file, library)
    phase_name = "no_stub" if iteration == 0 else f"stub_{iteration}"

    stats = {
        "iteration": iteration,
        "phase": phase_name,
        "alerts": n_alerts,
        "unique_alerts": n_unique,
        "stubs": count_stubbed_functions(accumulated_stubs),
        "hooked_bn": len(hooked_bn),
        "hooked_bn_funcs": sorted(hooked_bn),
        "log_file": os.path.relpath(log_file, args.root),
    }

    leak_sites = set()
    leak_times = {}
    if args.report_diff and os.path.exists(leaks_path):
        s = extract_unique_leak_sites([leaks_path])
        t = extract_leak_sites_with_time(leaks_path)
        leak_sites = s if s else set()
        leak_times = t if t else {}

    # ── Print evidence ──
    if hooked_bn:
        print(f"  [BN HOOKS] {len(hooked_bn)} BN functions applied:")
        for f in sorted(hooked_bn):
            print(f"    {f}")

    total_lines = sum(func_counts.values())
    if total_lines == 0:
        print(f"  [AUTO] No traced lines found in log")
        return stats, leaks_path, leak_sites, leak_times, set(), {}, func_counts, set()

    bn_lines = sum(c for f, c in func_counts.items() if is_bn_function(f, library))
    leak_bn_funcs = {f for chain in leak_call_chains for f in chain if is_bn_function(f, library)}

    print()
    print(f"  {'─'*56}")
    print(f"  LOG ANALYSIS REPORT  (iteration {iteration})")
    print(f"  {'─'*56}")
    print(f"  Total traced lines : {total_lines}")
    print(f"  BN function lines  : {bn_lines} ({100*bn_lines/total_lines:.1f}%)")
    print(f"  Other lines        : {total_lines - bn_lines} ({100*(total_lines - bn_lines)/total_lines:.1f}%)")
    print()
    # Show all functions whose subtree cost >= AUTO_DISPLAY_MIN_PCT of total,
    # sorted descending.  Subtree costs double-count (ancestor includes
    # descendants) so cumulative accumulation is meaningless; a per-function
    # minimum threshold gives a stable, predictable list that always includes
    # any P3 candidate and any wrapper with significant analysis weight.
    min_sc = total_lines * AUTO_DISPLAY_MIN_PCT
    print(f"  Functions with subtree cost >= {AUTO_DISPLAY_MIN_PCT:.0%} of total (sorted by subtree cost):")
    print(f"    {'Function':40s} {'SubCost':>8s} {'(%tot)':>7s}  {'AnnLines':>8s}")
    top_count = 0
    for f in sorted(func_counts, key=lambda f: subtree_costs.get(f, func_counts[f]), reverse=True):
        sc = subtree_costs.get(f, func_counts[f])
        if sc < min_sc:
            break
        c = func_counts[f]
        pct = 100 * sc / total_lines
        bn_mark = " [BN]" if is_bn_function(f, library) else ""
        leak_mark = " *** LEAK" if f in leak_bn_funcs else ""
        print(f"    {f:40s} {sc:8d}  ({pct:5.1f}%)  {c:8d}{bn_mark}{leak_mark}")
        top_count += 1
    remaining = len(func_counts) - top_count
    if remaining > 0:
        print(f"    ... and {remaining} more functions below {AUTO_DISPLAY_MIN_PCT:.0%}")

    bn_dominant = bn_lines / total_lines > 0.50
    print()
    print(f"  BN dominance (>50%): {'YES' if bn_dominant else 'NO'} ({100*bn_lines/total_lines:.1f}%)")

    # Build stub map before reporting so we can show BN targets for non-BN leakers
    all_bn_funcs = {f for f in func_counts if is_bn_function(f, library)}
    func_to_file = find_stub_files_for_auto(script_root, library, args.platform, all_bn_funcs, resolved_keylen)

    # Leaking functions not resolved by BN prefix
    leak_nonbn = {chain[0] for chain in leak_call_chains if chain
                  and not is_bn_function(chain[0], library)}
    if leak_nonbn:
        # Build nearest-BN-caller map for each non-BN leaker
        nonbn_to_bn = {}
        for chain in leak_call_chains:
            if not chain or is_bn_function(chain[0], library):
                continue
            leaker = chain[0]
            for f in chain[1:]:
                if is_bn_function(f, library) and f in func_to_file:
                    nonbn_to_bn[leaker] = f
                    break
        print()
        print(f"  Leaking non-BN functions ({len(leak_nonbn)}):")
        for f in sorted(leak_nonbn, key=lambda x: -(subtree_costs.get(x, func_counts.get(x, 0)))):
            sc = subtree_costs.get(f, func_counts.get(f, 0))
            pct = 100 * sc / total_lines
            target = nonbn_to_bn.get(f)
            target_str = f"  -> stub {target}" if target else "  (no BN caller with stub)"
            print(f"    {f:40s}  {pct:5.1f}%{target_str}")

    strategy, resolved, strat_info, excluded = resolve_auto_stubs(
        leak_call_chains, func_counts, subtree_costs, func_to_file, library,
        newprimeall=args.newprimeall, newprimeone=args.newprimeone
    )

    print()
    if strategy == "NewPrimeAll":
        print(f"  Strategy: NewPrimeAll (stub all terminal leakers, {len(strat_info)} found)")
        for func, pct, _ in strat_info:
            print(f"    {func:40s}  {100*pct:5.1f}%  [terminal leaker]")
        if excluded:
            print(f"  Functions in A but excluded (also in B): {', '.join(excluded)}")
    elif strategy == "NewPrimeOne":
        func, pct, _ = strat_info[0]
        print(f"  Strategy: NewPrimeOne (stub highest-cost terminal leaker)")
        print(f"    SELECTED: {func:30s}  {100*pct:5.1f}%  [terminal leaker]")
        if excluded:
            print(f"  Functions in A but excluded (also in B): {', '.join(excluded)}")
    elif strategy == "P1":
        func, pct, _ = strat_info[0]
        print(f"  Strategy: P1 (dominant leaking BN, threshold={AUTO_P1_DOMINANCE_THRESHOLD:.0%})")
        print(f"    {func:40s}  {100*pct:5.1f}%  [leaking + dominant]")
    elif strategy == "P2":
        print(f"  Strategy: P2 (leaking BN functions, {len(strat_info)} found)")
        for func, pct, _ in strat_info:
            print(f"    {func:40s}  {100*pct:5.1f}%  [leaking]")
    elif strategy == "P3":
        func, pct, _ = strat_info[0]
        print(f"  Strategy: P3 (deepest BN above threshold={AUTO_P3_SUBTREE_THRESHOLD:.0%})")
        print(f"    {func:40s}  {100*pct:5.1f}%  [deepest above threshold]")
    else:
        print(f"  No stubs found (no leaking BN functions, no BN function reaches {AUTO_P3_SUBTREE_THRESHOLD:.0%} subtree share).")
        print(f"  {'─'*56}")
        return stats, leaks_path, leak_sites, leak_times, set(), func_to_file, func_counts, excluded

    # Compute new files respecting --group
    resolved_files = set(resolved.values())
    new_files = resolved_files - accumulated_stubs

    def _file_share(fpath):
        return sum(func_counts.get(f, 0) for f, fp in func_to_file.items() if fp == fpath)

    ranked_new = sorted(new_files, key=_file_share, reverse=True)
    all_new_files = set(ranked_new)

    if args.group > 0 and len(ranked_new) > args.group:
        new_files = set(ranked_new[:args.group])
        deferred = set(ranked_new[args.group:])
    else:
        new_files = set(ranked_new)
        deferred = set()

    next_funcs = {f for f, fp in func_to_file.items() if fp in new_files}
    print()
    if next_funcs:
        print(f"  Functions to stub NEXT ({len(next_funcs)}):")
        for f in sorted(next_funcs, key=lambda x: -func_counts.get(x, 0)):
            print(f"    {f:40s} -> {os.path.basename(func_to_file[f])}")

    if deferred:
        deferred_funcs = {f for f, fp in func_to_file.items() if fp in deferred}
        print(f"  Deferred to next iteration ({len(deferred_funcs)}):")
        for f in sorted(deferred_funcs, key=lambda x: -func_counts.get(x, 0)):
            print(f"    {f:40s} -> {os.path.basename(func_to_file[f])}")

    already_stubbed = {f for f, fp in func_to_file.items() if fp in accumulated_stubs}
    if already_stubbed:
        print(f"  Already stubbed ({len(already_stubbed)}): {', '.join(sorted(already_stubbed))}")

    print(f"  {'─'*56}")

    if new_files:
        group_label = f" (group {args.group}, {len(all_new_files)} available)" if args.group > 0 else ""
        print(f"\n[AUTO] Adding {len(new_files)} new stub files{group_label}:")
        for fpath in sorted(new_files, key=_file_share, reverse=True):
            covered = [f for f, fp in func_to_file.items() if fp == fpath]
            print(f"  + {os.path.relpath(fpath, args.root)} (replaces: {', '.join(sorted(covered))})")

    return stats, leaks_path, leak_sites, leak_times, new_files, func_to_file, func_counts, excluded


def auto_test(args):
    """Auto mode: iteratively discover and add bignum stubs."""
    script_root = f"{args.root}/binsec/"

    base_ini = f"{script_root}{args.platform}/core.ini" if args.startfrom == "core" else \
               f"{script_root}{args.platform}/{args.startfrom}"

    library_str = args.library if not args.optimization else f"{args.library}-{args.optimization}"

    base_dir = f"{script_root}{args.platform}/{args.library}"

    # Base library stubs (loaded when bn is enabled)
    base_stub_files = list_files(base_dir)
    base_stubs = ("," + ",".join(base_stub_files)) if base_stub_files else ""

    # Load keylen config and resolve
    keylen_config = load_keylen_config(args.root)
    resolved_keylen = args.keylen
    try:
        if args.library in keylen_config:
            lib_conf = keylen_config[args.library]
            if args.algorithm in lib_conf:
                alg_conf = lib_conf[args.algorithm]
                if args.platform in alg_conf:
                    resolved_keylen = alg_conf[args.platform]
    except Exception:
        pass

    bn_option = f"-bn -bn-backend {args.library} -bn-keylen {resolved_keylen} "

    base_root_ini = base_ini if args.nature == "dry" else \
                    f"{base_ini},{script_root}{args.platform}/{args.nature}.ini"

    random_file = ""
    random_dir = f"{script_root}{args.platform}/{args.library}/random"
    if os.path.exists(random_dir):
        if args.random == RandomMode.RANDOM.value:
            random_file = f",{random_dir}/rand.ini"
        else:
            random_file = f",{random_dir}/const.ini"

    algorithm = args.algorithm
    nature = args.nature

    gs_path = ""
    if args.platform == Platform.X86.value:
        gs_path = f",{args.root}/benchmark/{args.platform}/{library_str}/{algorithm}/bin/gs.ini"

    extra = f",{args.extra}" if args.extra else ""
    tag = args.tag if not args.tag else f"_{args.tag}"

    dbg = 0 if args.no_details else 2
    if args.report and dbg < 2:
        dbg = 2

    # Determine binary path
    if args.startfrom == "core":
        binary_path = f"{args.root}/benchmark/{args.platform}/{library_str}/{algorithm}/bin/{algorithm}_{library_str}_{args.platform}.core"
        debug_binary = binary_path[:-5]
    else:
        binary_path = f"{args.root}/benchmark/{args.platform}/{library_str}/{algorithm}/bin/{algorithm}_{library_str}_{args.platform}"
        debug_binary = binary_path

    # Auto-build if starting from core or --build is specified
    if args.build or args.startfrom == "core":
        if not prepare_benchmark(args.root, args.platform, library_str, args.algorithm):
            print(f"[ERROR] Failed to prepare benchmark, aborting", file=sys.stderr)
            return False

    # Create output directory
    output_path = f"{args.root}/results/{args.platform}/{library_str}/{algorithm}"
    os.makedirs(output_path, exist_ok=True)

    # Clean existing results and reports if requested
    if args.clean:
        import glob as _glob
        # Clean result logs
        for f in _glob.glob(os.path.join(output_path, "*")):
            os.remove(f)
            print(f"[CLEAN] Removed {os.path.relpath(f, args.root)}")
        # Clean report .leaks files
        if args.report:
            report_base = args.report
        else:
            report_base = os.path.join(args.root, "reports")
        if args.optimization:
            report_dir = os.path.join(report_base, args.optimization)
        else:
            report_dir = report_base
        if os.path.isdir(report_dir):
            pattern = os.path.join(report_dir, f"{library_str}_{algorithm}*")
            for f in _glob.glob(pattern):
                os.remove(f)
                print(f"[CLEAN] Removed {os.path.relpath(f, args.root)}")

    # Auto mode iteration loop
    accumulated_stubs = set()  # file paths discovered so far
    iteration = 0
    success = True
    iteration_stats = []  # list of dicts: {iteration, phase, alerts, unique_alerts, stubs, log_file}
    iteration_leaks_files = []  # .leaks file paths per iteration (for progressive merge)
    iteration_leak_sites = []  # list of sets of leak site strings per iteration (for diff report)
    iteration_leak_times = []  # list of dicts mapping site -> earliest_time (parallel)

    # --resume-from N: reconstruct accumulated stubs by reading only log N-1.
    # That log was run with all stubs from iterations 0..N-2 already applied
    # (visible as `hook at` annotations), plus iteration N-1 adds its own new
    # stubs.  Together they give the full accumulated stub set for iteration N.
    resume_from = getattr(args, 'resume_from', 0)
    if resume_from > 0:
        prev_log = f"{output_path}/{nature}_auto_{resume_from - 1}{tag}.log"
        if not os.path.exists(prev_log):
            print(f"[ERROR] Cannot resume: log for iteration {resume_from - 1} not found: {prev_log}",
                  file=sys.stderr)
            return False

        print(f"\n[AUTO] Resuming from iteration {resume_from} — reading log {resume_from - 1}")
        print(f"{'='*60}")
        print(f"[AUTO] Replay iteration {resume_from - 1}  (log: {os.path.relpath(prev_log, args.root)})")
        print(f"{'='*60}")

        # Reconstruct stubs that were already active in log N-1 (hooks in the log)
        # and map them back to stub files via func_to_file.
        all_bn_funcs_r = get_hooked_bn_functions(prev_log, args.library)
        func_to_file_r = find_stub_files_for_auto(
            script_root, args.library, args.platform, all_bn_funcs_r, resolved_keylen)
        for func, fpath in func_to_file_r.items():
            accumulated_stubs.add(fpath)

        # Also run the report to pick up stubs decided by iteration N-1 itself.
        stats_r, leaks_path_r, sites_r, times_r, new_files_r, _, _, _ = \
            _auto_iter_report(resume_from - 1, prev_log, debug_binary, accumulated_stubs,
                              args, script_root, resolved_keylen, generate_leaks=False)

        iteration_stats.append(stats_r)
        if leaks_path_r and os.path.exists(leaks_path_r):
            iteration_leaks_files.append(leaks_path_r)
        iteration_leak_sites.append(sites_r)
        iteration_leak_times.append(times_r)
        accumulated_stubs.update(new_files_r)

        iteration = resume_from
        print(f"\n[AUTO] State restored — starting execution at iteration {iteration}")
        print(f"[AUTO] Accumulated stubs: {len(accumulated_stubs)}")
        for sf in sorted(accumulated_stubs):
            print(f"  + {os.path.relpath(sf, args.root)}")

    while True:
        print(f"\n{'='*60}")
        print(f"[AUTO] Iteration {iteration}")
        print(f"{'='*60}")

        is_keygen = "keygen" in algorithm

        if iteration == 0:
            # First run: no bn, no stubs (except keygen always uses bn)
            use_bn = bn_option if is_keygen else ""
            use_base_stubs = base_stubs if is_keygen else ""
            auto_scripts = ""
        else:
            use_bn = bn_option
            use_base_stubs = base_stubs
            auto_scripts = ("," + ",".join(sorted(accumulated_stubs))) if accumulated_stubs else ""

        script_files = (
            f"{base_root_ini},{script_root}{args.platform}/mem.ini"
            f"{random_file}{gs_path}{extra}{use_base_stubs}{auto_scripts}"
        )

        log_file = f"{output_path}/{nature}_auto_{iteration}{tag}.log"

        run_cmd = (
            f"binsec -sse -checkct {use_bn}-sse-missing-symbol warn -sse-script {script_files} "
            f"-sse-debug-level {dbg} -sse-depth 1000000000 "
            f"-fml-solver-timeout 600 -sse-timeout {args.timeout} {binary_path} "
            f"-smt-solver bitwuzla:smtlib"
        )

        parts = run_cmd.split()
        if not parts:
            break

        program = parts[0]
        run_args = parts[1:]

        print(f"[AUTO] Accumulated stubs: {len(accumulated_stubs)} files")
        for sf in sorted(accumulated_stubs):
            print(f"  + {os.path.relpath(sf, args.root)}")

        print(f"[CASE] auto iteration {iteration}")
        if not run_and_log(program, run_args, log_file, algorithm, nature, tag, args.memlimit):
            success = False

        stats, leaks_path, leak_sites, leak_times, new_files, func_to_file, func_counts, excluded = \
            _auto_iter_report(iteration, log_file, debug_binary, accumulated_stubs,
                              args, script_root, resolved_keylen, generate_leaks=True)

        if not args.end_report:
            gzip_log(log_file)

        iteration_stats.append(stats)
        if leaks_path and os.path.exists(leaks_path):
            iteration_leaks_files.append(leaks_path)
        iteration_leak_sites.append(leak_sites)
        iteration_leak_times.append(leak_times)

        if not new_files:
            break  # helper already printed the reason

        accumulated_stubs.update(new_files)
        iteration += 1

    total_iterations = iteration + 1
    print(f"\n[AUTO] Completed after {total_iterations} iteration(s)")
    print(f"[AUTO] Total stubs used: {len(accumulated_stubs)}")
    if accumulated_stubs:
        for sf in sorted(accumulated_stubs):
            print(f"  {os.path.relpath(sf, args.root)}")

    is_keygen = "keygen" in algorithm

    # ── All-stubs run: use every keylen-compatible stub file ──
    if not args.no_all:
        all_stubs = find_all_keylen_stubs(script_root, args.library, args.platform, resolved_keylen)
        new_all_stubs = all_stubs - accumulated_stubs

        print(f"\n{'='*60}")
        print(f"[AUTO] All-stubs run ({len(all_stubs)} stub files, {len(new_all_stubs)} new)")
        print(f"{'='*60}")

        if new_all_stubs:
            print(f"  Additional stubs beyond progressive:")
            for sf in sorted(new_all_stubs):
                print(f"    + {os.path.relpath(sf, args.root)}")

        all_stubs_scripts = ("," + ",".join(sorted(all_stubs))) if all_stubs else ""
        script_files = (
            f"{base_root_ini},{script_root}{args.platform}/mem.ini"
            f"{random_file}{gs_path}{extra}{base_stubs}{all_stubs_scripts}"
        )

        log_file = f"{output_path}/{nature}_auto_allstubs{tag}.log"

        run_cmd = (
            f"binsec -sse -checkct {bn_option}-sse-missing-symbol warn -sse-script {script_files} "
            f"-sse-debug-level {dbg} -sse-depth 1000000000 "
            f"-fml-solver-timeout 600 -sse-timeout {args.timeout} {binary_path} "
            f"-smt-solver bitwuzla:smtlib"
        )

        parts = run_cmd.split()
        if parts:
            program = parts[0]
            run_args = parts[1:]

            print(f"[CASE] auto allstubs")
            if not run_and_log(program, run_args, log_file, algorithm, nature, tag, args.memlimit):
                success = False
            n_alerts = count_leaks_in_log(log_file)
            leaks_path = log_file.replace('.log', '.leaks')
            n_unique = 0
            if generate_leaks_file(log_file, debug_binary, leaks_path):
                generate_uniq_file(leaks_path, leaks_path + ".uniq")
                n = count_unique_in_leaks([leaks_path])
                if n is not None:
                    n_unique = n
                iteration_leaks_files.append(leaks_path)
            elif n_alerts > 0:
                n_unique = len(get_unique_leak_addrs(log_file))
            hooked_bn = get_hooked_bn_functions(log_file, args.library)
            if not args.end_report:
                gzip_log(log_file)
            iteration_stats.append({
                "iteration": "allstubs",
                "phase": "allstubs",
                "alerts": n_alerts,
                "unique_alerts": n_unique,
                "stubs": count_stubbed_functions(all_stubs),
                "hooked_bn": len(hooked_bn),
                "hooked_bn_funcs": sorted(hooked_bn),
                "log_file": os.path.relpath(log_file, args.root),
            })
            if args.report_diff and leaks_path and os.path.exists(leaks_path):
                sites = extract_unique_leak_sites([leaks_path])
                times = extract_leak_sites_with_time(leaks_path)
                iteration_leak_sites.append(sites if sites else set())
                iteration_leak_times.append(times if times else {})
            else:
                iteration_leak_sites.append(set())
                iteration_leak_times.append({})
            if hooked_bn:
                print(f"  [BN HOOKS] {len(hooked_bn)} BN functions applied:")
                for f in sorted(hooked_bn):
                    print(f"    {f}")

    # ── Final run: no stubs, extended timeout ──
    if not args.no_final:
        # For keygen, keep bn enabled (same as iteration 0)
        final_timeout = args.timeout * (total_iterations + 1)  # +1 for allstubs run
        final_bn = bn_option if is_keygen else ""
        final_base_stubs = base_stubs if is_keygen else ""

        bn_label = "with BN" if is_keygen else "no BN"
        print(f"\n{'='*60}")
        print(f"[AUTO] Final run ({bn_label}, no extra stubs, timeout={final_timeout}s)")
        print(f"{'='*60}")

        script_files = (
            f"{base_root_ini},{script_root}{args.platform}/mem.ini"
            f"{random_file}{gs_path}{extra}{final_base_stubs}"
        )

        log_file = f"{output_path}/{nature}_auto_final{tag}.log"

        run_cmd = (
            f"binsec -sse -checkct {final_bn}-sse-missing-symbol warn -sse-script {script_files} "
            f"-sse-debug-level {dbg} -sse-depth 1000000000 "
            f"-fml-solver-timeout 600 -sse-timeout {final_timeout} {binary_path} "
            f"-smt-solver bitwuzla:smtlib"
        )

        parts = run_cmd.split()
        if parts:
            program = parts[0]
            run_args = parts[1:]

            print(f"[CASE] auto final")
            if not run_and_log(program, run_args, log_file, algorithm, nature, tag, args.memlimit):
                success = False
            n_alerts = count_leaks_in_log(log_file)
            leaks_path = log_file.replace('.log', '.leaks')
            n_unique = 0
            final_leaks_file = None
            if generate_leaks_file(log_file, debug_binary, leaks_path):
                generate_uniq_file(leaks_path, leaks_path + ".uniq")
                n = count_unique_in_leaks([leaks_path])
                if n is not None:
                    n_unique = n
                final_leaks_file = leaks_path
            elif n_alerts > 0:
                n_unique = len(get_unique_leak_addrs(log_file))
            hooked_bn = get_hooked_bn_functions(log_file, args.library)
            if not args.end_report:
                gzip_log(log_file)
            iteration_stats.append({
                "iteration": "final",
                "phase": "final",
                "alerts": n_alerts,
                "unique_alerts": n_unique,
                "stubs": 0,
                "hooked_bn": len(hooked_bn),
                "hooked_bn_funcs": sorted(hooked_bn),
                "log_file": os.path.relpath(log_file, args.root),
            })
            if args.report_diff and leaks_path and os.path.exists(leaks_path):
                sites = extract_unique_leak_sites([leaks_path])
                times = extract_leak_sites_with_time(leaks_path)
                iteration_leak_sites.append(sites if sites else set())
                iteration_leak_times.append(times if times else {})
            else:
                iteration_leak_sites.append(set())
                iteration_leak_times.append({})
            if hooked_bn:
                print(f"  [BN HOOKS] {len(hooked_bn)} BN functions applied:")
                for f in sorted(hooked_bn):
                    print(f"    {f}")

    # ── Compute merged unique alert counts via merge_reports ──
    # Per-phase: use the individual iteration stats (already computed)
    no_stub_count = iteration_stats[0]["unique_alerts"] if iteration_stats else 0
    allstubs_count = next((s["unique_alerts"] for s in iteration_stats if s["phase"] == "allstubs"), 0)
    final_count = next((s["unique_alerts"] for s in iteration_stats if s["phase"] == "final"), 0)

    # Progressive: merge all non-final .leaks files together
    progressive_count = count_unique_in_leaks(iteration_leaks_files)
    if progressive_count is None:
        # Fallback: sum individual uniques (overcount but better than 0)
        progressive_count = sum(s["unique_alerts"] for s in iteration_stats if s["phase"] != "final")

    merged_counts = {
        "no_stub": no_stub_count,
        "allstubs": allstubs_count,
        "progressive": progressive_count,
        "final": final_count,
    }

    if args.end_report:
        # ── Summary statistics ──
        print(f"\n{'='*60}")
        print(f"[AUTO] Summary")
        print(f"{'='*60}")
        print(f"  {'Phase':<20s} {'Alerts':>8s} {'Uniq Src':>8s} {'Stubs':>8s} {'BN Hook':>8s}  BN Functions Applied")
        print(f"  {'-'*100}")
        for s in iteration_stats:
            bn_list = ", ".join(s.get('hooked_bn_funcs', []))
            print(f"  {s['phase']:<20s} {s['alerts']:>8d} {s['unique_alerts']:>8d} {s['stubs']:>8d} {s['hooked_bn']:>8d}  {bn_list}")
        print(f"  {'-'*100}")
        print(f"  {'No Stub (iter 0)':<20s} {'':<8s} {merged_counts['no_stub']:>8d}")
        print(f"  {'All Stubs':<20s} {'':<8s} {merged_counts['allstubs']:>8d}")
        print(f"  {'Progressive (all)':<20s} {'':<8s} {merged_counts['progressive']:>8d}")
        print(f"  {'Final':<20s} {'':<8s} {merged_counts['final']:>8d}")

        # Diff report
        if args.report_diff and iteration_leak_sites:
            print_diff_report(iteration_stats, iteration_leak_sites, iteration_leak_times)

        # LaTeX tables
        latex_title = f"{args.library} {algorithm} {args.optimization or ''} (auto)"
        print_latex_table(iteration_stats, latex_title)
        if args.report_diff and iteration_leak_sites:
            print_latex_diff_table(iteration_stats, iteration_leak_sites, latex_title)

    # ── Write JSON results ──
    json_data = {
        "library": args.library,
        "primitive": algorithm,
        "optimization": args.optimization or "",
        "nature": nature,
        "platform": args.platform,
        "timeout": args.timeout,
        "keylen": resolved_keylen,
        "iterations": iteration_stats,
        "unique_alerts": merged_counts,
    }
    json_file = os.path.join(
        output_path,
        f"{nature}_{library_str}_{algorithm}{tag}.json"
    )
    with open(json_file, 'w') as jf:
        json.dump(json_data, jf, indent=2)
    print(f"\n[AUTO] Results written to {os.path.relpath(json_file, args.root)}")

    return success


# ============================================================================
# Build and GDB Functions
# ============================================================================

def get_makefile_target(makefile_path: str) -> Optional[str]:
    """Parse Makefile to find the TARGET variable."""
    try:
        with open(makefile_path, 'r') as f:
            for line in f:
                match = re.match(r'^TARGET\s*[:]?=\s*(.+)', line.strip())
                if match:
                    return match.group(1).strip()
    except Exception:
        pass
    return None


def build_benchmark(root: str, platform: str, library_str: str, algorithm: str) -> bool:
    """Build the benchmark by running make clean && make in the src directory."""
    src_dir = os.path.join(root, "benchmark", platform, library_str, algorithm, "src")
    bin_dir = os.path.join(root, "benchmark", platform, library_str, algorithm, "bin")

    if not os.path.exists(src_dir):
        print(f"[ERROR] Source directory does not exist: {src_dir}", file=sys.stderr)
        return False

    os.makedirs(bin_dir, exist_ok=True)
    print(f"[BUILD] {src_dir}")

    try:
        result = subprocess.run(
            "make clean && make",
            shell=True,
            cwd=src_dir,
            capture_output=True,
            text=True
        )

        if result.returncode != 0:
            print(f"[ERROR] Build failed", file=sys.stderr)
            if result.stderr:
                print(result.stderr, file=sys.stderr)
            return False

        print(f"[OK] Build successful")

        # Check if executable needs to be renamed
        expected_name = f"{algorithm}_{library_str}_{platform}"
        expected_path = os.path.join(bin_dir, expected_name)

        if os.path.exists(expected_path):
            return True

        # Try to find the actual target from Makefile
        makefile_path = os.path.join(src_dir, "Makefile")
        makefile_target = get_makefile_target(makefile_path)

        if makefile_target:
            actual_path = os.path.join(bin_dir, makefile_target)
            if os.path.exists(actual_path):
                os.rename(actual_path, expected_path)
                print(f"[RENAME] {makefile_target} -> {expected_name}")
                return True

        # Fallback: find any executable in bin_dir
        if os.path.exists(bin_dir):
            for fname in os.listdir(bin_dir):
                fpath = os.path.join(bin_dir, fname)
                if os.path.isfile(fpath) and os.access(fpath, os.X_OK) and not fname.endswith('.core'):
                    os.rename(fpath, expected_path)
                    print(f"[RENAME] {fname} -> {expected_name}")
                    return True

        print(f"[ERROR] Could not find built executable in {bin_dir}", file=sys.stderr)
        return False

    except Exception as e:
        print(f"[ERROR] Build execution failed: {e}", file=sys.stderr)
        return False


def make_gdb_script(path_to_core: str) -> str:
    """Generate a GDB script to capture gs_base and create a core file."""
    return '\n'.join([
        'set interactive-mode off',
        'catch syscall set_thread_area',
        'break tester_main',
        'run',
        'printf "gs_base<32> := %#x\\n", *($ebx + 4)',
        'continue',
        'continue',
        f'generate-core-file {path_to_core}',
        'kill',
        'quit'
    ])


def run_gdb_and_generate_core(bin_path: str) -> Optional[str]:
    """Run GDB on the binary, generate core file, and return the gs_base line."""
    core_path = bin_path + ".core"

    print(f"[GDB] Generating core and capturing gs_base")

    try:
        process = subprocess.run(
            f"gdb --args {bin_path}",
            shell=True,
            input=make_gdb_script(core_path),
            capture_output=True,
            text=True
        )

        match = re.search(r"gs_base<32> := 0x[0-9a-f]{1,8}", process.stdout)
        if match:
            gs_base_line = match.group(0)
            print(f"[OK] {gs_base_line}")
            return gs_base_line
        else:
            print(f"[ERROR] Could not find gs_base in GDB output", file=sys.stderr)
            if process.stderr:
                print(process.stderr, file=sys.stderr)
            return None

    except Exception as e:
        print(f"[ERROR] GDB execution failed: {e}", file=sys.stderr)
        return None


def write_gs_ini(bin_dir: str, gs_base_line: str) -> bool:
    """Write the gs.ini file with the gs_base line."""
    gs_ini_path = os.path.join(bin_dir, "gs.ini")

    try:
        with open(gs_ini_path, 'w') as f:
            f.write(f"{gs_base_line}\n")
        print(f"[OK] Wrote {gs_ini_path}")
        return True
    except Exception as e:
        print(f"[ERROR] Failed to write gs.ini: {e}", file=sys.stderr)
        return False


def prepare_benchmark(root: str, platform: str, library_str: str, algorithm: str) -> bool:
    """Build the benchmark and generate gs.ini (for x86 32-bit only)."""
    # Build the benchmark
    if not build_benchmark(root, platform, library_str, algorithm):
        return False

    # For 32-bit x86, run GDB to get gs_base and write gs.ini
    if platform == Platform.X86.value:
        bin_dir = os.path.join(root, "benchmark", platform, library_str, algorithm, "bin")
        bin_path = os.path.join(bin_dir, f"{algorithm}_{library_str}_{platform}")

        gs_base_line = run_gdb_and_generate_core(bin_path)
        if not gs_base_line:
            return False

        if not write_gs_ini(bin_dir, gs_base_line):
            return False

    return True


# ============================================================================
# Utility Functions
# ============================================================================

def all_combinations(items: List[str]) -> List[Tuple[str, List[str]]]:
    n = len(items)
    result = []

    for mask in range(1 << n):
        combo = []
        for i in range(n):
            if (mask >> i) & 1:
                combo.append(items[i])
        result.append((str(mask), combo))

    return result

def progressive_list(bn_dir: str, s_items: str, only: str) -> List[Tuple[str, List[str]]]:
    x = []
    acc = []
    acc.append(("0", list(x)))

    folders = []
    try:
        entries = os.listdir(bn_dir)
        for entry in entries:
            full_path = os.path.join(bn_dir, entry)
            if os.path.isdir(full_path):
                folders.append(entry)
    except OSError: 
        pass

    if folders:
        folders.sort()

        if only:
            try:
                target_pos = folders.index(only)
                for folder in folders[:target_pos + 1]:
                    folder_path = os.path.join(bn_dir, folder) + "/"
                    files_in_folder = list_files(folder_path)
                    x.extend(files_in_folder)
                return [(only, x)]
            except ValueError: 
                print(f"[WARN] Folder '{only}' not found in progressive directory", file=sys.stderr)

        for folder in folders:
            folder_path = os.path.join(bn_dir, folder) + "/"
            files_in_folder = list_files(folder_path)
            x.extend(files_in_folder)
            acc.append((folder, list(x)))
    else:
        if s_items:
            items = s_items.split(',')
            for i, item in enumerate(items):
                item = item.strip()
                if item:
                    x.append(f"{bn_dir}{item}")
                    acc.append((str(i + 1), list(x)))

    return acc

def list_files(directory: str) -> List[str]:
    filenames = []
    if not os.path.exists(directory):
        return filenames
    
    try:
        entries = os.listdir(directory)
        entries.sort()
        
        for fname in entries:
            full_path = os.path.join(directory, fname)
            if os.path.isfile(full_path):
                 filenames.append(f"{directory}/{fname}" if not directory.endswith('/') else f"{directory}{fname}")
                 
    except OSError: 
        pass
        
    return filenames

def run_callstack2source(log_file, binary_path, output_file):
    script_dir = os.path.dirname(os.path.abspath(__file__))
    callstack2source = os.path.join(script_dir, "callstack2source.py")

    print(f"[REPORT] {output_file}")
    try:
        result = subprocess.run(
            [sys.executable, callstack2source, log_file, binary_path, output_file],
            capture_output=True, text=True,
        )
        if result.returncode == 0:
            print(f"[OK] Report saved to {output_file}")
        else:
            print(f"[ERROR] callstack2source failed for {log_file}", file=sys.stderr)
            if result.stderr:
                print(result.stderr, file=sys.stderr)
    except Exception as e:
        print(f"[ERROR] callstack2source execution failed: {e}", file=sys.stderr)


def run_merge_reports(leaks_files, output_file):
    script_dir = os.path.dirname(os.path.abspath(__file__))
    merge_reports = os.path.join(script_dir, "merge_reports.py")

    print(f"[MERGE] {len(leaks_files)} reports -> {output_file}")
    try:
        result = subprocess.run(
            [sys.executable, merge_reports, '--uniq-source', '-o', output_file] + leaks_files,
            capture_output=True, text=True,
        )
        if result.returncode == 0:
            print(f"[OK] Merged report saved to {output_file}")
            if result.stdout:
                print(result.stdout)
        else:
            print(f"[ERROR] merge_reports failed", file=sys.stderr)
            if result.stderr:
                print(result.stderr, file=sys.stderr)
    except Exception as e:
        print(f"[ERROR] merge_reports execution failed: {e}", file=sys.stderr)

def load_keylen_config(root_dir: str) -> dict:
    keylen_path = os.path.join(root_dir, "keylen.json")
    if not os.path.exists(keylen_path):
        return {}
    
    try:
        with open(keylen_path, 'r') as f:
            return json.load(f)
    except Exception as e:
        print(f"[WARN] Could not load keylen.json: {e}", file=sys.stderr)
        return {}



def make_memlimit_fn(memlimit_mb: int):
    """Return a function that sets memory limit, for use with preexec_fn."""
    def set_memlimit():
        limit_bytes = memlimit_mb * 1024 * 1024
        resource.setrlimit(resource.RLIMIT_AS, (limit_bytes, limit_bytes))
    return set_memlimit


def run_and_log(program, args, log_file_name, algorithm, nature, tag, memlimit_mb: int = 0, gzip_after: bool = False):
    """Run program, write stdout+stderr to log_file_name.

    If gzip_after=True and the log file is not already .gz, compress it with
    gzip after a successful or failed run (so the plain file is removed).
    """
    import gzip as _gzip, shutil as _shutil

    print(f"[RUN] {program} {' '.join(args)}")
    print(f"[LOG] {log_file_name}")
    if memlimit_mb > 0:
        print(f"[MEM] Limit: {memlimit_mb} MB")

    success = False
    try:
        with open(log_file_name, 'w') as log_file:
            preexec = make_memlimit_fn(memlimit_mb) if memlimit_mb > 0 else None
            result = subprocess.run(
                [program] + args,
                stdout=log_file,
                stderr=log_file,
                preexec_fn=preexec,
            )

            if result.returncode == 0:
                print(f"[OK] Output saved to {log_file_name}")
                success = True
            elif result.returncode == -9:
                print(f"[KILLED] Out of memory (limit: {memlimit_mb} MB). See {log_file_name}", file=sys.stderr)
            else:
                print(f"[ERROR] Binsec failed for {algorithm} ({nature}{tag}). See {log_file_name}", file=sys.stderr)

    except Exception as e:
        print(f"[ERROR] Execution failed: {e}", file=sys.stderr)
        return False

    if gzip_after and not log_file_name.endswith('.gz') and os.path.exists(log_file_name):
        gz_name = log_file_name + '.gz'
        try:
            with open(log_file_name, 'rb') as f_in, _gzip.open(gz_name, 'wb') as f_out:
                _shutil.copyfileobj(f_in, f_out)
            os.remove(log_file_name)
            print(f"[GZ] Compressed to {gz_name}")
        except Exception as e:
            print(f"[WARN] gzip failed for {log_file_name}: {e}", file=sys.stderr)

    return success


def gzip_log(log_file_name):
    """Compress log_file_name to log_file_name.gz and remove the plain file."""
    import gzip as _gzip, shutil as _shutil
    if log_file_name.endswith('.gz') or not os.path.exists(log_file_name):
        return
    gz_name = log_file_name + '.gz'
    try:
        with open(log_file_name, 'rb') as f_in, _gzip.open(gz_name, 'wb') as f_out:
            _shutil.copyfileobj(f_in, f_out)
        os.remove(log_file_name)
        print(f"[GZ] Compressed to {gz_name}")
    except Exception as e:
        print(f"[WARN] gzip failed for {log_file_name}: {e}", file=sys.stderr)

if __name__ == "__main__":
    main()
