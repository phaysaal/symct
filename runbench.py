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
    parser.add_argument("--tree", action="store_true", help="Tree mode: start with all stubs, progressively unstub to find leak sources")
    parser.add_argument("--group", type=int, default=0, help="In auto mode, add at most K new stub files per iteration (0 = all at once)")
    parser.add_argument("--clean", action="store_true", help="Delete existing results and reports for this primitive before running")

    return parser.parse_args()

# ============================================================================ 
# Main Entry Point
# ============================================================================ 

def main():
    args = parse_args()
    if not drive_test(args):
        sys.exit(1)

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
    else:
        binary_path = f"{args.root}/benchmark/{args.platform}/{library_str}/{algorithm}/bin/{algorithm}_{library_str}_{args.platform}"

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
    success = True

    # Run tests for each combination
    total_combs = len(all_combs)
    for idx, (name, c) in enumerate(all_combs, 1):
        bn_scripts = ""
        if c:
            bn_scripts = "," + ",".join(c)

        script_files = f"{base_root_ini},{script_root}{args.platform}/mem.ini{random_file}{gs_path}{extra}{base_stubs}{bn_scripts}"

        script_list = f"_{name}"
        log_file = f"{args.root}/results/{args.platform}/{library_str}/{algorithm}/{nature}{script_list}{tag}.log"

        run_bn = bn_option
        run_sse_script = script_files
        run_timeout = args.timeout
        run_source = binary_path
        run_debug_level = dbg
        run_solver_timeout = 600
        run_sse_depth = 1000000000

        run_cmd = (
            f"binsec -sse -checkct {run_bn}-sse-missing-symbol warn -sse-script {run_sse_script} "
            f"-sse-debug-level {run_debug_level} -sse-depth {run_sse_depth} "
            f"-fml-solver-timeout {run_solver_timeout} -sse-timeout {run_timeout} {run_source} "
            f"-smt-solver bitwuzla:smtlib"
        )

        parts = run_cmd.split()
        if not parts:
            continue

        program = parts[0]
        run_args = parts[1:]

        if args.progressive:
            print(f"[STEP {idx}/{total_combs}] progressive={args.progressive} step={name}")
        print(f"[CASE] {bn_scripts}")
        if not run_and_log(program, run_args, log_file, algorithm, nature, tag, args.memlimit):
            success = False

        # Generate callstack2source report if --report is given
        if report_dir:
            # Use the non-.core binary for addr2line/objdump (it has debug symbols)
            debug_binary = binary_path
            if debug_binary.endswith('.core'):
                debug_binary = debug_binary[:-5]
            log_basename = os.path.basename(log_file)
            leaks_basename = log_basename.replace('.log', '.leaks')
            leaks_file = os.path.join(report_dir, leaks_basename)
            run_callstack2source(log_file, debug_binary, leaks_file)
            leaks_files.append(leaks_file)

    # Merge reports if progressive mode
    if report_dir and args.progressive and len(leaks_files) > 1:
        merged_name = f"{args.library}_{algorithm}_{args.platform}{tag}.leaks"
        merged_file = os.path.join(report_dir, merged_name)
        run_merge_reports(leaks_files, merged_file)

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


def parse_log_for_auto(log_file, library):
    """Parse a binsec log for auto mode analysis.

    Returns:
        func_line_counts: dict mapping function name -> number of [sse:debug] lines
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
        return func_line_counts, leak_call_chains, {}

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

            # Resolve addresses to function names (deepest first = #0 first)
            chain = []
            for addr in call_addrs:
                func = addr_to_func.get(addr)
                if func and (not chain or chain[-1] != func):
                    chain.append(func)
            leak_call_chains.append(chain)
            i = j
        else:
            i += 1

    return func_line_counts, leak_call_chains, dict(call_graph)


def find_target_bn_functions(func_line_counts, library, leak_bn_funcs=None, cumulative_threshold=0.75):
    """Determine which BN functions need stubs.

    1. Sort all functions by line count descending.
    2. Take the shortest prefix whose cumulative share crosses cumulative_threshold.
    3. Filter to BN functions only.
    4. Always include any BN function that has a leak, regardless of share.

    Returns set of BN function names to target for stubbing.
    """
    total_lines = sum(func_line_counts.values())
    if total_lines == 0:
        return set()

    sorted_funcs = sorted(func_line_counts.items(), key=lambda x: -x[1])

    target_funcs = set()
    cumulative = 0.0
    for func, count in sorted_funcs:
        if cumulative / total_lines >= cumulative_threshold:
            break
        cumulative += count
        if is_bn_function(func, library):
            target_funcs.add(func)

    # Always include leaking BN functions
    if leak_bn_funcs:
        target_funcs.update(leak_bn_funcs)

    return target_funcs


def resolve_stubs_via_callers(target_funcs, func_to_file, call_graph, library):
    """For each target BN function, find a stub — either directly or via callers.

    For functions that have a stub file directly, use that.
    For functions without a stub, walk up the call graph to find the closest
    caller (BN function) that has a stub file.

    Returns:
        resolved: dict of func -> stub_file (includes both direct and caller stubs)
        resolutions: list of (func, resolved_via, caller_chain) for reporting
    """
    # Build reverse call graph: callee -> [(caller, count)]
    reverse_graph = {}
    for caller, callees in call_graph.items():
        for callee, count in callees.items():
            if callee not in reverse_graph:
                reverse_graph[callee] = []
            reverse_graph[callee].append((caller, count))

    resolved = {}
    resolutions = []

    for func in sorted(target_funcs):
        if func in func_to_file:
            # Direct stub exists
            resolved[func] = func_to_file[func]
            resolutions.append((func, func, [func]))
        else:
            # Walk up call graph to find a caller with a stub
            visited = set()
            caller_chain = [func]
            current = func
            found = None

            for _ in range(10):  # max depth
                callers = reverse_graph.get(current, [])
                # Filter to BN callers, sort by transition count (most frequent first)
                bn_callers = [(c, n) for c, n in callers if is_bn_function(c, library) and c not in visited]
                if not bn_callers:
                    break
                bn_callers.sort(key=lambda x: -x[1])
                best_caller = bn_callers[0][0]
                visited.add(best_caller)
                caller_chain.append(best_caller)

                if best_caller in func_to_file:
                    found = best_caller
                    resolved[best_caller] = func_to_file[best_caller]
                    break
                current = best_caller

            resolutions.append((func, found, caller_chain))

    return resolved, resolutions


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
    else:
        binary_path = f"{args.root}/benchmark/{args.platform}/{library_str}/{algorithm}/bin/{algorithm}_{library_str}_{args.platform}"

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

    def run_tree_iteration(label, stub_files, log_name):
        """Run binsec with given stub files. Returns (n_alerts, n_unique, hooked_bn)."""
        stub_scripts = ("," + ",".join(sorted(stub_files))) if stub_files else ""
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
            return 0, 0, set(), log_file

        program = parts[0]
        run_args = parts[1:]

        print(f"[CASE] tree {label}")
        nonlocal success
        if not run_and_log(program, run_args, log_file, algorithm, nature, tag, args.memlimit):
            success = False

        n_alerts = count_leaks_in_log(log_file)
        hooked_bn = get_hooked_bn_functions(log_file, args.library)

        # Generate .leaks and count unique
        n_unique = 0
        leaks_path = log_file.replace('.log', '.leaks')
        if n_alerts > 0 and generate_leaks_file(log_file, binary_path, leaks_path):
            n = count_unique_in_leaks([leaks_path])
            if n is not None:
                n_unique = n
            iteration_leaks_files.append(leaks_path)
        elif n_alerts > 0:
            n_unique = len(get_unique_leak_addrs(log_file))

        return n_alerts, n_unique, hooked_bn, log_file

    # ── Phase 0: All stubs ──
    print(f"\n{'='*60}")
    print(f"[TREE] Phase 0: All stubs ({len(all_stubs)} files, {count_stubbed_functions(all_stubs)} functions)")
    print(f"{'='*60}")

    n_alerts, n_unique, hooked_bn, log_file = run_tree_iteration(
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

    # ── Progressive unstubbing ──
    # Queue: list of (func_to_remove, parent_phase, current_stub_set)
    # Start with all hooked BN functions from phase 0
    current_stubs = set(all_stubs)
    unstub_queue = []
    seen_funcs = set()  # all BN functions we've already queued for removal

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

        print(f"\n{'='*60}")
        print(f"[TREE] Step {step}: Remove {func_to_remove}")
        print(f"  Parent: {parent}")
        print(f"  Stub file: {os.path.relpath(stub_file, args.root)}")
        if len(removed_funcs) > 1:
            print(f"  Also removes: {', '.join(sorted(removed_funcs - {func_to_remove}))}")
        print(f"  Remaining stubs: {len(new_stubs)} files")
        print(f"{'='*60}")

        phase_name = f"remove_{func_to_remove}"
        n_alerts, n_unique, hooked_bn, log_file = run_tree_iteration(
            f"step {step} (remove {func_to_remove})", new_stubs, f"s{step}_{func_to_remove}"
        )

        if hooked_bn:
            print(f"  [BN HOOKS] {len(hooked_bn)} BN functions applied:")
            for f in sorted(hooked_bn):
                print(f"    {f}")

        # Find newly exposed BN functions (hooked now but not seen before)
        new_bn = hooked_bn - seen_funcs
        if new_bn:
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
            "log_file": os.path.relpath(log_file, args.root),
        })

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
        if not run_and_log(program, run_args, log_file, algorithm, nature, tag, args.memlimit):
            success = False

        n_alerts = count_leaks_in_log(log_file)
        leaks_path = log_file.replace('.log', '.leaks')
        n_unique = 0
        if n_alerts > 0 and generate_leaks_file(log_file, binary_path, leaks_path):
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
        if hooked_bn:
            print(f"  [BN HOOKS] {len(hooked_bn)} BN functions applied:")
            for f in sorted(hooked_bn):
                print(f"    {f}")

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
        print(f"  {phase:<40s} {s['alerts']:>8d} {s['unique_alerts']:>8d} {s['stubs']:>8d} {s['hooked_bn']:>8d}")

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
    else:
        binary_path = f"{args.root}/benchmark/{args.platform}/{library_str}/{algorithm}/bin/{algorithm}_{library_str}_{args.platform}"

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

        # Parse the log
        func_counts, leak_call_chains, call_graph = parse_log_for_auto(log_file, args.library)
        n_alerts = count_leaks_in_log(log_file)

        # Generate .leaks and count unique source-level alerts
        leaks_path = log_file.replace('.log', '.leaks')
        n_unique = 0
        if n_alerts > 0 and generate_leaks_file(log_file, binary_path, leaks_path):
            n = count_unique_in_leaks([leaks_path])
            if n is not None:
                n_unique = n
            iteration_leaks_files.append(leaks_path)
        elif n_alerts > 0:
            n_unique = len(get_unique_leak_addrs(log_file))  # fallback

        phase_name = "no_stub" if iteration == 0 else f"stub_{iteration}"
        hooked_bn = get_hooked_bn_functions(log_file, args.library)
        iteration_stats.append({
            "iteration": iteration,
            "phase": phase_name,
            "alerts": n_alerts,
            "unique_alerts": n_unique,
            "stubs": count_stubbed_functions(accumulated_stubs),
            "hooked_bn": len(hooked_bn),
            "hooked_bn_funcs": sorted(hooked_bn),
            "log_file": os.path.relpath(log_file, args.root),
        })

        if hooked_bn:
            print(f"  [BN HOOKS] {len(hooked_bn)} BN functions applied:")
            for f in sorted(hooked_bn):
                print(f"    {f}")

        total_lines = sum(func_counts.values())
        bn_counts = {f: c for f, c in func_counts.items() if is_bn_function(f, args.library)}
        bn_lines = sum(bn_counts.values())
        non_bn_counts = {f: c for f, c in func_counts.items() if not is_bn_function(f, args.library)}

        # Collect all BN functions that appear in any leak chain
        leak_bn_funcs = set()
        for chain in leak_call_chains:
            for func in chain:
                if is_bn_function(func, args.library):
                    leak_bn_funcs.add(func)

        if total_lines == 0:
            print(f"[AUTO] No traced lines found in log")
            break

        # ── Detailed analysis report ──
        print()
        print(f"  {'─'*56}")
        print(f"  LOG ANALYSIS REPORT  (iteration {iteration})")
        print(f"  {'─'*56}")
        print(f"  Total traced lines : {total_lines}")
        print(f"  BN function lines  : {bn_lines} ({100*bn_lines/total_lines:.1f}%)")
        print(f"  Other lines        : {total_lines - bn_lines} ({100*(total_lines - bn_lines)/total_lines:.1f}%)")

        # Top functions by cumulative share (75% of trace)
        sorted_all = sorted(func_counts.items(), key=lambda x: -x[1])
        cumulative = 0.0
        print()
        print(f"  Top functions (75% cumulative share):")
        top_count = 0
        for f, c in sorted_all:
            if cumulative / total_lines >= 0.75:
                break
            cumulative += c
            pct = 100 * c / total_lines
            cum_pct = 100 * cumulative / total_lines
            bn_mark = " [BN]" if is_bn_function(f, args.library) else ""
            leak_mark = " *** LEAK" if f in leak_bn_funcs else ""
            print(f"    {f:40s} {c:8d}  ({pct:5.1f}%)  cum {cum_pct:5.1f}%{bn_mark}{leak_mark}")
            top_count += 1
        remaining = len(func_counts) - top_count
        if remaining > 0:
            print(f"    ... and {remaining} more functions in remaining {100 - 100*cumulative/total_lines:.1f}%")

        # Find target BN functions (top cumulative share + any leaking BN)
        target_funcs = find_target_bn_functions(func_counts, args.library, leak_bn_funcs)

        if target_funcs:
            print()
            print(f"  BN stub targets ({len(target_funcs)} from above):")
            for f in sorted(target_funcs, key=lambda x: -func_counts.get(x, 0)):
                c = func_counts.get(f, 0)
                pct = 100 * c / total_lines
                leak_mark = " *** LEAK" if f in leak_bn_funcs else ""
                print(f"    {f:40s} {c:8d}  ({pct:5.1f}%){leak_mark}")

        bn_dominant = bn_lines / total_lines > 0.50
        print()
        print(f"  BN dominance (>50%): {'YES' if bn_dominant else 'NO'} ({100*bn_lines/total_lines:.1f}%)")

        if not target_funcs:
            print(f"  No bignum functions to stub.")
            print(f"  {'─'*56}")
            break

        # Find stub files for ALL BN functions in the trace (not just targets)
        # so that call graph walks can discover caller stubs
        all_bn_funcs = {f for f in func_counts if is_bn_function(f, args.library)}
        func_to_file = find_stub_files_for_auto(script_root, args.library, args.platform, all_bn_funcs, resolved_keylen)

        # Resolve stubs: direct match or walk up call graph to find caller with stub
        resolved, resolutions = resolve_stubs_via_callers(target_funcs, func_to_file, call_graph, args.library)

        # Show resolution details
        if resolutions:
            direct = sum(1 for f, via, chain in resolutions if via == f)
            via_caller = sum(1 for f, via, chain in resolutions if via and via != f)
            unresolved = sum(1 for f, via, chain in resolutions if via is None)
            print()
            print(f"  Stub resolution: {direct} direct, {via_caller} via caller, {unresolved} unresolved")
            for func, via, chain in resolutions:
                pct = 100 * func_counts.get(func, 0) / total_lines
                if via == func:
                    print(f"    {func:40s} ({pct:5.1f}%) -> DIRECT stub")
                elif via:
                    chain_str = " -> ".join(chain)
                    print(f"    {func:40s} ({pct:5.1f}%) -> via {via}")
                    print(f"      chain: {chain_str}")
                else:
                    print(f"    {func:40s} ({pct:5.1f}%) -> NO STUB")

        # Merge resolved stubs into func_to_file (caller stubs found by graph walk)
        for func_name, stub_file in resolved.items():
            if func_name not in func_to_file:
                func_to_file[func_name] = stub_file

        # Determine new files not yet accumulated
        all_new_files = set(func_to_file.values()) - accumulated_stubs
        covered_funcs = set(func_to_file.keys())
        missing = target_funcs - covered_funcs

        # Rank new files by total trace share of the functions they replace
        def file_trace_share(fpath):
            funcs = [f for f, fp in func_to_file.items() if fp == fpath]
            return sum(func_counts.get(f, 0) for f in funcs)

        ranked_new = sorted(all_new_files, key=file_trace_share, reverse=True)

        # Apply --group limit: pick top K new files per iteration
        if args.group > 0 and len(ranked_new) > args.group:
            new_files = set(ranked_new[:args.group])
            deferred = set(ranked_new[args.group:])
        else:
            new_files = set(ranked_new)
            deferred = set()

        # Functions to be stubbed next (only from selected new_files)
        next_funcs = {f for f, fp in func_to_file.items() if fp in new_files}

        print()
        if next_funcs:
            print(f"  Functions to stub NEXT ({len(next_funcs)}):")
            for f in sorted(next_funcs, key=lambda x: -func_counts.get(x, 0)):
                fpath = func_to_file[f]
                c = func_counts.get(f, 0)
                via_mark = ""
                for orig, via, chain in resolutions:
                    if via == f and orig != f:
                        via_mark = f" [CALLER of {orig}]"
                        break
                print(f"    {f:40s} -> {os.path.basename(fpath)}{via_mark}")

        if deferred:
            deferred_funcs = {f for f, fp in func_to_file.items() if fp in deferred}
            print(f"  Deferred to next iteration ({len(deferred_funcs)}):")
            for f in sorted(deferred_funcs, key=lambda x: -func_counts.get(x, 0)):
                print(f"    {f:40s} -> {os.path.basename(func_to_file[f])}")

        # Already-stubbed functions (from previous iterations)
        already_stubbed = {f for f, fp in func_to_file.items() if fp in accumulated_stubs}
        if already_stubbed:
            print(f"  Already stubbed ({len(already_stubbed)}): {', '.join(sorted(already_stubbed))}")

        # Missing stubs
        if missing:
            print(f"  No stubs available ({len(missing)}): {', '.join(sorted(missing))}")

        print(f"  {'─'*56}")

        if not new_files:
            print(f"\n[AUTO] No new stub files found, stopping")
            break

        # Summary of new files being added
        group_label = f" (group {args.group}, {len(all_new_files)} available)" if args.group > 0 else ""
        print(f"\n[AUTO] Adding {len(new_files)} new stub files{group_label}:")
        for fpath in sorted(new_files, key=file_trace_share, reverse=True):
            covered = [f for f, fp in func_to_file.items() if fp == fpath]
            print(f"  + {os.path.relpath(fpath, args.root)} (replaces: {', '.join(sorted(covered))})")

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
        if n_alerts > 0 and generate_leaks_file(log_file, binary_path, leaks_path):
            n = count_unique_in_leaks([leaks_path])
            if n is not None:
                n_unique = n
            iteration_leaks_files.append(leaks_path)
        elif n_alerts > 0:
            n_unique = len(get_unique_leak_addrs(log_file))
        hooked_bn = get_hooked_bn_functions(log_file, args.library)
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
        if hooked_bn:
            print(f"  [BN HOOKS] {len(hooked_bn)} BN functions applied:")
            for f in sorted(hooked_bn):
                print(f"    {f}")

    # ── Final run: no stubs, extended timeout ──
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
        if n_alerts > 0 and generate_leaks_file(log_file, binary_path, leaks_path):
            n = count_unique_in_leaks([leaks_path])
            if n is not None:
                n_unique = n
            final_leaks_file = leaks_path
        elif n_alerts > 0:
            n_unique = len(get_unique_leak_addrs(log_file))
        hooked_bn = get_hooked_bn_functions(log_file, args.library)
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

    # ── Summary statistics ──
    print(f"\n{'='*60}")
    print(f"[AUTO] Summary")
    print(f"{'='*60}")
    print(f"  {'Phase':<20s} {'Alerts':>8s} {'Uniq Src':>8s} {'Stubs':>8s} {'BN Hook':>8s}")
    print(f"  {'-'*58}")
    for s in iteration_stats:
        print(f"  {s['phase']:<20s} {s['alerts']:>8d} {s['unique_alerts']:>8d} {s['stubs']:>8d} {s['hooked_bn']:>8d}")
    print(f"  {'-'*58}")
    print(f"  {'No Stub (iter 0)':<20s} {'':<8s} {merged_counts['no_stub']:>8d}")
    print(f"  {'All Stubs':<20s} {'':<8s} {merged_counts['allstubs']:>8d}")
    print(f"  {'Progressive (all)':<20s} {'':<8s} {merged_counts['progressive']:>8d}")
    print(f"  {'Final':<20s} {'':<8s} {merged_counts['final']:>8d}")

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


def run_and_log(program, args, log_file_name, algorithm, nature, tag, memlimit_mb: int = 0):
    print(f"[RUN] {program} {' '.join(args)}")
    print(f"[LOG] {log_file_name}")
    if memlimit_mb > 0:
        print(f"[MEM] Limit: {memlimit_mb} MB")

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
                return True
            elif result.returncode == -9:
                print(f"[KILLED] Out of memory (limit: {memlimit_mb} MB). See {log_file_name}", file=sys.stderr)
            else:
                print(f"[ERROR] Binsec failed for {algorithm} ({nature}{tag}). See {log_file_name}", file=sys.stderr)

    except Exception as e:
        print(f"[ERROR] Execution failed: {e}", file=sys.stderr)

    return False

if __name__ == "__main__":
    main()
