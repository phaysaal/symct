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
    parser.add_argument("--random", type=str, choices=[r.value for r in RandomMode], default=RandomMode.RANDOM.value, help="Randomization mode")
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

    return parser.parse_args()

# ============================================================================ 
# Main Entry Point
# ============================================================================ 

def main():
    args = parse_args()
    drive_test(args)

# ============================================================================ 
# Test Driver Functions
# ============================================================================ 

def drive_test(args):
    if args.batch_file:
        batch_file_test(args)
    else:
        single_test(args)

def batch_file_test(args):
    try:
        with open(args.batch_file, 'r') as f:
            lines = f.readlines()
    except Exception as e:
        sys.exit(f"Could not open batch file: {args.batch_file}. Error: {e}")

    print(f"[INFO] Running tests from batch file: {args.batch_file}")
    print("----------------------------------------")

    for line_num, line in enumerate(lines):
        line = line.strip()
        
        if not line or line.startswith('#'):
            continue

        # Create a new namespace for the test to avoid modifying the original args
        new_args = argparse.Namespace(**vars(args))
        new_args.nature = line

        print(f"\n[TEST] {line_num + 1}: {line}")
        single_test(new_args)
        print(f"[DONE] {line}")

    print("\n----------------------------------------")
    print("[OK] All tests from batch file completed")

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
            return

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

    # Prepare report directory if requested
    report_dir = args.report
    if report_dir:
        os.makedirs(report_dir, exist_ok=True)
    leaks_files = []

    # Run tests for each combination
    for name, c in all_combs:
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

        print(f"[CASE] {bn_scripts}")
        run_and_log(program, run_args, log_file, algorithm, nature, tag, args.memlimit)

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
            elif result.returncode == -9:
                print(f"[KILLED] Out of memory (limit: {memlimit_mb} MB). See {log_file_name}", file=sys.stderr)
            else:
                print(f"[ERROR] Binsec failed for {algorithm} ({nature}{tag}). See {log_file_name}", file=sys.stderr)

    except Exception as e:
        print(f"[ERROR] Execution failed: {e}", file=sys.stderr)

if __name__ == "__main__":
    main()
