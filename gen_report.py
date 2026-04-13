#!/usr/bin/env python3
"""gen_report.py — Generate leak reports from existing auto-mode log files.

For each matching log file:
  1. Decompress .log.gz → .log
  2. Run callstack2source to produce a .leaks file
  3. Re-gzip the .log back to .log.gz
  4. Merge all .leaks files into a combined report

Usage:
  python3 gen_report.py --library openssl --optimization O0 --mode one
  python3 gen_report.py --library openssl --optimization O0 --primitive rsa_decrypt ecdsa_sign --mode one
"""

import argparse
import glob
import gzip
import os
import shutil
import subprocess
import sys
import tempfile

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
CALLSTACK2SOURCE = os.path.join(SCRIPT_DIR, "callstack2source.py")
MERGE_REPORTS    = os.path.join(SCRIPT_DIR, "merge_reports.py")


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def decompress_gz(gz_path, plain_path):
    """Decompress gz_path → plain_path."""
    with gzip.open(gz_path, 'rb') as f_in, open(plain_path, 'wb') as f_out:
        shutil.copyfileobj(f_in, f_out)


def compress_gz(plain_path, gz_path):
    """Compress plain_path → gz_path, then remove plain_path."""
    with open(plain_path, 'rb') as f_in, gzip.open(gz_path, 'wb') as f_out:
        shutil.copyfileobj(f_in, f_out)
    os.remove(plain_path)


def run_callstack2source(log_file, binary_path, leaks_file):
    """Run callstack2source.py; return True on success."""
    try:
        r = subprocess.run(
            [sys.executable, CALLSTACK2SOURCE, log_file, binary_path, leaks_file],
            capture_output=True, text=True, timeout=300,
        )
        if r.returncode != 0:
            print(f"  [WARN] callstack2source failed: {r.stderr.strip()}", file=sys.stderr)
        return r.returncode == 0
    except Exception as e:
        print(f"  [WARN] callstack2source error: {e}", file=sys.stderr)
        return False


def run_merge_reports(leaks_files, output_file):
    """Merge leaks files into a combined report; return True on success."""
    if not leaks_files:
        return False
    try:
        r = subprocess.run(
            [sys.executable, MERGE_REPORTS, '--uniq-source', '-o', output_file] + leaks_files,
            capture_output=True, text=True, timeout=120,
        )
        return r.returncode == 0
    except Exception as e:
        print(f"  [WARN] merge_reports error: {e}", file=sys.stderr)
        return False


def find_binary(root, platform, library, optimization, primitive):
    """Locate the debug binary for the given primitive."""
    lib_opt = f"{library}-{optimization}"
    binary = os.path.join(
        root, "benchmark", platform, lib_opt, primitive, "bin",
        f"{primitive}_{lib_opt}_{platform}",
    )
    if os.path.exists(binary):
        return binary
    # Some builds use the .core file; prefer plain binary for callstack2source
    core = binary + ".core"
    if os.path.exists(core):
        return core
    return None


def find_log_files(root, platform, library, optimization, primitives, mode):
    """Return list of (primitive, gz_path) for matching .log.gz files."""
    lib_opt   = f"{library}-{optimization}"
    base_dir  = os.path.join(root, "results", platform, lib_opt)
    results   = []

    for primitive in primitives:
        prim_dir = os.path.join(base_dir, primitive)
        if not os.path.isdir(prim_dir):
            print(f"  [SKIP] directory not found: {prim_dir}", file=sys.stderr)
            continue

        if mode:
            pattern = os.path.join(prim_dir, f"*_auto_*_{mode}.log.gz")
        else:
            # No mode tag — match auto logs that do NOT have a tag suffix
            # e.g. rsa_openssl_auto_0.log.gz  (not rsa_openssl_auto_0_one.log.gz)
            pattern = os.path.join(prim_dir, "*_auto_*.log.gz")

        matches = sorted(glob.glob(pattern))

        if mode:
            # Exclude files that have additional suffixes beyond the mode tag
            # (e.g. avoid matching *_auto_0_one_extra.log.gz)
            filtered = []
            suffix = f"_{mode}.log.gz"
            for p in matches:
                if os.path.basename(p).endswith(suffix):
                    filtered.append(p)
            matches = filtered

        if not matches:
            print(f"  [SKIP] no matching logs in {prim_dir}", file=sys.stderr)
            continue

        for gz_path in matches:
            results.append((primitive, gz_path))

    return results


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="Generate leak reports from existing auto-mode .log.gz files."
    )
    parser.add_argument("--library", required=True,
                        choices=["openssl", "bearssl", "wolfssl", "mbedtls"],
                        help="Library name")
    parser.add_argument("--optimization", required=True,
                        help="Optimization level (e.g. O0, O2)")
    parser.add_argument("--primitive", nargs="+", default=None,
                        help="Primitive(s) to process (default: all found)")
    parser.add_argument("--mode", default="",
                        help="Tag suffix of log files to process (e.g. 'one', 'all'); "
                             "omit for untagged logs")
    parser.add_argument("--platform", default="32", choices=["32", "64", "arm64"],
                        help="Platform (default: 32)")
    parser.add_argument("--root", default=".",
                        help="Project root directory (default: .)")
    parser.add_argument("--report", default="reports",
                        help="Output directory for merged report (default: reports/)")
    args = parser.parse_args()

    root      = os.path.abspath(args.root)
    lib_opt   = f"{args.library}-{args.optimization}"
    base_dir  = os.path.join(root, "results", args.platform, lib_opt)

    # Discover primitives if not specified
    if args.primitive:
        primitives = args.primitive
    else:
        if not os.path.isdir(base_dir):
            print(f"[ERROR] Result directory not found: {base_dir}", file=sys.stderr)
            sys.exit(1)
        primitives = sorted(
            d for d in os.listdir(base_dir)
            if os.path.isdir(os.path.join(base_dir, d))
        )
        if not primitives:
            print(f"[ERROR] No primitives found in {base_dir}", file=sys.stderr)
            sys.exit(1)
        print(f"[INFO] Primitives found: {', '.join(primitives)}")

    # Find matching log files
    log_entries = find_log_files(root, args.platform, args.library,
                                 args.optimization, primitives, args.mode)
    if not log_entries:
        print("[ERROR] No matching log files found.", file=sys.stderr)
        sys.exit(1)

    print(f"[INFO] Found {len(log_entries)} log file(s) to process")

    # Prepare output directory
    report_dir = os.path.abspath(args.report)
    os.makedirs(report_dir, exist_ok=True)

    all_leaks_files = []

    for primitive, gz_path in log_entries:
        basename = os.path.basename(gz_path)          # e.g. rsa_openssl_auto_0_one.log.gz
        plain_name = basename[:-3]                     # strip .gz
        plain_path = gz_path[:-3]                     # full path without .gz
        leaks_name = plain_name.replace(".log", ".leaks")
        leaks_path = os.path.join(os.path.dirname(gz_path), leaks_name)

        print(f"\n[LOG] {os.path.relpath(gz_path, root)}")

        # 1. Decompress
        print(f"  [DECOMPRESS] → {plain_name}")
        try:
            decompress_gz(gz_path, plain_path)
        except Exception as e:
            print(f"  [ERROR] decompress failed: {e}", file=sys.stderr)
            continue

        # 2. Find binary
        binary = find_binary(root, args.platform, args.library,
                             args.optimization, primitive)
        if not binary:
            print(f"  [ERROR] binary not found for {primitive}", file=sys.stderr)
            compress_gz(plain_path, gz_path)
            continue

        # 3. Generate .leaks file
        print(f"  [LEAKS] → {leaks_name}")
        ok = run_callstack2source(plain_path, binary, leaks_path)
        if ok:
            all_leaks_files.append(leaks_path)
        else:
            print(f"  [WARN] leaks file not generated for {basename}", file=sys.stderr)

        # 4. Re-compress log
        print(f"  [COMPRESS] → {basename}")
        try:
            compress_gz(plain_path, gz_path)
        except Exception as e:
            print(f"  [WARN] re-compress failed: {e}", file=sys.stderr)

    if not all_leaks_files:
        print("\n[ERROR] No leaks files generated — nothing to report.", file=sys.stderr)
        sys.exit(1)

    # 5. Merge into combined report
    tag_str   = f"_{args.mode}" if args.mode else ""
    merged_name = f"{args.library}_{args.optimization}{tag_str}_merged.leaks"
    merged_path = os.path.join(report_dir, merged_name)

    print(f"\n[MERGE] {len(all_leaks_files)} leaks file(s) → {os.path.relpath(merged_path, root)}")
    if run_merge_reports(all_leaks_files, merged_path):
        print(f"[OK] Report written to {merged_path}")
    else:
        print(f"[ERROR] merge_reports failed", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
