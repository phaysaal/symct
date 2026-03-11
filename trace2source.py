#!/usr/bin/env python3
"""
Convert binsec execution trace from binary addresses to source code locations.

Reads a binsec log file, extracts [sse:debug] trace lines, resolves each
address to file:line using addr2line, and outputs a source-annotated trace.

Usage:
    python trace2source.py <log_file> <binary> [-o output_file] [--no-asm] [--context N]

Arguments:
    log_file    - Binsec log file (.log or .log.gz)
    binary      - Path to the ELF binary (with debug symbols, non-.core)

Options:
    -o FILE     - Write output to FILE (default: stdout)
    --no-asm    - Omit assembly instructions, show only source lines
    --context N - Show N lines of source context around each location (default: 0)
    --compact   - Collapse consecutive lines in the same source line into one
"""

import argparse
import gzip
import os
import re
import subprocess
import sys
from collections import OrderedDict


# ── Regex patterns ──

# [sse:debug] 0x565bf168 mov eax, [ebx + 0x241c]  \t# <tester_main> + 0x12
TRACE_RE = re.compile(
    r'\[sse:debug\]\s+(0x[0-9a-fA-F]+)\s+(.+?)\s*#\s*<([^>]+)>\s*(?:\+\s*(0x[0-9a-fA-F]+))?'
)

# Memory map line: [sse:debug] 56555000 :: 0x56555000-0x565be000 00000000 /path/to/binary
MEMMAP_RE = re.compile(
    r'\[sse:debug\]\s+[0-9a-fA-F]+\s+::\s+(0x[0-9a-fA-F]+)-(0x[0-9a-fA-F]+)\s+[0-9a-fA-F]+\s+(\S+)'
)

# Function header from objdump: 0804f7f0 <function_name>:
OBJDUMP_FUNC_RE = re.compile(r'^([0-9a-fA-F]+)\s+<([^>]+)>:')


def parse_args():
    parser = argparse.ArgumentParser(
        description="Convert binsec execution trace to source code trace"
    )
    parser.add_argument("log_file", help="Binsec log file (.log or .log.gz)")
    parser.add_argument("binary", help="ELF binary with debug symbols")
    parser.add_argument("-o", "--output", default=None, help="Output file (default: stdout)")
    parser.add_argument("--no-asm", action="store_true", help="Omit assembly instructions")
    parser.add_argument("--context", type=int, default=0, help="Source context lines (default: 0)")
    parser.add_argument("--compact", action="store_true",
                        help="Collapse consecutive instructions at the same source line")
    return parser.parse_args()


def open_log(path):
    """Open a log file, handling .gz transparently."""
    if path.endswith(".gz"):
        return gzip.open(path, "rt")
    return open(path, "r")


def get_function_addresses(binary_path):
    """Get function name -> static address mapping from objdump."""
    try:
        result = subprocess.run(
            ["objdump", "-d", binary_path],
            capture_output=True, text=True, timeout=30,
        )
        func_to_addr = {}
        for line in result.stdout.split("\n"):
            m = OBJDUMP_FUNC_RE.match(line)
            if m:
                func_to_addr[m.group(2)] = int(m.group(1), 16)
        return func_to_addr
    except Exception as e:
        print(f"Warning: objdump failed: {e}", file=sys.stderr)
        return {}


def calculate_offset(trace_entries, func_to_static):
    """Calculate runtime - static address offset using function entry points in the trace."""
    # Collect runtime addresses of function entries (offset == 0 or first occurrence)
    runtime_funcs = {}
    for addr, _asm, func, offset in trace_entries:
        if offset == 0 and func not in runtime_funcs:
            runtime_funcs[func] = addr

    offsets = []
    for func, runtime_addr in runtime_funcs.items():
        if func in func_to_static:
            offsets.append(runtime_addr - func_to_static[func])

    if not offsets:
        # Fallback: try from memory map
        return 0

    # Most common offset
    from collections import Counter
    return Counter(offsets).most_common(1)[0][0]


def batch_addr2line(binary_path, addresses):
    """Resolve a batch of static addresses to (func, file, line) using addr2line.

    Calls addr2line once with all addresses for efficiency.
    """
    if not addresses:
        return {}

    hex_addrs = [hex(a) for a in sorted(set(addresses))]

    try:
        result = subprocess.run(
            ["addr2line", "-e", binary_path, "-f", "-C"] + hex_addrs,
            capture_output=True, text=True, timeout=30,
        )
    except Exception as e:
        print(f"Warning: addr2line failed: {e}", file=sys.stderr)
        return {}

    lines = result.stdout.strip().split("\n")
    mapping = {}

    for i in range(0, len(lines) - 1, 2):
        idx = i // 2
        if idx >= len(hex_addrs):
            break
        static_addr = int(hex_addrs[idx], 16)
        func = lines[i]
        location = lines[i + 1] if i + 1 < len(lines) else "??:?"

        if "?" in location:
            mapping[static_addr] = (func, None, None)
        else:
            parts = location.rsplit(":", 1)
            file_name = parts[0]
            line_num = parts[1].split()[0] if len(parts) > 1 else None  # strip discriminator
            mapping[static_addr] = (func, file_name, line_num)

    return mapping


def read_source_lines(file_path, line_num, context=0):
    """Read source lines around a given line number. Returns list of (lineno, text)."""
    try:
        with open(file_path, "r") as f:
            all_lines = f.readlines()
    except (OSError, IOError):
        return []

    start = max(0, line_num - 1 - context)
    end = min(len(all_lines), line_num + context)
    return [(i + 1, all_lines[i].rstrip()) for i in range(start, end)]


def main():
    args = parse_args()

    if not os.path.exists(args.log_file):
        print(f"Error: Log file not found: {args.log_file}", file=sys.stderr)
        sys.exit(1)
    if not os.path.exists(args.binary):
        print(f"Error: Binary not found: {args.binary}", file=sys.stderr)
        sys.exit(1)

    # ── Step 1: Parse trace lines from the log ──
    trace_entries = []  # (runtime_addr_int, asm_text, func_name, offset_int)
    other_lines = []    # non-trace lines to preserve (leak results, etc.)

    with open_log(args.log_file) as f:
        for line in f:
            line = line.rstrip()
            m = TRACE_RE.search(line)
            if m:
                addr = int(m.group(1), 16)
                asm = m.group(2).strip()
                func = m.group(3)
                offset = int(m.group(4), 16) if m.group(4) else 0
                trace_entries.append((addr, asm, func, offset))
            elif "[checkct:result]" in line:
                other_lines.append(line)

    if not trace_entries:
        print("No [sse:debug] trace lines found in log.", file=sys.stderr)
        sys.exit(1)

    print(f"Parsed {len(trace_entries)} trace instructions", file=sys.stderr)

    # ── Step 2: Calculate address offset ──
    func_to_static = get_function_addresses(args.binary)
    offset = calculate_offset(trace_entries, func_to_static)
    print(f"Address offset: {hex(offset)}", file=sys.stderr)

    # ── Step 3: Batch-resolve all unique addresses ──
    unique_static = set()
    for addr, _, _, _ in trace_entries:
        unique_static.add(addr - offset)

    print(f"Resolving {len(unique_static)} unique addresses...", file=sys.stderr)
    addr_map = batch_addr2line(args.binary, list(unique_static))

    # ── Step 4: Output annotated trace ──
    out = open(args.output, "w") if args.output else sys.stdout

    try:
        out.write(f"# Execution trace: {args.log_file}\n")
        out.write(f"# Binary: {args.binary}\n")
        out.write(f"# Instructions: {len(trace_entries)}\n")
        out.write(f"# Address offset: {hex(offset)}\n")
        out.write("#\n")

        prev_source_loc = None  # (file, line) for compact mode
        source_cache = {}       # file_path -> [lines]

        for i, (addr, asm, func, func_offset) in enumerate(trace_entries):
            static_addr = addr - offset
            resolved = addr_map.get(static_addr)

            if resolved:
                r_func, r_file, r_line = resolved
            else:
                r_func, r_file, r_line = func, None, None

            # Build source location string
            if r_file and r_line:
                # Shorten path: keep only last 3 components
                short_file = r_file
                parts = r_file.split("/")
                if len(parts) > 3:
                    short_file = ".../" + "/".join(parts[-3:])
                source_loc = f"{short_file}:{r_line}"
            else:
                source_loc = "??:?"

            current_loc = (r_file, r_line)

            # Compact mode: skip if same source line as previous
            if args.compact and current_loc == prev_source_loc and r_file is not None:
                continue
            prev_source_loc = current_loc

            # Format output line
            if args.no_asm:
                out.write(f"{source_loc:50s}  {func}+{hex(func_offset)}\n")
            else:
                out.write(f"{source_loc:50s}  {hex(static_addr)}  {asm:40s}  # {func}+{hex(func_offset)}\n")

            # Source context
            if args.context > 0 and r_file and r_line:
                try:
                    line_int = int(r_line)
                except ValueError:
                    continue
                src_lines = read_source_lines(r_file, line_int, args.context)
                for ln, text in src_lines:
                    marker = ">>>" if ln == line_int else "   "
                    out.write(f"    {marker} {ln:5d} | {text}\n")

        # Append checkct results at the end
        if other_lines:
            out.write("\n# ── CheckCT Results ──\n")
            for line in other_lines:
                out.write(line + "\n")

    finally:
        if args.output:
            out.close()

    dest = args.output or "stdout"
    print(f"Done. Output: {dest}", file=sys.stderr)


if __name__ == "__main__":
    main()
