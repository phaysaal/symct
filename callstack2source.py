#!/usr/bin/env python3
"""
Static Call Stack Analysis Tool for CheckCT Violations

Parses CheckCT log output and uses static analysis (objdump, addr2line)
to reconstruct detailed call stacks without running GDB.
"""

import re
import subprocess
import sys
import os
from collections import Counter


class CallInfo:
    """Represents a call instruction"""
    def __init__(self, call_addr, target_addr, source_func, target_func):
        self.call_addr = call_addr
        self.target_addr = target_addr
        self.source_func = source_func
        self.target_func = target_func

    def __repr__(self):
        return f"CallInfo({self.call_addr} -> {self.target_addr}: {self.source_func} -> {self.target_func})"


class CTViolation:
    """Represents a constant-time violation with call stack"""
    def __init__(self, address, leak_type, time, call_stack):
        self.address = address
        self.leak_type = leak_type
        self.time = time
        self.call_stack = call_stack  # List of call instruction addresses (deepest first)

    def __repr__(self):
        return f"CTViolation({self.address}, {self.leak_type}, {self.time}s, stack depth: {len(self.call_stack)})"


class StackFrame:
    """Represents a resolved stack frame"""
    def __init__(self, address, function, file_name=None, line_num=None):
        self.address = address
        self.function = function
        self.file_name = file_name
        self.line_num = line_num

    def __repr__(self):
        if self.line_num:
            return f"{self.function} ({self.file_name}:{self.line_num})"
        elif self.file_name:
            return f"{self.function} ({self.file_name})"
        else:
            return f"{self.function}"

    def to_tuple(self):
        """Convert to tuple for hashing/comparison"""
        return (self.function, self.file_name, self.line_num)


def parse_checkct_log(log_file, verbose=False):
    """
    Parse CheckCT log to extract:
    1. Call mappings (call_addr -> CallInfo)
    2. Violations with their call stacks

    Streams the file line-by-line to avoid loading the entire file into memory.
    """
    call_mappings = {}  # call_addr -> CallInfo
    violations = []

    call_samples = []  # Store first few call patterns for debugging
    violation_samples = []  # Store first few violation patterns for debugging

    # Diagnostic counters
    total_lines = 0
    lines_with_sse = 0
    lines_with_call = 0
    lines_with_dash = 0
    lines_with_checkct = 0
    raw_call_samples = []

    # For non-consuming lookahead on call instructions:
    # when we see a call, we store it and resolve it using the next line
    pending_call = None  # (call_addr, target_addr, source_func)

    with open(log_file, 'r') as f:
        pushback_line = None  # For re-processing a line consumed by the violation inner loop

        while True:
            # Get next line: either pushed-back or from file
            if pushback_line is not None:
                line = pushback_line
                pushback_line = None
            else:
                raw_line = f.readline()
                if not raw_line:
                    break
                line = raw_line.strip()

            total_lines += 1

            # Diagnostic counting
            if '[sse:debug]' in line:
                lines_with_sse += 1
            if 'call' in line.lower() and '[sse:debug]' in line:
                lines_with_call += 1
                if len(raw_call_samples) < 10:
                    raw_call_samples.append(line)
            if '----' in line:
                lines_with_dash += 1
            if '[checkct:result]' in line:
                lines_with_checkct += 1

            # Resolve pending call from previous line using current line as lookahead
            if pending_call:
                p_call_addr, p_target_addr, p_source_func = pending_call
                pending_call = None

                next_addr_match = re.search(r'\[sse:debug\]\s+(0x[0-9a-fA-F]+)', line)
                target_match = re.search(r'#\s*<([^>]+)>', line)

                if next_addr_match and target_match:
                    target_func = target_match.group(1).split('>')[0].strip()
                    if target_func != p_source_func:
                        call_mappings[p_call_addr] = CallInfo(p_call_addr, p_target_addr, p_source_func, target_func)
                        if len(call_samples) < 5:
                            call_samples.append(f"  -> {line}")

            # Look for call instructions
            # Pattern: [sse:debug] 0x5658655a call 0x5658c790          \t# <encode_rsa> + 0x107
            call_match = re.search(r'\[sse:debug\]\s+(0x[0-9a-fA-F]+)\s+(?:d?call)\s+(0x[0-9a-fA-F]+)\s+.*#\s*<([^>]+)>', line)
            if call_match:
                call_addr = call_match.group(1)
                target_addr = call_match.group(2)
                source_func = call_match.group(3).split('>')[0].strip()

                if len(call_samples) < 5:
                    call_samples.append(line)

                pending_call = (call_addr, target_addr, source_func)

            # Look for violations
            # Pattern: [checkct:result] Instruction 0x5658c4d8 has control flow leak (0.396s)
            violation_match = re.search(r'\[checkct:result\]\s+Instruction\s+(0x[0-9a-fA-F]+)\s+has\s+(.+?)\s+leak\s+\(([0-9.]+)s\)', line)
            if violation_match:
                viol_addr = violation_match.group(1)
                leak_type = violation_match.group(2)
                time_val = violation_match.group(3)

                if len(violation_samples) < 3:
                    violation_samples.append(line)

                # Parse call stack (consume subsequent lines)
                call_stack = []
                safety = 0
                while True:
                    raw_line = f.readline()
                    if not raw_line:
                        break
                    stack_line = raw_line.strip()
                    safety += 1

                    if '[checkct:result] CT call stack' in stack_line:
                        continue

                    # Pattern: [checkct:result]   #0  0x5658655a
                    stack_match = re.search(r'\[checkct:result\]\s+#\d+\s+(0x[0-9a-fA-F]+)', stack_line)
                    if stack_match:
                        call_stack.append(stack_match.group(1))
                        if len(violation_samples) < 3:
                            violation_samples.append(f"  {stack_line}")
                    elif '[checkct:result]' in stack_line and not stack_line.endswith(':'):
                        # End of call stack - push back for re-processing
                        pushback_line = stack_line
                        break
                    else:
                        if safety > 20:
                            break

                violations.append(CTViolation(viol_addr, leak_type, time_val, call_stack))

    if verbose:
        print(f"    Total lines processed: {total_lines}")
        print(f"    Parsed {len(call_mappings)} call mappings")
        print(f"    Parsed {len(violations)} violations")
        print(f"\n    DIAGNOSTICS:")
        print(f"      Lines with [sse:debug]: {lines_with_sse}")
        print(f"      Lines with [sse:debug] + 'call': {lines_with_call}")
        print(f"      Lines with '----' (old marker): {lines_with_dash}")
        print(f"      Lines with [checkct:result]: {lines_with_checkct}")

        if raw_call_samples:
            print(f"\n    Raw [sse:debug] call instruction lines (first 10):")
            for sample in raw_call_samples[:10]:
                print(f"      {repr(sample)}")

        if call_samples:
            print(f"\n    Successfully parsed call patterns:")
            for sample in call_samples[:10]:
                print(f"      {sample}")
        if violation_samples:
            print(f"\n    Sample violation patterns found:")
            for sample in violation_samples[:10]:
                print(f"      {sample}")

    return call_mappings, violations, call_samples, violation_samples


def get_function_addresses(binary_path):
    """Use objdump to get static function addresses"""
    try:
        result = subprocess.run(
            ['objdump', '-d', binary_path],
            capture_output=True,
            text=True,
            timeout=30
        )

        func_addrs = {}  # static_addr -> func_name
        func_to_addr = {}  # func_name -> static_addr

        for line in result.stdout.split('\n'):
            # Pattern: 0804f7f0 <RsaFunctionPrivate>:
            func_match = re.match(r'^([0-9a-fA-F]+)\s+<([^>]+)>:', line)
            if func_match:
                addr = '0x' + func_match.group(1)
                func_name = func_match.group(2)
                func_addrs[addr] = func_name
                func_to_addr[func_name] = addr

        return func_addrs, func_to_addr
    except Exception as e:
        print(f"Warning: Could not run objdump: {e}")
        return {}, {}


def calculate_address_offset(call_mappings, func_to_static_addr, verbose=False):
    """
    Calculate offset between runtime and static addresses
    offset = runtime_addr - static_addr

    Uses common functions found in both call_mappings and objdump
    """
    # Collect runtime addresses of functions from call_mappings
    runtime_funcs = {}  # func_name -> runtime_addr

    for call_info in call_mappings.values():
        # Target address is usually the function entry point
        if call_info.target_func not in runtime_funcs:
            runtime_funcs[call_info.target_func] = call_info.target_addr

    # Find common functions and calculate offset
    offsets = []
    common_funcs = []

    for func_name in runtime_funcs:
        if func_name in func_to_static_addr:
            runtime_addr = int(runtime_funcs[func_name], 16)
            static_addr = int(func_to_static_addr[func_name], 16)
            offset = runtime_addr - static_addr
            offsets.append(offset)
            common_funcs.append((func_name, hex(runtime_addr), hex(static_addr), hex(offset)))

            if len(offsets) >= 10:  # Sample first 10
                break

    if not offsets:
        if verbose:
            print("    WARNING: No common functions found between runtime and static!")
            print("    Cannot calculate address offset. Results may be incorrect.")
        return 0

    # All offsets should be the same (or very close)
    # Use the most common offset
    offset_counts = Counter(offsets)
    final_offset = offset_counts.most_common(1)[0][0]

    if verbose:
        print(f"    Found {len(common_funcs)} common functions")
        print(f"    Calculated offset: {hex(final_offset)} ({final_offset})")
        print(f"\n    Sample function address mappings:")
        for func_name, runtime, static, off in common_funcs[:5]:
            print(f"      {func_name}:")
            print(f"        Runtime: {runtime}")
            print(f"        Static:  {static}")
            print(f"        Offset:  {off}")

    return final_offset


def runtime_to_static_addr(runtime_addr, offset):
    """Convert runtime address to static address"""
    if isinstance(runtime_addr, str):
        runtime_val = int(runtime_addr, 16)
    else:
        runtime_val = runtime_addr

    static_val = runtime_val - offset
    return hex(static_val)


def addr2line(binary_path, address):
    """Use addr2line to get source file and line number"""
    try:
        result = subprocess.run(
            ['addr2line', '-e', binary_path, '-f', '-C', address],
            capture_output=True,
            text=True,
            timeout=5
        )

        lines = result.stdout.strip().split('\n')
        if len(lines) >= 2:
            function = lines[0]
            location = lines[1]

            if ':' in location and '?' not in location:
                parts = location.rsplit(':', 1)
                file_name = parts[0]
                line_num_raw = parts[1] if len(parts) > 1 else None

                # Clean up line number (remove discriminator, e.g., "491 (discriminator 2)" -> "491")
                if line_num_raw:
                    line_num = line_num_raw.split()[0]  # Take first token
                else:
                    line_num = None

                return function, file_name, line_num
            else:
                return function, None, None

        return None, None, None
    except Exception as e:
        return None, None, None


def resolve_call_stack(call_stack, call_mappings, binary_path, addr_offset=0):
    """
    Resolve call stack addresses to detailed stack frames
    call_stack is ordered deepest first (#0, #1, #2, ...)
    addr_offset is used to convert runtime addresses to static addresses
    """
    frames = []

    for call_addr in call_stack:
        # Convert runtime address to static address
        static_addr = runtime_to_static_addr(call_addr, addr_offset)

        # Get call info from mappings
        call_info = call_mappings.get(call_addr)

        if call_info:
            # Try to get source location using addr2line with static address
            func, file_name, line_num = addr2line(binary_path, static_addr)

            # Prefer the source function from call mapping
            if not func or func == '??':
                func = call_info.source_func

            frame = StackFrame(call_addr, func, file_name, line_num)
            frames.append(frame)
        else:
            # No call info, try addr2line only with static address
            func, file_name, line_num = addr2line(binary_path, static_addr)
            if func:
                frame = StackFrame(call_addr, func, file_name, line_num)
                frames.append(frame)
            else:
                # Unknown function
                frame = StackFrame(call_addr, f"unknown@{call_addr}")
                frames.append(frame)

    return frames


class CallTreeNode:
    """Represents a node in the call tree"""
    def __init__(self, frame):
        self.frame = frame
        self.children = {}
        self.hit_count = 0
        self.is_violation = False

    def add_path(self, frames, index=0):
        """Add a call path to the tree"""
        self.hit_count += 1

        if index >= len(frames):
            self.is_violation = True
            return

        frame = frames[index]
        key = frame.to_tuple()

        if key not in self.children:
            self.children[key] = CallTreeNode(frame)

        self.children[key].add_path(frames, index + 1)

    def format_tree(self, indent=0, show_counts=False, violation_marker=""):
        """Format the tree as a string"""
        output = []

        # Format current node
        if indent == 0:
            line = str(self.frame)
        else:
            line = "\t" + "  " * (indent - 1) + "└─ " + str(self.frame)

        if show_counts and self.hit_count > 1:
            line += f" [{self.hit_count} hits]"

        output.append(line)

        # If this is a violation point, mark it
        if self.is_violation:
            marker_indent = "\t" + "  " * indent
            output.append(f"{marker_indent}    {violation_marker}")

        # Format children
        for child in sorted(self.children.values(), key=lambda x: x.hit_count, reverse=True):
            child_output = child.format_tree(indent + 1, show_counts, violation_marker)
            output.append(child_output)

        return '\n'.join(output)


def build_call_tree(frames):
    """Build a call tree from resolved frames (reversed order: main -> ... -> violation)"""
    if not frames:
        return None

    # Frames are already in deepest-first order, reverse to get main->...->violation
    reversed_frames = list(reversed(frames))

    # Create root node
    root = CallTreeNode(reversed_frames[0])
    root.add_path(reversed_frames[1:])

    return root


def generate_report(violations, call_mappings, binary_path, output_file, debug_file=None, addr_offset=0):
    """
    Generate analysis report.

    This function filters out duplicate callstacks by using a hash-based deduplication approach.
    Only violations with unique callstacks (based on function, file, and line number tuples) are included
    in the final report.

    Returns:
        tuple: (unique_count, duplicate_count)
    """

    # Track unique callstacks using a hash set
    seen_callstacks = set()
    unique_violations = []  # Store violations with unique callstacks
    duplicate_count = 0

    # Generate debug output if requested
    if debug_file:
        with open(debug_file, 'w') as df:
            df.write("=" * 80 + "\n")
            df.write("DEBUG OUTPUT\n")
            df.write("=" * 80 + "\n\n")

            df.write(f"Address offset (runtime - static): {hex(addr_offset)}\n\n")

            df.write(f"CALL MAPPINGS FOUND: {len(call_mappings)}\n")
            df.write("-" * 40 + "\n")
            for call_addr in sorted(call_mappings.keys())[:50]:  # Show first 50
                info = call_mappings[call_addr]
                df.write(f"{call_addr}: {info.source_func} -> {info.target_func}\n")
            if len(call_mappings) > 50:
                df.write(f"... and {len(call_mappings) - 50} more\n")
            df.write("\n\n")

            df.write(f"VIOLATIONS: {len(violations)}\n")
            df.write("=" * 80 + "\n\n")

            for i, violation in enumerate(violations, 1):
                df.write(f"\nVIOLATION #{i}: {violation.address}\n")
                df.write("-" * 40 + "\n")
                df.write(f"Call stack addresses ({len(violation.call_stack)} items):\n")
                for idx, addr in enumerate(violation.call_stack):
                    static_addr = runtime_to_static_addr(addr, addr_offset)
                    df.write(f"  #{idx}  {addr} (runtime) -> {static_addr} (static)\n")

                    # Check if we have call mapping
                    if addr in call_mappings:
                        info = call_mappings[addr]
                        df.write(f"       Call mapping: {info.source_func} -> {info.target_func}\n")
                    else:
                        df.write(f"       Call mapping: NOT FOUND\n")

                    # Try addr2line with static address
                    func, file_name, line_num = addr2line(binary_path, static_addr)
                    df.write(f"       addr2line: func={func}, file={file_name}, line={line_num}\n")

                df.write("\n")

    # Entry-point functions to ignore when comparing call stacks
    SKIP_FUNCS = {'main', 'tester_main', 'encode_rsa', 'encode_ecdsa', 'encode_eddsa'}

    # First pass: identify unique callstacks using raw addresses
    # (same call path will have the same runtime addresses, no need to resolve)
    for violation in violations:
        if violation.call_stack:
            # Trim shallowest frames (end of list) whose source_func is boilerplate
            trimmed = list(violation.call_stack)
            while trimmed:
                info = call_mappings.get(trimmed[-1])
                if info and info.source_func in SKIP_FUNCS:
                    trimmed.pop()
                else:
                    break
            callstack_signature = (violation.address, violation.leak_type, tuple(trimmed))
            if callstack_signature not in seen_callstacks:
                seen_callstacks.add(callstack_signature)
                unique_violations.append(violation)
            else:
                duplicate_count += 1
        else:
            unique_violations.append(violation)

    with open(output_file, 'w') as f:
        f.write("=" * 80 + "\n")
        f.write("CONSTANT-TIME VIOLATION ANALYSIS REPORT (STATIC ANALYSIS)\n")
        f.write("=" * 80 + "\n\n")

        f.write(f"Total Violations Found: {len(violations)}\n")
        f.write(f"Unique Call Stacks: {len(unique_violations)}\n")
        f.write(f"Duplicate Call Stacks: {duplicate_count}\n\n")

        for i, violation in enumerate(unique_violations, 1):
            f.write("-" * 80 + "\n")
            f.write(f"VIOLATION #{i}\n")
            f.write("-" * 80 + "\n")
            f.write(f"Address:    {violation.address}\n")
            f.write(f"Leak Type:  {violation.leak_type}\n")
            f.write(f"Time:       {violation.time}s\n")
            f.write(f"Stack Depth: {len(violation.call_stack)}\n")
            f.write("\n")

            if violation.call_stack:
                # Resolve call stack
                frames = resolve_call_stack(violation.call_stack, call_mappings, binary_path, addr_offset)

                # Remove boilerplate entry-point frames from display
                # Frames are deepest-first, so entry points are at the end
                display_frames = list(frames)
                while display_frames and display_frames[-1].function in SKIP_FUNCS:
                    display_frames.pop()

                f.write("CALL HIERARCHY:\n")
                f.write("-" * 40 + "\n")

                # Build and display call tree
                tree = build_call_tree(display_frames)
                if tree:
                    # Resolve violation point (convert to static address)
                    viol_static = runtime_to_static_addr(violation.address, addr_offset)
                    viol_func, viol_file, viol_line = addr2line(binary_path, viol_static)
                    viol_desc = f"{viol_func}" if viol_func else f"unknown@{violation.address}"
                    if viol_file:
                        viol_desc += f" ({viol_file}"
                        if viol_line:
                            viol_desc += f":{viol_line}"
                        viol_desc += ")"

                    violation_marker = f"[{violation.address}] {viol_desc} <-- {violation.leak_type} leak"
                    tree_output = tree.format_tree(
                        indent=0,
                        show_counts=False,
                        violation_marker=violation_marker
                    )
                    f.write(tree_output + "\n")
                else:
                    # Fallback: just list frames
                    for idx, frame in enumerate(display_frames):
                        f.write(f"  #{idx}  {frame.address}: {frame}\n")

                    # Show the violation point
                    f.write(f"\n  Violation at: {violation.address}\n")
                    viol_static = runtime_to_static_addr(violation.address, addr_offset)
                    viol_func, viol_file, viol_line = addr2line(binary_path, viol_static)
                    if viol_func:
                        f.write(f"      {viol_func}")
                        if viol_file:
                            f.write(f" ({viol_file}")
                            if viol_line:
                                f.write(f":{viol_line}")
                            f.write(")")
                        f.write("\n")

                    f.write(f"\n      [{violation.address}] <-- {violation.leak_type} leak\n")

                f.write("\n")
            else:
                f.write("(No call stack captured)\n\n")

            f.write("\n")

    return len(unique_violations), duplicate_count


def main():
    if len(sys.argv) < 4:
        print("Usage: python static_analysis.py <checkct_log> <binary> <output_file> [--debug debug.txt]")
        print()
        print("Arguments:")
        print("  checkct_log  - CheckCT log file")
        print("  binary       - Path to the executable binary")
        print("  output_file  - Output report file")
        print("  --debug      - Optional: Generate debug output file")
        print()
        print("Example:")
        print("  python static_analysis.py checkct.log ./program output.txt")
        print("  python static_analysis.py checkct.log ./program output.txt --debug debug.txt")
        sys.exit(1)

    log_file = sys.argv[1]
    binary_path = sys.argv[2]
    output_file = sys.argv[3]

    # Parse optional arguments
    debug_file = None

    i = 4
    while i < len(sys.argv):
        if sys.argv[i] == '--debug':
            debug_file = sys.argv[i + 1] if i + 1 < len(sys.argv) else 'debug_output.txt'
            i += 2
        else:
            i += 1

    # Verify files exist
    if not os.path.exists(log_file):
        print(f"Error: Log file '{log_file}' not found")
        sys.exit(1)

    if not os.path.exists(binary_path):
        print(f"Error: Binary '{binary_path}' not found")
        sys.exit(1)

    print("=" * 80)
    print("STATIC CALL STACK ANALYSIS")
    print("=" * 80)
    print()

    # Step 1: Parse CheckCT log
    print(f"[1] Parsing CheckCT log: {log_file}")
    verbose = debug_file is not None
    call_mappings, violations, call_samples, violation_samples = parse_checkct_log(log_file, verbose=verbose)
    print(f"    Found {len(violations)} violations")
    print()

    # Display violations
    for v in violations:
        print(f"    • {v.address}: {v.leak_type} leak ({v.time}s) - stack depth: {len(v.call_stack)}")
    print()

    # Step 2: Calculate address offset
    print(f"[2] Analyzing binary with objdump: {binary_path}")
    func_addrs, func_to_static_addr = get_function_addresses(binary_path)
    print(f"    Found {len(func_to_static_addr)} functions in binary")

    print(f"\n[3] Calculating address offset (runtime - static)...")
    addr_offset = calculate_address_offset(call_mappings, func_to_static_addr, verbose=verbose)
    print()

    # Step 3: Generate report
    print(f"[4] Generating report: {output_file}")
    if debug_file:
        print(f"    Debug mode enabled: {debug_file}")

    unique_count, duplicate_count = generate_report(violations, call_mappings, binary_path, output_file, debug_file, addr_offset)

    print()
    print("=" * 80)
    print("ANALYSIS COMPLETE")
    print("=" * 80)
    print(f"Report written to: {output_file}")
    if debug_file:
        print(f"Debug output written to: {debug_file}")
    print()

    print("SUMMARY:")
    print(f"  Total violations:     {len(violations)}")
    print(f"  Unique call stacks:   {unique_count}")
    print(f"  Duplicate call stacks: {duplicate_count}")
    print()


if __name__ == "__main__":
    main()
