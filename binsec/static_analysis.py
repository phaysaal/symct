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
from collections import defaultdict, Counter
from pathlib import Path


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
    """
    call_mappings = {}  # call_addr -> CallInfo
    violations = []

    call_samples = []  # Store first few call patterns for debugging
    violation_samples = []  # Store first few violation patterns for debugging

    # Diagnostic counters
    lines_with_sse = 0
    lines_with_call = 0
    lines_with_dash = 0
    lines_with_checkct = 0
    raw_call_samples = []  # Lines that contain 'call' and '----'

    with open(log_file, 'r') as f:
        lines = f.readlines()

    if verbose:
        print(f"    Total lines in log: {len(lines)}")

    i = 0
    while i < len(lines):
        line = lines[i].strip()

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

        # Look for call instructions
        # Pattern: [sse:debug] 0x5658655a call 0x5658c790          \t# <encode_rsa> + 0x107
        call_match = re.search(r'\[sse:debug\]\s+(0x[0-9a-fA-F]+)\s+(?:d?call)\s+(0x[0-9a-fA-F]+)\s+.*#\s*<([^>]+)>', line)
        if call_match:
            call_addr = call_match.group(1)
            target_addr = call_match.group(2)
            source_func = call_match.group(3).split('>')[0].strip()

            # Store sample for debugging
            if len(call_samples) < 5:
                call_samples.append(line)

            # Next line should have the target function
            # Check if next line has [sse:debug] and a function name
            if i + 1 < len(lines):
                next_line = lines[i + 1].strip()

                # Check if next line starts with the target address (or is close)
                next_addr_match = re.search(r'\[sse:debug\]\s+(0x[0-9a-fA-F]+)', next_line)
                target_match = re.search(r'#\s*<([^>]+)>', next_line)

                if next_addr_match and target_match:
                    next_addr = next_addr_match.group(1)
                    # Verify the addresses are close (within reasonable range for function entry)
                    # Or the target function is different from source
                    target_func = target_match.group(1).split('>')[0].strip()

                    # Only add if target function is different from source (it's actually a call to another function)
                    if target_func != source_func:
                        call_mappings[call_addr] = CallInfo(call_addr, target_addr, source_func, target_func)

                        if len(call_samples) < 5:
                            call_samples.append(f"  -> {next_line}")

        # Look for violations
        # Pattern: [checkct:result] Instruction 0x5658c4d8 has control flow leak (0.396s)
        violation_match = re.search(r'\[checkct:result\]\s+Instruction\s+(0x[0-9a-fA-F]+)\s+has\s+(.+?)\s+leak\s+\(([0-9.]+)s\)', line)
        if violation_match:
            viol_addr = violation_match.group(1)
            leak_type = violation_match.group(2)
            time = violation_match.group(3)

            # Store sample for debugging
            if len(violation_samples) < 3:
                violation_samples.append(line)

            # Parse call stack (next few lines)
            call_stack = []
            j = i + 1
            while j < len(lines):
                stack_line = lines[j].strip()
                if '[checkct:result] CT call stack' in stack_line:
                    j += 1
                    continue

                # Pattern: [checkct:result]   #0  0x5658655a
                stack_match = re.search(r'\[checkct:result\]\s+#\d+\s+(0x[0-9a-fA-F]+)', stack_line)
                if stack_match:
                    call_stack.append(stack_match.group(1))
                    if len(violation_samples) < 3:
                        violation_samples.append(f"  {stack_line}")
                    j += 1
                elif '[checkct:result]' in stack_line and not stack_line.endswith(':'):
                    # End of call stack
                    break
                else:
                    j += 1
                    if j - i > 20:  # Safety limit
                        break

            violations.append(CTViolation(viol_addr, leak_type, time, call_stack))
            i = j
            continue

        i += 1

    if verbose:
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


def extract_function_body(file_path, function_name, line_num):
    """
    Extract the complete function body from source file
    Returns (start_line, end_line, function_code)
    """
    try:
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            lines = f.readlines()

        if not lines or line_num <= 0 or line_num > len(lines):
            return None, None, None

        # Search backwards from line_num to find function start
        # Look for function signature (return_type function_name(...))
        func_start = None
        for i in range(line_num - 1, max(0, line_num - 100), -1):
            line = lines[i].strip()
            # Look for function name followed by opening parenthesis
            if function_name in line and '(' in line:
                # Check if this looks like a function definition (not a call)
                # Function definitions usually have return type before function name
                func_start = i
                break

        if func_start is None:
            # Fallback: use line_num as start
            func_start = line_num - 1

        # Find the first opening brace after function start
        brace_start = None
        for i in range(func_start, min(len(lines), func_start + 20)):
            if '{' in lines[i]:
                brace_start = i
                break

        if brace_start is None:
            return None, None, None

        # Find matching closing brace
        brace_count = 0
        func_end = None
        for i in range(brace_start, len(lines)):
            for char in lines[i]:
                if char == '{':
                    brace_count += 1
                elif char == '}':
                    brace_count -= 1
                    if brace_count == 0:
                        func_end = i
                        break
            if func_end is not None:
                break

        if func_end is None:
            return None, None, None

        # Extract function code
        function_code = ''.join(lines[func_start:func_end + 1])
        return func_start + 1, func_end + 1, function_code

    except Exception as e:
        return None, None, None


def generate_leak_file(violation, frames, binary_path, addr_offset, leak_dir="leaks"):
    """
    Generate a .leak file for a specific violation
    Contains call stack and full function bodies
    """
    # Create leak directory if it doesn't exist
    os.makedirs(leak_dir, exist_ok=True)

    # Clean address for filename (remove 0x prefix)
    leak_filename = f"{violation.address[2:]}.leak"
    leak_path = os.path.join(leak_dir, leak_filename)

    with open(leak_path, 'w', encoding='utf-8') as f:
        f.write("=" * 80 + "\n")
        f.write(f"CONSTANT-TIME VIOLATION LEAK ANALYSIS\n")
        f.write("=" * 80 + "\n\n")

        f.write(f"Violation Address: {violation.address}\n")
        f.write(f"Leak Type:         {violation.leak_type}\n")
        f.write(f"Detection Time:    {violation.time}s\n")
        f.write("\n")

        # Resolve violation point
        viol_static = runtime_to_static_addr(violation.address, addr_offset)
        viol_func, viol_file, viol_line = addr2line(binary_path, viol_static)

        f.write("Violation Point:\n")
        f.write(f"  Function: {viol_func if viol_func else 'unknown'}\n")
        if viol_file:
            f.write(f"  File:     {viol_file}\n")
            if viol_line:
                f.write(f"  Line:     {viol_line}\n")
        f.write("\n")

        f.write("=" * 80 + "\n")
        f.write("CALL STACK (deepest to shallowest)\n")
        f.write("=" * 80 + "\n\n")

        # Display call stack
        for idx, frame in enumerate(frames):
            f.write(f"[{idx}] {frame.address}\n")
            f.write(f"    Function: {frame.function}\n")
            if frame.file_name:
                f.write(f"    Location: {frame.file_name}")
                if frame.line_num:
                    f.write(f":{frame.line_num}")
                f.write("\n")
            f.write("\n")

        f.write("\n")
        f.write("=" * 80 + "\n")
        f.write("FUNCTION SOURCE CODE\n")
        f.write("=" * 80 + "\n\n")

        # Extract and write function bodies
        seen_functions = set()
        for idx, frame in enumerate(frames):
            # Skip if we've already included this function
            func_key = (frame.function, frame.file_name)
            if func_key in seen_functions:
                continue
            seen_functions.add(func_key)

            f.write("-" * 80 + "\n")
            f.write(f"[{idx}] {frame.function}\n")
            f.write("-" * 80 + "\n")

            if frame.file_name and frame.line_num:
                f.write(f"Location: {frame.file_name}:{frame.line_num}\n\n")

                # Try to extract function body
                try:
                    line_num_int = int(frame.line_num)
                except (ValueError, TypeError):
                    line_num_int = 1  # Fallback

                start_line, end_line, func_code = extract_function_body(
                    frame.file_name, frame.function, line_num_int
                )

                if func_code:
                    f.write(f"Lines {start_line}-{end_line}:\n")
                    f.write("-" * 40 + "\n")
                    f.write(func_code)
                    f.write("\n")
                else:
                    f.write("(Could not extract function body - file may not be accessible)\n")
            else:
                f.write("(No source location available)\n")

            f.write("\n\n")

        # Add violation point function if not already included
        if viol_func and viol_file and viol_line:
            func_key = (viol_func, viol_file)
            if func_key not in seen_functions:
                f.write("-" * 80 + "\n")
                f.write(f"[VIOLATION] {viol_func}\n")
                f.write("-" * 80 + "\n")
                f.write(f"Location: {viol_file}:{viol_line}\n\n")

                try:
                    viol_line_int = int(viol_line)
                except (ValueError, TypeError):
                    viol_line_int = 1  # Fallback

                start_line, end_line, func_code = extract_function_body(
                    viol_file, viol_func, viol_line_int
                )

                if func_code:
                    f.write(f"Lines {start_line}-{end_line}:\n")
                    f.write("-" * 40 + "\n")
                    f.write(func_code)
                    f.write("\n")
                else:
                    f.write("(Could not extract function body)\n")

                f.write("\n")

    return leak_path


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


def generate_report(violations, call_mappings, binary_path, output_file, debug_file=None, addr_offset=0, leak_dir="leaks"):
    """Generate analysis report and individual leak files"""

    # Track generated leak files
    leak_files = []

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

    with open(output_file, 'w') as f:
        f.write("=" * 80 + "\n")
        f.write("CONSTANT-TIME VIOLATION ANALYSIS REPORT (STATIC ANALYSIS)\n")
        f.write("=" * 80 + "\n\n")

        f.write(f"Total Violations Found: {len(violations)}\n\n")

        for i, violation in enumerate(violations, 1):
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

                # Generate individual leak file
                leak_file = generate_leak_file(violation, frames, binary_path, addr_offset, leak_dir)
                leak_files.append(leak_file)

                f.write("CALL HIERARCHY:\n")
                f.write("-" * 40 + "\n")

                # Build and display call tree
                tree = build_call_tree(frames)
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
                    for idx, frame in enumerate(frames):
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

        # Summary of call mappings
        f.write("=" * 80 + "\n")
        f.write("CALL MAPPINGS DISCOVERED\n")
        f.write("=" * 80 + "\n\n")
        f.write(f"Total call sites tracked: {len(call_mappings)}\n\n")

        if call_mappings:
            for call_addr in sorted(call_mappings.keys()):
                info = call_mappings[call_addr]
                f.write(f"  {call_addr}: {info.source_func} -> {info.target_func}\n")

    return leak_files


def main():
    if len(sys.argv) < 4:
        print("Usage: python static_analysis.py <checkct_log> <binary> <output_file> [--debug debug.txt] [--leak-dir leaks]")
        print()
        print("Arguments:")
        print("  checkct_log  - CheckCT log file")
        print("  binary       - Path to the executable binary")
        print("  output_file  - Output report file")
        print("  --debug      - Optional: Generate debug output file")
        print("  --leak-dir   - Optional: Directory for individual leak files (default: 'leaks')")
        print()
        print("Example:")
        print("  python static_analysis.py checkct.log ./program output.txt")
        print("  python static_analysis.py checkct.log ./program output.txt --debug debug.txt")
        print("  python static_analysis.py checkct.log ./program output.txt --leak-dir my_leaks")
        sys.exit(1)

    log_file = sys.argv[1]
    binary_path = sys.argv[2]
    output_file = sys.argv[3]

    # Parse optional arguments
    debug_file = None
    leak_dir = "leaks"

    i = 4
    while i < len(sys.argv):
        if sys.argv[i] == '--debug':
            debug_file = sys.argv[i + 1] if i + 1 < len(sys.argv) else 'debug_output.txt'
            i += 2
        elif sys.argv[i] == '--leak-dir':
            leak_dir = sys.argv[i + 1] if i + 1 < len(sys.argv) else 'leaks'
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
    print(f"    Tracked {len(call_mappings)} call sites")
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
    print(f"    Leak files directory: {leak_dir}/")

    leak_files = generate_report(violations, call_mappings, binary_path, output_file, debug_file, addr_offset, leak_dir)

    print()
    print("=" * 80)
    print("ANALYSIS COMPLETE")
    print("=" * 80)
    print(f"Report written to: {output_file}")
    if debug_file:
        print(f"Debug output written to: {debug_file}")
    if leak_files:
        print(f"\nGenerated {len(leak_files)} leak files in '{leak_dir}/':")
        for leak_file in leak_files[:10]:  # Show first 10
            print(f"  • {os.path.basename(leak_file)}")
        if len(leak_files) > 10:
            print(f"  ... and {len(leak_files) - 10} more")
    print()

    print("SUMMARY:")
    print(f"  Violations analyzed: {len(violations)}")
    print(f"  Call sites tracked:  {len(call_mappings)}")
    print()


if __name__ == "__main__":
    main()
