#!/usr/bin/env python3
"""
Merge multiple callstack2source report files and produce a deduplicated
list of unique call stacks.

Address, time, and stack depth are ignored for uniqueness — only the
leak type and the call hierarchy (function names + source locations) matter.
"""

import re
import sys
import os


def parse_report(path):
    """
    Parse a callstack2source report file.
    Yields (leak_type, hierarchy_lines) for each violation block.
    """
    with open(path, 'r') as f:
        lines = f.readlines()

    i = 0
    while i < len(lines):
        line = lines[i].rstrip('\n')

        # Detect start of a violation block
        if re.match(r'^VIOLATION #\d+', line):
            leak_type = None
            hierarchy = []
            in_hierarchy = False
            i += 1  # skip the dash line after "VIOLATION #N"

            # Read the block until the next violation or section separator
            while i < len(lines):
                line = lines[i].rstrip('\n')

                # Next violation or end-of-section
                if re.match(r'^VIOLATION #\d+', line):
                    break
                if line.startswith('=' * 40):
                    break

                # Extract leak type
                m = re.match(r'^Leak Type:\s+(.+)$', line)
                if m:
                    leak_type = m.group(1).strip()

                # Detect hierarchy section
                if line.startswith('CALL HIERARCHY:'):
                    in_hierarchy = True
                    i += 1  # skip the dash line
                    i += 1
                    continue

                if in_hierarchy:
                    # Stop hierarchy at blank-line followed by a dash separator
                    # or at "(No call stack captured)"
                    if line == '' or line.startswith('-' * 40):
                        # Could be trailing blank inside the tree — peek ahead
                        if line == '':
                            # Check if the next non-blank line is still tree or new section
                            j = i + 1
                            while j < len(lines) and lines[j].strip() == '':
                                j += 1
                            if j < len(lines):
                                next_line = lines[j].rstrip('\n')
                                if (re.match(r'^VIOLATION #\d+', next_line)
                                        or next_line.startswith('-' * 40)
                                        or next_line.startswith('=' * 40)):
                                    in_hierarchy = False
                                else:
                                    # Still part of tree (blank line inside tree output)
                                    hierarchy.append(line)
                            else:
                                in_hierarchy = False
                        else:
                            in_hierarchy = False
                    else:
                        hierarchy.append(line)

                i += 1

            if leak_type is not None and hierarchy:
                yield leak_type, hierarchy
            continue

        i += 1


def normalize_hierarchy(hierarchy_lines, uniq_source=False):
    """
    Normalise hierarchy lines for comparison:
    - Strip runtime addresses from violation marker lines
      e.g. "[0x5658c4d8] func (file:line) <-- control flow leak"
      becomes "func (file:line) <-- leak"
    - Remove hit-count annotations like "[3 hits]"

    If uniq_source is True, additionally:
    - Remove violation marker lines  ([0x...] ... <-- ... leak)
    - Remove tree nodes with unresolved '??' function names
    This makes comparison purely source-level.
    """
    normalised = []
    for line in hierarchy_lines:
        # Strip the [0x...] address prefix from violation marker lines
        line = re.sub(r'\[0x[0-9a-fA-F]+\]\s*', '', line)
        # Strip hit counts
        line = re.sub(r'\s*\[\d+ hits\]', '', line)
        # Strip trailing whitespace
        line = line.rstrip()

        if uniq_source:
            # Strip leak-type annotation but keep the function + source location
            if '<--' in line and 'leak' in line:
                line = re.sub(r'\s*<--.*$', '', line).rstrip()
            # Skip lines whose only function content is '??'
            stripped = re.sub(r'[└─│\s\t]', '', line)
            if stripped == '??' or stripped == '':
                continue

        if line:
            normalised.append(line)
    return tuple(normalised)


def main():
    if len(sys.argv) < 2:
        print("Usage: python merge_reports.py <report1> [report2 ...] [-o output_file] [--uniq-source]")
        print()
        print("Reads callstack2source report files and outputs the unique")
        print("call stacks across all files.")
        print()
        print("Options:")
        print("  -o FILE         Write output to FILE instead of stdout")
        print("  --uniq-source   Compare only source-level call chains, stripping")
        print("                  unresolved '??' nodes, violation marker lines, and")
        print("                  ignoring leak type differences")
        sys.exit(1)

    # Parse arguments
    report_files = []
    output_file = None
    uniq_source = False
    i = 1
    while i < len(sys.argv):
        if sys.argv[i] == '-o' and i + 1 < len(sys.argv):
            output_file = sys.argv[i + 1]
            i += 2
        elif sys.argv[i] == '--uniq-source':
            uniq_source = True
            i += 1
        else:
            report_files.append(sys.argv[i])
            i += 1

    if not report_files:
        print("Error: No report files specified.")
        sys.exit(1)

    # Collect unique call stacks
    seen = set()            # normalised signatures
    unique_entries = []      # (leak_type, raw hierarchy lines)
    total_violations = 0
    files_processed = 0

    for path in report_files:
        if not os.path.exists(path):
            print(f"Warning: '{path}' not found, skipping.")
            continue
        files_processed += 1
        for leak_type, hierarchy in parse_report(path):
            total_violations += 1
            norm = normalize_hierarchy(hierarchy, uniq_source)
            # When --uniq-source, ignore leak type for uniqueness
            sig = (leak_type, norm) # (norm,) if uniq_source else 
            if sig not in seen:
                seen.add(sig)
                unique_entries.append((leak_type, hierarchy))

    # Format output
    out_lines = []
    out_lines.append("=" * 80)
    out_lines.append("UNIQUE CALL STACKS (MERGED)")
    out_lines.append("=" * 80)
    out_lines.append("")
    out_lines.append(f"Report files processed: {files_processed}")
    out_lines.append(f"Total violations read:  {total_violations}")
    out_lines.append(f"Unique call stacks:     {len(unique_entries)}")
    out_lines.append(f"Duplicates removed:     {total_violations - len(unique_entries)}")
    out_lines.append("")

    for idx, (leak_type, hierarchy) in enumerate(unique_entries, 1):
        out_lines.append("-" * 80)
        out_lines.append(f"UNIQUE #{idx}  ({leak_type} leak)")
        out_lines.append("-" * 80)
        for h in hierarchy:
            out_lines.append(h)
        out_lines.append("")

    text = '\n'.join(out_lines) + '\n'

    if output_file:
        with open(output_file, 'w') as f:
            f.write(text)
        print(f"Written {len(unique_entries)} unique call stacks to {output_file}")
    else:
        print(text)

    print(f"\nSummary: {len(unique_entries)} unique / {total_violations} total from {files_processed} file(s)")


if __name__ == "__main__":
    main()
