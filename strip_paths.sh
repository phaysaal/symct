#!/bin/bash
# Replace debug info paths in library .a files with dots (same length).
# Longer patterns must be replaced first to avoid partial matches.

ROOT="${1:-.}"
BENCHMARK_DIR="$ROOT/benchmark"

if [ ! -d "$BENCHMARK_DIR" ]; then
    echo "Error: $BENCHMARK_DIR not found" >&2
    exit 1
fi

# Patterns to replace (longer first), each replaced with dots of same length
PATTERNS=(
    "/home/faisal/code/lsl/ct-bignum/"
    "/home/faisal/code/lsl/"
)

count=0
for lib in $(find "$BENCHMARK_DIR" -name '*.a' -type f); do
    modified=false
    for pat in "${PATTERNS[@]}"; do
        dots=$(printf '%*s' ${#pat} '' | tr ' ' '.')
        if strings "$lib" | grep -qF "$pat"; then
            perl -pi -e "s|\Q${pat}\E|${dots}|g" "$lib"
            modified=true
        fi
    done
    if $modified; then
        echo "patched: $lib"
        count=$((count + 1))
    fi
done

echo "Patched $count files"
