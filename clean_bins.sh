#!/bin/bash
# Remove all executables, core dumps, GDB scripts, and gs.ini from benchmark bin/ directories.

ROOT="${1:-.}"
BENCHMARK_DIR="$ROOT/benchmark"

if [ ! -d "$BENCHMARK_DIR" ]; then
    echo "Error: $BENCHMARK_DIR not found" >&2
    exit 1
fi

count=0
for bindir in "$BENCHMARK_DIR"/*/bin "$BENCHMARK_DIR"/*/*/bin "$BENCHMARK_DIR"/*/*/*/bin; do
    [ -d "$bindir" ] || continue
    for f in "$bindir"/*; do
        [ -f "$f" ] || continue
        case "$f" in
            *.core)
                rm -v "$f"
                count=$((count + 1))
                ;;
            *)
                # Remove ELF executables
                if file "$f" 2>/dev/null | grep -q 'ELF'; then
                    rm -v "$f"
                    count=$((count + 1))
                fi
                ;;
        esac
    done
done

echo "Removed $count files"
