# SCT -- Side-Channel Testing Framework

A framework for automated constant-time analysis of cryptographic library implementations using symbolic execution (BINSEC) and SMT solving (Bitwuzla/Z3).

## Tested Libraries

| Library | Optimization Levels |
|---------|-------------------|
| OpenSSL | O0, O2, O3 |
| BearSSL | O0 |
| WolfSSL | O0, O2 |
| MbedTLS | O0 |

## Tested Algorithms

`rsa_decrypt`, `rsa_sign`, `rsa_keygen`, `ecdsa_sign`, `ecdsa_keygen`, `eddsa_sign`, `eddsa_keygen`

## Project Structure

```
benchmark/
  common/             Shared inputs (keys, templates)
  32/<library>/        Per-library benchmarks
    lib/               Pre-compiled static libraries and headers
    common.h           Library-specific common header
    <algorithm>/
      src/             Makefile and wrapper.c
      bin/             Built executables, core dumps, gs.ini

binsec/
  32/                  BINSEC configuration files (.ini)
    <library>/         Library-specific stubs and hooks
      random/          Randomization mode configs
      progressive/     Progressive analysis steps

plugin/                OCaml BINSEC plugin (bignum modeling)

runbench.py            Main test driver
callstack2source.py    Maps binary addresses to source locations
merge_reports.py       Deduplicates violation reports across runs
keylen.json            Key length configuration per library/algorithm
```

## Quick Start (Docker)

### Installing Docker (Native)

Use native Docker Engine, not Docker Desktop. Docker Desktop runs a VM with limited memory, which is problematic for SMT solvers.

On Ubuntu/Debian:

```
sudo apt-get update
sudo apt-get install ca-certificates curl
sudo install -m 0755 -d /etc/apt/keyrings
sudo curl -fsSL https://download.docker.com/linux/ubuntu/gpg -o /etc/apt/keyrings/docker.asc
sudo chmod a+r /etc/apt/keyrings/docker.asc

echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.asc] \
  https://download.docker.com/linux/ubuntu $(. /etc/os-release && echo "$VERSION_CODENAME") stable" | \
  sudo tee /etc/apt/sources.list.d/docker.list > /dev/null

sudo apt-get update
sudo apt-get install docker-ce docker-ce-cli containerd.io docker-buildx-plugin
```

Add your user to the docker group (to avoid `sudo`):

```
sudo usermod -aG docker $USER
newgrp docker
```

If you previously had Docker Desktop, remove its credential helper:

```
# In ~/.docker/config.json, delete the line:
#   "credsStore": "desktop",
```

### Building and Running

```
docker build -f artifact/Dockerfile -t sct-artifact .
docker run -it sct-artifact
```

Inside the container:

```
cd /home/artifact/sct
python3 runbench.py openssl rsa_decrypt rsa_openssl --optimization O0 --bn
```

## Manual Setup

### Prerequisites

- GCC with 32-bit support (`gcc-multilib`)
- GDB
- Python 3
- BINSEC 0.10.1 (OCaml/opam)
- Bitwuzla (SMT solver)
- Z3 (optional, alternative solver)

### Plugin Install

```
cd plugin
dune build @install
dune install
```

## Running an Analysis

```
python3 runbench.py <library> <algorithm> <nature> [options]
```

### Positional Arguments

| Argument | Description |
|----------|-------------|
| `library` | `openssl`, `bearssl`, `wolfssl`, `mbedtls` |
| `algorithm` | e.g. `rsa_decrypt`, `ecdsa_sign`, `eddsa_keygen` |
| `nature` | Test config name, e.g. `rsa_openssl`, `ecdsa_bearssl_nd`, `dry` |

### Options

| Option | Default | Description |
|--------|---------|-------------|
| `--optimization` | (none) | Optimization level: `O0`, `O2`, `O3` |
| `--bn` | off | Enable bignum modeling plugin |
| `--progressive <dir>` | (none) | Progressive analysis with stub folders |
| `--only <step>` | (none) | Run only up to a specific progressive step |
| `--random <mode>` | `rand` | Randomization: `rand` or `const` |
| `--platform` | `32` | Target platform: `32`, `64`, `arm64` |
| `--keylen` | 2048 | Key length in bits |
| `--timeout` | 1800 | Analysis timeout in seconds |
| `--memlimit` | 16384 | Memory limit in MB (0 = unlimited) |
| `--build` | off | Force rebuild before analysis |
| `--report <dir>` | (none) | Generate callstack2source reports |
| `--batch-file <file>` | (none) | Run multiple natures from a file |
| `--tag` | (none) | Tag suffix for log filenames |
| `--no-details` | off | Disable debug output |
| `--auto` | off | Auto mode: iterative stub discovery (see below) |

### Auto Mode (`--auto`)

Auto mode iteratively discovers which bignum (BN) functions need to be replaced with symbolic stubs so that the analysis can proceed past computationally expensive arithmetic. It runs the analysis, inspects the resulting trace, selects appropriate stub files, and repeats until no new stubs are found.

```
python3 runbench.py openssl rsa_decrypt rsa_openssl --optimization O0 --auto
```

#### Algorithm

```
accumulated_stubs = {}

for iteration = 0, 1, 2, ...:

    ┌─────────────────────────────────────────────────────┐
    │ 1. RUN BINSEC                                       │
    │                                                     │
    │    iteration 0: run WITHOUT --bn and without stubs  │
    │    iteration N: run WITH --bn and accumulated_stubs │
    └─────────────────────────────────────────────────────┘
                              │
                              ▼
    ┌─────────────────────────────────────────────────────┐
    │ 2. PARSE LOG                                        │
    │                                                     │
    │  From [sse:debug] lines, extract:                   │
    │    a. func_line_counts — how many trace lines each  │
    │       function consumed                             │
    │    b. addr_to_func — map instruction addresses to   │
    │       function names                                │
    │    c. call_graph — inferred caller→callee edges     │
    │       from function transition pairs (A→B then B→A  │
    │       = call/return; direction determined by which   │
    │       transition was seen first in the trace)       │
    │                                                     │
    │  From [checkct:result] lines, extract:              │
    │    d. leak_call_chains — for each leak, the full    │
    │       call stack (#0, #1, ...) resolved to function │
    │       names via addr_to_func (deepest first)        │
    └─────────────────────────────────────────────────────┘
                              │
                              ▼
    ┌─────────────────────────────────────────────────────┐
    │ 3. IDENTIFY TARGET BN FUNCTIONS                     │
    │                                                     │
    │  A function is a "target" if EITHER:                │
    │                                                     │
    │    a. It is a BN function that appears anywhere in  │
    │       a leak call chain                             │
    │                                                     │
    │    b. BN functions collectively consume >75% of     │
    │       trace lines (BN dominance) — in this case     │
    │       ALL traced BN functions become targets        │
    └─────────────────────────────────────────────────────┘
                              │
                              ▼
    ┌─────────────────────────────────────────────────────┐
    │ 4. SEARCH FOR STUB FILES                            │
    │                                                     │
    │  Walk binsec/<platform>/<library>/ (excluding       │
    │  random/) for .ini files containing:                │
    │    replace <FUNC_NAME>(...) by ... end              │
    │                                                     │
    │  Filter by keylen: if a stub file contains          │
    │    popBV var<SIZE>                                   │
    │  then SIZE must match the resolved keylen.          │
    │  Files without popBV are accepted for any keylen.   │
    └─────────────────────────────────────────────────────┘
                              │
                              ▼
    ┌─────────────────────────────────────────────────────┐
    │ 5. RESOLVE LEAKS VIA CALL CHAINS                    │
    │                                                     │
    │  For each leak's call chain (deepest → shallowest): │
    │    Walk from #0 upward. Pick the first function     │
    │    that is a BN function AND has a stub file.       │
    │                                                     │
    │  This handles the case where the leaking            │
    │  instruction is inside a low-level function with    │
    │  no stub — its caller (or caller's caller) may      │
    │  have one.                                          │
    └─────────────────────────────────────────────────────┘
                              │
                              ▼
    ┌─────────────────────────────────────────────────────┐
    │ 6. RESOLVE DOMINANT FUNCTIONS VIA CALL GRAPH        │
    │                                                     │
    │  For each BN function consuming >5% of trace lines  │
    │  that has NO stub file:                             │
    │    Walk UP the inferred call graph (callee→caller), │
    │    following the most frequent BN caller at each    │
    │    step, up to 10 levels.                           │
    │    Stop at the first ancestor that has a stub.      │
    │                                                     │
    │  Example: bn_mul_mont (79.6%, no stub)              │
    │    → caller bn_mul_mont_fixed_top (has stub)        │
    │    Stubbing the caller eliminates the callee too.   │
    └─────────────────────────────────────────────────────┘
                              │
                              ▼
    ┌─────────────────────────────────────────────────────┐
    │ 7. ACCUMULATE AND REPEAT                            │
    │                                                     │
    │  new_files = found stub files − accumulated_stubs   │
    │                                                     │
    │  if new_files is empty → STOP (converged)           │
    │  else → add to accumulated_stubs, go to step 1     │
    └─────────────────────────────────────────────────────┘

After convergence:

    ┌─────────────────────────────────────────────────────┐
    │ 8. FINAL RUN                                        │
    │                                                     │
    │  Run once more WITHOUT --bn and without stubs       │
    │  (same configuration as iteration 0), but with      │
    │  timeout = per_timeout × total_iterations.          │
    │                                                     │
    │  This gives the analysis the full accumulated time  │
    │  budget to explore as far as possible without any   │
    │  symbolic modeling, producing a baseline result.    │
    └─────────────────────────────────────────────────────┘
```

#### BN Function Prefixes

| Library | Prefixes |
|---------|----------|
| OpenSSL | `BN_`, `bn_` |
| BearSSL | `br_i31_`, `br_i15_` |
| WolfSSL | `sp_` |
| MbedTLS | `mbedtls_mpi_` |

#### Call Graph Inference

The call graph is built from function transitions in `[sse:debug]` trace lines. When the trace shows function A executing, then function B, then A again, this indicates A called B. For each pair (A, B) where both A→B and B→A transitions exist, the **direction seen first** in the trace determines which is the caller. This is more reliable than a global first-seen heuristic because it correctly handles functions called by multiple callers at different points in the execution.

### Examples

Basic RSA analysis on OpenSSL at O0:

```
python3 runbench.py openssl rsa_decrypt rsa_openssl --optimization O0 --bn
```

ECDSA analysis on WolfSSL with progressive stubs:

```
python3 runbench.py wolfssl ecdsa_sign ecdsa_wolfssl --bn --progressive ecdsa
```

Force rebuild and run with report generation:

```
python3 runbench.py bearssl rsa_sign rsa_bearssl --build --bn --report reports/
```

Batch run with constant randomization:

```
python3 runbench.py openssl rsa_decrypt rsa_openssl --bn --random const --batch-file tests.txt
```

### Build Process

When `--build` is used (or automatically when starting from core):

1. Runs `make clean && make` in `benchmark/<platform>/<library>/<algorithm>/src/`
2. Verifies the executable name matches the expected convention; renames if needed
3. On 32-bit x86: runs GDB to capture `gs_base` and generate a core dump
4. Writes `gs.ini` for BINSEC to use

### Output

Results are written to `results/<platform>/<library>/<algorithm>/`.

## Running All Tests

`runall.py` discovers and runs all available benchmark tests, then prints a pass/fail summary followed by a leak analysis report.

```
python3 runall.py [options]
```

### Options

| Option | Default | Description |
|--------|---------|-------------|
| `--timeout` | 120 | Timeout per test in seconds |
| `--memlimit` | 16384 | Memory limit in MB |
| `--root` | `.` | Project root directory |
| `--library` | (all) | Filter by library (comma-separated or repeated) |
| `--report` | (none) | Directory for `.leaks` reports and per-library merged reports |
| `--dry-run` | off | List tests without running |

### Examples

List all discovered tests:

```
python3 runall.py --dry-run
```

Run only WolfSSL tests with a 2-minute timeout:

```
python3 runall.py --library wolfssl --timeout 120
```

Run OpenSSL and BearSSL tests:

```
python3 runall.py --library openssl,bearssl --timeout 120
```

### Leak Analysis Summary

After all tests complete, `runall.py` parses each test's binsec log file for `[checkct:result]` leak lines and prints an aggregated summary:

```
==============================================================
LEAK ANALYSIS SUMMARY
==============================================================
Primitives checked: 45
  - Completed (reached timeout or finished): 41
  - Build/run failures: 4

Leaks by library:
  openssl     : 12 control flow, 3 memory access  (15 total)
  bearssl     :  0 control flow, 0 memory access   (0 total)
  wolfssl     :  5 control flow, 1 memory access   (6 total)
  mbedtls     :  2 control flow, 0 memory access   (2 total)

Leaks by algorithm:
  rsa_decrypt   : 8 control flow, 2 memory access
  rsa_sign      : 5 control flow, 1 memory access
  ecdsa_sign    : 3 control flow, 0 memory access

Total: 23 leaks across 45 primitives

Merged source-level reports (unique alerts per library):
  openssl     : reports/openssl_merged.leaks
  wolfssl     : reports/wolfssl_merged.leaks

Detailed output files:
  openssl-O0/rsa_decrypt                    log: results/32/openssl-O0/rsa_decrypt/rsa_openssl_0.log
                                             leaks: reports/openssl-O0_rsa_decrypt.leaks  (8 leaks)
  ...
==============================================================
```

### Source-Level Reports (`--report`)

When `--report <dir>` is given, `runall.py` runs `callstack2source.py` on each log that contains leaks to produce individual `.leaks` files, then merges them per library using `merge_reports.py --uniq-source` to deduplicate alerts at the source level:

```
python3 runall.py --library openssl --timeout 120 --report reports/
```

This generates:
- `reports/<library-opt>_<algorithm>.leaks` — per-test source-level violation reports
- `reports/<library>_merged.leaks` — deduplicated unique alerts across all optimization levels and algorithms for each library

## Adding a New Benchmark

1. Under `benchmark/32/<library>/`, create `<algorithm>/src/` and `<algorithm>/bin/` directories.
2. In `src/`, create `wrapper.c` implementing the crypto operation and a `Makefile` with `TARGET` set to the executable name.
3. Place library headers under `<library>/lib/include/` and static libraries (`.a`) under `<library>/lib/`.
4. Create a corresponding `.ini` config under `binsec/32/`.
