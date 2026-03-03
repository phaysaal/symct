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
==============================================================
```

## Adding a New Benchmark

1. Under `benchmark/32/<library>/`, create `<algorithm>/src/` and `<algorithm>/bin/` directories.
2. In `src/`, create `wrapper.c` implementing the crypto operation and a `Makefile` with `TARGET` set to the executable name.
3. Place library headers under `<library>/lib/include/` and static libraries (`.a`) under `<library>/lib/`.
4. Create a corresponding `.ini` config under `binsec/32/`.
