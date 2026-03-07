FROM ubuntu:24.04

ARG DEBIAN_FRONTEND=noninteractive

# ============================================================================
# System packages
# ============================================================================

RUN apt-get update && apt-get install -y --no-install-recommends \
    # Build essentials
    build-essential gcc-multilib g++-multilib \
    # Tools
    gdb python3 python3-pip \
    # For opam/ocaml
    opam m4 pkg-config libgmp-dev libmpfr-dev \
    # For bitwuzla build
    git cmake meson ninja-build \
    # Misc
    sudo file curl ca-certificates less xz-utils \
    && rm -rf /var/lib/apt/lists/*

# ============================================================================
# Non-root user
# ============================================================================

RUN useradd -ms /bin/bash artifact && echo "artifact ALL=(ALL) NOPASSWD:ALL" >> /etc/sudoers
USER artifact
WORKDIR /home/artifact

# ============================================================================
# OCaml + opam
# ============================================================================

RUN opam init --disable-sandboxing --auto-setup -y \
    && opam switch create 4.14.1 \
    && eval $(opam env)

ENV PATH="/home/artifact/.opam/4.14.1/bin:${PATH}"
ENV OPAM_SWITCH_PREFIX="/home/artifact/.opam/4.14.1"
ENV CAML_LD_LIBRARY_PATH="/home/artifact/.opam/4.14.1/lib/stublibs:/home/artifact/.opam/4.14.1/lib/ocaml/stublibs:/home/artifact/.opam/4.14.1/lib/ocaml"
ENV OCAML_TOPLEVEL_PATH="/home/artifact/.opam/4.14.1/lib/toplevel"

# ============================================================================
# BINSEC dependencies (from opam) + custom BINSEC build (from tarball)
# ============================================================================

RUN eval $(opam env) && opam install menhir ocamlgraph zarith dune-site grain_dypgen toml fmt conf-gcc conf-g++ -y

COPY --chown=artifact:artifact artifact/binsec.tar.xz /tmp/binsec.tar.xz
RUN mkdir -p /home/artifact/binsec \
    && cd /home/artifact/binsec \
    && tar xf /tmp/binsec.tar.xz \
    && eval $(opam env) \
    && dune build @install \
    && dune install \
    && rm /tmp/binsec.tar.xz

# ============================================================================
# Bitwuzla (build from source for smtlib CLI)
# ============================================================================

RUN pip3 install --break-system-packages meson \
    && git clone --depth 1 https://github.com/bitwuzla/bitwuzla.git /home/artifact/bitwuzla \
    && cd /home/artifact/bitwuzla \
    && meson setup build --prefix=/home/artifact/.local \
    && cd build && ninja && ninja install \
    && rm -rf /home/artifact/bitwuzla

ENV PATH="/home/artifact/.local/bin:${PATH}"

# ============================================================================
# Z3 (from apt)
# ============================================================================

USER root
RUN apt-get update && apt-get install -y --no-install-recommends z3 && rm -rf /var/lib/apt/lists/*
USER artifact

# ============================================================================
# Copy project (selective - see .dockerignore)
# ============================================================================

WORKDIR /home/artifact/sct

# Python scripts and config
COPY --chown=artifact:artifact runbench.py callstack2source.py merge_reports.py keylen.json runall.py clean_bins.sh strip_paths.sh ./

# OCaml plugin source
COPY --chown=artifact:artifact plugin/ plugin/

# Binsec ini configs (32-bit)
COPY --chown=artifact:artifact binsec/32/ binsec/32/

# Benchmark: common inputs and main_template, and
COPY --chown=artifact:artifact benchmark/32/ benchmark/32/

# Benchmark: 32-bit libraries (static libs, headers, source code)
COPY --chown=artifact:artifact benchmark/common/ benchmark/common/

# ============================================================================
# Build OCaml plugin
# ============================================================================

RUN cd plugin && eval $(opam env) && dune build @install && dune install

# ============================================================================
# Default
# ============================================================================

CMD ["/bin/bash"]
