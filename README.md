# SCT

## Benchmark

### How to organize/create a benchmark

- Under `benchmark` folder, select <PLATFORM> (32 or 64, so far) folder.
- Under <PLATFORM> folder, select/create <LIBRARY> folder.
- Under <LIBRARY> folder, select/create <ALGORITHM> (or Primitive) folder.
- Under <LIBRARY>, place `common.h` file.
- Under <ALGORITHM> select/create `src` and `bin` folder.
- Under `src` folder, place `wrapper.c` and without changing any function names, implement according to your library, and make an approriate Makefile.
- Under `bin` folder, gs.ini file and <ALGORITHM>_<LIBRARY_PLATFORM>_gdb_script.gdb need to be places.
- Under <LIBRARY>, place `lib` folder.
- Under `lib`, place library binaries and `include` folder.

### Compilations

```
cd benchmark/<PLATFORM>/<LIBRARY>/<ALHORITHM>/src/
make
cd ../bin/
gdb -x <ALGORITHM>_<LIBRARY>_<PLATFORM>_gdb_script.gdb <ALGORITHM>_<LIBRARY>_<PLATFORM>
```



## Binsec Plugin Install

- Install OCaml
- Install dune
- Enter into `plugin` folder.
```
dune build @install
dune install
```


## Testng Tool

### Building

- Download and install rust programming environment (especially cargo) in the standard procedure.
```
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source $HOME/.cargo/env
```
- Inside `driver` folder use --
```
cargo build
cargo build --release
cargo install --path .
```


- Read driver/README.md to see how to run an analysis.