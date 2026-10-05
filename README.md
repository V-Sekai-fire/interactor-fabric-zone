# interactor-fabric-zone

The fabric's zone, session CA, transport and asset store as sandbox guest programs, with Lean tests that link the same C++.

## What it is for

Each piece is C++ built as a riscv64 guest for the engine's sandbox: a session certificate authority whose root key never leaves guest memory, a QUIC peer with mutual TLS and a WebTransport session, one zone of the fabric with its hand-over and crash journal, and a chunked, content-addressed asset store. The host relays packets and the time; keys and plaintext stay in the guest. A Lean package in `tests/` links the same C++ built for the host and checks its properties, each against a control that plants the defect. `tools/offline_ca.exs` keeps an offline root's seed sealed to a key the desk's own operating system holds, and issues certificates from it. RFD 2287 and RFD 2256 own the design.

## Build and test

The guests build with CMake and the org's riscv64 toolchain file:

```sh
cmake -S . -B build/guest -G Ninja -DCMAKE_TOOLCHAIN_FILE=<riscv64-sysroot>/toolchain.cmake
cmake --build build/guest
```

The Lean tests build the host copy themselves:

```sh
cd tests && lake build && .lake/build/bin/tests
```

## Licence

MIT; see LICENSE. Vendored code in `thirdparty/` keeps its own licence, listed in `thirdparty/CITATION.cff`.
