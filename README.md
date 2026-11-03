# interactor-fabric-zone

The fabric's zone, session CA, transport and asset store as sandbox guest programs, with Lean tests that link the same C++.

## What it is for

Each piece is C++ built as a riscv64 guest for the engine's sandbox: a session certificate authority whose root key never leaves guest memory, a QUIC peer with mutual TLS and a WebTransport session, one zone of the fabric with its hand-over and crash journal, and a chunked, content-addressed asset store. The host relays packets and the time; keys and plaintext stay in the guest. A Lean package in `tests/` links the same C++ built for the host and checks its properties, each against a control that plants the defect. `tools/offline_ca.exs` keeps an offline root's seed sealed to a key the desk's own operating system holds, and issues certificates from it. RFD66606-2287 and RFD66606-2256 own the design.

## Build and test

The guests build with CMake, the toolchain file from [repository-riscv64-sysroot](https://github.com/V-Sekai-fire/repository-riscv64-sysroot) (its pixi environment has the clang and lld) and the shared [contract-guest-runtime](https://github.com/V-Sekai-fire/contract-guest-runtime). Without `GUEST_RUNTIME_ROOT`, the vendored copy of the sandbox API builds them. Either way the result is rv64gc without V, with a double-precision Variant, stripped with `--strip-debug` only, and installed as `project/*.elf`:

```sh
cmake -S . -B build/guest -G Ninja -DCMAKE_TOOLCHAIN_FILE=<riscv64-sysroot>/toolchain.cmake \
  -DGUEST_RUNTIME_ROOT=<contract-guest-runtime>
cmake --build build/guest
python3 tools/check_elf.py --self-test project/*.elf
```

The Godot gates (`project/tests/*_gate.gd`) run the ELFs headless under the pinned double-precision editor and godot-sandbox addon from service-godot-build. Each gate also runs once with a planted control that must fail. `tools/gates.sh` downloads both, checks their sha256, and runs every gate on Linux x86_64 or macOS. An engine with the sandbox module built in, such as an entities-zone build passed as `GODOT=`, runs the gates with no addon:

```sh
bash tools/gates.sh            # or: bash tools/gates.sh quic
```

CI (`.github/workflows/guests.yml`) does both steps.

The Lean tests build the host copy themselves:

```sh
cd tests && lake build && .lake/build/bin/tests
```

## Licence

MIT; see LICENSE. Vendored code in `thirdparty/` keeps its own licence, listed in `thirdparty/CITATION.cff`.
