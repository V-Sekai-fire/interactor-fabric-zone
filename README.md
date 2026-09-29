# interactor-fabric-zone
The fabric's zones, client, CA and casync assets as godot-sandbox guest ELFs, with Lean tests beside them

This repository is part of RFD 2287, the first rung. Every piece is C++ built as a godot-sandbox
guest ELF. Its tests are a Lean package (`tests/`) that links the same C++ built for the host,
through a small FFI shim. Lean is never in the running path.

## The session CA (`ca.elf`)

`ca.elf` makes the session's root key in guest memory. The key has no export permission, so
not even the guest's own code can read it out. The host receives only the public root certificate
and the certificates the CA issues.

- **Names:** the CA issues only names of the form `<label>.zone.fabric.internal`, where the label
  is lowercase letters, digits and inner hyphens.
- **Lifetime:** at most one hour.
- **Proof of the key:** the CSR's own signature must check out.
- **Entropy:** it comes from the guest's `getrandom`. If that fails or returns zeros, it comes
  from bytes the host feeds (`ca_entropy_feed`). With neither, the CA refuses to make a root.

Source: `src/ca/` (the C API in `fz_ca.h`) and `guest/ca/main.cpp`. The mbedTLS configuration is
in `src/mbedtls_config/`: X.509 and the crypto core only, with no files, threads or sockets.

## Build and test

The riscv64 guests, on a desk with the org's riscv64 sysroot, the same one interactor-dress-on
uses:

    cmake -S . -B build/guest -G Ninja -DCMAKE_BUILD_TYPE=Release -DSANDBOX_RISCV_EXT_V=OFF \
      -DCMAKE_TOOLCHAIN_FILE=<riscv64-sysroot>/toolchain.cmake
    cmake --build build/guest        # writes project/ca.elf

The Lean tests build the host copy themselves. CI runs them.

    cd tests && lake build && .lake/build/bin/tests

The gate runs `ca.elf` in a real Sandbox. It needs the godot-sandbox addon in
`project/addons/godot_sandbox`, which isn't tracked here; copy it from interactor-dress-on.

    godot --headless --path project --script tests/ca_gate.gd

Every check comes with a control that plants the defect and must be caught. A control that
passes is a failure.
