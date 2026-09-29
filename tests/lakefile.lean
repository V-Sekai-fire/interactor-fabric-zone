-- SPDX-FileCopyrightText: 2026 K. S. Ernest (iFire) Lee
-- SPDX-License-Identifier: MIT
import Lake
open Lake DSL System

package FabricZoneTests where
  leanOptions := #[⟨`autoImplicit, false⟩]

require «plausible-witness-dag» from git
  "https://github.com/fire/plausible-witness-dag" @ "160b94c9c6eed3bb9ebffce919fc6f989dcafba8"

-- The repository's own CMake build of the CA for the host (FZ_NATIVE): the same sources the
-- guests compile, so the tests exercise the code ca.elf runs.
def nativeDir : FilePath := __dir__ / ".." / "build" / "native"

extern_lib fabriczone_ffi pkg := do
  let root := pkg.dir / ".."
  proc { cmd := "cmake", args := #["-S", root.toString, "-B", nativeDir.toString, "-G", "Ninja",
    "-DFZ_NATIVE=ON", "-DCMAKE_BUILD_TYPE=Release", "-DCMAKE_C_COMPILER=clang",
    "-DCMAKE_CXX_COMPILER=clang++"] }
  proc { cmd := "cmake", args := #["--build", nativeDir.toString] }
  let includes := #["-I", (← getLeanIncludeDir).toString, "-I", (root / "src" / "ca").toString,
    "-I", (root / "src" / "transport").toString]
  let shim ← buildO (pkg.buildDir / "ffi" / "shim.o") (← inputTextFile (pkg.dir / "ffi" / "shim.cpp"))
    includes #["-std=c++17", "-O2", "-fPIC"] "c++"
  buildStaticLib (pkg.staticLibDir / nameToStaticLib "fabriczone_ffi") #[shim]

lean_lib FabricZoneTests

@[default_target]
lean_exe tests where
  root := `Main
  moreLinkArgs := #[(nativeDir / "libfz_quic.a").toString, (nativeDir / "libfz_picoquic.a").toString,
    (nativeDir / "libfz_ca.a").toString, (nativeDir / "libfz_mbedtls.a").toString, "-lpthread", "-lm"]
