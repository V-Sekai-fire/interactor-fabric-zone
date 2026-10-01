-- SPDX-FileCopyrightText: 2026 K. S. Ernest (iFire) Lee
-- SPDX-License-Identifier: MIT
/-!
# The CA's C API, through tests/ffi/shim.cpp

Handles cross as `USize`, times as seconds since the epoch in a `UInt64` (two's complement for the
C side's `int64_t`), PEM text as `String`. A PEM-returning call gives `ERR <code>` on failure.
-/

namespace FabricZoneTests.Ffi

@[extern "fzl_probe"] opaque probe : IO UInt32
@[extern "fzl_crypto_init"] opaque cryptoInit : IO UInt32
@[extern "fzl_force_host"] opaque forceHost : UInt8 → IO Unit
@[extern "fzl_feed"] opaque feed : @& ByteArray → IO UInt32
@[extern "fzl_name_allowed"] opaque nameAllowed : @& String → UInt8
@[extern "fzl_ca_new"] opaque caNew : UInt64 → UInt64 → IO USize
@[extern "fzl_ca_new_seeded"] opaque caNewSeeded : @& ByteArray → UInt64 → UInt64 → IO USize
@[extern "fzl_ca_root"] opaque caRoot : USize → IO String
@[extern "fzl_ca_root_public_hex"] opaque caRootPublicHex : USize → IO String
@[extern "fzl_ca_export"] opaque caExport : USize → IO UInt32
@[extern "fzl_ca_issue"] opaque caIssue : USize → @& String → @& String → UInt64 → UInt64 → IO String
@[extern "fzl_key_new"] opaque keyNew : IO USize
@[extern "fzl_key_csr"] opaque keyCsr : USize → @& String → IO String
@[extern "fzl_key_pem"] opaque keyPem : USize → IO String
@[extern "fzl_verify"] opaque verify : @& String → @& String → @& String → UInt64 → IO UInt32
@[extern "fzl_quic_handshake"] opaque quicHandshake :
  @& String → @& String → @& String → @& String → @& String → @& String → @& String → UInt8 → IO UInt32

end FabricZoneTests.Ffi
