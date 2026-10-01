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

## The offline root (`fz_ca_new_seeded`)

The same 32-byte seed always gives the same root key, by RFC 9180's DeriveKeyPair for
DHKEM(P-256, HKDF-SHA256). The scalar is imported without export permission. The seed lives in the
operating system's secret store through `contract-keychain`, never in a repository. This root
issues only `<label>.fdb.fabric.internal` names, for FoundationDB peers, under the same one-hour
limit, and the tests check RFC 9180's published P-256 vectors: `ikmE` gives `pkEm`, and `ikmR`
gives `pkRm`.

Certificates carry subject and authority key identifiers. Every offline root has the same subject,
so without them a trust store holding two roots, as in a rotation, makes OpenSSL pick one root for
both and refuse the other's certificates.

On a desk, `tools/offline_ca.exs` keeps the seed under `weftspun.fabric-zone` / `offline-ca-root`
and drives `fz_offline_ca`, which takes the seed on stdin and builds natively on Windows with MinGW.
`init` stores a new seed and refuses if one exists. `issue LABEL DIR` refuses if none exists, so a
deleted seed is never replaced in silence. `fdb-e2e DIR` runs FoundationDB 7.3 on 127.0.0.1:4690
over TLS, trusting only the stored root. Its controls:

- A client signed by another seed's root is refused.
- An expired client is refused.
- A `.zone.fabric.internal` name, an `fdb-*.chibifire.com` name and a lifetime over the hour are not
  issued.

`--control=trust-other-root` makes the server trust the other root too, so that row must fail.
`--self-test` runs RFC 9180's `ikmE` vector through the binary and checks the store's refusals
against `Keychain.Mock`.

## The transport (`quic_peer.elf`)

QUIC with mutual TLS, a WebTransport session over HTTP/3 on the path `/zone`, and datagrams on
that session, all inside the guest. It uses picoquic with h3zero, and picotls on mbedTLS.

- **No sockets, no clock:** the host relays each UDP datagram through `PacketPeerUDP` and passes
  the time in, and never sees plaintext. picoquic's only clock is that host time, through its
  simulated-time pointer.
- **Keys stay in the guest:** each peer makes its key in guest memory and sends only a CSR to
  `ca.elf`.
- **One trust root:** both ends present a certificate from the session CA and accept only its
  root. A certificate from any other CA, a client trusting another root, or the wrong server name
  ends the handshake with a TLS `bad_certificate` alert.

Source: `src/transport/` (the C API in `fz_quic.h`) and `guest/quic_peer/main.cpp`. The build
follows the fabric engine build's `modules/http3`, with two differences:
- `MBEDTLS_PK_HAVE_ECC_KEYS` is defined for picoquic's mbedTLS glue, because mbedTLS 4 dropped
  that macro and without it the glue can't read an EC key.
- The server context clears picoquic's client-only flag, because its certificate comes from
  memory rather than a file.

## The zones (`zone.elf`) and assets (`asset.elf`)

`zone.elf` is one fabric zone, ported from the fabric engine build's `modules/multiplayer_fabric`:

- **The hand-over:** OWNED → STAGING → ACK, with the Jacobson/Karels STAGING timeout (SRTT + 4
  RTTVAR). A worker zone owns the garment while it makes it. Its ghost appears in the players'
  zone, then `zone_handover` moves ownership there.
- **Ghosts:** rows other zones publish on `CH_INTEREST`, which a zone relays to its players.
- **Poses:** the root plus up to 55 humanoid bones, in the engine's humanoid bone order. Both rung
  avatars declare the same 53. A zone takes a player's id from its transport peer, never from the packet.
- **The crash journal:** SQLite's in-memory database. After a tick, `zone_journal_take()` returns
  the database image if it changed, and the host writes it to disk. `zone_journal_open(image)`
  replays it after a restart.

`asset.elf` is casync, ported from `modules/multiplayer_fabric_asset`. It stores a garment as zstd
chunks under a `.caibx` index, and fetches it chunk by chunk from a peer on `CH_ASSET`. The ghost
carries the index's SHA-512/256.

Both guests share one `Transport` interface (`src/transport/transport.h`). The host carries it as
frames: `zone_tick()` returns `[peer i32][channel u32][length u32][bytes]`, where peer -1 means
broadcast, and `zone_packet_in` takes a received packet. Zone `z` is peer `z`, and player `p` is peer
`1000 + p`. The WebTransport session must honour each channel's contract:

| Channel | Delivery | Why |
| --- | --- | --- |
| `CH_MIGRATION` (1) | reliable, ordered stream | a hand-over waits on its intent and its ACK |
| `CH_INTEREST` (2) | datagram, may drop | the next tick's rows replace it |
| `CH_PLAYER` (3) | datagram, may drop | the next pose replaces it |
| `CH_ASSET` (4) | reliable, ordered stream | a chunk reply can run to 256 KiB, and a fetch sends each request once |

**What changed from the engine modules:**
- `SceneTree`'s main loop is `Zone::tick()`, and `MultiplayerPeer` is `Transport`.
- The engine containers are std ones, and `relativistic_zone.h` runs on a small `LocalVector` shim.
- The predictive BVH comes from `core/math/predictive_bvh_adapter.h`, as plain C++ (`src/zone/pbvh_adapter.h`).

**Not ported:**
- the benchmark scenarios;
- drain to zone 0, and the snapshot `Resource`;
- the interest band's culling (a zone relays every neighbour row to its players);
- `CMD_INSTANCE_ASSET`;
- the asset module's uro HTTP, ACL and key calls.

A hand-over is single-owner while the ACK arrives inside the STAGING timeout. An ACK delayed past it
rolls the source back while the target already owns the entity, as in the engine module.

**Two bugs in the engine modules, fixed here:**
- `upload_asset` wrote each chunk's *start* offset into the `.caibx` table, where casync (and
  `parse_caibx`) read the *end*. The first start is 0, which is also the terminator, so an uploaded
  asset parsed as empty.
- An empty journal snapshot bound its slot data as SQL NULL, which the `NOT NULL` column refused. The
  prune after it still dropped the covered mutations, so a despawned entity came back on replay.

Each has a Lean property whose control plants the original behaviour.

Source: `src/zone/`, `src/casync/`, `src/transport/{transport,loopback,frame_transport}`,
`guest/zone/` and `guest/asset/`. zstd, SQLite and r128 are in `thirdparty/`, listed in
`thirdparty/CITATION.cff`.

## Build and test

The riscv64 guests, on a desk with the org's riscv64 sysroot, the same one interactor-dress-on
uses:

    cmake -S . -B build/guest -G Ninja -DCMAKE_BUILD_TYPE=Release -DSANDBOX_RISCV_EXT_V=OFF \
      -DCMAKE_TOOLCHAIN_FILE=<riscv64-sysroot>/toolchain.cmake
    cmake --build build/guest        # writes project/ca.elf, quic_peer.elf, zone.elf and asset.elf

The Lean tests build the host copy themselves, and link with the system compiler, crt and libraries
(on Ubuntu 24.04: `libc++-18-dev libc++abi-18-dev libgmp-dev libuv1-dev`). CI runs them.

    cd tests && LEAN_CC=cc LIBRARY_PATH=/usr/lib/llvm-18/lib lake build && .lake/build/bin/tests

The zone and asset properties search seeds 0 to 199, so a defect has to touch more than about 1.5%
of seeds to be seen. The single-owner property means at most one zone owns the entity, and one
always holds it, on a network that drops datagrams and delays every packet 1 to 4 ticks. It never
delays an ACK past the STAGING timeout.

The gate runs `ca.elf` in a real Sandbox. It needs the godot-sandbox addon in
`project/addons/godot_sandbox`, which isn't tracked here; copy it from interactor-dress-on.

    godot --headless --path project --script tests/ca_gate.gd
    godot --headless --path project --script tests/quic_gate.gd
    godot --headless --path project --script tests/zone_gate.gd

All four guests are built with single-precision `real_t`, like the stock addon they are tested on. The
engine for RFD 2287 is built with `precision=double`, and a guest's `Variant` is 24 bytes in a
single-precision build and 40 in a double one. So once the double-precision addon exists, rebuild all
four with `-DDOUBLE_PRECISION=ON` and rerun the three gates against it.

Every check comes with a control that plants the defect and must be caught. A control that
passes is a failure.
