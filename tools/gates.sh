#!/bin/bash
# The Godot gates on the guest ELFs in project/, under the pinned double-precision editor and the
# godot-sandbox addon from service-godot-build, each file checked against its pinned sha256.
#
#   bash tools/gates.sh [ca|quic|zone ...]      (default: all three)
#
# GODOT=<editor> skips the download and uses that editor; it must be a double build. Each gate runs
# once as it is, which must print RESULT: PASS, and once per planted control (--control=<name>),
# which must exit non-zero with the named check's FAIL line. The gates' own controls run inside
# every pass.
set -euo pipefail
cd "$(dirname "$0")/.."
root=$PWD
work=${WORK:-$root/build/gates}
mkdir -p "$work"

base=https://github.com/V-Sekai-fire/service-godot-build/releases/download
engine_tag=v20260930-double.1
addon_tag=v20261019-addon.1
case "$(uname -s)-$(uname -m)" in
  Linux-x86_64)
    engine=godot.linuxbsd.editor.double.x86_64
    engine_sha=37c6962fcc76d1773a596440f310f52ad5cf18011e74a712a5b465c3240e919b
    addon=libgodot_riscv.linux.template_release.double.x86_64.so
    addon_sha=8ab42de8462452e22bc091af0aedf2446934d8ee691adcd1bbccb9818642aed6 ;;
  Darwin-*)
    engine=godot.macos.editor.double.arm64
    engine_sha=5f6f2df33708d8f522e0cb5f40af58bd44c1eccb2dda7128081f4056b1de8dce
    addon=libgodot_riscv.macos.template_release.double.universal
    addon_sha=14f542887f322bbe9847fa0f24734a46d68458db366f139118b45fc8eb7479f0 ;;
  *) echo "FAIL no pinned double editor for $(uname -s)-$(uname -m)"; exit 1 ;;
esac

# A wall clock per Godot run; macOS has no timeout(1) unless coreutils is installed.
wall=$(command -v timeout || command -v gtimeout || true)
wall=${wall:+$wall 300}
sum256() { if command -v sha256sum >/dev/null; then sha256sum "$1"; else shasum -a 256 "$1"; fi | cut -d' ' -f1; }
fetch() { # url path sha
  if [ ! -f "$2" ] || [ "$(sum256 "$2")" != "$3" ]; then
    curl -fsSL --retry 3 -o "$2.part" "$1"
    got=$(sum256 "$2.part")
    [ "$got" = "$3" ] || { echo "FAIL $(basename "$2"): sha256 $got, pinned $3"; exit 1; }
    mv "$2.part" "$2"
  fi
  echo "$(basename "$2"): sha256 $3"
}

if [ -z "${GODOT:-}" ]; then
  fetch "$base/$engine_tag/$engine" "$work/$engine" "$engine_sha"
  chmod +x "$work/$engine"
  GODOT=$work/$engine
fi
"$GODOT" --headless --version | tee "$work/version.txt"
grep -q '\.double\.' "$work/version.txt" || { echo "FAIL $GODOT is not a double build"; exit 1; }

bin=project/addons/godot_sandbox/bin
mkdir -p "$bin" project/.godot
fetch "$base/$addon_tag/$addon" "$work/$addon" "$addon_sha"
cp "$work/$addon" "$bin/$addon"
cat > "$bin/godot-riscv.gdextension" <<'EOF'
[configuration]

entry_symbol = "riscv_library_init"
compatibility_minimum = "4.4"

[libraries]

linux.debug.double.x86_64 = "./libgodot_riscv.linux.template_release.double.x86_64.so"
linux.release.double.x86_64 = "./libgodot_riscv.linux.template_release.double.x86_64.so"
macos.debug.double = "./libgodot_riscv.macos.template_release.double.universal"
macos.release.double = "./libgodot_riscv.macos.template_release.double.universal"
EOF
echo "res://addons/godot_sandbox/bin/godot-riscv.gdextension" > project/.godot/extension_list.cfg

for elf in ca quic_peer zone asset; do
  [ -f "project/$elf.elf" ] || { echo "FAIL no project/$elf.elf: build the guests first (README.md)"; exit 1; }
done
# The ELFs are resources: an import pass registers them before a gate loads one.
$wall "$GODOT" --headless --path project --import > "$work/import.txt" 2>&1 || true

failed=0
run() { # gate log [args...]
  local gate=$1 log=$2; shift 2
  $wall "$GODOT" --headless --path project --script "tests/${gate}_gate.gd" -- "$@" > "$log" 2>&1
}

# Each gate's planted control, and the start of the check's line it must FAIL.
control() {
  case $1 in
    ca) echo "starved|ca_open makes the session root" ;;
    quic) echo "foreign_root|the handshake completes" ;;
    zone) echo "drop_handover|the players' zone owns the garment" ;;
  esac
}

[ $# -gt 0 ] || set -- ca quic zone
for g in "$@"; do
  log="$work/$g.txt"
  if run "$g" "$log" && grep -q "^RESULT: PASS" "$log"; then
    grep -E "^(PASS|FAIL) " "$log"; echo "PASS gate $g"
  else
    cat "$log"; echo "FAIL gate $g"; failed=$((failed + 1))
  fi
  pair=$(control "$g"); c=${pair%%|*}; want=${pair#*|}
  log="$work/$g-$c.txt"
  if run "$g" "$log" "--control=$c"; then
    cat "$log"; echo "FAIL control $g --control=$c: the gate passed"; failed=$((failed + 1))
  elif ! grep -q "^FAIL $want" "$log"; then
    cat "$log"; echo "FAIL control $g --control=$c: no 'FAIL $want' line"; failed=$((failed + 1))
  else
    grep "^FAIL " "$log"; echo "PASS control $g --control=$c fails as planted"
  fi
done
echo "RESULT: $([ $failed = 0 ] && echo PASS || echo "FAIL ($failed)")"
[ $failed = 0 ]
