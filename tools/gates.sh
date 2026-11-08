#!/bin/bash
# The Godot gates on the guest ELFs in project/, under the double-precision editor an entities-zone
# release publishes, which has the sandbox built in, each file checked against the release's SHA256SUMS.
#
#   bash tools/gates.sh [ca|quic|zone ...]      (default: all three)
#   MM_CLIPS=<clip dir>[:<dir>] bash tools/gates.sh mm   (needs project/mm.elf; not in the default)
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

base=https://github.com/V-Sekai-fire/entities-zone/releases/download
engine_tag=${ZONE_TAG:-v0.0.0-20261106225526-d632cdf2be4c}
case "$(uname -s)-$(uname -m)" in
  Linux-x86_64) engine=godot.linuxbsd.editor.double.x86_64 fdb=libfdb_c.so ;;
  Darwin-*) engine=godot.macos.editor.double.arm64 fdb= ;;
  *) echo "FAIL no double editor for $(uname -s)-$(uname -m)"; exit 1 ;;
esac

# A wall clock per Godot run; macOS has no timeout(1) unless coreutils is installed.
wall=$(command -v timeout || command -v gtimeout || true)
wall=${wall:+$wall 300}
sum256() { if command -v sha256sum >/dev/null; then sha256sum "$1"; else shasum -a 256 "$1"; fi | cut -d' ' -f1; }
pinned() { awk -v f="$1" '$2 == f || $2 == "*" f { print $1 }' "$work/SHA256SUMS"; }
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
  curl -fsSL --retry 3 -o "$work/SHA256SUMS" "$base/$engine_tag/SHA256SUMS" \
    || { echo "FAIL entities-zone $engine_tag has no published SHA256SUMS"; exit 1; }
  for f in $engine $fdb; do
    sha=$(pinned "$f"); [ -n "$sha" ] || { echo "FAIL $f is not in $engine_tag's SHA256SUMS"; exit 1; }
    fetch "$base/$engine_tag/$f" "$work/$f" "$sha"
  done
  chmod +x "$work/$engine"
  export LD_LIBRARY_PATH="$work${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"
  GODOT=$work/$engine
fi
"$GODOT" --headless --version | tee "$work/version.txt"
grep -q '\.double\.' "$work/version.txt" || { echo "FAIL $GODOT is not a double build"; exit 1; }

mkdir -p project/.godot
rm -rf project/addons/godot_sandbox project/.godot/extension_list.cfg
probe=$(mktemp -d)
printf 'config_version=5\n' > "$probe/project.godot"
printf 'extends SceneTree\nfunc _init():\n\tprint("SANDBOX_BUILTIN=", ClassDB.class_exists("Sandbox"))\n\tquit()\n' > "$probe/p.gd"
builtin=$($wall "$GODOT" --headless --path "$probe" --script p.gd 2>/dev/null | grep -o 'SANDBOX_BUILTIN=[a-z]*' || true)
rm -rf "$probe"
[ "$builtin" = "SANDBOX_BUILTIN=true" ] || { echo "FAIL $GODOT has no Sandbox class built in"; exit 1; }

need="ca quic_peer zone asset"
case " $* " in *" mm "*) need="zone mm"; [ -n "${MM_CLIPS:-}" ] || { echo "FAIL the mm gate needs MM_CLIPS=<clip dir>[:<dir>]"; exit 1; } ;; esac
for elf in $need; do
  [ -f "project/$elf.elf" ] || { echo "FAIL no project/$elf.elf: build the guests first (README.md)"; exit 1; }
done
# The ELFs are resources: an import pass registers them before a gate loads one.
$wall "$GODOT" --headless --path project --import > "$work/import.txt" 2>&1 || true

failed=0
run() { # gate log [args...]
  local gate=$1 log=$2; shift 2
  local script="tests/${gate}_gate.gd" extra=
  [ "$gate" = mm ] && { script=tests/mm_gate.gd; extra="--clips=$MM_CLIPS"; }
  $wall "$GODOT" --headless --path project --script "$script" -- $extra "$@" > "$log" 2>&1
}

# Each gate's planted control, and the start of the check's line it must FAIL.
control() {
  case $1 in
    ca) echo "starved|ca_open makes the session root" ;;
    quic) echo "foreign_root|the handshake completes" ;;
    zone) echo "drop_handover|the players' zone owns the garment" ;;
    mm) echo "zero_velocity|mm.elf's later positions stay inside" ;;
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
