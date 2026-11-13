#!/bin/sh
# SPDX-License-Identifier: MIT
# Usage: sh tools/morton_gate.sh [guest.elf ...]; see docs/morton.md.
set -eu
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BIN="${BIN:-$(mktemp -d)}"
CXX="${CXX:-c++}"
OLD='[h]ilbert'
lint() { grep -r -n -i "$OLD" "$1" --include='*.h' --include='*.hpp' --include='*.c' --include='*.cpp' --include='*.gd' --include='*.lean' --include='*.md' --include='*.txt' --include='*.yml' --exclude-dir=.git --exclude-dir=build --exclude-dir=.lake --exclude=morton.md; }
build() { "$CXX" -std=c++17 -O2 -I "$1" -I "$ROOT" -o "$BIN/$2" "$ROOT/tests/morton_vectors.cpp"; }
must_fail() {
  rc=0; "$@" > "$BIN/control.out" 2>&1 || rc=$?
  tail -2 "$BIN/control.out"
  if [ "$rc" != 1 ]; then echo "RESULT: ERROR a control was not caught"; exit 2; fi
}

mkdir -p "$BIN/named/src" "$BIN/h-swapped/thirdparty/misc"
printf 'uint32_t ghost_%s = 0;\n' "hilbert" > "$BIN/named/src/planted.h"
if ! lint "$BIN/named" > /dev/null; then echo "RESULT: ERROR the lint did not find a planted name"; exit 2; fi
if lint "$ROOT"; then echo "RESULT: FAIL a source line names the old curve"; exit 1; fi

cp "$ROOT/thirdparty/misc/r128.h" "$BIN/h-swapped/thirdparty/misc/"
sed 's/(pbvh_part1by2(x) << 2) | (pbvh_part1by2(y) << 1) | pbvh_part1by2(z)/(pbvh_part1by2(z) << 2) | (pbvh_part1by2(y) << 1) | pbvh_part1by2(x)/' "$ROOT/thirdparty/misc/predictive_bvh.h" > "$BIN/h-swapped/thirdparty/misc/predictive_bvh.h"
if cmp -s "$ROOT/thirdparty/misc/predictive_bvh.h" "$BIN/h-swapped/thirdparty/misc/predictive_bvh.h"; then echo "RESULT: ERROR the old axis order was not planted"; exit 2; fi
awk 'BEGIN{FS=OFS="\t"} NR==200{$4=$4+1} {print}' "$ROOT/thirdparty/misc/morton_golden.tsv" > "$BIN/altered.tsv"
build "$ROOT" real
build "$BIN/h-swapped" swapped
must_fail "$BIN/swapped" "$ROOT/thirdparty/misc/morton_golden.tsv"
must_fail "$BIN/real" "$BIN/altered.tsv"
"$BIN/real" "$ROOT/thirdparty/misc/morton_golden.tsv" | head -1

for elf in "$@"; do
  if strings -a "$elf" | grep -i "$OLD"; then echo "RESULT: FAIL $elf names the old curve"; exit 1; fi
  echo "$(basename "$elf"): no symbol or string of the old curve"
done
echo "RESULT: PASS"
