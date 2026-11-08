#!/bin/bash
# The pinned interactor-motion-matching-guest, shallow and sparse: only the named paths of
# MM_GUEST_SHA land in mm-guest/, not the whole repository (its clip data is about 166 MB).
#   MM_GUEST_SHA=<sha> bash tools/fetch_mm.sh <path> [<path> ...]
set -euo pipefail
: "${MM_GUEST_SHA:?set MM_GUEST_SHA to the pinned commit}"
[ $# -gt 0 ] || { echo "usage: fetch_mm.sh <path> [<path> ...]" >&2; exit 2; }
dir=${MM_GUEST_DIR:-mm-guest}
rm -rf "$dir"
git init -q "$dir"
git -C "$dir" remote add origin https://github.com/V-Sekai-fire/interactor-motion-matching-guest
git -C "$dir" sparse-checkout set "$@"
git -C "$dir" fetch -q --depth 1 --filter=blob:none origin "$MM_GUEST_SHA"
git -C "$dir" checkout -q FETCH_HEAD
[ "$(git -C "$dir" rev-parse HEAD)" = "$MM_GUEST_SHA" ] || { echo "FAIL mm-guest is not $MM_GUEST_SHA" >&2; exit 1; }
