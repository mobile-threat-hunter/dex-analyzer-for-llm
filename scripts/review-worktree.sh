#!/usr/bin/env bash
# review-worktree.sh — make an ISOLATED copy of this repo for a reviewer agent,
# on DISK, and reclaim it when the review is done.
#
# Why this exists. Review agents need a private tree (this repo's record has
# several readings retracted because two agents shared one worktree), and the
# obvious `cp -a . /tmp/advNN` is wrong on this box twice over:
#
#   1. /tmp is a **tmpfs** — 62 GB of RAM. Nine finished reviewer copies were
#      found holding **3.8 GB of RAM**, never reclaimed, plus pytest tmp dirs and
#      a duplicate jadx. Total /tmp was 6.8 GB before this script existed.
#   2. `cp -a` of the whole tree drags in `build/` and `.venv` (~440 MB of the
#      ~500 MB), and a reviewer must rebuild anyway: a copied `CMakeCache.txt`
#      still points `CMAKE_HOME_DIRECTORY` at the ORIGINAL, and copied `.venv`
#      shebangs/`.pth` still address it — so `pip install -e .` from the copy
#      REPOINTS the author's venv. Copying them is worse than useless.
#
# Usage:
#   scripts/review-worktree.sh new adv85      -> prints the new tree's path
#   scripts/review-worktree.sh list
#   scripts/review-worktree.sh drop adv85
#   scripts/review-worktree.sh drop-all
set -euo pipefail

ROOT="$(git -C "$(dirname "${BASH_SOURCE[0]}")" rev-parse --show-toplevel)"
BASE="${DEXLLM_REVIEW_BASE:-$HOME/Project/.dexllm-reviews}"

case "${1:-}" in
new)
    name="${2:?usage: $0 new <name>}"
    dst="$BASE/$name"
    [ -e "$dst" ] && { echo "exists: $dst" >&2; exit 1; }
    mkdir -p "$BASE"
    # Excludes are the point, not an optimisation: build/ and .venv/ must be
    # rebuilt in the copy or they silently address the original.
    rsync -a --exclude build/ --exclude .venv/ --exclude test_apk/ \
          --exclude 'target/' --exclude '__pycache__/' --exclude '.git/modules' \
          "$ROOT"/ "$dst"/
    # test_apk is the gitignored corpus: LINK it rather than copy (it is ~2 GB
    # and read-only to a reviewer).
    [ -d "$ROOT/test_apk" ] && ln -s "$ROOT/test_apk" "$dst/test_apk"
    echo "$dst"
    ;;
list)
    [ -d "$BASE" ] || { echo "(none)"; exit 0; }
    du -sh "$BASE"/* 2>/dev/null || echo "(none)"
    ;;
drop)
    name="${2:?usage: $0 drop <name>}"
    rm -rf "${BASE:?}/${name:?}" && echo "dropped $BASE/$name"
    ;;
drop-all)
    rm -rf "${BASE:?}" && echo "dropped $BASE"
    ;;
*)
    sed -n '2,30p' "${BASH_SOURCE[0]}"; exit 1
    ;;
esac
