#!/usr/bin/env bash
# capped.sh — run an EXTERNAL tool inside its own memory-capped systemd scope.
#
# Why. On 2026-09-06 `dex-decompile` (androguard/dex-decompiler, under
# evaluation) reached **RSS 119 GB / virt 161 GB** on one APK -- essentially all
# of a 123 GB machine. It had been launched from the VS Code integrated
# terminal, so it lived in `app-gnome-code-<pid>.scope`, and systemd-oomd kills
# the whole **cgroup scope**, not the one process: VS Code went down with it,
# taking the session and every background task. The kernel log is unambiguous
# (`task=dex-decompile ... task_memcg=.../app-gnome-code-13641.scope`).
#
# A third-party analyser is untrusted input for MEMORY as much as for anything
# else. Give it its own scope with a hard ceiling so a runaway dies alone.
#
#   scripts/capped.sh 8G ./some-tool --args
#   MEM=16G scripts/capped.sh ./some-tool --args      # first arg optional
#
# Exit 137 (or the scope reporting oom-kill) means IT hit the cap, not you.
set -euo pipefail

if [[ "${1:-}" =~ ^[0-9]+[MG]$ ]]; then MEM="$1"; shift; else MEM="${MEM:-8G}"; fi
[ $# -gt 0 ] || { sed -n '2,20p' "${BASH_SOURCE[0]}"; exit 1; }

if ! command -v systemd-run >/dev/null; then
    # Fallback: address-space rlimit. Weaker (virtual, not RSS) but better than
    # nothing, and it still fails the allocation instead of the machine.
    unit=1024; [ "${MEM: -1}" = G ] && unit=1048576
    kb=$(( ${MEM%[MG]} * unit ))
    exec bash -c 'ulimit -v "$1"; shift; exec "$@"' _ "$kb" "$@"
fi

exec systemd-run --user --scope --quiet --collect \
    -p MemoryMax="$MEM" -p MemorySwapMax=0 \
    --unit "capped-$$-$(date +%s)" -- "$@"
