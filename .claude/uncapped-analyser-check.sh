#!/usr/bin/env bash
# PreToolUse(Bash) gate — runs before every Bash tool call.
#
# Purpose: never run a THIRD-PARTY analyser without a memory ceiling again.
#
# On 2026-09-06 `dex-decompile` (androguard/dex-decompiler, under evaluation)
# reached RSS 119 GB / virt 161 GB on ONE 4.6 MB APK, on a 123 GB machine. It had
# been launched from the VS Code integrated terminal, so it lived in VS Code's
# cgroup SCOPE — and systemd-oomd kills the scope, not the process. VS Code went
# down with it, taking the session and every background task, which is why an
# IDLE task died at the same second. The kernel log names it exactly:
#
#   Out of memory: Killed process 1788679 (dex-decompile)
#     total-vm:161238004kB  anon-rss:119269648kB
#     task_memcg=.../app-gnome-code-13641.scope   global_oom
#   app-gnome-code-13641.scope: A process of this unit has been killed by the
#   OOM killer.
#
# Reproduced under a cap, so the growth is unbounded rather than a spike: the
# default `restructure` mode hits an 8 GB ceiling and is SIGKILLed, while
# `-m simple` completes the same APK in 174 MB. A third-party analyser is
# untrusted input for MEMORY as much as for correctness.
#
# CLAUDE.md states the rule; this makes it a conscious step instead of a thing to
# remember. Fix by wrapping the command:
#
#     scripts/capped.sh 8G <tool> --args
#
# or, when you have a reason to accept the risk (a tiny input, a tool you have
# already bounded), re-run the SAME command prefixed with UNCAPPED=1.
#
# SCOPE — deliberately narrow, so it does not cry wolf:
#   * Only binaries OUTSIDE this repo. Our own build/ artefacts (ctest, the
#     parity suites, the built .so) pass untouched.
#   * A third-party build output (…/target/{release,debug}/…) or a name on the
#     known-heavy list.
#   * Anything already wrapped in capped.sh / systemd-run / ulimit passes.
# It will NOT catch a heavy tool invoked by some name it has never seen. That is
# a real limit, stated rather than papered over: widen KNOWN_HEAVY when one turns
# up, and prefer capped.sh by default for anything you did not build here.
set -u

cmd="$(jq -r '.tool_input.command // empty' 2>/dev/null || true)"
[[ -z "$cmd" ]] && exit 0

# Already bounded, or a deliberate opt-out → allow.
grep -qE 'capped\.sh|systemd-run|ulimit[[:space:]]+-[vm]|UNCAPPED=1' <<<"$cmd" && exit 0

root="${CLAUDE_PROJECT_DIR:-.}"

# Tools known to be memory-unsafe or simply not ours. Add on discovery.
KNOWN_HEAVY='dex-decompile|dex-decompiler|yara-droid|axml-parser'

hit=""
# (a) a third-party Cargo/Bazel-style build output that is NOT under this repo
while read -r tok; do
    [[ -z "$tok" ]] && continue
    case "$tok" in
        "$root"/*) continue ;;                      # our own tree — fine
        */target/release/*|*/target/debug/*) hit="$tok"; break ;;
    esac
done < <(grep -oE '[~/][^[:space:]"'"'"']*/target/(release|debug)/[^[:space:]"'"'"']+' <<<"$cmd" || true)

# (b) a known-heavy tool by name, wherever it came from
[[ -z "$hit" ]] && hit="$(grep -oE "(^|[[:space:]/])($KNOWN_HEAVY)([[:space:]]|$)" <<<"$cmd" \
                          | head -1 | tr -d ' ' || true)"

[[ -z "$hit" ]] && exit 0

{
    echo "🧠 Uncapped-analyser gate — this runs a THIRD-PARTY analyser with no"
    echo "   memory ceiling: ${hit}"
    echo
    echo "   One of these reached RSS 119 GB on a 4.6 MB APK and systemd-oomd"
    echo "   killed VS Code's whole cgroup scope with it — the session and every"
    echo "   background task died together. A third-party tool is untrusted input"
    echo "   for MEMORY as much as for correctness."
    echo
    echo "   Wrap it:"
    echo "       scripts/capped.sh 8G <tool> --args"
    echo "   (exit 137 then means IT hit the cap, alone, and your editor lives.)"
    echo
    echo "   If you have a reason to accept the risk, re-run the SAME command"
    echo "   prefixed with UNCAPPED=1."
} >&2
exit 2
