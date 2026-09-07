#!/usr/bin/env bash
# PreToolUse(Bash) gate — runs before every Bash tool call.
#
# Purpose: never run a THIRD-PARTY analyser without a memory ceiling again.
#
# On 2026-09-06 `dex-decompile` (androguard/dex-decompiler, under evaluation)
# reached RSS 119 GB / virt 161 GB on ONE 4.6 MB APK, on a 123 GB machine. It had
# been launched from the VS Code integrated terminal, so it SHARED A CGROUP with
# the editor. The KERNEL's global OOM killer fired -- systemd-oomd never acted --
# and killed only dex-decompile; but VS Code's ptyHost died under the pressure,
# taking the terminal and every process in it, which is why an IDLE task died at
# the same second. Tuning oomd would have been WORSE: it kills a whole CGROUP,
# and the runaway sat in the editor's own scope. The kernel log:
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
# SCOPE — deliberately narrow, because a gate that cries wolf gets bypassed on
# reflex, which is the failure mode this file exists to prevent:
#   * COMMAND POSITION only. Naming a tool is not running it: `cd ~/x/dex-decompiler`,
#     `grep dex-decompile docs/`, `wc -l */dex-decompile*` and a report that merely
#     mentions it all pass. (Learned the hard way -- the first cut matched the name
#     anywhere and fired on a `cd`, then on the patch that was fixing it.)
#   * HEREDOC BODIES ARE STRIPPED before scanning, since a Python/shell heredoc
#     routinely contains these words as data.
#   * Only binaries OUTSIDE this repo. Our own build/ artefacts (ctest, the parity
#     suites, the built .so) pass untouched.
#   * Anything already wrapped in capped.sh / systemd-run / ulimit passes.
#
# KNOWN LIMITS, stated rather than papered over: it cannot catch a heavy tool
# under a name it has never seen (widen KNOWN_HEAVY on discovery, and prefer
# capped.sh by default for anything you did not build here), and it does not
# parse shell -- a sufficiently exotic invocation (eval, a variable holding the
# path) slips through. It is a speed bump on the common case, not a sandbox.
set -u

cmd="$(jq -r '.tool_input.command // empty' 2>/dev/null || true)"
[[ -z "$cmd" ]] && exit 0

# Already bounded, or a deliberate opt-out → allow.
grep -qE 'capped\.sh|systemd-run|ulimit[[:space:]]+-[vm]|UNCAPPED=1' <<<"$cmd" && exit 0

root="${CLAUDE_PROJECT_DIR:-.}"

# Tools known to be memory-unsafe or simply not ours. Add on discovery.
KNOWN_HEAVY='dex-decompile|dex-decompiler|yara-droid|axml-parser'

# --- Strip heredoc bodies. `cmd <<'EOF' … EOF` carries arbitrary text that is
# data, not commands; scanning it produced two false positives in three minutes.
stripped="$(awk '
    BEGIN { skip = 0 }
    skip { if ($0 ~ ("^[[:space:]]*" term "[[:space:]]*$")) skip = 0; next }
    {
        line = $0
        if (match(line, /<<-?[[:space:]]*['"'"'"]?[A-Za-z_][A-Za-z0-9_]*['"'"'"]?/)) {
            t = substr(line, RSTART, RLENGTH)
            gsub(/^<<-?[[:space:]]*/, "", t); gsub(/['"'"'"]/, "", t)
            term = t; skip = 1
        }
        print line
    }
' <<<"$cmd")"

# --- Blank out QUOTED RUNS. A quoted string is data: `grep "dex-decompile" docs/`
# and `pgrep -af "bench.sh|dex-decompile"` are not invocations, and the second one
# also hides a `|` that would otherwise be split as an operator. Cost, stated: a
# tool genuinely invoked as `"dex-decompile" …` slips through -- nobody writes that,
# and this is a speed bump rather than a sandbox.
stripped="$(printf '%s\n' "$stripped" | sed -E -e 's/"[^"]*"/__Q__/g' -e "s/'[^']*'/__Q__/g")"

# --- COMMAND POSITION only: split into segments, drop leading env assignments
# and wrapper words, and look at the word that would actually be EXECUTED.
hit=""
while IFS= read -r seg; do
    [[ -n "$hit" ]] && break
    while [[ "$seg" =~ ^[[:space:]]*([A-Za-z_][A-Za-z0-9_]*=[^[:space:]]*|time|nohup|exec|command|sudo|env|xargs)[[:space:]]+ ]]; do
        seg="${seg#"${BASH_REMATCH[0]}"}"
    done
    read -r word _ <<<"$seg" || true
    [[ -z "$word" ]] && continue
    word="${word%\"}"; word="${word#\"}"; word="${word#\'}"; word="${word%\'}"
    case "$word" in
        "$root"/*)  : ;;                                  # our own tree — fine
        */target/release/*|*/target/debug/*) hit="$word" ;;
    esac
    if [[ -z "$hit" && "${word##*/}" =~ ^($KNOWN_HEAVY)$ ]]; then hit="$word"; fi
done < <(printf '%s\n' "$stripped" | sed -E 's/(\|\||&&|\||;)/\n/g')

[[ -z "$hit" ]] && exit 0

{
    echo "🧠 Uncapped-analyser gate — this runs a THIRD-PARTY analyser with no"
    echo "   memory ceiling: ${hit}"
    echo
    echo "   One of these reached RSS 119 GB on a 4.6 MB APK. It shared a cgroup"
    echo "   with the editor, whose ptyHost then died under the pressure and took"
    echo "   the terminal and every task in it. A third-party tool is untrusted"
    echo "   input for MEMORY as much as for correctness."
    echo
    echo "   Wrap it:"
    echo "       scripts/capped.sh 8G <tool> --args"
    echo "   (exit 137 then means IT hit the cap, alone, and your editor lives.)"
    echo
    echo "   If you have a reason to accept the risk, re-run the SAME command"
    echo "   prefixed with UNCAPPED=1."
} >&2
exit 2
