#!/usr/bin/env bash
# PreToolUse(Bash) gate — runs before every Bash tool call.
#
# Purpose: after any FIX (a change to production source), force an ADVERSARIAL
# CODE REVIEW before the commit/push lands. A decompiler type/dataflow change can
# be subtly wrong in a way tests don't catch; the project's practice is to spawn
# independent reviewer agents on the diff, triage their findings, fix the real
# ones, and re-verify (a/b before-after + parity + 0-crash sweep) BEFORE
# committing. This gate makes that a mandatory, conscious step at publish time.
#
# What "adversarial review" means here (do ALL of it, then commit):
#   0. HACK SELF-CHECK (root-cause, not output masking). Before reviewing, ask:
#      does this fix address the ROOT of the defect, or does it mask a symptom at
#      the output/late layer? A change that suppresses/rewrites Writer or dast
#      OUTPUT to hide a defect whose true origin is the IR builder / dataflow /
#      control-flow (opcode_ins, instruction, dataflow, graph, control_flow) is a
#      HACK — even when the emitted text looks correct (the AST/other consumers
#      still carry the defect). Precedent: the v0.1.12 void-invoke "fix" masked in
#      Writer::visit_assign, left `this = voidcall` in the AST, and was REWRITTEN
#      at the IR builder (the range invoke handlers). If this is a hack, DO NOT
#      commit — RECONSIDER and redo it at the layer where the defect originates
#      (CLAUDE.md: "structural defects must be fixed at the IR level, not in Writer
#      output"). Only genuine beyond-DAD emit divergences (return-literal, catch-
#      clamp, <clinit> static{}) legitimately live in the Writer; a defect with an
#      earlier structural origin does not.
#   1. Spawn ≥2 INDEPENDENT reviewer agents on the diff — e.g. the Agent tool with
#      compound-engineering:ce-adversarial-reviewer + ce-correctness-reviewer, or
#      invoke the `code-review` skill. Each must try to CONSTRUCT a breaking input,
#      not just pattern-match.
#   2. Triage every finding (CONFIRMED / PLAUSIBLE / REFUTED). Fix the real ones.
#   3. Re-verify: a/b (fix on vs off) shows 0 regression on the relevant axes,
#      parity 28/28, sweep 0-crash. Remove any temporary a/b env-gate.
#   4. THEN re-run the SAME commit/push command prefixed with REVIEWED=1, e.g.:
#          REVIEWED=1 git commit -m "..."
#      (Combine with the docs gate when both apply: DOCS_CHECKED=1 REVIEWED=1 …)
#
# Only gates commits/pushes whose change touches PRODUCTION source (native/**,
# vendor/dexkit_core/Core/**, src/dexllm/**). Docs-only / test-only / config-only
# commits, non-git Bash, and git reads pass through untouched.
set -u

cmd="$(jq -r '.tool_input.command // empty' 2>/dev/null || true)"
[[ -z "$cmd" ]] && exit 0

# Only gate git commit / git push.
grep -qE 'git[^&|;]*\b(commit|push)\b' <<<"$cmd" || exit 0

# Already reviewed this turn → allow.
grep -qE 'REVIEWED=1|#[[:space:]]*reviewed' <<<"$cmd" && exit 0

root="${CLAUDE_PROJECT_DIR:-.}"
cd "$root" 2>/dev/null || exit 0

# Collect the files this operation would carry. A COMMIT carries only its own
# change (staged + unstaged-tracked, covering `git commit -a`); a PUSH carries
# every commit ahead of upstream. Keeping these separate means a config/docs-only
# commit is not blocked just because earlier (already-reviewed) code commits are
# still unpushed — while a push still re-confirms the whole set.
if grep -qE 'git[^&|;]*\bpush\b' <<<"$cmd"; then
    up="$(git rev-parse --abbrev-ref --symbolic-full-name '@{upstream}' 2>/dev/null || true)"
    changed="$([[ -n "$up" ]] && git diff --name-only "$up"...HEAD 2>/dev/null)"
else
    changed="$( { git diff --cached --name-only 2>/dev/null
                  git diff --name-only 2>/dev/null; } | sort -u )"
fi

# Does the change touch PRODUCTION source (a "fix")? If not, pass through.
grep -qE '^(native/|vendor/dexkit_core/Core/|src/dexllm/).*\.(cpp|cc|h|hpp|py)$' \
    <<<"$changed" || exit 0

{
    echo "🔬 Adversarial-review gate — this commit/push changes production source"
    echo "   (a fix). Before it lands, run an ADVERSARIAL CODE REVIEW and address"
    echo "   the findings:"
    echo "     0. HACK SELF-CHECK (root-cause, not output masking): does this fix"
    echo "        the ROOT of the defect, or mask a symptom in Writer/dast OUTPUT"
    echo "        while the true origin is the IR builder / dataflow / control-flow?"
    echo "        Output-layer suppression that hides an earlier structural defect"
    echo "        (AST still carries it) is a HACK — RECONSIDER and redo it at the"
    echo "        originating layer (cf. v0.1.12 void-invoke: Writer-hack → IR fix)."
    echo "        Only genuine beyond-DAD emit divergences belong in the Writer."
    echo "     1. Spawn ≥2 INDEPENDENT reviewers on the diff (Agent tool:"
    echo "        compound-engineering:ce-adversarial-reviewer +"
    echo "        ce-correctness-reviewer, or the code-review skill). Each must try"
    echo "        to CONSTRUCT a breaking input, not just pattern-match."
    echo "     2. Triage findings; fix the real ones."
    echo "     3. Re-verify: a/b (fix on vs off) 0-regression + parity 28/28 +"
    echo "        0-crash sweep; remove any temp a/b env-gate."
    echo "   Then re-run the SAME command prefixed with REVIEWED=1, e.g.:"
    echo "       REVIEWED=1 git commit -m \"...\""
    echo "   (with the docs gate: DOCS_CHECKED=1 REVIEWED=1 git commit -m \"...\")"
} >&2
exit 2
