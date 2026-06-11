#!/usr/bin/env bash
# PreToolUse(Bash) gate — runs before every Bash tool call.
#
# Purpose: before `git commit` / `git push`, force a review of the project's
# docs .md files for drift against the change (and an update of any that are
# now inaccurate) in the same commit. Docs drift silently — perf numbers, API
# names, file paths, counts, install/build steps — so this makes the doc pass
# a conscious step at publish time.
#
# The LLM does the actual review; this hook only ensures it happens. Once the
# docs have been reviewed (and any drift fixed), bypass the gate by prefixing
# the SAME command with `DOCS_CHECKED=1`, e.g.:
#     DOCS_CHECKED=1 git commit -m "..."
#     DOCS_CHECKED=1 git push origin master
#
# Non-git Bash, and git reads (status/log/diff/add/...), pass through untouched.
set -u

cmd="$(jq -r '.tool_input.command // empty' 2>/dev/null || true)"
[[ -z "$cmd" ]] && exit 0

# Only gate git commit / git push.
grep -qE 'git[^&|;]*\b(commit|push)\b' <<<"$cmd" || exit 0

# Already reviewed this turn → allow.
grep -qE 'DOCS_CHECKED=1|#[[:space:]]*docs-checked' <<<"$cmd" && exit 0

root="${CLAUDE_PROJECT_DIR:-.}"
docs="$(cd "$root" 2>/dev/null && ls README.md CLAUDE.md docs/*.md 2>/dev/null)"

{
    echo "📝 Docs gate — before committing/pushing, review these for drift against"
    echo "   this change and update any that are now inaccurate (API names, file"
    echo "   paths, perf numbers, counts, behavior, install/build steps) IN THIS"
    echo "   COMMIT:"
    if [[ -n "$docs" ]]; then
        echo "$docs" | sed 's/^/       - /'
    fi
    echo "   Then re-run the SAME command prefixed with DOCS_CHECKED=1, e.g.:"
    echo "       DOCS_CHECKED=1 git commit -m \"...\""
    echo "   If every doc already matches the new state, just add the prefix."
} >&2
exit 2
