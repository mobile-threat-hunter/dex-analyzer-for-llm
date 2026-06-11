#!/usr/bin/env bash
# PostToolUse hook: enforce the project's Python standards on every edit to a
# package source file (PEP 8 / PEP 257 / PEP 484 via Black, Ruff, mypy).
#
# Behaviour:
#   1. Auto-applies Black + `ruff check --fix` in place (formatting + safe fixes).
#   2. Reports any REMAINING Ruff violations and mypy errors back to Claude
#      (exit 2 surfaces stderr as actionable feedback). Clean → silent exit 0.
#
# Scoped to src/dexllm/**.py — the typed public package. Other dirs
# (examples/bench/tests) are intentionally exempt (see pyproject per-file
# ignores; mypy is configured for the package only).

f="$(jq -r '.tool_input.file_path // empty')"
[ -z "$f" ] && exit 0
case "$f" in
  */src/dexllm/*.py) ;;
  *) exit 0 ;;
esac
[ -f "$f" ] || exit 0

cd "${CLAUDE_PROJECT_DIR:-.}" || exit 0

# 1. Auto-format + auto-fix in place (these mutate the file).
black -q "$f" 2>/dev/null || true
ruff check --fix -q "$f" 2>/dev/null || true

# 2. Collect what still needs a human/Claude decision.
issues=""
ruff_left="$(ruff check "$f" 2>&1)" || issues+="$ruff_left"$'\n'
mypy_out="$(mypy 2>&1)" || true
if echo "$mypy_out" | grep -q "error:"; then
  issues+="$mypy_out"$'\n'
fi

if [ -n "${issues//[$' \t\n']/}" ]; then
  {
    echo "⚠ Python standards: Black + Ruff auto-fixes applied to $f."
    echo "   Remaining issues to fix (PEP 8 / PEP 257 / PEP 484):"
    echo "$issues"
  } >&2
  exit 2
fi
exit 0
