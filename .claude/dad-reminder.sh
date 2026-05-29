#!/usr/bin/env bash
# Pre-edit hook for DAD-aligned C++ sources.
# Reads tool_input JSON from stdin (Claude Code hook protocol).
# Emits a system reminder enforcing DAD-reference development when the target
# file is under vendor/dexkit_core/Core/, dex_analyzer/binding/, dex_analyzer/dad_cpp/,
# or dex_analyzer/core_ext/.
#
# Removed subsystems (2026-05-26 audit, do NOT reintroduce):
#   - Legacy expr-tree pipeline (Phase 2a/2b/3/4/5/6/8e)
#   - L6_NO_EXPR_TREE / L6_LEGACY_MODE / L6_SSA_MODE env flags
#   - PostInlineSingleUse / PostInlineShortExitTargets / PostStructureForwardGotos
#   - PostEliminateDeadWrites / PostCollapseEmptyBlocks / PostSuppressUnusedLabels
#   - PostSSARename / PostSuppressOrphanGotos (Phase 22)
#   - All text-based regex post-passes on emit output
# Never block the tool call: any failure (malformed JSON, missing jq, parse
# error) should silently exit 0 so the user's edit proceeds. The reminder is
# advisory, not enforced.
set -u

path="$(jq -r '.tool_input.file_path // empty' 2>/dev/null || true)"
if [[ -z "$path" ]]; then
    exit 0
fi
if ! [[ "$path" =~ /vendor/dexkit_core/Core/.*\.(cpp|cc|h|hpp)$ ]] && \
   ! [[ "$path" =~ /dex_analyzer/binding/.*\.(cpp|cc|h|hpp)$ ]] && \
   ! [[ "$path" =~ /dex_analyzer/dad_cpp/.*\.(cpp|cc|h|hpp)$ ]] && \
   ! [[ "$path" =~ /dex_analyzer/core_ext/.*\.(cpp|cc|h|hpp)$ ]]; then
    exit 0
fi

cat <<'MSG'
🔬 DAD-aligned source. Before editing this file:

  1. Identify the corresponding DAD algorithm in androguard:
     /home/nyahumi/Downloads/androguard-master/androguard/decompiler/
       basic_blocks.py | control_flow.py | dast.py | dataflow.py
       decompile.py    | graph.py        | instruction.py | node.py
       opcode_ins.py   | util.py         | writer.py

  2. If your change has NO DAD analogue, it is a band-aid. Do not add
     ad-hoc text/regex post-passes, opportunistic pattern matchers, or
     heuristic structural detection. Discuss with the user first.

  3. Reference the DAD file:lineno in the code comment AND commit message.
     Example: "// DAD: control_flow.py:225 switch_struct"

  4. Removed in 2026-05-26 audit — DO NOT REINTRODUCE:
       - Legacy expr-tree pipeline (Phase 2a/2b/3/4/5/6/8e)
       - L6_NO_EXPR_TREE / L6_LEGACY_MODE / L6_SSA_MODE flags
       - Post* text regex passes (Inline*, *ForwardGotos, *DeadWrites,
         CollapseEmptyBlocks, SuppressUnusedLabels, SSARename,
         SuppressOrphanGotos (Phase 22))

  5. After C++ changes, run /dexkit-build (ninja + pip install -e) then
     /dexkit-sweep. Aggregate counts must not regress.
MSG
