# Additive SSA — design (version-split done right)

**Status:** Phase 0 (design), 2026-07-05. Approved architecture: **Additive SSA**
(Option A). Motivation and the failed heuristic attempts that preceded it are in
`docs/type-inference-design.md` (Phase 3) and the `project_type_inference` /
`project_current_status` memories.

## Why

`GroupVariables` / `SplitVariables` (DAD's register-level dataflow, ported 1:1)
is not real SSA. It forms a version by transitively merging a register's defs
through **shared uses** (a weak phi-web), then types the version from the
register's last write. Two failure modes follow:

1. **Over-merge → mistype.** A register reused across a reference and a primitive
   becomes ONE version (they reach a common use), typed once → invalid Java
   (`FontCallback v = -3`, `int v = someView`).
2. **Unsound repartition.** The `SplitConflatedVersion` heuristic tries to
   re-separate such a version by classifying each def's region (`region_of`) and
   partitioning uses by reaching-def. It is measurably unsound: broadening it to
   catch the residual conflations mis-split a clean `int` loop counter
   (`multiple_locale…` `v1`) into `int v1_1` declared in an argument position +
   `v1_1 += 2` before any def — because a `const 0` loop-init was heuristically
   grouped with the reference region ("N goes with R"), leaving the prim region
   with no initializer. (2026-07-05 measured; reverted.)

Real SSA fixes both **by construction**: each def is a distinct value with a
unique name; φ (phi) nodes are placed **only** at genuine merge points
(dominance frontiers); a use references exactly one reaching value. There is no
heuristic region-guess, so the loop-counter mis-split cannot arise, and the
"genuine conflation" set is exactly *"a φ whose operands include both a
reference value and a primitive value"* — precise, not the ~60×-inflated
heuristic candidate set.

## Architecture — Additive (Option A)

The existing DAD-ported reaching-def (`BasicReachDef`) is **sound over loops**
already; the imprecision is only in `GroupVariables`' version formation. So SSA
is added as a **new analysis pass** that produces precise per-value types and the
precise conflation set, then translates back into the existing `lvars` /
`Variable` world (out-of-SSA). **The Writer / dast / 28 parity pipeline is
unchanged** — SSA informs *typing* and *splitting* decisions inside the
`SplitVariables` stage and hands the same downstream IR structure onward.

```
Construct → BuildDefUse → [SSA construct → SSA type/conflation]        ← NEW analysis
                        → SplitVariables (out-of-SSA: rename / Object) ← informed by SSA
                        → DCE → RegisterPropagation → PlaceDeclarations
                        → SplitIfNodes → Simplify → IdentifyStructures → Writer
```

### SSA core (both options would build this; ~150–250 lines, new `ssa.{h,cpp}`)

Reuses the existing `DomLt` (Lengauer–Tarjan idom), `compute_rpo`, `preds`/`sucs`.

1. **Dominance frontiers** — Cytron et al. from the idom map. `DF(n)` = nodes
   where `n`'s dominance ends.
2. **φ insertion** — for each register `r` (int-keyed `lvars`), collect its
   def-blocks; place a φ for `r` at the *iterated* dominance frontier of that
   set (worklist). A φ is a synthetic def of `r` at a block head with one operand
   per predecessor edge.
3. **Renaming** — dominator-tree DFS with a per-register version stack: each real
   def and each φ gets a fresh subscript; every use is rewritten to the
   top-of-stack version; φ operands are filled from the predecessor's
   top-of-stack on each CFG edge.

Output (analysis only — does NOT mutate the IR the Writer reads in Phase 1):
- `ssa_def[value] = loc | φ` — the single defining site of each SSA value.
- `ssa_uses[value] = [loc…]`.
- `ssa_type[value]` — def-anchored (allocation → exact class; `new[]` → array;
  `<init>` → constructed class; method → return type; field → field type;
  `move` → the source value's type, resolved transitively/through φ; `const 0`
  in a ref context → null; other `const`/arith → primitive; `move-exception` →
  catch type).
- `phi_operands[φ] = [value…]`.

### Out-of-SSA (the ONLY place A and B differ)

A φ is classified by the types of its operands:
- **All the same type `T` (or `T` + null)** → the merge is fine; the register's
  version is `T` (this alone fixes the current last-write mistypes).
- **Different but compatible references** (`A`, `B` both `L…`) → verifier
  guarantees assignability to the use; keep the current behaviour (or `Object` —
  no new invalid either way; decide empirically to preserve output).
- **Reference operand(s) AND primitive operand(s)** → the genuine int↔ref
  conflation. There is no single Java type. Two sub-cases:
  - The φ is *removable* (its value never forces a real merge — the two arms
    reach disjoint uses; equivalently the φ was placed but one side is dead on
    every path to a use): **rename-split** into two `lvars` versions, each typed
    from its own SSA value. SOUND because SSA proved disjointness, unlike the
    reverted heuristic.
  - The φ is a real merge (a use genuinely reads both arms): type the register
    `Object` and let the Writer emit `(T)` casts at type-specific uses — the
    established jadx-informed model already in `writer.cpp` (`visit_invoke`,
    field-owner cast). No 60× over-count, because SSA only flags real merges.

Translation to `lvars`: each SSA value with a distinct type becomes a
`vN_k` `Variable` (as `SplitVariables` already mints split versions), its
def/use locs rewired via `replace_lhs`/`replace_var` and `du`/`ud` re-keyed —
the exact mechanism `SplitVariables` uses today.

## Phasing (safe, gated — each phase its own commit + full gate)

- **Phase 1 — SSA construction as PURE ANALYSIS (0 output change).**
  Build DF + φ insertion + renaming producing the SSA maps above, WITHOUT wiring
  to `SplitVariables`. The IR the Writer reads is untouched → output
  **byte-identical** (the hard, safe gate). Verified by:
  - unit tests: DF on a textbook CFG (diamond, loop) with known frontiers; the
    `v1` loop case renders identically (analysis-only).
  - the SSA oracle (below).
  - `dexkit-sweep` byte-identical + parity 28/28 + determinism.
  - Sub-cuts: **1a** DF, **1b** φ-insert + rename, **1c** oracle + type derivation.

- **Phase 2 — wire SSA typing + conflation into `SplitVariables` (output changes).**
  Replace the `region_of`/`partition` heuristic inside `SplitConflatedVersion`
  with SSA truth: disjoint → rename-split (sound), real ref+prim φ → `Object` +
  casts. Retire the heuristic once SSA subsumes it. Gate:
  - a/b (SAME census script OFF vs ON, env-gated) — residual kind_mismatch /
    reftype-int / op-null reduced, **line-set diff 0-ADDED** (the v1 case now
    correct, not broken).
  - parity 28/28, determinism (multi-process byte-identical), **repeated**
    0-crash/0-hang sweeps (control-flow-adjacent → a single run is insufficient),
    ≥2 adversarial reviewers attacking the headline invariants, HACK self-check
    (this is a root-cause IR/dataflow change, not a Writer mask).

- **Phase 3 (optional, later) — migrate more of versioning to SSA.**
  Only if Phase 2 leaves value on the table. Not required for the residual.

## SSA oracle (independent soundness check, per the tail-position precedent)

After renaming, assert on every method:
1. **Single reaching def.** Every use references exactly one SSA value; that
   value's def dominates the use (or the use is a φ operand from the matching
   predecessor).
2. **φ completeness.** Every φ has exactly one operand per predecessor edge.
3. **Reconstruction faithfulness (Phase 1 gate).** Dropping subscripts and
   collapsing φ back to the register reproduces the original def/use chains
   (`du`/`ud`) — proves the SSA analysis did not lose or invent edges, so
   analysis-only output stays byte-identical.

Mutation-test the oracle (flip a subscript / drop a φ operand → oracle must
fire) so it is not vacuous.

## Invariants this must not break (CLAUDE.md §5)

- **parity 28/28** — Phase 1 is analysis-only (byte-identical); Phase 2 changes
  only conflated-register typing, which the parity suites do not assert (the
  return-literal / cascade precedent), so parity stays green. If a parity suite
  *does* move, split it `*DADFaithful` — do not silently break it.
- **0-crash / 0-hang** — SSA passes are bounded (φ-insert worklist terminates on
  a fixed DF; rename is a single dominator-tree DFS). Repeated sweeps + a work
  cap on any fixpoint (the `gt_budget` precedent).
- **determinism** — iterate blocks in `rpo` order and registers in sorted int
  order; no pointer-keyed map iteration feeds a decision (the historical
  non-determinism root cause). Multi-process byte-identical check each phase.
- **byte-identical for the 99.97% already-correct** — Phase 1 guarantees it
  structurally; Phase 2 gates it via 0-ADDED line-set diff.

## Non-goals

- No generics (dex erases them), no inter-procedural inference (return/param
  types taken as declared) — same as `type-inference-design.md`.
- Not replacing the DAD-ported control-flow structuring (`control_flow.cpp`) —
  SSA informs dataflow typing only.
