# Type inference v2 — jadx-informed constraint model on our SSA (Phase B)

**Status:** design (2026-07-05). Roadmap decision: **B → A → 0.2.0** (user).
- **B (this doc):** port jadx's *type-inference approach* (constraint bounds +
  hierarchy-based selection) onto our Phase-1 SSA + `is_assignable` oracle,
  replacing the accreted `FixInitResultTypes` heuristics. Additive — DAD IR /
  control-flow structuring / Writer / 28 parity all unchanged.
- **A (later):** a fuller jadx engine port. Separate design when B lands.

**License.** jadx is Apache-2.0. This is an **algorithm adaptation** (re-implemented
against our IR — NOT a verbatim copy). We add jadx attribution to `NOTICE`. The
prior "conceptual reference only" rule ([[feedback_decompiler_choice]]) is
superseded for the type-inference layer; jadx as a *runtime tool* stays forbidden.

## What jadx does (studied from jadx-core `visitors/typeinference/`)

`TypeInferenceVisitor`:
1. **initTypeBounds** — for each `SSAVar`, collect `ITypeBound`s:
   - **ASSIGN bound** (from the def) = the type the defining instruction
     *produces*: NEW_INSTANCE→class, CONSTRUCTOR→constructed class, CONST→literal
     type, MOVE_EXCEPTION→catch type, INVOKE→return type, IGET→field type,
     CHECK_CAST→cast type, else→result init type.
   - **USE bounds** (from each use) = the type the *use position requires*
     (invoke receiver→declaring class, invoke arg→param type, field store→field
     type, array store→element type, …). `BoundEnum` tags each ASSIGN vs USE.
2. **mergePhiBounds** — a phi shares bounds across its result and all operands
   (the whole phi web is one constraint set).
3. **selectBestTypeFromBounds** — pick the type that is `.max` under the
   hierarchy comparator (`TypeCompare` → EQUAL/NARROW/WIDER/CONFLICT via the
   classpath graph `ClspGraph`): the narrowest type satisfying every USE bound
   and compatible with every ASSIGN bound.
4. **TypeUpdate.apply** — applying a chosen type *propagates* through the SSA
   graph (moves, phis), rejecting on any `TypeCompare` conflict.
5. **TypeSearch** — backtracking search when bounds don't converge.
6. **FixTypesVisitor** — fallback: insert casts / split vars for the residual.

`TypeCompare.compareTypes(a, b)` = our **`is_assignable`** (partial-sound dex
hierarchy BFS; unknown → conservative). That is the piece we already built.

## Mapping onto our stack

| jadx | ours |
|---|---|
| `SSAVar` (1 def + uses) | an SSA value `(reg, version)` from `SsaResult` |
| `PhiInsn` | `SsaPhi` |
| ASSIGN bound | the def instruction's produced type (`def_site` loc → ins rhs type) |
| USE bound | the use position's required type (`use_version` loc → ins) |
| `TypeCompare`/`ClspGraph` | `is_assignable` (already injected, hexagonal-clean) |
| `selectBestTypeFromBounds` | narrowest type ⊒ all ASSIGN, ⊑ all USE, via `is_assignable` |
| `FixTypesVisitor` conflict | ref+prim (no single type) → `Object` + cast (already in writer.cpp) |
| out-of-SSA | write the per-version type into `lvars` (the SplitVariables path) |

**Deliberately skipped (not needed for the residual, avoid risk):** generics
(dex erases them), the full `TypeUpdate` propagation engine and `TypeSearch`
backtracking in the first cut (the phi-bound merge + hierarchy selection resolves
the vast majority; add propagation only if measured need), region/codegen (DAD's).

## The USE-position type table (the new precision — enumerate from our IR)

For a use of version v at loc L (instruction `ins`), the required type:

| use position | required (USE bound) |
|---|---|
| invoke receiver (`ins.base() == v`) | the method's declaring class `ins.cls()` |
| invoke arg i (`ins.args()[i] == v`) | `ParseParamsType(ins.proto())[i]` |
| iget/iput owner (`v` is the instance) | field's declaring class |
| iput/sput stored value (`v` is the value) | field type |
| array load/store base | (array — element from context) |
| array store value | array element type |
| `throw v` | `Ljava/lang/Throwable;` |
| `return v` | method return type |
| arithmetic / array-index / ordered-compare operand | a primitive (I/J/F/D by op) |

(These generalize the ad-hoc `object_vids` / `int_use_vids` sets the heuristics
built — now every position contributes a *typed* bound, not a boolean gate.)

## Selection rule (no generics, hierarchy via is_assignable)

For version v with ASSIGN bounds A = {a_i} and USE bounds U = {u_j}:
1. If all ASSIGN + USE bounds are mutually compatible under `is_assignable`
   (each a_i assignable to each u_j; the a_i share a common type), pick the
   **narrowest reference** ⊒ every a_i and ⊑ every u_j — in practice the def's
   allocation type when present (exact), else the most specific USE bound.
2. **Primitive vs reference conflict** (an ASSIGN or USE says primitive AND
   another says reference) → genuine int↔ref conflation → `Object` + explicit
   casts at the reference uses (the established writer model). This is the jadx
   FixTypes "can't unify → cast" outcome, precise now (only real conflicts, not
   the heuristic 60× over-count, because SSA gives exact per-value bounds).
3. Width conflicts among primitives (I vs J) → widen per rank (existing rule).

## Phasing (each its own commit + full gate; a/b + parity + determinism + sweep + review)

- **B1 — bounds model.** Build, per SSA version, the ASSIGN bound (def type) and
  the USE bounds (the position table above) from our IR. Env-gated dump; validate
  the bounds are sane on the corpus. No output change yet.
- **B2 — phi merge + selection.** Merge bounds across phi webs; select the best
  type per version via `is_assignable`. Produce a `version → type` map. Validate
  against the current typing (expect: agrees on the 99.97%, differs on the
  conflation residual). No output change yet (analysis-only compare).
- **B3 — out-of-SSA wiring.** Feed the selected types into `SplitVariables` /
  `lvars`, replacing the `FixInitResultTypes` cascade/mirror heuristics for the
  cases SSA covers; ref+prim conflict → Object+cast. **Output changes → a/b gate**
  (same census OFF/ON, line-set 0-added, the `v1` loop correct, parity 28/28,
  determinism, repeated 0-crash/0-hang sweeps, ≥2 adversarial reviewers, HACK
  self-check). Retire the subsumed heuristics as SSA proves them redundant.
- **B4 (optional) — propagation / search.** Add a bounded `TypeUpdate`-style
  propagation or `TypeSearch` pass only for residual hard cases B3 leaves.

## Invariants (CLAUDE.md §5) — same as the SSA design

Additive: DAD IR / structuring / Writer / 28 parity unchanged. B1/B2 analysis-only
(byte-identical). B3 gated 0-ADDED. `is_assignable` is partial-sound (never a
false positive). Determinism via sorted iteration. Bounded (no unbounded search
in the first cut; any fixpoint gets a work cap — the `gt_budget` precedent).
