# Version-level type inference — design

**Status:** in progress. Replaces the accreted per-shape type patches in
`FixInitResultTypes` (int→ref, `<init>`-result, new-array, move-from-alloc,
catch-Throwable single-def, use-based multi-def — 6 stacked post-passes) with
one principled analysis. This is the fundamental fix for DAD's weakest area:
DAD assigns types at the **register** level (last-write wins), not the **value /
version** level, so a Dalvik register reused across incompatible types leaves
its split versions mistyped.

## Problem

`split_variables` gives each register a set of *versions* but types every
version from the register's last write (`orig_var.type`). A version whose value
is a `new FileInputStream()` can therefore end up typed `Throwable` (from a
`catch` reuse of the same register), or `int` (from a trailing numeric reuse) —
producing uncompilable `Throwable v = new FileInputStream(); v.getChannel()`.

The 6 post-passes each patch one *shape* of this. They work and are individually
verified, but the accretion is a smell (altitude): they re-implement pieces of a
dataflow analysis ad-hoc, and they only cover the shapes seen so far (e.g. the
use-based pass only looks at receiver-invoke positions, not arg / field / throw
/ return).

## Approach — def-anchored, use-corroborated, split-on-conflict

Each version's true Java type is the type of the **value it holds**, which its
DEFINITIONS determine. USES only constrain / corroborate. Crucially, **no
external class hierarchy is needed** if we type from defs and *split* genuine
conflations instead of merging them to a least-common-supertype.

### 1. Per-version def type

For every version `v`, derive a type from each of its defining instructions:

| def | version type |
|---|---|
| `v = new X` / `new X[]` | exactly `X` / `[X` (allocation ground truth) |
| `v = X.<init>(…)` (constructor result, base is `v`) | `X` (the constructed class) |
| `v = move src` | `src`'s type (transitive — resolve via fixpoint) |
| `v = m()` (method result) | `m`'s return type |
| `v = obj.f` (field get) | field type |
| `v = (T) x` (cast) | `T` |
| `v = const 0` in a ref slot | *null* (compatible with any reference) |
| `v = const <int>` / `a op b` | primitive |
| `v = move-exception` (catch) | the catch's exception type |

### 2. Merge / split

A version can have multiple defs (branches). Reconcile:

- **All defs agree** on a concrete type `T` (or *null*) → the version is `T`.
- **Defs disagree** (e.g. `new A` in one branch, `new B` in another; or an
  allocation in one branch and an unrelated method-result in another) → the
  register is genuinely conflated. **Split** the version so each def-region gets
  its own type, rather than picking one (which mistypes the others) or merging
  to a supertype (which needs the hierarchy and loses precision).

Splitting is the piece DAD lacks; it is what makes `IOException v = new
ByteArrayOutputStream(); … v = <the real IOException>` become two variables.

### 3. Use corroboration (soundness, no hierarchy)

A use pins a *lower bound* on the version's type:

| use | constraint |
|---|---|
| `v.m()` (receiver) | `type(v) <: declaringClass(m)` |
| `f(…, v, …)` (arg) | `type(v) <: paramType` |
| `obj.field = v` | `type(v) <: fieldType` |
| `arr[i] = v` | `type(v) <: elementType` |
| `throw v` | `type(v) <: Throwable` |
| `return v` | `type(v) <: methodReturnType` |

Because the input is real, verified Dalvik, the allocation type from step 1
already satisfies every use bound (the verifier guarantees it). So uses are used
to **corroborate** a def-derived allocation type (the current PR #12 receiver-
invoke check generalized to all positions) and to **type versions with no
informative def** (a param / method-result / field-get version keeps its
declared type; a use can refine it only downward to a subtype we can prove — we
do NOT invent a subtype without a def, staying sound).

### Why no class hierarchy

- Allocation → **exact** type (no supertype query).
- Disagreeing defs → **split** (inequality test only, no LCA).
- Uses → the def-derived type already satisfies them (verifier), so we never
  compute `A <: B` ourselves.

## Phase 3 investigation finding (2026-07) — the residual is mostly a CASCADE

Instrumenting `split_variables`/`GroupVariables` on the corpus settled what the
residual conflation actually is. `GroupVariables` is a standard SSA phi-web: two
defs share a version ONLY through a common use. So a *sequential* reuse
(`v = new X; use; v = 7; use2`) is already separate versions — already typed
correctly. Every remaining multi-def-disagree version therefore has a genuine
merge use (typically a null / zero check `if-eqz`, which the verifier allows on
both a reference and an int).

Classifying each ref-typed multi-def version by its **transitive ground-truth
producers** (resolving moves to their ultimate source) gave, per obfuscated APK:

- **cascade** (ref-typed but NO ground-truth reference producer — a `move`
  copied a stale reference type off a sibling conflated register; the value is
  really a primitive flag): the large majority (≈275–308 / APK).
- **genuine** (a real allocation AND a real primitive forcer both reach the
  merge): far fewer (≈0–57 / APK).

So the dominant invalid-Java residual (`ArrayList v = 1;`) is a **typing** bug,
not a merge that needs splitting — fixable by correct def-anchored typing with
**no control-flow surgery**. Genuine splitting is only needed for the smaller
`genuine` set. This inverted the expected risk: the cheap, safe typing pass
handles most of it. **Implemented** as the cascade re-type in `FixInitResultTypes`
(see dataflow.h): re-type an object-less ref version to its primitive descriptor
when no ground-truth reference backs it AND it is never used as an object.

**Adversarial-review hardening.** Two independent reviewers flagged the same
constructible-but-unconfirmed holes: the object-use guard covers only
receiver/field (not throw/array-store/return/ref-arg), and `gt()` could hide a
genuine reference behind a move-cycle or a no-def move-source fallback, yielding
a false all-primitive classification. The resolution is a single conservative
rule that makes all of them unreachable: **re-type only when EVERY def is
definitively primitive/null — any unresolved def (`'M'` move-cycle or `'U'`
unknown-type producer) blocks it**, because such a def might be a hidden
reference. Since an all-primitive value cannot be used as an object in valid
Dalvik, this def-side rule also subsumes the use-side gaps. Plus the re-type
width is the resolved descriptor (`'I'`/`'J'`/…), so a `long`/`double` cascade is
not narrowed to an uncompilable `int v = <out-of-range>`.

Measured (reference-declared-nonzero-int invalid lines, before→after, hardened):
aggregate 422→26 (−94%) across a 13-APK a/b; obfuscated e.g. 61→1, 14→4; clean
tvleanback 41→4. **0 regression on every axis** — `prim = new`, `prim.member`,
`throw prim`, `prim[]` all byte-identical fix-on vs fix-off. The ~20 cases the
hardening leaves (vs the aggressive variant that reached ≈6) are provably
uncertain move-chains — correctly untouched rather than guessed. parity 28/28,
sweep 0-crash / 51k classes. The `genuine` set (true object/primitive merge at a
shared null-check) still needs the merge-point split and remains the next cut.

## Rollout (safe, incremental)

The 6 post-passes are SAFE (each verified, additive). Replacing them with one
pass risks the whole-corpus output. So:

- **Phase 1 — unify, behaviour-preserving.** Build `InferVersionTypes` computing
  step-1 def types + step-2 merge (no split yet) + step-3 use corroboration, and
  verify byte-identical output to the current accreted `FixInitResultTypes` on
  the full corpus (bundled + obfuscated). This is the de-hack: 6 patches → 1
  pass, 0 behaviour change. Retire the old code once 0-diff is proven.
- **Phase 2 — completeness of use positions.** Extend corroboration to arg /
  field / throw / return (PR #12 only did receiver-invoke). Verify: more
  catch-conflation residual fixed, 0 regression (sound-oracle: every re-type is
  def-anchored + use-corroborated).
- **Phase 3 — split on conflict.** Implement version splitting for genuinely
  conflated registers (the residual PR #12 leaves). This touches variable
  numbering + def/use rewiring — the highest-risk piece; gate behind the sound
  oracle and a full before/after.

## Oracle (from the tail-position / use-based work)

An independent, def+use consistency check: for every version's final type `T`,
(a) `T` is one of its def-derived types or null, and (b) every use's required
type is satisfiable by `T` (receiver declaring-class equals `T` or the code
never calls a method `T` lacks — verified against the emitted text: no
`v.method()` where `method`'s declaring class contradicts `T`). Mutation-test
the oracle (as in the tail-position work) so a wrong inference is caught.

## Non-goals (this project)

- No generics (dex erases them).
- No inter-procedural inference (return/param types are taken as declared).
- The register-allocation-level "one Dalvik reg, two live objects" that even
  needs *renaming across the whole method* beyond simple version split is out of
  scope for Phase 3's first cut; document any residual.
