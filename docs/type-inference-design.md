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
