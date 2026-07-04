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
sweep 0-crash / 51k classes.

**The mirror direction (prim→ref).** The same cascade occurs reversed — a
PRIMITIVE-typed version whose ground truth is a reference + null, mistyped `int`
by DAD's last-write (`int v = ObjectAnimator.ofFloat(...); v = 0; …
v.addListener(); return v`). This is the larger population (a primitive used AS an
object — bundled ~349). `gt()` now also carries the resolved reference descriptor,
and the pass is a symmetric two-phase classify-then-apply (reads only pre-mutation
types so the directions can't interfere): re-type a primitive version to the
agreeing reference class when its producers are a reference + null with no genuine
primitive forcer, no unresolved def, and no disagreeing references. The `!has_prim`
guard keeps a genuine int/ref merge untouched (PR#7). Sound by the same
valid-Dalvik argument in reverse (an all-reference value cannot be used as an int).
Measured (a/b, 7 APKs): primitive-used-as-object 249→111 (−138), 0 new `ref = int`
/ `ref`-used-as-int, cascade unchanged.

**Adversarial-review hardening (mirror).** Two reviewers found the mirror UNSOUND
on register-conflated obfuscated dex: a register holding an `int` AND a `String`
param, whose single split version has defs `[N:const-0, R:String-param]` (the
primitive nature only in the USES), was re-typed `String` → `String v6; v6 <=
null; v6 - 1`. The `!has_prim` def-side guard was insufficient — the reference arm
is a moved-in param, so the version looks all-reference on its defs. Two coupled
fixes: (1) `gt()`'s move-source aggregation no longer short-circuits on the first
`'R'` — a source mixing a reference and a primitive returns `'U'` (block); the
short-circuit had inverted safety polarity for prim→ref (it swallowed the
primitive sibling). (2) USE-CORROBORATION symmetric to the ref→prim `object_vids`:
an `int_use_vids` set (arithmetic operand, array index, ordered comparison) blocks
the mirror on any int-used version. Both make the pass sound for lenient/unverified
dex. Verified a/b: 0 new `v <op> null` / ref-used-as-int (a ~109 residual on
bundled is PRE-EXISTING, a separate split_variables/init-result typing bug present
mirror-off — out of scope). This is why the gate exists: the review caught a
real regression the author's a/b sample (which lacked the Kotlin-split conflation
shape) missed.

**Single-def method-result mistypes (ref→prim, use-corroborated).** The cascade
originally skipped single-def versions. But a lone primitive-returning method
typed a reference by register conflation (`String v = p.indexOf(','); v >= null;
v + 1`) is a common, uncompilable mistype. The pass now re-types a single-def ref
version to its resolved primitive when it is int-USE-corroborated (arithmetic /
array-index / ordered-comparison operand), width-correct (`Long.parseLong` →
`long`). A single-def version never used as an int is ambiguous and left
untouched. Two adversarial-review nits: `instanceof` operands are excluded from
the int-use set (a reference), and a `boolean`-returning def reaching an int use
is a genuine boolean/int conflation left untouched (neither `boolean v; v+1` nor
`int v = booleanMethod()` is valid). Verified: 1155 re-types / 6 apks, 0
valid→invalid; ref-declared-used-as-int 239→66, `v <op> null` 109→53, 0 new
boolean-arith. The residual `v <op> null` is a genuine ref-DEF + int-use merge
(needs a version split) — plus a separate PRE-EXISTING split_variables/init-result
bug that types an ordered-compared variable as a reference (deferred).

**Width-resolved use-driven ref→prim (attempted "version splitting", 2026-07).**
Asked to attempt genuine version splitting for this residual, analysis showed it
is the wrong tool: `GroupVariables` merges defs only through a shared use, so a
genuine merge always has a phi point (no clean split) — BUT the residual was
proven to have 0 real reference uses. The values are primitives mistyped a
reference by register conflation (`Object v0_2 = zza(); if (v0_2 < 0);
list.get(v0_2)`), and in valid Dalvik an ordered-compare/arithmetic operand
cannot be a reference. So a USE-DRIVEN ref→prim branch re-types a `cur_ref`,
int-used, non-object-used version to the width resolved from its def closure
(`resolve_prim_width`, walking moves to a genuine primitive, preserving
long/float/double — a naive force-int would truncate 1332/8119 candidates).
Adversarial review (finding #1) required requiring EVERY def to resolve to an
AGREEING primitive width: any genuine reference producer (allocation / reference
method → "") or width disagreement leaves the version untouched (a real object+int
or mixed-width merge that genuinely needs a version split, since `object_vids`
does not cover return/throw/aput-object/ref-cast/ref-arg). Measured: ref-declared
used-as-int 35→20, `v <op> null` 11→3, 0 new truncation, 0 regression. The true
genuine merges that remain DO need control-flow version splitting — deferred; this
handles the spurious-reference majority with no control-flow surgery.

**prim→WIDER-prim (int→long/float/double, 2026-07).** A separate pre-existing bug:
`int v = System.currentTimeMillis()` (a long value in a wide register mistyped
`int` by split_variables — an uncompilable narrowing). A `cur_prim` version is
re-typed to the def width when EVERY def resolves to the SAME primitive WIDER than
the current type (`rank(w) > rank(cur)`), guarded by an `int_required_vids` set
(array index / `switch` selector / `new int[v]` size — where a wide type is
invalid; ordinary arithmetic/comparison is fine). Adversarial review added
switch/array-size to the guard and made `resolve_prim_width` aggregate move-source
siblings (return "" on width disagreement, symmetric to `gt`). Measured: `int v =
<wide method>` 2→0, 0 regression. The remaining split_variables ordered-compare→ref
mistype and the true genuine object+int / mixed-width merges stay deferred.

The `genuine` set (true object/primitive merge at a shared null-check, `has_ref &&
has_prim`) still needs the merge-point split and remains the next cut.

**Move-cycle resolution (2026-07).** A classification-first census of the residual
found it was NOT dominated by the `genuine` set but by a `gt()` RESOLUTION gap: a
version whose all-primitive/null defs reconverge through a move-DIAMOND or move-
cycle (e.g. a boolean `equals()` result `1`/`null` moved v1→v2→`return`) hit a move
back-edge that `gt()` reported `'M'` and the aggregator treated as blocking `'U'`,
so the version kept DAD's reference type. Making a genuine cycle back-edge NEUTRAL
(it targets an ancestor frame that already resolves the cycle member's real defs —
no ground truth is lost, a reference entering the cycle still surfaces as `'R'` on
its first visit) resolves them. Soundness needs per-path cycle detection, done by
BACKTRACKING `seen` as a DFS stack (a diamond is not a cycle); the O(2^N) re-
exploration on a crafted nested-diamond chain is bounded by a `gt_budget` work cap
(bail to `'U'`). Measured: ref-declared-int bundled 26→6, prim-used-as-object 33→17,
`prim = new` flat. The remaining `has_ref && has_prim` genuine merges still need the
split — but they are a far smaller set than the pre-resolution residual suggested.

## Rollout (safe, incremental)

The 6 post-passes are SAFE (each verified, additive). Replacing them with one
pass risks the whole-corpus output. So:

- **Phase 1 — unify, behaviour-preserving.** Build `InferVersionTypes` computing
  step-1 def types + step-2 merge (no split yet) + step-3 use corroboration, and
  verify byte-identical output to the current accreted `FixInitResultTypes` on
  the full corpus (bundled + obfuscated). This is the de-hack: 6 patches → 1
  pass, 0 behaviour change. Retire the old code once 0-diff is proven.

  **Phase 1a — structural split done (2026-07).** As the safe, incremental first
  cut, the 607-line `FixInitResultTypes` was split by pure code-motion into a
  thin driver calling two named, documented static passes: `FixAllocationResult
  Types` (design §1 — allocation ground truth: `new`/`<init>`/move-from-alloc)
  and `InferCascadeTypes` (design §2/§3 — move-chain cascade/mirror, def-anchored
  + use-corroborated). Each carries a design-doc-mapped header comment; the two
  are independent except the shared `is_ref` (a local in each). Verified
  **byte-identical** (0 changed / 43,399 class hashes, bundled + obfuscated) and
  parity 28/28. This is legibility only — the classifiers (`gt()`,
  `resolve_prim_width`, `source_is_allocation`) are NOT yet merged into one §1
  table (deferred; the two serve different purposes — allocation-result fixup vs
  cascade classification — so a merge is a larger, riskier change with bounded
  cleanliness gain since each branch encodes a reviewer-caught soundness rule
  that must survive).
- **Phase 2 — completeness of use positions.** Extend corroboration to arg /
  field / throw / return (PR #12 only did receiver-invoke). Verify: more
  catch-conflation residual fixed, 0 regression (sound-oracle: every re-type is
  def-anchored + use-corroborated).

  **Phase 2a — use-bound prim→ref from a REFERENCE ARGUMENT (2026-07).** The
  first use-as-TYPE-source cut (the earlier passes used a use only as a boolean
  int/object GATE). A primitive-typed version with NO reference DEF (`!has_ref`,
  so the existing mirror cannot fire), NEVER used as an int (`!int_use_vids`),
  and passed at a REFERENCE-argument position is re-typed to that param's type.
  The `int v4 = p10(Function1); actor(…, v4, …)` Kotlin `$default` shape: a
  Dalvik register shared between a reference param and a scratch local leaves the
  version typed `int` (last write), the reference lost from every def (a move off
  the conflated register reports type I), present ONLY at the ref-arg use.
  Sound on verified Dalvik (a value at a reference-param position IS a reference;
  the verifier rejects an int there), so the primitive type is a conflation
  artifact. Two support pieces in `InferCascadeTypes` ([dataflow.cpp](../native/dad_cpp/dataflow.cpp)):
  a `ref_arg_type` map (vid → the ref param type, from `note_obj`; exact-match —
  `ref_arg_conflict` skips a vid passed at two different ref-param types rather
  than compute an LUB), and `has_prim_producer` — a transitive move-resolving
  check that BLOCKS the re-type if any def's closure contains a genuine primitive
  producer (nonzero const / arithmetic / prim-invoke / prim-field), while a move
  to a PARAM (no def) is NOT a producer. Resolving moves is what distinguishes
  `v4 = p10(param)` (fixable) from `v = move vR; vR = x.intValue()` (blocked — a
  form-only check misses the int producer behind the move; caught in
  adversarial-review a/b as a `String v = intValue()` regression, fixed by the
  move resolution). `has_prim_producer` carries its own work budget (2M, mirrors
  gt_budget) so its O(2^N) per-path backtracking cannot hang on a crafted nested
  move-diamond (adversarial-review — the defense was otherwise only emergent via
  gt() exhausting its budget first on the same closure). **Measured (a/b, 0
  regression on every axis):** bundled 252 lines improved (≈14 versions re-typed
  prim→ref + the cascade `= 0`→`= null` null-renders), obfuscated (15-APK
  sample) 130 lines; parity 28/28, determinism (multi-process 0-diff), 0-crash,
  the budget cap output-neutral vs uncapped. Lenient-dex caveat (both reviewers,
  low/suppressed): a genuine int param passed at a ref-arg slot under
  `check_insns=false` could over-fire to `RefType v = intParam` — verifier-
  unreachable on strict dex, garbage-in/garbage-out matching the documented
  precedent for the other use-corroborated re-types; NOT closable cheaply (a
  move-to-param reads the conflated register type I, indistinguishable from a
  real int param). Guard: `test_use_bound_prim_to_ref_typing` in
  `tests/test_cascade_type.py`.

  **Phase 2b — field-store + throw sources, two-tier resolver (2026-07).**
  Extended the use-bound type source beyond the reference argument to a FIELD
  STORE (`obj.f = v` iput → the field type `atype`; `Cls.f = v` sput → `ftype`)
  and a THROW (`throw v` → `Ljava/lang/Throwable;`, cast to `ThrowExpression`
  specifically so the sibling `MoveExceptionExpression` catch-DEF is not misread
  as a use). To keep these ADDITIVE, the single `ref_arg_type` map became a
  TWO-TIER resolver: PRIMARY = the reference argument (a param type is exact and
  reliable), FALLBACK = field-store/throw (used only when no ref-arg pins the
  vid). A field store to an unrelated type can therefore never revert a ref-arg
  re-type — the first single-map attempt HAD exactly that regression (`p3 = null`
  → `p3 = 0` when a store conflicted with the arg). A PRESENT-but-CONFLICTED
  primary returns EMPTY (skip) — it does NOT descend to the fallback: a vid
  passed at two different ref-param types is a genuine LUB case no exact-match
  tier can satisfy, and descending could re-type to a type incompatible with the
  arg uses (`Runnable v` passed at `m(List v)` — both reviewers converged on
  this; the fix is output-neutral on the corpus, the shape is constructible-only).
  **Measured (a/b, strictly additive vs the committed ref-arg version, 0
  regression):** bundled +19 null-render lines, obfuscated (15-APK) +28. parity
  28/28, determinism (2 fresh processes byte-identical), 0-crash. Reviewers:
  correctness sound; adversarial 5/6 REFUTED + 1 (the conflicted-primary
  fall-through, FIXED).

  **Phase 2c — return source (2026-07).** Added the RETURN position (`return v` →
  the method's declared return type) as a FALLBACK-tier source. This needed the
  method return type threaded into the pass: `FixInitResultTypes` / `InferCascade
  Types` gained a `const std::string& ret_type` param (from `m.ret_type` at the
  decompile.cpp call site; header default `= {}` keeps the unit-parity-test
  callers compiling and behaviour-neutral — `is_ref("")` is false). A returned
  value is assignment-compatible with the return type (a `return-object` at a
  reference-return method proves the value is a reference), so it pins the vid to
  that reference type in the fallback tier (a return type can be a supertype, so
  a ref-arg still wins). **Measured (a/b, strictly additive vs the committed
  field-store/throw version, 0 regression):** bundled +110 lines (50 null-renders
  + `Long`/`Animator`/`SyncQueueItem` re-typed decls) — the largest single-source
  payoff yet (a conflated register RETURNED as a reference is a common shape).
  parity 28/28, determinism (2 fresh processes byte-identical), 0-crash.
  Reviewers: correctness sound, adversarial 6/6 REFUTED (0 findings). Array-store
  (aput-object) stays TODO: the ArrayStoreInstruction carries only a category
  MARKER (`"O"`), not the element type descriptor, so the element type would have
  to be derived from the array variable's (possibly-conflated) type — fragile,
  low payoff, deferred. Genuine `has_ref && has_prim` merges still need a version
  split (Phase 3).
- **Phase 3 — split on conflict.** Implement version splitting for genuinely
  conflated registers (the residual PR #12 leaves). This touches variable
  numbering + def/use rewiring — the highest-risk piece; gate behind the sound
  oracle and a full before/after.

### Phase 3 handoff — precise target + plan (2026-07)

After the cascade/mirror/move-cycle/ref-arg passes converged, the remaining
invalid-Java (~0.07% of methods, dominated by `T v = varOfOtherKind` prim/ref
mismatches) was shown to be **genuine `has_ref && has_prim` merges only** — a
version whose def set contains BOTH a real reference producer AND a real
primitive producer. Everything else (arrays' `arr.length`+`arr[i]`, int-argument
positions, relay-cycle mistypes, move-from-reference mistypes) is a
classification artifact or a use-corroboration/propagation gap, NOT a split
target.

**The target is the code's OWN signal, not an output regex.** Output-text
regexes are unreliable here (they conflate array `.length`+index, int-args, and
move mistypes — measured counts swung 0/3/171/123 across regex variants). The
authoritative genuine-merge set is exactly the versions that hit
`InferCascadeTypes`' `if (has_unknown || (has_ref && has_prim)) continue;`
(dataflow.cpp) with `has_ref && has_prim`. Instrument it (an env-gated fprintf
of `vid`/`cur`/`ref_type`/`prim_type` right before that line) to enumerate the
set: measured **~348 hits / ~123 distinct type-pairs** on bundled + 4 obfuscated
APKs (inflated by repeated library classes). Representative pairs: `CharSequence
× I`, `String × I`, `View × I`, `Object × Z`, `Object × I`, `SimpleArrayMap × I`.

**Plan.** For each `has_ref && has_prim` version v: classify its defs into a
ref-region (`gt()=='R'`) and a prim-region (`gt()=='P'`) and, per USE, run
reaching-def to see which region(s) reach it. A use reached by ONLY one region
is renamed to that region's fresh version-id (pure rename — no control-flow
change). A use reached by BOTH regions is a genuine phi point (rare — most
conflations are disjoint-CFG-region register reuse, so most uses are
single-region) and needs a copy/phi inserted. Start with the disjoint case
(rename-only, low risk); do the phi case as a separate, later cut.

**Do NOT retry (measured failures):** (a) `saw_block` relay-cycle skip in
`resolve_prim_width` — re-types one SCC member, leaving the relay partner as a
new `RefType v = <int>` mismatch. (b) move-from-object propagation (single-def
`int v = move vSrc` where `vSrc ∈ object_vids`) — object_vids is display-vid-keyed
so it over-fires on conflated sources; net payoff was ~−6 with a muddled a/b. (c)
fixpoint over classify+apply — −2. All confirm a use-corroboration/propagation
shortcut cannot resolve a genuine merge; only a real split can.

**Verification (mandatory — a prior attempt mis-measured a regression):** run the
a/b with the SAME regex for fix-OFF and fix-ON — never reuse another run's
baseline (a broad `\d [-+*/%] v` ref-used-as-int regex false-matches `v5 + v1`,
inflating the count; the narrow clean baseline is ~15 bundled, the broad ~23, not
329). Metrics: prim/ref-mismatch var-assign (bundled 107 / obf 278 baseline);
plus REPEATED sweeps (a non-deterministic hang — cf. the historical
ShortCircuitStruct hang — can pass a single run), a multi-process determinism
check, parity 28/28, 0-crash, a snapshot diff, and two adversarial reviewers
explicitly attacking the 0-crash / determinism / parity headline invariants.

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
