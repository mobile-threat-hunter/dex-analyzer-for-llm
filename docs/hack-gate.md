# The hack gate

A **hack** is a change that makes the observed output right without making the
system's model of the input right. It passes the test that found the defect and
leaves the defect alive somewhere else: in another surface that carries the same
fact, in another reader of the same rule, or in a heuristic that is right on the
sample and confidently wrong off it.

This file turns step 0 of the adversarial-review gate
([.claude/review-precommit-check.sh](../.claude/review-precommit-check.sh)) from a
question into **eight criteria, each with a check that can be RUN**. A criterion
whose check was not run is not passed — it is unexamined, and the review must
say so.

| # | criterion | the check | precedent |
|---|---|---|---|
| **HG1** | **Origin layer.** The change sits where the wrong fact is PRODUCED, not where it is displayed. No rewrite of an artefact another layer already emitted. | Name the producer of the wrong value; the diff must touch it. Grep the diff for post-processing of rendered text (regex over output, string replace on a listing). | v0.1.12 void-invoke masked in `Writer::visit_assign`, AST still wrong; rewritten at the IR builder |
| **HG2** | **Every reader of the input.** All code that consumes the same input is enumerated — derived from the format/opcode table, vendored tree included — and each is shown correct or fixed. | Derive the set (e.g. every opcode of a format from `dex_instruction_list.h`), grep every reader of it, and state a verdict per reader. Decide REACHABILITY by walking inward from the binding's `.def`s, never from the reader's internal names (dexllm#87's first cut got this wrong). | dexllm#61 — "is this an invoke" spelled four times, all four wrong the same way |
| **HG3** | **The views agree, mechanically.** Every surface carrying the same fact is compared by an oracle that does not reuse the reasoning under test, and the oracle is shown to FAIL on the pre-fix behaviour. | A cross-view test over a committed fixture (CI) and the corpus; run it against the OFF behaviour and report the disagreement count. | dexllm#75 / dexllm#77 — smali and Java disagreeing about one method |
| **HG4** | **No value-sniffing.** The output is decided by what the input MEANS (opcode, format, declared type), never by a heuristic on its value. A heuristic that can be confidently wrong fails even at a high hit rate. | Look for branches on magic values, bit patterns or "likely" predicates; measure the error rate and the worst error. | dexllm#87 option C below |
| **HG5** | **No silent re-derivation.** If the rule already exists elsewhere, the new reading is either the same definition or held in lockstep with it by a test that fails when they drift. | List every implementation of the rule; name the test that compares them. "They agree today" is not a lockstep. | dexllm#63, #70, #83 — a rule read a second time drifts |
| **HG6** | **No new convention without a contract and a guard.** A new output form is documented, and every in-tree consumer that PARSES that output is audited. | Grep `src/dexllm` for parsers of the surface (regexes over smali / Java); state the contract in `docs/api.md`. | dexllm#64 `CommentSafe`; `tls_trust.py`'s `$`-anchored smali regexes |
| **HG7** | **No incidental guarantee.** Whatever the fix relies on (a decoder's sign-handling, an ordering, a table) is pinned by a craft or a source guard, not assumed. | For each precondition, name the guard that fails if it stops holding. | dexllm#45 / #63 — a gate promise that holds only in lockstep |
| **HG8** | **Removal is observable.** Each load-bearing part of the fix has a mutant that is BUILT, RUN and killed. | The mutation matrix, with md5 identity per mutant and a restored control. | every section of CLAUDE.md since dexllm#56 |

## Applied: dexllm#87 (`const/high16` in the smali view)

The defect: the smali listing printed the raw 16-bit `BBBB` of a `k21h`
instruction where the register receives `BBBB << 16` (or `<< 48` for
`const-wide/high16`). Five candidate designs were put through the gate.

### What the gate measured first

**HG2 — every reader of a `k21h` operand.** Derived from the slicer table, `k21h`
is exactly `{0x15 const/high16, 0x19 const-wide/high16}`. Its readers:

| reader | layer | shifts? | reachable from dexllm? |
|---|---|---|---|
| `native/dad_cpp/opcode_ins.cpp` `ConstHigh16` / `ConstWideHigh16` | decompiler | yes, `<<16` / `<<48` | yes — Java, AST |
| `native/core_ext/invoke_args.cpp` `AnalyzeInvokes` | `resolve_call_args` | yes | yes |
| `native/core_ext/smali_render.cpp` `FormatOperands` | smali view | **no — the defect** | yes |
| `vendor/.../dexkit/dex_item.cpp` `PushEncodeNumber` | DexKit number matcher | yes | **yes** — `find_methods_using_{int,double}_literals` |
| `vendor/.../slicer/code_ir.cc:590` | slicer code IR | yes, branching on the opcode exactly as the fix does | no — compiled, never called |

(The decompiler's `int16` decode of `BBBB` is in `instruction_dispatch.cpp`,
which hands it to `opcode_ins.cpp`. Slicer's `bytecode_encoder.cc` is a sixth
`k21h` site, but it is an ENCODER and unreachable. `opcode_util.h` reads only
the width.)

So the defect was one reader out of five omitting a rule the other four apply,
and the fix brings the fifth into line with them.

**The first cut of this table got HG2 wrong, and a reviewer caught it.** It
marked `PushEncodeNumber` unreachable because a grep for the matcher's INTERNAL
names (`using_numbers`, `EncodeNumber`) found no binding. The binding exists
under a different name: `find_methods_using_int_literals` builds a `using_numbers`
matcher. The check behind HG2 is therefore **reachability from the BINDING**:
start from the `.def`s in `native/binding/module.cpp` and walk inward. Grepping
outward from the reader's internal names misses any wrapper that renames them.
Measured once that was fixed:

- **narrow:** every `const/high16` site is found by its signed 32-bit value,
  **7,181 / 7,181**.
- **wide:** every finite `const-wide/high16` is found by its double,
  **808 / 808**.
- The other 41 wide sites are NaN or ±Inf. The matcher compares floating values
  as `abs(a - b) < EPS`, which is never true for NaN or for `inf - inf`, so no
  query can find them, whatever the reader did. The slicer's own canonical
consumer (`code_ir.cc`) does the same thing the fix does: it branches on the
OPCODE and casts to `u8` before `<< 48`. The fix is the shape upstream already
uses, not something invented for this case.

**HG3 — the readers compared to each other.** For every high16 that
defines a call argument in the same straight-line stretch as the call, the
oracle compares the smali literal with `resolve_call_args`'s value and with the
Java line `pc_map` anchors at that call:

| population | smali = resolve | Java line carries the value |
|---|---:|---:|
| whole bundled corpus + committed fixtures | **2,847 / 2,847** | **1,270 / 1,270** decidable (1,577 calls anchor no Java line) |
| the same pairs, pre-fix smali rendering | **0 / 415** (two sources) | — |

The oracle's first cut reported **3 disagreements, and all 3 were the oracle's
own error**: it scanned backwards across a `packed-switch` arm, pairing a call
with a `const/high16` that cannot reach it. `resolve_call_args`, which follows
the CFG, was right. The oracle now stops at the first block-ending instruction.
The one Java line that matched none of the oracle's spellings rendered the NaN
bit pattern as `Double.NaN`, which is correct output. ±Infinity has the same
shape (`Float.POSITIVE_INFINITY`). The bundled corpus carries none at a call
argument, but a reviewer crafted one and the oracle failed on correct output.
The oracle now derives the named constants from the bits.

Three known limits of the oracle:

1. **The Java check is token-set membership on one line, not positional.** On a
   line such as `setSizeParameters(56, 56, 12.5, 3, 12f, 6f)`, a corrupted double
   argument whose correct spelling is `56` would still find a `56`.
2. **It covers only straight-line pairs.** 1,577 of 2,847 calls anchor no Java
   line of their own, because `pc_map` keeps one anchor per line and the call
   was folded into a later statement.
3. **"Nearest later anchor" was tried and rejected.** Measured, it picked the
   wrong line 6 times, all of them correct output reported as failures.

Committed in [tests/test_smali_high16.py](../tests/test_smali_high16.py):

- **cross-view tests**, one each on:
  - the fixture's two call-argument sites;
  - a crafted top-bit-set `-1.0f`;
  - a crafted `+Infinity`;
  - a crafted **`const-wide/high16` call argument**;
  - the corpus.
- **number-matcher tests:** the fixture plus both top-bit crafts, and the corpus.

Every craft is on the committed fixture, so all but the two corpus cases run in
the corpus-less CI leg.

**The wide craft exists because a reviewer showed the wide half was uncovered
in CI.** The fixture's two call-argument sites are both narrow. Corrupting the
`<< 48` in `resolve_call_args`, or in the decompiler, passed the whole guard file
narrowed to `tests/data/multidex.apk`. The craft rewrites `const-wide/16 v1, #0`
feeding `Double.valueOf(D)` into `const-wide/high16 v1, #0xc045` (-42.0). Both
are 2 code units, so the craft is length-preserving. That call is folded into
the next statement, so the decompiler is checked by value: the method's Java
must carry `Double.valueOf(-42)`.

**The cross-view matrix: 10 mutants across the four readers, each built with its own `.so` md5 and run, each killed.** (The form's own 14-mutant matrix is separate, below.) The
control `.so` (`7e7db7f4`) was asserted before the matrix and restored after it. That matrix was measured on the first-cut (unsigned-hex) build. Every reader it mutates is outside the smali arm, so the form change does not touch them. The cross-view tests themselves were re-run green on the shipped form.

| mutant | md5 | killed in |
|---|---|---|
| smali: raw `BBBB` (pre-fix) | `0e16d214` | cross-view |
| resolve: narrow shift dropped | `fd47d940` | cross-view |
| resolve: wrong only for a top-bit-set `BBBB` | `84cd4fd7` | the `-1.0f` craft alone |
| decompiler: narrow shift dropped | `f5521a40` | cross-view |
| number matcher: narrow shift dropped | `d3db3878` | number-matcher |
| number matcher: wide `<< 32` | `08284b37` | number-matcher |
| **resolve: wide `<< 32`** | `249a38bf` | wide craft, **CI shape** |
| **decompiler: wide `<< 32`** | `9013abf1` | wide craft, **CI shape** |
| **decompiler: wide `& 0x7fff`** | `d87abd64` | wide craft, **CI shape** |
| guard: the oracle forgets the infinities | (test-only) | the `+Infinity` craft |

The three bold rows all survived the CI shape before the wide craft existed.

### The designs

| design | HG1 | HG2 | HG3 | HG4 | HG5 | HG6 | verdict |
|---|---|---|---|---|---|---|---|
| **① shifted value, unsigned hex** (first cut) | PASS | PASS | PASS | PASS | PASS — held by the cross-view tests | PASS | passes; superseded by J |
| **D** ① plus one shared helper for dexllm's 3 readers | PASS | PASS | PASS | PASS | PASS by construction for 3 of 5 | PASS | passes; not required |
| **B** ① plus a `// = <decimal>` comment | PASS | PASS | PASS | PASS | PASS | **FAIL** unless guarded | conditional |
| **C** baksmali's float/double comment heuristic | PASS | PASS | — | **FAIL** | — | FAIL | **fails** |
| **E** shifted value, signed decimal like the other const arms | PASS | PASS | PASS | PASS | PASS | PASS | passes |
| **H** `pc_map` records every contributing offset | — | — | — | — | — | — | not a fix for this defect |
| **J** jadx's fallback literal: signed value + every reading (**chosen**) | PASS | PASS | PASS | PASS | PASS | PASS — contract in `docs/api.md`, parsers audited, three guard layers | **passes; shipped** |

HG7 and HG8 are properties of the shipped arm, and it passes both.

- **HG7:** the zero-extension of `insn.vB` that the shift relies on is pinned by
  the `0xbf80` / `0xc045` crafts.
- **HG8:** the shipped form's mutation matrix is recorded in CLAUDE.md's
  dexllm#87 section: 14 mutants, each built with its own `.so` md5. 13 are killed
  in the CI shape; the 14th is proven equivalent by the exhaustive JDK
  comparison, which covers every possible high16 input. The cross-view matrix is
  above.

**D does not earn its churn.** A shared helper would make the rule one
definition for three of the five readers. The two vendored readers cannot join
it without opening a new vendor divergence. The HG3 cross-view tests are needed
anyway, and they already fail when any of the four reachable readers drifts. D
would also rewrite the DAD-traceable `ConstHigh16` signature in `dad_cpp`. So
under HG5 it buys "same definition" where the test already gives "held in
lockstep", and nothing else.

**B fails HG6 as it stands.** It opens a `//` convention in the smali listing.
`src/dexllm/tls_trust.py` parses smali with `$`-anchored regexes, and a trailing
comment on a matched line flips a verdict from `permissive` to `not_proven`.
High16 cannot reach those regexes today, because `const/high16` cannot encode 1.
The convention would still be general, so B is acceptable only with a guard on
every smali parser.

**C fails HG4 by measurement.** Ported baksmali's `isLikelyFloat/Double`
predicate (validated 1,365/1,365 against baksmali 3.0.3). It agrees with the
decompiler on 87.0% of narrow sites and 97.6% of wide ones. Its worst error is
`0x40000000` annotated as `2.0f` at 875 sites where the value is
`MeasureSpec.EXACTLY`, which is confidently wrong.

**①, E and J all pass, so the gate does not decide between them. The decision
was made on what other tools do, measured on one crafted dex:**

| tool | `-1.0f` (`0xbf80`) | mask `0xff000000` | wide `-42.0` |
|---|---|---|---|
| baksmali 3.0.3 (apktool, jadx GUI smali view) | `-0x40800000 # -1.0f` | `-0x1000000` | `-0x3fbb000000000000L # -42.0` |
| jadx 1.5.3 fallback | `-1082130432(0xffffffffbf800000, float:-1.0)` | `-16777216(0xffffffffff000000, float:-1.7014118E38)` | `-4592264245034352640(0xc045000000000000, double:-42.0)` |
| AOSP dexdump (source + its expected outputs) | `#int -1082130432 // #bf80` | `#int -16777216 // #ff00` | `#long … // #c045` |
| androguard 4.1.4 / its Rust `dex-bytecode` | `-1082130432` | `-16777216` | `-4592264245034352640` |
| dexllm ① | `#0xbf800000` | `#0xff000000` | `#0xc045000000000000` |

Every tool prints the shifted value. ① was the only one printing it UNSIGNED.
That made it the only form whose literal differed, at 2,117 top-bit-set corpus
sites, from the number `resolve_call_args` and the Java view report.

J (the user's choice) fixes that, because its leading value is signed decimal.
It also answers the float-readability question without a heuristic: it shows
every reading rather than guessing one.

The three places J departs from jadx are deliberate and pinned:

- **The hex is the register's width.** jadx sign-extends to 64 bits even for a
  32-bit load. (Width means "not sign-extended", not zero-padded:
  `BBBB = 0x0100` prints `0x1000000`.)
- **The float string is JDK 19+'s shortest form.** jadx's own output varies with
  the JDK it runs on: JDK 17 prints `2.5243549E-29` where JDK 21 prints
  `2.524355E-29`.
- **The `|v| > 100` threshold is compared exactly.** jadx's `Math.abs`
  overflows on `Long.MIN_VALUE`, so it prints the wide `BBBB = 0x8000` (`-0.0`)
  bare.

The second is checked exhaustively. All 131,072 possible high16 readings are
compared against a JDK 21, and the committed test does this whenever a JDK 19+
and a smali-assembler jar are present. A pinned edge table covers the same layout
rules in CI.

HG6 for J: the decoration is a new operand form.
- **Parsers:** the only in-tree smali parser, `tls_trust.py`, matches
  `const/4|/16|const` and cannot see a high16.
- **Contract:** stated in `docs/api.md`.
- **Guards:** every test that parses a listing re-checks each high16 line's three
  readings against each other, so the corpus legs check it at every site.

**H addresses a different defect.** It is about how good the smali↔Java join is.
The 1,577 undecidable pairs above are a measure of it. Its value is real, and it
belongs in its own issue.

### Findings the gate surfaced outside the fix

- The vendored DexKit `PushEncodeNumber` labels `const` (0x14) as `FLOAT` and
  `const-wide/32` (0x17) as `INT`. It IS reachable (see HG2 above).
  - **Integer searches are unaffected, measured:** `find_methods_using_int_literals`
    finds every `const` site by its value (3,675 / 3,675) and every
    `const-wide/32` site (143 / 143). The matcher reads the union's raw bits for
    an integer query.
  - **The double-query path is unmeasured.** A `const-wide/32` labelled `INT`
    might be read as a float there. It is upstream code, and outside dexllm#87.
- The decompiler types a float high16 as `int` through register reuse, e.g.
  RatingCompat's `v0 = 1065353216;` (= `1.0f`), in at least 129 places. That is a
  type-inference defect in a different reader, and the cross-view test cannot
  see it: it compares values, not types.

## Applied: dexllm#102 (an untyped constant at a declared position)

The defect as filed: `getBooleanExtra("…", 1)` — an integer constant passed at a
`boolean` parameter, 179 lines. A Dalvik `const*` is UNTYPED; every handler
builds an INT-typed `Constant` (DAD), and the type comes from the position that
consumes it. The issue proposed rendering `true`/`false` at a `Z` argument in
both emitters.

### What the gate measured first

**HG2 — every position, not the one in the title.** A census over the AST of
the whole corpus (201,607 methods), by the DECLARED type of the position an
integer literal lands in:

| position | OFF | ON |
|---|---:|---:|
| invoke / constructor argument at `Z`, value 0/1 | 11,925 | 1 |
| invoke / constructor argument at a reference type, value 0 | 9,064 | 0 |
| invoke / constructor argument at `B`/`S`/`C` | 968 | 3 |
| field store into a `Z` field, value 0/1 | 13,026 | 0 |
| field store into a reference field, value 0 | 5,497 | 0 |
| `aput-boolean` / `aput-object` of 0/1 / 0 | 484 | 0 |
| an `int` LOCAL passed at a `Z` parameter | 1,878 | 321 |

So the issue's 179 was a regex over two framework methods; the defect class is
~40,000 sites across SIX position kinds, plus the same fact for a VARIABLE. The
residual 1 + 3 are the deliberately unprojected call-site arguments of
`invoke-custom.dex`'s `TestBadBootstrapArguments` (encoded values, see HG4).

`B`/`S`/`C` at an argument is the sharpest one: Java does not narrow a constant
in an INVOCATION context (JLS 5.3), so `sb.append(125)` compiles — to
`append(int)`, appending `"125"` where the bytecode appends `'}'`.

**HG5 — the rule already existed, six times.** Before the change the
"untyped constant at a typed position" projection was spelled in `visit_return`
(text), the ReturnStatement branch (AST), `write_inplace_if_possible` (text, Z
and null), `typed_rhs_expr` (AST), `emit_fp_const_typed` (text, F/D) and
`visit_expr_fp_typed` (AST, F/D) — and applied at return, local assignment and
F/D operands only. The issue's direction would have added a seventh copy at
one more position.

### The designs

| design | HG1 | HG2 | HG3 | HG4 | HG5 | HG6 | verdict |
|---|---|---|---|---|---|---|---|
| **A** the issue's: `true`/`false` at a `Z` argument, both emitters | PASS | **FAIL** — 5 of 6 positions and the variable half left | — | PASS | **FAIL** — a seventh copy | PASS | fails |
| **B** A at every position, each spelled in place | PASS | PASS (literals) | PASS | PASS | **FAIL** — ~14 copies | PASS | fails |
| **C** retype the `Constant` NODE in the IR at RegisterPropagation | PASS | PASS | PASS | PASS | PASS | PASS | **structurally unsound** — see below |
| **D** one projection `ConstantAt(context, position type, operand)` read by both emitters at every declared position, plus the variable half in the type-inference pass (**chosen**) | PASS | PASS | PASS | PASS | PASS | PASS | passes |

**C fails on the IR's own keying.** An `IRForm` keys its operands by `Vid()`,
and a `Constant`'s id is value-derived (`c1`), so `takeZI(true, 1)` — one
register, two declared types in ONE call (d8 emits exactly that) — holds ONE
node for both arguments; RegisterPropagation also shares a constant node across
uses. The type of a constant use is a property of the (node, position) edge,
and the position's declared type is already in the IR (`ptype()`, the field
type, the aput opcode, `ret_type`). The IR is complete; the emitters were
ignoring a fact it carries. The fixture's `mixed` method pins this.

**HG1 for D.** The two facts have two producers, and each is fixed where it is
produced:

* the LITERAL kind of an inlined constant is produced where the constant meets
  its position — the emitter's projection — and both emitters now read one
  definition (`ConstantAt`, `instruction.h`). Nothing downstream re-reads
  rendered text.
* the TYPE of a variable is produced by the type-inference pass:
  `bool_use_vids` (#86's `Z`-return channel) gains the `Z` parameter, `Z` field
  store and `aput-boolean` sources, and a re-typed version's whole MOVE
  COMPONENT is re-typed or none of it.

**HG4.** The decision reads the position's DECLARED type and the constant's
provenance, never its value. The value guards refuse what Java cannot spell,
and say so by ART's rules rather than by a heuristic: ART accepts only its Zero
constant at a reference position (so `takeRef(1)` is a dex no VM loads, left
as `1`), and checks only the CATEGORY at a narrow-integral parameter, field or
array store (`VerifyInvocationArgsFromIterator`, `VerifyPrimitivePut`), so
`takeZ(2)` is legal and left as `2`. A `Constant` built from an encoded_value
(a call-site argument, dexllm#67) states its own type and is never projected —
an encoded INT `0` at a `String...` vararg is the integer 0, not `null`
(`Constant::encoded_type`).

**HG6.** The output forms are not new: `true`/`false`/`null` are the
existing literals, and the argument cast `((char) 125)` is the spelling the
Writer already gives a `CastExpression` (the AST node is the existing
`Parenthesis(Cast(...))`). No in-tree code parses decompiled Java
(`tls_trust.py` parses SMALI, unchanged).

**HG7 — three incidental guarantees the first cut leaned on, each found by a
measurement and each now pinned.**

1. **#86's soundness claim was false.** It said "in verified Dalvik `return v`
   in a `Z` method requires v to hold a boolean". ART's `return` takes an
   Integer for a boolean, and invocation / field / array positions check only
   the category. The re-type was sound anyway because of its DEF-anchor
   (`all_defs_boolean_valued`); the comment now says so, and the def-anchor is
   what carries the new sources too.
2. **A per-VERSION numeric-use guard.** #86 refused a version used as an int
   anywhere, but a use only ONE constant reaches renders that constant
   (RegisterPropagation): `AdapterHelper.onItemRangeInserted` compares `p6 >= 1`
   and passes `1` at an int parameter through the very register it later
   returns as the flag. The guard is now per POSITION, read through #94's own
   rule (`OnlyAConstantReaches`, hoisted to one definition). This cut `boolean`
   methods returning an `int` local from 652 to 220.
3. **#94's move width rule compared exact types.** A destination SplitVariables
   typed from a register's last write (`int-to-float`) is corrected to its
   sources' class — but `{I, Z}` sources compared unequal, so once #102 typed
   one source `Z` the destination stayed `float`
   (`Tx3gDecoder.decodeInitializationData`, `float v3_25 = 0f` stored into a
   boolean field). Sources of one CLASS now join to `I`, as ART's merge does.
   **That stopped at `int`, and the review caught it**: nothing after the
   width rule refines its `I` (the narrow-integral pass has already run), so
   the destination read `int v3_25; … this.customVerticalPlacement = v3_25;`
   — an int stored into a boolean field, the very position #102 is about.
   The rule now takes `Z` when the destination is a boolean (a `Z` use, no
   numeric or object use, every def 0/1) AND every source flowing into it is
   already `Z` or renders as its literal.

**Two regressions the first cuts created, both caught by measurement, not by
reasoning.** Widening the `Z` sources seeded flags whose move partners were
ints: `boolean v0 … int v2; v2 = v0;` (`int-reuse.dex` `sharedConst`) and, in
the other direction, `int v0_5 = v14` beside `boolean v14`
(`CoordinatorLayout.offsetChildToAnchor`). #86's propagation went backwards
only and LEFT a source that failed a guard. The fix is the component rule: the
move-connected component (excluding moves only a constant reaches) is typed
whole or not at all. A scanner for `boolean`/number assignments between locals
is what found the second shape — the text a/b's normaliser maps `boolean` to
`int` and was blind to it.

### Measured

a/b OFF = v0.25.0 (`5c4e66c6`) vs ON (`78ba1bcf`), SAME capture script, both
`.so` md5-asserted: 44 sources / 2,348,601 decompiled lines, **46,233 lines
changed on 25 sources, line counts equal on every source**; every changed line
is one of the intended substitutions (`0`/`1` → `false`/`true`, `0` → `null`, a
narrowing cast, `int` → `boolean` declarations and the `v == 0` → `!v` spelling
that follows) except 2 `byte` → `boolean` declarations of values stored into
`boolean` fields, both correct. AST: 24,048 changed methods, every changed node
classified, none outside those kinds. Invalid-Java axes, OFF → ON: `boolean`
method returns an `int` local 652 → 220; `boolean`/number assignment between
locals 41 → 27; `boolean` local used numerically 25 → 25; `boolean v = <int>`
1 → 1.

**HG3 — an oracle that never reads the IR.** From the SMALI listing and the
callee / field DESCRIPTOR only: every argument / field store / aput whose
straight-line reaching def is a `const`, and the literal Java needs there. Over
the corpus: `Z` positions **17,155 disagreements OFF → 0 ON** (17,175 agree),
reference positions **11,520 → 0** (11,899 agree), `B`/`S`/`C` **750 → 0** (763
agree). Text and AST: per-method literal counts agree on all 24,048 changed
methods (2 counter artefacts — a `byte[][]` check-cast of `null`).

**javac**, class-level over the 7,661 changed classes: errors excluding
unresolved symbols **64,033 → 43,261**, `incompatible types` **25,325 →
5,026**. Per UNCHANGED line: 1,229 better, 21 worse — all 21 are
`unreported exception RemoteException` on a pre-existing `throw v1_0;`, which
javac reaches only because the same method stopped failing attribution
(`transact(1, v0, 0, 1)` → `transact(1, v0, null, 1)`). **19 new
`reference to X is ambiguous`** errors: a `null` argument where the callee has
several reference overloads (`putExtra("…", null)`, `this(p2, null)`). OFF's
`0` there either failed to compile or silently resolved to the `int` overload;
choosing the overload needs a cast, which needs overload resolution — recorded,
not fixed (see the residuals). **Both halves of that last sentence were later
corrected:** the cast needs only the DECLARED parameter type, and dexllm#109
applies it to every `null` argument (16 of the 18 such errors at that capture
gone; the residual 2 have another cause on the same line).

**HG8.** 24 mutants, each BUILT with its own `.so` md5 and run against six
guard files, control md5 asserted before and after: **24 killed**. Four
survived the first matrix and each became a fixture method or a pin: the
forward half of the propagation (the fixture's destination was inlined away —
`forwardKeep` keeps one), the `== <nonzero>` position (`eqneLone`), and two
lines no dex can reach, pinned at SOURCE level and saying so (a numeric use
recorded without a position refuses; a `ThisParam` lhs keeps the Operand
context).

### What the two reviewers found

Two independent reviewers (adversarial + correctness), each in a private copy
with its own build, each constructing inputs. **Neither found a defect in the
projection itself**: every removed branch maps 1:1 onto a `ConstantAt` context,
text and AST agree on every changed method, the shared-node case
(`takeZI(v0, v0)` → `takeZI(true, 1)`) holds, and the HG2 census re-derived
(11,929 / 9,072 / 971 with the fixture included). Everything they found was in
the VARIABLE half's convergence or in the guards — the pattern this repo keeps
recording.

* **CONFIRMED by BOTH, MEDIUM — a component typed half `boolean`, half `int`.**
  `component_ok` was asked once per seed and re-walked the whole component per
  member, each walk re-running `all_defs_boolean_valued`: roughly O(N³) on a
  flag move chain, which drained the shared `bv_budget` part-way. Seeds decided
  before exhaustion were typed `Z`, later ones refused — `boolean v5 = v4`
  beside `int v4`, the exact shape the component rule exists to forbid, on a
  strict-valid dex (OFF: all `boolean`). Fixed by deciding the component ONCE
  and recording the verdict for every member, and by memoising
  `all_defs_boolean_valued` per version (its answer is a function of the
  version alone). Pinned by `flagChain`, a 200-link chain.
* **CONFIRMED by BOTH, LOW-MED — a narrowing cast that changes the value.**
  `takeB(((byte) 200))` says -56 where the callee's register holds 200 (ART
  checks only the category there). A B/S/C argument is cast only when the
  value fits; otherwise it stays the integer, like `takeZ(2)` and
  `takeRef(1)`. 0 of the 967 corpus casts were out of range.
* **CONFIRMED, LOW — HG7 item 3 above was only half done** (see the note
  there): the width-joined destination stayed `int` beside a boolean field
  store. Fixed; `mixedWidthSources` now asserts `boolean`, and
  `mixedWidthIntSource` pins the other side (a real int source keeps it int).
* **CONFIRMED, guard holes, each a mutant that passed the whole suite:** the
  component member guard checking only the seed (`compNum` — a member used as
  a number must refuse the whole component; under the mutant `int v1_0 = v0`
  with a boolean `v0`), and `sput-boolean` as a source (`sputSeed`; the
  fixture covered `iput` only).
* **PLAUSIBLE → fixed, LOW — a number RETURN type was not a numeric position.**
  #94's `z_pos` already treats `return v` in an `int` method as ruling `Z` out;
  #102's `numeric_use` did not, so a flag passed at a `Z` parameter and
  returned from an `int` method became `boolean v0 … return v0;`. The two
  passes now agree (`zThenIntReturn`). OFF was invalid there too
  (`takeZ(int)`), so the invalid line moved rather than appeared; 0 corpus
  impact.
* **Stale prose**, all fixed: a comment saying the narrow-integral pass refines
  the joined `I` later (it runs earlier), the CLAUDE.md #86 soundness claim
  this change corrects in the source, and three helper names the change
  deleted.

**Re-measured on the fixed build (`7fcb3cc5`), same scripts:** vs the pre-review
build the corpus moves on exactly 3 lines (Tx3gDecoder, `int` → `boolean` and
its two literals) and 1 AST method; vs OFF, 46,236 lines on 25 corpus sources
(the new fixture excluded — OFF's capture predates it), line counts equal on
every source. Oracle: Z 17,183 agree / 0 disagree, REF 11,906 / 0, B/S/C
766 / 0 (+3 out-of-range values correctly left as integers). Invalid-Java
axes unchanged (`boolean` method returns an `int` local 652 → 220; boolean /
number assignment between locals 41 → 27). Mutation matrix **35 mutants, 32
killed, 3 equivalent individually**: the two memos MASK EACH OTHER (either
alone keeps the cost bounded), so removing one is output-equivalent; removing
BOTH fails `flagChain` — killed.

### Residuals, recorded

* **An `int` local at a `Z` parameter: 1,878 → 321.** The remaining ones are
  #86-class refusals — a version whose def closure is path-insensitively
  non-boolean, or whose component holds a genuine int. No wrong output: they
  stay as OFF rendered them. Filed as dexllm#110.
* **A `null` argument at an overloaded callee: 19 new javac ambiguity
  errors.** jadx casts such a `null`. The first version of this bullet said
  that needs the callee's overload set; an adversarial reviewer showed it does
  NOT: casting to the DECLARED parameter type (which `ConstantAt` already
  receives) always selects that exact method, the most specific applicable
  one (`putExtra("a", (String) null)` compiles against android-36). Filed as
  dexllm#109 and FIXED there: every `null` argument is cast to its declared
  parameter type.
* **Two numeric positions `numeric_use` still does not record**, both shared
  with #94's `z_pos`: `==` against a non-constant int and a bitwise op with an
  int. A flag seeded by a `Z` parameter can be typed `boolean` there; OFF was
  invalid at the same site (`takeZ(int)`), so the invalid line moves rather
  than appears, and corpus boolean/number moves fall (41 → 27). One corpus
  method gains an `int == boolean` (`GridLayoutManager.onFocusSearchFailed`,
  already invalid OFF).
* **`filled-new-array` elements do not go through `ConstantAt`**:
  `new Object[] {0}` stays an autoboxed `Integer` where the bytecode stores
  `null`. Pre-existing and identical OFF — the #96 / #97 family.
* **A char / byte / short VARIABLE at a narrowing parameter** (`int v6_20`
  passed to `append(C)`): the type-inference pass has no `C` use source.
* Adjacent, pre-existing, unchanged (164 lines OFF and ON): a reference
  PARAMETER whose register is later reused renders `p1 == 0`, because the
  write corrupts the `Param`'s type.

## Applied: dexllm#112 (a dex whose value strings are out of order)

The input: a real gambling-app `classes.dex` that `DexKit` refused strict AND
lenient with `Out-of-order string_ids`, while androguard decompiled it. Not a
wrong output — an over-strict GATE — so the gate was run on the question "what
may the verifier accept, and on what evidence".

### What the gate measured first

**The sample.** 8 of 20,953 `string_ids` violate ART's order rule
(`CheckInterStringIdItem`, `dex_file_verifier.cc:2720`), all in one block of
URLs: `https://hadesbet3.com` ×5 and `https://betonredcasinobe.com` ×4,
duplicated and out of place, with consistent length fields and a recomputed
adler32 / SHA-1 — a post-build string swap (AppsFlyer URL templates and a
`CustomTabsHelper` example URL replaced) that did not re-sort the table. With the
order check alone disabled every other check passes and 3,343 classes load.
The 12,857 strings used as identifiers are still sorted and unique among
themselves; none of the 8 is an identifier; `strings[0] == ""`.

**ART rejects it on every app load path.** `DexFile_openDexFileNative` /
`OatFileManager::OpenDexFilesFromOat` (`:492`, `:598`) and dex2oat's
`WriteDexFiles` (`oat_writer.cc:3418`) all run `dex::Verify`; it is skipped
only with a matching vdex or `VerifyMode::kNone`. ART needs the order because
its runtime BINARY-SEARCHES the table (`DexFile::FindStringId`,
`class_linker.cc` "Ordering enforced by DexFileVerifier"). So the strict verdict
stays ART's, and accepting is an explicit divergence.

**HG2 — every reader of string order or uniqueness, vendored tree included.**

| reader | relies on | under value-string disorder |
|---|---|---|
| any binary search over the string table | order | none exists (grep, both reviewers) |
| DexKit `empty_string_id` (`dex_item.cpp:62`) + 5 `""` Equal-search sites | `""` at index 0 | wrong answer unless `""` stays at 0 → **I3** |
| DexItem `type_ids_map`, DexKit `class_declare_dex_map`, core_ext `type_to_idx`, slicer `FindClassIndex` | type descriptors unique by content | **I1** |
| core_ext dexllm#108 single-dex fast path | member descriptors unique by content | **I1** |
| value-string consumers (string search, declaring index, `list_*_strings`, IOC, smali / Java) | index, or content dedupe | correct with duplicates (fuzzed by a reviewer: 331 crafts, 0 failures) |

### The designs

| design | verdict |
|---|---|
| A — drop the check | **FAIL HG7**: an identifier duplicate silently merges two fields or two types in the content-keyed readers (a reviewer's mutant: `APOS` listed twice, every `String` field read as `Object`) |
| B — skip it in lenient only | same failure |
| C — re-sort the table and remap every string index | **FAIL HG1/HG5**: a second reader of every string-index position (code, encoded values, annotations, debug info, call sites) |
| **D — accept under lenient only what the readers need** | passes |

**D**, in `AcceptUnsortedValueStrings` (`dex_verifier.cpp`): a lenient pass
accepts when **I1** the strings used as identifiers (type descriptors, proto
shorty, field / method names) are strictly increasing among themselves and
**I3** the empty string is only at index 0; otherwise ART's failure stands. The
acceptance is decided by ROLE, from the id tables (HG4), and REPORTED: a new
`art_deviations` list on every verify row, raw / `.pyi` / SDK / MCP (HG6). A
strict pass never accepts it, so a strict row is ART's verdict with `[]`.
Decided by the user: lenient (not a new flag) carries it; the MCP server and
HTTP `/upload` — whose callers cannot pass `lenient=True` — try strict, retry
lenient, and say so (`session_note`, `opened` / `strict_refusal`), through one
helper (`_open.py`, HG5).

### What the two reviewers found

No crash, hang or wrong answer from the core claim. Every finding was in the
server fallback or the guards, and all are fixed:

* **CONFIRMED by BOTH — the fallback missed the realistic shape.** A strict load
  of an APK whose `classes.dex` carries the swap beside a good `classes2.dex`
  does not RAISE: the sibling loads (dexllm#25), so the main dex was dropped with
  no note. The helper now also retries when a strict row is rejected, and takes
  the lenient session when it loads more dexes.
* **CONFIRMED by BOTH — I1's strictness was unguarded.** Every craft SWAPPED two
  identifiers; equal contents passed a `> 0` mutant. Two duplicate-identifier
  crafts now pin it.
* the note pointed at `art_deviations` while a lenient fallback also lifts
  `VerifyInsns` refusals (an empty list then proves nothing) — reworded, and the
  tool description says the converse does not hold; a stale-note mutant
  (a path re-opened cleanly kept its note) is pinned; the deviation message
  counted adjacent PAIRS while saying "strings" — reworded; and a dozen
  comments, docstrings and examples still called lenient
  "ART-structural-equivalent" or listed the row without the new field.

### Measured

a/b over 304 real inputs (bundled corpus, committed fixtures, AOSP
`art/test/dexdump`, `tools/dexter/testdata`, all four ART fuzzer corpora, the
voice-phishing APKs) × strict + lenient: **0 verdict changes**, every strict
row's `art_deviations` empty. The mechanism fires on the crafts and the sample
only: the sample verifies strict-invalid and lenient-valid with one deviation,
3,343 classes / ~270,000 lines decompile with 0 `DECOMPILE ERROR`, and an
oracle that never reads the IR (androguard) agrees on the class list and on the
const-strings of 4,142 / 4,142 methods it can decode (21 more it cannot decode
at all). Mutation matrix **15 mutants, all killed** (each identifier role, I1
strictness, I3, strict relaxed, deviation dropped on each layer, the fallback,
the multidex retry, the note).
