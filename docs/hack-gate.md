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
