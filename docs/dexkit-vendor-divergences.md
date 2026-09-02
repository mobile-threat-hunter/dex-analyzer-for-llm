# Vendored DexKit Core — divergence registry

**Baseline: LuckyPray/DexKit `dff66e8` (`2.2.0-2-gdff66e8`, 2026-05-22).**
Recorded in [`vendor/dexkit_core/UPSTREAM`](../vendor/dexkit_core/UPSTREAM);
the fork-point blob SHA of every vendored file is in
[`vendor/dexkit_core/UPSTREAM.blobs`](../vendor/dexkit_core/UPSTREAM.blobs).

This is the DexKit-side sibling of
[aosp-oob-divergences.md](aosp-oob-divergences.md). That one catalogs where
dexllm's own code diverges from an AOSP/ART reference it re-implements; this one
catalogs where the *vendored* tree diverges from the upstream it was copied from.

Measured against the baseline, the vendored subset is **136 files: 125
byte-identical, 11 modified, 0 added**, **+1271 / -131 lines**.

The line counts are `git diff --numstat` against the fork-point tree — the same
predicate the rest of this repo uses for a diffstat. (An earlier draft published
+1215/-130 from a `diff -u | grep -c '^+[^+]'` pipeline, which silently drops
*added blank lines*; the difference is 56 of them. A count is only as good as the
predicate printed next to it.)

| file | + | - | hunks | marked | marker lines |
|---|---:|---:|---:|---:|---:|
| `Core/dexkit/dex_item.cpp` | 723 | 56 | 16 | 14 | 33 |
| `Core/dexkit/include/dex_item.h` | 155 | 2 | 5 | 4 | 21 |
| `Core/third_party/thread_helper/ThreadPool.h` | 149 | 40 | 3 | 3 | 9 |
| `Core/dexkit/dexkit.cpp` | 168 | 22 | 8 | 6 | 9 |
| `Core/third_party/slicer/reader.cc` | 24 | 0 | 1 | 1 | 4 |
| `Core/dexkit/include/zip_archive.h` | 16 | 0 | 1 | 1 | 1 |
| `Core/third_party/slicer/common.cc` | 13 | 10 | 2 | 1 | 1 |
| `Core/CMakeLists.txt` | 7 | 1 | 1 | 1 | 1 |
| `Core/dexkit/include/dexkit.h` | 6 | 0 | 2 | 1 | 1 |
| `Core/third_party/slicer/export/slicer/dex_format.h` | 5 | 0 | 1 | 1 | 1 |
| `Core/third_party/slicer/export/slicer/dex_ir.h` | 5 | 0 | 1 | 1 | 1 |

**0 added files is a property, not an accident.** dexllm#32 moved the L4
argument-origin analysis (858 lines) out of the vendored tree into
`native/core_ext/invoke_args.cpp`, and that is the standing direction: a dexllm
analysis belongs outside `vendor/`, where it can be tested, reviewed and
rebased without colliding with upstream.

## Treatments

| | meaning | entries |
|---|---|---|
| **U** | upstreamable — upstream still has the defect and would plausibly take the fix | D1 D2 D3 D4 D5 D6 D11 D13 D14 |
| **C** | converged — upstream reached the same behaviour independently; the entry disappears on the next rebase | D7 |
| **P** | permanent — an extension hook or a product decision incompatible with upstream's goals | D8 D9 D10 |
| **R** | reduction candidate — dexllm code that happens to live in the vendored tree and could move out | D12 |

**A treatment is a classification of KIND, not a prediction that upstream would
accept anything.** Nothing here has been proposed upstream. Entry ids are
allocation order and stable; they are not ordered by section.

dexllm#65 estimated "roughly 29 of 54 [markers] are upstreamable bug fixes and 17
are permanent divergence", i.e. that over half the debt could be given away. At
this granularity the direction holds — 9 of 14 entries are **U** — but the
largest single item by volume is neither: **D12 is 560 of `dex_item.cpp`'s 2,018
lines, about 44% of everything this fork adds**, and it is a *reduction*
candidate, code that should leave the vendored tree rather than be sent upstream.
An entry-weighted count and a line-weighted one point at different work.

## The marker convention, and exactly what it does not cover

Every divergence is marked in-source with a `dexllm` comment — **82 marker lines
across all 11 files**, and the marker set and the divergent set are now equal in
both directions (no pristine file carries one). The convention is **checked**
rather than merely followed:
[`tests/test_vendor_baseline.py`](../tests/test_vendor_baseline.py) hashes every
vendored file against the fork-point manifest and requires the divergent set to
equal the set catalogued here.

It was not checked before, and it undercounted three ways. **Three files carried
no marker at all** — `Core/CMakeLists.txt`, `Core/dexkit/include/zip_archive.h`,
`Core/third_party/slicer/common.cc` — so a `grep dexllm` census saw 8 files where
there are 11. **Two further hunks in an already-marked file** were unmarked
(`ThreadPool.h`'s Emscripten blocks), so one divergence, D10, was marked in
`CMakeLists.txt` and not in the file that carries the rest of it. And **two
divergences, D13 and D14, were neither marked nor catalogued** — D13 not marked
at all, D14 marked but with no entry. Six markers were added in the change that
built this registry; both missing entries were found by review, not by the
census.

**At hunk granularity the convention is still incomplete, and the guard is
file-granular: 41 divergent hunks, 34 marked, 7 not.** Those 7 are honest rather
than sloppy: **2 are pure deletions with no added line that could carry a marker**
(D11's declaration and definition), and 5 are continuations of a divergence marked
elsewhere in the same file (an `#include <stdexcept>` for D1; the two `Abort*`
definitions, one `try` block and a second comment for D4).

The two deletions are the point: **an addition leaves a marker, a deletion leaves
nothing.** D11 and D7 are both invisible to any census of the current tree and
both visible to a manifest comparison. That is why the manifest, not the marker,
is the guard.

---

## U — upstreamable

### D1. `SLICER_CHECK` throws instead of aborting

- **Where:** `Core/third_party/slicer/common.cc` `_checkFailed`, both
  `_checkFailedOp` overloads (and the `<stdexcept>` include they need).
- **Upstream:** `log(buf); std::abort();` — still so at upstream HEAD.
- **Divergence:** `throw std::runtime_error(buf)`.
- **Why:** the slicer's checks fire on malformed dex, which is the input this
  product exists to read. Aborting turns one bad method into a dead process; a
  throw is caught per method and yields an empty decompile.
- **Predates the vendoring** — it is one of the three files that already
  differed at import (see `UPSTREAM`). It is the load-bearing assumption behind
  every "no crash on malformed dex" claim in CLAUDE.md and the README, and behind
  the totality guarantee in
  [`native/core_ext/include/dex_verifier.h`](../native/core_ext/include/dex_verifier.h),
  which now says so at the site.

### D2. `GetUncompressData` bounds the stored region

- **Where:** `Core/dexkit/include/zip_archive.h` `GetUncompressData`.
- **Upstream:** reads `e.comp_size` bytes at `e.data_offset` with no bound —
  `parse_cd_block` validated `lfh_offset` + header + name + extra and never the
  data extent. Still so at upstream HEAD.
- **Divergence:** an overflow-safe `data_offset + comp_size <= len` guard, plus a
  rejection of `uncomp_size > 4 GiB` (`MemMap`'s length is `uint32_t`, so the
  output buffer truncates while the STORE `memcpy` copies the full 64-bit
  length — an OOB **write**).
- **Why:** both are crafted-input OOBs on a path `DexKit(path)` reaches, found by
  adversarial review of `32dcecb`. No-op on valid input.

### D3. A pool destroyed on its own worker survives (dexllm#50, dexllm#55)

- **Where:** `Core/third_party/thread_helper/ThreadPool.h`.
- **Upstream:** the destructor joins every worker unconditionally; the worker
  lambda and the queued task capture `this`; the spawn loop is not
  exception-safe. Still so at upstream HEAD.
- **Divergence:** all shared state moved into a `shared_ptr<State>` the workers
  capture instead of `this`; the destructor **detaches** the one worker it is
  running on and joins the rest; the spawn loop joins what it built before
  rethrowing (`std::thread`'s constructor throws when the process is out of
  threads, and unwinding past a joinable thread is `std::terminate`); only the
  ids of threads that were actually joined have their matcher caches released.
- **Why:** a task can hold the last reference to its own pool, and joining the
  thread you are executing on is `std::system_error` "Resource deadlock avoided"
  — uncaught in a thread, so `std::terminate`. Reproduced 10/10 by a standalone
  program. Guarded by `thread_pool_selfdestruct_test` (the 29th ctest suite).
- The same file also carries D10, which is a separate divergence.

### D4. A cache-init failure reports instead of blocking forever (dexllm#55)

- **Where:** `Core/dexkit/dex_item.cpp` and `Core/dexkit/include/dex_item.h` —
  `AbortInitCache` **and** `AbortPutCrossRef` (both defined in `dex_item.cpp`),
  the failed-flag/error members, the `BeginInitCache` exclusion, the
  `WaitInitCache` throw; `Core/dexkit/dexkit.cpp` and
  `Core/dexkit/include/dexkit.h` — `AbortBuildCrossRefAggregates` and
  `EnterQueryExecution`'s cleanup.
- **Upstream:** the ready flag is published only on the success path, the future
  is discarded, and `WaitInitCache` is a `cv.wait` with no failure state — so a
  task that throws leaves every waiter blocked **forever**, silently. Still so at
  upstream HEAD (no `AbortInitCache`).
- **Divergence:** each claim/publish state machine gains a failure half; the
  matching `Wait*` waits on `(ready | failed)` and throws with the recorded
  reason; a failed flag is sticky so a retry reports instead of re-running work
  known to throw.
- **Why:** reachable from a `verify()`-valid dex. Fixes a permanent hang, which
  is the strongest upstreamable case in the tree.

### D5. Instruction operands are bounded at collection

- **Where:** `Core/dexkit/dex_item.cpp` — `InitCache` (the string, field and
  method operand bounds, all three inside its instruction walk) and
  `GetUsingStringsFromCode` (two `strings.size()` guards). Not
  `InitBaseCache`, which an earlier draft named: it holds D7 and D9 and no
  bound at all. The method-operand bound sits one line under D14's opcode
  test, in the same hunk — two divergences, one marker.
- **Upstream:** indexes the string / field / method tables with the raw operand.
- **Divergence:** each index is bounded and an out-of-range operand is dropped.
- **Why:** `lenient=True` skips `VerifyInsns`, so a partially-decrypted packer
  dump reaches these collectors with unvalidated operands — a 32-bit
  `const-string/jumbo` index SEGV'd the string pool. No-op on strict-verified
  input.
- An earlier draft also named `GetClassStrings` / `GetMethodStrings` here. **No
  such functions exist anywhere in the repository**; the forward string accessors
  it was reaching for are `DexKitExt::ListClassStrings` / `ListMethodStrings`,
  which live in `native/core_ext/dexkit_ext.cpp` and are not a divergence at all.

### D6. `encoded_value` 0x15 / 0x16 are parsed (dexllm#57)

- **Where:** `Core/third_party/slicer/export/slicer/dex_format.h`
  (`kEncodedMethodType`, `kEncodedMethodHandle`),
  `Core/third_party/slicer/export/slicer/dex_ir.h` (two union members),
  `Core/third_party/slicer/reader.cc` (two cases),
  `Core/dexkit/dex_item.cpp` `GetAnnotationEncodeValueBean` (the `default:` arm
  now assigns rather than leaving `type` indeterminate).
- **Upstream:** both codes fall to `SLICER_CHECK(!"unexpected value type")` —
  the header predates invoke-dynamic. Still so at upstream HEAD, and **AOSP's
  own slicer has the same gap**.
- **Divergence:** both are read as `(arg+1)`-byte indices and resolved through
  `GetProto` / `GetMethodHandle`. Read-only: the writer has no case for either.
- **Why:** both are legal per the dex spec (API 26+), so upstream's behaviour is
  a throw on a valid dex — and the `default: break` left `bean.type`
  uninitialised, which is undefined behaviour.

### D11. `GetInvokeMethodsFromCode` removed (dexllm#61)

- **Where:** `Core/dexkit/include/dex_item.h:169` — a tombstone comment in the
  `public:` section beside `EnumerateInvokeSites`; the declaration it records
  was in `private:` (fork-point line 221) and the definition is gone from
  `Core/dexkit/dex_item.cpp`. The tombstone is deliberately next to the two
  live functions that answer the same question, not at the old address.
- **Upstream:** still present, and still with **no caller** (it had none in the
  import snapshot either).
- **Divergence:** deleted.
- **Why:** it selects invoke sites by instruction FORMAT (`k35c`/`k3rc`), which
  also admits `filled-new-array` (a *type* index, 624 live corpus sites),
  `invoke-virtual-quick` (a vtable offset) and `invoke-custom` (a call-site
  index) — so had it ever been called it would have asserted that a method calls
  a method it does not. It is a strictly worse third implementation of a question
  two live functions already answer.
- **Treatment U, and an earlier draft had this wrong.** It was filed under **P**,
  which by this registry's own definition means an extension hook or a product
  decision — a deletion of dead, wrong upstream code is neither. Deleting it is
  exactly the kind of change upstream could take.
- **A deletion is the least visible divergence there is.** Nothing in the current
  tree distinguishes "upstream never had this" from "we removed it" except the
  tombstone, and its two hunks are the ones that structurally cannot carry a
  marker.

### D13. Duplicate class declarations resolve first-wins (dexllm#65, found by review)

- **Where:** `Core/dexkit/dexkit.cpp` `DexKit::PutDeclaredClass`.
- **Upstream:** `class_declare_dex_map[class_name] = {dex_id, type_idx};` — an
  unconditional overwrite. Still so at upstream HEAD.
- **Divergence:** insert if absent, otherwise replace only when
  `dex_id < it->second.first`, i.e. keep the **lowest dex_id**.
- **Why:** `DexItem` construction runs in parallel, so an unconditional overwrite
  makes the winner depend on completion order — non-deterministic across runs on
  the same input, which is a gate this project markets. First-wins-by-load-order
  also matches ART (`DexPathList.findClass` returns the first dex that defines
  the class), and it is what makes `add_dumped_dexes(prefer=True)` mean anything:
  a dumped dex is listed first precisely so its class wins. Introduced by
  `1b7b38d`, 2026-06-12.
- **This entry exists because a reviewer found it, and it is the counter-example
  to this registry's own headline claim.** It carried no marker and no entry
  while the change that created the registry said every divergence was recorded.
  The manifest saw the *file* (`dexkit.cpp` is divergent for D4 anyway), so
  file-granularity is exactly the limit stated above, demonstrated rather than
  hypothesised.

### D14. The invoke collector admits `invoke-polymorphic` (dexllm#61, found by review)

- **Where:** `Core/dexkit/dex_item.cpp` `InitCache`, the `need_method_invoking`
  opcode test — `|| op == 0xfa || op == 0xfb`.
- **Upstream:** `(op >= 0x6e && op <= 0x72) || (op >= 0x74 && op <= 0x78)` only,
  at the baseline and still at upstream HEAD.
- **Divergence:** the two `invoke-polymorphic` opcodes are admitted; the two
  `invoke-custom` opcodes (0xFC/0xFD) are deliberately NOT, because their BBBB is
  a `call_site` index rather than a `method_ids` one.
- **Why:** without them a `MethodHandle.invoke` call site reached neither
  `method_invoking_ids` nor `method_caller_ids`, so `find_call_sites_to` answered
  **0** for a target the dex plainly calls — and every consumer built on the
  caller index inherited the blindness. This is the live half of dexllm#61; D11
  is the dead half.
- **Found by the same review that found D13**, in a hunk that already carried a
  marker for D5 (the bound one line below it). Two divergences in one hunk is the
  file-granularity limit at its smallest, and it is why this registry's
  completeness claim is stated as a limit rather than as a guarantee.

---

## C — converged with upstream

### D7. Method access flags are the raw dex bits

- **Where:** `Core/dexkit/dex_item.cpp` `InitBaseCache` (both method loops),
  `Core/dexkit/include/dex_item.h` `GetMethodAccessFlags`.
- **Upstream at the baseline:** rewrote `ACC_DECLARED_SYNCHRONIZED` (0x20000) to
  `ACC_SYNCHRONIZED` (0x20) for `java.lang.reflect.Modifier` compatibility.
- **Divergence:** the rewrite is REMOVED; the dex's own bits are stored verbatim.
- **Why:** the rewrite is lossy (0x20 means `synchronized native` in dex, a
  different property) and it made one method describe itself two ways —
  `get_class_summary` said `synchronized` while `decompile_class` said
  `declared_synchronized`.
- **Upstream status: CONVERGED.** Upstream removed the same rewrite in
  `42b30c4` ("feat(core)!: expose raw DEX access flags", 2026-08-02) — four days
  *before* dexllm did. On the next rebase this entry disappears and the two
  trees agree. Note that `42b30c4` also rewrites the vendored `README.md` and
  `README_zh.md` to document the new behaviour, so a rebase that takes only its
  `Core/` half leaves those READMEs describing behaviour neither tree has.

This is the entry that justifies the whole issue. dexllm#65 classified this
bucket as **permanent**, reasoning that "upstream wants `Modifier`
compatibility, which is exactly what this removed". Without a baseline there was
no way to see that the premise had already stopped being true.

---

## P — permanent

### D8. Extension hooks

- **Where:** `Core/dexkit/include/dex_item.h` — the L1 (`GetReader`,
  `GetTypeNames`, `GetStrings`, `GetTypeDefFlags`), L1.5 (`GetClassMethodIds`,
  `GetClassFieldIds`, `GetTypeDefIdx`, `GetMethodAccessFlags`,
  `GetFieldAccessFlags`), L2 (`GetMethodInvokingIds`), L2.5
  (`GetMethodCallerIds`, `EnumerateInvokeSites`), L5 (`RenderMethodSmali`,
  `RenderClassSmali`) and L8 (`GetMethodCode`) accessors, plus dexllm#20's
  hoisting of `IsStringMatched` from private.
- **Why permanent:** `native/core_ext/` is an adapter over private core state.
  Upstream is a query library whose C++ core is an implementation detail behind
  a FlatBuffers/JNI boundary; it has no reason to expose these.
- **Present at import** — they are the bulk of the 689 pre-vendoring lines.
- The two L5 accessors are the declaration half of D12, so if that reduction is
  ever done they leave with it.

### D9. Declared vs referenced members (dexllm#41, dexllm#45)

- **Where:** `Core/dexkit/dex_item.cpp` `InitBaseCache` (the
  `field_access_flags_declared` bitvector and its two writes) and
  `Core/dexkit/include/dex_item.h`.
- **Upstream:** `class_field_ids` is keyed on the whole `field_ids` table grouped
  by the class named in the *reference*, and the access-flag slots default to 0.
- **Divergence:** a parallel bitvector records which slots a `class_data` walk
  actually wrote, so dexllm can tell "declared package-private" (a legal 0) from
  "never declared here".
- **Why permanent-ish:** upstream is a *search* library, where matching an
  inherited reference is arguably correct; dexllm built declaration-shaped APIs
  (`get_class_summary`, `render_class_smali`) on a reference-shaped index. Parts
  may be upstreamable as an additional accessor rather than a behaviour change.

### D10. Emscripten single-threaded build

- **Where:** `Core/CMakeLists.txt` (skip `-pthread` under Emscripten) and
  `Core/third_party/thread_helper/ThreadPool.h` (launch no workers and drain
  inline under `__EMSCRIPTEN__ && !__EMSCRIPTEN_PTHREADS__` — three blocks).
- **Why permanent:** it exists because GitHub Pages cannot serve the COOP/COEP
  headers `SharedArrayBuffer` needs. That is a deployment fact about dexllm's
  web demo, not about DexKit. Guarded to a no-op on native builds.

---

## R — reduction candidates

### D12. The smali renderer and `EnumerateInvokeSites` live in `dex_item.cpp`

- **Where:** `Core/dexkit/dex_item.cpp`, lines 1459-2018 —
  `EscapeSmaliString`, `SmaliIdent`, `FormatAccessFlags`,
  `FormatFieldAccessFlags`, `FormatMethodAccessFlags`, `FormatProto`,
  `FormatMethodRef`, `FormatFieldRef`, `EmitRegisterRange`, `FormatOperands`,
  `RenderMethodSmali`, `RenderClassSmali`, `EnumerateInvokeSites`.
- **Upstream:** **none of these functions exists**, under any name.
- **Size:** 560 lines, about 44% of everything this fork adds, and the single
  largest divergence in the tree.
- **Why it is a reduction candidate:** this is a wholly dexllm subsystem, and it
  is where most of dexllm's own later work landed — the MUTF-8 decode-then-escape
  fix (dexllm#22 / dexllm#23), the `invoke-polymorphic` formats (dexllm#60), the
  index-kind labels (dexllm#66), the invoke opcode set (dexllm#61). Every one of
  those is a dexllm change to dexllm code that happens to sit inside a vendored
  file, so it collides with upstream on every rebase for no reason.
- Moving it out is the dexllm#32 pattern exactly: that change took 858 lines of
  `AnalyzeMethodInvokes` out to `native/core_ext/invoke_args.cpp` and found the
  whole input was two already-public accessors (`GetMethodCode()`,
  `GetImage()`). **This entry read "the renderer's inputs look similar" until the
  intersection was actually taken, and the hedge was weaker than the evidence:**
  of `DexItem`'s 70 private members, the span touches **9** — `reader` (27 uses),
  `type_names` (26), `strings` (15), `method_codes` (6),
  `field_access_flags_declared` (3), `class_field_ids` (2), `type_def_idx`,
  `type_def_flag`, `class_method_ids` — and **every one already has a public
  accessor** (`GetReader` / `GetTypeNames` / `GetStrings` / `GetMethodCode`,
  which bounds the index exactly as the span does / `GetFieldAccessFlagsDeclared`
  / `GetClassFieldIds` / `GetTypeDefIdx` / `GetTypeDefFlags` /
  `GetClassMethodIds`). Nine accessors instead of dexllm#32's two; nothing
  private is reached. Not attempted here — it is a refactor with its own a/b, not
  part of recording a baseline — and it is filed as **dexllm#80**, which also
  states what the move does NOT buy: several of those accessors are themselves
  D8 hooks, so moving the renderer out shrinks D12, not D8.

---

## Not proposed

De-vendoring — treating DexKit as an external dependency — is not on the table.
D8 alone requires reading private core state, and D9 is a behaviour change
upstream has no reason to want in that form. (Not D7 — upstream made that
same change itself.)

## What this registry does not do

It records **where** the trees differ and **what kind** of difference each is. It
does not upstream anything, and it does not pick up the three upstream fixes the
baseline revealed dexllm is missing (`6ca92c3`, `47f7324`, `7415df9` — see
`UPSTREAM` for each one's reachability verdict). Those are step 3 of dexllm#65
and need their own change with its own a/b.

Step 3 is now filed rather than merely deferred, one issue per bucket:
**dexllm#79** proposes the nine **U** entries upstream, **dexllm#80** moves
**D12** (**R**) out of the vendored tree, and **dexllm#81** picks up the three
fixes above — in which **D7** (**C**) disappears, the one entry a rebase must
*drop* rather than carry.
