# AOSP OOB-prevention divergences — decision registry

**Status: OPEN — collected for a later keep/remove decision (2026-06-19).**

This file catalogs every point where dexllm's behavior diverges from its AOSP/ART
(or slicer) reference **specifically to prevent an out-of-bounds read** on
malformed or truncated input. None of these change output on a *valid* dex — they
only differ on input the reference would over-read on.

The recurring question for each: now that the load-time structural verifier
([`VerifyDex`](../native/core_ext/include/dex_verifier.h)) gates every loaded dex,
is the guard **redundant** (the verifier already guarantees the precondition that
makes the unchecked AOSP code safe) — in which case it's a removal candidate per
the "trust the verifier, drop redundant in-decode guards" policy
([CLAUDE.md](../CLAUDE.md) "Snapshot ABI") — or is it a **leaf self-defense**
worth keeping (the `SafeWidth` precedent: a safe-wrapper around an OOB-by-design
primitive, justified independent of caller provenance)?

Key fact for all "Type A" entries below: **string/IR output on any valid dex is
byte-identical to the unchecked AOSP reference.** The guard is invisible except on
malformed input the verifier already rejects. So these are *not* fidelity
limits — they are purely a memory-safety-layering choice.

---

## Type A — safe-wrappers that diverge from an AOSP/slicer function

These add a bounds check the AOSP reference function omits. They are the genuine
"diverge from AOSP because of OOB" cases and the real subjects of the
keep-vs-remove decision.

### A1. MUTF-8 decode — `cont()` bound in `GetUtf16FromUtf8`

- **Where:** [`native/dad_cpp/mutf8.cpp`](../native/dad_cpp/mutf8.cpp) `GetUtf16FromUtf8`.
- **AOSP reference:** `art/libdexfile/dex/utf-inl.h:32 GetUtf16FromUtf8` +
  `utf.cc:112 ConvertModifiedUtf8ToUtf16(out, out_chars, in, in_bytes)`. ART reads
  the N-1 continuation bytes of a multibyte sequence **without bounds checks** —
  safe in ART because its input is NUL-terminated and `DexFileVerifier`-validated
  (every sequence complete).
- **Our divergence:** a `cont()` check (`*data < end && (**data & 0xC0) == 0x80`)
  before each continuation read; on a truncated/invalid sequence we return the
  lead byte as a lone code unit instead of reading past `end`.
- **Verifier coverage:** [`VerifyMutf8`](../native/core_ext/dex_verifier.cpp)
  (`dex_verifier.cpp:484`) rejects truncated 2/3-byte sequences, stray
  continuation bytes, 4-byte forms, and non-NUL-terminated string_data. So for a
  **verified** string the guard is strictly redundant — `cont()` is always true.
- **Provenance risk if removed:** `Mutf8ToUtf16` / `EscapeJavaString` are exported
  `dad_cpp/` utilities. Today's callers (const-string literals, type descriptors,
  identifiers) are all verified string_data, but a future caller passing an
  unverified/pool-external string would OOB.
- **Output impact:** none. 300k well-formed inputs byte-identical to pre-guard;
  4000 random well-formed streams 0-mismatch vs an inline copy of ART's
  `GetUtf16FromUtf8` (`mutf8_parity_test.cpp`, 28th ctest suite).
- **Assessment:** redundant-given-verifier, but the direct `SafeWidth` analogue
  (safe-wrapper around an OOB-by-design AOSP primitive). **Currently KEPT.**
  Decision pending.

### A2. Instruction width — `SafeWidth` around `GetWidthFromBytecode`

- **Where:** [`native/dad_cpp/method_snapshot_builder.cpp:148`](../native/dad_cpp/method_snapshot_builder.cpp) `SafeWidth`.
- **Reference:** the slicer's `dex::GetWidthFromBytecode(p)` dereferences a
  payload size field (`p[1]` for packed/sparse-switch, `p[1..3]` for
  fill-array-data) — it **OOB-reads by design** on a payload marker near the
  buffer end.
- **Our divergence:** `SafeWidth` validates the payload header units fit
  (`PayloadHeaderUnits`) and the full instruction fits (`p + w <= end`) before/after
  the slicer call; throws `std::runtime_error` on truncation → the per-method
  try/catch yields an empty decompile, not a crash.
- **Verifier coverage:** `VerifyInsns` (see B1) now validates instruction/payload
  bounds at load, so in production `SafeWidth` should never trip.
- **Assessment:** explicitly KEPT in CLAUDE.md as "NOT redundant" — wraps a
  primitive (the third-party slicer) whose internal reads we don't audit. Lowest
  removal priority.

### A3. Data-range base — refuse the `header_offset` underflow

- **Where:** [`native/core_ext/dex_verifier.cpp`](../native/core_ext/dex_verifier.cpp)
  `DexVerifier::ComputeDataRange` (added for dexllm#25).
- **AOSP reference:** `art/libdexfile/dex/dex_file.cc:240 DexFile::GetDataRange`,
  which for a v41 container does `data -= headerV41->header_offset_;` with the
  comment *"Allow underflow and later overflow"* and clamps afterwards with
  `std::min<size_t>(size, container->End() - data)`. That clamp does not restore
  the LOW end: a `header_offset` larger than the header's own position in the
  container leaves `data` **before** the container start.
- **Our divergence:** we are handed the image base explicitly, so the underflow is
  a rejection (`"Dex container starts before the image"`) instead of a pointer
  outside the mapping. ART reaches an equivalent verdict one phase later
  (`CheckHeader`'s `container_size_ <= header_offset_` block, `:670`, which we also
  port), but only after `GetDataRange` has already produced the bad pointer.
- **Output impact:** none on any dex the ART check would accept — the two reject
  the same inputs, ours just refuses before constructing the pointer.
- **Assessment:** leaf self-defense, same family as A1/A2. **KEPT.**

### A4. Data-range size — reject an over-long `container_size` instead of clamping

- **Where:** [`native/core_ext/dex_verifier.cpp`](../native/core_ext/dex_verifier.cpp)
  `DexVerifier::ComputeDataRange` (added for dexllm#25).
- **AOSP reference:** the same `GetDataRange`, which ends with
  `std::min<size_t>(size, container->End() - data)` — a v41 `container_size`
  pointing past the file is silently **clamped** to what is there.
- **Our divergence:** we reject it (`"Dex container size is past the image"`).
- **Why, and why this one is NOT just belt-and-braces:** the slicer — the parser
  that actually reads our dexes — does **not** clamp. `Reader::ValidateHeader`
  asserts `SLICER_CHECK_LE(ContainerSize() - ContainerOff(), size)`. So a clamped
  accept means `verify()` reports a dex as loadable and the loader then throws on
  it, breaking the documented `verify()` ≡ `verify_report()` equality. Found by
  adversarial review with `container_size = 0xFFFFFF00`.
- **Output impact:** none on a well-formed container (`container_size` never
  exceeds the container). AOSP's `art/test/dexdump/multidex-container.dex` still
  verifies and loads both dexes.
- **Assessment:** deliberate, motivated by the parser we actually pair with rather
  than by ART's. **KEPT.**

---

## Type B — validation ADDED beyond AOSP's structural scope

### B1. `VerifyInsns` — instruction-operand bounds

- **Where:** [`native/core_ext/dex_verifier.cpp:616`](../native/core_ext/dex_verifier.cpp) `VerifyInsns`.
- **AOSP:** ART's *structural* `DexFileVerifier` does **not** check
  instruction-operand bounds (register/index/branch/switch/array-data targets);
  those live in the 6032-line *runtime* `method_verifier` ART refuses-to-vendor
  territory.
- **Our divergence:** we ADD a bounded operand checker anchored to the Dalvik
  bytecode spec (slicer `VerifyFlags`/`IndexType` tables). This is an *addition*,
  not a guard-on-an-AOSP-function — it is the deliberate one-line non-port called
  out in `dex_verifier.h`.
- **Known cost, and the shape it takes (dexllm#58):** an ADDED check can only
  fail in one direction ART's own verifier cannot — by rejecting a dex ART
  accepts. It happened: the vararg-register loop read `Instruction::arg[]` for
  every opcode carrying `kVerifyVarArg`, which is where the argument registers
  live for `35c` and NOT for `45cc` (`invoke-polymorphic`), whose `arg[4]` holds
  a second index (proto@HHHH) and whose first argument register lives in `vC`.
  The window was shifted by one at EVERY arity — `vC` unchecked at the front, one
  slot too many at the end — and at `A == 5` that extra slot IS the proto index,
  so an unmodified AOSP dex (`tools/dexter/testdata/method_handles.dex`, two such
  sites, proto 82/91 against 5 registers) was refused outright. Fixed by branching
  on the instruction FORMAT; the durable lesson is in `dex_verifier.h`'s
  divergence paragraph — an operand check must be read against the decoder's
  per-format layout, not against the flag's name.
- **Assessment:** intentional, foundational to the "0-crash on malformed dex"
  contract. Not a removal candidate — listed here for completeness because its
  purpose is OOB prevention.

### B2. ~~`IsDataSectionType` excludes three types ART includes~~ — CLOSED (dexllm#62)

- **Where:** [`native/core_ext/dex_verifier.cpp`](../native/core_ext/dex_verifier.cpp)
  `IsDataSectionType`, consumed only by `CheckMap`'s alignment branch.
- **What it was:** ART's `dex_file_verifier.cc:82` returns **true** for
  `kDexTypeCallSiteIdItem` (:92), `kDexTypeMethodHandleItem` (:93) and
  `kDexTypeMapList` (:94) — only the header item and the six `*_id` tables are
  false. This port had all three in its *false* arm, so the alignment check never
  reached them and a **misaligned** section offset was ACCEPTED where ART rejects
  it. Never memory safety (dexllm#57's extent bound spans both fixed-size sections
  whatever their alignment, and an unaligned `u2`/`u4` load is harmless on every
  supported target) — spec fidelity.
- **Resolved:** the three cases were dropped, so the predicate is now byte-for-byte
  ART's. **Measured (a/b OFF vs ON, same script, both `.so` md5-verified):** 58
  real sources / 439 axis records — the whole bundled corpus, both committed
  fixtures, every `art/test/dexdump/*.dex` and the dexter testdata dexes — **0
  changed, 0 false-reject**. 41 of 84 crafted sources flip to `Misaligned map
  item`. A format-level census over **1,413 logical dexes in 1,256 containers**
  (the whole local AOSP tree plus the corpus) finds exactly **one** item the new
  rule rejects, and it is an ART **dex-verifier fuzz-corpus** input
  (`art/tools/fuzzer/dex-verifier-corpus/b391842969.dex`) — a real, unmodified
  file that ART rejects at the identical check, and the strongest single piece of
  evidence for the fix.
- **One claim the controls corrected:** `map_list` looked like a no-op, because
  `CheckHeader`'s `CheckValidOffsetAndSize(map_off, …, 4, "map")` runs first. It
  covers the HEADER field only — the map_list item's own **self-referential**
  offset is a separate `u4` nothing compares against it, and misaligning that one
  was accepted before and is rejected now (27 crafted sources).

### B2b. ART's `data_items_left` budget is not ported

> **Category note:** B2 and B2b sit under a "validation ADDED beyond AOSP" heading
> but are both validations **OMITTED** relative to AOSP. The miscategorisation is
> inherited from B2's original filing; kept here so the IDs stay stable rather
> than renumbering the whole document.

- **AOSP:** `dex_file_verifier.cc:777` — `CheckMap` keeps a running budget seeded
  from the data segment's byte size and subtracts every data section's item
  COUNT, rejecting when the sum exceeds it. A coarse sanity bound (each item is
  at least one byte), reachable only through `IsDataSectionType`.
- **Our divergence:** no equivalent exists anywhere in the port. ART has a THIRD
  call site too — `:2354`, in `CheckIntraSectionIterate`, which rejects a
  data-section item at offset 0 (`:2356`) and fills `offset_to_type_map_`. Also
  unported, and for a structural reason: this port has no map-driven intra pass
  (see D1 / `dex_verifier.h`). dexllm#62 widened the predicate to ART's own set,
  which does not bring either consumer with it.
- **Assessment:** deliberately **KEPT**, decided while closing B2 rather than
  inherited. This port is REFERENCE-driven and consumes `item->size` for exactly
  the two fixed-size sections the header does not describe — where `CheckMap`'s
  per-section BYTE-SPAN bound (dexllm#57) is strictly tighter than a running item
  budget — while for every variable-length section the count is never read at
  all, so an absurd one is inert. Porting it would be a pure new rejection
  direction with no reachable defect behind it, and a new rejection direction is
  the one way an added check can fail (dexllm#58).

### B2c. The `0x16` encoded_value's method_handle index — CLOSED (dexllm#72)

> Same category note as B2/B2b: an OMISSION filed under an "ADDED" heading.

- **AOSP:** `dex_file_verifier.cc` `CheckEncodedValue`, the
  `kDexAnnotationMethodHandle` arm — `:1204` rejects `value_arg > 3` ("Bad
  encoded_value method handle size") and `:1212` bounds the decoded index against
  `NumMethodHandles()`. ART's `CheckInterCallSiteIdItem` applies the same bound to
  a call site's first element (`:3119`); that one belongs to call_site CONTENTS
  (C3's family) and stays out of scope.
- **What it was:** `VerifyEncodedValue`'s `case 0x16` was `skip(arg + 1)` — it
  consumed the payload and checked neither half. Every other index-bearing arm
  gets the width cap for free from the shared `idx` lambda, so `0x16` was the one
  arm where an EIGHT-byte "index" was gate-legal; dexllm#71's lockstep guard is
  parametrised around exactly that asymmetry, which is now gone.
- **Resolved:** the arm is
  `case 0x16: return idx(method_handle_count_, "encoded method_handle idx");`, so
  both ART checks arrive together. `method_handle_count_` is ART's
  `NumMethodHandles()` — the count lives ONLY in the map (it is not a header
  field), so `CheckMap` carries it forward, which is why this had to wait for
  dexllm#59 to put the section itself in scope. 0 when the dex declares no
  method_handle section, which is exactly ART (`dex_file.cc` :159 zero-inits it,
  :290 assigns it only from a `kDexTypeMethodHandleItem` map entry).
- **Measured (a/b OFF vs ON, same script, both `.so` md5-verified):** 112 sources
  / 805 axis records — the whole bundled corpus, every committed fixture, every
  `art/test/dexdump/*.dex`, every `tools/dexter/testdata/*.dex`, every ART
  fuzzer-corpus dex, and 20 crafts — **8 changed, ALL crafted, 0 REAL**. The
  boundary is EXACT (index `count - 1` accepted, `count` rejected) and widths 0..3
  are untouched while 4..7 flip to `encoded_value bad index size`.
- **It RETIRED a test vehicle, and that is the cost of record.**
  `tests/test_cache_init_failure.py` (dexllm#55) crafted this very value on a
  section-less dex, where the index is out of range by construction. That file and
  CLAUDE.md both called the channel one *"no future verifier improvement can take
  away, because closing it at the gate would be a false-reject"* — ART `:1212`
  refutes that, and dexllm#59 measured it. An exhaustive retype sweep (every bare
  corpus dex × all 32 type codes, width-preserving) shows `0x16` was the LAST
  crafted-dex channel that verified and then threw in cache init: **2 of 64 before,
  0 after**, with 1,700 random mutations across every map section and a lenient
  instruction fuzz finding none either. So there was no third vehicle to move to —
  see that file's docstring for what was retired and why.

### B2d. A per-image memo and entry budget for the method_handle walk (dexllm#59)

> Same category note as B2/B2b/B2c — except this one really is an ADDITION.

- **AOSP:** no analogue. ART's nearest thing, the `data_items_left` budget
  (`:751`, unported as B2b), is seeded at `:731` from `dex_file_->Begin()` to
  `EndOfFile()` for a **v41** dex — a GEOMETRIC span, not `header_->data_size_` —
  so an early slice's budget is ~the whole container and ART is quadratic here
  too. (An earlier draft of this entry said the seed was a per-dex `data_size` a
  crafted slice could inflate. Both delta reviewers read the AOSP source and
  disproved it; the conclusion survives, the mechanism was wrong.)
- **Our divergence:** `VerifyImageState`, threaded by `ClassifyImageSlices` across
  the slices of ONE image. A memo keyed on a section's BYTES — `(offset, count)`
  — storing the two maxima the walk found, plus a running entry budget seeded from
  `image_size / 8 + 1`.
- **Why it exists.** dexllm#59 walks the section's CONTENTS, and for a **v41
  CONTAINER** that walk is quadratic: `ComputeDataRange` gives EVERY slice the
  whole container as its span while `LogicalDexSlices` strides by `file_size`, so
  one shared section is walked once per sibling and `count` is bounded by the
  container rather than by the slice. Measured on a crafted container of
  bare-header slices sharing one map: 2/4/8/16 MB → 0.34 / 1.29 / 5.19 / 20.59 s
  where HEAD pays 0.00 / 0.01 / 0.02 / 0.04 s — quadrupling per doubling, with
  every slice rejected either way, so the delta is nothing but the walk. The work
  is paid BEFORE the rejection and it is reachable from the load-free public
  `dexllm.verify(path)`. Post-fix the same crafts measure HEAD's numbers.
- **Why it rejects (almost) nothing.** The memo changes no verdict at all — its
  O(1) re-check of a later slice's own tables is exactly equivalent to
  re-walking, since "every index < limit" is "max index < limit". Only the budget
  can reject, and a legitimate image cannot reach it: real sections occupy
  DISJOINT bytes, so their entries sum to at most `image / 8`, and a SHARED one
  is counted once. What exhausts it is overlapping sections at distinct offsets,
  i.e. the same bytes charged many times — a craft.
- **What this REPLACED, and why.** The first cut bounded `count` by the slice's
  own `file_size / 8`. A delta reviewer refuted it by construction: starting from
  AOSP's own `multidex-container.dex`, appending a shared section and nothing
  else, the crossover is exactly that bound — **70 entries accepted, 71
  rejected** — and the v41 sibling rule then takes the whole container down. Its
  justification ("N distinct handles imply id tables of at least 8N bytes inside
  `file_size`") assumed handles are DISTINCT, which nothing enforces, and assumed
  the tables sit INSIDE `file_size`, which is exactly what a container does not
  guarantee: in that same sample slice 0 has `file_size` 564 and `string_ids_off`
  684. Sharing is the point of the format.
- **Assessment:** deliberately KEPT — removing either half reopens a DoS on a
  public, load-free entry point. Plain concatenation (dexllm#25) needs neither
  and is self-limiting: there `stride == file_size == size_`, so the sum is
  already bounded by the image (measured: a 16 MB concatenated craft with every
  count maxed verifies in 0.001 s).

---

## Type C — internal null/index guards (not AOSP-function divergences)

These guard snapshot/IR data at internal boundaries. They don't diverge from a
specific AOSP function (the analogous DAD Python raises an exception or relies on
CPython bounds), but they exist for memory safety and are part of the same
"don't crash on malformed input" posture.

### C1. CFG edge index guards

- **Where:** [`native/dad_cpp/graph.cpp:685` / `:713`](../native/dad_cpp/graph.cpp)
  — `edge.target_block_id >= nodes.size()` / `ci.handler_block_id >= nodes.size()`
  → `continue` (skip the dangling edge).
- **Why:** snapshot-supplied block ids index `nodes[]`; a malformed/synthesized id
  would OOB. DAD relies on Python dict/list semantics; we guard explicitly.

### C2. `MoveExpression` null-operand guard

- **Where:** [`native/dad_cpp/instruction.cpp:273`](../native/dad_cpp/instruction.cpp).
- **Why:** `move-result` with no preceding `invoke` leaves an operand null. DAD
  raises `AttributeError` on `None.get_type()` and the caller skips the method; we
  throw to match (a segfault would be the divergence). This *matches DAD's
  effective behavior* — included as a memory-safety guard, not an AOSP divergence.

### C3. `encoded_value` index bounds in `DecodeEncodedValueText` (dexllm#71)

- **Where:** [`native/core_ext/dexitem_code_source.cpp`](../native/core_ext/dexitem_code_source.cpp)
  — the `0x17` / `0x18` / `0x19` / `0x1b` arms: `if (idx >= table.size()) return {};`
  before the subscript. (The `0x15` / `0x16` / `0x1a` / `0x1d` arms already had one.)
- **Why:** `VerifyEncodedValue` bounds every index it accepts, so this is
  redundant — but only while the decoder walks the array in LOCKSTEP with the
  gate. A wrong consumed width for one element makes every later index
  attacker-controlled, and dexllm#70's over-consume mutants showed that is a
  SIGSEGV rather than a wrong answer. Lockstep is itself pinned, per type code and
  per accepted `value_arg`, by
  [`tests/test_encoded_value_lockstep.py`](../tests/test_encoded_value_lockstep.py).
- **Not an AOSP divergence:** ART has no analogous decoder here (this renders Java
  text); the bound is the reader tier the safety contract permits for values whose
  validity is established elsewhere, the same tier dexllm#66 / dexllm#67 chose.

### C4. `encoded_value` recursion depth caps (dexllm#71)

- **Where:** [`native/core_ext/dexitem_code_source.cpp`](../native/core_ext/dexitem_code_source.cpp)
  (`kEncodedValueMaxDepth`) and
  [`native/core_ext/dexkit_ext.cpp`](../native/core_ext/dexkit_ext.cpp)
  (`kScanMaxDepth`) — both 16, the gate's own `kMaxDepth`, applied at the same
  cutoff (a top-level value is depth 0, so a 17th nested level is refused by both).
- **Why:** the 0x1c/0x1d arms recursed with no depth of their own, under a comment
  saying the gate's cap "bounds this walk too". Same conditional promise as C3: in
  lockstep it does; on a desync the nesting is bounded only by `end - p`, i.e. one
  stack frame per 0x1c byte — an uncatchable SIGSEGV of the emit-walk /
  ShortCircuitStruct family. A correctness reviewer pointed out it was the one
  instance of that promise the change had left undone.
- **Not an AOSP divergence:** same as C3.

---

## Decision framing (for later)

| ID | Diverges from AOSP fn | Redundant given verifier | Output impact | Removal candidate |
|----|----|----|----|----|
| A1 mutf8 `cont()` | yes (ART `GetUtf16FromUtf8`) | yes (VerifyMutf8) | none | **yes — under review** |
| A2 `SafeWidth`     | yes (slicer width)         | yes (VerifyInsns)  | none | low (3rd-party primitive) |
| B1 `VerifyInsns`   | no (addition)              | n/a (IS the verifier) | n/a | no |
| B2 `IsDataSectionType` | ~~yes~~ **none** | n/a (IS the verifier) | ~~accepts a misaligned call_site/method_handle offset~~ | **CLOSED — dexllm#62** |
| B2d method_handle walk memo + budget | **yes** (an ADDITION; ART has no analogue) | n/a (IS the verifier) | none — the memo changes no verdict, and a legitimate image cannot exhaust the budget | no (removing either half reopens a v41 DoS) |
| B2c `0x16` handle index | **yes** (ART :1204 width cap, :1212 index bound) | n/a (IS the verifier) | **CLOSED** (dexllm#72) — `idx(method_handle_count_, …)` | n/a — ported |
| B2b `data_items_left` | **yes** (ART :777 budget) | n/a (IS the verifier) | none — the count is never consumed for a variable-length section, and the fixed-size ones have a tighter span bound | no (deliberate) |
| C1 edge index      | no (DAD relies on Python)  | partial            | none | no (cheap, internal) |
| C2 move-result null| no (matches DAD effective) | n/a                | none | no |
| C3 encoded_value idx | no (no AOSP analogue) | yes (VerifyEncodedValue) — but only while the decoder stays in lockstep with it | none (0-diff a/b) | no (defence in depth; the gate's promise is conditional) |
| C4 encoded_value depth | no (no AOSP analogue) | yes (VerifyEncodedValue kMaxDepth) — same conditional promise as C3 | none (0-diff a/b; cutoff verified equal to the gate's) | no (same reason) |

The live question is **A1** (and by extension the policy for A2): keep the leaf
decoder self-defending (SafeWidth precedent, provenance-independent), or remove
the guard for pure ART 1:1 and rely solely on the verifier. Both are defensible;
output is identical either way on valid input. Deferred per 2026-06-19 decision.
