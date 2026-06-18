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
- **Assessment:** intentional, foundational to the "0-crash on malformed dex"
  contract. Not a removal candidate — listed here for completeness because its
  purpose is OOB prevention.

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

---

## Decision framing (for later)

| ID | Diverges from AOSP fn | Redundant given verifier | Output impact | Removal candidate |
|----|----|----|----|----|
| A1 mutf8 `cont()` | yes (ART `GetUtf16FromUtf8`) | yes (VerifyMutf8) | none | **yes — under review** |
| A2 `SafeWidth`     | yes (slicer width)         | yes (VerifyInsns)  | none | low (3rd-party primitive) |
| B1 `VerifyInsns`   | no (addition)              | n/a (IS the verifier) | n/a | no |
| C1 edge index      | no (DAD relies on Python)  | partial            | none | no (cheap, internal) |
| C2 move-result null| no (matches DAD effective) | n/a                | none | no |

The live question is **A1** (and by extension the policy for A2): keep the leaf
decoder self-defending (SafeWidth precedent, provenance-independent), or remove
the guard for pure ART 1:1 and rely solely on the verifier. Both are defensible;
output is identical either way on valid input. Deferred per 2026-06-19 decision.
