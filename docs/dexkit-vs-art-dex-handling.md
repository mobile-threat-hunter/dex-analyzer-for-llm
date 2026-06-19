# dexllm vs AOSP/ART — how each handles DEX

How dexllm (DexKit Core + the slicer dex reader) treats a `.dex` differs from how
AOSP/ART loads, verifies, and resolves one. This matters for **malware triage**:
in a few cases what dexllm *shows* is not what ART would actually *run*.

Sourced from the AOSP wiki (`aosp-wiki`, android16-qpr2: `dex-file-format`,
`dexfileverifier`, `app-classloader`, `class-linker`) and dexllm's own
[CLAUDE.md](../CLAUDE.md) + vendored slicer (`vendor/dexkit_core/Core/third_party/slicer/`).
AOSP `file:line` anchors drift on re-sync — re-verify before quoting.

## 0. Root difference — execute vs analyze

| | AOSP/ART | dexllm |
|---|---|---|
| Purpose | load DEX to **execute** it | load DEX to **statically analyze / decompile** it |
| Consequence | verification is a **security boundary** (false-accept → exploit) | verification is a **crash-safety boundary** (false-accept → at worst an analyzer crash, never code-exec) |
| Parser | ART `DexFileLoader` + `DexFileVerifier` (`art/libdexfile/dex/`) | Google **slicer** (`reader.cc`), vendored, **gated by a load-time `VerifyDex` port of `DexFileVerifier`** (`native/core_ext/dex_verifier.{h,cpp}`) |

Every difference below follows from this.

## 0.5. Parser lineage — slicer (dexter) vs ART libdexfile

dexllm parses with Google's **slicer**; ART parses with **libdexfile**. They are
**independent AOSP libraries** — cousins that share the on-disk dex *format*
vocabulary (`dex_format.h` constants, same layout) but are separate
implementations with different purposes, not shared code.

| | slicer (`tools/dexter/slicer`) | ART libdexfile (`art/libdexfile/dex`) |
|---|---|---|
| Purpose | dex **instrumentation / rewriting** — read → IR → transform → **write** | **runtime loader** — load, verify, then execute |
| Parse model | materializes a **mutable heap IR** (`ir::DexFile` graph; `Reader::GetClass`/`ParseClass`, lazy per-index via placeholder) | **lazy zero-copy accessors** (`ClassAccessor`/`CodeItemDataAccessor` = `DexFile& + const uint8_t* ptr_pos_`, a cursor over the mmap'd bytes) |
| Mutability | mutable objects (built to round-trip and re-emit) | immutable views (no materialization) |
| Verification | **none** — only `SLICER_CHECK_*` assertions (index/pointer sanity; upstream aborts, DexKit patches to `throw`) | full structural `dex_file_verifier.cc` + runtime method verifier |
| Writes dex? | **yes** (`writer.cc`, `instrumentation.cc`) | no (read-only loader) |
| Malformed input | assertion → abort / throw (no reason) | verifier rejects with a byte-level reason |
| Versions | `kMinVersion=35 … kMaxVersion=41` (035–041, incl. v041 container) | `StandardDexFile::kDexMagicVersions` (same range) |
| CompactDex (cdex) | never supported | **removed** from current AOSP → both StandardDex now, aligned |
| MUTF-8 | `dex_utf8.cc` | `utf.cc` — decode to identical UTF-16 units (see §6) |

**Why dexllm combines them.** slicer is the *parse engine* (we need its decoded
instructions + IR to build a `MethodSnapshot`), but slicer does **no structural
verification** — a malformed dex only trips a `SLICER_CHECK` (abort/throw, no
reason) or, worse, is decoded out of bounds. So dexllm gates every dex through a
**1:1 port of ART's `DexFileVerifier`** (`VerifyDex`, §1) *before* slicer parses,
and ports ART's `utf.cc` for MUTF-8 fidelity (§6). The result is **slicer's parsing
convenience + ART's verification rigor** — which is also why the OOB-prevention
guards (slicer's `SafeWidth`, the MUTF-8 `cont()` bound) exist:
[aosp-oob-divergences.md](aosp-oob-divergences.md).

### Why not replace slicer with ART libdexfile?

A recurring question: if ART libdexfile is the canonical parser, why not use it
directly? Because it's not a parser swap — it's a foundation rewrite, for a benefit
we already have:

1. **slicer is the backbone of DexKit Core, not just our decompiler's parser.**
   `dex::Reader` is a *member of `DexItem`* (`dex_item.h`) — the entire L1–L7 search
   engine and class/method enumeration (the headline speed features) run through it.
   Replacing slicer means re-porting all of DexKit onto a new parser, or dropping
   DexKit and reimplementing search/enumeration. Tens of thousands of lines.
2. **libdexfile is not standalone-vendorable.** `dex_file.cc`/`dex_file_verifier.cc`
   pull in **libartbase** (`base/leb128.h`, `base/globals.h`, `base/mman.h`,
   `base/hiddenapi_domain.h`, …) and **libbase** (`android-base/*`), and build with
   **Soong (`Android.bp`), not CMake**. Vendoring it means extracting and
   CMake-porting libartbase + libbase and maintaining that fork — far more than we
   vendor today. This is exactly why standalone dex tooling uses dexter/slicer
   (purpose-built standalone) rather than libdexfile (purpose-built to live *inside*
   the ART runtime).
3. **libdexfile's one real advantage — rigorous structural verification — we already
   have**, via the `DexFileVerifier` and `utf.cc` ports. So we get ART-grade
   verification + MUTF-8 fidelity *without* libdexfile's build burden.

Net: replacing slicer is huge cost (rewrite DexKit + vendor libartbase/libbase +
Soong→CMake) for marginal benefit (rigor we already ported). It would only make
sense if we both dropped DexKit and were willing to vendor libartbase/libbase — a
standing maintenance burden, not a one-time port. **Decision: keep slicer.**

## 1. Verification depth — gap now closed by a load-time verifier

**AOSP** — `dex::Verify` (`dex_file_verifier.cc:3541`) runs **4 upfront phases** on
every untrusted DEX:
- `CheckHeader` — magic/version, `endian_tag`, **adler32**, every section
  offset/size via overflow-safe `size_-offset<size`
- `CheckMap` — map items strictly increasing, in-bounds, aligned, required sections
- `CheckIntraSection` — per-item: class_def dup, ULEB128, CodeItem/try-catch
  bounds, **MUTF-8 validity**
- `CheckInterSection` — cross-refs: id ordering/uniqueness, descriptor syntax,
  superclass-defined-before

This is the **trust boundary**, and it is **skipped entirely** when a matching
`vdex` exists (`verify = (vdex==nullptr) && IsVerificationEnabled()`).

**dexllm** — **reproduces `DexFileVerifier`** as a self-contained
load-time gate, `dexkit::ext::VerifyDex` (`native/core_ext/dex_verifier.{h,cpp}`),
run by `DexKitExt` before the slicer parses any dex (raw `.dex` and each
`classes*.dex`; reject → throw with a byte-level reason, surfaced by
`dk.verify_report()`). It is a readable 1:1 port of all four ART phases
(`// ART :NNNN` anchors) — header/map/intra (incl. code_item, MUTF-8,
encoded_array) / inter (id ordering+uniqueness, descriptor + member-name syntax,
class_def semantics) — **plus** `VerifyInsns`, an instruction-operand bounds pass
that ART keeps in the *runtime* method_verifier (deliberately not vendored), here
re-derived from the Dalvik bytecode spec. **Intentional differences from ART:**
adler32/SHA-1 still **not** checked (policy — checksums are not a crash vector and
malware routinely lies about them); instruction *dataflow* semantics, annotations,
call_site/method_handle, debug_info are out of scope (documented in
`dex_verifier.h`). The slicer's own `Reader::ValidateHeader()` still runs after as
a second cheap sanity layer; per-item decode problems beyond the verifier's scope
still surface lazily as `SLICER_CHECK` → `std::runtime_error`, skipping that method.

> **Implication:** dexllm verifies for **crash-safety**, not as an execution trust
> boundary — a structurally-malformed DEX that would crash the analyzer is rejected
> at load with a byte-level reason (ASan-validated 0 heap-overflow/UAF/SEGV on a
> malformed-dex fuzz that segfaults 66/120 with no structural verifier). It is
> intentionally lenient where ART is strict for *execution* safety (checksums,
> dataflow), so "ART would reject this" and "dexllm rejects this" are not identical
> sets — but the structural crash surface ART's `DexFileVerifier` covers is covered
> here too.

### Per-check breakdown

Legend: ✅ ported (behavioural parity) · ⊕ beyond ART's *structural* verifier ·
⊖ intentionally skipped (policy) · ◐ out of scope (lazy-parsed / not dereferenced)
· ⚠ minor gap (ART has it, low crash-value).

**CheckHeader (ART :617) / CheckMap (:738)**

| ART check | VerifyDex |
|---|---|
| magic / version / header_size / file_size / endian_tag | ✅ |
| every section offset+size (overflow-safe `CheckValidOffsetAndSize`) | ✅ |
| type_ids / proto_ids < 65536 (`CheckSizeLimit`) | ✅ |
| adler32 checksum / SHA-1 signature | ⊖ (not a crash vector; malware forges them) |
| map ordering / in-bounds / alignment / unknown+dup types / required sections | ✅ |

**CheckIntraSection (ART :2450)**

| ART check | VerifyDex |
|---|---|
| string_data — MUTF-8 + length + NUL | ✅ `VerifyStringData`/`VerifyMutf8` |
| type / proto / field / method / class id index validity | ✅ |
| type_list (proto params, interfaces) — incl. `type_idx < count` | ✅ `VerifyTypeList` |
| code_item — registers / ins / outs / insns / try / handler offsets | ✅ `VerifyCodeItem` (= ART `CheckIntraCodeItem` :1726) |
| encoded_array / encoded_value — recursive index validity | ✅ `VerifyEncodedArrayAt` (= ART `CheckEncodedArray` :1225) |
| class_data_item | ✅ `VerifyClassData` |
| **per-instruction operand bounds** (reg / index / branch / switch / array target) | ⊕ `VerifyInsns` — **not in ART's structural verifier** (it lives in the 6032-line runtime `method_verifier`); re-derived from the Dalvik spec via the slicer's VerifyFlags/IndexType tables |
| debug_info_item | ◐ dexllm never parses it |
| annotation_item / annotations_directory / hiddenapi | ◐ lazy, not on the decompile path |
| method / field access_flags validity | ⚠ not checked (raw flags used; not a crash vector) |

**CheckInterSection (ART :3477)**

| ART check | VerifyDex |
|---|---|
| string / type / proto id ordering + uniqueness (verbatim UTF-16 comparator) | ✅ |
| field_id — class `L`, type ≠ `V`, member-name, ordering | ✅ `VerifyTypeDescriptor` + `IsValidMemberName` |
| method_id — class `L`/`[`, member-name, proto bound, ordering | ✅ |
| class_def — class/super/interface `L`, dup, self-inherit, super-defined-before, dup interface, class_data definer-match | ✅ `VerifyClassDefs` (= ART `CheckInterClassDefItem` :2935) |
| proto shorty ↔ descriptor match | ◐ correctness-only (descriptors themselves are verified) |
| annotations definer-match · call_site / method_handle inter | ◐ not dereferenced |
| `CheckOffsetToTypeMap` (offset matches its declared map-item type) | ⚠ not checked — contents are validated directly (`VerifyTypeList`/`VerifyClassData`/`VerifyEncodedArrayAt`) so it stays crash-safe, but type-confusion of an offset is caught by ART, not here |

**Bottom line:** the structural crash surface is at ART parity (plus `VerifyInsns`
goes beyond it); every divergence is either an *execution-trust* check (checksums,
access flags, type-map, dataflow) that a read-only analyzer does not need, or a
documented lazy/out-of-scope section.

## 2. Multidex duplicate-class resolution — aligned with ART

When the same class descriptor is defined in more than one dex, dexllm resolves it
the way ART does — **first-wins, deterministic**:

- **AOSP/ART:** `PathClassLoader` → `ClassLinker::FindClass` (loader delegation) walks
  the dex element list **in order**; the **first dex that defines the class wins**
  (libcore `DexPathList.findClass` returns the first match).
- **dexllm:** `DexKit::PutDeclaredClass` (`vendor/dexkit_core/Core/dexkit/dexkit.cpp`)
  keeps the **lowest `dex_id`** (classes.dex before classes2.dex). Because `dex_id`
  is fixed by load order, the result is order-independent → deterministic **and**
  matches ART's first-wins.

→ `locate_class_dex` / decompile of a descriptor declared in multiple dex resolves
to the same class body ART would execute, regardless of thread count. Standard APKs
are unaffected (R8/D8 dedups); this matters for **packer / merged-dex** analysis: a
2-dex container with every class duplicated resolves all duplicates to dex0, stable
across repeated loads.

## 3. Multidex loading scope — essentially the same

- AOSP `GetMultiDexClassesDexName`: index0 = `classes.dex`, N = `classes{N+1}.dex`,
  loop until not-found (warn at 100).
- dexllm (DexKit `AddZipPath`): `classes.dex`, `classes2.dex`, … sequential, **stop
  at the first gap**.

Both load only `classes*.dex` from the ZIP. `assets/*.dex`, non-standard names, and
secondary dex (`DexClassLoader`) are outside this path for both — dexllm covers them
by extracting the raw `.dex` and loading it individually.

## 4. Cross-dex reference resolution — runtime linking vs self-contained

- **AOSP**: `ClassLinker` resolves at runtime via `FindClass` → `ResolveType/Method/
  Field`, following classloader delegation, caching pointers in the **DexCache**. A
  dex depends on external definitions **at runtime**.
- **dexllm**: a dex carries external refs as **descriptor strings** in its own
  method/proto/type tables → loading **only that dex** decompiles use-sites
  **byte-identically** to loading both (CLAUDE.md: cross-dex self-contained). Missing
  the defining dex only loses (a) that class itself and (b) cross-dex xrefs.

## 5. AOSP-only security mechanisms (no dexllm analog)

- **Janus (CVE-2017-13156)**: from a ZIP, ART's `location_checksum` = **ZIP CRC32**,
  not the DEX adler32 (`dex_file_loader.cc:564`). dexllm reads no checksum at all.
- **vdex skip-verify**, **`access(W_OK)` writable-dex block** (`dalvik_system_DexFile.cc:380`),
  **`VerifyMode::kNone`** — all *execution-trust* mechanisms, irrelevant to a
  read-only analyzer.

## 6. Versions & encoding — mostly aligned, dexllm just emits more

- **Versions**: slicer `kMinVersion=35, kMaxVersion=41` → **v041 container support**,
  same range as AOSP android16 (`035–041`).
- **MUTF-8**: AOSP validates then stores as-is; dexllm **decodes to the exact UTF-16
  code units ART builds in a `mirror::String`** (shared decoder ported 1:1 from
  `art/libdexfile/dex/utf-inl.h GetUtf16FromUtf8` — see
  [`native/dad_cpp/mutf8.h`](../native/dad_cpp/include/mutf8.h)), then renders each
  unit for output: a BMP non-surrogate → readable UTF-8 (한글/CJK), a surrogate or
  control char → `\uXXXX` (the only valid, pybind11-decodable text form).
  - **Supplementary chars are kept as a surrogate PAIR, exactly like ART** — NOT
    folded into one 4-byte UTF-8 code point. ART decodes each 3-byte MUTF-8 sequence
    to one UTF-16 unit, so a dex-canonical supplementary char (two 3-byte sequences)
    stays two units. Verified against the **real AOSP source**: compiling the
    checkout's actual `utf-inl.h` and feeding it the on-disk bytes of a supplementary
    char (e.g. U+DFFFD, MUTF-8 `ED AC BF  ED BF BD`) yields the two units
    `0xDB3F, 0xDFFD` — byte-identical to our decoder and to our decompiled output
    `"\udb3f\udffd"`. (Locked in by the surrogate-pair cases in
    [`tests/parity/mutf8_parity_test.cpp`](../tests/parity/mutf8_parity_test.cpp),
    which differentially compares our port against an inline verbatim copy of ART's
    `GetUtf16FromUtf8`.)
  - This diverges from androguard/Python, which collapses the pair to one code point,
    and from DAD, which ASCII-escapes everything (`unicode-escape`). dexllm matches
    **ART's in-memory representation**.
- **EncodedValue**: AOSP reads per spec and stores; dexllm **decodes IEEE754 float/
  double and null/true/false into spec-correct Java literals** for decompiler output
  (a vs-androguard fix, but the intent — Java-source correctness — is dexllm-specific).

## Bottom line for a threat hunter

1. **Multidex duplicate classes resolve like ART** — first-wins by lowest `dex_id`,
   deterministic — so dexllm agrees with runtime on which class body a packer's
   collision resolves to.
2. dexllm **reproduces `DexFileVerifier`** at the load boundary (`VerifyDex`, §1) —
   a structurally-malformed DEX is rejected with a byte-level reason instead of
   crashing the analyzer (ASan-validated 0-crash). It stays intentionally lenient on
   *execution-trust* checks (adler32/SHA-1, instruction dataflow), so "dexllm loads
   it" ≠ "ART executes it" — but the structural crash surface is covered, and
   `dk.verify_report()` exposes per-dex verdicts.
