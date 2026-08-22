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
`dk.verify_report()`). It gates each **logical** dex: one image can carry several
(a concatenated / packer dump, or a v041 container), and it derives the byte range
a dex's offsets are relative to the way ART's `DexFile::GetDataRange`
(`dex_file.cc:240`) does — a standard v035–040 dex is bounded by its own
`file_size`, while a v041 container dex is based at the container and bounded by
`container_size`, because container dexes deliberately **share** one data section.
It is a readable 1:1 port of all four ART phases
(`// ART :NNNN` anchors) — header/map/intra (incl. code_item, MUTF-8,
encoded_array) / inter (id ordering+uniqueness, descriptor + member-name syntax,
class_def semantics) — **plus** `VerifyInsns`, an instruction-operand bounds pass
that ART keeps in the *runtime* method_verifier (deliberately not vendored), here
re-derived from the Dalvik bytecode spec. **Intentional differences from ART:**
adler32/SHA-1 still **not** checked (policy — checksums are not a crash vector and
malware routinely lies about them); instruction *dataflow* semantics,
call_site CONTENTS and debug_info are out of scope (documented in
`dex_verifier.h`) — for both fixed-size sections the EXTENT is bounded and, since
dexllm#62, the 4-byte ALIGNMENT is checked, which is what ART's `CheckMap` does.
**method_handle CONTENTS left that list in dexllm#59** (ART
`CheckIntraMethodHandleItem` :1492): a handle's type and the index it implies are
now checked at the gate rather than throwing later at `GetFieldDecl` /
`GetMethodDecl`. What is still not read is a call_site's contents, and one index
INTO the method_handle section — the `0x16` encoded_value's, which ART caps and
bounds at :1204/:1212. Annotations were on that list until dexllm#56 — see the
`annotation_item` row below for why "the core lazy-parses it" was the wrong test. The slicer's own `Reader::ValidateHeader()` still runs after as
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
| map ordering / in-bounds / alignment / unknown+dup types / required sections | ✅ — the alignment half only became complete in dexllm#62: `IsDataSectionType` had `call_site_id` / `method_handle` / `map_list` in its *false* arm where ART :82 has them true, and that predicate gates the alignment branch, so a misaligned offset on any of the three was accepted. ART's other use of the predicate, the `data_items_left` item budget (:777), stays unported on purpose — see `docs/aosp-oob-divergences.md` B2b |

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
| annotations_directory / annotation_set(_ref_list) / annotation_item | ✅ `VerifyAnnotationsDirectory` (= ART `CheckIntraAnnotationsDirectoryItem` :2111 + `CheckIntraAnnotationItem` :2056, fused with the offset-following of `CheckInterAnnotationsDirectoryItem` :3276) — added for dexllm#56. The row used to read "◐ lazy, not on the decompile path", which was true of the *decompile* path and false of the one that mattered: `Reader::ExtractAnnotations` runs off `class_def.annotations_off` during cache init, so a 4-byte repoint of that offset produced a dex `verify()` called valid in both modes on which `ParseAnnotation` walked off the end (SIGSEGV, uncatchable). The walk covers exactly what `reader.cc` dereferences, and requires the three per-member offsets to be non-zero as ART does — for the parameter one that is load-bearing rather than parity, since `ExtractAnnotationSetRefList` has no zero guard and would read the dex header as a list |
| hiddenapi_class_data | ◐ not parsed by the core |
| annotation definer-match (a field/method annotation belongs to the annotated class) | ◐ not checked — a wrong-answer gap, not crash surface |
| method / field access_flags validity | ⚠ not checked (raw flags used; not a crash vector) |

**CheckInterSection (ART :3477)**

| ART check | VerifyDex |
|---|---|
| string / type / proto id ordering + uniqueness (verbatim UTF-16 comparator) | ✅ |
| type_id — descriptor syntax for EVERY entry (`CheckInterTypeIdItem` :2735) | ✅ `VerifyTypeDescriptor` (added for dexllm#23 — previously a descriptor was checked only where another id table referenced it, so a proto-only or instruction-operand type could hold arbitrary bytes and forge a smali instruction line in the rendered listing) |
| field_id — class `L`, type ≠ `V`, member-name, ordering | ✅ `VerifyTypeDescriptor` + `IsValidMemberName` |
| method_id — class `L`/`[`, member-name, proto bound, ordering | ✅ |
| class_def — class/super/interface `L`, dup, self-inherit, super-defined-before, dup interface | ✅ `VerifyClassDefs` (= ART `CheckInterClassDefItem` :2935) |
| class_data — EVERY member's defining class (`CheckInterClassDataItem` :3208, field loop :3226 / method loop :3244) | ✅ `CheckClassDataDefiners` (added for dexllm#48 — the port previously compared only the FIRST member, ART's `FindFirstClassDataDefiner` :2579, so a class_data whose first entry was its own could declare another class's members and still verify) |
| class_data — member access flags (`CheckFieldAccessFlags` / `CheckMethodAccessFlags` :934/:961) · `CheckStaticFieldTypes` :1289 (a static field's declared type vs its `encoded_array` initializer) · orphan class_data (ART drives from the MAP and requires a `class_def`; this port drives from `class_defs`) | ◐ not checked — wrong-answer gaps, not crash surface. The `CheckStaticFieldTypes` one is *relied upon* today: `tests/test_mutf8_identifiers.py::test_astral_type_in_a_field_initializer_decompiles` retypes a static value `0x17`→`0x18` and expects the dex to load. Orphan class_data is inert (the core walks `class_defs`, never the map) |
| proto shorty ↔ descriptor match | ◐ correctness-only (descriptors themselves are verified) |
| the method_handle walk is memoised per IMAGE, under an entry budget | ✅ an ADDITION, no ART analogue (`docs/aosp-oob-divergences.md` B2d). For a **v41 container** `size_` is the whole container for EVERY slice while `LogicalDexSlices` strides by `file_size`, so a SHARED section was walked once per sibling — quadratic, measured 0.04 s → 20.59 s at 16 MB. The memo changes no verdict (a later slice re-checks its own tables against the maxima the walk recorded, which is equivalent to re-walking); only the budget can reject, and a legitimate image cannot exhaust it because real sections occupy disjoint bytes |
| method_handle CONTENTS — handle type ≤ kLast (:1501), `field_or_method_idx` against field_ids/method_ids (:1512/:1521) | ✅ `VerifyMethodHandleSection` (= ART `CheckIntraMethodHandleItem` :1492, added for dexllm#59). Fused into `CheckMap`, where the map item is in hand — ART reaches it by ITERATING the map's sections and this port has no such pass. Never an OOB, but "a throw" (how dexllm#59 was filed) covers only half of it: measured on crafted entries, 0 signals and 0 exceptions, and instead — a TYPE past `kLast` decompiled BYTE-IDENTICALLY to a legal `invoke-static` handle, because `IsField()` sends everything outside 0x00-0x03 to the method table and the Writer renders by the same partition; an out-of-range INDEX throws only through the slicer, while dexllm#67's `ResolveMethodHandle` bounds it and renders nothing, so two bootstrap lines silently vanished |
| annotations definer-match · call_site CONTENTS · the `0x16` encoded_value's index into method_handle (ART caps its width :1204 and bounds it :1212) | ◐ not checked. Both fixed-size sections' EXTENT and ALIGNMENT are (`CheckMap`, dexllm#57 and dexllm#62), and each unbounded index is bounded AT ITS READER — a throw through the slicer, an empty render through `DecodeEncodedValueText`. Porting :1212 is a new rejection direction with its own a/b, and it retires the vehicle `tests/test_cache_init_failure.py` drives |
| `CheckOffsetToTypeMap` (offset matches its declared map-item type) | ⚠ not checked — contents are validated directly (`VerifyTypeList`/`VerifyClassData`/`VerifyEncodedArrayAt`/`VerifyAnnotationsDirectory`) so it stays crash-safe, but type-confusion of an offset is caught by ART, not here. **That sentence was false for annotations until dexllm#56** and the gap was exactly this one plus the missing walk: with no type map, "the contents are validated directly" has to hold for *every* referenced structure, and one exception is a crash. ART is map-driven (walk each section, record `offset -> type`, check references against it); this port is reference-driven (walk from the header's tables, validate what each offset points at) — so a section the port never walks is a section nothing checks at all |

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
  same range as AOSP android16 (`035–041`). `VerifyDex` matches: it checks ART's
  v041 header self-consistency block (`dex_file_verifier.cc:670`) and verifies
  *every* dex of a container against the container's shared data range (before
  dexllm#25 only the first one was verified at all).
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
  - Scope: the code-unit claim is about a **string LITERAL** in the Java TEXT path —
    `mirror::String` CONTENT, where reproducing ART's exact units is the point. Three
    other axes deliberately differ. An **IDENTIFIER** in that same Java text renders
    readably (dexllm#28): it is a source symbol rather than string content, and the
    code-unit spelling made one class read two ways across the Java, smali and
    `list_classes()` views — a correlation failure for anyone reading them side by
    side or pasting a class name into a hooking script, and one a BMP identifier
    never had. The string **VALUE** accessors (`list_*_strings`,
    `ArgOrigin.string_value`, AST string values) return the combined code point for a
    pair and, since dexllm#29, preserve a LONE surrogate rather than replacing it with
    U+FFFD, because a caller feeds those values back as queries. The smali listing is
    display text and keeps the lossy decode. See docs/api.md.
- **EncodedValue**: AOSP reads per spec and stores; dexllm **decodes IEEE754 float/
  double and null/true/false into spec-correct Java literals** for decompiler output
  (a vs-androguard fix, but the intent — Java-source correctness — is dexllm-specific).
  Since dexllm#64 the type/field/enum/method-type/method-handle/method/array/annotation
  values render too — the ones with no Java expression form as a trailing `// = …`
  comment, so an unrenderable initializer is distinguishable from none.
  A float/double payload is **zero-extended to the RIGHT** — the stored bytes are the
  MOST significant ones, ART's `ReadUnsignedInt(..., fill_on_right = true)` — so a
  short encoding such as `80 3F` is `1.0f` and not the `0x00003F80` denormal a
  left-justified read gives (dexllm#70; the decoder read it the wrong way until then,
  and the FULL-WIDTH encodings every assertion used are where the two readings agree).

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
