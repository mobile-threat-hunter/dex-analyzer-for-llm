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
- **MUTF-8**: AOSP validates then stores as-is; dexllm **decodes to UTF-8 / `\uXXXX`**
  for output.
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
