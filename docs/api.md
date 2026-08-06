# dexllm — API Reference

Complete reference for the `dexllm` Python API: every method, its exact return
type, and a real example output captured from
`test_apk/APK/com.example.android.tvleanback.apk`.

For a task-oriented walkthrough (the L1–L7 analysis levels), see
[usage.md](usage.md). This document is the flat reference.

The package is **[PEP 561](https://peps.python.org/pep-0561/) typed** — it ships
`py.typed` + `.pyi` stubs (`_dexkit_core.pyi` / `__init__.pyi`), so every method
and return type below is available to editors and type-checkers (mypy / pyright).
The stubs also carry a **worked example on every `DexKit` method and module
function**, so the same reference is available on hover without leaving the
editor. Those examples are real captured output, machine-verified against the
bundled corpus — not illustrative.

Conventions:
- **Descriptor** = a Dalvik type/method descriptor, e.g. class `Lcom/foo/Bar;`,
  method `Lcom/foo/Bar;->baz(I)V`, field `Lcom/foo/Bar;->f:I`.
- Methods on the `DexKit` instance are marked `dk.method(...)`; module-level
  functions are `dexllm.func(...)`.
- All decompile calls **release the GIL** (safe to parallelize across threads).

---

## 1. Loading & identification

### `dexllm.identify(path: str) -> dict`
Content-based probe **without loading** — pre-filter resources-only containers.
```python
dexllm.identify('app.apk')
# {'format': 'zip', 'is_apk': True, 'has_manifest': True, 'dex_count': 1}
```
| key | type | meaning |
|---|---|---|
| `format` | `str` | `"dex"` \| `"zip"` \| `"unknown"` |
| `is_apk` | `bool` | a zip carrying `AndroidManifest.xml` |
| `has_manifest` | `bool` | manifest present in the container |
| `dex_count` | `int` | number of sequential `classes*.dex` |

### `dexllm.verify(path: str, lenient: bool = False) -> list[dict]`
Structural verification **without loading** — the `verify()` sibling of
`identify()`. Runs the `VerifyDex` gate over a path's dex(es) and returns one
verdict per dex (a bare `.dex` → one entry; a zip/apk → one per `classes*.dex`).
**Never raises**: a malformed / unopenable / non-dex path is reported as a
`valid=False` verdict with a `reason` (where `DexKit(path)` would throw). For a
loadable source the result is byte-identical to `DexKit(path).verify_report()`
(same `VerifyDex` call, same `dex_id` assignment — accepted dexes get a running
0-based id, rejected/undecompressible get `-1`). `lenient=True` skips
`VerifyInsns` (ART-structural-equivalent mode), as in the constructor.
```python
dexllm.verify('app.apk')
# [{'dex_id': 0, 'name': 'classes.dex', 'valid': True, 'reason': ''}]
dexllm.verify('broken.dex')
# [{'dex_id': -1, 'name': 'broken.dex', 'valid': False, 'reason': 'Empty or truncated file'}]
```
Entry shape matches `dk.verify_report()` (below). Use it to screen an unknown
file (dumped/decrypted dex, disguised container) before committing to a load.

### `dexllm.DexKit(apk_path: str)` / `DexKit(sources: list[str], lenient=False)`
Constructs the analyzer. Identifies the file **by content, not extension** (a
disguised `.apk` still loads). Multiple sources load in order — earlier sources
get lower `dex_id`, so first-wins prefers them (packer/unpack ordering). Raises
`std::runtime_error` (Python `RuntimeError`) on a non-dex/non-zip file or a zip
with no `classes*.dex`. `lenient=True` runs the verifier in
ART-structural-equivalent mode (accepts partially-decrypted dumps).

### `dk.dex_count() -> int`
```python
dk.dex_count()   # 1
```

### `dk.sources() -> list[str]`
The construction sources (for `add_dumped_dexes`).
```python
dk.sources()     # ['test_apk/APK/com.example.android.tvleanback.apk']
```

### `dk.verify_report() -> list[dict]`
Per-dex structural-verification verdict (the load-time `VerifyDex` gate results).
```python
dk.verify_report()
# [{'dex_id': 0, 'name': 'classes.dex', 'valid': True, 'reason': ''}]
```
| key | type |
|---|---|
| `dex_id` | `int` |
| `name` | `str` |
| `valid` | `bool` |
| `reason` | `str` (empty when valid; byte-level reason when rejected) |

### `dk.warm_analysis_caches() -> None`
One-time (~200 ms on a 50-dex APK) eager warm of all analysers; otherwise they
warm lazily on first access.

---

## 2. Enumeration

### `dk.list_classes() -> list[str]`
Every declared class descriptor across all loaded dexes.
```python
dk.list_classes()          # len 4135
# ['Landroid/arch/core/internal/FastSafeIterableMap;', 'Landroid/arch/core/internal/SafeIterableMap$1;', ...]
```

### `dk.list_class_methods(cls_desc: str) -> list[str]`
Every declared method's full Dalvik descriptor.
```python
dk.list_class_methods('Lcom/example/android/tvleanback/Utils;')     # len 5
# ['Lcom/example/android/tvleanback/Utils;-><init>()V',
#  'Lcom/example/android/tvleanback/Utils;->convertDpToPixel(Landroid/content/Context;I)I', ...]
```

### Identifiers are decoded on the way out and encoded on the way in
An identifier — a class descriptor, a member name, a proto — is dex string-pool
MUTF-8 exactly like a literal is, and a supplementary-plane (astral) character is
stored there as a **surrogate pair**, which is not valid UTF-8. Every API that
RETURNS an identifier decodes it, and every API that TAKES one encodes it back
before matching (dexllm#22). This is a pair by necessity: identifiers are also the
input to every identity API, and the matchers compare against raw pool bytes, so
decoding alone would turn a loud `UnicodeDecodeError` into a silent miss. The
round trip therefore holds — a descriptor from `list_classes()` resolves through
`list_class_methods` → `decompile_*` / `render_*_smali` / `find_*` / the xref
family — and the same encoding is applied to the NAME matchers, which closes the
residual dexllm#19 recorded (an astral identifier was unfindable).

The two directions are exact inverses for **everything a loadable dex can hold**,
and that is enforced rather than assumed. Two encodings would break it — a LONE
surrogate and a non-NUL OVERLONG both decode to something that cannot be encoded
back — and the verifier rejects both: a lone surrogate by ART's member-name rules,
an overlong by ART's "Illegal representation" check (`CheckIntraStringDataItem`),
which dexllm#22 ported after finding it missing. That matters because the failure
mode is silent, not loud: an overlong descriptor enumerated fine and then resolved
to nothing in every identity API. Corpus incidence of any non-ASCII identifier is 0.

### `dk.list_value_strings() -> list[str]`
Every distinct string the app **loads as a value** (`const-string`/`jumbo` +
static-field `VALUE_STRING` initializers), MUTF-8→UTF-8, deduplicated. Excludes
identifier/metadata pool entries. This is the IOC feed.
```python
dk.list_value_strings()    # len 4939
# ['An entry modification is not supported', '=', ...]
```

### `dk.list_class_strings(cls_desc: str) -> list[str]` / `dk.list_method_strings(method_desc: str) -> list[str]`
The **forward** direction of `find_classes_using_strings` / `find_methods_using_strings`
("which strings does *this* code load", vs "which code uses string S"), and the
code-scoped counterpart of `list_value_strings()`. MUTF-8→UTF-8, deduplicated,
first-occurrence order. Answers "what literals does this method carry" without
rendering a whole smali listing or decompiling.
```python
dk.list_method_strings('Lcom/example/android/tvleanback/Utils;'
                       '->getDisplaySize(Landroid/content/Context;)Landroid/graphics/Point;')
# ['window']
dk.list_class_strings('Lcom/example/android/tvleanback/Utils;')
# ['window']
```
- `list_method_strings` is **bytecode only** — the method's `const-string`/`jumbo`
  (0x1a/0x1b) operands. A **compile-time-constant** `static final String` is a
  class-level `EncodedValue`, not part of any method body, so it appears in
  `list_class_strings` instead. (A non-constant initializer — `static final String X
  = "a" + f();` — is compiled into `<clinit>`, so it *does* show up under
  `list_method_strings("…-><clinit>()V")`.)
- `list_class_strings` = the union over the class's **declared** methods (ascending
  `method_idx` — the dex's per-class order, the same order `list_class_methods`
  returns; no superclass walk) **then** the class's static-field `VALUE_STRING`
  initializers — the same (a) code / (b) static-init order `list_value_strings()` uses
  app-wide. It is always a subset of `list_value_strings()`.
- Both return `[]` (never raise) for an external / abstract / native / unknown target,
  the same graceful-empty contract as `render_method_smali`.
- They decode MUTF-8 → UTF-8, as `render_*_smali` now does too (dexllm#22 — until
  then the renderer escaped raw BYTES and handed the pool bytes through, so a literal
  carrying a surrogate pair (a supplementary-plane character) or an embedded NUL
  (`C0 80`) made the text API raise `UnicodeDecodeError`: **26 of the 188,065 methods
  and 22 of the 25,309 classes** of the apk-only sweep corpus — 29 / 25 counting the
  bare `.dex` files too). The accessors' remaining advantages are
  scope (one method / one class), dedup on the decoded text, and a graceful empty
  rather than a whole rendered listing to parse.
- **Round-trip caveat — "forward direction" is a scope statement, not an exact
  inverse.** Feeding a returned string back into `find_*_using_strings` finds the
  origin whenever the string appears in *bytecode*, but of 29,588 distinct
  value-strings in the bundled corpus **1,236 do not round-trip** — all for one
  reason: the reverse index covers only `const-string` bytecode, so a string seen
  only as a static-field `VALUE_STRING` initializer is not in it. Use
  `find_classes_declaring_strings` for those. (A second cause — a supplementary-plane
  or NUL-bearing literal never matching because the query was compared as UTF-8
  against MUTF-8 pool bytes — accounted for 63 more until dexllm#19; the query is now
  encoded to MUTF-8 at the binding boundary. One crafted-only residual remains,
  absent from the corpus: a pool string carrying a LONE surrogate — pybind11 encodes
  arguments as strict UTF-8, which rejects an unpaired surrogate, and the decode
  direction replaces it with U+FFFD, though passing the raw MUTF-8 as `bytes` does
  match. The other former residual, a non-NUL OVERLONG encoding, is gone: it was
  listed as "the verifier accepts it, as ART does", which was wrong on both counts —
  ART rejects it, and dexllm#22 ported that check, so such a dex no longer loads.)
  Both directions are individually correct — do not assume set equality.

### Per-dex enumeration (uniform scope axis)
The bare form is all loaded dexes; the `…_in_dex(dex_id)` form is one dex (empty for
an out-of-range id), and the all-dexes form is exactly the per-dex concatenation.
Classes are DECLARED (union == all); field/method descriptors are the dex id-table
references (declared + referenced), so a cross-dex reference recurs once per dex.
```python
dk.list_classes_in_dex(0)                 # classes DECLARED in dex 0        (len 4135)
dk.list_field_descriptors()               # every 'Lcls;->name:Type'         (len 32824)
dk.list_field_descriptors_in_dex(0)       # …of one dex
dk.list_method_descriptors()              # every 'Lcls;->name(proto)ret'    (len 36876)
dk.list_method_descriptors_in_dex(0)      # …of one dex
dk.locate_class_dex('La2dp/Vol/ALauncher;')   # 0  (declaring dex id, -1 if external; cheaper than get_class_summary().dex_id)
```

### `dk.extract_dex_bytes(dex_id: int) -> bytes`
Raw bytes of one loaded dex — its own `file_size` slice (`header_off` applied, so a
concatenated/packer container yields THIS dex, not the shared image). `b""` for an
out-of-range id. The packer/dump-analysis primitive (feed a runtime-decrypted dex
back via `dexllm.add_dumped_dexes`).
```python
raw = dk.extract_dex_bytes(0)   # len 5472720, raw[:4] == b'dex\n'
```

---

## 3. Decompilation (DAD-aligned Java)

**Naming.** The `decompile_*` family always produces **Java**; the suffix says how
much structure comes back for that *same* decompilation — bare = text,
`_with_pc_map` = text + offset map, `_ast` = text + structured tree (at the default
`include_source=True` the AST call carries the identical Java in its `source`). A genuinely different output form is a
different verb: `render_*_smali`. The former `_java`-suffixed spellings
(`decompile_method_java`, `decompile_class_java`, `decompile_method_java_with_pc`,
plus `dexllm.safe_decompile_method_java` / `safe_decompile_class_java`) advertised a
parallelism with `_ast` that does not exist. They were kept as deprecated aliases
for one release and are **now removed** — use the names below, the ones the typed
[`dexllm.sdk`](sdk.md) layer already used (all three) and the MCP tool catalog
already used (`decompile_method` / `decompile_class`; it exposes no pc-map tool).

### `dk.decompile_method(desc: str) -> str`
Java text for a single method. GIL released. Empty string for external refs.
```python
dk.decompile_method('Lcom/example/android/tvleanback/Utils;->convertDpToPixel(Landroid/content/Context;I)I')
```
```java

public static int convertDpToPixel(android.content.Context p2, int p3)
{
    return Math.round((((float) p3) * p2.getResources().getDisplayMetrics().density));
}
```

### `dk.decompile_method_with_pc_map(desc: str) -> dict`
**D-3** — Java text + a source-line ↔ dex bytecode-offset map for smali sync.
```python
dk.decompile_method_with_pc_map(M)
# {'source': '\npublic static int convertDpToPixel(...)...',
#  'pc_map': [(4, 32)]}
```
| key | type | meaning |
|---|---|---|
| `source` | `str` | same bytes as `decompile_method` |
| `pc_map` | `list[tuple[int, int]]` | `(line_1based, byte_off)`; one entry per emitted line that maps to a dex op; `line` = 1-based index into `source.split("\n")` (**use `\n`, not `splitlines()`**) |

### `dk.decompile_class(cls_desc: str) -> str`
Full Java class text — `package`, class header (access + extends + implements),
static→instance field declarations with decoded EncodedValue initializers, then
method bodies. The header+fields region matches androguard `DvClass.get_source()`
byte for byte **except** that a `"` inside a `String` initializer is escaped as
`\"` (dexllm#22). androguard escapes the value with Python's `unicode-escape`,
whose repr is single-quoted, then wraps it in DOUBLE quotes to form a Java
literal — so an embedded `"` ends the literal early. 9 lines of the bundled
corpus are affected; all of them were invalid Java before.

### `dk.decompile_method_ast(desc: str, include_source: bool = True) -> dict`
Signature components + Java `source` + the full DAD nested-list AST + D-3 pc_map.
`include_source=False` skips the text-emit pipeline (~1.7× faster, AST only).
```python
dk.decompile_method_ast(M).keys()
# ['found', 'cls_name', 'name', 'proto', 'ret_type', 'params_type', 'access', 'source', 'ast', 'pc_map']
```
| key | type | example |
|---|---|---|
| `found` | `bool` | `True` |
| `cls_name` | `str` | `'Lcom/example/android/tvleanback/Utils;'` |
| `name` | `str` | `'convertDpToPixel'` |
| `proto` | `str` | `'(Landroid/content/Context;I)I'` |
| `ret_type` | `str` | `'I'` |
| `params_type` | `list[str]` | `['Landroid/content/Context;', 'I']` |
| `access` | `list[str]` | `['public', 'static']` |
| `source` | `str` | Java text (omitted body if `include_source=False`) |
| `ast` | `dict` | keys `{triple, flags, ret, params, comments, body}` — the DAD `get_ast()` nested-list tree (50+ node types) |
| `pc_map` | `list[tuple[int,int]]` | `(statement_seq, byte_off)` — sidechannel kept OUT of `ast` |

---

## 4. Smali rendering (baksmali-style, no JVM)

### `dk.render_method_smali(desc: str) -> str`
```python
dk.render_method_smali(M)
# 'Lcom/.../Utils;->convertDpToPixel(...)I\n    .registers 4\n    0x0: invoke-virtual {v2}, ...'
```

### `dk.render_class_smali(cls_desc: str) -> str`
Whole-class smali.

**Encoding contract (dexllm#22).** A pool string used as a **string literal** (a
`const-string` operand, and `.source`) is MUTF-8-**decoded before it is escaped**. A
surrogate PAIR becomes one code point (an astral character renders as itself — the
Java text path escapes it as `\uXXXX` code units instead, a deliberate difference:
that path claims ART code-unit fidelity, this one is a readable listing); a LONE
surrogate collapses to U+FFFD (lossy, absent from the corpus); every **C0** control
character (`cp < 0x20`) — including a NUL, which arrives as `C0 80` — escapes as
`\xNN`. Escaping the DECODED characters (rather than the raw bytes) is what stopped
an OVERLONG sequence (`E0 80 A2` = `"`, `E0 80 8A` = newline) from injecting
structure into a literal; since dexllm#22 also ported ART's canonicality check such
a dex no longer loads at all, so this is now defence in depth rather than the only
barrier. A rendered literal equals what `list_method_strings` reports for the same
method.

**IDENTIFIERS** (type / method / field names) do not go through the escaper — they
are unquoted in smali — but they are pool MUTF-8 too, so each one is DECODED at its
emission point (dexllm#22). A class or member carrying a supplementary-plane
character therefore renders instead of raising. They are decoded, not escaped,
because a loadable dex cannot carry a structural character in an identifier: member
names were always name-validated, and since dexllm#23 every `type_id` descriptor is
too — on the DECODED code points, so an overlong that would decode to `"` or a
newline is rejected at load rather than rendered here.

One thing this does **not** cover:
- Only C0 is escaped. **DEL, the C1 range and the Unicode line separators U+2028 /
  U+2029 / U+0085 render as themselves**, and Python's `str.splitlines()` treats the
  last three as line breaks — `PatternsCompat.<clinit>` renders 208 `\n` but 248
  `splitlines()` lines. **Split rendered smali on `\n`, never `str.splitlines()`** —
  the same contract the D-3 `pc_map` line numbering carries.

---

## 5. Search family (L1–L7)

The `find_*` methods return **typed match objects** (not strings). Their common
fields are listed in [§13](#13-return-type-object-reference).

**`match_type`** (the name/string finders) is one of `equals` / `contains`
(default) / `starts_with` / `ends_with` / `regex`; `ignore_case=False` by default.
**`regex` is DexKit's *SimilarRegex* — only the `^` (prefix) and `$` (suffix)
anchors, NOT full regex** (`"^com/foo"`, `"Activity$"`); an unrecognised
`match_type` falls back to `contains`. (The typed `dexllm.sdk` layer narrows this
to a `Literal` of the five canonical values — see [sdk.md](sdk.md).)

### Name search → `list[ClassMatch]` / `list[MethodMatch]`
```python
dk.find_classes_by_name('Utils')      # list[ClassMatch]  len 19
dk.find_methods_by_name('onCreate')   # list[MethodMatch] len 296
```

### String search → `list[ClassMatch]` / `list[MethodMatch]`
```python
dk.find_classes_using_strings(['entry'])   # list[ClassMatch]  len 9
dk.find_methods_using_strings(['entry'])   # list[MethodMatch] len 14
```

### `dk.find_classes_declaring_strings(strings, match_type='contains', ignore_case=False) -> list[ClassMatch]`
The **declaration** side of `find_classes_using_strings`. The `using` family searches
the `const-string` **bytecode** index — "which code LOADS S" — so a `static final
String` the app declares but never loads is invisible to it. That empty result is
*correct* for the question it asks (javac inlines a compile-time constant at each use
site, so a constant that IS used also exists as a `const-string` and is found); this
API answers the other question, and is the only way to locate an indicator that lives
solely in a constant.
```python
dk.find_classes_using_strings(['android.contentMaturity.all'], 'equals')      # []
dk.find_classes_declaring_strings(['android.contentMaturity.all'], 'equals')
# [ClassMatch 'Landroid/support/app/recommendation/ContentRecommendation;']
```
- Same match semantics as the rest of the family (it reuses the core's own
  `IsStringMatched`): `equals` / `contains` / `starts_with` / `ends_with` / `regex`
  (SimilarRegex `^prefix` / `suffix$`), optional `ignore_case`, and **ALL** query
  strings must match (each by some declared string of the class).
- **Edge cases differ from the `using` family** — deliberately. `using` routes an
  empty-ish matcher through upstream's Aho-Corasick keyword path rather than
  `IsStringMatched`, so on tvleanback an empty query list returns **every** class
  (4135) there but **nothing** here, and `[""]` / `["^"]` / `["$"]` return 61 there vs
  403 here (every class that declares any string). For a non-empty pattern the two run
  the same comparison and agree exactly.
- **No method-level analogue** — a *static-field* `EncodedValue` belongs to a
  class_def, not to a method, so `find_methods_declaring_strings` would be
  meaningless. (Method annotations do carry EncodedValues; this index does not scan
  them.)
- Non-ASCII literals match like any other: the query is encoded to MUTF-8 at the
  binding boundary (dexllm#19), so a supplementary-plane or NUL-bearing constant is
  findable here too.

### Literal search → `list[MethodMatch]`
```python
dk.find_methods_using_int_literals([255])      # len 133
dk.find_methods_using_double_literals([1.0])   # len 243
```

### Hierarchy / annotation search → `list[ClassMatch]` / `list[MethodMatch]`
```python
dk.find_classes_by_super('Landroid/app/Activity;')      # list[ClassMatch]  len 6
dk.find_classes_implementing('Ljava/lang/Runnable;')    # list[ClassMatch]  len 217
dk.find_classes_by_annotation('Landroid/annotation/TargetApi;')  # len 29
dk.find_methods_by_annotation('L.../SomeAnno;')         # list[MethodMatch]
```

### Batch string search → `dict[str, list[MethodMatch]]`
Query map is `{group_name: [strings]}`; returns per-group matches.
```python
dk.batch_find_methods_using_strings({'grpA': ['entry'], 'grpB': ['density']},
                                    match_type='contains', ignore_case=False)
# {'grpA': [<14 MethodMatch>], 'grpB': [<3 MethodMatch>]}
dk.batch_find_classes_using_strings({...})   # dict[str, list[ClassMatch]]
```

### Call sites → `list[CallSite]`
Every invoke of a specific API descriptor (internal or external) — the target's
CALLERS.
```python
dk.find_call_sites_to('Landroid/content/Context;->getSystemService(Ljava/lang/String;)Ljava/lang/Object;')
# list[CallSite]  len 54; each .caller_descriptor calls the (fixed) .callee_descriptor
```

### Callees of a method → `list[CallSite]` (forward direction)
The mirror of the above: every call site INSIDE a method — the methods it invokes.
Each `CallSite` fixes `.caller_descriptor` (this method) and varies `.callee_descriptor`
(+ `.bytecode_offset`, `.invoke_opcode`). `[]` for an external / bodyless / unresolved
method. `find_call_sites_from(M)` and `find_call_sites_to(C)` are forward
and reverse of the same edge: if `M` invokes `C`, `M` is among `C`'s callers.
```python
dk.find_call_sites_from('La2dp/Vol/ALauncher;->onCreate()V')
# list[CallSite]  len 17; e.g. .callee_descriptor 'Ljava/io/FileInputStream;->read([B)I'
```

**Naming.** `find_call_sites_to` / `find_call_sites_from` is one spelling across all
four layers — raw `DexKit`, the typed [`dexllm.sdk`](sdk.md) port and its adapter, and
the MCP tool catalog — and there is no longer any other: the pre-unification names
(`find_call_sites`, `find_call_sites_to_api`, `find_call_sites_from_method`) were
**removed**. The argument is `method_descriptor` in BOTH directions; the method name
carries the role (`_to` = the callee whose callers you want, `_from` = the caller
whose callees you want), so the parameter names what the value IS. It was
`api_descriptor` on the `_to` side, which said "framework API" — only the common
case, and not what the value is. The MCP catalog likewise advertises exactly one
name per tool, and an unadvertised spelling returns `{"error": "unknown tool: ..."}`:
mcp validates arguments only against the schema of the tool it ADVERTISES, so an
alias there would silently lose input validation.

### Intra-method arg resolution → `list[ResolvedCallSite]`
Same as call sites, plus the resolved origin of each argument (L4 dataflow).
```python
dk.resolve_call_args('Landroid/content/Context;->getSystemService(Ljava/lang/String;)Ljava/lang/Object;')
# list[ResolvedCallSite]  len 54; each has .args -> list[ArgOrigin]
```
**What it does and does not prove (dexllm#16).** A forward register simulation with a
**meet at every control-flow join**: a definition is reported only when it reaches the
call on *every* path, so a reported value is never one path's value presented as
unconditional. It is deliberately not a fixed point (two passes, no iteration to convergence): a
value defined **before** a loop and not re-established inside it does not survive the
loop header, and a **catch handler** starts from an unknown register file; both yield
`Unknown`. (A value the loop re-establishes identically *does* survive — the second
pass meets in what the backward edge carries.) `ArgOrigin.crossed_branch` separates
the two flavours of `Unknown`:

| `kind` | `crossed_branch` | meaning |
|---|---|---|
| a value kind | `False` | this **origin** reaches the call on every path. Exact for the `Const*` kinds; for `MethodReturn` / `FieldRead` / `NewInstance` it is the origin that is invariant ("the result of `X()`", "a read of field `F`", "a fresh `X`") — the runtime object may still differ per path |
| `Unknown` | `True` | a tracked definition was **discarded at a merge** — the paths disagree (a genuinely conditional argument), or the analyzer gave up wholesale at a loop header / catch handler (which also discards registers that happen to agree). **Do not read it as a proven "two values"; read it as "not proven".** |
| `Unknown` | `False` | no tracked definition at that point — never tracked (arithmetic, array load, …), or cleared by a later untracked write |

Reading `int_value` / `string_value` without checking `kind` yields a silent `0` / `""`
for both `Unknown` flavours — check `kind` first. For an argument whose value depends
on a branch, decompile the caller (`decompile_method` / `decompile_method_ast`),
which carries the real control flow.
```python
for s in dk.resolve_call_args(API):
    a = s.args[1]
    if a.kind == "ConstString":      trust(a.string_value)   # holds on every path
    elif a.crossed_branch:           conditional(s)          # ≥2 possible values
    else:                            untracked(s)
```

### Field read/write xref → `list[str]`
Which methods READ (`iget*`/`sget*`) vs WRITE (`iput*`/`sput*`) a specific field
(L2.5 reverse index). `field_descriptor` is the `Lcls;->name:Type` form; each returns
plain method descriptors (`[]` if the field isn't declared in a loaded dex). The
pre-rename spellings `find_field_read_methods` / `find_field_write_methods` (and the
SDK's `find_field_readers` / `find_field_writers`) are **removed** — every other
`find_*` names what it RETURNS right after `find_`, and those named the queried
field instead.
```python
fd = 'La2dp/Vol/AppChooser$1;->this$0:La2dp/Vol/AppChooser;'
dk.find_methods_reading_field(fd)   # ['La2dp/Vol/AppChooser$1;->onClick(Landroid/view/View;)V']   (readers)
dk.find_methods_writing_field(fd)  # ['La2dp/Vol/AppChooser$1;-><init>(La2dp/Vol/AppChooser;)V']  (writers)
```
**One entry per ACCESS INSTRUCTION, not per method** — the same semantics as
`CallSite`. A method with two `iget`s of the field appears twice, so the list is
not deduplicated; wrap in `set()` (or `dict.fromkeys()` to keep order) when you
want distinct methods. Measured on the bundled corpus: of 634 fields with at
least one reader, 164 have a reader that repeats.
```python
tp = 'Lcom/google/android/exoplayer2/ui/DefaultTimeBar;->touchPosition:Landroid/graphics/Point;'
len(dk.find_methods_reading_field(tp))   # 2 — one method, two iget-object
len(dk.find_methods_writing_field(tp))   # 1 — the same method, one iput-object
```

### Type references → `TypeReferences`
Signature-position uses of a `Lpkg/Cls;` type — where it appears as a field type, a
method return type, or a method parameter (NOT call/instruction xref). Empty lists if
the type isn't referenced.
```python
tr = dk.find_type_references('Landroid/content/Intent;')
tr.fields              # fields OF this type          len 4    e.g. '…ShareCompat$IntentBuilder;->mIntent:Landroid/content/Intent;'
tr.methods_returning   # methods returning it          len 62   e.g. 'La2dp/Vol/EditDevice;->getIntent()Landroid/content/Intent;'
tr.methods_with_param  # methods taking it as a param  len 153  e.g. 'La2dp/Vol/ALauncher;->onBind(Landroid/content/Intent;)…'
```

---

## 6. External references (typed objects)

APIs the app calls but doesn't define (framework/library refs).

### `dk.list_external_method_refs() -> list[ExternalMethodRef]`
```python
em = dk.list_external_method_refs()[0]   # len 4821
em.signature        # 'Landroid/accessibilityservice/AccessibilityServiceInfo;->getCanRetrieveWindowContent()Z'
em.java_signature   # 'android.accessibilityservice.AccessibilityServiceInfo.getCanRetrieveWindowContent() -> boolean'
em.class_descriptor # 'Landroid/accessibilityservice/AccessibilityServiceInfo;'
em.java_class       # 'android.accessibilityservice.AccessibilityServiceInfo'
em.name             # 'getCanRetrieveWindowContent'
em.proto            # '()Z'
em.parameters       # []                 (list[str])
em.return_type      # 'Z'
em.is_constructor   # False
em.is_static_initializer      # False
em.referenced_in_dex_ids      # [0]      (list[int])
```

### `dk.list_external_field_refs() -> list[ExternalFieldRef]`
```python
# ExternalFieldRef(Landroid/app/Notification$Action;->actionIntent:Landroid/app/PendingIntent;)   len 281
```

### `dk.list_external_type_refs() -> list[ExternalTypeRef]`
```python
# ExternalTypeRef(Landroid/accessibilityservice/AccessibilityServiceInfo;)   len 1035
```

Python-side filter helpers: `dexllm.filter_method_refs(refs, ...)`,
`filter_field_refs`, `filter_type_refs` (e.g. keep only `android.content.*`).
`dexllm.find_call_sites_to_ref(dk, ref)` → the `list[CallSite]` for an
`ExternalMethodRef` (the convenience that resolves `ref.signature` and calls
`find_call_sites_to`).

---

## 7. Class summary & capabilities

### `dk.get_class_summary(cls_desc: str) -> ClassSummary`
Works on internal AND external classes.
```python
s = dk.get_class_summary('Lcom/example/android/tvleanback/Utils;')
s.descriptor              # 'Lcom/example/android/tvleanback/Utils;'
s.dex_id                  # 0
s.is_internal             # True
s.access_flags            # 1
s.superclass_descriptor   # 'Ljava/lang/Object;'
s.interface_descriptors   # []                          (list[str])
s.source_file             # 'Utils.java'
s.fields                  # []                          (list[ClassMemberField])
s.methods                 # [ClassMemberMethod(<init>()V), ClassMemberMethod(convertDpToPixel(...)I), ...]
```
Every `access_flags` here — on the class and on each member — is the **raw dex
bits**, with no `java.lang.reflect.Modifier` normalization; a method declared
`synchronized` reads `0x20000`, not `0x20`. See
[`ClassSummary`](#classsummary) for why.
Render a summary as Java-source-style text (header + static→instance fields + methods):
```python
dexllm.format_class(dk, 'Lcom/example/android/tvleanback/Utils;')   # str — fetch + format
dexllm.format_class_summary(s, indent='    ')                       # str — format an already-fetched ClassSummary
```

### `dexllm.summarize_capabilities(dk) -> CapabilityReport`
Aggregate permission + category profile.
```python
r = dexllm.summarize_capabilities(dk)
r.permissions   # Counter({'android.permission.INTERNET': 3, 'android.permission.ACCESS_FINE_LOCATION': 1, ...})
r.categories    # Counter({'REFLECTION': 3476, 'CRYPTO': 202, 'RISKY': 45, ...})
```
The `dexllm.capability` module also exposes `ApiHit` / `CapabilityReport` types.

---

## 8. IOC extraction (Python)

### `dexllm.extract_iocs(dk, *, with_xref=True, denoise=True, xref_limit=300) -> dict`
Static network-IOC over `list_value_strings()`. Defang-aware, public-suffix-
validated (tldextract).
```python
dexllm.extract_iocs(dk).keys()          # dict_keys(['urls', 'ips', 'domains', 'emails', 'onion'])
# each value is a list of {'value': str, 'methods': list[str], 'declared_in': list[str]}:
# {'domains': [{'value': 'dolby.com',
#               'methods': ['L.../DashManifestParser;->parseAudioChannelConfiguration(...)V'],
#               'declared_in': []}], ...}
```
`methods` are the call sites that LOAD the indicator (const-string xref); `declared_in`
are the classes that DECLARE it as a static-field constant. An indicator kept only as a
constant has no const-string, so it used to be reported with **no location at all** —
`declared_in` gives it one (21 such indicators in the bundled corpus, e.g.
`https://wear.googleapis.com/3p_auth/` → `Landroid/support/wearable/authentication/OAuthClient;`).
Both are populated independently, so an empty `methods` with a non-empty `declared_in`
means exactly "declared but never loaded". Both are `[]` when `with_xref=False`.
`dexllm.IOC_CATEGORIES == ('urls', 'ips', 'domains', 'emails', 'onion')`.

### `dexllm.detect_content_providers(dk, *, with_xref=True, xref_limit=300) -> list`
The `content://` provider query-URIs (SMS / contacts / call-log / calendar handles
that `ContentResolver` takes — the surface `READ_SMS`/`READ_CONTACTS` gate, invisible
to the `@RequiresPermission` signature map because the `Uri` is assembled at runtime)
referenced by the app's value-strings, matched against a bundled AOSP-derived dataset
(`data/content_uris.json`). Returns `[{'uri', 'family', 'methods'}]` sorted by URI; a
dataset URI is a hit iff it occurs as a substring of some value-string.

---

## 9. Dangerous permission APIs (Python)

Joins AOSP's `@RequiresPermission` map against the APK's external refs →
signature-precise (overload-disambiguated).

### `dexllm.dangerous_permission_apis(dk) -> dict[str, list[str]]`
```python
dexllm.dangerous_permission_apis(dk)
# {'android.permission.ACCESS_COARSE_LOCATION': ['android.location.LocationManager#getLastKnownLocation(String)'],
#  'android.permission.ACCESS_FINE_LOCATION':   ['android.location.LocationManager#getLastKnownLocation(String)', ...]}
```

### `dexllm.dangerous_permission_api_callers(dk, app_only=True) -> dict`
Same, plus the calling methods (default drops bundled framework/library callers).

### `dexllm.permission_api_callers(dk, *, app_only=True, levels=None) -> list`
The full-surface generalisation (issue #14): **all** protection levels, not just the
dangerous slice. Returns `[{"perm", "protectionLevel", "rows": [{"api", "descriptors",
"callers"}]}]` sorted by permission, each group with its real `protectionLevel` bucket
(`dexllm.PERM_LEVELS = (dangerous, signature, internal, normal, other)`); pass `levels=`
to filter. `dk.permission_callers(app_only)` is the byte-identical C++ engine port
shared with the WASM binding. The bundled `perm_api.json` (571 perms — metalava
`@RequiresPermission` + the AOSP runtime-enforcement bridge) + `perm_levels.json`
are the single source of truth; the dangerous variants derive from them.

---

## 10. Packer / multi-source (Python)

### `dexllm.add_dumped_dexes(dk, dumps, prefer=True, lenient=True) -> DexKit`
Re-analyze with runtime-dumped dex(es): returns a **fresh** `DexKit` over
`dumps + dk.sources()` (prefer → dumps win collisions; lenient → accept
partial-decrypt dumps).
```python
dk2 = dexllm.add_dumped_dexes(dk, ['/tmp/dump.dex'])
```

---

## 11. Decompiler cache management

```python
dk.decompiler_cache_capacity()          # 4096   (int; default cap)
dk.decompiler_cache_size()              # 0      (int; current entries)
dk.set_decompiler_cache_capacity(8192)  # None   (0 = unbounded)
dk.clear_decompiler_cache()             # None
```
An **action** is verb-first, a **read-only accessor** is a noun — the scheme the
already-verb-first `warm_analysis_caches` was following. The pre-rename action
spellings `decompiler_clear_cache` / `decompiler_set_cache_capacity` are **removed**,
and the setter's parameter is `capacity` (it was `cap`, the only abbreviation in the
API and the one place raw disagreed with the SDK port).

---

## 12. Descriptor helpers & safe wrappers (Python)

### Descriptor conversion
```python
dexllm.descriptor_to_java('Lcom/foo/Bar;')     # 'com.foo.Bar'
dexllm.java_to_descriptor('com.foo.Bar')       # 'Lcom/foo/Bar;'
dexllm.is_framework_descriptor('Landroid/app/Activity;')   # True
dexllm.method_ref_java('Lcom/foo/Bar;->baz(I)V')           # human-readable form
dexllm.parse_proto('(ILjava/lang/String;)Z')  # (['I', 'Ljava/lang/String;'], 'Z')  — (param descriptors, return)
dexllm.pretty_proto('(ILjava/lang/String;)Z') # '(int, java.lang.String) -> boolean'
```

### Safe (hang-guarded) decompile wrappers
Run the decompile on a daemon thread with a wall-clock deadline. **Use in
batch/CI/automation** (belt-and-suspenders vs the IR-level cap).
```python
out = dexllm.safe_decompile_method(dk, desc, timeout=10.0)   # -> str
out = dexllm.safe_decompile_class(dk, cls, timeout=10.0)     # -> str
if dexllm.is_timeout_marker(out):
    ...   # hit the deadline
dexllm.DEFAULT_TIMEOUT_S    # 10.0
```

### MCP tool definitions
```python
dexllm.tools.tool_definitions()    # list of 35 MCP tool schemas
```

---

## 13. Return-type object reference

Typed objects returned by the search/ref APIs. All are pybind11-bound; fields
are read-only attributes.

### `ClassMatch`
| field | type |
|---|---|
| `descriptor` | `str` |
| `class_id` | `int` |
| `dex_id` | `int` |

### `MethodMatch`
| field | type |
|---|---|
| `descriptor` | `str` |
| `method_id` | `int` |
| `dex_id` | `int` |

### `ExternalMethodRef`
`class_descriptor`, `name`, `proto`, `return_type`, `signature` (`str`);
`java_class`, `java_signature` (`str`); `parameters` (`list[str]`);
`referenced_in_dex_ids` (`list[int]`); `is_constructor`,
`is_static_initializer` (`bool`).

### `ExternalFieldRef` / `ExternalTypeRef`
Field: class/name/type descriptors + `signature`. Type: `descriptor` +
`java_class` + `referenced_in_dex_ids`.

### `CallSite`
| field | type | meaning |
|---|---|---|
| `caller_descriptor` | `str` | the calling method |
| `callee_descriptor` | `str` | the API called |
| `caller_dex_id` | `int` | dex the caller lives in |
| `caller_method_idx` | `int` | **dex-local** `method_ids` index — only meaningful paired with `caller_dex_id`, not a stable global id |
| `bytecode_offset` | `int` | byte offset of the invoke, always **inside the caller** |
| `invoke_opcode` | `int` | Dalvik opcode (e.g. 110 = `invoke-virtual`) |

**Which half is fixed depends on the producing direction** — `find_call_sites_to(X)`
fixes `callee_descriptor` and varies `caller_*` ("who calls X");
`find_call_sites_from(M)` fixes `caller_*` and varies `callee_descriptor`
("what M calls"), so the repeated caller on every element is the queried method.

### `ResolvedCallSite`
All `CallSite` fields plus `args: list[ArgOrigin]`. Only `resolve_call_args` produces
it, i.e. always the reverse direction (callee fixed).

### `ArgOrigin`
Where one argument came from (intra-method).
| field | type | meaning |
|---|---|---|
| `kind` | `str` | `'MethodReturn'` \| `'NewInstance'` \| `'StringConst'` \| `'IntConst'` \| `'Field'` \| `'Parameter'` \| … |
| `reg_num` | `int` | register holding the arg |
| `string_value` | `str` | for string constants |
| `int_value` | `int` | for int constants |
| `class_descriptor` | `str` | for new-instance/type origins |
| `method_signature` | `str` | for method-return origins |
| `field_signature` | `str` | for field origins |
| `parameter_index` | `int` | for parameter origins (`-1` if n/a) |

### `ClassSummary`
`descriptor`, `superclass_descriptor`, `source_file` (`str`); `dex_id`,
`access_flags` (`int`); `is_internal` (`bool`); `interface_descriptors`
(`list[str]`); `fields` (`list[ClassMemberField]`); `methods`
(`list[ClassMemberMethod]`).

**Access flags are the RAW dex bits** — the values as stored in the file, with no
`java.lang.reflect.Modifier` normalization, on the class and on every member. In
particular a method declared `synchronized` in Java carries
`ACC_DECLARED_SYNCHRONIZED` (`0x20000`), **not** `ACC_SYNCHRONIZED` (`0x20`) — in
dex, `0x20` means JNI `synchronized native`, a different property. (Upstream
DexKit rewrote `0x20000` → `0x20` for Modifier compatibility; dexllm removed that
because it conflates the two and because the decompiler already reported the raw
form, so one method described itself two ways.) The same bits drive the
`declared_synchronized` modifier in `decompile_class` /
`decompile_method_ast(...)["access"]`.

### `CapabilityReport`
`permissions: collections.Counter[str]`, `categories: collections.Counter[str]`.

---

## Typed SDK API (`dexllm.sdk`)

For embedding, `dexllm.sdk` wraps this surface in ports & adapters:
`@runtime_checkable` Protocol ports + frozen-dataclass models with an accurate
type on every argument/return.

```python
from dexllm.sdk import open_apk, identify, DexAnalysisUseCase

session: DexAnalysisUseCase = open_apk("app.apk")   # or open_apk([dump, apk], lenient=True)
session.decompile_method("Lcom/x/Y;->m(I)V")        # -> DecompiledMethod
session.permission_callers(app_only=True)           # -> tuple[PermissionCallerGroup]
session.extract_iocs()                              # -> IocReport
session.raw                                          # underlying DexKit (escape hatch)
```

Ports: `DexAnalysisUseCase` (composite) + `DecompilationPort` / `EnumerationPort`
/ `DexExtractionPort` / `ClassInspectionPort` / `CrossReferencePort` / `SearchPort`
/ `PermissionAnalysisPort` / `IndicatorExtractionPort` / `CapabilityPort` /
`ContentProviderPort` / `CacheControlPort` / `ContainerProbePort`. Full walkthrough
in [usage.md](usage.md#typed-sdk--ports--adapters-dexllmsdk);
source in `src/dexllm/sdk/`.

---

## Notes

- **Descriptors in / typed objects or strings out.** Enumeration + decompile
  return `str`; search returns typed match objects; refs return typed ref
  objects. Read `.descriptor` / `.signature` to get back a string.
- **Threading.** Decompile calls release the GIL — parallelize across threads
  for whole-APK sweeps. Use the `safe_*` wrappers in automation.
- **Framework filtering.** `is_framework_descriptor` + the `filter_*_refs`
  helpers separate app code from bundled androidx/kotlin/play-services.
