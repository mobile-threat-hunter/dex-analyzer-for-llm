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
# {'format': 'zip', 'is_apk': True, 'has_manifest': True, 'dex_count': 1,
#  'source': 'app.apk'}
```
| key | type | meaning |
|---|---|---|
| `format` | `str` | `"dex"` \| `"zip"` \| `"unknown"` |
| `is_apk` | `bool` | a zip carrying `AndroidManifest.xml` |
| `has_manifest` | `bool` | manifest present in the container |
| `dex_count` | `int` | number of sequential `classes*.dex` |
| `source` | `str` | the path these keys describe — echoes the argument, and is what lets [`dk.source_info()`](#dksource_info---listdict) reuse the shape |

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
# [{'dex_id': 0, 'name': 'classes.dex', 'valid': True, 'reason': '', 'source': 'app.apk'}]
dexllm.verify('broken.dex')
# [{'dex_id': -1, 'name': 'broken.dex', 'valid': False, 'reason': 'Empty or truncated file',
#   'source': 'broken.dex'}]
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

### `dk.source_info() -> list[dict]`
What each construction source **was**, probed once at load — one entry per
[`sources()`](#dksources---liststr) entry, in the same order, carrying the same
keys as [`identify()`](#dexllmidentifypath-str---dict).

```python
dk.source_info()
# [{'format': 'zip', 'is_apk': True, 'has_manifest': True, 'dex_count': 1,
#   'source': 'test_apk/APK/com.example.android.tvleanback.apk'}]
```

A **session fact**, not a fresh read: it stays true after the file is deleted,
which a dumped dex in a temp directory routinely is. Probing the path again would
answer `dex_count: 0` — the documented "resources-only container, nothing to
analyse" sentinel — for a session that still works. Use `identify(path)` when the
question is about a path on disk, and this when it is about the session.

### `dk.verify_report() -> list[dict]`
Per-dex structural-verification verdict (the load-time `VerifyDex` gate results).
```python
dk.verify_report()
# [{'dex_id': 0, 'name': 'classes.dex', 'valid': True, 'reason': '', 'source': 'app.apk'}]
```
| key | type |
|---|---|
| `dex_id` | `int` |
| `name` | `str` |
| `valid` | `bool` |
| `reason` | `str` (empty when valid; byte-level reason when rejected) |
| `source` | `str` — the path handed to the constructor. `name` alone is ambiguous: it is the file path for a bare `.dex` but only the entry name for a zip member, so two sources both report `classes.dex` (dexllm#26) |

**Rows ↔ dex_ids** (dexllm#25/#27). One row per **logical** dex, not per file: a
concatenated / packer-dump container is split by the loader into several logical
dexes and each is verified on its own, so such a source contributes several rows
that share a `name` and are told apart by `dex_id` (and by
`extract_dex(dex_id)["offset"]`). An **accepted** row's `dex_id` is the real
`dex_id` of that dex in this session — the accepted rows are exactly
`0 … dex_count()-1`, in order. A **rejected** row has `dex_id == -1`: it occupies
no id, contributed no classes, and its `reason` names the first structural
violation. Before v0.9.1 the field was the load-order *image* index, which drifted
by the split count as soon as one source was concatenated.

At most **65536** dexes can be loaded in one session (the core addresses a dex by
`uint16_t`); the excess is refused with that reason, counted across *all* sources.
Real containers are nowhere near this — it exists so an unaddressable `dex_id` is
never handed out.

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

### `dk.list_class_methods(class_descriptor: str) -> list[str]`
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

An identifier also **renders readably in decompiled Java** (dexllm#28), not as
`\uXXXX` code units: a class named `A𐀀sTest` reads the same in
`decompile_class`, in `render_class_smali` and in `list_classes()`. The ART
code-unit-fidelity claim is about string CONTENT — what `mirror::String` holds —
and a string LITERAL still honours it. An identifier is a source symbol, and the
split spelling meant one class read two ways in a single session, which breaks
naive correlation between the Java and smali views and the copy-paste of a class
name into a hooking script. A BMP identifier (`A한ysisTest`) always rendered
readably, so the old rule held by unit count rather than by principle. A LONE
surrogate still escapes — it has no UTF-8 form — but the verifier rejects one in a
name, so it cannot occur there.

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

### `dk.list_class_strings(class_descriptor: str) -> list[str]` / `dk.list_method_strings(method_descriptor: str) -> list[str]`
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
  encoded to MUTF-8 at the binding boundary. The two former residuals are both gone.
  A non-NUL OVERLONG encoding was listed as "the verifier accepts it, as ART does",
  which was wrong on both counts — ART rejects it, and dexllm#22 ported that check,
  so such a dex no longer loads. A LONE surrogate is closed by dexllm#29, below.)
  Both directions are individually correct — do not assume set equality.
- **Lone surrogates survive the boundary (dexllm#29).** A string LITERAL may legally
  hold an unpaired surrogate — `VerifyMutf8` checks sequence shape and canonicality,
  not surrogate PAIRING, exactly as ART's `CheckIntraStringDataItem` does. (An
  identifier cannot: `IsValidPartOfMemberNameUtf8Slow` accepts a leading surrogate
  only when a trailing one follows. The asymmetry is deliberate.) The value used to
  come back as U+FFFD and every reverse query on it then returned nothing, silently.
  Both directions now use CPython's `surrogatepass` handler instead of pybind11's
  strict UTF-8 codec, so the pool's 3-byte form survives OUT (`list_value_strings`,
  `list_class_strings`, `list_method_strings`, `ResolvedArg.string_value`, AST string
  values) and IN (the five content matchers — which still accept `bytes` and
  `bytearray` unchanged, so the former `bytes` workaround keeps working).
  The rule for what stays LOSSY is **display vs query**, not identifier vs
  content: a surface whose value is fed back as a query is lossless; one that
  exists to be shown keeps U+FFFD, because printing a lone surrogate raises. That
  covers the NAME matchers (where a lone surrogate is also unreachable — the
  verifier rejects it in a name), every `__repr__`, the smali renderer, and
  `ClassSummary.source_file` — which is NOT verifier-protected the way a name is
  (`CheckClassDefItem` only range-checks `source_file_idx`), so it can carry one
  and deliberately shows it as U+FFFD.
  **Cost, stated plainly:** a `str` carrying a lone surrogate RAISES at any strict
  UTF-8 **encode** of it — `str.encode()`, a text-mode file write, `print()` to a
  UTF-8 stream, `json.dump(fp)`. It is safe through `==`, `in`, `re`, and
  `json.dumps` at its default `ensure_ascii=True`, which is what the MCP and HTTP
  servers use. (`json.dumps(..., ensure_ascii=False)` does **not** raise — it
  returns a `str`; the raise comes when that result is encoded.) The failure this
  can produce is loud and local; the one it replaces was a silent miss in the
  reverse lookup of a crafted sample. Corpus incidence is 0.
- **Known ambiguity, inherent to MUTF-8 and not introduced by the above.** The pool
  stores an astral character as a **surrogate pair** (CESU-8), so `"\U000dfffd"`
  and the two-half string `"󟿽"` — different Python strings — have
  IDENTICAL pool bytes. A byte-comparing matcher cannot separate them: a
  half-surrogate query matches *inside* a legitimately-paired literal under
  `contains`, and `equals` on the split form finds the paired one. Symmetrically,
  the listing always reports the pair as the combined character, so you cannot tell
  from the output which the dex held. Passing the halves as `bytes` always did
  this; making a `str` query work is what puts it in reach of a `str`. Pinned by
  `tests/test_lone_surrogate.py::test_half_surrogate_query_matches_inside_a_paired_literal`.
- **Over MCP the value is readable but not requeryable.** The rule above holds
  inside the Python API. A lone surrogate comes OUT of a tool safely (the server
  serializes at `ensure_ascii=True`, so the wire payload is ASCII), but sending it
  back IN as a tool argument is rejected while the request is PARSED — mcp's JSON
  parser refuses a lone-surrogate escape that stdlib `json.loads` accepts. Use the
  Python API for that round trip.
- **Batch KEYS are still strict UTF-8.** `batch_find_*` converts the query VALUES,
  not the dict key, which is a caller-chosen label rather than pool content (and
  comes back as a `str` key in the result). So `{s: [s] for s in
  dk.list_value_strings()}` raises `TypeError` if `s` holds a lone surrogate — use
  any label (`{"g": [s]}`). Loud, and unchanged from before.

### Per-dex enumeration (uniform scope axis)
The bare form is all loaded dexes; the `…_in_dex(dex_id)` form is one dex (empty for
an out-of-range id), and the all-dexes form is exactly the per-dex concatenation.
Classes are DECLARED (union == all); field/method descriptors are the dex id-table
references (declared + referenced), so a cross-dex reference recurs once per dex.
```python
dk.list_classes_in_dex(0)      # classes DECLARED in dex 0       (len 4135)
dk.list_fields()               # every 'Lcls;->name:Type'        (len 32824)
dk.list_fields_in_dex(0)       # …of one dex
dk.list_methods()              # every 'Lcls;->name(proto)ret'   (len 36876)
dk.list_methods_in_dex(0)      # …of one dex
dk.locate_class_dex('La2dp/Vol/ALauncher;')   # 0  (declaring dex id, -1 if external; cheaper than get_class_summary().dex_id)
```

### `dk.extract_dex(dex_id: int) -> dict`
Raw bytes of one loaded dex **and where it came from**. `bytes` is the dex's own
`file_size` slice (`header_off` applied, so a concatenated/packer container yields
THIS dex, not the shared image). The packer/dump-analysis primitive (feed a
runtime-decrypted dex back via `dexllm.add_dumped_dexes`).
```python
d = dk.extract_dex(0)
# {'bytes': b'dex\n...', 'dex_id': 0, 'source': 'app.apk',
#  'entry': 'classes.dex', 'offset': 0, 'size': 5472720}
```
| key | meaning |
|---|---|
| `bytes` | the dex image; `b""` for an out-of-range id |
| `dex_id` | echoes the argument; `-1` when out of range, and only then. A logical dex the core could not construct (a packer dump whose second dex has an intact header but an undecrypted body) keeps its own id with empty `bytes` — check `size` |
| `source` | the path handed to the constructor |
| `entry` | the member inside it (`classes2.dex`); `""` when the source IS the dex |
| `offset` | this logical dex's start within the **loaded image** — the decompressed `entry` when `entry` is set, otherwise the file at `source`. Nonzero only for a concatenated / packer-dump container. A packer apk whose `classes.dex` is two concatenated dexes has `entry` set **and** a nonzero `offset`, so slicing the `.apk` at it is meaningless |
| `size` | `len(bytes)` |

`dk.extract_dexes()` is the whole-container form — every loaded dex in `dex_id`
order, the same dict per entry, so `len()` equals `dex_count()`. It is a separate
PLURAL name rather than an optional `dex_id` so the return type never depends on
the argument (the same all-vs-one axis as `list_classes()` /
`list_classes_in_dex(dex_id)`); it copies every dex's bytes, so use
`extract_dex(i)` when one is wanted.

**Why provenance is part of the return** (dexllm#26 — this was `extract_dex_bytes`,
returning only the bytes). Nothing else could answer "which file did this come
from": `verify_report()['name']` is the file path for a bare `.dex` but only the
entry name for a zip member, so two sources in one session both report
`classes.dex`. `verify_report()` now also carries `source` for the same reason.
(It also once had **no row at all** for a concatenated source's second logical
dex — fixed separately in dexllm#25, see the rows↔dex_ids note above — but
`offset` remains the only thing that says WHERE in the container a dex starts.)

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

### `dk.decompile_method(method_descriptor: str) -> str`
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

**A declaration line can carry a marker**, so a rendering is never silently
something other than a straight decompile. Every text is fixed (no dex bytes
reach one).

| marker | when |
|---|---|
| `// no instructions` | the method HAS a code item with nothing decodable in it, so there is no body to emit — without the marker the signature-only form is indistinguishable from `abstract`/`native`, which differ only by a modifier (dexllm#73) |
| `// entry is not at offset 0` | the code item opens with a switch/fill-array payload, so the body starts at the first decodable instruction instead of where a VM enters. Such a method cannot execute at all, so what is rendered is a reinterpretation (dexllm#75) |
| `// control enters at a non-instruction offset` | a basic-block LEADER — a branch/switch target, a try-range start or a handler address — points into payload data or into the TAIL of a multi-unit instruction, so the block is read from the first instruction at or after it and falls through when it holds none (dexllm#77) |

The first is EXCLUSIVE with the other two (it needs a code item with no
decodable instruction at all, which the other two conditions cannot then hold
for). **The second and third are independent** and a method can carry both: one
needs the FIRST instruction not to be at byte 0, the other needs a LEADER off an
instruction boundary, and neither implies the other.

The last two are crafted-input shapes: across the bundled corpus, the committed
fixtures, `art/test/dexdump`, `tools/dexter/testdata` and the four ART fuzzer
corpora, no method begins its body with a payload and none has a leader off an
instruction boundary. The first is NOT — the unmodified AOSP file
`art/tools/fuzzer/class-verifier-corpus/b391844326.dex` carries a method with a
code item and no decodable instruction, and it is where dexllm#73 was found.

### `dk.decompile_method_with_pc_map(method_descriptor: str) -> dict`
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

### `dk.decompile_class(class_descriptor: str) -> str`
Full Java class text — `package`, class header (access + extends + implements),
static→instance field declarations with decoded EncodedValue initializers, then
method bodies.

The header+fields region was ported from androguard `DvClass.get_source()` and
follows its structure, but it is **not** byte-for-byte equal to it. Every
divergence is deliberate: in most rows androguard emits something that is not
valid Java at all, and in the float/double row it emits Java that compiles with
the WRONG VALUE (`= 16256` for a field AOSP declares as `1f` — an int literal
widening to float).

| EncodedValue | androguard | dexllm |
|---|---|---|
| `VALUE_NULL` / `VALUE_BOOLEAN` | `None` / `True` / `False` | `null` / `true` / `false` |
| `VALUE_FLOAT` / `VALUE_DOUBLE` | the raw payload as an integer | the IEEE754 value, round-trip formatted (dexllm#70) |
| `VALUE_TYPE` / `VALUE_FIELD` / `VALUE_ENUM` | a raw descriptor / a Python list | `pkg.Cls.class` / `pkg.Cls.NAME` |
| `VALUE_METHOD_TYPE` / `VALUE_METHOD_HANDLE` | the raw payload as an integer | `invoke.MethodType.methodType(…)` / a trailing `// = Cls::name` comment (dexllm#64) |
| `VALUE_METHOD` | a Python list — `['LMain;', '<init>', ['()', 'V']]` | a trailing `// = Main::new` comment (dexllm#64) |
| `VALUE_ARRAY` / `VALUE_ANNOTATION` | a **memory address** — different every run | `{a, b}` / a trailing `// = @Foo(…)` comment (dexllm#64) |
| a `"` inside a `String` | ends the literal early | escaped as `\"` (dexllm#22) |

A value with **no Java expression form at all** — a method handle, a method
reference, an annotation, or an array containing one — is rendered as a trailing
`// = …` comment rather than after an `=`, so the declaration stays valid Java
and `Type name;` never means both "no initializer" and "an initializer that
could not be spelled" (dexllm#64). `decompile_class` is the only surface that
reads `static_values`, so that comment is the only place the value appears.

### `dk.decompile_method_ast(method_descriptor: str, include_source: bool = True) -> dict`
Signature components + Java `source` + the full DAD nested-list AST + D-3 pc_map.
`include_source=False` skips the text-emit pipeline (~1.7× faster, AST only).
```python
dk.decompile_method_ast(M).keys()
# ['found', 'class_descriptor', 'name', 'proto', 'return_type', 'param_types', 'access_flags', 'source', 'ast', 'pc_map']
```
| key | type | example |
|---|---|---|
| `found` | `bool` | `True` |
| `class_descriptor` | `str` | `'Lcom/example/android/tvleanback/Utils;'` |
| `name` | `str` | `'convertDpToPixel'` |
| `proto` | `str` | `'(Landroid/content/Context;I)I'` |
| `return_type` | `str` | `'I'` |
| `param_types` | `list[str]` | `['Landroid/content/Context;', 'I']` |
| `access_flags` | `list[str]` | `['public', 'static']` |
| `source` | `str` | Java text (omitted body if `include_source=False`) |
| `ast` | `dict` | keys `{triple, flags, ret, params, comments, body}` — the DAD `get_ast()` nested-list tree (50+ node types). `comments` is `[]` in DAD and stays `[]` here except for the dexllm#75 and dexllm#77 markers, which it carries WITHOUT the leading `// ` (e.g. `['entry is not at offset 0']`, and both when a method earns both) so an `include_source=False` consumer can see the reinterpretation too |
| `pc_map` | `list[tuple[int,int]]` | `(statement_seq, byte_off)` — sidechannel kept OUT of `ast` |

---

## 4. Smali rendering (baksmali-style, no JVM)

### `dk.render_method_smali(method_descriptor: str) -> str`
```python
dk.render_method_smali(M)
# 'Lcom/.../Utils;->convertDpToPixel(...)I\n    .registers 4\n    0x0: invoke-virtual {v2}, ...'
```

### `dk.render_class_smali(class_descriptor: str) -> str`
Whole-class smali. A `.field` line is emitted for each entry of the class's own
`class_data`, as baksmali does — an inherited field it only references gets none
(dexllm#45); those live in `list_fields()`.

**Encoding contract (dexllm#22).** A pool string used as a **string literal** (a
`const-string` operand, and `.source`) is MUTF-8-**decoded before it is escaped**. A
surrogate PAIR becomes one code point (an astral character renders as itself — as it
now does in decompiled Java too for an IDENTIFIER, since dexllm#28; the Java text
path still escapes it as `\uXXXX` code units inside a string LITERAL, which is where
the ART code-unit-fidelity claim applies); a LONE
surrogate collapses to U+FFFD (lossy, absent from the corpus — the smali listing is
display text, so it keeps the lossy decode even though the VALUE accessors stopped
using it in dexllm#29); every **C0** control
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

**Operand contract (dexllm#66).** Every index operand a named opcode can carry is
either RESOLVED or LABELLED — none renders as a bare `@N`, which does not say what
table the number indexes:

| operand | renders as |
|---|---|
| string / type / field / method | the resolved literal or descriptor |
| `invoke-polymorphic`'s two operands | the method ref **and** the call-site proto |
| `const-method-type` | the proto, e.g. `(CSIJFDLjava/lang/Object;)Z` |
| `const-method-handle` | `method_handle@N` |
| `invoke-custom[/range]` | `call_site@N` |
| `iget/iput-*-quick` | `field_off@N` |
| `invoke-virtual[/range]-quick` | `vtable@N` |

The last four are **labels, not resolutions**. A method handle and a call site are
not resolved here because AOSP's own dexdump does not resolve them either ("too
large to detail in disassembly"). **The smali listing stays this way on purpose**:
dexllm#67 built a `call_site_ids` reader for the DECOMPILER, and deliberately did
not feed it into this view, which is baksmali-shaped. The label
values are **decimal**, matching the `string@N` / `type@N` fallbacks alongside
them, where dexdump uses zero-padded hex — this listing is baksmali-shaped, not
dexdump-shaped, and carries no `// kind@N` provenance comment on any operand
either. The last two
are ODEX **offsets** rather than table indices — which is why `@N` was not merely
uninformative there but actively wrong — and they are reachable on a
strict-verified dex because `VerifyInsns` has no opcode-legality gate, so an
odex-derived packer dump carries them.

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

### Name search → `list[ClassRef]` / `list[MethodRef]` / `list[FieldRef]`
```python
dk.find_classes_by_name('Utils')      # list[ClassRef]  len 19
dk.find_methods_by_name('onCreate')   # list[MethodRef] len 296
dk.find_fields_by_name('DB')          # list[FieldRef]  len 8
```
`find_methods_by_name` and `find_fields_by_name` also take
`declaring_class=` (a class descriptor) to scope the search, plus `match_type=` /
`ignore_case=`. The field arm completes the class/method/field symmetry: before
dexllm#37 `FieldRef` was a registered public type that **no call could
produce**.

**Scoped searches answer with DECLARATIONS; unscoped ones include references.**
Both `method_ids` and `field_ids` hold an entry per REFERENCE, grouped under the
class each reference names, so a subclass appears there for a member it merely
inherits. `declaring_class=` excludes those (for fields, since dexllm#45); without
it they are kept, so the unscoped form is the one that shows where an inherited
member is *touched* under an app class:

```python
C = 'Landroid/support/constraint/ConstraintLayout$LayoutParams;'   # inherits it
len(dk.find_fields_by_name('bottomMargin'))                  # 8  — app-class references
dk.find_fields_by_name('bottomMargin', declaring_class=C)    # [] — C declares no such field
len([f for f in dk.list_fields() if f.endswith('->bottomMargin:I')])   # 11 — every entry
```

Neither form reaches all 11: **name search only considers entries grouped under a
class some loaded dex DECLARES** (`type_def_flag`, a pre-existing property of the
whole `find_*_by_name` family, not of dexllm#45). The 3 missing here are spelled
under framework classes — `ViewGroup$MarginLayoutParams`, `FrameLayout$LayoutParams`,
`LinearLayout$LayoutParams`. Only `list_fields()` enumerates those.

### String search → `list[ClassRef]` / `list[MethodRef]`
```python
dk.find_classes_using_strings(['entry'])   # list[ClassRef]  len 9
dk.find_methods_using_strings(['entry'])   # list[MethodRef] len 14
```

### `dk.find_classes_declaring_strings(strings, match_type='contains', ignore_case=False) -> list[ClassRef]`
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
# [ClassRef 'Landroid/support/app/recommendation/ContentRecommendation;']
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

### Literal search → `list[MethodRef]`
```python
dk.find_methods_using_int_literals([255])      # len 133
dk.find_methods_using_double_literals([1.0])   # len 243
```

### Hierarchy / annotation search → `list[ClassRef]` / `list[MethodRef]`
```python
dk.find_classes_by_super('Landroid/app/Activity;')      # list[ClassRef]  len 6
dk.find_classes_implementing('Ljava/lang/Runnable;')    # list[ClassRef]  len 217
dk.find_classes_by_annotation('Landroid/annotation/TargetApi;')  # len 29
dk.find_methods_by_annotation('L.../SomeAnno;')         # list[MethodRef]
```

### Batch string search → `dict[str, list[MethodRef]]`
Query map is `{group_name: [strings]}`; returns per-group matches.
```python
dk.batch_find_methods_using_strings({'grpA': ['entry'], 'grpB': ['density']},
                                    match_type='contains', ignore_case=False)
# {'grpA': [<14 MethodRef>], 'grpB': [<3 MethodRef>]}
dk.batch_find_classes_using_strings({...})   # dict[str, list[ClassRef]]
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
case, and not what the value is. (`ApiUsage.api_descriptor` keeps the
`api_` prefix for the opposite reason: that record IS one catalog-API hit, so
the prefix names the catalog entry rather than asserting anything about a
callee — dexllm#68.) The MCP catalog likewise advertises exactly one
name per tool, and an unadvertised spelling returns `{"error": "unknown tool: ..."}`:
mcp validates arguments only against the schema of the tool it ADVERTISES, so an
alias there would silently lose input validation.

### Intra-method arg resolution → `list[ResolvedCallSite]`
Same as call sites, plus the resolved origin of each argument (L4 dataflow).
```python
dk.resolve_call_args('Landroid/content/Context;->getSystemService(Ljava/lang/String;)Ljava/lang/Object;')
# list[ResolvedCallSite]  len 54; each has .args -> list[ResolvedArg]
```
**How far it looks: `depth`.** The analysis is bounded to a **basic-block window** —
the call site's own block plus `depth` predecessor levels above it. `depth=0` is that
block alone; the default `2` adds two levels. Nothing outside the window is looked at,
so `depth` *is* the analysis budget and the caller chooses it:

```python
import dexllm
dk = dexllm.DexKit("app.apk")
API = "Landroid/content/Context;->getSystemService(Ljava/lang/String;)Ljava/lang/Object;"

shallow = dk.resolve_call_args(API, depth=0)   # the call's own block only — cheapest
default = dk.resolve_call_args(API)            # its block + 2 levels above
deep = dk.resolve_call_args(API, depth=6)      # further back: more resolved, more cost
assert len(shallow) == len(default) == len(deep)   # the SITES never depend on depth
```

Raising it resolves more arguments; an argument whose definition lies further back
reads as `Unknown`. The **call sites themselves never depend on `depth`** — only the
arguments do.

**What it does and does not prove (dexllm#16).** Within the window it is a forward
register simulation with a **meet at every control-flow join**: a definition is
reported only when it reaches the call on *every* path of the window, so a reported
value is never one path's value presented as unconditional. An edge coming from
*outside* the window carries nothing, so it tombstones a register some **other**
in-window edge does define — a register no in-window edge defines is simply absent.
It is deliberately not a fixed point: a **catch handler** is entered with an *empty*
register file (nothing is carried in, so nothing is tombstoned there either), and a
cycle inside the window is resolved by taking nothing from the not-yet-resolved edge.
The method **entry** counts as an edge of the entry block, so a loop that reassigns a
parameter register yields `Unknown` at the header rather than the loop-carried value.
`ResolvedArg.crossed_branch` separates the two flavours of `Unknown`:

| `kind` | `crossed_branch` | meaning |
|---|---|---|
| a value kind | `False` | this **origin** reaches the call on every path. Exact for the `Const*` kinds; for `MethodReturn` / `FieldRead` / `NewInstance` it is the origin that is invariant ("the result of `X()`", "a read of field `F`", "a fresh `X`") — the runtime object may still differ per path |
| `Unknown` | `True` | a tracked definition was **discarded at a merge** — the paths disagree (a genuinely conditional argument), or one merged edge carried nothing because it came from outside the window or from a block the walk had not resolved yet (which also discards registers that happen to agree). **Do not read it as a proven "two values"; read it as "not proven".** |
| `Unknown` | `False` | no tracked definition **within the window** — never tracked (arithmetic, array load, …), cleared by a later untracked write, defined further back than `depth` blocks with no merge in between, or inside a catch handler |

Raising `depth` can turn **either** flavour into a value; neither flag promises it
will, because a catch handler is a hard stop rather than a radius.

"Cleared by a later untracked write" is the load-bearing half of that table. The
fall-through branch of the analyzer's opcode switch clears nothing, so a writer it
does not enumerate leaves the previous origin in place and reports a value the code had
overwritten — with `crossed_branch` `False`, i.e. as unconditional. The enumeration is
machine-checked against slicer's own instruction table by
`tests/test_arg_opcode_coverage.py`, and dexllm#32 closed the seven holes it found
(ART's runtime-only `iget-*-quick` forms, which reach the analyzer because `VerifyInsns`
bounds registers and indices but has no opcode-legality gate, so a dex carrying one
verifies clean in both strict and lenient mode).

Enumeration completeness is **necessary but not sufficient** for that row: a 64-bit
value occupies a register PAIR, so it is also destroyed by a write to either half.
dexllm#32 closed the aliasing direction too (a narrow write to `vN+1` now invalidates a
wide origin at `vN`). Both are crafted-input corrections — no dex in the test corpus
carries either shape — so they change no result you can observe on ordinary input; they
bound what a hostile or odex-derived one can make this API assert.

Reading `int_value` / `string_value` without checking `kind` yields a silent `0` / `""`
for both `Unknown` flavours — check `kind` first. For an argument whose value depends
on a branch, decompile the caller (`decompile_method` / `decompile_method_ast`),
which carries the real control flow.
```python
for s in dk.resolve_call_args(API):
    a = s.args[1]
    if a.kind == "ConstString":      trust(a.string_value)   # holds on every path
    elif a.crossed_branch:           unproven(s)             # a definition was discarded
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
**The argument is a field REFERENCE, not a field.** One inherited field is
addressed by as many `field_ids` entries as there are classes referencing it —
`Sub;->f:I` and `Base;->f:I` are different descriptors and each answers only for
the accesses spelled its way, so a COMPLETE read/write set is the union over every
reference. Since dexllm#45 `class_fields` no longer surfaces the subclass
spellings; `list_fields()` does:
```python
# the spellings under one class — what class_fields used to surface
C = 'La2dp/Vol/AppChooser$1;'
sorted({f for f in dk.list_fields() if f.startswith(C + '->')})
```
Prefer the `Lcls;->` prefix over a `->name:Type` suffix — the suffix also matches
same-named fields in unrelated hierarchies. `list_fields()` is the raw table, so
it repeats a descriptor once per dex carrying the entry; `set()` before counting.

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
em.descriptor       # 'Landroid/accessibilityservice/AccessibilityServiceInfo;->getCanRetrieveWindowContent()Z'
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
`ExternalMethodRef` (the convenience that resolves `ref.descriptor` and calls
`find_call_sites_to`).

---

## 7. Class summary & capabilities

### `dk.get_class_summary(class_descriptor: str) -> ClassSummary`
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
s.fields                  # []                          (list[FieldInfo])
s.methods                 # [MethodInfo(<init>()V), MethodInfo(convertDpToPixel(...)I), ...]
```
Every `access_flags` here — on the class and on each member — is the **raw dex
bits**, with no `java.lang.reflect.Modifier` normalization; a method declared
`synchronized` reads `0x20000`, not `0x20`. See
[`ClassSummary`](#classsummary) for why.

`access_flags` is **`None` when the modifiers are UNKNOWN** — never `0`, which is
a legal dex value (package-private, non-static, non-final: 5.1% of the test
corpus's methods, 8.7% of its fields, 34.9% of its classes). One case produces it
(dexllm#41): an **external** class — no `class_data` at all, so the class's own
flags and every member's are unknown, and the members are reconstructed from the
`method_ids` / `field_ids` entries other classes reference.

```python
ext = dk.get_class_summary('Landroid/app/Activity;')     # EXTERNAL class
ext.is_internal, ext.dex_id, ext.access_flags   # (False, -1, None)
[m.access_flags for m in ext.methods][:3]       # [None, None, None]
```

So `f.access_flags & ACC_STATIC` raises `TypeError` on such a member instead of
answering `0`.

**On an INTERNAL class, `fields` and `methods` are what it DECLARES** — which is
why their flags are always known. An inherited field the class only REFERENCES is
not a member (dexllm#45), even though the dex `field_ids` table groups that
reference under the referencing class. (An EXTERNAL class has no `class_data` to
declare anything, so its members are exactly those references — see above.) Read
the references from `list_fields()`, the whole table:

```python
C = 'Landroid/support/graphics/drawable/VectorDrawableCompat$VClipPath;'
[f.name for f in dk.get_class_summary(C).fields]              # [] — it declares none
[f for f in dk.list_fields() if f.startswith(C + '->')]       # the 3 it inherits from $VPath
```

Render a summary as Java-source-style text (header + fields + methods). The fields
are in `field_ids` order, **not** grouped static-then-instance the way
`decompile_class` emits them — so the two agree on the set but not the order (this
line claimed static→instance before dexllm#45; it never did):
```python
dexllm.format_class(dk, 'Lcom/example/android/tvleanback/Utils;')   # str — fetch + format
dexllm.format_class_summary(s, indent='    ')                       # str — format an already-fetched ClassSummary
```

### `dexllm.summarize_capabilities(dk, *, app_only=True, only_categories=None, data_dir=None) -> CapabilityReport`
Aggregate permission + capability profile over the catalog. `data_dir=` (else
`$DEXLLM_DATA_DIR`, else bundled) points at a directory holding a replacement
`android_api_map.json` — see [§14](#14-overriding-the-bundled-data).
```python
r = dexllm.summarize_capabilities(dk)
r.permissions   # Counter({'android.permission.INTERNET': 2})
                # what the API REQUIRES, at every protection level — not what the app requests
r.categories    # Counter({'STORAGE': 2, 'REFLECTION': 2, 'NETWORK_IO': 2, 'SCHEDULING': 1, 'CRYPTO': 1})
r.flags         # Counter() on this APK; Counter({'IDENTIFIER': 2}) on one calling
                # both getDeviceId overloads (IDENTIFIER also covers getSubscriberId,
                # getSimSerialNumber, getLine1Number, BluetoothAdapter.getAddress)
```
A key is a method descriptor or a field descriptor (the two are unambiguous by
shape, so no schema key says which). Four are the **constructor** of a class an app
subclasses (`AccessibilityService`, `InputMethodService`,
`NotificationListenerService`, `DeviceAdminReceiver`), where a hit means the APK
**declares such a service** — the members are invoked on the app's own subclass or
are callbacks the system calls, and only `super()` is spelled under the framework
class. They aggregate exactly like any other method key. See
[usage](usage.md#reading-an--key-on-a-framework-service) for the three limits
(no manifest check, no ctor-less subclass, one key per ctor overload), for why the
implication is exact only for the two classes AOSP declares `abstract`, and for
why an **interface** needs no key form of its own — for a capability-shaped one
the registration call that hands it to the framework is already an ordinary call
site (`requestLocationUpdates`, `SSLContext.init`), which the corpus demonstrates
on a real APK implementing `LocationListener`.

`app_only=True` (the default since dexllm#49) counts only the app's own callers,
dropping bundled framework / library plumbing by the same predicate and the same
default as [`dangerous_permission_api_callers`](#dexllmdangerous_permission_api_callersdk--dataset_pathnone-app_onlytrue---dict).
An API left with no kept caller drops out of `api_usages` entirely, so a whole
category can disappear — which is the point: on this same APK the unfiltered run
reports `REFLECTION: 120`, of which **2** are the app's, and `USE_FINGERPRINT: 3`,
of which none are (`FingerprintManagerCompat` is merely bundled). `app_only=False`
counts every caller and reproduces the pre-dexllm#49 numbers exactly:
```python
dexllm.summarize_capabilities(dk, app_only=False).categories
# Counter({'REFLECTION': 120, 'SCHEDULING': 8, 'CRYPTO': 8, 'STORAGE': 6, ...})
```
`dropped_touches` / `dropped_apis` report what the filter removed, so an empty
report under the default is distinguishable from an APK that exercises none of
the catalog — the module raises on an unknown `only_categories` tag for exactly
that reason, and on the corpus 11 of the 17 sources that report anything at all
report nothing under the default. Both are 0 when `app_only=False`.

It is a package-prefix heuristic, so read a filtered report as a triage aid and
not as proof of absence. It is wrong in two directions, and only one of them is
safe: a library the list does not name reads as app code and is KEPT (the hits
above are mostly `com.bumptech.glide`), while code that merely *sits* under
`com.google.android.*` — what a repackaged sample does — reads as a library and is
DROPPED. Answer the second with `app_only=False` plus `by_caller`.
The catalog keeps two axes apart: `categories` is a single axis (domain /
behaviour) with no tag implied by another, so one call site is never counted
twice under two names for the same concern (an API that genuinely spans two
domains does count once in each, so `sum(r.categories.values()) >=
r.total_call_sites + r.total_field_accesses` — both totals, because the Counters
count TOUCHES while the totals keep the units apart, dexllm#36); `flags` is the
orthogonal axis a domain tag cannot express
(today only `IDENTIFIER` — the API provably returns a device/user identifier,
rolling up across TELEPHONY / BLUETOOTH / …).

`only_categories=` matches **either** axis, so `{"IDENTIFIER"}` selects the
identifier-returning APIs even though it is a flag. A tag the catalog does not
declare raises `ValueError` rather than returning an empty report.

`r.by_caller` is the caller-indexed view — which method in the app invokes which
catalog API, the transpose of `ApiUsage.callers`:
```python
r = dexllm.summarize_capabilities(dk)
next(iter(r.by_caller.items()), None)
# ('Lcom/example/android/tvleanback/recommendation/RecommendationReceiver;->scheduleRecommendationUpdate(...)',
#  {'Landroid/app/AlarmManager;->setInexactRepeating(IJJLandroid/app/PendingIntent;)V'})
```
It held `{permissions}` until dexllm#35 and was built inside the permission loop,
so an API declaring none registered no callers at all. Every `REFLECTION` /
`PROCESS_EXEC` / `DYNAMIC_LOAD` / `NATIVE_CODE` / `CRYPTO` / `WEBVIEW` / `STORAGE`
entry is permission-less — 156 of the catalog's 281 entries carry no permission
at all, including `Settings$Secure.getString`, the ANDROID_ID read. Measured on the
0.3 catalog at the time, the index covered **17 of the corpus's 317 distinct callers
(5.4%)**; the corpus now has 515 distinct callers under `app_only=False` and every
one is indexed — 52 of them are the apps' own, which is what the default reports.

Either view is derivable from `api_usages`, so `by_caller` is a convenience index
rather than new information; descriptors make it the more primary one, and within
the field the derivation runs only one way — APIs give back permissions and tags,
a permission set could not give back an API:
```python
r = dexllm.summarize_capabilities(dk)
by_api = {h.api_descriptor: h for h in r.api_usages}
for caller, apis in r.by_caller.items():
    {p for a in apis for p in by_api[a].permissions}   # the pre-dexllm#35 value
```
The join is defined WITHIN one report: `only_categories` filters `by_caller` and
`api_usages` together, so joining across two differently filtered calls is
meaningless.

The `dexllm.capability` module also exposes `ApiUsage` / `CapabilityReport` types.

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

### `dexllm.detect_content_providers(dk, *, with_xref=True, xref_limit=300, data_dir=None) -> list`
The `content://` provider query-URIs (SMS / contacts / call-log / calendar handles
that `ContentResolver` takes — the surface `READ_SMS`/`READ_CONTACTS` gate, invisible
to the `@RequiresPermission` signature map because the `Uri` is assembled at runtime)
referenced by the app's value-strings, matched against a bundled AOSP-derived dataset
(`data/content_uris.json`). Returns `[{'uri', 'family', 'methods'}]` sorted by URI; a
dataset URI is a hit iff it occurs as a substring of some value-string.
`family` ∈ `blockednumber` / `bluetooth` / `browser` / `calendar` / `calllog` / `contacts` / `media` / `settings` / `simphonebook` / `sms` / `telephony` / `timezone` / `userdictionary` / `voicemail` — the 14 the BUNDLED dataset uses, and a
test keeps it closed. An override (`data_dir=`) may carry any string: `family` is
validated as a `str`, deliberately, because the whole point of the channel is a
consumer's own triage vocabulary. The `provider` catch-all is GONE (dexllm#31): it was never a family but "unclassified", and at 20 of 209 it
made a tenth of the dataset group under a label that told a consumer nothing
while the entry read as though classification had succeeded. `data_dir=` (else `$DEXLLM_DATA_DIR`) points
at a replacement `content_uris.json` — see [§14](#14-overriding-the-bundled-data).

### `dexllm.detect_permissive_tls(dk, *, with_xref=True) -> list`
The TLS trust components the app DECLARES, and which of them provably accept
everything. Returns `[{'class_descriptor', 'interface_descriptor', 'kind',
'method_descriptor', 'verdict', 'reason', 'constructed_in'}]` sorted by
`(class_descriptor, method_descriptor)`, one row per implementing CLASS — a
descriptor declared in several loaded dexes (an ordinary multidex app, and the norm
for a packer session) yields one row, not one per declaration.

Two components, both **platform** interfaces, so nothing third-party is shipped:

| `kind` | interface | `permissive` iff |
|---|---|---|
| `hostname_verifier` | `javax.net.ssl.HostnameVerifier` | `verify` is exactly a constant 1 loaded into a register and returned |
| `trust_manager` | `javax.net.ssl.X509TrustManager` | `checkServerTrusted` is exactly `return-void` **and is the method the platform would call** — it signals rejection by THROWING, so a body that cannot throw accepts every chain |

`verdict` is `'permissive'` or `'not_proven'`, and **`not_proven` is the absence
of a proof, never "proven safe"**: a verifier that logs and then returns true is
permissive and reported `not_proven`, because proving it needs real dataflow. It
is a string rather than a bool for that reason (`permissive=False` reads as a
clean bill of health, and this analysis cannot issue one). Every implementor is
reported whatever its verdict, so "this app carries a custom TLS trust component"
stays legible.

The second clause is what keeps the tool from ACCUSING a correct app. Conscrypt's
`Platform.checkServerTrusted` casts to `X509ExtendedTrustManager` when it can and
otherwise DUCK-TYPES a 3-argument overload (`…, Socket)` / `…, String)`), reaching
the 2-argument method only when neither exists — so an empty 2-argument body
beside a 3-argument sibling that pins a hostname is a CORRECT trust manager. A
row is therefore declined when the class declares another `checkServerTrusted`,
or when its superclass is not `java.lang.Object` (the overload may be INHERITED,
and `Class#getMethod` searches the whole hierarchy). `HostnameVerifier` needs no
such clause: it declares one method and nothing duck-types it.

Complements `summarize_capabilities`' `CUSTOM_TLS_TRUST` (dexllm#52) rather than
replacing it, and it is a DIFFERENT question rather than a strictly stronger one:
that tag reports the app SUPPLIES its own trust decision (via curated platform
keys like `SSLContext#init`) and cannot say the decision accepts everything, which
is what this says — but a manager written `extends X509ExtendedTrustManager`
declares no interface, so on that shape #52 answers and this does not. Read them
together. What this reaches that no call-site key can is the OkHttp / Volley /
Retrofit install, which is bundled library code with no framework spelling
(dexllm#53).

Bounds, stated rather than discovered: `checkClientTrusted` is deliberately NOT
checked (an empty one is what a CLIENT is supposed to have, so checking it would
report every well-behaved app); `find_classes_implementing` matches a class that
DECLARES the interface, so a trust-all that declares neither — `extends
X509ExtendedTrustManager`, an implementor of a SUB-interface such as the legacy
Apache `X509HostnameVerifier`, or a subclass of the app's own permissive base — is
invisible (all three conservative, all three dexllm#78); a class that is itself an
INTERFACE is skipped, since it would stand in for the implementor that was never
examined; and a class is a dex fact — `constructed_in` (the methods calling one of
its constructors, `[]` when `with_xref=False`) is what separates a live component
from dead code, and an empty one is proof of neither (a component reached only
through reflection has no constructor call site).

### `dexllm.classify_tls_method(kind, smali) -> (verdict, reason)`
The predicate above, pure — takes the `render_method_smali` TEXT, not a `DexKit` —
so the decision that an app disables TLS validation is testable on crafted bodies.
Raises `ValueError` for a `kind` outside the table above; a silent `not_proven`
there would read as "this app does not do this".

---

## 9. Dangerous permission APIs (Python)

Joins AOSP's `@RequiresPermission` map against the APK's external refs →
signature-precise (overload-disambiguated). All three take a keyword-only
`dataset_path=` (else `$DEXLLM_AOSP_DATASET`, else the bundled tables) pointing at
a checkout of the full AOSP dataset.

### `dexllm.dangerous_permission_apis(dk, *, dataset_path=None) -> dict[str, list[str]]`
```python
dexllm.dangerous_permission_apis(dk)
# {'android.permission.ACCESS_COARSE_LOCATION': ['android.location.LocationManager#getLastKnownLocation(String)'],
#  'android.permission.ACCESS_FINE_LOCATION':   ['android.location.LocationManager#getLastKnownLocation(String)', ...]}
```

### `dexllm.dangerous_permission_api_callers(dk, *, dataset_path=None, app_only=True) -> dict`
Same, plus the calling methods (default drops bundled framework/library callers).

### `dexllm.permission_api_callers(dk, *, app_only=True, levels=None, dataset_path=None) -> list`
The full-surface generalisation (issue #14): **all** protection levels, not just the
dangerous slice. Returns `[{"perm", "protectionLevel", "apis": [{"api", "descriptors",
"callers"}]}]` sorted by permission, each group with its real `protectionLevel` bucket
(`dexllm.PERM_LEVELS = (dangerous, signature, internal, normal, other)`); pass `levels=`
to filter. `dk.permission_callers(app_only)` is the C++ engine port shared with the
WASM binding, byte-identical **over the bundled data** — its dataset is compiled
into the extension, so under `dataset_path=` / `$DEXLLM_AOSP_DATASET` this Python
function follows the override and `dk.permission_callers()` does not.
The bundled `perm_api.json` (571 perms — metalava
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
dexllm.method_ref_java('Lcom/foo/Bar;', 'baz', '(I)V')     # 'com.foo.Bar.baz(int) -> void'
dexllm.parse_proto('(ILjava/lang/String;)Z')  # (['I', 'Ljava/lang/String;'], 'Z')  — (param descriptors, return)
dexllm.pretty_proto('(ILjava/lang/String;)Z') # '(int, java.lang.String) -> boolean'
dexllm.method_descriptor('Lcom/foo/Bar;', 'baz', '(I)V')   # 'Lcom/foo/Bar;->baz(I)V'
```

`method_descriptor` builds the wire form the `method_descriptor` PARAMETER of
`find_call_sites_to` / `resolve_call_args` / `decompile_method` consumes, and
that `require_member_descriptor` validates. It was `dexllm.signature()` until
dexllm#68 — a builder and its validator naming one grammar two ways.

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
dexllm.tools.tool_definitions()    # list of 36 MCP tool schemas
```

---

## 13. Return-type object reference

Typed objects returned by the search/ref APIs. All are pybind11-bound; fields
are read-only attributes.

### `ClassRef`
| field | type |
|---|---|
| `descriptor` | `str` |
| `class_idx` | `int` |
| `dex_id` | `int` |

### `MethodRef`
| field | type |
|---|---|
| `descriptor` | `str` |
| `method_idx` | `int` |
| `dex_id` | `int` |

### `FieldRef`
Returned by `find_fields_by_name` (dexllm#37 — the type existed from the start but
had no producer until then).

| field | type |
|---|---|
| `descriptor` | `str` (`Lcls;->name:Type`) |
| `field_idx` | `int` |
| `dex_id` | `int` |

### `ExternalMethodRef`
`class_descriptor`, `name`, `proto`, `return_type`, `descriptor` (`str`);
`java_class`, `java_signature` (`str`); `parameters` (`list[str]`);
`referenced_in_dex_ids` (`list[int]`); `is_constructor`,
`is_static_initializer` (`bool`).

### `ExternalFieldRef` / `ExternalTypeRef`
Field: class/name/type descriptors + `descriptor`. Type: `descriptor` +
`java_type` + `referenced_in_dex_ids`.

### `CallSite`
| field | type | meaning |
|---|---|---|
| `caller_descriptor` | `str` | the calling method |
| `callee_descriptor` | `str` | the API called |
| `caller_dex_id` | `int` | dex the caller lives in |
| `caller_method_idx` | `int` | **dex-local** `method_ids` index — only meaningful paired with `caller_dex_id`, not a stable global id |
| `bytecode_offset` | `int` | byte offset of the invoke, always **inside the caller** |
| `invoke_opcode` | `int` | Dalvik opcode — one of `0x6E`–`0x72` (invoke-kind), `0x74`–`0x78` (…/range), or `0xFA`/`0xFB` (`invoke-polymorphic`, i.e. a `MethodHandle`/`VarHandle` call — reported since dexllm#61). `invoke-custom` is NOT among them: its operand is a `call_site` index, not a method reference |

**Which half is fixed depends on the producing direction** — `find_call_sites_to(X)`
fixes `callee_descriptor` and varies `caller_*` ("who calls X");
`find_call_sites_from(M)` fixes `caller_*` and varies `callee_descriptor`
("what M calls"), so the repeated caller on every element is the queried method.

### `ResolvedCallSite`
All `CallSite` fields plus `args: list[ResolvedArg]`. Only `resolve_call_args` produces
it, i.e. always the reverse direction (callee fixed).

### `ResolvedArg`
Where one argument came from (intra-method).
| field | type | meaning |
|---|---|---|
| `kind` | `str` | exactly one of `ConstString` \| `ConstInt` \| `ConstWide` \| `ConstClass` \| `ConstNull` \| `FieldRead` \| `MethodReturn` \| `Parameter` \| `NewInstance` \| `NewArray` \| `Unknown` — the full set the binding emits |
| `register_index` | `int` | register holding the arg |
| `string_value` | `str` | for string constants |
| `int_value` | `int` | for int constants |
| `class_descriptor` | `str` | for new-instance/type origins |
| `method_descriptor` | `str` | for method-return origins |
| `field_descriptor` | `str` | for field origins |
| `parameter_index` | `int` | for parameter origins (`-1` if n/a) |
| `crossed_branch` | `bool` | `Unknown` only — a definition was DISCARDED at a merge, so the value is UNPROVEN. `crossed_branch` `False` means no definition was found in the window at all — the two flavours are tabled under `resolve_call_args` |

### `MethodInfo` / `FieldInfo`
One member a class DECLARES, carried by `ClassSummary.methods` / `.fields` and by
the SDK's `class_methods` / `class_fields`.

| field | type | meaning |
|---|---|---|
| `name` | `str` | the member's SimpleName |
| `proto` (method) / `type` (field) | `str` | `(args)Ret` / the field's type descriptor |
| `access_flags` | `int \| None` | RAW dex bits; `None` when UNKNOWN (every member of an external class) |
| `class_descriptor` | `str` | the class it is DECLARED on |
| `descriptor` | `str` | the IDENTITY the xref / decompile APIs consume — `Lcls;->name(proto)ret` / `Lcls;->name:Type` |

The last two arrived in dexllm#69: every other member-shaped record already carried
an identity string — `MethodRef`, `ExternalMethodRef`, `ClassSummary` — and `*Info`
was the only one without, so a caller reading `class_methods()` had to re-assemble it
by hand. `descriptor` is COMPUTED from `class_descriptor` plus the member's own
fields, so the two cannot disagree.

### `ClassSummary`
`descriptor`, `superclass_descriptor`, `source_file` (`str`); `dex_id` (`int`);
`access_flags` (`int | None`); `is_internal` (`bool`); `interface_descriptors`
(`list[str]`); `fields` (`list[FieldInfo]`); `methods`
(`list[MethodInfo]`).

**`access_flags` is `None` when UNKNOWN** — every entity of an external class; see
[`get_class_summary`](#dkget_class_summaryclass_descriptor-str---classsummary).
It was `0` before dexllm#41, which collided with the legal dex value `0`.
On an INTERNAL class `fields` / `methods` list only what it DECLARES (dexllm#45);
an external one has no `class_data`, so its members are the references others make.

**Access flags are the RAW dex bits** — the values as stored in the file, with no
`java.lang.reflect.Modifier` normalization, on the class and on every member. In
particular a method declared `synchronized` in Java carries
`ACC_DECLARED_SYNCHRONIZED` (`0x20000`), **not** `ACC_SYNCHRONIZED` (`0x20`) — in
dex, `0x20` means JNI `synchronized native`, a different property. (Upstream
DexKit rewrote `0x20000` → `0x20` for Modifier compatibility; dexllm removed that
because it conflates the two and because the decompiler already reported the raw
form, so one method described itself two ways.) The same bits drive the
`declared_synchronized` modifier in `decompile_class` /
`decompile_method_ast(...)["access_flags"]`.

### `CapabilityReport`
`permissions: collections.Counter[str]`, `categories: collections.Counter[str]`,
`flags: collections.Counter[str]`, `by_caller: dict[str, set[str]]` (caller
descriptor → the catalog API descriptors it invokes — dexllm#35; it was
`→ {permissions}` before), `api_usages: list[ApiUsage]`, `total_call_sites: int`
(invoke instructions), `catalog_version: str`, `catalog_size: int`,
`matched_apis: int`, `dropped_touches: int` / `dropped_apis: int` (what
`app_only=True` filtered out — 0 under `app_only=False`; see above),
`total_field_accesses: int` (READ INSTRUCTIONS against a
field-descriptor entry — dexllm#36; `find_methods_reading_field` is not
deduplicated, so this is the same unit as the line above and summing them is
meaningful. The two are kept apart only so `total_call_sites`' released meaning
is untouched).

---

## 14. Overriding the bundled data

Two of the four files in `dexllm/data/` carry **hand judgement**, so they take an
override: the capability catalog (`android_api_map.json`) and the `family` labels
in `content_uris.json`. The catalog is generated
(`scripts/gen_capability_catalog.py` resolves descriptors and permissions out of
the AOSP dataset), but WHICH APIs it names is a curated selection — that is the
judgement, and it is what an override replaces.

```python
dexllm.summarize_capabilities(dk, data_dir="/etc/dexllm")
dexllm.detect_content_providers(dk, data_dir="/etc/dexllm")
```

| | |
|---|---|
| resolution | `data_dir=` → `$DEXLLM_DATA_DIR` → bundled; an **empty** value means "not configured" through either spelling |
| granularity | **per file** — a directory holding only one of the two still serves the bundled other |
| semantics | whole-file **replacement**, not a merge |
| bad directory | `NotADirectoryError` naming which of the two spellings supplied it — checked per call, so a vanished directory fails loudly instead of serving a stale cache |
| entry that is not a regular file | `OSError` naming the path — a directory, a FIFO or a **dangling symlink** is a misconfiguration, not a partial override; only a genuinely absent file falls back. An override directory that exists but is **empty** is not an error: it cannot be told apart from a deliberate partial override |
| malformed file | `ValueError` naming the path (invalid JSON, non-UTF-8 bytes, or a wrong shape — including a tag list written as a bare string) |
| caching | per `resolve()`d path, bounded (16) — the parsed data, and the decision to use an **override**, so a `rm` + `cp` redeploy cannot demote a running server to bundled data mid-request. Above the bound the evicted decisions are re-made. A bundled **fallback** is re-decided every call, so an override appearing later is picked up and a transient failure cannot pin bundled data for the process lifetime |
| unset value | `None` or `""`. NOT `Path("")` — pathlib turns it into `Path(".")`, a real request for the process directory |

`$DEXLLM_DATA_DIR` is the form that also reaches the MCP and HTTP servers, which
take no such argument. The permission tables (`perm_api.json` / `perm_levels.json`)
are deliberately **not** here — they are mechanical extraction with no hand
content, and [`dataset_path=`](#9-dangerous-permission-apis-python) /
`$DEXLLM_AOSP_DATASET` already serve a fresher AOSP snapshot.

### `dexllm.clear_data_caches() -> None`
Drop the parsed data and the frozen override decisions. Not needed to switch
`data_dir` (both are keyed by resolved path), nor to pick up an override that
appears later (a bundled fallback is re-decided every call) — only to pick up a
change at a path already in use: bytes edited in place, or the file replaced.

---

## Typed SDK API (`dexllm.sdk`)

For embedding, `dexllm.sdk` wraps this surface in ports & adapters:
`@runtime_checkable` Protocol ports + frozen-dataclass models with an accurate
type on every argument/return.

```python
from dexllm.sdk import open_apk, identify, DexAnalysisUseCase

session: DexAnalysisUseCase = open_apk("app.apk")   # or open_apk([dump, apk], lenient=True)
session.decompile_method("Lcom/x/Y;->m(I)V")        # -> DecompiledMethod
session.permission_callers(app_only=True)           # -> tuple[PermissionCallers]
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
  objects. Read `.descriptor` to get back a string — `signature` is reserved
  for the dotted Java rendering (`java_signature`), which dexllm#68 made the
  rule rather than a coincidence. Two ROLE names on those records also hold a
  descriptor and say what it IS rather than repeating the word (`type` on a
  field ref, `return_type` / `parameters` on a method ref). dexllm#69 closed the
  rest: the SDK used to drop the suffix on `ClassInfo.superclass` / `.interfaces`
  where raw says `superclass_descriptor` / `interface_descriptors`, and
  `MethodAst` said `class_name` for a value that is a descriptor — all three now
  agree with the raw layer, so the audit's DRIFT list is empty.
- **Threading.** Decompile calls release the GIL — parallelize across threads
  for whole-APK sweeps. Use the `safe_*` wrappers in automation.
- **Framework filtering.** `is_framework_descriptor` + the `filter_*_refs`
  helpers separate app code from bundled androidx/kotlin/play-services.
