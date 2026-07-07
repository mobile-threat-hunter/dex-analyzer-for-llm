# dexllm — API Reference

Complete reference for the `dexllm` Python API: every method, its exact return
type, and a real example output captured from
`test_apk/APK/com.example.android.tvleanback.apk`.

For a task-oriented walkthrough (the L1–L7 analysis levels), see
[usage.md](usage.md). This document is the flat reference.

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

### `dk.list_value_strings() -> list[str]`
Every distinct string the app **loads as a value** (`const-string`/`jumbo` +
static-field `VALUE_STRING` initializers), MUTF-8→UTF-8, deduplicated. Excludes
identifier/metadata pool entries. This is the IOC feed.
```python
dk.list_value_strings()    # len 4939
# ['An entry modification is not supported', '=', ...]
```

---

## 3. Decompilation (DAD-aligned Java)

### `dk.decompile_method_java(desc: str) -> str`
Java text for a single method. GIL released. Empty string for external refs.
```python
dk.decompile_method_java('Lcom/example/android/tvleanback/Utils;->convertDpToPixel(Landroid/content/Context;I)I')
```
```java

public static int convertDpToPixel(android.content.Context p2, int p3)
{
    return Math.round((((float) p3) * p2.getResources().getDisplayMetrics().density));
}
```

### `dk.decompile_method_java_with_pc(desc: str) -> dict`
**D-3** — Java text + a source-line ↔ dex bytecode-offset map for smali sync.
```python
dk.decompile_method_java_with_pc(M)
# {'source': '\npublic static int convertDpToPixel(...)...',
#  'pc_map': [(4, 32)]}
```
| key | type | meaning |
|---|---|---|
| `source` | `str` | same bytes as `decompile_method_java` |
| `pc_map` | `list[tuple[int, int]]` | `(line_1based, byte_off)`; one entry per emitted line that maps to a dex op; `line` = 1-based index into `source.split("\n")` (**use `\n`, not `splitlines()`**) |

### `dk.decompile_class_java(cls_desc: str) -> str`
Full Java class text — `package`, class header (access + extends + implements),
static→instance field declarations with decoded EncodedValue initializers, then
method bodies. The header+fields region is byte-identical to androguard
`DvClass.get_source()`.

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

---

## 5. Search family (L1–L7)

The `find_*` methods return **typed match objects** (not strings). Their common
fields are listed in [§13](#13-return-type-object-reference).

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
Every invoke of a specific API descriptor (internal or external).
```python
dk.find_call_sites_to_api('Landroid/content/Context;->getSystemService(Ljava/lang/String;)Ljava/lang/Object;')
# list[CallSite]  len 54
```

### Intra-method arg resolution → `list[ResolvedCallSite]`
Same as call sites, plus the resolved origin of each argument (L4 dataflow).
```python
dk.resolve_call_args('Landroid/content/Context;->getSystemService(Ljava/lang/String;)Ljava/lang/Object;')
# list[ResolvedCallSite]  len 54; each has .args -> list[ArgOrigin]
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

### `dexllm.summarize_capabilities(dk) -> CapabilityReport`
Aggregate permission + category profile.
```python
r = dexllm.summarize_capabilities(dk)
r.permissions   # Counter({'android.permission.INTERNET': 3, 'android.permission.ACCESS_FINE_LOCATION': 1, ...})
r.categories    # Counter({'REFLECTION': 3476, 'CRYPTO': 202, 'RISKY': 45, ...})
```
The `dexllm.capability` module also exposes `ApiHit` / `CapabilityReport` types.

### `dk.summarize_capabilities_native() -> dict`
The **C++ engine port** of `summarize_capabilities` (issue #13, Phase 2), returning
the report as a dict (`permissions`, `categories`, `by_caller`, `api_hits`,
`total_call_sites`, `catalog_version`, `catalog_size`, `matched_apis`) over the
engine-bundled catalog (`native/core_ext/gen/android_api_data.h`). Byte-identical to
the Python path (`tests/test_capability_native.py`); it exists so the WASM (embind)
binding and pybind share one join. Prefer `summarize_capabilities` in Python code.

---

## 8. IOC extraction (Python)

### `dexllm.extract_iocs(dk, *, with_xref=True, denoise=True, xref_limit=300) -> dict`
Static network-IOC over `list_value_strings()`. Defang-aware, public-suffix-
validated (tldextract).
```python
dexllm.extract_iocs(dk).keys()          # dict_keys(['urls', 'ips', 'domains', 'emails', 'onion'])
# each value is a list of {'value': str, 'methods': list[str]} when with_xref=True:
# {'domains': [{'value': 'dolby.com', 'methods': ['L.../DashManifestParser;->parseAudioChannelConfiguration(...)V']}], ...}
```
`dexllm.IOC_CATEGORIES == ('urls', 'ips', 'domains', 'emails', 'onion')`.

### `dk.extract_iocs_native(with_xref=True, denoise=True, xref_limit=300) -> dict`
The **C++ engine port** of `extract_iocs` (issue #13), returning the identical
`{category: [{'value', 'methods'}]}` shape and byte-identical results (verified by a
full-corpus + fuzz differential, `tests/test_ioc_native.py`). It exists so the WASM
(embind) binding and pybind share ONE implementation over the engine-bundled
public-suffix data (`native/core_ext/gen/psl_data.h`), instead of a consumer
re-implementing the scan and shipping its own PSL copy. Prefer the Python
`extract_iocs` in Python code; this is the WASM-shared backend.

### `dexllm.detect_content_providers(dk, *, with_xref=True, xref_limit=300) -> list`
The `content://` provider query-URIs (SMS / contacts / call-log / calendar handles
that `ContentResolver` takes — the surface `READ_SMS`/`READ_CONTACTS` gate, invisible
to the `@RequiresPermission` signature map because the `Uri` is assembled at runtime)
referenced by the app's value-strings, matched against a bundled AOSP-derived dataset
(`data/content_uris.json`). Returns `[{'uri', 'family', 'methods'}]` sorted by URI; a
dataset URI is a hit iff it occurs as a substring of some value-string.
`dk.detect_content_providers_native(with_xref=True, xref_limit=300)` is the
byte-identical C++ engine port shared with the WASM binding (issue #13).

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
dk.decompiler_set_cache_capacity(8192)  # None   (0 = unbounded)
dk.decompiler_clear_cache()             # None
```

---

## 12. Descriptor helpers & safe wrappers (Python)

### Descriptor conversion
```python
dexllm.descriptor_to_java('Lcom/foo/Bar;')     # 'com.foo.Bar'
dexllm.java_to_descriptor('com.foo.Bar')       # 'Lcom/foo/Bar;'
dexllm.is_framework_descriptor('Landroid/app/Activity;')   # True
dexllm.method_ref_java('Lcom/foo/Bar;->baz(I)V')           # human-readable form
```

### Safe (hang-guarded) decompile wrappers
Run the decompile on a daemon thread with a wall-clock deadline. **Use in
batch/CI/automation** (belt-and-suspenders vs the IR-level cap).
```python
out = dexllm.safe_decompile_method_java(dk, desc, timeout=10.0)   # -> str
out = dexllm.safe_decompile_class_java(dk, cls, timeout=10.0)     # -> str
if dexllm.is_timeout_marker(out):
    ...   # hit the deadline
dexllm.DEFAULT_TIMEOUT_S    # 10.0
```

### MCP tool definitions
```python
dexllm.tools.tool_definitions()    # list of 18 MCP tool schemas
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
| `caller_dex_id` | `int` | |
| `caller_method_idx` | `int` | |
| `bytecode_offset` | `int` | byte offset of the invoke |
| `invoke_opcode` | `int` | Dalvik opcode (e.g. 110 = `invoke-virtual`) |

### `ResolvedCallSite`
All `CallSite` fields plus `args: list[ArgOrigin]`.

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

### `CapabilityReport`
`permissions: collections.Counter[str]`, `categories: collections.Counter[str]`.

---

## Typed hexagonal API (`dexllm.hexagonal`)

For embedding, `dexllm.hexagonal` wraps this surface in ports & adapters:
`@runtime_checkable` Protocol ports + frozen-dataclass models with an accurate
type on every argument/return.

```python
from dexllm.hexagonal import open_apk, identify, DexAnalysisUseCase

session: DexAnalysisUseCase = open_apk("app.apk")   # or open_apk([dump, apk], lenient=True)
session.decompile_method("Lcom/x/Y;->m(I)V")        # -> DecompiledMethod
session.permission_callers(app_only=True)           # -> tuple[PermissionCallerGroup]
session.extract_iocs()                              # -> IocReport
session.raw                                          # underlying DexKit (escape hatch)
```

Ports: `DexAnalysisUseCase` (composite) + `DecompilationPort` / `EnumerationPort`
/ `ClassInspectionPort` / `CrossReferencePort` / `PermissionAnalysisPort` /
`IndicatorExtractionPort` / `CapabilityPort` / `ContentProviderPort` /
`ContainerProbePort`. Full walkthrough
in [usage.md](usage.md#typed-api--hexagonal-ports--adapters-dexllmhexagonal);
source in `src/dexllm/hexagonal/`.

---

## Notes

- **Descriptors in / typed objects or strings out.** Enumeration + decompile
  return `str`; search returns typed match objects; refs return typed ref
  objects. Read `.descriptor` / `.signature` to get back a string.
- **Threading.** Decompile calls release the GIL — parallelize across threads
  for whole-APK sweeps. Use the `safe_*` wrappers in automation.
- **Framework filtering.** `is_framework_descriptor` + the `filter_*_refs`
  helpers separate app code from bundled androidx/kotlin/play-services.
