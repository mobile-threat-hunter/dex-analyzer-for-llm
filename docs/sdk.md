# `dexllm.sdk` — typed SDK (ports & adapters)

A **hexagonal (ports & adapters)** interface over `dexllm.DexKit`. It exists so
other code consumes dexllm as a **typed domain service** — programming against
Protocol interfaces and frozen-dataclass value objects — instead of against raw
`dict` keys and pybind struct attributes.

```
   consumer code
        │  (depends only on ports + models — never on DexKit)
        ▼
   ports.py   ──  @runtime_checkable Protocol use cases  (the CONTRACT)
        ▲
        │  implements
   adapter.py ──  DexKitAdapter  (raw pybind/dict  ──►  typed models)
        │
        ▼
   dexllm.DexKit  (the existing C++-backed engine)

   model.py   ──  frozen dataclasses  (the VALUE OBJECTS crossing every boundary)
```

Three components, three files:

| Component | File | What it is |
|---|---|---|
| **Domain models** | [`model.py`](../src/dexllm/sdk/model.py) | 25 frozen dataclasses — the typed values every port returns/accepts. |
| **Ports** | [`ports.py`](../src/dexllm/sdk/ports.py) | 12 `@runtime_checkable` Protocol use cases + the composite `DexAnalysisUseCase`. |
| **Adapter** | [`adapter.py`](../src/dexllm/sdk/adapter.py) | `DexKitAdapter` (implements the ports over `DexKit`) + `ContainerProbe` + `open_apk` / `identify` factories. |

---

## Quick start

```python
from dexllm.sdk import open_apk, identify, DexAnalysisUseCase

info = identify("app.apk")                       # ContainerInfo (no load)
session: DexAnalysisUseCase = open_apk("app.apk")  # or open_apk([dump, apk], lenient=True)

for g in session.permission_callers(app_only=True):   # tuple[PermissionCallerGroup]
    print(g.permission, g.protection_level, len(g.rows))

m   = session.decompile_method("Lcom/x/Y;->m(I)V")    # DecompiledMethod
ioc = session.extract_iocs()                          # IocReport
session.raw                                            # the underlying DexKit (escape hatch)
```

Annotate with `DexAnalysisUseCase` and an IDE / mypy surfaces every method and its
typed return.

---

## Component 1 — Domain models (`model.py`)

Every value crossing a port boundary is a `@dataclass(frozen=True)`. Sequence
fields are `tuple`s; `Mapping` fields are read-only views. See
[Conventions](#conventions) for the immutability / hashability rules.

### Loading & probing
- **`ContainerInfo`** `(format, is_apk, has_manifest, dex_count)` — content-based
  file probe. `format` ∈ `"dex" | "zip" | "unknown"`.
- **`DexVerifyStatus`** `(dex_id, name, valid, reason)` — one loaded dex's
  structural-verification verdict; `reason` is empty when `valid`.

### Decompilation
- **`SourceLocation`** `(line, byte_offset)` — one line ↔ bytecode-offset entry.
  `line` is a 1-based index into `source.split("\n")` (only `\n` delimits).
- **`StatementLocation`** `(statement_index, byte_offset)` — the **AST** map entry.
  `statement_index` is a post-order-DFS statement number, **not** a line — which is
  why it is a distinct type from `SourceLocation`.
- **`DecompiledMethod`** `(descriptor, source, found, pc_map)` — Java text of one
  method. `found` = non-empty `source` produced (see [`found` semantics](#found)).
- **`DecompiledClass`** `(descriptor, source)` — full Java text of one class.
- **`MethodAst`** `(found, class_name, name, proto, return_type, param_types,
  access_flags, source, ast, pc_map)` — the DAD nested-list AST. `ast` is a
  read-only mapping `{triple, flags, ret, params, comments, body}` **or `None`**
  for a not-found method; `pc_map` is a tuple of `StatementLocation`.

### Enumeration
- **`ExternalMethodRef`** `(class_descriptor, name, proto, java_class,
  java_signature, signature, return_type, parameters, is_constructor,
  is_static_initializer, referenced_in_dex_ids)` — a framework/library method the
  app references but does not define.
- **`ExternalFieldRef`** `(class_descriptor, name, type, java_class, java_type,
  java_signature, signature, referenced_in_dex_ids)` — the field analogue.
- **`ExternalTypeRef`** `(descriptor, java_name, referenced_in_dex_ids)` — a
  framework/library type the app references but does not declare (may be an array
  descriptor, e.g. `[Landroid/content/Intent;`).

### Search (L1–L7)
DexKit's headline capability — fast static class/method search (`SearchPort`). A hit
is a light match record; `MatchType` is the name-match mode.
- **`MatchType`** = `Literal["equals", "contains", "starts_with", "ends_with", "regex"]` — note `regex` is DexKit's *SimilarRegex* (`^`/`$` anchors only, not full regex).
- **`ClassMatch`** `(class_id, descriptor, dex_id)` — one class hit.
- **`MethodMatch`** `(method_id, descriptor, dex_id)` — one method hit. The `batch_*`
  searches return `Mapping[str, tuple[Match, ...]]` keyed by the query key.

### Class inspection
The C++ `get_class_summary` bundles class metadata + fields + methods into one
object; the SDK layer splits it (ISP) so a consumer depends only on what it
needs (methods stay on `EnumerationPort.list_class_methods`).
- **`ClassInfo`** `(descriptor, dex_id, is_internal, access_flags, superclass,
  interfaces, source_file, dex_name)` — class metadata, no members. `dex_name` is the
  declaring dex's file name (`classes.dex` / `classes2.dex` / …); `""` for an external
  class (`dex_id == -1`).
- **`FieldInfo`** `(name, type, access_flags)` — one declared field; its descriptor
  is `f"{cls}->{name}:{type}"`.

### Cross-reference
- **`ArgOrigin`** `(kind, reg_num, string_value?, int_value?, class_descriptor?,
  field_signature?, method_signature?, parameter_index?)` — the provenance of one
  invoke argument. Only the field its `kind` carries is set; `kind` ∈ ConstString /
  ConstInt / ConstWide / ConstClass / ConstNull / FieldRead / MethodReturn /
  Parameter / NewInstance / NewArray / Unknown.
- **`CallSite`** `(caller_descriptor, caller_dex_id, caller_method_idx,
  callee_descriptor, bytecode_offset, invoke_opcode)` — one invoke edge. Returned by
  both `find_call_sites` (a target's CALLERS — callee fixed) and
  `find_call_sites_from_method` (a method's CALLEES — caller fixed); the two are the
  reverse and forward of the same edge.
- **`ResolvedCallSite`** — a `CallSite` plus `args: tuple[ArgOrigin, ...]`.
- Field read/write xref (`find_field_readers` / `find_field_writers`) returns plain
  method descriptors `tuple[str, ...]` — the methods that iget*/sget* (read) or
  iput*/sput* (write) a `Lcls;->name:Type` field (from dexkit's L2.5 reverse index).
- **`TypeReferences`** `(fields, methods_returning, methods_with_param)` —
  `find_type_references(Lpkg/Cls;)` signature-position xref: where a type appears as
  a field type, a method return type, or a method parameter (each a `tuple[str]`).

### Permission analysis
- **`PermissionCallerRow`** `(api, descriptors, callers)` — one gated API and the
  app methods that call it.
- **`PermissionCallerGroup`** `(permission, protection_level, rows)` — a permission,
  its protection-level bucket, and its referenced gated APIs (ALL protection levels).
  See the [protection-level reference](#protection-levels). The dangerous-only view
  is a one-liner filter (`[g for g in permission_callers(app_only=False) if
  g.protection_level == "dangerous"]`).

### Indicators (IOC)
- **`Indicator`** `(value, methods)` — one network indicator + the app methods
  referencing it (`methods` empty without cross-reference).
- **`IocReport`** `(urls, ips, domains, emails, onion)` — each a tuple of
  `Indicator`; defang-aware, public-suffix-validated.

### Capabilities
- **`CapabilityHit`** `(api_signature, call_site_count, permissions, categories,
  callers)` — one catalog API the app exercises.
- **`CapabilityReport`** `(catalog_version, catalog_size, matched_apis,
  total_call_sites, permissions, categories, api_hits, by_caller)` — the app's
  capability profile (holds `Mapping`s → immutable, **not hashable**).

### Content providers
- **`ContentProviderUse`** `(uri, family, methods)` — a `content://` provider URI
  the app references (the runtime-assembled surface the `@RequiresPermission` map
  misses). `family` ∈ sms / contacts / call-log / calendar / …

---

## Component 2 — Ports (`ports.py`)

Each port is a `@runtime_checkable` `typing.Protocol` — a **structural** contract:
any object with the right methods satisfies it (test doubles need no base class),
and `isinstance(x, SomePort)` verifies method presence at runtime. Split by concern
so a consumer depends on just what it needs:

| Port | Methods |
|---|---|
| **`ContainerProbePort`** | `identify(path) -> ContainerInfo` |
| **`DecompilationPort`** | `decompile_method`, `decompile_method_with_pc_map`, `decompile_class`, `decompile_method_ast`, `render_method_smali`, `render_class_smali` |
| **`EnumerationPort`** | `list_classes` / `list_classes_in_dex`, `list_class_methods`, `list_field_descriptors` / `list_field_descriptors_in_dex`, `list_method_descriptors` / `list_method_descriptors_in_dex`, `list_value_strings`, `list_external_method_refs` / `list_external_field_refs` / `list_external_type_refs`, `verify_report` (uniform scope axis: bare = all dexes, `…_in_dex(dex_id)` = one dex) |
| **`DexExtractionPort`** | `extract_dex_bytes` (raw per-dex byte extraction; packer/dump primitive) |
| **`ClassInspectionPort`** | `class_info`, `class_fields`, `locate_class_dex` (metadata + fields split out; methods via `list_class_methods`; `locate_class_dex` = cheap declaring-dex lookup, vs the heavy `class_info().dex_id`) |
| **`CrossReferencePort`** | `find_call_sites` (callers) / `find_call_sites_from_method` (callees — the forward edge), `resolve_call_args`, `find_field_readers`, `find_field_writers`, `find_type_references` |
| **`SearchPort`** | `find_classes_by_name` / `by_super` / `implementing` / `by_annotation` / `using_strings`, `find_methods_by_name` / `by_annotation` / `using_strings` / `using_int_literals` / `using_double_literals`, `batch_find_{classes,methods}_using_strings` (DexKit's L1–L7 search; `match_type` ∈ `MatchType`) |
| **`PermissionAnalysisPort`** | `permission_callers` (all protection levels) |
| **`IndicatorExtractionPort`** | `extract_iocs` |
| **`CapabilityPort`** | `summarize_capabilities` |
| **`ContentProviderPort`** | `detect_content_providers` |
| **`CacheControlPort`** | `decompiler_cache_capacity` / `set_decompiler_cache_capacity` / `decompiler_cache_size` / `clear_decompiler_cache`, `warm_analysis_caches` (operational cache/lifecycle knobs, not analysis — a long-lived embedder bounds/frees/warms caches without dropping to `.raw`) |

**`DexAnalysisUseCase`** composes the eleven session-bound ports (every port except
`ContainerProbePort`, which is load-free) and adds `sources` / `apk_path` (=
`sources[0]`) / `dex_count()`. It is
the single interface a consumer annotates against — the analogue of a top-level
application use-case interface.

> `@runtime_checkable` checks method **presence only**, not signatures or types —
> static checking (mypy) covers the rest.

---

## Component 3 — Adapter & factories (`adapter.py`)

- **`DexKitAdapter`** — wraps one loaded `DexKit` and converts every raw return
  (pybind objects, dicts) into the typed models, so it satisfies
  `DexAnalysisUseCase`. Constructed from a single path or a sequence (earlier
  sources get lower dex_ids → first-wins on a class collision); `lenient=True` runs
  the load-time verifier in ART-structural-equivalent mode for partially-decrypted
  dumps. Accepts `str` or `os.PathLike`. **`.raw`** exposes the underlying `DexKit`
  as an escape hatch (e.g. for L7 search not surfaced by a port).
- **`ContainerProbe`** — the object implementing `ContainerProbePort` (stateless).
- **`open_apk(sources, *, lenient=False) -> DexKitAdapter`** — the factory; returns
  a `DexAnalysisUseCase`.
- **`identify(path) -> ContainerInfo`** — the load-free probe (functional form of
  `ContainerProbe`).

The adapter is the ONLY component that imports `dexllm.DexKit`; models and ports
have no engine dependency, so a consumer (or a test) can depend on the contract
alone.

---

## Conventions

### Immutability & hashability
- All models are `frozen=True` (no attribute rebinding).
- Sequence fields are `tuple`s; `Mapping` fields
  (`CapabilityReport.permissions/categories/by_caller`, `MethodAst.ast`) are wrapped
  in a read-only `MappingProxyType` — so no model can be mutated in place.
- **Hashable:** the value-object models (only tuple/scalar fields) are hashable.
  The two that carry a `Mapping` — `CapabilityReport`, `MethodAst` — are frozen but
  **not** hashable; do not use them as a set member / dict key.

### <a name="found"></a>`found` semantics
- `DecompiledMethod.found` = "non-empty Java `source` was produced" — `False` for an
  external/framework ref and for the rare located-but-empty emit.
- `MethodAst.found` = "the method was **located**" (from the engine), independent of
  whether emission produced text. The two can differ on a located-but-empty method;
  `MethodAst.ast` is `None` when not found.

### Empty results
Enumeration / analysis methods return an **empty tuple** (never `None`) when nothing
matches; `decompile_*` return a model with `found=False` / empty `source`.

---

## <a name="protection-levels"></a>Protection-level reference

`PermissionCallerGroup.protection_level` (Android `protectionLevel`, bucketed):

| Bucket | Granted how | A normal app can hold it? | Triage meaning |
|---|---|---|---|
| **dangerous** | runtime user consent (API 23+) | ✅ if the user allows | Touches private data / sensitive functions (CAMERA, READ_SMS, ACCESS_FINE_LOCATION). Primary "handles sensitive data" signal. |
| **normal** | auto-granted at install | ✅ any app | Low risk (INTERNET, ACCESS_NETWORK_STATE, VIBRATE). |
| **signature** | same signing key as the declarer | ❌ platform/OEM only | A non-system app *referencing* it (MANAGE_USERS, STATUS_BAR_SERVICE, INTERACT_ACROSS_USERS) is a notable signal — privilege probing / repackaged system code / library FP. |
| **internal** | internal flags (role / installer), A12+ | ❌ | Not obtainable by a normal app. |
| **other** | no / unknown `protectionLevel` | — | Catch-all. |

`permission_callers()` returns **all** levels; filter to
`g.protection_level == "dangerous"` for the dangerous-only view. (The raw
reference-level `dexllm.dangerous_permission_apis(dk)` is still reachable via
`session.raw` if you need it.)

---

Full narrative walkthrough: [`docs/usage.md`](usage.md#typed-sdk--ports--adapters-dexllmsdk).
API reference: [`docs/api.md`](api.md#typed-sdk-api-dexllmsdk).
