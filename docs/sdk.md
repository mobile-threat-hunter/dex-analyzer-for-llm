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
| **Domain models** | [`model.py`](../src/dexllm/sdk/model.py) | 28 frozen dataclasses — the typed values every port returns/accepts. |
| **Ports** | [`ports.py`](../src/dexllm/sdk/ports.py) | 12 `@runtime_checkable` Protocol use cases + the composite `DexAnalysisUseCase`. |
| **Adapter** | [`adapter.py`](../src/dexllm/sdk/adapter.py) | `DexKitAdapter` (implements the ports over `DexKit`) + `ContainerProbe` + `open_apk` / `identify` / `verify` factories. |

---

## Quick start

```python
from dexllm.sdk import open_apk, identify, DexAnalysisUseCase

info = identify("app.apk")                       # ContainerInfo (no load)
session: DexAnalysisUseCase = open_apk("app.apk")  # or open_apk([dump, apk], lenient=True)

for g in session.permission_callers(app_only=True):   # tuple[PermissionCallers]
    print(g.permission, g.protection_level, len(g.apis))

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
- **`ContainerInfo`** `(format, is_apk, has_manifest, dex_count, source)` — content-based
  file probe. `format` ∈ `"dex" | "zip" | "unknown"`.
- **`DexVerifyStatus`** `(dex_id, name, valid, reason, source)` — one loaded dex's
  structural-verification verdict; `reason` is empty when `valid`. `name` is the
  entry name for a zip member but the file path for a bare `.dex`, so `source` —
  the path handed to the session — is what identifies it (dexllm#26).
- **`ExtractedDex`** `(dex_id, data, source, entry, offset, size)` — one dex's
  bytes plus its provenance, returned by `extract_dex`. `data` is spelled `bytes`
  on the raw `DexKit.extract_dex` dict (a `bytes: bytes` dataclass field would
  shadow the builtin in its own annotation scope). `offset` indexes the **loaded
  image** — the decompressed `entry` when `entry` is set, otherwise the file at
  `source` — so a packer apk whose `classes.dex` is two concatenated dexes has
  `entry` set **and** a nonzero `offset`.

### Decompilation
- **`SourceLocation`** `(line, byte_offset)` — one line ↔ bytecode-offset entry.
  `line` is a 1-based index into `source.split("\n")` (only `\n` delimits).
- **`StatementLocation`** `(statement_index, byte_offset)` — the **AST** map entry.
  `statement_index` is a post-order-DFS statement number, **not** a line — which is
  why it is a distinct type from `SourceLocation`.
- **`DecompiledMethod`** `(descriptor, source, found, pc_map)` — Java text of one
  method. `found` = non-empty `source` produced (see [`found` semantics](#found)).
- **`DecompiledClass`** `(descriptor, source)` — full Java text of one class.
- **`MethodAst`** `(found, class_descriptor, name, proto, return_type, param_types,
  access_flags, source, ast, pc_map)` — the DAD nested-list AST. `ast` is a
  read-only mapping `{triple, flags, ret, params, comments, body}` **or `None`**
  for a not-found method; `pc_map` is a tuple of `StatementLocation`. Note
  `access_flags` here is `tuple[str, ...]` — decoded modifier NAMES
  (`('public', 'static')`) — unlike the `int` bit-field on `ClassInfo` /
  `FieldInfo` that shares the name.

### Enumeration
- **`ExternalMethodRef`** `(class_descriptor, name, proto, descriptor, java_class,
  java_signature, return_type, parameters, is_constructor,
  is_static_initializer, referenced_in_dex_ids)` — a framework/library method the
  app references but does not define.
- **`ExternalFieldRef`** `(class_descriptor, name, type, descriptor, java_class,
  java_type, java_signature, referenced_in_dex_ids)` — the field analogue.
- **`ExternalTypeRef`** `(descriptor, java_type, referenced_in_dex_ids)` — a
  framework/library type the app references but does not declare (may be an array
  descriptor, e.g. `[Landroid/content/Intent;`).

### Search (L1–L7)
DexKit's headline capability — fast static class/method search (`SearchPort`). A hit
is a light match record; `MatchType` is the name-match mode.
- **`MatchType`** = `Literal["equals", "contains", "starts_with", "ends_with", "regex"]` — note `regex` is DexKit's *SimilarRegex* (`^`/`$` anchors only, not full regex).
- **`ClassRef`** `(class_idx, descriptor, dex_id)` — one class hit.
- **`MethodRef`** `(method_idx, descriptor, dex_id)` — one method hit. The `batch_*`
  searches return `Mapping[str, tuple[Match, ...]]` keyed by the query key.
- **`FieldRef`** `(field_idx, descriptor, dex_id)` — one field hit, from
  `find_fields_by_name`. Unlike its two siblings this model is NEW rather than a
  rename: the raw type existed but nothing produced one until dexllm#37.

### Class inspection
The C++ `get_class_summary` bundles class metadata + fields + methods into one
object; the SDK layer splits it (ISP) so a consumer depends only on what it
needs — metadata, fields and methods are three queries.
- **`ClassInfo`** `(descriptor, dex_id, is_internal, access_flags,
  superclass_descriptor, interface_descriptors, source_file, dex_name)` — class metadata, no members. `dex_name` is the
  declaring dex's file name (`classes.dex` / `classes2.dex` / …); `""` for an external
  class (`dex_id == -1`).
- **`FieldInfo`** `(name, type, access_flags, class_descriptor, descriptor)` — one
  declared field.
- **`MethodInfo`** `(name, proto, access_flags, class_descriptor, descriptor)` — one
  declared method, returned by `class_methods`. Both names are shared verbatim with
  the raw layer (dexllm#37 renamed raw's `ClassMemberField` / `ClassMemberMethod`,
  which were a second name for the same records).

`descriptor` is the IDENTITY the xref / decompile APIs consume, and
`class_descriptor` the class it is declared on. dexllm#69 added both: every other
member-shaped record already carried one — `MethodRef`, `ExternalMethodRef`,
`ClassSummary` — and `*Info` was the only one without, so a caller reading
`class_methods()` had to re-assemble `f"{cls}->{name}{proto}"` by hand. They are
APPENDED, so the three positional arguments before them keep their meaning.

`access_flags` on all three is `int | None` — the **raw dex bit-field**, or
`None` when UNKNOWN.

`None` covers every entity of an EXTERNAL class (`is_internal == False`), which
has no `class_data`. Reading a modifier off one raises `TypeError` rather than
answering `0`, which in dex is a legal value — package-private, non-static,
non-final (dexllm#41).

On an INTERNAL class, `class_fields` / `class_methods` list what it DECLARES — an
inherited field it only REFERENCES is not a member (dexllm#45); that lives in
`list_fields()`, the whole `field_ids` table. An EXTERNAL class declares nothing
here, so its members are exactly the references other classes make to it.

The bit-field is not normalized to `java.lang.reflect.Modifier`. Since dexllm#37 that includes METHOD flags via
`MethodInfo`, so the `ACC_DECLARED_SYNCHRONIZED` (`0x20000`) vs
`ACC_SYNCHRONIZED` (`0x20`) distinction documented for the raw layer's
`get_class_summary` (see [api.md](api.md#classsummary)) applies here too: a Java
`synchronized` method reads `0x20000`. The decoded NAMES remain available on
`MethodAst.access_flags` (`declared_synchronized`) — that is the same fact in the
other spelling, and the reason `MethodInfo` exposes the bits instead.

### Cross-reference
- **`ResolvedArg`** `(kind, register_index, string_value?, int_value?, class_descriptor?,
  field_descriptor?, method_descriptor?, parameter_index?, crossed_branch)` — the
  provenance of one invoke argument. Only the field its `kind` carries is set; `kind`
  ∈ ConstString / ConstInt / ConstWide / ConstClass / ConstNull / FieldRead /
  MethodReturn / Parameter / NewInstance / NewArray / Unknown. A reported origin holds
  on **every** path to the call *within the analysis window*; `crossed_branch`
  (Unknown only) means a tracked definition was **discarded at a control-flow merge** —
  the paths disagree, or one merged edge carried nothing because it came from outside
  the window. Treat it as *not proven*, not as *absent*. An `Unknown` with
  `crossed_branch=False` found nothing in the window at all — it may simply lie
  further back, so `resolve_call_args(..., depth=N)` can resolve it, except inside a
  catch handler, which is entered empty at every depth (see docs/api.md §"Intra-method
  arg resolution").
- **`CallSite`** `(caller_descriptor, caller_dex_id, caller_method_idx,
  callee_descriptor, bytecode_offset, invoke_opcode)` — one invoke edge. Returned by
  both `find_call_sites_to` (a target's CALLERS — callee fixed, `caller_*` vary) and
  `find_call_sites_from` (a method's CALLEES — `caller_*` fixed, callee varies); the two are
  the reverse and forward of the same edge, so **which half is constant depends on
  which method produced the list**. `bytecode_offset` is always an offset inside the
  CALLER; `caller_method_idx` is a **dex-local** `method_ids` index, meaningful only
  paired with `caller_dex_id` (not a stable global id).
- **`ResolvedCallSite`** — a `CallSite` plus `args: tuple[ResolvedArg, ...]`. Only the
  reverse direction produces it (`resolve_call_args`), so callee is the fixed half.
- Field read/write xref (`find_methods_reading_field` / `find_methods_writing_field`
  — named for what they RETURN, like every other `find_*`; the former
  `find_field_readers`/`_writers` inverted that and have been removed) returns plain
  method descriptors `tuple[str, ...]` — the methods that iget*/sget* (read) or
  iput*/sput* (write) a `Lcls;->name:Type` field (from dexkit's L2.5 reverse index).
  **One entry per access INSTRUCTION, not per method** (like `CallSite`), so a
  method accessing the field twice appears twice; `set()` it for distinct methods.
- **`TypeReferences`** `(fields, methods_returning, methods_with_param)` —
  `find_type_references(Lpkg/Cls;)` signature-position xref: where a type appears as
  a field type, a method return type, or a method parameter (each a `tuple[str]`).

### Permission analysis
- **`ApiCallers`** `(api, descriptors, callers)` — one gated API and the
  app methods that call it.
- **`PermissionCallers`** `(permission, protection_level, apis)` — a permission,
  its protection-level bucket, and its referenced gated APIs (ALL protection levels).
  See the [protection-level reference](#protection-levels). The dangerous-only view
  is a one-liner filter (`[g for g in permission_callers(app_only=False) if
  g.protection_level == "dangerous"]`).

### Indicators (IOC)
- **`Indicator`** `(value, methods, declared_in)` — one network indicator and where it
  lives: `methods` = the call sites that LOAD it (const-string xref), `declared_in` =
  the classes that DECLARE it as a static-field constant. An indicator kept only as a
  constant has no call site, so `declared_in` is its only location. Both empty without
  cross-reference.
- **`IocReport`** `(urls, ips, domains, emails, onion)` — each a tuple of
  `Indicator`; defang-aware, public-suffix-validated.

### Capabilities
- **`ApiUsage`** `(api_descriptor, call_site_count, permissions, categories,
  flags, callers, field_access_count)` — one catalog API the app exercises. Which
  counter is filled follows the catalog key's form: a METHOD key fills
  `call_site_count` (invoke instructions), a FIELD key — how an app reaches
  contacts / call log / calendar, by reading a `CONTENT_URI` constant — fills
  `field_access_count` (read instructions — `find_methods_reading_field` is not
  deduplicated) and leaves the other 0. Both count instructions, so summing them
  is meaningful; they are kept apart only so `call_site_count`'s released meaning
  is untouched.
- **`CapabilityReport`** `(catalog_version, catalog_size, matched_apis,
  total_call_sites, permissions, categories, flags, api_usages, by_caller,
  total_field_accesses, dropped_touches, dropped_apis)` — the
  app's capability profile (holds `Mapping`s → immutable, **not hashable**).
  `categories` is one axis (domain / behaviour), so one call site is never counted
  twice under two names for the same concern — an API that genuinely spans two
  domains does count once in each, so `sum(categories.values()) >=
  total_call_sites + total_field_accesses` (both, because the Counters count
  TOUCHES of either kind while the two totals keep the units apart). `flags` is the orthogonal cross-domain axis (today only
  `IDENTIFIER`). `by_caller` maps a calling method to the catalog APIs it invokes
  — the transpose of `ApiUsage.callers`, and what answers "who calls
  `Runtime.exec` / `DexClassLoader` here". It held `{permissions}` until
  dexllm#35, built inside the permission loop, so an API declaring none registered
  no callers and the index covered 17 of the corpus's 317 distinct callers (5.4%).
  Either view is derivable from `api_usages`, so this is a convenience index; the
  permission view is one join away
  (`{p for a in by_caller[c] for p in by_api[a].permissions}`) while a permission
  set could not give back an API.

### Content providers
- **`ContentProviderUse`** `(uri, family, methods)` — a `content://` provider URI
  the app references (the runtime-assembled surface the `@RequiresPermission` map
  misses). `family` ∈ `blockednumber` / `bluetooth` / `browser` / `calendar` / `calllog` / `contacts` / `media` / `settings` / `simphonebook` / `sms` / `telephony` / `timezone` / `userdictionary` / `voicemail` — the 14 the BUNDLED dataset uses (an
  override may carry any string; `family` is validated only as a `str`, since the
  channel exists for a consumer's own vocabulary). The `provider` catch-all is
  GONE (dexllm#31): it meant "unclassified", not a family.

---

## Component 2 — Ports (`ports.py`)

Each port is a `@runtime_checkable` `typing.Protocol` — a **structural** contract:
any object with the right methods satisfies it (test doubles need no base class),
and `isinstance(x, SomePort)` verifies method presence at runtime. Split by concern
so a consumer depends on just what it needs:

| Port | Methods |
|---|---|
| **`ContainerProbePort`** | `identify(path) -> ContainerInfo`, `verify(path, *, lenient=False) -> tuple[DexVerifyStatus, …]` (load-free) |
| **`DecompilationPort`** | `decompile_method`, `decompile_method_with_pc_map`, `decompile_class`, `decompile_method_ast`, `render_method_smali`, `render_class_smali` |
| **`EnumerationPort`** | `list_classes` / `list_classes_in_dex`, `list_class_methods`, `list_fields` / `list_fields_in_dex`, `list_methods` / `list_methods_in_dex`, `list_value_strings` / `list_class_strings` / `list_method_strings` (app-wide, class-scoped, method-scoped — the forward direction of `find_*_using_strings`), `list_external_method_refs` / `list_external_field_refs` / `list_external_type_refs`, `verify_report`, `source_info` (what each source WAS, probed at load — a session fact that survives the file) (uniform scope axis: bare = all dexes, `…_in_dex(dex_id)` = one dex) |
| **`DexExtractionPort`** | `extract_dex` → `ExtractedDex` / `extract_dexes` → all of them in `dex_id` order (bytes + provenance: `source` / `entry` / `offset`; the packer/dump primitive). Provenance is not derivable elsewhere — the verify report's `name` is only the entry name for a zip member, so two sources both report `classes.dex`, and only `offset` says where in a concatenated container a dex starts |
| **`ClassInspectionPort`** | `class_info`, `class_fields`, `class_methods`, `locate_class_dex` (the ISP split of raw's `get_class_summary`; `class_methods` is the structured twin of `class_fields` — `EnumerationPort.list_class_methods` returns descriptors, which carry no access flags, so before dexllm#37 a method modifier was reachable only by dropping to `.raw`; `locate_class_dex` = cheap declaring-dex lookup, vs the heavy `class_info().dex_id`) |
| **`CrossReferencePort`** | `find_call_sites_to` (a target's callers — the reverse edge) / `find_call_sites_from` (a method's callees — the forward edge), `resolve_call_args`, `find_methods_reading_field`, `find_methods_writing_field`, `find_type_references`. `find_call_sites_to` / `find_call_sites_from` is the same pair the raw `DexKit` and the MCP catalog use — one spelling across all three layers, and the only one: the pre-unification adapter aliases (`find_call_sites`, `find_call_sites_to_api`, `find_call_sites_from_method`, `find_field_readers`, `find_field_writers`) were removed. Both call-site directions and `resolve_call_args` take `method_descriptor` |
| **`SearchPort`** | `find_classes_by_name` / `by_super` / `implementing` / `by_annotation` / `using_strings` / `declaring_strings` (the declaration side — static-field constants the `using` index cannot see), `find_methods_by_name` / `by_annotation` / `using_strings` / `using_int_literals` / `using_double_literals`, `find_fields_by_name` (the field arm, dexllm#37 — `FieldRef` was a public type nothing could produce), `batch_find_{classes,methods}_using_strings` (DexKit's L1–L7 search; `match_type` ∈ `MatchType`) |
| **`PermissionAnalysisPort`** | `permission_callers` (all protection levels) |
| **`IndicatorExtractionPort`** | `extract_iocs` |
| **`CapabilityPort`** | `summarize_capabilities` (`app_only=True` by default — the app's own callers, not the bundled libraries it ships; `dropped_touches` / `dropped_apis` say what that removed, so an empty report is not mistaken for an inert APK; dexllm#49) |
| **`ContentProviderPort`** | `detect_content_providers` |
| **`TlsTrustPort`** | `detect_permissive_tls` |
| **`CacheControlPort`** | `decompiler_cache_capacity` / `set_decompiler_cache_capacity` / `decompiler_cache_size` / `clear_decompiler_cache`, `warm_analysis_caches` (operational cache/lifecycle knobs, not analysis — a long-lived embedder bounds/frees/warms caches without dropping to `.raw`) |

**`DexAnalysisUseCase`** composes the twelve session-bound ports (every port except
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
- **`verify(path, *, lenient=False) -> tuple[DexVerifyStatus, ...]`** — load-free
  structural verification (functional form of `ContainerProbe.verify`). One
  verdict per dex, byte-identical to loading the source and reading
  `verify_report`; never raises (a malformed/unopenable path is a `valid=False`
  verdict).

The adapter is the ONLY component that imports `dexllm.DexKit`; models and ports
have no engine dependency, so a consumer (or a test) can depend on the contract
alone.

---

## Conventions

### Immutability & hashability
- All models are `frozen=True` (no attribute rebinding).
- Sequence fields are `tuple`s; `Mapping` fields
  (`CapabilityReport.permissions/categories/flags/by_caller`, `MethodAst.ast`) are wrapped
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

`PermissionCallers.protection_level` (Android `protectionLevel`, bucketed):

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
