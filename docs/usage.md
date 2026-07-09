# dexllm

Python static analysis library for Android APK / DEX files, built on top of [LuckyPray/DexKit](https://github.com/LuckyPray/DexKit) with pybind11.

Adds capabilities that upstream DexKit doesn't expose, oriented for **security analysis / malware triage** rather than Xposed module development:

- **External API reference enumeration** — every Android framework API the app touches
- **Call site mapping with bytecode offsets** — including external (framework) callees
- **Capability / permission summary** — API → category aggregation (LOCATION, CRYPTO, REFLECTION, …)
- **Intra-method dataflow** — track ConstString / NewInstance / argument origin per call site
- **Smali rendering** — baksmali-style, no JVM needed
- **Java decompiler** — full DAD-aligned C++ port in `dad_cpp/`: `decompile_method_java`, `decompile_class_java`, and `decompile_method_ast` (the complete androguard `dast.py` nested AST). ~92% byte / ~98% line parity vs androguard DAD, 0-crash on a 22-APK / 443k-method corpus, and ~4.5× faster per method than androguard (see [comparison](#performance)).
- **LLM backends** — a shared tool catalog (`dexllm.tools`) exposed via an MCP stdio server and a FastAPI/SSE web backend.

> **Looking for the flat reference?** [docs/api.md](api.md) lists every method
> with its exact return type and a real example output. This page is the
> task-oriented walkthrough.

**`L` = capability level** — a numbered grouping of analysis capabilities, not a strict abstraction hierarchy: `L7` (the find/match engine) is the bottom-layer search primitive that `L1`–`L4` build on, and `L5`/`L6` are the smali/Java decompile paths. All of L1–L7 below are operational. The decompiler is a strict function-by-function port of androguard's DAD (`decompiler/*.py`: graph → dataflow → control_flow → writer/dast); see [CLAUDE.md](../CLAUDE.md#dad-aligned-development-policy) for the port roadmap.

## Install

Requires:
- Python 3.9+
- CMake 3.20+, Ninja
- pybind11 3.0+, scikit-build-core 0.10+
- C++20 compiler

```bash
# from the repo root
pip install -e .                           # editable build
# or:
pip install -e . --no-build-isolation --force-reinstall   # force a clean native rebuild
```

## TL;DR — load an APK

```python
import dexllm

dk = dexllm.DexKit("/path/to/app.apk")
print(dk.dex_count(), "dex files,", dk.apk_path())
# Optional: warm all analysis caches upfront (one-time ~200ms on a 50-dex APK).
# Otherwise caches warm lazily on first access of each analyser.
dk.warm_analysis_caches()
```

`DexKit(path)` identifies the file **by content, not by extension** — a `dex\n` magic loads as a bare `.dex`, anything else must prove out as a real zip/apk container (PK signature + a valid central directory) carrying at least one `classes*.dex`. So a **disguised or extension-less APK** (a renamed `.png`, no extension, …) still loads, while a non-dex/non-zip file or a zip with no `classes*.dex` raises a clear error instead of silently loading nothing.

```python
dk = dexllm.DexKit("classes2.dex")            # raw secondary dex (dex\n magic), loaded directly
dk = dexllm.DexKit("/tmp/evil.png")           # disguised APK — loaded by its PK content
print(dk.decompile_class_java("Lcom/blafoo/bar/Blafoo;"))
```

Probe a file **without loading it** with `dexllm.identify(path)` — handy for triaging a directory of unknown blobs:

```python
dexllm.identify("/path/to/suspect")
# → {'format': 'zip', 'is_apk': True, 'has_manifest': True, 'dex_count': 2}
#   format: "dex" | "zip" | "unknown";  is_apk = a zip carrying an AndroidManifest.xml
```

Every loaded dex is **structurally verified at load** (a port of ART's
`DexFileVerifier`) before the core parses it — malformed or crafted input is
rejected with a byte-level reason instead of crashing the analyzer. Inspect the
per-dex verdicts with `dk.verify_report()`:

```python
for r in dk.verify_report():
    print(r)   # → {'dex_id': 0, 'name': 'classes.dex', 'valid': True, 'reason': ''}
```

A container whose every dex fails verification raises at construction. See the
[DEX-handling comparison](dexkit-vs-art-dex-handling.md) §1 for exactly what's checked.

In a multidex APK, a class declared in more than one `classes*.dex` resolves **first-wins by lowest dex_id** (classes.dex before classes2.dex), deterministically — matching ART/AOSP, so packer collisions decompile to the body that actually runs (see [DEX-handling comparison](dexkit-vs-art-dex-handling.md)).

### Multiple sources — priority by order (packer / runtime-unpack)

Pass a **list** of sources to load them in order; earlier sources get lower
dex_ids, and resolution is first-wins, so the **first source wins a class
collision**:

```python
# Analysing a packed app: a runtime-decrypted/dumped dex should win over the
# original (stub) classes. List it FIRST so first-wins prefers it — the same
# order the packer arranges at runtime (ART consults the decrypted dex first).
dk = dexllm.DexKit(["/tmp/dumped_real.dex", "app.apk"])   # dumped wins collisions
dk.decompile_class_java("Lcom/evil/RealC2;")              # the unpacked body

dk = dexllm.DexKit(["dump1.dex", "dump2.dex", "app.apk"]) # several dumps + apk
```

Each source is a bare `.dex` or a zip/apk, every dex still passes the load-time
verifier, and classes from **all** sources are cross-indexed (search/decompile see
the merged set). This is the static side of the unpack workflow — dump the
decrypted dex with an external dynamic tool, then load it first. (`apk_path()`
reports the first source; `sources()` returns the whole list.)

`dexllm.add_dumped_dexes` is the ergonomic verb for the "re-analyze after dumping"
step — it rebuilds from the dump(s) **plus** the current sources:

```python
dk = dexllm.DexKit("app.apk")
# ... detect packing, dump the decrypted dex to /tmp/dump.dex with a dynamic tool ...
dk = dexllm.add_dumped_dexes(dk, "/tmp/dump.dex")   # dump prepended → unpacked wins
dk.decompile_class_java("Lcom/evil/RealC2;")        # the real body
```

Defaults: `prefer=True` (dumps loaded first → win collisions) and `lenient=True`
(verify in **ART-structural-equivalent** mode — skip instruction-operand checks — so
a *partially*-decrypted dump, with valid structure but garbage method bodies, still
loads, exactly as ART loads it; header/structure/bounds are still verified). It
returns a fresh `DexKit` (a clean rebuild, consistent caches) — keep the new handle.

The single-source constructor argument is still named `apk_path` for backward
compatibility. A zip APK loads in ~150ms for a 50-dex app using zero-copy slicer-based dex parsing. Subsequent operations cache aggressively — the second call is always ≤1µs marshalling overhead plus the algorithm cost.

---

## L1 — what external (Android framework) APIs does this APK touch?

```python
# Methods
for ref in dk.list_external_method_refs(framework_only=True):
    print(ref.java_signature)
    # → android.util.Log.d(java.lang.String, java.lang.String) -> int
    # → android.content.Intent.<init>(java.lang.String) -> void
    # ...

# Types
for ref in dk.list_external_type_refs(framework_only=True):
    print(ref.java_class)
    # → android.app.Activity
    # → android.util.Log

# Fields
for ref in dk.list_external_field_refs(framework_only=True):
    print(ref.java_signature)
```

Pass `framework_only=False` to also include non-framework external refs (SDKs you embed, …).

### Filter with helpers

```python
from dexllm import filter_method_refs

# Only methods on android.content.* / android.net.*
hits = filter_method_refs(
    dk.list_external_method_refs(),
    class_prefix=("android.content.", "android.net."),
)
```

---

## L1.5 — class summary (works on internal AND external classes)

```python
summary = dk.get_class_summary("Lcom/ss/android/agilelogger/ALog;")
print(summary.internal, summary.dex_id, summary.super_descriptor)
print("methods:", len(summary.methods))
print("fields:", len(summary.fields))
```

For external classes (e.g. `Landroid/util/Log;`), the summary lists only the members the APK *actually references* — useful for understanding the subset of an SDK that's in use.

---

## L2 — find every call site to a specific API (internal or external)

```python
for site in dk.find_call_sites_to_api(
    "Landroid/util/Log;->d(Ljava/lang/String;Ljava/lang/String;)I"
):
    print(f"[opcode {site.invoke_opcode:02x} @ off 0x{site.bytecode_offset:x}] "
          f"{site.caller_descriptor}  dex={site.caller_dex_id}")
```

Each site is a distinct invoke instruction — if the same caller invokes the API twice, you get two entries. `bytecode_offset` is the absolute byte offset within the method's code item.

The **forward** direction — what a given method calls (its callees) — is
`dk.find_call_sites_from_method(method)`: the same `CallSite` list, but the caller is
fixed to the method and `callee_descriptor` varies. `find_call_sites_from_method(M)`
and `find_call_sites_to_api(C)` are the forward and reverse of one invoke edge (if
`M` invokes `C`, `M` is among `C`'s callers). `[]` for an external / bodyless method.

### L2.5 — field read/write xref

Which methods **read** (`iget*`/`sget*`) or **write** (`iput*`/`sput*`) a field —
from dexkit's exact `field_get_method_ids` / `field_put_method_ids` reverse index:

```python
fd = "La2dp/Vol/StoreLoc;->MAX_ACC:F"          # Lcls;->name:Type
dk.find_field_read_methods(fd)                  # -> [method descriptors that read it]
dk.find_field_write_methods(fd)                 # -> [method descriptors that write it]
```

Type xref (signature positions) — where a `Lpkg/Cls;` type appears as a field type,
a method return type, or a method parameter:

```python
tr = dk.find_type_references("Landroid/location/Location;")
tr.fields              # fields OF this type
tr.methods_returning   # methods returning it
tr.methods_with_param  # methods taking it as a param
```

Per-dex enumeration follows a uniform scope axis — the bare form is all loaded
dexes, the `…_in_dex(dex_id)` form is one dex (empty if out of range), and the
all-dexes form is exactly the per-dex concatenation: `dk.list_classes` /
`dk.list_classes_in_dex(dex_id)` (declared classes), `dk.list_field_descriptors` /
`dk.list_field_descriptors_in_dex(dex_id)`, `dk.list_method_descriptors` /
`dk.list_method_descriptors_in_dex(dex_id)` (id-table references), and
`dk.extract_dex_bytes(dex_id)` (raw dex image bytes).

---

## L3 — what permissions / categories does this APK exercise?

```python
report = dexllm.summarize_capabilities(dk)

# Top permissions touched (via API usage)
for perm, count in report.top_permissions(10):
    print(f"{count:>5}× {perm}")
# → 3 × android.permission.CAMERA
# → 2 × android.permission.ACCESS_FINE_LOCATION

# Top categories
for cat, count in report.top_categories(10):
    print(f"{count:>5}× {cat}")
# → 3476 × REFLECTION
# →  202 × CRYPTO
# →   45 × RISKY

# Filter to a subset (only crypto-related APIs)
crypto = dexllm.summarize_capabilities(dk, only_categories={"CRYPTO", "HASH"})
for hit in crypto.hits:
    print(hit.api, "→", hit.permission, hit.categories)
```

The catalog is JSON; extend it to taste at `src/dexllm/data/android_api_map.json`.

---

## L4 — intra-method dataflow (what's actually passed at each call site?)

```python
# Every (Intent, String action) constructor site
sites = dk.resolve_call_args(
    "Landroid/content/Intent;-><init>(Ljava/lang/String;)V"
)

# arg[0] is the receiver (NewInstance), arg[1] is the action string
actions = sorted({
    s.args[1].string_value
    for s in sites
    if s.args[1].kind == "ConstString"
})
print(f"{len(actions)} unique Intent actions:")
for a in actions:
    print(" ", a)

# Same trick for Cipher.getInstance — find every transformation used
ciphers = sorted({
    s.args[0].string_value
    for s in dk.resolve_call_args(
        "Ljavax/crypto/Cipher;->getInstance(Ljava/lang/String;)Ljavax/crypto/Cipher;")
    if s.args[0].kind == "ConstString"
})
# → ['AES/CBC/PKCS5Padding', 'AES/ECB/NoPadding', ...]
```

`ArgOrigin.kind` values: `ConstString`, `ConstClass`, `ConstInt`, `NewInstance`, `NewArray`, `IGet`, `SGet`, `MoveResult`, `Register`, `Unknown`. Available fields depend on kind (`string_value`, `int_value`, `class_descriptor`, …).

---

## L5 — smali rendering (baksmali-style, no JVM)

```python
# Whole class
print(dk.render_class_smali("Lcom/ss/android/agilelogger/ALog;"))

# Single method
print(dk.render_method_smali(
    "Lcom/ss/android/agilelogger/ALog;->d(Ljava/lang/String;Ljava/lang/String;)V"
))
```

Returns `""` for external / missing classes.

---

## L6 — Java decompilation (DAD port — complete)

```python
# Single method → DAD-quality Java (GIL released → parallel-safe)
print(dk.decompile_method_java("Lcom/example/Utils;->getDisplaySize(Landroid/content/Context;)Landroid/graphics/Point;"))

# Whole class → package + header + fields + methods
print(dk.decompile_class_java("Lcom/example/Utils;"))

# Structured AST — the full androguard dast.py nested form
ast = dk.decompile_method_ast("Lcom/example/Utils;->getDisplaySize(Landroid/content/Context;)Landroid/graphics/Point;")
print(ast["ast"]["body"])      # {triple, flags, ret, params, comments, body}
# Skip the redundant text emit when only the AST is needed (~1.7x faster):
ast_only = dk.decompile_method_ast(desc, include_source=False)

# Java text + source-line ↔ bytecode-offset map (smali ↔ Java cursor sync):
pc = dk.decompile_method_java_with_pc("Lcom/example/Utils;->getDisplaySize(Landroid/content/Context;)Landroid/graphics/Point;")
print(pc["source"], pc["pc_map"])   # pc_map: [(line_1based, byte_off), …], headers included
```

API surface: `decompile_method_java` / `decompile_method_java_with_pc` / `decompile_class_java` / `decompile_method_ast` / `render_method_smali`, plus cache control
(`decompiler_clear_cache`, `decompiler_cache_size`, `decompiler_set_cache_capacity`). External / native / abstract methods return `""` (graceful — androguard crashes on these).

The decompiler is a strict, function-by-function port of androguard's `decompiler/*.py` (graph → dataflow → control_flow → writer/dast) under `dad_cpp/`, validated by 25 DAD parity suites (`ninja parity_tests && ctest`) and an end-to-end diff vs androguard. A few spec-correctness divergences are intentional (valid `null`/`true`/`false` where androguard leaks `None`/`True`/`False`; IEEE754 floats) — see [CLAUDE.md](../CLAUDE.md) "Upstream DAD bug fixes".

---

## L7 — find / match operations (Aho-Corasick + matcher engine from upstream)

All operations auto-normalise their inputs — pass descriptor (`Landroid/app/Activity;`), smali path (`android/app/Activity`), or Java dotted (`android.app.Activity`).

```python
# Name patterns
dk.find_classes_by_name("Activity", "ends_with")       # match mode: equals / starts_with / ends_with / contains / regex
dk.find_methods_by_name("onCreate", "equals",
                        declaring_class="Landroid/app/Activity;")

# String literal usage
dk.find_classes_using_strings(["android.permission.READ_CONTACTS"])
dk.find_methods_using_strings(["AES/CBC/PKCS5Padding"])

# Batch (Aho-Corasick) — multiple keys at once, much faster than N separate scans
dk.batch_find_classes_using_strings({
    "ROOT_CHECK": ["/system/bin/su", "/system/xbin/su"],
    "REFLECTION": ["java.lang.reflect.Method"],
    "DEBUG": ["isDebuggerConnected"],
})

# Numeric literals (useful for magic constants, ports, opcodes)
dk.find_methods_using_int_literals([0xDEADBEEF, 0xCAFEBABE])
dk.find_methods_using_double_literals([3.14159])

# Type hierarchy
dk.find_classes_by_super("Landroid/app/Activity;")
dk.find_classes_implementing("Landroid/os/Parcelable;")

# Annotations
dk.find_classes_by_annotation("Lkotlin/Metadata;")
dk.find_methods_by_annotation("Landroidx/annotation/RequiresApi;")
```

---

## Static C2 / IOC extraction

VirusTotal shows the URLs, domains, and IPs an app *contacts*; `extract_iocs`
recovers the same indicators **statically** — with no execution — and ties each one
back to the class/method that references it.

> **Requires** `pip install "dexllm[ioc]"` (pulls `tldextract` for public-suffix
> domain validation). The defang + indicator regexes are in-tree.

```python
import dexllm

dk = dexllm.DexKit("app.apk")

iocs = dexllm.extract_iocs(dk)           # with_xref=True, denoise=True by default
for category in dexllm.IOC_CATEGORIES:   # urls / ips / domains / emails / onion
    for row in iocs[category]:
        print(category, row["value"], "<-", row["methods"][:1])
# urls https://c2.example.top/gate.php <- ['Lcom/x/Net;->beacon()V']

# The value-string feed it scans, for custom queries:
value_strings = dk.list_value_strings()  # strings loaded as DATA (no identifiers)
```

**Input** is `dk.list_value_strings()` — only strings the app loads *as data*
(`const-string`/`jumbo` operands + static `VALUE_STRING` initializers), so
type/method/field-name identifiers never enter the scan. **Defanged** indicators are
recovered (`hxxps://evil[.]top`, `1[.]2[.]3[.]4`, `admin[at]phish[.]kr`) by a
literal, linear un-defang pass. **Domains** are validated against the public suffix
list (`tldextract`), so `com.google.util` (not a real suffix) is rejected while
`maps.google.co.uk` resolves correctly. **Denoising** then drops the residual
identifier hosts: the app's own dex package paths (self-calibrating, from its type
descriptors), reverse-DNS / platform roots (`com.*`, `org.*`, `android.*`, …),
XML-namespace URIs (`http://schemas.android.com/...`), and word-gTLD identifier
collisions where a Java path's tail is a dictionary-word gTLD (`os.name`,
`Matcher.group`, `*.support` — `.name`/`.group`/`.support` are real TLDs). A
scheme-qualified URL keeps its host regardless. The classifier regexes are
hand-bounded (ReDoS-safe) and each string is length-capped — important because dex
value-strings include multi-MB blobs. Set `with_xref=False` to skip the per-indicator
L7 cross-reference, or lower `xref_limit` on string-heavy apps. Also the `extract_iocs`
MCP tool (returns `{indicators, counts}`).

> Note: the indicator extraction is in-tree and ReDoS-bounded by design —
> `iocextract` was evaluated but its regexes backtrack catastrophically on the dotted
> blobs dex strings contain, so only the safe `tldextract` PSL lookup is used.

### `content://` provider query URIs

The `content://` URIs a `ContentResolver` reads are the real handles for
SMS / contacts / call-log / calendar — the surface `READ_SMS` / `READ_CONTACTS`
gate, and invisible to the `@RequiresPermission` map (the `Uri` is assembled at
runtime). `detect_content_providers` matches the app's value-strings against a
bundled AOSP provider-URI dataset (`src/dexllm/data/content_uris.json`):

```python
for hit in dexllm.detect_content_providers(dk):
    print(hit["uri"], hit["family"], "<-", hit["methods"][:1])
# content://sms sms <- ['Lb/g/a/m/f;->run()V']
```

### Engine C++ port — permission callers (shared with the WASM binding)

`permission_api_callers` has a byte-identical **C++ engine port**,
`dk.permission_callers()` (all protection levels), so the WASM (embind) binding and
pybind run **one implementation over the engine-bundled AOSP dataset** (issue #14).
The pybind/SDK permission surface uses this C++ join directly.

The IoC / content-provider / capability analyses are **pure Python**
(`dexllm.extract_iocs` / `detect_content_providers` / `summarize_capabilities`) —
the canonical, ReDoS-safe, PSL-validated implementations dexllm's own API uses. The
earlier C++ mirrors of these three (which existed only to back the WASM binding)
were removed: dexllm does not carry web-only engine code, and a WASM consumer must
vendor its own in-browser engine.

The bundled AOSP data — the full `@RequiresPermission` permission→API map + level
buckets (`perm_api.json` / `perm_levels.json`, all protection levels) and the provider
URIs (`content_uris.json`) — is a committed snapshot of
[aosp_data_set](https://github.com/mobile-threat-hunter/aosp_data_set) (metalava
permission table + content-URI CSVs), verified in sync with upstream as of the
2026-07-04 dataset revision. (`android_api_map.json` is a separate hand-seed catalog
for `summarize_capabilities`, extend at will.)

---

## Dangerous-permission API usage

Which **dangerous** permissions does the APK exercise *through real API calls* —
not just `<uses-permission>` claims? This joins AOSP's `@RequiresPermission`
permission→API map ([aosp_data_set](https://github.com/mobile-threat-hunter/aosp_data_set))
against the APK's referenced framework APIs.

```python
import dexllm

dk = dexllm.DexKit("app.apk")

# {permission: [pkg.Class#method(signature), ...]} for the gated APIs actually used
apis = dexllm.dangerous_permission_apis(dk)
# {'android.permission.ACCESS_FINE_LOCATION':
#     ['android.location.LocationManager#getLastKnownLocation(String)', ...], ...}

# same, plus WHO calls each gated API (jump straight to the code)
callers = dexllm.dangerous_permission_api_callers(dk)   # app_only=True by default
for perm, rows in callers.items():
    for row in rows:
        print(perm, row["api"], "<-", row["callers"][:1])
# ACCESS_FINE_LOCATION  android.location.LocationManager#getLastKnownLocation(String)
#   <- ['La2dp/Vol/StoreLoc;->grabGPS()V']
```

By default `app_only=True` drops callers that are bundled framework / official-library
code (`androidx.*`, `android.support.*`, `kotlin.*`, `com.google.android.*`, …) — a
dangerous-API call from there (e.g. AppCompat's `TwilightManager` reading location for
day/night theming) is library plumbing, not the app's own behaviour. Pass
`app_only=False` to keep every caller:

```python
dexllm.dangerous_permission_api_callers(dk, app_only=False)   # include framework callers
```

### All protection levels

`permission_api_callers` generalises this to the **full** permission surface — not just
the ~25 dangerous permissions, but all levels (`dangerous` / `signature` / `internal` /
`normal`, per `dexllm.PERM_LEVELS`), each group carrying its real `protectionLevel`:

```python
for g in dexllm.permission_api_callers(dk):           # app_only=True by default
    print(g["protectionLevel"], g["perm"], "→", len(g["rows"]), "APIs")
# signature  android.permission.WRITE_SECURE_SETTINGS → 1 APIs
# dangerous  android.permission.READ_SMS → 2 APIs

# filter to a subset of levels
sig = dexllm.permission_api_callers(dk, levels={"signature", "internal"})
```

It returns `[{"perm", "protectionLevel", "rows": [{"api", "descriptors", "callers"}]}]`
sorted by permission — the same shape the C++/WASM `permission_callers()` binding
returns (the dangerous slice is just this filtered to `protectionLevel == "dangerous"`).

The table carries the full method signature for each gated API, so **overloads are
matched precisely** — `getLastKnownLocation(String)` and its `LastLocationRequest`
overload are distinguished, and only the one the app actually references is reported
(arity is the primary, parse-robust discriminator; a `(class, method)` with a single
overload of an arity still matches on that alone, so a signature edge case can't drop
a real hit).

The full permission→API table (`perm_api.json`, 571 perms across all levels) + the
protection-level buckets (`perm_levels.json`) ship bundled — AOSP's metalava-extracted
`@RequiresPermission` inventory (clean, fully-qualified types) plus the AOSP
runtime-enforcement bridge (runtime-enforced public APIs that carry no annotation, e.g.
`SmsManager#copyMessageToIcc` → SEND_SMS; recorded arity-only, matched on arity); the
dangerous slice is DERIVED from them (single source of truth). Regenerate from a fresher checkout with
`python scripts/gen_perm_data.py /path/to/aosp_data_set`, or pass
`dataset_path="…/aosp_data_set"` (or set `$DEXLLM_AOSP_DATASET`) at call time to
compute live. `dangerous_permission_apis` / `dangerous_permission_api_callers` are also
MCP tools (the latter takes `app_only`).

---

## Descriptor helpers

```python
from dexllm import descriptor_to_java, java_to_descriptor, parse_proto, pretty_proto

descriptor_to_java("Landroid/util/Log;")     # → 'android.util.Log'
descriptor_to_java("[[I")                    # → 'int[][]'
java_to_descriptor("java.util.List")         # → 'Ljava/util/List;'
parse_proto("(II)Ljava/lang/String;")        # → (['I', 'I'], 'Ljava/lang/String;')
pretty_proto("(II)Ljava/lang/String;")       # → '(int, int) -> java.lang.String'
```

---

## End-to-end example: malware triage

```python
import dexllm

dk = dexllm.DexKit("/path/to/suspicious.apk")
dk.warm_analysis_caches()

# 1. What permissions does it actually exercise?
report = dexllm.summarize_capabilities(dk)
for perm, count in report.top_permissions(15):
    print(f"  {count:>4}× {perm}")

# 2. What Intent actions does it construct?
actions = sorted({
    s.args[1].string_value
    for s in dk.resolve_call_args("Landroid/content/Intent;-><init>(Ljava/lang/String;)V")
    if s.args[1].kind == "ConstString"
})
print(f"\n{len(actions)} Intent actions:")
for a in actions:
    print(" ", a)

# 3. Any weak crypto?
ciphers = sorted({
    s.args[0].string_value
    for s in dk.resolve_call_args("Ljavax/crypto/Cipher;->getInstance(Ljava/lang/String;)Ljavax/crypto/Cipher;")
    if s.args[0].kind == "ConstString"
})
for c in ciphers:
    flag = " ⚠️" if "ECB" in c or "NoPadding" in c else ""
    print(f"  cipher: {c}{flag}")

# 4. Reflection hotspots (Class.forName)
sites = dk.resolve_call_args(
    "Ljava/lang/Class;->forName(Ljava/lang/String;)Ljava/lang/Class;"
)
for s in sites[:20]:
    if s.args[0].kind == "ConstString":
        print(f"  Class.forName(\"{s.args[0].string_value}\") @ {s.caller_descriptor}")

# 5. Drill into one suspicious method
print("\n--- decompiled ---")
print(dk.decompile_method_java(
    "Lcom/example/SuspiciousReceiver;->onReceive(Landroid/content/Context;Landroid/content/Intent;)V"
))
```

---

## Typed SDK — ports & adapters (`dexllm.sdk`)

The calls above return a mix of `str`, `list`, `dict`, and pybind objects. For
embedding dexllm in a larger system, `dexllm.sdk` wraps the same engine in a
**ports-and-adapters** layer: `@runtime_checkable` Protocol *ports* (the use-case
interfaces) and frozen-dataclass *domain models* with an accurate type on every
argument and return value — so callers program against types, not dict keys.

```python
from dexllm.sdk import open_apk, identify, DexAnalysisUseCase

# identify is load-free; open_apk returns a session satisfying DexAnalysisUseCase
info = identify("app.apk")                      # -> ContainerInfo(format, is_apk, has_manifest, dex_count)
session: DexAnalysisUseCase = open_apk("app.apk")
# packer/unpack: open_apk([dumped_dex, "app.apk"], lenient=True)  (earlier source wins)

m = session.decompile_method("Lcom/x/Y;->m(I)V")          # -> DecompiledMethod(descriptor, source, found, pc_map)
d = session.decompile_method_with_pc_map("Lcom/x/Y;->m(I)V")  # + pc_map: tuple[SourceLocation(line, byte_offset)]
c = session.decompile_class("Lcom/x/Y;")                  # -> DecompiledClass(descriptor, source)
a = session.decompile_method_ast("Lcom/x/Y;->m(I)V")      # -> MethodAst(name, proto, ast, pc_map, ...)

for cls in session.list_classes():                        # -> tuple[str, ...]
    for meth in session.list_class_methods(cls): ...       # -> tuple[str, ...]
refs = session.list_external_method_refs(framework_only=True)  # -> tuple[ExternalMethodRef, ...]

sites = session.find_call_sites("Landroid/util/Log;->d(...)I")  # -> tuple[CallSite, ...]
for rc in session.resolve_call_args("...->getInstance(Ljava/lang/String;)..."):
    for arg in rc.args: arg.kind, arg.string_value          # -> ArgOrigin (only the kind's field set)
session.find_field_readers("Lcom/x/Y;->token:Ljava/lang/String;")  # -> methods that iget/sget it
session.find_field_writers("Lcom/x/Y;->token:Ljava/lang/String;")  # -> methods that iput/sput it
session.find_type_references("Lcom/x/Y;")                 # -> TypeReferences(fields, methods_returning, methods_with_param)

info = session.class_info("Lcom/x/Y;")                    # -> ClassInfo(superclass, interfaces, access_flags, ...)
fields = session.class_fields("Lcom/x/Y;")                # -> tuple[FieldInfo(name, type, access_flags)]
methods = session.list_class_methods("Lcom/x/Y;")         # class members are separate fine-grained queries

for g in session.permission_callers(app_only=True):       # -> tuple[PermissionCallerGroup, ...]
    g.permission, g.protection_level                        # dangerous|signature|internal|normal|other
    for row in g.rows: row.api, row.callers                 # PermissionCallerRow

ioc = session.extract_iocs()                              # -> IocReport; ioc.domains: tuple[Indicator(value, methods)]
cap = session.summarize_capabilities()                   # -> CapabilityReport(api_hits, permissions, categories, ...)
prov = session.detect_content_providers()                # -> tuple[ContentProviderUse(uri, family, methods)]

session.raw       # the underlying dexllm.DexKit (escape hatch for L7 search etc.)
```

The models are immutable (frozen; `Mapping` fields are read-only views) — the
value-object models are also hashable, while the two carrying a `Mapping`
(`CapabilityReport`, `MethodAst`) are not. The ports are structural, so
`isinstance(session, DecompilationPort)` works and any object with the same methods
satisfies the contract (test doubles need no base class). Split ports —
`DecompilationPort`, `EnumerationPort`, `DexExtractionPort`, `ClassInspectionPort`,
`CrossReferencePort`, `SearchPort`, `PermissionAnalysisPort`,
`IndicatorExtractionPort`, `CapabilityPort`, `ContentProviderPort`,
`CacheControlPort`, `ContainerProbePort` — let a consumer depend on just the concern it needs. See the [component reference](sdk.md) and the source
[`src/dexllm/sdk/`](../src/dexllm/sdk/) (`model.py` / `ports.py` / `adapter.py`).

---

## Architecture

```
.
├── native/core_ext/   — C++ extension over upstream DexKit (find/match wrappers, ref enumeration)
├── native/dad_cpp/    — DAD-aligned Java decompiler (complete: graph/dataflow/control_flow/writer/dast)
├── native/binding/    — pybind11 module (boundary between C++ and Python)
├── src/dexllm/        — Python facade + descriptor helpers + capability catalog + tools/MCP/FastAPI
└── tests/             — C++ parity suites (tests/parity, ctest) + Python pytest suite
```

Vendored DexKit Core fork lives at `vendor/dexkit_core/`. Public accessors added to upstream's `DexItem` class live in `vendor/dexkit_core/Core/dexkit/{include/dex_item.h,dex_item.cpp}`. The fork stays small and re-rebases easily on upstream updates.

For the ports & adapters boundary see [architecture.md](architecture.md); for the end-to-end runtime flows (load → verify → decompile → agent) as diagrams see [workflow.md](workflow.md).

---

## Performance (representative 50-dex APK)

| Stage | First call | Cached |
|---|---|---|
| Constructor + slicer | 115–145 ms | — |
| `warm_analysis_caches()` | 260–290 ms | < 1 µs (no-op) |
| L1 external refs | 20–60 ms | same |
| L2 call sites (153 k hits) | 80–110 ms | same |
| L3 capability summary | 90–120 ms | same |
| L4 resolve_call_args (2.4 k sites) | 23 ms | same |
| L5 render_class_smali (77 methods) | 0.5 ms | same |
| L6 decompile_method_java | ~0.06 ms / method (warm) | cached |
| L7 find_classes_by_name | 1–3 ms | same |

Python ↔ C++ marshalling overhead stays under 1 ms per call.

<a name="performance"></a>
### vs androguard (decompile, Telegram 12.7.3 — 39,146 classes)

| | dexllm (C++) | androguard (Python) |
|---|---|---|
| APK load (incl. structural verification) | **~120 ms** | 28.8 s |
| Full decompile (1 thread) | **54 s** | impractical |
| Full decompile (parallel) | **18.5 s** (GIL released) | — (GIL-bound) |
| Peak RSS | **523 MB** | — |
| Crashes | 0 | — |

Per-method decompile is ~4.5× faster than androguard; APK load is ~100× faster (lazy slicer parse + load-time structural verification), and the gap grows with APK size — this 39k-class app loads ~240× faster than androguard's 28.8 s. On this heavy app the parallel decompile speedup is ~3× — returning hundreds of MB of decompiled text is GIL-bound, so small/medium APKs scale higher (~10× on tvleanback). Search (L1–L7) is 3–6× faster than androguard's scan.

Reproduce the androguard comparison on any APK: [`bench/bench_vs_androguard.py`](../bench/bench_vs_androguard.py) (`pip install -e ".[dev]"`, then `python bench/bench_vs_androguard.py app.apk`). It prints a paste-ready table of load / decompile / search timings plus byte-parity.

---

## Licence

- This wrapper (everything in this repo): **Apache 2.0**
- Upstream LuckyPray DexKit (linked statically): **LGPLv3**
- DAD algorithm references (androguard): **Apache 2.0**

When distributing, ensure LGPL compliance for the linked `dexkit_static` library.
