# dexkit-py

Python static analysis library for Android APK / DEX files, built on top of [LuckyPray/DexKit](https://github.com/LuckyPray/DexKit) with pybind11.

Adds capabilities that upstream DexKit doesn't expose, oriented for **security analysis / malware triage** rather than Xposed module development:

- **External API reference enumeration** — every Android framework API the app touches
- **Call site mapping with bytecode offsets** — including external (framework) callees
- **Capability / permission summary** — API → category aggregation (LOCATION, CRYPTO, REFLECTION, …)
- **Intra-method dataflow** — track ConstString / NewInstance / argument origin per call site
- **Smali rendering** — baksmali-style, no JVM needed
- **Java decompiler** — DAD-aligned C++ port in `dad_cpp/`. **Status (2026-05-26): port in progress, returns a stub for now.** See [CLAUDE.md](../CLAUDE.md#dad-aligned-development-policy) for the port roadmap.

L1–L5 and L7 below are operational. L6 (Java decompilation) is being rebuilt as a faithful port of androguard's DAD; the prior in-tree implementation was removed as not DAD-grounded.

## Install

Requires:
- Python 3.9+
- CMake 3.20+, Ninja
- pybind11 3.0+, scikit-build-core 0.10+
- C++20 compiler

```bash
cd dex_analyzer
pip install -e .                           # editable build
# or:
pip install -e . --no-build-isolation --force-reinstall   # force a clean native rebuild
```

## TL;DR — load an APK

```python
import dexkit_py

dk = dexkit_py.DexKit("/path/to/app.apk")
print(dk.dex_count, "dex files,", dk.apk_path)
# Optional: warm all analysis caches upfront (one-time ~200ms on a 50-dex APK).
# Otherwise caches warm lazily on first access of each analyser.
dk.warm_analysis_caches()
```

`DexKit("/path/to/app.apk")` loads in ~150ms for a 50-dex APK using zero-copy slicer-based dex parsing. Subsequent operations cache aggressively — the second call is always ≤1µs marshalling overhead plus the algorithm cost.

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
from dexkit_py import filter_method_refs

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
          f"{site.caller_descriptor}  dex={site.dex_id}")
```

Each site is a distinct invoke instruction — if the same caller invokes the API twice, you get two entries. `bytecode_offset` is the absolute byte offset within the method's code item.

---

## L3 — what permissions / categories does this APK exercise?

```python
report = dexkit_py.summarize_capabilities(dk)

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
crypto = dexkit_py.summarize_capabilities(dk, only_categories={"CRYPTO", "HASH"})
for hit in crypto.hits:
    print(hit.api, "→", hit.permission, hit.categories)
```

The catalog is JSON; extend it to taste at `python/dexkit_py/data/android_api_map.json`.

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

## L6 — Java decompilation (DAD port in progress)

```python
src = dk.decompile_method_java(
    "Lcom/ss/android/agilelogger/ALog;->init(Landroid/content/Context;LX/0q57;)V"
)
print(src)
# → "// DexKit-DAD: empty skeleton. Port DAD modules in dad_cpp/ — see CLAUDE.md.\n"
```

The decompiler API surface (`decompile_method_java`, `decompile_class_java`, `decompile_method`, `decompile_class`, `decompiler_cache_size`, `decompiler_clear_cache`) is wired and stable — it currently routes to a stub while the C++ DAD port lands. See [CLAUDE.md](../CLAUDE.md#port-status--dex_analyzerdad_cpp) for the per-module port status and recommended order.

The prior in-tree implementation was removed (2026-05-26) because it was not a port of androguard's DAD; it had grown into a parallel decompiler with ad-hoc text-regex post-passes. The replacement under `dad_cpp/` is a strict, function-by-function port of androguard's `decompiler/*.py` (graph → dataflow → control_flow → writer), with a `PreToolUse` hook that injects a DAD-reference reminder on every edit.

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

## Descriptor helpers

```python
from dexkit_py import descriptor_to_java, java_to_descriptor, parse_proto, pretty_proto

descriptor_to_java("Landroid/util/Log;")     # → 'android.util.Log'
descriptor_to_java("[[I")                    # → 'int[][]'
java_to_descriptor("java.util.List")         # → 'Ljava/util/List;'
parse_proto("(II)Ljava/lang/String;")        # → (['I', 'I'], 'Ljava/lang/String;')
pretty_proto("(II)Ljava/lang/String;")       # → '(int, int) -> java.lang.String'
```

---

## End-to-end example: malware triage

```python
import dexkit_py

dk = dexkit_py.DexKit("/path/to/suspicious.apk")
dk.warm_analysis_caches()

# 1. What permissions does it actually exercise?
report = dexkit_py.summarize_capabilities(dk)
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

## Architecture

```
dexkit-py/
├── core_ext/        — C++ extension over upstream DexKit (find/match wrappers, ref enumeration)
├── dad_cpp/         — DAD-aligned Java decompiler (port in progress — see CLAUDE.md)
├── binding/         — pybind11 module (boundary between C++ and Python)
├── python/dexkit_py/— Python facade + descriptor helpers + capability catalog
```

Vendored DexKit Core fork lives at `../vendor/dexkit_core/` (sibling directory). Public accessors added to upstream's `DexItem` class live in `vendor/dexkit_core/Core/dexkit/{include/dex_item.h,dex_item.cpp}`. The fork stays small and re-rebases easily on upstream updates.

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
| L6 decompile_method_java | n/a (stub) | n/a |
| L7 find_classes_by_name | 1–3 ms | same |

Python ↔ C++ marshalling overhead stays under 1 ms per call.

---

## Licence

- This wrapper (everything under `dex_analyzer/`): **Apache 2.0**
- Upstream LuckyPray DexKit (linked statically): **LGPLv3**
- DAD algorithm references (androguard): **Apache 2.0**

When distributing, ensure LGPL compliance for the linked `dexkit_static` library.
