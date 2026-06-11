# dex-analyzer-for-llm (`dexllm`)

LLM-facing **Android APK / DEX static analyzer**: a C++ core (pybind11 wrapper around
[LuckyPray/DexKit](https://github.com/LuckyPray/DexKit)) with an embedded, **fully ported
DAD-aligned Java decompiler**, plus MCP and FastAPI/SSE backends for agent integrations.

Built for **mobile threat hunting / malware triage** — fast, low-memory, embeddable, and
parallel-safe — rather than Xposed module development.

## Why

| | dexllm |
|---|---|
| APK load | ~15 ms (lazy slicer parse — 100–1800× faster than androguard) |
| Decompile | DAD-quality Java; ~2–9× faster than the Java port (JandroGuard), 4.5× faster per-method than androguard |
| Memory | ~520 MB on a 39k-class app (vs 9.9 GB for the JVM port) |
| Parallel | C++ releases the GIL → real multi-threaded decompile from one in-process instance |
| Search | L1–L7 (name / string / annotation / super / API call-site / xref) — 3–6× faster than androguard |
| AST | `decompile_method_ast` returns the full androguard `dast.py` nested AST |
| LLM | `dexllm.tools` catalog → MCP stdio server + FastAPI/SSE web backend |

See [docs/usage.md](docs/usage.md) for the full API walkthrough (L1–L7 + decompile)
and [CLAUDE.md](CLAUDE.md) for the decompiler port internals.

## Benchmark vs androguard

dexllm ports androguard's DAD decompiler to C++, so the comparison is pure runtime
(native vs Python) and output parity, **single-threaded, same APK / same methods**.
Reproduce with [`bench/bench_vs_androguard.py`](bench/bench_vs_androguard.py):

```bash
pip install -e ".[dev]"          # dexllm + androguard
python bench/bench_vs_androguard.py /path/to/app.apk
```

**APK:** `com.example.android.tvleanback.apk` — 4135 classes · 500-method decompile sample · single-threaded
(Ryzen 9 9950X, Python 3.13):

| Operation | dexllm | androguard | speedup |
|---|---|---|---|
| APK load | **24.5 ms** | 2.84 s | 116× |
| Decompile — method (500) | **28.4 ms** | 128.9 ms | 4.5× |
| └ per method | **0.06 ms** | 0.26 ms | 4.5× |
| Decompile — whole class (200) | **77.6 ms** | 368.7 ms | 4.8× |
| └ per class | **0.39 ms** | 1.84 ms | 4.8× |
| search: class name `contains "Activity"` | **0.59 ms** | 1.55 ms | 3× |
| search: methods using string `"http"` | **1.95 ms** | 8.28 ms | 4× |
| search: call sites of `Log.d` | **0.27 ms** | 1.22 ms | 5× |

**Java decompile output parity vs androguard** (indent-normalized):
method byte-identical **92.4%** (462/500) · whole-class byte-identical **56.5%** · whole-class
line-overlap **94.0%**. (Byte-identical at class scale is strict — one differing line fails the
whole class; line-overlap is the fairer "how close" measure.) Residual mismatches are
semantic-equivalent (variable-name suffixes) or cases where dexllm emits spec-correct Java that
androguard gets wrong.

**Parallel decompile** — dexllm releases the GIL in `decompile_*`, so threads give real
parallelism on one shared instance; androguard cannot use threads at all (GIL + non-thread-safe
analysis). Full-APK decompile of the same 4135 classes:

| dexllm | wall | speedup |
|---|---|---|
| sequential (1 thread) | 1.85 s | 1.0× |
| 32 threads (shared instance) | **188 ms** | **9.9×** |

Speedup is workload-dependent. Here it peaks at **~10.5× near the 16 physical cores** (Ryzen 9
9950X is 16C/32T); the 32 logical (SMT) threads regress slightly to ~9.9× from scheduler
contention, so `bench_vs_androguard.py` (which uses `os.cpu_count()` = 32) reports the 32-thread
figure above. On a 39k-class app the speedup drops to ~3× because returning hundreds of MB of
decompiled text becomes GIL-bound. The APK-load gap instead widens with size (≈1800× on the
39k-class app — lazy slicer parse is near-constant-time).

**Each tool at its realistic max** — dexllm parallel (32 threads) vs androguard single-threaded
(its *only* mode), full-APK decompile, end-to-end:

| stage | dexllm (parallel) | androguard (single) | speedup |
|---|---|---|---|
| APK load | 23.5 ms | 2.78 s | 118× |
| full decompile (4135 classes) | **188 ms** | 9.91 s | 53× |
| **END-TO-END** | **0.21 s** | 12.69 s | **60×** |

## Repository layout

```
.
├── pyproject.toml          scikit-build-core build config
├── CMakeLists.txt          native build (drives vendor/ + native/)
├── src/dexllm/             Python package: DexKit, tools, mcp_server, server, capability, …
├── native/                 C++ sources
│   ├── core_ext/             extension over upstream DexKit (search / ref enumeration)
│   ├── dad_cpp/              DAD-aligned Java decompiler (graph/dataflow/control_flow/writer/dast)
│   └── binding/              pybind11 module (C++ ↔ Python boundary)
├── tests/                  C++ parity suites (tests/parity, ctest) + Python pytest suite
├── examples/               runnable usage examples
├── bench/                  reproducible androguard benchmark
├── docs/                   detailed API walkthrough (usage.md)
├── vendor/dexkit_core/     vendored LuckyPray DexKit Core (its own LICENSE)
├── test_apk/               APK corpus for regression (fetched separately; gitignored)
├── CLAUDE.md               decompiler port internals / dev notes
└── LICENSE                 Apache-2.0
```

## Install

Requirements: Python 3.9+, CMake 3.20+, Ninja, a C++20 compiler, pybind11 3.0+, scikit-build-core 0.10+.

```bash
# from the repo root
pip install -e .                 # core (native analyzer + decompiler)
pip install -e ".[all]"          # + MCP server + FastAPI backend
pip install -e ".[dev]"          # + pytest + androguard (for tests / parity)
```

After editing C++ sources, rebuild with the two-step loop (or `/dexkit-build`):

```bash
cd build/cp*-cp*-linux_x86_64 && ninja      # 1. rebuild the native lib
cd - && pip install -e . --no-build-isolation   # 2. reinstall from repo root
```

## Quick start

```python
import dexllm

dk = dexllm.DexKit("/path/to/app.apk")   # .apk/.jar/.zip, or a bare .dex file

# What framework APIs does it touch? (capability / threat triage)
for ref in dk.list_external_method_refs(framework_only=True)[:10]:
    print(ref.java_signature)

# Decompile
print(dk.decompile_method_java("Lcom/example/Foo;->bar()V"))
print(dk.decompile_class_java("Lcom/example/Foo;"))
ast = dk.decompile_method_ast("Lcom/example/Foo;->bar()V")   # nested AST + Java text

# Search
for m in dk.find_methods_using_strings(["http"]):
    print(m)
for site in dk.find_call_sites_to_api("Landroid/util/Log;->d(Ljava/lang/String;Ljava/lang/String;)I"):
    print(site)
```

LLM backends (need the `[all]` extra):

```bash
python -m dexllm.mcp_server                 # MCP stdio (Claude Desktop / Cursor / Continue)
uvicorn dexllm.server:app --port 8000       # FastAPI + SSE web backend
```

## Tests

```bash
# C++ parity suites (self-contained, no APK needed) — primary regression gate
cd build/cp*-cp*-linux_x86_64 && ninja parity_tests && ctest --output-on-failure

# Python suite (skips APK-dependent tests if no APK is available)
pip install -e ".[dev]"
DEXLLM_TEST_APK=/path/to/app.apk pytest tests -v
```

See [tests/README.md](tests/README.md) for details.

## Licence

Apache-2.0 — see [LICENSE](LICENSE). Vendored DexKit Core under `vendor/dexkit_core/` keeps its
own licence ([vendor/dexkit_core/LICENSE](vendor/dexkit_core/LICENSE)).
