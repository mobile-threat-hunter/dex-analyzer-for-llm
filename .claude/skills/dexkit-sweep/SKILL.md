---
name: dexkit-sweep
description: |
  Full-APK regression sweep across every loadable APK in test_apk/APK/. Decompiles every class,
  counts crashes/errors/empties, reports throughput. Use as the primary success gate for any
  decompiler change — a green sweep means no class in the corpus crashes the C++ pipeline.
---

## What this measures

For every method in every loadable APK:
- **class_crash**: `decompile_class_java()` raised a Python exception (segfault, runtime_error, etc.)
- **method_decompile_error / method_method_error**: output starts with `// DECOMPILE ERROR:` or
  `// METHOD ERROR:` (caught in C++ via `try{...}catch(std::exception&)`)
- **method_empty**: empty output — usually external method ref (no ClassData in this dex),
  matches DAD's effective behavior
- **method_success**: any other non-empty output

The previous L6-era defect categories (orphan goto, brace imbalance, invalid_lhs,
duplicate_return, self_assign) were text artifacts of the L6 output and are no longer relevant.
The DAD pipeline produces correct Java by construction; defects manifest as either crashes,
exceptions, or wrong-but-non-crashing output (which the sweep won't catch — use
[/dexkit-diff](../dexkit-diff/SKILL.md) for that).

## Execute

```bash
python /tmp/full_sweep.py
```

If `/tmp/full_sweep.py` is missing, recreate it. It must:
- Glob every `*.apk` in `/home/nyahumi/Project/Dexkit/test_apk/APK/`
- Skip APKs with `dex_count() == 0` (resources-only)
- For each APK, enumerate classes via `androguard.misc.AnalyzeAPK` (DexKit has no class
  enumeration API)
- Call `dk.decompile_class_java(class_descriptor)` for each class
- Categorize each method block by marker (`// DECOMPILE ERROR`, `// METHOD ERROR`) or empty
- For APKs >5MB, cap class processing at 200 to keep total time bounded; for true full
  coverage on the cap'd APK, run a focused sweep instead (see below)
- **`gc.collect()` between APKs** (mandatory). androguard's `AnalyzeAPK` returns a heavy
  `dx`/`d_list` graph held by Python cyclic refs; without explicit GC the working set grows
  monotonically and later APK iterations slow down (~30× slowdown observed at ~17 APKs on
  this corpus, hang-like behavior visible to the user). The dropped refs free both the
  androguard analysis and any DexKit-side caches scoped to the per-APK `DexKit` instance.

## Focused full-coverage sweep (no cap)

For one APK without the 200-class cap:
```bash
python << 'EOF'
import sys, time; sys.stdout.reconfigure(line_buffering=True)
from loguru import logger; logger.remove()
import dexllm; from androguard.misc import AnalyzeAPK
APK = "/home/nyahumi/Project/Dexkit/test_apk/APK/com.example.android.tvleanback.apk"
dk = dexllm.DexKit(APK)
_, d_list, _ = AnalyzeAPK(APK)
classes = [c.get_name() for dex in d_list for c in dex.get_classes()]
print(f"{len(classes)} classes", flush=True)
crashes = 0; t = time.time()
for c in classes:
    try: dk.decompile_class_java(c)
    except Exception as e:
        crashes += 1
        print(f"CRASH {c}: {type(e).__name__}: {str(e)[:80]}", flush=True)
print(f"{crashes} crashes / {len(classes)} classes in {time.time()-t:.1f}s")
EOF
```

## Comparing runs

When investigating a category, save a baseline before your change:
```bash
python /tmp/full_sweep.py > /tmp/sweep_before.txt
```

Then patch + `/dexkit-build` + re-sweep, and diff the AGGREGATE block. Per-category deltas
tell you whether the patch helped, regressed, or was neutral.

## Performance reference

- Workstation: Ryzen 9 9950X (16C/32T), 128GB DDR5 — single-process sequential.
- Last reference run (2026-05-27): 22 APKs, 20,221 classes, 159,305 methods, **0 crashes**,
  ~17,900 methods/sec.
- Bottleneck is androguard `AnalyzeAPK` loading (per-APK), not DexKit decompilation.
- If runtime > 30s on the full sweep, suspect a hang in one specific method — bisect by
  enumerating classes and decompiling per-class until a target hangs.

## Multi-process variant (legacy reference)

The L6-era multi-process sweep used `ProcessPoolExecutor(max_workers=24)` with class-chunks
of 200. Currently overkill — single-process sweep finishes in ~10s for the full corpus.
If sweeping enormous external APK collections (1000+ APKs), revive the multi-process pattern.
