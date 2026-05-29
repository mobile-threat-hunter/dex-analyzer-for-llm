---
name: dexkit-bench
description: |
  Head-to-head performance benchmark — androguard DAD (Python reference) vs DexKit-DAD (C++ port).
  Measures wall-clock time per method on the same corpus, verifies parity of output where the
  port is byte-identical to DAD. Use to validate that the C++ port preserves DAD semantics while
  delivering the expected speedup.
---

## What this measures

For a chosen APK, decompile a sample of N methods (default 500) on both implementations:

| Metric | DexKit-DAD (C++) | androguard DAD (Python) |
|---|---|---|
| Total wall time | sum of `dk.decompile_method_java()` | sum of `DvMethod(m).process()` + `get_source()` |
| Per-method mean | ms | ms |
| Output match rate | byte-identical method count / N | — |
| Empty rate | external-ref methods (both should agree) | same |

A healthy result: DexKit ~50-200× faster, with high byte-identical match rate on non-external
methods (mismatches are either DAD quirks already deferred in CLAUDE.md or genuine port bugs
worth investigating via [/dexkit-diff](../dexkit-diff/SKILL.md)).

## Execute

```bash
python << 'EOF'
import sys, time, random
sys.stdout.reconfigure(line_buffering=True)
from loguru import logger; logger.remove()
import dexkit_py
from androguard.misc import AnalyzeAPK
from androguard.decompiler.decompile import DvMethod

APK = "/home/nyahumi/Project/Dexkit/test_apk/APK/com.example.android.tvleanback.apk"
N = 500

dk = dexkit_py.DexKit(APK)
_a, _d_list, dx = AnalyzeAPK(APK)
methods = [m for m in dx.get_methods() if not m.is_external() and m.get_method().get_code() is not None]
random.seed(42); random.shuffle(methods); sample = methods[:N]
print(f"Sampling {len(sample)} methods from {APK}", flush=True)

def norm(s):
    # androguard DAD emits standalone-method output with class-context 4-space
    # indent; DexKit's decompile_method_java is true standalone (no indent).
    # Strip leading whitespace per line so byte-match isn't dominated by indent.
    return "\n".join(line.lstrip() for line in s.splitlines()) if s else ""

# DexKit-DAD pass
t0 = time.time(); dk_out = {}
for m in sample:
    em = m.get_method()
    desc = f"{em.get_class_name()}->{em.get_name()}{em.get_descriptor()}"
    try: dk_out[desc] = dk.decompile_method_java(desc)
    except Exception as e: dk_out[desc] = f"// CRASH: {type(e).__name__}"
dk_ms = (time.time() - t0) * 1000

# androguard DAD pass
t0 = time.time(); dad_out = {}
for m in sample:
    em = m.get_method()
    desc = f"{em.get_class_name()}->{em.get_name()}{em.get_descriptor()}"
    try:
        dv = DvMethod(m); dv.process(); dad_out[desc] = dv.get_source()
    except Exception as e: dad_out[desc] = f"// CRASH: {type(e).__name__}"
dad_ms = (time.time() - t0) * 1000

match = sum(1 for d in dk_out if norm(dk_out[d]) == norm(dad_out.get(d, "")))
both_nonempty = sum(1 for d in dk_out if dk_out[d] and dad_out.get(d, ""))
print(f"\n=== Bench result over {N} methods ===")
print(f"  DexKit-DAD : {dk_ms:>8.1f} ms total ({dk_ms/N:.3f} ms/method)")
print(f"  androguard : {dad_ms:>8.1f} ms total ({dad_ms/N:.3f} ms/method)")
print(f"  speedup    : {dad_ms/max(dk_ms,0.001):.1f}x")
print(f"  byte-match : {match}/{N} ({match/N*100:.1f}%), both-nonempty: {both_nonempty}")
EOF
```

## Interpreting results

- **Speedup < 10×**: investigate. The DAD port should be heavily faster — Python interpreter
  + per-instance object overhead is the dominant cost in androguard DAD.
- **Match rate < 80% on non-trivial methods**: investigate divergence with `/dexkit-diff` on
  a sample of mismatches. Common legitimate causes (mismatches from DAD bugs we've fixed in
  production — see CLAUDE.md "Upstream DAD bug fixes" section):
  - `get_params_type` quirk (DAD: `IJ p0`, DexKit: `int p0, long p1`)
  - `java/lang/*` char-set strip bug (DAD: `otation.Foo`, DexKit: `annotation.Foo` — fixed)
- **Match rate ~90%**: port is healthy. The residual mismatch is dominated by `var_naming`
  suffix off-by-N (semantic-equivalent) and other deep-IR categories — see CLAUDE.md
  `project-deferred-decompiler-tasks`.

## Caveats

- androguard DAD crashes (RecursionError, AttributeError on ExternalMethod, etc.) — caught as
  `// CRASH:` strings in the bench output. These count as legitimate divergence from DexKit
  (which generally doesn't crash on the same input).
- `random.seed(42)` keeps the sample deterministic across runs for diff-able output.
- `AnalyzeAPK` load time (~3-5s for tvleanback) is NOT in the per-pass timing; both passes
  reuse the loaded `dx` object.
