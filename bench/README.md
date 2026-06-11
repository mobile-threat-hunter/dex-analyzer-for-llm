# Benchmarks

Reproducible performance comparison of `dexllm` against androguard (the upstream
DAD decompiler dexllm ports).

```bash
pip install -e "..[dev]"        # dexllm + androguard
python bench_vs_androguard.py [path/to/app.apk] [N_methods] [M_classes]
```

`bench_vs_androguard.py` measures, single-threaded on the same APK / same inputs:

- **APK load** time
- **Decompile — method**: `N`-method sample (default 500), time + **byte-identical
  parity** vs androguard (indent-normalized)
- **Decompile — whole class**: `M`-class sample (default 200), time + class-level
  byte-identical and line-overlap parity
- **Search** time for three queries (class-name / string-use / API call-site)

It prints a paste-ready Markdown table. Numbers vary with hardware and APK; the
table in the top-level [README](../README.md#benchmark-vs-androguard) is from a
Ryzen 9 9950X on `com.example.android.tvleanback.apk`.

> Note: androguard's `AnalyzeAPK` load dominates its wall-clock and scales with
> APK size, while dexllm's slicer load is near-constant — so the load speedup
> grows on larger apps (≈115× here, ≈1800× on a 39k-class APK).
