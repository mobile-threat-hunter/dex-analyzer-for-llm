---
name: jadx-diff
description: |
  Side-by-side comparison between jadx (reference oracle) and our decompiler for a class/method,
  and the jadx-parity gate metric. Use when porting a jadx algorithm (Phase C onward) to verify
  the ported axis converges toward jadx while other axes hold. jadx is a DEV/CI reference ONLY —
  never shipped (embedded-only policy); this mirrors how the DAD port uses androguard.
---

## What this is (and the hard constraint)

The jadx **runtime is forbidden in the product** (no JVM/subprocess decompiler ships —
[[feedback_decompiler_choice]]). We **reimplement** jadx algorithms in C++ (Apache-2.0 NOTICE
attribution) and validate the port against jadx's own output using jadx as a **test-time
reference oracle** — the exact pattern the DAD port uses with androguard. This skill drives that
comparison. Do **not** wire jadx into any product path.

## Setup (once)

jadx must be resolvable by `scripts/jadx_ref.py` (`$JADX` → `$JADX_HOME/bin/jadx` →
`/tmp/jadx-dist/bin/jadx` → PATH). Get it:

```bash
# prebuilt release (fastest):
curl -sL -o /tmp/jadx.zip https://github.com/skylot/jadx/releases/download/v1.5.0/jadx-1.5.0.zip
mkdir -p /tmp/jadx-dist && (cd /tmp/jadx-dist && unzip -oq /tmp/jadx.zip)
python scripts/jadx_ref.py   # prints the resolved jadx path
```

If jadx is absent the harness returns `None` and the gate SKIPS (never fails) — like the
AOSP-dataset-gated tooling.

## Usage

### Per-method / per-class side-by-side (dev inspection)

```
/jadx-diff <class-or-method-descriptor> [from <apk>]
```

```bash
# our engine (whichever backend) vs jadx, for one class:
python scripts/jadx_ref.py test_apk/APK/<apk> 'La2dp/Vol/StoreLoc;'   # jadx's Java
python -c "import dexllm; print(dexllm.DexKit('test_apk/APK/<apk>').decompile_class_java('La2dp/Vol/StoreLoc;'))"
```

Read them side by side. jadx and our output differ in STYLE (imports vs FQNs, var names,
formatting) — do NOT chase byte-identity. Compare the AXIS you are porting:

- **type inference** — does our declared type for a value match jadx's (esp. framework upcasts:
  jadx `List v = new ArrayList()` via its classpath vs our `ArrayList`/`Object`)? Is our
  invalid-Java (`int v = new X()`, `Object v; v.m()`) gone where jadx is clean?
- **control-flow structuring** — same loop/if/try nesting, no empty blocks vs jadx?
- **var naming** — jadx uses debug names when present; ours may not (a later axis).

### Aggregate convergence metric (the gate)

```bash
python scripts/jadx_parity.py --limit 150            # DAD-vs-jadx today; jadx-backend later
# → {"type_jaccard": 0.17, "ours_invalid_java": 0, ...}
```

`type_jaccard` = mean set-similarity of declared types (ours vs jadx), a **directional**
convergence proxy (absolute value is noisy; the BEFORE→AFTER delta is the signal).
`ours_invalid_java` = our clearly-invalid-Java count (jadx's ≈ 0).

### The AUTOMATIC gate (ratchet test)

Convergence is enforced by a test, not by remembering to run a script:

```bash
pytest tests/test_jadx_parity.py    # part of `pytest tests/`; FAILS on a convergence regression
```

`tests/test_jadx_parity.py` runs the metric vs the committed `tests/jadx_parity_baseline.json`
and fails if `type_jaccard` drops below the floor or `ours_invalid_java` rises above the ceiling.
jadx-availability + jadx-version gated → SKIPS in CI without jadx / on a version mismatch (never a
false fail). When a port RAISES convergence, ratchet the floor up in the baseline in the same PR.

## The gate (run for EVERY ported jadx feature)

Porting a jadx algorithm is a production C++ change, so it already goes through a/b
0-regression + parity 28/28 + 0-crash sweep + the ≥2-reviewer adversarial gate + HACK
self-check. The jadx-parity gate ADDS, on top:

1. **Baseline** — before the port, record `jadx_parity.py` (the whole metric) AND, for a curated
   handful of methods the feature targets, the `/jadx-diff` side-by-side.
2. **Port**, then **re-measure with the SAME command**:
   - the **ported axis converges toward jadx** — `type_jaccard` (or the axis-specific signal)
     RISES; the targeted methods now match jadx's decision in the side-by-side.
   - **other axes hold** — no regression on `ours_invalid_java` or the a/b buckets.
3. **Pin it** — add jadx-sourced fixtures for the specific decisions ported (a method where jadx
   makes decision X → assert our engine now makes X), analogous to the DAD `*_parity_test.cpp`
   suites. These become the permanent regression gate (jadx-availability-gated, so CI without
   jadx skips them, like `test_header_roundtrips_generator_source`).

Do NOT accept a port that leaves the ported axis flat/worse vs jadx, or that regresses another
axis. jadx bug vs our bug: if jadx and our output diverge, decide whether jadx is RIGHT (port
harder) or jadx itself is wrong here (rare — note it, keep our correct output; the analogue of a
"DAD-faithful vs DAD-bug" call in `/dexkit-diff`).
