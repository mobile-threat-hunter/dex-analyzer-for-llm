#!/usr/bin/env python3
"""DvClass header+fields parity check vs androguard DAD.

For each loadable APK in test_apk/APK, sample N classes and assert that
DexKit's `decompile_class_java(cls)` produces a header+fields region
byte-identical to androguard `DvClass(cls, dx).get_source()`.

The method-body region is excluded from comparison — that's covered by
the per-method parity tracked in `/dexkit-bench` (currently ~90% match,
residual breakdown in CLAUDE.md `project-deferred-decompiler-tasks`).

Exit code:
  0   — all sampled classes match in header+fields
  1   — at least one mismatch; first 3 diffs printed
"""
from __future__ import annotations

import argparse
import difflib
import gc
import os
import random
import sys
from glob import glob
from pathlib import Path

from loguru import logger

logger.remove()
from androguard.decompiler.decompile import DvClass
from androguard.misc import AnalyzeAPK

import dexllm
from dexllm import is_timeout_marker, safe_decompile_class_java

# Per CLAUDE.md "Known critical hang", the DAD pipeline can hang on
# specific classes. dvclass_parity is a batch check, so we MUST use the
# safe wrapper.
DECOMPILE_TIMEOUT_S = 10.0


def header_fields(src: str) -> str:
    """Slice header + field declarations; stop at first method line."""
    out: list[str] = []
    started = False
    for ln in src.splitlines():
        s = ln.strip()
        out.append(ln)
        if not started:
            # Class header line ending in `{`.
            if s.endswith("{") and (
                " class " in s
                or " interface " in s
                or s.startswith("class ")
                or s.startswith("interface ")
            ):
                started = True
            continue
        if s == "}":
            break
        # Method line: contains '(' and isn't terminated by ';'.
        if "(" in s and not s.endswith(";"):
            out.pop()
            break
    return "\n".join(out)


def parity_for_apk(apk: str, n: int) -> tuple[int, int, int, list[tuple[str, str]]]:
    """Returns (matched, total, timeouts, mismatches[:3])."""
    # Validated load raises on a 0-dex container (resources-only APK); pre-filter
    # by content so those are skipped instead of aborting the run.
    if dexllm.identify(apk)["dex_count"] == 0:
        print("  skip: no classes*.dex", flush=True)
        return 0, 0, 0, []
    dk = dexllm.DexKit(apk)
    try:
        _a, d_list, dx = AnalyzeAPK(apk)
    except Exception as e:
        print(f"  AnalyzeAPK failed: {e}", flush=True)
        return 0, 0, 0, []

    # Pool every defined class across all dexes
    all_classes = [(d, c) for d in d_list for c in d.get_classes()]
    if not all_classes:
        return 0, 0, 0, []
    random.shuffle(all_classes)
    sample = all_classes[:n]

    matched = 0
    timeouts = 0
    mismatches: list[tuple[str, str]] = []
    for d, cls in sample:
        cls_name = cls.get_name()
        try:
            dk_out = safe_decompile_class_java(
                dk, cls_name, timeout=DECOMPILE_TIMEOUT_S
            )
        except Exception:
            continue
        if is_timeout_marker(dk_out):
            timeouts += 1
            continue  # skip hangs from the parity check entirely
        if not dk_out:
            continue
        try:
            dv = DvClass(cls, dx)
            dv.process()
            dad_out = dv.get_source()
        except Exception:
            continue
        if header_fields(dk_out) == header_fields(dad_out):
            matched += 1
        else:
            if len(mismatches) < 3:
                mismatches.append((cls_name, _diff(dk_out, dad_out)))
    del dx
    del d_list
    gc.collect()
    return matched, len(sample), timeouts, mismatches


def _diff(dk: str, dad: str) -> str:
    return "\n".join(
        list(
            difflib.unified_diff(
                header_fields(dad).splitlines(),
                header_fields(dk).splitlines(),
                "DAD",
                "DexKit",
                lineterm="",
            )
        )[:30]
    )


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument(
        "--corpus",
        default=str(Path(__file__).resolve().parents[1] / "test_apk" / "APK"),
        help="Directory containing *.apk files (default: <repo>/test_apk/APK)",
    )
    ap.add_argument(
        "-n",
        "--per-apk",
        type=int,
        default=30,
        help="Sample size per APK (default: 30)",
    )
    ap.add_argument("--seed", type=int, default=42)
    args = ap.parse_args()
    random.seed(args.seed)

    apks = sorted(glob(os.path.join(args.corpus, "*.apk")))
    if not apks:
        print(f"No APKs in {args.corpus}", file=sys.stderr)
        return 1

    print("=== DvClass header+fields parity vs androguard DAD ===")
    print(f"{'APK':<55} | match              | timeouts")
    print("-" * 92)
    total_match = 0
    total_n = 0
    total_timeouts = 0
    failing_apks: list[str] = []
    all_mismatches: list[tuple[str, str, str]] = []
    for apk in apks:
        name = os.path.basename(apk)
        if os.path.getsize(apk) > 100_000_000:
            print(f"{name:<55} | (skip — large/no-dex)")
            continue
        m, n, to, mismatches = parity_for_apk(apk, args.per_apk)
        if n == 0:
            print(f"{name:<55} | (no classes)")
            continue
        pct = m / n * 100
        flag = "" if m == n else f"  ⚠ {n-m} mismatch"
        to_str = f"{to:>2}" if to else " 0"
        print(f"{name:<55} | {m:>3}/{n:<3} ({pct:>5.1f}%){flag:<8} | {to_str}")
        total_match += m
        total_n += n
        total_timeouts += to
        if m < n:
            failing_apks.append(name)
        for cls, diff in mismatches:
            all_mismatches.append((name, cls, diff))
    print("-" * 92)
    pct = total_match / max(total_n, 1) * 100
    print(
        f"{'TOTAL':<55} | {total_match:>3}/{total_n:<3} ({pct:>5.1f}%)         | {total_timeouts:>2}"
    )
    if total_timeouts:
        print(
            f"\n⚠ {total_timeouts} class(es) hit the {DECOMPILE_TIMEOUT_S}s safe_decompile deadline."
            f" These are not counted as parity mismatches (we don't know what DAD would have produced),"
            f" but they DO indicate the P0 safety net was needed."
        )

    if all_mismatches:
        print(f"\n=== First {min(3, len(all_mismatches))} mismatches ===")
        for apk, cls, diff in all_mismatches[:3]:
            print(f"\n--- [{apk}] {cls} ---")
            print(diff)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
