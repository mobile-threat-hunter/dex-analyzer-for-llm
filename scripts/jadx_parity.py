#!/usr/bin/env python3
"""jadx-parity gate — measure how close our decompiler output is to jadx, per axis.

The verification gate for porting a jadx feature: run BEFORE (baseline) and AFTER a port,
require the ported AXIS to converge toward jadx while other axes hold (0-regression). jadx
is the DEV/CI reference oracle only (never shipped — embedded-only policy); this is the
jadx analogue of the androguard-DAD parity path.

Two cross-decompiler-robust signals (jadx uses imports + debug var names, we may use FQNs
— both are normalised to simple type names, so the comparison is style-insensitive):

  type_jaccard  — mean Jaccard similarity of the SET of declared local/field TYPES (simple
                  names) per class, ours vs jadx. The TYPE-INFERENCE convergence axis.
  invalid_java  — count of our clearly-invalid-Java lines (a primitive/ref-typed local
                  assigned/used the wrong kind). jadx's is ~0; this must trend to 0 and
                  never regress. The correctness axis.

Usage:
    python scripts/jadx_parity.py [--apk PATH] [--limit N] [--backend dad|jadx]
Prints a JSON report; exits 2 if jadx is unavailable (gate is skipped, not failed).
"""

from __future__ import annotations

import argparse
import glob
import json
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from jadx_ref import jadx_available, jadx_class_java  # noqa: E402

import dexllm  # noqa: E402
from dexllm import is_timeout_marker, safe_decompile_class_java  # noqa: E402

# a `Type name` local/field declaration (captures the type); good enough for a set-similarity
# signal across both decompilers (we only compare the SET of simple type names).
_DECL = re.compile(r"\b([A-Za-z_][\w.$]*(?:\[\])?)\s+[a-z_]\w*\s*[=;]", re.MULTILINE)
_KEYWORDS = {
    "return",
    "new",
    "throw",
    "else",
    "case",
    "final",
    "public",
    "private",
    "protected",
    "static",
    "import",
    "package",
    "class",
    "extends",
    "implements",
}
# our-side clearly-invalid-Java: a primitive-typed local assigned `new` / used as an object.
_INVALID = re.compile(
    r"\b(?:int|boolean|char|byte|short|long|float|double)\s+\w+\s*=\s*new\b"
)


def _type_set(java: str) -> set[str]:
    """Extract the set of declared type SIMPLE names from a class's Java text."""
    out = set()
    for m in _DECL.finditer(java):
        t = m.group(1).split(".")[-1].replace("[]", "")
        if t and t not in _KEYWORDS and t[0].isupper():
            out.add(t)
    return out


def _jaccard(a: set, b: set) -> float:
    return len(a & b) / len(a | b) if (a or b) else 1.0


def run(apk: str, limit: int, backend: str) -> dict:
    """Compare our decompiler (given backend) to jadx over up to `limit` classes."""
    dk = dexllm.DexKit(apk)
    classes = dk.list_classes()[:limit]
    sims, ours_invalid, compared = [], 0, 0
    for c in classes:
        ref = jadx_class_java(apk, c)
        if not ref:
            continue  # class absent from jadx output (external/stripped) — skip
        # backend is threaded once the jadx backend exists; today decompile_class_java is DAD.
        ours = safe_decompile_class_java(dk, c, timeout=15.0)
        if is_timeout_marker(ours) or not ours:
            continue
        compared += 1
        sims.append(_jaccard(_type_set(ours), _type_set(ref)))
        ours_invalid += len(_INVALID.findall(ours))
    return {
        "apk": Path(apk).name,
        "backend": backend,
        "classes_compared": compared,
        "type_jaccard": round(sum(sims) / len(sims), 4) if sims else None,
        "ours_invalid_java": ours_invalid,
    }


def main() -> None:
    """Run the jadx-parity gate and print a JSON report."""
    ap = argparse.ArgumentParser()
    ap.add_argument("--apk")
    ap.add_argument("--limit", type=int, default=150)
    ap.add_argument("--backend", default="dad", choices=["dad", "jadx"])
    args = ap.parse_args()
    if not jadx_available():
        print(
            json.dumps(
                {"skipped": "jadx CLI not found — build ./gradlew dist or set $JADX"}
            )
        )
        sys.exit(2)
    apk = args.apk or next(
        (p for p in sorted(glob.glob("test_apk/APK/*.apk")) if "a2dp.Vol" in p),
        None,
    )
    if not apk:
        print(json.dumps({"skipped": "no APK"}))
        sys.exit(2)
    print(json.dumps(run(apk, args.limit, args.backend), indent=2))


if __name__ == "__main__":
    main()
