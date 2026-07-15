"""AUTOMATIC jadx-convergence ratchet gate.

Runs the jadx-parity metric (ours vs jadx) against a committed baseline and FAILS on a
regression — so "did this decompiler change move us away from jadx?" is checked
automatically, not by hand. This is the enforced half of the jadx-port gate (the
`/jadx-diff` skill is the manual per-method companion).

Ratchet semantics: a change must keep ``type_jaccard >= floor`` and
``ours_invalid_java <= ceiling`` (from tests/jadx_parity_baseline.json). When a jadx-algorithm
port IMPROVES convergence, raise the floor to the new value (coverage-ratchet) in the same PR.

jadx is a DEV/CI reference oracle ONLY (never shipped — embedded-only policy). The test SKIPS
when jadx is unavailable (CI without jadx) or when the installed jadx version differs from the
baseline's pin (a different jadx gives a different reference — skip, don't false-fail).
"""

from __future__ import annotations

import glob
import json
import subprocess
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "scripts"))

from jadx_ref import jadx_available, jadx_cli  # noqa: E402

BASELINE = json.loads((REPO / "tests" / "jadx_parity_baseline.json").read_text())


def _jadx_version() -> str | None:
    cli = jadx_cli()
    if not cli:
        return None
    try:
        out = subprocess.run(
            [cli, "--version"], capture_output=True, text=True, timeout=60
        )
        return out.stdout.strip().splitlines()[0].strip() if out.stdout else None
    except Exception:  # noqa: BLE001 — any failure → treat as unavailable
        return None


def test_jadx_convergence_does_not_regress():
    """type_jaccard >= floor and ours_invalid_java <= ceiling vs the committed baseline."""
    if not jadx_available():
        pytest.skip("jadx CLI not found — build/install jadx or set $JADX")
    ver = _jadx_version()
    if ver != BASELINE["jadx_version"]:
        pytest.skip(
            f"jadx {ver} != baseline pin {BASELINE['jadx_version']} — "
            f"reference differs, skip (re-baseline for a new jadx)"
        )
    apk = next(
        (
            p
            for p in sorted(glob.glob(str(REPO / "test_apk" / "APK" / "*.apk")))
            if BASELINE["apk_match"] in p
        ),
        None,
    )
    if not apk:
        pytest.skip(f"baseline APK matching {BASELINE['apk_match']!r} not present")

    from jadx_parity import run  # imported here so a jadx-less CI never touches it

    r = run(apk, BASELINE["limit"], BASELINE["backend"])
    assert r["classes_compared"] > 0, "no classes compared — jadx output empty?"
    # convergence must not drop below the ratchet floor (a change moved us away from jadx)
    assert r["type_jaccard"] >= BASELINE["type_jaccard_floor"], (
        f"jadx convergence REGRESSED: type_jaccard {r['type_jaccard']} < floor "
        f"{BASELINE['type_jaccard_floor']}. If this change is intended and correct, it "
        f"should not lower convergence; if a port RAISED it, ratchet the floor up."
    )
    # our invalid-Java must not rise above the ceiling (correctness axis)
    assert r["ours_invalid_java"] <= BASELINE["invalid_ceiling"], (
        f"invalid-Java REGRESSED: {r['ours_invalid_java']} > ceiling "
        f"{BASELINE['invalid_ceiling']}"
    )
