"""Issue #13/#14 — the engine C++ permission→API→callers join
(``dk.permission_callers``, all protection levels) must be byte-equivalent to the
authoritative Python ``dexllm.permission_api_callers`` on the bundled AOSP dataset.

The two share the dataset (embedded into C++ via ``scripts/gen_perm_api_data.py``)
and the WASM binding reuses the C++ join, so this equivalence is the contract that
keeps every consumer (Python, WASM/web, future) in agreement. Adversarial review
verified the internal helpers (Dalvik-proto parsing, overload disambiguation) with
a 200k-proto differential; this is the end-to-end product gate over real APKs.
"""
from __future__ import annotations

import glob
import importlib.util
import json
import os
import tempfile
from pathlib import Path

import pytest

import dexllm

_REPO = Path(__file__).resolve().parents[1]
_APK_DIR = os.path.join(os.path.dirname(__file__), "..", "test_apk", "APK")
_APKS = sorted(glob.glob(os.path.join(_APK_DIR, "*.apk")))


def test_perm_data_sorted_and_header_in_sync():
    """perm_api.json is perm-sorted (C++/Python group-order contract) and the
    committed perm_api_data.h byte-equals a fresh codegen run — a stale header (JSON
    edited without re-running the codegen) would silently diverge the two paths."""
    data = _REPO / "src" / "dexllm" / "data"
    perm_api = json.loads((data / "perm_api.json").read_text())
    assert list(perm_api) == sorted(perm_api), "perm_api.json must be sorted by perm"
    spec = importlib.util.spec_from_file_location(
        "_gen_perm_api_data", _REPO / "scripts" / "gen_perm_api_data.py"
    )
    gen = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(gen)
    committed = (_REPO / "native" / "core_ext" / "gen" / "perm_api_data.h").read_text()
    with tempfile.TemporaryDirectory() as d:
        gen.OUT = Path(d) / "perm_api_data.h"
        gen.main()
        regenerated = gen.OUT.read_text()
    assert regenerated == committed, (
        "perm_api_data.h out of sync with perm_api.json/perm_levels.json — "
        "re-run scripts/gen_perm_api_data.py"
    )


def _norm(groups):
    """Normalise groups for equality — group order AND within-group row order matter
    (both paths return an ordered list), so rows stay an ordered tuple, not a dict."""
    return [
        (
            g["perm"],
            g["protectionLevel"],
            tuple(
                (r["api"], tuple(r["descriptors"]), tuple(r["callers"]))
                for r in g["rows"]
            ),
        )
        for g in groups
    ]


@pytest.mark.parametrize("app_only", [True, False])
def test_cpp_join_matches_python(app_only):
    """C++ permission_callers == Python permission_api_callers (all levels), per APK."""
    from dexllm.dangerous_api import permission_api_callers

    nonempty = 0
    for apk in _APKS:
        try:
            dk = dexllm.DexKit(apk)
        except Exception:
            continue  # unloadable fixtures (Invalid.apk, resources-only, …)
        py = _norm(permission_api_callers(dk, app_only=app_only))
        cpp = _norm(dk.permission_callers(app_only))
        assert cpp == py, f"{os.path.basename(apk)} (app_only={app_only})"
        if py:
            nonempty += 1
    # The bundled corpus must exercise the non-empty path (a2dp.Vol /
    # partialsignature reference dangerous APIs with app-code callers), else the
    # equivalence check is vacuous. (Some APKs reference dangerous APIs but only
    # from framework callers, dropped under app_only, so the caller-level count is
    # smaller than the API-reference count.)
    assert nonempty >= 2, f"expected ≥2 APKs with permission-API callers, got {nonempty}"


def test_protection_levels_span_and_are_valid():
    """Groups carry a valid level bucket, and the corpus spans beyond dangerous."""
    from dexllm.dangerous_api import PERM_LEVELS

    seen = set()
    for apk in _APKS:
        try:
            dk = dexllm.DexKit(apk)
        except Exception:
            continue
        for g in dk.permission_callers(False):
            assert g["protectionLevel"] in PERM_LEVELS
            assert g["rows"], "a group with no rows should be omitted"
            seen.add(g["protectionLevel"])
    # Issue #14: the full surface must expose non-dangerous levels the old
    # dangerous-only slice hid (the bundled corpus references signature/normal APIs).
    assert "dangerous" in seen and seen - {"dangerous"}, f"levels seen: {seen}"
