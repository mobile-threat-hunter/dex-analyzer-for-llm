"""Issue #13 — the engine C++ permission→API→callers join (``dk.permission_callers``)
must be byte-equivalent to the authoritative Python
``dexllm.dangerous_permission_api_callers`` on the bundled AOSP dataset.

The two share the dataset (embedded into C++ via ``scripts/gen_perm_api_data.py``)
and the WASM binding reuses the C++ join, so this equivalence is the contract that
keeps every consumer (Python, WASM/web, future) in agreement. Adversarial review
verified the internal helpers (Dalvik-proto parsing, overload disambiguation) with
a 200k-proto differential; this is the end-to-end product gate over real APKs.
"""
from __future__ import annotations

import glob
import os

import pytest

import dexllm

_APK_DIR = os.path.join(os.path.dirname(__file__), "..", "test_apk", "APK")
_APKS = sorted(glob.glob(os.path.join(_APK_DIR, "*.apk")))


def _norm_py(d):
    return {
        perm: {
            r["api"]: (tuple(r["descriptors"]), tuple(r["callers"])) for r in rows
        }
        for perm, rows in d.items()
    }


def _norm_cpp(lst):
    return {
        g["perm"]: {
            r["api"]: (tuple(r["descriptors"]), tuple(r["callers"]))
            for r in g["rows"]
        }
        for g in lst
    }


@pytest.mark.parametrize("app_only", [True, False])
def test_cpp_join_matches_python(app_only):
    """C++ permission_callers == Python dangerous_permission_api_callers, per APK."""
    nonempty = 0
    for apk in _APKS:
        try:
            dk = dexllm.DexKit(apk)
        except Exception:
            continue  # unloadable fixtures (Invalid.apk, resources-only, …)
        py = _norm_py(
            dexllm.dangerous_permission_api_callers(dk, app_only=app_only)
        )
        cpp = _norm_cpp(dk.permission_callers(app_only))
        assert cpp == py, f"{os.path.basename(apk)} (app_only={app_only})"
        if py:
            nonempty += 1
    # The bundled corpus must exercise the non-empty path (a2dp.Vol /
    # partialsignature reference dangerous APIs with app-code callers), else the
    # equivalence check is vacuous. (Some APKs reference dangerous APIs but only
    # from framework callers, dropped under app_only, so the caller-level count is
    # smaller than the API-reference count.)
    assert nonempty >= 2, f"expected ≥2 APKs with dangerous-API callers, got {nonempty}"


def test_protection_level_is_dangerous():
    """Every group carries the bundled slice's protection level."""
    for apk in _APKS:
        try:
            dk = dexllm.DexKit(apk)
        except Exception:
            continue
        for g in dk.permission_callers(True):
            assert g["protectionLevel"] == "dangerous"
            assert g["rows"], "a group with no rows should be omitted"
