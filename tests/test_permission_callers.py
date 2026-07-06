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


def _load_codegen():
    spec = importlib.util.spec_from_file_location(
        "_gen_perm_api_data", _REPO / "scripts" / "gen_perm_api_data.py"
    )
    gen = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(gen)
    return gen


def test_blob_codec_roundtrips_non_ascii_and_specials():
    """Issue #15 blob codec: the C++-literal escaper must round-trip ANY byte through
    the compiler-decode, including non-ASCII (multi-byte UTF-8) and codepoints > 0o777
    — an earlier draft octal-escaped the Python CODEPOINT, silently corrupting é (233→
    1 byte vs UTF-8's 2) and mis-emitting a 5-digit octal for CJK. Guards adversarial
    finding #1 (the bundled corpus is ASCII-only, so the sha256 a/b cannot catch it)."""
    gen = _load_codegen()
    for s in [
        "com.example.Café",  # U+00E9 (2-byte UTF-8)
        "com.example.ᐁ",  # U+1441 (3-byte, codepoint > 0o777)
        "emoji.😀.Cls",  # U+1F600 (4-byte, supplementary)
        'sig(java.util.List<java.lang.String>, "quoted", back\\slash)',
        "digits123.after456",  # a digit right after data (octal-absorb guard)
        "",  # empty
        "a\x1eb",  # would-be RS in payload — escaper still round-trips the bytes
    ]:
        decoded = gen._decode_cpp_literal(gen._cpp_escape_blob(s))
        assert decoded == s.encode("utf-8"), f"blob codec not byte-identical: {s!r}"


def test_roundtrip_records_reconstructs_fields():
    """_roundtrip_records (the build-time self-check the codegen runs) must reconstruct
    multi-field records incl. a non-ASCII field and an empty (0-arity) param field."""
    gen = _load_codegen()
    FS, PS = gen.FS, gen.PS
    recs = [
        FS.join(["android.permission.FOO", "dangerous", "com.x.Café", "m", "sig()", ""]),
        FS.join(["p", "normal", "C", "n", "s", PS.join(["int", "String"])]),
    ]
    got = gen._roundtrip_records(recs)
    assert got[0] == ["android.permission.FOO", "dangerous", "com.x.Café", "m", "sig()", ""]
    assert got[1][5].split(PS) == ["int", "String"]


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
