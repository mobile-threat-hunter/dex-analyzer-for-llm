"""Differential gate: C++ ExtractIocs (dk.extract_iocs_native) must be byte-
identical to the Python dexllm.ioc.extract_iocs over the bundled corpus.

Issue #13 — the C++ engine port backs the WASM (embind) binding, replacing
dexllm-web's JS re-implementation + shipped PSL copy; single source of truth
requires the two paths agree exactly (values, per-category order, and the method
xref). This mirrors the Phase 1a permission-callers 0-mismatch methodology.

The obfuscated corpus (local-only) was also verified 0-mismatch during
development; this committed test uses the bundled test_apk/APK corpus.
"""

from __future__ import annotations

import glob
import random
from pathlib import Path

import pytest

import dexllm
from dexllm._dexkit_core import _ioc_scan_strings
from dexllm.ioc import IOC_CATEGORIES, _scan_value_strings, extract_iocs

REPO = Path(__file__).resolve().parents[1]
_APKS = sorted(glob.glob(str(REPO / "test_apk" / "APK" / "*.apk")))

# (with_xref, denoise, xref_limit) — exercise the xref, denoise, and budget paths.
_CONFIGS = [(True, True, 300), (False, True, 300), (True, False, 50)]


def _norm(d: dict) -> dict:
    """Normalise a category dict to {cat: [(value, sorted-methods)]} for equality."""
    return {
        c: [(r["value"], tuple(sorted(r["methods"]))) for r in d[c]]
        for c in IOC_CATEGORIES
    }


@pytest.mark.skipif(not _APKS, reason="no bundled test APK")
@pytest.mark.parametrize("apk", _APKS, ids=lambda p: Path(p).name)
def test_extract_iocs_native_matches_python(apk):
    try:
        dk = dexllm.DexKit(apk)
    except Exception as e:  # noqa: BLE001 — a bad/unloadable APK isn't this test's concern
        pytest.skip(f"APK did not load: {e}")

    for with_xref, denoise, xref_limit in _CONFIGS:
        py = _norm(extract_iocs(dk, with_xref=with_xref, denoise=denoise,
                                xref_limit=xref_limit))
        cpp = _norm(dk.extract_iocs_native(with_xref, denoise, xref_limit))
        assert cpp == py, (
            f"{Path(apk).name} cfg=({with_xref},{denoise},{xref_limit}): "
            f"C++ ExtractIocs diverges from Python extract_iocs"
        )


def _first_loadable():
    for apk in _APKS:
        try:
            return dexllm.DexKit(apk)
        except Exception:  # noqa: BLE001 — skip 0-dex / malformed containers
            continue
    return None


# --- Synthetic scanner differential (the corpus gate cannot inject strings). ---
# _ioc_scan_strings runs the C++ scanners over a supplied list (denoise off, no
# xref); _scan_value_strings is the same-shaped Python scan. These catch scanner
# divergences the corpus misses (e.g. the IPv4 :port backtrack, the codepoint cap).

_REVIEWER_CASES = [
    # IPv4 :port backtracking — Python keeps the bare quad when the port is
    # oversized / dot-followed (the group is a backtrackable optional).
    "10.0.0.1:8080.5", "127.0.0.1:123456", "1.2.3.4:12345.6", "8.8.8.8:800.9",
    "185.220.101.1:1234567", "1.2.3.4:12345", "1.2.3.4:12345x", "1.2.3.4:12345/x",
    # _MAX_SCAN must cap by CODE POINTS, not bytes: 33008 x 'ñ' (2 bytes) is
    # <=65536 code points (Python scans it all) but >65536 bytes.
    "ñ" * 33008 + " 8.8.8.8",
    # A `\b`-adjacent C1 control (non-word) — the case the corpus surfaced.
    "x\x13android@android.com\x82y",
]


def _norm_scan(d: dict) -> dict:
    return {c: sorted(d[c]) for c in IOC_CATEGORIES}


@pytest.mark.parametrize("s", _REVIEWER_CASES)
def test_scan_reviewer_cases(s):
    assert _norm_scan(_ioc_scan_strings([s])) == _norm_scan(
        _scan_value_strings([s], False, frozenset())
    ), "C++ scanner diverges from Python on a crafted input"


def test_scan_fuzz_differential():
    """Random strings from the scanner alphabets: C++ scanners == Python, byte-wise."""
    chars = list(
        "0123456789.:-_@/abcdefABCDEF onion http s ftp ws xn--p1ai []().,;\"'<>\\"
    ) + ["ñ", "\x00", "\x82", "\x1c", "\x1f", "\xa0", "。", "．", "х"]
    rng = random.Random(20260705)
    for _ in range(20000):
        s = "".join(rng.choice(chars) for _ in range(rng.randint(0, 40)))
        got = _norm_scan(_ioc_scan_strings([s]))
        want = _norm_scan(_scan_value_strings([s], False, frozenset()))
        assert got == want, f"scanner fuzz divergence on {s!r}: C++={got} Python={want}"


@pytest.mark.skipif(not _APKS, reason="no bundled test APK")
def test_native_shape_and_categories():
    """The native result carries exactly the five IOC_CATEGORIES with the row shape."""
    dk = _first_loadable()
    if dk is None:
        pytest.skip("no loadable bundled APK")
    out = dk.extract_iocs_native(True, True, 300)
    assert set(out) == set(IOC_CATEGORIES)
    for rows in out.values():
        for r in rows:
            assert set(r) == {"value", "methods"}
            assert isinstance(r["value"], str)
            assert isinstance(r["methods"], list)
