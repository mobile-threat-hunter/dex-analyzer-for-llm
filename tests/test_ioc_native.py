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
import re
from pathlib import Path

import pytest

import dexllm
from dexllm._dexkit_core import _detect_providers_from_strings, _ioc_scan_strings
from dexllm.ioc import IOC_CATEGORIES, _scan_value_strings, extract_iocs
from dexllm.providers import (
    detect_content_providers,
    load_content_uris,
    match_content_uris,
)

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

    # content:// providers (issue #13) — same byte-identical contract. Methods are
    # compared IN ORDER (not sorted): both bindings call one FindMethodsUsingStrings,
    # so order/dedup must match too. xref_limit 0 and 1 exercise the budget-exhausted
    # tail (hits past the budget must still be reported with empty methods).
    def _pnorm(rows):
        return [(r["uri"], r["family"], tuple(r["methods"])) for r in rows]

    for with_xref, xref_limit in [(True, 300), (False, 300), (True, 1), (True, 0)]:
        pyp = _pnorm(detect_content_providers(dk, with_xref=with_xref,
                                              xref_limit=xref_limit))
        cppp = _pnorm(dk.detect_content_providers_native(with_xref, xref_limit))
        assert cppp == pyp, (
            f"{Path(apk).name} cfg=({with_xref},{xref_limit}): "
            f"C++ DetectContentProviders diverges from Python"
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


# --- content:// provider substring-match differential (crafted + fuzz). ---

def test_content_uris_header_in_sync_with_dataset():
    """The committed gen/content_uris_data.h must match data/content_uris.json.

    The C++ port never re-sorts — it trusts the codegen-baked array — so a stale
    header (JSON edited without re-running scripts/gen_content_uris_data.py) would
    silently diverge from the Python path. This is the deterministic guard the
    fuzz differential only catches probabilistically.
    """
    header = (REPO / "native" / "core_ext" / "gen" / "content_uris_data.h").read_text()
    pairs = re.findall(r'\{"((?:[^"\\]|\\.)*)",\s*"((?:[^"\\]|\\.)*)"\}', header)
    header_rows = [
        (u.encode().decode("unicode_escape"), f.encode().decode("unicode_escape"))
        for u, f in pairs
    ]
    dataset = load_content_uris()
    expected = sorted((uri, meta["family"]) for uri, meta in dataset.items())
    assert header_rows == expected, (
        "content_uris_data.h is out of sync with content_uris.json — "
        "re-run scripts/gen_content_uris_data.py"
    )


def test_provider_match_seam_crafted():
    keys = list(load_content_uris())
    cases = [
        "content://sms/inbox/1", "content://smsfoo", "xcontent://sms",
        "content://call_log/calls/filter/9", "no-provider-here", "content://",
        keys[0], keys[-1], keys[5] + "/extra",
    ]
    for s in cases:
        assert [tuple(t) for t in _detect_providers_from_strings([s])] == \
            match_content_uris([s]), f"provider seam diverges on {s!r}"


def test_provider_match_seam_fuzz():
    """Random strings from content:// fragments: C++ substring match == Python."""
    keys = list(load_content_uris())
    frags = keys[:40] + [
        "content://", "content://sms/inbox/1", "content://smsfoo", "xcontent://x",
        "random", "content://contacts/people/", "", "沖content://sms",
    ]
    tails = ["", "/9", "z", "/data", "?q=1"]
    rng = random.Random(31)
    for _ in range(20000):
        batch = [
            rng.choice(frags) + rng.choice(tails)
            for _ in range(rng.randint(0, 3))
        ]
        got = [tuple(t) for t in _detect_providers_from_strings(batch)]
        assert got == match_content_uris(batch), f"provider fuzz divergence on {batch!r}"


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
