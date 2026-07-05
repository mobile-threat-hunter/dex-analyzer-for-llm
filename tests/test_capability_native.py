"""Differential gate: C++ SummarizeCapabilities (dk.summarize_capabilities_native)
must equal the Python dexllm.capability.summarize_capabilities over the bundled
corpus, and the codegen'd catalog header must stay in sync with the JSON dataset.

Issue #13 Phase 2 — the C++ engine port backs the WASM binding; single source of
truth requires the two paths agree.
"""

from __future__ import annotations

import glob
import importlib.util
import tempfile
from pathlib import Path

import pytest

import dexllm
from dexllm.capability import summarize_capabilities

REPO = Path(__file__).resolve().parents[1]
_APKS = sorted(glob.glob(str(REPO / "test_apk" / "APK" / "*.apk")))


def _reshape(rep):
    """The Python CapabilityReport in the dict shape the native binding returns."""
    return {
        "permissions": dict(rep.permissions),
        "categories": dict(rep.categories),
        "by_caller": {c: sorted(p) for c, p in rep.by_caller.items()},
        "api_hits": [
            {
                "api_signature": h.api_signature,
                "permissions": list(h.permissions),
                "categories": list(h.categories),
                "call_site_count": h.call_site_count,
                "callers": sorted(h.callers),
            }
            for h in rep.api_hits
        ],
        "total_call_sites": rep.total_call_sites,
        "catalog_version": rep.catalog_version,
        "catalog_size": rep.catalog_size,
        "matched_apis": rep.matched_apis,
    }


@pytest.mark.skipif(not _APKS, reason="no bundled test APK")
@pytest.mark.parametrize("apk", _APKS, ids=lambda p: Path(p).name)
def test_summarize_capabilities_native_matches_python(apk):
    try:
        dk = dexllm.DexKit(apk)
    except Exception as e:  # noqa: BLE001 — unloadable container isn't this test's concern
        pytest.skip(f"APK did not load: {e}")
    assert dk.summarize_capabilities_native() == _reshape(summarize_capabilities(dk))


def test_catalog_header_in_sync_with_dataset():
    """The committed gen/android_api_data.h must byte-equal a fresh codegen run.

    The C++ port reads signatures AND permissions/categories/version straight from
    the codegen'd header, so a stale header (JSON edited without re-running the
    codegen) silently diverges from the Python path on every one of those axes. A
    full regenerate-and-byte-compare (not a signature-only check) is the guard.
    """
    spec = importlib.util.spec_from_file_location(
        "_gen_android_api_data", REPO / "scripts" / "gen_android_api_data.py"
    )
    gen = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(gen)
    committed = (REPO / "native" / "core_ext" / "gen" / "android_api_data.h").read_text()
    with tempfile.TemporaryDirectory() as d:
        gen.OUT = Path(d) / "android_api_data.h"
        gen.main()
        regenerated = gen.OUT.read_text()
    assert regenerated == committed, (
        "android_api_data.h out of sync with android_api_map.json — "
        "re-run scripts/gen_android_api_data.py"
    )
