"""End-to-end test for static C2 / network-IOC extraction.

Drives the package API (dexllm.list_strings + dexllm.extract_iocs) and the MCP
tool (dexllm.tools.execute "extract_iocs") over the bundled corpus, asserting:

  - the dex string pool is exposed (list_strings is non-empty)
  - real URLs / domains are recovered from a known-good APK
  - each indicator is cross-referenced to a referencing method (descriptor str)
  - denoising drops framework package names that look like hosts
  - the MCP tool returns a JSON-serialisable {indicators, counts} dict

a2dp.Vol_137.apk carries http://maps.google.com, https://github.com/... and
listen.googlelabs.com — a stable, benign fixture for the mechanism. Skips if the
bundled corpus is absent.
"""

import glob
import json
import os
from pathlib import Path

import pytest

import dexllm

REPO = Path(__file__).resolve().parents[1]
_FRAMEWORK = ("android.", "androidx.", "java.", "javax.", "kotlin.", "dalvik.")


def _apks():
    env = os.environ.get("DEXLLM_TEST_APK")
    if env and os.path.isfile(env):
        return [env]
    return sorted(glob.glob(str(REPO / "test_apk" / "APK" / "*.apk")))


def _fixture_apk():
    """Prefer a2dp.Vol (known URLs); fall back to any APK with URLs."""
    apks = _apks()
    pref = [p for p in apks if "a2dp.Vol" in p]
    return (pref + apks)[:1]


@pytest.fixture(scope="module")
def dk():
    apks = _fixture_apk()
    if not apks:
        pytest.skip("no bundled test APK")
    return dexllm.DexKit(apks[0])


def test_list_strings_exposed(dk):
    strings = dk.list_strings()
    assert isinstance(strings, list) and len(strings) > 100
    assert all(isinstance(s, str) for s in strings[:50])
    # distinct (the binding deduplicates)
    assert len(strings) == len(set(strings))


def test_extract_iocs_recovers_urls_and_domains(dk):
    iocs = dexllm.extract_iocs(dk, with_xref=True, xref_limit=100)
    assert set(iocs) == set(dexllm.IOC_CATEGORIES)

    urls = {r["value"] for r in iocs["urls"]}
    domains = {r["value"] for r in iocs["domains"]}

    # If this is the a2dp.Vol fixture, assert the exact known indicators.
    if any("github.com" in u for u in urls):
        assert any("maps.google.com" in u for u in urls)
        assert "github.com" in domains
        assert "maps.google.com" in domains


def test_xref_is_method_descriptor_strings(dk):
    iocs = dexllm.extract_iocs(dk, with_xref=True, xref_limit=100)
    for cat in dexllm.IOC_CATEGORIES:
        for row in iocs[cat]:
            assert isinstance(row["value"], str)
            assert isinstance(row["methods"], list)
            for m in row["methods"]:
                # descriptor string, not a repr/object
                assert isinstance(m, str)
                assert "->" in m or m.startswith("L")


def test_denoise_drops_framework_packages(dk):
    iocs = dexllm.extract_iocs(dk, with_xref=False)
    leaked = [
        r["value"]
        for r in iocs["domains"]
        if r["value"].lower().startswith(_FRAMEWORK)
    ]
    assert leaked == [], f"framework packages leaked into domains: {leaked}"


def test_ips_have_valid_octets(dk):
    iocs = dexllm.extract_iocs(dk, with_xref=False)
    for row in iocs["ips"]:
        host = row["value"].split(":", 1)[0]
        octets = host.split(".")
        assert len(octets) == 4
        assert all(0 <= int(o) <= 255 for o in octets)


def test_denoise_is_dex_derived_and_complete():
    """Denoising keys off the dex's own packages + structural roots, not a list.

    APK-free unit test of the internal helpers proving the accuracy gains over a
    hardcoded prefix list: per-app package derivation, generic reverse-DNS / platform
    roots (no per-library enumeration), and that genuine domains survive.
    """
    from dexllm.ioc import _dex_package_prefixes, _is_package_like

    pkgs = _dex_package_prefixes(
        ["Landroid/app/Activity;", "Lcom/evil/Bot;", "[Lkotlin/io/X;"]
    )
    assert {"android", "android.app", "com.evil", "kotlin.io"} <= pkgs

    # (1) dex-derived: a declared package that collides with a TLD-label -> dropped
    assert _is_package_like("android.app", pkgs)
    assert _is_package_like("kotlin.io", pkgs)
    # (2) generic reverse-DNS root — any com.*/org.* package, no enumeration needed
    assert _is_package_like("org.apache.commons.io", frozenset())
    assert _is_package_like("com.facebook.internal.cc", frozenset())
    # (3) platform constant namespace (android.intent.* etc.), not a real host
    assert _is_package_like("android.intent.extra.cc", frozenset())
    assert _is_package_like("android.r.id", frozenset())
    # (4) genuine domains survive — first label is neither a platform nor RDN root
    assert not _is_package_like("github.com", frozenset())
    assert not _is_package_like("maps.google.com", frozenset())
    assert not _is_package_like("app.attacker.io", frozenset())  # 'app' is a gTLD, not a root
    assert not _is_package_like("c2-panel.top", frozenset())


def test_mcp_tool_extract_iocs_serialisable(dk):
    out = dexllm.tools.execute("extract_iocs", {"xref_limit": 50}, dk)
    assert "indicators" in out and "counts" in out
    assert set(out["counts"]) == set(dexllm.IOC_CATEGORIES)
    # the whole tool response must be JSON-serialisable for MCP transport
    json.dumps(out)
