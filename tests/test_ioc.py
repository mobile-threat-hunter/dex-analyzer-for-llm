"""Tests for static C2 / network-IOC extraction (library-based redesign).

Input is dk.list_value_strings() (value-only feed); extraction uses iocextract
(defang-aware) + tldextract/PSL domain validation. These assert the output
contract, the carried-over edge-case lessons (IPv4 version-slice vs trailing-dot,
userinfo-host stripping, namespace-URI denoise, ReDoS-bounded), and the new defang
capability — without needing a real APK (via _FakeDK) where possible.

a2dp.Vol_137.apk carries http://maps.google.com, https://github.com/... and
listen.googlelabs.com — a stable, benign fixture. Skips if the corpus is absent.
"""

import glob
import json
import os
import time
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
    apks = _apks()
    pref = [p for p in apks if "a2dp.Vol" in p]
    return (pref + apks)[:1]


@pytest.fixture(scope="module")
def dk():
    apks = _fixture_apk()
    if not apks:
        pytest.skip("no bundled test APK")
    return dexllm.DexKit(apks[0])


class _FakeDK:
    """Minimal dk stand-in for APK-free extract_iocs unit tests."""

    def __init__(self, strings):
        self._s = strings

    def list_value_strings(self):
        return self._s

    def list_classes(self):
        return []

    def list_external_type_refs(self, framework_only):
        return []

    def find_methods_using_strings(self, vals, **kw):
        return []


# --- output contract + real-APK recovery ------------------------------------


def test_value_strings_feed_exposed(dk):
    strings = dk.list_value_strings()
    assert isinstance(strings, list) and len(strings) > 50
    assert len(strings) == len(set(strings))  # deduplicated


def test_extract_iocs_shape_and_recovery(dk):
    iocs = dexllm.extract_iocs(dk, with_xref=False)
    assert set(iocs) == set(dexllm.IOC_CATEGORIES)
    for cat in dexllm.IOC_CATEGORIES:
        for row in iocs[cat]:
            assert set(row) == {"value", "methods"}
            assert isinstance(row["value"], str) and isinstance(row["methods"], list)
        # value-sorted
        assert [r["value"] for r in iocs[cat]] == sorted(r["value"] for r in iocs[cat])
    if any("a2dp.Vol" in p for p in _fixture_apk()):
        urls = {r["value"] for r in iocs["urls"]}
        domains = {r["value"] for r in iocs["domains"]}
        assert any("maps.google.com" in u for u in urls)
        assert "github.com" in domains


def test_xref_ties_indicator_to_method(dk):
    iocs = dexllm.extract_iocs(dk, with_xref=True, xref_limit=100)
    for cat in dexllm.IOC_CATEGORIES:
        for row in iocs[cat]:
            for m in row["methods"]:
                assert isinstance(m, str) and ("->" in m or m.startswith("L"))


# --- the new capability: defang ---------------------------------------------


def test_defanged_indicators_are_refanged():
    dk = _FakeDK(
        [
            "hxxps://evil[.]top/gate.php",
            "1[.]2[.]3[.]4",
            "admin@phish.kr",
        ]
    )
    iocs = dexllm.extract_iocs(dk, with_xref=False)
    assert "https://evil.top/gate.php" in {r["value"] for r in iocs["urls"]}
    assert any(r["value"].startswith("1.2.3.4") for r in iocs["ips"])
    assert "admin@phish.kr" in {r["value"] for r in iocs["emails"]}


# --- carried-over edge lessons ----------------------------------------------


def test_ipv4_rejects_version_string_slices():
    from dexllm.ioc import _IPV4

    # a 4-octet slice of a longer dotted-decimal version is NOT an IP
    assert not _IPV4.search("ver 1.0.0.0.5 build")
    assert not _IPV4.search("10.0.0.1.2")
    # a real IP merely followed by a dot still matches (reverse-DNS / sentence end)
    assert _IPV4.search("8.8.8.8.in-addr.arpa").group(0) == "8.8.8.8"
    assert _IPV4.search("dns 8.8.8.8 here").group(0) == "8.8.8.8"
    assert _IPV4.search("c2 1.2.3.4:8080 x").group(0) == "1.2.3.4:8080"


def test_version_string_is_not_an_ip_end_to_end():
    iocs = dexllm.extract_iocs(_FakeDK(["lib version 1.0.0.0.5 release"]), with_xref=False)
    assert iocs["ips"] == []


def test_host_of_strips_userinfo_and_port():
    from dexllm.ioc import _host_of

    assert _host_of("http://user:pass@evil.com:8080/c2") == "evil.com"
    assert _host_of("https://evil.com/x") == "evil.com"
    assert _host_of("http://[2001:db8::1]:443/x") == "2001:db8::1"


def test_userinfo_url_yields_real_host_in_domains():
    iocs = dexllm.extract_iocs(_FakeDK(["http://admin:pw@evil.com/c2"]), with_xref=False)
    doms = {r["value"] for r in iocs["domains"]}
    assert "evil.com" in doms
    assert not any("@" in d for d in doms)


def test_identifier_path_is_not_a_domain():
    # a Java identifier path whose last label isn't a public suffix -> not a domain
    iocs = dexllm.extract_iocs(_FakeDK(["com.google.util.Foo", "java.lang.String"]), with_xref=False)
    assert iocs["domains"] == []


def test_onion_not_double_listed_as_domain():
    iocs = dexllm.extract_iocs(_FakeDK(["abcdefabcdefabcd.onion"]), with_xref=False)
    assert any(".onion" in r["value"] for r in iocs["onion"])
    assert not any(".onion" in r["value"] for r in iocs["domains"])


def test_ip_url_host_not_double_categorized():
    iocs = dexllm.extract_iocs(_FakeDK(["http://1.2.3.4:8080/gate.php"]), with_xref=False)
    assert any(v["value"].startswith("1.2.3.4") for v in iocs["ips"])
    assert not any("1.2.3.4" in d["value"] for d in iocs["domains"])  # IP host != domain


# --- denoising ---------------------------------------------------------------


def test_denoise_drops_framework_packages(dk):
    iocs = dexllm.extract_iocs(dk, with_xref=False)
    leaked = [r["value"] for r in iocs["domains"] if r["value"].lower().startswith(_FRAMEWORK)]
    assert leaked == [], f"framework packages leaked into domains: {leaked}"


def test_dex_package_denoise_helpers():
    from dexllm.ioc import _dex_package_prefixes, _is_package_like

    pkgs = _dex_package_prefixes(["Landroid/app/Activity;", "Lcom/evil/Bot;", "[Lkotlin/io/X;"])
    assert {"android", "android.app", "com.evil", "kotlin.io"} <= pkgs
    assert _is_package_like("android.app", pkgs)  # declared package
    assert _is_package_like("com.facebook.x", frozenset())  # reverse-DNS root
    assert _is_package_like("schemas.android.com", frozenset())  # xmlns host
    assert not _is_package_like("github.com", frozenset())
    assert not _is_package_like("c2-panel.top", frozenset())


def test_namespace_uri_dropped_from_urls_and_domains():
    dk = _FakeDK(["http://schemas.android.com/apk/res/android"])
    clean = dexllm.extract_iocs(dk, with_xref=False, denoise=True)
    for cat in ("urls", "domains"):
        assert not any("schemas.android.com" in r["value"] for r in clean[cat])


# --- robustness --------------------------------------------------------------


def test_extract_iocs_bounded_on_oversized_strings():
    # adversarial: huge blobs must not blow up wall-clock (per-string cap + bounded
    # regexes). Includes a defanged-IP-flavoured blob.
    dk = _FakeDK(["a." * 200000 + "x", "1." * 200000, "x" * 1_000_000, "hxxp://" + "a" * 500000])
    t0 = time.time()
    dexllm.extract_iocs(dk, with_xref=False)
    assert time.time() - t0 < 5.0


def test_mcp_tool_extract_iocs_serialisable(dk):
    out = dexllm.tools.execute("extract_iocs", {"xref_limit": 50}, dk)
    assert "indicators" in out and "counts" in out
    assert set(out["counts"]) == set(dexllm.IOC_CATEGORIES)
    json.dumps(out)  # MCP transport requires JSON-serialisable
