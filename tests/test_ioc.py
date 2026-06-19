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


def test_namespace_uris_are_not_iocs():
    """XML namespace URIs (xmlns) are identifiers, not contacted endpoints.

    `http://schemas.android.com/apk/res/android` and the bare host must be dropped
    from BOTH urls and domains, even though urls are otherwise never denoised.
    """
    from dexllm.ioc import _host_of, _is_package_like, _NAMESPACE_HOSTS

    # unit: namespace hosts are dropped from the domains bucket
    assert _is_package_like("schemas.android.com", frozenset())
    assert _is_package_like("www.w3.org", frozenset())

    # integration: on a bundled APK that actually carries the namespace URI, it
    # appears with denoise=False but is gone (urls + domains) with denoise=True.
    apks = _apks()
    for apk in apks:
        try:
            d = dexllm.DexKit(apk)
        except Exception:
            continue
        if not any("schemas.android.com" in s for s in d.list_strings()):
            continue
        raw = dexllm.extract_iocs(d, with_xref=False, denoise=False)
        clean = dexllm.extract_iocs(d, with_xref=False, denoise=True)
        raw_ns = [
            r["value"]
            for cat in ("urls", "domains")
            for r in raw[cat]
            if "schemas.android.com" in r["value"]
        ]
        assert raw_ns, "fixture APK should expose the namespace URI when raw"
        for cat in ("urls", "domains"):
            for r in clean[cat]:
                host = _host_of(r["value"]) if "://" in r["value"] else r["value"]
                assert host.split(":", 1)[0].lower() not in _NAMESPACE_HOSTS
        return  # one fixture is enough
    pytest.skip("no bundled APK carries an XML namespace URI in dex strings")


class _FakeDK:
    """Minimal dk stand-in for extract_iocs unit tests (no APK needed)."""

    def __init__(self, strings):
        self._s = strings

    def list_strings(self):
        return self._s

    def list_classes(self):
        return []

    def list_external_type_refs(self, framework_only):
        return []

    def find_methods_using_strings(self, vals, **kw):
        return []


def test_regexes_are_redos_safe():
    """Adversarial strings must not drive the classifier regexes catastrophic."""
    import time

    from dexllm.ioc import _EMAIL, _HOST, _IPV4, _ONION, _URL

    attacks = ["a." * 5000 + "x", "a@" + "a." * 40000 + "!", "1." * 50000]
    for s in attacks:
        for rx in (_URL, _IPV4, _HOST, _EMAIL, _ONION):
            t0 = time.time()
            list(rx.finditer(s))
            dt = time.time() - t0
            assert dt < 2.0, f"ReDoS: {rx.pattern[:40]!r} took {dt:.1f}s on len {len(s)}"


def test_host_of_strips_userinfo_and_port():
    from dexllm.ioc import _host_of

    assert _host_of("http://user:pass@evil.com:8080/c2") == "evil.com"
    assert _host_of("https://evil.com/x") == "evil.com"
    assert _host_of("ftp://u@1.2.3.4:21/p") == "1.2.3.4"
    assert _host_of("http://[2001:db8::1]:443/x") == "2001:db8::1"


def test_ipv4_rejects_dotted_version_strings():
    from dexllm.ioc import _IPV4

    assert not _IPV4.search("v1.0.0.0.5 build")  # 5-component
    assert not _IPV4.search("ver 1.2.3.4.5")
    assert not _IPV4.search("10.0.0.1.2")
    assert _IPV4.search("dns 8.8.8.8 here")  # real IP survives
    assert _IPV4.search("c2 1.2.3.4:8080 port")  # ip:port survives


def test_ip_url_host_not_double_categorized():
    iocs = dexllm.extract_iocs(_FakeDK(["http://1.2.3.4:8080/gate.php"]), with_xref=False)
    ips = {r["value"] for r in iocs["ips"]}
    doms = {r["value"] for r in iocs["domains"]}
    assert any(v.startswith("1.2.3.4") for v in ips)  # ip (with :port) captured
    assert not any("1.2.3.4" in d for d in doms)  # an IP host is NOT a domain


def test_userinfo_url_yields_real_host_in_domains():
    iocs = dexllm.extract_iocs(_FakeDK(["http://admin:pw@evil.com/c2"]), with_xref=False)
    doms = {r["value"] for r in iocs["domains"]}
    assert "evil.com" in doms
    assert not any("@" in d for d in doms)  # no userinfo garbage


def test_extract_iocs_bounded_on_oversized_strings():
    import time

    dk = _FakeDK(["a@" + "a." * 200000 + "!", "x" * 1000000, "1." * 200000])
    t0 = time.time()
    dexllm.extract_iocs(dk, with_xref=False)
    assert time.time() - t0 < 3.0


def test_mcp_tool_extract_iocs_serialisable(dk):
    out = dexllm.tools.execute("extract_iocs", {"xref_limit": 50}, dk)
    assert "indicators" in out and "counts" in out
    assert set(out["counts"]) == set(dexllm.IOC_CATEGORIES)
    # the whole tool response must be JSON-serialisable for MCP transport
    json.dumps(out)
