"""Static network-IOC (C2) extraction from an APK's dex value-strings.

VirusTotal shows the URLs / domains / IPs an app *contacts*; this module recovers
the same indicators **statically** from the dex — with no execution — and, unlike
VirusTotal, ties each indicator back to the class/method that references it.

Redesign (2026-06, scaffold). Pipeline:

  dk.list_value_strings()                  # only strings loaded AS DATA — const-string
                                           # + static VALUE_STRING — so identifier noise
                                           # (type/method/field names) is gone at source
    -> _refang (literal, O(n))             # un-defang hxxp:// , [.] , [at] , [dot]
    -> our bounded regexes                 # URLs / IPs / emails / onion, ReDoS-safe
    -> _HOST_CANDIDATE + tldextract/PSL    # bare domains, validated against the PSL
    -> denoise (dex packages + xmlns URIs) # residual identifier false-positives
    -> per-indicator method xref (L7)      # "where in the code", budgeted

**Why our own regexes, not iocextract:** iocextract's URL/email/refang regexes
backtrack CATASTROPHICALLY on long dotted blobs (`"a.a.a…"` 32KB → ~10s URL extract;
emails are exponential even at 1KB) — a ReDoS vector, and dex value-strings DO
contain such blobs. So we keep our hand-bounded, linear-time regexes (the prior
version's hard-won ones) and do defang ourselves with literal replaces. tldextract
is safe (a public-suffix-list lookup, not a text scan) and is the one library we
use — it replaces the old hand-rolled TLD gate.

Design lessons carried over live in the [[project-ioc-redesign-lessons]] memory:
ReDoS-bounded regexes + per-string cap, the IPv4 version-slice vs trailing-dot edge,
denoising roots, namespace URIs, userinfo-host stripping, highest-signal-first xref.

tldextract is an optional dep (``pip install "dexllm[ioc]"``), imported lazily so
the rest of the package works without it.
"""

from __future__ import annotations

import re
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    import tldextract as _tldextract_mod

__all__ = ["extract_iocs", "IOC_CATEGORIES"]

IOC_CATEGORIES = ("urls", "ips", "domains", "emails", "onion")
# Spend the cross-reference budget highest-signal indicators first.
_XREF_PRIORITY = ("onion", "ips", "domains", "emails", "urls")

# Per-string scan cap. Real network IOCs are short; an oversized blob is itself a
# signal, not a host. Bounds worst-case cost on an adversarial APK (all regexes are
# linear, but this keeps even linear work bounded over millions of bytes).
_MAX_SCAN = 65536

# Defang markers -> their refanged form. LITERAL str.replace only (O(n), ReDoS-immune
# — unlike iocextract's regex refang). Covers the common forms malware uses to store
# IOCs as inert text. Applied longest-first where it matters (e.g. `[dot]` before `.`).
_DEFANG = [
    ("[.]", "."),
    ("(.)", "."),
    ("{.}", "."),
    ("[dot]", "."),
    ("(dot)", "."),
    (" dot ", "."),
    ("[:]", ":"),
    ("[://]", "://"),
    ("[at]", "@"),
    ("(at)", "@"),
    (" at ", "@"),
    ("hxxps", "https"),
    ("hxxp", "http"),
    ("fxp", "ftp"),
    ("\\", "/"),
]


def _refang(s: str) -> str:
    """Un-defang a string with literal replaces — linear, no catastrophic regex."""
    low_markers = s
    for marker, repl in _DEFANG:
        if marker in low_markers:
            low_markers = low_markers.replace(marker, repl)
    return low_markers


# --- extraction regexes (all bounded / linear — ReDoS-safe) -----------------

# Scheme-qualified URL (http/https/ftp/ws/wss). Stops at whitespace/quotes/<>.
_URL = re.compile(r"\b(?:https?|ftp|wss?)://[^\s\"'<>\\]+", re.IGNORECASE)

# Email. Every quantifier BOUNDED so a long non-matching run can't drive
# catastrophic backtracking (these run over every string, some huge blobs).
_EMAIL = re.compile(
    r"(?<![A-Za-z0-9._%+\-])[A-Za-z0-9._%+\-]{1,64}@"
    r"[A-Za-z0-9.\-]{1,253}\.[A-Za-z]{2,24}\b"
)

# Dotted-quad IPv4 with validated octets + optional :port. The lookarounds reject a
# quad that is one slice of a longer dotted-decimal token (a version string like
# `1.0.0.0.5` / `2.30.1.7`) WITHOUT losing a valid IP merely followed by a dot
# (`8.8.8.8.`).
_IPV4 = re.compile(
    r"(?<!\d)(?<!\d\.)(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)"
    r"(?::\d{1,5})?(?!\.?\d)"
)

# Tor v2/v3 onion address (no scheme required).
_ONION = re.compile(r"\b[a-z2-7]{16}(?:[a-z2-7]{40})?\.onion\b", re.IGNORECASE)

# A bare-host CANDIDATE: labels then an alphabetic tail. Deliberately loose — the
# public-suffix validator (tldextract) is the real gate. ReDoS-safe: each label is a
# single bounded class, the label count is bounded, no nested optional group.
_HOST_CANDIDATE = re.compile(
    r"\b(?:[a-z0-9][a-z0-9-]{0,62}\.){1,32}[a-z]{2,24}\b", re.IGNORECASE
)

# --- denoising (ported — see lessons §4/§5) ---------------------------------

_RDN_ROOTS = frozenset({"com", "org", "net", "edu", "gov", "mil", "int"})
_PLATFORM_ROOTS = frozenset(
    {
        "android",
        "androidx",
        "java",
        "javax",
        "kotlin",
        "kotlinx",
        "dalvik",
        "sun",
        "junit",
    }
)
_DROP_ROOTS = _RDN_ROOTS | _PLATFORM_ROOTS

# XML-namespace / schema authority hosts — xmlns identifiers, never contacted.
_NAMESPACE_HOSTS = frozenset(
    {
        "schemas.android.com",
        "schemas.xmlsoap.org",
        "schemas.microsoft.com",
        "schemas.openxmlformats.org",
        "xmlpull.org",
        "www.xmlpull.org",
        "www.w3.org",
        "w3.org",
        "java.sun.com",
        "ns.adobe.com",
        "purl.org",
    }
)

_PKG_LABEL = re.compile(r"[a-z0-9_$]+")

# tldextract instance, lazily built with the BUNDLED public-suffix snapshot only
# (suffix_list_urls=()), so domain validation is deterministic and never touches the
# network at runtime.
_TLD: _tldextract_mod.TLDExtract | None = None


def _tld():  # type: ignore[no-untyped-def]
    global _TLD
    if _TLD is None:
        import tldextract

        _TLD = tldextract.TLDExtract(suffix_list_urls=(), cache_dir=None)
    return _TLD


def _registered_domain(host: str) -> str:
    """Return the registered domain under the public suffix, or ``""`` if none.

    `maps.google.co.uk` -> `google.co.uk`; `com.google.util` -> `""` (util is not a
    public suffix, so the dotted token is not a real domain).
    """
    return str(_tld()(host).top_domain_under_public_suffix)


def _dex_package_prefixes(descriptors: list[str]) -> frozenset[str]:
    """Dotted package prefixes from a list of type descriptors.

    `Landroid/app/Activity;` -> `{"android", "android.app"}`. Keyed off the dex's
    structured type tables, so it is self-calibrating (covers every library the app
    references) rather than a hardcoded list.
    """
    pkgs: set[str] = set()
    for s in descriptors:
        core = s.lstrip("[")
        if not (core.startswith("L") and core.endswith(";") and "/" in core):
            continue
        labels = [p.lower() for p in core[1:-1].split("/")[:-1]]
        if not labels or not all(_PKG_LABEL.fullmatch(p) for p in labels):
            continue
        for i in range(1, len(labels) + 1):
            pkgs.add(".".join(labels[:i]))
    return frozenset(pkgs)


def _is_package_like(host: str, dex_packages: frozenset[str]) -> bool:
    """Return True if ``host`` is a Java/Android package, not a network domain."""
    low = host.lower()
    if low in _NAMESPACE_HOSTS:
        return True
    if low in dex_packages:
        return True
    return low.split(".", 1)[0] in _DROP_ROOTS


def _host_of(url: str) -> str:
    """Bare host of a scheme-qualified URL — no userinfo, no port.

    `http://user:pass@evil.com:8080/c2` -> `evil.com`. Dropping `user:pass@` is
    essential, else the real C2 host is mis-extracted.
    """
    try:
        rest = url.split("://", 1)[1]
    except IndexError:
        return ""
    authority = rest.split("/", 1)[0].split("?", 1)[0].split("#", 1)[0]
    authority = authority.rsplit("@", 1)[-1]
    if authority.startswith("[") and "]" in authority:
        return authority[1 : authority.index("]")].lower()
    return authority.split(":", 1)[0].lower()


def extract_iocs(
    dk: Any,
    *,
    with_xref: bool = True,
    denoise: bool = True,
    xref_limit: int = 300,
) -> dict[str, list[dict[str, Any]]]:
    """Extract network indicators (URLs / IPs / domains / emails / onion) from ``dk``.

    Args:
        dk: A loaded ``dexllm.DexKit`` instance.
        with_xref: If True, attach the referencing method descriptors to each
            indicator (the "where in the code" view). One L7 search per indicator.
        denoise: If True, drop residual identifier hosts (dex packages, xmlns URIs)
            that survive into the candidate set.
        xref_limit: Cap on indicators cross-referenced, spent highest-signal first.

    Returns:
        A dict keyed by :data:`IOC_CATEGORIES`; each value a list of
        ``{"value": str, "methods": list[str]}`` sorted by value.
    """
    strings = dk.list_value_strings()

    dex_packages: frozenset[str] = frozenset()
    if denoise:
        descriptors = list(dk.list_classes())
        descriptors += [t.descriptor for t in dk.list_external_type_refs(False)]
        dex_packages = _dex_package_prefixes(descriptors)

    urls: set[str] = set()
    ips: set[str] = set()
    domains: set[str] = set()
    emails: set[str] = set()
    onion: set[str] = set()

    for raw in strings:
        capped = raw if len(raw) <= _MAX_SCAN else raw[:_MAX_SCAN]
        # Un-defang first (literal, linear), then run only our bounded regexes.
        s = _refang(capped)
        for m in _URL.finditer(s):
            url = m.group(0).rstrip(".,);\"'")
            if denoise and _host_of(url) in _NAMESPACE_HOSTS:
                continue
            urls.add(url)
        for m in _EMAIL.finditer(s):
            emails.add(m.group(0))
        for m in _IPV4.finditer(s):
            ips.add(m.group(0))
        for m in _ONION.finditer(s):
            onion.add(m.group(0).lower())
        # Bare domains: candidate tokens validated against the public suffix list.
        for m in _HOST_CANDIDATE.finditer(s):
            host = m.group(0).lower()
            if host.endswith(".onion"):
                continue  # its own category; .onion is in the PSL but isn't a domain
            if not _registered_domain(host):
                continue  # not a real registered domain (e.g. com.google.util)
            if denoise and _is_package_like(host, dex_packages):
                continue
            # TODO(refine): an identifier path ending in a gTLD label (e.g.
            # `libcore.icu.icu`, `android.app`) still passes the PSL when it isn't a
            # declared dex package. value-strings input already removes most; a
            # tighter heuristic (reject when every label is a lowercase identifier
            # with no digits/hyphens AND the apex is a single short word) is a
            # follow-up. Kept permissive for now (recall-first).
            domains.add(host)

    # A URL's own host is a high-confidence domain — fold it in (post-denoise),
    # skipping IP-literal hosts (those belong to the ips bucket).
    for u in urls:
        h = _host_of(u)
        if (
            "." in h
            and not _IPV4.fullmatch(h)
            and _registered_domain(h)
            and not (denoise and _is_package_like(h, dex_packages))
        ):
            domains.add(h)

    buckets = {
        "urls": urls,
        "ips": ips,
        "domains": domains,
        "emails": emails,
        "onion": onion,
    }

    xref_budget = xref_limit
    result: dict[str, list[dict[str, Any]]] = {}
    for cat in _XREF_PRIORITY:
        rows: list[dict[str, Any]] = []
        for value in sorted(buckets[cat]):
            methods: list[str] = []
            if with_xref and xref_budget > 0:
                try:
                    hits = dk.find_methods_using_strings(
                        [value], match_type="contains", ignore_case=False
                    )
                    methods = [
                        m.descriptor if hasattr(m, "descriptor") else str(m)
                        for m in hits
                    ]
                except (
                    Exception
                ):  # noqa: BLE001 — one bad query must not abort the report
                    methods = []
                xref_budget -= 1
            rows.append({"value": value, "methods": methods})
        result[cat] = rows
    return {cat: result[cat] for cat in IOC_CATEGORIES}
