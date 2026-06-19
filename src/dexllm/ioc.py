"""Static network-indicator (C2 / IOC) extraction from an APK's dex strings.

VirusTotal shows the URLs, domains, and IPs an app *contacts*; this module
recovers the same indicators **statically** — from the dex string pool, with no
execution — and, unlike VirusTotal, ties each indicator back to the class/method
that references it.

The pipeline is: ``dk.list_strings()`` (every distinct string literal across all
loaded dexes) -> regex classification into URLs / IPs / domains / emails / onion
addresses -> denoising (framework package names that *look* like hosts are
dropped) -> optional cross-reference of each indicator to its referencing methods
via the L7 search engine.
"""

from __future__ import annotations

import re
from typing import Any

__all__ = ["extract_iocs", "IOC_CATEGORIES"]

IOC_CATEGORIES = ("urls", "ips", "domains", "emails", "onion")

# --- classification regexes -------------------------------------------------

# A scheme-qualified URL (http/https/ftp/ws/wss). Stop at whitespace/quotes/<>.
_URL = re.compile(r"\b(?:https?|ftp|wss?)://[^\s\"'<>\\]+", re.IGNORECASE)

# Dotted-quad IPv4 with validated octets, optional :port.
_IPV4 = re.compile(
    r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)"
    r"(?::\d{1,5})?\b"
)

# Tor v2/v3 onion address.
_ONION = re.compile(r"\b[a-z2-7]{16}(?:[a-z2-7]{40})?\.onion\b", re.IGNORECASE)

_EMAIL = re.compile(r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b")

# A hostname: one or more labels then a public-ish TLD. Deliberately TLD-gated so
# arbitrary dotted tokens (e.g. version numbers) do not match.
_TLDS = (
    "com|net|org|io|cn|ru|info|top|xyz|app|me|co|tk|cc|biz|site|online|club|"
    "vip|pw|su|ws|cm|tv|gg|sh|dev|live|store|shop|fun|click|link|host|space|"
    "pro|mobi|asia|uk|de|fr|jp|kr|in|br|us|nl|eu|ir|kz|ua|by|ng|id|vn|th|ph"
)
_HOST = re.compile(
    r"\b(?:[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?\.)+(?:" + _TLDS + r")\b",
    re.IGNORECASE,
)

# --- denoising --------------------------------------------------------------

# A hostname whose LEFTMOST label is one of these is a Java package / framework
# constant namespace, not a network host. Two groups:
#  - classic reverse-DNS roots (com/org/net/...) — no registrable host starts with
#    a bare `com.`/`org.`, so this generically covers `com.facebook.*`,
#    `org.apache.*` etc. WITHOUT enumerating every library.
#  - platform/runtime roots (android/java/kotlin/...) — trademark namespaces the
#    framework uses for constants (`android.intent.*`, `android.permission.*`) and
#    packages. Deliberately excludes gTLDs that are also common subdomains (`io`,
#    `app`, `dev`, `info`) so real hosts like `app.foo.com` survive.
# Scheme-ful C2 is never lost to this: URLs are extracted (and surfaced) without
# denoising — only the bare-domain bucket is filtered.
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

# Explicit benign infrastructure: a real host, but pure noise for triage.
_DROP_HOSTS = frozenset({"schemas.android.com", "www.w3.org", "xmlpull.org"})

# A package label inside a type descriptor `Lpkg/sub/Class;`.
_PKG_LABEL = re.compile(r"[a-z0-9_$]+")


def _dex_package_prefixes(descriptors: list[str]) -> frozenset[str]:
    """Dotted package prefixes from a list of type descriptors.

    From ``Landroid/app/Activity;`` derive ``{"android", "android.app"}``. The caller
    supplies the dex's *structured* type tables (internal class defs +
    external type refs), so denoising keys off real type-ids — not a regex over raw
    strings and not a hardcoded library list. Complete (every framework/SDK the app
    references is covered) and self-calibrating: a host equal to a declared library
    package is dropped even for libraries no static list would enumerate.
    """
    pkgs: set[str] = set()
    for s in descriptors:
        core = s.lstrip("[")  # arrays: [Landroid/...; -> Landroid/...;
        if not (core.startswith("L") and core.endswith(";") and "/" in core):
            continue
        labels = [p.lower() for p in core[1:-1].split("/")[:-1]]  # drop class name
        if not labels or not all(_PKG_LABEL.fullmatch(p) for p in labels):
            continue
        for i in range(1, len(labels) + 1):
            pkgs.add(".".join(labels[:i]))
    return frozenset(pkgs)


def _is_package_like(host: str, dex_packages: frozenset[str]) -> bool:
    """Return True if ``host`` is a Java/Android package, not a network domain."""
    low = host.lower()
    if low in _DROP_HOSTS:
        return True
    if low in dex_packages:  # the dex declares it as a package (authoritative)
        return True
    return low.split(".", 1)[0] in _DROP_ROOTS  # reverse-DNS / platform root


def _host_of(url: str) -> str:
    """Extract the host[:port] authority from a scheme-qualified URL."""
    rest = url.split("://", 1)[1]
    return rest.split("/", 1)[0].split("?", 1)[0]


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
            indicator (the "where in the code" view VirusTotal lacks). Costs one
            L7 search per distinct indicator.
        denoise: If True, drop framework package names that the host regex would
            otherwise mistake for domains.
        xref_limit: Cap on the number of indicators cross-referenced, to bound
            cost on string-heavy apps. Extras still appear, with empty ``methods``.

    Returns:
        A dict keyed by :data:`IOC_CATEGORIES`; each value is a list of
        ``{"value": str, "methods": list[str]}`` sorted by value.
    """
    strings = dk.list_strings()

    # Self-calibrating denoise set, from the dex's STRUCTURED type tables (not a
    # regex over raw strings): internal class defs + external type refs -> package
    # prefixes. A host candidate that equals one is package usage, not a domain.
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

    for s in strings:
        for m in _URL.finditer(s):
            urls.add(m.group(0).rstrip(".,);"))
        for m in _ONION.finditer(s):
            onion.add(m.group(0).lower())
        for m in _IPV4.finditer(s):
            ips.add(m.group(0))
        for m in _EMAIL.finditer(s):
            emails.add(m.group(0))
        for m in _HOST.finditer(s):
            host = m.group(0).lower()
            if not (denoise and _is_package_like(host, dex_packages)):
                domains.add(host)

    # A URL's own host is a high-confidence domain — fold it in (post-denoise).
    for u in urls:
        h = _host_of(u).split(":", 1)[0].lower()
        if "." in h and not (denoise and _is_package_like(h, dex_packages)):
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
    for cat in IOC_CATEGORIES:
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
                ):  # noqa: BLE001 - one bad query must not abort the report
                    methods = []
                xref_budget -= 1
            rows.append({"value": value, "methods": methods})
        result[cat] = rows
    return result
