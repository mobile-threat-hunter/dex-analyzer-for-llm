"""L3 capability summarisation — maps L2 call sites against a bundled
catalog of Android API → permission/category metadata.

The catalog is hand-seeded; replace data/android_api_map.json with a richer
source (PScout / Axplorer / @RequiresPermission scrape) without code changes.
"""

from __future__ import annotations

import json
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Set

_CATALOG_PATH = Path(__file__).parent / "data" / "android_api_map.json"
_CATALOG_CACHE: dict | None = None


def _load_catalog() -> dict:
    global _CATALOG_CACHE
    if _CATALOG_CACHE is None:
        _CATALOG_CACHE = json.loads(_CATALOG_PATH.read_text())
    return _CATALOG_CACHE


@dataclass
class ApiHit:
    """A single API in the catalog that was found in the APK."""
    api_signature: str
    permissions: List[str]
    categories: List[str]
    call_site_count: int
    callers: Set[str] = field(default_factory=set)


@dataclass
class CapabilityReport:
    permissions: Counter        # permission -> count of invocations
    categories: Counter         # category -> count of invocations
    by_caller: Dict[str, Set[str]]  # caller descriptor -> {permissions}
    api_hits: List[ApiHit]      # one entry per matched API
    total_call_sites: int
    catalog_version: str
    catalog_size: int
    matched_apis: int

    def top_permissions(self, n: int = 10) -> List[tuple]:
        return self.permissions.most_common(n)

    def top_categories(self, n: int = 10) -> List[tuple]:
        return self.categories.most_common(n)


def summarize_capabilities(dk, *, only_categories=None) -> CapabilityReport:
    """Walk the catalog, look up each API's call sites via dk, aggregate.

    Args:
        dk: a dexllm.DexKit instance (caches will be warmed lazily)
        only_categories: if set, restrict aggregation to APIs that include any
            of these categories (e.g. {"LOCATION", "TELEPHONY"})
    """
    catalog = _load_catalog()
    entries = catalog["entries"]

    permissions: Counter = Counter()
    categories: Counter = Counter()
    by_caller: Dict[str, Set[str]] = {}
    api_hits: List[ApiHit] = []
    total_sites = 0

    for api_sig, meta in entries.items():
        cats = meta.get("categories", [])
        if only_categories and not (set(cats) & set(only_categories)):
            continue
        sites = dk.find_call_sites_to_api(api_sig)
        if not sites:
            continue

        perms = meta.get("permissions", [])
        hit = ApiHit(
            api_signature=api_sig,
            permissions=list(perms),
            categories=list(cats),
            call_site_count=len(sites),
        )

        for s in sites:
            total_sites += 1
            hit.callers.add(s.caller_descriptor)
            for perm in perms:
                permissions[perm] += 1
                by_caller.setdefault(s.caller_descriptor, set()).add(perm)
            for cat in cats:
                categories[cat] += 1
        api_hits.append(hit)

    return CapabilityReport(
        permissions=permissions,
        categories=categories,
        by_caller=by_caller,
        api_hits=api_hits,
        total_call_sites=total_sites,
        catalog_version=catalog.get("version", "unknown"),
        catalog_size=len(entries),
        matched_apis=len(api_hits),
    )
