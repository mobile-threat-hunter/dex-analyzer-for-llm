"""L3 capability summarisation.

Maps L2 call sites against a bundled catalog of Android API →
permission/capability metadata.

The catalog keeps **two axes** apart so the aggregate counters stay meaningful:

* ``categories`` — ONE axis (domain / behaviour). No tag may be implied by
  another, so one call site is never counted twice under two names for the SAME
  concern (which is what made the pre-0.2 counts measure how many tags an entry
  was given rather than what the APK does). A second tag is only correct when
  the API genuinely spans two domains (``WifiManager.getScanResults`` → WIFI +
  LOCATION) — and then it does count once in each, so
  ``sum(report.categories.values()) >= report.total_call_sites``, with equality
  exactly when every matched entry carries a single tag.
* ``flags`` — the orthogonal, cross-domain concerns a domain tag cannot express.
  Today only ``IDENTIFIER`` (the API provably returns a device/user identifier),
  which rolls up across TELEPHONY / BLUETOOTH / … and is not recoverable from
  the domain axis.

``only_categories`` matches **either** axis, so a tag keeps working as a filter
whichever axis it lives on (``only_categories={"IDENTIFIER"}`` selects the
identifier-returning APIs even though ``IDENTIFIER`` is a flag). A tag outside
the catalog's declared vocabularies raises instead of returning an empty report,
so a stale rule fails loudly rather than reading as "the APK does not do this".

Catalog keys are METHOD descriptors: a field descriptor resolves nothing (the
lookup is ``find_call_sites_to``), so it would sit in the catalog matching
nothing — ``tests/test_capability_catalog.py`` rejects one.

The catalog is hand-seeded. A consumer can point this module at a richer source
(PScout / Axplorer / @RequiresPermission scrape) without code changes, provided
the replacement:

* declares its own ``category_vocabulary`` / ``flag_vocabulary`` (else the
  ``only_categories`` validation silently switches off — an unvalidated filter is
  better than rejecting every tag on a catalog predating the keys, but it does
  give back the silent-empty-report failure mode);
* gives every entry at least one category — the ``>=`` above rests on it, and an
  entry with none contributes call sites but no counts, so the sum would fall
  *below* ``total_call_sites``;
* uses METHOD descriptors as keys, and no duplicate tag inside one list (the
  emitter dedupes defensively, but a duplicate signals a merge bug upstream).

Replacing the file *in this repo* additionally means updating the vocabulary
pinned in ``tests/test_capability_catalog.py``, which is deliberate: it is what
keeps a bulk load from re-introducing an unnormalised taxonomy.
"""

from __future__ import annotations

import json
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, Dict, List, Optional, Set

if TYPE_CHECKING:
    from ._dexkit_core import DexKit

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
    # `flags` is appended rather than placed next to `categories` on purpose: the
    # pre-0.2 positional arity was 5 (`callers` has a default), so inserting a
    # 5th required field mid-signature would make a legacy 5-positional call bind
    # silently wrong (flags=<int>, call_site_count=<set>) instead of raising.
    flags: List[str] = field(default_factory=list)


@dataclass
class CapabilityReport:
    """Aggregated capability profile of an APK across all matched catalog APIs."""

    permissions: Counter  # permission -> count of invocations
    categories: Counter  # category -> count of invocations
    flags: Counter  # cross-domain concern -> count of invocations
    by_caller: Dict[str, Set[str]]  # caller descriptor -> {permissions}
    api_hits: List[ApiHit]  # one entry per matched API
    total_call_sites: int
    catalog_version: str
    catalog_size: int
    matched_apis: int

    def top_permissions(self, n: int = 10) -> List[tuple]:
        """Return the n most-invoked permissions as (permission, count) pairs."""
        return self.permissions.most_common(n)

    def top_categories(self, n: int = 10) -> List[tuple]:
        """Return the n most-invoked categories as (category, count) pairs."""
        return self.categories.most_common(n)


def _catalog_vocabulary(catalog: dict) -> Set[str]:
    """Return the union of the catalog's two declared tag vocabularies.

    A catalog that declares neither returns an empty set, which disables the
    ``only_categories`` validation below — an older or hand-rolled replacement
    keeps working instead of rejecting every filter.
    """
    return set(catalog.get("category_vocabulary", ())) | set(
        catalog.get("flag_vocabulary", ())
    )


def summarize_capabilities(
    dk: DexKit, *, only_categories: Optional[Set[str]] = None
) -> CapabilityReport:
    """Walk the catalog, look up each API's call sites via dk, aggregate.

    Args:
        dk: a dexllm.DexKit instance (caches will be warmed lazily)
        only_categories: if set, restrict aggregation to APIs carrying any of
            these tags on **either** axis (e.g. ``{"LOCATION", "TELEPHONY"}``, or
            ``{"IDENTIFIER"}`` — a flag). Matching both axes is what keeps a tag
            usable as a filter regardless of which axis it lives on.

    Raises:
        ValueError: if ``only_categories`` holds a tag the catalog does not
            declare. Silently returning an empty report would be indistinguishable
            from "the APK exercises none of this", so a stale tag (one the 0.2
            taxonomy normalisation removed, or a typo) fails loudly instead.
    """
    catalog = _load_catalog()
    entries = catalog["entries"]

    want = set(only_categories) if only_categories else None
    if want:
        vocabulary = _catalog_vocabulary(catalog)
        unknown = want - vocabulary if vocabulary else set()
        if unknown:
            raise ValueError(
                f"unknown capability tag(s) {sorted(unknown)} — the catalog "
                f"(version {catalog.get('version', 'unknown')}) declares "
                f"{sorted(vocabulary)}"
            )

    permissions: Counter = Counter()
    categories: Counter = Counter()
    flags: Counter = Counter()
    by_caller: Dict[str, Set[str]] = {}
    api_hits: List[ApiHit] = []
    total_sites = 0

    for api_sig, meta in entries.items():
        # dict.fromkeys dedupes while preserving order: a tag repeated inside one
        # entry's list is malformed input, not a fact to count twice, and counting
        # it twice would reproduce the very inflation the two-axis split removed.
        cats = list(dict.fromkeys(meta.get("categories", [])))
        entry_flags = list(dict.fromkeys(meta.get("flags", [])))
        # Match on EITHER axis, so a tag stays filterable whichever axis it is on.
        if want and not (want & (set(cats) | set(entry_flags))):
            continue
        sites = dk.find_call_sites_to(api_sig)
        if not sites:
            continue

        perms = meta.get("permissions", [])
        hit = ApiHit(
            api_signature=api_sig,
            permissions=list(perms),
            categories=list(cats),
            flags=list(entry_flags),
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
            for flag in entry_flags:
                flags[flag] += 1
        api_hits.append(hit)

    return CapabilityReport(
        permissions=permissions,
        categories=categories,
        flags=flags,
        by_caller=by_caller,
        api_hits=api_hits,
        total_call_sites=total_sites,
        catalog_version=catalog.get("version", "unknown"),
        catalog_size=len(entries),
        matched_apis=len(api_hits),
    )
