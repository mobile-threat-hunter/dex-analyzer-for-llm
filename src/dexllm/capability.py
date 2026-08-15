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
  ``sum(report.categories.values()) >= report.total_call_sites +
  report.total_field_accesses``, with equality exactly when every matched entry
  carries a single tag. BOTH totals: the Counters count touches of either kind,
  while the two totals keep the key forms apart (dexllm#36).
* ``flags`` — the orthogonal, cross-domain concerns a domain tag cannot express.
  Today only ``IDENTIFIER`` (the API provably returns a device/user identifier),
  which rolls up across TELEPHONY / BLUETOOTH / … and is not recoverable from
  the domain axis.

``only_categories`` matches **either** axis, so a tag keeps working as a filter
whichever axis it lives on (``only_categories={"IDENTIFIER"}`` selects the
identifier-returning APIs even though ``IDENTIFIER`` is a flag). A tag outside
the catalog's declared vocabularies raises instead of returning an empty report,
so a stale rule fails loudly rather than reading as "the APK does not do this".

A catalog key is a METHOD descriptor (``Lcls;->name(proto)ret``) or, since
dexllm#36, a FIELD descriptor (``Lcls;->NAME:Ltype;``). The two are
unambiguous by shape — a type descriptor cannot contain ``(`` — so the key form
alone selects the lookup and no schema key is needed to say which it is:

* a method key resolves through ``find_call_sites_to`` and counts INVOKE
  INSTRUCTIONS, one per call site, into ``call_site_count``;
* a field key resolves through ``find_methods_reading_field`` and counts
  READING METHODS into the separate ``field_access_count``.

**The two counters are separate on purpose** and are not summed for you: a call
site is an instruction and a field access is a method, so adding them would
produce a number that means neither. ``call_site_count`` keeps exactly the
meaning it has always had — a field entry leaves it 0 — because widening it
would change a released field's value silently, with no type or name change to
warn a consumer. ``total_call_sites`` / ``total_field_accesses`` mirror the split.

**Reads only, and that is a bound on the claim.** The lookup is
``find_methods_reading_field``, and a framework ``static final Uri`` can only be
read — so there is nothing for ``find_methods_writing_field`` to find. But that
answers the wrong sense of "write": ``resolver.insert(Events.CONTENT_URI, …)``
and ``resolver.query(Events.CONTENT_URI, …)`` emit the SAME ``sget-object``, so a
field entry cannot tell a reader from a writer of the PROVIDER and a pure writer
is reported under ``READ_CALENDAR`` when it needs ``WRITE_CALENDAR``. The entry
says "this app touches the calendar provider"; the permission is the read-side
one because that is the common case, not because it was proven. Distinguishing
them needs the resolver call site, which is `resolve_call_args`' territory.

The catalog is hand-seeded. A consumer can point this module at a richer source
(PScout / Axplorer / @RequiresPermission scrape) without code changes, provided
the replacement:

* declares its own ``category_vocabulary`` / ``flag_vocabulary`` (else the
  ``only_categories`` validation silently switches off — an unvalidated filter is
  better than rejecting every tag on a catalog predating the keys, but it does
  give back the silent-empty-report failure mode);
* gives every entry at least one category — the ``>=`` above rests on it, and an
  entry with none contributes touches but no counts, so the sum would fall
  *below* ``total_call_sites + total_field_accesses``;
* uses METHOD or FIELD descriptors as keys (see the dispatch above — a third
  shape routes to a lookup that answers nothing, silently), and no duplicate tag
  inside one list (the emitter dedupes defensively, but a duplicate signals a
  merge bug upstream).

Replacing the file *in this repo* additionally means updating the vocabulary
pinned in ``tests/test_capability_catalog.py``, which is deliberate: it is what
keeps a bulk load from re-introducing an unnormalised taxonomy.
"""

from __future__ import annotations

import os
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, Dict, List, Optional, Set, Union

from .datadir import load_data_json

if TYPE_CHECKING:
    from ._dexkit_core import DexKit

_CATALOG_FILE = "android_api_map.json"


def _validate_catalog(obj: object, path: Path) -> None:
    """Reject a malformed override loudly, naming the file (issue #33).

    Only the shape :func:`summarize_capabilities` relies on is checked — an
    ``entries`` mapping of API signature to metadata, whose three tag lists must be
    lists of strings. A user-supplied catalog is untrusted input on the analysis
    path, and the alternative is a bare ``KeyError`` / ``TypeError`` raised from
    inside a cached loader.

    The tag-list check is not pedantry — it is the difference between a named error
    and a SILENTLY WRONG report. The aggregator iterates each list, so a bare
    string (the commonest hand-edit slip, ``"categories": "REFLECTION"``) is
    perfectly iterable and counts each CHARACTER as a category; a non-iterable
    raises ``TypeError`` deep inside the walk, which ``tools.execute`` then reports
    to an LLM as "bad arguments" — sending it to retry its own call forever while
    the real cause, this file, is never mentioned.
    """
    if not isinstance(obj, dict):
        raise ValueError(f"{path} must be a JSON object")
    entries = obj.get("entries")
    if not isinstance(entries, dict):
        raise ValueError(f"{path} must carry an 'entries' object mapping API -> meta")
    for sig, meta in entries.items():
        if not isinstance(meta, dict):
            raise ValueError(f"{path}: entry {sig!r} must be an object")
        for key in ("permissions", "categories", "flags"):
            value = meta.get(key)
            if value is None:
                continue
            if isinstance(value, str) or not isinstance(value, list):
                raise ValueError(
                    f"{path}: entry {sig!r} has a non-list {key!r} "
                    f"({type(value).__name__}) — it must be a list of strings"
                )
            if not all(isinstance(tag, str) for tag in value):
                raise ValueError(
                    f"{path}: entry {sig!r} has a non-string item in {key!r}"
                )


def _load_catalog(data_dir: Union[str, os.PathLike, None] = None) -> dict:
    """Return the capability catalog, honouring the ``data_dir`` override channel."""
    return load_data_json(_CATALOG_FILE, data_dir=data_dir, validate=_validate_catalog)


def _is_field_key(key: str) -> bool:
    """Report whether the key is a FIELD descriptor rather than a method one.

    ``Lcls;->NAME:Ltype;`` vs ``Lcls;->name(proto)ret``. The member part of a
    field descriptor cannot contain ``(``: a type descriptor is
    ``L…;`` / ``[…`` / one primitive letter, none of which admits a parenthesis,
    while a method's proto always opens with one. So the two forms are
    distinguishable without a schema key saying which — which is why the catalog
    grew none.

    Deliberately NOT `require_member_descriptor`-strict: this only has to route,
    and a malformed key routes to a lookup that returns nothing, which is what an
    unmatched entry does anyway. The catalog's own guard is the test that every
    key is one of the two real forms.
    """
    _, _, member = key.partition(";->")
    return "(" not in member


@dataclass
class ApiHit:
    """A single API in the catalog that was found in the APK."""

    api_signature: str
    permissions: List[str]
    categories: List[str]
    # INVOKE INSTRUCTIONS, one per call site. A FIELD entry leaves this 0 and
    # fills `field_access_count` instead (dexllm#36) — widening this one to mean
    # "places that touch the API" would change a released field's value with no
    # type or name change to warn a consumer, which is the quiet break dexllm#35
    # was. Summing the two IS meaningful (both are instruction counts); they are
    # kept apart so this one's released meaning is untouched, not because the
    # units differ.
    call_site_count: int
    callers: Set[str] = field(default_factory=set)
    # `flags` is appended rather than placed next to `categories` on purpose: the
    # pre-0.2 positional arity was 5 (`callers` has a default), so inserting a
    # 5th required field mid-signature would make a legacy 5-positional call bind
    # silently wrong (flags=<int>, call_site_count=<set>) instead of raising.
    # `field_access_count` is appended for the same reason.
    flags: List[str] = field(default_factory=list)
    # READ INSTRUCTIONS, for a field-descriptor key; 0 for a method key. The
    # lookup is NOT deduplicated, so a method reading the field twice contributes
    # 2 — the same unit as `call_site_count`, and therefore NOT `len(callers)`.
    field_access_count: int = 0


@dataclass
class CapabilityReport:
    """Aggregated capability profile of an APK across all matched catalog APIs.

    ``by_caller`` maps a calling method to the catalog APIs it invokes — the
    transpose of ``ApiHit.callers``, and the index that answers "who in this app
    calls ``Runtime.exec`` / ``DexClassLoader`` / ``Class.forName``".

    It held ``{permissions}`` until dexllm#35, populated inside the permission
    loop, so an API declaring none registered no callers at all — and every
    ``REFLECTION`` / ``PROCESS_EXEC`` / ``DYNAMIC_LOAD`` / ``NATIVE_CODE`` /
    ``CRYPTO`` / ``WEBVIEW`` / ``STORAGE`` entry in the bundled catalog is
    permission-less, as are 6 domain entries including the ANDROID_ID read
    (``Settings$Secure.getString``). The index covered **17 of the corpus's 317
    distinct callers (5.4%)**.

    It is a CONVENIENCE INDEX, not new information: ``api_hits`` carries
    ``callers`` per API, so either view has always been derivable from a report —
    including from a PRE-fix one, which is why the bug lost no data. The value is
    signatures because that is the more primary view (the caller-indexed question
    is what the index is FOR), and because within the FIELD the derivation only
    runs one way — APIs give back permissions and tags, a permission set could not
    give back an API::

        by_api = {h.api_signature: h for h in report.api_hits}
        perms = {p for a in report.by_caller[caller] for p in by_api[a].permissions}
        tags = {t for a in report.by_caller[caller] for t in by_api[a].categories}

    The join is defined WITHIN one report: ``only_categories`` filters
    ``by_caller`` and ``api_hits`` together, so joining against a differently
    filtered call is meaningless.
    """

    # The three Counters count TOUCHES: one per invoke instruction for a method
    # entry, one per read instruction for a field entry (dexllm#36) — the same
    # unit, so the sum is well-defined. The per-API counters below stay separate
    # only to keep `call_site_count`'s released meaning intact.
    permissions: Counter  # permission -> count of touches
    categories: Counter  # category -> count of touches
    flags: Counter  # cross-domain concern -> count of touches
    by_caller: Dict[str, Set[str]]  # caller descriptor -> {api signatures}
    api_hits: List[ApiHit]  # one entry per matched API
    total_call_sites: int  # invoke instructions, method entries only
    catalog_version: str
    catalog_size: int
    matched_apis: int
    # Appended, like ApiHit.field_access_count and for the same positional-arity
    # reason. Read instructions against field-descriptor entries; 0 when the
    # catalog has no field keys, which is why an existing consumer sees no change.
    total_field_accesses: int = 0

    def top_permissions(self, n: int = 10) -> List[tuple]:
        """Return the n most-touched permissions as (permission, count) pairs.

        "Touched", not "invoked": the Counter includes field reads since dexllm#36.
        """
        return self.permissions.most_common(n)

    def top_categories(self, n: int = 10) -> List[tuple]:
        """Return the n most-touched categories as (category, count) pairs.

        "Touched", not "invoked": the Counter includes field reads since dexllm#36.
        """
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
    dk: DexKit,
    *,
    only_categories: Optional[Set[str]] = None,
    data_dir: Union[str, os.PathLike, None] = None,
) -> CapabilityReport:
    """Walk the catalog, look up each API's call sites via dk, aggregate.

    Args:
        dk: a dexllm.DexKit instance (caches will be warmed lazily)
        only_categories: if set, restrict aggregation to APIs carrying any of
            these tags on **either** axis (e.g. ``{"LOCATION", "TELEPHONY"}``, or
            ``{"IDENTIFIER"}`` — a flag). Matching both axes is what keeps a tag
            usable as a filter regardless of which axis it lives on.
        data_dir: directory holding a replacement ``android_api_map.json`` (else
            ``$DEXLLM_DATA_DIR``, else the bundled catalog) — see
            :mod:`dexllm.datadir`. The vocabulary validated below is the
            REPLACEMENT's, so a custom catalog brings its own taxonomy — and a
            catalog declaring NEITHER vocabulary key switches the check below off
            entirely (see the module docstring), so an override that wants the
            loud failure must declare them.

    Raises:
        ValueError: if ``only_categories`` holds a tag the catalog does not
            declare. Silently returning an empty report would be indistinguishable
            from "the APK exercises none of this", so a stale tag (one the 0.2
            taxonomy normalisation removed, or a typo) fails loudly instead. The
            bundled catalog declares both vocabularies; a replacement that omits
            them is exempt, as above.
    """
    catalog = _load_catalog(data_dir)
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

    total_field_accesses = 0

    for api_sig, meta in entries.items():
        # dict.fromkeys dedupes while preserving order: a tag repeated inside one
        # entry's list is malformed input, not a fact to count twice, and counting
        # it twice would reproduce the very inflation the two-axis split removed.
        cats = list(dict.fromkeys(meta.get("categories", [])))
        entry_flags = list(dict.fromkeys(meta.get("flags", [])))
        # Match on EITHER axis, so a tag stays filterable whichever axis it is on.
        if want and not (want & (set(cats) | set(entry_flags))):
            continue
        # The key's SHAPE selects the lookup — a type descriptor cannot contain
        # `(`, so a field key is unambiguous and needs no schema flag to say so
        # (dexllm#36). A field entry resolves to the METHODS that read it.
        is_field = _is_field_key(api_sig)
        if is_field:
            touches = list(dk.find_methods_reading_field(api_sig))
        else:
            touches = [s.caller_descriptor for s in dk.find_call_sites_to(api_sig)]
        if not touches:
            continue

        perms = meta.get("permissions", [])
        hit = ApiHit(
            api_signature=api_sig,
            permissions=list(perms),
            categories=list(cats),
            flags=list(entry_flags),
            call_site_count=0 if is_field else len(touches),
            field_access_count=len(touches) if is_field else 0,
        )

        for caller in touches:
            if is_field:
                total_field_accesses += 1
            else:
                total_sites += 1
            hit.callers.add(caller)
            # OUTSIDE the permission loop, and outside the tag loops below
            # (dexllm#35). Nesting it inside `for perm in perms:` meant an API
            # carrying no `permissions` never registered its callers at all —
            # every REFLECTION / PROCESS_EXEC / DYNAMIC_LOAD / NATIVE_CODE /
            # CRYPTO / WEBVIEW / STORAGE entry is permission-less, as are 6 domain
            # entries incl. the ANDROID_ID read — so the index covered 17 of the
            # corpus's 317 distinct callers. A replacement catalog need not give
            # an entry any tag either, so this must not be nested in a tag loop
            # for the same reason.
            by_caller.setdefault(caller, set()).add(api_sig)
            for perm in perms:
                permissions[perm] += 1
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
        total_field_accesses=total_field_accesses,
        catalog_version=catalog.get("version", "unknown"),
        catalog_size=len(entries),
        matched_apis=len(api_hits),
    )
