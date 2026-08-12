"""Schema and behaviour guards for the L3 capability catalog + its aggregation.

The catalog (``data/android_api_map.json``) is hand-curated with no generator, so
nothing but a test enforces its shape. These guards exist because each failure mode
has already happened or would silently corrupt the aggregate report as the file
grows (issue #30):

1. a FIELD descriptor sits in a table looked up with ``find_call_sites_to`` — it
   matches nothing, forever, and no error is raised (three such entries shipped
   from 2026-05 to 2026-08 and were counted in ``catalog_size`` the whole time);
2. the two metadata axes leak into each other, which is what makes the aggregate
   Counter a measure of tagging density rather than of the APK;
3. the vocabulary drifts — ``DYNAMIC`` next to ``REFLECTION`` double-counted the
   same call sites under two names and occupied the top two report slots;
4. a tag is repeated inside one entry's list, which reproduces (3) while passing
   every set-based guard.

The schema guards are catalog-only, so they run in CI without an APK. The
behaviour guards at the bottom use a STUB dk (no corpus either) to pin decisions a
schema check cannot see: which axes ``only_categories`` matches, that an unknown
tag raises, the per-call-site aggregation scope, and that ``flags`` survives all
three layers (raw → SDK → MCP) — each of those was individually revertible with a
green suite before these were added.
"""

import json
from pathlib import Path

import pytest

CATALOG = (
    Path(__file__).resolve().parents[1]
    / "src"
    / "dexllm"
    / "data"
    / "android_api_map.json"
)

# The closed `categories` vocabulary, PINNED. The catalog declares the same set in
# `category_vocabulary` (so `summarize_capabilities` can validate `only_categories`
# at runtime and a consumer can enumerate it); this copy exists so that CHANGING it
# is a conscious edit in two places — the only thing standing between a 10x bigger
# catalog and an unusable taxonomy. The two are asserted equal below.
CATEGORY_VOCABULARY = {
    # domains
    "ACCOUNTS",
    "BLUETOOTH",
    "CAMERA",
    "LOCATION",
    "MICROPHONE",
    "NETWORK_IO",
    "PACKAGE_INFO",
    "SETTINGS",
    "SMS",
    "STORAGE",
    "TELEPHONY",
    "WEBVIEW",
    "WIFI",
    # behaviours
    "CRYPTO",
    "DYNAMIC_LOAD",
    "NATIVE_CODE",
    "PROCESS_EXEC",
    "REFLECTION",
}

# The closed `flags` vocabulary — the orthogonal axis: cross-domain concerns a
# domain tag cannot express.
FLAG_VOCABULARY = {"IDENTIFIER"}


def _catalog():
    return json.loads(CATALOG.read_text())


def _entries():
    return _catalog()["entries"]


def test_every_catalog_key_is_a_method_descriptor():
    """A key must be ``Lcls;->name(proto)ret``.

    ``summarize_capabilities`` resolves each key with ``find_call_sites_to``, which
    looks up METHODS. A field descriptor (``Lcls;->NAME:Ltype;``) returns zero call
    sites on every APK and raises nothing, so it is dead weight that still inflates
    ``catalog_size``. Three ``CONTENT_URI`` field entries shipped that way.
    """
    bad = []
    for key in _entries():
        cls, sep, member = key.partition(";->")
        if not sep or not cls.startswith("L"):
            bad.append(key)
        elif "(" not in member or ")" not in member:
            bad.append(key)
    assert not bad, f"catalog keys that are not method descriptors: {bad}"


def test_category_and_flag_axes_stay_disjoint():
    """No tag may appear on both axes.

    ``categories`` counts are only meaningful because they are a single axis; a tag
    living on both would be counted twice for one call site and re-create exactly
    the inflation the two-axis split removes.

    NON-DISCRIMINATING by design: it also passes against the pre-``flags`` catalog,
    where the second axis is empty. It guards the drift ahead, not the fix behind.
    """
    entries = _entries()
    cats = {c for e in entries.values() for c in e.get("categories", [])}
    flags = {f for e in entries.values() for f in e.get("flags", [])}
    assert not (cats & flags), f"tags on both axes: {sorted(cats & flags)}"


def test_vocabularies_are_closed():
    """No entry may carry a tag outside the declared vocabulary.

    This is what stops an ad-hoc tag — a synonym, a severity, a restatement of the
    key — from entering as the catalog grows. The reverse direction (a declared tag
    nothing uses) is deliberately NOT asserted: it is harmless (``only_categories``
    accepts it and correctly reports nothing), while asserting it would break on any
    entry deletion and forbid declaring a tag before filling it.
    """
    entries = _entries()
    cats = {c for e in entries.values() for c in e.get("categories", [])}
    flags = {f for e in entries.values() for f in e.get("flags", [])}
    assert not (
        cats - CATEGORY_VOCABULARY
    ), f"undeclared categories: {sorted(cats - CATEGORY_VOCABULARY)}"
    assert not (
        flags - FLAG_VOCABULARY
    ), f"undeclared flags: {sorted(flags - FLAG_VOCABULARY)}"


def test_catalog_declares_the_pinned_vocabulary():
    """The catalog's own declaration must equal the set pinned in this file.

    ``summarize_capabilities`` validates ``only_categories`` against the catalog's
    ``category_vocabulary`` / ``flag_vocabulary``, so those keys are the runtime
    contract. Pinning the same set here is what makes widening it a conscious edit
    rather than a side effect of adding an entry.
    """
    catalog = _catalog()
    assert set(catalog["category_vocabulary"]) == CATEGORY_VOCABULARY
    assert set(catalog["flag_vocabulary"]) == FLAG_VOCABULARY


def test_no_entry_repeats_a_tag():
    """A tag repeated inside one entry's list would be counted twice per call site.

    That is exactly the inflation the two-axis split removed (``REFLECTION`` and
    ``DYNAMIC`` double-counting the same sites), reachable again through the bulk
    load the module docstring plans for, where merging two sources duplicates rows.
    The emitter dedupes defensively; this keeps the bundled catalog honest.
    """
    dup = {
        key: axis
        for key, e in _entries().items()
        for axis in ("categories", "flags")
        if len(e.get(axis, [])) != len(set(e.get(axis, [])))
    }
    assert not dup, f"entries repeating a tag: {dup}"


def test_tag_and_permission_values_are_lists_of_strings():
    """``categories`` / ``flags`` / ``permissions`` must each be a list of strings.

    A bare string passes every other guard and is then iterated CHARACTER-wise by
    the emitter (``flags: "IDENTIFIER"`` → ``{'I': n, 'D': n, …}``) — silent
    corruption with no exception. ``null`` raises deep inside the aggregation.
    """
    bad = []
    for key, e in _entries().items():
        for axis in ("categories", "flags", "permissions"):
            if axis not in e:
                continue
            v = e[axis]
            if not isinstance(v, list) or not all(isinstance(x, str) for x in v):
                bad.append((key, axis, v))
    assert not bad, f"non list-of-str values: {bad}"


def test_every_entry_carries_at_least_one_category():
    """``categories`` is the primary axis — an entry without one is invisible to
    ``only_categories`` filtering and contributes nothing to the report's grouping.

    NON-DISCRIMINATING by design: the pre-patch catalog satisfied it too. It is the
    invariant stated so a future bulk load cannot quietly add untagged rows.
    """
    missing = [k for k, e in _entries().items() if not e.get("categories")]
    assert not missing, f"entries with no category: {missing}"


# ── behaviour guards (stub dk — no corpus needed) ────────────────────────────


class _Site:
    """Minimal stand-in for a CallSite: the aggregation reads one attribute."""

    def __init__(self, caller):
        self.caller_descriptor = caller


class _StubDk:
    """A dk whose `find_call_sites_to` answers from a {descriptor: [callers]} map."""

    def __init__(self, sites):
        self._sites = sites

    def find_call_sites_to(self, descriptor):
        return [_Site(c) for c in self._sites.get(descriptor, ())]


_GET_DEVICE_ID = "Landroid/telephony/TelephonyManager;->getDeviceId()Ljava/lang/String;"
_FOR_NAME = "Ljava/lang/Class;->forName(Ljava/lang/String;)Ljava/lang/Class;"


def test_only_categories_matches_either_axis():
    """A flag must stay usable as a filter, not just as a reported value.

    `IDENTIFIER` moved from `categories` to `flags` in 0.2. If the selection gate
    read only the `categories` axis, `only_categories={"IDENTIFIER"}` — the most
    obvious triage query the catalog supports — would return an empty report while
    the unfiltered run still shows `flags={'IDENTIFIER': …}`: visible but
    unselectable.

    Verified discriminating against the exact regression (reverting the gate to
    `want & set(cats)` fails this test). It also passes against pre-0.2 HEAD, for a
    different reason — there `IDENTIFIER` was still a category.
    """
    from dexllm.capability import summarize_capabilities

    dk = _StubDk({_GET_DEVICE_ID: ["La/B;->m()V"], _FOR_NAME: ["La/B;->n()V"]})

    by_flag = summarize_capabilities(dk, only_categories={"IDENTIFIER"})
    assert by_flag.matched_apis == 1
    assert by_flag.api_hits[0].api_signature == _GET_DEVICE_ID

    by_category = summarize_capabilities(dk, only_categories={"REFLECTION"})
    assert by_category.matched_apis == 1
    assert by_category.api_hits[0].api_signature == _FOR_NAME


def test_unknown_only_categories_tag_raises_instead_of_reporting_nothing():
    """A stale tag must fail loudly.

    The 0.2 normalisation deleted 17 tag names. A rule hardcoding one of them would
    otherwise get a well-formed report with `matched_apis=0`, byte-identical to the
    correct answer for an APK that genuinely exercises none of that domain.
    """
    from dexllm.capability import summarize_capabilities

    dk = _StubDk({_FOR_NAME: ["La/B;->n()V"]})
    with pytest.raises(ValueError, match="DYNAMIC"):
        summarize_capabilities(dk, only_categories={"DYNAMIC"})
    # a valid tag alongside an invalid one must still raise (no partial credit)
    with pytest.raises(ValueError, match="HASH"):
        summarize_capabilities(dk, only_categories={"REFLECTION", "HASH"})


def test_flags_are_counted_per_call_site_like_categories():
    """Pins the aggregation SCOPE, which no schema check can see.

    `report.flags` counts INVOCATIONS (as `permissions` and `categories` do), not
    matched APIs and not distinct callers. Moving the two counting lines out of the
    per-site loop turns 3 into 1; deduping by caller (a plausible refactor, since
    `hit.callers` is already a set) turns 3 into 2.

    The stub REPEATS a caller on purpose: with three distinct callers the per-site
    and per-caller readings coincide, and the caller-dedupe regression passes. Real
    APKs have the repeated shape — a2dp.Vol calls `requestLocationUpdates` 3 times
    from one method.
    """
    from dexllm.capability import summarize_capabilities

    dk = _StubDk({_GET_DEVICE_ID: ["La/B;->m()V", "La/B;->m()V", "La/C;->m()V"]})
    r = summarize_capabilities(dk)
    assert r.total_call_sites == 3
    assert r.flags == {"IDENTIFIER": 3}
    assert r.categories == {"TELEPHONY": 3}
    # …while the caller SET collapses the repeat, which is what makes the two
    # readings distinguishable here.
    assert r.api_hits[0].callers == {"La/B;->m()V", "La/C;->m()V"}
    assert r.api_hits[0].call_site_count == 3
    # the per-hit list stays per-API (one entry, not repeated per site)
    assert r.api_hits[0].flags == ["IDENTIFIER"]


def test_a_repeated_tag_is_not_counted_twice():
    """The emitter dedupes a malformed entry rather than inflating its count.

    A duplicate is not a fact to count twice — counting it reproduces exactly the
    `REFLECTION`/`DYNAMIC` double-count that motivated the 0.2 taxonomy.
    """
    import dexllm.capability as cap

    original = cap._CATALOG_CACHE
    try:
        catalog = _catalog()
        catalog["entries"][_FOR_NAME]["categories"] = ["REFLECTION", "REFLECTION"]
        cap._CATALOG_CACHE = catalog
        r = cap.summarize_capabilities(_StubDk({_FOR_NAME: ["La/B;->n()V"]}))
        assert r.total_call_sites == 1
        assert r.categories == {"REFLECTION": 1}
        assert r.api_hits[0].categories == ["REFLECTION"]
    finally:
        cap._CATALOG_CACHE = original


def test_flags_survive_the_sdk_and_mcp_layers():
    """`flags` must traverse raw -> SDK model -> MCP tool dict.

    Each hop is a separate line (`sdk/adapter.py`, `tools.py`) and either was
    individually deletable with a green corpus-less suite before this guard.

    The SDK half calls ``DexKitAdapter.summarize_capabilities`` ITSELF rather than
    re-implementing the conversion: an inline copy asserts what the test does, not
    what the adapter does, and would have kept passing with both adapter lines
    deleted (CI has no corpus, so the APK-backed SDK tests that catch it are
    skipped there). ``__new__`` + ``_dk`` is enough — the method touches nothing
    else, so no real APK load is needed.
    """
    from dexllm.capability import summarize_capabilities
    from dexllm.sdk.adapter import DexKitAdapter

    dk = _StubDk({_GET_DEVICE_ID: ["La/B;->m()V", "La/C;->m()V"]})
    raw = summarize_capabilities(dk)
    assert raw.flags == {"IDENTIFIER": 2}

    adapter = DexKitAdapter.__new__(DexKitAdapter)
    adapter._dk = dk  # type: ignore[attr-defined]
    sdk_report = DexKitAdapter.summarize_capabilities(adapter)
    assert dict(sdk_report.flags) == {"IDENTIFIER": 2}
    assert sdk_report.api_hits[0].flags == ("IDENTIFIER",)

    from dexllm.tools import TOOL_IMPLS

    out = TOOL_IMPLS["capability_report"](dk)
    assert out["flags"] == {"IDENTIFIER": 2}
    assert out["api_hits"][0]["flags"] == ["IDENTIFIER"]
    assert out["catalog_version"] == raw.catalog_version
