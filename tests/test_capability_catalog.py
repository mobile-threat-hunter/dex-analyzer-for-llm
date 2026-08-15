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
import pathlib
from pathlib import Path

import pytest
from conftest import require_corpus_shape

from dexllm import capability

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
    # CALENDAR / CALL_LOG / CONTACTS arrived with the field-descriptor keys
    # (dexllm#36): an app reaches those providers by READING a CONTENT_URI
    # constant, so before field keys existed the catalog had no way to express
    # them and the three domains were absent from the vocabulary entirely.
    "CALENDAR",
    "CALL_LOG",
    "CAMERA",
    "CONTACTS",
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


@pytest.fixture
def write_catalog(tmp_path_factory):
    """Write an override catalog to a fresh temp dir and return its path.

    A fresh directory per call because `datadir` caches by RESOLVED path (#43), so
    reusing one would serve the first catalog to every later test. Through
    `tmp_path_factory` rather than a bare `mkdtemp`, which the first cut used and
    which never cleaned up — 117 `/tmp/capcat*` directories had accumulated.
    """

    def _write(catalog):
        d = tmp_path_factory.mktemp("capcat")
        (d / "android_api_map.json").write_text(json.dumps(catalog))
        return str(d)

    return _write


def test_every_catalog_key_is_a_method_or_field_descriptor():
    """A key is ``Lcls;->name(proto)ret`` OR ``Lcls;->NAME:Ltype;``.

    INVERTED at dexllm#36. This used to reject a FIELD descriptor outright,
    because `summarize_capabilities` resolved every key with `find_call_sites_to`
    and a field key therefore matched nothing on every APK while still inflating
    `catalog_size` — three `CONTENT_URI` entries shipped that way and were deleted.
    The lookup now dispatches on the key's shape, so a field key is a first-class
    form and the rule is that a key must be one of the two, not that it must be a
    method. A third shape is still dead weight, which is what this now guards.
    """
    bad = []
    for key in _entries():
        cls, sep, member = key.partition(";->")
        if not sep or not cls.startswith("L") or not member:
            bad.append(key)
        elif "(" in member:  # method: a complete proto, and a return type after it
            if not member.endswith(tuple("VZBSCIJFD;[")) or ")" not in member:
                bad.append(key)
        elif ":" not in member or not member.split(":", 1)[1]:  # field: NAME:type
            bad.append(key)
    assert not bad, f"catalog keys that are neither a method nor a field: {bad}"

    # …and BOTH forms are actually present, or the dispatch this pins is untested
    # by the bundled catalog and the inversion above would be a claim, not a check.
    forms = {"(" in k.partition(";->")[2] for k in _entries()}
    assert forms == {True, False}, f"the catalog carries only one key form: {forms}"


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
    """A dk answering from {descriptor: [callers]} maps — one per key FORM.

    A FIELD key resolves through `find_methods_reading_field`, which returns
    method descriptors rather than call sites (dexllm#36), so the stub needs both
    lookups: `summarize_capabilities` picks one by the key's shape. That is also
    the contract note for any duck-typed `dk` stand-in — a catalog carrying field
    keys now requires the field lookup too.
    """

    def __init__(self, sites, reads=None):
        self._sites = sites
        self._reads = reads or {}

    def find_call_sites_to(self, descriptor):
        return [_Site(c) for c in self._sites.get(descriptor, ())]

    def find_methods_reading_field(self, descriptor):
        return list(self._reads.get(descriptor, ()))


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


def test_a_repeated_tag_is_not_counted_twice(tmp_path):
    """The emitter dedupes a malformed entry rather than inflating its count.

    A duplicate is not a fact to count twice — counting it reproduces exactly the
    `REFLECTION`/`DYNAMIC` double-count that motivated the 0.2 taxonomy.

    The malformed catalog is injected through the ``data_dir`` override channel
    (issue #33) rather than by assigning the module's cache global, which is the
    unsupported pattern that channel exists to replace.

    The sentinel ``version`` assertion is what keeps that substitution honest: the
    BUNDLED catalog also yields ``{"REFLECTION": 1}`` here, so if the override
    silently fell back to it every assertion below would still pass and the test
    would prove nothing about the dedupe (verified by sabotaging
    ``resolve_data_file`` to ignore ``data_dir`` — it passed).
    """
    import dexllm.capability as cap

    catalog = _catalog()
    catalog["version"] = "dedupe-fixture"
    catalog["entries"][_FOR_NAME]["categories"] = ["REFLECTION", "REFLECTION"]
    (tmp_path / "android_api_map.json").write_text(json.dumps(catalog))

    r = cap.summarize_capabilities(
        _StubDk({_FOR_NAME: ["La/B;->n()V"]}), data_dir=str(tmp_path)
    )
    assert r.catalog_version == "dedupe-fixture", "the override did not take effect"
    assert r.total_call_sites == 1
    assert r.categories == {"REFLECTION": 1}
    assert r.api_hits[0].categories == ["REFLECTION"]


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

    out = TOOL_IMPLS["summarize_capabilities"](dk)
    assert out["flags"] == {"IDENTIFIER": 2}
    assert out["api_hits"][0]["flags"] == ["IDENTIFIER"]
    assert out["catalog_version"] == raw.catalog_version


def test_by_caller_covers_a_permissionless_api():
    """The caller index must hold callers of APIs that declare no permission.

    `by_caller` was populated INSIDE `for perm in perms:`, so an entry with no
    `permissions` registered no callers at all (dexllm#35) — and that is the
    catalog's behavioural half: 20 of its 42 entries, every REFLECTION /
    PROCESS_EXEC / DYNAMIC_LOAD / NATIVE_CODE / CRYPTO / WEBVIEW / STORAGE API.
    The index covered 26 of the corpus's 634 distinct callers, so "who calls
    `Runtime.exec` here" — the question those entries exist to answer — could not
    be asked of it.

    Corpus-less: `_FOR_NAME` carries no permission and `_GET_DEVICE_ID` does, so
    the stub pins both arms without an APK.
    """
    from dexllm.capability import summarize_capabilities

    dk = _StubDk({_GET_DEVICE_ID: ["La/B;->m()V"], _FOR_NAME: ["La/C;->n()V"]})
    report = summarize_capabilities(dk)

    assert (
        "La/C;->n()V" in report.by_caller
    ), "the caller of a permission-less API is absent from by_caller"
    assert "La/B;->m()V" in report.by_caller


def test_by_caller_values_are_api_signatures():
    """The value is WHICH APIs the caller invokes, not which permissions.

    dexllm#35 chose signatures because they are lossless: the permission and tag
    views are recoverable from the report alone (see the next test), while a
    permission set could not be turned back into an API.
    """
    from dexllm.capability import summarize_capabilities

    dk = _StubDk({_GET_DEVICE_ID: ["La/B;->m()V"], _FOR_NAME: ["La/B;->m()V"]})
    report = summarize_capabilities(dk)

    assert report.by_caller["La/B;->m()V"] == {_GET_DEVICE_ID, _FOR_NAME}


def test_the_permission_view_of_a_caller_is_still_recoverable():
    """The pre-dexllm#35 value must be derivable, or the change lost information.

    This is the join the docstrings hand the reader; it is a guard because the
    field-level half of the argument for signatures over permissions rests on it.
    (The report-level half does NOT: `api_hits` carries `callers`, so either view
    was always derivable from a report — including a pre-fix one. The bug lost no
    data, only the index.)

    The expectation is derived from the CATALOG rather than written out, so adding
    a permission to `getDeviceId` becomes a catalog edit instead of a red test
    blaming the join. It stays discriminating — every by_caller mutant fails it.
    """
    from dexllm.capability import summarize_capabilities

    dk = _StubDk({_GET_DEVICE_ID: ["La/B;->m()V"], _FOR_NAME: ["La/B;->m()V"]})
    report = summarize_capabilities(dk)

    by_api = {h.api_signature: h for h in report.api_hits}
    perms = {p for a in report.by_caller["La/B;->m()V"] for p in by_api[a].permissions}
    expected = set(_entries()[_GET_DEVICE_ID].get("permissions") or ()) | set(
        _entries()[_FOR_NAME].get("permissions") or ()
    )
    assert expected, "the fixture APIs carry no permission — the join proves nothing"
    assert perms == expected


def test_by_caller_is_the_exact_transpose_of_the_hit_callers():
    """Every caller of every matched API appears, and nothing else does.

    The property the nesting bug broke, stated directly rather than as a count —
    a fix that merely moved the line one level out but kept a filter would satisfy
    the tests above on the stub and still under-report on a real APK.
    """
    from dexllm.capability import summarize_capabilities

    dk = _StubDk(
        {
            _GET_DEVICE_ID: ["La/B;->m()V", "La/C;->n()V"],
            _FOR_NAME: ["La/C;->n()V", "La/D;->o()V"],
        }
    )
    report = summarize_capabilities(dk)

    expected: dict = {}
    for hit in report.api_hits:
        for caller in hit.callers:
            expected.setdefault(caller, set()).add(hit.api_signature)
    assert report.by_caller == expected
    assert set(report.by_caller) == {"La/B;->m()V", "La/C;->n()V", "La/D;->o()V"}


def test_by_caller_survives_the_sdk_layer():
    """`sdk/adapter.py` converts each set to a tuple — one deletable line.

    The caller must hold TWO APIs, and the comparison is on sets: with a
    one-API-per-caller stub a reviewer's `tuple(v)[:1]` mutant passed the whole
    suite, and that is not a contrived edit — the field just grew ~25x and
    `tools.py` already justifies omitting it because per-caller sets "can be
    huge", so capping is the natural next change. Comparing as sets also keeps
    this independent of the tuple ORDER, which is only deterministic because the
    adapter sorts.

    The MCP tool deliberately omits `by_caller` (context size), which is why this
    stops at the SDK; that omission is asserted at the end.
    """
    from dexllm.capability import summarize_capabilities
    from dexllm.sdk.adapter import DexKitAdapter

    dk = _StubDk({_FOR_NAME: ["La/C;->n()V"], _GET_DEVICE_ID: ["La/C;->n()V"]})
    raw = summarize_capabilities(dk)
    assert raw.by_caller == {"La/C;->n()V": {_FOR_NAME, _GET_DEVICE_ID}}

    adapter = DexKitAdapter.__new__(DexKitAdapter)
    adapter._dk = dk  # type: ignore[attr-defined]
    sdk_report = DexKitAdapter.summarize_capabilities(adapter)
    assert {k: set(v) for k, v in sdk_report.by_caller.items()} == {
        "La/C;->n()V": {_FOR_NAME, _GET_DEVICE_ID}
    }

    from dexllm.tools import TOOL_IMPLS

    # NON-DISCRIMINATING BY DESIGN on the fix itself: it pins the documented
    # omission, so a later change that starts emitting the (now much larger)
    # caller index into an LLM context is a conscious edit, not a slip.
    assert "by_caller" not in TOOL_IMPLS["summarize_capabilities"](dk)


def test_the_sdk_orders_the_caller_index_deterministically():
    """A `set` -> `tuple` conversion must sort, or the order varies per process.

    `PYTHONHASHSEED` randomises string hashing, so `tuple(some_set)` differs
    between runs. This repo gates cross-process byte-identity elsewhere, and the
    change made multi-valued entries common (they were rare when the values were
    permissions), so the exposure went from a corner case to the normal one.

    MANY on BOTH axes, deliberately: with two elements an unsorted `tuple(set)`
    lands in sorted order half the time, so the first cut of this guard let the
    mutant through on the seed it happened to run under — and with one caller per
    API the `callers` half was trivially sorted, so its mutant survived every seed.
    At n=8..10 the unsorted variant agrees with `sorted` in 1 of n! orders, which
    is deterministic in every sense that matters; verified against both mutants on
    five `PYTHONHASHSEED` values.
    """
    from dexllm.sdk.adapter import DexKitAdapter

    many = list(_entries())[:10]
    callers = [f"La/C{i};->n()V" for i in range(8)]
    assert len(many) >= 8, "catalog too small to make the order check discriminating"
    dk = _StubDk({sig: callers for sig in many})
    adapter = DexKitAdapter.__new__(DexKitAdapter)
    adapter._dk = dk  # type: ignore[attr-defined]
    report = DexKitAdapter.summarize_capabilities(adapter)

    assert set(report.by_caller) == set(callers)
    for values in report.by_caller.values():
        assert values == tuple(sorted(values))
        assert set(values) == set(many)
    for hit in report.api_hits:
        assert hit.callers == tuple(sorted(hit.callers))
        assert set(hit.callers) == set(callers)


def test_the_caller_index_does_not_depend_on_the_tag_axes_either(tmp_path):
    """An entry with NEITHER permissions NOR categories must still index.

    The same defect shape as dexllm#35 one axis over: nesting the line in
    `for cat in cats:` passes every other guard, because every BUNDLED entry
    carries a category. A replacement catalog need not — `_validate_catalog`
    requires the tag lists to be lists, not to be non-empty, and the module
    docstring only says an entry "should" have one. So the override path, which is
    a supported feature, could silently reproduce the bug.
    """
    from dexllm.capability import summarize_capabilities

    bare = "Lp/Q;->r()V"
    (tmp_path / "android_api_map.json").write_text(
        json.dumps(
            {
                "version": "test",
                "category_vocabulary": ["REFLECTION"],
                "flag_vocabulary": [],
                "entries": {bare: {"permissions": [], "categories": [], "flags": []}},
            }
        )
    )
    dk = _StubDk({bare: ["La/Z;->z()V"]})
    report = summarize_capabilities(dk, data_dir=tmp_path)

    assert report.by_caller == {"La/Z;->z()V": {bare}}


def test_relocating_the_caller_index_left_the_counters_alone():
    """The half the a/b covered and the suite did not.

    dexllm#35 moved one statement out of `for perm in perms:`; nothing else in the
    loop changed. A future refactor that gets the caller index right while
    disturbing a counter would pass every test above.
    """
    from dexllm.capability import summarize_capabilities

    dk = _StubDk(
        {
            _GET_DEVICE_ID: ["La/B;->m()V", "La/C;->n()V"],
            _FOR_NAME: ["La/C;->n()V"],
        }
    )
    report = summarize_capabilities(dk)

    assert report.total_call_sites == 3
    assert report.permissions == {"android.permission.READ_PHONE_STATE": 2}
    assert report.categories == {"TELEPHONY": 2, "REFLECTION": 1}
    assert report.flags == {"IDENTIFIER": 2}


def test_every_indexed_signature_is_a_key_of_the_report_s_own_hits():
    """Join totality as a PROPERTY, so the documented recipe cannot KeyError.

    `test_the_permission_view_of_a_caller_is_still_recoverable` exercises the join
    on one caller of a two-API stub, so it would survive an unmatched signature
    leaking into the index; this states the invariant instead.
    """
    from dexllm.capability import summarize_capabilities

    dk = _StubDk({_GET_DEVICE_ID: ["La/B;->m()V"], _FOR_NAME: ["La/C;->n()V"]})
    report = summarize_capabilities(dk)

    indexed = set().union(*report.by_caller.values())
    assert indexed <= {h.api_signature for h in report.api_hits}
    assert indexed == {_GET_DEVICE_ID, _FOR_NAME}


def test_only_categories_filters_the_caller_index_with_the_hits():
    """What makes the documented join well-defined per report.

    `only_categories` `continue`s before both `by_caller` and `api_hits` are
    written, so the two stay the same subset. Pre-dexllm#35 this was vacuous for a
    permission-less filter like REFLECTION — the index was empty either way — so it
    is newly observable behaviour with nothing pinning it.
    """
    from dexllm.capability import summarize_capabilities

    dk = _StubDk({_GET_DEVICE_ID: ["La/B;->m()V"], _FOR_NAME: ["La/B;->m()V"]})
    report = summarize_capabilities(dk, only_categories={"REFLECTION"})

    assert report.by_caller == {"La/B;->m()V": {_FOR_NAME}}
    assert {h.api_signature for h in report.api_hits} == {_FOR_NAME}


# --- dexllm#36: FIELD-descriptor keys -----------------------------------------

_FIELD_KEYS = {
    "Landroid/provider/ContactsContract$Contacts;->CONTENT_URI:Landroid/net/Uri;": (
        "ContactsContract.java",
        ["Contacts"],
    ),
    "Landroid/provider/ContactsContract$CommonDataKinds$Phone;"
    "->CONTENT_URI:Landroid/net/Uri;": (
        "ContactsContract.java",
        ["CommonDataKinds", "Phone"],
    ),
    "Landroid/provider/CallLog$Calls;->CONTENT_URI:Landroid/net/Uri;": (
        "CallLog.java",
        ["Calls"],
    ),
    "Landroid/provider/CalendarContract$Events;->CONTENT_URI:Landroid/net/Uri;": (
        "CalendarContract.java",
        ["Events"],
    ),
}


def test_a_field_key_resolves_through_the_field_lookup(write_catalog):
    """The dispatch itself: a field key must NOT go to `find_call_sites_to`.

    That is the whole defect — `ParseApiDescriptor` requires a `(` after `->`, so
    a field descriptor matched nothing on every possible input and raised nothing.
    Three entries shipped that way for 15 months.
    """
    field_key = next(iter(_FIELD_KEYS))
    catalog = {
        "version": "t",
        "category_vocabulary": ["CONTACTS"],
        "flag_vocabulary": [],
        "entries": {field_key: {"categories": ["CONTACTS"]}},
    }

    class _Dk:
        def find_call_sites_to(self, descriptor):
            raise AssertionError(f"a FIELD key went to the method lookup: {descriptor}")

        def find_methods_reading_field(self, descriptor):
            return ["La/B;->m()V", "La/C;->n()V"] if descriptor == field_key else []

    rep = capability.summarize_capabilities(_Dk(), data_dir=write_catalog(catalog))
    assert rep.matched_apis == 1
    hit = rep.api_hits[0]
    assert hit.field_access_count == 2
    assert hit.call_site_count == 0, "a field entry must not claim invoke sites"
    assert rep.total_field_accesses == 2 and rep.total_call_sites == 0
    assert rep.categories == {"CONTACTS": 2}
    assert set(rep.by_caller) == {"La/B;->m()V", "La/C;->n()V"}


def test_the_two_counters_are_never_summed_into_one(write_catalog):
    """`call_site_count` keeps EXACTLY its released meaning (dexllm#36).

    Widening it to "places that touch the API" needs no type or name change, so a
    consumer would read a different number with nothing to warn them — the quiet
    break dexllm#35 was. This pins the split in a report holding both forms.
    """
    field_key = next(iter(_FIELD_KEYS))
    catalog = {
        "version": "t",
        "category_vocabulary": ["CONTACTS", "REFLECTION"],
        "flag_vocabulary": [],
        "entries": {
            field_key: {"categories": ["CONTACTS"]},
            _FOR_NAME: {"categories": ["REFLECTION"]},
        },
    }

    class _Dk:
        def find_call_sites_to(self, descriptor):
            return [_Site("La/B;->m()V")] if descriptor == _FOR_NAME else []

        def find_methods_reading_field(self, descriptor):
            return ["La/C;->n()V", "La/D;->o()V"] if descriptor == field_key else []

    rep = capability.summarize_capabilities(_Dk(), data_dir=write_catalog(catalog))
    by_sig = {h.api_signature: h for h in rep.api_hits}
    assert by_sig[_FOR_NAME].call_site_count == 1
    assert by_sig[_FOR_NAME].field_access_count == 0
    assert by_sig[field_key].field_access_count == 2
    assert by_sig[field_key].call_site_count == 0
    # the two totals stay apart, and neither absorbs the other
    assert rep.total_call_sites == 1 and rep.total_field_accesses == 2
    # …while the tag Counters DO count both, which is the documented asymmetry
    assert rep.categories == {"REFLECTION": 1, "CONTACTS": 2}


def test_field_counts_reach_the_sdk_and_mcp_layers(write_catalog, monkeypatch):
    """A counter nothing propagates is a counter nobody can read."""
    field_key = next(iter(_FIELD_KEYS))
    catalog = {
        "version": "t",
        "category_vocabulary": ["CONTACTS"],
        "flag_vocabulary": [],
        "entries": {field_key: {"categories": ["CONTACTS"]}},
    }

    class _Dk:
        def find_call_sites_to(self, descriptor):
            return []

        def find_methods_reading_field(self, descriptor):
            return ["La/B;->m()V"] if descriptor == field_key else []

    from dexllm import datadir, tools
    from dexllm.sdk.adapter import DexKitAdapter

    # monkeypatch, per conftest's own stated rule — the first cut mutated
    # os.environ directly and was contained only by an autouse fixture it does
    # not use.
    monkeypatch.setenv(datadir.ENV_VAR, write_catalog(catalog))
    datadir.clear_data_caches()

    # …through the adapter's real method, not a private converter: the point is
    # that the value survives the layer a consumer actually calls.
    model = DexKitAdapter.summarize_capabilities(type("_A", (), {"_dk": _Dk()})())
    assert model.api_hits[0].field_access_count == 1
    # …and the REPORT-level total, which docs/sdk.md documents. It was missing
    # from the SDK model in the first cut while the docs already asserted the
    # inequality that needs it — "a counter nothing propagates is a counter
    # nobody can read" applied to the very test that says so.
    assert model.total_field_accesses == 1
    assert sum(model.categories.values()) >= (
        model.total_call_sites + model.total_field_accesses
    )

    out = tools.execute("summarize_capabilities", {}, _Dk())
    assert out["total_field_accesses"] == 1
    assert out["api_hits"][0]["field_accesses"] == 1
    assert out["api_hits"][0]["call_sites"] == 0


def test_the_bundled_field_keys_name_real_aosp_fields():
    """A typo'd key matches nothing and raises nothing — the #36 failure itself.

    Shape guards cannot catch `CONTENT_URl` or a wrong nesting, and the bundled
    corpus references no `CONTENT_URI` at all (measured: 0), so nothing else here
    can. Checked against a local AOSP checkout; SKIPS without one, since that is
    an environment fact (CI has none).
    """
    import os
    import re

    root = pathlib.Path(
        os.environ.get("DEXLLM_AOSP_SRC", pathlib.Path.home() / "Project" / "aosp")
    )
    provider = root / "frameworks/base/core/java/android/provider"
    if not provider.is_dir():
        pytest.skip(f"no AOSP checkout at {root} (set $DEXLLM_AOSP_SRC)")

    for key, (fname, nesting) in _FIELD_KEYS.items():
        assert key in _entries(), f"{key} is not in the bundled catalog"
        member = key.partition(";->")[2]
        name, _, ftype = member.partition(":")
        body = (provider / fname).read_text()
        for cls in nesting:  # walk into the nested class by brace matching
            m = re.search(rf"\b(?:class|interface)\s+{cls}\b[^{{]*\{{", body)
            assert m, f"{fname}: no class {cls} for {key}"
            i = m.end() - 1
            depth = 0
            for j in range(i, len(body)):
                depth += body[j] == "{"
                depth -= body[j] == "}"
                if depth == 0:
                    break
            body = body[i + 1 : j]
        assert re.search(
            rf"public\s+static\s+final\s+Uri\s+{name}\s*=", body
        ), f"{key}: {'.'.join(nesting)} declares no `public static final Uri {name}`"
        assert ftype == "Landroid/net/Uri;", key


def test_the_documented_counter_inequality_holds_with_both_key_forms(write_catalog):
    """`sum(categories) >= total_call_sites + total_field_accesses` (dexllm#36).

    docs/usage.md, docs/api.md and docs/sdk.md all assert this. It used to read
    `>= total_call_sites` alone, which a matched FIELD entry falsifies: the
    Counters count TOUCHES of either kind while the two totals keep the units
    apart, so a field access lands on the left and not on the right.
    """
    field_key = next(iter(_FIELD_KEYS))
    catalog = {
        "version": "t",
        "category_vocabulary": ["CONTACTS", "REFLECTION"],
        "flag_vocabulary": [],
        "entries": {
            field_key: {"categories": ["CONTACTS"]},
            _FOR_NAME: {"categories": ["REFLECTION"]},
        },
    }

    class _Dk:
        def find_call_sites_to(self, descriptor):
            return [_Site("La/B;->m()V")] if descriptor == _FOR_NAME else []

        def find_methods_reading_field(self, descriptor):
            return ["La/C;->n()V", "La/D;->o()V"] if descriptor == field_key else []

    rep = capability.summarize_capabilities(_Dk(), data_dir=write_catalog(catalog))
    total = rep.total_call_sites + rep.total_field_accesses
    assert sum(rep.categories.values()) >= total
    # …and equality holds here, since every entry carries exactly one tag — which
    # is what makes the field half genuinely load-bearing rather than slack
    assert sum(rep.categories.values()) == total == 3
    # the OLD wording would be false on this very report
    assert sum(rep.categories.values()) > rep.total_call_sites


def test_a_field_entry_matches_on_a_REAL_dex(dk):
    """The gap that let the 15-month bug ship again, one layer down.

    Every other field test drives a stub, so none of them could see that
    `find_methods_reading_field` resolved nothing for a FRAMEWORK class: it began
    with `LocateClassDex`, which answers only for a class DECLARED in a loaded
    dex. So dexllm#36's first cut swapped one always-empty lookup for another and
    the four `CONTENT_URI` entries were inert on every possible input — the very
    defect the issue is about. Two reviewers found it; no test could.

    This asserts the primitive against the real binding, corpus-independently: any
    field the app provably reads must resolve to at least one reader.
    """
    fields = dk.list_fields()
    # A FRAMEWORK field — the case that was broken. `SDK_INT` is read by
    # essentially every Android app and its class is never declared in the APK.
    sdk_int = "Landroid/os/Build$VERSION;->SDK_INT:I"
    require_corpus_shape(
        sdk_int in fields,
        "reference to Build.VERSION.SDK_INT",
        "the corpus stopped carrying the most universal framework field read",
    )
    assert dk.locate_class_dex("Landroid/os/Build$VERSION;") == -1, (
        "premise: the declaring class is NOT in the app, which is exactly what "
        "the old lookup required"
    )
    readers = dk.find_methods_reading_field(sdk_int)
    assert readers, "a framework field the app reads must resolve to its readers"
    assert all(";->" in r for r in readers)


def test_field_access_count_is_per_instruction_not_per_method(write_catalog):
    """Pins the UNIT, which the stubs cannot (dexllm#36).

    `find_methods_reading_field` is documented as NOT deduplicated — one entry per
    read instruction — but every field stub returned DISTINCT method descriptors,
    so a mutant applying `dict.fromkeys` (i.e. making the code match an earlier,
    wrong docstring that said "reading methods") survived the entire suite. Both
    counters are the same unit, which is why summing them is meaningful and why
    `field_access_count` is NOT `len(callers)`.
    """
    field_key = next(iter(_FIELD_KEYS))
    catalog = {
        "version": "t",
        "category_vocabulary": ["CONTACTS"],
        "flag_vocabulary": [],
        "entries": {field_key: {"categories": ["CONTACTS"]}},
    }

    class _Dk:
        def find_call_sites_to(self, descriptor):
            return []

        def find_methods_reading_field(self, descriptor):
            # ONE method, TWO read instructions — what the real binding returns
            return ["La/B;->m()V", "La/B;->m()V"] if descriptor == field_key else []

    rep = capability.summarize_capabilities(_Dk(), data_dir=write_catalog(catalog))
    hit = rep.api_hits[0]
    assert hit.field_access_count == 2, "instructions, not methods"
    assert len(hit.callers) == 1, "…while `callers` is a set, so they differ"
    assert rep.total_field_accesses == 2
    assert rep.categories == {"CONTACTS": 2}, "the Counter follows the instructions"


def test_the_mcp_ranking_counts_field_accesses(write_catalog, monkeypatch):
    """A field entry must be able to outrank a method one.

    The sort key changed to touches; nothing asserted it, so reverting it to
    `call_site_count` alone — which sinks every field entry to the bottom with a 0
    it is not supposed to have — survived the whole suite.
    """
    field_key = next(iter(_FIELD_KEYS))
    catalog = {
        "version": "t",
        "category_vocabulary": ["CONTACTS", "REFLECTION"],
        "flag_vocabulary": [],
        "entries": {
            field_key: {"categories": ["CONTACTS"]},
            _FOR_NAME: {"categories": ["REFLECTION"]},
        },
    }

    class _Dk:
        def find_call_sites_to(self, descriptor):
            return [_Site("La/B;->m()V")] if descriptor == _FOR_NAME else []

        def find_methods_reading_field(self, descriptor):
            return ["La/C;->n()V"] * 5 if descriptor == field_key else []

    from dexllm import datadir, tools

    monkeypatch.setenv(datadir.ENV_VAR, write_catalog(catalog))
    datadir.clear_data_caches()
    out = tools.execute("summarize_capabilities", {}, _Dk())
    assert [h["api"] for h in out["api_hits"]] == [
        field_key,
        _FOR_NAME,
    ], "5 field accesses must outrank 1 call site"


def test_the_ranking_is_a_total_order(write_catalog, monkeypatch):
    """Ties break on the signature, so catalog ORDER cannot move the ranking.

    `sorted` is stable, so the ranking followed `entries` iteration order — and
    re-serialising the catalog (as dexllm#36 did) reordered the MCP `top_apis` on
    16 of 32 corpus sources with no count changing.
    """
    keys = [_FOR_NAME, _GET_DEVICE_ID]
    base = {
        "version": "t",
        "category_vocabulary": ["REFLECTION", "TELEPHONY"],
        "flag_vocabulary": [],
    }
    meta = {
        _FOR_NAME: {"categories": ["REFLECTION"]},
        _GET_DEVICE_ID: {"categories": ["TELEPHONY"]},
    }

    class _Dk:  # equal counts, so only the tie-break can order them
        def find_call_sites_to(self, descriptor):
            return [_Site("La/B;->m()V")] if descriptor in meta else []

        def find_methods_reading_field(self, descriptor):
            return []

    from dexllm import datadir, tools

    seen = []
    for order in (keys, list(reversed(keys))):
        catalog = {**base, "entries": {k: meta[k] for k in order}}
        monkeypatch.setenv(datadir.ENV_VAR, write_catalog(catalog))
        datadir.clear_data_caches()
        seen.append(
            [
                h["api"]
                for h in tools.execute("summarize_capabilities", {}, _Dk())["api_hits"]
            ]
        )
    assert (
        seen[0] == seen[1] == sorted(keys)
    ), f"the ranking followed catalog order: {seen}"


def test_is_field_key_routes_a_malformed_key_to_the_field_lookup():
    """Pins the documented routing of a third shape.

    `_is_field_key`'s docstring reasons about malformed keys ("routes to a lookup
    that returns nothing"), so WHICH lookup is stated behaviour — and a mutant
    sending a key with no `;->` to the METHOD lookup survived the suite. Both
    lookups are silent on such input, so the cost is only which one is asked; the
    point is that the answer is pinned rather than incidental.
    """
    from dexllm.capability import _is_field_key

    for method_key in (
        _FOR_NAME,
        "Lcls;-><init>()V",
        "Lcls;->m(Ljava/lang/String;I)Ljava/lang/Object;",
    ):
        assert not _is_field_key(method_key), method_key
    for field_or_malformed in (
        "Lcls;->NAME:Ltype;",
        "Lcls;->NAME:[I",
        "",
        "garbage",
        "Lcls;",
        "Lcls;->",
    ):
        assert _is_field_key(field_or_malformed), field_or_malformed
