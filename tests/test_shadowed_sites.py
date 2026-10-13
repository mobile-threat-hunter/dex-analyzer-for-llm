"""A site in a SHADOWED copy of its method is reported and marked (dexllm#107).

When a class is declared in more than one loaded dex — an ``add_dumped_dexes``
packer session, or any multi-source load whose sources overlap — it resolves to
ONE of them: the first-wins declaring dex that ``locate_class_dex`` and
``decompile_*`` answer for. A method body in any other copy never executes under
that order, so an invoke or field access inside it is *shadowed*.

The per-instruction APIs (``find_call_sites_to``, ``resolve_call_args``,
``find_field_read_sites`` / ``find_field_write_sites``) still report such a site,
because the copies can DIFFER (a partial dump, an undecrypted original) and a
site present only in the shadowed copy is real evidence about the app. They mark
it ``shadowed=True``. Every consumer that answers "what does the app DO" — the
capability counts and the descriptor-keyed caller joins (``permission_callers``,
``dangerous_permission_api_callers``, ``permission_api_callers``, the TLS and
component ``constructed_in``) — leaves it out, so they agree with the body
``decompile_method`` renders.

The oracle for "which dex declares a class first" is ``list_class_headers()``,
which walks every dex's class_defs and is independent of the core's
declared-class map the production predicate reads.

Every case runs on committed fixtures, so it holds in the corpus-less CI leg,
except the two that need a corpus sample (a permission-gated call, a cross-dex
field accessor); the permission joins are also SOURCE-pinned for that leg.
"""

from __future__ import annotations

import json
import os
import struct
from pathlib import Path

import pytest
from conftest import require_corpus_shape
from test_empty_code_item import _code_items

import dexllm
import dexllm.sdk

DATA = Path(__file__).parent / "data"
FIXTURE = DATA / "invoke-custom.dex"
OTHER = DATA / "multidex.apk"  # two dexes, declares none of FIXTURE's classes

# A void call with exactly one site in the fixture, and no move-result after it,
# so three nop code units remove it without leaving a dangling result.
DUMP_STACK = "Ljava/lang/Thread;->dumpStack()V"
FAIL = "LTestBase;->fail()V"
# A FIELD catalog key: summarize_capabilities resolves it through the field xref,
# a different lookup from the call keys (dexllm#36), so it is filtered separately.
SYSTEM_OUT = "Ljava/lang/System;->out:Ljava/io/PrintStream;"


def _first_declaring(dk) -> dict[str, int]:
    out: dict[str, int] = {}
    for h in dk.list_class_headers():
        out.setdefault(h.descriptor, h.dex_id)
    return out


def _cls(desc: str) -> str:
    return desc.split("->")[0]


def _call_targets(dk) -> list[str]:
    return [r.descriptor for r in dk.list_external_method_refs()]


def _field_targets(dk) -> list[str]:
    return sorted(set(dk.list_fields()))


@pytest.fixture(scope="module")
def once():
    return dexllm.DexKit(str(FIXTURE))


@pytest.fixture(scope="module", params=["twice", "dumped", "behind_other"])
def dup(request, once):
    """Three sessions declaring every FIXTURE class twice.

    ``behind_other`` puts two OTHER dexes first, so the first-wins copy is dex 2,
    not dex 0 — a predicate that only asked ``dex_id != 0`` passes the other two.
    """
    if request.param == "twice":
        return dexllm.DexKit([str(FIXTURE), str(FIXTURE)])
    if request.param == "dumped":
        return dexllm.add_dumped_dexes(once, [str(FIXTURE)])
    return dexllm.DexKit([str(OTHER), str(FIXTURE), str(FIXTURE)])


def _call_rows(dk):
    for t in _call_targets(dk):
        for s in dk.find_call_sites_to(t):
            yield t, _cls(s.caller_descriptor), s.caller_dex_id, s


def test_a_single_source_session_has_no_shadowed_site(once):
    calls = [s for t in _call_targets(once) for s in once.find_call_sites_to(t)]
    assert calls, "premise: the fixture makes calls"
    assert not any(s.shadowed for s in calls)
    reads = [s for f in _field_targets(once) for s in once.find_field_read_sites(f)]
    assert reads, "premise: the fixture reads fields"
    assert not any(s.shadowed for s in reads)


def test_shadowed_means_not_the_first_declaring_dex(dup):
    first = _first_declaring(dup)
    n = 0
    for _t, cls, dex, s in _call_rows(dup):
        assert s.shadowed == (first[cls] != dex), (s.caller_descriptor, dex)
        n += 1
    for f in _field_targets(dup):
        for s in dup.find_field_read_sites(f) + dup.find_field_write_sites(f):
            want = first[_cls(s.method_descriptor)] != s.dex_id
            assert s.shadowed == want, (s.method_descriptor, s.dex_id)
            n += 1
    assert n > 400, n


def test_the_live_sites_are_exactly_one_sources_sites(once, dup):
    """Drop the shadowed rows and what is left is the single-source answer.

    Scoped to callers FIXTURE declares: ``behind_other`` adds OTHER's own calls.
    """
    first = _first_declaring(dup)
    mine = set(once.list_classes())
    for t in _call_targets(once):
        want = [
            (s.caller_descriptor, s.bytecode_offset, s.invoke_opcode)
            for s in once.find_call_sites_to(t)
        ]
        rows = [
            s for s in dup.find_call_sites_to(t) if _cls(s.caller_descriptor) in mine
        ]
        live = [
            (s.caller_descriptor, s.bytecode_offset, s.invoke_opcode)
            for s in rows
            if not s.shadowed
        ]
        assert sorted(live) == sorted(want), t
        # every shadowed row is a real second copy of a live one
        assert len(rows) == 2 * len(want), t
        assert all(
            first[_cls(s.caller_descriptor)] == s.caller_dex_id
            for s in rows
            if not s.shadowed
        )


def test_resolve_call_args_marks_the_same_rows(dup):
    for t in _call_targets(dup)[:60]:
        a = [
            (s.caller_dex_id, s.bytecode_offset, s.shadowed)
            for s in dup.find_call_sites_to(t)
        ]
        b = [
            (s.caller_dex_id, s.bytecode_offset, s.shadowed)
            for s in dup.resolve_call_args(t)
        ]
        assert a == b, t


def test_the_forward_direction_is_never_shadowed(dup):
    """``find_call_sites_from`` resolves its method first-wins, so it walks the copy that runs."""
    callers = {s.caller_descriptor for _t, _c, _d, s in _call_rows(dup)}
    assert callers
    for c in sorted(callers)[:80]:
        assert not any(s.shadowed for s in dup.find_call_sites_from(c)), c


def test_the_typed_layers_carry_the_flag(dup):
    sdk = dexllm.sdk.DexKitAdapter(dup.sources())
    t = DUMP_STACK
    raw = [s.shadowed for s in dup.find_call_sites_to(t)]
    assert True in raw and False in raw, raw
    assert [s.shadowed for s in sdk.find_call_sites_to(t)] == raw
    assert [s.shadowed for s in sdk.resolve_call_args(t)] == raw
    f = next(f for f in _field_targets(dup) if dup.find_field_read_sites(f))
    assert [s.shadowed for s in sdk.find_field_read_sites(f)] == [
        s.shadowed for s in dup.find_field_read_sites(f)
    ]
    from dexllm import tools

    for name, arg in (
        ("find_call_sites_to", {"method_descriptor": t}),
        ("resolve_call_args", {"method_descriptor": t}),
        ("find_field_read_sites", {"field_descriptor": f}),
    ):
        items = tools.execute(name, arg, dup)["items"]
        assert sorted(i["shadowed"] for i in items) == sorted(
            [True] * (len(items) // 2) + [False] * (len(items) // 2)
        ), name
    items = tools.execute("find_call_sites_from", {"method_descriptor": FAIL}, dup)[
        "items"
    ]
    assert items and not any(i["shadowed"] for i in items)


# ── capability counts ───────────────────────────────────────────────────────


@pytest.fixture()
def catalog_dir(tmp_path):
    (tmp_path / "android_api_map.json").write_text(
        json.dumps(
            {
                "version": "test",
                "entries": {
                    DUMP_STACK: {"permissions": ["P"], "categories": ["C"]},
                    "Ljava/lang/Thread;->start()V": {"categories": ["C"]},
                    SYSTEM_OUT: {"categories": ["F"]},
                },
            }
        )
    )
    return str(tmp_path)


def _report(dk, d):
    return dexllm.summarize_capabilities(dk, app_only=False, data_dir=d)


def test_capability_counts_do_not_double(once, dup, catalog_dir):
    # The baseline is the same session with each source loaded ONCE, in order —
    # `behind_other` contributes OTHER's own touches, which are not duplicates.
    base = dexllm.DexKit(list(dict.fromkeys(dup.sources())))
    a, b = _report(base, catalog_dir), _report(dup, catalog_dir)
    assert a.total_call_sites == 2 and a.shadowed_touches == 0
    assert a.total_field_accesses > 10, "premise: the fixture reads System.out"
    assert b.total_call_sites == a.total_call_sites
    assert b.total_field_accesses == a.total_field_accesses
    # exactly FIXTURE's second copy is shadowed — OTHER's own touches are not
    c = _report(once, catalog_dir)
    want = c.total_call_sites + c.total_field_accesses
    assert b.shadowed_touches == want
    assert dict(b.categories) == dict(a.categories)
    assert dict(b.permissions) == dict(a.permissions)
    assert b.by_caller == a.by_caller
    sdk = dexllm.sdk.DexKitAdapter(dup.sources())
    from unittest import mock

    with mock.patch.dict(os.environ, {"DEXLLM_DATA_DIR": catalog_dir}):
        dexllm.datadir.clear_data_caches()
        assert sdk.summarize_capabilities(app_only=False).shadowed_touches == want
        from dexllm import tools

        out = tools.execute("summarize_capabilities", {"app_only": False}, dup)
        assert out["shadowed_touches"] == want and out["total_call_sites"] == 2
    dexllm.datadir.clear_data_caches()


# ── the copies DIFFER: a call present in one copy only ──────────────────────


def _nop_call(tmp_path: Path, src: Path, method: str, target: str, name: str) -> str:
    """Write ``src`` with the single call to ``target`` inside ``method`` nopped.

    Located through the PRODUCT (the site's offset), patched in the raw bytes,
    length-preserving, verdict asserted in both modes.
    """
    dk = dexllm.DexKit(str(src))
    sites = [s for s in dk.find_call_sites_to(target) if s.caller_descriptor == method]
    assert len(sites) == 1, (method, target, sites)
    off, op = sites[0].bytecode_offset, sites[0].invoke_opcode
    raw = bytearray(src.read_bytes())
    (co,) = [c for d, c, *_ in _code_items(bytes(raw)) if d == method]
    at = co + 16 + off
    assert raw[at] == op, (hex(raw[at]), hex(op))
    struct.pack_into("<3H", raw, at, 0, 0, 0)
    out = tmp_path / name
    out.write_bytes(bytes(raw))
    for lenient in (False, True):
        assert all(r["valid"] for r in dexllm.verify(str(out), lenient=lenient))
    return str(out)


def test_a_call_only_in_the_shadowed_copy_is_kept_and_marked(tmp_path, catalog_dir):
    dump = _nop_call(tmp_path, FIXTURE, FAIL, DUMP_STACK, "dump.dex")
    dk = dexllm.DexKit([dump, str(FIXTURE)])  # the dump wins, as prefer=True does
    sites = dk.find_call_sites_to(DUMP_STACK)
    assert [(s.caller_dex_id, s.shadowed) for s in sites] == [(1, True)]
    # the view that RUNS agrees: the resolving body makes no such call
    assert "dumpStack" not in dk.decompile_method(FAIL)
    rep = _report(dk, catalog_dir)
    assert DUMP_STACK not in {h.api_descriptor for h in rep.api_usages}
    assert rep.permissions["P"] == 0
    reads = rep.total_field_accesses
    # dumpStack + the shadowed copy of Thread.start + every shadowed System.out read
    assert rep.shadowed_touches == 1 + 1 + reads
    # and the other way round the same call is live
    dk2 = dexllm.DexKit([str(FIXTURE), dump])
    assert [
        (s.caller_dex_id, s.shadowed) for s in dk2.find_call_sites_to(DUMP_STACK)
    ] == [(0, False)]
    assert _report(dk2, catalog_dir).permissions["P"] == 1


@pytest.mark.parametrize(
    "fixture, cls, ctor_caller",
    [
        ("permissive-tls.dex", "LPermissiveTrust;", "LInstaller;"),
        ("component-bases.dex", "Lcom/example/cb/ComponentBases$NewedService;", None),
    ],
)
def test_a_construction_only_in_the_shadowed_copy_is_not_constructed_in(
    tmp_path, fixture, cls, ctor_caller
):
    src = DATA / fixture
    dk = dexllm.DexKit(str(src))
    ctor = next(m for m in dk.list_class_methods(cls) if "-><init>(" in m)
    sites = dk.find_call_sites_to(ctor)
    sites = [
        s
        for s in sites
        if not s.caller_descriptor.startswith(cls + "->")
        and (ctor_caller is None or s.caller_descriptor.startswith(ctor_caller))
    ]
    assert len(sites) == 1, [s.caller_descriptor for s in sites]
    caller = sites[0].caller_descriptor
    dump = _nop_call(tmp_path, src, caller, ctor, "dump_" + fixture)
    shadow = dexllm.DexKit([dump, str(src)])
    live = dexllm.DexKit([str(src), dump])
    if fixture.startswith("permissive"):
        rows = dexllm.detect_permissive_tls
        key = "class_descriptor"
    else:
        rows = dexllm.find_component_subclasses
        key = "descriptor"

    def get(d):
        return {r[key]: r["constructed_in"] for r in rows(d)}

    assert caller in get(live)[cls]
    assert caller not in get(shadow)[cls]


def test_the_permission_joins_drop_a_shadowed_only_caller(tmp_path, loadable_apks):
    """C++ ``permission_callers`` and both Python joins, on a real permission API.

    No committed fixture calls a permission-gated API, so this crafts the
    bundled corpus: a dangerous-permission call with one caller is nopped in a
    dump of dex 0, and the dump is loaded in front of the original.
    """
    apk = next((p for p in loadable_apks if "a2dp.Vol" in p), None)
    require_corpus_shape(
        apk is not None, "a2dp.Vol in the corpus", "a2dp.Vol is bundled"
    )
    dk = dexllm.DexKit(apk)
    rows = dexllm.dangerous_permission_api_callers(dk)
    pick = None
    for perm, apis in sorted(rows.items()):
        for r in apis:
            for d in r["descriptors"]:
                sites = dk.find_call_sites_to(d)
                if len(sites) == 1 and sites[0].caller_dex_id == 0:
                    pick = (perm, d, sites[0].caller_descriptor)
                    break
            if pick:
                break
        if pick:
            break
    require_corpus_shape(
        pick is not None, "a single-caller permission API", "a2dp has one"
    )
    perm, desc, caller = pick
    d0 = tmp_path / "d0.dex"
    d0.write_bytes(bytes(dk.extract_dex(0)["bytes"]))
    dump = _nop_call(tmp_path, d0, caller, desc, "dump.dex")
    shadow = dexllm.DexKit([dump, apk])
    live = dexllm.DexKit([str(d0), apk])

    # Per API, not per caller: the picked caller may also make OTHER permission
    # calls, which stay live; only the row for the nopped descriptor moves.
    def _of(rows):
        return {c for r in rows if desc in r["descriptors"] for c in r["callers"]}

    def callers_cpp(d):
        return _of(r for g in d.permission_callers(False) for r in g["apis"])

    def callers_py(d):
        found = dexllm.dangerous_permission_api_callers(d, app_only=False)
        return _of(r for apis in found.values() for r in apis)

    def callers_py2(d):
        found = dexllm.permission_api_callers(d, app_only=False)
        return _of(r for g in found for r in g["apis"])

    for f in (callers_cpp, callers_py, callers_py2):
        assert caller in f(live), f.__name__
        assert caller not in f(shadow), f.__name__


def test_a_cross_dex_accessor_is_judged_in_its_own_dex(loadable_apks):
    """The field xref walks an accessor in its ORIGIN dex, not the declaring one.

    The core aggregates a field's accessors into the dex that declares the field,
    tagged with the dex each accessor lives in. Judging such an accessor against
    the DECLARING dex marks it wrong, and no committed fixture has an accessor in
    another dex from its field — every one is single-dex or has no cross-dex
    access — so this needs a multidex sample, loaded twice.
    """
    found = None
    for apk in loadable_apks:
        if dexllm.identify(apk).get("dex_count", 0) < 2:
            continue
        once = dexllm.DexKit(apk)
        fields = sorted(set(once.list_fields()))[:3000]
        rows = []
        for f in fields:
            home = once.locate_class_dex(_cls(f))
            if home < 0:
                continue
            rows += [(f, home, s.dex_id) for s in once.find_field_read_sites(f)]
        if any(d != home for _f, home, d in rows):
            found = (apk, fields)
            break
    require_corpus_shape(
        found is not None,
        "a multidex sample with a cross-dex field accessor",
        "app-prod-debug.apk / multiple_locale_appname_test.apk carry hundreds",
    )
    apk, fields = found
    dup = dexllm.DexKit([apk, apk])
    first = _first_declaring(dup)
    n = cross = 0
    for f in fields:
        home = dup.locate_class_dex(_cls(f))
        for s in dup.find_field_read_sites(f) + dup.find_field_write_sites(f):
            assert s.shadowed == (first[_cls(s.method_descriptor)] != s.dex_id), (
                f,
                s.method_descriptor,
                s.dex_id,
            )
            n += 1
            cross += home >= 0 and s.dex_id % (dup.dex_count() // 2) != home
    assert cross > 50, (apk, n, cross)


class _Site:
    def __init__(self, caller, shadowed):
        self.caller_descriptor = caller
        self.shadowed = shadowed


class _StubDk:
    def __init__(self, sites):
        self._sites = sites

    def find_call_sites_to(self, descriptor):
        return self._sites.get(descriptor, [])

    def find_field_read_sites(self, descriptor):
        return []


def test_the_shadowed_filter_runs_before_app_only(catalog_dir):
    """A shadowed LIBRARY caller is shadowed, not dropped by ``app_only``.

    ``dropped_touches`` counts library callers among the sites that execute; if
    ``app_only`` ran first, a session loading the APK twice would report every
    library caller twice there and the shadowed count would come up short.
    """
    lib, app = "Landroidx/core/X;->m()V", "Lcom/app/A;->m()V"
    dk = _StubDk(
        {
            DUMP_STACK: [
                _Site(lib, False),
                _Site(lib, True),
                _Site(app, False),
                _Site(app, True),
            ]
        }
    )
    r = dexllm.summarize_capabilities(dk, app_only=True, data_dir=catalog_dir)
    assert (r.total_call_sites, r.dropped_touches, r.shadowed_touches) == (1, 1, 2)
    r = dexllm.summarize_capabilities(dk, app_only=False, data_dir=catalog_dir)
    assert (r.total_call_sites, r.dropped_touches, r.shadowed_touches) == (2, 0, 2)


# The C++ ``PermissionCallers`` join and the two ``dangerous_api`` joins can only
# be exercised behaviourally on a permission-gated API, which no committed fixture
# calls, so the behavioural case above skips in the corpus-less CI leg. These pins
# are the CI half: weaker (a present-but-wrong line passes), and they say so.
_SRC = Path(__file__).resolve().parents[1]


def _strip(path: str) -> str:
    """Source with comments removed and whitespace normalised (a re-wrap still matches)."""
    text = (_SRC / path).read_text()
    if path.endswith(".py"):
        import io
        import tokenize

        toks = tokenize.generate_tokens(io.StringIO(text).readline)
        text = tokenize.untokenize(
            (t.type, t.string) for t in toks if t.type != tokenize.COMMENT
        )
    else:
        from test_arg_opcode_coverage import _strip_comments

        text = _strip_comments(text)
    return "".join(text.split())


@pytest.mark.parametrize(
    "path, loop, filt, count",
    [
        (
            "native/core_ext/analysis.cpp",
            "for (const auto& site : ext.FindCallSitesToApi(desc)) {",
            "if (site.shadowed) continue;",
            1,
        ),
        (
            "src/dexllm/dangerous_api.py",
            "for site in dk.find_call_sites_to(desc):",
            "if site.shadowed: continue",
            2,
        ),
    ],
)
def test_the_permission_joins_filter_before_they_collect(path, loop, filt, count):
    """The filter is the FIRST statement of every caller loop, in every join.

    First statement, not merely present: a filter wrapped in dead code
    (``if (false) {…}``) or placed after the collect keeps the substring and drops
    nothing. The loop COUNT is pinned too, so a respelled loop cannot leave the pin
    looking at the other one alone.
    """
    src = _strip(path)
    norm = ["".join(x.split()) for x in (loop, filt)]
    loop, filt = norm
    starts = [i for i in range(len(src)) if src.startswith(loop, i)]
    assert len(starts) == count, (path, len(starts))
    # every call of the site API in the file is one of these loops
    api = loop.split("in" if path.endswith(".py") else ":", 1)[1]
    api = api.split("(", 1)[0]
    assert src.count(api + "(") == count, (path, api)
    for i in starts:
        assert src.startswith(filt, i + len(loop)), (path, src[i : i + 200])
