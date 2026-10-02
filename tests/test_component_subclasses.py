"""Component-subclass detection — every class that CAN be used as a component.

Every behavioural case runs on ``tests/data/component-bases.dex``, which is
COMMITTED and AUTHORED (its source sits beside it), so it holds in the
corpus-less CI leg and under any ``$DEXLLM_TEST_APK`` narrowing. The bundled
corpus cannot carry these guards: it has no depth-2 chain through an app-side
abstract class, no ``ZygotePreload`` implementor, no class whose parent is in
neither the dex nor the SDK, and no ``Service`` subclass without a public
no-arg constructor — and a fixture where the shipped predicate and the plausible
wrong one AGREE proves nothing.

The expected rows are pinned as a LITERAL table, both directions: a row that
appears which should not (``ViewSub``, ``ThreadSub``, the ``MyPreload``
interface) fails as loudly as one that vanishes. A guard parametrised over the
production table cannot catch an EDIT of the table, so the roots and the eight
corpus intermediates are literals too.
"""

from __future__ import annotations

import glob
import inspect
import os
import pathlib

import pytest
from conftest import REPO_ROOT, corpus_is_narrowed, require_corpus_shape

import dexllm
from dexllm.components import (
    RESOLVED,
    UNRESOLVED,
    find_component_subclasses,
    load_component_bases,
)

FIXTURE = REPO_ROOT / "tests" / "data" / "component-bases.dex"
P = "Lcom/example/cb/ComponentBases$"

# The nine roots an AndroidManifest.xml can name, and the kind each is the root
# OF. Eight classes and one interface (checked with isAssignableFrom at
# AppZygoteInit.java:88, where every class root is a cast at its newInstance()
# site). Pinned as a literal: the bundled table is what this guards.
_ROOTS = {
    "Landroid/app/Activity;": "activity",
    "Landroid/app/Service;": "service",
    "Landroid/content/BroadcastReceiver;": "receiver",
    "Landroid/content/ContentProvider;": "provider",
    "Landroid/app/Application;": "application",
    "Landroid/app/backup/BackupAgent;": "backup_agent",
    "Landroid/app/Instrumentation;": "instrumentation",
    "Landroid/app/AppComponentFactory;": "app_component_factory",
    "Landroid/app/ZygotePreload;": "zygote_preload",
}

# The framework intermediates the corpus measurement found as DIRECT parents of
# app classes (25 classes across 21 APKs) — the 0-of-25 a five-root dex walk
# finds, and the reason the table exists. Each must be in the bundled table at
# the stated depth.
_CORPUS_INTERMEDIATES = {
    "Landroid/service/media/MediaBrowserService;": ("service", 1),
    "Landroid/preference/PreferenceActivity;": ("activity", 2),
    "Landroid/app/ListActivity;": ("activity", 1),
    "Landroid/app/IntentService;": ("service", 1),
    "Landroid/service/notification/NotificationListenerService;": ("service", 1),
    "Landroid/appwidget/AppWidgetProvider;": ("receiver", 1),
    "Landroid/service/wallpaper/WallpaperService;": ("service", 1),
    "Landroid/app/TabActivity;": ("activity", 2),
}

# descriptor -> (root_kind, resolution, is_abstract, is_instantiable, chain)
_EXPECTED = {
    P
    + "PlainActivity;": ("activity", RESOLVED, False, True, ["Landroid/app/Activity;"]),
    P
    + "BaseActivity;": ("activity", RESOLVED, True, False, ["Landroid/app/Activity;"]),
    P
    + "LeafActivity;": (
        "activity",
        RESOLVED,
        False,
        True,
        [P + "BaseActivity;", "Landroid/app/Activity;"],
    ),
    P
    + "MyTile;": (
        "service",
        RESOLVED,
        False,
        True,
        ["Landroid/service/quicksettings/TileService;", "Landroid/app/Service;"],
    ),
    P
    + "Widget;": (
        "receiver",
        RESOLVED,
        False,
        True,
        [
            "Landroid/appwidget/AppWidgetProvider;",
            "Landroid/content/BroadcastReceiver;",
        ],
    ),
    P + "CtorService;": ("service", RESOLVED, False, False, ["Landroid/app/Service;"]),
    P + "PkgService;": ("service", RESOLVED, False, False, ["Landroid/app/Service;"]),
    P + "PkgClass;": ("service", RESOLVED, False, False, ["Landroid/app/Service;"]),
    P + "NewedService;": ("service", RESOLVED, False, True, ["Landroid/app/Service;"]),
    P + "SuperOnly;": ("service", RESOLVED, False, True, ["Landroid/app/Service;"]),
    P
    + "SubOfSuperOnly;": (
        "service",
        RESOLVED,
        False,
        True,
        [P + "SuperOnly;", "Landroid/app/Service;"],
    ),
    P
    + "Registrar$1;": (
        "receiver",
        RESOLVED,
        False,
        False,
        ["Landroid/content/BroadcastReceiver;"],
    ),
    P
    + "Preload;": (
        "zygote_preload",
        RESOLVED,
        False,
        True,
        ["Landroid/app/ZygotePreload;"],
    ),
    P
    + "ViaIface;": (
        "zygote_preload",
        RESOLVED,
        False,
        True,
        [P + "MyPreload;", "Landroid/app/ZygotePreload;"],
    ),
    P + "MyApp;": ("application", RESOLVED, False, True, ["Landroid/app/Application;"]),
    P
    + "MyBackup;": (
        "backup_agent",
        RESOLVED,
        False,
        True,
        ["Landroid/app/backup/BackupAgent;"],
    ),
    P
    + "MyFactory;": (
        "app_component_factory",
        RESOLVED,
        False,
        True,
        ["Landroid/app/AppComponentFactory;"],
    ),
    P
    + "MyInstr;": (
        "instrumentation",
        RESOLVED,
        False,
        True,
        ["Landroid/app/Instrumentation;"],
    ),
    # BOTH roots hold on PreloadActivity; the class root wins (it decides how
    # the framework instantiates the class), the interface root is a fallback
    P
    + "PreloadActivity;": (
        "activity",
        RESOLVED,
        False,
        True,
        ["Landroid/app/Activity;"],
    ),
    P + "Delegating;": ("service", RESOLVED, False, True, ["Landroid/app/Service;"]),
    P
    + "Rcv;": (
        "receiver",
        RESOLVED,
        False,
        True,
        ["Landroid/content/BroadcastReceiver;"],
    ),
    P + "PrivCtor;": ("service", RESOLVED, False, False, ["Landroid/app/Service;"]),
    P + "TwiceSvc;": ("service", RESOLVED, False, True, ["Landroid/app/Service;"]),
    P + "Orphan;": ("", UNRESOLVED, False, True, ["Lcom/example/missing/Vanished;"]),
}

# Declared in the fixture and NOT candidates — each for a different reason.
_NOT_ROWS = {
    P + "ViewSub;": "extends android.view.View — a known SDK class, not a base",
    P + "ThreadSub;": "extends java.lang.Thread — java.*, not a base",
    P + "MyPreload;": "an INTERFACE extending the interface root is a type",
    P + "Factory;": "constructs a component; is not one",
    P + "Registrar;": "registers a component; is not one",
    P + "Holder;": "registers a component from its constructor; is not one",
    P + "Twice;": "constructs a component twice; is not one",
}


@pytest.fixture(scope="module")
def fdk():
    """The committed fixture, loaded."""
    if not FIXTURE.is_file():  # pragma: no cover - the file is committed
        pytest.skip("tests/data/component-bases.dex missing")
    return dexllm.DexKit(str(FIXTURE))


@pytest.fixture(scope="module")
def rows(fdk):
    rs = find_component_subclasses(fdk)
    return rs, {r["descriptor"]: r for r in rs}


# ── the bundled table ────────────────────────────────────────────────────────


def test_the_roots_are_the_nine_manifest_nameable_types():
    """Both directions: a dropped root and an added one fail."""
    table = load_component_bases()
    assert {d: r["root_kind"] for d, r in table["roots"].items()} == _ROOTS
    assert table["roots"]["Landroid/app/ZygotePreload;"]["kind"] == "interface"
    assert all(
        r["kind"] == "class"
        for d, r in table["roots"].items()
        if d != "Landroid/app/ZygotePreload;"
    )


def test_every_base_chain_reaches_its_root_at_its_depth():
    """The invariant the detector's framework tail rests on."""
    bases = load_component_bases()["bases"]
    assert len(bases) == 152 + 9, "152 subclasses + 9 roots (aosp_data_set layer 13)"
    for desc, e in bases.items():
        cur, steps = desc, 0
        while bases[cur]["depth"] > 0:
            cur = bases[cur]["direct_super"]
            steps += 1
            assert cur in bases, f"{desc}: chain leaves the table at {cur}"
        assert (cur, steps) == (e["root"], e["depth"]), desc
        assert e["root"] in _ROOTS and e["root_kind"] == _ROOTS[e["root"]]


def test_the_corpus_intermediates_are_in_the_table():
    """The 8 framework parents the corpus walk found; a 5-root walk finds 0."""
    bases = load_component_bases()["bases"]
    for desc, (kind, depth) in _CORPUS_INTERMEDIATES.items():
        assert desc in bases, desc
        assert (bases[desc]["root_kind"], bases[desc]["depth"]) == (kind, depth), desc
        assert bases[desc]["api_surface"] == "public", desc


def test_the_sdk_class_list_is_what_separates_unresolved_from_not_a_candidate():
    """A parent absent from the dex is UNKNOWN only if it is also absent here."""
    table = load_component_bases()
    sdk = table["_sdk_set"]
    assert len(sdk) >= 9_000, "the whole public+system+module-lib catalog"
    assert set(_ROOTS) <= sdk
    assert "Landroid/view/View;" in sdk and "Ljava/lang/Thread;" in sdk
    # the walk has no Object special case: `extends Object` ends at the SDK arm,
    # so Object's presence here is load-bearing, not incidental
    assert "Ljava/lang/Object;" in sdk
    # nested classes are spelled with `$`, the dex way — a dotted spelling would
    # never match a descriptor and the whole list would be dead
    assert "Landroid/app/Notification$Builder;" in sdk
    assert not any("." in d for d in sdk)
    assert "Lcom/example/missing/Vanished;" not in sdk


def test_the_bundled_table_is_what_the_generator_produces():
    """A hand edit to the JSON drifts from the dataset on the next regen."""
    root = os.environ.get("DEXLLM_AOSP_DATASET") or str(
        pathlib.Path.home() / "Project" / "aosp_data_set"
    )
    if not (pathlib.Path(root) / "component_bases.tsv").is_file():
        pytest.skip("no aosp_data_set checkout at layer 13")
    import subprocess
    import sys
    import tempfile

    gen = REPO_ROOT / "scripts" / "gen_component_data.py"
    bundled = REPO_ROOT / "src" / "dexllm" / "data" / "component_bases.json"
    with tempfile.TemporaryDirectory() as td:
        out = pathlib.Path(td) / "component_bases.json"
        r = subprocess.run(
            [sys.executable, str(gen), root, str(out)], capture_output=True, text=True
        )
        assert r.returncode == 0, r.stderr
        assert out.read_bytes() == bundled.read_bytes(), (
            "the committed table is not what the generator produces from the "
            "dataset at " + root
        )


# ── the rows ─────────────────────────────────────────────────────────────────


def test_the_fixture_declares_every_shape(fdk):
    """Non-vacuity: a rebuilt fixture that lost a class fails here, not later."""
    declared = set(fdk.list_classes())
    assert set(_EXPECTED) <= declared
    assert set(_NOT_ROWS) <= declared


def test_the_rows_are_exactly_the_expected_set(rows):
    """Set equality BOTH ways: an extra row is as wrong as a missing one."""
    rs, by = rows
    assert set(by) == set(
        _EXPECTED
    ), f"missing {set(_EXPECTED) - set(by)} | extra {set(by) - set(_EXPECTED)}"
    assert len(rs) == len(by), "a descriptor yielded two rows"
    for desc, (kind, res, abstract, ctor, tail) in _EXPECTED.items():
        r = by[desc]
        assert r["root_kind"] == kind, desc
        assert r["resolution"] == res, desc
        assert r["is_abstract"] is abstract, desc
        assert r["is_instantiable"] is ctor, desc
        assert r["chain_descriptors"] == [desc] + tail, desc
        assert r["root_descriptor"] == (tail[-1] if res == RESOLVED else ""), desc
        assert r["dex_id"] == 0


@pytest.mark.parametrize("desc", sorted(_NOT_ROWS))
def test_a_declared_non_candidate_yields_no_row(rows, desc):
    assert desc not in rows[1], _NOT_ROWS[desc]


def test_a_chain_through_an_app_intermediate_lists_the_intermediate(rows):
    r = rows[1][P + "LeafActivity;"]
    assert r["chain_descriptors"][1] == P + "BaseActivity;"
    assert rows[1][P + "BaseActivity;"]["is_abstract"] is True


def test_a_chain_through_a_framework_intermediate_is_the_tables_whole_point(rows):
    """MyTile's parent is in no dex; only the table says TileService is a Service."""
    r = rows[1][P + "MyTile;"]
    assert r["chain_descriptors"] == [
        P + "MyTile;",
        "Landroid/service/quicksettings/TileService;",
        "Landroid/app/Service;",
    ]
    assert r["root_kind"] == "service"


def test_an_unknown_parent_is_reported_unresolved_not_dropped(fdk, rows):
    """The parent is in no dex AND not in the SDK: a candidate of unknown kind."""
    r = rows[1][P + "Orphan;"]
    parent = r["chain_descriptors"][-1]
    assert parent == "Lcom/example/missing/Vanished;"
    assert fdk.locate_class_dex(parent) == -1
    assert parent not in load_component_bases()["_sdk_set"]
    assert r["resolution"] == UNRESOLVED
    assert r["root_kind"] == "" and r["root_descriptor"] == ""


def test_an_interface_root_is_reached_through_implements(rows):
    """ZygotePreload is the one interface root; isAssignableFrom, not a cast."""
    assert rows[1][P + "Preload;"]["chain_descriptors"] == [
        P + "Preload;",
        "Landroid/app/ZygotePreload;",
    ]
    via = rows[1][P + "ViaIface;"]
    assert via["chain_descriptors"] == [
        P + "ViaIface;",
        P + "MyPreload;",
        "Landroid/app/ZygotePreload;",
    ]
    assert P + "MyPreload;" not in rows[1], "an interface is a type, never a component"


def test_is_instantiable_needs_both_halves(rows):
    """PUBLIC and NO-ARG: a package ctor and an (int) ctor each fail one half."""
    by = rows[1]
    assert by[P + "PlainActivity;"]["is_instantiable"] is True
    assert by[P + "CtorService;"]["is_instantiable"] is False
    assert by[P + "PkgService;"]["is_instantiable"] is False
    assert by[P + "Registrar$1;"]["is_instantiable"] is False


def test_constructed_in_excludes_a_subclass_super_call(fdk, rows):
    """super() reaches the constructor exactly like new; only the header tells."""
    by = rows[1]
    assert by[P + "NewedService;"]["constructed_in"] == [
        P + "Factory;->make()Landroid/app/Service;"
    ]
    assert by[P + "SuperOnly;"]["constructed_in"] == []
    # premise: the subclass's <init> DOES call SuperOnly.<init>, so the empty
    # list above is the filter working, not an absent call
    callers = {
        s.caller_descriptor for s in fdk.find_call_sites_to(P + "SuperOnly;-><init>()V")
    }
    assert P + "SubOfSuperOnly;-><init>()V" in callers


def test_a_construction_inside_an_unrelated_constructor_is_kept(rows):
    """The `<init>` exclusion is for a SUBCLASS's super(); Holder is not one.

    An adversarial review's mutant dropped EVERY `<init>` caller and passed the
    whole suite, because no fixture class constructed a component from a
    constructor that is not a subclass's. `Holder(Context)` does, and it is the
    dynamic-registration shape in its most common real form.
    """
    r = rows[1][P + "Rcv;"]
    assert r["constructed_in"] == [P + "Holder;-><init>(Landroid/content/Context;)V"]


def test_is_instantiable_checks_the_constructor_too(rows):
    """A PUBLIC class with a PRIVATE no-arg constructor: the class half passes,
    the constructor half (ART `java_lang_Class.cc:925`, VerifyAccess) refuses.
    `PkgClass` and `PkgService` short-circuit on the class half, so without this
    class the constructor check was unguarded (review mutant: 40 passed).
    """
    assert rows[1][P + "PrivCtor;"]["is_instantiable"] is False
    assert rows[1][P + "PrivCtor;"]["is_abstract"] is False


def test_constructed_in_is_deduplicated_and_sorted(fdk, rows):
    """Two `new TwiceSvc()` sites in ONE method yield that method once."""
    r = rows[1][P + "TwiceSvc;"]
    assert r["constructed_in"] == [P + "Twice;->make(Z)Landroid/app/Service;"]
    sites = [
        s
        for s in fdk.find_call_sites_to(P + "TwiceSvc;-><init>()V")
        if s.caller_descriptor == P + "Twice;->make(Z)Landroid/app/Service;"
    ]
    assert len(sites) == 2, "premise: the method constructs it at TWO sites"
    for row in rows[0]:
        assert row["constructed_in"] == sorted(set(row["constructed_in"]))


def test_a_dynamically_registered_receiver_is_the_constructed_in_shape(rows):
    r = rows[1][P + "Registrar$1;"]
    assert r["constructed_in"] == [P + "Registrar;->go(Landroid/content/Context;)V"]
    assert r["is_instantiable"] is False


def test_with_xref_false_leaves_constructed_in_empty(fdk):
    assert all(
        r["constructed_in"] == []
        for r in find_component_subclasses(fdk, with_xref=False)
    )


def test_rows_are_sorted_by_descriptor(rows):
    rs = rows[0]
    assert [r["descriptor"] for r in rs] == sorted(r["descriptor"] for r in rs)


def test_a_class_declared_in_two_dexes_is_reported_once(fdk):
    """A packer session holds the dump AND the original; the row is first-wins."""
    twice = dexllm.DexKit([str(FIXTURE), str(FIXTURE)])
    assert twice.dex_count() == 2
    rs = find_component_subclasses(twice, with_xref=False)
    assert len(rs) == len(_EXPECTED)
    assert all(r["dex_id"] == 0 for r in rs)


def _craft_superclass_cycle(tmp_path):
    """SuperOnly <-> NewedService: each class_def's superclass_idx set to the other.

    IN PLACE and length-preserving (two u4 fields), so nothing but the two
    parents moved. superclass_idx is at +8 of the 32-byte class_def
    (class_idx, access_flags, superclass_idx, ...).
    """
    import struct

    raw = bytearray(FIXTURE.read_bytes())

    def u4(o):
        return struct.unpack_from("<I", raw, o)[0]

    sid_off = u4(0x3C)
    tid_off, tid_n = u4(0x44), u4(0x40)
    cd_off, cd_n = u4(0x64), u4(0x60)

    def string(i):
        o = u4(sid_off + 4 * i)
        n = shift = 0
        while True:
            b = raw[o]
            o += 1
            n |= (b & 0x7F) << shift
            shift += 7
            if not b & 0x80:
                break
        return raw[o : o + n].decode("utf-8", "replace")

    types = {string(u4(tid_off + 4 * i)): i for i in range(tid_n)}
    a, b = types[P + "SuperOnly;"], types[P + "NewedService;"]
    defs = {u4(cd_off + 32 * i): cd_off + 32 * i for i in range(cd_n)}
    assert (
        u4(defs[a] + 8) == types["Landroid/app/Service;"]
    ), "premise: both extend Service"
    assert u4(defs[b] + 8) == types["Landroid/app/Service;"]
    struct.pack_into("<I", raw, defs[a] + 8, b)
    struct.pack_into("<I", raw, defs[b] + 8, a)
    out = tmp_path / "cycle.dex"
    out.write_bytes(raw)
    assert len(raw) == FIXTURE.stat().st_size
    return out


def test_a_superclass_cycle_is_gate_legal_and_the_walk_terminates(tmp_path):
    """A class_def naming a cycle verifies VALID in both modes (ART's structural
    verifier does not check it either — link time does), so the walk must not
    recurse forever on it. Run in a SUBPROCESS: a walk that does recurse dies
    with RecursionError, and the three cycle-bound classes must simply not be
    rows — a cycle cannot be linked, so nothing in it is a component.
    """
    import subprocess
    import sys

    crafted = _craft_superclass_cycle(tmp_path)
    for lenient in (False, True):
        assert dexllm.verify(str(crafted), lenient=lenient)[0]["valid"], lenient
    code = (
        "import dexllm, json, sys\n"
        "dk = dexllm.DexKit(sys.argv[1])\n"
        "rows = dexllm.find_component_subclasses(dk, with_xref=False)\n"
        "print(json.dumps(sorted(r['descriptor'] for r in rows)))\n"
    )
    r = subprocess.run(
        [sys.executable, "-c", code, str(crafted)],
        capture_output=True,
        text=True,
        timeout=120,
    )
    assert r.returncode == 0, r.stderr[-400:]
    import json

    got = set(json.loads(r.stdout.strip().splitlines()[-1]))
    cycle_bound = {P + "SuperOnly;", P + "NewedService;", P + "SubOfSuperOnly;"}
    assert not (got & cycle_bound), got & cycle_bound
    # and nothing else moved: every other expected row is still there
    assert got == set(_EXPECTED) - cycle_bound


# ── list_class_headers ───────────────────────────────────────────────────────


def test_class_headers_agree_with_the_per_class_summary(fdk):
    """The bulk record and the per-class one read the same class_def fields."""
    headers = {h.descriptor: h for h in fdk.list_class_headers()}
    assert set(headers) == set(fdk.list_classes())
    for desc, h in headers.items():
        s = fdk.get_class_summary(desc)
        assert h.superclass_descriptor == s.superclass_descriptor, desc
        assert list(h.interface_descriptors) == list(s.interface_descriptors), desc
        assert h.access_flags == s.access_flags, desc
        assert h.dex_id == s.dex_id == 0


def test_class_headers_carry_a_framework_superclass(fdk):
    """The parent is a type_id of the declaring dex, declared or not."""
    h = next(h for h in fdk.list_class_headers() if h.descriptor == P + "MyTile;")
    assert h.superclass_descriptor == "Landroid/service/quicksettings/TileService;"
    assert fdk.locate_class_dex(h.superclass_descriptor) == -1
    p = next(h for h in fdk.list_class_headers() if h.descriptor == P + "Preload;")
    assert list(p.interface_descriptors) == ["Landroid/app/ZygotePreload;"]


def test_class_headers_are_one_row_per_declaration(fdk):
    """Like list_classes: a descriptor in two dexes appears twice, each dex_id."""
    twice = dexllm.DexKit([str(FIXTURE), str(FIXTURE)])
    hs = twice.list_class_headers()
    assert len(hs) == 2 * len(fdk.list_class_headers())
    assert sorted({h.dex_id for h in hs}) == [0, 1]


def test_an_interface_cycle_does_not_poison_a_reachable_type():
    """`X implements Z`, `Z implements X, R`: X DOES reach R through Z.

    A memoised DFS that enters at Z abandons X (its path leads back into the
    stack) and records X as unreachable — measured on a model of the first cut.
    Interface cycles are invalid Java, but the structural verifier does not
    refuse them, so the answer must not depend on visit order. Pure, so no dex
    is needed to pin it.
    """
    from dexllm.components import interface_root_paths

    roots = frozenset({"LR;"})
    cyc = {"LZ;": ["LX;", "LR;"], "LX;": ["LZ;"], "LC;": ["LX;"]}
    got = interface_root_paths(cyc, roots)
    assert got["LZ;"] == ["LR;"]
    assert got["LX;"] == ["LZ;", "LR;"]
    assert got["LC;"] == ["LX;", "LZ;", "LR;"]
    # order-independence: the same map with the keys reversed gives the same answer
    rev = dict(reversed(list(cyc.items())))
    assert interface_root_paths(rev, roots) == got
    # a pure cycle with no root reaches nothing
    assert interface_root_paths({"LA;": ["LB;"], "LB;": ["LA;"]}, roots) == {}


def test_a_class_root_wins_over_the_interface_root(fdk, rows):
    """`extends Activity implements ZygotePreload` is an activity row.

    Both roots hold and a row carries one; the class root says how the
    framework instantiates the class, so it takes precedence. The premise —
    the class DOES declare the interface — is asserted so the row is a decision
    and not an absent edge.
    """
    r = rows[1][P + "PreloadActivity;"]
    assert r["root_kind"] == "activity"
    assert r["chain_descriptors"] == [P + "PreloadActivity;", "Landroid/app/Activity;"]
    h = next(
        h for h in fdk.list_class_headers() if h.descriptor == P + "PreloadActivity;"
    )
    assert "Landroid/app/ZygotePreload;" in h.interface_descriptors


def test_a_this_delegation_is_not_a_construction(fdk, rows):
    """`Delegating() { this(1); }` reaches `<init>(I)V` through invoke-direct like
    `new` does; the caller being the class's OWN `<init>` is what excludes it.
    """
    assert rows[1][P + "Delegating;"]["constructed_in"] == []
    callers = {
        s.caller_descriptor
        for s in fdk.find_call_sites_to(P + "Delegating;-><init>(I)V")
    }
    assert P + "Delegating;-><init>()V" in callers, "premise: this(1) IS a call"


def test_interface_paths_are_shortest_and_order_free():
    """The documented rule: a shortest path, not the first-declared route.

    `A implements B, C`, `B implements D`, `C implements R`, `D implements R`:
    A reaches R in two hops through C and three through B, so the row carries
    C although B is declared first.
    """
    from dexllm.components import interface_root_paths

    roots = frozenset({"LR;"})
    m = {"LA;": ["LB;", "LC;"], "LB;": ["LD;"], "LC;": ["LR;"], "LD;": ["LR;"]}
    got = interface_root_paths(m, roots)
    assert got["LA;"] == ["LC;", "LR;"]
    assert got["LB;"] == ["LD;", "LR;"] and got["LD;"] == ["LR;"]
    assert interface_root_paths(dict(reversed(list(m.items()))), roots) == got
    # a direct edge to the root is length 1 and beats any longer declared route
    assert interface_root_paths({"LB;": ["LD;", "LR;"], "LD;": ["LR;"]}, roots)[
        "LB;"
    ] == ["LR;"]


def test_a_long_interface_chain_is_linear(monkeypatch):
    """8,000 types in one reversed chain: the first cut's per-type fixed point
    took 7 s / 257 MB here (a correctness review measured it); the reverse BFS
    holds one pointer per type. The gate does not refuse such a dex.
    """
    import time

    from dexllm.components import interface_root_paths

    n = 8_000
    m = {f"LI{i};": [f"LI{i + 1};"] for i in range(n)}
    m[f"LI{n};"] = ["LR;"]
    t0 = time.perf_counter()
    got = interface_root_paths(m, frozenset({"LR;"}))
    assert len(got) == n + 1 and len(got["LI0;"]) == n + 1
    assert time.perf_counter() - t0 < 5.0


def _craft_no_superclass(tmp_path):
    """One class_def's superclass_idx set to NO_INDEX (0xFFFFFFFF), in place.

    The gate admits it (`dex_verifier.cpp`: `superclass_idx != kNoIndex &&
    ... >= type_count`), and `get_class_summary`'s `superclass_descriptor` read
    was an unchecked OOB on exactly that value until this guard existed.
    """
    import struct

    raw = bytearray(FIXTURE.read_bytes())

    def u4(o):
        return struct.unpack_from("<I", raw, o)[0]

    sid_off = u4(0x3C)
    tid_off, tid_n = u4(0x44), u4(0x40)
    cd_off, cd_n = u4(0x64), u4(0x60)

    def string(i):
        o = u4(sid_off + 4 * i)
        n = shift = 0
        while True:
            b = raw[o]
            o += 1
            n |= (b & 0x7F) << shift
            shift += 7
            if not b & 0x80:
                break
        return raw[o : o + n].decode("utf-8", "replace")

    types = {string(u4(tid_off + 4 * i)): i for i in range(tid_n)}
    target = types[P + "PlainActivity;"]
    defs = {u4(cd_off + 32 * i): cd_off + 32 * i for i in range(cd_n)}
    struct.pack_into("<I", raw, defs[target] + 8, 0xFFFFFFFF)
    out = tmp_path / "noindex.dex"
    out.write_bytes(raw)
    return out


def test_a_no_index_superclass_is_gate_legal_and_every_reader_survives(tmp_path):
    """verify() calls it valid in BOTH modes; the summary, the bulk header and
    the walk must all answer rather than fault. Judged by SUBPROCESS exit
    status — a try/except cannot see a SIGSEGV.
    """
    import json
    import subprocess
    import sys

    crafted = _craft_no_superclass(tmp_path)
    for lenient in (False, True):
        assert dexllm.verify(str(crafted), lenient=lenient)[0]["valid"], lenient
    code = (
        "import dexllm, json, sys\n"
        "P = 'Lcom/example/cb/ComponentBases$'\n"
        "dk = dexllm.DexKit(sys.argv[1])\n"
        "s = dk.get_class_summary(P + 'PlainActivity;').superclass_descriptor\n"
        "h = next(h for h in dk.list_class_headers() if h.descriptor == P + 'PlainActivity;')\n"
        "rows = {r['descriptor'] for r in dexllm.find_component_subclasses(dk, with_xref=False)}\n"
        "print(json.dumps([s, h.superclass_descriptor, P + 'PlainActivity;' in rows]))\n"
    )
    r = subprocess.run(
        [sys.executable, "-c", code, str(crafted)],
        capture_output=True,
        text=True,
        timeout=120,
    )
    assert r.returncode == 0, f"exit {r.returncode}: {r.stderr[-400:]}"
    summary_super, header_super, is_row = json.loads(r.stdout.strip().splitlines()[-1])
    assert summary_super == "" and header_super == ""
    assert is_row is False, "a class with no superclass reaches no root"


# ── the typed layers ─────────────────────────────────────────────────────────


def test_the_sdk_model_carries_every_field():
    from dexllm.sdk import ComponentSubclass, open_apk

    sdk = open_apk(str(FIXTURE))
    got = {c.descriptor: c for c in sdk.find_component_subclasses()}
    assert all(isinstance(c, ComponentSubclass) for c in got.values())
    t = got[P + "MyTile;"]
    assert t.root_kind == "service" and t.root_descriptor == "Landroid/app/Service;"
    assert t.chain_descriptors == (
        P + "MyTile;",
        "Landroid/service/quicksettings/TileService;",
        "Landroid/app/Service;",
    )
    assert t.resolution == RESOLVED and t.is_abstract is False
    assert t.is_instantiable is True and t.constructed_in == ()
    # the two bools are independent: PkgClass is NOT abstract and NOT
    # instantiable, so an adapter deriving one from the other is caught here
    pk = got[P + "PkgClass;"]
    assert pk.is_abstract is False and pk.is_instantiable is False
    assert got[P + "NewedService;"].constructed_in == (
        P + "Factory;->make()Landroid/app/Service;",
    )
    assert got[P + "Orphan;"].resolution == UNRESOLVED


def test_the_sdk_class_header_carries_every_field():
    from dexllm.sdk import ClassHeader, open_apk

    sdk = open_apk(str(FIXTURE))
    hs = {h.descriptor: h for h in sdk.list_class_headers()}
    h = hs[P + "Preload;"]
    assert isinstance(h, ClassHeader)
    assert h.superclass_descriptor == "Ljava/lang/Object;"
    assert h.interface_descriptors == ("Landroid/app/ZygotePreload;",)
    assert (h.access_flags & 0x1) == 0x1  # a public static nested class is ACC_PUBLIC
    assert h.dex_id == 0 and isinstance(h.class_idx, int)


def test_the_adapter_forwards_with_xref():
    """An adapter that ACCEPTS the flag and drops it type-checks and lies."""
    from dexllm.sdk import open_apk

    sdk = open_apk(str(FIXTURE))
    assert all(
        c.constructed_in == () for c in sdk.find_component_subclasses(with_xref=False)
    )
    assert any(c.constructed_in for c in sdk.find_component_subclasses(with_xref=True))


def test_the_mcp_payload_carries_every_field_and_the_unresolved_count(fdk):
    from dexllm import tools

    out = tools.execute("find_component_subclasses", {}, fdk)
    assert out["total"] == len(_EXPECTED)
    assert out["unresolved_count"] == 1
    for r in out["items"]:
        assert set(r) == {
            "descriptor",
            "dex_id",
            "root_descriptor",
            "root_kind",
            "chain_descriptors",
            "resolution",
            "is_abstract",
            "is_instantiable",
            "constructed_in",
        }
    assert out["with_xref"] is True


def test_the_mcp_tool_paginates(fdk):
    from dexllm import tools

    page = tools.execute("find_component_subclasses", {"limit": 5, "offset": 5}, fdk)
    assert len(page["items"]) == 5 and page["total"] == len(_EXPECTED)
    assert page["items"][0]["descriptor"] == sorted(_EXPECTED)[5]
    # the unresolved count is over the WHOLE list, not the page: the first
    # three rows carry no unresolved row, and a page-scoped count says 0 there
    first = tools.execute("find_component_subclasses", {"limit": 3, "offset": 0}, fdk)
    assert not any(r["resolution"] == UNRESOLVED for r in first["items"])
    assert first["unresolved_count"] == 1


def test_the_mcp_schema_default_is_the_impl_default():
    from dexllm import tools

    schema = next(
        d for d in tools.TOOL_DEFINITIONS if d["name"] == "find_component_subclasses"
    )
    assert schema["input_schema"]["properties"]["with_xref"]["default"] is True
    sig = inspect.signature(tools.TOOL_IMPLS["find_component_subclasses"])
    assert sig.parameters["with_xref"].default is True


def test_the_mcp_tool_honours_with_xref(fdk):
    from dexllm import tools

    out = tools.execute("find_component_subclasses", {"with_xref": False}, fdk)
    assert all(r["constructed_in"] == [] for r in out["items"])
    assert out["with_xref"] is False


def test_the_mcp_tool_echoes_the_coerced_with_xref(fdk):
    """dexllm#49's shape: `with_xref="false"` is a truthy STRING, so it enables
    the xref; the payload must say which mode produced it, or the response is
    indistinguishable from a `True` call (an adversarial review's finding).
    """
    from dexllm import tools

    out = tools.execute("find_component_subclasses", {"with_xref": "false"}, fdk)
    assert out["with_xref"] is True
    assert any(r["constructed_in"] for r in out["items"])


# ── the corpus ───────────────────────────────────────────────────────────────


def _corpus_sources():
    if corpus_is_narrowed():
        return [os.environ["DEXLLM_TEST_APK"]]
    srcs = sorted(glob.glob(str(REPO_ROOT / "test_apk" / "APK" / "*")))
    if not srcs:
        pytest.skip("no corpus")
    return srcs


def test_a_real_app_class_reaches_its_root_through_a_framework_intermediate():
    """Evidence from dex nobody wrote for this feature.

    HONOURS the narrowing explicitly (the dexllm#53 shape): re-globbing the
    corpus would ignore `$DEXLLM_TEST_APK` and make the skip branch dead.
    """
    found = []
    for p in _corpus_sources():
        if not os.path.isfile(p):
            continue
        try:
            d = dexllm.DexKit(p)
        except Exception:  # noqa: BLE001 - not a container
            continue
        for r in find_component_subclasses(d, with_xref=False):
            if r["resolution"] == RESOLVED and len(r["chain_descriptors"]) >= 3:
                mid = r["chain_descriptors"][1]
                if mid in _CORPUS_INTERMEDIATES and d.locate_class_dex(mid) == -1:
                    found.append((os.path.basename(p), r["descriptor"], mid))
    require_corpus_shape(
        bool(found),
        "app class whose direct parent is a framework component intermediate "
        "absent from the dex",
        "the table stopped joining the dex walk to the framework half",
    )
