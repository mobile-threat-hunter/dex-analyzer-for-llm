"""A class declared in several loaded dexes is ONE result, first dex wins (dexllm#106).

An ``add_dumped_dexes`` packer session — or any multi-source load whose sources
overlap — declares the same class in more than one dex. Every descriptor-keyed API
resolves such a class first-wins in dex_id order, and the core's ``FindMethod`` /
``FindField`` drop an already-seen descriptor. ``FindClass`` and both
``BatchFind*UsingStrings`` did not, so every class search and both batch xrefs
listed the class (or its methods) once per declaring dex. ``DexKitExt`` now applies
the same first-wins rule to all of them, on every layer (raw, SDK, MCP).

The batch CLASS variant also returned a different ORDER from
``find_classes_using_strings`` on any session: the single path walks class_defs in
index order, the batch walked type_idx order. It is re-keyed by class_def position.

Every case runs on committed fixtures, so they hold in the corpus-less CI leg.
"""

from __future__ import annotations

import struct
from pathlib import Path

import pytest

import dexllm

DATA = Path(__file__).parent / "data"
FIXTURE = DATA / "invoke-custom.dex"
KW = {"match_type": "contains", "ignore_case": False}


@pytest.fixture(scope="module")
def once():
    return dexllm.DexKit(str(FIXTURE))


@pytest.fixture(scope="module")
def twice():
    return dexllm.DexKit([str(FIXTURE), str(FIXTURE)])


@pytest.fixture(scope="module")
def dumped(once):
    return dexllm.add_dumped_dexes(once, [str(FIXTURE)])


@pytest.fixture(scope="module")
def values(once):
    vs = [v for v in once.list_value_strings() if v]
    vs += [v[:2] for v in vs if len(v) >= 2]
    return list(dict.fromkeys(vs))


def _searches(values):
    """Every class search plus both batch xrefs, as (name, call) pairs."""
    some = values[:40]
    return [
        ("find_classes_by_name", lambda d: d.find_classes_by_name("Test", "contains")),
        ("find_classes_by_super", lambda d: d.find_classes_by_super("LTestBase;")),
        (
            "find_classes_implementing",
            lambda d: d.find_classes_implementing("Ljava/lang/Runnable;"),
        ),
        (
            "find_classes_by_annotation",
            lambda d: d.find_classes_by_annotation("Ldalvik/annotation/Signature;"),
        ),
        (
            "find_classes_using_strings",
            lambda d: [
                r for v in some for r in d.find_classes_using_strings([v], **KW)
            ],
        ),
        (
            "batch_find_classes_using_strings",
            lambda d: [
                r
                for v in d.batch_find_classes_using_strings(
                    {str(i): [v] for i, v in enumerate(some)}, **KW
                ).values()
                for r in v
            ],
        ),
        (
            "batch_find_methods_using_strings",
            lambda d: [
                r
                for v in d.batch_find_methods_using_strings(
                    {str(i): [v] for i, v in enumerate(some)}, **KW
                ).values()
                for r in v
            ],
        ),
    ]


@pytest.mark.parametrize("session", ["twice", "dumped"])
@pytest.mark.parametrize("idx", range(7))
def test_a_duplicate_declaration_session_answers_like_one_source(
    request, session, idx, once, values
):
    name, call = _searches(values)[idx]
    dup = request.getfixturevalue(session)
    want = [r.descriptor for r in call(once)]
    got = call(dup)
    assert want, f"premise: {name} finds something on the fixture"
    assert [r.descriptor for r in got] == want, name
    assert {r.dex_id for r in got} == {0}, f"{name}: the FIRST dex must win"


def test_a_constant_declared_in_two_dexes_is_one_declaring_class():
    """find_classes_declaring_strings is dexllm's own scan, not FindClass, and
    carried the same duplicate. invoke-custom.dex declares no String constant, so
    this uses the authored fixture whose whole point is its String constants."""
    path = str(DATA / "literal-escapes.dex")
    once = dexllm.DexKit(path)
    vals = [v for v in once.list_value_strings() if v]
    want = [
        [c.descriptor for c in once.find_classes_declaring_strings([v], **KW)]
        for v in vals
    ]
    assert any(want), "premise: the fixture declares String constants"
    for dup in (dexllm.DexKit([path, path]), dexllm.add_dumped_dexes(once, [path])):
        got = [dup.find_classes_declaring_strings([v], **KW) for v in vals]
        assert [[c.descriptor for c in g] for g in got] == want
        assert {c.dex_id for g in got for c in g} == {0}


def test_the_batch_class_order_is_the_single_paths_order(once, values):
    """Pinned on a value whose classes' class_def order is not their type order, so
    a batch that walked type_idx (as it did) returns them in a different order."""
    got = once.batch_find_classes_using_strings({"k": [", "]}, **KW)["k"]
    single = once.find_classes_using_strings([", "], **KW)
    assert [c.descriptor for c in got] == [c.descriptor for c in single]
    by_type = sorted(single, key=lambda c: (c.dex_id, c.class_idx))
    assert [c.descriptor for c in by_type] != [
        c.descriptor for c in single
    ], "premise: type order and class_def order differ for this value"
    assert [c.descriptor for c in single] == [
        "LTestBase;",
        "LTestBadBootstrapArguments;",
        "LTestDynamicBootstrapArguments;",
        "LTestInvocationKinds;",
        "LTestVariableArityLinkerMethod;",
    ]


def test_every_batch_class_answer_matches_the_single_path(once, values):
    res = once.batch_find_classes_using_strings(
        {str(i): [v] for i, v in enumerate(values)}, **KW
    )
    for i, v in enumerate(values):
        single = once.find_classes_using_strings([v], **KW)
        assert [c.descriptor for c in res[str(i)]] == [c.descriptor for c in single], v


def test_the_batch_class_order_holds_across_different_dexes():
    """The batch re-sort is by (dex_id, class_def position); a sort that dropped
    the dex key would interleave two dexes' classes, which a one-dex fixture or a
    duplicate session (where dex 0 always wins) cannot show."""
    dk = dexllm.DexKit([str(DATA / "method_handles.dex"), str(FIXTURE)])
    vals = [v for v in dk.list_value_strings() if v]
    vals += [v[:1] for v in vals]
    vals = list(dict.fromkeys(vals))
    res = dk.batch_find_classes_using_strings(
        {str(i): [v] for i, v in enumerate(vals)}, **KW
    )
    spans = 0
    for i, v in enumerate(vals):
        single = dk.find_classes_using_strings([v], **KW)
        assert [c.descriptor for c in res[str(i)]] == [c.descriptor for c in single], v
        spans += len({c.dex_id for c in single}) > 1
    assert spans, "premise: some value hits classes in both dexes"


def test_two_different_dexes_keep_both_classes_in_dex_order():
    """Not every multi-dex hit is a duplicate: distinct classes in two dexes must
    all survive, grouped dex by dex."""
    dk = dexllm.DexKit([str(DATA / "method_handles.dex"), str(FIXTURE)])
    got = dk.find_classes_by_super("Ljava/lang/Object;")
    assert {c.dex_id for c in got} == {0, 1}
    assert [c.dex_id for c in got] == sorted(c.dex_id for c in got)


# --- a class whose copies DIFFER: the first copy that MATCHES wins -------------


@pytest.fixture(scope="module")
def variant(tmp_path_factory, once):
    """invoke-custom.dex with every const-string in LTestBase; repointed to string 0,
    so the dex-0 copy of LTestBase no longer loads ", " while the dex-1 copy does."""
    import re

    raw = bytearray(FIXTURE.read_bytes())
    from test_xref_batch import _code_items  # the shared raw-dex walker

    methods = once.list_methods_in_dex(0)
    patched = 0
    for midx, code_off in _code_items(bytes(raw)):
        desc = methods[midx]
        if not desc.startswith("LTestBase;->"):
            continue
        smali = once.render_method_smali(desc)
        for m in re.finditer(r"0x([0-9a-f]+): const-string v\d+, ", smali):
            at = code_off + 16 + int(m.group(1), 16) + 2
            if raw[at - 2] == 0x1A:
                struct.pack_into("<H", raw, at, 0)
                patched += 1
    assert patched, "premise: LTestBase; loads a string"
    path = tmp_path_factory.mktemp("first106") / "variant.dex"
    path.write_bytes(bytes(raw))
    assert all(r["valid"] for r in dexllm.verify(str(path)))
    return path


def test_the_first_copy_that_matches_wins(variant):
    dk = dexllm.DexKit([str(variant), str(FIXTURE)])
    single = dk.find_classes_using_strings([", "], **KW)
    batch = dk.batch_find_classes_using_strings({"k": [", "]}, **KW)["k"]
    for got in (single, batch):
        base = [c for c in got if c.descriptor == "LTestBase;"]
        assert [c.dex_id for c in base] == [1], "only the dex-1 copy loads it"
        assert len({c.descriptor for c in got}) == len(got)
    assert [c.descriptor for c in batch] == [c.descriptor for c in single]


# --- the typed and MCP layers carry it, since they pass the raw answer through --


def test_the_sdk_and_mcp_batch_answers_are_deduplicated(once, values):
    from dexllm import tools
    from dexllm.sdk import open_apk

    q = {str(i): [v] for i, v in enumerate(values[:30])}
    want = {
        k: [m.descriptor for m in v]
        for k, v in once.batch_find_methods_using_strings(q, **KW).items()
    }
    session = open_apk([str(FIXTURE), str(FIXTURE)])
    got = session.batch_find_methods_using_strings(q, **KW)
    assert {k: [m.descriptor for m in v] for k, v in got.items()} == want
    out = tools.execute(
        "batch_find_methods_using_strings",
        {"query_map": q, "limit": 10_000},
        dexllm.DexKit([str(FIXTURE), str(FIXTURE)]),
    )
    assert {k: out[k]["items"] for k in want} == want
    assert all(out[k]["total"] == len(want[k]) for k in want)
    assert sum(map(len, want.values())) > 0


def test_both_declaring_strings_return_paths_deduplicate():
    """SOURCE pin, deliberately weaker than a behavioural guard. The index-REFUSED
    fallback of `FindClassesDeclaringStrings` runs only on a crafted amplification
    input (kMaxDeclaredIds), so no committed fixture reaches it; this asserts that
    both of its return paths apply the dedupe, which a reviewer's mutant removing
    it from the fallback alone otherwise survived. It cannot see a call that is
    present and wrong."""
    from test_arg_opcode_coverage import _strip_comments

    src = _strip_comments(
        (Path(__file__).parents[1] / "native/core_ext/dexkit_ext.cpp").read_text()
    )
    import re

    start = src.index("DexKitExt::FindClassesDeclaringStrings(")
    end = src.index("DexKitExt::FindMethodsUsingStrings(", start)
    body = src[start:end]
    # Every `return out;` after the empty-query early return must be IMMEDIATELY
    # preceded by the dedupe as a statement of its own — not inside an `if`, not
    # undone by a copy. The early return (an empty result) needs none.
    returns = [m.start() for m in re.finditer(r"\breturn\s+out\s*;", body)]
    assert len(returns) >= 3, "premise: early return + index path + fallback path"
    guarded = re.findall(
        r"[;{}]\s*KeepFirstPerDescriptor\(out\);\s*return\s+out\s*;", body
    )
    assert len(guarded) == len(returns) - 1
    assert body.count("KeepFirstPerDescriptor(") == len(returns) - 1
