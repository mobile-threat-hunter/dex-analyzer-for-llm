"""``find_type_references`` lists each descriptor once (dexllm#108).

The lookup walks every loaded dex's REFERENCE tables (``field_ids``,
``method_ids``). Any two dexes that both reference a member carry an entry for
it — ordinary multidex does, and so does a session declaring a class in two
loaded dexes — so the lists used to repeat the same descriptor once per dex. A
row carries no dex id, so a repeat said nothing; each list is now the distinct
descriptors in first-occurrence (dex_id, then table) order, which loses none.

The oracle re-derives that from the per-dex descriptor listings
(``list_fields_in_dex`` / ``list_methods_in_dex``), parsing the type positions
itself where the product compares ``type_idx``, and re-doing the dedupe. It is NOT
independent of descriptor BUILDING or of the table walk order, which those listings
share with the product, so a defect there would be invisible to it. Every case runs on
committed fixtures — ``tests/data/multidex.apk`` is two dexes that both reference
``Foobar.somemethod(String)`` — so they hold in the corpus-less CI leg.
"""

from __future__ import annotations

from pathlib import Path

import pytest

import dexllm

DATA = Path(__file__).parent / "data"
MULTIDEX = DATA / "multidex.apk"
FIXTURE = DATA / "invoke-custom.dex"
# The one committed v41 container: two logical dexes over one data section, which
# the loader splits into two DexItems, so it takes the dedupe path too.
CONTAINER = DATA / "multidex-container.dex"


def _split_types(sig: str) -> list[str]:
    """``(ILjava/lang/String;[J)`` contents -> ``["I", "Ljava/lang/String;", "[J"]``."""
    out, i = [], 0
    while i < len(sig):
        j = i
        while sig[j] == "[":
            j += 1
        if sig[j] == "L":
            j = sig.index(";", j)
        out.append(sig[i : j + 1])
        i = j + 1
    return out


def _oracle(dk, t: str) -> list[list[str]]:
    fields, ret, par = [], [], []
    for d in range(dk.dex_count()):
        for f in dk.list_fields_in_dex(d):
            if f.split(":", 1)[1] == t and f not in fields:
                fields.append(f)
        for m in dk.list_methods_in_dex(d):
            member = m.split("->", 1)[1]
            params, rtype = member[member.index("(") + 1 :].split(")", 1)
            if rtype == t and m not in ret:
                ret.append(m)
            if t in _split_types(params) and m not in par:
                par.append(m)
    return [fields, ret, par]


def _lists(dk, t: str) -> list[list[str]]:
    r = dk.find_type_references(t)
    return [list(r.fields), list(r.methods_returning), list(r.methods_with_param)]


def _types(dk) -> list[str]:
    """Every type that appears in a signature position — primitives and arrays too.

    Most real repeats are on ``I`` / ``V`` / ``Z`` and array types (a review found
    the first cut of this file never queried one), so a scope of class types alone
    would leave the commonest case unexercised.
    """
    out = {r.descriptor for r in dk.list_external_type_refs()} | set(dk.list_classes())
    for d in range(dk.dex_count()):
        for f in dk.list_fields_in_dex(d):
            out.add(f.split(":", 1)[1])
        for m in dk.list_methods_in_dex(d):
            member = m.split("->", 1)[1]
            params, rtype = member[member.index("(") + 1 :].split(")", 1)
            out.add(rtype)
            out.update(_split_types(params))
    return sorted(out)


def test_the_type_scope_includes_primitives_and_arrays():
    t = _types(dexllm.DexKit(str(FIXTURE)))
    assert {"I", "V", "Z"} <= set(t)
    assert any(x.startswith("[") for x in t)


@pytest.mark.parametrize("src", [MULTIDEX, FIXTURE, CONTAINER], ids=lambda p: p.name)
def test_every_list_is_the_distinct_descriptors_in_first_occurrence_order(src):
    dk = dexllm.DexKit(str(src))
    n = 0
    for t in _types(dk):
        got = _lists(dk, t)
        assert got == _oracle(dk, t), t
        for v in got:
            assert len(v) == len(set(v)), (t, v)
        n += sum(map(len, got))
    assert n >= 3, n


def test_a_member_two_dexes_reference_is_listed_once():
    """The committed multidex sample's own repeat, pinned as the issue measured it."""
    dk = dexllm.DexKit(str(MULTIDEX))
    assert dk.dex_count() == 2
    per_dex = [
        m
        for d in range(2)
        for m in dk.list_methods_in_dex(d)
        if m == "Lcom/foobar/foo/Foobar;->somemethod(Ljava/lang/String;)V"
    ]
    assert len(per_dex) == 2, "premise: both dexes reference somemethod(String)"
    got = dk.find_type_references("Ljava/lang/String;").methods_with_param
    assert got == [
        "Lcom/foobar/foo/Foobar;->somemethod(Ljava/lang/String;)V",
        "Ljava/io/PrintStream;->println(Ljava/lang/String;)V",
    ]


@pytest.mark.parametrize("src", [MULTIDEX, FIXTURE], ids=lambda p: p.name)
def test_a_class_declared_twice_answers_like_one_source(src):
    once = dexllm.DexKit(str(src))
    twice = dexllm.DexKit([str(src), str(src)])
    dumped = dexllm.add_dumped_dexes(once, [str(src)])
    for t in _types(once):
        want = _lists(once, t)
        assert _lists(twice, t) == want, t
        assert _lists(dumped, t) == want, t


def test_two_different_dexes_keep_both_sides():
    """Distinct dexes are unioned, not collapsed: the first dex's rows come first."""
    a, b = dexllm.DexKit(str(MULTIDEX)), dexllm.DexKit(str(FIXTURE))
    both = dexllm.DexKit([str(MULTIDEX), str(FIXTURE)])
    t = "Ljava/lang/String;"
    for i in range(3):
        want = list(dict.fromkeys(_lists(a, t)[i] + _lists(b, t)[i]))
        assert _lists(both, t)[i] == want, i


def test_the_typed_layers_carry_the_deduplicated_lists():
    import dexllm.sdk
    from dexllm import tools

    t = "Ljava/lang/String;"
    raw = _lists(dexllm.DexKit(str(MULTIDEX)), t)
    sdk = dexllm.sdk.DexKitAdapter(str(MULTIDEX)).find_type_references(t)
    assert [
        list(sdk.fields),
        list(sdk.methods_returning),
        list(sdk.methods_with_param),
    ] == raw
    out = tools.execute(
        "find_type_references", {"type_descriptor": t}, dexllm.DexKit(str(MULTIDEX))
    )
    flat = repr(out)
    for m in raw[2]:
        assert flat.count(m) == 1, (m, out)


def test_a_short_descriptor_survives_being_moved_during_the_dedupe():
    """The in-place dedupe takes a view of an element only in its FINAL slot.

    A descriptor short enough for the small-string buffer (``LMain;->fail()V`` is
    15 bytes) lives inside the string object, so a view taken before the element is
    moved would point at the moved-from slot. To exercise it the list needs a
    repeat BEFORE the short descriptor (so it is moved, not left in place) and the
    short descriptor again AFTER it: MULTIDEX's ``Object.<init>`` comes first, then
    FIXTURE repeats it, then FIXTURE's own short method, then FIXTURE again.
    """
    dk = dexllm.DexKit([str(MULTIDEX), str(FIXTURE), str(FIXTURE)])
    short = "LMain;->fail()V"
    assert len(short) < 16
    got = dk.find_type_references("V").methods_returning
    assert got.count(short) == 1
    assert got == _oracle(dk, "V")[1]
    assert got.index("Ljava/lang/Object;-><init>()V") < got.index(short)
    for t in _types(dk):
        assert _lists(dk, t) == _oracle(dk, t), t
