"""Guards for the field arm of the L7 search family and the SDK method record.

Issue #37 found `FieldMatch` registered as a public pybind type and declared in
the stub while **no binding could return one** — the field arm of the C/M/F search
family was declared and never built. Its siblings were live (`ClassMatch` from six
`find_classes_*`, `MethodMatch` from five `find_methods_*`), so the asymmetry was
invisible unless you grepped for a producer.

The same issue found the one gap that cost a consumer capability rather than a
confusing name: `class_fields()` returned structured `FieldInfo` while the method
side offered only `list_class_methods()` (descriptors, no access flags), so any
consumer testing `ACC_NATIVE` / `ACC_ABSTRACT` / `ACC_SYNTHETIC` /
`ACC_DECLARED_SYNCHRONIZED` had to drop out of the SDK to the raw
`get_class_summary`.

These guards therefore pin PRODUCIBILITY and REACHABILITY, not just presence — a
type nothing returns and a port nothing implements both pass an `hasattr` check.
"""

import pytest

from dexllm import _dexkit_core as core
from dexllm import tools
from dexllm.sdk import FieldMatch, MethodInfo, open_apk


def _a_declared_field(dk):
    """A (class, field name) the corpus actually declares, or skip."""
    for cls in dk.list_classes():
        for f in dk.get_class_summary(cls).fields:
            if f.name:
                return cls, f.name
    pytest.skip("no corpus class declares a field")


def test_find_fields_by_name_produces_a_field_match(dk):
    """The raw binding returns FieldMatch objects — the type now has a producer.

    Asserts the TYPE, not just non-emptiness: before #37 nothing constructed one,
    so `isinstance(..., core.FieldMatch)` is the assertion that would have failed.
    """
    cls, name = _a_declared_field(dk)

    hits = dk.find_fields_by_name(name, match_type="equals")
    assert hits, f"{name!r} is declared but not found"
    assert all(isinstance(h, core.FieldMatch) for h in hits)

    hit = next(h for h in hits if h.descriptor.startswith(cls + "->"))
    assert hit.descriptor.startswith(f"{cls}->{name}:")
    # dex_id/field_id are unsigned in C++, so a `>= 0` assertion would be
    # vacuous — pin them against the session instead.
    assert hit.dex_id < dk.dex_count()
    assert hit.field_id < len(dk.list_fields_in_dex(hit.dex_id))
    assert repr(hit).startswith("FieldMatch(")


def test_find_fields_by_name_honours_declaring_class_and_ignore_case(dk):
    """The 3rd and 4th positional arguments are independently wired.

    Same shape as the `find_methods_by_name` guard: this is a 4-positional-arg
    forwarder through C++, so an argument swap is the likely defect and neither
    scoping alone nor case-folding alone would reveal it.
    """
    cls, name = _a_declared_field(dk)

    scoped = dk.find_fields_by_name(name, match_type="equals", declaring_class=cls)
    assert scoped and all(h.descriptor.startswith(cls + "->") for h in scoped)

    miscased = name.swapcase()
    declared = {f.name for f in dk.get_class_summary(cls).fields}
    if miscased == name or miscased in declared:
        # Nothing to flip, or the class declares BOTH spellings — then a
        # case-sensitive search legitimately hits and the delta proves nothing.
        # An obfuscated APK (`a`/`A`/`b`/`B` fields) makes this real, so it must
        # skip the assertion rather than fail on a valid $DEXLLM_TEST_APK.
        return
    off = dk.find_fields_by_name(
        miscased, match_type="equals", declaring_class=cls, ignore_case=False
    )
    on = dk.find_fields_by_name(
        miscased, match_type="equals", declaring_class=cls, ignore_case=True
    )
    assert not off and on


def test_the_field_search_reaches_every_layer(apk_path, dk):
    """raw → SDK → MCP all expose it, under the one unified name.

    Each hop is a separate call site; the SDK adapter and the tool registry were
    each individually omittable with a green suite before this.
    """
    cls, name = _a_declared_field(dk)
    session = open_apk(apk_path)

    typed = session.find_fields_by_name(name, match_type="equals", declaring_class=cls)
    assert typed and all(isinstance(h, FieldMatch) for h in typed)

    out = tools.execute(
        "find_fields_by_name",
        {"name": name, "match_type": "equals", "declaring_class": cls},
        dk,
    )
    assert "error" not in out
    assert {h.descriptor for h in typed} == set(out["items"])


def test_class_methods_agrees_with_the_descriptor_enumeration(apk_path, dk):
    """For an INTERNAL class the two views list the same members, in order.

    Both resolve through `GetClassDeclaredPair` and walk `GetClassMethodIds` in
    the same order, so this is structural rather than a corpus accident — asserted
    as an ordered list, not a set, and over a slice of classes rather than the
    first one, since the first class is usually trivial.

    Scoped to internal classes deliberately: see
    `test_class_methods_and_list_class_methods_diverge_on_an_external_class`.
    """
    session = open_apk(apk_path)
    checked = 0
    for cls in dk.list_classes()[:200]:
        methods = session.class_methods(cls)
        if not methods:
            continue
        assert all(isinstance(m, MethodInfo) for m in methods)
        assert [f"{m.name}{m.proto}" for m in methods] == [
            d.split("->", 1)[1] for d in session.list_class_methods(cls)
        ]
        checked += 1
    if not checked:
        pytest.skip("no class in the slice declares a method")


def test_class_methods_is_the_only_way_to_a_method_modifier(apk_path, dk):
    """The #37 capability gap itself: a modifier bit, without leaving the SDK.

    A descriptor carries no flags at all, so this hunts a method with a
    NON-TRIVIAL modifier (beyond public/private/protected/static/final) and
    asserts `class_methods` reports it. Checking the first class instead would
    pass on a plain `<init>` and prove nothing about the flags being carried.
    """
    session = open_apk(apk_path)
    interesting = (
        0x0100 | 0x0400 | 0x1000 | 0x20000
    )  # native|abstract|synthetic|decl-sync
    for cls in dk.list_classes():
        for m in session.class_methods(cls):
            if m.access_flags & interesting:
                assert isinstance(m, MethodInfo)
                # the same fact the AST path spells as decoded NAMES
                names = dk.decompile_method_ast(f"{cls}->{m.name}{m.proto}")["access"]
                assert names, "the AST path reports no modifiers for the same method"
                return
    pytest.skip("no corpus method carries a non-trivial modifier")


def test_class_methods_and_list_class_methods_diverge_on_an_external_class(dk):
    """An EXTERNAL class is where the two views legitimately disagree.

    `get_class_summary` reconstructs members from the `method_ids` references
    other classes make, so `class_methods` reports them while
    `list_class_methods` (declared members only) returns nothing — and their
    `access_flags` are all None, meaning UNKNOWN (dexllm#41). Pinned because the
    sibling test above is internal-only by design and a reader would otherwise
    take its equality as universal.
    """
    for ref in dk.list_external_type_refs(framework_only=True):
        summary = dk.get_class_summary(ref.descriptor)
        if not summary.methods:
            continue
        assert summary.is_internal is False
        assert dk.list_class_methods(ref.descriptor) == []
        assert all(m.access_flags is None for m in summary.methods)
        return
    pytest.skip("no external class in this corpus carries method refs")


def test_renamed_names_are_gone_and_the_new_ones_produce(dk):
    """The three #37 renames landed in every layer, with no alias left behind.

    This repo removed its alias mechanism deliberately (#24), so a rename must be
    absent on the old spelling AND working on the new one — asserting absence
    alone would pass if the whole surface broke.
    """
    for gone in ("list_method_descriptors", "list_field_descriptors"):
        assert not hasattr(dk, gone), f"{gone} is still on DexKit"
        assert not hasattr(dk, gone + "_in_dex")
    for gone in ("ClassMemberField", "ClassMemberMethod"):
        assert not hasattr(core, gone), f"{gone} is still a public type"

    # The new spellings must PRODUCE, not merely exist. Non-emptiness is a corpus
    # fact, not an API fact: `ExceptionHandling.dex` in this repo's own corpus has
    # an EMPTY field_ids pool, so asserting `list_fields()` is truthy fails on a
    # legitimate `$DEXLLM_TEST_APK` — the "an environment fact must skip, never
    # fail" rule this repo records twice. Assert the callable and its type instead,
    # and only assert content where the corpus supplies it.
    for produce in (dk.list_methods, dk.list_fields):
        assert isinstance(produce(), list)
    for produce in (dk.list_methods_in_dex, dk.list_fields_in_dex):
        assert isinstance(produce(0), list)
    assert dk.list_methods(), "a dex with no method_ids is not a thing"

    summary = dk.get_class_summary(dk.list_classes()[0])
    assert all(isinstance(f, core.FieldInfo) for f in summary.fields)
    assert all(isinstance(m, core.MethodInfo) for m in summary.methods)


def test_list_methods_is_the_all_dex_concatenation(dk):
    """The rename kept the documented relationship between the two forms.

    A rename that hit only one of the pair would leave the docs' "exactly the
    concatenation of ..._in_dex over every dex" claim silently false.
    """
    n = dk.dex_count()
    for whole, per_dex in (
        (dk.list_methods(), dk.list_methods_in_dex),
        (dk.list_fields(), dk.list_fields_in_dex),
    ):
        concat = [d for i in range(n) for d in per_dex(i)]
        assert list(whole) == concat
