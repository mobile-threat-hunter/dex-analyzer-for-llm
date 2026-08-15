"""dexllm#45 — a class's field list is what it DECLARES.

`DexItem::class_field_ids` is keyed on the whole `field_ids` table, grouped by the
class named in the REFERENCE, so it also holds inherited fields a subclass merely
references. #41 made those entries' modifiers honest (`access_flags is None`);
this issue removed the entries from the four surfaces that present a class's
members: `get_class_summary` (and everything derived from it — `class_fields`,
`format_class`, the MCP `field_count`), `render_class_smali`, and
`find_fields_by_name`'s `declaring_class` scope.

The reference view is NOT lost: it is `list_fields()` — the whole `field_ids`
table — filtered by the `Lcls;->` prefix (a superset, and one that repeats a
descriptor once per dex carrying the entry, so dedupe before counting). That
recovery claim is what made dropping the right answer rather than adding an
accessor, so it is guarded here too.

The equality against an independent `class_data` parse lives in
`test_access_flags.py::test_an_internal_class_lists_exactly_the_fields_it_declares`
(it reuses that file's oracle); this file guards the other three surfaces and the
cross-layer propagation.
"""

import pytest
from conftest import require_corpus_shape
from test_access_flags import _declared_fields_oracle


def _inherited_references(dk):
    """Every (class, field name, field type) DEX 0 references under a class that
    does not declare it — the shape the whole issue is about.

    Established from `list_fields_in_dex(0)` (the raw `field_ids` table, unaffected
    by the fix) minus the independent `class_data` parse, so neither side of the
    finder is the value under test.

    Scoped to dex 0 on BOTH sides deliberately. The oracle can only read one dex,
    while `get_class_summary` / `render_class_smali` resolve a class first-wins
    across all of them, so a whole-session candidate list could yield a dex-1
    reference to a dex-0 class — an entry that is absent from the dex-0 summary
    both before AND after the fix, silently turning the guards below into
    tautologies. It does not occur in the bundled corpus (checked), which is
    exactly why it must be closed structurally rather than left to luck.
    """
    raw = dk.extract_dex(0)["bytes"]
    declared = _declared_fields_oracle(raw)
    out = []
    for fd in dk.list_fields_in_dex(0):
        cls, rest = fd.split("->", 1)
        name, _, type_desc = rest.partition(":")
        own = declared.get(cls)
        if own is None or (name, type_desc) in own:
            continue
        if not dk.get_class_summary(cls).is_internal:
            continue
        out.append((cls, name, type_desc, declared))
    return out


@pytest.fixture(scope="module")
def inherited_ref(dk):
    """An inherited reference. Its declaring class may be external (a framework
    field), which is the common case and fine for every guard except the one that
    needs the declaration to still be findable — that one uses the fixture below.
    """
    found = _inherited_references(dk)
    require_corpus_shape(
        bool(found),
        "class that references a field it does not declare",
        "the shape dexllm#45 is about vanished from the corpus, so these guards "
        "would pass without exercising the filter",
    )
    cls, name, type_desc, _declared = found[0]
    return cls, name, type_desc


@pytest.fixture(scope="module")
def inherited_ref_declared_internally(dk):
    """An inherited reference, plus the class that actually DECLARES it.

    Needed because the usual case is a framework field (`ViewGroup$MarginLayoutParams
    ->bottomMargin`), whose declaration no loaded dex holds — a guard asserting
    "the declaring class still answers" would then fail on a CORPUS fact, which
    this repo's rule (issue #46) forbids. On the bundled corpus 43 of tvleanback's
    412 candidates and 59 of app-prod-debug's 237 are of that kind, so picking the
    first one blindly is luck, not a guard.

    Returns the OWNER, rather than leaving the caller to guess it. An earlier cut
    had the test re-derive it from the unscoped search hits minus the candidate
    class — but those hits are REFERENCES, so it picked a sibling that merely
    references the field too, whose scoped query correctly answers nothing. That
    made the guard fail on `hello-world.apk` and `app-prod-debug.apk`: a fix FOR
    the corpus-fact rule that broke the same rule.
    """
    for cls, name, type_desc, declared in _inherited_references(dk):
        # `declared` is keyed on dex-0 class_defs, so every owner here is internal
        # by construction — the real condition is that an owner exists at all.
        owners = sorted(c for c, own in declared.items() if (name, type_desc) in own)
        if owners:
            return cls, name, type_desc, owners[0]
    require_corpus_shape(
        False,
        "inherited field reference whose declaring class is in the same dex",
        "every candidate's declaration is external, so the declaration-survives "
        "guard cannot be exercised",
    )
    return None  # unreachable — require_corpus_shape raises


def test_an_inherited_field_is_not_a_member_of_the_referencing_class(dk, inherited_ref):
    """The summary — the surface every other one derives from."""
    cls, name, type_desc = inherited_ref
    listed = {(f.name, f.type) for f in dk.get_class_summary(cls).fields}
    assert (name, type_desc) not in listed, (
        f"{cls} lists {name}:{type_desc}, which it only references — a member list "
        f"claiming a declaration the class does not have"
    )


def test_an_inherited_field_is_still_reachable_through_list_fields(dk, inherited_ref):
    """The recovery claim that made dropping preferable to a new accessor.

    NON-DISCRIMINATING BY DESIGN: `list_fields()` is the raw `field_ids` table and
    the fix does not touch it, so this passes on both sides of the change. It is
    here because the docs now tell a reader to use this exact expression, and a
    silent regression in `list_fields()` would strand them.
    """
    cls, name, type_desc = inherited_ref
    refs = [f for f in dk.list_fields() if f.startswith(cls + "->")]
    assert f"{cls}->{name}:{type_desc}" in refs


def test_smali_emits_a_field_line_only_for_a_declared_field(dk, inherited_ref):
    """baksmali emits `.field` for a class's own class_data entries only."""
    cls, name, type_desc = inherited_ref
    lines = [
        line
        for line in dk.render_class_smali(cls).splitlines()
        if line.startswith(".field ")
    ]
    assert f".field {name}:{type_desc}" not in lines, (
        f"render_class_smali({cls}) emits a .field line for an inherited "
        f"reference; baksmali would not"
    )


def test_smali_field_lines_agree_with_the_summary(dk, inherited_ref):
    """The two presentation surfaces must not drift apart.

    They are filtered in different translation units — `FillInternalClassSummary`
    in core_ext and `RenderClassSmali` in the vendored core — so a fix applied to
    one only is exactly the regression this pins. Verified: it kills each of those
    one-sided mutants.

    It is BLIND to a symmetric regression (both surfaces wrong the same way), and
    so passes against the whole pre-fix build; the equality against the raw
    `class_data` parse is what covers that direction.

    The scan is capped, so it needs a floor: it must actually REACH a class that
    carries an inherited reference, else on 8 of the 26 bundled samples the window
    holds none and the equality is satisfied by classes the filter never touches.
    """
    affected_cls = inherited_ref[0]
    seen_affected = False
    checked = 0
    for cls in dk.list_classes():
        summary = dk.get_class_summary(cls)
        if not summary.is_internal:
            continue
        smali = {
            line[len(".field ") :]
            for line in dk.render_class_smali(cls).splitlines()
            if line.startswith(".field ")
        }
        assert smali == {f"{f.name}:{f.type}" for f in summary.fields}, cls
        seen_affected = seen_affected or cls == affected_cls
        checked += 1
        if checked >= 300 and seen_affected:
            return
    assert checked, "no internal class in this corpus"
    require_corpus_shape(
        seen_affected,
        "class carrying an inherited field reference among those compared",
        "the comparison never reached a class the #45 filter acts on, so it holds "
        "vacuously",
    )


def test_a_class_declaring_no_fields_emits_no_field_separator(dk):
    """The blank line after the `.field` block is gated on a line being EMITTED.

    `RenderClassSmali` used `if (!class_field_ids[type_idx].empty())`, which is
    true for a class whose entries are ALL inherited references — it would print a
    separator for a block it no longer emits. Nothing else covers this: every other
    smali assertion in the repo matches `.field ` / `.method ` / `0xNN:` prefixes,
    and the change's own a/b attributed diffs per `.field` LINE, so a blank line is
    invisible to both.
    """
    # The DISCRIMINATING shape is "declares nothing but DOES carry references" —
    # only such a class had a non-empty `class_field_ids` for the old gate to fire
    # on. A class with no `field_ids` entry at all emitted no separator before the
    # change either, so flooring on "declares no fields" (true of ~700 classes in
    # any APK) let the mutant survive a `$DEXLLM_TEST_APK=a2dp.Vol_137.apk` run:
    # 0 of its 21 discriminating classes fell inside a `[:200]` window of that
    # much larger set. Membership is read from `list_fields()`, which the fix does
    # not touch, so the selection is not the value under test.
    referenced = {}
    for fd in dk.list_fields():
        referenced.setdefault(fd.split("->", 1)[0], 0)
        referenced[fd.split("->", 1)[0]] += 1
    discriminating = [
        cls
        for cls in dk.list_classes()
        if referenced.get(cls)
        and dk.get_class_summary(cls).is_internal
        and not dk.get_class_summary(cls).fields
    ]
    require_corpus_shape(
        bool(discriminating),
        "internal class that references fields but declares none",
        "no class can exercise the field-separator gate, so it holds vacuously",
    )
    for cls in discriminating[:200]:
        smali = dk.render_class_smali(cls)
        head = smali.split("\n.method", 1)[0]
        assert ".field " not in head
        assert not head.endswith("\n\n"), (
            f"{cls} declares no field yet the renderer emitted a separator for the "
            f"empty block"
        )


def test_find_fields_by_name_scoped_to_a_subclass_finds_no_inherited_field(
    dk, inherited_ref
):
    """`declaring_class` must mean declaring, as it does for methods.

    The core scans `class_field_ids` and its declaring-class matcher reads the same
    `field_id.class_idx`, so before the fix the inherited reference matched under
    the subclass that only references it.
    """
    cls, name, type_desc = inherited_ref
    hits = dk.find_fields_by_name(name, "equals", cls, False)
    assert [h.descriptor for h in hits] == [], (
        f"find_fields_by_name({name!r}, declaring_class={cls!r}) returned a field "
        f"{cls} does not declare"
    )


def test_an_unscoped_field_search_still_returns_references(dk, inherited_ref):
    """The filter is scoped to `declaring_class`, and this pins that it is.

    An unscoped name search walks the whole `field_ids` table, references included —
    what `find_methods_by_name` does without a `declaring_class` (verified: it
    returns `FastSafeIterableMap->descendingIterator`, which that class inherits).
    Filtering unconditionally would make the field arm the asymmetric one AND lose
    real answers: an inherited field is usually DECLARED in the framework, outside
    every loaded dex, so `find_fields_by_name("rightMargin")` went 12 hits to 0.

    This is the guard for the mutant a reviewer constructed — hoisting the
    `erase_if` out of its `if (!declaring_class.empty())` — which the rest of the
    suite does not kill.
    """
    cls, name, type_desc = inherited_ref
    hits = [h.descriptor for h in dk.find_fields_by_name(name, "equals", "", False)]
    assert f"{cls}->{name}:{type_desc}" in hits, (
        f"an unscoped search for {name!r} dropped the reference {cls}->{name}:"
        f"{type_desc}; the declared-only filter must apply to a SCOPED query only"
    )


def test_the_declaring_class_still_answers_for_the_same_field(
    dk, inherited_ref_declared_internally
):
    """The filter must remove the reference, not the declaration.

    Without this a fix that dropped everything would look green above. It takes the
    `_declared_internally` fixture because the declaration has to be IN a loaded dex
    for the question to have an answer at all, and it takes the OWNER from that
    fixture rather than re-deriving it from the search hits — those hits are
    REFERENCES, so picking one that is merely "not the candidate class" lands on a
    sibling that also only references the field, whose scoped query correctly
    answers nothing. That mistake made this guard fail on `hello-world.apk` and
    `app-prod-debug.apk`.
    """
    cls, name, type_desc, owner = inherited_ref_declared_internally
    assert owner != cls  # the fixture's whole point
    wanted = f"{owner}->{name}:{type_desc}"

    hits = [h.descriptor for h in dk.find_fields_by_name(name, "equals", "", False)]
    assert wanted in hits, (
        f"{wanted} vanished from an unscoped search — the filter removed the "
        f"declaration as well as the reference"
    )
    # And the DECLARING class answers when scoped, where the referencing one does
    # not. Membership, not equality: one class may declare two fields of the same
    # name with different types, and may be declared in more than one dex.
    scoped = [
        h.descriptor for h in dk.find_fields_by_name(name, "equals", owner, False)
    ]
    assert wanted in scoped, f"scoping to the DECLARING class {owner} lost {wanted}"


def test_the_drop_propagates_to_the_sdk_and_the_mcp_tool(dk, apk_path, inherited_ref):
    """A C++-side filter is worthless if a Python layer re-derives the old list.

    Each of the three legs is compared against the INDEPENDENT `class_data` oracle,
    not against `get_class_summary`. An earlier cut compared the MCP `field_count`
    with `len(get_class_summary(...).fields)` — but `tools.py` computes it from
    that very call, so it was `len(X) == len(X)` and no production change could
    fail it; and it asserted the absence of a `name:Type` substring from
    `format_class`, which renders `java.lang.Type name;` and therefore never
    contains that form, for a declared field either. Both passed against the whole
    pre-fix build.
    """
    import dexllm
    from dexllm import tools
    from dexllm.sdk import open_apk

    cls, name, type_desc = inherited_ref
    declared = _declared_fields_oracle(dk.extract_dex(0)["bytes"])[cls]

    port = open_apk(apk_path)
    assert {(f.name, f.type) for f in port.class_fields(cls)} == declared

    assert tools._t_get_class_summary(dk, class_descriptor=cls)["field_count"] == len(
        declared
    )

    # format_class renders `<java type> <name>;` — build the line the way it does
    # and require the inherited one absent while a declared one (if any) is present.
    rendered = dexllm.format_class(dk, cls)
    java = type_desc.lstrip("[").rstrip(";").lstrip("L").replace("/", ".")
    assert f" {name};" not in rendered, (
        f"format_class({cls}) still renders the inherited field {name} "
        f"(type {java})"
    )
    for dname, _dtype in declared:
        assert f" {dname};" in rendered, (
            f"format_class({cls}) lost the DECLARED field {dname} — the filter "
            f"removed too much"
        )
