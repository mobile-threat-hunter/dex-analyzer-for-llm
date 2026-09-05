"""dexllm#69 — the record vocabulary is ONE vocabulary, and it stays one.

dexllm#37 locks *"a record type that exists on both layers uses ONE name"* and
dexllm#68 locks *"one Dalvik descriptor, one word for it"*. Both are satisfied by
a vocabulary that is internally incoherent: every record passed #37 while the
suffixes spanned NINE words on FIVE different axes (`Match` / `Hit` / `Origin`
were three words for PROVENANCE alone), an ordinal was spelled four ways, and the
same value changed name at the layer boundary. Coherence WITHIN the vocabulary is
a different axis and nothing checked it.

These guards are that axis. Each pins a LITERAL, because a guard parametrised
over the production source cannot catch an EDIT of it — the defence
`test_capability_catalog`'s prefix guard had to be rebuilt around after a
reviewer deleted an entry and watched the suite stay green.

Corpus-INDEPENDENT: every live probe runs on the committed `tests/data/
multidex.apk`, so these hold in the CI leg with no APKs and under any
`$DEXLLM_TEST_APK` narrowing.
"""

from __future__ import annotations

import dataclasses
import re
from pathlib import Path

import pytest
from _records import assert_skips_are_optional, public_record_attrs
from conftest import require_corpus_shape

import dexllm

COMMITTED_APK = str(Path(__file__).parent / "data" / "multidex.apk")

# ── the pinned vocabulary ────────────────────────────────────────────────────
#
# THE RULE (dexllm#69 §2): a record's suffix names WHAT THE RECORD IS, never how
# it was obtained. `Match` / `Hit` / `Origin` were provenance, and `Row` was a
# presentation shape; all four are gone. `External*Ref` keeps `Ref` because there
# the STATUS is carried by the `External` prefix, which is where a status belongs.
#
# Set equality BOTH ways: a new suffix fails, and a stale entry fails. A record
# added under an existing suffix fails too — the value is the record set, so the
# table says which records each word covers, not merely which words exist.
_SUFFIX_TO_RECORDS: dict[str, frozenset[str]] = {
    # what it IS — an entity reference, a location, a rendering, a verdict
    "Ref": frozenset(
        {
            "ClassRef",
            "MethodRef",
            "FieldRef",
            "ExternalFieldRef",
            "ExternalMethodRef",
            "ExternalTypeRef",
        }
    ),
    "Info": frozenset({"ClassInfo", "ContainerInfo", "FieldInfo", "MethodInfo"}),
    "Summary": frozenset({"ClassSummary"}),
    "Site": frozenset({"CallSite", "FieldAccessSite", "ResolvedCallSite"}),
    "Location": frozenset({"SourceLocation", "StatementLocation"}),
    "Ast": frozenset({"MethodAst"}),
    "Status": frozenset({"DexVerifyStatus"}),
    "Report": frozenset({"CapabilityReport", "IocReport"}),
    "Dex": frozenset({"ExtractedDex"}),
    "Arg": frozenset({"ResolvedArg"}),
    "Usage": frozenset({"ApiUsage"}),
    "Callers": frozenset({"ApiCallers", "PermissionCallers"}),
    "Use": frozenset({"ContentProviderUse"}),
    "Component": frozenset({"TlsTrustComponent"}),
    "Indicator": frozenset({"Indicator"}),
    "References": frozenset({"TypeReferences"}),
    # head nouns, not suffixes — the word IS the thing
    "Class": frozenset({"DecompiledClass"}),
    "Method": frozenset({"DecompiledMethod"}),
}

#: Words that name HOW a record was obtained or WHAT SHAPE it arrived in. The
#: positive rule above is the real guard; this is the targeted regression half,
#: so re-adding `MethodMatch` fails with the CAUSE rather than as an anonymous
#: set difference [[a-ban-is-not-the-rule-you-documented]].
_PROVENANCE_OR_SHAPE_SUFFIXES = frozenset(
    {"Match", "Hit", "Origin", "Row", "Group", "Entry", "Result", "Item", "Record"}
)

#: dexllm#69 §5 — an ordinal is spelled by WHAT IT INDEXES, three tiers:
#:   `_idx`   a position in a dex ``*_ids`` table (the dex spec's own word)
#:   `_id`    a handle dexllm assigns (load order), not a dex structure
#:   `_index` any other ordinal
#: `_num` is gone. Pinned as a LITERAL so a fourth spelling is a conscious edit.
_ORDINAL_ATTRS: dict[str, str] = {
    "class_idx": "idx",
    "method_idx": "idx",
    "field_idx": "idx",
    "caller_method_idx": "idx",
    "dex_id": "id",
    "caller_dex_id": "id",
    "parameter_index": "index",
    "register_index": "index",
    "statement_index": "index",
}

#: dexllm#69 §1 — the dotted-Java rendering names its INPUT's kind. All of them
#: are the same `descriptor_to_java()` transform, so the noun is the only thing
#: telling them apart. `java_name` named neither the input's kind nor the
#: output's, on the one record whose input IS a type descriptor.
_JAVA_RENDERING_ATTRS = frozenset({"java_class", "java_type", "java_signature"})


def _records_by_layer() -> dict[str, frozenset[str]]:
    """``{'raw.X' | '<module>.X': {attrs}}`` — the SHARED walker, one definition.

    `_records.public_record_attrs` is the one dexllm#68's audits already use. This
    file re-implemented it, and the copy was WEAKER on two axes a correctness
    reviewer and an adversarial reviewer each found independently: it did not
    enumerate `NamedTuple` records (the exact hole a dexllm#68 reviewer had already
    had to construct against the original), and it hard-FAILED on a module whose
    optional extra is absent — which is the CI shape (`pip install -e ".[ioc]"`),
    so five of these guards were RED there while green locally.
    """
    qualified, skipped = public_record_attrs()
    assert_skips_are_optional(skipped)
    assert len(qualified) >= 25, f"the walk found only {len(qualified)} records"
    return {k: frozenset(v) for k, v in qualified.items()}


def _record_names() -> set[str]:
    """The vocabulary itself: a name on two layers is ONE entry — which is what
    makes `ApiUsage` a single record instead of the two it used to be."""
    return {q.rsplit(".", 1)[1] for q in _records_by_layer()}


def _all_attrs() -> set[str]:
    """Every public attribute name on every record, on every layer."""
    return {a for attrs in _records_by_layer().values() for a in attrs}


def test_a_record_suffix_names_what_the_record_is():
    """dexllm#69 §2 — one axis for the suffixes, pinned as a literal."""
    suffix_re = re.compile(r"([A-Z][a-z]+)$")
    seen: dict[str, set[str]] = {}
    for n in _record_names():
        m = suffix_re.search(n)
        assert m, f"{n} has no CamelCase tail — classify it in _SUFFIX_TO_RECORDS"
        seen.setdefault(m.group(1), set()).add(n)

    pinned = {k: set(v) for k, v in _SUFFIX_TO_RECORDS.items()}
    assert seen == pinned, (
        f"the record vocabulary moved. new/changed: "
        f"{ {k: sorted(v) for k, v in seen.items() if pinned.get(k) != v} } | "
        f"stale pins: { {k: sorted(v) for k, v in pinned.items() if seen.get(k) != v} }"
    )


def test_no_suffix_names_how_a_record_was_obtained():
    """The targeted regression half — re-adding `Match` fails with the CAUSE.

    Non-vacuous by construction: the banned set is a literal, and the assertion
    below proves it is not empty and not already satisfied by an empty scan.
    """
    assert _PROVENANCE_OR_SHAPE_SUFFIXES, "the banned set is empty — vacuous"
    offenders = {
        n
        for n in _record_names()
        if any(n.endswith(w) for w in _PROVENANCE_OR_SHAPE_SUFFIXES)
    }
    assert not offenders, (
        f"{sorted(offenders)} end in a word that names HOW the record was obtained "
        f"or what SHAPE it arrived in, not what it IS (dexllm#69 §2)"
    )


def test_no_two_record_names_describe_the_same_shape():
    """One record, one name — on EVERY layer, not only the two dexllm#37 compares.

    `capability.ApiHit` and `sdk.CapabilityHit` had identical field sets and two
    names for as long as both existed, and #37's audit could not see it: its
    "raw" side is `_dexkit_core` (pybind types) alone, so a plain python
    dataclass carrying a second name was outside its reach entirely.
    """
    by_shape: dict[frozenset[str], set[str]] = {}
    for qual, attrs in _records_by_layer().items():
        by_shape.setdefault(attrs, set()).add(qual.rsplit(".", 1)[1])
    dupes = {
        tuple(sorted(names)): sorted(shape)
        for shape, names in by_shape.items()
        if len(names) > 1
    }
    assert not dupes, (
        f"these are one record under two names — give them one name or make the "
        f"shapes genuinely differ: {dupes}"
    )
    assert len(by_shape) >= 25, "the shape index collapsed — the walk is broken"


def test_an_ordinal_is_spelled_by_what_it_indexes():
    """dexllm#69 §5 — `_id` / `_idx` / `_num` / `_index` were four spellings."""
    tail = re.compile(r"_(id|idx|num|index)$")
    seen = {a: tail.search(a).group(1) for a in _all_attrs() if tail.search(a)}
    assert seen == _ORDINAL_ATTRS, (
        f"the ordinal vocabulary moved. new/changed: "
        f"{ {k: v for k, v in seen.items() if _ORDINAL_ATTRS.get(k) != v} } | "
        f"stale pins: { {k: v for k, v in _ORDINAL_ATTRS.items() if seen.get(k) != v} }"
    )
    assert "num" not in seen.values(), "`_num` is not one of the three tiers"


def test_the_java_rendering_names_its_input_kind():
    """dexllm#69 §1 — `java_name` named neither the input's kind nor the output's."""
    found = {a for a in _all_attrs() if a.startswith("java_")}
    assert found == _JAVA_RENDERING_ATTRS, (
        f"unexpected java_* attributes {sorted(found - _JAVA_RENDERING_ATTRS)} / "
        f"missing {sorted(_JAVA_RENDERING_ATTRS - found)}"
    )

    # …and the one that moved renders what its name claims, on BOTH layers.
    dk = dexllm.DexKit(COMMITTED_APK)
    from dexllm.sdk import open_apk

    for layer in (dk, open_apk(COMMITTED_APK)):
        refs = layer.list_external_type_refs()
        assert refs, "the committed fixture stopped carrying external type refs"
        r = refs[0]
        assert not hasattr(r, "java_name")
        assert r.java_type == r.descriptor.strip("L;").replace("/", ".")


#: (fixture, does it declare FIELDS). `tests/data/multidex.apk` is the minimal
#: committed container and its two classes declare ZERO fields — so a guard driven
#: on it alone runs `for f in fields:` zero times, in every environment. BOTH
#: reviewers found that independently and each BUILT the mutant it lets through: a
#: `FieldInfo.descriptor` that drops the class (`this$0:LFoo;`, not a member
#: descriptor at all) passes the entire suite. `tests/data/invoke-custom.dex` is
#: committed and declares 17 fields across 14 classes.
_IDENTITY_FIXTURES = [("multidex.apk", False), ("invoke-custom.dex", True)]


@pytest.mark.parametrize("layer", ["raw", "sdk"])
@pytest.mark.parametrize("fixture,has_fields", _IDENTITY_FIXTURES)
def test_a_member_record_can_produce_its_own_identity(layer, fixture, has_fields):
    """dexllm#69 §3 — `*Info` was the only member record with no identity string.

    `MethodRef`, `ExternalMethodRef` and `ClassSummary` all carry `descriptor`;
    `MethodInfo` / `FieldInfo` did not, so a caller reading `class_methods()` had
    to re-assemble `Lcls;->name(proto)ret` by hand — and the helper that does that
    assembly is the one dexllm#68 found most misnamed.
    """
    from dexllm.sdk import open_apk

    path = str(Path(__file__).parent / "data" / fixture)
    dk = dexllm.DexKit(path)
    seen_m = seen_f = 0
    for cls in sorted(dk.list_classes()):
        if layer == "raw":
            s = dk.get_class_summary(cls)
            methods, fields = s.methods, s.fields
        else:
            h = open_apk(path)
            methods, fields = h.class_methods(cls), h.class_fields(cls)
        for m in methods:
            seen_m += 1
            assert m.class_descriptor == cls
            assert m.descriptor == f"{cls}->{m.name}{m.proto}"
            # …and it is the identity the descriptor-taking APIs actually accept.
            assert dk.render_method_smali(m.descriptor) != ""
        for f in fields:
            seen_f += 1
            assert f.class_descriptor == cls
            assert f.descriptor == f"{cls}->{f.name}:{f.type}"
            assert f.descriptor in dk.list_fields()

    # Floors — without them the loops can go vacuous and say nothing, which is
    # exactly what happened to the FIELD half.
    assert seen_m, f"{fixture} declares no method — the fixture changed"
    if has_fields:
        assert seen_f, f"{fixture} declares no field — the fixture changed"


def test_the_ast_dict_keys_are_the_model_field_names():
    """dexllm#69 §4 — the raw dict renamed 5 of its 10 keys at the boundary.

    One call, both layers, same session: `cls_name` / `ret_type` / `params_type` /
    `access` on one side and `class_name` / `return_type` / `param_types` /
    `access_flags` on the other — and `cls_name`'s VALUE is a descriptor, which
    made it a THIRD spelling of what everything else calls `class_descriptor`.
    """
    from dexllm.sdk import open_apk

    dk = dexllm.DexKit(COMMITTED_APK)
    cls = sorted(dk.list_classes())[0]
    md = dk.list_class_methods(cls)[0]
    raw = dk.decompile_method_ast(md)
    model = open_apk(COMMITTED_APK).decompile_method_ast(md)
    assert set(raw) == {f.name for f in dataclasses.fields(model)}, (
        f"raw-only {sorted(set(raw) - {f.name for f in dataclasses.fields(model)})} | "
        f"sdk-only {sorted({f.name for f in dataclasses.fields(model)} - set(raw))}"
    )
    # the key that carried the third spelling holds a DESCRIPTOR, not a name
    assert raw["class_descriptor"] == cls
    assert model.class_descriptor == cls


#: The permission-group dict has TWO producers and they must move together.
#: `dk.permission_callers()` is built in C++ and
#: `dangerous_api.permission_api_callers()` in Python; both are documented as the
#: same shape, and the SDK adapter reads whichever it is handed. Renaming the key
#: in one and not the other is a `KeyError` on exactly one path — which is what
#: happened while dexllm#69 was being written.
_PERMISSION_GROUP_KEYS = frozenset({"perm", "protectionLevel", "apis"})

#: …and the SDK model the adapter builds from them. Pinned SEPARATELY because the
#: SDK deliberately renames two of the three (`perm` -> `permission`,
#: `protectionLevel` -> `protection_level`; the raw layer's camelCase key is the
#: only one in the API and is dexllm#69-measured but not in its decision list), so
#: a shared literal would be wrong. Nothing else covers this: the source pin below
#: reads the two RAW producers and the runtime twin compares them to each other,
#: so a mutant renaming the SDK field alone SURVIVED the whole suite until this
#: existed — found by the dexllm#69 mutation matrix, not by review.
_PERMISSION_MODEL_FIELDS = frozenset({"permission", "protection_level", "apis"})
_API_CALLERS_MODEL_FIELDS = frozenset({"api", "descriptors", "callers"})


#: Spellings dexllm#68 and dexllm#69 RETIRED. A record attribute cannot carry one
#: (the audits above), but a PARAMETER is a different axis and nothing reached it:
#: dexllm#44 locks argument names raw<->port and MCP-schema<->impl, and a module
#: helper has neither twin. `java_to_descriptor(java_name=...)` sat there through
#: both issues — an adversarial reviewer flagged it, it was declined once, and the
#: family's own convention refutes the decline: the inverse is
#: `descriptor_to_java(descriptor)`, i.e. the parameter is named after WHAT THE
#: VALUE IS, and this value is a TYPE (a class, a primitive, or an array).
_RETIRED_SPELLINGS = frozenset(
    {
        "signature",  # dexllm#68 — reserved for the dotted Java rendering
        "class_id",
        "method_id",
        "field_id",  # dexllm#69 §5 — a dex table position is `_idx`
        "reg_num",  # …and any other ordinal is `_index`
        "java_name",  # §1 — the dotted rendering of a type is `java_type`
        "api_hits",
        "rows",  # §2 — a shape word
        "cls_name",
        "ret_type",
        "params_type",  # §4 — the AST keys
    }
)


def test_no_public_parameter_carries_a_retired_spelling():
    """dexllm#68 + #69 at the PARAMETER axis — the one dexllm#44 does not reach.

    #44 locks a parameter name raw<->port and MCP-schema<->impl. A module-level
    helper has neither twin, so `dexllm.java_to_descriptor(java_name=...)` kept a
    word both issues retired, on a public keyword-callable surface, through both.

    Scanned: every public module function, every port and adapter method, every
    MCP impl AND its advertised schema, and the raw pybind signatures — the same
    four layers #44 audits, one axis over.
    """
    import importlib
    import inspect
    import pkgutil

    from conftest import raw_param_names

    from dexllm import sdk, tools

    offenders, scanned = [], 0

    def note(where, fn):
        nonlocal scanned
        try:
            params = inspect.signature(fn).parameters
        except (TypeError, ValueError):
            return
        for name in params:
            if name in ("self", "args", "kwargs"):
                continue
            scanned += 1
            if name in _RETIRED_SPELLINGS:
                offenders.append(f"{where}({name})")

    mods = [dexllm] + [
        importlib.import_module(f"dexllm.{m.name}")
        for m in pkgutil.iter_modules(dexllm.__path__)
        if m.name not in ("mcp_server", "server")  # optional extras (CI has neither)
    ]
    for mod in mods:
        for n, o in vars(mod).items():
            if not n.startswith("_") and inspect.isfunction(o):
                note(f"{mod.__name__}.{n}", o)
    for mod in (sdk.ports, sdk.adapter):
        for n, o in vars(mod).items():
            if n.startswith("_") or not isinstance(o, type):
                continue
            for mn, mo in vars(o).items():
                if not mn.startswith("_") and callable(mo):
                    note(f"{o.__name__}.{mn}", mo)
    for n, fn in tools.TOOL_IMPLS.items():
        note(f"mcp:{n}", fn)
    for d in tools.tool_definitions():
        for prop in (d.get("input_schema") or {}).get("properties", {}):
            scanned += 1
            if prop in _RETIRED_SPELLINGS:
                offenders.append(f"mcp-schema:{d['name']}({prop})")
    for n in dir(dexllm.DexKit):
        if n.startswith("_"):
            continue
        try:
            params = raw_param_names(getattr(dexllm.DexKit, n))
        except Exception:  # noqa: BLE001 - not every attribute has a signature
            continue
        for name in params or []:
            scanned += 1
            if name in _RETIRED_SPELLINGS:
                offenders.append(f"raw:DexKit.{n}({name})")

    assert scanned >= 300, f"only {scanned} parameters scanned — the walk is broken"
    assert (
        not offenders
    ), f"these parameters carry a spelling dexllm#68/#69 retired: {sorted(offenders)}"


def test_the_ast_docstring_advertises_the_keys_the_call_returns():
    """The pybind docstring is the ONLY description of the shape at a REPL.

    dexllm#69 renamed four of `decompile_method_ast`'s keys and left the docstring
    580 lines below the edit naming all four — so `help(dk.decompile_method_ast)`
    promised `cls_name` / `ret_type` / `params_type` / `access`, each a `KeyError`.
    Both reviewers found it; nothing in the repo read a docstring.
    """
    import re

    doc = dexllm.DexKit.decompile_method_ast.__doc__
    assert doc, "the binding lost its docstring"
    m = re.search(r"\{([^}]*)\}", doc)
    assert m, f"the docstring no longer names the returned keys: {doc[:120]}"
    advertised = {k.strip() for k in m.group(1).split(",") if k.strip()}

    dk = dexllm.DexKit(COMMITTED_APK)
    cls = sorted(dk.list_classes())[0]
    actual = set(dk.decompile_method_ast(dk.list_class_methods(cls)[0]))
    assert advertised == actual, (
        f"advertised-but-absent {sorted(advertised - actual)} | "
        f"returned-but-undocumented {sorted(actual - advertised)}"
    )


def test_the_permission_models_name_the_entities_not_the_table_shape():
    """dexllm#69 §2 at the ATTRIBUTE level — `rows` is a presentation word.

    The type rename (`PermissionCallerRow` -> `ApiCallers`) is covered by the
    suffix audit; the FIELD holding them is a separate name and was covered by
    nothing.
    """
    from dexllm.sdk.model import ApiCallers, PermissionCallers

    assert {f.name for f in dataclasses.fields(PermissionCallers)} == set(
        _PERMISSION_MODEL_FIELDS
    )
    assert {f.name for f in dataclasses.fields(ApiCallers)} == set(
        _API_CALLERS_MODEL_FIELDS
    )
    # the element type is what the field is named for, so the two cannot drift apart
    assert (
        PermissionCallers.__dataclass_fields__["apis"].type == "tuple[ApiCallers, ...]"
    )


def test_both_producers_of_the_permission_group_agree_on_its_keys():
    """SOURCE-level, because the committed fixture can never exercise this.

    `tests/data/multidex.apk` has TWO external method refs and matches no
    permission-gated API, so a behavioural guard here would SKIP in the corpus-less
    CI leg forever — a guard that never fires
    [[a-guard-can-pass-having-exercised-nothing]]. The runtime half is the
    corpus-gated twin below; this half is what runs everywhere.

    A source pin is WEAKER than a behavioural one — it cannot see a key that is
    present and wrong — and saying so is part of the record.
    """
    cpp = Path(__file__).parent.parent / "native" / "binding" / "module.cpp"
    py = Path(__file__).parent.parent / "src" / "dexllm" / "dangerous_api.py"
    body = _between(
        cpp.read_text(), "py::list permission_callers(bool app_only)", "\n    }"
    )
    cpp_keys = set(re.findall(r'gd\["(\w+)"\]', body))
    assert cpp_keys == set(
        _PERMISSION_GROUP_KEYS
    ), f"the C++ producer emits {sorted(cpp_keys)}"
    py_src = py.read_text()
    m = re.search(r"result\.append\(\{([^}]*)\}\)", py_src)
    assert m, "the python producer's dict literal moved — re-anchor this guard"
    py_keys = set(re.findall(r'"(\w+)":', m.group(1)))
    assert py_keys == set(
        _PERMISSION_GROUP_KEYS
    ), f"the python producer emits {sorted(py_keys)}"
    assert (
        "rows" not in cpp_keys | py_keys
    ), "`Row` is a table shape, not what the record IS (dexllm#69 §2)"


def test_both_permission_producers_agree_at_runtime(loadable_apks):
    """The behavioural twin — corpus-gated, so it SKIPS where there is no APK."""
    from dexllm.dangerous_api import permission_api_callers

    checked = 0
    for p in loadable_apks:
        d = dexllm.DexKit(p)
        cpp = d.permission_callers()
        if not cpp:
            continue
        checked += 1
        py = permission_api_callers(d)
        assert {frozenset(g) for g in cpp} == {frozenset(g) for g in py}
        for g in list(cpp) + list(py):
            assert set(g) == set(_PERMISSION_GROUP_KEYS)
        if checked == 2:  # two independent samples is enough evidence
            break
    require_corpus_shape(
        checked,
        "an APK exercising a permission-gated API",
        "both producers stopped emitting any permission group",
    )


def _between(text: str, start: str, end: str) -> str:
    """The source between an anchor and the next `end`, or a loud failure."""
    i = text.find(start)
    assert i != -1, f"anchor {start!r} not found — re-anchor this guard"
    j = text.find(end, i)
    assert j != -1, f"end {end!r} not found after {start!r}"
    return text[i:j]
