"""Tests for the dexllm SDK (typed ports & adapters) API.

Self-contained tests (imports, Protocol runtime-checkability, frozen/immutable
models) always run; the end-to-end conformance tests use the ``apk_path`` fixture
and skip without a test APK.
"""

import dataclasses
import pathlib
from types import MappingProxyType

import pytest
from _records import assert_skips_are_optional, public_record_attrs
from conftest import require_corpus_shape

from dexllm.sdk import (
    CacheControlPort,
    CapabilityPort,
    CapabilityReport,
    ClassInspectionPort,
    ClassRef,
    ContainerInfo,
    ContainerProbe,
    ContainerProbePort,
    ContentProviderPort,
    CrossReferencePort,
    DecompilationPort,
    DecompiledMethod,
    DexAnalysisUseCase,
    DexExtractionPort,
    EnumerationPort,
    ExternalFieldRef,
    ExternalMethodRef,
    ExternalTypeRef,
    IndicatorExtractionPort,
    IocReport,
    MethodAst,
    MethodRef,
    PermissionAnalysisPort,
    PermissionCallers,
    ResolvedArg,
    SearchPort,
    SourceLocation,
    StatementLocation,
    identify,
    open_apk,
)

_PORTS = [
    DexAnalysisUseCase,
    DecompilationPort,
    EnumerationPort,
    DexExtractionPort,
    ClassInspectionPort,
    CrossReferencePort,
    SearchPort,
    PermissionAnalysisPort,
    IndicatorExtractionPort,
    CapabilityPort,
    ContentProviderPort,
    CacheControlPort,
]

# value-object models (only tuple/scalar fields) — must be hashable
_HASHABLE_MODELS = [
    ContainerInfo,
    DecompiledMethod,
    SourceLocation,
    StatementLocation,
    ResolvedArg,
    PermissionCallers,
    IocReport,
    ExternalMethodRef,
    ExternalFieldRef,
    ExternalTypeRef,
    ClassRef,
    MethodRef,
]
# models carrying a Mapping — frozen but NOT hashable (documented)
_MAPPING_MODELS = [CapabilityReport, MethodAst]

# dexllm#21's adapter-only back-compat spellings were REMOVED (issue #24 resolved
# by deletion, not by a warning policy). Kept as an empty set so the drift audit
# below still states "no adapter method outside the ports except `.raw`" as an
# explicit allowance rather than an implicit one.
_DEPRECATED_ALIASES: set[str] = set()

# ── the raw ↔ port name boundary (dexllm#21) ─────────────────────────────────
# One operation, one spelling: a raw `DexKit` method and its port method share a
# name. The whole dexllm#21 series existed because that had drifted and nothing
# noticed. These are the ONLY licensed exceptions; anything else fails the audit.

# raw-only deprecated spellings — now EMPTY: the nine pre-rename names were
# removed rather than carried forever (issue #24). The mapping (alias → canonical)
# stays as the declared shape, so re-introducing an alias is a conscious edit and
# the audit still refuses to let one smuggle in an unrelated new raw method.
_RAW_DEPRECATED_ALIASES: dict[str, str] = {}

# raw-only, because the SDK deliberately DECOMPOSES it (ISP) — a different
# operation shape, so a different name is correct. Maps raw name → port pieces.
_RAW_DECOMPOSED = {"get_class_summary": ("class_info", "class_fields", "class_methods")}

# SDK-only record types (dexllm#37's type axis). Each is genuinely SDK-side: a
# composite the raw layer has no single object for, or a raw dict/tuple return
# given a type. None of them is a second name for a registered pybind class —
# that is exactly what the audit refuses.
_SDK_ONLY_MODELS = {
    # raw returns a plain dict
    "ContainerInfo",
    "DexVerifyStatus",
    "ExtractedDex",
    "DecompiledMethod",
    "DecompiledClass",
    "MethodAst",
    "SourceLocation",
    "StatementLocation",
    # raw returns nested dicts / lists from a module-level python function
    "IocReport",
    "Indicator",
    "ContentProviderUse",
    "CapabilityReport",
    "ApiUsage",
    "PermissionCallers",
    "ApiCallers",
    # the ISP split of raw's ClassSummary (see _RAW_DECOMPOSED)
    "ClassInfo",
}

# raw-only record types. `ClassSummary` is the god-object the SDK decomposes into
# ClassInfo + FieldInfo + MethodInfo, so it correctly has no single SDK twin.
_RAW_ONLY_MODELS = {"ClassSummary"}

# port-only, because the raw layer exposes them as MODULE-level dexllm functions
# rather than DexKit methods — a location difference, not a naming drift.
_PORT_FROM_MODULE_FUNCTION = {
    "identify",
    "verify",
    "extract_iocs",
    "detect_content_providers",
    "summarize_capabilities",
}


# ── self-contained ────────────────────────────────────────────────────────────


def test_ports_are_runtime_checkable():
    """Every port is a @runtime_checkable Protocol (isinstance works structurally)."""
    for port in _PORTS:
        assert not isinstance(object(), port)  # a bare object is not a session


def test_all_models_are_frozen_dataclasses():
    for model in _HASHABLE_MODELS + _MAPPING_MODELS:
        assert dataclasses.is_dataclass(model)
        assert model.__dataclass_params__.frozen  # type: ignore[attr-defined]


def test_value_object_models_are_hashable():
    """Models with only tuple/scalar fields honour the documented hashability."""
    loc = SourceLocation(line=4, byte_offset=24)
    assert hash(loc) == hash(SourceLocation(line=4, byte_offset=24))
    with pytest.raises(dataclasses.FrozenInstanceError):
        loc.line = 5  # type: ignore[misc]


def test_mapping_backed_models_are_immutable_but_not_hashable():
    """CapabilityReport / MethodAst hold a Mapping: read-only view, not hashable."""
    cr = CapabilityReport(
        catalog_version="v",
        catalog_size=1,
        matched_apis=0,
        total_call_sites=0,
        permissions={"A": 1},
        categories={},
        flags={},
        api_usages=(),
        by_caller={},
    )
    assert isinstance(cr.permissions, MappingProxyType)
    assert isinstance(cr.flags, MappingProxyType)
    with pytest.raises(TypeError):  # in-place mutation blocked
        cr.permissions["INJECT"] = 9  # type: ignore[index]
    with pytest.raises(TypeError):  # not hashable (documented)
        hash(cr)

    ma = MethodAst(
        found=True,
        class_descriptor="C",
        name="m",
        proto="()V",
        return_type="void",
        param_types=(),
        access_flags=("public",),
        source="",
        ast={"body": []},
        pc_map=(),
    )
    assert isinstance(ma.ast, MappingProxyType)
    with pytest.raises(TypeError):
        hash(ma)
    # ast may be None (not-found method) — the field is Optional
    assert (
        MethodAst(
            found=False,
            class_descriptor="",
            name="",
            proto="",
            return_type="",
            param_types=(),
            access_flags=(),
            source="",
            ast=None,
            pc_map=(),
        ).ast
        is None
    )


def test_arg_origin_only_kinds_field_is_set():
    """The typed ResolvedArg sets only the field its kind carries."""
    a = ResolvedArg(kind="ConstString", register_index=2, string_value="s")
    assert a.string_value == "s" and a.int_value is None and a.class_descriptor is None


# ── end-to-end (APK) ──────────────────────────────────────────────────────────


def test_open_apk_conforms_to_use_case(apk_path):
    """open_apk returns an object satisfying DexAnalysisUseCase + every sub-port."""
    session = open_apk(apk_path)
    assert isinstance(session, DexAnalysisUseCase)
    for port in _PORTS:
        assert isinstance(session, port), f"session is not a {port.__name__}"
    assert session.dex_count() >= 1
    assert type(session.raw).__name__ == "DexKit"  # escape hatch


def test_sources_round_trip_and_pathlib(apk_path):
    """Single str and pathlib.Path inputs both round-trip through .sources."""
    session = open_apk(apk_path)
    assert session.sources == (apk_path,)
    assert open_apk(pathlib.Path(apk_path)).sources == (apk_path,)
    # apk_path is the primary source convenience — equal to sources[0]
    assert session.apk_path == session.sources[0] == apk_path


def test_identify_and_container_probe(apk_path):
    info = identify(apk_path)
    assert isinstance(info, ContainerInfo)
    assert info.format in ("zip", "dex") and info.dex_count >= 1
    # `is_apk` is exactly "a zip carrying an AndroidManifest.xml"
    # (dexkit_ext.cpp `info.is_apk = p.has_manifest`) — asserting it outright
    # asserted a corpus fact, and multidex.apk is a manifest-less zip.
    assert info.is_apk == (info.format == "zip" and info.has_manifest)
    probe = ContainerProbe()
    assert isinstance(probe, ContainerProbePort)
    assert probe.identify(apk_path) == info


def test_typed_decompile_and_pc_map(apk_path, sample_method):
    session = open_apk(apk_path)
    dm = session.decompile_method_with_pc_map(sample_method)
    assert isinstance(dm, DecompiledMethod)
    assert dm.found and "{" in dm.source
    assert all(isinstance(e, SourceLocation) for e in dm.pc_map)
    # AST path: statement-index pc_map is a distinct typed model, not SourceLocation
    ast = session.decompile_method_ast(sample_method)
    assert ast.found and isinstance(ast.ast, MappingProxyType)
    assert all(isinstance(e, StatementLocation) for e in ast.pc_map)
    # access_flags is the decoded modifier-name tuple[str, ...] (NOT an int bitmask);
    # guards against a revert of adapter.py's tuple(r["access_flags"]) back to a list.
    assert isinstance(ast.access_flags, tuple)
    assert all(isinstance(a, str) for a in ast.access_flags)


def test_external_ref_decompiles_to_not_found(apk_path):
    """An external / framework ref: empty text (found=False) and a None AST."""
    session = open_apk(apk_path)
    ext = "Landroid/util/Log;->d(Ljava/lang/String;Ljava/lang/String;)I"
    assert session.decompile_method(ext).found is False
    assert session.decompile_method_ast(ext).ast is None


def test_typed_enumeration_and_xref(apk_path):
    """Enumeration + xref conversions produce the typed models with correct fields."""
    session = open_apk(apk_path)
    refs = session.list_external_method_refs(framework_only=True)
    assert all(isinstance(r, ExternalMethodRef) for r in refs)
    # reference or ARRAY owner, never a primitive — `[Ljava/lang/Object;->clone()`
    # is a real external ref (3 of hello-world's 3443), which the previous
    # first-element-only check happened not to sample.
    assert all(
        r.class_descriptor[:1] in ("L", "[") and isinstance(r.parameters, tuple)
        for r in refs
    )
    # external field / type refs — symmetric with method refs, distinct typed models.
    frefs = session.list_external_field_refs(framework_only=True)
    assert all(isinstance(f, ExternalFieldRef) for f in frefs)
    assert all(
        f.descriptor == f"{f.class_descriptor}->{f.name}:{f.type}" for f in frefs
    )
    trefs = session.list_external_type_refs(framework_only=True)
    assert all(isinstance(t, ExternalTypeRef) for t in trefs)
    # external types are reference (L…;) or array ([…) descriptors, never primitives
    assert all(t.descriptor and t.descriptor[0] in "L[" for t in trefs)
    # find_call_sites_to / resolve_call_args → typed, with per-kind ResolvedArg
    crossed = 0
    for rc in session.resolve_call_args(
        "Landroid/util/Log;->d(Ljava/lang/String;Ljava/lang/String;)I"
    ):
        assert rc.callee_descriptor.endswith(")I")
        for arg in rc.args:
            assert isinstance(arg, ResolvedArg) and isinstance(arg.kind, str)
            # dexllm#16: the merge marker is typed through and only ever set on
            # Unknown (a resolved value holds on every path, so it cannot "vary").
            assert isinstance(arg.crossed_branch, bool)
            assert not (arg.crossed_branch and arg.kind != "Unknown")
            crossed += int(arg.crossed_branch)
    # Every all(...) above is satisfied by an empty tuple, so a converter that
    # regressed to one would pass vacuously — these floors are what catch it.
    # An APK that references no framework FIELD at all (com.politedroid_4) is a
    # property of the sample, not a regression.
    for got, shape in (
        (refs, "framework method reference"),
        (frefs, "framework field reference"),
        (trefs, "framework type reference"),
    ):
        require_corpus_shape(
            bool(got), shape, "the typed converter regressed to an empty tuple"
        )


def test_crossed_branch_reaches_the_typed_model(apk_path):
    """dexllm#16: `crossed_branch` must survive the raw→typed conversion.

    The invariant assertions alone pass when the flag is always False (the pre-fix
    behaviour, and what a dropped kwarg in `_to_arg` would produce), so pin that at
    least one True arrives.
    """
    session = open_apk(apk_path)
    for api in (
        "Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;",
        "Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z",
        "Landroid/util/Log;->d(Ljava/lang/String;Ljava/lang/String;)I",
    ):
        for rc in session.resolve_call_args(api):
            if any(a.crossed_branch for a in rc.args):
                return
    pytest.skip("no conditional argument in this fixture APK")


def test_typed_smali_rendering(apk_path):
    """DecompilationPort renders baksmali-style smali; empty string for external."""
    session = open_apk(apk_path)
    rendered = False
    for cls in session.list_classes():
        # every declared method, not just the first: an abstract one renders the
        # `# (no code item)` marker instead of a body, so taking methods[0] made
        # the `.registers` assertion depend on which class came first (issue #46).
        for m in session.list_class_methods(cls):
            sm = session.render_method_smali(m)
            if not sm:
                continue
            # the rendered method's FIRST line is its own descriptor verbatim, and the
            # body carries smali structure — a load-bearing content check, not just
            # "non-empty" (which any smali would satisfy via a stray "->").
            assert sm.splitlines()[0] == m
            # a rendered method carries EITHER a body or the explicit no-code marker
            assert ".registers" in sm or "# (no code item)" in sm, sm
            if ".registers" not in sm:
                continue
            cs = session.render_class_smali(cls)
            assert cs.startswith(".class ") and cls in cs
            rendered = True
            break
        if rendered:
            break
    assert rendered, "no method with a code item rendered smali on the fixture APK"
    # unknown / external → empty string, never an exception
    assert session.render_method_smali("Lno/such/C;->x()V") == ""
    assert session.render_class_smali("Lno/such/C;") == ""


def test_typed_search(apk_path):
    """SearchPort — DexKit's L1–L7 search returns typed ClassRef / MethodRef.

    Verifies each hit is the right typed model with a real descriptor + dex location,
    that a hit round-trips (its descriptor is a decompilable/enumerable member), that
    match_type is honoured, and that the batch form returns an immutable mapping keyed
    by the query key with the same element type.
    """
    session = open_apk(apk_path)

    # class search → ClassRef; every hit descriptor is a real declared class
    all_classes = set(session.list_classes())
    # the needle is derived from a REAL class, so the search is exercised on any
    # sample — a hard-coded "a" matches nothing in StringTests.dex and made a
    # working search look broken (issue #46).
    needle = sorted(all_classes)[0][1:-1].rsplit("/", 1)[-1][:3]
    cmatches = session.find_classes_by_name(needle, match_type="contains")
    assert cmatches and all(isinstance(c, ClassRef) for c in cmatches)
    c0 = cmatches[0]
    assert c0.descriptor in all_classes and c0.dex_id >= 0 and needle in c0.descriptor
    # match_type is load-bearing: equals on a real descriptor returns exactly it,
    # a bogus exact name returns nothing
    exact = session.find_classes_by_name(c0.descriptor, match_type="equals")
    assert c0.descriptor in {c.descriptor for c in exact}
    assert session.find_classes_by_name("No/Such/Zzz;", match_type="equals") == ()

    # method search → MethodRef; body-string search hits are real methods
    mmatches = session.find_methods_using_strings(["http"])
    assert all(isinstance(m, MethodRef) for m in mmatches)
    for mm in mmatches:
        assert mm.descriptor.startswith("L") and "->" in mm.descriptor

    # int-literal search returns typed matches (may be empty on a tiny APK)
    assert all(
        isinstance(m, MethodRef) for m in session.find_methods_using_int_literals([1])
    )

    # find_methods_by_name is the ONLY 4-positional-arg forwarder
    # (name, match_type, declaring_class, ignore_case) — the most arg-swap-prone.
    # Scope to a REAL declaring class and assert the results are confined to it
    # (declaring_class, arg 3), then assert ignore_case (arg 4) is independently
    # wired via a case-mismatch delta. A future declaring_class/ignore_case swap
    # breaks one of these.
    for cls in session.list_classes():
        methods = session.list_class_methods(cls)
        if not methods:
            continue
        mname = methods[0].split("->", 1)[1].split("(", 1)[0]
        scoped = session.find_methods_by_name(
            mname, match_type="equals", declaring_class=cls
        )
        assert scoped and all(m.descriptor.startswith(cls + "->") for m in scoped)
        if mname.lower() != mname.upper():  # has case to flip
            miscased = mname.swapcase()
            off = session.find_methods_by_name(
                miscased, match_type="equals", declaring_class=cls, ignore_case=False
            )
            on = session.find_methods_by_name(
                miscased, match_type="equals", declaring_class=cls, ignore_case=True
            )
            assert not off and on  # case-insensitive finds it, case-sensitive doesn't
        break

    # the remaining class/method search families return the right typed tuple
    # (possibly empty — smoke coverage so an arg/converter regression surfaces)
    for hits, model in (
        (session.find_classes_by_super("Ljava/lang/Object;"), ClassRef),
        (session.find_classes_implementing("Landroid/os/Parcelable;"), ClassRef),
        (session.find_classes_by_annotation("Lkotlin/Metadata;"), ClassRef),
        (session.find_classes_using_strings(["a"]), ClassRef),
        (session.find_methods_by_annotation("Lkotlin/Metadata;"), MethodRef),
        (session.find_methods_using_double_literals([1.0]), MethodRef),
    ):
        assert isinstance(hits, tuple) and all(isinstance(h, model) for h in hits)

    # batch (both sides) → immutable Mapping keyed by query key, same element type,
    # and each per-key result equals the single-query result (shared-trie ≡ N calls)
    batch = session.batch_find_methods_using_strings({"q": ["http"]})
    assert isinstance(batch, MappingProxyType) and set(batch) == {"q"}
    assert {m.descriptor for m in batch["q"]} == {m.descriptor for m in mmatches}
    cbatch = session.batch_find_classes_using_strings({"q": ["a"]})
    assert isinstance(cbatch, MappingProxyType) and set(cbatch) == {"q"}
    assert all(isinstance(c, ClassRef) for c in cbatch["q"])


def test_search_rejects_bare_string(apk_path):
    """A bare str where a Sequence[str] is expected is a footgun (per-char search) —
    the adapter raises TypeError instead of silently ANDing single characters."""
    session = open_apk(apk_path)
    with pytest.raises(TypeError):
        session.find_methods_using_strings("http")  # must be ["http"]
    with pytest.raises(TypeError):
        session.find_classes_using_strings("http")
    with pytest.raises(TypeError):
        session.batch_find_methods_using_strings({"q": "http"})  # bare value


def test_cache_control(apk_path, sample_method):
    """CacheControlPort — the operational cache/lifecycle knobs actually take effect:
    capacity set/get round-trips, the size reflects a decompile then a clear, and
    warm_analysis_caches is a no-op-safe None-returning call."""
    session = open_apk(apk_path)
    assert isinstance(session, CacheControlPort)
    session.set_decompiler_cache_capacity(8192)
    assert session.decompiler_cache_capacity() == 8192
    session.clear_decompiler_cache()
    assert session.decompiler_cache_size() == 0
    session.decompile_method(sample_method)  # caches one entry
    assert session.decompiler_cache_size() == 1
    session.clear_decompiler_cache()
    assert session.decompiler_cache_size() == 0
    assert session.warm_analysis_caches() is None  # operational, returns nothing


def test_cache_is_per_session_and_lru_bounded(apk_path):
    """The decompiler cache is PER-SESSION (per DexKit instance), not process-global,
    and the LRU capacity is enforced. Both are the contract the port's docstrings
    imply and the properties a long-lived embedder relies on — a future refactor to a
    global singleton or an unbounded cache would leave the single-session test green
    while breaking these."""
    a, b = open_apk(apk_path), open_apk(apk_path)
    # cross-session isolation: mutating a's cache must not touch b's
    a.set_decompiler_cache_capacity(123)
    assert b.decompiler_cache_capacity() != 123  # b keeps the default
    m = next(mm for c in a.list_classes() for mm in a.list_class_methods(c)[:1] if mm)
    a.clear_decompiler_cache()
    b.clear_decompiler_cache()
    a.decompile_method(m)
    assert a.decompiler_cache_size() == 1 and b.decompiler_cache_size() == 0

    # LRU cap enforced: cap=1, two distinct methods -> size never exceeds 1
    two = [mm for c in a.list_classes() for mm in a.list_class_methods(c)][:2]
    if len(two) >= 2 and two[0] != two[1]:
        a.set_decompiler_cache_capacity(1)
        a.clear_decompiler_cache()
        a.decompile_method(two[0])
        a.decompile_method(two[1])
        assert a.decompiler_cache_size() <= 1


def test_forward_string_accessors_typed(apk_path):
    """EnumerationPort forward string accessors return tuples and stay consistent:
    a class's strings contain its methods' strings and are a subset of the app feed;
    a dotted (non-descriptor) target raises the guiding ValueError."""
    session = open_apk(apk_path)
    app = set(session.list_value_strings())
    for cls in session.list_classes():
        cs = session.list_class_strings(cls)
        assert isinstance(cs, tuple)
        assert set(cs) <= app
        for m in session.list_class_methods(cls):
            ms = session.list_method_strings(m)
            assert isinstance(ms, tuple)
            assert set(ms) <= set(cs)
        if cs:
            break
    with pytest.raises(ValueError):
        session.list_class_strings("com.foo.Bar")
    with pytest.raises(ValueError):
        session.list_method_strings("com.foo.Bar.doIt")


def test_enumeration_companions_typed(apk_path):
    """EnumerationPort companions: per-dex classes, flat member descriptors, raw dex.

    Mirrors the raw-binding test_enumeration_companions, but through the typed port —
    every return is a tuple[str, ...] (or bytes), and the invariants hold: the union
    of per-dex classes == list_classes, and extract_dex returns THIS dex's slice
    (its own magic + file_size), not the shared image.
    """
    session = open_apk(apk_path)
    all_classes = set(session.list_classes())
    per_dex: set[str] = set()
    for d in range(session.dex_count()):
        chunk = session.list_classes_in_dex(d)
        assert isinstance(chunk, tuple)
        per_dex |= set(chunk)
    assert per_dex == all_classes
    assert session.list_classes_in_dex(9999) == ()

    fields = session.list_fields()
    methods = session.list_methods()
    assert isinstance(fields, tuple) and isinstance(methods, tuple)
    assert methods
    # a dex CAN declare no field at all (ExceptionHandling.dex) — that is a
    # property of the sample, not an enumerator that stopped walking (#46).
    require_corpus_shape(
        bool(fields), "declared field", "list_fields stopped enumerating"
    )
    assert all(":" in f and "->" in f for f in fields[:50])
    assert all("(" in m and "->" in m for m in methods[:50])
    # the all-dexes form is exactly the per-dex concatenation (uniform scope axis)
    f_concat: tuple[str, ...] = ()
    m_concat: tuple[str, ...] = ()
    for d in range(session.dex_count()):
        f_concat += session.list_fields_in_dex(d)
        m_concat += session.list_methods_in_dex(d)
    assert f_concat == fields and m_concat == methods
    assert session.list_fields_in_dex(9999) == ()
    assert session.list_methods_in_dex(-1) == ()

    raw = session.extract_dex(0).data
    assert isinstance(raw, bytes) and raw[:4] == b"dex\n"
    # the slice is THIS dex only — length == the header's file_size, not the map len
    assert len(raw) == int.from_bytes(raw[32:36], "little")
    assert session.extract_dex(9999).data == b""


def test_enumeration_companions_multidex():
    """Genuine multidex: per-dex enumeration must SLICE by dex, not ignore dex_id.

    The single-dex apk_path fixture makes the union/concat invariants vacuous (a
    broken "return everything regardless of dex_id" impl would still pass), so this
    loads a real >1-dex container. Asserts: class slices are DISJOINT/non-empty and
    partition list_classes; extract_dex yields a distinct dex per id; and the
    field/method aggregate equals the per-dex CONCATENATION with a genuine cross-dex
    duplicate present (so a set-union impl would drop it and fail) — the case the
    single-dex fixture cannot exercise.
    """
    import glob
    import os

    apk = os.path.join(
        os.path.dirname(__file__), "..", "test_apk", "APK", "multidex.apk"
    )
    if not glob.glob(apk):
        pytest.skip("multidex.apk fixture missing")
    session = open_apk(apk)
    if session.dex_count() < 2:
        pytest.skip("multidex.apk did not load as >1 dex")
    slices = [set(session.list_classes_in_dex(d)) for d in range(session.dex_count())]
    assert all(slices), "a dex slice is empty"
    for i in range(len(slices)):
        for j in range(i + 1, len(slices)):
            assert slices[i].isdisjoint(slices[j]), "per-dex class slices overlap"
    union: set[str] = set()
    for s in slices:
        union |= s
    assert union == set(session.list_classes())
    # locate_class_dex must attribute each class to its OWN dex across >1 dex — the
    # cross-dex case a single-dex fixture can't exercise (a class in dex 1 must
    # return 1). One sample per dex keeps it cheap.
    for d in range(session.dex_count()):
        sample = next(iter(slices[d]))
        assert session.locate_class_dex(sample) == d
        assert session.class_info(sample).dex_id == d  # cheap path == heavy path
    # each dex extracts as its own dex blob (own magic + own file_size)
    for d in range(session.dex_count()):
        b = session.extract_dex(d).data
        assert b[:4] == b"dex\n" and len(b) == int.from_bytes(b[32:36], "little")

    # field/method descriptors: the all-dexes form is the per-dex CONCATENATION,
    # NOT a set union — the dex id-tables reference the same framework members
    # (java/lang/Object etc.) from both dexes, so those recur. This is the case the
    # single-dex fixture can't exercise: assert the aggregate carries a genuine
    # cross-dex duplicate (so a union-based impl would drop it and FAIL the concat
    # equality below — the assertion is non-vacuous here).
    m_agg = session.list_methods()
    m_concat: tuple[str, ...] = ()
    for d in range(session.dex_count()):
        m_concat += session.list_methods_in_dex(d)
    assert m_concat == m_agg
    assert len(m_agg) > len(set(m_agg)), "expected cross-dex method recurrence"
    f_agg = session.list_fields()
    f_concat: tuple[str, ...] = ()
    for d in range(session.dex_count()):
        f_concat += session.list_fields_in_dex(d)
    assert f_concat == f_agg


def test_field_xref_readers_writers(apk_path):
    """CrossReferencePort exposes field read/write xref (L2.5): the descriptors of
    methods that iget*/sget* (read) or iput*/sput* (write) a field. The direction is
    verified against the smali (via session.raw) so readers/writers can't be swapped.
    """
    session = open_apk(apk_path)
    for cls in session.list_classes():
        summary = session.raw.get_class_summary(cls)
        for f in getattr(summary, "fields", []):
            fd = f"{cls}->{f.name}:{f.type}"
            readers = session.find_methods_reading_field(fd)
            writers = session.find_methods_writing_field(fd)
            assert all(isinstance(m, str) and "->" in m for m in readers + writers)
            reader_only = [m for m in readers if m not in writers]
            writer_only = [m for m in writers if m not in readers]
            if reader_only:
                sm = session.raw.render_method_smali(reader_only[0])
                assert f.name in sm and ("iget" in sm or "sget" in sm)
                return
            if writer_only:
                sm = session.raw.render_method_smali(writer_only[0])
                assert f.name in sm and ("iput" in sm or "sput" in sm)
                return
    pytest.skip("no field with a direction-distinct read/write xref in the test APK")


def test_class_inspection_decomposed(apk_path):
    """ClassInspectionPort exposes class metadata + fields as SEPARATE fine-grained
    queries (the decomposition of the C++ get_class_summary god-object); methods stay
    on EnumerationPort.list_class_methods."""
    from dexllm.sdk import ClassInfo, ClassInspectionPort, FieldInfo

    session = open_apk(apk_path)
    assert isinstance(session, ClassInspectionPort)
    cls = next(
        c
        for c in session.list_classes()
        if session.raw.get_class_summary(c).is_internal
    )
    info = session.class_info(cls)
    assert isinstance(info, ClassInfo)
    assert info.descriptor == cls and info.superclass_descriptor.startswith("L")
    # the declaring dex's file name is reported directly (an internal class → non-empty,
    # and it agrees with verify_report's name for that dex_id)
    dex_names = {v.dex_id: v.name for v in session.verify_report()}
    assert info.dex_name == dex_names[info.dex_id]
    assert info.dex_name.endswith(".dex")
    fields = session.class_fields(cls)
    assert all(isinstance(f, FieldInfo) for f in fields)
    # methods are the separate list_class_methods query, not bundled here
    assert isinstance(session.list_class_methods(cls), tuple)
    # locate_class_dex — the cheap dex-attribution lookup; equals class_info().dex_id
    # (same result, cheaper path) and -1 for a class no dex declares
    assert session.locate_class_dex(cls) == info.dex_id
    assert session.locate_class_dex("Lno/such/Class;") == -1


def test_dex_name_excludes_rejected_dex(apk_path):
    """A rejected dex (verify_report dex_id=-1) must NOT leak its name onto the shared
    -1 sentinel that external classes use — the map excludes dex_id < 0."""
    import types

    session = open_apk(apk_path)
    # inject a verify_report with a rejected (dex_id=-1) dex, then re-read the lazy map
    session._dk = types.SimpleNamespace(  # type: ignore[assignment]
        verify_report=lambda: [
            {"dex_id": 0, "name": "classes.dex"},
            {"dex_id": -1, "name": "classes2.dex"},  # rejected / unverifiable dex
        ]
    )
    session._dex_names = None
    assert session._dex_name(0) == "classes.dex"
    assert (
        session._dex_name(-1) == ""
    )  # external / rejected → empty, not 'classes2.dex'


def test_type_references_xref(apk_path):
    """CrossReferencePort.find_type_references — signature-position type xref."""
    from dexllm.sdk import TypeReferences

    session = open_apk(apk_path)
    # a type sure to be referenced: java.lang.String
    tr = session.find_type_references("Ljava/lang/String;")
    assert isinstance(tr, TypeReferences)
    assert all(isinstance(x, str) for x in tr.fields + tr.methods_returning)
    # a method that returns String must have descriptor ending in the type
    assert all(m.endswith(")Ljava/lang/String;") for m in tr.methods_returning)


def test_call_sites_from_method_callees(apk_path):
    """CrossReferencePort.find_call_sites_from — the CALLEE direction, typed.

    The forward of find_call_sites_to: each CallSite fixes the caller (this method) and
    varies callee. Verified symmetric — the method is a caller of its own callee — and
    empty for an external/unresolved method."""
    from dexllm.sdk import CallSite

    session = open_apk(apk_path)
    for cls in session.list_classes():
        for m in session.list_class_methods(cls):
            callees = session.find_call_sites_from(m)
            if callees:
                assert all(isinstance(c, CallSite) for c in callees)
                assert all(c.caller_descriptor == m for c in callees)  # caller fixed
                # forward ≡ reverse for EVERY distinct callee
                for callee in {c.callee_descriptor for c in callees}:
                    callers = {
                        c.caller_descriptor for c in session.find_call_sites_to(callee)
                    }
                    assert m in callers
                assert session.find_call_sites_from("Lno/x;->y()V") == ()
                return
    pytest.skip("no method with a callee in the test APK")


def test_call_site_names_are_unified_across_layers(apk_path):
    """dexllm#21: raw DexKit, the SDK port/adapter and the MCP catalog all spell the
    pair find_call_sites_to / find_call_sites_from — and nothing spells it any other
    way, now that the pre-rename aliases are removed on every layer. The argument is
    `method_descriptor` in BOTH directions: the method name carries the role, the
    parameter names what the value IS."""
    import dexllm
    from dexllm import tools

    session = open_apk(apk_path)
    for name in ("find_call_sites_to", "find_call_sites_from"):
        assert hasattr(CrossReferencePort, name)  # the port states the contract
        assert hasattr(dexllm.DexKit, name)  # raw agrees
        assert any(t["name"] == name for t in tools.TOOL_DEFINITIONS)  # MCP agrees
    # no layer carries any other spelling of the pair
    assert not hasattr(tools, "TOOL_ALIASES")  # the catalog is one name per tool
    for gone in (
        "find_call_sites",
        "find_call_sites_to_api",
        "find_call_sites_from_method",
    ):
        assert not hasattr(CrossReferencePort, gone)
        assert not hasattr(session, gone)
        assert not hasattr(dexllm.DexKit, gone)
        assert gone not in tools.TOOL_IMPLS
    # The unified ARGUMENT name, on every layer that DECLARES one, checked by
    # SIGNATURE. The port needs an explicit check: a Protocol carries no runtime
    # conformance for PARAMETER names, so reverting only ports.py passes mypy and
    # every other assertion in this file (verified). `__code__.co_varnames` would
    # also match a local, so use inspect.signature.
    import inspect

    from dexllm.sdk.adapter import DexKitAdapter

    for layer, fn in (
        ("port/to", CrossReferencePort.find_call_sites_to),
        ("port/from", CrossReferencePort.find_call_sites_from),
        ("port/resolve", CrossReferencePort.resolve_call_args),
        ("adapter/to", DexKitAdapter.find_call_sites_to),
        ("adapter/from", DexKitAdapter.find_call_sites_from),
        ("adapter/resolve", DexKitAdapter.resolve_call_args),
        ("mcp/to", tools.TOOL_IMPLS["find_call_sites_to"]),
        ("mcp/resolve", tools.TOOL_IMPLS["resolve_call_args"]),
    ):
        assert "method_descriptor" in inspect.signature(fn).parameters, layer
    for spec in tools.TOOL_DEFINITIONS:
        if spec["name"] in (
            "find_call_sites_to",
            "find_call_sites_from",
            "resolve_call_args",
        ):
            assert "method_descriptor" in spec["input_schema"]["properties"], spec[
                "name"
            ]

    for cls in session.list_classes():
        for m in session.list_class_methods(cls):
            callees = session.find_call_sites_from(m)
            if not callees:
                continue
            api = callees[0].callee_descriptor
            callers = session.find_call_sites_to(api)
            assert callers  # non-vacuous: m itself is among them
            # the unified kwarg resolves on both layers, both directions
            assert session.find_call_sites_to(method_descriptor=api) == callers
            raw = session.raw
            assert [
                c.caller_descriptor
                for c in raw.find_call_sites_to(method_descriptor=api)
            ] == [c.caller_descriptor for c in raw.find_call_sites_to(api)]
            raw_fwd = raw.find_call_sites_from(method_descriptor=m)
            # and the adapter's forward direction matches raw value-for-value
            assert [c.callee_descriptor for c in callees] == [
                c.callee_descriptor for c in raw_fwd
            ]
            return
    pytest.skip("no method with a callee in the test APK")


def test_adapter_public_surface_has_no_undeclared_drift():
    """The audit invariant CLAUDE.md asserts, actually locked.

    Every public adapter member must be either declared on a port, the documented
    ``raw`` escape hatch, or one of the enumerated back-compat aliases. Without
    this, a method could be added to the adapter and never reach the contract —
    the isinstance conformance test only checks ports ⊆ adapter, not the reverse.
    """
    from dexllm.sdk.adapter import DexKitAdapter

    on_ports: set[str] = set()
    for port in _PORTS:
        on_ports |= {n for n in vars(port) if not n.startswith("_")}
    allowed = on_ports | {"raw"} | _DEPRECATED_ALIASES
    public = {n for n in dir(DexKitAdapter) if not n.startswith("_")}
    assert public - allowed == set(), f"undeclared adapter surface: {public - allowed}"


def test_raw_and_port_share_one_spelling_per_operation():
    """dexllm#21: lock the raw ↔ port name boundary so drift cannot creep back.

    The whole issue existed because `find_call_sites_to_api` (raw) and
    `find_call_sites` (port) were the same operation under two names and nothing
    noticed for three releases. A raw method and its port method must share a
    name; every exception must be one of three LICENSED kinds, declared above:
    a deprecated alias of a unified name, an ISP decomposition, or an operation
    the raw layer exposes as a module-level function.

    Set EQUALITY, not subset: removing an alias, or adding a raw method the SDK
    does not expose, both have to be a conscious edit here.
    """
    import dexllm
    import dexllm.sdk.ports as ports_mod

    raw = {n for n in dir(dexllm.DexKit) if not n.startswith("_")}
    ports: set[str] = set()
    for name in dir(ports_mod):
        obj = getattr(ports_mod, name)
        if isinstance(obj, type) and (
            name.endswith("Port") or name == "DexAnalysisUseCase"
        ):
            ports |= {m for m in vars(obj) if not m.startswith("_")}

    licensed_raw_only = set(_RAW_DEPRECATED_ALIASES) | set(_RAW_DECOMPOSED)
    assert raw - ports == licensed_raw_only, (
        f"unlicensed raw-only names: {(raw - ports) - licensed_raw_only} | "
        f"stale exceptions: {licensed_raw_only - (raw - ports)}"
    )

    licensed_port_only = _PORT_FROM_MODULE_FUNCTION | {
        piece for pieces in _RAW_DECOMPOSED.values() for piece in pieces
    }
    assert ports - raw == licensed_port_only, (
        f"unlicensed port-only names: {(ports - raw) - licensed_port_only} | "
        f"stale exceptions: {licensed_port_only - (ports - raw)}"
    )

    # An exception must be justified, not merely listed:
    for alias, canonical in _RAW_DEPRECATED_ALIASES.items():
        assert alias in raw, f"{alias} is no longer on raw"
        # the canonical it defers to must itself be unified across both layers,
        # so a brand-new raw method cannot be hidden here
        assert (
            canonical in raw and canonical in ports
        ), f"{alias} claims canonical {canonical}, which is not unified"
    for raw_name, pieces in _RAW_DECOMPOSED.items():
        assert raw_name in raw
        assert all(p in ports for p in pieces), f"{raw_name} pieces missing: {pieces}"
    for name in _PORT_FROM_MODULE_FUNCTION:
        assert callable(
            getattr(dexllm, name, None)
        ), f"{name} is not a module-level dexllm function"


def test_raw_and_port_share_one_spelling_per_argument():
    """dexllm#44: the ARGUMENT axis of one-operation-one-spelling.

    The sibling audits lock METHOD names (#21) and TYPE names (#37); parameter
    names were pinned for exactly three operations by
    `test_call_site_names_are_unified_across_layers` and were otherwise unified
    only because #21 stage 4 did it by hand. That is the state the whole #21
    series exists because of: a unification nothing keeps.

    Two rules, one per layer pair:

    1. **raw ⊇ port, in order.** A port parameter must carry the name the raw
       operation gives it, and the shared names must appear in the same relative
       order, so a positional call means the same thing on both layers. Only
       CONTAINMENT, not equality: the SDK deliberately omits knobs
       (`dataset_path`, `only_categories`), and an absence is not drift.
    2. **adapter == port, exactly.** The adapter IS the port's implementation, so
       there is no licensed difference. It needs its own check because a
       `Protocol` carries NO runtime conformance for parameter names: mypy is
       blind to a COHERENT rename on either side — verified by renaming a port
       parameter alone, and by renaming the adapter's parameter together with its
       body, both of which the CI trio accepts and this test rejects.

    Raw names are read from pybind's generated signature line, i.e. what a
    keyword call actually resolves against; an unreadable one FAILS rather than
    silently shrinking the audit to nothing.
    """
    import inspect

    from conftest import raw_param_names

    import dexllm
    import dexllm.sdk.ports as ports_mod
    from dexllm.sdk.adapter import DexKitAdapter

    port_fns: dict[str, object] = {}
    for name in dir(ports_mod):
        obj = getattr(ports_mod, name)
        if isinstance(obj, type) and (
            name.endswith("Port") or name == "DexAnalysisUseCase"
        ):
            for m, v in vars(obj).items():
                if not m.startswith("_") and inspect.isfunction(v):
                    port_fns.setdefault(m, v)

    def params(fn):
        return [p for p in inspect.signature(fn).parameters if p != "self"]

    shared = sorted(n for n in port_fns if hasattr(dexllm.DexKit, n))
    # Floor without a magic number: the sibling method audit pins raw ∩ ports
    # exactly, so every member of it must be reached AND must parse. A parser
    # that started returning None would otherwise empty this test in silence.
    assert shared, "no operation is on both raw and a port — the audit is vacuous"

    for name in shared:
        raw_names = raw_param_names(getattr(dexllm.DexKit, name))
        assert raw_names is not None, (
            f"cannot read raw parameter names for {name!r} — the audit would "
            f"silently skip it"
        )
        port_names = params(port_fns[name])
        assert not set(port_names) - set(raw_names), (
            f"{name}: port parameter(s) {sorted(set(port_names) - set(raw_names))} "
            f"are spelled differently on raw {raw_names} — one operation, one "
            f"spelling per argument"
        )
        assert [p for p in raw_names if p in set(port_names)] == port_names, (
            f"{name}: the shared parameters are ordered {port_names} on the port "
            f"but {raw_names} on raw — a positional call would mean two things"
        )

    # …the session-bound ports only: `ContainerProbePort` is the load-free probe,
    # implemented as a module-level `sdk.identify`, so it is deliberately absent
    # from the adapter (the same distinction `_PORTS` already draws).
    session_bound = {
        m: v
        for port in _PORTS
        for m, v in vars(port).items()
        if not m.startswith("_") and inspect.isfunction(v)
    }
    for name, port_fn in sorted(session_bound.items()):
        adapter_fn = getattr(DexKitAdapter, name, None)
        assert adapter_fn is not None, f"{name} is on a port but not the adapter"
        assert params(adapter_fn) == params(port_fn), (
            f"{name}: adapter {params(adapter_fn)} != port {params(port_fn)} — the "
            f"adapter implements the port, so there is no licensed difference"
        )


def test_raw_and_sdk_share_one_spelling_per_record_type():
    """dexllm#37: the same axis as above, for TYPE names.

    `test_raw_and_port_share_one_spelling_per_operation` locks METHOD names, so
    the type axis was unexamined — and `ClassMemberField` (raw) / `FieldInfo`
    (SDK) turned out to be one field-for-field identical record under two names,
    exactly the defect #21 spent three releases removing, on an axis nothing
    checked. Reverting a type rename in `model.py` passed every assertion.

    The rule is the one the nine already-shared names establish: a record type
    that exists on both layers uses ONE name. It is set equality against a
    declared exception list, so adding an SDK-only model is a conscious edit.
    """
    import dexllm.sdk.model as model
    from dexllm import _dexkit_core as core

    def _types(mod):
        return {
            n
            for n in dir(mod)
            if not n.startswith("_") and isinstance(getattr(mod, n), type)
        }

    raw_types = _types(core) - {"DexKit"}
    sdk_types = {
        n for n in _types(model) if hasattr(getattr(model, n), "__dataclass_fields__")
    }

    # Every shared name must describe the SAME record — a name shared by two
    # different shapes would be worse than two names for one shape. EQUALITY, not
    # subset: a subset check sees only fields the SDK added, and silently passes an
    # attribute raw has that the SDK dropped, which is equally "two shapes".
    for name in sorted(raw_types & sdk_types):
        sdk_fields = set(getattr(model, name).__dataclass_fields__)
        raw_attrs = {a for a in dir(getattr(core, name)) if not a.startswith("_")}
        assert sdk_fields == raw_attrs, (
            f"{name} is one name for two shapes: SDK-only "
            f"{sorted(sdk_fields - raw_attrs)}, raw-only {sorted(raw_attrs - sdk_fields)}"
        )

    # No floor on len(shared): the two set equalities below already pin it exactly
    # (shared == raw_types - _RAW_ONLY_MODELS), so a floor would be unreachable
    # dead code — verified by simulating a full revert of the #37 type unification,
    # which drops `shared` to 10 and is caught by the equalities, not by a floor.

    # An SDK model with no raw counterpart is fine only when it is genuinely
    # SDK-side — a composite, a dict-return made typed, or a value the raw layer
    # returns as a plain tuple/dict rather than a registered pybind class.
    assert sdk_types - raw_types == _SDK_ONLY_MODELS, (
        f"undeclared SDK-only models: {(sdk_types - raw_types) - _SDK_ONLY_MODELS} | "
        f"stale exceptions: {_SDK_ONLY_MODELS - (sdk_types - raw_types)}"
    )
    # …and the other direction, so a raw type the SDK never models (the thing
    # `FieldRef` WAS before #37) cannot appear unnoticed either.
    assert raw_types - sdk_types == _RAW_ONLY_MODELS, (
        f"undeclared raw-only models: {(raw_types - sdk_types) - _RAW_ONLY_MODELS} | "
        f"stale exceptions: {_RAW_ONLY_MODELS - (raw_types - sdk_types)}"
    )

    # An exception must be JUSTIFIED, not merely listed — the same defence the
    # sibling method audit applies to its alias/decomposition lists. Without it the
    # cheapest way past a failure is to add BOTH names to the two lists, which
    # absorbs the exact defect this test exists for (constructed: renaming SDK
    # `MethodRef` to `MethodHit` goes green that way, and the assertion messages
    # above name the entries to add). A raw-only type that is field-identical to an
    # SDK-only model is not two records — it is one record under two names.
    for raw_name in sorted(_RAW_ONLY_MODELS):
        raw_attrs = {a for a in dir(getattr(core, raw_name)) if not a.startswith("_")}
        for sdk_name in sorted(_SDK_ONLY_MODELS):
            sdk_fields = set(getattr(model, sdk_name).__dataclass_fields__)
            assert sdk_fields != raw_attrs, (
                f"{raw_name} (raw) and {sdk_name} (SDK) have identical fields "
                f"{sorted(raw_attrs)} — that is one record under two names, not "
                f"two records; unify the name instead of listing both"
            )


# ── dexllm#68: one Dalvik descriptor, one word for it ────────────────────────
# `signature` is reserved for the DOTTED JAVA rendering
# (`android.util.Log.d(java.lang.String) -> int`) — a genuinely different
# artifact, and the `java_` prefix already says so. Every OTHER public name
# holding the Dalvik form is `descriptor`, which is what every PARAMETER, every
# validator and every MCP schema already said while five attributes did not.
#
# Pinned as a LITERAL rather than derived: a set built by scanning for a `java_`
# prefix would accept any rename that kept the prefix, and a guard parametrised
# over the thing it guards cannot catch an EDIT of it (the dexllm#49 lesson).
_JAVA_RENDERING_ATTRS = frozenset(
    {
        "raw.ExternalFieldRef.java_signature",
        "raw.ExternalMethodRef.java_signature",
        "dexllm.sdk.model.ExternalFieldRef.java_signature",
        "dexllm.sdk.model.ExternalMethodRef.java_signature",
    }
)


def test_signature_is_reserved_for_the_dotted_java_rendering():
    """dexllm#68: the fourth NAME axis — record ATTRIBUTES.

    #21 locks method names, #37 type names, #44 argument names. Attributes were
    the axis nothing audited, and it had drifted: `ExternalMethodRef.signature`,
    `ExternalFieldRef.signature`, `ResolvedArg.field_signature` / `.method_signature`
    and `ApiUsage.api_signature` all carried the SAME Dalvik grammar the rest
    of the API spells `descriptor` — and one side's OUTPUT is the other side's
    INPUT: `find_call_sites_to(ref.signature)` resolved, at a parameter named
    `method_descriptor`. Worse than the `AttributeError` #21 removed, because BOTH
    names resolved, so a consumer that guessed wrong got a wrong attribute.

    The gap was MEASURED, not assumed, and the issue's own claim ("renaming
    `signature` in model.py to anything at all passes the whole suite") is FALSE:
    a ONE-layer rename fails 2 tests — `test_raw_and_sdk_share_one_spelling_per_
    record_type` above compares the two layers' attribute SETS. What nothing
    audited is the WORD, and a COHERENT rename across every layer was caught only
    incidentally and unevenly: `ExternalFieldRef.signature` failed **1** test (a
    value-composition assertion that happens to spell the name),
    `ApiUsage.api_signature` failed **13**. Whether a rename was noticed
    depended on how often the name appeared in an assertion.

    Set equality both ways, so a new `*signature*` attribute AND a stale exception
    both fail; the exception is JUSTIFIED by the test below, not merely listed.
    """
    import dexllm

    records, skipped = public_record_attrs()
    assert_skips_are_optional(skipped)
    # Non-vacuity. The set equality below is self-guarding in one direction (an
    # empty scan cannot equal a non-empty exception set), but a floor names the
    # cause instead of reporting four "stale exceptions".
    assert len(records) >= 25, f"only {len(records)} records enumerated"
    n_attrs = sum(len(v) for v in records.values())
    assert n_attrs >= 120, f"only {n_attrs} attributes enumerated"

    found = {
        f"{rec}.{attr}"
        for rec, attrs in records.items()
        for attr in attrs
        if "signature" in attr
    }
    # …and the MODULE surface, so `dexllm.signature()` — the helper that BUILT the
    # very string, and which this issue renamed to `method_descriptor` — cannot
    # come back either. A record audit alone would not have seen it.
    # The module NAMESPACE, not just `__all__`: an adversarial reviewer re-added
    # `dexllm.signature()` without listing it, and `from dexllm import signature`
    # worked while the audit saw nothing.
    found |= {
        f"dexllm.{n}"
        for n in set(dexllm.__all__) | {n for n in dir(dexllm) if not n.startswith("_")}
        if "signature" in n
    }

    assert found == _JAVA_RENDERING_ATTRS, (
        f"a Dalvik descriptor spelled `signature`: "
        f"{sorted(found - _JAVA_RENDERING_ATTRS)} | stale exceptions: "
        f"{sorted(_JAVA_RENDERING_ATTRS - found)}"
    )

    # The module HELPER by name and by value. A ban on one word cannot see a
    # rename to a third (`build_method_sig`), and the value audit below walks
    # record attributes, not module functions — so this one function, which is
    # the thing this issue renamed, is pinned directly.
    assert dexllm.method_descriptor("Lc/D;", "m", "(I)V") == "Lc/D;->m(I)V"


def test_the_java_rendering_exception_is_earned():
    """dexllm#68: an exception must be JUSTIFIED, not merely listed.

    Without this the cheapest way past the audit above is to add the offending
    name to `_JAVA_RENDERING_ATTRS`, which absorbs the exact defect it exists for
    — the same defence `test_raw_and_sdk_share_one_spelling_per_record_type`
    applies to its own two lists. So each exempted attribute must NOT hold a
    Dalvik descriptor, and the `descriptor` sibling on the same record must.

    Runs on the one container this repo commits, so it holds in the corpus-less
    CI leg and under any `$DEXLLM_TEST_APK` narrowing.
    """
    from conftest import REPO_ROOT

    import dexllm
    from dexllm.descriptors import is_member_descriptor, is_type_descriptor
    from dexllm.sdk import open_apk

    blob = REPO_ROOT / "tests" / "data" / "multidex.apk"
    dk = dexllm.DexKit(str(blob))
    holders = {
        "raw.ExternalMethodRef": dk.list_external_method_refs()[0],
        "raw.ExternalFieldRef": dk.list_external_field_refs()[0],
    }
    sdk = open_apk(str(blob))
    holders["dexllm.sdk.model.ExternalMethodRef"] = sdk.list_external_method_refs()[0]
    holders["dexllm.sdk.model.ExternalFieldRef"] = sdk.list_external_field_refs()[0]

    checked = 0
    for pinned in sorted(_JAVA_RENDERING_ATTRS):
        rec, _, attr = pinned.rpartition(".")
        obj = holders[rec]
        v = getattr(obj, attr)
        assert not is_member_descriptor(v) and not is_type_descriptor(v), (
            f"{pinned} holds the Dalvik descriptor {v!r} — the exception is not "
            f"earned; spell it `descriptor` rather than adding it to the list"
        )
        # …and not a Dalvik form the two validators happen not to cover. An
        # adversarial reviewer showed a proto `(Ljava/lang/String;)I`, a shorty
        # `ILL`, a bare internal name `android/util/Log` and a truncated
        # `Lc;->d` are all EXEMPTABLE under those two alone, so anything carrying
        # the internal `/` separator or the `;->` arrow is refused here too. A
        # dotted Java rendering — the ONE thing this list is for — has neither.
        assert "/" not in v and ";->" not in v, (
            f"{pinned} holds {v!r}, which is a Dalvik form (internal separator), "
            f"not the dotted Java rendering the exception is for"
        )
        # …and the other half of the rule: the record's Dalvik identity IS the
        # attribute spelled for it. Without this the audit is satisfied by
        # DELETING the descriptor attribute rather than renaming it.
        assert is_member_descriptor(
            obj.descriptor
        ), f"{rec}.descriptor holds {obj.descriptor!r}, not a member descriptor"
        checked += 1
    # …and the loop RAN: an empty exception set would satisfy every assertion
    # above by executing none of them.
    assert checked == len(_JAVA_RENDERING_ATTRS) >= 4, checked


# The audit above is a BAN on one word. The rule the docs state is the POSITIVE
# one — every name holding a Dalvik descriptor is `descriptor` — and a ban does
# not enforce it: a correctness reviewer renamed `api_descriptor` to `api_sig`
# coherently across four layers, the tests and the docs, and the whole suite stayed
# green. A third word re-creates the exact one-concept-two-names defect this issue
# exists to ratchet, so the positive half is checked by VALUE below.
#
# These are the attributes whose live value IS a descriptor and whose name is not.
# Each must be JUSTIFIED, and the two kinds are different:
_DESCRIPTOR_ROLE_ATTRS = frozenset(
    {
        # ROLE — the name says WHICH descriptor it is, and BOTH layers agree, so
        # there is one concept with one name. `type` on a field ref is the field's
        # type, not its identity; that identity is `descriptor`.
        "raw.ExternalFieldRef.type",
        "sdk.ExternalFieldRef.type",
        "raw.ExternalMethodRef.return_type",
        "sdk.ExternalMethodRef.return_type",
        "raw.ExternalMethodRef.parameters",
        "sdk.ExternalMethodRef.parameters",
        "sdk.MethodAst.return_type",
        "sdk.MethodAst.param_types",
        "raw.ApiUsage.callers",
        "sdk.ApiUsage.callers",
        "sdk.ApiCallers.descriptors",  # spelled, listed for completeness
    }
)
#: DRIFT — a genuine one-value-two-names divergence. dexllm#69 CLOSED the three
#: this list was created to hold (`sdk.ClassInfo.superclass` /
#: `.interfaces`, which the SDK had shortened away from the raw
#: `*_descriptor(s)` spelling, and `sdk.MethodAst.class_name`, whose raw key was
#: a third spelling `cls_name`), so it is EMPTY. It is kept as a declaration
#: rather than deleted: re-introducing a drift then has to be a conscious edit,
#: the same shape as dexllm#21 stage 4's now-empty alias lists.
_DESCRIPTOR_NAME_DRIFT: frozenset[str] = frozenset()


def _descriptor_valued_attrs(source):
    """``{'raw.X.attr'|'sdk.X.attr'}`` whose LIVE value is a Dalvik descriptor."""
    import dexllm
    from dexllm.descriptors import is_member_descriptor, is_type_descriptor
    from dexllm.sdk import open_apk

    def is_desc(v):
        return isinstance(v, str) and (is_member_descriptor(v) or is_type_descriptor(v))

    def desc_valued(v):
        if is_desc(v):
            return True
        return bool(isinstance(v, (list, tuple)) and v and all(is_desc(x) for x in v))

    found = set()

    def probe(label, obj):
        for a in dir(obj):
            if a.startswith("_"):
                continue
            try:
                v = getattr(obj, a)
            except Exception:  # noqa: BLE001 - a property may legitimately raise
                continue
            if not callable(v) and desc_valued(v):
                found.add(f"{label}.{a}")

    dk = dexllm.DexKit(source)
    sdk = open_apk(source)
    cls = sorted(dk.list_classes())[0]
    for layer, h in (("raw", dk), ("sdk", sdk)):
        for r in h.list_external_method_refs()[:3]:
            probe(f"{layer}.ExternalMethodRef", r)
        for r in h.list_external_field_refs()[:3]:
            probe(f"{layer}.ExternalFieldRef", r)
        for r in h.list_external_type_refs()[:3]:
            probe(f"{layer}.ExternalTypeRef", r)
        for m in h.find_classes_by_name("a", match_type="Contains")[:3]:
            probe(f"{layer}.ClassRef", m)
        for m in h.find_methods_by_name("a", match_type="Contains")[:3]:
            probe(f"{layer}.MethodRef", m)
        for md in h.list_class_methods(cls)[:6]:
            for cs in h.find_call_sites_from(md)[:3]:
                probe(f"{layer}.CallSite", cs)
            for rs in h.resolve_call_args(md)[:3]:
                probe(f"{layer}.ResolvedCallSite", rs)
                for arg in rs.args[:4]:
                    probe(f"{layer}.ResolvedArg", arg)
    summary = dk.get_class_summary(cls)
    probe("raw.ClassSummary", summary)
    probe("sdk.ClassInfo", sdk.class_info(cls))
    for f in summary.fields[:3]:
        probe("raw.FieldInfo", f)
    for m in summary.methods[:3]:
        probe("raw.MethodInfo", m)
    for f in sdk.class_fields(cls)[:3]:
        probe("sdk.FieldInfo", f)
    for m in sdk.class_methods(cls)[:3]:
        probe("sdk.MethodInfo", m)
    md = sdk.list_class_methods(cls)[0]
    probe("sdk.DecompiledMethod", sdk.decompile_method(md))
    probe("sdk.MethodAst", sdk.decompile_method_ast(md))
    # A capability HIT is not reachable from the committed fixture (it matches no
    # catalog API), and that record is one this issue renames — so it is driven
    # from a STUB through the real pipeline rather than left unaudited. A
    # corpus-gated probe would leave it invisible in exactly the CI leg that has
    # no corpus.
    for hit in _stub_capability_hits():
        probe("raw.ApiUsage", hit)
    for hit in sdk.summarize_capabilities(app_only=False).api_usages[:3]:
        probe("sdk.ApiUsage", hit)
    return found


class _CapSite:
    def __init__(self, caller):
        self.caller_descriptor = caller


class _CapStubDk:
    """Answers the two lookups `summarize_capabilities` makes, for one key."""

    def __init__(self, key):
        self._key = key

    def find_call_sites_to(self, descriptor):
        return (
            [_CapSite("Lcom/example/App;->onCreate()V")]
            if descriptor == self._key
            else []
        )

    def find_methods_reading_field(self, descriptor):
        return []


def _stub_capability_hits():
    """Real `capability.ApiUsage`s, built by the real pass over a stub `dk`."""
    import dexllm
    from dexllm.capability import _load_catalog

    key = next(k for k in _load_catalog()["entries"] if "(" in k.partition(";->")[2])
    rep = dexllm.summarize_capabilities(_CapStubDk(key), app_only=False)
    return rep.api_usages[:3]


def test_a_descriptor_valued_attribute_is_spelled_descriptor():
    """dexllm#68: the POSITIVE half of the rule, checked by VALUE not by name.

    `test_signature_is_reserved_for_the_dotted_java_rendering` bans ONE word, so a
    THIRD one evades it — a correctness reviewer built `api_descriptor` ->
    `api_sig` coherently across every layer, the tests and the docs, and the whole
    suite stayed green. This asserts what the docs actually claim: an attribute
    whose LIVE value is a Dalvik descriptor is spelled `descriptor`, unless it is
    pinned as a ROLE name (both layers agree, so it is one concept with one name)
    or as KNOWN pre-existing DRIFT that dexllm#69 owns.

    SUBSET, not equality: which records are reachable depends on the sample — a
    class with no interfaces never produces `ClassInfo.interfaces` — so an absent
    exception is an environment fact, while a NEW offender is a product fact and
    fails. Runs on the one container this repo commits.
    """
    from conftest import REPO_ROOT

    blob = REPO_ROOT / "tests" / "data" / "multidex.apk"
    found = _descriptor_valued_attrs(str(blob))
    # Non-vacuity: the scan must actually have resolved descriptors, and must have
    # reached the records this issue renamed.
    assert len(found) >= 20, f"only {len(found)} descriptor-valued attributes seen"
    for must in ("raw.ExternalMethodRef.descriptor", "sdk.ExternalFieldRef.descriptor"):
        assert must in found, f"the scan never reached {must}"

    allowed = _DESCRIPTOR_ROLE_ATTRS | _DESCRIPTOR_NAME_DRIFT
    offenders = {a for a in found if "descriptor" not in a.rsplit(".", 1)[1]} - allowed
    assert not offenders, (
        f"these hold a Dalvik descriptor and are not spelled `descriptor`: "
        f"{sorted(offenders)} — rename them, or pin them as a ROLE (both layers "
        f"agree) / as dexllm#69 DRIFT, with the reason"
    )

    # An exception must be JUSTIFIED, not merely listed. A ROLE name is one BOTH
    # layers use — that is exactly what separates it from a cross-layer rename —
    # so a `sdk.` entry must have its `raw.` twin listed too when the raw layer has
    # that record at all. Without this the list is a dumping ground and the audit
    # is satisfied by adding to it, the defect it exists to catch.
    assert not (_DESCRIPTOR_ROLE_ATTRS & _DESCRIPTOR_NAME_DRIFT), "an attr in both"
    raw_records = {a.split(".")[1] for a in found if a.startswith("raw.")}
    for entry in sorted(_DESCRIPTOR_ROLE_ATTRS):
        layer, record, attr = entry.split(".", 2)
        if layer != "sdk" or record not in raw_records:
            continue
        twin = f"raw.{record}.{attr}"
        assert twin in _DESCRIPTOR_ROLE_ATTRS, (
            f"{entry} is pinned as a ROLE but its raw twin {twin} is not — a name "
            f"only ONE layer uses is drift, not a role"
        )


def test_the_arg_kind_attribute_map_has_one_definition():
    """dexllm#68: `_ARG_VALUE_FIELD` was two copies that had to move in lockstep.

    `tools.py` and `sdk/adapter.py` each carried a private copy mapping an
    `ResolvedArg.kind` to the attribute it fills, and this issue renamed two of the
    values — so "must change in lockstep" stopped being theoretical. They share
    one object now (the `_callers.py` precedent from dexllm#49).

    IDENTITY, not equal contents: a correct COPY passes every behavioural test in
    the suite and drifts on the first edit, which is the shape #49's own review
    had to construct.
    """
    from dexllm import _argkinds, tools
    from dexllm import _dexkit_core as core
    from dexllm.sdk import adapter

    shared = _argkinds.ARG_VALUE_ATTR_BY_KIND
    assert tools.ARG_VALUE_ATTR_BY_KIND is shared, "tools.py holds its own copy"
    assert adapter.ARG_VALUE_ATTR_BY_KIND is shared, "adapter.py holds its own copy"

    # …and every value must be an attribute the raw record ACTUALLY has, so a
    # rename that misses the map fails HERE — structurally, corpus-free — rather
    # than as an AttributeError inside a corpus-dependent xref call.
    assert len(shared) >= 9, f"only {len(shared)} kinds mapped"
    for kind, attr in shared.items():
        assert hasattr(
            core.ResolvedArg, attr
        ), f"kind {kind!r} maps to {attr!r}, which ResolvedArg does not have"

    # …and the USE SITE, not only the module attribute. An adversarial reviewer
    # kept the shared import (so identity passes, and ruff sees the name used) and
    # had the consumer read a correct PRIVATE copy — the exact hole dexllm#49's own
    # review had to construct one axis over. So neither consumer may declare a
    # kind->attribute mapping of its own, and each must NAME the shared one.
    import inspect
    import re

    for mod in (tools, adapter):
        src = inspect.getsource(mod)
        assert "ARG_VALUE_ATTR_BY_KIND" in src, f"{mod.__name__} never names it"
        # A dict literal mapping any ResolvedArg kind to an attribute string IS a
        # second definition, whatever it is called.
        for kind in shared:
            pattern = rf'["\']{kind}["\']\s*:\s*["\']'
            assert not re.search(pattern, src), (
                f"{mod.__name__} declares its own mapping for {kind!r} — the map "
                f"has ONE definition, in _argkinds.py"
            )


def test_no_adapter_alias_survives(apk_path):
    """The dexllm#21 adapter aliases are gone — and stay gone.

    They existed to keep the pre-unification spellings working; issue #24
    resolved the silent-deprecation question by DELETING them. This guards the
    removal from both sides: the old spellings must be absent, and the canonical
    ones must still work — "absent" alone would pass if the whole class broke.

    The names are enumerated here rather than derived from the (now empty)
    allow-list, which would make the check vacuous.
    """
    from dexllm.sdk.adapter import DexKitAdapter

    for gone in (
        "find_call_sites",
        "find_call_sites_to_api",
        "find_call_sites_from_method",
        "find_field_readers",
        "find_field_writers",
    ):
        assert not hasattr(DexKitAdapter, gone), f"{gone} is still on the adapter"

    session = DexKitAdapter(apk_path)
    api = "Landroid/util/Log;->d(Ljava/lang/String;Ljava/lang/String;)I"
    session.find_call_sites_to(api)  # canonical spellings still resolve
    session.resolve_call_args(api)
    fd = next(
        (f for f in session.raw.list_fields() if session.find_methods_reading_field(f)),
        None,
    )
    if fd is not None:
        assert session.find_methods_reading_field(fd)
        session.find_methods_writing_field(fd)


def test_typed_analysis_surface(apk_path):
    """Permission / IOC / capability returns are the typed models, not raw dicts."""
    session = open_apk(apk_path)
    for g in session.permission_callers(app_only=False):
        assert isinstance(g, PermissionCallers)
        assert g.protection_level in {
            "dangerous",
            "signature",
            "internal",
            "normal",
            "other",
        }
    assert isinstance(session.extract_iocs(), IocReport)
    assert isinstance(session.extract_iocs(with_xref=False), IocReport)
    assert isinstance(session.summarize_capabilities(), CapabilityReport)


def test_source_info_reaches_the_typed_layer_for_every_source(tmp_path):
    """dexllm#42 on the SDK: the load-time record, one typed row per source.

    Guarded here as well as on the raw layer because the adapter's own conversion
    is where a per-source list can quietly collapse to the primary — a mutant
    returning only ``source_info()[0]`` passed a single-source version of this.

    Corpus-free, and deliberately so: an earlier cut took the ``apk_path``
    fixture and asserted the second row is a zip, which hard-FAILED on all nine
    bundled bare ``.dex`` samples under a ``$DEXLLM_TEST_APK`` narrowing — an
    environment fact turning the suite red, the exact rule issue #46 exists for.
    """
    from conftest import committed_container

    zip_bytes, dex_bytes = committed_container()
    dump, apk = tmp_path / "dump.dex", tmp_path / "app.apk"
    dump.write_bytes(dex_bytes)
    apk.write_bytes(zip_bytes)

    session = open_apk([str(dump), str(apk)])
    rows = session.source_info()
    assert isinstance(
        rows, tuple
    ), "the port declares a tuple (docs/sdk.md's sequence rule); a list passes every other assertion here"
    assert len(rows) == len(session.sources) == 2
    assert all(isinstance(r, ContainerInfo) for r in rows)
    assert [r.source for r in rows] == [str(dump), str(apk)]
    assert rows[0].format == "dex" and rows[1].format == "zip"
    # …the typed model agrees with the on-demand probe while the files are there
    assert rows[1] == identify(str(apk))

    apk.unlink()
    assert session.source_info() == rows, "a session fact must survive its file"
    assert identify(str(apk)).dex_count == 0, "premise: a fresh probe would not"
