"""Tests for the dexllm SDK (typed ports & adapters) API.

Self-contained tests (imports, Protocol runtime-checkability, frozen/immutable
models) always run; the end-to-end conformance tests use the ``apk_path`` fixture
and skip without a test APK.
"""

import dataclasses
import pathlib
from types import MappingProxyType

import pytest

from dexllm.sdk import (
    ArgOrigin,
    CacheControlPort,
    CapabilityPort,
    CapabilityReport,
    ClassInspectionPort,
    ClassMatch,
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
    MethodMatch,
    PermissionAnalysisPort,
    PermissionCallerGroup,
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
    ArgOrigin,
    PermissionCallerGroup,
    IocReport,
    ExternalMethodRef,
    ExternalFieldRef,
    ExternalTypeRef,
    ClassMatch,
    MethodMatch,
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
    "CapabilityHit",
    "PermissionCallerGroup",
    "PermissionCallerRow",
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
        api_hits=(),
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
        class_name="C",
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
            class_name="",
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
    """The typed ArgOrigin sets only the field its kind carries."""
    a = ArgOrigin(kind="ConstString", reg_num=2, string_value="s")
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
    assert info.format == "zip" and info.is_apk and info.dex_count >= 1
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
    # guards against a revert of adapter.py's tuple(r["access"]) back to a list.
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
    assert refs and all(isinstance(r, ExternalMethodRef) for r in refs)
    r = refs[0]
    assert r.class_descriptor.startswith("L") and isinstance(r.parameters, tuple)
    # external field / type refs — symmetric with method refs, distinct typed models.
    # Require non-empty (mirrors the method-ref guard above) so a converter that
    # regressed to an empty tuple can't pass the all(...) assertions vacuously.
    frefs = session.list_external_field_refs(framework_only=True)
    assert frefs and all(isinstance(f, ExternalFieldRef) for f in frefs)
    assert all(f.signature == f"{f.class_descriptor}->{f.name}:{f.type}" for f in frefs)
    trefs = session.list_external_type_refs(framework_only=True)
    assert trefs and all(isinstance(t, ExternalTypeRef) for t in trefs)
    # external types are reference (L…;) or array ([…) descriptors, never primitives
    assert all(t.descriptor and t.descriptor[0] in "L[" for t in trefs)
    # find_call_sites_to / resolve_call_args → typed, with per-kind ArgOrigin
    crossed = 0
    for rc in session.resolve_call_args(
        "Landroid/util/Log;->d(Ljava/lang/String;Ljava/lang/String;)I"
    ):
        assert rc.callee_descriptor.endswith(")I")
        for arg in rc.args:
            assert isinstance(arg, ArgOrigin) and isinstance(arg.kind, str)
            # dexllm#16: the merge marker is typed through and only ever set on
            # Unknown (a resolved value holds on every path, so it cannot "vary").
            assert isinstance(arg.crossed_branch, bool)
            assert not (arg.crossed_branch and arg.kind != "Unknown")
            crossed += int(arg.crossed_branch)


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
        methods = session.list_class_methods(cls)
        if not methods:
            continue
        m = methods[0]
        sm = session.render_method_smali(m)
        if sm:
            # the rendered method's FIRST line is its own descriptor verbatim, and the
            # body carries smali structure — a load-bearing content check, not just
            # "non-empty" (which any smali would satisfy via a stray "->").
            assert sm.splitlines()[0] == m
            assert ".registers" in sm
            cs = session.render_class_smali(cls)
            assert cs.startswith(".class ") and cls in cs
            rendered = True
            break
    assert rendered, "no method rendered smali on the fixture APK"
    # unknown / external → empty string, never an exception
    assert session.render_method_smali("Lno/such/C;->x()V") == ""
    assert session.render_class_smali("Lno/such/C;") == ""


def test_typed_search(apk_path):
    """SearchPort — DexKit's L1–L7 search returns typed ClassMatch / MethodMatch.

    Verifies each hit is the right typed model with a real descriptor + dex location,
    that a hit round-trips (its descriptor is a decompilable/enumerable member), that
    match_type is honoured, and that the batch form returns an immutable mapping keyed
    by the query key with the same element type.
    """
    session = open_apk(apk_path)

    # class search → ClassMatch; every hit descriptor is a real declared class
    all_classes = set(session.list_classes())
    cmatches = session.find_classes_by_name("a", match_type="contains")
    assert cmatches and all(isinstance(c, ClassMatch) for c in cmatches)
    c0 = cmatches[0]
    assert c0.descriptor in all_classes and c0.dex_id >= 0 and "a" in c0.descriptor
    # match_type is load-bearing: equals on a real descriptor returns exactly it,
    # a bogus exact name returns nothing
    exact = session.find_classes_by_name(c0.descriptor, match_type="equals")
    assert c0.descriptor in {c.descriptor for c in exact}
    assert session.find_classes_by_name("No/Such/Zzz;", match_type="equals") == ()

    # method search → MethodMatch; body-string search hits are real methods
    mmatches = session.find_methods_using_strings(["http"])
    assert all(isinstance(m, MethodMatch) for m in mmatches)
    for mm in mmatches:
        assert mm.descriptor.startswith("L") and "->" in mm.descriptor

    # int-literal search returns typed matches (may be empty on a tiny APK)
    assert all(
        isinstance(m, MethodMatch) for m in session.find_methods_using_int_literals([1])
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
        (session.find_classes_by_super("Ljava/lang/Object;"), ClassMatch),
        (session.find_classes_implementing("Landroid/os/Parcelable;"), ClassMatch),
        (session.find_classes_by_annotation("Lkotlin/Metadata;"), ClassMatch),
        (session.find_classes_using_strings(["a"]), ClassMatch),
        (session.find_methods_by_annotation("Lkotlin/Metadata;"), MethodMatch),
        (session.find_methods_using_double_literals([1.0]), MethodMatch),
    ):
        assert isinstance(hits, tuple) and all(isinstance(h, model) for h in hits)

    # batch (both sides) → immutable Mapping keyed by query key, same element type,
    # and each per-key result equals the single-query result (shared-trie ≡ N calls)
    batch = session.batch_find_methods_using_strings({"q": ["http"]})
    assert isinstance(batch, MappingProxyType) and set(batch) == {"q"}
    assert {m.descriptor for m in batch["q"]} == {m.descriptor for m in mmatches}
    cbatch = session.batch_find_classes_using_strings({"q": ["a"]})
    assert isinstance(cbatch, MappingProxyType) and set(cbatch) == {"q"}
    assert all(isinstance(c, ClassMatch) for c in cbatch["q"])


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
    assert fields and methods
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
    assert info.descriptor == cls and info.superclass.startswith("L")
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
    # `FieldMatch` WAS before #37) cannot appear unnoticed either.
    assert raw_types - sdk_types == _RAW_ONLY_MODELS, (
        f"undeclared raw-only models: {(raw_types - sdk_types) - _RAW_ONLY_MODELS} | "
        f"stale exceptions: {_RAW_ONLY_MODELS - (raw_types - sdk_types)}"
    )

    # An exception must be JUSTIFIED, not merely listed — the same defence the
    # sibling method audit applies to its alias/decomposition lists. Without it the
    # cheapest way past a failure is to add BOTH names to the two lists, which
    # absorbs the exact defect this test exists for (constructed: renaming SDK
    # `MethodMatch` to `MethodHit` goes green that way, and the assertion messages
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
        assert isinstance(g, PermissionCallerGroup)
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
