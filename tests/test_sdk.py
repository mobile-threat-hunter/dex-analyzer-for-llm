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
        api_hits=(),
        by_caller={},
    )
    assert isinstance(cr.permissions, MappingProxyType)
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
    # find_call_sites / resolve_call_args → typed, with per-kind ArgOrigin
    for rc in session.resolve_call_args(
        "Landroid/util/Log;->d(Ljava/lang/String;Ljava/lang/String;)I"
    ):
        assert rc.callee_descriptor.endswith(")I")
        for arg in rc.args:
            assert isinstance(arg, ArgOrigin) and isinstance(arg.kind, str)


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


def test_enumeration_companions_typed(apk_path):
    """EnumerationPort companions: per-dex classes, flat member descriptors, raw dex.

    Mirrors the raw-binding test_enumeration_companions, but through the typed port —
    every return is a tuple[str, ...] (or bytes), and the invariants hold: the union
    of per-dex classes == list_classes, and extract_dex_bytes returns THIS dex's slice
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

    fields = session.list_field_descriptors()
    methods = session.list_method_descriptors()
    assert isinstance(fields, tuple) and isinstance(methods, tuple)
    assert fields and methods
    assert all(":" in f and "->" in f for f in fields[:50])
    assert all("(" in m and "->" in m for m in methods[:50])
    # the all-dexes form is exactly the per-dex concatenation (uniform scope axis)
    f_concat: tuple[str, ...] = ()
    m_concat: tuple[str, ...] = ()
    for d in range(session.dex_count()):
        f_concat += session.list_field_descriptors_in_dex(d)
        m_concat += session.list_method_descriptors_in_dex(d)
    assert f_concat == fields and m_concat == methods
    assert session.list_field_descriptors_in_dex(9999) == ()
    assert session.list_method_descriptors_in_dex(-1) == ()

    raw = session.extract_dex_bytes(0)
    assert isinstance(raw, bytes) and raw[:4] == b"dex\n"
    # the slice is THIS dex only — length == the header's file_size, not the map len
    assert len(raw) == int.from_bytes(raw[32:36], "little")
    assert session.extract_dex_bytes(9999) == b""


def test_enumeration_companions_multidex():
    """Genuine multidex: per-dex enumeration must SLICE by dex, not ignore dex_id.

    The single-dex apk_path fixture makes the union/concat invariants vacuous (a
    broken "return everything regardless of dex_id" impl would still pass), so this
    loads a real >1-dex container. Asserts: class slices are DISJOINT/non-empty and
    partition list_classes; extract_dex_bytes yields a distinct dex per id; and the
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
        b = session.extract_dex_bytes(d)
        assert b[:4] == b"dex\n" and len(b) == int.from_bytes(b[32:36], "little")

    # field/method descriptors: the all-dexes form is the per-dex CONCATENATION,
    # NOT a set union — the dex id-tables reference the same framework members
    # (java/lang/Object etc.) from both dexes, so those recur. This is the case the
    # single-dex fixture can't exercise: assert the aggregate carries a genuine
    # cross-dex duplicate (so a union-based impl would drop it and FAIL the concat
    # equality below — the assertion is non-vacuous here).
    m_agg = session.list_method_descriptors()
    m_concat: tuple[str, ...] = ()
    for d in range(session.dex_count()):
        m_concat += session.list_method_descriptors_in_dex(d)
    assert m_concat == m_agg
    assert len(m_agg) > len(set(m_agg)), "expected cross-dex method recurrence"
    f_agg = session.list_field_descriptors()
    f_concat: tuple[str, ...] = ()
    for d in range(session.dex_count()):
        f_concat += session.list_field_descriptors_in_dex(d)
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
            readers = session.find_field_readers(fd)
            writers = session.find_field_writers(fd)
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
    fields = session.class_fields(cls)
    assert all(isinstance(f, FieldInfo) for f in fields)
    # methods are the separate list_class_methods query, not bundled here
    assert isinstance(session.list_class_methods(cls), tuple)
    # locate_class_dex — the cheap dex-attribution lookup; equals class_info().dex_id
    # (same result, cheaper path) and -1 for a class no dex declares
    assert session.locate_class_dex(cls) == info.dex_id
    assert session.locate_class_dex("Lno/such/Class;") == -1


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
    """CrossReferencePort.find_call_sites_from_method — the CALLEE direction, typed.

    The forward of find_call_sites: each CallSite fixes the caller (this method) and
    varies callee. Verified symmetric — the method is a caller of its own callee — and
    empty for an external/unresolved method."""
    from dexllm.sdk import CallSite

    session = open_apk(apk_path)
    for cls in session.list_classes():
        for m in session.list_class_methods(cls):
            callees = session.find_call_sites_from_method(m)
            if callees:
                assert all(isinstance(c, CallSite) for c in callees)
                assert all(c.caller_descriptor == m for c in callees)  # caller fixed
                # forward ≡ reverse for EVERY distinct callee
                for callee in {c.callee_descriptor for c in callees}:
                    callers = {
                        c.caller_descriptor for c in session.find_call_sites(callee)
                    }
                    assert m in callers
                assert session.find_call_sites_from_method("Lno/x;->y()V") == ()
                return
    pytest.skip("no method with a callee in the test APK")


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
