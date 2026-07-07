"""Tests for the dexllm hexagonal (ports & adapters) API.

Self-contained tests (imports, Protocol runtime-checkability, frozen/immutable
models) always run; the end-to-end conformance tests use the ``apk_path`` fixture
and skip without a test APK.
"""

import dataclasses
import pathlib
from types import MappingProxyType

import pytest

from dexllm.hexagonal import (
    ArgOrigin,
    CapabilityReport,
    ContainerInfo,
    ContainerProbe,
    ContainerProbePort,
    CrossReferencePort,
    DecompilationPort,
    DecompiledMethod,
    DexAnalysisUseCase,
    DexExtractionPort,
    EnumerationPort,
    ExternalMethodRef,
    IndicatorExtractionPort,
    IocReport,
    MethodAst,
    PermissionAnalysisPort,
    PermissionCallerGroup,
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
    CrossReferencePort,
    PermissionAnalysisPort,
    IndicatorExtractionPort,
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
        access_flags=0,
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
            access_flags=0,
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
    assert open_apk(apk_path).sources == (apk_path,)
    assert open_apk(pathlib.Path(apk_path)).sources == (apk_path,)


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
    # find_call_sites / resolve_call_args → typed, with per-kind ArgOrigin
    for rc in session.resolve_call_args(
        "Landroid/util/Log;->d(Ljava/lang/String;Ljava/lang/String;)I"
    ):
        assert rc.callee_descriptor.endswith(")I")
        for arg in rc.args:
            assert isinstance(arg, ArgOrigin) and isinstance(arg.kind, str)


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

    fields = session.list_all_field_descriptors()
    methods = session.list_all_method_descriptors()
    assert isinstance(fields, tuple) and isinstance(methods, tuple)
    assert fields and methods
    assert all(":" in f and "->" in f for f in fields[:50])
    assert all("(" in m and "->" in m for m in methods[:50])

    raw = session.extract_dex_bytes(0)
    assert isinstance(raw, bytes) and raw[:4] == b"dex\n"
    # the slice is THIS dex only — length == the header's file_size, not the map len
    assert len(raw) == int.from_bytes(raw[32:36], "little")
    assert session.extract_dex_bytes(9999) == b""


def test_enumeration_companions_multidex():
    """Genuine multidex: list_classes_in_dex must SLICE by dex, not ignore dex_id.

    The single-dex apk_path fixture makes the union==all invariant vacuous (a broken
    "return all classes regardless of dex_id" impl would still pass), so this loads a
    real >1-dex container and asserts the per-dex slices are DISJOINT, each non-empty,
    and partition list_classes — a wrong-slice impl cannot pass. extract_dex_bytes is
    likewise checked to yield a distinct dex per id.
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
    # each dex extracts as its own dex blob (own magic + own file_size)
    for d in range(session.dex_count()):
        b = session.extract_dex_bytes(d)
        assert b[:4] == b"dex\n" and len(b) == int.from_bytes(b[32:36], "little")


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
    from dexllm.hexagonal import ClassInfo, ClassInspectionPort, FieldInfo

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


def test_type_references_xref(apk_path):
    """CrossReferencePort.find_type_references — signature-position type xref."""
    from dexllm.hexagonal import TypeReferences

    session = open_apk(apk_path)
    # a type sure to be referenced: java.lang.String
    tr = session.find_type_references("Ljava/lang/String;")
    assert isinstance(tr, TypeReferences)
    assert all(isinstance(x, str) for x in tr.fields + tr.methods_returning)
    # a method that returns String must have descriptor ending in the type
    assert all(m.endswith(")Ljava/lang/String;") for m in tr.methods_returning)


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
