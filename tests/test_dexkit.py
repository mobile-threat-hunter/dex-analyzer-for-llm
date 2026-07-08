"""Python-level smoke/regression tests for dexllm.

Self-contained tests (import, API surface) always run. APK-dependent tests
use the `dk`/`sample_method` fixtures and skip when no test APK is present.

Run:  pytest tests -v
"""

import re

import pytest

import dexllm

# ── self-contained (no APK) ──────────────────────────────────────────────────


def test_import_and_version():
    assert isinstance(dexllm.__version__, str)
    assert dexllm.DexKit is not None


def test_tools_catalog():
    defs = dexllm.tools.tool_definitions()
    assert len(defs) >= 10
    names = {d["name"] for d in defs}
    assert {"decompile_method", "list_classes", "find_methods_using_strings"} <= names


# ── enumeration ──────────────────────────────────────────────────────────────


def test_enumeration(dk):
    classes = dk.list_classes()
    assert len(classes) > 0
    methods = dk.list_class_methods(classes[0])
    assert isinstance(methods, list)


# ── decompile: Java ──────────────────────────────────────────────────────────


def test_decompile_method_java(dk, sample_method):
    src = dk.decompile_method_java(sample_method)
    assert src and "{" in src


def test_decompile_class_java(dk):
    for cls in dk.list_classes():
        out = dk.decompile_class_java(cls)
        if out:
            assert out.lstrip().startswith(
                ("package", "public", "class", "final", "abstract", "interface", "enum")
            )
            return


def test_external_method_returns_empty(dk):
    # External / framework methods must decompile to "" (graceful — androguard crashes).
    out = dk.decompile_method_java(
        "Landroid/util/Log;->d(Ljava/lang/String;Ljava/lang/String;)I"
    )
    assert out == ""


# ── decompile: AST (dast.py port) ────────────────────────────────────────────


def test_decompile_method_ast_shape(dk, sample_method):
    res = dk.decompile_method_ast(sample_method)
    assert res["found"] is True
    ast = res["ast"]
    assert set(ast.keys()) == {"triple", "flags", "ret", "params", "comments", "body"}
    assert ast["body"][0] == "BlockStatement"  # nested-list AST tag
    assert len(ast["triple"]) == 3


def test_decompile_method_ast_include_source(dk, sample_method):
    full = dk.decompile_method_ast(sample_method)  # source + ast
    ast_only = dk.decompile_method_ast(sample_method, include_source=False)
    assert ast_only["source"] == ""
    assert ast_only["ast"] == full["ast"]  # AST identical regardless of source


# ── search (L1–L7) ───────────────────────────────────────────────────────────


def test_search_classes_by_name(dk):
    hits = dk.find_classes_by_name("a", "contains")
    assert isinstance(hits, list)


def test_search_call_sites(dk):
    sites = dk.find_call_sites_to_api(
        "Landroid/util/Log;->d(Ljava/lang/String;Ljava/lang/String;)I"
    )
    assert isinstance(sites, list)  # may be empty if the APK never logs


def test_call_sites_from_method_is_forward_of_to_api(dk):
    """find_call_sites_from_method (callees) is the exact FORWARD of
    find_call_sites_to_api (callers): if M invokes C, then M appears among C's callers.
    Verified structurally on a real method, plus the external/unresolved empty case."""
    for cls in dk.list_classes():
        for m in dk.list_class_methods(cls):
            callees = dk.find_call_sites_from_method(m)
            if len(callees) >= 1:
                for s in callees:
                    assert s.caller_descriptor == m  # caller is fixed to M
                    assert "->" in s.callee_descriptor
                # symmetry over EVERY distinct callee (not just the first): M must be
                # among the callers of each method it invokes (forward ≡ reverse edge).
                for callee in {c.callee_descriptor for c in callees}:
                    callers = {
                        x.caller_descriptor for x in dk.find_call_sites_to_api(callee)
                    }
                    assert m in callers, f"{m} invokes {callee} but is not its caller"
                assert dk.find_call_sites_from_method("Lno/such/C;->x()V") == []
                return
    pytest.skip("no method with a callee in the test APK")


def test_field_read_write_xref(dk):
    """L2.5 field xref — methods that iget/sget (read) vs iput/sput (write) a field.

    The DIRECTION is verified against the method's smali, so a reader/writer swap
    (FieldGetMethods vs FieldPutMethods wired backwards) is caught, not just the
    membership. An unknown field returns []."""
    assert dk.find_field_read_methods("Lno/such/Class;->x:I") == []
    for cls in dk.list_classes():
        for f in getattr(dk.get_class_summary(cls), "fields", []):
            fd = f"{cls}->{f.name}:{f.type}"
            rd = dk.find_field_read_methods(fd)
            wr = dk.find_field_write_methods(fd)
            assert all(isinstance(m, str) and "->" in m for m in rd + wr)
            # a method that ONLY reads must contain an iget*/sget* of the field;
            # a method that ONLY writes must contain an iput*/sput* — verified via
            # smali so the two directions can't be silently swapped.
            reader_only = [m for m in rd if m not in wr]
            writer_only = [m for m in wr if m not in rd]
            if reader_only:
                sm = dk.render_method_smali(reader_only[0])
                assert f.name in sm and ("iget" in sm or "sget" in sm)
                return
            if writer_only:
                sm = dk.render_method_smali(writer_only[0])
                assert f.name in sm and ("iput" in sm or "sput" in sm)
                return
    pytest.skip("no field with a direction-distinct read/write xref in the test APK")


def test_call_sites_cross_dex_multidex():
    """find_call_sites_to_api / resolve_call_args must find a CROSS-DEX caller — a
    target method declared in one classes*.dex but invoked from another. The caller
    reverse-index redesign made this the sharp edge (DexKit aggregates cross-dex
    callers into the declaring dex, tagged with their source dex_id)."""
    import glob
    import os

    apk = os.path.join(
        os.path.dirname(__file__), "..", "test_apk", "APK", "multidex.apk"
    )
    if not glob.glob(apk):
        pytest.skip("multidex.apk fixture missing")
    dk = dexllm.DexKit(apk)
    assert dk.dex_count() > 1
    # Foobar is declared in dex 0; Blafoo (dex 1) calls its <init> and somemethod.
    for target in (
        "Lcom/foobar/foo/Foobar;-><init>()V",
        "Lcom/foobar/foo/Foobar;->somemethod(Ljava/lang/String;)V",
    ):
        callers = {s.caller_descriptor for s in dk.find_call_sites_to_api(target)}
        assert any(
            "Lcom/blafoo/bar/Blafoo;" in c for c in callers
        ), f"cross-dex caller of {target} lost: {callers}"
        # resolve_call_args must also see the cross-dex caller (same reverse-index path)
        rca = {s.caller_descriptor for s in dk.resolve_call_args(target)}
        assert any("Lcom/blafoo/bar/Blafoo;" in c for c in rca)
        # ORDER CONTRACT: the reverse-index path emits callers in (living-dex,
        # caller_method_idx) order — identical to the pre-redesign forward scan. Lock
        # it so a future grouping change can't silently reorder the returned list.
        sites = dk.find_call_sites_to_api(target)
        keys = [(s.caller_dex_id, s.caller_method_idx) for s in sites]
        assert keys == sorted(
            keys
        ), f"caller order not (dex, method_idx)-sorted: {keys}"

    # CROSS-DEX callee direction: a Blafoo (dex 1) caller of Foobar.somemethod (dex 0)
    # must, via find_call_sites_from_method, list that dex-0 method as a callee — the
    # forward path resolving a cross-dex edge round-trips against the reverse index.
    target = "Lcom/foobar/foo/Foobar;->somemethod(Ljava/lang/String;)V"
    caller = next(
        s.caller_descriptor
        for s in dk.find_call_sites_to_api(target)
        if "Lcom/blafoo/bar/Blafoo;" in s.caller_descriptor
    )
    callee_descs = {s.callee_descriptor for s in dk.find_call_sites_from_method(caller)}
    assert target in callee_descs, f"cross-dex callee {target} lost from {caller}"


# ── external API enumeration ─────────────────────────────────────────────────


def test_type_references(dk):
    """L2.5 type xref — fields of / methods returning / methods taking a type."""
    tr = dk.find_type_references("Ljava/lang/String;")
    assert all(m.endswith(")Ljava/lang/String;") for m in tr.methods_returning)
    assert all(":Ljava/lang/String;" in f for f in tr.fields)
    assert dk.find_type_references("Lno/such/T;").fields == []


def test_enumeration_companions(dk):
    """Per-dex enumeration + extraction: uniform bare/all vs ...InDex(dex_id) axis."""
    all_classes = set(dk.list_classes())
    per_dex = set()
    for d in range(dk.dex_count()):
        per_dex |= set(dk.list_classes_in_dex(d))
    assert per_dex == all_classes  # union of per-dex == all (classes: declared)
    assert dk.list_classes_in_dex(9999) == []
    # field/method descriptors: the all-dexes form is exactly the concatenation of
    # the per-dex form (id-table references, so cross-dex refs recur — a set union
    # would drop them; concatenation is the correct invariant here).
    f_concat, m_concat = [], []
    for d in range(dk.dex_count()):
        f_concat += dk.list_field_descriptors_in_dex(d)
        m_concat += dk.list_method_descriptors_in_dex(d)
    assert f_concat == dk.list_field_descriptors() and len(f_concat) > 0
    assert m_concat == dk.list_method_descriptors() and len(m_concat) > 0
    assert dk.list_field_descriptors_in_dex(9999) == []
    assert dk.list_method_descriptors_in_dex(-1) == []
    raw = dk.extract_dex_bytes(0)
    assert isinstance(raw, bytes) and raw[:4] == b"dex\n"
    # the slice is THIS dex only — length == the header's file_size, not the map len
    assert len(raw) == int.from_bytes(raw[32:36], "little")
    assert dk.extract_dex_bytes(9999) == b""


def test_extract_dex_bytes_slices_concatenated_container(apk_path, tmp_path):
    """extract_dex_bytes must return THIS logical dex's slice (header_off applied),
    not the whole shared MemMap — the packer/concatenated-dex case. A single buffer
    of two dexes splits into two logical dexes sharing one image; each extract must
    yield its own dex (own magic, own file_size), NOT the full container."""
    import zipfile

    if not zipfile.is_zipfile(apk_path):
        pytest.skip("fixture is not a zip apk")
    with zipfile.ZipFile(apk_path) as z:
        names = [n for n in z.namelist() if n.endswith(".dex")]
        if not names:
            pytest.skip("apk has no dex")
        one = z.read(names[0])
    cat = tmp_path / "concat.dex"
    cat.write_bytes(one + one)  # two logical dexes in one buffer
    dk = dexllm.DexKit(str(cat))
    if dk.dex_count() < 2:
        pytest.skip("core did not split the concatenated buffer")
    a, b = dk.extract_dex_bytes(0), dk.extract_dex_bytes(1)
    assert a[:4] == b"dex\n" and b[:4] == b"dex\n"  # each starts at its own magic
    assert len(a) == len(one) and len(b) == len(one)  # each is one dex, not the pair


def test_external_refs(dk):
    refs = dk.list_external_method_refs(framework_only=True)
    assert isinstance(refs, list)
    if refs:
        r = refs[0]
        assert r.class_descriptor and r.name and r.java_signature


# ── regression: EncodedValue must emit valid Java literals, not Python ones ───


def test_no_python_literals_in_output(dk):
    """null/true/false, never None/True/False (androguard-bug fix)."""
    pat = re.compile(r"=\s*(None|True|False)\b")
    for cls in dk.list_classes()[:500]:
        out = dk.decompile_class_java(cls)
        if out:
            assert not pat.search(out), f"python literal leaked in {cls}"
