"""Regression for MCP/LLM tool-surface output correctness (tools.py).

Two tools read attributes that don't exist on the C++ binding objects and silently
returned wrong values (the binding exposes superclass_descriptor /
interface_descriptors / caller_descriptor, not super_class / interfaces /
caller_method). These pin the corrected field reads.
"""

import glob
import json
from pathlib import Path

import pytest

import dexllm
import dexllm.tools as tools

REPO = Path(__file__).resolve().parents[1]


@pytest.fixture(scope="module")
def dk():
    apks = sorted(glob.glob(str(REPO / "test_apk" / "APK" / "*.apk")))
    pref = [p for p in apks if "a2dp.Vol" in p] + apks
    if not pref:
        pytest.skip("no bundled APK")
    return dexllm.DexKit(pref[0])


def test_get_class_summary_reports_real_superclass(dk):
    # a2dp.Vol/main extends android.app.Activity — the tool used to report null.
    out = tools.execute(
        "get_class_summary", {"class_descriptor": "La2dp/Vol/main;"}, dk
    )
    assert out["superclass"] == "Landroid/app/Activity;"
    assert isinstance(out["interfaces"], list)
    assert out["method_count"] > 0 and out["field_count"] >= 0
    json.dumps(out)


def test_find_call_sites_returns_clean_caller_descriptor(dk):
    api = "Landroid/util/Log;->d(Ljava/lang/String;Ljava/lang/String;)I"
    out = tools.execute("find_call_sites_to_api", {"api_descriptor": api}, dk)
    if not out["items"]:
        pytest.skip("fixture has no Log.d call sites")
    for item in out["items"]:
        assert "->" in item["caller"]  # a real Dalvik descriptor
        assert "CallSite(" not in item["caller"]  # not the repr fallback
        assert item["callee"] == api
        assert isinstance(item["bytecode_offset"], int)
    json.dumps(out)


def test_tool_catalog_definitions_match_impls():
    """Every declared tool has an implementation and vice-versa, no dup names —
    so a new impl without a schema (or a schema without an impl) fails here."""
    names = [d["name"] for d in tools.tool_definitions()]
    assert len(names) == len(set(names)), "duplicate tool name"
    assert set(names) == set(tools.TOOL_IMPLS), (
        f"def-only={set(names) - set(tools.TOOL_IMPLS)} "
        f"impl-only={set(tools.TOOL_IMPLS) - set(names)}"
    )


def test_resolve_call_args_shapes_compact_args(dk):
    """resolve_call_args yields JSON-safe {index, kind, value} args whose value
    matches the raw ArgOrigin, and the same call sites as find_call_sites_to_api."""
    api = "Landroid/util/Log;->d(Ljava/lang/String;Ljava/lang/String;)I"
    out = tools.execute("resolve_call_args", {"api_descriptor": api}, dk)
    json.dumps(out)  # must be serialisable for the transport
    if not out["items"]:
        pytest.skip("fixture has no Log.d call sites")
    callers = {s.caller_descriptor for s in dk.find_call_sites_to_api(api)}
    for site in out["items"]:
        assert site["caller"] in callers  # same sites as the plain xref tool
        for i, a in enumerate(site["args"]):
            assert a["index"] == i  # index is the invoke-arg position
            assert isinstance(a["kind"], str)
            # a const kind carries its literal; a leaf kind carries None/sig/pN
            if a["kind"] in ("ConstInt", "ConstWide"):
                assert isinstance(a["value"], int)
            elif a["kind"] == "ConstString":
                assert isinstance(a["value"], str)
            elif a["kind"] in ("ConstNull", "Unknown"):
                assert a["value"] is None


def test_new_xref_tools_execute_without_error(dk):
    """The added xref/literal tools return a clean (non-error) dict on real input."""
    cls = dk.list_classes()[0]
    f = next((mm for mm in dk.list_class_methods(cls)), None)
    calls = [
        ("find_call_sites_from_method", {"method_descriptor": f}) if f else None,
        ("find_type_references", {"type_descriptor": "Ljava/lang/String;", "limit": 5}),
        ("find_methods_using_int_literals", {"values": [2, 255], "limit": 5}),
        ("find_methods_using_double_literals", {"values": [1.0], "limit": 5}),
        ("find_field_read_methods", {"field_descriptor": "Lno/such/C;->x:I"}),
        ("find_field_write_methods", {"field_descriptor": "Lno/such/C;->x:I"}),
    ]
    for call in filter(None, calls):
        out = tools.execute(*call, dk)
        assert "error" not in out, f"{call[0]} -> {out}"
        json.dumps(out)
    # an unknown field is a clean empty page, not a crash
    assert (
        tools.execute(
            "find_field_read_methods", {"field_descriptor": "Lno/such/C;->x:I"}, dk
        )["items"]
        == []
    )


def test_literal_tools_reject_empty_values(dk):
    """An empty `values` list must NOT dump the whole method table (the C++ matcher
    treats an empty literal set as match-all) — the handler short-circuits to an
    empty page, and the schema marks the array minItems:1."""
    for name in (
        "find_methods_using_int_literals",
        "find_methods_using_double_literals",
    ):
        out = tools.execute(name, {"values": []}, dk)
        assert out["total"] == 0 and out["items"] == [], f"{name} leaked the full table"
    defs = {d["name"]: d for d in tools.tool_definitions()}
    for name in (
        "find_methods_using_int_literals",
        "find_methods_using_double_literals",
    ):
        assert defs[name]["input_schema"]["properties"]["values"].get("minItems") == 1
    # a real value still matches
    assert tools.execute("find_methods_using_int_literals", {"values": [2]}, dk)[
        "total"
    ] < len(dk.list_method_descriptors())


def test_arg_compact_covers_every_arg_kind():
    """_arg_to_compact handles EXACTLY the ArgKind set the C++ ArgKindName emits — a
    drift guard so a new native kind isn't silently mapped to value=None."""
    handled = set(tools._ARG_VALUE_FIELD) | {"Parameter", "ConstNull", "Unknown"}
    expected = {
        "ConstString",
        "ConstInt",
        "ConstWide",
        "ConstClass",
        "ConstNull",
        "FieldRead",
        "MethodReturn",
        "Parameter",
        "NewInstance",
        "NewArray",
        "Unknown",
    }
    assert handled == expected, f"drift: {handled ^ expected}"


def test_type_references_paging_is_recoverable(dk):
    """find_type_references pages each list by offset/next_offset (not a hard cap) so
    a high-fan-in type's references past `limit` stay reachable."""
    first = tools.execute(
        "find_type_references",
        {"type_descriptor": "Ljava/lang/String;", "limit": 1},
        dk,
    )
    for key in ("fields", "methods_returning", "methods_with_param"):
        page = first[key]
        assert set(page) >= {"total", "offset", "items", "next_offset"}
        if page["total"] > 1:
            assert page["next_offset"] == 1  # more to fetch, recoverably
            nxt = tools.execute(
                "find_type_references",
                {"type_descriptor": "Ljava/lang/String;", "limit": 1, "offset": 1},
                dk,
            )[key]
            assert nxt["items"] and nxt["items"] != page["items"]  # advanced
            return
    pytest.skip("String has <=1 reference in every category in this fixture")


def test_identity_xref_tools_reject_non_descriptor_input(dk):
    """Identity (descriptor) tools demand the exact Dalvik form and return a clear
    error — NOT a silent empty — on a dotted/Java name, so an LLM that learned
    leniency from the name-search family gets a guiding message instead of a false
    'no usages'. This is DexKit's own split: name-query is lenient, identity is strict.
    """
    # L-form works
    ldesc = tools.execute(
        "find_type_references", {"type_descriptor": "Ljava/lang/String;"}, dk
    )["fields"]["total"]
    assert ldesc > 0, "fixture has no String field references"
    # dotted / smali → a structured ValueError, not a 0-count result
    for form in ("java.lang.String", "java/lang/String"):
        r = tools.execute("find_type_references", {"type_descriptor": form}, dk)
        assert r.get("error", "").startswith(
            "ValueError"
        ), f"{form!r} not rejected: {r}"
        assert "descriptor" in r["error"]
    # a called API in L-form works; the dotted member form errors
    api_l = "Landroid/util/Log;->d(Ljava/lang/String;Ljava/lang/String;)I"
    assert "error" not in tools.execute(
        "resolve_call_args", {"api_descriptor": api_l}, dk
    )
    for form in (
        "android.util.Log->d(Ljava/lang/String;Ljava/lang/String;)I",
        "android/util/Log->d(Ljava/lang/String;Ljava/lang/String;)I",
    ):
        r = tools.execute("resolve_call_args", {"api_descriptor": form}, dk)
        assert r.get("error", "").startswith(
            "ValueError"
        ), f"{form!r} not rejected: {r}"


def test_name_search_tools_stay_lenient(dk):
    """The name-query family keeps DexKit's upstream leniency: the dotted, smali, and
    L-form of the SAME declared class all resolve to the same match (find_classes_by_name
    uses NameToDescriptor). Only identity APIs are strict — the two concepts must not be
    conflated, and the search family must NOT have gained validation."""
    # a class actually declared in the fixture (so an `equals` query has a real target)
    cls = next(c for c in dk.list_classes() if "/" in c)  # e.g. La2dp/Vol/main;
    ldesc = cls  # 'La2dp/Vol/main;'
    smali = cls[1:-1]  # 'a2dp/Vol/main'
    dotted = smali.replace("/", ".")  # 'a2dp.Vol.main'
    counts = {
        form: tools.execute(
            "find_classes_by_name", {"name": form, "match_type": "equals"}, dk
        )["total"]
        for form in (ldesc, smali, dotted)
    }
    # leniency: all three spellings normalise to the same query → same non-zero match
    assert counts[dotted] == counts[smali] == counts[ldesc] >= 1, counts
    # and none of them errored (no identity validation leaked into the search family)
    for form in (ldesc, smali, dotted):
        r = tools.execute(
            "find_classes_by_name", {"name": form, "match_type": "equals"}, dk
        )
        assert "error" not in r, f"search family gained validation on {form!r}: {r}"


def test_list_value_strings_tool(dk):
    """list_value_strings pages the value-string feed and the regex pattern filters."""
    allv = tools.execute("list_value_strings", {"limit": 5}, dk)
    assert allv["total"] > 0 and all(isinstance(s, str) for s in allv["items"])
    filt = tools.execute("list_value_strings", {"pattern": "://", "limit": 5}, dk)
    assert filt["total"] <= allv["total"]  # a filter never grows the set
    assert all("://" in s for s in filt["items"])
    json.dumps(allv)


def test_render_class_smali_tool(dk):
    """render_class_smali truncates on the descriptor form and rejects a dotted class."""
    cls = dk.list_classes()[0]
    full = tools.execute("render_class_smali", {"class_descriptor": cls}, dk)
    assert full["full_chars"] > 0 and full["truncated"] is False
    cut = tools.execute(
        "render_class_smali", {"class_descriptor": cls, "max_chars": 20}, dk
    )
    assert cut["truncated"] is True and cut["full_chars"] == full["full_chars"]
    from dexllm.descriptors import descriptor_to_java

    dotted = tools.execute(
        "render_class_smali", {"class_descriptor": descriptor_to_java(cls)}, dk
    )
    assert dotted.get("error", "").startswith("ValueError")  # dotted → clear error


def test_detect_content_providers_tool(dk):
    """detect_content_providers returns a JSON-safe {providers, count} shape."""
    out = tools.execute("detect_content_providers", {"with_xref": True}, dk)
    assert "providers" in out and out["count"] == len(out["providers"])
    assert isinstance(out["providers"], list)
    json.dumps(out)


def test_pattern_filter_is_similarregex_and_redos_impossible(dk):
    """`pattern` is DexKit SimilarRegex (^/$ anchors + literal substring), NOT a full
    regex engine — so a catastrophic-backtracking pattern is just a literal substring
    search: it cannot hang (no engine to backtrack), returns fast, never errors."""
    import time

    # ReDoS-shaped inputs are treated as LITERAL substrings → fast, no error, no hang.
    for redos in ("(.*)*Z", "(a|a)*Z", "((a+))+Z", "(a+?)+Z"):
        t = time.time()
        out = tools.execute("list_value_strings", {"pattern": redos}, dk)
        assert time.time() - t < 2.0, f"{redos!r} was slow — engine still present?"
        assert "error" not in out
        assert out["total"] == 0  # no value-string contains that literal substring
    # SimilarRegex semantics, verified against list_classes descriptors.
    classes = dk.list_classes()
    pfx = classes[0][:6]  # e.g. 'Landro'
    starts = tools.execute("list_classes", {"pattern": f"^{pfx}", "limit": 1000}, dk)
    assert starts["total"] > 0 and all(c.startswith(pfx) for c in starts["items"])
    ends = tools.execute("list_classes", {"pattern": ";$", "limit": 1000}, dk)
    assert ends["total"] > 0 and all(c.endswith(";") for c in ends["items"])
    exact = tools.execute("list_classes", {"pattern": f"^{classes[0]}$"}, dk)
    assert exact["total"] == 1 and exact["items"] == [classes[0]]
    contains = tools.execute("list_classes", {"pattern": "/", "limit": 1000}, dk)
    assert all("/" in c for c in contains["items"])


def test_container_verify_ast_batch_tools(dk):
    """The 4 completeness tools (identify / verify_report / decompile_method_ast /
    batch_find_methods_using_strings) return clean JSON-safe shapes."""
    idf = tools.execute("identify", {}, dk)
    # dex_count reflects the LOADED total (== dk.dex_count()), not just the primary probe
    assert idf["dex_count"] == dk.dex_count() and idf["format"] in ("dex", "zip")
    assert idf["source_count"] == len(dk.sources())
    json.dumps(idf)

    vr = tools.execute("verify_report", {}, dk)
    assert isinstance(vr["dexes"], list) and vr["dexes"]
    assert set(vr["dexes"][0]) >= {"dex_id", "name", "valid", "reason"}

    # a known-decompilable method (non-abstract, has a body) so found is really True
    m = next(
        mm
        for c in dk.list_classes()
        for mm in dk.list_class_methods(c)
        if tools.execute("decompile_method_ast", {"method_descriptor": mm}, dk)["found"]
    )
    ast = tools.execute("decompile_method_ast", {"method_descriptor": m}, dk)
    assert ast["found"] is True and ast["ast"] is not None
    assert ast["source"] == ""  # include_source defaults to False
    json.dumps(ast)
    with_src = tools.execute(
        "decompile_method_ast", {"method_descriptor": m, "include_source": True}, dk
    )
    assert isinstance(with_src["source"], str)
    # max_chars bounds the AST: a tiny cap drops the tree with an explanation
    tiny = tools.execute(
        "decompile_method_ast", {"method_descriptor": m, "max_chars": 5}, dk
    )
    assert tiny["ast"] is None and "ast_omitted" in tiny

    b = tools.execute(
        "batch_find_methods_using_strings",
        {"query_map": {"g1": ["http"], "g2": ["reflect"]}},
        dk,
    )
    assert set(b) == {"g1", "g2"}
    for grp in b.values():  # each group is {total, items, truncated}
        assert set(grp) == {"total", "items", "truncated"}
        assert all(isinstance(x, str) and "->" in x for x in grp["items"])
    json.dumps(b)


def test_batch_find_methods_bounded_and_bad_shapes(dk):
    """batch CAPS every group at `limit` ({total, items, truncated}) so a broad query
    — or an empty group (C++ vacuous match-all, like the single find tool) — can't
    dump the whole method table while `total` stays honest; a bare-string value is a
    clean error; a `['']` edge query is a real query (not silently stripped)."""
    tot = len(dk.list_method_descriptors())
    # empty group = match-all but BOUNDED by limit (not a 3-9 MB dump), total honest
    out = tools.execute(
        "batch_find_methods_using_strings",
        {"query_map": {"all": [], "real": ["http"]}, "limit": 5},
        dk,
    )
    assert len(out["all"]["items"]) <= 5 and out["all"]["total"] <= tot
    assert out["all"]["truncated"] is (out["all"]["total"] > 5)
    assert out["real"]["total"] < tot
    # a broad common substring is capped, not dumped whole
    broad = tools.execute(
        "batch_find_methods_using_strings", {"query_map": {"g": ["a"]}, "limit": 5}, dk
    )["g"]
    if broad["total"] > 5:
        assert len(broad["items"]) == 5 and broad["truncated"] is True
    # [''] is a real query passed through (not silently stripped away) — valid shape
    es = tools.execute(
        "batch_find_methods_using_strings", {"query_map": {"g": [""]}}, dk
    )["g"]
    assert set(es) == {"total", "items", "truncated"}
    # a bare-string value → clean error (the binding rejects str where list[str] is required)
    assert "error" in tools.execute(
        "batch_find_methods_using_strings", {"query_map": {"g": "http"}}, dk
    )
    defs = {d["name"]: d for d in tools.tool_definitions()}
    ap = defs["batch_find_methods_using_strings"]["input_schema"]["properties"][
        "query_map"
    ]["additionalProperties"]
    assert ap.get("minItems") == 1


def test_descriptor_validators_unit():
    """The shared validators recognise Dalvik descriptor forms and reject Java names."""
    from dexllm.descriptors import (
        is_member_descriptor,
        is_type_descriptor,
        require_member_descriptor,
        require_type_descriptor,
    )

    # types: L-form, arrays (incl. nested), every primitive
    assert is_type_descriptor("Ljava/lang/String;")
    assert is_type_descriptor("La2dp/Vol/main$Inner;")  # '$' inner
    assert is_type_descriptor("[I") and is_type_descriptor("[[Ljava/lang/Object;")
    assert all(is_type_descriptor(p) for p in "VZBSCIJFD")
    assert not is_type_descriptor("java.lang.String")  # dotted
    assert not is_type_descriptor("java/lang/String")  # smali (no L;)
    assert not is_type_descriptor("")  # empty must not IndexError

    # members: method (has '(') and field (name:type); field TYPE must be a descriptor
    assert is_member_descriptor("Landroid/util/Log;->d(Ljava/lang/String;)I")
    assert is_member_descriptor("Lc;->m([ILjava/lang/String;)[Ljava/lang/Object;")
    assert is_member_descriptor("Lc;-><init>()V")  # <init> name
    assert is_member_descriptor("Lcom/foo/Bar;->f:I")  # field
    assert is_member_descriptor("Lcom/foo/Bar;->f:[Ljava/lang/Object;")  # array field
    assert not is_member_descriptor("android.util.Log->d()V")  # dotted class
    assert not is_member_descriptor("Ljava/lang/String;")  # no '->'
    assert not is_member_descriptor("Lc;->f:int")  # dotted field type
    assert not is_member_descriptor("Lc;->f:")  # empty field type
    # method-vs-field routing: '(' wins over ':' (a proto never contains ':')
    assert is_member_descriptor("Lc;->m()V")

    assert require_type_descriptor("Ljava/lang/String;") == "Ljava/lang/String;"
    with pytest.raises(ValueError, match="descriptor"):
        require_type_descriptor("java.lang.String")
    with pytest.raises(ValueError, match="descriptor"):
        require_member_descriptor("android.util.Log->d()V")
    with pytest.raises(ValueError, match="descriptor"):
        require_member_descriptor("Lc;->f:int")  # dotted field type also rejected


def test_sdk_identity_apis_reject_non_descriptor(dk):
    """SDK identity methods raise ValueError on a dotted/Java name (strict, like MCP)."""
    from dexllm.sdk import open_apk

    apks = sorted(glob.glob(str(REPO / "test_apk" / "APK" / "*.apk")))
    pref = [p for p in apks if "a2dp.Vol" in p] + apks
    session = open_apk(pref[0])
    with pytest.raises(ValueError):
        session.find_type_references("java.lang.String")
    with pytest.raises(ValueError):
        session.decompile_method("android.util.Log->d()V")
    with pytest.raises(ValueError):
        session.list_class_methods("java.lang.String")
    # L-form still works
    assert session.find_type_references("Ljava/lang/String;") is not None
