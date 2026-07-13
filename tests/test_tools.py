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
