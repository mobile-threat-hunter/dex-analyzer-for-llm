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
    out = tools.execute("get_class_summary", {"class_descriptor": "La2dp/Vol/main;"}, dk)
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
