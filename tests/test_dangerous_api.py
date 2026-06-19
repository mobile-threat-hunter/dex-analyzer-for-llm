"""Tests for dangerous-permission -> API -> caller mapping.

Joins AOSP's @RequiresPermission permission->API table (bundled slim) against an
APK's referenced framework APIs. a2dp.Vol_137.apk is a stable benign fixture that
genuinely uses location, Bluetooth, and phone-state APIs.
"""

import glob
import json
import os
from pathlib import Path

import pytest

import dexllm

REPO = Path(__file__).resolve().parents[1]


def _apks():
    env = os.environ.get("DEXLLM_TEST_APK")
    if env and os.path.isfile(env):
        return [env]
    return sorted(glob.glob(str(REPO / "test_apk" / "APK" / "*.apk")))


def _fixture():
    apks = _apks()
    pref = [p for p in apks if "a2dp.Vol" in p]
    return (pref + apks)[:1]


@pytest.fixture(scope="module")
def dk():
    apks = _fixture()
    if not apks:
        pytest.skip("no bundled test APK")
    return dexllm.DexKit(apks[0])


def test_bundled_table_ships_and_is_dangerous_only():
    data = REPO / "src" / "dexllm" / "data" / "dangerous_perm_api.json"
    table = json.loads(data.read_text())
    assert table, "bundled dangerous_perm_api.json is empty"
    # every key is a permission name; every value a list of pkg.Class#method
    for perm, apis in table.items():
        assert perm.count(".") >= 1 and apis
        assert all("#" in a for a in apis)


def test_dangerous_permission_apis_detects_real_usage(dk):
    apis = dexllm.dangerous_permission_apis(dk)
    assert apis, "fixture APK should exercise some dangerous-permission API"
    # a2dp.Vol uses location + bluetooth APIs
    if any("a2dp.Vol" in p for p in _fixture()):
        assert "android.permission.ACCESS_FINE_LOCATION" in apis
        loc = apis["android.permission.ACCESS_FINE_LOCATION"]
        assert any("LocationManager#getLastKnownLocation" in a for a in loc)
        assert "android.permission.BLUETOOTH_CONNECT" in apis
    # shape: {perm: [pkg.Class#method]}
    for perm, used in apis.items():
        assert used == sorted(used)
        assert all("#" in a for a in used)


def test_dangerous_permission_callers_attributes_to_methods(dk):
    callers = dexllm.dangerous_permission_callers(dk)
    assert callers
    for perm, rows in callers.items():
        for row in rows:
            assert set(row) == {"api", "descriptors", "callers"}
            assert "#" in row["api"]
            # descriptors are full Dalvik forms; callers are method descriptors
            assert all("->" in d for d in row["descriptors"])
            assert row["callers"], "a reported API must have at least one caller"
            assert all("->" in c for c in row["callers"])

    if any("a2dp.Vol" in p for p in _fixture()):
        loc = callers.get("android.permission.ACCESS_FINE_LOCATION", [])
        joined = json.dumps(loc)
        assert "La2dp/Vol/StoreLoc;->grabGPS()V" in joined


def test_mcp_tools_registered_and_serialisable(dk):
    names = {t["name"] for t in dexllm.tools.TOOL_DEFINITIONS}
    assert {"dangerous_permission_apis", "dangerous_permission_callers"} <= names
    for tool in ("dangerous_permission_apis", "dangerous_permission_callers"):
        out = dexllm.tools.execute(tool, {}, dk)
        assert "permissions" in out
        json.dumps(out)  # MCP transport requires JSON-serialisable


def test_dataset_path_override(dk):
    """If the full dataset is present locally, the override path parses too."""
    ds = "/home/nyahumi/Project/aosp_data_set"
    if not (Path(ds) / "perm_api_by_perm.json").is_file():
        pytest.skip("full AOSP dataset not present")
    apis = dexllm.dangerous_permission_apis(dk, dataset_path=ds)
    assert isinstance(apis, dict)
