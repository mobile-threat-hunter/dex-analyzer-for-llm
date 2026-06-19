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


def test_dangerous_permission_api_callers_attributes_to_methods(dk):
    callers = dexllm.dangerous_permission_api_callers(dk)
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


def test_app_only_filters_framework_callers(dk):
    """app_only (default) drops bundled framework/library callers; False keeps them."""
    from dexllm.dangerous_api import _is_framework_caller

    # unit: descriptor-prefix classification
    assert _is_framework_caller("Landroidx/core/app/ActivityCompat;->x()V")
    assert _is_framework_caller("Landroid/support/v7/app/TwilightManager;->y()V")
    assert _is_framework_caller("Lkotlin/io/Foo;->z()V")
    assert not _is_framework_caller("La2dp/Vol/StoreLoc;->grabGPS()V")

    # integration: on an APK whose only caller of a gated API is framework code,
    # app_only=True drops it while app_only=False keeps it.
    for apk in _apks():
        try:
            d = dexllm.DexKit(apk)
        except Exception:
            continue
        full = dexllm.dangerous_permission_api_callers(d, app_only=False)
        fw_total = sum(
            1
            for rows in full.values()
            for r in rows
            for c in r["callers"]
            if _is_framework_caller(c)
        )
        if not fw_total:
            continue
        app = dexllm.dangerous_permission_api_callers(d, app_only=True)
        kept = [c for rows in app.values() for r in rows for c in r["callers"]]
        assert not any(_is_framework_caller(c) for c in kept)
        full_total = sum(len(r["callers"]) for rows in full.values() for r in rows)
        assert len(kept) == full_total - fw_total
        return
    pytest.skip("no bundled APK has a framework caller of a dangerous API")


def test_mcp_tools_registered_and_serialisable(dk):
    names = {t["name"] for t in dexllm.tools.TOOL_DEFINITIONS}
    assert {"dangerous_permission_apis", "dangerous_permission_api_callers"} <= names
    for tool in ("dangerous_permission_apis", "dangerous_permission_api_callers"):
        out = dexllm.tools.execute(tool, {}, dk)
        assert "permissions" in out
        json.dumps(out)  # MCP transport requires JSON-serialisable


def test_lru_cache_honours_env_change():
    """A later $DEXLLM_AOSP_DATASET change must NOT return the stale cached table."""
    from dexllm.dangerous_api import _load_dangerous_map

    os.environ.pop("DEXLLM_AOSP_DATASET", None)
    bundled = _load_dangerous_map(None)
    assert bundled  # bundled table cached under resolved root ""
    os.environ["DEXLLM_AOSP_DATASET"] = "/nonexistent/dexllm/garbage/path"
    try:
        # must re-resolve to the new root and fail loudly, not silently reuse bundled
        with pytest.raises((FileNotFoundError, ValueError)):
            _load_dangerous_map(None)
    finally:
        os.environ.pop("DEXLLM_AOSP_DATASET", None)


def test_override_missing_files_clear_error(tmp_path):
    from dexllm.dangerous_api import _load_dangerous_map_cached

    with pytest.raises(FileNotFoundError):
        _load_dangerous_map_cached(str(tmp_path))  # empty dir, no JSON files


def test_override_wrong_shape_clear_error(tmp_path):
    from dexllm.dangerous_api import _load_dangerous_map_cached

    (tmp_path / "permissions.json").write_text('{"a": 1}')  # dict, expected list
    (tmp_path / "perm_api_by_perm.json").write_text("{}")
    with pytest.raises(ValueError):
        _load_dangerous_map_cached(str(tmp_path))


def test_dataset_path_override(dk):
    """If the full dataset is present locally, the override path parses too."""
    ds = "/home/nyahumi/Project/aosp_data_set"
    if not (Path(ds) / "perm_api_by_perm.json").is_file():
        pytest.skip("full AOSP dataset not present")
    apis = dexllm.dangerous_permission_apis(dk, dataset_path=ds)
    assert isinstance(apis, dict)
