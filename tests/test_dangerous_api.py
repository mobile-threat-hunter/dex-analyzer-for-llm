"""Tests for dangerous-permission -> API -> caller mapping.

Joins AOSP's @RequiresPermission permission->API table (bundled slim) against an
APK's referenced framework APIs. a2dp.Vol_137.apk is a stable benign fixture that
genuinely uses location, Bluetooth, and phone-state APIs.
"""

import glob
import json
import os
import re
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


def test_bundled_full_tables_ship_and_dangerous_derives():
    # Single source of truth (issue #14): the full perm→API map + level buckets
    # ship; the dangerous slice is DERIVED from them, not a separate file.
    from dexllm.dangerous_api import _load_dangerous_map, _load_full_map, _load_levels

    data = REPO / "src" / "dexllm" / "data"
    perm_api = json.loads((data / "perm_api.json").read_text())
    perm_levels = json.loads((data / "perm_levels.json").read_text())
    assert perm_api and perm_levels
    for perm, apis in perm_api.items():
        assert perm.count(".") >= 1 and apis
        assert all("#" in a for a in apis)
    from dexllm.dangerous_api import PERM_LEVELS

    assert set(perm_levels.values()) <= set(PERM_LEVELS)
    # The derived dangerous map is non-empty and dangerous-only.
    full, levels = _load_full_map(None), _load_levels(None)
    dangerous = _load_dangerous_map(None)
    assert dangerous and set(dangerous) < set(full)
    assert all(levels.get(p) == "dangerous" for p in dangerous)


def test_dangerous_permission_apis_detects_real_usage(dk):
    apis = dexllm.dangerous_permission_apis(dk)
    assert apis, "fixture APK should exercise some dangerous-permission API"
    # a2dp.Vol uses location + bluetooth APIs
    if any("a2dp.Vol" in p for p in _fixture()):
        assert "android.permission.ACCESS_FINE_LOCATION" in apis
        loc = apis["android.permission.ACCESS_FINE_LOCATION"]
        assert any("LocationManager#getLastKnownLocation" in a for a in loc)
        # the reported entry is the full signature now
        assert all("(" in a and a.endswith(")") for a in loc)
        # overload precision: the app calls getLastKnownLocation(String); the
        # 2-arg LastLocationRequest overload must NOT be reported. (metalava
        # signatures are clean — fully-qualified types, no annotations/param names.)
        gk = [a for a in loc if "getLastKnownLocation" in a]
        assert any(a.endswith("getLastKnownLocation(String)") for a in gk)
        assert not any("LastLocationRequest" in a for a in gk)
        assert "android.permission.BLUETOOTH_CONNECT" in apis
    # shape: {perm: [pkg.Class#method(sig)]}
    for perm, used in apis.items():
        assert used == sorted(used)
        assert all("#" in a for a in used)


def test_signature_parsers():
    from dexllm.dangerous_api import _dalvik_param_types, _parse_api

    # Java signature -> (class, method, simple param types); generics erased,
    # annotations + `final` dropped, varargs/arrays normalised, field -> None.
    assert _parse_api("p.C#m(@NonNull String a)") == ("p.C", "m", ("String",))
    assert _parse_api("p.C#m()") == ("p.C", "m", ())
    assert _parse_api("p.C#FIELD") == ("p.C", "FIELD", None)
    assert _parse_api(
        "p.C#m(@NonNull @CallbackExecutor Executor e, @NonNull Consumer<Location> c)"
    ) == ("p.C", "m", ("Executor", "Consumer"))
    assert _parse_api("p.C#m(int... ids, String[] names)") == (
        "p.C",
        "m",
        ("int[]", "String[]"),
    )
    assert _parse_api("p.C#m(final Map<String, Integer> kv)") == (
        "p.C",
        "m",
        ("Map",),
    )
    assert _parse_api("p.C#m(Outer.Inner x)") == ("p.C", "m", ("Inner",))

    # Adversarial real-dataset shapes (found by stressing the parser over the full
    # AOSP table) — all must parse to clean simple types, never crash:
    # value annotation with parens/`=`/`,` (its inner comma must NOT split params)
    assert _parse_api("p.C#m(@FloatRange(from = 0f, to = 1f) float d)") == (
        "p.C",
        "m",
        ("float",),
    )
    # dotted/qualified annotation name
    assert _parse_api("p.C#m(@TelephonyManager.AllowedNetworkTypesReason int r)") == (
        "p.C",
        "m",
        ("int",),
    )
    # Kotlin `name: Type` order (type is AFTER the colon)
    assert _parse_api("p.C#m(context: Context, action: PinRecoveryAction)") == (
        "p.C",
        "m",
        ("Context", "PinRecoveryAction"),
    )
    # unbalanced parens / garbage must not raise — treated as a non-call (None)
    assert _parse_api("p.C#val x: Y? = if (Flags.foo")[2] is None

    # metalava clean format: fully-qualified types, no param names, no annotations.
    assert _parse_api(
        "android.location.LocationManager#getLastKnownLocation(String, "
        "android.location.LastLocationRequest)"
    ) == (
        "android.location.LocationManager",
        "getLastKnownLocation",
        (
            "String",
            "LastLocationRequest",
        ),
    )
    # wildcard generic `<? extends X>` has spaces but is NOT a param name (metalava
    # carries no names) — generics are erased before the name heuristic runs.
    assert _parse_api(
        "p.C#m(java.util.List<java.lang.Class<? extends p.Rec>>, "
        "java.util.concurrent.Executor)"
    ) == ("p.C", "m", ("List", "Executor"))
    # metalava varargs
    assert _parse_api("p.C#m(int, java.lang.Object...)") == (
        "p.C",
        "m",
        ("int", "Object[]"),
    )

    # Dalvik proto -> the SAME simple-name tuple, so the two compare equal.
    assert _dalvik_param_types("(Ljava/lang/String;)V") == ("String",)
    assert _dalvik_param_types("()V") == ()
    assert _dalvik_param_types("([ILjava/util/function/Consumer;)V") == (
        "int[]",
        "Consumer",
    )
    assert _dalvik_param_types("(Lp/Outer$Inner;)V") == ("Inner",)
    assert _dalvik_param_types("(Ljava/lang/String;)Landroid/location/Location;") == (
        "String",
    )


class _Ref:
    def __init__(self, java_class, name, proto, class_descriptor):
        self.java_class = java_class
        self.name = name
        self.proto = proto
        self.class_descriptor = class_descriptor


class _OverloadDK:
    """dk stand-in referencing ONLY the 1-arg getLastKnownLocation overload."""

    def list_external_method_refs(self, framework_only):
        return [
            _Ref(
                "android.location.LocationManager",
                "getLastKnownLocation",
                "(Ljava/lang/String;)Landroid/location/Location;",
                "Landroid/location/LocationManager;",
            )
        ]

    def find_call_sites_to_api(self, desc):
        return []


def test_overload_disambiguation(monkeypatch):
    """A 2-overload method, only one referenced -> only that overload reported."""
    import dexllm.dangerous_api as da

    table = {
        "android.permission.ACCESS_FINE_LOCATION": (
            "android.location.LocationManager#getLastKnownLocation(@NonNull String provider)",
            "android.location.LocationManager#getLastKnownLocation(@NonNull String provider, @NonNull LastLocationRequest r)",
        )
    }
    monkeypatch.setattr(da, "_load_dangerous_map", lambda _p: table)
    monkeypatch.setattr(da, "_load_full_map", lambda _p: table)
    apis = da.dangerous_permission_apis(_OverloadDK())
    used = apis["android.permission.ACCESS_FINE_LOCATION"]
    assert used == [
        "android.location.LocationManager#getLastKnownLocation(@NonNull String provider)"
    ]  # the 2-arg overload is NOT reported


def test_single_overload_name_fallback(monkeypatch):
    """A lone overload matches on name even if the dex proto differs slightly."""
    import dexllm.dangerous_api as da

    # dataset has ONE overload with an odd (unparseable-ish) signature; the dex
    # ref's proto need not agree because there's no ambiguity to resolve.
    table = {
        "android.permission.ACCESS_FINE_LOCATION": (
            "android.location.LocationManager#getLastKnownLocation(@NonNull String provider)",
        )
    }
    monkeypatch.setattr(da, "_load_dangerous_map", lambda _p: table)
    monkeypatch.setattr(da, "_load_full_map", lambda _p: table)

    class _DK(_OverloadDK):
        def list_external_method_refs(self, framework_only):
            # proto differs (extra arg) but it's the only overload -> still matched
            return [
                _Ref(
                    "android.location.LocationManager",
                    "getLastKnownLocation",
                    "(Ljava/lang/String;J)Landroid/location/Location;",
                    "Landroid/location/LocationManager;",
                )
            ]

    apis = da.dangerous_permission_apis(_DK())
    assert "android.permission.ACCESS_FINE_LOCATION" in apis


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
    from dexllm.dangerous_api import _load_dangerous_map

    with pytest.raises(FileNotFoundError):
        _load_dangerous_map(str(tmp_path))  # empty dir, no JSON files


def test_override_wrong_shape_clear_error(tmp_path):
    from dexllm.dangerous_api import _load_dangerous_map

    (tmp_path / "permissions.json").write_text('{"a": 1}')  # dict, expected list
    (tmp_path / "perm_api_by_perm.json").write_text("{}")
    with pytest.raises(ValueError):
        _load_dangerous_map(str(tmp_path))


def test_override_api_file_non_dict_clear_error(tmp_path):
    from dexllm.dangerous_api import _load_dangerous_map

    (tmp_path / "permissions.json").write_text("[]")  # valid (empty) list
    (tmp_path / "perm_api_by_perm.json").write_text("[1, 2]")  # list, expected object
    with pytest.raises(ValueError):
        _load_dangerous_map(str(tmp_path))


def test_dataset_path_override(dk):
    """If the full dataset is present locally, the override path parses too."""
    ds = "/home/nyahumi/Project/aosp_data_set"
    if not (Path(ds) / "perm_api_metalava_by_perm.json").is_file():
        pytest.skip("full AOSP dataset not present")
    apis = dexllm.dangerous_permission_apis(dk, dataset_path=ds)
    assert isinstance(apis, dict)


def test_ref_filter_rejects_garbage_entries():
    """_REF accepts `Class#method[(sig)]` and rejects malformed scrapes."""
    from dexllm.dangerous_api import _REF

    assert _REF.match("a.b.C#m")
    assert _REF.match("a.b.C#m(@NonNull String a)")
    assert _REF.match("a.b.C#FIELD")
    # a stray Kotlin source line (member name followed by junk, unbalanced paren)
    assert not _REF.match("MediaSessions#val mediaRouter2: X? = if (Flags.foo")
    assert not _REF.match("a.b.C#m() trailing junk")
    assert not _REF.match("no hash here")


def test_full_dataset_parses_without_crash():
    """Every _REF-accepted entry in the full metalava dataset parses cleanly.

    Beyond not raising, every parsed param type must reduce to a clean simple name
    (no leaked annotations / param names / generics) — the metalava table is the
    canonical clean source, so a stray anomaly means a parser regression.
    """
    ds = Path("/home/nyahumi/Project/aosp_data_set/perm_api_metalava_by_perm.json")
    if not ds.is_file():
        pytest.skip("full AOSP dataset not present")
    from dexllm.dangerous_api import _REF, _parse_api

    clean = re.compile(r"^[A-Za-z_$][\w$]*(\[\])*$")
    table = json.loads(ds.read_text())
    entries = {e for apis in table.values() for e in apis}
    parsed = 0
    for e in entries:
        if not _REF.match(e):
            continue
        cls, method, types = _parse_api(e)  # must not raise
        assert cls and method
        if types is not None:
            assert all(
                clean.match(t) for t in types
            ), f"anomalous type in {e!r}: {types}"
        parsed += 1
    assert parsed > 1000  # sanity: the table really was exercised


def test_same_arity_overloads_need_type_match(monkeypatch):
    """Two overloads of the SAME arity -> the param types disambiguate."""
    import dexllm.dangerous_api as da

    table = {
        "android.permission.FOO": (
            "p.C#m(@NonNull String s)",
            "p.C#m(int i)",
        )
    }
    monkeypatch.setattr(da, "_load_dangerous_map", lambda _p: table)
    monkeypatch.setattr(da, "_load_full_map", lambda _p: table)

    class _DK:
        def list_external_method_refs(self, framework_only):
            return [_Ref("p.C", "m", "(I)V", "Lp/C;")]  # the int overload

        def find_call_sites_to_api(self, desc):
            return []

    apis = da.dangerous_permission_apis(_DK())
    assert apis["android.permission.FOO"] == ["p.C#m(int i)"]  # not the String one


def test_constructor_entries_match_init_refs(monkeypatch):
    """Dataset writes a ctor as `Class#SimpleName(...)`; the dex ref is `<init>`."""
    import dexllm.dangerous_api as da

    table = {
        "android.permission.RECORD_AUDIO": (
            "android.media.AudioRecord#AudioRecord(int audioSource, int sampleRateInHz)",
        )
    }
    monkeypatch.setattr(da, "_load_dangerous_map", lambda _p: table)
    monkeypatch.setattr(da, "_load_full_map", lambda _p: table)

    class _DK:
        def list_external_method_refs(self, framework_only):
            return [
                _Ref(
                    "android.media.AudioRecord",
                    "<init>",  # dex names constructors <init>
                    "(II)V",
                    "Landroid/media/AudioRecord;",
                )
            ]

        def find_call_sites_to_api(self, desc):
            return []

    apis = da.dangerous_permission_apis(_DK())
    assert "android.permission.RECORD_AUDIO" in apis


def test_inner_class_separator_canonicalised(monkeypatch):
    """Dataset `Outer.Inner` must match the dex's `Outer$Inner` java_class."""
    import dexllm.dangerous_api as da

    table = {
        "android.permission.FOO": ("android.app.Notification.Builder#setX(int i)",)
    }
    monkeypatch.setattr(da, "_load_dangerous_map", lambda _p: table)
    monkeypatch.setattr(da, "_load_full_map", lambda _p: table)

    class _DK:
        def list_external_method_refs(self, framework_only):
            return [
                _Ref(
                    "android.app.Notification$Builder",  # dex uses `$`
                    "setX",
                    "(I)V",
                    "Landroid/app/Notification$Builder;",
                )
            ]

        def find_call_sites_to_api(self, desc):
            return []

    apis = da.dangerous_permission_apis(_DK())
    assert "android.permission.FOO" in apis
