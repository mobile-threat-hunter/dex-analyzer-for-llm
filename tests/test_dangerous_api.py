"""Tests for dangerous-permission -> API -> caller mapping.

Joins AOSP's @RequiresPermission permission->API table (bundled slim) against an
APK's referenced framework APIs. a2dp.Vol_137.apk is a stable benign fixture that
genuinely uses location, Bluetooth, and phone-state APIs.
"""

import glob
import json
import os
import re
import sys
import threading
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
    if not apis:
        # A corpus fact, not a code fact — $DEXLLM_TEST_APK can select an APK that
        # calls no gated API (14 of the 25 bundled ones). Skip, never fail.
        pytest.skip("this APK exercises no dangerous-permission API")
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

    def find_call_sites_to(self, desc):
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
    if not callers:
        pytest.skip("this APK has no app caller of a dangerous-permission API")
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

        def find_call_sites_to(self, desc):
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

        def find_call_sites_to(self, desc):
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

        def find_call_sites_to(self, desc):
            return []

    apis = da.dangerous_permission_apis(_DK())
    assert "android.permission.FOO" in apis


# --- the derived overload index is memoised (issue #39) ------------------------
#
# `_overload_index` rebuilt a 5,150-row index on every call — ~30 ms of the ~39 ms
# warm `permission_api_callers`, paid again by each of its three consumers. It is
# now memoised on the identity of the table it derives from.


@pytest.fixture
def memo():
    """An EMPTY, isolated `_OVERLOAD_CACHE` for the test, restored afterwards.

    The memo is a module global in a shared pytest process: without this a test
    that fills it evicts the bundled entry for every later test (and one that
    leaves a single extra entry can flip an `is` assertion here).
    """
    import dexllm.dangerous_api as da

    saved = da._OVERLOAD_CACHE
    da._OVERLOAD_CACHE = {}
    try:
        yield da
    finally:
        da._OVERLOAD_CACHE = saved


def _fake_dataset(root, keep=slice(None, None, 2)):
    """Write a dataset override at `root` holding a SUBSET of the bundled table."""
    data = REPO / "src" / "dexllm" / "data"
    full = json.loads((data / "perm_api.json").read_text())
    levels = json.loads((data / "perm_levels.json").read_text())
    sub = {p: v[keep] for i, (p, v) in enumerate(sorted(full.items())) if i % 2 == 0}
    (root / "perm_api_metalava_by_perm.json").write_text(json.dumps(sub))
    (root / "permissions.json").write_text(
        json.dumps(
            [{"name": p, "protectionLevel": levels.get(p, "normal")} for p in sub]
        )
    )
    return sub


def test_overload_index_is_memoised_per_table(memo):
    """Same table object -> the same index; a different table -> its OWN index."""
    da = memo

    table = da._load_full_map(None)
    first = da._overload_index(table)
    assert da._overload_index(table) is first  # not rebuilt

    other = {"android.permission.FOO": ("a.B#m(int i)",)}
    other_index = da._overload_index(other)
    assert other_index is not first
    assert other_index == {("a.B", "m"): {1: 1}}  # derived from ITS table, not the
    assert da._overload_index(table) is first  # ... bundled one, which is intact


def test_public_paths_do_not_rebuild_the_overload_index(dk, memo, monkeypatch):
    """The three consumers hit the memo, not the builder — the point of #39."""
    da = memo

    warm = (
        da.dangerous_permission_apis(dk),
        da.dangerous_permission_api_callers(dk),
        da.permission_api_callers(dk),
    )

    def _explode(_table):
        raise AssertionError("overload index rebuilt on a warm call")

    monkeypatch.setattr(da, "_build_overload_index", _explode)
    assert (
        da.dangerous_permission_apis(dk),
        da.dangerous_permission_api_callers(dk),
        da.permission_api_callers(dk),
    ) == warm


def test_consumers_do_not_mutate_the_shared_overload_index(dk, memo):
    """The memo hands out ONE shared mapping — no consumer may write to it."""
    da = memo

    table = da._load_full_map(None)
    expected = da._build_overload_index(table)
    shared = da._overload_index(table)  # hold it: an eviction must not hide a write
    da.dangerous_permission_apis(dk)
    da.dangerous_permission_api_callers(dk, app_only=False)
    da.permission_api_callers(dk, levels={"dangerous"})
    assert shared == expected


def test_overload_index_cache_is_bounded_and_evicts_oldest_first(memo):
    """Feeding it many tables must not grow the memo, and must evict in order."""
    da = memo

    tables = [
        {"android.permission.FOO": (f"a.B{i}#m(int i)",)}
        for i in range(da._OVERLOAD_CACHE_MAX + 3)
    ]
    for t in tables:
        da._overload_index(t)
    assert len(da._OVERLOAD_CACHE) == da._OVERLOAD_CACHE_MAX
    # the OLDEST 3 were evicted, the newest MAX are still resident
    assert [id(t) for t in tables[3:]] == list(da._OVERLOAD_CACHE)
    # and the memo still answers correctly for a table it evicted
    assert da._overload_index(tables[0]) == {("a.B0", "m"): {1: 1}}


def test_overload_index_survives_concurrent_misses(memo):
    """The miss path mutates a module global — worker threads must not tear it.

    Both servers dispatch these calls with `asyncio.to_thread`. Unlocked, the
    `len`/`next(iter)`/`pop`/`__setitem__` sequence raised `KeyError` and
    `RuntimeError: dictionary changed size during iteration` out of a read-only
    query, and ratcheted the cache past its bound.
    """
    da = memo

    for i in range(da._OVERLOAD_CACHE_MAX):  # fill it, so every call below evicts
        da._overload_index({"p": (f"a.Fill{i}#m(int i)",)})

    errors: list[BaseException] = []

    def hammer(tid: int) -> None:
        for i in range(1500):
            table = {
                "android.permission.FOO": tuple(
                    f"a.T{tid}_{i}_{k}#m{k}(int i)" for k in range(30)
                )
            }
            try:
                da._overload_index(table)
            except BaseException as exc:  # noqa: BLE001
                errors.append(exc)

    saved = sys.getswitchinterval()
    sys.setswitchinterval(1e-6)  # force interleaving inside the eviction block
    try:
        threads = [threading.Thread(target=hammer, args=(t,)) for t in range(12)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
    finally:
        sys.setswitchinterval(saved)

    assert not errors, f"{len(errors)} errors, first: {errors[0]!r}"
    assert len(da._OVERLOAD_CACHE) <= da._OVERLOAD_CACHE_MAX


def test_a_dataset_override_is_not_served_the_bundled_index(dk, memo, tmp_path):
    """A second root must get ITS own index, and the bundled one must survive it.

    Must hold on BOTH sides of #39 — non-discriminating by design (a root-keyed
    memo could get this wrong; the identity-keyed one cannot). It pins the
    invariant the memo must not break, it does not prove the memo exists.
    """
    da = memo

    _fake_dataset(tmp_path)
    bundled = da.permission_api_callers(dk)
    override = da.permission_api_callers(dk, dataset_path=str(tmp_path))
    if bundled == override:
        # An APK that exercises no permission API answers [] under BOTH roots, so
        # it cannot tell them apart. That is a property of the sample: skip, never
        # fail (17 of the 25 bundled APKs are in this position).
        pytest.skip("this APK exercises no permission API — the roots cannot differ")
    assert da.permission_api_callers(dk) == bundled
    assert da.permission_api_callers(dk, dataset_path=str(tmp_path)) == override
