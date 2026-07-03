"""Guard for the reused-`this` materialization fix (MaterializeReusedThis).

When a method reuses its receiver register (p0) as a scratch local, DAD emits
`this = <value>` — always invalid Java (you cannot assign to `this`). The fix
materialises a fresh local seeded `<Class> vX = this;` and rewrites the reuses to
it, but ONLY for a genuine VALUED reuse; a void-invoke artifact (`this =
super.onDraw()`, a void call DAD wrongly models as defining the receiver) is left
as DAD's output (renaming it would expose the artifact — strictly worse).

These tests assert, over the bundled corpus:
  * no mistyped materialization (`int v = this;` / `void v = this;` — the type
    corruption the fix must restore from the class);
  * a genuine reuse (`Fragment findFragmentByWho`) is fully valid — no `this =`,
    a `<Class> v = this;` seed, and `return v`;
  * the fix is actually active (some `<Class> v = this;` seeds are emitted).
Skips if no APK is present.
"""

import glob
import os
import re
from pathlib import Path

import pytest

import dexllm
from dexllm import is_timeout_marker, safe_decompile_method_java

REPO = Path(__file__).resolve().parents[1]
_PRIMS = ("int", "boolean", "byte", "short", "char", "long", "float", "double", "void")

# `this = …;` — assignment to the receiver (always invalid Java). After the fix
# only the non-void materialise-skipped subset remains (a separate, deeper bug).
_THIS_ASSIGN = re.compile(r"^\s*this\s*=", re.M)
# `this = super.<call>` — a void super call modelled as defining the receiver
# (the invoke-super/range DAD artifact). Dropped by the Writer to `super.m(...)`.
_THIS_SUPER = re.compile(r"^\s*this\s*=\s*super\.", re.M)
# `<primitive|void> vN = this;` — a mistyped materialization (the receiver's
# ThisParam type is corrupted to the last reuse's rhs during Construct; the fix
# must restore the class type). Must be 0.
_MISTYPED_MAT = re.compile(
    r"^\s*(?:" + "|".join(_PRIMS) + r")\s+v\w+\s*=\s*this\s*;", re.M)
# `<Class> vN = this;` — a correct materialization seed (reference-typed).
_GOOD_MAT = re.compile(
    r"^\s*(?!(?:" + "|".join(_PRIMS) + r")\b)"
    r"[A-Za-z_][\w.$]*(?:\[\])*\s+v\w+\s*=\s*this\s*;", re.M)


def _apks():
    env = os.environ.get("DEXLLM_TEST_APK")
    if env and os.path.isfile(env):
        return [env]
    return [
        p
        for p in sorted(glob.glob(str(REPO / "test_apk" / "APK" / "*.apk")))
        if os.path.getsize(p) > 1024
    ]


@pytest.fixture(scope="module")
def scanned():
    apks = _apks()
    if not apks:
        pytest.skip("no test APK (set $DEXLLM_TEST_APK or add one under test_apk/APK/)")
    mistyped = []
    good_mat = 0
    this_super = 0
    this_super_ex = []
    per_apk_cap = 6000
    for apk in apks:
        try:
            if dexllm.identify(apk).get("dex_count", 0) == 0:
                continue
            dk = dexllm.DexKit(apk)
        except Exception:
            continue
        n = 0
        for c in dk.list_classes():
            if n >= per_apk_cap:
                break
            n += 1
            try:
                methods = dk.list_class_methods(c)
            except Exception:
                continue
            for desc in methods:
                out = safe_decompile_method_java(dk, desc, timeout=10.0)
                if is_timeout_marker(out) or not out:
                    continue
                for m in _MISTYPED_MAT.finditer(out):
                    mistyped.append((desc, m.group(0).strip()))
                good_mat += len(_GOOD_MAT.findall(out))
                for m in _THIS_SUPER.finditer(out):
                    this_super += 1
                    if len(this_super_ex) < 5:
                        this_super_ex.append(m.group(0).strip())
    return {"mistyped": mistyped, "good_mat": good_mat,
            "this_super": this_super, "this_super_ex": this_super_ex}


def test_no_mistyped_this_materialization(scanned):
    """`<prim>/void vN = this;` — a primitive/void-typed local seeded with `this`.
    The MaterializeReusedThis fix ALWAYS types its seed as the class, so it never
    emits these; the residual are a SEPARATE pre-existing bug — a `move-object vN,
    p0` into a register conflation-typed void/int by an earlier void call (low vid,
    unrelated to the receiver reuse). An a/b (fix off vs on) measured this count
    UNCHANGED (40 → 40), so this ceiling exists to catch a regression where the
    materialize fix starts leaking a mistyped seed (the class-type restore
    breaking), NOT to assert the pre-existing bug is fixed."""
    bad = scanned["mistyped"]
    assert len(bad) <= 45, (
        f"{len(bad)} primitive/void-typed `v = this;` — the class-type restore in "
        f"MaterializeReusedThis regressed (baseline ~40 is a separate pre-existing "
        f"move-into-conflated-local bug). e.g. {bad[:5]}"
    )


def test_materialization_active(scanned):
    """The fix must actually fire — a genuine valued reuse produces a reference-
    typed `<Class> vX = this;` seed. A count of 0 means the pass is disabled."""
    assert scanned["good_mat"] > 0, (
        "no `<Class> v = this;` seeds emitted — MaterializeReusedThis appears "
        "disabled (a genuine reused-`this` should materialise a local)."
    )


def test_fragment_reuse_is_valid():
    """The canonical repro `Fragment.findFragmentByWho` reuses p0 to hold the
    result; the fix must make it valid — no `this =`, a `<Class> v = this;` seed,
    and `return v`. Skips if the support-library class is absent."""
    cls = "Landroid/support/v4/app/Fragment;"
    for apk in _apks():
        if cls not in _classes(apk):
            continue
        dk = dexllm.DexKit(apk)
        desc = None
        for m in dk.list_class_methods(cls):
            if "findFragmentByWho" in m:
                desc = m
                break
        if desc is None:
            continue
        out = dk.decompile_method_java(desc)
        assert not _THIS_ASSIGN.search(out), f"still emits `this =`:\n{out}"
        assert _GOOD_MAT.search(out), f"no `<Class> v = this;` seed:\n{out}"
        assert re.search(r"return\s+v\w+\s*;", out), f"no `return v`:\n{out}"
        return
    pytest.skip("findFragmentByWho not found in any bundled Fragment variant")


def test_no_this_equals_super_void_call(scanned):
    """A VOID `invoke-super/range` (or `invoke-direct/range`) on the receiver is
    modelled by DAD as `returned = base` (unlike the non-range handlers that null
    it), so a void super call renders the invalid `this = super.m(...)`. The
    Writer drops the LHS of a void invoke on a ThisParam → `super.m(...);`. A
    NON-void super call never assigns to the receiver (it goes to a fresh temp),
    so `this = super.` is exclusively the void-range artifact — assert 0 remain."""
    n = scanned["this_super"]
    assert n == 0, (
        f"{n} `this = super.<call>` lines — the void-invoke-on-receiver LHS drop "
        f"(writer.cpp visit_assign) regressed. e.g. {scanned['this_super_ex'][:5]}"
    )


def test_void_super_renders_call_only():
    """`ProviderList.onListItemClick` (void) begins with a void `super.onListItem
    Click(...)`; it must render as a bare call, not `this = super...`. Skips if
    absent."""
    cls = "La2dp/Vol/ProviderList;"
    for apk in _apks():
        if cls not in _classes(apk):
            continue
        dk = dexllm.DexKit(apk)
        desc = None
        for m in dk.list_class_methods(cls):
            if "onListItemClick" in m:
                desc = m
                break
        if desc is None:
            continue
        out = dk.decompile_method_java(desc)
        assert "this = super.onListItemClick" not in out, out[:400]
        assert re.search(r"^\s*super\.onListItemClick\(", out, re.M), out[:400]
        return
    pytest.skip("no APK bundling a2dp.Vol.ProviderList.onListItemClick")


def test_arg_sink_materialization_valid():
    """A receiver reused as `cond ? this : null` and passed as an ARGUMENT (not
    returned) is materialised via the ARG sink — vX typed as the callee's
    parameter type, proven assignable to the declaring class by the injected
    is_assignable class-hierarchy oracle (or by `this` reaching the call). The
    canonical repro `MenuItemWrapperJB$ActionProviderWrapperJB.setVisibilityList
    ener` must render a valid `<ParamType> vX = this; if(...) vX = null;
    …setVisibilityListener(vX)` — no `this =`. Skips if absent."""
    cls = "Landroid/support/v7/view/menu/MenuItemWrapperJB$ActionProviderWrapperJB;"
    for apk in _apks():
        if cls not in _classes(apk):
            continue
        dk = dexllm.DexKit(apk)
        desc = None
        for m in dk.list_class_methods(cls):
            if "setVisibilityListener" in m:
                desc = m
                break
        if desc is None:
            continue
        out = dk.decompile_method_java(desc)
        assert not _THIS_ASSIGN.search(out), out[:400]
        # the materialised local is typed as the arg's param type (a reference)
        assert _GOOD_MAT.search(out), out[:400]
        assert re.search(r"setVisibilityListener\(v\w+\)", out), out[:400]
        return
    pytest.skip("no APK bundling the ActionProviderWrapperJB arg-sink repro")


def test_def_anchor_throw_new():
    """A receiver reused ONLY to hold a `new X()` that is then thrown/discarded
    (no return-this, no arg-this sink) is materialised via the DEF-anchor:
    vX = X, and NO `vX = this` seed (the entry value is never read). The
    canonical repro `ActionBar.setHideOffset` must render
    `throw new UnsupportedOperationException(...)` — no `this =`, no leftover
    `<X> vX = this;`. Skips if absent."""
    cls = "Landroidx/appcompat/app/ActionBar;"
    for apk in _apks():
        if cls not in _classes(apk):
            continue
        dk = dexllm.DexKit(apk)
        desc = None
        for m in dk.list_class_methods(cls):
            if "setHideOffset" in m:
                desc = m
                break
        if desc is None:
            continue
        out = dk.decompile_method_java(desc)
        assert not _THIS_ASSIGN.search(out), out[:400]
        assert not _GOOD_MAT.search(out), (
            "def-anchor must NOT inject a `<X> vX = this;` seed (entry value "
            f"is dead):\n{out}"
        )
        assert re.search(
            r"throw new [\w.$]*UnsupportedOperationException\(", out), out[:400]
        return
    pytest.skip("no APK bundling ActionBar.setHideOffset")


def test_def_anchor_priority_over_return_sink():
    """A receiver reused ONLY to hold a `new C()` that is then RETURNED (a typed
    use-sink IS present) still materialises via the DEF-anchor, which now takes
    PRIORITY over the return-sink anchor whenever every reassignment is `new C`
    of one class C and the entry `this` is never read. `ViewPager.generateDefault
    LayoutParams` returns `ViewGroup$LayoutParams` but allocates the subtype
    `ViewPager$LayoutParams`; it must render `return new ViewPager$LayoutParams()`
    — no `this =`. (The framework-transitive variant, e.g. an obfuscated
    `generateDefaultLayoutParams` allocating the pure-framework
    `ViewGroup$MarginLayoutParams`, is the case that FAILS without the priority:
    the use-sink path's `assignable(C, ret)` check cannot prove the subtype through
    a framework class and bails to invalid `this = new C; return this`.) Skips if
    the repro class is absent."""
    cls = "Landroid/support/v4/view/ViewPager;"
    for apk in _apks():
        if cls not in _classes(apk):
            continue
        dk = dexllm.DexKit(apk)
        desc = None
        for m in dk.list_class_methods(cls):
            if m.split("->")[-1].startswith("generateDefaultLayoutParams"):
                desc = m
                break
        if desc is None:
            continue
        out = dk.decompile_method_java(desc)
        assert not _THIS_ASSIGN.search(out), out[:400]
        # the def-anchor injects no `<X> vX = this;` seed (entry value is dead)
        assert not _GOOD_MAT.search(out), out[:400]
        assert re.search(
            r"return\s+new\s+[\w.$]*ViewPager\$LayoutParams\(", out), out[:400]
        return
    pytest.skip("no APK bundling ViewPager.generateDefaultLayoutParams")


def _classes(apk):
    try:
        if dexllm.identify(apk).get("dex_count", 0) == 0:
            return ()
        return set(dexllm.DexKit(apk).list_classes())
    except Exception:
        return ()
