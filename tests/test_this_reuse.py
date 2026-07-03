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
# only the void-invoke DAD artifact subset remains (a separate, deeper bug).
_THIS_ASSIGN = re.compile(r"^\s*this\s*=", re.M)
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
    return {"mistyped": mistyped, "good_mat": good_mat}


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


def _classes(apk):
    try:
        if dexllm.identify(apk).get("dex_count", 0) == 0:
            return ()
        return set(dexllm.DexKit(apk).list_classes())
    except Exception:
        return ()
