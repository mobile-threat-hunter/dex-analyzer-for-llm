"""End-to-end guard for the move-chain type-CASCADE re-typing fix.

DAD types every split version from its register's last write, so a Dalvik
register reused across incompatible types can leave a version typed as a
REFERENCE while it actually holds a primitive (an obfuscator's 0/1 flag reusing
an object slot). The reference type is copied off a sibling conflated register by
a `move`, and the version then emits uncompilable Java such as:

    java.util.ArrayList v1_0 = 1;      // reference declared, integer assigned

`FixInitResultTypes`' second pass (dataflow.cpp) fixes this in BOTH directions
by resolving each def to its transitive ground truth: ref→prim (the case above)
and prim→ref (a PRIMITIVE version whose ground truth is a reference + null —
`int v = ObjectAnimator.ofFloat(...); v = 0; v.addListener()` — the "Shape B"
primitive-used-as-object bug). It re-types only when the ground truth is
unambiguous (no unresolved/mixed def; agreeing references).

These tests scan the bundled corpus per method and assert the regression
directions are absent — a real object never made primitive (`prim = new`), a
`RefType v = <nonzero int>` residual bounded, and primitive-used-as-object kept
low by the mirror. Skips if no APK is present.
"""

import glob
import os
import re
from pathlib import Path

import pytest

import dexllm
from dexllm import is_timeout_marker, safe_decompile_method_java

REPO = Path(__file__).resolve().parents[1]

# `<RefType> v<id> = <nonzero int>;` — a reference-declared local assigned a bare
# non-zero integer literal (a `= 0` is the legal null rewrite, so it is excluded).
# The type may be an uppercase class, a dotted package path, or an array.
_PRIMS = ("int", "boolean", "byte", "short", "char", "long", "float", "double")
_REF_INT = re.compile(
    r"^\s*(?!(?:" + "|".join(_PRIMS) + r"|void)\b)"
    r"(?:\[+)?[A-Za-z_]\w*(?:\.[A-Za-z_]\w*)*(?:\[\])*\s+v\w+\s*=\s*"
    r"(-?\d+)\s*;\s*$",
    re.M,
)
# `<prim> v<id> = new …;` — a primitive declared local assigned an allocation
# (the reverse-direction regression this fix must never introduce). A method
# CHAIN (`new X().m()`) is valid, so require the `new` to terminate at `;`.
_PRIM_NEW = re.compile(
    r"^\s*(?:" + "|".join(_PRIMS) + r")\s+v\w+\s*=\s*new\s+[\w.]+"
    r"(?:\[[^\]]*\])?\([^()]*\)\s*;\s*$",
    re.M,
)
# a `<prim> v` declaration whose exact name is later used as an object receiver
_PRIM_DECL = re.compile(
    r"^\s*(?:" + "|".join(_PRIMS) + r")\s+(v\w+)\s*[=;]", re.M)
# a variable ORDERED-compared to null (`v <= null`) — the low-false-positive
# fingerprint of an INT mistyped as a reference (the prim→ref mirror's
# regression: the const-0 renders `null` because the var is reference-typed, and
# `<=` requires numeric operands). `==`/`!=` are excluded (valid null checks).
_REF_ORD_NULL = re.compile(r"(?<![\w.])(v\w+)\s*(?:<=|>=|<|>)\s*null\b")


def _apks():
    env = os.environ.get("DEXLLM_TEST_APK")
    if env and os.path.isfile(env):
        return [env]
    return [
        p
        for p in sorted(glob.glob(str(REPO / "test_apk" / "APK" / "*.apk")))
        if os.path.getsize(p) > 1024
    ]


# a primitive-declared local `v` used AS AN OBJECT in the SAME method: member
# access `v.x`, `throw v;`, or array-deref `v[`. This is the inverse regression
# the pass must NEVER introduce (re-typing a real object to a primitive).
def _object_uses(out, v):
    e = re.escape(v)
    hits = []
    if re.search(r"(?<![\w.])" + e + r"\.\w", out):
        hits.append(f"{v}.member")
    if re.search(r"\bthrow\s+" + e + r"\s*;", out):
        hits.append(f"throw {v}")
    if re.search(r"(?<![\w.])" + e + r"\[", out):
        hits.append(f"{v}[…]")
    return hits


@pytest.fixture(scope="module")
def scanned():
    apks = _apks()
    if not apks:
        pytest.skip("no test APK (set $DEXLLM_TEST_APK or add one under test_apk/APK/)")
    ref_int = []
    prim_new = []
    prim_object = set()  # DEDUPED (class::method, var) — one entry per var, so a
    #                      library method recurring across bundled APKs and a var
    #                      with several object uses each count once (avoids the
    #                      inflation + timing-fragility of a per-hit list).
    ref_ord_null = 0     # `v <op> null` occurrences (mirror ref-used-as-int flood)
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
                # per-method: primitive names may legitimately collide ACROSS
                # methods with reference names (split-version display aliasing),
                # so object-use must be checked within one method's text only.
                out = safe_decompile_method_java(dk, desc, timeout=10.0)
                if is_timeout_marker(out) or not out:
                    continue
                for m in _REF_INT.finditer(out):
                    if m.group(1) != "0":
                        ref_int.append((desc, m.group(0).strip()))
                for m in _PRIM_NEW.finditer(out):
                    prim_new.append((desc, m.group(0).strip()))
                for pv in {m.group(1) for m in _PRIM_DECL.finditer(out)}:
                    if _object_uses(out, pv):
                        prim_object.add((desc, pv))
                ref_ord_null += len(_REF_ORD_NULL.findall(out))
    return {"ref_int": ref_int, "prim_new": prim_new,
            "prim_object": sorted(prim_object), "ref_ord_null": ref_ord_null}


# The pass is SOUND-by-construction (it re-types a reference version to a
# primitive ONLY when every def is provably primitive/null and the version is
# never used as an object). These two tests assert the two regression
# directions it must never introduce.
def test_no_primitive_assigned_allocation(scanned):
    """The fix must never make a real object primitive (`prim v = new …`)."""
    bad = scanned["prim_new"]
    assert not bad, (
        f"{len(bad)} primitive-declared locals assigned `new …()` "
        f"(reverse-direction regression). e.g. {bad[:5]}"
    )


def test_primitive_used_as_object_bounded(scanned):
    """`prim v; … v.m()` / `throw v` / `v[i]` (a primitive used AS an object) is
    Shape B — a primitive mistyped where a reference belongs. The prim→ref MIRROR
    pass fixes most of these (bundled deduped ~262 → ~60). This ceiling documents
    that: the mirror must keep them low (a regression that DISABLED the mirror,
    or the ref→prim cascade wrongly re-typing an object to a primitive, both push
    this back up). The residual is genuine int/ref merges + display-name-collision
    artifacts (a distinct `v4` version legitimately int in the same method).
    Deduped per (method, var) so it is stable across corpus size / timeouts."""
    bad = scanned["prim_object"]
    assert len(bad) <= 90, (
        f"{len(bad)} primitive-declared locals used AS AN OBJECT (mirror keeps "
        f"this ~60; a jump means the mirror is disabled or the cascade re-typed "
        f"an object to a primitive). e.g. {bad[:8]}"
    )


def test_ref_used_as_int_bounded(scanned):
    """`v <op> null` (a variable ordered-compared to null) is the low-false-
    positive fingerprint of an INT mistyped as a REFERENCE. Two forces move it:
    (a) the prim→ref MIRROR must not CREATE it (its int-use guard blocks re-typing
    an int-used version — an a/b measured 0 new); (b) the single-def ref→prim
    CASCADE FIXES it — a lone primitive-returning method typed reference by
    register conflation (`String v = p.indexOf(','); v >= null`) is re-typed to
    the resolved primitive (`int v = …indexOf(); v >= 0`). That cascade cut the
    bundled count ~109 → ~53. The residual is genuine int/ref merges (a ref DEF
    and an int use, needing a version split) — this ceiling catches a regression
    (mirror flooding it, or the cascade being disabled) without pinning an exact
    count."""
    n = scanned["ref_ord_null"]
    assert n <= 75, (
        f"{n} `v <op> null` (a variable ordered-compared to null — an int mistyped "
        f"as a reference). Bundled ~53 after the single-def cascade; a jump means "
        f"the cascade is disabled or the mirror re-typed an int-used version."
    )


# The cascade re-type removes most `ReferenceType v = <nonzero int>;` lines; a
# provably-uncertain residual (an unresolvable move-chain def) is left untouched
# by design. This is a loose ceiling: it documents the fix keeps cascades low
# and catches a regression that FLOODS them (e.g. the pass silently disabled),
# without asserting an exact count that a corpus change would make brittle.
def test_reference_int_cascades_bounded(scanned):
    """Reference-declared-nonzero-int cascades stay well below the un-fixed
    baseline (bundled corpus was ~150+ before the pass)."""
    residual = scanned["ref_int"]
    assert len(residual) <= 40, (
        f"{len(residual)} `RefType v = <nonzero int>;` lines — the cascade "
        f"re-type appears disabled or regressed. e.g. {residual[:8]}"
    )
