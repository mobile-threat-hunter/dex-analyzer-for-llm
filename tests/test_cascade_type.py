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
_PRIM_DECL = re.compile(r"^\s*(?:" + "|".join(_PRIMS) + r")\s+(v\w+)\s*[=;]", re.M)
# a variable ORDERED-compared to null (`v <= null`) — the low-false-positive
# fingerprint of an INT mistyped as a reference (the prim→ref mirror's
# regression: the const-0 renders `null` because the var is reference-typed, and
# `<=` requires numeric operands). `==`/`!=` are excluded (valid null checks).
_REF_ORD_NULL = re.compile(r"(?<![\w.])(v\w+)\s*(?:<=|>=|<|>)\s*null\b")
# `int/short/byte/char v = <wide-returning method>();` — a long/float/double
# value narrowed into a too-narrow declaration (uncompilable). The prim→WIDER
# pass fixes it by re-typing to the def width (`long v = System.currentTimeMillis()`).
_NARROW_WIDE = re.compile(
    r"^\s*(?:int|short|byte|char)\s+v\w+\s*=\s*[\w.]*\."
    r"(?:parseLong|currentTimeMillis|nanoTime|longValue|getTimeInMillis"
    r"|parseFloat|parseDouble|doubleValue|floatValue)\b",
    re.M,
)
# a variable declared a REFERENCE (not primitive/void/keyword) — captures its name.
_REF_DECL = re.compile(
    r"^\s*(?!(?:" + "|".join(_PRIMS) + r"|void|return|new|throw|case|else"
    r"|if|while|for|do|switch)\b)"
    r"(?:\[+)?[A-Za-z_]\w*(?:\.[A-Za-z_]\w*)*(?:\[\])*\s+(v\w+)\s*[=;]",
    re.M,
)
# `v == <nonzero>` / `v != <nonzero>` (either operand order). A reference compares
# `==` only to null (const 0) or another reference — never to a nonzero literal —
# so a reference-declared var here is an INT mistyped as a reference. The eq/ne
# post-pass in FixInitResultTypes re-types such a var to a primitive (unless it is
# itself genuinely int/ref-conflated, which the path-robust proof deliberately skips).
_EQ_NONZERO = re.compile(
    r"(?<![\w.])(v\w+)\s*[!=]=\s*(-?\d+)\b|(?<![\w.])(-?\d+)\s*[!=]=\s*(v\w+)"
)


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
    ref_ord_null = 0  # `v <op> null` occurrences (mirror ref-used-as-int flood)
    narrow_wide = 0  # `int v = <wide-returning method>` (narrowing, prim→wider)
    ref_eq_nonzero = 0  # `RefType v; v == <nonzero>` (int mistyped ref; eq/ne pass)
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
                narrow_wide += len(_NARROW_WIDE.findall(out))
                refs = {m.group(1) for m in _REF_DECL.finditer(out)}
                eqv = set()
                for m in _EQ_NONZERO.finditer(out):
                    v, lit = (
                        (m.group(1), m.group(2))
                        if m.group(1)
                        else (m.group(4), m.group(3))
                    )
                    if lit != "0":
                        eqv.add(v)
                ref_eq_nonzero += len(refs & eqv)
    return {
        "ref_int": ref_int,
        "prim_new": prim_new,
        "prim_object": sorted(prim_object),
        "ref_ord_null": ref_ord_null,
        "narrow_wide": narrow_wide,
        "ref_eq_nonzero": ref_eq_nonzero,
    }


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
    pass fixes most of these — both the multi-def (reference + null) and the
    single-def object-USE-corroborated shape (`int v2 = getViewHolderInt(...);
    v2.isRemoved()` → the reference the method returns; deduped ~181 → ~35). This
    ceiling documents that: the mirror must keep them low (a regression that
    DISABLED the mirror — single-def or multi — or the ref→prim cascade wrongly
    re-typing an object to a primitive, all push this back up). The residual is
    genuine int/ref merges (both an object AND an int def, needing a version
    split). Deduped per (method, var) so it is stable across corpus size."""
    bad = scanned["prim_object"]
    # ~17 after the move-cycle gt() resolution (a cycle back-edge is NEUTRAL, so
    # a mirror/cascade chain that reconverges through a move-diamond now resolves
    # instead of blocking on a spurious 'U') — down from ~35 before it.
    assert len(bad) <= 30, (
        f"{len(bad)} primitive-declared locals used AS AN OBJECT (mirror keeps "
        f"this ~17; a jump means the mirror — single-def or multi — is disabled "
        f"or the cascade re-typed an object to a primitive). e.g. {bad[:8]}"
    )


def test_ref_used_as_int_bounded(scanned):
    """`v <op> null` (a variable ordered-compared to null) is the low-false-
    positive fingerprint of an INT mistyped as a REFERENCE. Two forces move it:
    (a) the prim→ref MIRROR must not CREATE it (its int-use guard blocks re-typing
    an int-used version — an a/b measured 0 new); (b) the single-def ref→prim
    CASCADE FIXES it — a lone primitive-returning method typed reference by
    register conflation (`String v = p.indexOf(','); v >= null`) is re-typed to
    the resolved primitive (`int v = …indexOf(); v >= 0`). The int-use set covers
    two-operand ordered comparisons AND single-operand vs-zero ones (`if-ltz` →
    `v < 0`; a ConditionalZExpression), which together cut the bundled count ~109
    → ~11. The residual is genuine int/ref merges (a ref DEF and an int use,
    needing a version split) — this ceiling catches a regression (mirror flooding
    it, or the cascade being disabled) without pinning an exact count."""
    n = scanned["ref_ord_null"]
    assert n <= 30, (
        f"{n} `v <op> null` (a variable ordered-compared to null — an int mistyped "
        f"as a reference). Bundled ~11 after the vs-zero int-use corroboration; a "
        f"jump means the cascade is disabled or the mirror re-typed an int-used "
        f"version."
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
    # ~6 after the move-cycle gt() resolution (down from ~26): a version whose
    # all-primitive/null defs reconverge through a move-diamond used to block on a
    # spurious cycle-'U' and keep DAD's reference type; the neutral back-edge now
    # lets the cascade re-type it. A jump means that resolution regressed.
    assert len(residual) <= 15, (
        f"{len(residual)} `RefType v = <nonzero int>;` lines — the cascade "
        f"re-type appears disabled or regressed. e.g. {residual[:8]}"
    )


def test_no_wide_value_narrowed_to_int(scanned):
    """A `long`/`float`/`double`-returning method whose result was mistyped into a
    too-narrow declaration (`int v = System.currentTimeMillis()`) is uncompilable.
    The prim→WIDER pass re-types the version to the def width. Assert 0 remain."""
    n = scanned["narrow_wide"]
    assert n == 0, (
        f"{n} `int/short/byte/char v = <wide-returning method>()` narrowing(s) "
        f"— the prim→wider re-type appears disabled or regressed."
    )


def test_ref_equals_nonzero_int_bounded(scanned):
    """`RefType v; … if (v == 5)` is an INT mistyped as a REFERENCE — a reference
    compares `==`/`!=` only to null or another reference, never to a nonzero
    literal. The eq/ne post-pass adds the comparison partner to the int-use set so
    the prim→ref MIRROR won't type it a reference (and the ref→prim CASCADE can
    re-type an existing conflated one to its resolved primitive). An a/b on the
    bundled corpus measured 100 (pass OFF) → 8 (pass ON); the residual is genuine
    int/ref-conflated versions (a nonzero-int def AND a reference def on different
    arms), which the path-robust `is_nonzero_int_const` proof deliberately skips —
    re-typing those needs a real version split. This ceiling catches a regression
    that DISABLES the pass (count jumps back toward the ~100 baseline)."""
    n = scanned["ref_eq_nonzero"]
    assert n <= 25, (
        f"{n} `RefType v = …; v == <nonzero int>` lines (an int mistyped as a "
        f"reference). Bundled ~8 after the eq/ne pass (baseline ~100 without it); "
        f"a jump means the eq/ne re-type is disabled or regressed."
    )


def test_prim_ref_mismatch_var_assign_bounded():
    """`T1 v = v2;` where one of {T1, decl-type-of v2} is primitive and the other
    a reference is uncompilable — a register conflated across a prim and a ref
    reused via a move. Two fixes bound this residual: the prim→ref MIRROR (a
    version used at a REFERENCE-ARGUMENT position — `int v = findViewById();
    removeView(v)` → `View v`), and the MOVE-OPCODE ground truth (a single-def
    move-DEST whose declared type contradicts the move opcode — `move-object` ⇒
    reference, `move`/`move-wide` ⇒ primitive — is re-typed to agree, e.g.
    `OnPrepareListViewListener v4 = v1` [v1 int via `move`] → `int v4 = v1`). The
    move-opcode fix (a bounded-fixpoint post-pass reading FINAL types) cut the
    bundled residual 108 → 36 (obfuscated 55 → 31) with 0 new mismatches (verified
    by an OFF/ON line-set diff on both corpora — 72/24 removed, 0 added — the
    fixpoint converges move CHAINS and reads settled source types so no
    move-chain-boundary cascade appears). A regression toward ~108 means the
    move-opcode kind plumbing or the corroboration regressed. The residual is
    genuine object+int merges (a real ref def AND a real prim def on one register)
    that need a version split."""
    apks = _apks()
    if not apks:
        pytest.skip("no test APK")
    prims = set(_PRIMS)
    decl = re.compile(r"^\s*([A-Za-z_][\w.$]*(?:\[\])*)\s+(v\w+)\s*[=;]", re.M)
    assign = re.compile(
        r"^\s*([A-Za-z_][\w.$]*(?:\[\])*)\s+(v\w+)\s*=\s*(v\w+)\s*;", re.M
    )
    mism = 0
    for apk in apks:
        try:
            if dexllm.identify(apk).get("dex_count", 0) == 0:
                continue
            dk = dexllm.DexKit(apk)
        except Exception:
            continue
        per = 0
        for c in dk.list_classes():
            if per >= 6000:
                break
            per += 1
            try:
                methods = dk.list_class_methods(c)
            except Exception:
                continue
            for desc in methods:
                out = safe_decompile_method_java(dk, desc, timeout=10.0)
                if is_timeout_marker(out) or not out:
                    continue
                dt = {}
                for m in decl.finditer(out):
                    dt.setdefault(m.group(2), m.group(1))
                for m in assign.finditer(out):
                    rt = dt.get(m.group(3))
                    if rt and (m.group(1) in prims) != (rt in prims):
                        mism += 1
    assert mism <= 48, (
        f"{mism} `T v = varOfOtherKind;` prim/ref-mismatch assigns (bundled ~36 "
        f"after the move-opcode ground-truth fixpoint; a jump toward ~108 means "
        f"the move-kind plumbing or corroboration regressed)."
    )


def _find_method(substr, methodname):
    """Return (dk, desc) for the first bundled method whose class contains
    `substr` and whose descriptor contains `methodname`, else (None, None)."""
    for apk in _apks():
        try:
            if dexllm.identify(apk).get("dex_count", 0) == 0:
                continue
            dk = dexllm.DexKit(apk)
        except Exception:
            continue
        for c in dk.list_classes():
            if substr not in c:
                continue
            try:
                methods = dk.list_class_methods(c)
            except Exception:
                continue
            for desc in methods:
                if methodname in desc:
                    return dk, desc
    return None, None


def test_use_bound_prim_to_ref_typing():
    """USE-BOUND prim→ref (design §3): a primitive-typed version with NO
    reference DEF, pinned as a reference ONLY by a ref-argument USE, is re-typed
    to that use's reference type. The canonical shape is a Kotlin `$default`
    bridge: a Dalvik register shared between a reference param and a scratch
    local leaves the version typed `int` (DAD last-write), the reference lost
    from every def, present only at the ref-arg call — DAD emits
    `int v = pRefParam; refCall(v)`. The fix re-types it to the param type.

    `ActorKt.actor$default` reuses p10 (`Function1`) as the merged version v4;
    without the fix it is `int v4; v4 = p10; … actor(…, v4, …)`. With it, v4 is
    the reference and the `= 0` default renders `= null`."""
    dk, desc = _find_method("kotlinx/coroutines/channels/ActorKt", "actor$default")
    if desc is None:
        pytest.skip("ActorKt.actor$default not in the bundled corpus")
    out = safe_decompile_method_java(dk, desc, timeout=10.0)
    if is_timeout_marker(out) or not out:
        pytest.skip("actor$default did not decompile")
    # The merged version is now the reference param type, not `int`.
    assert "Function1 v4" in out, (
        "the use-bound prim→ref re-type appears disabled: v4 should be typed "
        f"`Function1` (the ref-arg param), not `int`.\n{out}"
    )
    assert (
        re.search(r"\bint v4\b", out) is None
    ), f"v4 is still declared `int` — the use-bound typing did not fire.\n{out}"
    # And its null default renders `= null`, not the uncompilable `= 0`.
    assert re.search(
        r"\bv4\s*=\s*null\b", out
    ), f"v4's reference default should render `= null`.\n{out}"


def test_conflated_register_typed_object_with_casts():
    """A Dalvik register genuinely reused across a REFERENCE and a NONZERO
    INTEGER LITERAL (a conflation Java cannot express as one type) is typed
    `Object` — the honest common type — instead of DAD's misleading
    `RefType v = -3`; the Writer then emits an explicit `(Type)` cast wherever an
    Object-typed variable is used at a more-specific reference position, so the
    consuming LLM sees the real type at each use (jadx Object+cast).

    `ResourcesCompat.loadFont(...Resources...)` reuses register 8 as both the
    `FontCallback` param and the int `-3` error sentinel merging at a phi-use;
    without the fix it is the misleading `FontCallback v8 = -3`."""
    dk, desc = _find_method("core/content/res/ResourcesCompat", "loadFont")
    if desc is None:
        pytest.skip("ResourcesCompat.loadFont not in the bundled corpus")
    # pick the multi-arg overload (the one with the conflation)
    src = None
    for apk in _apks():
        try:
            d2 = dexllm.DexKit(apk)
        except Exception:
            continue
        for c in d2.list_classes():
            if "core/content/res/ResourcesCompat" not in c:
                continue
            for m in d2.list_class_methods(c):
                if "->loadFont(" in m and "Resources;" in m:
                    o = safe_decompile_method_java(d2, m, timeout=10.0)
                    if o and not is_timeout_marker(o) and "Object v8" in o:
                        src = o
                        break
            if src:
                break
        if src:
            break
    if not src:
        pytest.skip("loadFont conflation overload not found")
    # The conflated register is Object, not the misleading `FontCallback v = -3`.
    assert re.search(r"\bObject v8\b", src), (
        f"the conflated register should be typed `Object`, not a misleading "
        f"specific reference assigned an int.\n{src}"
    )
    assert not re.search(
        r"FontCallback v8\s*=\s*-?\d", src
    ), f"the misleading `FontCallback v8 = <int>` must be gone.\n{src}"
    # No no-op `((Object) ...)` cast was introduced.
    assert "((Object) v8" not in src, f"no-op Object cast on v8.\n{src}"


def test_object_typed_use_gets_explicit_cast():
    """An Object-typed variable used at a more-specific reference invoke
    arg/receiver position gets an explicit `(Type)` cast (LLM type-clarity), and
    never a no-op `((Object) x)` cast. Scans the corpus for the cast form."""
    apks = _apks()
    if not apks:
        pytest.skip("no test APK")
    casts = noop = 0
    for apk in apks:
        try:
            if dexllm.identify(apk).get("dex_count", 0) == 0:
                continue
            dk = dexllm.DexKit(apk)
        except Exception:
            continue
        n = 0
        for c in dk.list_classes():
            if n >= 4000:
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
                # a specific-type cast on a variable/param (the A behaviour)
                casts += len(
                    re.findall(r"\(\([A-Za-z][\w.$]*(?:\.[\w$]+)+\)\s+[vp]\w+\)", out)
                )
                noop += len(re.findall(r"\(\(Object\)\s+[vp]\w+\)\.\w", out))
    # The cast machinery fires broadly (Object-var uses made type-explicit).
    assert casts > 0, "no `(Type) v` casts emitted — the Object-cast pass is off"
    # And the no-op-Object exclusion holds corpus-wide (allow the small
    # pre-existing DAD `((Object) this).wait()` set; assert we did not flood it).
    assert noop <= 15, (
        f"{noop} `((Object) v).m()` no-op casts — the Object→Object exclusion "
        f"regressed."
    )


def test_object_typed_field_access_gets_owner_cast():
    """An Object-typed variable used as the OWNER of a field access (`v.field`
    read or write) gets an explicit `((OwnerClass) v).field` cast, so the LLM
    sees the receiver's real type (Kotlin coroutine state machines reuse a
    register as the Continuation and access `.label` / `.L$0`; DAD leaves the
    uncompilable `Object v; v.label`). Corpus-scan: assert the cast form fires
    and no `Object v; v.<non-Object-field>` receiver survives beyond a small
    residual (field owner unknown / not covered)."""
    apks = _apks()
    if not apks:
        pytest.skip("no test APK")
    _OBJM = {
        "toString",
        "hashCode",
        "equals",
        "getClass",
        "notify",
        "notifyAll",
        "wait",
        "length",
    }
    field_casts = uncast = 0
    for apk in apks:
        try:
            if dexllm.identify(apk).get("dex_count", 0) == 0:
                continue
            dk = dexllm.DexKit(apk)
        except Exception:
            continue
        n = 0
        for c in dk.list_classes():
            if n >= 6000:
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
                # `((Owner) v).field` — a cast immediately owning a field access
                field_casts += len(
                    re.findall(r"\(\([A-Za-z][\w.$]*\)\s+[vp]\w+\)\.[A-Za-z]", out)
                )
                # residual: `Object v` whose name is a bare field/method owner
                for v in set(re.findall(r"\bObject (v\w+)\s*[;=]", out)):
                    for mm in re.finditer(
                        r"(?<![\w.])" + re.escape(v) + r"\.(\w+)", out
                    ):
                        if mm.group(1) not in _OBJM:
                            uncast += 1
    # the owner-cast machinery fires (field-access + receiver casts)
    assert (
        field_casts > 0
    ), "no `((Owner) v).field/method` casts — the owner-cast pass is off"
    # bundled residual `Object v; v.member` is small (field-owner unknown /
    # array positions not yet covered — a later cut). Was ~12 before the field
    # cast; the receiver + field casts cut it to ~1.
    assert uncast <= 5, (
        f"{uncast} `Object v; v.member` uncast receivers — the owner-cast "
        f"regressed (was ~1 after the field-access cast)."
    )


def test_array_used_variable_typed_as_array():
    """A version used as an ARRAY base (`v[i]`, `v.length`, `arr = v`) but typed
    a NON-array (DAD's last-write / a lost move-source array type, e.g. `Object v
    = spanArray` from a Kotlin `getSpans` result) is re-typed to the array type
    recovered from its def — so every array use is valid at once (root-cause,
    vs a per-use `((T[]) v)` cast). `SpannableStringKt.clearSpans` reuses the
    `getSpans()` Object[] result: DAD leaves `Object v; v.length; v[i]`."""
    dk, desc = _find_method("SpannableString", "clearSpans")
    if desc is None:
        # any method that indexes an array-typed local
        pytest.skip("clearSpans not in the bundled corpus")
    src = safe_decompile_method_java(dk, desc, timeout=10.0)
    if is_timeout_marker(src) or not src:
        pytest.skip("clearSpans did not decompile")
    # the array-used local is declared an array type, not bare Object.
    assert re.search(r"\bObject\[\] v\w+\s*=", src) or re.search(
        r"[A-Za-z][\w.$]*\[\] v\w+\s*=.*getSpans", src
    ), f"the getSpans() array result should be an array-typed local.\n{src}"
    # no `Object v; v.length` (array length on a bare Object) survives here.
    for v in set(re.findall(r"\bObject (v\w+)\s*[;=]", src)):
        assert not re.search(
            r"(?<![\w.])" + re.escape(v) + r"\.length\b", src
        ), f"{v} is array-length-used but typed bare Object.\n{src}"


def test_array_used_not_typed_object_bounded():
    """Corpus-wide: an `Object v` (or other non-array) used as `v[i]` / `v.length`
    should be rare — the array-use-driven typing re-types the recoverable ones.
    Bounds the residual (circular-move / genuine array+non-array conflations that
    resolve_array_type conservatively skips)."""
    apks = _apks()
    if not apks:
        pytest.skip("no test APK")
    bad = 0
    for apk in apks:
        try:
            if dexllm.identify(apk).get("dex_count", 0) == 0:
                continue
            dk = dexllm.DexKit(apk)
        except Exception:
            continue
        n = 0
        for c in dk.list_classes():
            if n >= 6000:
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
                for v in set(re.findall(r"\bObject (v\w+)\s*[;=]", out)):
                    if re.search(r"(?<![\w.])" + re.escape(v) + r"\[", out):
                        bad += 1
    assert bad <= 4, (
        f"{bad} `Object v; v[i]` array-index-on-Object (was ~2; a jump means "
        f"the array-use-driven typing regressed)."
    )


def test_reftype_eq_nonzero_int_bounded_mixed_version():
    """A genuine ref+nonzero-int conflation among a MULTI-version register (a
    register split into a clean reference version AND a conflated version, e.g.
    `zzj v1 = 1` beside a real `zzj v4`) is typed `Object` in the rename loop —
    the size==1 pre-pass only covers the unsplit case. Bounds the corpus-wide
    `RefType v = <nonzero int>` residual (was ~5 before the mixed-version cut)."""
    apks = _apks()
    if not apks:
        pytest.skip("no test APK")
    _P = (
        "int",
        "boolean",
        "byte",
        "short",
        "char",
        "long",
        "float",
        "double",
        "void",
        "Object",
    )
    _RX = re.compile(
        r"^\s*(?!(?:" + "|".join(_P) + r")\b)(?:\[+)?[A-Za-z_][\w.$]*"
        r"(?:\[\])*\s+v\w+\s*=\s*-?[1-9]\d*\s*;",
        re.M,
    )
    bad = 0
    for apk in apks:
        try:
            if dexllm.identify(apk).get("dex_count", 0) == 0:
                continue
            dk = dexllm.DexKit(apk)
        except Exception:
            continue
        n = 0
        for c in dk.list_classes():
            if n >= 6000:
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
                bad += len(_RX.findall(out))
    # ~3 residual (circular-move conflations region_of can't resolve without
    # gt-style transitive resolution). A jump means the mixed-version Object
    # typing regressed.
    assert bad <= 6, (
        f"{bad} `RefType v = <nonzero int>` misleading conflations (was ~3 "
        f"after the mixed-version Object typing)."
    )
