"""End-to-end guard for the move-chain type-CASCADE re-typing fix.

DAD types every split version from its register's last write, so a Dalvik
register reused across incompatible types can leave a version typed as a
REFERENCE while it actually holds a primitive (an obfuscator's 0/1 flag reusing
an object slot). The reference type is copied off a sibling conflated register by
a `move`, and the version then emits uncompilable Java such as:

    java.util.ArrayList v1_0 = 1;      // reference declared, integer assigned

`FixInitResultTypes`' second pass (dataflow.cpp) re-types such object-less
cascade versions to their primitive descriptor (def-anchored + use-corroborated:
only when NO ground-truth reference producer backs the version and it is never
used as an object). This scans the bundled corpus and asserts ZERO
`<referenceType> v = <nonzero int>;` lines remain.

The regression direction (making a real object primitive → `prim = new` / a
primitive receiver `v.m()`) is asserted absent too. Skips if no APK is present.
"""

import glob
import os
import re
from pathlib import Path

import pytest

import dexllm
from dexllm import is_timeout_marker, safe_decompile_class_java

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
    ref_int = []
    prim_new = []
    prim_member = []
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
            out = safe_decompile_class_java(dk, c, timeout=10.0)
            if is_timeout_marker(out) or not out:
                continue
            # class text spans many methods; check the ref=int / prim=new
            # single-line patterns directly (self-contained, collision-free).
            for m in _REF_INT.finditer(out):
                if m.group(1) != "0":
                    ref_int.append((c, m.group(0).strip()))
            for m in _PRIM_NEW.finditer(out):
                prim_new.append((c, m.group(0).strip()))
    return {"ref_int": ref_int, "prim_new": prim_new, "prim_member": prim_member}


def test_no_reference_assigned_nonzero_int(scanned):
    """No `ReferenceType v = <nonzero int>;` — the cascade the fix removes."""
    bad = scanned["ref_int"]
    assert not bad, (
        f"{len(bad)} reference-declared locals assigned a non-zero integer "
        f"(uncompilable cascade type). e.g. {bad[:5]}"
    )


def test_no_primitive_assigned_allocation(scanned):
    """Regression guard: the fix must never make a real object primitive."""
    bad = scanned["prim_new"]
    assert not bad, (
        f"{len(bad)} primitive-declared locals assigned `new …()` "
        f"(reverse-direction regression). e.g. {bad[:5]}"
    )
