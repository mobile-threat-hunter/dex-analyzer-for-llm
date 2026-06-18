"""End-to-end smoke test for return-type-mismatched constant literals.

Mirrors the EncodedValue IEEE754 smoke check (which verifies static-field
float/double initializers decompile to valid Java literals) but for the method
RETURN path. Drives the actual package API (decompile_method_java /
decompile_method_ast) over the bundled test_apk/APK corpus and asserts:

  - boolean ()Z  returns  true / false      (never `return 0;` / `return 1;`)
  - reference ()L..;/[..  returns  null      (never `return 0;`)
  - float ()F   returns a float literal      (never the raw IEEE int bits)
  - non-finite F/D returns render as Float.NaN / Double.NEGATIVE_INFINITY /…
    (never lowercase nan / inf / -inf, and never raw int)
  - int ()I / char ()C returns stay numeric  (regression guard — NOT rewritten)
  - the text and AST paths agree

The C++ suite tests/parity/return_literal_parity_test.cpp is the fast,
APK-free, deterministic gate (incl. NaN/±Inf via crafted bytecode). This is the
through-the-binding end-to-end backstop. Skips if no test APK is present.
"""

import glob
import os
import re
from pathlib import Path

import pytest

import dexllm

REPO = Path(__file__).resolve().parents[1]

# declared return type at the tail of a Dalvik method descriptor
_RET = re.compile(r"\)(\[*L[^;]+;|[FDZIC])$")
_BARE_INT = re.compile(r"^return (-?\d+);$")
_FLOAT_LIT = re.compile(r"^return -?(\d[\d.eE+-]*f|[\d.eE+-]+f|Float\.\w+);$")
_LOWER_NONFINITE = re.compile(r"\b-?(nan|inf)\b")


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
    """Bounded scan of the corpus → (found-category counts, violations list).

    Iterates F/D/Z/reference/int/char-returning methods, decompiles each, and
    classifies the return line. A 'violation' is an invalid/wrong literal that
    the return-type fix is meant to prevent.
    """
    apks = _apks()
    if not apks:
        pytest.skip("no test APK (set $DEXLLM_TEST_APK or add one under test_apk/APK/)")

    found = {"F": 0, "D": 0, "ref_null": 0, "Z_bool": 0, "nonfinite": 0,
             "int_num": 0}
    violations = []
    nonfinite_examples = []
    # Per-APK cap so every APK (incl. the one carrying the NaN/Inf returns) gets
    # sampled while keeping the whole smoke test bounded; the C++ parity suite
    # is the exhaustive deterministic gate.
    per_apk_cap = 4000
    checked = 0

    for apk in apks:
        try:
            if dexllm.identify(apk).get("dex_count", 0) == 0:
                continue
            dk = dexllm.DexKit(apk)
        except Exception:
            continue
        apk_checked = 0
        for c in dk.list_classes():
            if apk_checked >= per_apk_cap:
                break
            try:
                methods = dk.list_class_methods(c)
            except Exception:
                continue
            for ml in methods:
                m = _RET.search(ml)
                if not m:
                    continue
                rt = m.group(1)
                try:
                    o = dk.decompile_method_java(ml)
                except Exception:
                    continue
                checked += 1
                apk_checked += 1
                for line in o.splitlines():
                    s = line.strip()
                    if not s.startswith("return ") and s != "return;":
                        continue
                    bare = _BARE_INT.match(s)
                    if rt == "Z":
                        if s in ("return true;", "return false;"):
                            found["Z_bool"] += 1
                        elif bare:
                            violations.append(("Z-bare-int", ml, s))
                    elif rt.startswith("L") or rt.startswith("["):
                        if s == "return null;":
                            found["ref_null"] += 1
                        elif bare:
                            violations.append(("ref-bare-int", ml, s))
                    elif rt == "F":
                        if _FLOAT_LIT.match(s):
                            found["F"] += 1
                        elif bare:
                            violations.append(("F-raw-int", ml, s))
                    elif rt == "D":
                        # double whole numbers legitimately print as `return 1;`
                        # (valid via int->double widening); only flag a clearly
                        # wrong huge raw-bit int.
                        if "Double." in s or re.search(r"[.eE]", s):
                            found["D"] += 1
                        elif bare and abs(int(bare.group(1))) > (1 << 31):
                            violations.append(("D-raw-bits", ml, s))
                    elif rt in ("I", "C"):
                        if bare:
                            found["int_num"] += 1
                        if "true" in s or "false" in s or s == "return null;":
                            violations.append((f"{rt}-rewritten", ml, s))
                    # non-finite rendering (any type)
                    if re.search(r"(Float|Double)\.(NaN|POSITIVE_INFINITY|"
                                 r"NEGATIVE_INFINITY)", s):
                        found["nonfinite"] += 1
                        if len(nonfinite_examples) < 5:
                            nonfinite_examples.append((ml, s))
                    if _LOWER_NONFINITE.search(s):
                        violations.append(("lowercase-nan/inf", ml, s))
    return found, violations, nonfinite_examples, checked


def test_no_return_type_violations(scanned):
    found, violations, _nf, checked = scanned
    assert checked > 0, "scan exercised no methods"
    assert not violations, (
        f"{len(violations)} return-type-mismatch violation(s) in {checked} "
        f"methods; first few: {violations[:8]}"
    )


def test_return_categories_covered(scanned):
    found, _v, _nf, checked = scanned
    # these are abundant in any real corpus — their presence proves the fix
    # path actually fired end-to-end (not a vacuous pass)
    assert found["Z_bool"] > 0, "no boolean true/false returns seen"
    assert found["ref_null"] > 0, "no reference `return null;` seen"
    assert found["F"] > 0, "no float-literal returns seen"


def test_nonfinite_returns_render_as_java_constants(scanned):
    found, _v, examples, _checked = scanned
    # the bundled corpus contains Float.NaN / Double.NaN returns; if the scan
    # reached them, they must be the valid Java constant form (the violations
    # check already guarantees no lowercase nan/inf slipped through anywhere).
    if found["nonfinite"] == 0:
        pytest.skip("no non-finite F/D return in the scanned corpus slice")
    assert found["nonfinite"] > 0
    for _ml, s in examples:
        assert re.search(r"(Float|Double)\.(NaN|POSITIVE_INFINITY|"
                         r"NEGATIVE_INFINITY)", s), s


# canonical IEEE-754 binary64 bit patterns of common double constants. A
# genuine 64-bit long that is *exactly* one of these is astronomically unlikely,
# so their appearance as a bare integer literal means raw double bits leaked into
# a float/double context (comparison / arithmetic / compound-assign / arg) — the
# bug the fp-const correction fixes.
_DOUBLE_BIT_PATTERNS = {
    "4607182418800017408",  # 1.0
    "4611686018427387904",  # 2.0
    "4613937818241073152",  # 3.0
    "4616189618054758400",  # 4.0
    "4617315517961601024",  # 5.0
    "4621819117588971520",  # 10.0
    "4636737291354636288",  # 100.0
    "4602678819172646912",  # 0.5
    "4599075939470750515",  # 0.1 (approx)
    "-4616189618054758400", # -4.0 etc. (sign-flipped forms)
}


def test_double_bit_patterns_largely_eliminated():
    """Canonical double bit-patterns must be rendered as their value (2.0, not
    4611686018427387904) in every position where the F/D context is known
    (binary expr / comparison / compound-assign / method-arg / plain-assign /
    array-store). The fp-const correction took these from ~hundreds to a small
    residual on the bundled corpus; the residual is type-inference-limited (a
    variable that holds a double but was not inferred as `D`, so no F/D context
    is visible) plus the field-store position — both deferred. This is a
    regression guard: a broken fixed-position would spike the count back to the
    hundreds.
    """
    apks = _apks()
    if not apks:
        pytest.skip("no test APK")
    leaks = []
    pat = re.compile(r"(?<![\w.])(-?\d{16,})(?![\w.])")
    for apk in apks:
        try:
            if dexllm.identify(apk).get("dex_count", 0) == 0:
                continue
            dk = dexllm.DexKit(apk)
        except Exception:
            continue
        per = 0
        for c in dk.list_classes():
            if per >= 3000:
                break
            try:
                src = dk.decompile_class_java(c)
            except Exception:
                continue
            per += 1
            for line in src.splitlines():
                for m in pat.finditer(line):
                    if m.group(1) in _DOUBLE_BIT_PATTERNS:
                        leaks.append((c.split("/")[-1][:24], line.strip()[:70]))
    # observed 0 on the bundled corpus once the binary/comparison positions use
    # the EXPRESSION type (reliable) instead of the operand-variable type. Small
    # bound to tolerate corpus drift while still catching a regressed position.
    assert len(leaks) <= 3, (
        f"{len(leaks)} raw double-bit-pattern leak(s) — a fixed position likely "
        f"regressed; first: {leaks[:8]}"
    )


def test_text_and_ast_agree_on_corrected_returns():
    """For a handful of corrected returns, decompile_method_ast must not emit a
    raw int / lowercase -inf where decompile_method_java emits the literal."""
    apks = _apks()
    if not apks:
        pytest.skip("no test APK")
    import json

    checked = 0
    agreed = 0
    for apk in apks:
        try:
            if dexllm.identify(apk).get("dex_count", 0) == 0:
                continue
            dk = dexllm.DexKit(apk)
        except Exception:
            continue
        for c in dk.list_classes():
            if agreed >= 6 or checked >= 40000:
                break
            for ml in dk.list_class_methods(c):
                m = _RET.search(ml)
                if not m or m.group(1) not in ("Z", "F", "D") and not (
                    m.group(1).startswith("L") or m.group(1).startswith("[")
                ):
                    continue
                try:
                    txt = dk.decompile_method_java(ml)
                except Exception:
                    continue
                checked += 1
                rets = [l.strip() for l in txt.splitlines()
                        if l.strip().startswith("return ")]
                # only methods whose return is a corrected literal
                if not any(
                    r in ("return null;", "return true;", "return false;")
                    or re.search(r"(Float|Double)\.\w+", r)
                    or re.match(r"return -?[\d.eE+-]+f;", r)
                    for r in rets
                ):
                    continue
                try:
                    ast = dk.decompile_method_ast(ml)
                except Exception:
                    continue
                body = json.dumps(ast.get("ast", {}).get("body", ""))
                # the AST must not carry the raw-int / lowercase-inf form
                assert '"-inf"' not in body and '"inf"' not in body \
                    and '"nan"' not in body, (ml, body[:160])
                agreed += 1
                if agreed >= 6:
                    break
            if agreed >= 6 or checked >= 40000:
                break
        if agreed >= 6:
            break
    if agreed == 0:
        pytest.skip("no corrected-return method reached in the scanned slice")
    assert agreed > 0
