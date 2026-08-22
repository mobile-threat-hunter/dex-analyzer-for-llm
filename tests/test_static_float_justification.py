"""A static float/double initializer is zero-extended to the RIGHT (dexllm#70).

`DecodeEncodedValueText` — the decoder behind `decompile_class`'s static-field
initializers — filled a `VALUE_FLOAT` / `VALUE_DOUBLE` payload from the LSB end.
The dex spec says the stored bytes are the MOST significant ones ("zero-extended
to the right") and ART reads them that way
(`ReadUnsignedInt(..., fill_on_right = true)`), so every SHORT encoding rendered
as a denormal: `AutoScrollHelper.DEFAULT_RELATIVE_VELOCITY` read
`2.27795078e-41f` where AOSP declares `1f`, and Kotlin's `FloatCompanionObject`
field literally NAMED `NaN` rendered a finite `4.5828065e-41f`.

**Why it survived:** a FULL-WIDTH encoding is exactly where the two readings
agree, and every pre-existing float/double assertion in the suite uses one. So
each craft here SHORTENS, and `test_a_full_width_float_still_renders` pins the
half that did not move — it is non-discriminating BY DESIGN and says so.

The crafts run on the committed `tests/data/invoke-custom.dex`: no corpus,
narrowing-proof. The corpus tests below carry real-world EVIDENCE — that the
bundled AOSP support library and Kotlin runtime really are affected — rather
than reachability; every rendering branch is reachable from the fixture, and an
adversarial reviewer had to show that, because the first cut of this file used a
one-byte craft everywhere and left the non-finite branches to the corpus alone.
"""

from __future__ import annotations

import math
import pathlib
import struct

import pytest
from conftest import REPO_ROOT, corpus_is_narrowed, require_corpus_shape

_CUSTOM = REPO_ROOT / "tests" / "data" / "invoke-custom.dex"

# `LTestLinkerMethodMinimalArguments`'s static_values: four one-byte INT (0x04)
# elements, values 1 / 2 / 0 / 3, in the eight bytes 29641..29648.  Every craft
# below re-lays THOSE EIGHT BYTES and nothing else — a payload of N bytes takes
# 1 + N, so the array's count drops to 1 + (7 - N) // 2 and the surviving INTs
# follow it; the leftover byte or two are simply never read.  No offset, no
# section size and no neighbouring structure moves.
#
# The surviving INTs are a DESYNC oracle: a decoder that consumes a fixed 4 or 8
# bytes for a short payload walks into them and their values shift.
_FIXTURE_CLASS = "LTestLinkerMethodMinimalArguments;"
_EL0_COUNT_OFF = 29640
_EL0_HEADER_OFF = 29641
_EL0_PAYLOAD_OFF = 29642
_ARRAY_BYTES = 8
_TAIL_VALUES = (2, 0, 3)


def _decl_lines(src: str) -> list[str]:
    return [
        ln.strip()
        for ln in src.splitlines()
        if ln.strip().startswith("static final") and " = " in ln
    ]


def _craft(tmp_path, value_type: int, payload: bytes, stem: str) -> pathlib.Path:
    """Retype element [0] to `value_type` with `payload`, LENGTH-PRESERVING.

    See the layout note above: the array's own eight bytes are re-laid, so the
    craft is a pure in-place edit however wide the payload is.
    """
    n = len(payload)
    assert 1 <= n <= 4, n
    survivors = (_ARRAY_BYTES - (1 + n)) // 2
    raw = bytearray(_CUSTOM.read_bytes())
    assert raw[_EL0_COUNT_OFF] == 0x04, hex(raw[_EL0_COUNT_OFF])
    assert raw[_EL0_HEADER_OFF] == 0x04, hex(raw[_EL0_HEADER_OFF])
    raw[_EL0_COUNT_OFF] = 1 + survivors
    raw[_EL0_HEADER_OFF] = value_type | ((n - 1) << 5)
    off = _EL0_PAYLOAD_OFF
    raw[off : off + n] = payload
    off += n
    for value in _TAIL_VALUES[:survivors]:
        raw[off] = 0x04  # INT, value_arg 0
        raw[off + 1] = value
        off += 2
    assert off <= _EL0_PAYLOAD_OFF + _ARRAY_BYTES - 1, off
    out = tmp_path / f"{stem}.dex"
    out.write_bytes(bytes(raw))
    return out


def _crafted_decls(tmp_path, value_type, payload, stem):
    dexllm = pytest.importorskip("dexllm")
    out = _craft(tmp_path, value_type, payload, stem)
    # The craft must still LOAD, or a rejection would be doing the asserting.
    assert dexllm.verify(str(out))[0]["valid"], dexllm.verify(str(out))
    dk = dexllm.DexKit(str(out))
    return _decl_lines(dk.decompile_class(_FIXTURE_CLASS))


# Every width at which the shift differs, and every RENDERING branch reachable
# from the fixture's array.  ONE byte alone is not enough: the fix IS the
# width-dependence (`raw << (8 * (4 - nbytes))`), and at n == 1 that exponent is
# the constant 24, so a decoder that HARDCODES the shift renders every one-byte
# case correctly.  A correctness reviewer built exactly that mutant and it passed
# the whole file in the corpus-less leg, where the crafts are the only cases that
# run.  The two- and three-byte rows are what kill it — and two of them
# reproduce, on a committed fixture, real AOSP constants the corpus manifests
# (`1f` from `80 3f`, `100` from `59 40`).
#
# `wrong` is what a PLAUSIBLE wrong implementation renders and must be absent:
# usually the left-justified denormal, and for the last row also the
# over-precise format (see its comment).
_SHORT_CASES = [
    pytest.param(0x10, b"\x3f", "0.5f", ("8.82818033e-44f",), id="float-1byte"),
    pytest.param(0x10, b"\x80\x3f", "1f", ("2.27795078e-41f",), id="float-2byte"),
    pytest.param(0x10, b"\x00\x80\x3f", "1f", ("5.83155401e-39f",), id="float-3byte"),
    pytest.param(
        0x11,
        b"\x3f",
        "3.0517578125e-05",
        ("3.1126135687998532e-322",),
        id="double-1byte",
    ),
    pytest.param(
        0x11, b"\x59\x40", "100", ("8.1387433839428543e-320",), id="double-2byte"
    ),
    pytest.param(
        0x11,
        b"\x00\x59\x40",
        "100",
        ("2.0835183062893707e-317",),
        id="double-3byte",
    ),
    # The three non-finite branches per type.  They are only REACHED once the
    # bits are read correctly — which is the change's own headline case, a field
    # literally named `NaN` that rendered a finite denormal — yet an adversarial
    # reviewer built each branch's deletion and all three survived the
    # corpus-less leg, because every finite craft above is blind to them.  These
    # payloads are the Kotlin companion objects' OWN bytes, so the fixture now
    # carries the real-world case and the corpus test below carries only the
    # real-world EVIDENCE.  One byte genuinely cannot encode a non-finite value
    # (`7f` is 0x7F000000, a large finite number, not 0x7F800000); two can.
    pytest.param(0x10, b"\xc0\x7f", "Float.NaN", ("4.5828065e-41f",), id="float-nan"),
    pytest.param(
        0x10,
        b"\x80\x7f",
        "Float.POSITIVE_INFINITY",
        ("4.57383819e-41f",),
        id="float-posinf",
    ),
    pytest.param(
        0x10,
        b"\x80\xff",
        "Float.NEGATIVE_INFINITY",
        ("9.165613e-41f",),
        id="float-neginf",
    ),
    pytest.param(
        0x11,
        b"\xf8\x7f",
        "Double.NaN",
        ("1.6185590557759237e-319",),
        id="double-nan",
    ),
    pytest.param(
        0x11,
        b"\xf0\x7f",
        "Double.POSITIVE_INFINITY",
        ("1.6181638032592507e-319",),
        id="double-posinf",
    ),
    pytest.param(
        0x11,
        b"\xf0\xff",
        "Double.NEGATIVE_INFINITY",
        ("3.2371181115518474e-319",),
        id="double-neginf",
    ),
    # The float arm's `%.9gf` is the OTHER load-bearing half of that line and was
    # guarded by nothing: an adversarial reviewer widened it to `%.17gf` and the
    # WHOLE suite still passed, because every literal pinned above is exactly
    # representable and a short encoding puts few significant bits in the top
    # bytes, so the corpus population is biased the same way.  (The double arm was
    # already covered — `double-1byte` needs the wider format.)  This value is
    # not exactly representable, so it separates the two formats.
    pytest.param(
        0x10,
        b"\xcd\x4c\x3e",
        "0.200000763f",
        ("5.72135169e-39f", "0.20000076293945312f"),
        id="float-round-trip-format",
    ),
]


@pytest.mark.parametrize("value_type,payload,correct,wrong", _SHORT_CASES)
def test_a_short_encoded_static_value_is_zero_extended_to_the_right(
    tmp_path, value_type, payload, correct, wrong
) -> None:
    """The stored bytes are the TOP ones, so `80 3f` is 1.0f — not a denormal.

    The field's declared type is left as `int` on purpose: the decoder under
    test never consults it (it dispatches on the encoded_value type code), so
    retyping the `field_id` would change nothing here and would perturb every
    other reference to that field.
    """
    stem = f"short{value_type:02x}x{payload.hex()}"
    decls = _crafted_decls(tmp_path, value_type, payload, stem)
    rendered = [d for d in decls if "RETURNS_NULL" in d]
    assert rendered, decls
    assert f"= {correct};" in rendered[0], rendered[0]
    joined = "\n".join(decls)
    for bad in wrong:
        assert bad not in joined, (bad, decls)


@pytest.mark.parametrize("value_type,payload,correct,wrong", _SHORT_CASES)
def test_a_short_encoded_value_consumes_only_its_declared_payload(
    tmp_path, value_type, payload, correct, wrong
) -> None:
    """The INT values AFTER the craft must be untouched.

    A decoder reading a fixed 4 or 8 bytes for a short payload walks into the
    following elements and the array's remaining values shift — the desync class
    dexllm#63 fixed for the two unimplemented type codes.  Nothing else in this
    file would see it: the crafted element renders correctly either way.
    """
    del correct, wrong
    stem = f"desync{value_type:02x}x{payload.hex()}"
    decls = _crafted_decls(tmp_path, value_type, payload, stem)
    survivors = (_ARRAY_BYTES - (1 + len(payload))) // 2
    tail = [d.split(" = ")[1].rstrip(";") for d in decls if "RETURNS_NULL" not in d]
    assert tuple(tail) == tuple(str(v) for v in _TAIL_VALUES[:survivors]), decls


def test_a_full_width_float_still_renders(tmp_path) -> None:
    """Non-discriminating BY DESIGN — it pins the half that did NOT move.

    A four-byte payload is where the left- and right-justified readings agree,
    which is why this rule went wrong unnoticed: it is the shape every existing
    float assertion in the suite uses.  Kept so a fix that over-shifts a
    full-width value fails here rather than only on the corpus.

    There is no full-width DOUBLE twin: nine bytes do not fit in the array's
    eight.  Lengthening it would push past 29649, which is where this fixture's
    `call_site_id[0]` target begins — all 46 invoke-custom bootstrap arrays live
    in 29649..30255, i.e. exactly the bytes dexllm#67 reads.  So width 8 is
    reachable only through the corpus oracle below, and the double helper's
    `nbytes >= 8` fast path is invisible to the corpus-less leg; closing that
    needs a fixture class with a larger `static_values` array.
    """
    decls = _crafted_decls(tmp_path, 0x10, struct.pack("<f", 12.5), "fullwidth")
    assert any(d.endswith("= 12.5f;") for d in decls), decls
    # A five-byte read would swallow the INT that follows.
    assert any(d.endswith("= 2;") for d in decls), decls


# -- corpus evidence the crafts structurally cannot carry ---------------------


def _corpus_short_values(dexllm, apks):
    """Every SHORT-encoded float/double static value, read from the dex BYTES.

    An independent parser: it walks `class_defs` -> `static_values` itself and
    never asks the decoder under test what a payload means.

    The nested ARRAY (0x1c) / ANNOTATION (0x1d) branches are spec-correct but
    INERT on this corpus — measured 0 nested values across all 42 sources — so a
    bug in them would undercount silently rather than fail.
    """

    def u4(b, o):
        return struct.unpack_from("<I", b, o)[0]

    def uleb(b, o):
        r = s = 0
        while True:
            x = b[o]
            o += 1
            r |= (x & 0x7F) << s
            if not x & 0x80:
                return r, o
            s += 7

    def walk(b, o, n, out):
        for _ in range(n):
            h = b[o]
            o += 1
            vt, va = h & 0x1F, (h >> 5) & 7
            if vt == 0x1C:  # ARRAY
                cnt, o = uleb(b, o)
                o = walk(b, o, cnt, out)
            elif vt == 0x1D:  # ANNOTATION
                _t, o = uleb(b, o)
                cnt, o = uleb(b, o)
                for _ in range(cnt):
                    _n, o = uleb(b, o)
                    o = walk(b, o, 1, out)
            elif vt in (0x1E, 0x1F):  # NULL / BOOLEAN — no payload
                out.append((vt, b""))
            else:
                out.append((vt, bytes(b[o : o + va + 1])))
                o += va + 1
        return o

    found = []
    for apk in apks:
        try:
            dk = dexllm.DexKit(str(apk))
        except Exception:  # pragma: no cover - resources-only containers
            continue
        for did in range(dk.dex_count()):
            b = dk.extract_dex(did)["bytes"]
            if not b or b[:4] != b"dex\n":
                continue
            ncd, ocd, otid, osid = u4(b, 96), u4(b, 100), u4(b, 68), u4(b, 60)

            def type_name(i):
                so = u4(b, osid + 4 * u4(b, otid + 4 * i))
                _, so = uleb(b, so)
                return b[so : b.index(b"\0", so)].decode("utf-8", "replace")

            for i in range(ncd):
                cd = ocd + 32 * i
                sv = u4(b, cd + 28)
                if sv == 0:
                    continue
                cnt, o = uleb(b, sv)
                leaves: list = []
                try:
                    walk(b, o, cnt, leaves)
                except Exception:  # pragma: no cover - malformed sample
                    continue
                for vt, pay in leaves:
                    width = 4 if vt == 0x10 else 8
                    if vt in (0x10, 0x11) and len(pay) < width:
                        found.append((dk, type_name(u4(b, cd)), vt, pay))
    return found


def _render(vt: int, pay: bytes, *, justify: str) -> str:
    width = 4 if vt == 0x10 else 8
    bits = (
        int.from_bytes(pay.ljust(width, b"\0"), "little")
        if justify == "left"
        else int.from_bytes(pay, "little") << (8 * (width - len(pay)))
    )
    fmt, pack, suffix = ("<f", "<I", "f") if vt == 0x10 else ("<d", "<Q", "")
    value = struct.unpack(fmt, struct.pack(pack, bits))[0]
    name = "Float" if vt == 0x10 else "Double"
    if math.isnan(value):
        return f"{name}.NaN"
    if math.isinf(value):
        return f"{name}.{'POSITIVE' if value > 0 else 'NEGATIVE'}_INFINITY"
    return (f"{value:.9g}{suffix}") if vt == 0x10 else f"{value:.17g}"


def test_every_short_encoded_corpus_value_matches_the_byte_level_oracle(
    loadable_apks,
) -> None:
    """The rendered constant equals the RIGHT-justified reading of its bytes.

    A property over the whole corpus rather than a fixture: 332 of the bundled
    corpus's 382 short-encoded float/double statics read differently under the
    two rules (the other 50 encode zero, which reads alike either way).  It is
    also the only place width 8 is exercised — a full-width double does not fit
    in the fixture's array.

    The `stale` half is the DISCRIMINATING one: `checked` matches per CLASS
    rather than per FIELD, so a same-valued sibling field can satisfy it, while
    the denormal string must be absent from the class outright.
    """
    dexllm = pytest.importorskip("dexllm")
    values = _corpus_short_values(dexllm, loadable_apks)
    differing = [
        (dk, cls, vt, pay)
        for dk, cls, vt, pay in values
        if _render(vt, pay, justify="left") != _render(vt, pay, justify="right")
    ]
    require_corpus_shape(
        bool(differing),
        "a short-encoded float/double static value whose two readings differ",
        "the corpus carries 332 — a count of 0 means the scan stopped working",
    )
    stale = []
    checked = 0
    for dk, cls, vt, pay in differing:
        src = dk.decompile_class(cls) or ""
        want = _render(vt, pay, justify="right")
        wrong = _render(vt, pay, justify="left")
        if f"= {want};" in src:
            checked += 1
        if f"= {wrong};" in src:
            stale.append((cls, pay.hex(), wrong))
    assert not stale, stale[:5]
    assert checked == len(differing), (checked, len(differing))
    if not corpus_is_narrowed():
        # `checked == len(differing)` is trivially true for a scan that collapsed
        # to one value, so the un-narrowed corpus states a floor as well.  313 is
        # what the 25 bundled APKs carry (332 counting the bare `.dex` files this
        # fixture does not reach); 50 tolerates corpus churn, not a broken walk.
        assert len(differing) >= 50, len(differing)


def test_a_constant_named_nan_is_not_a_finite_denormal(loadable_apks) -> None:
    """The sharpest single case, and unreachable from a one-byte craft.

    Kotlin's `FloatCompanionObject` / `DoubleCompanionObject` store NaN and
    +-Infinity SHORT (`c0 7f`, `f0 ff`, ...), so under the old rule a field
    named `NaN` rendered a finite `4.5828065e-41f` — output that refutes itself.

    The BRANCH is pinned by the six non-finite crafts above, which use these very
    bytes; what this adds is that a real shipped library carries them, which no
    craft can say.  It rides the corpus and skips without it.
    """
    dexllm = pytest.importorskip("dexllm")
    seen = []
    for apk in loadable_apks:
        try:
            dk = dexllm.DexKit(str(apk))
        except Exception:  # pragma: no cover
            continue
        for cls in (
            "Lkotlin/jvm/internal/FloatCompanionObject;",
            "Lkotlin/jvm/internal/DoubleCompanionObject;",
        ):
            if dk.locate_class_dex(cls) < 0:
                continue
            src = dk.decompile_class(cls) or ""
            name = "Float" if "Float" in cls else "Double"
            for field, literal in (
                ("NaN", f"{name}.NaN"),
                ("POSITIVE_INFINITY", f"{name}.POSITIVE_INFINITY"),
                ("NEGATIVE_INFINITY", f"{name}.NEGATIVE_INFINITY"),
            ):
                line = next(
                    (
                        ln.strip()
                        for ln in src.splitlines()
                        if f" {field} = " in ln and ln.strip().endswith(";")
                    ),
                    None,
                )
                if line is None:
                    continue
                seen.append(line)
                assert line.endswith(f"= {literal};"), line
    require_corpus_shape(
        bool(seen),
        "kotlin's Float/DoubleCompanionObject",
        "the bundled corpus carries both — 0 means the class lookup stopped working",
    )


# -- the rule lives in ONE place ---------------------------------------------


_DECODER = REPO_ROOT / "native" / "core_ext" / "dexitem_code_source.cpp"


@pytest.mark.parametrize(
    "case,helper",
    [
        pytest.param("0x10", "DecodeEncodedFloat", id="float"),
        pytest.param("0x11", "DecodeEncodedDouble", id="double"),
    ],
)
def test_the_static_value_decoder_shares_one_justification_rule(case, helper) -> None:
    """`DecodeEncodedValueText` must CALL the shared helper, not re-read the rule.

    dexllm#70's own scope note: this file holds one of FOUR encoded_value
    decoders, and the fix is to share dexllm#67's helper rather than to add a
    fifth reading of the same spec sentence.  A duplicated-but-currently-correct
    body passes every behavioural test here and drifts on the first edit — the
    shape the `_callers.py` identity guard pins for the app-only prefix list.
    """
    body = _decoder_case_body(case)
    assert f"{helper}(" in body, body


def _decoder_case_body(case: str) -> str:
    """The `case <code>:` arm of `DecodeEncodedValueText`, comments stripped.

    Comment stripping is not decoration: this repo has twice had a source-level
    guard satisfied by a COMMENTED-OUT line (dexllm#32, dexllm#57).
    """
    text = _strip_comments(_DECODER.read_text())
    start = text.index("std::string DecodeEncodedValueText(")
    end = text.index("\n}\n", start)
    fn = text[start:end]
    arm = fn.index(f"case {case}: {{")
    nxt = fn.find("case 0x", arm + 8)
    return fn[arm : nxt if nxt != -1 else len(fn)]


def _strip_comments(text: str) -> str:
    """Left-to-right scanner — a regex pass for `/* */` swallows `// a/* b`."""
    out = []
    i, n = 0, len(text)
    in_line = in_block = in_str = False
    while i < n:
        c = text[i]
        two = text[i : i + 2]
        if in_line:
            if c == "\n":
                in_line = False
                out.append(c)
            i += 1
        elif in_block:
            if two == "*/":
                in_block = False
                i += 2
            else:
                if c == "\n":
                    out.append(c)
                i += 1
        elif in_str:
            out.append(c)
            if c == "\\":
                out.append(text[i + 1 : i + 2])
                i += 2
                continue
            if c == '"':
                in_str = False
            i += 1
        elif two == "//":
            in_line = True
            i += 2
        elif two == "/*":
            in_block = True
            i += 2
        else:
            if c == '"':
                in_str = True
            out.append(c)
            i += 1
    return "".join(out)


def test_the_comment_stripper_does_not_swallow_the_file() -> None:
    """Self-check: the scanner must survive this file's own `//` + `/*` mix."""
    stripped = _strip_comments("int a; // x /* y\nint b; /* z */ int c;\n")
    assert "int a;" in stripped and "int b;" in stripped and "int c;" in stripped
    assert "x" not in stripped and "z" not in stripped
