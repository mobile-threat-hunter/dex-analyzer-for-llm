"""dexllm#71 - the gate's index promise holds only in LOCKSTEP, so bound at the reader.

`DecodeEncodedValueText` (`native/core_ext/dexitem_code_source.cpp`) renders
static-field initializers for `decompile_class`. Its `0x17 STRING` /
`0x18 TYPE` / `0x19 FIELD` / `0x1b ENUM` arms indexed `strings[idx]` /
`type_names[idx]` / `field_ids[idx]` with an UNBOUNDED subscript, justified in
the source by "idx validated in-range by VerifyEncodedValue".

That promise is real, and it is about the value at a given OFFSET. It holds only
while the decoder walks the `encoded_array` in lockstep with the gate - same
element boundaries, same consumed widths. A decoder that consumes the wrong
number of bytes for any element reads DIFFERENT bytes for every element after
it, and the index it then extracts was validated by nothing.

**Measured, not argued.** dexllm#70's over-consume mutants SIGSEGV in
`decompile_class` on ordinary, well-formed corpus APKs, and the SAME mutant with
these four bounds added gives 0 signals. So dexllm#63's recorded conclusion for
this function - "wrong-answer only" - was not merely incomplete, it was wrong: a
desync here is a crash surface.

**Not reachable on the shipped code**, which is why this file exists in two
layers rather than one:

* the four bounds cannot fire on any loadable dex (the gate bounds every index
  it accepts, and lockstep holds), so they are pinned at SOURCE level - the same
  place, and for the same reason, as this decoder's `default:` arm, whose mutant
  no runtime test can kill either;
* lockstep itself is pinned two ways - a WIDTH invariant DERIVED from the gate's
  source and each decoder's, per type code and per accepted `arg`, and crafted
  dexes that make a wrong width move a value the assertion names.

The width layer is the durable half. `test_every_decoder_implements_every_value_
the_verifier_accepts` (dexllm#57, widened by dexllm#63) asserts that every type
the gate accepts is HANDLED; it says nothing about how many bytes each arm
consumes, so a future code added to both with a MISMATCHED width satisfies it
while re-opening exactly this.

**Two review findings shaped what is here, and both were in the GUARDS.** The
arm-text derivation is blind to `nbytes` itself, which is computed once at the
top of each decoder and is the line the production comment names as the reason
lockstep holds - so it is pinned as a literal. And "args 5..7 are unreachable
behaviourally" was an artefact of the in-place craft, not a fact: an
append-and-repoint craft on the same committed fixture reaches every width.
"""

from __future__ import annotations

import pathlib
import re
import struct

import pytest
from conftest import REPO_ROOT

_VERIFIER = REPO_ROOT / "native/core_ext/dex_verifier.cpp"
_CORE_EXT = REPO_ROOT / "native/core_ext/dexitem_code_source.cpp"
_DEXKIT_EXT = REPO_ROOT / "native/core_ext/dexkit_ext.cpp"
_READER = REPO_ROOT / "vendor/dexkit_core/Core/third_party/slicer/reader.cc"
_FORMAT = (
    REPO_ROOT / "vendor/dexkit_core/Core/third_party/slicer/export/slicer/dex_format.h"
)
_FIXTURE = REPO_ROOT / "tests/data/invoke-custom.dex"
_CRAFT_CLASS = "LTestLinkerMethodMinimalArguments;"

_STRUCTURAL = "structural"


# -- source parsing -----------------------------------------------------------


def _strip_comments(text: str) -> str:
    """Remove // and /* */ comments, scanning left to right.

    One pass, in source order: a `//` line can contain `/*`, and this repo has
    paid for the two-regex version twice (dexllm#32, dexllm#57). The scanner is
    self-checked below.
    """
    out = []
    i, n = 0, len(text)
    while i < n:
        if text.startswith("//", i):
            j = text.find("\n", i)
            i = n if j < 0 else j
        elif text.startswith("/*", i):
            j = text.find("*/", i + 2)
            i = n if j < 0 else j + 2
        else:
            out.append(text[i])
            i += 1
    return "".join(out)


_CASE = re.compile(r"case\s+(?:dex::)?(k\w+|0x[0-9a-fA-F]+)\s*:")


def _encoded_names() -> dict[str, int]:
    return {
        name: int(value, 16)
        for name, value in re.findall(
            r"constexpr u1 (kEncoded\w+)\s*=\s*(0x[0-9a-fA-F]+);",
            _strip_comments(_FORMAT.read_text()),
        )
    }


def _switch_body(
    path: pathlib.Path, anchor: str, default: str, close: str = "\n    }"
) -> tuple[str, str]:
    """(the arms of one switch, the body of its `default:`), comment-stripped.

    Anchored on a signature fragment and raising loudly if it moves, rather than
    silently auditing an empty string - the failure mode a dexllm#64 guard hit.
    """
    body = _strip_comments(path.read_text())
    start = body.find(anchor)
    assert start >= 0, f"{path.name}: anchor {anchor!r} moved or was renamed"
    body = body[start:]
    cut = body.find(default)
    assert cut >= 0, f"{path.name}: default arm {default!r} moved or was renamed"
    tail = body[cut + len(default) :]
    end = tail.find(close)
    assert end >= 0, f"{path.name}: the switch close {close!r} was not found"
    return body[:cut], tail[:end]


def _arms(body: str, names: dict[str, int]) -> list[tuple[frozenset[int], str]]:
    """[(type codes, arm body)] - consecutive empty-bodied labels share an arm."""
    marks = list(_CASE.finditer(body))
    out: list[tuple[frozenset[int], str]] = []
    pending: list[int] = []
    for i, m in enumerate(marks):
        token = m.group(1)
        code = int(token, 16) if token.startswith("0x") else names.get(token)
        if code is None:
            continue
        pending.append(code)
        stop = marks[i + 1].start() if i + 1 < len(marks) else len(body)
        segment = body[m.end() : stop]
        if segment.strip():
            out.append((frozenset(pending), segment))
            pending = []
    assert not pending, f"trailing labels with no body: {pending}"
    return out


# -- what each side consumes --------------------------------------------------


def _gate_accepts(arm: str) -> frozenset[int]:
    """The `value_arg` values this gate arm lets through.

    Derived from the arm's own guard. `idx(` carries its constraint inside the
    lambda (`if (arg > 3) return Fail`), which is why it maps to 0..3 without a
    visible `arg <= 3` in the arm.
    """
    if "arg == 0" in arm or "arg != 0" in arm:
        return frozenset({0})
    if "arg <= 1" in arm:
        return frozenset({0, 1})
    if "arg <= 3" in arm or "idx(" in arm:
        return frozenset(range(4))
    return frozenset(range(8))


def _gate_width(arm: str):
    if "ReadUleb" in arm or "VerifyEncodedAnnotation" in arm:
        return _STRUCTURAL
    if "skip(1)" in arm:
        return lambda arg: 1
    if "skip(arg + 1)" in arm or "idx(" in arm:
        return lambda arg: arg + 1
    return lambda arg: 0


def _core_width(arm: str):
    """core_ext dialect - `nbytes` is `value_arg + 1`, computed at the top."""
    if "ReadULEB128(" in arm or "ScanUleb(" in arm:
        return _STRUCTURAL
    if "ReadIntLE(p, end, 1)" in arm:
        return lambda arg: 1
    if (
        "ReadIntLE(p, end, nbytes)" in arm
        or "ScanIntLE(p, end, nbytes)" in arm
        or "std::min(nbytes, avail)" in arm  # the advancing `default:` arm
    ):
        return lambda arg: arg + 1
    return lambda arg: 0


def _slicer_width(arm: str):
    """slicer dialect - the width is spelled `arg + 1` at each read."""
    if "ParseEncodedArray" in arm or "ParseAnnotation" in arm:
        return _STRUCTURAL
    if "arg + 1" in arm:
        return lambda arg: arg + 1
    return lambda arg: 0


def _gate_model() -> dict[int, tuple[frozenset[int], object]]:
    body, _ = _switch_body(
        _VERIFIER,
        "bool DexVerifier::VerifyEncodedValue",
        'default: return Fail("encoded_value bad type code")',
    )
    model = {}
    for codes, arm in _arms(body, {}):
        for code in codes:
            model[code] = (_gate_accepts(arm), _gate_width(arm))
    return model


def _decoder_model(
    path: pathlib.Path, anchor: str, default: str, width, names=None, close="\n    }"
) -> tuple[dict[int, object], object]:
    """({type code: width}, the `default:` arm's width).

    The default matters: `ScanEncodedValueStrings` implements 5 codes and routes
    the other 13 through it, which is the structural reason that decoder never
    carried dexllm#63's bug.
    """
    body, tail = _switch_body(path, anchor, default, close)
    per = {}
    for codes, arm in _arms(body, names or {}):
        for code in codes:
            per[code] = width(arm)
    return per, width(tail)


_DECODERS = {
    "core_ext DecodeEncodedValueText": lambda: _decoder_model(
        _CORE_EXT,
        "DecodeEncodedValueText(const U1*& p",
        "        default:",
        _core_width,
    ),
    "core_ext ScanEncodedValueStrings": lambda: _decoder_model(
        _DEXKIT_EXT, "void ScanEncodedValueStrings", "default: {", _core_width
    ),
    "slicer ParseEncodedValue": lambda: _decoder_model(
        _READER,
        "Reader::ParseEncodedValue",
        "default:",
        _slicer_width,
        _encoded_names(),
        "\n  }",
    ),
}


# -- the durable half: the WIDTH, not only the case set -----------------------


def test_the_comment_scanner_is_not_fooled_by_a_slash_star_inside_a_line_comment():
    """Self-check: every derivation below rests on this scanner.

    `dexitem_code_source.cpp` contains `// ---- const-wide/* ----`; a `/* */`
    regex pass applied first swallows ~290 lines to the next `*/`, which SHRINKS
    an audit silently instead of failing it.
    """
    assert _strip_comments("a // x /* y\nb /* c */ d") == "a \nb  d"
    assert "case 0x99" not in _strip_comments("/* case 0x99: */ case 0x11:")


# How many arms each decoder must have of its own. Without this an arm could be
# DELETED and the code would silently take the `default:` width, which for the 16
# codes whose gate width is also `arg + 1` is indistinguishable (an adversarial
# reviewer's PLAUSIBLE). Only `ScanEncodedValueStrings` legitimately routes most
# codes through its default - it implements the 5 it cares about.
_MIN_ARMS = {
    "core_ext DecodeEncodedValueText": 18,
    "slicer ParseEncodedValue": 18,
    "core_ext ScanEncodedValueStrings": 5,
}


@pytest.mark.parametrize("decoder", sorted(_DECODERS), ids=lambda k: k.split()[-1])
def test_every_decoder_consumes_exactly_what_the_gate_consumes(decoder):
    """The lockstep invariant, per type code and per `value_arg` the gate accepts.

    Both sides are DERIVED from source, so a future code added to
    `VerifyEncodedValue` and to a decoder with a MISMATCHED width fails here -
    which the sibling case-set test (dexllm#57 / dexllm#63) structurally cannot
    see, since it only asks whether an arm EXISTS.

    A width mismatch is not a wrong constant. It shifts every element after it,
    and the index the next arm then extracts was validated by nothing - which
    dexllm#70's mutants showed is a SIGSEGV, not a wrong answer.

    `ParseCallSiteArg` (the fourth decoder) is deliberately absent: it walks a
    call_site array, which `VerifyEncodedValue` never walks, so there is no gate
    for it to be in lockstep WITH. Its own reader-tier bounds are what stand in
    (dexllm#67), pinned by `test_a_decoder_cannot_desync_by_construction`.
    """
    gate = _gate_model()
    per_code, fallback = _DECODERS[decoder]()

    # Non-vacuity: a degraded parse finds few arms, and would pass everything.
    assert len(gate) >= 18, sorted(hex(c) for c in gate)
    assert len(per_code) >= _MIN_ARMS[decoder], (
        decoder,
        sorted(hex(c) for c in per_code),
    )

    compared = 0
    for code, (accepted, gate_width) in sorted(gate.items()):
        mine = per_code.get(code, fallback)
        if gate_width is _STRUCTURAL or mine is _STRUCTURAL:
            assert gate_width is mine, (
                decoder,
                hex(code),
                "one side treats this as a self-delimiting (uleb-driven) value "
                "and the other as a fixed (arg + 1)-byte payload",
            )
            continue
        for arg in sorted(accepted):
            assert gate_width(arg) == mine(arg), (
                decoder,
                hex(code),
                f"value_arg={arg}",
                f"gate consumes {gate_width(arg)}, decoder consumes {mine(arg)}",
            )
            compared += 1
    # Pinned, not a floor: 64 is the exact number of (code, accepted arg) pairs
    # with a numeric width. An adversarial reviewer showed a floor of 60 had ZERO
    # margin - one gate narrowing lands on it exactly - so a 19th type code, or a
    # deliberate change to an arm's accepted args, has to bump this by hand.
    assert compared == 64, compared


def test_the_gate_model_matches_the_real_gate_on_every_type_and_arg(gate_probe):
    """The accepted-`arg` half of the model, adjudicated by `dexllm.verify()`.

    The width invariant above is only as good as its notion of which `value_arg`
    the gate lets through, and that notion is read out of the same source file it
    is auditing. Here it is checked against the shipped verifier over all 32 type
    codes x `value_arg` 0..4 - so a source-parse that silently degrades to
    "everything is accepted" fails.
    """
    gate = _gate_model()
    for (value_type, value_arg), valid in sorted(gate_probe.items()):
        predicted = value_type in gate and value_arg in gate[value_type][0]
        assert predicted == valid, (
            hex(value_type),
            value_arg,
            f"source model says {predicted}, dexllm.verify() says {valid}",
        )


# The ONE line every arm's width is a function of. `nbytes` / `arg` is computed
# once at the top of each decoder, OUTSIDE every arm, so the arm-text derivation
# above is structurally blind to it. BOTH reviewers built the same mutant -
# `min(value_arg + 1, 5)` - and it left this whole file GREEN, and the TRUE
# corpus-less run green too, while ordinary corpus `long` initializers
# (`value_arg == 7`, which d8 emits for any long >= 2**56) rendered wrong values
# AND desynced the rest of the array.
#
# Pinned as literals, which is the same "derived on one axis, literal on the
# other" device the bound guard below uses, and for the same reason: a guard
# parametrised over the production source cannot catch an EDIT of it.
_WIDTH_DERIVATION = {
    "gate VerifyEncodedValue": (
        _VERIFIER,
        ["const u4 arg = static_cast<u4>(header >> 5);"],
    ),
    "core_ext DecodeEncodedValueText": (
        _CORE_EXT,
        [
            "uint8_t value_arg = (header >> 5) & 0x07;",
            "size_t nbytes = static_cast<size_t>(value_arg) + 1;",
        ],
    ),
    "core_ext ParseCallSiteArg": (
        _CORE_EXT,
        ["const size_t nbytes = static_cast<size_t>((header >> 5) & 0x07) + 1;"],
    ),
    "core_ext ScanEncodedValueStrings": (
        _DEXKIT_EXT,
        [
            "uint8_t value_arg = (header >> 5) & 0x07;",
            "size_t nbytes = static_cast<size_t>(value_arg) + 1;",
        ],
    ),
    "slicer ParseEncodedValue": (
        _READER,
        ["dex::u1 arg = header >> dex::kEncodedValueArgShift;"],
    ),
}


@pytest.mark.parametrize("decoder", sorted(_WIDTH_DERIVATION))
def test_the_payload_width_is_derived_from_the_header_the_same_way_everywhere(decoder):
    """`arg + 1`, spelled once per decoder, pinned because it is SHARED by every arm.

    `ParseCallSiteArg` is here even though it is excluded from the lockstep
    invariant: it has its own copy of the same line, and the blind spot is a
    property of the LINE, not of which gate the decoder answers to.
    """
    path, lines = _WIDTH_DERIVATION[decoder]
    body = _strip_comments(path.read_text())
    for line in lines:
        assert line in body, (decoder, line)
    # ...and `kEncodedValueArgShift` is the 5 the slicer's spelling hides.
    assert "constexpr u1 kEncodedValueArgShift  = 5;" in _FORMAT.read_text()


# -- args 5..7, which the in-place craft cannot reach -------------------------
#
# The in-place region is 8 bytes, so a 6-to-8-byte payload plus its header
# leaves no room for a sentinel. An adversarial reviewer showed that is an
# artefact of the CRAFT rather than a fact about the fixture, and that the
# uncovered args are exactly where the `nbytes` mutant bites: APPEND a fresh
# `encoded_array` at EOF (4-aligned), repoint the class's `static_values_off`
# at it, and grow `file_size` / `data_size`. The result verifies, loads and
# decompiles - so LONG, DOUBLE and METHOD_HANDLE (the three types the gate lets
# through at ANY arg) are covered at every width they can carry.
#
# This does not replace the in-place craft: that one is length-preserving, so
# nothing but the intended bytes can be what changed. This one trades that for
# reach, and pays for it by asserting the dex still verifies.
_UNCAPPED = (0x06, 0x11, 0x16)  # LONG / DOUBLE / METHOD_HANDLE
_CAPPED_CONTROL = 0x04  # INT - the gate rejects arg > 3, which the craft must show


def _uleb_bytes(value: int) -> bytes:
    out = bytearray()
    while True:
        byte = value & 0x7F
        value >>= 7
        out.append(byte | (0x80 if value else 0))
        if not value:
            return bytes(out)


def _class_def_offset(raw: bytes) -> int:
    """Offset of `_CRAFT_CLASS`'s class_def, found by walking the table."""

    def uleb(off: int) -> tuple[int, int]:
        value = shift = 0
        while True:
            byte = raw[off]
            off += 1
            value |= (byte & 0x7F) << shift
            shift += 7
            if not byte & 0x80:
                return value, off

    type_ids_off = struct.unpack_from("<I", raw, 0x44)[0]
    string_ids_off = struct.unpack_from("<I", raw, 0x3C)[0]
    defs_size, defs_off = struct.unpack_from("<II", raw, 0x60)
    for i in range(defs_size):
        base = defs_off + i * 32
        type_idx = struct.unpack_from("<I", raw, base)[0]
        str_idx = struct.unpack_from("<I", raw, type_ids_off + type_idx * 4)[0]
        data = struct.unpack_from("<I", raw, string_ids_off + str_idx * 4)[0]
        n, q = uleb(data)
        if raw[q : q + n].decode("utf-8", "replace") == _CRAFT_CLASS:
            return base
    raise AssertionError(f"{_CRAFT_CLASS} is not in the fixture")


def _append_array(dst: pathlib.Path, values: bytes, count: int) -> None:
    """Append an `encoded_array` at EOF and repoint `static_values_off` at it."""
    raw = bytearray(_FIXTURE.read_bytes())
    base = _class_def_offset(bytes(raw))
    while len(raw) % 4:
        raw.append(0)
    new_off = len(raw)
    raw += _uleb_bytes(count) + values
    while len(raw) % 4:  # slicer's ValidateHeader wants a 4-aligned data_size
        raw.append(0)
    struct.pack_into("<I", raw, base + 28, new_off)
    grown = len(raw) - struct.unpack_from("<I", raw, 0x20)[0]
    struct.pack_into("<I", raw, 0x20, len(raw))  # file_size
    struct.pack_into("<I", raw, 0x68, struct.unpack_from("<I", raw, 0x68)[0] + grown)
    dst.write_bytes(bytes(raw))


@pytest.mark.parametrize("value_arg", list(range(8)))
@pytest.mark.parametrize("value_type", [*_UNCAPPED, _CAPPED_CONTROL])
def test_a_wide_value_is_consumed_in_full_and_the_gate_agrees(
    tmp_path, value_type, value_arg
):
    """Widths 1..8, adjudicated the same two ways as the in-place craft.

    Two assertions in one, because the craft supports both and separating them
    would build the same dex twice: the SHIPPED gate must accept exactly the args
    the source model predicts (which extends the model cross-check past arg 4),
    and where it accepts, the sentinels must land on the fields FOLLOWING the
    crafted value.

    `_CAPPED_CONTROL` is what keeps the first half from being vacuous - INT is
    rejected at arg >= 4, so the craft has to be able to produce a REJECTED dex
    as well as an accepted one.
    """
    import dexllm

    sentinels = list(_SENTINELS)
    value = bytes([(value_arg << 5) | value_type]) + bytes(value_arg + 1)
    dst = tmp_path / f"wide-{value_type:02x}-{value_arg}.dex"
    _append_array(
        dst,
        value + b"".join(bytes([0x04, s]) for s in sentinels),
        1 + len(sentinels),
    )

    rows = dexllm.verify(str(dst))
    valid = bool(rows and rows[0]["valid"])
    predicted = value_arg in _gate_model()[value_type][0]
    assert valid == predicted, (hex(value_type), value_arg, rows)
    if not valid:
        return

    lines = _static_finals(dst)
    got = [line.rsplit("= ", 1)[-1] for line in lines[1 : 1 + len(sentinels)]]
    assert got == [f"{s};" for s in sentinels], (hex(value_type), value_arg, lines)


def test_an_over_declared_value_count_is_clamped_to_the_field_list(tmp_path):
    """`DecodeStaticInitMap`'s clamp - a load-bearing line with no guard until now.

    An adversarial reviewer deleted

        if (value_count > static_field_idxs.size()) value_count = ...;

    and the ENTIRE suite stayed green, while a `verify()`-valid dex declaring
    100,000 values for a 4-field class SIGSEGV'd on `static_field_idxs[i]`. The
    count is unconstrained because ART's `CheckStaticFieldTypes` is deliberately
    not ported, so the gate has nothing to say about it.

    This change's own reachability argument names that clamp as one of the four
    reasons the new bounds cannot fire, so it may not stay unpinned.

    WHAT THIS DOES AND DOES NOT CATCH, measured rather than assumed: removing the
    clamp is UNDEFINED BEHAVIOUR, not a guaranteed fault - `static_field_idxs[i]`
    for i up to 99,999 reads ~400 KB past a four-element vector, which lands in
    mapped heap as often as not. Rebuilt without the clamp, this case PASSES.
    So the killing guard is the SOURCE pin below, the same treatment the four
    bounds and the depth caps get; this one pins the observable half - the walk
    stops at the field list, and the process survives - in a SUBPROCESS judged by
    EXIT STATUS, since a `try/except` cannot see a signal.
    """
    import subprocess
    import sys

    dst = tmp_path / "over-count.dex"
    _append_array(dst, bytes([0x1E]) * 100_000, 100_000)  # 100k NULLs: all valid

    import dexllm

    assert dexllm.verify(str(dst))[0]["valid"]  # the premise

    probe = (
        "import sys, dexllm\n"
        f"src = dexllm.DexKit(sys.argv[1]).decompile_class({_CRAFT_CLASS!r})\n"
        "print(sum(1 for l in src.split(chr(10)) if 'static final' in l))\n"
    )
    r = subprocess.run(
        [sys.executable, "-c", probe, str(dst)], capture_output=True, text=True
    )
    assert r.returncode == 0, (r.returncode, r.stderr[-2000:])
    assert r.stdout.strip() == "4", r.stdout


# -- nesting: the gate's depth cap also held only in lockstep -----------------


def test_the_deepest_nesting_the_gate_accepts_still_renders(tmp_path):
    """The decoder's own cap must sit at EXACTLY the gate's, not below it.

    Before dexllm#71 the 0x1c/0x1d arms recursed with no depth parameter at all,
    leaning on `VerifyEncodedValue`'s kMaxDepth with a comment saying it "bounds
    this walk too" - the same conditional promise the four index arms were
    leaning on, in the same function, and a correctness reviewer pointed out it
    was the one left undone. On a desync the nesting is bounded only by
    `end - p`: one stack frame per 0x1c byte, an uncatchable SIGSEGV.

    A cap is invisible from outside unless it is set WRONG, so this pins the
    cutoff from both sides: 16 nested arrays verify AND render (so a cap set too
    low truncates and fails), 17 are refused by the gate (so the cap is not
    merely permissive).
    """
    import dexllm

    def nested(k: int) -> bytes:
        payload = bytes([0x04, 0x07])  # innermost: INT 7
        for _ in range(k):
            payload = bytes([0x1C, 0x01]) + payload  # one-element array
        return payload

    deep = tmp_path / "nest-16.dex"
    _append_array(deep, nested(16) + bytes([0x04, _SENTINELS[0]]), 2)
    assert dexllm.verify(str(deep))[0]["valid"]  # the premise

    lines = _static_finals(deep)
    assert lines[0].endswith("= " + "{" * 16 + "7" + "}" * 16 + ";"), lines
    # ...and the value after it is untouched, so nothing was consumed short.
    assert lines[1].endswith(f"= {_SENTINELS[0]};"), lines

    over = tmp_path / "nest-17.dex"
    _append_array(over, nested(17) + bytes([0x04, _SENTINELS[0]]), 2)
    assert not dexllm.verify(str(over))[0]["valid"]


def test_the_static_init_walk_clamps_the_value_count():
    """Source-level, because the UB it prevents does not reliably fault.

    An adversarial reviewer deleted this clamp and the ENTIRE suite stayed green.
    Nothing else in the repository pins it, and the gate has nothing to say about
    the count (ART's `CheckStaticFieldTypes` is deliberately not ported), so a
    `verify()`-valid dex can declare any number of values for any number of
    fields.
    """
    body = _strip_comments(_CORE_EXT.read_text())
    start = body.index("DecodeStaticInitMap(const dexkit::DexItem& item")
    walk = body[start : start + 2000]
    assert "if (value_count > static_field_idxs.size()) {" in walk, walk
    assert "value_count = static_field_idxs.size();" in walk, walk
    # ...and the clamp must precede both the reserve and the walk that use it.
    assert walk.index("value_count = static_field_idxs.size();") < walk.index(
        "init_map.reserve(value_count);"
    ), "the clamp must run before value_count is used"


def test_every_array_walking_decoder_caps_its_own_recursion():
    """Source-level: removing a cap is invisible from outside, so pin it.

    The cap only matters on a desync, which no loadable dex produces - the same
    position the four bounds are in, and pinned the same way. The VALUE is
    pinned against the gate's own `kMaxDepth`, so the two cannot drift apart.
    """
    gate = _strip_comments(_VERIFIER.read_text())
    assert "constexpr int kMaxDepth = 16;" in gate, "the gate's cap moved"

    for path, const, call in (
        (_CORE_EXT, "constexpr int kEncodedValueMaxDepth = 16;", "depth + 1);"),
        (_DEXKIT_EXT, "constexpr int kScanMaxDepth = 16;", "depth + 1);"),
    ):
        body = _strip_comments(path.read_text())
        assert const in body, (path.name, const)
        assert "if (depth > " in body, path.name
        assert call in body, (path.name, call)


# -- the crafted half: a wrong width MOVES a value ----------------------------


def _static_values_region(raw: bytes) -> tuple[int, int, int]:
    """(offset of the count uleb, offset of the first value, region length).

    Located by walking `class_defs`, so a substituted or regenerated fixture
    fails loudly here instead of being patched at a wrong offset.
    """

    def uleb(off: int) -> tuple[int, int]:
        value = shift = 0
        while True:
            byte = raw[off]
            off += 1
            value |= (byte & 0x7F) << shift
            shift += 7
            if not byte & 0x80:
                return value, off

    type_ids_off = struct.unpack_from("<I", raw, 0x44)[0]
    string_ids_off = struct.unpack_from("<I", raw, 0x3C)[0]
    defs_size, defs_off = struct.unpack_from("<II", raw, 0x60)

    def descriptor_of(type_idx: int) -> str:
        str_idx = struct.unpack_from("<I", raw, type_ids_off + type_idx * 4)[0]
        data = struct.unpack_from("<I", raw, string_ids_off + str_idx * 4)[0]
        n, q = uleb(data)
        return raw[q : q + n].decode("utf-8", "replace")

    for i in range(defs_size):
        base = defs_off + i * 32
        if descriptor_of(struct.unpack_from("<I", raw, base)[0]) != _CRAFT_CLASS:
            continue
        off = struct.unpack_from("<I", raw, base + 28)[0]
        assert off, f"{_CRAFT_CLASS} has no static_values"
        count, first = uleb(off)
        assert first == off + 1, "the value count is no longer a one-byte uleb"
        assert count == 4, f"{_CRAFT_CLASS} now declares {count} static values"
        # Four one-byte INTs: `04 01 | 04 02 | 04 00 | 04 03`. The region length
        # is what every craft below has to fit inside, byte for byte, so that no
        # offset, section size or neighbouring structure moves.
        assert raw[first : first + 8] == bytes([4, 1, 4, 2, 4, 0, 4, 3]), raw[
            first : first + 8
        ].hex()
        return off, first, 8
    raise AssertionError(f"{_CRAFT_CLASS} is not in the fixture")


# The payload the GATE says a value of this shape carries. Zero bytes, because
# index 0 is in range for every table this fixture has and a non-minimal encoding
# is something the gate's `idx` lambda explicitly allows. The two self-delimiting
# types are the exception - their payload IS structure - so the minimal correct
# encoding is spelled out.
#
# Taking the width from the gate model is what closes the loop: the crafts test
# the DECODER's width against the gate's, and `test_the_gate_model_matches_the_
# real_gate...` then tests the gate model against the shipped verifier. A model
# that got a width wrong lays out a malformed array, which `dexllm.verify()`
# rejects, so that test fails rather than the audit silently drifting.
_PAYLOAD = {
    0x1C: b"\x00",  # ARRAY: uleb size = 0, i.e. `{}`
    0x1D: b"\x00\x00",  # ANNOTATION: uleb type_idx = 0, uleb size = 0
}
_SENTINELS = (0x2A, 0x33, 0x11)  # 42 / 51 / 17 - none is a value the fixture has


def _payload(value_type: int, value_arg: int) -> bytes:
    if value_type in _PAYLOAD:
        return _PAYLOAD[value_type] if value_arg == 0 else bytes(value_arg + 1)
    entry = _gate_model().get(value_type)
    if entry is None or entry[1] is _STRUCTURAL:
        return bytes(value_arg + 1)  # an unknown code: rejected on the code alone
    return bytes(entry[1](value_arg))


def _craft(dst: pathlib.Path, value_type: int, value_arg: int) -> list[int]:
    """Re-lay the 8-byte value region as [crafted value][INT sentinels].

    Returns the sentinel values, which must come back on the fields FOLLOWING
    the crafted one. A decoder that consumes the wrong width for the crafted
    value reads a sentinel's header as part of the payload, so the sentinels
    move - which is the whole property, stated as an assertion about the right
    answer rather than as a difference from some mutant.

    Length-preserving: the count uleb stays one byte, the region stays 8, and
    any leftover byte is simply never read (the walk stops after `count`).
    """
    raw = bytearray(_FIXTURE.read_bytes())
    count_off, first, length = _static_values_region(bytes(raw))
    value = bytes([(value_arg << 5) | value_type]) + _payload(value_type, value_arg)
    assert len(value) < length, (value_type, value_arg)
    sentinels = list(_SENTINELS[: (length - len(value)) // 2])
    region = value + b"".join(bytes([0x04, s]) for s in sentinels)
    raw[first : first + len(region)] = region
    raw[count_off] = 1 + len(sentinels)
    dst.write_bytes(bytes(raw))
    return sentinels


@pytest.fixture(scope="module")
def gate_probe(tmp_path_factory) -> dict[tuple[int, int], bool]:
    """{(type, arg): does the shipped gate accept it} over 32 x 5 crafted dexes.

    `value_arg` stops at 4 because the region is 8 bytes: a 6-byte payload plus
    its header leaves no room for a sentinel, so args 5..7 of LONG/DOUBLE are
    unreachable behaviourally. The width invariant is symbolic in `arg`, so it
    covers them; this half covers what can be built.
    """
    import dexllm

    out: dict[tuple[int, int], bool] = {}
    d = tmp_path_factory.mktemp("gate-probe")
    for value_type in range(32):
        for value_arg in range(5):
            dst = d / f"probe-{value_type:02x}-{value_arg}.dex"
            _craft(dst, value_type, value_arg)
            rows = dexllm.verify(str(dst))
            out[(value_type, value_arg)] = bool(rows and rows[0]["valid"])
    return out


def _static_finals(path: pathlib.Path) -> list[str]:
    import dexllm

    src = dexllm.DexKit(str(path)).decompile_class(_CRAFT_CLASS)
    return [line.strip() for line in src.split("\n") if "static final" in line]


@pytest.mark.parametrize("value_type", list(range(32)))
def test_a_gate_accepted_value_does_not_shift_the_values_after_it(
    tmp_path, gate_probe, value_type
):
    """Every (type, arg) the SHIPPED gate accepts is walked at the right width.

    Not a hand-listed set: the accepted combinations come from `dexllm.verify()`
    on the crafts themselves, so a type code that becomes acceptable in future is
    exercised here the day it does.

    The sentinels are INTs the fixture does not otherwise contain, so "the values
    after it are 42/51/17" cannot be a coincidence, and the uncrafted baseline
    below shows what they replaced.
    """
    accepted = [arg for arg in range(5) if gate_probe[(value_type, arg)]]
    if not accepted:
        pytest.skip(f"the gate rejects every arg of {value_type:#04x}")
    for value_arg in accepted:
        dst = tmp_path / f"width-{value_type:02x}-{value_arg}.dex"
        sentinels = _craft(dst, value_type, value_arg)
        assert sentinels, (value_type, value_arg)
        lines = _static_finals(dst)
        got = [line.rsplit("= ", 1)[-1] for line in lines[1 : 1 + len(sentinels)]]
        assert got == [f"{s};" for s in sentinels], (
            hex(value_type),
            value_arg,
            lines,
        )


def test_the_probe_reaches_every_type_the_gate_implements(gate_probe):
    """Floor: the crafted matrix is not quietly empty, and not quietly total.

    Without both halves the parametrised guard above could pass by skipping
    everything, or by a gate that accepts anything.
    """
    accepted = {t for (t, _a), ok in gate_probe.items() if ok}
    assert len(accepted) == 18, sorted(hex(t) for t in accepted)
    assert len(gate_probe) == 32 * 5


def test_the_uncrafted_fixture_still_renders_its_own_values():
    """Non-discriminating BY DESIGN - the baseline the crafts are measured against."""
    lines = _static_finals(_FIXTURE)
    assert [line.rsplit("= ", 1)[-1] for line in lines] == [
        "1;",
        "2;",
        "0;",
        "3;",
    ], lines


# -- the bound itself, which no loadable dex can reach ------------------------

# `Lclass;->member` of the table each arm subscripts, pinned as a literal: a
# guard parametrised over the production source cannot catch an EDIT of it.
_BOUNDED_ARMS = {
    0x15: "proto_ids.size()",
    0x17: "strings.size()",
    0x18: "type_names.size()",
    0x19: "field_ids.size()",
    0x1B: "field_ids.size()",
    0x1A: "method_ids.size()",
}


def test_every_arm_that_subscripts_with_the_decoded_index_bounds_it_first():
    """The four dexllm#71 bounds, plus the two that already had one.

    Source-level because it is the only level left: the gate bounds every index
    it accepts and lockstep holds, so on a loadable dex these bails are dead -
    exactly the position this decoder's `default:` arm is in, and the reason it
    is pinned the same way.

    The SET is DERIVED (every arm that forms a `[idx]` subscript must appear),
    so a new arm cannot be added without a bound; the table NAME is pinned as a
    literal, so a bound cannot be quietly retargeted at a table that is always
    big enough.
    """
    body, _ = _switch_body(
        _CORE_EXT, "DecodeEncodedValueText(const U1*& p", "        default:"
    )
    arms = {c: arm for codes, arm in _arms(body, {}) for c in codes}

    # The variable is DERIVED, not the literal `idx`: hard-coding the name means a
    # rename empties the set silently (a correctness reviewer's note).
    decoded = {}
    for code, arm in arms.items():
        m = re.search(r"uint64_t\s+(\w+)\s*=\s*ReadIntLE\(", arm)
        if m and re.search(rf"\[\s*{m.group(1)}\s*\]", arm):
            decoded[code] = m.group(1)

    assert set(decoded) == set(_BOUNDED_ARMS), (
        sorted(hex(c) for c in decoded),
        sorted(hex(c) for c in _BOUNDED_ARMS),
    )

    for code, table in sorted(_BOUNDED_ARMS.items()):
        arm, var = arms[code], decoded[code]
        guard = f"if ({var} >= {table}) return {{}};"
        # Its own statement, not a substring: `if (false) { <guard> }` would
        # otherwise satisfy a plain `in` test.
        assert any(line.strip() == guard for line in arm.splitlines()), (
            hex(code),
            guard,
            arm,
        )
        assert arm.index(guard) < arm.index(f"[{var}]"), (
            hex(code),
            "the bound must precede the subscript it bounds",
        )
