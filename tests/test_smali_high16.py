"""The smali view of `const/high16` prints what the register receives (dexllm#87).

`BBBB` is the HIGH half of the loaded value and the slicer hands it over raw
(`dex_bytecode.cc:189` declines to shift, because the decoder "doesn't know if
it's the top bits of a 32- or 64-bit value"), so the shift belongs to the
consumer and its WIDTH comes from the OPCODE:

    0x15 const/high16       -> BBBB << 16   (a 32-bit int)
    0x19 const-wide/high16  -> BBBB << 48   (a 64-bit long)

Printing the raw `BBBB` made the two views of one instruction disagree — smali
`#0x1000` where the Java view says `268435456` — on 9,349 sites across 2,138 of
the 25,309 bundled classes. Nothing pinned the rendering before this file.

Every behavioural case runs on the COMMITTED `tests/data/invoke-custom.dex`,
which is the only fixture in git carrying both shapes (4 `const/high16` +
2 `const-wide/high16`), so they hold in the corpus-less CI leg and under any
`$DEXLLM_TEST_APK` narrowing. The corpus cases (the issue's own cross-view
evidence, the independent decoder, the reader cross-check) SKIP under one.

Two crafts exist because the fixture's own values do not separate the shipped
expression from the plausible wrong ones: all six have `BBBB < 0x8000`, so a
sign-extending variant renders identically on them. Each craft rewrites ONE u2
— the `BBBB` operand of a `k21h` instruction, same opcode, same width — so no
offset and no section size moves, and the craft asserts both that its pattern
occurs the expected number of times and that the dex still verifies.
"""

import os
import pathlib
import re
import struct

import pytest
from conftest import corpus_is_narrowed, require_corpus_shape

import dexllm

FIXTURE = pathlib.Path(__file__).resolve().parent / "data" / "invoke-custom.dex"

# The fixture's own six sites, as the shipped renderer prints them. Pinned as
# LITERALS: a guard parametrised over the production expression cannot catch an
# edit of it, and the whole subject here is which value gets printed. Each was
# checked by hand: 0x3f000000 is 1056964608 and 0.5f, and so on.
#
# The form is jadx's fallback literal (TypeGen.literalToString): the SIGNED
# value, then every reading of the bits -- see smali_render.cpp `case k21h`.
_FIXTURE_SITES = {
    # two methods of this class each load the NaN high bits, both at offset 0x6
    "LTestInvocationKinds;": [
        "const-wide/high16 v0, #9221120237041090560(0x7ff8000000000000, double:NaN)",
        "const-wide/high16 v0, #9221120237041090560(0x7ff8000000000000, double:NaN)",
    ],
    "LTestLinkerUnrelatedBSM;": [
        "const/high16 v0, #1056964608(0x3f000000, float:0.5)",
        "const/high16 v1, #1073741824(0x40000000, float:2.0)",
        "const/high16 v3, #1075838976(0x40200000, float:2.5)",
        "const/high16 v1, #1069547520(0x3fc00000, float:1.5)",
    ],
}

_HIGH16 = re.compile(
    r"^(const(?:-wide)?/high16) (v\d+), #(-?\d+)"
    r"(?:\(0x([0-9a-f]+), (float|double):([^)]*)\))?$"
)
_LINE = re.compile(r"^\s*(0x[0-9a-f]+): (.*)$")


def _fp_reading_matches(text, bits, wide):
    """Does the printed float/double reading denote exactly these bits?

    Parsed back rather than re-formatted: re-implementing Java's
    `Float.toString` here would test the renderer against a second copy of
    itself. Any decimal string that rounds to the same bit pattern passes; the
    exact spelling is pinned separately against a JDK 21.
    """
    import math

    fmt, ifmt = ("<d", "<Q") if wide else ("<f", "<I")
    x = struct.unpack(fmt, struct.pack(ifmt, bits))[0]
    if math.isnan(x):
        return text == "NaN"
    if math.isinf(x):
        return text == ("Infinity" if x > 0 else "-Infinity")
    try:
        y = float(text)
    except ValueError:
        return False
    if "." not in text:  # Java always prints a fractional digit
        return False
    return struct.unpack(ifmt, struct.pack(fmt, y))[0] == bits


def _insn_lines(text):
    """(byte_offset, instruction_text) for every rendered instruction."""
    out = []
    for raw in text.split("\n"):
        m = _LINE.match(raw)
        if m:
            out.append((int(m.group(1), 16), m.group(2).strip()))
    return out


def _high16_lines(text):
    """(offset, mnemonic, register, bits) per high16 instruction.

    `bits` is the loaded value as an UNSIGNED register-width integer. Every
    line is also checked for INTERNAL consistency, so every test that parses a
    listing checks it for free: the signed decimal fits the register, the hex
    (when printed) is the same bits, the reading is labelled for the width and
    parses back to those bits, and the decoration is absent only where jadx's
    `|v| > 100` threshold says it should be.
    """
    out = []
    for off, ins in _insn_lines(text):
        if "high16" not in ins:
            continue
        m = _HIGH16.match(ins)
        assert m, f"unparseable high16 line: {ins!r}"
        mn, reg, dec, hexs, kind, reading = m.groups()
        wide = mn == "const-wide/high16"
        width = 64 if wide else 32
        v = int(dec)
        assert -(1 << (width - 1)) <= v < (1 << (width - 1)), ins
        bits = v & ((1 << width) - 1)
        if hexs is None:
            assert abs(v) <= 100, f"undecorated but |v| > 100: {ins!r}"
        else:
            assert abs(v) > 100, f"decorated but |v| <= 100: {ins!r}"
            assert int(hexs, 16) == bits, f"hex disagrees with the value: {ins!r}"
            assert kind == ("double" if wide else "float"), ins
            assert _fp_reading_matches(reading, bits, wide), ins
        out.append((off, mn, reg, bits))
    return out


# --------------------------------------------------------------------------
# The fixture, unmodified
# --------------------------------------------------------------------------


@pytest.fixture(scope="module")
def fx():
    assert FIXTURE.is_file(), f"{FIXTURE} is committed; it must be present"
    return dexllm.DexKit(str(FIXTURE))


def _render(dk, cls, api):
    """A class's instructions through either smali API.

    `render_class_smali` and `render_method_smali` carry SEPARATE instruction
    walks (`smali_render.cpp` lines 512 and 583 each call `FormatOperands`
    once), so a defect can live in one and not the other. The first cut of this
    file called `render_class_smali` 7 times and `render_method_smali` ZERO, and
    an adversarial review built the mutant: post-processing only the
    method-API walk to print the raw operand left every case here GREEN while
    all 9,349 corpus sites were back to the pre-fix defect through that API.
    Both are documented, both are named in dexllm#87, so every value assertion
    runs through both.
    """
    if api == "class":
        return dk.render_class_smali(cls)
    return "\n".join(dk.render_method_smali(m) for m in dk.list_class_methods(cls))


_APIS = ("class", "method")


@pytest.mark.parametrize("api", _APIS)
@pytest.mark.parametrize("cls", sorted(_FIXTURE_SITES))
def test_the_fixture_renders_the_value_the_register_receives(fx, cls, api):
    """Each pinned site prints the shifted value, through BOTH smali APIs."""
    text = _render(fx, cls, api)
    _high16_lines(text)  # every line internally consistent
    got = [ins for _, ins in _insn_lines(text) if "high16" in ins]
    assert got == _FIXTURE_SITES[cls]


def _assert_is_bbbb_shifted(mn, val, where):
    """`val` must be exactly `BBBB << shift` for some 16-bit BBBB.

    Two assertions, and together they pin the WIDTH as well as the shift: a
    `const/high16` value satisfies them only for shift 16 and a wide one only
    for 48, so a swapped or wrong-width shift cannot pass either way.

    The digit COUNT is deliberately an upper bound, not an equality: hex drops a
    leading zero, so `BBBB = 0x010a` prints seven digits rather than eight.
    The first cut asserted the exact count and the corpus leg caught it on
    `Landroid/support/v4/app/ListFragment;` — a reminder that a derived property
    is weaker than the one it is derived from.
    """
    shift = 48 if mn == "const-wide/high16" else 16
    assert val & ((1 << shift) - 1) == 0, f"{where} {mn} 0x{val:x} has low bits set"
    assert val >> shift < 0x10000, f"{where} {mn} 0x{val:x} is not BBBB<<{shift}"
    assert len(f"{val:x}") <= (16 if shift == 48 else 8), f"{where} {mn} 0x{val:x}"


@pytest.mark.parametrize("api", _APIS)
def test_each_fixture_value_is_bbbb_shifted_by_its_opcodes_width(fx, api):
    """The two opcodes are not confused for one another.

    Width is the whole content of the opcode branch. Checked as a PROPERTY as
    well as through the pinned literals above, so a future fixture with
    different values still pins it.
    """
    seen = {"const/high16": 0, "const-wide/high16": 0}
    for cls in _FIXTURE_SITES:
        for _, mn, _, val in _high16_lines(_render(fx, cls, api)):
            seen[mn] += 1
            _assert_is_bbbb_shifted(mn, val, cls)
    assert seen == {"const/high16": 4, "const-wide/high16": 2}, seen


@pytest.mark.parametrize("api", _APIS)
def test_the_sibling_const_forms_are_unchanged(fx, api):
    """Every OTHER literal arm still prints what it printed.

    dexllm#87 touches one arm of a switch whose neighbours already printed the
    loaded value. Pinned so a fix applied to the wrong arm fails here rather
    than silently changing an unrelated literal.

    `const-wide` (k51l) is in the list because an adversarial review built the
    mutant that needed it: reading `insn.vB` where k51l's value is in
    `insn.vB_wide` — which the slicer never sets for k51l — renders every
    `const-wide` as `#0L`, **1,714 corpus sites**, and the whole guard file
    passed. Each arm carries its own FLOOR, because `const` (k31i) rides on two
    fixture sites and `const-wide` on one.

    These arms print a bare signed DECIMAL, with an `L` suffix on the 64-bit
    one. The k21h arm prints a signed decimal too, followed by jadx's readings;
    see `_HIGH16`.
    """
    want = {
        "const/4": r"-?\d+",
        "const/16": r"-?\d+",
        "const": r"-?\d+",
        "const-wide": r"-?\d+L",
    }
    # VALUES, not just the form. The form alone cannot see a wrong value: the
    # R4 mutant renders every `const-wide` as `#0L`, which matches the regex --
    # it survived a form-only version of this test, so each wide arm's distinct
    # values are pinned as a SET. (The 64-bit ones are the doubles this
    # invoke-dynamic fixture passes as bootstrap arguments.)
    pinned = {
        "const": {"#2147483647", "#1093769626"},
        "const-wide": {
            "#4613303445314885481L",
            "#4614256656552045848L",
            "#4612136378390124954L",
        },
    }
    seen = {}
    vals = {}
    for cls in fx.list_classes():
        for _, ins in _insn_lines(_render(fx, cls, api)):
            mn = ins.split(" ", 1)[0]
            if mn in want:
                seen[mn] = seen.get(mn, 0) + 1
                lit = ins.rsplit("#", 1)[1]
                assert re.fullmatch(want[mn], lit), f"{mn} printed #{lit}"
                vals.setdefault(mn, set()).add("#" + lit)
    for mn in want:
        assert seen.get(mn), f"the fixture must carry a {mn} for this to mean anything"
    for mn, exp in pinned.items():
        assert vals[mn] == exp, f"{mn} values moved: {sorted(vals[mn])}"


# --------------------------------------------------------------------------
# Crafted: a BBBB with the top bit set
# --------------------------------------------------------------------------


def _craft(tmp_path, pattern, replacement, want_occurrences, same_insn=True):
    """Rewrite one u2 operand in place and return the crafted dex path.

    `pattern` is the whole 4-byte instruction (opcode, AA, BBBB little-endian)
    and `replacement` differs from it only in BBBB, so the craft is
    length-preserving to the byte: no offset, no section size and no neighbouring
    structure moves, and the opcode and register are untouched.

    EVERY occurrence is rewritten, not one — `want_occurrences` is asserted first
    so the count is a premise rather than a surprise, and the caller asserts that
    all of them render the new value.
    """
    assert len(pattern) == len(replacement) == 4
    if same_insn:
        # the default: only BBBB moves, so the opcode and register are untouched
        assert pattern[:2] == replacement[:2], "this craft must not move the opcode"
    else:
        # REPLACES the whole instruction, which is how a high register is
        # reached: the four natural sites live in a `.registers 4` method, so
        # re-pointing their AA byte is out of range and the gate rejects it.
        # Still length-preserving, and the verify assertion below is what makes
        # the substitution safe rather than assumed.
        assert replacement[0] in (0x15, 0x19), "a whole-instruction craft writes a k21h"
    blob = bytearray(FIXTURE.read_bytes())
    n = bytes(blob).count(pattern)
    assert n == want_occurrences, (
        f"the fixture's {pattern.hex()} occurs {n}x, expected {want_occurrences} — "
        "the committed dex changed and this craft needs re-deriving"
    )
    out = tmp_path / "crafted.dex"
    out.write_bytes(bytes(blob).replace(pattern, replacement))
    # the craft must still be a dex the gate accepts, in BOTH modes: a rejected
    # dex never reaches the renderer, so a guard that skipped this could pass
    # for the wrong reason.
    for lenient in (False, True):
        rep = dexllm.verify(str(out), lenient=lenient)
        assert all(r["valid"] for r in rep), (lenient, rep)
    return out


@pytest.mark.parametrize("api", _APIS)
def test_a_top_bit_set_high16_is_shifted_not_sign_extended(tmp_path, api):
    """`BBBB = 0xbf80` must load `0xbf800000`:
    `#-1082130432(0xbf800000, float:-1.0)`.

    `0xbf80 << 16` is `-1.0f`, and it is the value the fixture's own four sites
    cannot reach: every one has `BBBB < 0x8000`, so a variant that sign-extends
    the operand before shifting renders identically on all of them. Here the
    signed decimal would still agree (both are -1082130432 as an int32), but the
    hex would read `0xffffffffbf800000`, which `_high16_lines` rejects because
    the hex must be the register's own bits.

    Also kills a plain truncation: `0xbf80` is not `BBBB << 16`.
    """
    dex = _craft(
        tmp_path, bytes([0x15, 0x00, 0x00, 0x3F]), bytes([0x15, 0x00, 0x80, 0xBF]), 1
    )
    dk = dexllm.DexKit(str(dex))
    vals = [
        (mn, f"{v:x}")
        for _, mn, _, v in _high16_lines(_render(dk, "LTestLinkerUnrelatedBSM;", api))
    ]
    assert ("const/high16", "bf800000") in vals, vals
    # the three untouched siblings are unmoved — the craft changed one operand
    assert ("const/high16", "40000000") in vals
    assert ("const/high16", "40200000") in vals
    assert ("const/high16", "3fc00000") in vals


@pytest.mark.parametrize("api", _APIS)
def test_a_top_bit_set_wide_high16_keeps_all_sixteen_digits(tmp_path, api):
    """`BBBB = 0xc045` must load `0xc045000000000000`, the double `-42.0`:
    `#-4592264245034352640(0xc045000000000000, double:-42.0)`.

    Sign-extending before the shift changes nothing in 64 bits, but a wrong
    width or a dropped high half does, and only a top-bit-set value separates
    some of those from the uncrafted sites — which is what this craft is for.

    It is NOT what catches a missing widening cast. `insn.vB << 48` on a 32-bit
    type is a shift count at the operand width, and a correctness review built
    it: gcc CONSTANT-FOLDS that UB to `0`, so it renders `#0` and dies on the
    UNCRAFTED pinned literal rather than here. An earlier version of this
    docstring claimed it shifts by `48 & 31` and prints `#0xc0450000` — the
    hardware's masked shift, which the compiler does not use.
    """
    dex = _craft(
        tmp_path, bytes([0x19, 0x00, 0xF8, 0x7F]), bytes([0x19, 0x00, 0x45, 0xC0]), 2
    )
    dk = dexllm.DexKit(str(dex))
    found = []
    for cls in dk.list_classes():
        found += [
            (mn, f"{v:x}") for _, mn, _, v in _high16_lines(_render(dk, cls, api))
        ]
    wide = [v for mn, v in found if mn == "const-wide/high16"]
    assert wide and all(v == "c045000000000000" for v in wide), found
    assert len(wide) == 2, wide


@pytest.mark.parametrize("api", _APIS)
def test_a_high_register_high16_renders_its_value(tmp_path, api):
    """A `const/high16` on v5 must still print the shifted value.

    Every naturally-occurring fixture site is v0, v1 or v3, and both other
    crafts preserve the opcode+AA byte, so the whole CI leg's value coverage sat
    at `vA <= 3`. An adversarial review built the mutant: zero the operand when
    `insn.vA > 3`, and the only case that failed was the corpus-GATED
    `ALauncher` one — green in the corpus-less leg while **4,407 of 9,349 corpus
    sites (47.1%)** rendered a zero. `_assert_is_bbbb_shifted` cannot see it
    either, since 0 satisfies all three of its properties.

    The four natural sites live in a `.registers 4` method, so re-pointing an AA
    byte there is an out-of-range register the gate rejects. This craft
    OVERWRITES a two-code-unit `const-class v2` in
    `LMain;->TestUninitializedCallSite()V` (`.registers 7`) — same length,
    register in range, and `_craft` asserts the result still verifies in both
    modes.
    """
    dex = _craft(
        tmp_path,
        bytes([0x1C, 0x02, 0x2C, 0x00]),  # const-class v2, <type 0x2c>
        bytes([0x15, 0x05, 0x80, 0xBF]),  # const/high16 v5, #0xbf80
        1,
        same_insn=False,
    )
    dk = dexllm.DexKit(str(dex))
    found = []
    for cls in dk.list_classes():
        found += [
            (mn, reg, f"{v:x}")
            for _, mn, reg, v in _high16_lines(_render(dk, cls, api))
        ]
    assert ("const/high16", "v5", "bf800000") in found, found


# --------------------------------------------------------------------------
# An independent oracle: the raw dex bytes, decoded here
# --------------------------------------------------------------------------


def _uleb(buf, p):
    r = s = 0
    while True:
        b = buf[p]
        p += 1
        r |= (b & 0x7F) << s
        if not b & 0x80:
            return r, p
        s += 7


def _code_items(buf):
    """`(code_off, insns_size)` for every method with code, from class_data.

    Walks `class_defs` -> `class_data` with its own parser, so the oracle never
    asks the renderer where an instruction is. Each of the four member lists
    restarts its own delta chain (the rule dexllm#48 exists for).
    """
    out = []
    cds_size, cds_off = struct.unpack_from("<II", buf, 0x60)
    for i in range(cds_size):
        cdo = struct.unpack_from("<I", buf, cds_off + i * 32 + 24)[0]
        if not cdo:
            continue
        p = cdo
        sf, p = _uleb(buf, p)
        inf, p = _uleb(buf, p)
        dm, p = _uleb(buf, p)
        vm, p = _uleb(buf, p)
        for _ in range(sf + inf):
            _, p = _uleb(buf, p)
            _, p = _uleb(buf, p)
        for n in (dm, vm):
            for _ in range(n):
                _, p = _uleb(buf, p)
                _, p = _uleb(buf, p)
                co, p = _uleb(buf, p)
                if co:
                    insns_size = struct.unpack_from("<I", buf, co + 12)[0]
                    out.append((co, insns_size))
    return out


_TABLE = (
    pathlib.Path(__file__).resolve().parents[1]
    / "vendor/dexkit_core/Core/third_party/slicer/export/slicer/dex_instruction_list.h"
)
_ROW = re.compile(r'\s*V\(\s*(0x[0-9A-Fa-f]{2}),\s*\w+,\s*"([^"]*)",\s*k(\w+),')


def _opcode_widths():
    """`{opcode: code_units}` for every NAMED opcode, from the slicer's own table.

    The format NAME carries the width: `k21h` is 2 code units, `k32x` is 3,
    `k51l` is 5 — asserted below over all 256 rows, so a format whose name does
    not start with its unit count fails loudly instead of being guessed at.

    Derived rather than hand-written, which is the house pattern two files over
    (`test_smali_instruction_formats.py`, `test_invoke_opcode_gates.py`): the
    table is a source INDEPENDENT of the renderer — they read different fields of
    the same rows — while a hand table is a second implementation that drifts.
    The first cut of this oracle DID hand-write one and was wrong for NINE named
    opcodes, `const-string` and `goto` among them, which a correctness review
    found by deriving exactly this. It desynced on the fixture it ran on (1,847
    positions visited where 1,761 are instructions) and on `TestActivity.apk` it
    MISSED two real sites — the direction that would let a renderer dropping the
    same sites AGREE with it.
    """
    rows = [m.groups() for m in map(_ROW.match, _TABLE.read_text().splitlines()) if m]
    assert len(rows) == 256, f"the slicer table parsed to {len(rows)} rows, not 256"
    out = {}
    for op, mnemonic, fmt in rows:
        if mnemonic.startswith("unused"):
            continue
        assert fmt[0].isdigit(), f"format k{fmt} does not start with its unit count"
        out[int(op, 16)] = int(fmt[0])
    return out


_WIDTH = _opcode_widths()


def _oracle_high16(buf):
    """Every high16 the raw bytes carry, as (code_off, byte_off, opcode, value).

    A linear decode over each code item, with widths from the slicer table (see
    `_opcode_widths`) and the three payload length rules spelled out, since a
    payload's length is in its own header rather than in any opcode table. It
    never asks the RENDERER anything, which is the point: an oracle built from
    the thing under test can only confirm it.

    An opcode the table does not name (an `unused-*` row) ends the walk for that
    code item rather than being assumed 2 units wide — a guess there would
    silently desync the rest of the method, which is the failure mode this
    function's first cut had.
    """
    out = []
    for co, isz in _code_items(buf):
        base = co + 16
        i = 0
        while i < isz:
            op = buf[base + i * 2]
            if op == 0x00:  # nop, or a payload whose length is in its own header
                ident = struct.unpack_from("<H", buf, base + i * 2)[0]
                if ident == 0x0100:  # packed-switch
                    n = struct.unpack_from("<H", buf, base + i * 2 + 2)[0]
                    i += 4 + n * 2
                    continue
                if ident == 0x0200:  # sparse-switch
                    n = struct.unpack_from("<H", buf, base + i * 2 + 2)[0]
                    i += 2 + n * 4
                    continue
                if ident == 0x0300:  # fill-array-data
                    w = struct.unpack_from("<H", buf, base + i * 2 + 2)[0]
                    n = struct.unpack_from("<I", buf, base + i * 2 + 4)[0]
                    i += 4 + (n * w + 1) // 2
                    continue
            if op in (0x15, 0x19):
                bbbb = struct.unpack_from("<H", buf, base + i * 2 + 2)[0]
                out.append((co, i * 2, op, bbbb << (48 if op == 0x19 else 16)))
            w = _WIDTH.get(op)
            if w is None:  # an unused-* row: stop rather than guess
                break
            i += w
    return out


def test_the_oracles_width_table_is_the_slicers(fx):
    """The derived widths agree with the renderer on where instructions START.

    Without this the oracle can be wrong in the direction that MASKS a defect:
    a desynced walk under-reports, so a renderer dropping the same sites agrees
    with it. Compared against the rendered instruction OFFSETS, which the
    renderer derives through the slicer's decoder rather than this table.
    """
    buf = fx.extract_dex(0)["bytes"]
    rendered = set()
    for cls in fx.list_classes():
        for off, _ in _insn_lines(fx.render_class_smali(cls)):
            rendered.add(off)
    # every position the oracle VISITS inside a code item must be an offset the
    # renderer also starts an instruction at (offsets are per-method, so this is
    # a containment check over the union — enough to catch a desync, which
    # produces positions no method starts an instruction at)
    visited = set()
    for co, isz in _code_items(buf):
        base = co + 16
        i = 0
        while i < isz:
            visited.add(i * 2)
            op = buf[base + i * 2]
            if op == 0x00:
                ident = struct.unpack_from("<H", buf, base + i * 2)[0]
                if ident in (0x0100, 0x0200, 0x0300):
                    break  # payloads are not rendered as instructions
            w = _WIDTH.get(op)
            if w is None:
                break
            i += w
    assert visited, "the oracle visited nothing"
    stray = sorted(visited - rendered)
    assert (
        not stray
    ), f"{len(stray)} oracle positions are not instruction offsets: {stray[:8]}"


def _oracle_vs_renderer(dk, dex_id=0):
    """(oracle multiset, rendered multiset) of (opcode, value) for one dex.

    MULTISETS because the oracle walks code items in class_data order and the
    renderer in class order. Restricted to the classes that dex DECLARES, so a
    multi-dex source compares like with like.
    """
    buf = dk.extract_dex(dex_id)["bytes"]
    want = sorted((op, v) for _, _, op, v in _oracle_high16(buf))
    got = []
    for cls in dk.list_classes():
        if dk.locate_class_dex(cls) != dex_id:
            continue
        for _, mn, _, v in _high16_lines(dk.render_class_smali(cls)):
            got.append((0x19 if mn == "const-wide/high16" else 0x15, v))
    return want, sorted(got)


def test_an_independent_decode_agrees_with_every_rendered_high16(fx):
    """The printed value equals `BBBB << shift` taken from the raw bytes.

    The oracle parses `class_defs` -> `class_data` -> `code_item` and decodes the
    instruction stream itself, so agreement is between two implementations rather
    than within one.

    On the FIXTURE this is redundant: `_FIXTURE_SITES` pins all 6 of 6 sites as
    exact strings, so the oracle never fails alone here — a correctness review
    measured exactly that. Its teeth are the corpus case below, which is also
    what would have caught the first cut's wrong width table immediately.
    """
    want, got = _oracle_vs_renderer(fx)
    assert want, "the oracle found no high16 — it has stopped decoding"
    assert got == want


def test_an_independent_decode_agrees_over_the_whole_corpus(loadable_apks):
    """The same two implementations, over every loadable sample.

    This is where the oracle earns its place: thousands of sites across real
    dexes, where the pinned literals reach six. A wrong width table desyncs and
    UNDER-reports, so this comparison is what separates "the renderer is right"
    from "two implementations are wrong together".
    """
    total = 0
    for path in loadable_apks:
        dk = dexllm.DexKit(path)
        for d in range(dk.dex_count()):
            want, got = _oracle_vs_renderer(dk, d)
            assert (
                got == want
            ), f"{path} dex {d}: oracle {len(want)} vs rendered {len(got)}"
            total += len(want)
    require_corpus_shape(
        total > 0,
        "const/high16 instruction the oracle can decode",
        "the oracle stopped decoding, or the renderer stopped emitting them",
    )


def test_the_corpus_renders_only_well_formed_high16_literals(loadable_apks):
    """Over the whole corpus: every printed value IS `BBBB << shift`.

    The strong form of the fix as a property rather than a sample — a raw `BBBB`
    would fail the `>> shift` bound for anything with a set bit above the 16th,
    and a wrong-width shift fails the digit count.
    """
    sites = 0
    for path in loadable_apks:
        dk = dexllm.DexKit(path)
        for cls in dk.list_classes():
            text = dk.render_class_smali(cls)
            if "high16" not in text:
                continue
            for _, mn, _, v in _high16_lines(text):
                sites += 1
                _assert_is_bbbb_shifted(mn, v, cls)
    require_corpus_shape(
        sites > 0,
        "const/high16 instruction",
        "the renderer stopped emitting them, or the parser stopped matching",
    )


def test_the_two_views_of_one_high16_agree(loadable_apks):
    """The issue's own evidence: `Intent.FLAG_ACTIVITY_NEW_TASK` on a2dp.Vol.

    `addFlags(0x10000000)` is `const/high16 v5, #0x1000` in the dex. Before
    dexllm#87 the smali view printed `#0x1000` and the Java view `268435456`,
    so a reader searching the listing for the flag found nothing — which is how
    the defect was found. Scoped to the ONE class the issue names, by value, so
    the case says what it is rather than scanning for a coincidence.
    """
    found = False
    for path in loadable_apks:
        dk = dexllm.DexKit(path)
        if dk.locate_class_dex("La2dp/Vol/ALauncher;") < 0:
            continue
        smali = dk.render_class_smali("La2dp/Vol/ALauncher;")
        java = dk.decompile_class("La2dp/Vol/ALauncher;")
        hits = [v for _, _, _, v in _high16_lines(smali)]
        if 0x10000000 not in hits:
            continue
        found = True
        assert "268435456" in java, "the Java view lost the flag"
        # both views now spell the int the same way, so a reader can search for
        # the one token and land in either listing
        assert "#268435456(0x10000000, float:2.524355E-29)" in smali
        assert "#0x1000\n" not in smali and not smali.endswith("#0x1000")
    require_corpus_shape(
        found,
        "a2dp.Vol ALauncher const/high16 #0x1000 site",
        "the renderer or the sample changed; this is the issue's own evidence",
    )


# --------------------------------------------------------------------------
# Cross-view gate: the SAME instruction, read by independent readers.
#
# The rule "BBBB is the high half" is implemented FIVE times in the tree, and
# FOUR are reachable from dexllm's surface: `smali_render.cpp` (this fix),
# `invoke_args.cpp` (resolve_call_args), `opcode_ins.cpp` (the decompiler) and
# the vendored DexKit `PushEncodeNumber` (find_methods_using_{int,double}_literals).
# The fifth, slicer's `code_ir.cc:590`, is not called by dexllm. dexllm#87 was
# ONE of those readings omitting the shift. Pinned literals catch a reader that drifts on a pinned value; this
# catches any reader drifting on ANY value that reaches a call, because it
# compares the readers to EACH OTHER.
# --------------------------------------------------------------------------

_ENDS_BLOCK = ("goto", "return", "throw", "packed-switch", "sparse-switch")
_WRITES_NOTHING = (
    "invoke",
    "if-",
    "iput",
    "sput",
    "aput",
    "return",
    "throw",
    "monitor",
    "fill-array",
    "packed-switch",
    "sparse-switch",
    "goto",
    "check-cast",
    "nop",
)


def _written_regs(mn, ops):
    if mn.startswith(_WRITES_NOTHING):
        return set()
    m = re.match(r"v(\d+)\b", ops)
    if not m:
        return set()
    r = int(m.group(1))
    # a 64-bit result occupies a register PAIR: `*-wide`, and the arithmetic /
    # conversion forms whose result is long or double (`add-long`,
    # `int-to-double`, `mul-double/2addr`, ...). `cmp-long` writes an int.
    wide = "-wide" in mn or re.search(r"-(long|double)(/2addr)?$", mn)
    return {r, r + 1} if wide and not mn.startswith("cmp") else {r}


def _java_forms(bits, width):
    """Every spelling the Writer can give these bits at a call argument.

    The integer reading, the round-trip float/double reading, and the named
    constants the Writer substitutes where a literal does not exist (NaN, the
    two infinities) -- a high16 encodes all three exactly, e.g. 0x7f80 is
    `Float.POSITIVE_INFINITY`.
    """
    import math

    if width == 32:
        signed = bits - (1 << 32) if bits >> 31 else bits
        x = struct.unpack("<f", struct.pack("<I", bits))[0]
        forms, box = {str(signed), ("%.9g" % x) + "f"}, "Float"
    else:
        signed = bits - (1 << 64) if bits >> 63 else bits
        x = struct.unpack("<d", struct.pack("<Q", bits))[0]
        forms, box = {str(signed), str(signed) + "L", "%.17g" % x}, "Double"
    if math.isnan(x):
        forms.add(f"{box}.NaN")
    elif math.isinf(x):
        forms.add(f"{box}.{'POSITIVE' if x > 0 else 'NEGATIVE'}_INFINITY")
    return forms


def _cross_view(dk):
    """(method, invoke offset, smali bits, resolve_call_args value, java line).

    A pair is formed only where the high16 DEFINES the argument register in the
    same straight-line stretch as the call (the backward scan stops at the
    first block-ending instruction), so the pairing does not depend on control
    flow -- the first cut of this oracle paired across a switch arm and
    reported three disagreements that were its own error, not the product's.
    `java` is None when the call's offset anchors no Java line (pc_map keeps
    the FIRST anchor per line, so a call folded into an earlier statement has
    none); such pairs are still checked smali-vs-resolve.
    """
    out = []
    for c in dk.list_classes():
        if "high16" not in dk.render_class_smali(c):
            continue
        for m in dk.list_class_methods(c):
            text = dk.render_method_smali(m)
            if "high16" not in text:
                continue
            ins = []
            for line in text.split("\n"):
                g = re.match(r"^\s*0x([0-9a-f]+): (\S+)\s*(.*)$", line)
                if g:
                    ins.append((int(g.group(1), 16), g.group(2), g.group(3)))
            jmap = jlines = None
            for site in dk.find_call_sites_from(m):
                for rs in dk.resolve_call_args(site.callee_descriptor):
                    if (rs.caller_descriptor, rs.bytecode_offset) != (
                        m,
                        site.bytecode_offset,
                    ):
                        continue
                    for a in rs.args:
                        if a.kind not in ("ConstInt", "ConstWide") or a.crossed_branch:
                            continue
                        d = None
                        for off, mn, ops in reversed(
                            [x for x in ins if x[0] < rs.bytecode_offset]
                        ):
                            if mn.startswith(_ENDS_BLOCK):
                                break
                            if a.register_index in _written_regs(mn, ops):
                                d = (mn, ops)
                                break
                        if d is None or "high16" not in d[0]:
                            continue
                        width = 64 if "wide" in d[0] else 32
                        ((_, _, _, bits),) = _high16_lines(f"0x0: {d[0]} {d[1]}")
                        if jmap is None:
                            r = dk.decompile_method_with_pc_map(m)
                            jlines = r["source"].split("\n")
                            jmap = {}
                            for ln, off in r["pc_map"]:
                                jmap.setdefault(off, ln)
                        ln = jmap.get(rs.bytecode_offset)
                        java = jlines[ln - 1] if ln else None
                        out.append(
                            (m, rs.bytecode_offset, bits, width, a.int_value, java)
                        )
                    break
    return out


def _assert_views_agree(pairs):
    for m, off, bits, width, resolved, java in pairs:
        assert bits == resolved & ((1 << width) - 1), (
            f"{m} @0x{off:x}: smali says 0x{bits:x}, resolve_call_args says "
            f"{resolved} -- two readers of one instruction disagree"
        )
        if java is None:
            continue
        # a numeric token must not be the tail of an identifier (`v0`, `p2`)
        toks = set(
            re.findall(
                r"(?<![\w.$])-?[0-9][0-9.e+\-]*[fL]?|Float\.\w+|Double\.\w+", java
            )
        )
        assert toks & _java_forms(bits, width), (
            f"{m} @0x{off:x}: smali/resolve say 0x{bits:x}, the Java line "
            f"carries none of its spellings: {java.strip()!r}"
        )


def test_three_readers_agree_on_the_committed_fixture(fx):
    """The two call-argument high16s in `LTestLinkerUnrelatedBSM;->test()V`."""
    pairs = _cross_view(fx)
    got = sorted((p[2], p[5] is not None) for p in pairs)
    # non-vacuity: both sites are reached AND both anchor a Java line
    assert got == [(0x3FC00000, True), (0x40200000, True)], got
    _assert_views_agree(pairs)


def test_three_readers_agree_on_a_top_bit_set_high16(tmp_path):
    """`2.5f` (0x4020) rewritten to `-1.0f` (0xbf80) at its call argument.

    The fixture's own values all have `BBBB < 0x8000`, where a reader that
    sign-extends the operand before shifting agrees with one that does not --
    so this is the case that separates them, in all three readers at once.
    """
    dex = _craft(
        tmp_path, bytes([0x15, 0x03, 0x20, 0x40]), bytes([0x15, 0x03, 0x80, 0xBF]), 1
    )
    pairs = _cross_view(dexllm.DexKit(str(dex)))
    assert sorted(p[2] for p in pairs) == [0x3FC00000, 0xBF800000], pairs
    assert all(p[5] is not None for p in pairs)
    _assert_views_agree(pairs)


def test_three_readers_agree_over_the_whole_corpus(loadable_apks):
    """Every high16 that reaches a call argument in a straight line, corpus-wide.

    `loadable_apks` is the `.apk` corpus only. Measured over it: 2,610
    smali-vs-resolve pairs, all equal, of which 1,164 also anchor a Java line,
    all carrying the value. (docs/hack-gate.md's 2,847 / 1,270 adds the bare
    `.dex` corpus files and the committed fixture.) Applying the pre-fix
    rendering to the same pairs makes 415 of 415 disagree on tvleanback +
    invoke-custom.dex, so the comparison is not satisfied vacuously.
    """
    pairs = []
    for path in loadable_apks:
        pairs += _cross_view(dexllm.DexKit(path))
    require_corpus_shape(
        any(p[5] is not None for p in pairs),
        "a const/high16 call argument anchored on a Java line",
        "the cross-view pairing found nothing to compare",
    )
    _assert_views_agree(pairs)


def test_three_readers_agree_on_a_wide_high16(tmp_path):
    """A `const-wide/high16` call argument, which no committed fixture carries.

    The fixture's two call-argument sites are both narrow, so before this case
    the WIDE half of every reader had no cross-view coverage in the CI leg: an
    adversarial review built `resolve_call_args` with `<< 32` for the wide form
    and the corpus-less run stayed green. `const-wide/16 v1, #0` feeding
    `Double.valueOf(D)` in `TestDynamicBootstrapArguments.testCallSites()V` is
    rewritten to `const-wide/high16 v1, #0xc045` (-42.0) -- both are 2 code
    units, so the craft is length-preserving.
    """
    dex = _craft(
        tmp_path,
        bytes([0x16, 0x01, 0x00, 0x00]),
        bytes([0x19, 0x01, 0x45, 0xC0]),
        1,
        same_insn=False,
    )
    dk = dexllm.DexKit(str(dex))
    pairs = _cross_view(dk)
    wide = [p for p in pairs if p[3] == 64]
    # smali == resolve_call_args on the wide pair (the call anchors no Java line
    # of its own: the decompiler folds it into the statement after it)
    assert [p[2] for p in wide] == [0xC045000000000000], pairs
    _assert_views_agree(pairs)
    # ...so the third reader is checked by value, scoped to this one call: the
    # decompiler must render the same -42.0 the other two readers loaded
    java = dk.decompile_method("LTestDynamicBootstrapArguments;->testCallSites()V")
    assert "Double.valueOf(-42)" in java, java


def test_three_readers_agree_on_an_infinite_high16(tmp_path):
    """`2.5f` rewritten to `+Infinity` (0x7f80), which has no float literal.

    The Writer spells it `Float.POSITIVE_INFINITY`. The oracle's first cut
    special-cased NaN only, so it FAILED on this correct output -- a correctness
    review crafted it; the bundled corpus happens to carry none, but another
    corpus would.
    """
    dex = _craft(
        tmp_path, bytes([0x15, 0x03, 0x20, 0x40]), bytes([0x15, 0x03, 0x80, 0x7F]), 1
    )
    pairs = _cross_view(dexllm.DexKit(str(dex)))
    inf = [p for p in pairs if p[2] == 0x7F800000]
    assert len(inf) == 1 and "Float.POSITIVE_INFINITY" in (inf[0][5] or ""), pairs
    _assert_views_agree(pairs)


def _number_matcher_misses(dk):
    """High16 sites the vendored number matcher fails to find by their value.

    Fourth reader: DexKit's `PushEncodeNumber`, reached through
    `find_methods_using_{int,double}_literals`. A narrow site is queried by its
    signed 32-bit value, a wide one by its double. NaN and the infinities are
    SKIPPED, and not because of the decoding: the matcher compares floating
    values as `abs(a - b) < EPS` (`dex_item_matcher.cpp`), which is never true
    for NaN or for inf - inf, so no query can find them whatever the reader did.
    Returns (checked, misses).
    """
    import math

    want = {}
    for c in dk.list_classes():
        if "high16" not in dk.render_class_smali(c):
            continue
        for m in dk.list_class_methods(c):
            for _, mn, _, v in _high16_lines(dk.render_method_smali(m)):
                want.setdefault((mn, v), set()).add(m)
    checked, misses = 0, []
    for (mn, bits), methods in want.items():
        if mn == "const/high16":
            q = bits - (1 << 32) if bits >> 31 else bits
            got = {r.descriptor for r in dk.find_methods_using_int_literals([q])}
        else:
            q = struct.unpack("<d", struct.pack("<Q", bits))[0]
            if math.isnan(q) or math.isinf(q):
                continue
            got = {r.descriptor for r in dk.find_methods_using_double_literals([q])}
        checked += len(methods)
        misses += [(mn, hex(bits), m) for m in methods - got]
    return checked, misses


def test_the_number_matcher_finds_each_high16_by_its_value(tmp_path):
    """The fourth reader, on the fixture's narrow sites and both top-bit crafts."""
    checked, misses = _number_matcher_misses(dexllm.DexKit(str(FIXTURE)))
    assert checked >= 4 and not misses, (checked, misses)
    for pat, rep_ in (
        (bytes([0x15, 0x03, 0x20, 0x40]), bytes([0x15, 0x03, 0x80, 0xBF])),
        (bytes([0x19, 0x00, 0xF8, 0x7F]), bytes([0x19, 0x00, 0x45, 0xC0])),
    ):
        sub = tmp_path / rep_.hex()
        sub.mkdir()
        dex = _craft(sub, pat, rep_, 1 if pat[0] == 0x15 else 2)
        checked, misses = _number_matcher_misses(dexllm.DexKit(str(dex)))
        assert not misses, misses
        # non-vacuity: the crafted value itself was among those checked
        hits = [
            v
            for c in dexllm.DexKit(str(dex)).list_classes()
            for _, _, _, v in _high16_lines(
                dexllm.DexKit(str(dex)).render_class_smali(c)
            )
        ]
        assert (0xBF800000 if pat[0] == 0x15 else 0xC045000000000000) in hits


def test_the_number_matcher_finds_each_high16_over_the_corpus(loadable_apks):
    """Measured over the `.apk` corpus `loadable_apks` scans: 7,373 (method,
    value) pairs queried, 0 missed. Adding the bare `.dex` files and the
    committed fixture: narrow 7,181 / 7,181 and finite wide 808 / 808; the other
    41 wide sites are NaN / +-Inf, which the matcher's EPS comparison cannot
    match whatever the reader did.
    """
    checked = 0
    for path in loadable_apks:
        n, misses = _number_matcher_misses(dexllm.DexKit(path))
        checked += n
        assert not misses, (path, misses[:5])
    require_corpus_shape(
        checked > 0,
        "a const/high16 site",
        "the number-matcher cross-check found nothing to query",
    )


# Java's own spelling of each reading, from `Float.toString` / `Double.toString`
# on a JDK 21 (the shortest round-trip string, JDK 19+). Chosen at the branches
# of Java's layout rule: zero and -0.0, a subnormal, either side of 1e-3 and of
# 1e7 (where plain notation turns into `E` notation), the two infinities, NaN.
_JDK21_NARROW = {
    0x0000: None,  # value 0 is under jadx's |v| > 100 threshold: bare `#0`
    0x0001: "9.1835E-41",
    0x8000: "-0.0",
    0x3A83: "9.994507E-4",
    0x3A84: "0.0010070801",
    0x4B18: "9961472.0",
    0x4B19: "1.0027008E7",
    0x7F80: "Infinity",
    0xFF80: "-Infinity",
    0x7FC0: "NaN",
    0x3F80: "1.0",
    0xBF80: "-1.0",
}
_JDK21_WIDE = {
    0x0000: None,
    0x0001: "1.390671161567E-309",
    0x8000: "-0.0",
    0x3F50: "9.765625E-4",
    0x3F51: "0.00103759765625",
    0x4163: "9961472.0",
    0x4164: "1.048576E7",
    0x7FF0: "Infinity",
    0xFFF0: "-Infinity",
    0xFFF8: "NaN",
    0xC045: "-42.0",
}


def _expected_line(wide, reg, bbbb, reading):
    width, shift = (64, 48) if wide else (32, 16)
    bits = bbbb << shift
    v = bits - (1 << width) if bits >> (width - 1) else bits
    mn = "const-wide/high16" if wide else "const/high16"
    if reading is None:
        return f"{mn} {reg}, #{v}"
    kind = "double" if wide else "float"
    return f"{mn} {reg}, #{v}(0x{bits:x}, {kind}:{reading})"


@pytest.mark.parametrize(
    "wide,bbbb",
    [(False, b) for b in _JDK21_NARROW] + [(True, b) for b in _JDK21_WIDE],
)
def test_the_reading_is_spelled_as_java_spells_it(tmp_path, wide, bbbb):
    """Each edge of Java's float layout, crafted onto a fixture site."""
    if wide:
        pat, n, cls = bytes([0x19, 0x00, 0xF8, 0x7F]), 2, "LTestInvocationKinds;"
        reg, reading = "v0", _JDK21_WIDE[bbbb]
    else:
        pat, n, cls = bytes([0x15, 0x03, 0x20, 0x40]), 1, "LTestLinkerUnrelatedBSM;"
        reg, reading = "v3", _JDK21_NARROW[bbbb]
    dex = _craft(tmp_path, pat, pat[:2] + bbbb.to_bytes(2, "little"), n)
    text = dexllm.DexKit(str(dex)).render_class_smali(cls)
    lines = [ins for _, ins in _insn_lines(text) if "high16" in ins]
    assert _expected_line(wide, reg, bbbb, reading) in lines, lines


def _jdk_and_smali():
    """(java >= 19, a jar carrying the smali assembler), or None."""
    import glob
    import shutil
    import subprocess

    javas = [
        os.environ.get("DEXLLM_JDK19_JAVA", ""),
        "/opt/android-studio/jbr/bin/java",
        shutil.which("java") or "",
    ]
    jars = [os.environ.get("DEXLLM_SMALI_JAR", "")] + sorted(
        glob.glob(os.path.expanduser("~/analysis_tool/jadx-*/lib/jadx-*-all.jar"))
    )
    jar = next((j for j in jars if j and os.path.isfile(j)), None)
    for j in javas:
        if not j or not os.path.isfile(j):
            continue
        out = subprocess.run([j, "-version"], capture_output=True, text=True)
        m = re.search(r'version "(\d+)', out.stderr)
        if m and int(m.group(1)) >= 19 and jar:
            return j, jar
    return None


def test_every_high16_reading_matches_a_jdk_exhaustively(tmp_path):
    """All 65,536 BBBB x both opcodes, against a real JDK's `toString`.

    A DEV-time oracle, like the jadx-parity gate: it needs a JDK 19+ and a jar
    carrying the smali assembler (jadx's all-in-one jar does), and SKIPS
    without them. The pinned table above is what holds in CI; this is what
    says the table is not a lucky sample.
    """
    import subprocess

    found = _jdk_and_smali()
    if found is None:
        pytest.skip("no JDK 19+ with a smali-assembler jar on this machine")
    java, jar = found
    lines = [".class public LX;", ".super Ljava/lang/Object;"]
    for wide in (False, True):
        mn, shift, sfx = (
            ("const-wide/high16", 48, "L") if wide else ("const/high16", 16, "")
        )
        for chunk in range(64):
            lines += [f".method public static m{int(wide)}_{chunk}()V", ".registers 2"]
            lines += [
                f"{mn} v0, 0x{b << shift:x}{sfx}"
                for b in range(chunk * 1024, (chunk + 1) * 1024)
            ]
            lines += ["return-void", ".end method"]
    (tmp_path / "X.smali").write_text("\n".join(lines) + "\n")
    subprocess.run(
        [
            java,
            "-cp",
            jar,
            "com.android.tools.smali.smali.Main",
            "a",
            str(tmp_path / "X.smali"),
            "-o",
            str(tmp_path / "X.dex"),
        ],
        check=True,
        capture_output=True,
    )
    (tmp_path / "J.java").write_text(
        "public class J{public static void main(String[] a){"
        "StringBuilder sb=new StringBuilder();"
        "for(int b=0;b<65536;b++)sb.append(Float.toString("
        "Float.intBitsToFloat(b<<16))).append('\\n');"
        "for(long b=0;b<65536;b++)sb.append(Double.toString("
        "Double.longBitsToDouble(b<<48))).append('\\n');"
        "System.out.print(sb);}}"
    )
    want = subprocess.run(
        [java, str(tmp_path / "J.java")], check=True, capture_output=True, text=True
    ).stdout.split("\n")[:131072]
    text = dexllm.DexKit(str(tmp_path / "X.dex")).render_class_smali("LX;")
    got = [ins for _, ins in _insn_lines(text) if "high16" in ins]
    assert len(got) == 131072
    # the listing orders methods by name, not by value: key each line by the
    # BBBB it carries, and require every (opcode, BBBB) exactly once
    bad, seen = [], set()
    for ins in got:
        wide = ins.startswith("const-wide/high16")
        v = int(re.match(r"\S+ v0, #(-?\d+)", ins).group(1))
        bits = v & ((1 << (64 if wide else 32)) - 1)
        b = bits >> (48 if wide else 16)
        seen.add((wide, b))
        reading = None if b == 0 else want[65536 * wide + b]
        exp = _expected_line(wide, "v0", b, reading)
        if ins != exp:
            bad.append((ins, exp))
    assert len(seen) == 131072
    assert not bad, (len(bad), bad[:5])


def test_k21h_carries_exactly_the_two_opcodes_the_arm_branches_on():
    """Derived from the slicer table: `k21h` is `{0x15, 0x19}` and nothing else.

    The arm is a ternary, so it fails OPEN — a third `k21h` opcode would silently
    take the `<< 16` branch whatever its real width. The format audit two files
    over cannot see that (`k21h` IS handled), and nothing else in `tests/` names
    these opcodes, so a correctness review asked for the house pattern:
    `test_smali_instruction_formats.py` and `test_invoke_opcode_gates.py` both
    derive their truth set from this table rather than trusting a constant.

    Dalvik is frozen, so this is a low-likelihood guard — but it is the one that
    would say WHY, instead of a wrong literal somewhere downstream.
    """
    rows = [m.groups() for m in map(_ROW.match, _TABLE.read_text().splitlines()) if m]
    assert len(rows) == 256, f"the slicer table parsed to {len(rows)} rows, not 256"
    k21h = {
        int(op, 16)
        for op, mnemonic, fmt in rows
        if fmt == "21h" and not mnemonic.startswith("unused")
    }
    assert k21h == {0x15, 0x19}, (
        f"k21h now carries {sorted(hex(o) for o in k21h)} — the smali renderer's "
        "arm branches on OP_CONST_WIDE_HIGH16 and treats everything else as "
        "<< 16, so a new opcode needs its own width there"
    )
    # and the arm must still be the one that branches, rather than having been
    # simplified back to a single shift
    src = (
        pathlib.Path(__file__).resolve().parents[1] / "native/core_ext/smali_render.cpp"
    ).read_text()
    i = src.index("case k21h:")
    j = src.index("case k21s:", i)
    arm = src[i:j]
    assert (
        "OP_CONST_WIDE_HIGH16" in arm
    ), "the k21h arm no longer branches on the opcode"
    assert "<< 48" in arm and "<< 16" in arm, "the k21h arm lost one of its two widths"


def test_the_fixture_is_the_only_committed_carrier():
    """Non-vacuity: the crafts rest on this fixture having the shape.

    Declared NON-DISCRIMINATING by design — it must hold on both sides of the
    fix. It is here so that a fixture swap fails with the reason rather than
    turning the two crafts into assertions about nothing.
    """
    if corpus_is_narrowed():
        pass  # the fixture is committed; a narrowing cannot remove it
    dk = dexllm.DexKit(str(FIXTURE))
    n = sum(len(_high16_lines(dk.render_class_smali(c))) for c in dk.list_classes())
    assert n == 6, f"the committed fixture carries {n} high16 sites, expected 6"
