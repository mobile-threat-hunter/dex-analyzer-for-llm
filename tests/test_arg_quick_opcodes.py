"""A write the analyzer does not model must not leave a value behind (dexllm#32).

The companion :mod:`test_arg_opcode_coverage` reads the SOURCE and proves the opcode
enumeration is complete. It cannot prove the branches it counts actually clear
anything — a body changed to a no-op keeps its `case` labels, and a label moved into
a comment still reads as handled. This module drives the built extension instead, on
dexes crafted to carry the instruction.

Every craft is length-preserving, so every offset, section size and structural check
is untouched and the result still verifies STRICT-valid — which is the point:
`VerifyInsns` bounds registers and indices and has no opcode-legality gate, so these
instructions reach the analyzer in both strict and lenient mode.

Three properties, each a way for a stale origin to be reported as unconditional:

* an unhandled WRITE (the seven ART `iget-*-quick` forms) — pre-fix the argument came
  back as the `const-string` the instruction had overwritten;
* a WIDE write that forgets its high half;
* a NARROW write that forgets it destroyed an aliased wide origin parked one register
  below (the dexllm#32 adversarial-review finding).

Plus the negative: `check-cast` must NOT clear, because its whole point is that the
value is unchanged. That one runs on unmodified corpus code.
"""

from __future__ import annotations

import re
import struct

import pytest
from conftest import require_corpus_shape

import dexllm

_IGET_OBJECT = 0x54
# The seven runtime-only forms the fix added. `iget-wide-quick` (0xE4) is the wide one.
_QUICK_IGETS = (0xE3, 0xE4, 0xE5, 0xEF, 0xF0, 0xF1, 0xF2)
_IGET_WIDE_QUICK = 0xE4
_CONST_4 = 0x12
_CONST_STRING = 0x1A

# How many classes to scan before giving up. The shapes are ordinary code; this only
# bounds the worst case on a large sample.
_SCAN_LIMIT = 400


# --------------------------------------------------------------------------
# A minimal raw-dex reader. Deliberately independent of DexKit: it locates the
# byte to patch, and using the component under test to aim at itself would let
# the fixture agree with the bug.
# --------------------------------------------------------------------------
def _uleb(buf: bytes, p: int) -> tuple[int, int]:
    r = s = 0
    while True:
        b = buf[p]
        p += 1
        r |= (b & 0x7F) << s
        s += 7
        if not b & 0x80:
            return r, p


def _string(buf: bytes, idx: int) -> str:
    off = struct.unpack_from(
        "<I", buf, struct.unpack_from("<II", buf, 56)[1] + 4 * idx
    )[0]
    _, q = _uleb(buf, off)
    return buf[q : buf.index(0, q)].decode("utf-8", "replace")


def _method_idx(buf: bytes, descriptor: str) -> int | None:
    """The `method_ids` row spelling `descriptor`, found by (class, name, proto)."""
    cls, rest = descriptor.split("->", 1)
    name, proto_tail = rest.split("(", 1)
    proto = "(" + proto_tail

    ti_off = struct.unpack_from("<II", buf, 64)[1]
    _pi_size, pi_off = struct.unpack_from("<II", buf, 72)
    mi_size, mi_off = struct.unpack_from("<II", buf, 88)

    def type_str(ti: int) -> str:
        return _string(buf, struct.unpack_from("<I", buf, ti_off + 4 * ti)[0])

    def proto_str(pi: int) -> str:
        ret, params_off = struct.unpack_from("<II", buf, pi_off + pi * 12 + 4)
        args = ""
        if params_off:
            n = struct.unpack_from("<I", buf, params_off)[0]
            args = "".join(
                type_str(struct.unpack_from("<H", buf, params_off + 4 + 2 * k)[0])
                for k in range(n)
            )
        return f"({args}){type_str(ret)}"

    for i in range(mi_size):
        c, pr, nm = struct.unpack_from("<HHI", buf, mi_off + i * 8)
        if type_str(c) == cls and _string(buf, nm) == name and proto_str(pr) == proto:
            return i
    return None


def _code_off(buf: bytes, want: int) -> int | None:
    """`code_off` of method_idx `want`, by walking class_defs -> class_data.

    Each of the four member lists restarts its own delta chain — the rule dexllm#48
    exists for.
    """
    cds_size, cds_off = struct.unpack_from("<II", buf, 0x60)
    for i in range(cds_size):
        class_data_off = struct.unpack_from("<I", buf, cds_off + i * 32 + 24)[0]
        if not class_data_off:
            continue
        p = class_data_off
        sf, p = _uleb(buf, p)
        inf, p = _uleb(buf, p)
        dm, p = _uleb(buf, p)
        vm, p = _uleb(buf, p)
        for _ in range(sf + inf):
            _, p = _uleb(buf, p)
            _, p = _uleb(buf, p)
        for n in (dm, vm):
            midx = 0
            for _ in range(n):
                d, p = _uleb(buf, p)
                midx += d
                _, p = _uleb(buf, p)
                co, p = _uleb(buf, p)
                if midx == want and co:
                    return co
    return None


def _insns_at(dk, cls: str, buf_of_dex) -> tuple[bytearray, int] | None:
    """(dex bytes, dex_id) for the dex that DECLARES `cls`.

    `list_classes()` spans every loaded dex, so a fixture that always reads dex 0
    hard-fails on a multi-dex sample whose shape lives elsewhere — an environment
    fact, which this repo requires to skip rather than fail (issue #46).
    """
    d = dk.locate_class_dex(cls)
    if d < 0:
        return None
    return buf_of_dex(d), d


# --------------------------------------------------------------------------
# Shape finding, over rendered smali.
#
# Instructions are parsed into (offset, text) pairs so a WIDTH can be taken as the
# difference between consecutive offsets — exact, and independent of any opcode table
# (using one here would let the fixture inherit the very classification under test).
#
# Each finder YIELDS candidates rather than returning the first: whether a shape is
# usable depends on what the analyzer actually resolves for it, so the caller filters
# by running the unpatched dex. A finder that returned one guess would fail the whole
# test on a sample whose first match happens to be redefined before the call.
# --------------------------------------------------------------------------
_BREAKS = re.compile(r"^(goto|if-|return|throw|packed-|sparse-|move-exception)")
_CONST_S = re.compile(r"^const-string(?:/jumbo)? v(\d+),")
_CONST_W = re.compile(r"^const-wide\S* v(\d+),")
_IGET_O = re.compile(r"^iget-object v(\d+), v\d+,")
_CCAST = re.compile(r"^check-cast v(\d+),")
_INVOKE = re.compile(r"^invoke-\S+ \{([^}]*)\}")
_FIRST_REG = re.compile(r"^[a-z0-9/-]+ v(\d+)")
_LINE = re.compile(r"^\s*0x([0-9a-f]+): (.*)$")


def _invoke_args(text: str) -> list[str] | None:
    m = _INVOKE.match(text)
    return [a.strip() for a in m.group(1).split(",")] if m else None


def _touches(text: str) -> int | None:
    """The first register operand, which for a writer is its destination.

    Read-first opcodes (`aput`, `iput`, `sput`, `if-`, `return`) are treated as
    writers too. That is deliberately conservative: it only DISCARDS candidates.
    """
    m = _FIRST_REG.match(text)
    return int(m.group(1)) if m else None


def _blocks(dk, limit=_SCAN_LIMIT):
    """(class, method, [(offset, text), ...]) for each straight-line run."""
    for cls in dk.list_classes()[:limit]:
        try:
            smali = dk.render_class_smali(cls)
        except Exception:
            continue
        for body in smali.split(".method ")[1:]:
            lines = body.split("\n")
            desc = lines[0].strip()
            if "->" not in desc:
                continue
            run: list[tuple[int, str]] = []
            for ln in lines:
                m = _LINE.match(ln)
                if not m:
                    continue
                off, text = int(m.group(1), 16), m.group(2).strip()
                run.append((off, text))
                if _BREAKS.match(text):
                    if len(run) > 1:
                        yield cls, desc, run
                    run = []
            if len(run) > 1:
                yield cls, desc, run


def _find_overwrite(dk):
    """`const-string vN` ... `iget-object vN` ... invoke(vN), nothing else touching vN.

    Yields the const-string's offset as well: the wide crafts below rewrite it in
    place, and taking the offset from the smali keeps an instruction-width table out
    of this file (walking the block by hand would reintroduce exactly the opcode
    knowledge these tests exist to audit).
    """
    for cls, desc, run in _blocks(dk):
        for c, (const_off, text) in enumerate(run):
            m = _CONST_S.match(text)
            if not m:
                continue
            n = int(m.group(1))
            for i in range(c + 1, len(run)):
                mi = _IGET_O.match(run[i][1])
                if mi and int(mi.group(1)) == n:
                    for u in range(i + 1, len(run)):
                        a = _invoke_args(run[u][1])
                        if a is not None:
                            if f"v{n}" in a:
                                yield cls, desc, const_off, run[i][0], n, run[u][0]
                            break
                        if _touches(run[u][1]) == n:
                            break
                    break
                if _touches(run[i][1]) == n:
                    break


def _find_check_cast(dk):
    """`iget-object vX` ... `check-cast vX` ... invoke(vX), nothing else touching vX."""
    for cls, desc, run in _blocks(dk):
        for i, (_off, text) in enumerate(run):
            m = _IGET_O.match(text)
            if not m:
                continue
            x = int(m.group(1))
            for c in range(i + 1, len(run)):
                mc = _CCAST.match(run[c][1])
                if mc and int(mc.group(1)) == x:
                    for u in range(c + 1, len(run)):
                        if _touches(run[u][1]) == x:
                            break
                        a = _invoke_args(run[u][1])
                        if a is not None:
                            if f"v{x}" in a:
                                yield cls, desc, x, run[u][0]
                            break
                    break
                if _touches(run[c][1]) == x:
                    break


# --------------------------------------------------------------------------
def _args_at(path: str, method: str, off: int):
    """Every resolved argument of the call site at `off` inside `method`."""
    dk = dexllm.DexKit(path)
    for callee in {c.callee_descriptor for c in dk.find_call_sites_from(method)}:
        for s in dk.resolve_call_args(callee, 2):
            if s.caller_descriptor == method and s.bytecode_offset == off:
                return list(s.args)
    return []


def _arg(args, reg: int):
    for a in args:
        if a.register_index == reg:
            return a
    return None


@pytest.fixture(scope="module")
def _dex_bytes(dk):
    cache: dict[int, bytes] = {}

    def get(d: int) -> bytearray:
        if d not in cache:
            cache[d] = dk.extract_dex(d)["bytes"]
        return bytearray(cache[d])

    return get


def _locate(dk, _dex_bytes, cls: str, method: str, insn_off: int, expect: int):
    """(buf, byte position of `insn_off`) inside the dex that declares `cls`."""
    got = _insns_at(dk, cls, _dex_bytes)
    assert got is not None, f"{cls} is not declared in any loaded dex"
    buf, _d = got
    midx = _method_idx(buf, method)
    assert midx is not None, f"cannot locate {method} in method_ids"
    co = _code_off(buf, midx)
    assert co is not None, f"cannot locate the code item of {method}"
    pos = co + 16 + insn_off  # code_item header is 16 bytes, then insns
    assert buf[pos] == expect, (
        f"expected 0x{expect:02X} at the located byte, found 0x{buf[pos]:02X} — "
        "the raw-dex locator disagrees with the smali render"
    )
    return buf, pos


# ==========================================================================
# Candidate selection: the first shape whose UNPATCHED behaviour matches the premise.
# ==========================================================================
def _pick(dk, _dex_bytes, tmp_path, candidates, premise, limit=40):
    """First candidate that loads, locates and satisfies `premise` unpatched.

    `premise(buf, cand) -> bool` is run against the real analyzer, so a shape the
    smali scan liked but the analyzer resolves differently is skipped rather than
    failing the test on an accident of the sample.
    """
    for k, cand in enumerate(candidates):
        if k >= limit:
            break
        cls, method = cand[0], cand[1]
        got = _insns_at(dk, cls, _dex_bytes)
        if got is None:
            continue
        buf, _d = got
        midx = _method_idx(buf, method)
        if midx is None:
            continue
        co = _code_off(buf, midx)
        if co is None:
            continue
        if premise(buf, co, cand, tmp_path):
            return buf, co, cand
    return None


# ==========================================================================
# 1. an unhandled WRITE, over all seven opcodes
# ==========================================================================
@pytest.fixture(scope="module")
def overwrite_case(dk, _dex_bytes, tmp_path_factory):
    tmp = tmp_path_factory.mktemp("ow")

    def premise(buf, co, cand, tmp):
        _cls, method, _const_off, patch_off, reg, site = cand
        if buf[co + 16 + patch_off] != _IGET_OBJECT:
            return False
        p = tmp / "orig.dex"
        p.write_bytes(bytes(buf))
        a = _arg(_args_at(str(p), method, site), reg)
        return a is not None and a.kind == "FieldRead"

    got = _pick(dk, _dex_bytes, tmp, _find_overwrite(dk), premise)
    require_corpus_shape(
        got is not None,
        "method with `const-string vN / iget-object vN / invoke(vN)` resolving to "
        "a FieldRead",
        "the shape is ordinary code; its absence means the smali scan broke",
    )
    return got


def test_the_unpatched_site_resolves_to_the_field(overwrite_case, tmp_path):
    """Control: unpatched, the argument is the field the iget read.

    Non-discriminating BY DESIGN — it holds on both sides of the fix. Without it an
    `Unknown` in the next test could be an artefact of a wrong offset rather than of
    the analyzer clearing the register.
    """
    buf, co, (_cls, method, const_off, patch_off, reg, site) = overwrite_case
    p = tmp_path / "orig.dex"
    p.write_bytes(bytes(buf))
    a = _arg(_args_at(str(p), method, site), reg)
    assert a is not None and a.kind == "FieldRead"
    assert buf[co + 16 + patch_off] == _IGET_OBJECT


@pytest.mark.parametrize(
    "opcode", _QUICK_IGETS, ids=[f"0x{o:02X}" for o in _QUICK_IGETS]
)
def test_an_unhandled_write_is_not_reported_as_a_stale_value(
    overwrite_case, tmp_path, opcode
):
    """Each of the seven must CLEAR the register it writes.

    Parametrised over all seven because the source-level guard only sees `case`
    LABELS: a review reverted six of them — by moving the labels into a comment —
    with the whole suite green, since only 0xE5 was ever executed here.
    """
    buf, co, (_cls, method, const_off, patch_off, reg, site) = overwrite_case
    buf = bytearray(buf)
    buf[co + 16 + patch_off] = opcode
    p = tmp_path / f"patched_{opcode:02x}.dex"
    p.write_bytes(bytes(buf))

    rows = dexllm.verify(str(p))
    assert rows and all(r["valid"] for r in rows), f"crafted dex rejected: {rows}"

    args = _args_at(str(p), method, site)
    assert args, f"no resolved site at 0x{site:x} in {method}"
    a = _arg(args, reg)
    assert a is not None, f"v{reg} is not an argument of the site"
    assert a.kind == "Unknown", (
        f"0x{opcode:02X} writes v{reg} but the analyzer still reports "
        f"{a.kind} — an overwritten register presented as a value"
    )


# ==========================================================================
# 1b. the same craft, over every 2-unit writer whose destination is the 4-bit A
#
# The seven quick igets are the opcodes this change ADDED, but the completeness
# obligation covers 167 writers and only these had runtime coverage. Any 2-unit
# opcode writing the 4-bit A can be swapped in at the same byte, so the same fixture
# exercises ~30 of them for free. A craft whose second code unit is now an index into
# the wrong table simply fails to verify and is skipped -- hence the floor.
# ==========================================================================
_TWO_UNIT_A_WRITERS = (
    0x20,  # instance-of vA, vB, type@CCCC
    0x23,  # new-array   vA, vB, type@CCCC
    0x52,
    0x53,
    0x54,
    0x55,
    0x56,
    0x57,
    0x58,  # iget*
    0xD0,
    0xD1,
    0xD2,
    0xD3,
    0xD4,
    0xD5,
    0xD6,
    0xD7,  # */lit16
    0xE3,
    0xE4,
    0xE5,
    0xEF,
    0xF0,
    0xF1,
    0xF2,  # iget-*-quick
)


def test_no_two_unit_writer_leaves_the_previous_origin(overwrite_case, tmp_path):
    """A register a writer touched may be anything EXCEPT what it held before."""
    buf0, co, (_cls, method, _const_off, patch_off, reg, site) = overwrite_case
    before = None
    checked, skipped = [], []
    for opcode in _TWO_UNIT_A_WRITERS:
        buf = bytearray(buf0)
        buf[co + 16 + patch_off] = opcode
        p = tmp_path / f"w_{opcode:02x}.dex"
        p.write_bytes(bytes(buf))
        rows = dexllm.verify(str(p))
        if not (rows and all(r["valid"] for r in rows)):
            skipped.append(opcode)  # second unit is an index into the wrong table
            continue
        a = _arg(_args_at(str(p), method, site), reg)
        if a is None:
            skipped.append(opcode)
            continue
        checked.append(opcode)
        if before is None:
            before = a
        assert a.kind != "ConstString", (
            f"0x{opcode:02X} writes v{reg} but the analyzer still reports the "
            f"const-string it overwrote ({a.string_value!r})"
        )
    require_corpus_shape(
        len(checked) >= 8,
        f"shape on which at least 8 two-unit writers verify "
        f"(checked {len(checked)}, skipped {[hex(o) for o in skipped]})",
        "the craft should verify for most of these; a near-empty run means the "
        "fixture stopped producing usable dexes and this test proves nothing",
    )


# ==========================================================================
# 2/3. wideness, crafted from the SAME shape
#
# `const-string vN` is k21c and `const-wide/16 vN` is k21s -- both two code units, and
# both take an 8-bit AA -- so swapping the opcode byte turns the literal into a 64-bit
# value covering (vN, vN+1) with every offset intact. `iget-object`'s destination is a
# 4-bit nibble, so retargeting it one register up or down is another in-place edit.
# Together they build the two wide scenarios out of a shape the corpus has plenty of,
# instead of waiting for one it almost never spells directly.
# ==========================================================================
_CONST_WIDE_16 = 0x16


def _retarget(buf: bytearray, pos: int, reg: int) -> None:
    """Point a k22c instruction's 4-bit destination nibble at `reg`."""
    unit = struct.unpack_from("<H", buf, pos)[0]
    struct.pack_into("<H", buf, pos, (unit & 0xF0FF) | ((reg & 0xF) << 8))


def test_a_wide_quick_write_also_kills_the_high_half(overwrite_case, tmp_path):
    """`iget-wide-quick vN-1` owns vN-1 AND vN.

    Guards the `is_wide_dest` half of the new case: a variant erasing only the named
    register (`st.erase(A)` in place of `erase_reg_op`) passes every other test here,
    because nothing else puts a tracked origin at the high half.
    """
    buf, co, (_cls, method, const_off, patch_off, reg, site) = overwrite_case
    if reg < 1:
        pytest.skip("the found shape's register has no register below it")
    buf = bytearray(buf)
    pos = co + 16 + patch_off
    buf[pos] = _IGET_WIDE_QUICK
    _retarget(buf, pos, reg - 1)  # writes (reg-1, reg): reg is the HIGH half
    p = tmp_path / "wide.dex"
    p.write_bytes(bytes(buf))

    rows = dexllm.verify(str(p))
    if not (rows and all(r["valid"] for r in rows)):
        pytest.skip(f"the craft does not verify on this shape: {rows}")

    a = _arg(_args_at(str(p), method, site), reg)
    assert a is not None and a.kind != "ConstString", (
        f"the high half v{reg} kept its origin across a wide write to v{reg - 1}: "
        f"{a and (a.kind, a.string_value)}"
    )


def test_a_narrow_write_kills_an_aliased_wide_origin(overwrite_case, tmp_path):
    """The dexllm#32 adversarial-review finding.

    dexllm#16 closed the forward direction (a wide write clears vN+1). The aliasing
    direction was open: a narrow write to vN+1 destroys the 64-bit value parked at
    vN, and the analyzer went on reporting the whole original constant with
    `crossed_branch` False, on a dex that verifies strict-valid.

    Craft: the `const-string vN` becomes `const-wide/16 vN` (same width, same AA), so
    vN owns (vN, vN+1); the `iget-object vN` is retargeted to vN+1, which is exactly
    a narrow write to the pair's high half; the call still reads vN.
    """
    buf, co, (_cls, method, const_off, patch_off, reg, site) = overwrite_case
    if reg + 1 > 15:
        pytest.skip("the found shape's register has no 4-bit neighbour above it")
    buf = bytearray(buf)

    _retarget(buf, co + 16 + patch_off, reg + 1)  # narrow write to the HIGH half

    src_pos = co + 16 + const_off
    if buf[src_pos] != _CONST_STRING:
        pytest.skip(
            f"expected const-string at 0x{const_off:x}, found 0x{buf[src_pos]:02X}"
        )
    buf[src_pos] = _CONST_WIDE_16  # 64-bit literal covering (reg, reg+1)

    p = tmp_path / "alias.dex"
    p.write_bytes(bytes(buf))
    rows = dexllm.verify(str(p))
    if not (rows and all(r["valid"] for r in rows)):
        pytest.skip(f"the craft does not verify on this shape: {rows}")

    a = _arg(_args_at(str(p), method, site), reg)
    assert a is not None and a.kind != "ConstWide", (
        f"v{reg}'s 64-bit origin survived a narrow write to its high half "
        f"v{reg + 1}: {a and (a.kind, a.int_value, a.crossed_branch)}"
    )


# ==========================================================================
# 4. the negative: check-cast must NOT clear
# ==========================================================================
def test_check_cast_preserves_the_origin(dk):
    """A cast is a checked read — the value is unchanged, so the origin survives.

    Runs on UNMODIFIED corpus code. It guards the natural next idea, "make
    `default:` fail closed by clearing vA whenever slicer says A is a register",
    which costs real resolution: adding check-cast to the erase group loses
    arguments on ordinary code while every source-level assertion stays green.
    """
    found = None
    for k, (_cls, method, reg, site) in enumerate(_find_check_cast(dk)):
        if k >= 40:
            break
        a = _arg(_args_at(dk.sources()[0], method, site), reg)
        if a is not None:
            found = (method, reg, a)
            break
    require_corpus_shape(
        found is not None,
        "method with `iget-object vX / check-cast vX / invoke(vX)` in one block",
        "the shape is ordinary code; its absence means the smali scan broke",
    )
    method, reg, a = found
    assert (
        a.kind == "FieldRead"
    ), f"v{reg}'s origin did not survive a check-cast in {method}: {a.kind}"
