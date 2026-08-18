"""dexllm(#58) - the vararg loop must read 45cc's registers, not its proto index.

`VerifyInsns` bounded `d.arg[0..vA-1]` for every opcode carrying `kVerifyVarArg`.
That is where the argument registers live for `35c`, and NOT for `45cc`
(`invoke-polymorphic`, 0xFA), which carries a SECOND index - proto@HHHH - that
`DecodeInstruction` parks in `d.arg[4]`, and whose FIRST argument register goes
to `d.vC`. So one loop had two defects:

* with `A == 5` it bounded a `proto_ids` index against `registers_size` and
  **rejected a spec-legal dex** - reproduced on an unmodified AOSP file,
  `tools/dexter/testdata/method_handles.dex`, whose two 5-argument sites carry
  proto 82 and 91 against 5 registers;
* `0xFA`'s flags carry no `kVerifyRegC`, so `vC` - a genuine register - was
  bounded by nothing. The loop checked one slot too many at the end and skipped
  the one at the front.

Every fixture here is crafted from `tests/data/multidex.apk`, the one container
this repo commits, so the guards hold in the corpus-less CI leg and under any
`$DEXLLM_TEST_APK` narrowing. The single exception is the no-false-reject floor
at the bottom, which walks the loaded corpus and therefore SKIPS where there is
none - an environment fact, never a failure. The craft is length-preserving to the code unit:
it overwrites an instruction prefix that measures exactly 4 code units
(`invoke-direct` + `return-void`) with one 4-unit instruction, so `insns_size`,
every later instruction boundary and every section offset are untouched.
"""

from __future__ import annotations

import pathlib
import struct
import zipfile

import pytest
from conftest import REPO_ROOT

# Header field offsets (dex spec): the four we read.
_PROTO_IDS_SIZE = 0x48
_METHOD_IDS_SIZE = 0x58
_CLASS_DEFS = 0x60  # size, then off

_MULTIDEX = REPO_ROOT / "tests" / "data" / "multidex.apk"

# The instruction prefix the craft replaces, as (opcode, code units). Pinning the
# expected shape means a different container silently substituted for the fixture
# fails loudly rather than being patched at a wrong offset.
_PREFIX = ((0x70, 3), (0x0E, 1))  # invoke-direct {v0}, <init>  +  return-void
_PREFIX_UNITS = 4


def _uleb(raw: bytes, off: int) -> tuple[int, int]:
    value = shift = 0
    while True:
        byte = raw[off]
        off += 1
        value |= (byte & 0x7F) << shift
        shift += 7
        if not byte & 0x80:
            return value, off


def _first_craftable_code_item(raw: bytes) -> tuple[int, int]:
    """(code_item offset, registers_size) for the first method this craft fits.

    "Fits" means: at least `_PREFIX_UNITS` code units of instructions, whose
    leading instructions measure exactly that (so nothing is left half
    overwritten), and no try/catch - a handler address inside the replaced
    window would be validated against a shape that is no longer there.
    """
    u4 = lambda o: struct.unpack_from("<I", raw, o)[0]  # noqa: E731
    u2 = lambda o: struct.unpack_from("<H", raw, o)[0]  # noqa: E731

    defs_size, defs_off = struct.unpack_from("<II", raw, _CLASS_DEFS)
    for i in range(defs_size):
        class_data_off = u4(defs_off + i * 32 + 24)
        if not class_data_off:
            continue
        p = class_data_off
        counts = []
        for _ in range(4):
            n, p = _uleb(raw, p)
            counts.append(n)
        static_fields, instance_fields, direct, virtual = counts
        for _ in range(static_fields + instance_fields):
            _, p = _uleb(raw, p)
            _, p = _uleb(raw, p)
        for _ in range(direct + virtual):
            _, p = _uleb(raw, p)
            _, p = _uleb(raw, p)
            code_off, p = _uleb(raw, p)
            if not code_off:
                continue
            registers_size = u2(code_off)
            tries_size = u2(code_off + 6)
            insns_size = u4(code_off + 12)
            if tries_size or insns_size < _PREFIX_UNITS:
                continue
            q, units = code_off + 16, 0
            for opcode, width in _PREFIX:
                if raw[q] != opcode:
                    break
                q += 2 * width
                units += width
            else:
                if units == _PREFIX_UNITS:
                    return code_off, registers_size
    raise AssertionError(
        "tests/data/multidex.apk no longer offers the instruction prefix this "
        "fixture rewrites - the craft would land at a wrong offset"
    )


def _craft(units: list[int], dst: pathlib.Path) -> None:
    """Write `tests/data/multidex.apk`'s first dex with `units` spliced in."""
    raw = bytearray(zipfile.ZipFile(_MULTIDEX).read("classes.dex"))
    code_off, _regs = _first_craftable_code_item(raw)
    assert len(units) == _PREFIX_UNITS, units
    for k, unit in enumerate(units):
        struct.pack_into("<H", raw, code_off + 16 + 2 * k, unit)
    dst.write_bytes(bytes(raw))


def _dex_facts() -> tuple[int, int, int]:
    """(registers_size of the crafted method, proto_ids_size, method_ids_size)."""
    raw = bytearray(zipfile.ZipFile(_MULTIDEX).read("classes.dex"))
    _code_off, regs = _first_craftable_code_item(raw)
    return (
        regs,
        struct.unpack_from("<I", raw, _PROTO_IDS_SIZE)[0],
        struct.unpack_from("<I", raw, _METHOD_IDS_SIZE)[0],
    )


def _invoke(opcode: int, a: int, g: int, method_idx: int, reg_list: int, hhhh: int):
    """One 45cc/35c instruction as code units.

    45cc is `A|G op BBBB F|E|D|C HHHH`; 35c is the same minus the final unit, so
    a 35c craft passes `hhhh=None` and pads with a `nop` to keep the window at
    4 code units.
    """
    head = (a << 12) | (g << 8) | opcode
    units = [head, method_idx, reg_list]
    units.append(0x0000 if hhhh is None else hhhh)  # nop pad, or proto@HHHH
    return units


@pytest.fixture(scope="module")
def facts():
    regs, protos, methods = _dex_facts()
    # The craft needs a register file small enough that an out-of-range register
    # is expressible in a 4-bit nibble, and at least one usable id of each kind.
    assert 0 < regs < 15, regs
    assert protos > 0 and methods > 0, (protos, methods)
    return regs, protos, methods


def _verify(tmp_path, units, name):
    import dexllm

    dst = tmp_path / name
    _craft(units, dst)
    report = dexllm.verify(str(dst))
    assert report, report
    return dst, report[0]


# -- the premise --------------------------------------------------------------


def test_the_uncrafted_dex_verifies(tmp_path):
    """Non-discriminating BY DESIGN - it pins the baseline.

    Every guard below attributes a verdict to the four code units it splices in.
    That attribution is only sound if the file verifies before the splice, so
    this pins it with the ORIGINAL prefix written back over itself.
    """
    import dexllm

    raw = bytearray(zipfile.ZipFile(_MULTIDEX).read("classes.dex"))
    dst = tmp_path / "pristine.dex"
    dst.write_bytes(bytes(raw))
    report = dexllm.verify(str(dst))
    assert report and all(r["valid"] for r in report), report


# -- the fix ------------------------------------------------------------------


def test_a_five_register_invoke_polymorphic_is_accepted(tmp_path, facts):
    """The false reject: `arg[4]` is the proto index, not a register.

    All five argument registers are v0, so nothing here is out of range. The
    only operand that could exceed `registers_size` is the prototype index -
    and bounding it as a register is the defect.
    """
    import dexllm

    regs, protos, _methods = facts
    proto = protos - 1
    assert proto >= regs, (proto, regs)  # else the pre-fix build would accept it
    dst, row = _verify(
        tmp_path,
        _invoke(0xFA, a=5, g=0, method_idx=0, reg_list=0x0000, hhhh=proto),
        "poly_ok.dex",
    )
    assert row["valid"], row
    dk = dexllm.DexKit([str(dst)])
    assert dk.list_classes()


@pytest.mark.parametrize("arity", [1, 2, 3, 4, 5])
def test_the_first_argument_register_of_a_polymorphic_is_checked(
    tmp_path, facts, arity
):
    """The missed check: `vC` carries the first argument and had no bound.

    `0xFA`'s flags carry no `kVerifyRegC`, so before the fix the ONLY thing that
    looked at the argument list skipped `vC` entirely - at EVERY arity, not just
    at 5. The parametrisation is what pins the ORDER of the sequence rather than
    merely its membership: a variant that appends `vC` after `arg[0..3]` still
    checks it when `vA == 5` and drops it for every smaller call, which is half
    of this defect restored. `vC` is an argument whenever `A >= 1`, so every
    value here must reject.

    The proto index is deliberately 0, i.e. BELOW `registers_size`: with a
    realistic proto the pre-fix build rejects on `arg[4]` and this guard passes
    against the defect it exists to catch. Keeping the one out-of-range operand
    down to `vC` is what makes the verdict attributable.
    """
    regs, _protos, _methods = facts
    assert 0 < regs, regs  # proto 0 must be a value the pre-fix loop accepts
    _dst, row = _verify(
        tmp_path,
        # F|E|D|C with C = 15: the first argument register, out of range.
        _invoke(0xFA, a=arity, g=0, method_idx=0, reg_list=0x000F, hhhh=0),
        f"poly_vc_a{arity}.dex",
    )
    assert not row["valid"], row
    assert "vararg register out of range" in row["reason"], row


def test_the_last_argument_register_of_a_polymorphic_is_checked(tmp_path, facts):
    """`vG` is the fifth argument and lives in the instruction's own A|G byte.

    The decoder parks it in `arg[3]`, one slot before the proto index, so a fix
    that stopped the loop early to avoid `arg[4]` - the obvious way to kill the
    false reject alone - drops `vG` with it. Only `A == 5` reaches this operand.
    """
    _regs, _protos, _methods = facts
    _dst, row = _verify(
        tmp_path,
        _invoke(0xFA, a=5, g=15, method_idx=0, reg_list=0x0000, hhhh=0),
        "poly_vg.dex",
    )
    assert not row["valid"], row
    assert "vararg register out of range" in row["reason"], row


# -- what the fix must NOT have relaxed ---------------------------------------


def test_a_polymorphic_argument_register_out_of_range_is_still_rejected(
    tmp_path, facts
):
    """Non-discriminating BY DESIGN on the pre-fix build - it pins that the
    branch still BOUNDS the registers it now reads, rather than skipping them.

    Proto 0 again, so the rejection is attributable to `vD` and not to the
    operand the fix stopped reading."""
    _regs, _protos, _methods = facts
    _dst, row = _verify(
        tmp_path,
        # F|E|D|C with D = 15: the second argument register.
        _invoke(0xFA, a=5, g=0, method_idx=0, reg_list=0x00F0, hhhh=0),
        "poly_vd.dex",
    )
    assert not row["valid"], row
    assert "vararg register out of range" in row["reason"], row


def test_the_fifth_register_of_a_35c_invoke_is_still_checked(tmp_path, facts):
    """35c keeps its own layout, and the fifth argument is the one at risk.

    For `35c` the registers are `arg[0..vA-1]` with the first MIRRORED into
    `vC`, so a fix that applied 45cc's `{vC, arg[0..3]}` sequence to every
    format would check `arg[0]` twice and never reach `arg[4]` - the fifth
    register - which is what this pins. `vG` lives in the instruction's own A|G
    byte, so it is set through `g`, not through the register list.
    """
    _regs, _protos, methods = facts
    _dst, row = _verify(
        tmp_path,
        _invoke(0x6E, a=5, g=15, method_idx=methods - 1, reg_list=0x0000, hhhh=None),
        "invoke_35c.dex",
    )
    assert not row["valid"], row
    assert "vararg register out of range" in row["reason"], row


def test_a_35c_invoke_with_registers_in_range_is_accepted(tmp_path, facts):
    """The control for the guard above: same shape, every register v0."""
    _regs, _protos, methods = facts
    _dst, row = _verify(
        tmp_path,
        _invoke(0x6E, a=5, g=0, method_idx=methods - 1, reg_list=0x0000, hhhh=None),
        "invoke_35c_ok.dex",
    )
    assert row["valid"], row


def test_the_corpus_verdicts_are_unchanged(dk):
    """Non-discriminating BY DESIGN - a no-false-reject floor.

    The bundled corpus carries no `invoke-polymorphic` at all, so this cannot
    see the fix; what it can see is the fix having made some OTHER instruction
    stop verifying.
    """
    import dexllm

    for source in dk.sources():
        report = dexllm.verify(source)
        assert report and all(r["valid"] for r in report), (source, report)


# -- the enumeration the branch rests on --------------------------------------

_INSTRUCTION_LIST = (
    REPO_ROOT
    / "vendor"
    / "dexkit_core"
    / "Core"
    / "third_party"
    / "slicer"
    / "export"
    / "slicer"
    / "dex_instruction_list.h"
)

# The formats `VerifyInsns` handles in its vararg branch: `k45cc` reads
# `{vC, arg[0..3]}`, everything else reads `arg[0..vA-1]`. Pinned as a LITERAL
# rather than derived from the same table the assertion parses - a set computed
# from the file cannot notice the file growing a third entry.
_VARARG_FORMATS = {"35c", "45cc"}


def test_the_vararg_branch_covers_every_format_that_sets_the_flag():
    """A third varargs FORMAT must be a failure, not a silent fall-through.

    The fix branches `k45cc` against everything else, which is correct only
    because those are the only two formats carrying `kVerifyVarArg` /
    `kVerifyVarArgNonZero`. That enumeration is hand-maintained in a comment; a
    future opcode that added a third layout would take the `arg[0..vA-1]` arm by
    default and read whatever that format parks there - which is exactly the
    defect this file exists for, one format over.
    """
    import re

    text = _INSTRUCTION_LIST.read_text()
    rows = re.findall(
        r'V\((0x[0-9A-Fa-f]{2}),\s*(\w+),\s*"([^"]*)",\s*k(\w+),\s*(\w+),'
        r"\s*([^,]+),\s*([^,]+),\s*([^)]*)\)",
        text,
    )
    assert len(rows) == 256, len(rows)
    found: dict[str, list[tuple[str, str]]] = {}
    for opcode, _upper, name, fmt, _idx, _flags, _size, verify in rows:
        if re.search(r"kVerifyVarArg(NonZero)?\b", verify):
            found.setdefault(fmt, []).append((opcode, name))
    assert set(found) == _VARARG_FORMATS, found
    # Non-vacuity: the parse must actually have found the two known families.
    assert len(found["35c"]) >= 5, found["35c"]
    assert [op for op, _ in found["45cc"]] == ["0xFA"], found["45cc"]
