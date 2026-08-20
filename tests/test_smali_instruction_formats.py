"""The smali emitter renders every instruction format a real opcode uses (dexllm#60).

``FormatOperands``' ``default:`` arm prints ``<unhandled-fmt-N>`` — the
mnemonic with no operands at all. That is not a diagnostic a reader can act on: the
listing is what an analyst or an LLM reads, so a call whose whole point is the
method handle it invokes rendered as a bare word.

Two formats were missing, both invoke-dynamic era: ``k45cc``
(``invoke-polymorphic``) and ``k4rcc`` (``invoke-polymorphic/range``). Before
dexllm#58 no dex carrying one could even load, so neither had ever been observed on
a real file.

The invariant is stated once, derived from slicer's own instruction table: **every
format that a named (non-``unused``) opcode uses must appear in the switch**. That
makes a future Dalvik format a FAILURE rather than a silent degradation, which is
the fail-closed direction — the cost of a missing arm is output nobody can read.

The behavioural half runs on the three committed fixtures, so it needs no corpus
and holds under any ``$DEXLLM_TEST_APK`` narrowing.
"""

from __future__ import annotations

import re

import pytest
from conftest import REPO_ROOT
from test_arg_opcode_coverage import _strip_comments

_TABLE = (
    REPO_ROOT
    / "vendor/dexkit_core/Core/third_party/slicer/export/slicer/dex_instruction_list.h"
)
_DEX_ITEM = REPO_ROOT / "vendor/dexkit_core/Core/dexkit/dex_item.cpp"

_FIXTURES = ("invoke-polymorphic.dex", "method_handles.dex", "invoke-custom.dex")

# The exact lines the polymorphic fixture must render. Pinned as literals rather
# than recomputed, because the thing most likely to break them is the register
# LAYOUT, and a check that derives the layout from the same idea as the code would
# move with it. slicer decodes k45cc as C in `vC` and D..G in `arg[0..3]` — unlike
# k35c, which puts C..G in `arg[0..4]` — so an arm that reuses the k35c walk emits
# the PROTO INDEX as a fifth register.
_EXPECTED_LINES = (
    "0x18: invoke-polymorphic/range {v0 .. v6}, "
    "Ljava/lang/invoke/MethodHandle;->invoke([Ljava/lang/Object;)Ljava/lang/Object;, "
    "(Ljava/lang/String;DILjava/lang/Object;I)Ljava/lang/String;",
    "0x22: invoke-polymorphic {v0, v2, v3, v4}, "
    "Ljava/lang/invoke/MethodHandle;->invokeExact([Ljava/lang/Object;)Ljava/lang/Object;, "
    "(DI)I",
    "0x32: invoke-polymorphic {v0, v1, v2, v3, v4}, "
    "Ljava/lang/invoke/MethodHandle;->invoke([Ljava/lang/Object;)Ljava/lang/Object;, "
    "(Ljava/lang/String;DI)V",
)

_ROW = re.compile(r'\s*V\(\s*(0x[0-9A-Fa-f]{2}),\s*\w+,\s*"([^"]*)",\s*k(\w+),')


def _formats_named_opcodes_use() -> set[str]:
    rows = [m.groups() for m in map(_ROW.match, _TABLE.read_text().splitlines()) if m]
    assert len(rows) == 256, f"the slicer table parsed to {len(rows)} rows, not 256"
    return {fmt for _op, mnemonic, fmt in rows if not mnemonic.startswith("unused")}


def _formats_the_emitter_handles() -> set[str]:
    src = _strip_comments(_DEX_ITEM.read_text())
    i = src.index("switch (fmt) {")
    j = src.index("return o.str();", i)
    return set(re.findall(r"case k(\w+):", src[i:j]))


def test_the_emitter_handles_every_format_a_real_opcode_uses() -> None:
    """The invariant. A missing arm degrades that opcode to a bare mnemonic.

    Derived from the table, so it fails CLOSED: a format introduced by a future
    Dalvik version arrives as a failure here rather than as unreadable output.
    """
    used = _formats_named_opcodes_use()
    handled = _formats_the_emitter_handles()
    assert used, "parsed no formats — the table locator moved"
    assert handled, "parsed no cases — the switch locator moved"
    missing = sorted(used - handled)
    assert not missing, (
        f"these formats render as <unhandled-fmt-N>: {missing}. "
        "The smali listing is a primary output; a bare mnemonic is not a diagnostic."
    )


@pytest.mark.parametrize("name", _FIXTURES)
def test_a_fixture_renders_no_unhandled_format(name) -> None:
    dexllm = pytest.importorskip("dexllm")
    path = REPO_ROOT / "tests" / "data" / name
    if not path.is_file():  # pragma: no cover - the files are committed
        pytest.skip(f"{name} missing")
    dk = dexllm.DexKit(str(path))
    bad = [
        line.strip()
        for c in dk.list_classes()
        for line in dk.render_class_smali(c).split("\n")
        if "<unhandled-fmt-" in line
    ]
    assert not bad, bad[:5]


def test_the_polymorphic_lines_render_exactly() -> None:
    """Both forms, three arities, with the call-site proto.

    `invoke-polymorphic` is the one instruction whose operands cannot be read off
    the method reference: its `method_ids` entry is the signature-polymorphic
    declaration (`invoke([Ljava/lang/Object;)Ljava/lang/Object;`) while the actual
    call signature is the separate `proto_ids` operand, which is why the line
    carries both.
    """
    dexllm = pytest.importorskip("dexllm")
    path = REPO_ROOT / "tests" / "data" / "invoke-polymorphic.dex"
    if not path.is_file():  # pragma: no cover - the file is committed
        pytest.skip("invoke-polymorphic.dex missing")
    dk = dexllm.DexKit(str(path))
    lines = [
        line.strip()
        for c in dk.list_classes()
        for line in dk.render_class_smali(c).split("\n")
        if "invoke-polymorphic" in line
    ]
    assert lines == list(_EXPECTED_LINES)


def _proto_register_width(proto: str) -> int:
    """Registers a proto's PARAMETERS occupy — `J` and `D` take two, all else one.

    An ARRAY is a reference and takes one register whatever its element type, so
    `[J` is 1 and not 2. An earlier version skipped the `[` and then read the base
    character, which made `([J)V` and `([[D)V` demand an extra register — a
    false positive against CORRECT output, waiting for a fixture with a `long[]`
    parameter. Review caught it before such a fixture existed.
    """
    params = proto[1 : proto.index(")")]
    n = i = 0
    while i < len(params):
        is_array = params[i] == "["
        while params[i] == "[":
            i += 1
        c = params[i]
        i = params.index(";", i) + 1 if c == "L" else i + 1
        n += 2 if (c in "JD" and not is_array) else 1
    return n


@pytest.mark.parametrize("name", _FIXTURES)
def test_the_register_window_agrees_with_the_call_site_proto(name) -> None:
    """An oracle the emitter did not choose: the proto predicts the register count.

    A polymorphic call passes the receiver plus the proto's parameters, with `J`
    and `D` taking two registers each. The rendered line carries BOTH the register
    list and the proto, which come from different operands (the nibbles/range vs
    `arg[4]`), so this catches an arm that emits the wrong NUMBER of registers —
    including one that drops the proto operand entirely, since the count then has
    nothing to agree with.

    It does NOT catch a re-indexing that preserves the count: reading `arg[0..3]`
    instead of `{vC, arg[0..2]}` still prints four registers, just the wrong four.
    A mutant doing exactly that is killed only by `test_the_polymorphic_lines_
    render_exactly`, which is why those literals are pinned rather than derived.
    """
    dexllm = pytest.importorskip("dexllm")
    path = REPO_ROOT / "tests" / "data" / name
    if not path.is_file():  # pragma: no cover - the files are committed
        pytest.skip(f"{name} missing")
    dk = dexllm.DexKit(str(path))
    checked = 0
    for c in dk.list_classes():
        for line in dk.render_class_smali(c).split("\n"):
            if "invoke-polymorphic" not in line:
                continue
            regs, proto = (
                line[line.index("{") + 1 : line.index("}")],
                line.rsplit(", ", 1)[1],
            )
            count = (
                int(regs.split("..")[1].strip()[1:])
                - int(regs.split("..")[0].strip()[1:])
                + 1
                if ".." in regs
                else len(regs.split(","))
            )
            assert count == 1 + _proto_register_width(proto), (
                f"{line.strip()}: {count} registers but the proto needs "
                f"{1 + _proto_register_width(proto)} (receiver + parameters)"
            )
            checked += 1
    assert checked, f"{name} rendered no polymorphic site — the fixture changed"


def test_an_ordinary_invoke_is_unchanged() -> None:
    """Non-discriminating BY DESIGN — it must hold on both sides.

    dexllm#60 factored the proto half out of `FormatMethodRef` so the new arms
    could reuse it. This pins that the refactor did not move ordinary output, which
    is otherwise only covered by a whole-corpus a/b that CI cannot run.
    """
    dexllm = pytest.importorskip("dexllm")
    path = REPO_ROOT / "tests" / "data" / "invoke-polymorphic.dex"
    if not path.is_file():  # pragma: no cover - the file is committed
        pytest.skip("invoke-polymorphic.dex missing")
    dk = dexllm.DexKit(str(path))
    lines = [
        line.strip()
        for c in dk.list_classes()
        for line in dk.render_class_smali(c).split("\n")
        if "invoke-direct" in line
    ]
    assert any(line.endswith("Ljava/lang/Object;-><init>()V") for line in lines), lines[
        :5
    ]


# -- the crafted inputs both reviews had to build ------------------------------


def _patch(raw: bytearray, off: int, value: int, width: int = 1) -> None:
    for k in range(width):
        raw[off + k] = (value >> (8 * k)) & 0xFF


def _polymorphic_window(raw: bytes) -> int:
    """Byte offset of the first `A|G op` unit of an invoke-polymorphic."""
    for i in range(0, len(raw) - 8, 2):
        if raw[i] == 0xFA:
            return i
    return -1


@pytest.fixture
def crafted(tmp_path):
    """A copy of the polymorphic fixture, patchable in place.

    Length-preserving throughout: every craft below rewrites bytes that are already
    there, so section sizes and offsets are untouched and nothing but the intended
    operand can be what changes the result.
    """
    src = REPO_ROOT / "tests" / "data" / "invoke-polymorphic.dex"
    if not src.is_file():  # pragma: no cover - the file is committed
        pytest.skip("invoke-polymorphic.dex missing")
    raw = bytearray(src.read_bytes())
    off = _polymorphic_window(raw)
    assert off >= 0, "the fixture no longer carries an invoke-polymorphic"
    return raw, off, tmp_path


@pytest.mark.parametrize("arity", [6, 8, 9, 15])
def test_an_oversized_arg_count_cannot_walk_past_the_register_array(
    crafted, arity
) -> None:
    """`insn.arg` is `u4 arg[5]`; `vA` is a NIBBLE, so 6..15 index past it.

    Nothing upstream rejects that. slicer's decoder checks the count for `k35c`
    (`SLICER_CHECK(!"Invalid arg count")`) but has no such check for `k45cc`, and
    `VerifyInsns`' vararg loop CLAMPS at 5 rather than failing — so a dex with
    `vA = 15` here verifies VALID. Unclamped, the render walked off a stack object:
    both reviews reproduced it, one with an ASan `stack-buffer-overflow` at the
    exact line, and the listing printed process addresses that changed between runs
    (an OOB read, an address leak into a primary output, and a determinism break, on
    a dex `verify()` calls valid).

    The assertion is on the RESULT, not on "it did not crash": at most five
    registers, none of them the proto index, and — the property no crash-check
    would give — the same bytes must render identically in a FRESH PROCESS.
    """
    dexllm = pytest.importorskip("dexllm")
    raw, off, tmp_path = crafted
    _patch(raw, off + 1, (arity << 4) | (raw[off + 1] & 0x0F))
    dst = tmp_path / f"arity{arity}.dex"
    dst.write_bytes(bytes(raw))
    if not dexllm.verify(str(dst))[0]["valid"]:  # pragma: no cover
        pytest.skip("the craft no longer verifies — the fixture changed")

    dk = dexllm.DexKit(str(dst))
    lines = [
        ln.strip()
        for c in dk.list_classes()
        for ln in dk.render_class_smali(c).split("\n")
        if "invoke-polymorphic " in ln
    ]
    assert lines, "the crafted instruction vanished from the listing"
    regs = lines[0][lines[0].index("{") + 1 : lines[0].index("}")].split(", ")
    assert len(regs) <= 5, f"walked past arg[5]: {lines[0]}"
    assert all(int(r[1:]) < 65536 for r in regs), (
        f"a register number outside any Dalvik frame — this is memory, not a "
        f"register: {lines[0]}"
    )

    import subprocess
    import sys

    again = subprocess.run(
        [
            sys.executable,
            "-c",
            "import dexllm,sys;dk=dexllm.DexKit(sys.argv[1]);"
            "print(''.join(dk.render_class_smali(c) for c in dk.list_classes()))",
            str(dst),
        ],
        capture_output=True,
        text=True,
    )
    assert lines[0] in again.stdout, (
        "the same bytes rendered differently in a fresh process — the operand is "
        "being read from memory that moves, not from the instruction"
    )


def test_an_out_of_range_proto_index_is_reported_not_dereferenced(crafted) -> None:
    """`FormatProto`'s bound is the ONLY defence for this operand.

    dexllm#61 deliberately left the proto half of a polymorphic operand unbounded
    in `VerifyInsns` — the method half is bounded there because an out-of-range one
    produced an EMPTY `callee_descriptor`, indistinguishable from a real value,
    while this one has a visible sentinel instead. That makes the sentinel
    load-bearing, and a review found that DELETING it left the whole suite green
    (347 passed) while a crafted `proto@0xFFFF` on a `verify()`-valid dex threw
    `SLICER_CHECK_LT` out of `ArrayView` and killed the entire class listing.
    """
    dexllm = pytest.importorskip("dexllm")
    raw, off, tmp_path = crafted
    _patch(raw, off + 6, 0xFFFF, width=2)  # the HHHH proto operand
    dst = tmp_path / "badproto.dex"
    dst.write_bytes(bytes(raw))
    if not dexllm.verify(str(dst))[0]["valid"]:  # pragma: no cover
        pytest.skip("the craft no longer verifies — the fixture changed")

    dk = dexllm.DexKit(str(dst))
    rendered = "".join(dk.render_class_smali(c) for c in dk.list_classes())
    assert "<bad-proto-idx>" in rendered


_EXPECTED_LOW_ARITY = (
    "0x1e: invoke-polymorphic {v1}, "
    "Ljava/lang/invoke/MethodHandle;->invoke([Ljava/lang/Object;)Ljava/lang/Object;, "
    "()V",
    "0x7a: invoke-polymorphic {v1, v2, v3}, "
    "Ljava/lang/invoke/MethodHandle;->invoke([Ljava/lang/Object;)Ljava/lang/Object;, "
    "(IC)V",
)


def test_the_low_arity_lines_render_exactly() -> None:
    """A == 1 and A == 3, which the other pinned file does not reach.

    `_EXPECTED_LINES` covers arity 4, 5 and a 7-register range — 5 being the
    decisive one, since that is where `arg[4]` (the proto) borders the register
    window. A review pointed out that arity 1..3 was left to the count oracle,
    which by its own documented limit cannot see a re-indexing, so a mutant wrong
    ONLY at low arity would survive. A == 1 is also where slicer's own `code_ir`
    consumer drops the register entirely and emits `{}` — this renderer agrees with
    ART's dexdump instead, which is worth pinning rather than rediscovering.
    """
    dexllm = pytest.importorskip("dexllm")
    path = REPO_ROOT / "tests" / "data" / "invoke-custom.dex"
    if not path.is_file():  # pragma: no cover - the file is committed
        pytest.skip("invoke-custom.dex missing")
    dk = dexllm.DexKit(str(path))
    lines = [
        ln.strip()
        for c in dk.list_classes()
        for ln in dk.render_class_smali(c).split("\n")
        if "invoke-polymorphic" in ln
    ]
    assert lines == list(_EXPECTED_LOW_ARITY)


def test_a_zero_count_range_invoke_does_not_underflow(crafted) -> None:
    """`{vC .. vC+vA-1}` with vA == 0 prints `{v0 .. v4294967295}`.

    0xFB is `kVerifyVarArgRangeNonZero`, but `VerifyInsns`' range branch is guarded
    on `d.vA > 0` — so it CLAMPS rather than enforcing the flag, and a 0-count
    range invoke verifies valid and reaches the renderer. A review constructed it
    here and, on the OFF build, in the pre-existing `k3rc` arm as well
    (`invoke-virtual/range {v25 .. v24}` from a corpus dex), which is why the guard
    that fixes it is shared by both arms rather than added only to the new one.

    Output-only — no OOB — but a register window that spans the whole 32-bit space
    is not something a reader can act on.
    """
    dexllm = pytest.importorskip("dexllm")
    raw, _off, tmp_path = crafted
    rng = next(
        (i for i in range(0, len(raw) - 8, 2) if raw[i] == 0xFB),
        -1,
    )
    if rng < 0:  # pragma: no cover - the fixture carries one
        pytest.skip("the fixture no longer carries an invoke-polymorphic/range")
    _patch(raw, rng + 1, 0)  # the AA count
    dst = tmp_path / "zerorange.dex"
    dst.write_bytes(bytes(raw))
    if not dexllm.verify(str(dst))[0]["valid"]:  # pragma: no cover
        pytest.skip("the craft no longer verifies — the fixture changed")

    dk = dexllm.DexKit(str(dst))
    line = next(
        ln.strip()
        for c in dk.list_classes()
        for ln in dk.render_class_smali(c).split("\n")
        if "invoke-polymorphic/range" in ln
    )
    assert "4294967295" not in line, line
    assert "{}" in line, line
