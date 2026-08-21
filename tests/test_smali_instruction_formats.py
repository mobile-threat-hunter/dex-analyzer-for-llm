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
# Every committed sample. The three above are the POLYMORPHIC carriers, which the
# register-window oracle needs (it has a non-vacuity floor and would fail on a
# sample carrying none); the sweeps that only assert an ABSENCE take all five.
_ALL_FIXTURES = _FIXTURES + ("const-method-handle.dex", "multidex.apk")

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


@pytest.mark.parametrize("name", _ALL_FIXTURES)
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
    """`FormatProto`'s sentinel, now reachable only under `lenient=True`.

    It used to be reachable on a strict-verified dex, and DELETING its one line
    left the whole suite green while a crafted `proto@0xFFFF` threw
    `SLICER_CHECK_LT` out of `ArrayView` and killed the entire class listing.

    dexllm#60's IR half then BOUNDED that operand in `VerifyInsns` — because the IR
    is a second reader and, unlike this one, cannot signal an unresolved proto — so
    strict input can no longer reach here and this test was silently SKIPPING. A
    skip is not a pass. Retargeted at `lenient=True`, which skips `VerifyInsns`
    wholesale and is exactly the packer-dump mode where the sentinel still earns
    its place.
    """
    dexllm = pytest.importorskip("dexllm")
    raw, off, tmp_path = crafted
    _patch(raw, off + 6, 0xFFFF, width=2)  # the HHHH proto operand
    dst = tmp_path / "badproto.dex"
    dst.write_bytes(bytes(raw))
    assert not dexllm.verify(str(dst))[0]["valid"], "the gate should refuse this"
    assert dexllm.verify(str(dst), lenient=True)[0]["valid"]

    dk = dexllm.DexKit(str(dst), lenient=True)
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


# ==============================================================================
# The INDEX-kind analogue (dexllm#66).
#
# `FormatOperands`' inner `emit_index` lambda has the same shape as the format
# switch above and had the same gap: five index kinds fell to `default:` and
# rendered a bare `@N`, which does not even say what table N indexes. `@0` is
# strictly less informative than `call_site@0` — it does not distinguish a call
# site from a proto from a method handle, and for the two OFFSET kinds it is not
# merely uninformative but wrong, since `@N` reads as an id into some table.
#
# The truth set is derived from TWO independent places — slicer's instruction
# table (which index kind each opcode carries) and the format switch (which arms
# actually call `emit_index`) — and each is also PINNED as a literal, so a mutant
# that shrinks a derivation instead of adding a case fails here rather than
# silently narrowing the audit.
# ==============================================================================

# Every index kind a NAMED opcode can carry into `emit_index`. Pinned so that
# widening the derivation (e.g. gutting a format arm so it no longer calls
# `emit_index`) is a two-place edit rather than a silent shrink — the device
# `test_arg_opcode_coverage` uses for the same reason.
_INDEX_KINDS_REACHING_EMIT_INDEX = {
    "kIndexStringRef",
    "kIndexTypeRef",
    "kIndexFieldRef",
    "kIndexMethodRef",
    "kIndexMethodAndProtoRef",
    "kIndexProtoRef",  # const-method-type
    "kIndexMethodHandleRef",  # const-method-handle
    "kIndexCallSiteRef",  # invoke-custom[/range]
    # The two ODEX quick kinds. Modern ART deleted them (0xE3-0xF2 are `unused-e3`
    # there), but the VENDORED slicer table still names all 16 opcodes and that
    # table is what this decoder consults, so they are named opcodes HERE. dexllm#32
    # covers the same opcodes in the argument analyzer and records why they are
    # reachable on a STRICT-verified dex: `VerifyInsns` has no opcode-legality gate,
    # so an odex-derived packer dump carries them.
    "kIndexFieldOffset",
    "kIndexVtableOffset",
}

_EMIT_INDEX_FORMATS = {"21c", "22c", "31c", "35c", "3rc", "45cc", "4rcc"}

_ROW_IDX = re.compile(
    r'\s*V\(\s*0x[0-9A-Fa-f]{2},\s*\w+,\s*"([^"]*)",\s*k(\w+),\s*(k\w+)'
)


def _formats_that_call_emit_index() -> set[str]:
    src = _strip_comments(_DEX_ITEM.read_text())
    i = src.index("switch (fmt) {")
    j = src.index("return o.str();", i)
    body = src[i:j]
    out = set()
    for m in re.finditer(r"case k(\w+):", body):
        nxt = body.find("case k", m.end())
        arm = body[m.end() : nxt if nxt > 0 else len(body)]
        # Only up to this arm's own `break;` — a fall-through label shares the arm
        # below it, and `case k21c:` is not the one that emits for `case k10x:`.
        if "emit_index(" in arm.split("break;")[0]:
            out.add(m.group(1))
    return out


def _index_kinds_named_opcodes_carry(formats: set[str]) -> set[str]:
    rows = [
        m.groups() for m in map(_ROW_IDX.match, _TABLE.read_text().splitlines()) if m
    ]
    assert len(rows) == 256, f"the slicer table parsed to {len(rows)} rows, not 256"
    return {
        idx
        for mnemonic, fmt, idx in rows
        if fmt in formats and not mnemonic.startswith("unused")
    }


def _index_kinds_the_emitter_handles() -> set[str]:
    src = _strip_comments(_DEX_ITEM.read_text())
    i = src.index("auto emit_index = [&](uint32_t v) {")
    j = src.index("switch (fmt) {", i)
    return set(re.findall(r"case (kIndex\w+):", src[i:j]))


def test_the_derivation_of_the_index_kind_truth_set_has_not_shrunk() -> None:
    """Both halves of the derivation, pinned.

    A guard parametrised over the production source cannot catch an EDIT of that
    source. If a format arm stops calling `emit_index`, or the table stops giving an
    opcode its kind, the invariant below would go vacuously green while the output
    degraded. Pinning both sets makes either a deliberate two-place edit.
    """
    assert _formats_that_call_emit_index() == _EMIT_INDEX_FORMATS
    assert (
        _index_kinds_named_opcodes_carry(_EMIT_INDEX_FORMATS)
        == _INDEX_KINDS_REACHING_EMIT_INDEX
    )


def test_the_emitter_handles_every_index_kind_a_real_opcode_can_carry() -> None:
    """The invariant. A missing arm renders a bare `@N`.

    Derived from the table, so it fails CLOSED the same way its format sibling
    does: an index kind introduced by a future Dalvik version arrives as a failure
    here rather than as an operand nobody can identify.
    """
    used = _index_kinds_named_opcodes_carry(_formats_that_call_emit_index())
    handled = _index_kinds_the_emitter_handles()
    assert used, "parsed no index kinds — the table locator moved"
    assert handled, "parsed no cases — the emit_index locator moved"
    missing = sorted(used - handled)
    assert not missing, (
        f"these index kinds render as a bare @N: {missing}. `@0` does not say "
        "whether 0 is a call site, a proto, a method handle or an offset."
    )


# The lines the three carriers must render. Pinned as literals for the same reason
# the polymorphic ones are: what a derived check would move with is exactly what is
# most likely to break.
_EXPECTED_INDEX_LINES = {
    "const-method-handle.dex": (
        "0x0: const-method-handle v0, method_handle@0",
        # Fully RESOLVED, not labelled. Its operand is a proto_ids index — the same
        # thing invoke-polymorphic's HHHH is — so `FormatProto` renders it with the
        # bound already in place. The PROTO matches AOSP dexdump's own committed
        # expected output for this file character for character
        # (`art/test/dexdump/const-method-handle.txt`); the whole LINE does not, and
        # is not meant to: dexdump appends a `// proto@0011` provenance comment,
        # which this renderer has no convention for on any operand.
        "0x0: const-method-type v0, (CSIJFDLjava/lang/Object;)Z",
    ),
    "method_handles.dex": ("0x24: const-method-handle v3, method_handle@1",),
    "invoke-custom.dex": ("0xe: invoke-custom {}, call_site@0",),
}


@pytest.mark.parametrize("name", sorted(_EXPECTED_INDEX_LINES))
def test_the_index_kind_lines_render_exactly(name) -> None:
    """The three kinds that have a REAL carrier. The other two are crafted below."""
    dexllm = pytest.importorskip("dexllm")
    path = REPO_ROOT / "tests" / "data" / name
    if not path.is_file():  # pragma: no cover - the files are committed
        pytest.skip(f"{name} missing")
    dk = dexllm.DexKit(str(path))
    rendered = {
        ln.strip()
        for c in dk.list_classes()
        for ln in dk.render_class_smali(c).split("\n")
    }
    for want in _EXPECTED_INDEX_LINES[name]:
        assert want in rendered, want


# `emit_index`'s output is the LAST thing on the line for five of the seven
# formats that call it — but k45cc / k4rcc append ", (proto)" after it, so an
# end-anchored pattern swept 5 of 7 while its docstring claimed all. Accept a
# following comma too (a correctness review found this; not a live hole, since
# `_EXPECTED_LINES` pins both polymorphic operands, but the sweep now matches
# what it says it does).
_BARE_INDEX = re.compile(r", @\d+(?:,|$)")


@pytest.mark.parametrize("name", _ALL_FIXTURES)
def test_a_fixture_renders_no_unidentified_index(name) -> None:
    """No operand may come back as a bare `@N` — the `default:` arm's shape.

    Complements the pinned literals: they say the five kinds render correctly, this
    says nothing ELSE fell through. Both are needed — a sixth kind added to the
    table with no arm would satisfy every literal above.
    """
    dexllm = pytest.importorskip("dexllm")
    path = REPO_ROOT / "tests" / "data" / name
    if not path.is_file():  # pragma: no cover - the files are committed
        pytest.skip(f"{name} missing")
    dk = dexllm.DexKit(str(path))
    bad = [
        ln.strip()
        for c in dk.list_classes()
        for ln in dk.render_class_smali(c).split("\n")
        if _BARE_INDEX.search(ln.strip())
    ]
    assert not bad, bad[:5]


# -- the two ODEX quick kinds, which no real dex in reach carries ---------------
#
# 0 incidence across the whole gitignored corpus and every committed fixture (the
# only textual hits are `"application/x-quicktime-tx3g"` string literals), so a
# craft is the only proof — the dexllm#57 / dexllm#60 shape. Both are ONE byte and
# format-preserving: `iget-object` (0x54) and `iget-object-quick` (0xE5) are both
# k22c, `invoke-virtual` (0x6E) and `invoke-virtual-quick` (0xE9) are both k35c, so
# every width, offset and section size is untouched and the dex still verifies
# STRICT-valid. That it verifies is the point: `VerifyInsns` has no
# opcode-legality gate, so these reach the renderer in both modes.

_OPERAND_CRAFTS = (
    # (fixture, mnemonic, opcode before, opcode after, expected label)
    ("method_handles.dex", "iget-object", 0x54, 0xE5, "field_off@"),
    ("invoke-custom.dex", "invoke-virtual", 0x6E, 0xE9, "vtable@"),
    # No RETYPE (0xFE -> 0xFE) — only the operand is written. The two real
    # `const-method-handle` sites in reach carry 0 and 1, and a review's `v & 0xF`
    # mutant is EQUIVALENT on both, so the value half of that arm was unguardable
    # from the fixtures as they stand. Writing the operand makes it guardable.
    ("const-method-handle.dex", "const-method-handle", 0xFE, 0xFE, "method_handle@"),
)

_INSN_LINE = re.compile(r"^\s*0x([0-9a-f]+): (\S+)")

# The operand the quick crafts write. 10811 = 0x2A3B: above 15 (so a `v & 0xF`
# truncation shows), not round (so an off-by-one or a shift shows), and its
# decimal spelling differs from its hex one (so a `std::hex` rewrite shows).
_OPERAND = 10811


def _retype_first(path, mnemonic: str, old: int, new: int, dst):
    """Retype the first `mnemonic` in `path` to opcode `new`, in place.

    The instruction is located through its DECLARING method's `code_off`
    (`class_defs` -> `class_data`, each member list restarting its own delta chain)
    plus the rendered offset, not by scanning the file for a loose `old` byte: a
    raw scan lands on data as readily as on an opcode.

    `raw0[pos] != old` is a candidate FILTER, not a premise check — this SEARCHES
    for a usable site and a method whose `code_off` cannot be resolved is simply
    not one. The loud failure on drift is the caller's `assert meth`. (An earlier
    docstring called it an assertion, which would have named the wrong cause.)
    """
    from test_arg_quick_opcodes import _code_off, _method_idx

    import dexllm as _d

    raw0 = path.read_bytes()
    dk = _d.DexKit(str(path))
    for c in dk.list_classes():
        for meth in dk.list_class_methods(c):
            for ln in dk.render_method_smali(meth).split("\n"):
                m = _INSN_LINE.match(ln)
                if not m or m.group(2) != mnemonic:
                    continue
                mi = _method_idx(raw0, meth)
                co = _code_off(raw0, mi) if mi is not None else None
                if co is None:
                    continue
                pos = co + 16 + int(m.group(1), 16)  # code_item header is 16 bytes
                if raw0[pos] != old:
                    continue
                raw = bytearray(raw0)
                raw[pos] = new
                # WRITE the index operand rather than hoping the fixture supplies a
                # distinctive one — the first `iget-object` in this fixture carries
                # 0, and 0 is exactly the value that cannot tell a correct render
                # from `<< 0` or from `v & 0xF`. `_OPERAND` is > 15, is not a round
                # number, and differs in decimal from its own hex spelling, so it
                # separates all three mutant shapes at once. Safe to write anything:
                # both target opcodes carry an OFFSET, which `VerifyInsns` leaves in
                # its `default:` arm precisely because nothing dereferences it — the
                # craft is asserted STRICT-valid below, which is what proves that.
                # The operand is the u2 at code unit 1 for every format reaching
                # `emit_index` (k21c BBBB, k22c CCCC, k35c/k3rc BBBB), so one
                # expression serves both crafts.
                raw[pos + 2] = _OPERAND & 0xFF
                raw[pos + 3] = _OPERAND >> 8
                dst.write_bytes(bytes(raw))
                return meth, _OPERAND
    return None, None


@pytest.mark.parametrize(
    "name,mnemonic,old,new,want", _OPERAND_CRAFTS, ids=lambda v: str(v)[:24]
)
def test_a_crafted_labelled_operand_renders_the_value_that_was_written(
    name, mnemonic, old, new, want, tmp_path
) -> None:
    """The label AND the value, on kinds no dex in reach exercises adequately.

    The two ODEX quick kinds have no real carrier at all; `const-method-handle` has
    two, but both hold a value <= 15 (see `_OPERAND_CRAFTS`).

    An OFFSET rendered as `@N` reads as a table id, which is worse than useless.

    These two kinds are the ones the issue did not name: dexllm#66 scoped itself to
    the three invoke-dynamic kinds, but the index-kind invariant it proposed does
    not close at three — the vendored slicer still names all 16 ODEX quick opcodes
    (modern ART deleted them, so its own dexdump has no arm either) and this
    decoder consults that table. Handling them is what makes the invariant a total
    function instead of one needing an exception list.
    """
    dexllm = pytest.importorskip("dexllm")
    path = REPO_ROOT / "tests" / "data" / name
    if not path.is_file():  # pragma: no cover - the files are committed
        pytest.skip(f"{name} missing")
    dst = tmp_path / f"quick{new:02x}.dex"
    meth, operand = _retype_first(path, mnemonic, old, new, dst)
    assert meth, f"{name} no longer carries a {mnemonic} — the fixture changed"
    assert operand == _OPERAND
    assert dexllm.verify(str(dst))[0][
        "valid"
    ], "the craft must stay STRICT-valid, or it proves nothing about reachability"

    dk = dexllm.DexKit(str(dst))
    lines = [
        ln.strip() for ln in dk.render_method_smali(meth).split("\n") if want in ln
    ]
    assert lines, "the retyped instruction vanished from the listing"
    # The whole TAIL, not the label prefix. `o << "<label>@" << v` has two halves and
    # only the first is a constant; an adversarial review built four mutants that
    # rewrote the VALUE (`<< 0`, `& 0xF`, `std::hex`) and passed the entire file
    # against a prefix check. The craft knows the operand it left in place — the u2
    # at code unit 1, which is BBBB for k35c and CCCC for k22c alike — so the
    # expected value is computed from the BYTES rather than from the renderer.
    assert lines[0].endswith(f"{want}{operand}"), (lines[0], f"want …{want}{operand}")


_LABELLED = re.compile(r"^0x([0-9a-f]+): \S+ .*?(method_handle|call_site)@(\d+)$")


@pytest.mark.parametrize("name", sorted(_EXPECTED_INDEX_LINES))
def test_a_labelled_operand_carries_the_value_the_instruction_holds(name) -> None:
    """Every labelled site's VALUE, against the bytes rather than a pinned literal.

    `o << "<label>@" << v` has two halves and pinning one line only pins the half
    that is a constant. An adversarial review built `v & 0xF`, which moves 30 of
    this fixture's 46 `call_site@` lines and yet passes every literal above,
    because the one pinned value is `call_site@0` and `0 & 0xF == 0`. Hex mutants
    are killed by those literals only by luck of the same value.

    So the expected value is decoded INDEPENDENTLY: the index operand is the u2 at
    code unit 1 for every format that reaches `emit_index`, and the instruction is
    located through its declaring method's `code_off` (`class_defs` -> `class_data`,
    each member list restarting its own delta chain), never through the renderer.
    Covers every site rather than one, so a mutant wrong at any index dies.
    """
    dexllm = pytest.importorskip("dexllm")
    from test_arg_quick_opcodes import _code_off, _method_idx

    path = REPO_ROOT / "tests" / "data" / name
    if not path.is_file():  # pragma: no cover - the files are committed
        pytest.skip(f"{name} missing")
    raw = path.read_bytes()
    dk = dexllm.DexKit(str(path))
    checked = 0
    for c in dk.list_classes():
        for meth in dk.list_class_methods(c):
            mi = _method_idx(raw, meth)
            co = _code_off(raw, mi) if mi is not None else None
            if co is None:
                continue
            for ln in dk.render_method_smali(meth).split("\n"):
                m = _LABELLED.match(ln.strip())
                if not m:
                    continue
                pos = co + 16 + int(m.group(1), 16)
                want = raw[pos + 2] | (raw[pos + 3] << 8)
                assert int(m.group(3)) == want, (
                    f"{meth} {ln.strip()}: rendered {m.group(3)}, the instruction "
                    f"holds {want}"
                )
                checked += 1
    assert checked, f"{name} rendered no labelled operand — the fixture changed"
