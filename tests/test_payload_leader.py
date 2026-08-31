"""dexllm#77 — a block whose LEADER is not an instruction boundary.

A leader only has to be an in-range BYTE OFFSET.  ``VerifyInsns`` bounds a
branch/switch target and a try-range start and requires nothing more, and ART's
structural verifier does not either — opcode and dataflow legality live in the
runtime ``method_verifier`` this port deliberately does not vendor.  So a leader
may point **into a switch/fill-array payload** (which ``DecodeAllInsns`` skips)
or **into the TAIL of a multi-unit instruction**, and both are accepted by
``dexllm.verify()`` in BOTH modes.

``SplitIntoBlocks`` located a block's instruction span by ``ins_idx_by_byte``
**at the block START alone**, so such a block came back EMPTY even when
instructions lie inside ``[start, end)`` — those instructions belonged to no
block at all — and ``ComputeChildEdges`` then skipped every empty block, leaving
it with no successor.  Two losses, and only the first was recorded when the
issue was filed:

* the empty block is a **dead end**, so everything reachable only through it is
  dropped (``midbody_empty``);
* the empty block's **own span** is dropped, taking the real instructions inside
  it (``midbody_lost``).

`render_method_smali` still listed every instruction in both cases, so the two
views of one method disagreed with the **Java one wrong** — and silently.

The fix has two halves and BOTH are pinned here, because either alone leaves a
shape broken: the forward scan gives a block the instructions inside its span
(``midbody_lost``), and the fall-through keeps what follows a still-empty block
reachable (``midbody_empty``).  What is rendered is a REINTERPRETATION — no VM
enters at a non-instruction offset — so both emitters mark it, and the marker's
predicate is the GENERAL one: ``mid_insn`` carries no payload at all, which is
what a "payload" predicate would miss.

Crafted-only in reach: 0 methods across the whole a/b population carry a leader
off a boundary, so a corpus a/b is byte-identical BY CONSTRUCTION and these
crafts are the only thing that can show the mechanism firing.

Every craft rewrites only code units INSIDE one code item's ``insns`` of the
committed ``tests/data/method_handles.dex``, so it is length-preserving to the
byte — no offset, no section size and no neighbouring structure moves — and each
craft's verify verdict is ASSERTED in both modes rather than assumed (a rejected
dex never reaches the IR builder, so a guard that skipped this could pass for
the wrong reason).  They run in the corpus-less CI leg and under any
``$DEXLLM_TEST_APK`` narrowing.
"""

from __future__ import annotations

import json
import struct
import subprocess
import sys
from pathlib import Path

import pytest
from test_empty_code_item import _code_items  # one raw class_data walk, not two

import dexllm

REPO_ROOT = Path(__file__).resolve().parents[1]
FIXTURE = REPO_ROOT / "tests" / "data" / "method_handles.dex"

MARKER = "// control enters at a non-instruction offset"
AST_MARKER = "control enters at a non-instruction offset"
# dexllm#75's marker.  None of the crafts below touches the START of the body,
# so every one of them keeps its first instruction at offset 0 and NONE may
# carry it.  Asserted rather than assumed: the two flags are independent, and a
# fix that conflated them would show up right here.
ENTRY_MARKER = "// entry is not at offset 0"

# A size-0 packed-switch payload is exactly 4 code units: ident, size, first_key
# (u4).  DecodeAllInsns skips it, which is what lets a target land inside it.
_PAYLOAD = [0x0100, 0x0000, 0x0000, 0x0000]
_CONST4 = 0x1012  # const/4 v0, #1
_RETURN_VOID = 0x000E
_NOP = 0x0000

# Each body is laid out so the DEFECT is the only thing under test; the byte
# offsets in the comments are what the craft produces, and `test_the_crafts_have
# _the_shape_they_claim` re-derives them from the rendered smali rather than
# trusting these.
_BODIES = {
    # The empty block is a DEAD END.  0 const/4 | 2 if-eqz +3 -> 8 (inside the
    # payload at 6..14) | 6 payload | 14 const/4 | 16 return-void.  The if's
    # FALSE edge is `blk.end_byte` = the next leader = 8, so BOTH arms enter the
    # empty block and everything after it hangs off its successor.
    "midbody_empty": [_CONST4, 0x0038, 0x0003] + _PAYLOAD + [_CONST4, _RETURN_VOID],
    # The empty block's own SPAN carries instructions.  0 if-eqz +7 -> 14 (inside
    # the payload at 8..16) | 4 const/4 | 6 nop | 8 payload | 16 const/4 |
    # 18 return-void.  `return-void` makes the next instruction a leader, so the
    # block starting at 14 ends at 20 and covers 16 and 18.
    "midbody_lost": [0x0038, 0x0007, _CONST4, _NOP]
    + _PAYLOAD
    + [_CONST4, _RETURN_VOID],
    # NO PAYLOAD ANYWHERE.  0 const/4 | 2 if-eqz +1 -> 4, which is code unit 2
    # of the if-eqz ITSELF | 6 const/4 | 8 return-void.  The same empty-block
    # shape reached through a mid-INSTRUCTION target — the shape a "payload"
    # predicate cannot see.
    "mid_insn": [_CONST4, 0x0038, 0x0001, _CONST4, _RETURN_VOID],
    # The recovered span carries TWO instructions whose ORDER is observable:
    # 0 if-eqz +7 -> 14 (inside the payload at 8..16) | 4 const/4 v0 | 6 nop |
    # 8 payload | 16 const/4 v1,#3 | 18 return-object v1.  The block starting at
    # 14 must be read from the FIRST instruction at or after it — taking the
    # LAST one instead renders `return <undefined>` instead of `return 3`.
    "midbody_pair": [0x0038, 0x0007, _CONST4, _NOP] + _PAYLOAD + [0x3112, 0x0111],
    # The instruction AFTER the empty block is itself a CONDITIONAL BRANCH.
    # 0 const/4 | 2 if-eqz +3 -> 8 (inside the payload at 6..14) | 6 payload |
    # 14 if-eqz +2 -> 18 | 18 return-void.  The empty block `[0x8, 0xe)` ends
    # exactly where that second `if` begins, which is what makes it the shape
    # that separates the span bound from its absence — see
    # `test_a_block_never_claims_an_instruction_outside_its_own_span`.
    "steal_cond": [_CONST4, 0x0038, 0x0003] + _PAYLOAD + [0x0038, 0x0002, _RETURN_VOID],
    # THE CONTROL: the same instructions and the same branch, landing on a real
    # boundary.  Nothing may be marked and the body must render.
    "control": [_CONST4, 0x0038, 0x0004, _NOP, _NOP, _NOP, _NOP, _CONST4, _RETURN_VOID],
}
_MARKED = ("midbody_empty", "midbody_lost", "midbody_pair", "mid_insn", "steal_cond")
_ALL = tuple(_BODIES)

# The longest body plus room to spare.
_MIN_UNITS = 12


@pytest.fixture(scope="module")
def target():
    """``(descriptor, code_off, units)`` — a try-free code item with room.

    Try-free so the leaders are exactly the ones the body creates: a try-range
    start is a leader of its own, and one at byte 0 is dexllm#75's craft, not
    this file's.  The premise is asserted rather than assumed.
    """
    if not FIXTURE.is_file():  # pragma: no cover - the file is committed
        pytest.skip("tests/data/method_handles.dex missing")
    dex = FIXTURE.read_bytes()
    for desc, co, tries, units, _ao, _al in _code_items(dex):
        if tries == 0 and units >= _MIN_UNITS:
            return desc, co, units
    raise AssertionError(
        f"the fixture carries no try-free code item of >= {_MIN_UNITS} units"
    )


def _craft(tmp_path: Path, target, shape: str) -> tuple[str, str]:
    desc, co, units = target
    body = _BODIES[shape]
    assert len(body) <= units, (shape, len(body), units)
    dex = bytearray(FIXTURE.read_bytes())
    for k in range(units):
        struct.pack_into("<H", dex, co + 16 + 2 * k, body[k] if k < len(body) else 0)
    assert len(dex) == FIXTURE.stat().st_size, "the craft must be length-preserving"
    path = tmp_path / f"leader_{shape}.dex"
    path.write_bytes(bytes(dex))
    # The premise: the gate accepts it, in BOTH modes.  `check_insns_` gates
    # VerifyInsns and nothing else, and a leader off a boundary is exactly the
    # thing VerifyInsns is asked about — so a craft that only verified leniently
    # would prove a weaker claim than the issue makes.
    for lenient in (False, True):
        rows = dexllm.verify(str(path), lenient=lenient)
        assert all(r["valid"] for r in rows), (shape, lenient, rows)
    return str(path), desc


# ── every observation of a CRAFTED dex is made in a CHILD ───────────────────
#
# This file sorts early, and a regression that faults in the IR builder would
# abort the whole `pytest tests/` session here rather than report.  So no
# decompile of a crafted dex runs in the pytest process: one child gathers the
# observations and the tests assert on its JSON and its EXIT STATUS.  (`verify`
# is called above — it is the gate, it never reaches the IR builder, and its
# verdict is the premise.)

_PROBE = r"""
import json, sys
import dexllm

path, desc = sys.argv[1], sys.argv[2]
dk = dexllm.DexKit(path)
ast = dk.decompile_method_ast(desc)
bare = dk.decompile_method_ast(desc, include_source=False)
print(json.dumps({
    "text": dk.decompile_method(desc),
    "smali": dk.render_method_smali(desc),
    "ast_source": ast["source"],
    "ast_comments": ast["ast"]["comments"],
    "ast_comments_no_source": bare["ast"]["comments"],
    "class": dk.decompile_class(desc.split(";->")[0] + ";"),
}))
"""


@pytest.fixture(scope="module")
def probed(tmp_path_factory, target):
    """``{shape: (observations, descriptor)}`` — one child per shape."""
    tmp = tmp_path_factory.mktemp("leader")
    out = {}
    for shape in _ALL:
        path, desc = _craft(tmp, target, shape)
        r = subprocess.run(
            [sys.executable, "-c", _PROBE, path, desc],
            capture_output=True,
            text=True,
            timeout=300,
        )
        assert r.returncode == 0, f"{shape}: probe exited {r.returncode}\n{r.stderr}"
        out[shape] = (json.loads(r.stdout), desc)
    return out


def _body(text: str) -> list[str]:
    """The executable statements of a rendered method."""
    inside = text.split("{", 1)[1] if "{" in text else ""
    return [
        ln.strip()
        for ln in inside.splitlines()
        if ln.strip() and ln.strip() not in "{}" and not ln.strip().startswith("//")
    ]


def _smali_offsets(smali: str) -> list[int]:
    return [
        int(ln.strip().split(":", 1)[0], 16)
        for ln in smali.splitlines()
        if ln.strip().startswith("0x")
    ]


# ── the premise ────────────────────────────────────────────────────────────


def test_the_uncrafted_target_has_a_body(target, tmp_path):
    """Non-discriminating BY DESIGN, and not idle.

    Every assertion below is about a method whose body the craft REPLACES.  If
    the chosen code item were empty to begin with, "the body renders" would hold
    for the wrong reason on both halves.
    """
    desc, _co, _units = target
    dk = dexllm.DexKit(str(FIXTURE))
    assert _body(dk.decompile_method(desc)), f"{desc} renders no statement"


def test_the_crafts_have_the_shape_they_claim(probed):
    """The layout the comments describe, re-derived from the product's decoder.

    A craft whose payload landed elsewhere would exercise a different defect (or
    none) while every assertion below still passed.  The offsets come from
    `render_method_smali`, i.e. the same linear decode the builder runs, not
    from a hand-rolled width walk.
    """
    # `midbody_empty`: the if-eqz at 0x2 targets 0x8, which is INSIDE the
    # payload — the decoder skips 0x6..0xe, so 0x8 is not a listed offset.
    offs = _smali_offsets(probed["midbody_empty"][0]["smali"])
    assert 0x6 in offs and 0x8 not in offs and 0xE in offs, offs[:8]
    # `midbody_lost`: the target 0xe is inside the payload at 0x8, and 0x10 /
    # 0x12 are real instructions AFTER it — the ones the empty block's span
    # covered and lost.
    offs = _smali_offsets(probed["midbody_lost"][0]["smali"])
    assert 0x8 in offs and 0xE not in offs, offs[:8]
    assert 0x10 in offs and 0x12 in offs, offs[:8]
    # `mid_insn`: NO payload marker anywhere, and the target 0x4 is the second
    # code unit of the if-eqz at 0x2, so it is not a listed offset either.
    offs = _smali_offsets(probed["mid_insn"][0]["smali"])
    assert 0x2 in offs and 0x4 not in offs and 0x6 in offs, offs[:8]
    assert "packed-switch" not in probed["mid_insn"][0]["smali"], "craft grew a payload"


# ── the defect: the body is no longer lost ─────────────────────────────────


@pytest.mark.parametrize("shape", _MARKED)
def test_the_body_after_a_non_boundary_leader_is_rendered(probed, shape):
    """The headline.

    Each craft ends in `return-void`, which is the one instruction in it that
    survives DCE, so a rendered `return` is the proof that control reached the
    end of the body.  Before the fix `midbody_empty` and `mid_insn` rendered an
    empty method (the empty block was a dead end) and `midbody_lost` rendered
    the `if` and nothing after it (the empty block's span was dropped whole).
    """
    got, _desc = probed[shape]
    body = _body(got["text"])
    assert any(
        ln.startswith("return") for ln in body
    ), f"{shape}: the body after the leader is still missing\n{got['text']}"


def test_a_span_that_begins_off_a_boundary_keeps_the_instructions_inside_it(probed):
    """The FORWARD-SCAN half, pinned on its own.

    `midbody_lost`'s block `[0xe, 0x14)` starts inside the payload and covers
    the real instructions at 0x10 and 0x12.  The fall-through half alone does
    not rescue them — it would send control PAST them to the next block — so
    without the scan this method renders its `if` and stops.  Its sibling
    `midbody_empty` cannot see the difference: that block's span holds no
    instruction at all.
    """
    got, _desc = probed["midbody_lost"]
    offs = _smali_offsets(got["smali"])
    assert 0x10 in offs and 0x12 in offs, offs[:8]
    assert any(ln.startswith("return") for ln in _body(got["text"])), got["text"]


def test_a_block_never_claims_an_instruction_outside_its_own_span(probed):
    """The forward scan is bounded by the span END, and that bound is load-bearing.

    Dropping it is the plausible simplification — take the first instruction at
    or after `start` and be done — and on every other craft here it is
    EQUIVALENT, because the instruction it then steals is the first one of the
    very block control would have fallen through to.  `steal_cond` is the shape
    where it is not: that instruction is a CONDITIONAL BRANCH, so the empty
    block becomes a second `CondBlock` over the SAME `if-eqz`, whose false arm
    is the block that evaluates it again — and the structurer merges the two
    into a short-circuit condition the bytecode does not contain (measured:
    `if ((1 != 0) && (1 == 0))` where the fix renders `if (1 == 0)`).  A
    fabricated condition on the primary output is the wrong-answer class this
    whole issue is about, reached through the fix for it.

    Neither craft here carries a short-circuit pattern — every one is a chain of
    independent single-register `if-eqz` instructions — so a compound `&&` / `||`
    in the rendering can only come from one instruction being claimed by a block
    whose span does not contain it.
    """
    for shape in _ALL:
        got, _desc = probed[shape]
        assert "&&" not in got["text"] and "||" not in got["text"], (
            f"{shape}: the rendering invents a compound condition the bytecode "
            f"does not contain\n{got['text']}"
        )


def test_the_span_is_read_from_its_FIRST_instruction(probed):
    """The forward scan takes the FIRST instruction in the span, not any of them.

    "Take the first instruction at or after `start` that is inside the span" has
    two independent halves — WHICH instruction, and the span bound — and only
    the second was pinned.  A mutant taking the LAST instruction instead passed
    every other case in this file (a correctness reviewer built it), while
    silently dropping every instruction between the block's start and its last
    one: the exact defect class this issue closes, reached through its own fix.

    `midbody_lost` cannot see it — the one instruction it would lose is a dead
    `const/4` that DCE removes either way, so both readings render the same
    text.  `midbody_pair` makes the difference observable by having the FIRST
    recovered instruction define what the second returns: the correct reading
    renders `return 3`, the last-instruction reading returns an undefined
    register.
    """
    got, _desc = probed["midbody_pair"]
    offs = _smali_offsets(got["smali"])
    assert 0x10 in offs and 0x12 in offs, offs[:8]
    body = _body(got["text"])
    assert any(
        ln.replace(" ", "") == "return3;" for ln in body
    ), f"the span lost its first instruction — {got['text']}"


def test_a_still_empty_block_falls_through(probed):
    """The FALL-THROUGH half, pinned on its own.

    `midbody_empty`'s block `[0x8, 0xe)` is payload bytes end to end, so the
    forward scan finds nothing inside it and the block stays empty.  Everything
    after it is reachable ONLY through its successor edge.
    """
    got, _desc = probed["midbody_empty"]
    assert any(ln.startswith("return") for ln in _body(got["text"])), got["text"]


@pytest.mark.parametrize("shape", _MARKED)
def test_the_java_view_no_longer_contradicts_the_smali_view(probed, shape):
    """The two views of one method agree that there IS a body.

    The disagreement is the defect as an analyst meets it: smali lists real
    instructions while the Java pane shows a method that does nothing.
    """
    got, _desc = probed[shape]
    assert len(_smali_offsets(got["smali"])) > 2, got["smali"][:200]
    assert _body(got["text"]), f"{shape}: smali lists instructions, Java is empty"


# ── the marker ─────────────────────────────────────────────────────────────


@pytest.mark.parametrize("shape", _MARKED)
def test_the_reinterpretation_is_marked(probed, shape):
    """Text and AST carry the identical string, and the AST carries it alone.

    `include_source=False` is the reason the AST needs its own comment: such a
    consumer never sees the Writer's text, so marking one emitter and not the
    other is a text/AST divergence.
    """
    got, _desc = probed[shape]
    assert MARKER in got["text"], f"{shape}: unmarked\n{got['text']}"
    assert got["ast_comments"] == [AST_MARKER], f"{shape}: {got['ast_comments']!r}"
    assert got["ast_comments_no_source"] == [
        AST_MARKER
    ], f"{shape}: include_source=False loses the marker"
    assert (
        got["ast_source"] == got["text"]
    ), f"{shape}: ast['source'] is not byte-identical to decompile_method"


def test_a_method_with_no_payload_is_marked_too(probed):
    """The marker's predicate is the GENERAL one.

    `mid_insn` reaches the empty-block shape through a target landing in the
    TAIL of the if-eqz, and carries no payload anywhere — asserted above from
    its own smali.  A flag keyed on "a leader inside a payload" would leave this
    method silently reinterpreted, and a marker SAYING payload would be a false
    statement about it on the primary output.
    """
    got, _desc = probed["mid_insn"]
    assert MARKER in got["text"], got["text"]
    # And the RENDERED text must not claim one either.  Asserting `"payload"
    # not in MARKER` would only pin this file's own literal; this pins the
    # product's output, so a marker reworded to name a payload fails HERE on the
    # one craft that provably has none rather than only as a string mismatch.
    assert "payload" not in got["text"], (
        "the marker claims a payload this method does not have\n" + got["text"]
    )


def test_the_control_is_not_marked_and_still_renders(probed):
    """The same instructions and the same branch, landing on a boundary.

    Without this a build that marked EVERY method would satisfy every assertion
    above, and so would one that gave every block a fall-through edge.
    """
    got, _desc = probed["control"]
    assert MARKER not in got["text"], got["text"]
    assert got["ast_comments"] == [], got["ast_comments"]
    assert any(ln.startswith("return") for ln in _body(got["text"])), got["text"]


@pytest.mark.parametrize("shape", _ALL)
def test_dexllm75s_marker_stays_off(probed, shape):
    """The two flags are independent, and no craft here moves the first one.

    Every body above starts with a real instruction at offset 0, so dexllm#75's
    predicate is false for all four — including the marked three.  A fix that
    conflated the two conditions would show up here rather than as a silent
    second marker.
    """
    got, _desc = probed[shape]
    assert ENTRY_MARKER not in got["text"], f"{shape}: {got['text']}"
    assert ENTRY_MARKER.removeprefix("// ") not in (got["ast_comments"] or []), shape


@pytest.mark.parametrize("shape", _MARKED)
def test_the_marker_ends_the_declaration_line(probed, shape):
    """WHERE it goes, not merely that it is somewhere in the text.

    A line comment moved three statements later prefixes the first body
    statement and silently comments it out — a mutant that passed the whole file
    when dexllm#75 first shipped its own marker.
    """
    got, _desc = probed[shape]
    lines = got["text"].splitlines()
    hits = [i for i, ln in enumerate(lines) if MARKER in ln]
    assert len(hits) == 1, f"{shape}: {len(hits)} marked lines"
    i = hits[0]
    assert lines[i].rstrip().endswith(MARKER), f"{shape}: {lines[i]!r}"
    assert (
        lines[i + 1].strip() == "{"
    ), f"{shape}: the line after the marker is {lines[i + 1]!r}, not the body's `{{`"


# ── it does not spread ─────────────────────────────────────────────────────


@pytest.mark.parametrize("shape", _MARKED)
def test_the_class_still_decompiles_whole(probed, shape):
    """The sibling methods are untouched, and the marker does not reach them.

    The craft rewrites ONE code item; a marker driven off anything wider than
    the snapshot it belongs to would stamp the whole class.
    """
    got, _desc = probed[shape]
    assert got["class"].count(MARKER) == 1, f"{shape}: {got['class'].count(MARKER)}"
    assert "DECOMPILE ERROR" not in got["class"], got["class"][:400]


def test_a_method_with_no_instructions_is_not_marked_here(tmp_path):
    """dexllm#73's shape keeps ITS marker and does not gain this one.

    With no decodable instruction the span lookup misses for EVERY block, so an
    unguarded flag would stamp two markers on one method, one of them false.

    The craft has to be the PAYLOAD-ONLY-WITH-TRY-BLOCKS one, and that is the
    whole content of this test: `ComputeLeaders` returns early when there is no
    instruction, so simply blanking `insns_size` leaves the leader set EMPTY and
    `SplitIntoBlocks` iterates nothing — the branch under test is never reached
    and the guard passes for the wrong reason (measured: a mutant dropping the
    `!ins_storage.empty()` condition survived exactly that version).  Stage 3
    seeds a leader per try-range START, which is what makes `blocks` non-empty
    while `ins_storage` stays empty — the one state where the two predicates
    disagree.  Crafted on `invoke-custom.dex`, the only committed fixture with
    try blocks, exactly as dexllm#73 crafts it.
    """
    blob = REPO_ROOT / "tests" / "data" / "invoke-custom.dex"
    dex = blob.read_bytes()
    cands = [c for c in _code_items(dex) if c[2] != 0 and c[3] >= 6 and c[3] % 2 == 0]
    assert cands, "the fixture no longer carries a method with try blocks"
    desc, co, _tries, isz, _a, _l = cands[0]
    b = bytearray(dex)
    # One packed-switch payload filling the whole body.  The try ranges and
    # handler addresses still refer to offsets < insns_size, which is unchanged.
    size = (isz - 4) // 2
    struct.pack_into("<HHi", b, co + 16, 0x0100, size, 0)
    for k in range(size):
        struct.pack_into("<I", b, co + 24 + 4 * k, 0)
    assert len(b) == len(dex), "the craft must be length-preserving"
    path = tmp_path / "payload_try.dex"
    path.write_bytes(bytes(b))
    for lenient in (False, True):
        rows = dexllm.verify(str(path), lenient=lenient)
        assert all(r["valid"] for r in rows), (lenient, rows)

    r = subprocess.run(
        [sys.executable, "-c", _PROBE, str(path), desc],
        capture_output=True,
        text=True,
        timeout=300,
    )
    assert r.returncode == 0, r.stderr
    got = json.loads(r.stdout)
    # The premise: this really is the body-less shape, so the state under test
    # (blocks present, ins_storage empty) was actually reached.
    assert got["text"].rstrip().endswith("// no instructions"), got["text"]
    assert MARKER not in got["text"], f"two markers, one of them false\n{got['text']}"
    # dexllm#73 marks the AST STRUCTURALLY (`body: null` plus `flags` carrying
    # neither `abstract` nor `native`) rather than with a comment, so the list is
    # empty there — and this file's marker must not be what fills it.
    assert got["ast_comments"] == [], got["ast_comments"]
