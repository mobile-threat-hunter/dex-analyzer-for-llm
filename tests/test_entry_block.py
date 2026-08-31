"""dexllm#75 — a leader BELOW the first instruction must not become the entry.

``MethodSnapshotBuilder`` named block 0 the entry, with the comment ``first block
is entry (lowest byte_off)``.  The ordering half is right and the conclusion is
not.  Block 0's span starts at the lowest LEADER, and a leader is seeded per
branch target (stage 2) and per try-range start / handler address (stage 3) as
well as at the first instruction — so when the code item opens with a
switch/fill-array payload (which ``DecodeAllInsns`` skips) and any of those lands
inside it, block 0 is a span with **no instruction in it**.  It then gets no
successor from ``ComputeChildEdges`` (which skips a block with no last
instruction), so the graph is one empty block and the whole body is dropped:
``decompile_method`` renders ``{ }`` for a method whose ``render_method_smali``
lists real instructions.  A confident wrong answer on the primary LLM-facing
surface, with the two views of one method disagreeing.

The entry is chosen by CONTENT now — the block holding the first decodable
instruction — and the two rules agree wherever the old one was right.  The
equivalence is exact rather than empirical: ``ins_storage.front().byte_off`` is
itself a leader, so ``leaders[0] <= it``, and block 0 holds the first instruction
iff ``leaders[0] == it``, i.e. block 0 is non-empty iff it IS the block the new
rule looks up.

Starting at the first decodable instruction is a REINTERPRETATION, not what would
execute — a VM starts at ``insns[0]``, so a method whose first code unit is a
payload cannot run at all (ART's runtime ``method_verifier`` rejects it; the
STRUCTURAL verifier this port mirrors does not, so it loads and ``verify()``
calls it valid in BOTH modes).  Both emitters mark it, and the marker's predicate
is the WEAKER one — the first instruction is not at offset 0 — because a leading
payload is already a reinterpretation even where no leader sits inside it and the
entry choice was never wrong.  That case is the ``payload_only`` craft below, and
it is what separates the marker from the fix.

**Two routes to the entry defect, both crafted here**, because they reach the same
line through different stages and only one of them needs a try table at all:

* ``try``    — a try-range START at 0 (stage 3).  The issue's own repro shape.
* ``branch`` — an ``if-eqz`` whose target is 0 (stage 2).  ``VerifyInsns`` bounds
  a branch target's RANGE and does not require it to be an instruction boundary,
  so this is gate-legal with no try table anywhere in the method.

Every craft is on ``tests/data/method_handles.dex`` — a committed fixture — so
these run in the corpus-less CI leg and under any ``$DEXLLM_TEST_APK`` narrowing.
Each rewrites only code units INSIDE one code item's ``insns``, so it is
length-preserving to the byte: no offset, no section size and no neighbouring
structure moves, and the craft's verify verdict is asserted rather than assumed.

Crafted-only in reach: the dexllm#73 census (three independently written raw-dex
parsers over the bundled corpus, the committed fixtures, ``art/test/dexdump``,
``tools/dexter/testdata`` and all four ART fuzzer corpora) found **0** methods
whose first code units are a payload.  A packer dump or a non-javac producer is
the realistic source, which is why a corpus a/b is byte-identical by construction
and these crafts are the only thing that can show the mechanism firing.
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

MARKER = "// entry is not at offset 0"
# dexllm#77 marks a SECOND, independent reinterpretation: control ENTERING a
# block whose leader is not at an instruction boundary.  Only `branch` earns it
# here — its `if-eqz` targets code unit 0, so control genuinely reaches the block
# that starts inside the leading payload.  `try` does NOT, and the contrast is
# the sharp one: a try-range START at byte 0 makes that offset a LEADER, but
# nothing branches there and no handler names it, so `Construct`'s bfs never
# builds the block and nothing is reinterpreted.  dexllm#77's flag is qualified
# by that bfs reachability precisely so the marker cannot claim a
# reinterpretation that did not happen.  `payload_only` and `clinit` have no
# off-boundary leader at all.  Pinned per shape rather than relaxed to a
# membership test: WHICH marker each craft earns is the property, and `in` would
# lose it.
PAYLOAD_MARKER = "// control enters at a non-instruction offset"
_EXPECTED_COMMENTS = {
    "try": ["entry is not at offset 0"],
    "branch": [
        "entry is not at offset 0",
        "control enters at a non-instruction offset",
    ],
    "payload_only": ["entry is not at offset 0"],
    "clinit": ["entry is not at offset 0"],
}

# A size-0 packed-switch payload is exactly 4 code units: ident, size, first_key
# (u4).  It is the shortest thing that makes DecodeAllInsns skip the start of the
# body, and it leaves room for a real one inside the smallest candidate.
_PAYLOAD_UNITS = 4
_MIN_UNITS = _PAYLOAD_UNITS + 3


def _try_start(dex: bytes, code_off: int, insns_size: int) -> int:
    """``try_item[0].start_addr``.  The try table follows a 4-aligned insns."""
    off = code_off + 16 + insns_size * 2
    if insns_size % 2:
        off += 2
    return struct.unpack_from("<I", dex, off)[0]


@pytest.fixture(scope="module")
def targets():
    """``{"try": (desc, code_off, units), "plain": (desc, code_off, units)}``.

    Premises asserted rather than assumed — one code item with a try starting at
    0 and one with no try table at all, each with room for a payload plus a body.
    Without both, the crafts below would not produce the shapes they name and
    every assertion would hold for the wrong reason.
    """
    if not FIXTURE.is_file():  # pragma: no cover - the file is committed
        pytest.skip("tests/data/method_handles.dex missing")
    dex = FIXTURE.read_bytes()
    with_try = plain = clinit = None
    for desc, co, tries, units, _ao, _al in _code_items(dex):
        if units < _MIN_UNITS:
            continue
        if desc.endswith("-><clinit>()V") and tries == 0 and clinit is None:
            clinit = (desc, co, units)
        elif tries == 0 and plain is None:
            plain = (desc, co, units)
        elif tries and with_try is None and _try_start(dex, co, units) == 0:
            with_try = (desc, co, units)
    assert with_try, "the fixture carries no code item whose try starts at 0"
    assert plain, "the fixture carries no try-free code item of >= 7 units"
    assert clinit, "the fixture carries no try-free <clinit> of >= 7 units"
    return {"try": with_try, "plain": plain, "clinit": clinit}


def _rewrite(dex: bytes, code_off: int, units: int, body: list[int]) -> bytes:
    """Replace the code item's instruction words, keeping its LENGTH."""
    assert len(body) <= units, (len(body), units)
    b = bytearray(dex)
    for k in range(units):
        struct.pack_into(
            "<H", b, code_off + 16 + 2 * k, body[k] if k < len(body) else 0
        )
    assert len(b) == len(dex), "the craft must be length-preserving"
    return bytes(b)


_PAYLOAD = [0x0100, 0x0000, 0x0000, 0x0000]  # packed-switch, size 0, first_key 0
_CONST4 = 0x1012  # const/4 v0, #1
_RETURN_VOID = 0x000E
_IF_EQZ_BACK4 = [0x0038, 0xFFFC]  # if-eqz v0, -4  → target = code unit 0


def _craft(tmp_path: Path, targets, shape: str) -> tuple[str, str]:
    dex = FIXTURE.read_bytes()
    if shape == "try":
        # A try-range START at byte 0 is the leader inside the leading payload.
        desc, co, units = targets["try"]
        body = _PAYLOAD + [_CONST4, _RETURN_VOID]
    elif shape == "branch":
        # No try table at all: an if-eqz whose target is code unit 0.
        desc, co, units = targets["plain"]
        body = _PAYLOAD + _IF_EQZ_BACK4 + [_RETURN_VOID]
    elif shape == "payload_only":
        # A leading payload with NOTHING pointing inside it — the entry choice
        # was already right here, so only the marker may move.
        desc, co, units = targets["plain"]
        body = _PAYLOAD + [_CONST4, _RETURN_VOID]
    elif shape == "clinit":
        # A static initializer takes the SAME marker, and its declaration line is
        # the bare `static` keyword — the one shape where dexllm#73's own
        # rendering rule (`static;` is not Java) shares the line this one writes.
        desc, co, units = targets["clinit"]
        body = _PAYLOAD + [_CONST4, _RETURN_VOID]
    elif shape == "no_payload":
        # The same body rewrite on the same method WITHOUT the leading payload.
        # The control for everything above: entry at 0, nothing marked.
        desc, co, units = targets["plain"]
        body = [_CONST4, _RETURN_VOID]
    else:  # pragma: no cover - parametrisation is closed
        raise AssertionError(shape)
    path = tmp_path / f"entry_{shape}.dex"
    path.write_bytes(_rewrite(dex, co, units, body))
    # The premise: the gate accepts it.  Without this a guard could pass for the
    # wrong reason — a rejected dex never reaches the IR builder at all.
    for lenient in (False, True):
        rows = dexllm.verify(str(path), lenient=lenient)
        assert all(r["valid"] for r in rows), (shape, lenient, rows)
    return str(path), desc


# ── every observation of a CRAFTED dex is made in a CHILD ───────────────────
#
# This file sorts early, and a regression that faults in the IR builder would
# abort the whole `pytest tests/` session here rather than report.  So no
# decompile of a crafted dex runs in the pytest process: one child gathers the
# observations and the tests assert on its JSON.  (`verify` is called above — it
# is the gate, it never reaches the IR builder, and its verdict is the premise.)

_PROBE = r"""
import json, sys
import dexllm

path, desc = sys.argv[1], sys.argv[2]
cls = desc.split(";->")[0] + ";"
dk = dexllm.DexKit(path)
ast = dk.decompile_method_ast(desc)
json.dump(
    {
        "text": dk.decompile_method(desc),
        "smali": dk.render_method_smali(desc),
        "ast_comments": (ast["ast"] or {}).get("comments"),
        "ast_body": (ast["ast"] or {}).get("body"),
        "ast_source": ast["source"],
        # the AST marker exists so an include_source=False consumer can see
        # the reinterpretation — so the probe must ASK that way, which no
        # assertion did until a review pointed it out.
        "ast_comments_no_source": (
            dk.decompile_method_ast(desc, include_source=False)["ast"] or {}
        ).get("comments"),
        "class_text": dk.decompile_class(cls),
        "siblings": {
            m: dk.decompile_method(m)
            for m in dk.list_class_methods(cls)
            if m != desc
        },
        "pc_map": dk.decompile_method_with_pc_map(desc)["pc_map"],
    },
    sys.stdout,
)
"""


def _probe(path: str, desc: str) -> dict:
    r = subprocess.run(
        [sys.executable, "-c", _PROBE, path, desc],
        capture_output=True,
        text=True,
        timeout=300,
        cwd=REPO_ROOT,
    )
    assert r.returncode == 0, (r.returncode, r.stderr[-2000:])
    return json.loads(r.stdout)


@pytest.fixture(scope="module")
def probed(tmp_path_factory, targets):
    """Every shape crafted and observed once."""
    tmp = tmp_path_factory.mktemp("entry_block")
    out = {}
    for shape in ("try", "branch", "payload_only", "clinit", "no_payload"):
        path, desc = _craft(tmp, targets, shape)
        out[shape] = (_probe(path, desc), desc)
    return out


def _body(text: str) -> str:
    """Everything between the outermost braces of a single method rendering."""
    i, j = text.index("{"), text.rindex("}")
    return text[i + 1 : j].strip()


# ── the defect ──────────────────────────────────────────────────────────────


@pytest.mark.parametrize("shape", ["try", "branch"])
def test_a_leader_below_the_first_instruction_no_longer_drops_the_body(probed, shape):
    """The headline: block 0 is empty, and the body must survive anyway.

    It asserts the craft's OWN instruction — the ``return-void`` it plants — in
    both emitters, not merely that something non-empty came back.  Truthiness was
    the first cut and a correctness review MEASURED it vacuous on both halves:
    the pre-fix ``try`` shape renders ``try { } catch { } catch { }``, a
    non-empty string whose AST body is a non-empty list of one (empty)
    ``TryStatement``.  Only the ``branch`` shape renders the bare ``{ }`` that
    truthiness can see.  ``return-void`` is the right anchor because it is the
    one instruction in the craft that survives DCE — the ``const/4`` writes a
    register nothing reads.
    """
    got, _desc = probed[shape]
    body = _body(got["text"])
    assert body, f"{shape}: the body was dropped\n{got['text']}"
    assert "return;" in body, (
        f"{shape}: the craft's own return-void never reached the Writer\n"
        f"{got['text']}"
    )
    assert "ReturnStatement" in json.dumps(got["ast_body"]), (
        f"{shape}: the craft's own return-void never reached the AST — "
        f"{json.dumps(got['ast_body'])[:200]}"
    )
    assert got["pc_map"], f"{shape}: no line maps to any bytecode offset"


@pytest.mark.parametrize("shape", ["try", "branch"])
def test_the_java_view_no_longer_contradicts_the_smali_view(probed, shape):
    """The two views of one method must not disagree about whether it does anything.

    The smali listing was always right; it is the oracle here precisely because
    it is produced by a different emitter that never consults ``entry_block_id``.
    The Java side counts executable STATEMENTS rather than asking whether the
    body string is non-empty — a correctness review measured the weaker form
    PASSING against the pre-fix build for the ``try`` shape, whose dropped body
    still renders ``try { } catch { } catch { }``: braces, no statement, and the
    two views contradicting each other exactly as this test denies.
    """
    got, _desc = probed[shape]
    ops = [
        ln
        for ln in got["smali"].splitlines()
        if ln.strip().startswith("0x") and "nop" not in ln
    ]
    assert len(ops) >= 2, f"{shape}: the craft lost its own body\n{got['smali']}"
    stmts = [
        ln.strip() for ln in _body(got["text"]).splitlines() if ln.strip().endswith(";")
    ]
    assert stmts, (
        f"{shape}: smali lists {len(ops)} instructions and Java renders no "
        f"statement at all\n{got['text']}"
    )


# ── the marker ──────────────────────────────────────────────────────────────


@pytest.mark.parametrize("shape", ["try", "branch", "payload_only", "clinit"])
def test_the_reinterpretation_is_marked(probed, shape):
    """A body that does not start at offset 0 says so, on both emitters.

    ``payload_only`` is the case that separates the MARKER from the entry fix:
    nothing points inside its leading payload, so block 0 already held the first
    instruction and the entry choice does not move — only the marker fires.
    """
    got, _desc = probed[shape]
    assert MARKER in got["text"], f"{shape}: unmarked\n{got['text']}"
    assert (
        got["ast_comments"] == _EXPECTED_COMMENTS[shape]
    ), f"{shape}: AST comments {got['ast_comments']!r}"
    assert (
        got["ast_source"] == got["text"]
    ), f"{shape}: ast['source'] is not byte-identical to decompile_method"
    assert got["ast_comments_no_source"] == _EXPECTED_COMMENTS[shape], (
        f"{shape}: include_source=False loses the marker — "
        f"{got['ast_comments_no_source']!r}"
    )
    assert MARKER in got["class_text"], f"{shape}: the class rendering drops the marker"


def _marked_line(text: str, shape: str) -> tuple[list[str], int]:
    lines = text.split("\n")
    hit = [i for i, ln in enumerate(lines) if MARKER in ln]
    assert len(hit) == 1, f"{shape}: marker on {len(hit)} lines"
    return lines, hit[0]


@pytest.mark.parametrize("shape", ["try", "branch", "payload_only", "clinit"])
def test_the_marker_ends_the_declaration_line(probed, shape):
    """WHERE it is written, not merely that it is written somewhere.

    A line comment runs to the end of its line, so the only safe place for one is
    the end of a line the Writer is already finishing.  Moved a few statements
    later — after the ``{`` is emitted and before the body — it prefixes the
    first body statement instead, silently commenting it out.  ``MARKER in text``
    cannot see that: verified against exactly that mutant, which passed every
    other assertion in this file.
    """
    got, _desc = probed[shape]
    lines, i = _marked_line(got["text"], shape)
    # With dexllm#77 a craft can carry TWO markers; the LAST one must end the
    # line, and the first must still be on it.  Asserting only "a marker is
    # somewhere in the text" is what this test exists to be stronger than.
    last = MARKER if len(_EXPECTED_COMMENTS[shape]) == 1 else PAYLOAD_MARKER
    assert (
        lines[i].rstrip().endswith(last)
    ), f"{shape}: the marker does not end its line — {lines[i]!r}"
    assert MARKER in lines[i], f"{shape}: {MARKER!r} left its line — {lines[i]!r}"
    assert (
        lines[i + 1].strip() == "{"
    ), f"{shape}: the line after the marker is {lines[i + 1]!r}, not the body's `{{`"


@pytest.mark.parametrize("shape", ["try", "branch", "payload_only"])
def test_the_marked_line_is_the_signature(probed, shape):
    """…and for an ordinary method that line is the one closing the parameters."""
    got, _desc = probed[shape]
    lines, i = _marked_line(got["text"], shape)
    assert (
        "(" in lines[i] and ")" in lines[i]
    ), f"{shape}: the marker is not on the signature line — {lines[i]!r}"


def test_a_static_initializer_keeps_its_static_keyword(probed):
    """The two beyond-DAD emit rules meet on one line and must not collide.

    dexllm#73 emits a `<clinit>` as `static` with NO name, return type or
    parameters, because `static <ClassName>()` is not Java — so the line this
    marker ends is the bare keyword.  `static  // ...` followed by the block is
    valid; a marker that arrived before dexllm#73's own `;`/`{ }` decision, or
    after the `{`, would not be.
    """
    got, _desc = probed["clinit"]
    lines, i = _marked_line(got["text"], "clinit")
    assert lines[i] == f"static  {MARKER}", repr(lines[i])
    assert ";" not in lines[i], repr(lines[i])


def test_a_method_whose_code_starts_with_an_instruction_is_unmarked(probed):
    """The control: same fixture, same method, same body — no leading payload.

    Without this, a marker emitted unconditionally would satisfy every assertion
    above while appending the comment to every method in every APK.
    """
    got, _desc = probed["no_payload"]
    assert MARKER not in got["text"], got["text"]
    assert got["ast_comments"] == [], got["ast_comments"]
    assert _body(got["text"]), "the control craft lost its own body"


def test_the_marker_does_not_spread_to_the_sibling_methods(probed):
    """Only the crafted method is marked; its untouched siblings are not.

    A per-method flag read from the wrong snapshot, or a Writer that latched the
    marker across a class rendering, would show up here and nowhere else.
    """
    for shape in ("try", "branch", "payload_only", "clinit"):
        got, desc = probed[shape]
        assert got["siblings"], f"{shape}: no sibling method to compare against"
        for m, text in got["siblings"].items():
            assert MARKER not in text, f"{shape}: {m} was marked too\n{text}"
        assert got["class_text"].count(MARKER) == 1, (
            f"{shape}: the marker appears "
            f"{got['class_text'].count(MARKER)} times in one class"
        )


def test_the_two_markers_are_mutually_exclusive(tmp_path, targets):
    """A body that is ONLY payload gets dexllm#73's marker, never this one.

    They key on different states — ``code_without_instructions`` needs an EMPTY
    ``ins_storage``, ``entry_not_at_offset_zero`` a non-empty ``front()`` — so
    both firing at once would mean one of the predicates had drifted.
    """
    desc, co, units = targets["plain"]
    size = (units - 4) // 2
    body = [0x0100, size, 0x0000, 0x0000] + [0x0000] * (units - 4)
    path = tmp_path / "entry_all_payload.dex"
    path.write_bytes(_rewrite(FIXTURE.read_bytes(), co, units, body))
    for lenient in (False, True):
        rows = dexllm.verify(str(path), lenient=lenient)
        assert all(r["valid"] for r in rows), (lenient, rows)
    got = _probe(str(path), desc)
    assert "// no instructions" in got["text"], got["text"]
    assert MARKER not in got["text"], got["text"]
    assert got["ast_comments"] == [], got["ast_comments"]


# ── the one line no input can reach ─────────────────────────────────────────


def test_the_builder_bounds_its_own_entry_lookup():
    """SOURCE-level, because nothing can reach it — and that is the point.

    ``FindBlockIdForByteOff`` returns ``UINT32_MAX`` for an offset that starts no
    block, and the first instruction's offset is always seeded as a leader, so
    the miss cannot happen from any input.  Storing the sentinel unchecked would
    turn a builder invariant violation into ``entry_block_id = 0xFFFFFFFF`` — a
    value whose only reader is dexllm#73's bound one layer down, reported there
    as a malformed *snapshot* rather than as the producer bug it is.  Weaker than
    a behavioural guard (it cannot see a line that is present and wrong), which
    is why it says so.
    """
    src = (REPO_ROOT / "native/dad_cpp/method_snapshot_builder.cpp").read_text()
    i = src.index("snap->entry_block_id = entry;")
    head = src[:i]
    j = head.rindex("FindBlockIdForByteOff(snap->blocks")
    between = head[j:]
    assert (
        "UINT32_MAX" in between
    ), "the entry lookup's miss value is stored without a bound"
    assert (
        "throw std::runtime_error" in between
    ), "a builder invariant violation must be refused, not published"


# ── no false positives on the pristine fixture ──────────────────────────────


def test_the_unmodified_fixture_is_entirely_unmarked():
    """NON-DISCRIMINATING BY DESIGN on the entry fix — it is the marker's floor.

    Every real dex starts its body with an instruction, so this must hold on both
    sides of the change; it is here so a marker keyed on the wrong predicate (or
    on nothing) cannot pass the crafted guards above while flooding real output.
    The count is asserted non-zero so the sweep cannot satisfy itself by
    rendering nothing.
    """
    if not FIXTURE.is_file():  # pragma: no cover - the file is committed
        pytest.skip("tests/data/method_handles.dex missing")
    dk = dexllm.DexKit(str(FIXTURE))
    classes = dk.list_classes()
    assert len(classes) > 1, "the fixture must have real classes to sweep"
    seen = methods = 0
    for c in classes:
        text = dk.decompile_class(c)
        seen += text.count("\n")
        assert MARKER not in text, c
        # …and the AST, which the Writer sweep structurally CANNOT reach: the
        # Writer gates the marker on a non-null graph, so a flag that
        # defaulted to `true` stays invisible here and shows up only on a
        # method with no graph at all.  A review built exactly that mutant
        # and one assertion in this file was all that killed it.
        for m in dk.list_class_methods(c):
            methods += 1
            ast = dk.decompile_method_ast(m, include_source=False)["ast"]
            assert ast is None or ast["comments"] == [], m
    assert seen > 100, "the sweep rendered almost nothing, so it proves nothing"
    assert methods > 100, "the sweep reached almost no method, so it proves nothing"
