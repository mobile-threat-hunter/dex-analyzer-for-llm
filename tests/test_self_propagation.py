"""dexllm#76 — a definition is never propagated INTO ITSELF.

``RegisterPropagation`` (DAD ``dataflow.py:190``) substitutes a uniquely-reaching
definition into its use.  It read the reaching-definition chain without asking
WHERE that definition is, and ``ud[{var, i}] == {i}`` is a legal answer: a loop
back edge carries ``i``'s own definition to ``i``'s own use, and when no other
definition reaches — i.e. the register is READ BEFORE IT IS EVER WRITTEN — that
self-definition is the ONLY one.  ART's runtime ``method_verifier`` rejects such
a body; the structural verifier this port mirrors does not (instruction dataflow
is out of its documented scope), so the dex loads and ``verify()`` calls it valid
in BOTH modes.

Substituting a value into its own computation is meaningless, and mechanically it
splices the instruction's own rhs underneath itself: ``BinaryExpression::replace``
does ``var_map[old_v] = new_node``, so the node becomes its own operand and
``get_used_vars`` recurses without bound.  **A signal unwinds nothing**, so the
per-method ``catch (...)``, ``safe.py``'s deadline and the SDK wrapper all miss
it — it broke the two properties this project markets (0-crash on malformed dex,
``VerifyDex`` as the single gate) on a STRICT-valid dex, so ``lenient=True`` was
never the boundary.

Confirmed upstream: androguard DAD hits the identical defect on the identical
bytes, recursing in ``instruction.py:1095 BinaryExpression.get_used_vars`` until
``RecursionError``.  Python turns it into a catchable exception, C++ into an
uncatchable SIGSEGV.  So the guard is a beyond-DAD production divergence, on the
return-literal / catch-clamp precedent (no ``*DADFaithful`` sibling — the parity
suites do not assert this).

Crafted-only in reach: the condition fired **0 times** across 93 sources /
33,853 classes (the bundled corpus, every committed fixture, ``art/test/dexdump``,
``tools/dexter/testdata`` and all four ART fuzzer corpora), measured with an
instrumented build.  A corpus a/b is therefore byte-identical BY CONSTRUCTION and
these crafts are the only thing that can show the mechanism firing.

Every craft rewrites only code units INSIDE one code item's ``insns`` of the
committed ``tests/data/method_handles.dex``, so it is length-preserving to the
byte — no offset, no section size and no neighbouring structure moves — and each
craft's verify verdict is ASSERTED rather than assumed (a rejected dex never
reaches the IR builder at all, so a guard that skipped this could pass for the
wrong reason).  They run in the corpus-less CI leg and under any
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

# The crafted method, and a SIBLING in the same class that the craft never
# touches — it is the anti-vacuity anchor below.
CRAFTED = (
    "Lcom/code_intelligence/jazzer/api/FuzzedDataProvider;"
    "->pickValues(Ljava/util/Collection;I)Ljava/util/List;"
)
UNTOUCHED = (
    "Lcom/code_intelligence/jazzer/api/FuzzedDataProvider;"
    "->pickValue(Ljava/util/Collection;)Ljava/lang/Object;"
)
# `pickValue` renders its argument as a nested call, which is only possible
# because the `toArray()` temporary was PROPAGATED into it.  A build that
# disabled propagation — the way an over-broad guard (`loc <= i`, `loc >= i`)
# would — renders the temporary instead, so this line is what separates "the
# self-definition is skipped" from "propagation stopped happening".
PROPAGATED_LINE = "return this.pickValue(p5.toArray());"

_MIN_UNITS = 55  # the shapes below are laid out relative to the item's end


def _shl(dst: int, src: int, lit: int = 0xFF) -> list[int]:
    """``shl-int/lit8 vDST, vSRC, #lit`` — format 22b, two code units."""
    return [(dst << 8) | 0xE0, (lit << 8) | src]


def _add2(dst: int, src: int) -> list[int]:
    """``add-int/2addr vDST, vSRC`` — format 12x, one code unit."""
    return [(src << 12) | (dst << 8) | 0xB0]


def _if_eqz(reg: int, delta: int) -> list[int]:
    """``if-eqz vREG, +delta`` — format 21t, two code units."""
    return [(reg << 8) | 0x38, delta & 0xFFFF]


def _const4(reg: int, val: int) -> list[int]:
    """``const/4 vREG, #val`` — format 11n, one code unit."""
    return [(val << 12) | (reg << 8) | 0x12]


def _add(dst: int, a: int, b: int) -> list[int]:
    """``add-int vDST, vA, vB`` — format 23x, two code units."""
    return [(dst << 8) | 0x90, (b << 8) | a]


def _neg(dst: int, src: int) -> list[int]:
    """``neg-int vDST, vSRC`` — format 12x, one code unit."""
    return [(src << 12) | (dst << 8) | 0x7B]


def _array_length(dst: int, src: int) -> list[int]:
    """``array-length vDST, vSRC`` — format 12x, one code unit."""
    return [(src << 12) | (dst << 8) | 0x21]


def _aget(dst: int, arr: int, idx: int) -> list[int]:
    """``aget vDST, vARR, vIDX`` — format 23x, two code units."""
    return [(dst << 8) | 0x44, (idx << 8) | arr]


def _move(dst: int, src: int, obj: bool = False) -> list[int]:
    """``move``/``move-object vDST, vSRC`` — format 12x, one code unit."""
    return [(src << 12) | (dst << 8) | (0x07 if obj else 0x01)]


# Each body is `{unit_index_from_the_end: word}`.  Every one puts a register's
# own definition on a loop back edge with no other definition reaching it.
#
#   self      — the issue's own repro: `v1 = v1 << -1` with a wide back edge.
#   self_tight— the same with the back edge targeting the shl directly.
#   mutual2   — `v1 = v2 << -1; v2 = v1 << -1`, a two-instruction cycle.
#   mutual3   — the same over three registers.
#   self_2addr— the single-code-unit form, `v1 += v1`.
#
# The mutual shapes matter because they are the natural objection to a
# `loc == i` guard: they reach the cycle through TWO instructions.  Measured,
# they still create it at a `loc == i` step — the ud/du bookkeeping rewrites the
# chain onto the surviving instruction first — so the guard covers them, and
# these cases are what say so rather than an argument.
_CYCLE_SHAPES: dict[str, dict[int, int]] = {
    "self": dict(zip(range(-4, 0), _shl(1, 1) + _if_eqz(0, -41))),
    "self_tight": dict(zip(range(-4, 0), _shl(1, 1) + _if_eqz(0, -2))),
    "mutual2": dict(zip(range(-6, 0), _shl(1, 2) + _shl(2, 1) + _if_eqz(0, -4))),
    "mutual3": dict(
        zip(range(-8, 0), _shl(1, 2) + _shl(2, 3) + _shl(3, 1) + _if_eqz(0, -6))
    ),
    "self_2addr": dict(zip(range(-3, 0), _add2(1, 1) + _if_eqz(0, -1))),
    # A self-definition BESIDE a second, ordinary propagable operand.  The
    # instruction `v1 = v1 + v2` uses TWO variables: v1 is the circular one and
    # v2 is a plain constant that must still be propagated.  This is the shape
    # that separates `continue` (skip THIS variable) from `break` (abandon the
    # instruction's remaining variables too) — measured, `break` renders
    # `int v2 = 3; int v1 += v2;` where the fix renders `int v1 += 3;`.
    "self_with_sibling": dict(
        zip(range(-6, 0), _const4(2, 3) + _add(1, 1, 2) + _if_eqz(0, -3))
    ),
    # ── NOT a `BinaryExpression` ────────────────────────────────────────────
    # The five shapes above encode three different opcodes and build ONE IR
    # class.  The defect is a property of the IR being CYCLIC, not of which
    # node type holds the cycle, so a guard that only ever saw `BinaryExpression`
    # was satisfied by a narrowed fix.  Measured on a pre-fix build, each of
    # these SIGSEGVs on its own, and each recurses in its OWN `get_used_vars`
    # (and, when two classes alternate, mutually between them).
    "self_unary": dict(zip(range(-3, 0), _neg(1, 1) + _if_eqz(0, -1))),
    "self_array_length": dict(zip(range(-3, 0), _array_length(1, 1) + _if_eqz(0, -1))),
    "self_array_load": dict(zip(range(-4, 0), _aget(1, 1, 1) + _if_eqz(0, -2))),
}

# A self-definition that does NOT crash on either half, and whose rendering the
# fix nevertheless CHANGES.  `move v1, v1` is a self-assignment: pre-fix the
# propagation produced DAD's `// Both branches of the condition point to the
# same code.` form, and with the guard the loop body is empty in the TEXT while
# the AST still carries a `LocalDeclarationStatement` for `v1`.  Crafted-only —
# no real source in the a/b moves — but it is a rendering this change owns, so
# it is pinned rather than left to drift.  The text/AST fidelity difference here
# is PRE-EXISTING in kind (the AST is structural, the text is Java) and is
# recorded, not repaired: chasing the `Dummy` initializer is a separate defect
# on a read-before-write register with its own blast radius.
_NONCRASH_SHAPES: dict[str, dict[int, int]] = {
    "self_move": dict(zip(range(-3, 0), _move(1, 1) + _if_eqz(0, -1))),
    "self_move_object": dict(zip(range(-3, 0), _move(1, 1, obj=True) + _if_eqz(0, -1))),
}

# Controls: the same body MINUS one of the two ingredients.  Neither ever
# crashed, on either half — they are non-discriminating BY DESIGN and pin that
# the two ingredients are both necessary, which is what makes the shapes above
# a statement about a CYCLE rather than about arithmetic or about loops.
_CONTROL_SHAPES: dict[str, dict[int, int]] = {
    "no_self_def": dict(zip(range(-2, 0), _if_eqz(0, -41))),
    "no_back_edge": dict(zip(range(-2, 0), _shl(1, 1))),
    "mutual2_no_back_edge": dict(zip(range(-4, 0), _shl(1, 2) + _shl(2, 1))),
}


@pytest.fixture(scope="module")
def target():
    """``(code_off, units)`` of a try-free code item with room and registers.

    Premises asserted rather than assumed: without a try-free item of at least
    ``_MIN_UNITS`` code units and at least three registers, the bodies below
    would not lay out and every assertion would hold for the wrong reason.
    """
    if not FIXTURE.is_file():  # pragma: no cover - the file is committed
        pytest.fail("tests/data/method_handles.dex is committed and missing")
    dex = FIXTURE.read_bytes()
    for desc, co, tries, units, _ao, _al in _code_items(dex):
        if desc != CRAFTED:
            continue
        assert tries == 0, "the crafted item must have no try table"
        assert units >= _MIN_UNITS, (units, _MIN_UNITS)
        assert struct.unpack_from("<H", dex, co)[0] >= 4, "needs v0..v3"
        return co, units
    pytest.fail(f"the committed fixture no longer declares {CRAFTED}")


def _craft(tmp_path: Path, target, name: str, body: dict[int, int]) -> str:
    """Write the fixture with one code item's words replaced.  Verdict ASSERTED."""
    co, units = target
    dex = bytearray(FIXTURE.read_bytes())
    words = {(units + k) if k < 0 else k: w for k, w in body.items()}
    assert all(0 <= k < units for k in words), (name, sorted(words))
    for k in range(units):
        struct.pack_into("<H", dex, co + 16 + 2 * k, words.get(k, 0))
    assert len(dex) == FIXTURE.stat().st_size, "the craft must preserve length"
    path = tmp_path / f"selfprop_{name}.dex"
    path.write_bytes(bytes(dex))
    for lenient in (False, True):
        rows = dexllm.verify(str(path), lenient=lenient)
        assert all(r["valid"] for r in rows), (name, lenient, rows)
    return str(path)


# ── every observation of a CRAFTED dex is made in a CHILD ───────────────────
#
# The defect this file guards is an uncatchable SIGSEGV.  An in-process
# assertion cannot survive the thing it asserts about — a regression would abort
# the whole `pytest tests/` session here rather than report — so one child
# gathers the observations and the tests assert on its JSON and its EXIT STATUS.
# (`verify` is called above: it is the gate, it never reaches the IR builder,
# and its verdict is the craft's premise.)

_PROBE = r"""
import json, sys
import dexllm

path, crafted, untouched = sys.argv[1], sys.argv[2], sys.argv[3]
dk = dexllm.DexKit(path)
cls = crafted.split(";->")[0] + ";"
ast = dk.decompile_method_ast(crafted)
json.dump(
    {
        "text": dk.decompile_method(crafted),
        "smali": dk.render_method_smali(crafted),
        "ast_source": ast["source"],
        "ast_body": (ast["ast"] or {}).get("body"),
        "class_text": dk.decompile_class(cls),
        "untouched": dk.decompile_method(untouched),
        "classes": len(dk.list_classes()),
    },
    sys.stdout,
)
"""


def _probe(path: str) -> dict:
    """Run the child; a nonzero exit is the failure this file exists to catch."""
    r = subprocess.run(
        [sys.executable, "-c", _PROBE, path, CRAFTED, UNTOUCHED],
        capture_output=True,
        text=True,
        timeout=300,
    )
    assert r.returncode == 0, (
        f"decompiling the crafted dex exited {r.returncode} "
        f"({'SIGNAL' if r.returncode < 0 else 'error'}) — dexllm#76 is back.\n"
        f"{r.stderr[-2000:]}"
    )
    return json.loads(r.stdout)


# The exact loop body each shape must render.  Pinned as LITERALS, because
# "it did not crash" is satisfied by a build that stopped propagating
# ANYTHING — and by several near-miss guards that stop it in the wrong place.
# Two mutants that survived a no-crash-only version of this file are killed
# here and nowhere else:
#
#   `loc >= i`  suppresses legitimate loop-carried (backward) propagation as
#               well as the self-definition, so `mutual2` renders under v2 and
#               `mutual3` never folds.  0 REAL corpus sources move under it, so
#               only a crafted body can state the difference.
#   `break`     abandons the instruction's REMAINING variables, so the sibling
#               constant in `self_with_sibling` is left as a temporary.
_EXPECTED_BODY: dict[str, list[str]] = {
    "self": ["int v1 <<= -1;"],
    "self_tight": ["int v1 <<= -1;"],
    "mutual2": ["int v1 = ((v1 << -1) << -1);"],
    "mutual3": ["int v3 = (((v3 << -1) << -1) << -1);"],
    "self_2addr": ["int v1 += v1;"],
    "self_with_sibling": ["int v1 += 3;"],
    "self_unary": ["unknownType v1 = (- v1);"],
    "self_array_length": ["int v1 = v1.length;"],
    "self_array_load": ["unknownType v1 = v1[v1];"],
    "self_move": [],
    "self_move_object": [],
}


def _loop_body(text: str) -> list[str]:
    """The statements between ``do {`` and ``} while(...)``."""
    lines = [ln.strip() for ln in text.splitlines() if ln.strip()]
    assert "do {" in lines, text
    return lines[lines.index("do {") + 1 : -2]


@pytest.mark.parametrize("shape", sorted(_CYCLE_SHAPES))
def test_a_self_defining_value_does_not_crash_the_decompiler(tmp_path, target, shape):
    """The six cycle shapes all render instead of faulting.

    ``mutual2`` / ``mutual3`` are the ones that make this a claim about the
    guard rather than about one instruction: they build the cycle through two
    and three instructions respectively, and they still create it at a
    ``loc == i`` step because the ud/du bookkeeping rewrites the chain onto the
    surviving instruction first.
    """
    got = _probe(_craft(tmp_path, target, shape, _CYCLE_SHAPES[shape]))
    assert got["classes"] == 24, got["classes"]
    assert "DECOMPILE ERROR" not in got["text"], got["text"]
    assert got["ast_body"] is not None, "the body must survive as an AST too"
    assert _loop_body(got["text"]) == _EXPECTED_BODY[shape], got["text"]


@pytest.mark.parametrize("shape", sorted(_CONTROL_SHAPES))
def test_the_control_shapes_are_unaffected(tmp_path, target, shape):
    """Non-discriminating BY DESIGN — these never faulted on either half.

    They pin that BOTH ingredients are needed, so the tests above are a
    statement about a self-definition on a back edge and not about arithmetic
    or about loops on their own.
    """
    got = _probe(_craft(tmp_path, target, shape, _CONTROL_SHAPES[shape]))
    assert "DECOMPILE ERROR" not in got["text"], got["text"]


def test_the_self_defining_body_is_RENDERED_not_masked(tmp_path, target):
    """The repro renders the instruction the bytecode actually carries.

    This is what separates a ROOT fix from a MASK.  A recursion-depth cap on
    ``get_used_vars`` — the shape CLAUDE.md records being REMOVED for hiding a
    real port bug — would also stop the crash, and would leave the deeply
    nested self-substituted expression in the output.  The guard skips the
    substitution, so the shift-assign appears exactly once, at its own operand.
    """
    got = _probe(_craft(tmp_path, target, "self", _CYCLE_SHAPES["self"]))
    body = [ln.strip() for ln in got["text"].splitlines() if ln.strip()]
    assert "int v1 <<= -1;" in body, got["text"]
    assert sum(ln.count("<<=") for ln in body) == 1, got["text"]
    # the two views of one method must agree: smali lists the shl too
    assert "shl-int/lit8" in got["smali"], got["smali"][:400]


@pytest.mark.parametrize("shape", sorted(_CYCLE_SHAPES) + sorted(_NONCRASH_SHAPES))
def test_the_text_and_the_ast_agree(tmp_path, target, shape):
    """``decompile_method_ast(...)['source']`` runs the same Writer.

    Parametrised over EVERY shape, including the two that never crashed: a
    single-shape version of this could not see a rendering the fix changes on
    a shape it was not run against.
    """
    body = {**_CYCLE_SHAPES, **_NONCRASH_SHAPES}[shape]
    got = _probe(_craft(tmp_path, target, shape, body))
    assert got["ast_source"] == got["text"]


@pytest.mark.parametrize("shape", sorted(_NONCRASH_SHAPES))
def test_a_self_move_renders_an_empty_loop_body(tmp_path, target, shape):
    """A self-assignment is a no-op, and the TEXT says so.

    Neither shape ever faulted, so this is not about the crash — it pins a
    rendering this change owns. The AST is deliberately NOT asserted equal to
    the text here: it still carries a declaration of the register, which is a
    structural-vs-Java fidelity difference recorded above rather than repaired.
    """
    got = _probe(_craft(tmp_path, target, shape, _NONCRASH_SHAPES[shape]))
    assert _loop_body(got["text"]) == [], got["text"]
    assert "Both branches" not in got["text"], got["text"]
    assert got["ast_body"] is not None


def test_the_whole_class_still_decompiles(tmp_path, target):
    """The crafted method must not take its 23 siblings down with it."""
    got = _probe(_craft(tmp_path, target, "self", _CYCLE_SHAPES["self"]))
    assert got["class_text"].count("\n") > 20, got["class_text"]
    assert PROPAGATED_LINE in got["class_text"]


@pytest.mark.parametrize("shape", ["self", "mutual2", "self_2addr"])
def test_propagation_still_happens_in_the_same_dex(tmp_path, target, shape):
    """ANTI-VACUITY — the guard is scoped to the self-definition.

    Every other test here passes trivially against a build whose
    ``RegisterPropagation`` does nothing at all, which is exactly what an
    over-broad guard (``loc <= i``, ``loc >= i``, or the pass deleted) would
    produce: no propagation, no substitution, no cycle, no crash.  A sibling
    method in the SAME crafted file still renders its argument as a nested
    call, which requires the temporary to have been propagated.
    """
    got = _probe(_craft(tmp_path, target, shape, _CYCLE_SHAPES[shape]))
    assert PROPAGATED_LINE in got["untouched"], got["untouched"]


def test_a_sibling_operand_is_still_propagated(tmp_path, target):
    """The guard skips ONE variable, not the instruction.

    ``v1 = v1 + v2`` is circular in ``v1`` and perfectly ordinary in ``v2``.
    Abandoning the instruction (``break``) leaves the constant as a temporary,
    which is a real loss of quality on a shape the fix is supposed to leave
    alone — so the difference is pinned rather than argued.
    """
    got = _probe(
        _craft(
            tmp_path, target, "self_with_sibling", _CYCLE_SHAPES["self_with_sibling"]
        )
    )
    assert _loop_body(got["text"]) == ["int v1 += 3;"], got["text"]


def test_propagation_still_happens_in_the_pristine_fixture():
    """The same anchor on the UNMODIFIED fixture, in-process.

    No craft is involved, so this one holds even if the crafting helper ever
    stops producing the shape it names.
    """
    dk = dexllm.DexKit(str(FIXTURE))
    assert PROPAGATED_LINE in dk.decompile_method(UNTOUCHED)
