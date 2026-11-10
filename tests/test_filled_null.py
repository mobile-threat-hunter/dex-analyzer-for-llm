"""A `filled-new-array` element is a typed position (dexllm#117).

Every `const*` builds an int-typed Constant (DAD); its real type comes from the
position. dexllm#102 gave return / local / argument / iput / sput / aput /
check-cast / throw that projection (`ConstantAt`), and a filled-new-array
element was the one position left out: a `0` in an `Object[]` rendered `0`,
which Java reads as an autoboxed Integer -- a different value from the null the
bytecode passes.

The fixture is authored smali (`tests/data/filled-null.smali`), one method per
shape, so every case runs corpus-less.
"""

from __future__ import annotations

import pathlib
import re

import pytest
from conftest import require_corpus_shape

import dexllm

DATA = pathlib.Path(__file__).parent / "data"
FIXTURE = DATA / "filled-null.dex"
CLS = "LFilledNull;"

EXPECTED = {
    "refNull(Ljava/lang/Object;)[Ljava/lang/Object;": "return new Object[] {p2, null};",
    "strNullFirst()[Ljava/lang/String;": 'return new String[] {null, "a"};',
    "intZero()[I": "return new int[] {0, 1};",
    "nestedNull()[[I": "return new int[][] {null};",
    "refOne()[Ljava/lang/Object;": "return new Object[] {1};",
    "sharedZero()[Ljava/lang/Object;": "return new Object[] {null, new int[] {0}};",
    # dexllm#97: the /range form keeps its middle register too
    "rangeNulls()[Ljava/lang/Object;": 'return new Object[] {null, "a", null};',
    "rangeOne()[I": "return new int[] {7};",  # was {7, 7}: first == last
    "rangeTwo()[I": "return new int[] {7, 6};",  # the control
}


@pytest.fixture(scope="module")
def dk():
    return dexllm.DexKit(str(FIXTURE))


def _return_line(dk, member):
    text = dk.decompile_method(f"{CLS}->{member}")
    [line] = [x.strip() for x in text.split("\n") if x.strip().startswith("return ")]
    return line


def test_the_fixture_verifies_and_declares_every_case(dk):
    [row] = dexllm.verify(str(FIXTURE))
    assert row["valid"] and row["art_open"], row
    declared = {m.split("->", 1)[1] for m in dk.list_class_methods(CLS)}
    assert set(EXPECTED) <= declared, set(EXPECTED) - declared


@pytest.mark.parametrize("member", sorted(EXPECTED))
def test_each_element_renders_its_position_type(dk, member):
    assert _return_line(dk, member) == EXPECTED[member]


def _ast_literals(node, out):
    """Every ["Literal", text, [kind, ...]] inside ArrayInitializer nodes."""
    if isinstance(node, list):
        if node and node[0] == "ArrayInitializer":
            for e in node[1]:
                if isinstance(e, list) and e and e[0] == "Literal":
                    out.append((e[1], e[2][0]))
        for x in node:
            _ast_literals(x, out)
    return out


@pytest.mark.parametrize("member", sorted(EXPECTED))
def test_the_ast_agrees_with_the_text(dk, member):
    """Each emitter calls the projection separately, so each has its own guard:
    the AST's element literals must be the ones the text line spells."""
    ast = dk.decompile_method_ast(f"{CLS}->{member}")["ast"]
    lits = [(t, k) for t, k in _ast_literals(ast["body"], []) if k in (".null", ".int")]
    line = _return_line(dk, member)
    spelled = re.findall(r'null|"[^"]*"|\b\d+\b', line.split("{", 1)[1])
    assert [t for t, _ in lits] == [s for s in spelled if not s.startswith('"')], (
        lits,
        line,
    )
    assert all(kind == ".null" for t, kind in lits if t == "null"), lits
    assert all(kind == ".int" for t, kind in lits if t != "null"), lits


def test_the_corpus_case_from_the_issue(loadable_apks):
    """HandlerDispatcherKt.asHandler passes null as Handler's Callback argument."""
    desc = (
        "Lkotlinx/coroutines/android/HandlerDispatcherKt;->"
        "asHandler(Landroid/os/Looper;Z)Landroid/os/Handler;"
    )
    hits = []
    for apk in loadable_apks:
        dk = dexllm.DexKit(apk)
        if dk.locate_class_dex(desc.split("->")[0]) < 0:
            continue
        text = dk.decompile_method(desc)
        hits.append(text)
        assert "new Object[] {p7, null, Boolean.valueOf(true)}" in text, text
        assert "new Object[] {p7, 0," not in text
    require_corpus_shape(bool(hits), "HandlerDispatcherKt.asHandler", "dexllm#117")


def test_both_emitters_read_the_shared_position_rule():
    """A correct inline re-derivation in one emitter passes every behavioural
    case and drifts on the first edit (dexllm#102's lesson) -- so both must call
    the one helper."""
    root = pathlib.Path(__file__).resolve().parents[1] / "native" / "dad_cpp"
    for f in ("writer.cpp", "dast.cpp"):
        src = (root / f).read_text()
        assert src.count("FilledArrayElementPositionType(") == 1, f


def test_the_ast_carries_a_null_literal_node(dk):
    """Absolute, not only relative: a revert of BOTH emitters keeps text and AST
    agreeing, so the AST node itself is pinned."""
    ast = dk.decompile_method_ast(
        f"{CLS}->refNull(Ljava/lang/Object;)[Ljava/lang/Object;"
    )["ast"]
    assert _ast_literals(ast["body"], []) == [("null", ".null")]
