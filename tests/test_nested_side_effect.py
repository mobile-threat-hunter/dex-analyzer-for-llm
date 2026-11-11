"""A call nested in an expression is a side effect too (dexllm#124).

DAD's `has_side_effect()` looks at a node's own kind, and only
`BinaryExpression` looks at its operands, so once RegisterPropagation folded a
call into a cast, `.length`, a field read, a condition or a stored value, the
call stopped counting: dexllm#123's rules (a call does not move into a loop, a
read stays before a call, a call stays out of a try it was outside of) and
dexllm#122's handler check never saw it. The same blindness let one call be
substituted at two places when the instruction reading it named the register
twice.

The fixture is authored smali (`tests/data/nested-side-effect.smali`); each
method is what javac + d8 emit for the Java in its comment.
"""

from __future__ import annotations

import pathlib

import pytest

import dexllm

DATA = pathlib.Path(__file__).parent / "data"
FIXTURE = DATA / "nested-side-effect.dex"

EXPECTED = {
    # the cast's call runs once, before the loop
    "castIntoLoop(I)V": [
        "long v0_1 = ((long) N.next());",
        "int v2 = 0;",
        "do {",
        "N.sinkJ(v0_1);",
        "v2++;",
        "} while(v2 < p4);",
        "return;",
    ],
    "lengthIntoLoop(I)V": [
        "int v0_1 = N.arr().length;",
        "int v1 = 0;",
        "do {",
        "N.sinkI(v0_1);",
        "v1++;",
        "} while(v1 < p2);",
        "return;",
    ],
    # next() runs before mark()
    "castPastCall()V": [
        "long v0_1 = ((long) N.next());",
        "N.mark();",
        "N.sinkJ(v0_1);",
        "return;",
    ],
    # next() is outside the try
    "castIntoTry()V": [
        "long v0_1 = ((long) N.next());",
        "try {",
        "N.sinkJ(v0_1);",
        "return;",
        "} catch (RuntimeException _) {",
        "return;",
        "}",
    ],
    # F / this.f are read before the call in the condition changes them
    "staticThenIf()I": [
        "int v0_0 = N.F;",
        "if (N.next() <= 0) {",
        "return 0;",
        "} else {",
        "return v0_0;",
        "}",
    ],
    "fieldThenIf()I": [
        "int v0_0 = this.f;",
        "if (this.mutate() == 0) {",
        "return 0;",
        "} else {",
        "return v0_0;",
        "}",
    ],
    # the store's value is a call, which may write F
    "staticPastFieldStore()I": [
        "int v0 = N.F;",
        "this.g = N.next();",
        "return v0;",
    ],
    # the call between is an assignment's rhs, nested in a cast
    "staticPastAssignedCall()I": [
        "int v0 = N.F;",
        "long v2 = ((long) N.next());",
        "this.w = v2;",
        "this.w2 = v2;",
        "return v0;",
    ],
    # one call, its value read twice by one instruction: not two calls
    "readTwice()V": ["Object v0 = N.obj();", "N.two(v0, v0);", "return;"],
    "square()I": ["int v0_0 = N.next();", "return (v0_0 * v0_0);"],
    "aputSame([I)V": ["int v0 = N.next();", "p1[v0] = v0;", "return;"],
    "iputSame()V": ["N v0 = N.mk();", "v0.self = v0;", "return;"],
    "ifSame()I": [
        "int v0_0 = N.next();",
        "if (v0_0 != v0_0) {",
        "return 0;",
        "} else {",
        "return 1;",
        "}",
    ],
    # fill-array-data writes the array, so the earlier read stays before it
    "readBeforeFill([I)V": [
        "int v0 = p2[0];",
        "p2 = {7, 8};",
        "N.sinkI(v0);",
        "return;",
    ],
    # the control: read once, nothing in between — the call still folds
    "control()V": ["N.sinkJ(((long) N.next()));", "return;"],
}


@pytest.fixture(scope="module")
def dk():
    return dexllm.DexKit(str(FIXTURE))


def _body(text):
    lines = [x.strip() for x in text.split("\n")]
    i = lines.index("{")
    return [x for x in lines[i + 1 : len(lines) - 1 - lines[::-1].index("}")] if x]


def test_the_fixture_verifies():
    [row] = dexllm.verify(str(FIXTURE))
    assert row["valid"] and row["art_open"], row


@pytest.mark.parametrize("member", sorted(EXPECTED))
def test_a_nested_call_keeps_its_place_and_count(dk, member):
    assert _body(dk.decompile_method(f"LN;->{member}")) == EXPECTED[member]


def test_the_ast_runs_the_call_once_too(dk):
    """The fix is in the IR (IRForm::has_side_effect), so the AST carries the
    declaration before the call that would otherwise run twice."""
    top = dk.decompile_method_ast("LN;->readTwice()V")["ast"]["body"][2]
    assert [s[0] for s in top][:2] == [
        "LocalDeclarationStatement",
        "ExpressionStatement",
    ], top
