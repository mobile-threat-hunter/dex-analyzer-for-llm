"""An operand Java evaluates earlier does not run a later instruction (dexllm#125).

Java evaluates the operands of a call, an operator and a store left to right.
RegisterPropagation folded a definition into an operand without asking what
the operands BEFORE it already held: `int x = F; use((long) next(), x)` became
`use(((long) next()), F)`, which reads `F` after `next()` has changed it.
ClearPath scans only the instructions between a definition and its use, so it
could not see a call that had already been folded into the use itself. The
mirror case is a call moved PAST a memory read in an intervening statement
(`x = next(); W r = OBJ; r.m(x)` rendered `W v0 = W.OBJ; v0.m(W.next())`):
ClearPath stopped a call only at another side effect, never at a read.

A read of a field a loaded dex declares FINAL is exempt when no method of its
class other than an initializer writes it (ART lets any method of the
declaring class write the class's own final field), except inside that
class's own `<init>` / `<clinit>`, and, for a static field, only in a method
of the same class (a first read of another class's static runs its
`<clinit>`). A field whose declaration is not loaded (a framework field) is
ordered like any other.

The fixture is authored smali (`tests/data/arg-order.smali`); each method
carries the Java it was written from.
"""

from __future__ import annotations

import pathlib

import pytest

import dexllm

DATA = pathlib.Path(__file__).parent / "data"
FIXTURE = DATA / "arg-order.dex"

EXPECTED = {
    # the issue's shape: F is read before next() runs
    "castThenStatic()V": [
        "int v0 = W.F;",
        "W.useJI(((long) W.next()), v0);",
        "return;",
    ],
    "arithThenStatic()V": [
        "int v0 = W.F;",
        "W.useII((W.next() + 1), v0);",
        "return;",
    ],
    "binaryOperands()V": [
        "int v0 = W.F;",
        "W.useI((W.next() + v0));",
        "return;",
    ],
    "instanceThenCall()V": [
        "int v0 = this.f;",
        "W.useII(this.mutate(), v0);",
        "return;",
    ],
    "elementThenCall([I)V": [
        "int v0 = p3[0];",
        "W.useII(W.next(), v0);",
        "return;",
    ],
    "twoCallsSwapped()V": [
        "int v0 = W.a();",
        "W.useII(W.b(), v0);",
        "return;",
    ],
    # the array is evaluated before the value, and next() ran first
    "storeValueFirst()V": [
        "int v0 = W.next();",
        "W.arr()[0] = v0;",
        "return;",
    ],
    # a final field cannot be changed by the call, so its read may move...
    "finalInstanceThenCall()V": ["W.useII(this.mutate(), this.ff);", "return;"],
    "finalStaticThenCall()V": ["W.useII(W.next(), W.FF);", "return;"],
    "callPastFinalRead()V": [
        "int v0 = this.ff;",
        "W.useII(v0, W.next());",
        "W.useI(v0);",
        "return;",
    ],
    # ...unless another method of its class writes it (ART allows that)...
    "writtenFinalThenCall()V": [
        "int v0 = this.gg;",
        "W.useII(this.setGG(), v0);",
        "return;",
    ],
    "writtenStaticFinalThenCall()V": [
        "int v0 = W.HH;",
        "W.useII(W.setHH(), v0);",
        "return;",
    ],
    # ...or it is a static of another class, whose first read runs <clinit>...
    "otherClassStaticFinal()V": [
        "int v0 = V.X;",
        "W.useII(W.next(), v0);",
        "return;",
    ],
    # ...or we are in its own class's initializer, where it is still written
    "<init>(I)V": [
        "this.ff = p3;",
        "int v0 = this.ff;",
        "W.useII(this.mutate(), v0);",
        "return;",
    ],
    # the receiver is evaluated first but was read after next(): the call
    # stays before the read rather than moving past it
    "callPastRead()V": [
        "int v1 = W.next();",
        "int v0 = this.f;",
        "W.useII(v0, v1);",
        "W.useI(v0);",
        "return;",
    ],
    "receiverAfterCall()V": ["int v1 = W.next();", "W.OBJ.m(v1);", "return;"],
    # a folded copy chain leaves a stale id in the move's var_map; it is not
    # an operand, so the copies still fold
    "copyChainThenCall()V": [
        "int v2 = W.F;",
        "W.useII(W.next(), v2);",
        "W.useI(v2);",
        "return;",
    ],
    "copyChainNoCall()V": ["int v2 = W.F;", "W.useI(v2);", "W.useI(v2);", "return;"],
    # controls: Java's order is the bytecode's, so everything still folds
    "callFirst()V": ["W.useII(W.next(), W.F);", "return;"],
    "twoCallsInOrder()V": ["W.useII(W.a(), W.b());", "return;"],
    "receiverFirst()V": ["W.OBJ.m(W.next());", "return;"],
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
def test_an_operand_keeps_the_bytecode_order(dk, member):
    assert _body(dk.decompile_method(f"LW;->{member}")) == EXPECTED[member]


def test_the_ast_reads_the_field_first_too(dk):
    """The rule is in the IR (RegisterPropagation), so the AST declares the
    read before the call as the text does."""
    body = dk.decompile_method_ast("LW;->castThenStatic()V")["ast"]["body"][2]
    assert [s[0] for s in body][:2] == [
        "LocalDeclarationStatement",
        "ExpressionStatement",
    ], body
