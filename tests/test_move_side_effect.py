"""A move a call was folded into keeps the call's side effect (dexllm#123).

RegisterPropagation folds `v1 = make()` into the move that copies it, giving
`v0 = make()`. DAD's MoveExpression answers "no side effect" whatever its rhs,
so the folded call was then carried past a side-effecting statement: the
decompiled text ran the constructor AFTER a store it ran before. The same loophole
let OTHER expressions be propagated across a folded call, which DAD otherwise
refuses; with it closed, a plain register copy is the one thing allowed across a
call, since a call cannot change a register.

The fixture is authored smali (`tests/data/move-side-effect.smali`).
"""

from __future__ import annotations

import pathlib

import pytest
from conftest import require_corpus_shape

import dexllm

DATA = pathlib.Path(__file__).parent / "data"
FIXTURE = DATA / "move-side-effect.dex"

EXPECTED = {
    "ctorThenStore()LD;": ["D v0 = new D();", "D.I = 5;", "return v0;"],
    "callThenStore()Ljava/lang/Object;": [
        "Object v0 = D.make();",
        "D.I = 5;",
        "return v0;",
    ],
    # the control: nothing in between, the call still folds into the return
    "callNoStore()Ljava/lang/Object;": ["return D.make();"],
    # a plain copy still crosses a call folded into a move
    "copyAcrossFoldedCall()V": [
        "Object v1 = D.make();",
        "D.use(D.make());",
        "D.use(v1);",
        "D.use(v1);",
        "return;",
    ],
    # the copy's source is redefined first: the copy keeps the OLD value
    "copySourceRedefined()V": [
        "Object v1_0 = D.make();",
        "D.use(v1_0);",
        "D.use(D.make());",
        "D.use(v1_0);",
        "return;",
    ],
    # a field read is not a plain copy: the call between may change the field
    "fieldAcrossCall()V": [
        "Object v0 = this.f;",
        "this.change();",
        "D.use(v0);",
        "return;",
    ],
    # around a loop the source keeps ONE name, so only the redefinition check
    # keeps the copy from reading the incremented value
    "copyInLoop()V": [
        "int v1 = 0;",
        "do {",
        "int v0_0 = v1;",
        "v1++;",
        "D.useI(v0_0);",
        "} while(v1 < 3);",
        "return;",
    ],
    # the use's block is a one-block loop that redefines the copy's source after
    # the use: from the second iteration the source holds "x", so the copy stays
    "loopCopy(Z)V": [
        "String v1 = D.make();",
        "Object v0 = v1;",
        "D.make();",
        "do {",
        "D.use(v0);",
        "D.use(v1);",
        'v1 = "x";',
        "} while(!p2);",
        "return;",
    ],
    # the same with no call between: DAD itself propagated this one (wrongly)
    "loopNoCall(Z)V": [
        "String v1 = D.make();",
        "Object v0 = v1;",
        "do {",
        "D.use(v0);",
        "D.use(v1);",
        'v1 = "x";',
        "} while(!p2);",
        "return;",
    ],
    # a call before a loop runs once: it stays out of the loop
    "callIntoLoop()V": [
        "Object v2 = D.make();",
        "int v0 = 0;",
        "do {",
        "D.use(v2);",
        "v0++;",
        "} while(v0 < 3);",
        "return;",
    ],
    # a field read before a loop that changes the field stays out of it
    "fieldIntoLoop()V": [
        "Object v2 = this.f;",
        "int v0 = 0;",
        "do {",
        "D.use(v2);",
        "this.change();",
        "v0++;",
        "} while(v0 < 3);",
        "return;",
    ],
    # a plain copy still folds into a loop with a call in it
    "copyIntoLoop()V": [
        "Object v3 = D.make();",
        "int v0 = 0;",
        "do {",
        "D.use(v3);",
        "D.make();",
        "v0++;",
        "} while(v0 < 3);",
        "D.use(v3);",
        "return;",
    ],
    # the definition re-runs on the way round, so it still folds into its use
    "defInLoop(I)V": [
        "int v1 = 0;",
        "do {",
        "// Both branches of the condition point to the same code.",
        "// if (p3 == 0) {",
        "D.useI((v1 + 7));",
        "v1++;",
        "// }",
        "} while(v1 < 3);",
        "return;",
    ],
    # the redefinition is the LAST instruction of the use's block (it ends in a goto)
    "loopGoto(Z)V": [
        "String v1 = D.make();",
        "Object v0 = v1;",
        "while (p2) {",
        "D.use(v0);",
        "D.use(v1);",
        'v1 = "x";',
        "}",
        "return;",
    ],
    # the loop reads the call's result with no side effect of its own: the
    # call still stays before the loop
    "callIntoLoopArith()V": [
        "int v2 = D.num();",
        "int v0 = 0;",
        "do {",
        "int v3 = (v2 + v0);",
        "v0++;",
        "} while(v0 < 3);",
        "D.useI(v3);",
        "return;",
    ],
    # a static field read reads no register: it stays before a store to the field
    "sgetThenPut()V": ["int v0 = D.G;", "D.G = 7;", "D.useI(v0);", "return;"],
    "sgetIntoLoop(I)V": [
        "int v0 = D.G;",
        "int v1 = 0;",
        "do {",
        "D.useI(v0);",
        "D.G = v1;",
        "v1++;",
        "} while(v1 < p2);",
        "return;",
    ],
    # a folded call with an argument stays outside the try it was outside of
    "callIntoTry(Ljava/lang/Object;)V": [
        "Object v0 = D.wrap(p2);",
        "try {",
        "D.use(v0);",
        "return;",
        "} catch (RuntimeException _) {",
        "return;",
        "}",
    ],
    # only what can write a static field keeps a static read in place: a call
    "sgetPastCall()V": ["int v0 = D.G;", "D.make();", "D.useI(v0);", "return;"],
    # an array store cannot, so the read still folds
    "sgetPastArrayStore([I)V": ["p2[0] = 0;", "D.useI(D.G);", "return;"],
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
def test_side_effects_keep_their_bytecode_order(dk, member):
    assert _body(dk.decompile_method(f"LD;->{member}")) == EXPECTED[member]


@pytest.mark.parametrize(
    "member", ["ctorThenStore()LD;", "callThenStore()Ljava/lang/Object;"]
)
def test_the_ast_keeps_the_order_too(dk, member):
    """The fix is in the IR (MoveExpression::has_side_effect), so the AST must
    put the call's declaration before the store, not inside the return."""
    top = dk.decompile_method_ast(f"LD;->{member}")["ast"]["body"][2]
    assert [s[0] for s in top] == [
        "LocalDeclarationStatement",
        "ExpressionStatement",
        "ReturnStatement",
    ], top
    assert top[2][1][0] == "Local", top[2]


_KEYFRAMES = (
    "Landroid/support/graphics/drawable/AnimatorInflaterCompat;"
    "->distributeKeyframes([Landroid/animation/Keyframe;FII)V"
)


def test_a_loop_invariant_is_not_moved_into_the_loop(loadable_apks):
    """The corpus shape behind the loop fix: `p3 / ((p5 - p4) + 2)` is computed
    ONCE before the loop, and `p4++` in the loop's one block changes `p4`. DAD
    (and the OFF build) moved the division into the loop, where it reads the
    changing `p4` -- a wrong value, with no call involved at all."""
    seen = 0
    for path in loadable_apks:
        dk = dexllm.DexKit(path)
        if dk.locate_class_dex(_KEYFRAMES.split("->")[0]) < 0:
            continue
        smali = dk.render_method_smali(_KEYFRAMES)
        if "div-float/2addr v3, v0" not in smali or "goto" not in smali:
            continue  # another build of the class
        body = _body(dk.decompile_method(_KEYFRAMES))
        assert body[0] == "float v3_1 = (p3 / ((float) ((p5 - p4) + 2)));", body
        assert "(p2[(p4 - 1)].getFraction() + v3_1)" in "".join(body), body
        seen += 1
    require_corpus_shape(
        seen, "AnimatorInflaterCompat.distributeKeyframes", "the guard ran on nothing"
    )
