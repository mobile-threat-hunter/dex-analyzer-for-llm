"""An unconditional call is not moved into a branch (dexllm#126).

RegisterPropagation substituted a call into its single use whenever nothing
between them blocked it, without asking whether the use runs on every path
from the call: `x = f(); if (c) use(x)` became `if (c) use(f())`, which runs
`f()` only when `c` holds. dexllm#123 stopped a call moving into a loop; this
is the branch case. A side-effecting definition now moves only into a block
every normal path from its own block passes through, where a path that stays
forever in a cycle no normal edge leaves (an infinite loop, or one left only
by an exception) counts as one that skips it.

The fixture is authored smali (`tests/data/branch-call.smali`); each method
carries the Java it was written from.
"""

from __future__ import annotations

import pathlib

import pytest

import dexllm

DATA = pathlib.Path(__file__).parent / "data"
FIXTURE = DATA / "branch-call.dex"

EXPECTED = {
    "intoIf(I)V": [
        "int v0 = B.next();",
        "if (p1 != 0) {",
        "B.useI(v0);",
        "}",
        "return;",
    ],
    # the throw path skips the use, and next() runs before the test
    "pastThrowGuard(I)V": [
        "int v0 = B.next();",
        "if (p2 != 0) {",
        "B.useI(v0);",
        "return;",
        "} else {",
        "throw new RuntimeException();",
        "}",
    ],
    "pastEarlyReturn(I)V": [
        "int v0 = B.next();",
        "if (p1 == 0) {",
        "B.useI(v0);",
        "return;",
        "} else {",
        "return;",
        "}",
    ],
    # the path that skips the use never ends: still not a use on every path
    "pastInfiniteLoop(I)V": [
        "int v0 = B.next();",
        "if (p1 != 0) {",
        "B.useI(v0);",
        "return;",
        "}",
        "while(true) {",
        "B.spin();",
        "}",
    ],
    # a loop left only by an exception has no normal exit either
    "pastWorkerLoop(Ljava/util/concurrent/BlockingQueue;I)V": [
        "int v0 = p1.size();",
        "if (p2 != 0) {",
        "Integer.valueOf(v0);",
        "return;",
        "}",
        "while(true) {",
        "p1.take();",
        "}",
    ],
    # control: a loop with an exit edge is taken to terminate
    "pastTerminatingLoop(I)V": [
        "while (p1 != 0) {",
        "p1--;",
        "}",
        "B.useI(B.next());",
        "return;",
    ],
    # control: the use runs on every path, so next() still folds into it
    "acrossDiamond(I)V": [
        "int v1;",
        "if (p2 == 0) {",
        "v1 = 2;",
        "} else {",
        "v1 = 1;",
        "}",
        "B.useII(B.next(), v1);",
        "return;",
    ],
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
def test_a_call_runs_on_every_path_it_ran_on(dk, member):
    assert _body(dk.decompile_method(f"LB;->{member}")) == EXPECTED[member]


def test_the_ast_runs_the_call_before_the_branch_too(dk):
    """The rule is in the IR (RegisterPropagation), so the AST declares the
    call before the `if` as the text does."""
    body = dk.decompile_method_ast("LB;->intoIf(I)V")["ast"]["body"][2]
    assert [s[0] for s in body][:2] == [
        "LocalDeclarationStatement",
        "IfStatement",
    ], body


def test_the_corpus_case(dk):
    apk = DATA.parent.parent / "test_apk" / "APK" / "com.example.android.tvleanback.apk"
    if not apk.exists():
        pytest.skip("bundled corpus not present")
    corpus = dexllm.DexKit(str(apk))
    body = _body(
        corpus.decompile_method(
            "Landroid/support/v17/leanback/media/PlaybackControlGlue;->updateProgress()V"
        )
    )
    assert body[0] == "int v0 = this.getCurrentPosition();", body
    assert "this.mControlsRow.setCurrentTime(v0);" in body, body
