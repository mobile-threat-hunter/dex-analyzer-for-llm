"""A loop with a second back edge is not a do-while, and a back edge is `continue` (dexllm#138).

DAD types a loop posttest whenever the latch it settled on (the last back edge
MarkLoop saw) is a condition. A loop with several back edges, or whose latch
test stays in the loop on both branches, is not a do-while: rendered as one,
the other back edges read as falling off the body and the latch's in-loop
branch -- the header -- became the loop's follow, so a branch back to the
header was written `break` and the body after it was lost
(``ShortcutXmlParser.parseShortcutIds`` dropped ``List.add``). Such a loop is
typed as if its latch were not a test, and a back edge to an endless or pretest
loop's header from a point that does not fall off the end of the body is now
written ``continue`` -- DAD has no ``continue``, and such an edge fell through
into whatever join code the walk wrote next.

The fixture is authored smali (``tests/data/continue-loop.smali``).
"""

from __future__ import annotations

import collections
import pathlib
import re

import pytest

import dexllm

DATA = pathlib.Path(__file__).parent / "data"
FIXTURE = DATA / "continue-loop.dex"
CORPUS = pathlib.Path(__file__).parent.parent / "test_apk" / "APK"

BODIES = {
    "multiLatch()I": [
        "while(true) {",
        "int v0 = L.n();",
        "if (v0 == 0) {",
        "break;",
        "}",
        "if ((L.t(v0)) && (L.t2(v0))) {",
        "L.add(v0);",
        "}",
        "}",
        "return 1;",
    ],
    "continueJoin()V": [
        "while(true) {",
        "int v0 = L.n();",
        "if (v0 == 0) {",
        "break;",
        "}",
        "if (L.t(v0)) {",
        "if (L.t2(v0)) {",
        "L.a();",
        "} else {",
        "continue;",
        "}",
        "}",
        "L.b();",
        "}",
        "return;",
    ],
    "pretestJoin(I)V": [
        "while (p1 > 0) {",
        "p1--;",
        "if (L.t(p1)) {",
        "if (L.t2(p1)) {",
        "L.a();",
        "} else {",
        "continue;",
        "}",
        "}",
        "L.b();",
        "}",
        "return;",
    ],
    "switchTail()V": [
        "while(true) {",
        "int v0 = L.n();",
        "if (v0 == 0) {",
        "break;",
        "}",
        "switch (v0) {",
        "case 1:",
        "L.a();",
        "break;",
        "case 2:",
        "L.add(v0);",
        "break;",
        "default:",
        "L.b();",
        "}",
        "}",
        "return;",
    ],
    "sharedLatch()V": [
        "while(true) {",
        "int v0 = L.n();",
        "if (v0 == 0) {",
        "break;",
        "}",
        "if (!L.t(v0)) {",
        "continue;",
        "}",
        "while (L.n() != v0) {",
        "}",
        "}",
        "return;",
    ],
    # a try at the end of the body: leaving it reaches the header, so neither
    # the try nor the catch writes `continue`
    "tryTail()V": [
        "while (L.n() != 0) {",
        "try {",
        "L.a();",
        "} catch (RuntimeException v1) {",
        "L.b();",
        "}",
        "}",
        "return;",
    ],
    # a back edge inside a try body with join code after it. (That join code
    # is written inside the try and the catch's path to it is lost: the
    # pre-existing try scoping, the same before this change.)
    "tryJoin()V": [
        "while(true) {",
        "int v0 = L.n();",
        "if (v0 == 0) {",
        "break;",
        "}",
        "try {",
        "if (L.t(v0)) {",
        "L.a();",
        "} else {",
        "continue;",
        "}",
        "L.b();",
        "} catch (RuntimeException v1) {",
        "}",
        "}",
        "return;",
    ],
    # review: a `continue` in one arm of a case's if keeps the case's `break;`
    "swCont()V": [
        "while(true) {",
        "int v0 = L.n();",
        "if (v0 == 0) {",
        "break;",
        "}",
        "switch (v0) {",
        "case 1:",
        "if (L.t(v0)) {",
        "L.a();",
        "} else {",
        "continue;",
        "}",
        "break;",
        "case 2:",
        "L.add(v0);",
        "break;",
        "default:",
        "}",
        "L.b();",
        "}",
        "return;",
    ],
    # review: a `continue` before a switch does not reach its first case
    "contBeforeSwitch()V": [
        "while(true) {",
        "int v0 = L.n();",
        "if (v0 == 0) {",
        "break;",
        "}",
        "if (L.t(v0)) {",
        "if (L.n() != 0) {",
        "L.a();",
        "} else {",
        "continue;",
        "}",
        "}",
        "switch (v0) {",
        "case 1:",
        "L.c();",
        "break;",
        "case 2:",
        "L.add(v0);",
        "break;",
        "default:",
        "}",
        "L.b();",
        "}",
        "return;",
    ],
    # a latch test whose branches both return to the header: no exit, not a do-while
    "noExit()V": [
        "while(true) {",
        "L.a();",
        "// Both branches of the condition point to the same code.",
        "// if (L.n() == 0) {",
        "// }",
        "}",
    ],
    # a back edge through a handler (dexllm#134): left to DAD -- this do-while is
    # wrong, and unchanged; what is pinned is that no `continue` appears in it
    "handlerLatch()Z": [
        "do {",
        "int v0_0 = L.n();",
        "if (v0_0 != 0) {",
        "return true;",
        "} else {",
        "try {",
        "L.a();",
        "} catch (RuntimeException v1) {",
        "}",
        "}",
        "} while(L.t(v0_0));",
        "return false;",
    ],
    # a case ending in `continue` takes no `break`
    "caseContinue()V": [
        "while(true) {",
        "int v0 = L.n();",
        "if (v0 == 0) {",
        "break;",
        "}",
        "switch (v0) {",
        "case 1:",
        "L.a();",
        "continue;",
        "case 2:",
        "L.add(v0);",
        "break;",
        "default:",
        "}",
        "L.b();",
        "}",
        "return;",
    ],
    # the inner do-while's test is written once. (Its polarity is inverted --
    # `if-eq` LEAVES the inner loop -- a pre-existing posttest defect, as before.)
    "sharedLatchDo()V": [
        "while(true) {",
        "int v0 = L.n();",
        "if (v0 == 0) {",
        "break;",
        "}",
        "if (!L.t(v0)) {",
        "continue;",
        "}",
        "do {",
        "L.a();",
        "} while(L.n() == v0);",
        "}",
        "return;",
    ],
    # a throw ends a case: no `break` after it
    "caseThrow(I)V": [
        "switch (p1) {",
        "case 1:",
        "throw new IllegalStateException();",
        "case 2:",
        "L.a();",
        "break;",
        "}",
        "L.b();",
        "return;",
    ],
    # a try completes normally when its body does, whatever its catch ends in
    "tryInCase(I)V": [
        "switch (p1) {",
        "case 1:",
        "try {",
        "L.a();",
        "} catch (RuntimeException v0) {",
        "return;",
        "}",
        "break;",
        "case 2:",
        "L.add(p1);",
        "break;",
        "}",
        "L.b();",
        "return;",
    ],
    # a loop in a case: the `v0 == 0` exit into the switch's join is lost --
    # pre-existing and unchanged; pinned for the `return;` after the loop
    "loopInCase(I)V": [
        "switch (p2) {",
        "case 1:",
        "while(true) {",
        "int v0 = L.n();",
        "if (v0 == 0) {",
        "} else {",
        "if (!L.t(v0)) {",
        "break;",
        "}",
        "L.a();",
        "}",
        "}",
        "return;",
        "case 2:",
        "L.add(p2);",
        "break;",
        "}",
        "L.b();",
        "return;",
    ],
    # an if with one returning arm keeps the case's `break`
    "ifInCase(I)V": [
        "switch (p1) {",
        "case 1:",
        "if (!L.t(p1)) {",
        "L.a();",
        "} else {",
        "return;",
        "}",
        "break;",
        "case 2:",
        "L.add(p1);",
        "break;",
        "}",
        "L.b();",
        "return;",
    ],
    # a loop with no exit in a case: no unreachable `break` after it
    "exitlessInCase(I)V": [
        "switch (p1) {",
        "case 1:",
        "while(true) {",
        "L.a();",
        "}",
        "case 2:",
        "L.add(p1);",
        "break;",
        "}",
        "L.b();",
        "return;",
    ],
    # a handler-latch loop keeps DAD's do-while (wrong, unchanged); its mid-body
    # back edge must not become a `continue`, which would jump to the test
    "handlerLatchMid()V": [
        "do {",
        "int v0 = L.n();",
        "if (v0 != 0) {",
        "break;",
        "}",
        "try {",
        "if (L.t(v0)) {",
        "if (L.t2(v0)) {",
        "L.a();",
        "}",
        "}",
        "L.b();",
        "} catch (RuntimeException v1) {",
        "}",
        "} while(L.t2(v0));",
        "return;",
    ],
    # delta review: the arm that falls into the next case keeps falling; the
    # arm that completes takes its own `break`
    "fallTrue(I)V": [
        "switch (p1) {",
        "case 0:",
        "if (!L.t(p1)) {",
        "L.b();",
        "break;",
        "} else {",
        "L.a();",
        "}",
        "case 1:",
        "L.c();",
        "break;",
        "case 2:",
        "L.add(p1);",
        "break;",
        "default:",
        "}",
        "return;",
    ],
    # the mirror
    "fallFalse(I)V": [
        "switch (p1) {",
        "case 0:",
        "if (!L.t(p1)) {",
        "L.b();",
        "} else {",
        "L.a();",
        "break;",
        "}",
        "case 1:",
        "L.c();",
        "break;",
        "case 2:",
        "L.add(p1);",
        "break;",
        "default:",
        "}",
        "return;",
    ],
    # a loop in a case left straight into the next case: no arm takes a `break`,
    # which would leave the loop. (The next case is inlined into the arm and its
    # label lost -- next_case_ is not a stack; pre-existing.)
    "loopToNextCase(I)V": [
        "switch (p2) {",
        "case 0:",
        "while (L.t(p2)) {",
        "if (L.t2(p2)) {",
        "L.a();",
        "} else {",
        "L.c();",
        "}",
        "}",
        "L.b();",
        "break;",
        "case 2:",
        "L.add(p2);",
        "break;",
        "default:",
        "}",
        "return;",
    ],
    # CONTROL: a real do-while stays one
    "doWhile()V": [
        "do {",
        "L.a();",
        "} while(L.n() != 0);",
        "return;",
    ],
}

_JUMP = re.compile(r"^\s*(break|continue);$", re.M)
_INV = re.compile(r"^\s*0x[0-9a-f]+: invoke-\S+ \{[^}]*\}, L[^;]+;->([^(]+)\(")


@pytest.fixture(scope="module")
def dk():
    assert dexllm.verify(str(FIXTURE))[0]["valid"]
    return dexllm.DexKit(str(FIXTURE))


def _body(text):
    lines = [ln.strip() for ln in text.split("\n") if ln.strip()]
    return lines[lines.index("{") + 1 : -1]


@pytest.mark.parametrize("method", sorted(BODIES))
def test_the_loop_reads_as_the_bytecode_runs(dk, method):
    text = dk.decompile_method("LL;->" + method)
    assert _body(text) == BODIES[method], text


def _jumps(node, acc):
    if isinstance(node, list):
        if node and node[0] == "JumpStatement":
            acc.append(node[1])
        for x in node:
            _jumps(x, acc)
    elif isinstance(node, dict):
        for x in node.values():
            _jumps(x, acc)
    return acc


@pytest.mark.parametrize("method", sorted(BODIES))
def test_the_ast_writes_the_same_jumps(dk, method):
    """Each emitter decides `continue` by itself."""
    d = "LL;->" + method
    ast = dk.decompile_method_ast(d)["ast"]
    assert _jumps(ast, []) == _JUMP.findall(dk.decompile_method(d))


def _deficit(kit, method):
    names = collections.Counter(
        m.group(1)
        for ln in kit.render_method_smali(method).split("\n")
        if (m := _INV.match(ln)) and m.group(1) not in ("<init>", "<clinit>")
    )
    body = kit.decompile_method(method).split("\n", 1)[1]
    return {
        n: (k, c)
        for n, k in names.items()
        if (c := len(re.findall(r"(?<![\w$])" + re.escape(n) + r"\(", body))) != k
    }


@pytest.mark.parametrize("method", sorted(BODIES))
def test_every_call_is_written_once(dk, method):
    """The smali oracle: each invoked name appears as often as the bytecode
    calls it -- nothing dropped, and a shared latch is not written twice."""
    assert _deficit(dk, "LL;->" + method) == {}


def _ast_calls(node, acc):
    if isinstance(node, list):
        if node and node[0] == "MethodInvocation":
            acc[node[3]] += 1
        for x in node:
            _ast_calls(x, acc)
    elif isinstance(node, dict):
        for x in node.values():
            _ast_calls(x, acc)
    return acc


@pytest.mark.parametrize("method", sorted(BODIES))
def test_the_ast_writes_every_call_once(dk, method):
    """The same oracle on the AST, which decides its own latch visits."""
    d = "LL;->" + method
    want = collections.Counter(
        m.group(1)
        for ln in dk.render_method_smali(d).split("\n")
        if (m := _INV.match(ln)) and m.group(1) not in ("<init>", "<clinit>")
    )
    got = _ast_calls(dk.decompile_method_ast(d)["ast"], collections.Counter())
    assert {n: got[n] for n in want} == dict(want)


def _arm_ends_in_break(node):
    if isinstance(node, list):
        if node and node[0] == "IfStatement":
            for arm in node[3]:
                stmts = arm[2] if isinstance(arm, list) and len(arm) > 2 else []
                if stmts and stmts[-1] == ["JumpStatement", "break", None]:
                    return True
        return any(_arm_ends_in_break(x) for x in node)
    if isinstance(node, dict):
        return any(_arm_ends_in_break(x) for x in node.values())
    return False


@pytest.mark.parametrize("method", ["fallTrue(I)V", "fallFalse(I)V"])
def test_the_ast_puts_the_break_inside_the_completing_arm(dk, method):
    """Jump COUNTS match whether the break is in the arm or after the if; the
    AST has to put it in the arm as the text does."""
    assert _arm_ends_in_break(dk.decompile_method_ast("LL;->" + method)["ast"])


JAVA_FIXTURE = DATA / "continue-loop-java.dex"


def test_a_switch_whose_join_is_already_written_needs_no_continue():
    """javac's two-switch String switch (KeyAttributes.addValues): the second
    switch's join is a node already written, so leaving a case reaches the end
    of the loop body; no `continue` is written."""
    kit = dexllm.DexKit(str(JAVA_FIXTURE))
    text = kit.decompile_method("LK;->addValues(Ljava/util/Map;)V")
    assert "continue;" not in text, text
    assert "K.custom(v0_0);" in text and "K.c();" in text, text
    ast = kit.decompile_method_ast("LK;->addValues(Ljava/util/Map;)V")["ast"]
    assert "continue" not in _jumps(ast, []), ast


def _corpus(name):
    p = CORPUS / name
    if not p.exists():
        pytest.skip(f"{name} not in the corpus")
    return dexllm.DexKit(str(p))


def test_the_issue_repro_keeps_its_add_and_its_return():
    kit = _corpus("multiple_locale_appname_test.apk")
    d = (
        "Landroidx/core/content/pm/ShortcutXmlParser;->parseShortcutIds"
        "(Lorg/xmlpull/v1/XmlPullParser;)Ljava/util/List;"
    )
    text = kit.decompile_method(d)
    lines = [ln.strip() for ln in text.split("\n") if ln.strip()]
    assert "v0_1.add(v5_4);" in lines, text
    # one exit (the END_DOCUMENT / end-tag test), and the method returns after it
    assert lines.count("break;") == 1 and lines[-2:] == ["return v0_1;", "}"], text
    assert "do {" not in lines, text
    assert _deficit(kit, d) == {}


def test_a_failed_select_retries_instead_of_finishing():
    """SelectBuilderImpl.trySelectOther: a failed CAS loops back; without
    `continue` it fell through into doAfterSelect()."""
    kit = _corpus("multiple_locale_appname_test.apk")
    d = next(
        m
        for m in kit.list_class_methods(
            "Lkotlinx/coroutines/selects/SelectBuilderImpl;"
        )
        if "->trySelectOther(" in m
    )
    text = kit.decompile_method(d)
    assert len(re.findall(r"^\s*continue;$", text, re.M)) == 2, text
    assert _deficit(kit, d) == {}
