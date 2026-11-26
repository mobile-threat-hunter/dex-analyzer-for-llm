"""A loop entered only from a catch handler is rendered (dexllm#134).

``WhileBlockStruct`` replaces a loop header with a ``LoopBlock`` and re-points
the edges into it, taking them from ``Graph::preds``, which -- as DAD's
``graph.py`` does -- drops the ``in_catch`` predecessors. A loop inside a
handler is reached ONLY through ``in_catch`` predecessors: every edge into it
(its back edge too) was dropped and the loop vanished from the Java text, with
no marker; and a catch that returns to an enclosing loop's header lost the
edge that makes its end a ``continue``. ``Graph::rewire_preds`` re-points every
normal edge. The loop's latch is then in_catch too, so #138's ClosesDoWhile
leaves only a latch whose HEADER is not in_catch to DAD.

The fixture is authored smali (``tests/data/handler-loop.smali``).
"""

from __future__ import annotations

import collections
import pathlib
import re

import pytest

import dexllm

DATA = pathlib.Path(__file__).parent / "data"
FIXTURE = DATA / "handler-loop.dex"
CORPUS = pathlib.Path(__file__).parent.parent / "test_apk" / "APK"

BODIES = {
    # the loop after the try stays on the normal path (HEAD's output: the
    # exception path still reads E before the loop -- pre-existing)
    "loopAfterTry()V": [
        "try {",
        "H.get();",
        "} catch (java.io.IOException v0_1) {",
        "H.log(v0_1);",
        "}",
        "if (!H.E) {",
        "while (H.D) {",
        "H.x();",
        "}",
        "return;",
        "} else {",
        "return;",
        "}",
    ],
    "loopInHandler()V": [
        "try {",
        "H.get();",
        "return;",
        "} catch (java.io.IOException v0) {",
        "do {",
        "H.log(v0);",
        "} while(H.D);",
        "return;",
        "}",
    ],
    "finallyLoop(I)V": [
        "try {",
        "H.a();",
        "return;",
        "} catch (Throwable v0) {",
        "while (p2 > 0) {",
        "H.x();",
        "p2--;",
        "}",
        "throw v0;",
        "}",
    ],
    "twoBackInHandler()V": [
        "try {",
        "H.get();",
        "return;",
        "} catch (java.io.IOException v0) {",
        "while(true) {",
        "H.log(v0);",
        "if (H.E) {",
        "H.y();",
        "if (!H.D) {",
        "break;",
        "}",
        "}",
        "}",
        "return;",
        "}",
    ],
    "catchContinue(I)V": [
        "while (p1 > 0) {",
        "try {",
        "H.a();",
        "} catch (RuntimeException v0) {",
        "p1 -= 2;",
        "continue;",
        "}",
        "if (H.E) {",
        "H.y();",
        "}",
        "p1--;",
        "}",
        "return;",
    ],
    "shortCircuitInHandler()V": [
        "try {",
        "H.get();",
        "return;",
        "} catch (java.io.IOException v0) {",
        "boolean v1 = H.a();",
        "boolean v2 = H.b();",
        "if (v1) {",
        "if (v2) {",
        "H.x();",
        "}",
        "}",
        "return;",
        "}",
    ],
    "shortCircuitAfterHandler()V": [
        "boolean v1 = H.a();",
        "boolean v2 = H.b();",
        "try {",
        "H.get();",
        "} catch (java.io.IOException v0) {",
        "H.log(v0);",
        "}",
        "if ((v1) && (v2)) {",
        "H.x();",
        "}",
        "return;",
    ],
}

_INV = re.compile(r"^\s*0x[0-9a-f]+: invoke-\S+ \{[^}]*\}, L[^;]+;->([^(]+)\(")


@pytest.fixture(scope="module")
def dk():
    assert dexllm.verify(str(FIXTURE))[0]["valid"]
    return dexllm.DexKit(str(FIXTURE))


def _body(text):
    lines = [ln.strip() for ln in text.split("\n") if ln.strip()]
    return lines[lines.index("{") + 1 : -1]


@pytest.mark.parametrize("method", sorted(BODIES))
def test_the_handler_code_is_rendered(dk, method):
    assert _body(dk.decompile_method("LH;->" + method)) == BODIES[method]


def _calls_in_smali(kit, method):
    return collections.Counter(
        m.group(1)
        for ln in kit.render_method_smali(method).split("\n")
        if (m := _INV.match(ln)) and m.group(1) not in ("<init>", "<clinit>")
    )


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
def test_every_call_is_written_once_in_text_and_ast(dk, method):
    d = "LH;->" + method
    want = _calls_in_smali(dk, d)
    body = dk.decompile_method(d).split("\n", 1)[1]
    got = {n: len(re.findall(r"(?<![\w$])" + re.escape(n) + r"\(", body)) for n in want}
    assert got == dict(want)
    ast = _ast_calls(dk.decompile_method_ast(d)["ast"], collections.Counter())
    assert {n: ast[n] for n in want} == dict(want)


def test_the_catch_copy_loops_keep_their_calls():
    """The issue's own repro, tests/data/catch-copy.dex."""
    kit = dexllm.DexKit(str(DATA / "catch-copy.dex"))
    for m in ("loop()V", "loopStale()V"):
        text = kit.decompile_method("LC;->" + m)
        assert text.count("C.log(") == 2, text
        assert "} while(C.D);" in text, text


def _corpus(name):
    p = CORPUS / name
    if not p.exists():
        pytest.skip(f"{name} not in the corpus")
    return dexllm.DexKit(str(p))


def test_a_finally_relock_loop_and_its_rethrow_are_rendered():
    """kotlin.concurrent.LocksKt.write: the finally path re-acquires the read
    locks it dropped, then rethrows."""
    kit = _corpus("multiple_locale_appname_test.apk")
    text = kit.decompile_class("Lkotlin/concurrent/LocksKt;")
    i = text.index("} catch (Throwable v5_1) {")
    catch = text[i : text.index("\n    }\n", i)]
    assert "v0_2.lock();" in catch and "throw v5_1;" in catch, catch


def test_a_join_reached_normally_stays_outside_the_catch():
    """MergeShortCircuit keeps DAD's preds(): re-pointing the handler's edge
    into a merged test the normal path also reaches (the first cut) pulled
    a2dp's join code into the catch."""
    kit = _corpus("a2dp.Vol_137.apk")
    text = kit.decompile_method(
        "La2dp/Vol/main$14;->onReceive(Landroid/content/Context;Landroid/content/Intent;)V"
    )
    i = text.index("} catch (Exception v4) {")
    j = text.index('getBoolean("useLocalStorage", false)')
    assert "access$300" not in text[i:j], text
