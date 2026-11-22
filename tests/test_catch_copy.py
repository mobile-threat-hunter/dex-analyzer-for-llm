"""A copy of a catch variable takes the handler type (dexllm#133).

dexllm#130 types a version whose def IS a `move-exception`. A version defined
by a `move-object` FROM one was typed by SplitVariables' move-source rule,
which reads the source register's shared type -- its last write anywhere in the
method -- so `move-exception v0; move-object v1, v0; move-object v0, v1`
declared the copy with whatever v1 held elsewhere (`JobSupport v0_5 = v0_4` in
kotlinx `JobSupport.notifyCancelling`). The copy now takes the handler type
when every def of its version is such a copy, a move-exception or the null
constant, and the handler types they reach agree.

The fixture is authored smali (`tests/data/catch-copy.smali`).
"""

from __future__ import annotations

import os
import pathlib
import re

import pytest
from conftest import require_corpus_shape

import dexllm

DATA = pathlib.Path(__file__).parent / "data"
FIXTURE = DATA / "catch-copy.dex"

# Every declaration of a local, as rendered. Two of these are REFUSALS
# (orString / orCall): a String reaches the version on the other path, so the
# pass leaves it, and the `String` they read is the pre-existing multi-def rule's
# answer for a genuine String / IOException merge, not this change's.
DECLS = {
    # the issue's shape: v1 is last written with a String on the joined path
    "stale()V": ["java.io.IOException v0_1 = v0_0;"],
    # two DIFFERENT handler types into one register: REFUSED, since their
    # common supertype needs the class hierarchy (see subtypes). The
    # `IllegalStateException` is the pre-existing move-source answer, and it is
    # wrong for the IOException arm -- recorded, not this change's
    "twoHandlers()V": ["IllegalStateException v1_2;"],
    "withNull()V": ["java.io.IOException v1_0 = null;"],
    "loop()V": ["java.io.IOException v1;"],
    "orString()V": ["String v1;"],
    "orCall()V": ["String v1_1;"],
    # a parameter reaches it: the parameter's type, as before
    "orParam(Ljava/lang/Throwable;)V": ["Throwable v1_0 = p2;"],
    # every register last written with a String on the joined path; the copy
    # goes round a loop (the loop body after a handler is lost, pre-existing
    # and identical before this change -- what this pins is the declaration)
    "loopStale()V": [
        "java.io.IOException v0_1;",
        "String v2_2 = ((String) C.get());",
    ],
    # a copy of null merged with null: no handler type, so the pass leaves it
    "nullMerge()V": ["Object v1_0;"],
    # into the parameter register: a parameter keeps its declared type
    "toParam(Ljava/lang/Object;)V": [],
    # CRAFTED, ART-invalid: a PLAIN move is not followed (in verified Dalvik it
    # cannot carry a reference), so the copy keeps the stale type it had
    "plainMove()V": ["String v0_1 = v0_0;"],
    # CRAFTED, ART-invalid: a nonzero int refuses, as a String does
    "orInt()V": ["Object v1;"],
    # a null merged with the copy, every register stale on the joined path
    "nullStale()V": [
        "java.io.IOException v0_0 = null;",
        "String v2_2 = ((String) C.get());",
    ],
    # refused TWO hops deep: v1 copies v0, and v0 merges the exception with p3
    "deepParam(Ljava/lang/Throwable;)V": [
        "Throwable v0_0 = p3;",
        "Throwable v1_1 = v0_0;",
        "String v2_2 = ((String) C.get());",
    ],
    # a loop head copy whose catch source is defined later in the loop
    # FileNotFoundException + IOException passed on as an IOException: a
    # Throwable here would stop compiling, so the pass leaves it
    "subtypes()V": ["java.io.IOException v1_2;"],
    # a loop-head copy whose source copy comes later, over the back edge (the
    # pre-fix build declared v1_1 `String`)
    "loopBack()V": [
        "java.io.IOException v2_0 = null;",
        "java.io.IOException v0 = null;",
        "java.io.IOException v1_1 = v2_0;",
    ],
    "loopCarry()V": [
        "java.io.IOException v1 = null;",
        "java.io.IOException v2_0 = v1;",
    ],
}

_DECL = re.compile(r"^\s*((?:[\w.$]+)(?:\[\])*) (v\w+)( = [^;]*)?;$")


@pytest.fixture(scope="module")
def dk():
    assert dexllm.verify(str(FIXTURE))[0]["valid"]
    return dexllm.DexKit(str(FIXTURE))


def _decls(text):
    return [ln.strip() for ln in text.split("\n") if _DECL.match(ln)]


@pytest.mark.parametrize("method", sorted(DECLS))
def test_the_copy_is_declared_with_the_handler_type(dk, method):
    text = dk.decompile_method("LC;->" + method)
    assert _decls(text) == DECLS[method], text


def _ast_decls(node, out):
    if isinstance(node, list):
        if node and node[0] == "LocalDeclarationStatement":
            typen, local = node[2]
            out[local[1]] = typen[1][0]
        for v in node:
            _ast_decls(v, out)
    elif isinstance(node, dict):
        for v in node.values():
            _ast_decls(v, out)
    return out


def _desc(java):
    if "." not in java:
        java = "java.lang." + java
    return java.replace(".", "/")


@pytest.mark.parametrize("method", sorted(DECLS))
def test_the_ast_declares_the_same_type(dk, method):
    """The AST reads the same Variable; a separate guard per emitter."""
    got = _ast_decls(dk.decompile_method_ast("LC;->" + method)["ast"], {})
    want = {}
    for d in DECLS[method]:
        typ, name = _DECL.match(d).group(1, 2)
        want[name] = _desc(typ)
    assert got == want


def test_the_class_text_agrees_with_the_method_text(dk):
    cls = dk.decompile_class("LC;")
    for decls in DECLS.values():
        for d in decls:
            assert d in cls, d


_APK = (
    pathlib.Path(__file__).parent.parent
    / "test_apk"
    / "APK"
    / "multiple_locale_appname_test.apk"
)


def test_the_issue_repro():
    if not _APK.exists() or os.environ.get("DEXLLM_TEST_APK"):
        pytest.skip("needs the bundled corpus")
    kit = dexllm.DexKit(str(_APK))
    desc = (
        "Lkotlinx/coroutines/JobSupport;->notifyCancelling"
        "(Lkotlinx/coroutines/NodeList;Ljava/lang/Throwable;)V"
    )
    text = kit.decompile_method(desc)
    require_corpus_shape(
        "catch (Throwable v0_4)" in text,
        "JobSupport.notifyCancelling's catch copy",
        "the method no longer has the dexllm#133 shape",
    )
    assert "Throwable v0_5 = v0_4;" in [ln.strip() for ln in text.split("\n")], text
