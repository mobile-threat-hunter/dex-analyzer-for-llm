"""dexllm#96 — a `filled-new-array` initializer is closed by `}` and nothing else.

`WriterImpl::visit_filled_new_array` ported androguard `writer.py:652`
(`self.write('})')`) verbatim. Nothing opens the `(` that `)` closes, so every
filled-new-array line in the Java text was unbalanced: 648 of 648 such lines in
the bundled corpus + committed fixtures, each one `)` short of `(` per
initializer it carries. The AST (`ArrayInitializer`) never had the `)`.

The oracle here does not reuse the Writer: it counts parentheses with string
and char literals blanked out, and it compares the text against the AST by
counting initializers and their elements per method. Three committed fixtures
carry the opcode (both forms), so every case but the corpus sweep runs in the
corpus-less CI leg.
"""

from __future__ import annotations

import re

import pytest
from conftest import REPO_ROOT, require_corpus_shape

_DATA = REPO_ROOT / "tests" / "data"
_FILLED = re.compile(r"\bnew \S+?(?:\[\])+ \{")

# (fixture, method, the rendered line) - pinned LITERALLY so an edit of the
# rule cannot move the expectation with it. `new Object[] {v1, ...}` in
# NegativeStatics.all() is filled-new-array/RANGE, whose two-register element
# list is the separate DAD-faithful defect dexllm#97.
_PINNED = [
    (
        "bool-return.dex",
        "LBoolReturn;->fillArr(I)Z",
        "BoolReturn.sinkArr(new int[] {v1_1});",
    ),
    (
        "method_handles.dex",
        "LExampleJavaJniFuzzer;->fuzzerTestOneInput("
        "Lcom/code_intelligence/jazzer/api/FuzzedDataProvider;)V",
        "Object[] v2_2 = new Object[] {v0};",
    ),
    (
        "method_handles.dex",
        "Lcom/example/ExampleJavaHelper;->fuzzerTestOneInput([B)V",
        "Object[] v1_4 = new Object[] {new java.io.ByteArrayInputStream(p5)};",
    ),
    (
        "negative-statics.dex",
        "LNegativeStatics;->all()[Ljava/lang/Object;",
        "return new Object[] {v1, Byte.valueOf(((byte) -1))};",
    ),
]

_FIXTURES = ["bool-return.dex", "method_handles.dex", "negative-statics.dex"]


def _blank_literals(line: str) -> str:
    """Replace string/char literals with a space and drop a `//` comment."""
    out, i, n = [], 0, len(line)
    while i < n:
        c = line[i]
        if c in "\"'":
            i += 1
            while i < n and line[i] != c:
                i += 2 if line[i] == "\\" else 1
            i += 1
            out.append(" ")
        elif line.startswith("//", i):
            break
        else:
            out.append(c)
            i += 1
    return "".join(out)


def test_blank_literals_self_check() -> None:
    """The oracle must not count a parenthesis inside a literal."""
    assert _blank_literals("f(\"(\", ')') // )") == "f( ,  ) "


def _filled_lines(text: str):
    for ln in text.split("\n"):
        if _FILLED.search(_blank_literals(ln)):
            yield ln


def _elements(line: str) -> list[int]:
    """Top-level element count of each `new T[] {...}` on a line."""
    s, counts = _blank_literals(line), []
    for m in _FILLED.finditer(s):
        depth, n, nonempty, i = 0, 0, False, m.end()
        while i < len(s):
            c = s[i]
            if c in "({[":
                depth += 1
            elif c in ")}]":
                if depth == 0:
                    break
                depth -= 1
            elif c == "," and depth == 0:
                n += 1
            if not c.isspace():
                nonempty = True
            i += 1
        counts.append(n + 1 if nonempty else 0)
    return counts


def _ast_initializers(node):
    """Typed ArrayInitializer nodes (a fill-array-data one carries no type)."""
    if isinstance(node, list):
        if len(node) > 2 and node[0] == "ArrayInitializer" and node[2] is not None:
            yield node
        for x in node:
            yield from _ast_initializers(x)
    elif isinstance(node, dict):
        for x in node.values():
            yield from _ast_initializers(x)


@pytest.mark.parametrize("fixture,method,line", _PINNED)
def test_the_pinned_line_is_balanced_java(fixture, method, line) -> None:
    dexllm = pytest.importorskip("dexllm")
    text = dexllm.DexKit(str(_DATA / fixture)).decompile_method(method)
    assert line in [ln.strip() for ln in text.split("\n")], text


@pytest.mark.parametrize("fixture", _FIXTURES)
def test_every_filled_new_array_line_balances(fixture) -> None:
    dexllm = pytest.importorskip("dexllm")
    dk = dexllm.DexKit(str(_DATA / fixture))
    seen = 0
    for cls in sorted(set(dk.list_classes())):
        for ln in _filled_lines(dk.decompile_class(cls)):
            seen += 1
            s = _blank_literals(ln)
            # Parentheses only: a `{` on the same line may legitimately open an
            # `if (...) {` / `while (...) {` block, so braces are not per-line.
            assert s.count("(") == s.count(")"), (cls, ln)
    assert seen, f"{fixture} no longer renders a filled-new-array"


@pytest.mark.parametrize("fixture", _FIXTURES)
def test_the_text_and_the_ast_carry_the_same_initializers(fixture) -> None:
    """Per method: as many `new T[] {` in the text as typed ArrayInitializer
    nodes in the AST, with the same element counts in the same order.

    This does NOT detect dexllm#96 itself (`_elements` stops at the `}` before a
    stray `)`); it pins that the text and the AST describe the same
    initializers, which kills a Writer or a dast that drops an element. Both
    read one IR, so an IR-level element loss (dexllm#97) is outside it."""
    dexllm = pytest.importorskip("dexllm")
    dk = dexllm.DexKit(str(_DATA / fixture))
    compared = 0
    for cls in sorted(set(dk.list_classes())):
        for m in dk.list_class_methods(cls):
            text = dk.decompile_method(m)
            t = [n for ln in _filled_lines(text) for n in _elements(ln)]
            a = [
                len(n[1])
                for n in _ast_initializers(
                    dk.decompile_method_ast(m, include_source=False).get("ast")
                )
            ]
            assert t == a, (m, t, a, text)
            compared += len(t)
    assert compared, f"{fixture} carries no filled-new-array"


def test_every_corpus_filled_new_array_line_balances(loadable_apks) -> None:
    """Corpus sweep, restricted to classes whose SMALI carries the opcode (the
    smali view is a different emitter, so the selection does not reuse the
    Writer)."""
    dexllm = pytest.importorskip("dexllm")
    seen, bad = 0, []
    for apk in loadable_apks:
        dk = dexllm.DexKit(str(apk))
        for cls in sorted(set(dk.list_classes())):
            if "filled-new-array" not in dk.render_class_smali(cls):
                continue
            for ln in _filled_lines(dk.decompile_class(cls)):
                seen += 1
                s = _blank_literals(ln)
                if s.count("(") != s.count(")"):
                    bad.append((str(apk), cls, ln.strip()))
    require_corpus_shape(
        seen,
        "a filled-new-array in the corpus",
        "the corpus no longer renders any filled-new-array",
    )
    assert not bad, bad[:5]
