"""Sound tail-position oracle for the <clinit> return-void drop.

The Writer drops a <clinit>'s return-void only when it believes the return is in
TAIL POSITION (nothing executes after it → dropping it is equivalent to fall-
through, and `return` is illegal in an initializer per JLS §8.7). This test is an
INDEPENDENT oracle that recomputes tail position structurally from the AST (whose
emitter, dast.cpp, is untouched by the drop and carries EVERY return node), and
asserts the Writer never dropped a return the oracle marks non-tail.

Oracle rule (sound): a return-void is in tail position iff it is the last
statement of its block AND that block is in tail position; if/else branches
inherit the if's tail position; try / loop / switch bodies are non-tail
(conservative — matches the Writer). The method body is tail.

Safety invariant checked per <clinit>: `text_return_kept >= oracle_non_tail`.
A violation means the Writer dropped a return the oracle proves is NOT terminal —
a real semantic bug. Also asserts the oracle finds every return-void the AST has
(completeness — otherwise the invariant would pass vacuously).

APK-dependent; skips cleanly without the bundled corpus.
"""

import glob
import os

import pytest

import dexllm

APKS = sorted(
    p
    for p in glob.glob("test_apk/APK/*.apk")
    if os.path.getsize(p) > 1024 and dexllm.identify(p).get("dex_count", 0) > 0
)

pytestmark = pytest.mark.skipif(not APKS, reason="no bundled APK corpus")


def _collect(node, is_tail):
    """Return a list of bools — one per return-VOID under `node` — each True iff
    that return is in tail position."""
    out = []
    if not isinstance(node, list) or not node or not isinstance(node[0], str):
        return out
    tag = node[0]
    if tag == "ReturnStatement":
        if len(node) < 2 or node[1] is None:  # return-void
            out.append(is_tail)
        return out
    if tag == "BlockStatement":
        stmts = node[2] if len(node) > 2 and isinstance(node[2], list) else []
        for i, s in enumerate(stmts):
            out += _collect(s, is_tail and i == len(stmts) - 1)
        return out
    if tag == "IfStatement":  # [If, null, cond, [thenBlock, elseBlock?]]
        if len(node) > 3 and isinstance(node[3], list):
            for b in node[3]:
                out += _collect(b, is_tail)
        return out
    if tag == "TryStatement":  # [Try, null, tryBlock, [catch...]] — non-tail
        if len(node) > 2:
            out += _collect(node[2], False)
        if len(node) > 3 and isinstance(node[3], list):
            for cat in node[3]:
                if isinstance(cat, list):
                    for part in cat:
                        out += _collect_deep(part, False)
        return out
    # loops / switch / anything else — conservative non-tail
    for sub in node[1:]:
        out += _collect_deep(sub, False)
    return out


def _collect_deep(node, is_tail):
    if not isinstance(node, list):
        return []
    if node and isinstance(node[0], str):
        return _collect(node, is_tail)
    out = []
    for x in node:
        out += _collect_deep(x, is_tail)
    return out


def _count_return_void(node):
    c = 0
    if isinstance(node, list):
        if node and node[0] == "ReturnStatement" and (len(node) < 2 or node[1] is None):
            c += 1
        for x in node:
            c += _count_return_void(x)
    return c


def _iter_clinit(dk):
    for cls in dk.list_classes():
        for m in dk.list_class_methods(cls):
            if "<clinit>" in m:
                yield m


def test_no_non_tail_return_dropped():
    """Across every <clinit>, the Writer never drops a return the oracle proves
    is non-tail, and the oracle finds every return-void the AST carries."""
    total = 0
    unsafe = []
    undercount = 0
    discriminating = (
        0  # methods where the oracle found a non-tail return (proves it bites)
    )
    for apk in APKS:
        try:
            dk = dexllm.DexKit(apk)
        except Exception:
            continue
        for m in _iter_clinit(dk):
            try:
                ast = dk.decompile_method_ast(m, include_source=False)
                txt = dk.decompile_method_java(m)
            except Exception:
                continue
            if not txt:
                continue
            total += 1
            marks = _collect(ast["ast"]["body"], True)
            if len(marks) != _count_return_void(ast["ast"]["body"]):
                undercount += 1  # oracle missed a return-void → invariant is vacuous
            non_tail = sum(1 for x in marks if not x)
            kept = sum(1 for line in txt.split("\n") if line.strip() == "return;")
            if non_tail:
                discriminating += 1
            if (
                kept < non_tail
            ):  # Writer dropped a return the oracle says is NOT terminal
                unsafe.append((m, non_tail, kept, len(marks)))

    assert total > 0, "no <clinit> exercised"
    assert undercount == 0, f"oracle under-counted return-voids in {undercount} methods"
    assert (
        discriminating > 0
    ), "oracle never found a non-tail return — not discriminating"
    assert not unsafe, f"{len(unsafe)} <clinit> dropped a NON-tail return: {unsafe[:5]}"
