"""Two tries back to back are siblings, not nested (dexllm#122).

When a try's handlers rejoin exactly at the start of the next try, CatchStruct
sets the first TryBlock's follow to that block, which a LATER TryBlock then
wraps. DAD never remapped the follow -- its TryBlocks are not in graph.nodes --
so the Writer's stop test missed: the second try, and everything after it,
rendered INSIDE the first, including the method's `return`. androguard DAD
emits the identical nesting on the same bytes.

The fixture is authored smali (`tests/data/two-tries.smali`).
"""

from __future__ import annotations

import pathlib
import re

import pytest
from conftest import require_corpus_shape

import dexllm

DATA = pathlib.Path(__file__).parent / "data"
FIXTURE = DATA / "two-tries.dex"

SIBLINGS = {
    # the issue's repro: a constructor before each try, propagated into it
    # the issue's repro: a constructor before each try. It STAYS before the
    # try -- RegisterPropagation no longer carries a call into a block with
    # different exception handlers, which would change what catches it
    "twoTries()V": [
        'StringBuilder v0_1 = new StringBuilder("a");',
        "try {",
        "T.use(v0_1);",
        "} catch (Exception v2) {",
        "}",
        'StringBuilder v0_3 = new StringBuilder("b");',
        "try {",
        "T.use(v0_3);",
        "} catch (Exception v2) {",
        "}",
        "T.after();",
        "return;",
    ],
    # nothing but a constant before each try
    "twoTriesConst()V": [
        "try {",
        'T.use("a");',
        "} catch (Exception v2) {",
        "}",
        "try {",
        'T.use("b");',
        "} catch (Exception v2) {",
        "}",
        "T.after();",
        "return;",
    ],
    # no statement at all between the tries: the shape is CatchStruct's alone
    "twoTriesNoPrefix()V": [
        "try {",
        "T.after();",
        "} catch (Exception v2) {",
        "}",
        "try {",
        "T.after();",
        "} catch (Exception v2) {",
        "}",
        "T.after();",
        "return;",
    ],
    # each follow is wrapped by the NEXT try, so the remap has to chain
    "threeTries()V": [
        "try {",
        "T.after();",
        "} catch (Exception v2) {",
        "}",
        "try {",
        "T.use2();",
        "} catch (Exception v2) {",
        "}",
        "try {",
        "T.use3();",
        "} catch (Exception v2) {",
        "}",
        "return;",
    ],
    # the first try ends in an IF: its follow is the if's merge (a cond-type
    # TryBlock), not the block's single successor
    "condTry()V": [
        "try {",
        "if (T.flag()) {",
        "T.use2();",
        "}",
        "} catch (Exception v1) {",
        "}",
        "try {",
        "T.use3();",
        "} catch (Exception v1) {",
        "}",
        "T.after();",
        "return;",
    ],
}

# a local the try body defines and code outside it reads is declared BEFORE
# the try (Java scopes a local to its block)
HOISTED = {
    "hoistAfter()Ljava/lang/Object;": [
        "Object v0;",
        "try {",
        "v0 = T.get();",
        "} catch (Exception v1) {",
        "v0 = null;",
        "}",
        "T.use(v0);",
        "return v0;",
    ],
    # read by the try's own catch. (The `v0 = null` before the try is lost --
    # a definition reached only over the exception edge; pre-existing, the
    # pre-fix build loses it too.)
    "hoistIntoCatch()Ljava/lang/Object;": [
        "Object v0;",
        "try {",
        "v0 = T.get();",
        "T.use(v0);",
        "return v0;",
        "} catch (Exception v1) {",
        "return v0;",
        "}",
    ],
}

HOISTED.update(
    {
        # a catch def and a normal-path def meet in one return: one variable
        "catchDefShared()Ljava/lang/Object;": [
            "Object v0;",
            "try {",
            "T.after();",
            "v0 = T.get();",
            "} catch (Exception v1) {",
            "v0 = null;",
            "}",
            "return v0;",
        ],
    }
)

# the catch returns, so everything after the get() is inside the try and the
# local never leaves it: nothing to hoist
NOT_HOISTED = {
    "hoistCatchReturns()Ljava/lang/Object;": [
        "try {",
        "Object v0_0 = T.get();",
        "T.use(v0_0);",
        "return v0_0;",
        "} catch (Exception v1) {",
        "return null;",
        "}",
    ],
}

# shapes the remap must NOT touch, pinned as rendered -- each is what the
# pre-fix build renders too
LEFT_ALONE = {
    # NESTED: the outer handler also covers the inner try's block. The stale
    # follow is what keeps the inner try inside the outer; remapping it would
    # take use3() out of the outer handler's protection. (The outer catch's
    # type is the pre-existing shared-register catch-type defect.)
    "nestedTry()V": [
        "try {",
        "T.use2();",
        "try {",
        "T.use3();",
        "} catch (java.io.IOException v0) {",
        "}",
        "T.after();",
        "return;",
        "} catch (java.io.IOException v0) {",
        "return;",
        "}",
    ],
    # the first try is a do-while HEADER: the loop body is walked over the
    # header's own edges, so a remapped follow would split the loop between the
    # two tries. This rendering is itself wrong (the loop body is cut short) --
    # a loop/try region-structuring defect of its own, not this one.
    "loopHeadTry(I)V": [
        "try {",
        "do {",
        "T.use2();",
        "} while(p2 != 0);",
        "return;",
        "} catch (Exception v0) {",
        "try {",
        "T.use3();",
        "} catch (Exception v0) {",
        "}",
        "p2--;",
        "if (p2 == 0) {",
        "}",
        "return;",
        "}",
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


@pytest.mark.parametrize("member", sorted(SIBLINGS))
def test_back_to_back_tries_are_siblings(dk, member):
    assert _body(dk.decompile_method(f"LT;->{member}")) == SIBLINGS[member]


@pytest.mark.parametrize("member", sorted(HOISTED))
def test_a_local_used_outside_its_try_is_declared_before_it(dk, member):
    assert _body(dk.decompile_method(f"LT;->{member}")) == HOISTED[member]


@pytest.mark.parametrize("member", sorted(NOT_HOISTED))
def test_a_local_that_stays_in_its_try_is_not_hoisted(dk, member):
    assert _body(dk.decompile_method(f"LT;->{member}")) == NOT_HOISTED[member]


@pytest.mark.parametrize("member", sorted(HOISTED))
def test_the_ast_declares_it_before_the_try_too(dk, member):
    """Both emitters call the shared ScopeEscapingDefs; the AST must carry the
    declaration as its own statement ahead of the TryStatement."""
    top = dk.decompile_method_ast(f"LT;->{member}")["ast"]["body"][2]
    kinds = [s[0] for s in top]
    i = kinds.index("TryStatement")
    assert kinds[i - 1] == "LocalDeclarationStatement", kinds
    assert top[i - 1][1] is None, top[i - 1]  # declared, not initialised


@pytest.mark.parametrize("member", sorted(LEFT_ALONE))
def test_a_nested_or_loop_header_try_is_left_alone(dk, member):
    assert _body(dk.decompile_method(f"LT;->{member}")) == LEFT_ALONE[member]


@pytest.mark.parametrize("member", sorted(SIBLINGS))
def test_the_ast_has_them_at_top_level(dk, member):
    """The AST's TryStatements come from the same try_follow, so they must be
    siblings in the method body too, not one nested in the other."""
    body = dk.decompile_method_ast(f"LT;->{member}")["ast"]["body"]
    top = [s[0] for s in body[2]]
    n = SIBLINGS[member].count("try {")
    assert top.count("TryStatement") == n, top
    assert top[-1] == "ReturnStatement", top


def test_a2dp_on_create_keeps_its_registrations_outside_the_try(loadable_apks):
    """The corpus case the issue was filed from: dexllm#121 made one more
    method reach it, and the rest of onCreate rendered inside the first try."""
    desc = "La2dp/Vol/main;->onCreate(Landroid/os/Bundle;)V"
    hits = []
    for apk in loadable_apks:
        dk = dexllm.DexKit(apk)
        if dk.locate_class_dex("La2dp/Vol/main;") < 0:
            continue
        lines = [x.strip() for x in dk.decompile_method(desc).split("\n")]
        hits.append(apk)
        i = next(j for j, x in enumerate(lines) if '"a2dp.vol.service.RUNNING"' in x)
        # the IntentFilter is built BEFORE the try, as in the bytecode
        assert lines[i].startswith("android.content.IntentFilter v16"), lines[i]
        assert lines[i + 1] == "try {"
        assert lines[i + 3].startswith("} catch (Exception")
        assert lines[i + 6].startswith("android.content.IntentFilter v17")
        assert lines[i + 7] == "try {"
        assert lines[-2] == "}" and lines[-3] == "return;", lines[-6:]
    require_corpus_shape(bool(hits), "a2dp main.onCreate", "dexllm#122")


_DECL = re.compile(r"^\s*[\w.$]+(?:\[\])* ([vp]\d+(?:_\d+)?)(?: =|;)")


def _out_of_scope_uses(text):
    """Uses of a local after the brace block it was declared in has closed."""
    n = 0
    stack, closed = [set()], set()
    for line in text.split("\n"):
        if line and not line.startswith(" "):
            stack, closed = [set()], set()
            continue
        s = line.strip()
        m = _DECL.match(line)
        if not m and any(re.search(r"\b" + re.escape(v) + r"\b", s) for v in closed):
            n += 1
        if m:
            stack[-1].add(m.group(1))
            closed.discard(m.group(1))
        for _ in range(s.count("}")):
            if len(stack) > 1:
                closed |= stack.pop()
        for _ in range(s.count("{")):
            stack.append(set())
    return n


# corpus classes in which every local is declared where all its uses can see
# it once try-escaping locals are hoisted -- each one moves under a different
# half of ScopeEscapingDefs being disabled (catch bodies walked; a declaration
# PlaceDeclarations put inside the region; the walk stopping at follows; the
# walk entering a loop body through its header)
_SCOPE_CLEAN = {
    # class -> the most out-of-scope uses any bundled build of it may carry
    "Lcom/google/android/exoplayer2/DefaultRenderersFactory;": 0,
    "Lcom/bumptech/glide/load/data/mediastore/ThumbnailStreamOpener;": 0,
    "Landroid/support/v4/media/session/IMediaSession$Stub$Proxy;": 0,
    "Landroid/support/constraint/ConstraintSet;": 0,
    # a try inside a loop body, reached over the loop header's own edges (one
    # older support-library build keeps 1 use of its own)
    "Landroid/support/v4/text/util/LinkifyCompat;": 1,
}


@pytest.mark.parametrize("cls", sorted(_SCOPE_CLEAN))
def test_no_local_is_used_outside_its_declaring_block(loadable_apks, cls):
    hits = []
    for apk in loadable_apks:
        dk = dexllm.DexKit(apk)
        if dk.locate_class_dex(cls) < 0:
            continue
        hits.append(apk)
        assert _out_of_scope_uses(dk.decompile_class(cls)) <= _SCOPE_CLEAN[cls], apk
    require_corpus_shape(bool(hits), cls, "dexllm#122")


def test_hoisted_declarations_come_out_in_one_fixed_order(dk):
    """hoistMany: four locals defined in both arms of an if inside one try. The
    order once followed pointer hashing (and the text and AST disagreed)."""
    body = _body(dk.decompile_method("LT;->hoistMany(Z)V"))
    assert body[:5] == ["int v0;", "int v1;", "int v2;", "int v3;", "try {"], body
    top = dk.decompile_method_ast("LT;->hoistMany(Z)V")["ast"]["body"][2]
    decls = [
        s[2][1][1] for s in top if s[0] == "LocalDeclarationStatement" and s[1] is None
    ]
    assert decls == ["v0", "v1", "v2", "v3"], decls


def test_a_catch_variable_is_never_hoisted(dk):
    """catchVarShared: a sibling handler writes the catch variable. Hoisting it
    printed `Throwable v0;` beside `catch (Throwable v0)` -- javac: already
    defined."""
    body = _body(dk.decompile_method("LT;->catchVarShared()V"))
    assert "Throwable v0;" not in body, body
    assert "} catch (Throwable v0) {" in body, body
