"""An int value is typed int even when its register held a float (dexllm#94).

The opposite direction of dexllm#88. Two roots, both a version not typed from its
own definition:

* a `move-result` def was treated like a `move` source, whose type is the
  SHARED register's last write and may be stale, so SplitVariables trusted it
  only for a reference. Its rhs is in fact the invoke's own result temporary,
  written once by that invoke (`Variable::invoke_result`), so an `I`-returning
  `Math.min` into a register later reused for an `aget` off a `float[]` was
  declared `float` - and then used as an index;
* a register SplitVariables leaves UNSPLIT keeps its last write, and a `move`
  copies the source's type at BUILD time, so a stale `double` reached a version
  used only as an index (`QuantizerWu.createBoxes`). `InferCascadeTypes` now
  narrows a J/F/D version used where only an int is legal when every def
  resolves to the same narrow int width - the mirror of the prim->WIDER branch.

Trusting a `move-result` put a `B`/`S`/`C`/`Z` call result beside other narrow
producers in one version for the first time, so disagreeing narrow widths are
now joined the way ART's verifier merges them (B+S = S, any C or I = I, Z with a
non-constant narrow def = I, a constant neutral unless it does not fit) instead
of by def ORDER. The first cut emitted
`byte v = (v | (x << 28))` in corpus code; its `B/S/C/I -> I` join then turned a
compiling `short` merge into `int`, and keeping `Z` first-wins made an
`isEmpty()`/`length()` merge `boolean` - both found by adversarial review.

Every case but the corpus one runs on the committed
`tests/data/int-reuse.dex`, assembled from `int-reuse.smali` beside it.
"""

import re
from pathlib import Path

import pytest
from conftest import require_corpus_shape

import dexllm

FIXTURE = Path(__file__).resolve().parent / "data" / "int-reuse.dex"
CLS = "LIntReuse;"


@pytest.fixture(scope="module")
def fx():
    return dexllm.DexKit(str(FIXTURE))


def _lines(text):
    # the `\n`-only contract (dexllm#83): never splitlines()
    return [ln.strip() for ln in text.split("\n")]


# Each method pins the lines that carry the decision.
EXPECTED = {
    # the corpus shape: the call result is an INDEX
    "minIdx([FF)F": [
        "int v0_1 = Math.min((v0_0 - 1), v0_0);",
        "return ((p3[v0_1] + p4) + p3[v0_1]);",
    ],
    # no index use at all, so only the SplitVariables half can fix it - and
    # `float v0_1` here would make `v0_1 / 2` a FLOAT division (a wrong value)
    "minHalf([FI)F": [
        "int v0_1 = Math.min(p3, 7);",
        "return (((float) ((v0_1 / 2) + v0_1)) + p2[p3]);",
    ],
    # the unsplit register: `double v0` printed `v0 = 4.94e-324` for a 1
    "unsplitIdx([DIID)V": ["int v0 = 0;", "v0 = 1;", "p3[v0] = p6;"],
    # every def is a PLAIN move: 32 bits, so not `long` (returned from an int)
    "plainWide([JII)I": ["int v0_1;", "return ((v0_1 + p5) * v0_1);"],
    # the int/float CLASS of a plain move: OFF rendered the 3 as float bits
    "plainClass([FII)I": ["int v0_1;", "v0_1 = 3;"],
    # a constant is NEUTRAL in the join: `char` (OFF `int`, a lossy `char[]`
    # store), `byte` when it fits, otherwise the narrowest type that holds it
    # (ART's merge): `short` for 200, `int` for 40000
    "charConst([CI)V": ["char v0_0 = 65;", "p2[v0_0] = v0_0;"],
    "byteConstFit(Ljava/lang/Byte;Z)Ljava/lang/Byte;": ["byte v0_0 = 3;"],
    "byteConstWide(Ljava/lang/Byte;Z)I": ["short v0_0 = 200;"],
    "byteConstWider(Ljava/lang/Byte;Z)I": ["int v0_0 = 40000;"],
    # the narrow-integral forward dataflow over moves and bitwise ops
    "flagOr(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/Boolean;": [
        "boolean v0_2 = ((false | p2.isEmpty()) | p3.isEmpty());",
    ],
    "zMoveChain(Ljava/lang/String;ZZ)Ljava/lang/Boolean;": [
        "boolean v0_0;",
        "boolean v1 = false;",
        "v1 = v0_0;",
    ],
    "intThroughMove(I)V": ["int v1 = 0;", "v1 = v0;"],
    "parkedFlag(Ljava/lang/String;ZI)Ljava/lang/Boolean;": [
        "boolean v0;",
        "v0 = false;",
    ],
    # NEGATIVE: a lone `0` at an `I` argument does not rule out `boolean`
    "shortcutFlag(Landroid/view/Menu;Landroid/view/KeyEvent;I)Z": [
        "boolean v0 = false;",
        "v0 = p2.performShortcut(p4, p3, 0);",
    ],
    # NEGATIVE: a counter starting from the boolean's `0` stays `int`, the
    # boolean stays `boolean` (values flow forward through a move)
    "loopFlag([Ljava/lang/Object;Ljava/lang/Boolean;)Z": [
        "boolean v0 = false;",
        "int v1 = 0;",
        "return v0;",
    ],
    # NEGATIVE: a `Z` used as a number refuses `boolean`
    "zArith(Ljava/lang/String;)I": ["int v0 = p3.isEmpty();"],
    # NEGATIVE: `Z` + `I` with no numeric use, in either path order
    "zMergeEq(Ljava/lang/String;Z)I": ["int v0_0;"],
    "zMergeEqSwap(Ljava/lang/String;Z)I": ["int v0_0;"],
    # NEGATIVE: a move of a lone constant is no claim on its source
    "containerMatch([II)Z": ["boolean v3 = false;", "v0 = 0;", "return v3;"],
    # a 0/1 register moved into a flag takes the flag's type
    "stopDrag(IZZFZ)Ljava/lang/Boolean;": [
        "boolean v2 = true;",
        "v2 = false;",
        "v1_0 = v2;",
    ],
    # a written `boolean` parameter keeps its declared type, and the `1` beside
    # it in a bitwise op is `true`
    "paramFlag(ZI)Ljava/lang/Boolean;": [
        "boolean v2_1 = (p2 & true);",
        "v2_1 = false;",
    ],
    # the bitwise-boolean spelling recurses: a `1` beside a NESTED bitwise of
    # booleans is `true`
    "nestedFlag(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/Boolean;": [
        "return Boolean.valueOf(((p2.isEmpty() | p3.isEmpty()) | true));",
    ],
    # NEGATIVE: a bitwise of constants alone is not boolean-valued
    "constOnly()I": ["return ((0 | 1) | 1);"],
    # NEGATIVE: only 0/1 are booleans; a `2` beside a boolean stays `2`
    "zAndTwo(Ljava/lang/String;)I": ["return (p1.isEmpty() & 2);"],
    # each of twelve `!b` versions of ONE source comes out boolean, whatever
    # order the dataflow visits them in (a version visited before its source
    # was resolved used to be decided `int` for good)
    "manyNot(Ljava/lang/String;)V": ["Boolean.valueOf((v0 ^ true));"] * 12,
    # NEGATIVE (TransitionSet.getOrdering): `b ? 0 : 1` returned as an `int`
    # is a number, so the `1` stays `1`
    "ordering(Ljava/lang/String;)I": ["return (p1.isEmpty() ^ 1);"],
    # an `if-eqz` on a boolean xor is `!(a ^ b)`, not `(a ^ b) == 0`
    "sameEmpty(Ljava/lang/String;Ljava/lang/String;)I": [
        "if (!(p2.isEmpty() ^ p3.isEmpty())) {",
    ],
    # an unwritten `boolean` parameter keeps its declared type, so an
    # `if-eqz` on it is `!p1` (a later write re-typed the shared Param)
    "paramCond(ZI)I": ["if (!p1) {"],
    # a cycle of constant-only versions keeps its type, and the version it
    # flows into agrees with it
    "cycleFlag(Ljava/lang/String;I)Ljava/lang/Boolean;": [
        "int v0 = 0;",
        "int v2;",
        "v2 = v0;",
    ],
    # a printed (two-use) constant-like source: its destination agrees with it
    "sharedConst(Ljava/lang/String;Z[I)Ljava/lang/Boolean;": [
        "int v0 = 0;",
        "int v1;",
        "v1 = v0;",
    ],
    # an `== 0` test does not stop a 0/1 version taking its flag's type
    "testedFlag(Ljava/lang/String;Z)Ljava/lang/Boolean;": [
        "boolean v0 = true;",
        "if (v0) {",
        "v1 = v0;",
    ],
    # NEGATIVE: a `byte` call result and an `int` producer join to `int`
    "joinBI(Ljava/lang/Byte;)I": [
        "int v0_0 = p2.byteValue();",
        "v0_0 = (v0_1 | (v0_1 << 7));",
    ],
    # NEGATIVE: a `Z` producer beside a 0/1 constant stays `boolean` - `Z` is
    # not in the narrow join (MatcherMatchResult.contains)
    "instZ(Ljava/lang/Object;)I": ["boolean v0_0;", "v0_0 = (p2 instanceof String);"],
    # NEGATIVE: plain moves from an `int` AND a `float` - sources disagree, so
    # the move-width rule leaves the (stale) `long` rather than pick one
    "mixW([JII)I": ["long v0_1;", "v0_1 = 3;"],
    # NEGATIVE (adversarial review): a `Z` and an `I` call result merge to
    # `int` (ART's merge), whichever path comes first - the two are the same
    # bytecode with the branches swapped
    "zMerge(Ljava/lang/String;Z[I)I": ["int v0_1;"],
    "zMergeSwap(Ljava/lang/String;Z[I)I": ["int v0_1;"],
    # NEGATIVE (adversarial review): `byte` and `short` merge to `short`, so
    # `Short.valueOf(S)` still compiles
    "bsMerge(Ljava/lang/Short;Ljava/lang/Byte;Z[S)V": [
        "short v0_1;",
        "Short.valueOf(v0_1);",
    ],
    # NEGATIVE: a genuine `long` index (invalid Dalvik) is not narrowed
    "wideIdx([II)I": ["long v0 = 5;", "v0 = 6;", "return p3[v0];"],
    # POSITIVE (adversarial review): the COMPOUND form spells the 0/1 too
    "cmpXor(Ljava/lang/String;I)Z": ["boolean v0 = p1.isEmpty();", "v0 ^= true;"],
    "cmpAnd(Ljava/lang/String;I)Z": ["boolean v0 = p1.isEmpty();", "v0 &= false;"],
    # NEGATIVE (correctness review): a demotion by the consistency closure
    # travels on through the move it feeds
    "cycleChain(Ljava/lang/String;I)Ljava/lang/Boolean;": [
        "int v2;",
        "int v3;",
        "v3 = v2;",
    ],
    # NEGATIVE (mutation matrix): a constant-like RANGE must fit at both ends
    "rangeByte(Ljava/lang/Byte;I)I": ["int v0;", "v0 = 200;", "int v1 = v0;"],
    # POSITIVE (mutation matrix): constant-only moves across the sorted order
    "constLadder(Ljava/lang/String;I)Z": [
        "boolean v2;",
        "boolean v10;",
        "boolean v13;",
        "boolean v14;",
        "return v14;",
    ],
    # NEGATIVE (delta review): the closure's skip does not follow def order
    "defOrder(Ljava/lang/Byte;ILjava/lang/Short;)V": ["int v5 = 0;", "int v0;"],
    # NEGATIVE (delta review): a typed-from source rises with its destination
    "raisedDest(Ljava/lang/String;IZ)Ljava/lang/Boolean;": [
        "int v3 = 0;",
        "int v2;",
    ],
    # CONVERGENCE (adversarial review): 300 levels, the last one returned
    "boolLadder(Ljava/lang/String;I)Z": ["boolean v616;", "return v616;"],
    # NEGATIVE (hack-gate review): a non-boolean constant decides a bitwise
    # def even while its other operand is still unresolved
    "skipBit(Ljava/lang/String;Z)I": ["int v0;", "v0 = (0 | 2);"],
    "skipBit2(Ljava/lang/String;Z)I": ["int v0;", "v0 = (1 ^ 7);"],
    # POSITIVE (adversarial review): a move of a lone constant carries the
    # constant, not the type its parked register has elsewhere
    "parkedConst(Ljava/lang/String;I[I)Ljava/lang/Boolean;": [
        "int v1 = 0;",
        "boolean v0 = false;",
        "return Boolean.valueOf(v0);",
    ],
    # NEGATIVE (mutation matrix): the carried constant is still checked
    "parkedTwo(Ljava/lang/String;I[I)Ljava/lang/Boolean;": [
        "int v0 = 2;",
        "v0 = p3.isEmpty();",
    ],
    # POSITIVE (mutation matrix): every def a lone-constant move — the
    # parked registers' type is the only hint, and it is used
    "loneHint(Ljava/lang/String;Z)Z": ["boolean v2;", "v2 = false;", "v2 = true;"],
}

# Decompiled only in a memory-capped CHILD: on a build that keeps the
# constant-like values as a list this method needs 2^30 entries, which must
# fail the test, not take the machine with it.
SUBPROCESS_ONLY = {"diamondLadder(I)I"}


def test_the_fixture_verifies_in_both_modes():
    for lenient in (False, True):
        rows = dexllm.verify(str(FIXTURE), lenient=lenient)
        assert [r["valid"] for r in rows] == [True], rows


def test_the_fixture_carries_every_method_the_cases_name(fx):
    have = {m.split("->", 1)[1] for m in fx.list_class_methods(CLS)}
    assert set(EXPECTED) | SUBPROCESS_ONLY == have


@pytest.mark.parametrize("method", sorted(EXPECTED))
def test_each_version_takes_the_width_of_its_own_def(fx, method):
    lines = _lines(fx.decompile_method(f"{CLS}->{method}"))
    for want in set(EXPECTED[method]):
        # a line pinned N times must occur N times
        assert lines.count(want) >= EXPECTED[method].count(want), (method, want, lines)


def test_no_double_bits_for_an_int_constant(fx):
    # the wrong-VALUE half: an int `1` in a `double` version renders as the
    # double whose bits are 1
    text = fx.decompile_method(f"{CLS}->unsplitIdx([DIID)V")
    assert "e-324" not in text, text


def test_the_ast_agrees_with_the_text(fx):
    # the re-type is a property of the Variable both emitters read, so the AST
    # declaration node must carry `int` too: `[kind, init, [TypeName, Local]]`
    ast = fx.decompile_method_ast(f"{CLS}->minIdx([FF)F", include_source=False)
    decls = {}

    def walk(n):
        if isinstance(n, list):
            if n and n[0] == "LocalDeclarationStatement":
                decls[n[2][1][1]] = n[2][0]
            for x in n:
                walk(x)

    walk(ast["ast"]["body"])
    assert decls == {
        "v0_0": ["TypeName", [".int", 0]],
        "v0_1": ["TypeName", [".int", 0]],
    }, decls


def test_the_ast_spells_a_compound_boolean_constant_as_a_boolean(fx):
    # `v0 ^= true`: the compound path is a separate branch in BOTH emitters
    ast = fx.decompile_method_ast(
        f"{CLS}->cmpXor(Ljava/lang/String;I)Z", include_source=False
    )
    found = []

    def walk(n):
        if isinstance(n, list):
            if n and n[0] == "Assignment" and len(n) > 2 and n[2] == "^":
                found.append(n[1][1])
            for x in n:
                walk(x)

    walk(ast["ast"]["body"])
    assert found == [["Literal", "true", [".boolean", 0]]], found


def test_a_ladder_deeper_than_any_round_cap_is_typed_through(fx):
    # every version of a 300-diamond move ladder of two `!isEmpty()` flags is
    # a boolean; a capped round-robin stopped part-way and left `boolean` and
    # `int` disagreeing across a move
    text = fx.decompile_method(f"{CLS}->boolLadder(Ljava/lang/String;I)Z")
    assert len(re.findall(r"^\s*boolean v\d+", text, re.M)) == 601
    assert not re.search(r"^\s*int v\d+", text, re.M), text


_LADDER_CHILD = r"""
import resource, sys
resource.setrlimit(resource.RLIMIT_AS, (3 << 30, 3 << 30))
import dexllm
dk = dexllm.DexKit(sys.argv[1])
print(dk.decompile_method("LIntReuse;->diamondLadder(I)I"))
"""


def test_a_diamond_ladder_of_constants_stays_in_bounded_memory():
    # the values reaching a constant-only version are summarised as a RANGE;
    # as a list they double per diamond (2^30 here). Run capped, in a child.
    import subprocess
    import sys

    r = subprocess.run(
        [sys.executable, "-c", _LADDER_CHILD, str(FIXTURE)],
        capture_output=True,
        text=True,
        timeout=120,
    )
    assert r.returncode == 0, (r.returncode, r.stderr[-2000:])
    assert "DECOMPILE ERROR" not in r.stdout, r.stdout[-2000:]
    assert "return (v60 + 1);" in r.stdout, r.stdout[-2000:]


def _bitwise_literals(n, out):
    # every Literal operand of a bitwise BinaryInfix: ["BinaryInfix", [a, b], op]
    if isinstance(n, list):
        if n and n[0] == "BinaryInfix" and n[2] in ("|", "&", "^"):
            for operand in n[1]:
                if operand and operand[0] == "Literal":
                    out.append((n[2], operand[1], operand[2][0]))
        for x in n:
            _bitwise_literals(x, out)
    return out


def test_the_ast_negates_a_boolean_xor_tested_against_zero(fx):
    # the AST condition is `!(a ^ b)` too: the xor node carries `Z`
    ast = fx.decompile_method_ast(
        f"{CLS}->sameEmpty(Ljava/lang/String;Ljava/lang/String;)I",
        include_source=False,
    )
    cond = ast["ast"]["body"][2][0][2]
    assert cond[0] == "Unary" and cond[2] == "!", cond


@pytest.mark.parametrize(
    "method, want",
    [
        (
            "flagOr(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/Boolean;",
            [("|", "false", ".boolean")],
        ),
        ("paramFlag(ZI)Ljava/lang/Boolean;", [("&", "true", ".boolean")]),
    ],
)
def test_the_ast_spells_a_bitwise_boolean_constant_as_a_boolean(fx, method, want):
    # the Writer and the AST share BitwiseBoolConstant; each emitter calls it
    # separately, so each needs its own guard (the text cases pin the Writer)
    ast = fx.decompile_method_ast(f"{CLS}->{method}", include_source=False)
    assert _bitwise_literals(ast["ast"]["body"], []) == want


_DECL = re.compile(
    r"\b(float|double|long|int|short|byte|char|boolean) (v\d+(?:_\d+)?|p\d+)\b"
)
_IDX = re.compile(r"\[(v\d+(?:_\d+)?)\]")


def _wide_indices(text):
    """Variables declared float/double/long and used as an array index."""
    decl = {}
    for t, n in _DECL.findall(text):
        decl.setdefault(n, t)
    return sorted(
        {n for n in _IDX.findall(text) if decl.get(n) in ("float", "double", "long")}
    )


# The classes the issue's census found (dexllm#94, measured OFF 12 lines in 7
# methods over the bundled corpus, ON 0).
_CORPUS = (
    "Landroid/support/v4/view/animation/LookupTableInterpolator;",
    "Lcom/google/android/material/color/utilities/QuantizerWu;",
    "Landroidx/constraintlayout/solver/LinearSystem;",
    "Lkotlin/collections/ArraysKt___ArraysKt;",
)


def test_the_corpus_instances_declare_an_int_index(loadable_apks):
    seen = 0
    for apk in loadable_apks:
        dk = dexllm.DexKit(apk)
        for cls in _CORPUS:
            if dk.locate_class_dex(cls) < 0:
                continue
            for m in dk.list_class_methods(cls):
                bad = _wide_indices(dk.decompile_method(m))
                seen += 1
                assert not bad, (apk, m, bad)
    require_corpus_shape(
        seen > 0,
        "a bundled APK carrying one of the dexllm#94 corpus classes",
        "an int index is declared float/double/long again",
    )


def _source(rel):
    from test_arg_opcode_coverage import _strip_comments

    root = Path(__file__).resolve().parents[1]
    return re.sub(r"\s+", " ", _strip_comments((root / rel).read_text()))


def test_only_the_invoke_result_temporary_is_marked():
    # The flag is what separates a `move-result` rhs (written once, by its
    # invoke) from a register Variable (shared, last write). Set anywhere else
    # it would trust a stale register; pinned at SOURCE because a second setter
    # changes no fixture output until a stale register reaches it. Every write
    # under native/ is counted - headers and core_ext included - and the one
    # allowed write must sit inside GenInvokeRetName::New. This cannot see a
    # setter spelled through a constructor argument, which is why the member
    # has no constructor parameter.
    root = Path(__file__).resolve().parents[1]
    writes, decls = [], []
    for p in sorted((root / "native").rglob("*")):
        if p.suffix not in (".cpp", ".cc", ".h", ".hpp"):
            continue
        src = _source(str(p.relative_to(root)))
        # a member write goes through `->` or `.`; the declaration is
        # `bool invoke_result = false;` (a local reading it is neither)
        for m in re.finditer(r"(?:->|\.)\s*invoke_result\s*=(?!=)", src):
            writes.append(p.name)
        if re.search(r"\bbool invoke_result = false;", src):
            decls.append(p.name)
    assert decls == ["instruction.h"], decls
    assert writes == ["graph.cpp"], writes
    src = _source("native/dad_cpp/graph.cpp")
    body = src[src.index("IRFormPtr GenInvokeRetName::New()") :]
    body = body[: body.index("return ret_;")]
    assert "tmp->invoke_result = true;" in body
    assert src.count("invoke_result = true") == 1


def test_a_call_result_that_is_not_narrow_integral_is_foreign():
    # A `move-result` def is typed by its call. If that type is a reference
    # or a wide primitive, the version is not this dataflow's business and
    # must be marked foreign; otherwise `join(bottom, "Lfoo;")` lets the pass
    # set a non-narrow type it was never meant to decide. Pinned at SOURCE:
    # on the corpus the type it would set is the one the version already has
    # (3 versions, 0 output change measured), and reaching a visible change
    # needs a reference and an int merged in one register, which verified
    # Dalvik rejects.
    src = _source("native/dad_cpp/dataflow.cpp")
    assert (
        "if (rv && rv->invoke_result) { in.type = rf->get_type(); "
        "ok = is_nint(in.type); }"
    ) in src
