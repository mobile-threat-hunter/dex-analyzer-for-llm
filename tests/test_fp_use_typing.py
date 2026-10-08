"""A float USE types the register version it reads (dexllm#88).

Dalvik constants are untyped: `const/high16 v, #0x3f800000` is how a `1.0f` is
written, and every `const*` builds an INT-typed value. When the register is also
reused for an int, DAD's last-write typing declares the version `int` and the
Java view prints the raw IEEE-754 bits — and in a `float` method RETURNS them,
which Java widens to `1.06535322E9f`: a wrong VALUE, not merely a wrong type.

`InferCascadeTypes` (native/dad_cpp/dataflow.cpp) now treats a float/double USE
as the proof, the same way dexllm#86 treats a `Z` return: an `add-float` /
`cmp-float` / `neg-float` / `float-to-int` operand, the value of `return` in an
`F`/`D` method, an argument at an `F`/`D` parameter, a value stored into an
`F`/`D` field or a `float[]`/`double[]` element.

Every case here runs on the committed `tests/data/fp-reuse.dex` (assembled from
`fp-reuse.smali` beside it), so they hold in the corpus-less CI leg and under any
`$DEXLLM_TEST_APK` narrowing. The one corpus case is the real-world evidence and
goes through `require_corpus_shape`.
"""

import json
import re
from pathlib import Path

import pytest
from conftest import require_corpus_shape

import dexllm

FIXTURE = Path(__file__).resolve().parent / "data" / "fp-reuse.dex"
CLS = "LFpReuse;"


@pytest.fixture(scope="module")
def fx():
    return dexllm.DexKit(str(FIXTURE))


def _java(fx, method):
    return fx.decompile_method(f"{CLS}->{method}")


def _lines(text):
    # the `\n`-only contract (dexllm#83): never splitlines()
    return [ln.strip() for ln in text.split("\n")]


# Each POSITIVE pins the lines that carry the decision. A method whose only
# float use is ONE position (the `*F` family) is what makes a mutant that drops
# that position fail here and nowhere else.
POSITIVE = {
    # the corpus shape, LookupTableInterpolator.getInterpolation byte for byte
    "interp(F)F": ["float v4_0 = 1f;", "v4_0 = 0f;", "return v4_0;"],
    # the wide twin: whole-number doubles render as `1` (valid widening)
    "interpD(D)D": ["double v4_0 = 1;", "v4_0 = 0;", "return v4_0;"],
    "store(F[I)V": ["float v2_2;", "v2_2 = 1f;", "FpReuse.sOut = (v3_0 * v2_2);"],
    # typed by the backwards propagation: its only use is a move
    "viaMove(FI[I)F": ["float v1_0 = 2f;", "v1_0 = 3f;"],
    "retF(I)F": ["float v0 = 1f;", "v0 = 2f;", "return v0;"],
    "retD(I)D": ["double v0 = 1;", "v0 = 2;", "return v0;"],
    "cmpF(IF)I": ["float v0 = 1f;", "v0 = 2f;"],
    "negF(I)F": ["float v0 = 1f;", "v0 = 2f;", "return (- v0);"],
    "castF(I)I": ["float v0 = 1.5f;", "v0 = 2.5f;", "return ((int) v0);"],
    "binF(IF)F": ["float v0 = 1f;", "v0 = 2f;", "return (v0 + p3);"],
    "argF(I)V": ["float v0 = 1f;", "v0 = 2f;", "FpReuse.sinkF(v0);"],
    "sputF(I)V": ["float v0 = 1f;", "v0 = 2f;", "FpReuse.sOut = v0;"],
    "iputF(I)V": ["float v0 = 1f;", "v0 = 2f;", "this.mStepSize = v0;"],
    "aputF([FI)V": ["float v0 = 1f;", "v0 = 2f;", "p1[p2] = v0;"],
    # a parameter declared `float`, overwritten by a constant
    "paramF(FZ)F": ["p1 = 1f;"],
    # a REFERENCE-typed register overwritten by a constant (`drawShadow`):
    # SplitConflatedVersion types the version `Object`, and without the
    # reference admission the ref->prim branch would narrow it to `int`
    "refConf(I)F": ["float v0 = 2f;", "v0 = 1f;", "return v0;"],
    # a move CYCLE around a loop: the def walk's back edge must be neutral
    "swap(I)F": ["float v0 = 1f;", "float v1 = 2f;", "float v2 = v0;"],
    # the move's DESTINATION is already `float` (a float move-result is the
    # register's last write), so only the propagation can type the source
    "viaMoveF(I)F": ["float v1 = 2f;", "v1 = 3f;"],
    # a float moved into a register DAD leaves unsplit (a `float[]` on the
    # other path) that is used as a reference: a REFERENCE use behind a move
    # must not travel back and block the float source
    "refBehindMove(I)V": ["float v0 = 1f;", "v0 = 2f;", "FpReuse.sinkF(v0);"],
    # a destination with no use at all (DCE runs after this pass) is ADOPTED
    # forward instead of dropping its float source
    "deadCarrier(I)F": ["float v0 = 1f;", "v0 = 2f;"],
    # a float PARAMETER as a move source: only its declared type says so
    "paramSrc(FI)F": ["float v0_0 = 2f;", "v0_0 = p3;"],
}

# Each NEGATIVE pins the int rendering it must KEEP: no single Java type fits,
# or nothing proves a float, so the version is left as DAD typed it.
NEGATIVE = {
    "flags(I)I": ["int v0 = 268435456;", "return v0;"],
    # used as BOTH an int and a float
    "mixed(IF)F": [
        "int v0 = 1065353216;",
        "v0 = 1073741824;",
        "FpReuse.sInt = (v0 + 1);",
    ],
    # an int-PRODUCING def (add-int) reaching a float use
    "intDef(FI)F": ["int v0 = (p2 + 1);", "v0 = 1065353216;"],
    "sputI(I)V": ["int v0 = 1065353216;", "FpReuse.sInt = v0;"],
    "aputI([II)V": ["int v0 = 1065353216;", "p1[p2] = v0;"],
    # a parameter declared `int`: only the DECLARED type may decide
    "paramI(IZ)F": ["p1 = 1065353216;"],
    # lenient-only shapes the structural verifier still accepts: NARROW
    # constants reaching a double use (32 bits must not be read as 64), and one
    # version used as a float AND as the low half of a double (two widths)
    "narrowD(I)D": ["int v0 = 1065353216;", "v0 = 1073741824;"],
    "twoWidths(ID)F": ["int v0 = 1065353216;", "FpReuse.sD = (v0 + p4);"],
    # constructed by a correctness review against the first cut, each of which
    # it turned into invalid Java. ONE register at a float position AND an int
    # position of ONE instruction (an aput index + value; an F and an I arg):
    "aputIdx([FI)V": ["int v0 = 0;", "v0 = 1;", "p1[v0] = v0;"],
    "invFI(I)V": ["int v0 = 0;", "v0 = 1;", "FpReuse.sinkFI(v0, v0);"],
    # an int use BEHIND a move must travel back to the source — through the
    # propagation, and through the seed when the source has its own float use
    "fanout(I)F": ["int v1 = 1065353216;", "FpReuse.sInt = (v1 + 1);"],
    "seedBehindMove(I)F": ["int v1 = 1065353216;", "FpReuse.sInt = (v1 + 1);"],
    # the destination's value IS the int-used source's value
    "srcInt(I)F": [
        "int v1 = 1065353216;",
        "FpReuse.sInt = (v1 + 1);",
        "int v0 = 1077936128;",
        "v0 = v1;",
    ],
    # a cmp RESULT is an int although its IR node carries the operand width
    "cmpAsF(FFI)F": ["int v0 = p1 cmp p2;", "v0 = 1065353216;"],
    # constructed by a DELTA review against the responses above. A source
    # moved into a destination that stays non-float must stay `int` too (the
    # forward half of the move rule), a 0 is also `null`, and a plain move into
    # a reference-only register is not an unsplit register
    "forwardOrphan(FI)F": ["int v0 = 1065353216;", "v1 = v0;"],
    "zeroToInteger(FI)F": ["int v0 = 0;", "Integer v1 = v0;"],
    "plainIntoRef(FI)F": ["int v0 = 1065353216;", "int v1 = v0;"],
    # a 0 moved into a register WITH a reference arm: the unsplit-register
    # exception must not apply, 0 is also `null`
    "zeroIntoUnsplit(FI)F": ["int v0 = 0;", "v1 = v0;"],
    # (final delta review) a float ARITHMETIC def carries the width like a
    # move: a float operand under an `int` result renders `int v2 = (- v0)`
    "negIntoInt(I)V": ["int v0 = 1065353216;", "v2 = (- v0);"],
}


def test_the_fixture_verifies_in_both_modes():
    # an unverifiable craft never reaches the IR builder, so every case below
    # would pass for the wrong reason
    for lenient in (False, True):
        rows = dexllm.verify(str(FIXTURE), lenient=lenient)
        assert [r["valid"] for r in rows] == [True], rows


def test_the_fixture_carries_every_method_the_cases_name(fx):
    have = {m.split("->", 1)[1] for m in fx.list_class_methods(CLS)}
    assert set(POSITIVE) | set(NEGATIVE) <= have


@pytest.mark.parametrize("method", sorted(POSITIVE))
def test_a_float_use_types_the_version_float(fx, method):
    lines = _lines(_java(fx, method))
    for want in POSITIVE[method]:
        assert want in lines, (method, want, lines)


@pytest.mark.parametrize("method", sorted(POSITIVE))
def test_no_raw_ieee_bits_survive_in_a_positive(fx, method):
    # the defect's own signature: a float/double constant printed as its bits
    text = _java(fx, method)
    bits = re.findall(r"(?<![\w.$])-?\d{8,}(?![\w.])", text)
    assert not bits, (method, bits, text)


@pytest.mark.parametrize("method", sorted(NEGATIVE))
def test_an_unproven_version_stays_int(fx, method):
    lines = _lines(_java(fx, method))
    for want in NEGATIVE[method]:
        assert want in lines, (method, want, lines)


def test_the_ast_agrees_with_the_text(fx):
    # the re-type is a property of the Variable both emitters read, so the
    # AST's declaration must carry the float literal and the float type too
    ast = fx.decompile_method_ast(f"{CLS}->interp(F)F", include_source=False)
    blob = json.dumps(ast["ast"]["body"])
    i = blob.index('"LocalDeclarationStatement"')
    decl = blob[i : i + 200]
    assert '"Literal", "1.0f", [".float", 0]' in decl, decl
    assert '"TypeName", [".float", 0]' in decl, decl
    assert "1065353216" not in blob


def _source(rel):
    from test_arg_opcode_coverage import _strip_comments

    root = Path(__file__).resolve().parents[1]
    return re.sub(r"\s+", " ", _strip_comments((root / rel).read_text()))


def test_a_pure_move_cycle_is_not_called_a_float():
    # The `ground` requirement: an all-quantifier over a closure of nothing
    # but moves is satisfied vacuously. No dex that loads reaches it — a
    # register read before it is written has no version type for this branch
    # to replace (the fixture's `noGround` renders `unknownType`) — so it is
    # pinned at SOURCE level, which is weaker than a behavioural guard and is
    # stated as such: it cannot see the line present and wrong.
    src = _source("native/dad_cpp/dataflow.cpp")
    body = src[src.index("auto all_defs_fp_valued") : src.index("auto fp_retypable")]
    assert "bool ground = false;" in body
    assert re.search(r"return ground; \}; *$", body.rstrip()), body[-80:]


def test_the_move_rule_is_a_worklist():
    # A round-robin `while (changed)` over the move list advances one link per
    # round: O(N^2) on a crafted move chain. A first cut's closure was exactly
    # that, measured by a delta review at 12.8 s for 25,000 moves (OFF 2.7 s) —
    # past `safe.py`'s 10 s deadline for ONE method. A behavioural guard needs
    # a 25k-move dex and a timer; this pins the shape instead, which is weaker
    # and says so: a drop re-checks only the edges touching the dropped vid.
    src = _source("native/dad_cpp/dataflow.cpp")
    body = src[src.index("auto width_of = [&]") :]
    body = body[: body.index("std::vector<std::string> keys;")]
    assert "while (grew)" not in body and "while (changed)" not in body
    assert "while (!dropped.empty())" in body
    assert "srcs_into.find(x)" in body and "dsts_of.find(x)" in body


def test_a_cast_records_its_operand_width():
    # `float-to-int` and `long-to-int` were one IR node with type "I"; the
    # OPERAND width is what lets a cast be a float use at all. Pinned at the
    # handlers because no output can tell a missing width from a wrong one on
    # every opcode — `castF` covers float-to-int only.
    src = (
        Path(__file__).resolve().parents[1] / "native/dad_cpp/opcode_ins.cpp"
    ).read_text()
    conv = re.findall(
        r"IRFormPtr (\w+)\s*\(std::string_view a, std::string_view b, Vmap& v\) "
        r'\{ return AssignCastExp\(a, b, "[^"]+",\s*"([A-Z])", v, "([A-Z])"\); \}',
        src,
    )
    got = {name: srct for name, _, srct in conv}
    want = {
        "IntToLong": "I",
        "IntToFloat": "I",
        "IntToDouble": "I",
        "LongToInt": "J",
        "LongToFloat": "J",
        "LongToDouble": "J",
        "FloatToInt": "F",
        "FloatToLong": "F",
        "FloatToDouble": "F",
        "DoubleToInt": "D",
        "DoubleToLong": "D",
        "DoubleToFloat": "D",
        "IntToByte": "I",
        "IntToChar": "I",
        "IntToShort": "I",
    }
    assert got == want


# the corpus's own instance, by name. A real APK is the evidence that the
# shape is not an artefact of the fixture; the fixture is what holds in CI.
_CORPUS = {
    # (a smali line that marks the dx-built shape, the lines it must render)
    "Landroid/support/v4/view/animation/LookupTableInterpolator;->getInterpolation(F)F": (
        "move v4, v5",
        ("float v4_0 = 1f;", "v4_0 = 0f;"),
    ),
    "Lcom/google/android/material/shadow/ShadowDrawableWrapper;->drawShadow(Landroid/graphics/Canvas;)V": (
        "move v15, v6",
        ("float v15_0;", "v15_0 = 1f;"),
    ),
    # the reference-use-behind-a-move shape `refBehindMove` stands in for
    "Landroidx/core/content/res/GradientColorInflaterCompat;->createFromXmlInner"
    "(Landroid/content/res/Resources;Lorg/xmlpull/v1/XmlPullParser;"
    "Landroid/util/AttributeSet;Landroid/content/res/Resources$Theme;)"
    "Landroid/graphics/Shader;": (
        "move-result v14",
        (
            "float v14_1 = androidx.core.content.res.TypedArrayUtils.getNamedFloat("
            'v2_6, p29, "centerY", androidx.core.R$styleable.GradientColor_android_centerY, 0f);',
        ),
    ),
    # NOT a #88 site — OFF already declares it `float` (prim→WIDER). It pins
    # that a float candidate the FORWARD check drops falls back to the later
    # branches: a first cut `continue`d past them and printed `int v0_7`
    "Landroidx/recyclerview/widget/RecyclerView;->onGenericMotionEvent"
    "(Landroid/view/MotionEvent;)Z": (
        "getAxisValue(I)F",
        ("float v0_7 = p6.getAxisValue(26);",),
    ),
    # a `long` constant whose float candidate meets ANOTHER branch's pending
    # `double` re-type across a move: the move rule must read the pending type
    # (or the source is dropped) and a candidate must not `continue` past the
    # branches that produce it
    "Landroidx/constraintlayout/motion/widget/MotionPaths;->setView"
    "(Landroid/view/View;[I[D[D[D)V": (
        "move-wide/from16 v14, v18",
        ("double v18_1 = 0;", "double v14_4 = v18_1;"),
    ),
}


def test_the_corpus_instances_declare_float(loadable_apks):
    seen = 0
    for apk in loadable_apks:
        dk = dexllm.DexKit(apk)
        for desc, (marker, want) in _CORPUS.items():
            cls = desc.split("->", 1)[0]
            if dk.locate_class_dex(cls) < 0:
                continue
            # other APKs carry a d8 build of the same class, which never had
            # the shape (d8 duplicates the return) — select by the bytecode
            if marker not in dk.render_method_smali(desc):
                continue
            text = dk.decompile_method(desc)
            lines = _lines(text)
            seen += 1
            for w in want:
                assert w in lines, (apk, desc, w)
            assert "1065353216" not in text, (apk, desc)
    require_corpus_shape(
        seen > 0,
        "a bundled APK carrying LookupTableInterpolator or ShadowDrawableWrapper",
        "a float constant in a reused register is declared `int` again",
    )
