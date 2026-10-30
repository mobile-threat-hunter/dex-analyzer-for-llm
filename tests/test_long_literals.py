"""dexllm#92 — a `long` literal carries the `L` suffix, in every position.

A dex `const-wide*` builds a `J`-typed constant, and the text Writer printed its
decimal bare: `this.mStartTime = -9223372036854775808;` and
`static final long UTC_2000 = 946728000000;` do not lex (`integer number too
large`), and a small value at a `(J)` parameter binds an `(I)` overload when one
exists — `takeOv(220)` calls the wrong method, silently. The suffix is decided by
the TYPE, never by the value, which is also the spelling DAD's `dast.py:613`
`literal_long` always gave the AST.

A conversion (`double-to-int`) and a negation (`neg-double`) read their operand
as a TYPE too, and did not go through `ConstantAt`: a `const-wide` holding
double bits printed as the long `4607182418800017408` — rejected by javac before
this change, and ACCEPTED with the wrong value once it gained an `L` (an
adversarial review's finding). They are typed positions now, which also fixes
six corpus lines that already compiled with a wrong float value
(`(- 2139095039)` for `-Float.MAX_VALUE`).

Not covered, recorded: a `long[]` fill-array payload (no element type on the
IR node — dexllm#93's problem).

Two readers: the method body (`Constant::Accept` -> `visit_constant_long`) and
the static-initializer decoder (`DecodeEncodedValueText`'s 0x06 arm). Both call
one `FormatLongLiteral`. Controls: an int at an `(I)` parameter, an int static,
and a `const-wide` at a DOUBLE position (reinterpreted by `ConstantAt`) must not
gain an `L`.

The fixture `tests/data/long-literals.dex` is authored smali (see
tests/data/README.md), so every case runs without the corpus.
"""

from __future__ import annotations

import re
import shutil
import subprocess
from collections import Counter

import pytest
from conftest import REPO_ROOT
from test_static_float_justification import _strip_comments

dexllm = pytest.importorskip("dexllm")

_FIXTURE = REPO_ROOT / "tests" / "data" / "long-literals.dex"
_CLASS = "LLongLiterals;"

# The rendered body line of each method — LITERALS, so a change of the rule
# cannot move the expectation with it.
_BODY = {
    "argSmall()V": "LongLiterals.takeOv(220L);",
    "argBig()V": "LongLiterals.takeOv(946728000000L);",
    "retMin()J": "return -9223372036854775808L;",
    "retZero()J": "return 0L;",
    "retNeg()J": "return -1L;",
    "addOne(J)J": "return (p2 + 1L);",
    "cmpHundred(J)Z": "if (p2 <= 100L) {",
    "storeStatic()V": "LongLiterals.sJ = 7L;",
    "storeInstance()V": "this.iJ = 2147483648L;",
    # controls: an int, and a const-wide the DOUBLE position reinterprets
    "argInt()V": "LongLiterals.takeOv(220);",
    "argDouble()V": "LongLiterals.takeD(1);",
    # a conversion / negation reads its operand as a TYPE (review finding):
    # the long ones keep `L`, double/float bits are projected, never `...L`
    "castLong()I": "return ((int) 4294967296L);",
    "negLong()J": "return (- 5L);",
    "castDoubleBits()I": "return ((int) 1);",
    "negDoubleBits()D": "return (- 1);",
    "negFloatBits()F": "return (- 1f);",
}

_STATICS = {
    "SMALL": "long SMALL = 5L;",
    "NEG": "long NEG = -1L;",
    "BIG": "long BIG = 946728000000L;",
    "EDGE": "long EDGE = 2147483648L;",
    "MIN": "long MIN = -9223372036854775808L;",
    "MAX": "long MAX = 9223372036854775807L;",
    "INT_F": "int INT_F = 5;",  # control
}

_LONG_TOKEN = re.compile(r"(?<![\w.])(-?\d+)L\b")
_STRING = re.compile(r'"(?:\\.|[^"\\])*"')


@pytest.fixture(scope="module")
def fx():
    return dexllm.DexKit(str(_FIXTURE))


def _lines(text: str) -> list[str]:
    # `\n`, never splitlines() — the decompile_class contract (dexllm#83).
    return [line.strip() for line in text.split("\n")]


def test_the_fixture_verifies_strict() -> None:
    (row,) = dexllm.verify(str(_FIXTURE))
    assert row["valid"], row


@pytest.mark.parametrize("sig", sorted(_BODY))
def test_a_long_literal_is_spelled_with_its_type(fx, sig) -> None:
    text = fx.decompile_method(f"{_CLASS}->{sig}")
    assert _BODY[sig] in _lines(text), text


@pytest.mark.parametrize("field", sorted(_STATICS))
def test_a_static_long_initializer_carries_the_suffix(fx, field) -> None:
    decls = [ln for ln in _lines(fx.decompile_class(_CLASS)) if f" {field} = " in ln]
    assert len(decls) == 1 and decls[0].endswith(_STATICS[field]), decls


def _ast_longs(node, acc) -> None:
    if isinstance(node, list):
        if (
            len(node) >= 3
            and node[0] == "Literal"
            and isinstance(node[2], (list, tuple))
            and node[2][0] == ".long"
        ):
            acc.append(node[1])
        for c in node:
            _ast_longs(c, acc)
    elif isinstance(node, dict):
        for c in node.values():
            _ast_longs(c, acc)


@pytest.mark.parametrize(
    "fixture",
    [
        "long-literals.dex",
        "int-reuse.dex",
        "fp-reuse.dex",
        "negative-statics.dex",
        "invoke-custom.dex",
        "typed-positions.dex",
    ],
)
def test_the_text_and_the_ast_spell_the_same_long_literals(fixture) -> None:
    """Per method, the `NL` tokens of the text equal the AST's `.long` literal
    nodes — the AST is a different emitter (dast) reading the same nodes, and it
    has always carried the suffix. Measured over 201,670 corpus methods with no
    mismatch; the committed fixtures keep it in CI."""
    dk = dexllm.DexKit(str(REPO_ROOT / "tests" / "data" / fixture))
    seen = 0
    for cls in dict.fromkeys(dk.list_classes()):
        for m in dk.list_class_methods(cls):
            a = dk.decompile_method_ast(m)
            acc: list[str] = []
            _ast_longs(a.get("ast"), acc)
            text = _STRING.sub('""', a.get("source") or "")
            toks = [t + "L" for t in _LONG_TOKEN.findall(text)]
            assert Counter(acc) == Counter(toks), (m, acc, toks)
            seen += len(acc)
    if fixture == "long-literals.dex":
        assert seen >= 9, seen  # the guard reached the fixture's long literals


def test_javac_binds_the_overload_the_bytecode_calls(fx, tmp_path) -> None:
    """Compile the DECOMPILED methods beside the fixture's overloads: a bare
    `220` binds `takeOv(int)` where the bytecode calls `takeOv(long)`, and
    `946728000000` does not lex at all."""
    if not (shutil.which("javac") and shutil.which("javap")):
        pytest.skip("no JDK on PATH")
    names = ["argSmall()V", "argBig()V", "argInt()V", "retMin()J", "storeInstance()V"]
    body = "\n".join(fx.decompile_method(f"{_CLASS}->{n}") for n in names)
    src = (
        "public class LongLiterals {\n"
        "  long iJ;\n"
        "  static void takeOv(int i) {}\n"
        "  static void takeOv(long l) {}\n" + body + "\n}\n"
    )
    (tmp_path / "LongLiterals.java").write_text(src)
    r = subprocess.run(
        ["javac", "-d", str(tmp_path), str(tmp_path / "LongLiterals.java")],
        capture_output=True,
        text=True,
    )
    assert r.returncode == 0, r.stderr + src
    dis = subprocess.run(
        ["javap", "-c", "-cp", str(tmp_path), "LongLiterals"],
        capture_output=True,
        text=True,
        check=True,
    ).stdout
    for name, call in (
        ("argSmall", "takeOv:(J)V"),
        ("argBig", "takeOv:(J)V"),
        ("argInt", "takeOv:(I)V"),
    ):
        sect = dis.split(f" {name}();", 1)[1].split("\n\n", 1)[0]
        assert f"Method {call}" in sect, (name, sect)


def test_the_rule_is_read_once() -> None:
    """Both readers CALL `FormatLongLiteral`; a correct duplicate passes every
    behavioural case and drifts on the first edit (dexllm#70's lesson)."""
    writer = _strip_comments((REPO_ROOT / "native/dad_cpp/writer.cpp").read_text())
    m = re.search(
        r"void visit_constant_long\(int64_t value\) override \{(.*?)\}", writer, re.S
    )
    assert m and re.fullmatch(
        r"\s*w_->Write\(FormatLongLiteral\(value\)\);\s*", m.group(1)
    ), m and m.group(1)
    dec = _strip_comments(
        (REPO_ROOT / "native/core_ext/dexitem_code_source.cpp").read_text()
    )
    fn = dec[dec.index("DecodeEncodedValueText(const U1*& p") :]
    arm = fn[fn.index("case 0x06: {") :]
    arm = arm[: arm.index("case 0x03:")]
    assert "dexkit::dad::FormatLongLiteral(" in re.sub(r"\s+", "", arm), arm
    accept = _strip_comments(
        (REPO_ROOT / "native/dad_cpp/instruction_accept.cpp").read_text()
    )
    assert re.search(
        r'if \(type == "J"\) \{\s*v\.visit_constant_long\(cst2_\);', accept
    ), "Constant::Accept no longer routes J to visit_constant_long"


@pytest.mark.parametrize(
    "sig, kind",
    [
        ("castDoubleBits()I", ".double"),
        ("negDoubleBits()D", ".double"),
        ("negFloatBits()F", ".float"),
        ("castLong()I", ".long"),
        ("negLong()J", ".long"),
    ],
)
def test_a_conversion_or_negation_operand_is_a_typed_position_in_the_ast(
    fx, sig, kind
) -> None:
    """The AST twin: the literal under a `Cast` / `Unary` carries the type the
    operand is READ as, so text and AST agree on the projection too."""
    a = fx.decompile_method_ast(f"{_CLASS}->{sig}", include_source=False)
    kinds: list[str] = []

    def walk(n) -> None:
        if isinstance(n, list):
            if len(n) >= 3 and n[0] == "Literal" and isinstance(n[2], list):
                kinds.append(n[2][0])
            for c in n:
                walk(c)

    walk(a["ast"]["body"])
    assert kinds == [kind], kinds
