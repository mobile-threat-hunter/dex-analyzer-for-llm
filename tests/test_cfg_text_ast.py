"""The Java text and the AST agree on control flow (dexllm#113).

Both emitters walk the same structured graph; the AST one (dast.cpp) is a
port of DAD's dast.py and the text one (writer.cpp) of DAD's writer.py. The
text Writer had two porting gaps the AST did not:

* an `if` with NO follow folded into the follow path, so the false arm was
  skipped when already visited -- but a ReturnBlock is re-emitted at every
  path that reaches it, so a `return` the AST keeps vanished from the text
  and the method fell off its end (writer.py:352 visits both arms);
* a switch whose `default` IS one of its case blocks emitted that block
  twice (writer.py:398 labels it `default:` among the cases and skips the
  trailing default).

Every case runs on the committed `tests/data/cfg-shapes.dex`, assembled from
`cfg-shapes.smali`; one corpus case pins the method the issue was filed on.
"""

import re
from pathlib import Path

import pytest
from conftest import require_corpus_shape

import dexllm

DATA = Path(__file__).resolve().parent / "data"
ROOT = Path(__file__).resolve().parents[1]
FIXTURE = DATA / "cfg-shapes.dex"
HAS_CALLBACK = "LCfgShapes;->hasCallback(Ljava/lang/Object;)Z"
SHARED_DEFAULT = "LCfgShapes;->sharedDefault(I)I"
CASE_IF = "LCfgShapes;->caseIf(ILjava/lang/String;)I"
FALL_DEFAULT = "LCfgShapes;->fallDefault(I)I"

_RET = re.compile(r"^\s*return [^;]")


@pytest.fixture(scope="module")
def fx():
    return dexllm.DexKit(str(FIXTURE))


def _text_returns(text):
    return sum(1 for line in text.split("\n") if _RET.match(line))


def _ast_returns(node):
    n = 0
    if isinstance(node, list):
        if (
            node
            and node[0] == "ReturnStatement"
            and len(node) > 1
            and node[1] is not None
        ):
            n += 1
        for x in node:
            n += _ast_returns(x)
    elif isinstance(node, dict):
        for x in node.values():
            n += _ast_returns(x)
    return n


def _ast_switch_cases(node, out):
    """Collect the case-key lists of every SwitchStatement in the AST."""
    if isinstance(node, list):
        if node and node[0] == "SwitchStatement":
            for pair in node[3]:
                out.append(pair[0])
        for x in node:
            _ast_switch_cases(x, out)
    elif isinstance(node, dict):
        for x in node.values():
            _ast_switch_cases(x, out)
    return out


def _body(text):
    return [line.strip() for line in text.split("\n") if line.strip()]


def test_the_fixture_carries_both_shapes(fx):
    smali = fx.render_method_smali(HAS_CALLBACK)
    # one `return` instruction, reached by three paths
    assert smali.count(": return ") == 1, smali
    assert "packed-switch" in fx.render_method_smali(SHARED_DEFAULT)


def test_a_follow_less_if_keeps_its_return_arm(fx):
    text = fx.decompile_method(HAS_CALLBACK)
    lines = _body(text)
    i = lines.index("if (v0.get(p6) == null) {")
    assert lines[i : i + 7] == [
        "if (v0.get(p6) == null) {",
        "v2_0 = false;",
        "return v2_0;",
        "} else {",
        "return v2_0;",
        "}",
        "}",
    ], text


@pytest.mark.parametrize(
    "method", [HAS_CALLBACK, SHARED_DEFAULT, CASE_IF, FALL_DEFAULT]
)
def test_text_and_ast_agree_on_value_returns(fx, method):
    text = fx.decompile_method(method)
    ast = fx.decompile_method_ast(method, include_source=False)["ast"]
    assert _text_returns(text) == _ast_returns(ast["body"]), text


def test_an_arm_that_emits_nothing_opens_no_else(fx):
    """DAD writes `} else {` unconditionally in a follow-less if; when the
    false arm is the enclosing switch's follow, VisitNode writes nothing for
    it and the text omits the empty arm (the AST keeps an empty block)."""
    text = fx.decompile_method(CASE_IF)
    lines = _body(text)
    i = lines.index('if (p3.equals("tap")) {')
    assert lines[i : i + 4] == [
        'if (p3.equals("tap")) {',
        "v0 = 0;",
        "}",
        "break;",
    ], text
    assert not any(a == "} else {" and b == "}" for a, b in zip(lines, lines[1:])), text


def test_a_shared_default_is_emitted_once(fx):
    text = fx.decompile_method(SHARED_DEFAULT)
    lines = _body(text)
    assert lines.count("return 99;") == 1, text
    assert lines.count("default:") == 1, text
    i = lines.index("case 3:")
    assert lines[i : i + 3] == ["case 3:", "default:", "return 99;"], text


def test_a_default_that_falls_through_keeps_its_store(fx):
    """The default IS case 3's block, which falls through into case 4. Emitted
    separately after the cases (pre-#113), the default path skipped
    `v0 = 7` and the method returned 1 where the bytecode returns 8."""
    lines = _body(fx.decompile_method(FALL_DEFAULT))
    i = lines.index("case 3:")
    assert lines[i : i + 5] == [
        "case 3:",
        "default:",
        "v0_0 = 7;",
        "case 4:",
        "break;",
    ], lines
    assert lines.count("default:") == 1, lines


def test_the_text_switch_labels_match_the_ast(fx):
    text = fx.decompile_method(SHARED_DEFAULT)
    labels = []
    group = []
    for line in _body(text):
        m = re.fullmatch(r"case (-?\d+):", line)
        if m:
            group.append(int(m.group(1)))
        elif line == "default:":
            group.append(None)
        elif group:
            labels.append(group)
            group = []
    ast = fx.decompile_method_ast(SHARED_DEFAULT, include_source=False)["ast"]
    assert labels == _ast_switch_cases(ast["body"], []) == [[2], [3, None], [4]]


def test_the_corpus_method_the_issue_was_filed_on(loadable_apks):
    apk = next(
        (a for a in loadable_apks if a.endswith("com.example.android.tvleanback.apk")),
        None,
    )
    require_corpus_shape(
        apk is not None, "tvleanback.apk", "the bundled corpus lost tvleanback"
    )
    dk = dexllm.DexKit(apk)
    m = "Landroid/support/v4/media/session/MediaSessionCompatApi21;->hasCallback(Ljava/lang/Object;)Z"
    text = dk.decompile_method(m)
    ast = dk.decompile_method_ast(m, include_source=False)["ast"]
    assert _text_returns(text) == _ast_returns(ast["body"]) == 3, text


def test_the_writer_ports_both_dad_branches():
    """Source pin: the follow-less branch returns before the follow path, and
    the switch loop consumes the default it labels."""
    src = (ROOT / "native/dad_cpp/writer.cpp").read_text()
    body = src[src.index("void Writer::EmitIf(") : src.index("void Writer::EmitLoop(")]
    nf = body.index("if (follow == nullptr) {")
    assert nf < body.index("if_follow_.push_back(follow)")
    sw = src[src.index("void Writer::EmitSwitch(") : src.index("void Writer::EmitTry(")]
    assert "if (case_node == default_node) {" in sw
    assert "default_node = nullptr;" in sw
