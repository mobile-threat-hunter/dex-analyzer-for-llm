"""An untyped Dalvik constant takes the declared type of its position (dexllm#102).

A `const*` is untyped: `const/4 v0, 1` is how `true` is written, and `0` is how
`null` is. Every `const*` handler builds an INT-typed `Constant` (DAD), so the
type comes from the POSITION that consumes it: the declared type of the
parameter, field, array element, check-cast, throw, return value or local.

Before #102 that projection was spelled six times and applied at three of the
positions (return, local assignment, and F/D operands), so the corpus carried
`getBoolean("x", 1)`, `this.flag = 1`, `listener.set(0)`, `arr[i] = 0` and
`sb.append(125)` -- the last one compiling to the WRONG overload. Now ONE
definition, `ConstantAt` (instruction.h), decides it, and both emitters call it.

The same fact for a VARIABLE is the type-inference pass's: a `Z` parameter /
field store / `aput-boolean` is a boolean source (`bool_use_vids`), and the
move component of a re-typed version is re-typed whole or not at all.

Every case but the corpus ones runs on the committed
`tests/data/typed-positions.dex`, assembled from `typed-positions.smali`.
"""

import re
from pathlib import Path

import pytest
from conftest import require_corpus_shape

import dexllm

DATA = Path(__file__).resolve().parent / "data"
FIXTURE = DATA / "typed-positions.dex"
CLS = "LTypedPositions;"
ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture(scope="module")
def fx():
    return dexllm.DexKit(str(FIXTURE))


def _desc(fx, name):
    hits = [m for m in fx.list_class_methods(CLS) if f"->{name}(" in m]
    assert len(hits) == 1, (name, hits)
    return hits[0]


def _lines(text):
    # the `\n`-only contract (dexllm#83): never splitlines()
    return [ln.strip() for ln in text.split("\n")]


# The line that carries each decision, pinned.
EXPECTED = {
    # invocation context
    "argTrue": "TypedPositions.takeZ(true);",
    "argFalse": "TypedPositions.takeZ(false);",
    "argNull": "TypedPositions.takeRef(null);",
    "argNullStr": "TypedPositions.takeStr(null);",
    # `append(125)` resolves to append(int): the cast is what selects append(C)
    "argChar": "return p1.append(((char) 125)).toString();",
    "argByte": "TypedPositions.takeB(((byte) -1));",
    "argShort": "TypedPositions.takeS(((short) 500));",
    "ctorArgs": "return new TypedPositions(true, null);",
    # one register, two declared types in ONE call: the node is SHARED (an
    # IRForm keys constants by value), so the type is the position's, not the
    # node's
    "mixed": "TypedPositions.takeZI(true, 1);",
    # assignment context
    "fieldTrue": "this.iZ = true;",
    "staticFalse": "TypedPositions.sZ = false;",
    "fieldNull": "this.iRef = null;",
    "staticNull": "TypedPositions.sRef = null;",
    "aputTrue": "p2[0] = true;",
    "aputNull": "p2[1] = null;",
    "throwNull": "throw null;",
    "checkCastNull": "TypedPositions.takeVoids(((Void[]) null));",
    "retTrue": "return true;",
    "retNull": "return null;",
    # NEGATIVES: an int position keeps the integer, and a char ASSIGNMENT
    # narrows a constant implicitly in Java, so it takes no cast
    "argInt": "TypedPositions.takeI(1);",
    "fieldInt": "this.iI = 0;",
    "fieldChar": "this.iC = 120;",
    "retChar": "return 121;",
    # values Java cannot spell at that position stay the integer: ART checks
    # only the CATEGORY at a boolean parameter, and accepts nothing but its
    # Zero constant at a reference one (so `1` there is a dex no VM loads)
    "argTwoAtZ": "TypedPositions.takeZ(2);",
    "argOneAtRef": "TypedPositions.takeRef(1);",
    # a narrowing cast would CHANGE the value the callee receives (`(byte) 200`
    # is -56), and ART checks only the category there: the integer stays
    "argByteOut": "TypedPositions.takeB(200);",
    "argShortOut": "TypedPositions.takeS(40000);",
    "argCharNeg": "return p1.append(-1).toString();",
}


@pytest.mark.parametrize("name", sorted(EXPECTED))
def test_the_position_decides_the_literal(fx, name):
    text = fx.decompile_method(_desc(fx, name))
    assert EXPECTED[name] in _lines(text), text


def _ast_args(node, out):
    """Every literal (or cast literal) argument / stored value in an AST."""
    if isinstance(node, dict):
        for v in node.values():
            _ast_args(v, out)
        return
    if not isinstance(node, list):
        return
    if node and node[0] == "Literal":
        out.append((node[2][0], node[1]))
    if (
        node
        and node[0] == "Cast"
        and isinstance(node[1][1], list)
        and node[1][1][0] == "Literal"
    ):
        out.append(("cast" + node[1][0][1][0], node[1][1][1]))
    for c in node:
        _ast_args(c, out)


# What the AST must carry for each positive: its OWN node kinds, which the
# text path does not produce (a text match alone cannot see the AST).
AST_EXPECTED = {
    "argTrue": (".boolean", "true"),
    "argFalse": (".boolean", "false"),
    "argNull": (".null", "null"),
    "argChar": ("cast.char", "125"),
    "argByte": ("cast.byte", "-1"),
    "argShort": ("cast.short", "500"),
    "fieldTrue": (".boolean", "true"),
    "staticNull": (".null", "null"),
    "aputTrue": (".boolean", "true"),
    "aputNull": (".null", "null"),
    "throwNull": (".null", "null"),
    "checkCastNull": (".null", "null"),
}


@pytest.mark.parametrize("name", sorted(AST_EXPECTED))
def test_the_ast_carries_the_same_literal(fx, name):
    a = fx.decompile_method_ast(_desc(fx, name), include_source=False)
    lits = []
    _ast_args(a["ast"]["body"], lits)
    assert AST_EXPECTED[name] in lits, lits
    # and the integer it replaces is gone (a cast keeps its integer INSIDE)
    kind, val = AST_EXPECTED[name]
    if not kind.startswith("cast"):
        raw = {"true": "1", "false": "0", "null": "0"}[val]
        assert (".int", raw) not in lits, lits


def test_the_ast_keeps_the_integer_at_an_int_position(fx):
    a = fx.decompile_method_ast(_desc(fx, "mixed"), include_source=False)
    lits = []
    _ast_args(a["ast"]["body"], lits)
    assert (".boolean", "true") in lits and (".int", "1") in lits, lits


# ---- the VARIABLE half --------------------------------------------------


@pytest.mark.parametrize("name", ["varZ", "varField", "varAput"])
def test_a_flag_at_a_boolean_position_is_declared_boolean(fx, name):
    text = fx.decompile_method(_desc(fx, name))
    assert re.search(r"^boolean v\d", "\n".join(_lines(text)), re.M), text
    assert not re.search(r"^int v\d", "\n".join(_lines(text)), re.M), text


def test_numeric_uses_only_a_constant_reaches_do_not_refuse_the_flag(fx):
    """AdapterHelper.onItemRangeInserted: `v0` is compared and passed at an int
    parameter, but the constant `1` is the only value reaching those uses, so
    RegisterPropagation renders the literal there; the version itself is the
    flag the `Z` method returns. A per-VERSION guard refused it (652 corpus
    `boolean` methods returning an `int` local, 220 after)."""
    text = fx.decompile_method(_desc(fx, "loneConstUses"))
    lines = _lines(text)
    assert "boolean v0 = true;" in lines, text
    assert "TypedPositions.takeI(1);" in lines, text
    assert "if (p3 >= 1) {" in lines, text


def test_both_ends_of_a_move_end_boolean(fx):
    """CoordinatorLayout.offsetChildToAnchor: re-typing only the source of a
    move printed `int v0_5 = v14` beside `boolean v14`."""
    text = fx.decompile_method(_desc(fx, "forwardMove"))
    assert not re.search(r"\bint v\d", text), text
    assert re.search(r"\bboolean v\d", text), text


def test_a_component_with_an_int_member_is_left_whole(fx):
    """int-reuse.dex `sharedConst` / SwitchCompat.stopDrag: the flag's source is
    ALSO moved into an int index, so typing any part of the component boolean
    leaves `boolean`/`int` across a move."""
    text = fx.decompile_method(_desc(fx, "componentRefused"))
    assert "boolean v" not in text, text
    assert "v2 = v0;" in _lines(text), text


def test_a_mixed_width_move_does_not_keep_a_stale_float(fx):
    """Tx3gDecoder.decodeInitializationData: a destination SplitVariables typed
    from a register's LAST write (`int-to-float`) is corrected by #94's move
    width rule when its sources are ints. With one source now `Z`, an exact
    type comparison refused `{I, Z}` and the destination stayed `float`."""
    text = fx.decompile_method(_desc(fx, "mixedWidthSources"))
    assert "float v" not in text, text
    assert "0f" not in text and "e-45f" not in text, text
    # ... and the joined `I` must not stop there: the destination is stored
    # into a boolean field, every def is 0/1, and nothing after the width rule
    # refines it, so `int v3_0` here was `this.iZ = <int>` (review finding)
    assert "boolean v3_0;" in _lines(text), text
    assert "int v3_0;" not in _lines(text), text


def test_a_long_flag_chain_is_typed_whole(fx):
    """200 flag moves, each passed at a `Z` parameter: ONE move component.
    Deciding it per seed re-walked it per member and spent the work budget
    part-way, so the chain came out half `boolean` and half `int` (review
    finding, `boolean v5 = v4` beside `int v4`). Typed whole or not at all."""
    text = fx.decompile_method(_desc(fx, "flagChain"))
    decls = re.findall(r"^\s*(?!return\b)(\w+) v\d+(?:_\d+)? *(?:=|;)", text, re.M)
    assert decls and set(decls) == {"boolean"}, sorted(set(decls))


# ---- the two views ------------------------------------------------------


_STR = re.compile(r'"(?:\\.|[^"\\])*"')


def _text_counts(t):
    t = _STR.sub('""', t)
    body = t[t.index("{") :]
    c = {w: len(re.findall(rf"\b{w}\b", body)) for w in ("true", "false", "null")}
    for k in ("char", "byte", "short"):
        c["cast." + k] = len(re.findall(rf"\(\({k}\) -?\d+\)", body))
    return c


def test_text_and_ast_agree_on_every_method(fx):
    checked = 0
    for m in fx.list_class_methods(CLS):
        a = fx.decompile_method_ast(m)
        if not a.get("ast"):
            continue
        lits = []
        _ast_args(a["ast"], lits)
        ast_c = {
            "true": lits.count((".boolean", "true")),
            "false": lits.count((".boolean", "false")),
            "null": lits.count((".null", "null")),
        }
        for k in ("char", "byte", "short"):
            ast_c["cast." + k] = sum(1 for x in lits if x[0] == "cast." + k)
        assert _text_counts(a["source"]) == ast_c, (m, a["source"], lits)
        checked += 1
    assert checked >= 30


# ---- HG3: an oracle that never reads the IR ------------------------------

_INS = re.compile(r"^\s+0x([0-9a-f]+): (\S+)(?: (.*))?$")


def _params(proto):
    p = proto[proto.index("(") + 1 : proto.index(")")]
    out, i = [], 0
    while i < len(p):
        j = i
        while p[j] == "[":
            j += 1
        if p[j] == "L":
            j = p.index(";", j)
        out.append(p[i : j + 1])
        i = j + 1
    return out


def _smali_expectations(smali):
    """(kind, value) for every invoke argument / field store whose register
    the IMMEDIATELY preceding instruction loaded with a `const` -- read off the
    smali listing and the callee/field DESCRIPTOR, nothing else."""
    rows = [m.groups() for m in map(_INS.match, smali.split("\n")) if m]
    # a branch target is a join: the preceding `const` is then not the only
    # value that reaches the instruction
    targets = {
        int(off, 16) + 2 * int(ops.rsplit(" ", 1)[-1].replace("+", ""))
        for off, op, ops in rows
        if op.startswith(("if-", "goto"))
    }
    ins = [(op, ops or "") for _off, op, ops in rows]
    offs = [int(off, 16) for off, _op, _ops in rows]
    exp = []
    for i, (op, ops) in enumerate(ins):
        if i == 0 or ins[i - 1][0] not in ("const/4", "const/16"):
            continue
        if offs[i] in targets:
            continue
        reg, val = ins[i - 1][1].split(", #")
        val = int(val)
        if op.startswith("invoke-static"):
            regs = [r.strip() for r in ops[1 : ops.index("}")].split(",")]
            meth = ops.split("}, ")[1]
            for r, t in zip(regs, _params(meth[meth.index("(") :])):
                if r == reg:
                    exp.append((t, val))
        elif op.startswith(("iput", "sput")) and ops.split(",")[0] == reg:
            exp.append((ops.split(":")[-1], val))
    return exp


def test_the_smali_oracle_agrees_with_the_ast(fx):
    """Every (position type, value) the smali states must surface in the AST as
    the literal Java needs there: Z -> boolean, reference -> null (only for
    0), B/S -> a cast; an int position keeps the integer."""
    seen = 0
    for m in fx.list_class_methods(CLS):
        exp = _smali_expectations(fx.render_method_smali(m))
        if not exp:
            continue
        a = fx.decompile_method_ast(m, include_source=False)
        lits = []
        _ast_args(a["ast"]["body"], lits)
        for t, v in exp:
            if t == "Z" and v in (0, 1):
                want = (".boolean", "true" if v else "false")
            elif t[0] in "L[" and v == 0:
                want = (".null", "null")
            elif (t, -128 <= v <= 127) == ("B", True) or (
                t,
                -32768 <= v <= 32767,
            ) == ("S", True):
                # a cast only where it does not change the value
                want = ("cast" + {"B": ".byte", "S": ".short"}[t], str(v))
            else:
                want = (".int", str(v))
            assert want in lits, (m, t, v, lits)
            seen += 1
    assert seen >= 15


# ---- the encoded_value case: a call-site argument states its own type -----


def _craft_bsm_zero(tmp_path):
    """`bsmWithIntAndStringArray(…, 103, 104)` in invoke-custom.dex passes the
    encoded INT 104 at the `String...` vararg. Set it to 0: an encoded INT 0 is
    the integer 0 whatever parameter it lands at -- `null` would be invented."""
    b = bytearray((DATA / "invoke-custom.dex").read_bytes())
    at = bytes(b).find(b"\x04\x67\x04\x68")
    assert at > 0 and bytes(b).count(b"\x04\x67\x04\x68") == 1
    b[at + 3] = 0
    p = tmp_path / "bsm-zero.dex"
    p.write_bytes(bytes(b))
    return p


def test_an_encoded_call_site_int_is_never_nulled(tmp_path):
    p = _craft_bsm_zero(tmp_path)
    assert dexllm.verify(str(p))[0]["valid"]
    text = dexllm.DexKit(str(p)).decompile_class("LTestVariableArityLinkerMethod;")
    line = next(ln for ln in _lines(text) if '"methodO"' in ln)
    assert line.endswith("103, 0).dynamicInvoker().invoke() /* invoke-custom */;"), line


# ---- HG5: one definition --------------------------------------------------


def test_both_emitters_read_the_one_definition():
    """The projection is `ConstantAt`; a second spelling drifts (dexllm#63,
    #70, #83). Neither emitter may re-derive it."""
    from test_arg_opcode_coverage import _strip_comments

    for f, helper in (
        ("native/dad_cpp/writer.cpp", "emit_const_at"),
        ("native/dad_cpp/dast.cpp", "visit_const_at"),
    ):
        src = _strip_comments((ROOT / f).read_text())
        assert "ConstantAt(" in src, f
        for gone in ("emit_fp_const_typed", "visit_expr_fp_typed", "is_int_const"):
            assert gone not in src, (f, gone)
        assert src.count(helper + "(") >= 8, (f, src.count(helper + "("))


# ---- the corpus ----------------------------------------------------------


def _bad_literals(node, bad):
    """An integer literal the AST still places at a boolean / reference / B-S-C
    parameter of an invocation, or a boolean / reference field store."""
    if isinstance(node, dict):
        for v in node.values():
            _bad_literals(v, bad)
        return
    if not isinstance(node, list):
        return
    if node and node[0] in ("MethodInvocation", "ClassInstanceCreation"):
        if node[0] == "MethodInvocation":
            args, tr = node[1], node[2]
            params = args[1:] if node[4] else args
        else:
            tr, params = node[1], node[2]
        try:
            pts = _params(tr[2])
        except (ValueError, TypeError, IndexError):
            pts = []
        for p, t in zip(params, pts):
            if (
                isinstance(p, list)
                and p[:1] == ["Literal"]
                and p[2][0] == ".int"
                and (t in ("Z", "B", "S", "C") or (t[0] in "L[" and p[1] == "0"))
                and not (t == "Z" and p[1] not in ("0", "1"))
            ):
                bad.append((tr, t, p[1]))
    if node and node[0] == "Assignment":
        lhs, rhs = node[1][0], node[1][1]
        if (
            isinstance(lhs, list)
            and lhs[:1] == ["FieldAccess"]
            and isinstance(rhs, list)
            and rhs[:1] == ["Literal"]
            and rhs[2][0] == ".int"
        ):
            ft = lhs[2][2]
            if (ft == "Z" and rhs[1] in ("0", "1")) or (
                ft[0] in "L[" and rhs[1] == "0"
            ):
                bad.append((lhs[2], ft, rhs[1]))
    for c in node:
        _bad_literals(c, bad)


def test_no_corpus_constant_is_left_untyped_at_a_declared_position(loadable_apks):
    checked = 0
    bad = []
    for apk in loadable_apks[:6]:
        dk = dexllm.DexKit(str(apk))
        for c in sorted(set(dk.list_classes()))[:400]:
            for m in dk.list_class_methods(c):
                try:
                    a = dk.decompile_method_ast(m, include_source=False)
                except Exception:
                    continue
                if not a or not a.get("ast"):
                    continue
                checked += 1
                _bad_literals(a["ast"]["body"], bad)
    require_corpus_shape(
        checked > 1000,
        "corpus methods to scan",
        "the scan exercised too few methods to say anything",
    )
    assert not bad, bad[:10]


def test_a_surviving_move_destination_is_typed_with_its_source(fx):
    """The destination `v0` survives RegisterPropagation (its source register
    is reused before the use), so only the FORWARD half of the move-component
    propagation can make it boolean; without it the line is `int v0 = v1_0`
    beside `boolean v1_0`."""
    text = fx.decompile_method(_desc(fx, "forwardKeep"))
    assert "boolean v0 = v1_0;" in _lines(text), text
    assert not re.search(r"\bint v\d", text), text


def test_an_equality_use_only_a_constant_reaches_does_not_refuse(fx):
    """`v == 5` makes `v` a number, but only the constant `1` reaches that use,
    so it renders `1 == 5`; the eqne post-pass must record the POSITION or the
    version-level guard refuses the returned flag."""
    text = fx.decompile_method(_desc(fx, "eqneLone"))
    assert "boolean v0 = true;" in _lines(text), text


def test_the_unreachable_halves_are_pinned_in_the_source():
    """Two lines no dex can reach, pinned at SOURCE level (weaker than a
    behavioural guard -- it cannot see a line that is present and wrong):

    * a numeric use recorded WITHOUT a position refuses (`return !any`). Every
      insert into the three numeric-use sets records one today, so the branch
      is defence for the next insert that forgets to;
    * a `ThisParam` lhs keeps the Operand context: `this = 0` is the
      pre-existing DAD this-slot corruption, kept rather than turned into
      `this = null` (the rule the pre-#102 Writer already applied).
    """
    from test_arg_opcode_coverage import _strip_comments

    df = " ".join(
        _strip_comments((ROOT / "native/dad_cpp/dataflow.cpp").read_text()).split()
    )
    assert "return true; } return !any; };" in df
    wr = " ".join(
        _strip_comments((ROOT / "native/dad_cpp/writer.cpp").read_text()).split()
    )
    assert (
        "(lhs && !dynamic_cast<ThisParam*>(lhs)) ? ConstContext::Value : ConstContext::Operand"
        in wr
    )
    da = " ".join(
        _strip_comments((ROOT / "native/dad_cpp/dast.cpp").read_text()).split()
    )
    assert "const bool local = lhs && !dynamic_cast<ThisParam*>(lhs);" in da


# ---- review findings: each of these guards a line no other case reached ----


def _decls(text):
    return dict(
        (v, t)
        for t, v in re.findall(
            r"^\s*(?!return\b)(\w+) (v\d+(?:_\d+)?) *(?:=|;)", text, re.M
        )
    )


def test_a_component_member_used_as_a_number_refuses_the_whole_component(fx):
    """`v0` is a flag at a `Z` parameter, moved into `v1`, which is
    incremented. Checking only the seed's own uses would make `v0` boolean and
    leave `int v1_0 = v0` (an adversarial reviewer's mutant passed every other
    case). The component is left int, whole."""
    d = _decls(fx.decompile_method(_desc(fx, "compNum")))
    assert d.get("v0") == "int" and d.get("v1_0") == "int", d


def test_a_static_boolean_field_store_is_a_boolean_source(fx):
    """`sput-boolean` seeds on its own; `varField` covers only `iput`."""
    text = fx.decompile_method(_desc(fx, "sputSeed"))
    assert "boolean v0 = false;" in _lines(text), text
    assert "TypedPositions.sZ = v0;" in _lines(text), text


def test_a_width_joined_destination_with_a_real_int_source_stays_int(fx):
    """The `{I, Z}` join becomes `Z` only when every source flowing into the
    destination is already `Z` or renders as its literal. Here the source
    `v4` is a real int (incremented), so `boolean v3 = v4` must not appear."""
    d = _decls(fx.decompile_method(_desc(fx, "mixedWidthIntSource")))
    assert d.get("v4") == "int" and d.get("v3_1") == "int", d


def test_a_number_return_type_rules_out_boolean(fx):
    """A flag at a `Z` parameter that is also RETURNED from an `int` method
    stays int: a number return is a numeric position (#94's `z_pos` says the
    same), so `boolean v0 … return v0;` cannot appear."""
    text = fx.decompile_method(_desc(fx, "zThenIntReturn"))
    assert _decls(text).get("v0") == "int", text
