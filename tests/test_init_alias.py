"""A copy of an uninitialized new-instance reads the constructed object (dexllm#121).

`new-instance vA` makes an UNINITIALIZED reference and `invoke-direct <init>`
initializes that same object in place, so after the constructor every copy of
vA refers to it. DAD models the constructor as a fresh definition of the
receiver alone (`vA = vA.<init>(...)`), which left a copy taken before the
constructor reading the pre-construction definition: the allocation then had
two uses, RegisterPropagation could not fold `new X` into its <init>, and the
Writer rendered `X v = new X;` followed by `v(args);` -- invalid Java.

The fix is a pass at the IR builder's output (`HoistUninitializedCopies`,
dataflow.cpp) that hoists each such copy past the <init> within one block, and
when the <init> runs on a COPY (d8's /range form) retargets the allocation to
that copy. The fixture is authored smali (`tests/data/init-alias.smali`).
"""

from __future__ import annotations

import pathlib
import re

import pytest
from conftest import require_corpus_shape

import dexllm

DATA = pathlib.Path(__file__).parent / "data"
FIXTURE = DATA / "init-alias.dex"
CLS = "LAlias;"

# member -> the method body's statements, exactly
FIXED = {
    "oneCopy()V": [
        'Alias v1_1 = new Alias("A", 0);',
        "Alias v0_0 = v1_1;",
        "Alias.A = v1_1;",
        "Alias.V = new Alias[] {v0_0};",
        "return;",
    ],
    "copyOnly()LAlias;": ['return new Alias("A", 0);'],
    # d8's /range shape: the <init> receiver is the copy, the original is
    # stored and returned afterwards
    "recvIsCopy()LAlias;": [
        'Alias v3_1 = new Alias("A", 0);',
        "Alias.A = v3_1;",
        "return v3_1;",
    ],
    # a copy of a copy; the receiver is the second one
    "chain()LAlias;": [
        'Alias v4_1 = new Alias("A", 0);',
        "Alias.A = v4_1;",
        "return v4_1;",
    ],
    # the receiver's register holds an argument BEFORE it becomes the copy
    # (androidx AlertController$AlertParams.createListView): the allocation must
    # land where the copy was, not where the new-instance was
    "recvReused(Ljava/lang/String;)LAlias;": ["return new Alias(p4, 0);"],
    # the copy survives as its own statement and its register is later an int
    "copyLaterInt()V": [
        'Alias v1_1 = new Alias("A", 0);',
        "Alias v0_1 = v1_1;",
        "Alias.A = v1_1;",
        "Alias.V = new Alias[] {v0_1};",
        "Alias.A = v0_1;",
        "Alias.I = 5;",
        "return;",
    ],
    # the /range receiver is a scratch register that later holds a String
    # (a2dp.Vol service.DoDisconnected): the object's type must not follow it
    "recvLaterString()LAlias;": [
        'Alias v7_1 = new Alias("A", 0);',
        "Alias.A = v7_1;",
        'Alias.S = "zz";',
        "return v7_1;",
    ],
    # the /range receiver register is an int elsewhere and dead after the
    # <init>: its re-made copy must be dropped, or the int version takes the
    # object's type (kotlin FileTreeWalk, NotificationCompat$CarExtender)
    "deadRecv(ZLjava/lang/String;)Ljava/lang/Object;": [
        "if (p6) {",
        "Alias.sink(new Alias(p7, 0));",
        "return null;",
        "} else {",
        "int v2 = 0;",
        "if (p7 != null) {",
        "v2 = 1;",
        "}",
        "if (v2 == 0) {",
        "return p7;",
        "} else {",
        "return null;",
        "}",
        "}",
    ],
    # the same, with the receiver register written then read after the <init>
    "deadRecvKilled(ZLjava/lang/String;)Ljava/lang/Object;": [
        "if (p6) {",
        "Alias.sink(new Alias(p7, 0));",
        "Alias.I = 2;",
        "return null;",
        "} else {",
        "int v2 = 0;",
        "if (p7 != null) {",
        "v2 = 1;",
        "}",
        "if (v2 == 0) {",
        "return p7;",
        "} else {",
        "return null;",
        "}",
        "}",
    ],
    # ...and when it IS read later (in another block) the copy is kept
    "liveRecv(Z)Ljava/lang/Object;": [
        'Alias v0_1 = new Alias("A", 0);',
        "Alias v1_0 = v0_1;",
        "Alias.A = v0_1;",
        "if (!p4) {",
        "return null;",
        "} else {",
        "return v1_0;",
        "}",
    ],
    # the receiver register is written (an int) before it is read again: dead
    "recvKilled(Z)V": [
        'Alias.A = new Alias("A", 0);',
        "int v1 = 7;",
        "if (p4) {",
        "v1 = 6;",
        "}",
        "Alias.I = v1;",
        "return;",
    ],
    # read only by an exception handler of the next call: live, so kept
    "recvInHandler()Ljava/lang/Object;": [
        'Alias v0_1 = new Alias("A", 0);',
        "Alias v1 = v0_1;",
        "try {",
        "Alias.sink(v0_1);",
        "return null;",
        "} catch (RuntimeException v2) {",
        "return v1;",
        "}",
    ],
    # controls the pass never touches
    "noCopy()LAlias;": ['return new Alias("A", 0);'],
    "destKilled()Ljava/lang/Object;": [
        'Alias.A = new Alias("A", 0);',
        'return "B";',
    ],
}

# shapes the pass must REFUSE, pinned as rendered (each is either invalid
# Dalvik -- an uninitialized reference used as an argument or read -- or out of
# the pass's one-block scope); a change here means the pass fired where it must
# not, or the residual moved
REFUSED = {
    "aliasAsArg()LAlias;": [
        "Alias v1 = new Alias;",
        "Alias v0 = v1;",
        "v1(v0, 0);",
        "return v0;",
    ],
    "readBetween()LAlias;": [
        "Alias v1 = new Alias;",
        "Alias v0 = v1;",
        "Alias.sink(v0);",
        'v1("A", 0);',
        "return v0;",
    ],
    "plainMove()LAlias;": [
        "Alias v1 = new Alias;",
        "Alias v0 = v1;",
        'v1("A", 0);',
        "return v0;",
    ],
    "reuseThis()LAlias;": [
        "Alias v4 = new Alias;",
        "Alias v0 = v4;",
        'v4("A", 0);',
        "return v0;",
    ],
    "crossBlock(Z)LAlias;": [
        "int v3;",
        "Alias v1 = new Alias;",
        "Alias v0 = v1;",
        "if (!p4) {",
        "v3 = 0;",
        "} else {",
        "v3 = 1;",
        "}",
        'v1("A", v3);',
        "return v0;",
    ],
}

_CALL_ON_VAR = re.compile(r"\b[vp]\d+(?:_\d+)?\(")
_BARE_NEW = re.compile(r"= new [\w.$]+;$")


@pytest.fixture(scope="module")
def dk():
    return dexllm.DexKit(str(FIXTURE))


def _body(dk, member):
    text = dk.decompile_method(f"{CLS}->{member}")
    lines = [x.strip() for x in text.split("\n")]
    i = lines.index("{")
    return [x for x in lines[i + 1 : len(lines) - 1 - lines[::-1].index("}")] if x]


def test_the_fixture_verifies_and_declares_every_case(dk):
    [row] = dexllm.verify(str(FIXTURE))
    assert row["valid"] and row["art_open"], row
    declared = {m.split("->", 1)[1] for m in dk.list_class_methods(CLS)}
    assert set(FIXED) | set(REFUSED) <= declared


@pytest.mark.parametrize("member", sorted(FIXED))
def test_the_constructor_folds_into_its_allocation(dk, member):
    body = _body(dk, member)
    assert body == FIXED[member]
    assert not any(_CALL_ON_VAR.search(x) or _BARE_NEW.search(x) for x in body)


@pytest.mark.parametrize("member", sorted(REFUSED))
def test_an_unprovable_shape_is_left_alone(dk, member):
    assert _body(dk, member) == REFUSED[member]


def _init_calls(node, out):
    """Every MethodInvocation of <init> -- a constructor rendered as a call."""
    if isinstance(node, list):
        if node and node[0] == "MethodInvocation" and node[3] == "<init>":
            out.append(node)
        for x in node:
            _init_calls(x, out)
    return out


def _creations(node, out):
    if isinstance(node, list):
        if node and node[0] == "ClassInstanceCreation":
            out.append(node[1][0])
        for x in node:
            _creations(x, out)
    return out


@pytest.mark.parametrize("member", sorted(FIXED))
def test_the_ast_carries_the_constructed_object(dk, member):
    """The pass is upstream of both emitters, so the AST must agree: exactly one
    ClassInstanceCreation (with its arguments) and no <init> call on a local."""
    ast = dk.decompile_method_ast(f"{CLS}->{member}")["ast"]
    assert _creations(ast["body"], []) == ["Alias"], ast["body"]
    assert _init_calls(ast["body"], []) == []


def test_text_and_ast_agree_on_the_corpus_class(loadable_apks):
    """BlendModeCompat.<clinit> is the issue's own case: d8's enum pattern copies
    each constant before its constructor and stores the copy in $VALUES."""
    desc = "Landroidx/core/graphics/BlendModeCompat;-><clinit>()V"
    hits = []
    for apk in loadable_apks:
        dk = dexllm.DexKit(apk)
        if dk.locate_class_dex(desc.split("->")[0]) < 0:
            continue
        text = dk.decompile_method(desc)
        hits.append(apk)
        lines = [x.strip() for x in text.split("\n")]
        assert not any(_CALL_ON_VAR.search(x) or _BARE_NEW.search(x) for x in lines)
        assert any(
            x.startswith("androidx.core.graphics.BlendModeCompat v")
            and '= new androidx.core.graphics.BlendModeCompat("SRC", 1);' in x
            for x in lines
        ), text
        ast = dk.decompile_method_ast(desc)["ast"]
        assert _init_calls(ast["body"], []) == []
        n = len(_creations(ast["body"], []))
        assert n == sum(
            x.count("new androidx.core.graphics.BlendModeCompat(") for x in lines
        )
    require_corpus_shape(bool(hits), "BlendModeCompat.<clinit>", "dexllm#121")


def test_the_range_form_on_the_corpus(loadable_apks):
    """kotlin.text.RegexOption.<clinit>: `move-object v0, v7` then
    `invoke-direct/range {v0 .. v6} <init>` -- the receiver is the copy."""
    desc = "Lkotlin/text/RegexOption;-><clinit>()V"
    hits = []
    for apk in loadable_apks:
        dk = dexllm.DexKit(apk)
        if dk.locate_class_dex(desc.split("->")[0]) < 0:
            continue
        text = dk.decompile_method(desc)
        hits.append(apk)
        assert (
            'kotlin.text.RegexOption.IGNORE_CASE = new kotlin.text.RegexOption("IGNORE_CASE", 0,'
            in text
        ), text
        assert not any(_CALL_ON_VAR.search(x.strip()) for x in text.split("\n"))
    require_corpus_shape(bool(hits), "kotlin.text.RegexOption.<clinit>", "dexllm#121")


def test_a_hoisted_copy_keeps_its_own_bytecode_offset(dk):
    """D-3: the rebuilt `vD = vA` is a new IR node; its line must still map to
    the move-object it stands for (0x4), not to the <init> it now follows."""
    r = dk.decompile_method_with_pc_map(f"{CLS}->oneCopy()V")
    lines = r["source"].split("\n")
    pc = dict(r["pc_map"])
    copy_line = 1 + next(
        i for i, x in enumerate(lines) if x.strip() == "Alias v0_0 = v1_1;"
    )
    ctor_line = 1 + next(i for i, x in enumerate(lines) if "new Alias(" in x)
    assert pc[copy_line] == 0x4
    assert pc[ctor_line] == 0xC


def test_a_rebuilt_copy_does_not_retype_its_register(loadable_apks):
    """The rebuilt `vD = vA` is made after Construct, and MoveExpression's ctor
    applies DAD's last-write rule (lhs.set_type(rhs.get_type())) -- a write made
    then would be the LAST and win, retyping every other version of vD's
    register. MaterialCalendar.onCreateView is where that shows: the inflated
    View is copied into a register that also holds a GridView, and only keeping
    the type Construct left declares the copy `View`."""
    cls = "Lcom/google/android/material/datepicker/MaterialCalendar;"
    hits = []
    for apk in loadable_apks:
        dk = dexllm.DexKit(apk)
        if dk.locate_class_dex(cls) < 0:
            continue
        text = dk.decompile_class(cls)
        if "v8_1 = v15.inflate(v11_0, p22, false);" not in text:
            continue  # another build of the class
        hits.append(apk)
        lines = [x.strip() for x in text.split("\n")]
        assert "android.view.View v0_22 = v8_1;" in lines
        assert "android.widget.GridView v0_22 = v8_1;" not in lines
    require_corpus_shape(bool(hits), "MaterialCalendar.onCreateView", "dexllm#121")
