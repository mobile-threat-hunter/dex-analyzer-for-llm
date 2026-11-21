"""dexllm#129 — an anonymous class is written where it is constructed.

`decompile_method` / `decompile_class` render `new Outer$1(this, v)` of an
anonymous class constructed at exactly one site as `new Base(super_args) {
body }`, with `this.this$0` read as `Outer.this` and `this.val$x` as the value
the site passed. Whatever would make that rendering assert something the
bytecode does not say leaves the class as it was (constructed by name, with
its own `decompile_class`). The AST is unchanged (user decision): it keeps the
`ClassInstanceCreation` of the anonymous class.

Fixtures: ``anon-classes.dex`` (authored Java, see its source) and
``anon-sites.dex`` (smali, for the shapes Java cannot write).
"""

import re
from pathlib import Path

import pytest
from conftest import (
    fold_inline_anonymous,
    inline_anonymous_blocks,
    require_corpus_shape,
)

import dexllm

DATA = Path(__file__).parent / "data"
JAVA = DATA / "anon-classes.dex"
SMALI = DATA / "anon-sites.dex"


def _session(path):
    return dexllm.DexKit(str(path))


def _method_text(text, header):
    """The method chunk of a class text that starts at line ``header``."""
    lines = text.split("\n")
    i = lines.index(header)
    j = i + 1
    while j < len(lines) and lines[j] != "}":
        j += 1
    return "\n".join(lines[i : j + 1])


# ─── what is inlined, pinned as written ─────────────────────────────────────
INLINED = {
    # the outer instance and a parameter
    "public Runnable capture(int p2)": [
        "    return new Runnable() {",
        "            int v1 = p2;",
        "            if (ac.Anon.this.count > v1) {",
        "                ac.Anon.this.count = v1;",
        "    };",
    ],
    # superclass constructor arguments (constants), and a captured parameter
    "public ac.Anon.Base withSuper(int p4)": [
        '    return new ac.Anon.Base("t", 7) {',
        "            return (this.tag.length() + p4);",
    ],
    # a framework superclass whose constructor takes an argument
    "public static Thread thread(String p1)": [
        "    return new Thread(p1) {",
        "            this.setPriority(1);",
    ],
    # a statement: the constructed object is used, not returned
    "public void discard(int p2)": [
        "    new Thread() {",
        "            System.out.println(p2);",
        "    }.start();",
    ],
    "static Runnable make()": ["    return new Runnable() {"],
    # a static method's parameter
    "public static Runnable print(String p1)": [
        "    return new Runnable() {",
        "            System.out.println(p1);",
    ],
    # a wide captured value is one parameter, two registers
    "public Runnable wide(long p2, int p4)": [
        "            ac.Anon.this.count = ((int) (p2 + ((long) p4)));",
    ],
    # the inner class captures an anonymous outer instance, which no
    # `X.this` can name: the outer is inlined, the inner is not
    # a supplementary-plane identifier inside an inlined body
    "public static Runnable astral()": [
        "    return new Runnable() {",
        "            System.out.println(ac.Anon.\U00010000);",
    ],
    # the superclass constructor's own parameter type: `new Over(s)` with a
    # String would bind Over(String), the bytecode calls Over(Object)
    "public ac.Anon.Over overload(String p2)": [
        "    return new ac.Anon.Over(((Object) p2)) {",
    ],
    # a local holding the object is declared with the type the text names
    "public Runnable kept(int p2)": [
        "    Runnable v0_1 = new Runnable() {",
        "            System.out.println(p2);",
    ],
    # a parameter SplitVariables gives a version name: the body names it
    # by its register, as the site does (`p3`, never `p3_0`)
    "public Runnable reassign(int p3)": [
        "            System.out.println(p3);",
        "    System.out.println((p3 + 5));",
    ],
    "public Runnable nested(String p2)": [
        "    return new Runnable() {",
        "            new ac.Anon$9$1(this).run();",
    ],
}

NOT_INLINED = {
    # the body's own parameter `p1` would shadow the captured `p1`
    "public static java.util.Comparator byLength(boolean p1)": "    return new ac.Anon$2(p1);",
    # the constructor runs a field initializer
    "public static Object withInit()": "    return new ac.Anon$8();",
    # the base is a local class, which no source outside its method names
    "public Object localBase()": "    return new ac.Anon$11(this);",
    # the captured value is a call folded into the argument
    "public Runnable folded()": "    return new ac.Anon$12(this, String.valueOf(this.count));",
    # a member class declared inside the anonymous body
    "public static Runnable memberInside()": "    return new ac.Anon$13();",
    # the captured loop register is written again below the construction
    "public java.util.List loop(int p4)": "        v0_1.add(new ac.Anon$15(this, v1));",
}


@pytest.mark.parametrize("header", sorted(INLINED))
def test_an_anonymous_class_is_written_at_its_site(header):
    text = _session(JAVA).decompile_class("Lac/Anon;")
    method = _method_text(text, header).split("\n")
    for line in INLINED[header]:
        assert line in method, (header, line)
    assert not re.search(r"new ac\.Anon\$\d+\(", "\n".join(method[:2]))


@pytest.mark.parametrize("header", sorted(NOT_INLINED))
def test_a_class_that_cannot_be_written_inline_is_left_by_name(header):
    text = _session(JAVA).decompile_class("Lac/Anon;")
    assert NOT_INLINED[header] in _method_text(text, header).split("\n")


def test_no_captured_field_is_left_in_an_inlined_body():
    text = _session(JAVA).decompile_class("Lac/Anon;")
    lines = text.split("\n")
    for i, j in inline_anonymous_blocks(text):
        body = "\n".join(lines[i : j + 1])
        assert "this$0" not in body and "val$" not in body, body


def test_an_anonymous_class_in_a_member_keeps_its_spelling_when_not_inlined():
    lines = _session(JAVA).decompile_class("Lac/Anon;").split("\n")
    assert "        return new ac.Anon.Holder$1();" in lines


def test_an_enum_constant_body_is_not_inlined():
    text = _session(JAVA).decompile_class("Lac/Anon$Op;")
    assert '    ac.Anon.Op.PLUS = new ac.Anon.Op$1("PLUS", 0);' in text.split("\n")


# ─── the smali fixture: shapes Java cannot write ────────────────────────────
SMALI_CASES = {
    "public static Runnable a()": "    return new sm.Two$1();",  # two sites
    "public static Runnable b()": "    return new sm.Two$1();",
    "public static Runnable d(String p1)": "    return new sm.Two$3(p1);",  # field `p1`
    "public static Runnable e(String p1)": "    return new sm.Two$4(p1);",  # writes it
    "public static Runnable g()": "    return new sm.Two$7();",  # flagged enum
    "public static Object h()": "    return new sm.Two$8();",  # local-class base
    # stores into another instance's field
    "public static Runnable i(sm.Two$9 p1, String p2)": "    return new sm.Two$9(p1, p2);",
    "public static Runnable j()": "    return new sm.Two$10();",  # instance initializer
    "public static Runnable k()": "    return new sm.Two$11();",  # calls a non-super <init>
    "public static Runnable m(String p1)": "    return new sm.Two$13(p1);",  # one param, two fields
    "public static Runnable n(String p1)": "    return new sm.Two$14(p1);",  # read via another object
    "public static Runnable o()": "    return new sm.Two$15();",  # EnclosingMethod is a()
    "public static Runnable q()": "    return new sm.Two$16();",  # super called twice
    "public static Runnable r(sm.Two$17 p1)": "    return new sm.Two$17(p1);",  # super on another object
    "public static Object t(String p1, String p2)": "    return new sm.Two$18(p1, p2);",  # reversed
    "public static Runnable t2(int p1)": "    return new sm.Two$19(p1);",  # two constructors
    "public static Runnable x(String p1)": "    return new sm.Two$22(p1);",  # field not final
    "public static Runnable y()": "    return new sm.Two$23();",  # returns before super()
    "public static Object z(String p1)": "    return new sm.Two$24(p1);",  # base declares `p1`
    "public static Runnable zz()": "    return new sm.Two$25();",  # run() does not decompile
    # the captured parameter is written again on the loop's back edge
    "public static Runnable w(String p1)": "        Runnable v0_1 = new sm.Two$21(p1);",
    "public static Runnable u()": "    return new sm.Two$20(v0);",  # catch variable shadows
    "public static Runnable u2()": "    return new sm.Two$26(v0);",  # a body local shadows
    # the site still needs the class's own name: once inlined it has none
    "public static int k1()": "    return new sm.Two$27().label;",  # its own field
    "public static void k2()": "    new sm.Two$28().extra();",  # its own method
    "public static Object k3(Object p1)": "        return new sm.Two$29();",  # instanceof
    "public static Object k4()": "    return new sm.Two$30();",  # a field of its type
}


def test_a_class_enclosing_itself_is_not_written_inside_itself():
    text = _session(SMALI).decompile_class("Lsm/Two$6;")
    assert "    new sm.Two$6().run();" in text.split("\n")


def test_the_smali_fixture_verifies():
    assert all(r["valid"] for r in dexllm.verify(str(SMALI)))


@pytest.mark.parametrize("header", sorted(SMALI_CASES))
def test_a_smali_shape_is_left_by_name(header):
    text = _session(SMALI).decompile_class("Lsm/Two;")
    assert SMALI_CASES[header] in _method_text(text, header).split("\n")


@pytest.mark.parametrize(
    "header, line",
    [
        ("public static Runnable c()", "    return new Runnable() {"),
        ("public static Runnable f(String p1)", "            System.out.println(p1);"),
        # two levels: an anonymous class in an inlined one, nothing captured
        ("public static Runnable l()", "            new Runnable() {"),
        # an INHERITED method called through the class's own type
        ("public static String k5()", "    return new Runnable() {"),
        # a String constant passed where the superclass takes Object
        ("public static Object k6()", '    return new sm.Over(((Object) "s")) {'),
    ],
)
def test_the_smali_controls_are_inlined(header, line):
    text = _session(SMALI).decompile_class("Lsm/Two;")
    assert line in _method_text(text, header).split("\n")


# ─── the views ──────────────────────────────────────────────────────────────
def test_decompile_method_and_decompile_class_agree():
    dk = _session(JAVA)
    text = dk.decompile_class("Lac/Anon;")
    for desc in dk.list_class_methods("Lac/Anon;"):
        assert dk.decompile_method(desc) in text, desc


def test_the_anonymous_class_still_renders_on_its_own():
    text = _session(JAVA).decompile_class("Lac/Anon$1;")
    assert " class Anon$1 implements java.lang.Runnable {" in text.split("\n")
    assert "    this.this$0 = p1;" in text.split("\n")


def test_the_ast_keeps_the_construction_and_its_source_inlines():
    dk = _session(JAVA)
    ast = dk.decompile_method_ast("Lac/Anon;->capture(I)Ljava/lang/Runnable;")
    ret = ast["ast"]["body"][2][0]
    assert ret[0] == "ReturnStatement" and ret[1][0] == "ClassInstanceCreation"
    assert ret[1][1] == ["ac/Anon$1", "<init>", "(Lac/Anon;I)V"]
    assert "new Runnable() {" in ast["source"]
    assert ast["source"] == dk.decompile_method(
        "Lac/Anon;->capture(I)Ljava/lang/Runnable;"
    )


def test_the_pc_map_still_names_real_lines():
    dk = _session(JAVA)
    desc = "Lac/Anon;->discard(I)V"
    r = dk.decompile_method_with_pc_map(desc)
    lines = r["source"].split("\n")
    assert r["source"] == dk.decompile_method(desc)
    starts = [ln for ln, _ in r["pc_map"]]
    # the statement opening the block, and the one after its body
    assert lines[starts[0] - 1].strip() == "new Thread() {"
    assert lines[starts[-1] - 1].strip() == "return;"
    # nothing inside the body is mapped: those offsets belong to run()
    body = range(starts[0] + 1, len(lines) - 3)
    assert not [ln for ln in starts[1:-1] if ln in body]


# ─── the body is the class's own text, with only the captures substituted ───
def _standalone_parts(text, simple):
    lines = text.split("\n")
    if lines[0].startswith("package "):
        lines = lines[1:]
    lines = lines[1:]
    while lines and lines[-1] == "":
        lines.pop()
    assert lines[-1] == "}"
    lines = lines[:-1]
    fields, methods, cur = [], [], None
    for line in lines:
        if cur is None and line.startswith("    "):
            fields.append(line)
        elif line == "":
            cur = []
            methods.append(cur)
        else:
            cur.append(line)
    ctor = [
        m for m in methods if re.match(r"^[\w ]*\b" + re.escape(simple) + r"\(", m[0])
    ]
    assert len(ctor) == 1
    caps = set(re.findall(r"^    this\.([\w$]+) = p\d+;$", "\n".join(ctor[0]), re.M))
    expected = [f for f in fields if not any(f.endswith(" " + c + ";") for c in caps)]
    for m in methods:
        if m is not ctor[0]:
            expected += [""] + m
    return "\n".join(expected), caps


def _body_matches(body, expected, caps):
    """``body`` equals ``expected`` with each ``this.<cap>`` replaced by one
    consistent token (the site's name for the value, or ``X.this``)."""
    marked = expected
    for n, cap in enumerate(sorted(caps, key=len, reverse=True)):
        marked = re.sub(
            r"this\." + re.escape(cap) + r"(?![\w$])", f"\x00{n}\x00", marked
        )
    rx, seen = "", set()
    for part in re.split(r"(\x00\d+\x00)", marked):
        m = re.fullmatch(r"\x00(\d+)\x00", part)
        if m:
            g = "g" + m.group(1)
            rx += f"(?P={g})" if g in seen else rf"(?P<{g}>[\w.$]+)"
            seen.add(g)
        else:
            rx += re.escape(part)
    m = re.fullmatch(rx, body)
    return m.groupdict() if m else None


def _check_bodies(dk, outer, anon_classes):
    """Every inlined body of ``outer`` is one of ``anon_classes`` rendered on
    its own, minus its constructor and captured fields, captures substituted.
    Returns the number checked."""
    expected = []
    for c in anon_classes:
        text = dk.decompile_class(c)
        if not text:
            continue
        try:
            expected.append(_standalone_parts(text, c[1:-1].rsplit("/", 1)[-1]))
        except AssertionError:
            continue
    text = dk.decompile_class(outer)
    lines = text.split("\n")
    checked = 0
    for i, j in inline_anonymous_blocks(text):
        indent = len(lines[i]) - len(lines[i].lstrip(" ")) + 4
        raw = "\n".join(
            line[indent:] if line.strip() else "" for line in lines[i + 1 : j]
        )
        body = fold_inline_anonymous(raw).rstrip("\n")
        # a block nested inside the body is the inner class's own text. The
        # enclosing method's lines before the block hold every name the site
        # has: its header parameters and its locals.
        start = i
        while start > 0 and (lines[start].startswith(" ") or lines[start] in ("{", "")):
            start -= 1
        outside = "\n".join(lines[start : i + 1])

        def visible(tokens):
            return all(
                tok.endswith(".this")
                or re.search(r"(?<![\w$])" + re.escape(tok) + r"(?![\w$])", outside)
                for tok in tokens.values()
            )

        assert any(
            (t := _body_matches(body, fold_inline_anonymous(e).rstrip("\n"), caps))
            is not None
            and visible(t)
            for e, caps in expected
        ), body
        checked += 1
    return checked


def test_every_fixture_body_is_the_class_rendered_on_its_own():
    dk = _session(JAVA)
    anon = [c for c in dk.list_classes() if re.search(r"\$\d+;$", c)]
    assert _check_bodies(dk, "Lac/Anon;", anon) == len(INLINED)


def test_corpus_bodies_are_the_classes_rendered_on_their_own(loadable_apks):
    checked = 0
    for path in loadable_apks:
        dk = dexllm.DexKit(path)
        anon = [c for c in dict.fromkeys(dk.list_classes()) if re.search(r"\$\d+;$", c)]
        outers = sorted({c[: c.rindex("$")] + ";" for c in anon})[:60]
        checked += sum(_check_bodies(dk, o, anon) for o in outers)
    require_corpus_shape(checked > 0, "inlined anonymous class", "nothing is inlined")
