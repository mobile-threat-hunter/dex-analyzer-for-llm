"""dexllm#83 - one pool string renders ONE way inside a decompiled class.

`decompile_class` had TWO string-literal escapers and they disagreed:
`EscapeJavaString` for every literal in a method body, `PythonUnicodeEscape` for
the `0x17 STRING` arm that renders a `static final String` initializer. The same
value came out `\\x0b` in the declaration - not a Java escape at all - and
`\\u000b` two lines down in the body, with U+0085 / U+2028 / U+2029 escaped in
one and raw in the other.

Every case here runs on the COMMITTED `tests/data/literal-escapes.dex`, so they
hold in the corpus-less CI leg and under any `$DEXLLM_TEST_APK` narrowing. That
fixture exists because a fixture where the two escapers AGREE proves nothing:
its eleven values are one per branch of the rule, and each is BOTH a
`static final` constant (the encoded_value arm) and - because javac inlines a
compile-time constant at every read - a `const-string` inside `all()` (the
method-body arm). So one value reaches both renderers in one class.

Characters are written `chr(...)` rather than typed, so this file stays ASCII and
a control character cannot be lost to a copy.
"""

import pathlib
import re

import pytest
from conftest import require_corpus_shape

import dexllm

FIXTURE = pathlib.Path(__file__).resolve().parent / "data" / "literal-escapes.dex"
CLS = "LLiteralEscapes;"

NEL = chr(0x85)  # C1 NEXT LINE
DEL = chr(0x7F)  # DELETE - written raw, and 0 occurrences in the whole corpus
C1 = chr(0x9B)  # a C1 that is NOT U+0085 - likewise 0 in the corpus
LSEP = chr(0x2028)  # LINE SEPARATOR
PSEP = chr(0x2029)  # PARAGRAPH SEPARATOR
CJK = chr(0xC5F0) + chr(0xACB0)
ASTRAL = chr(0x1F600)

# A field declaration as `DvClass.get_source` writes it: class scope, indent 4,
# `<mods> <Type> <name> = <init>;`. Capturing the whole INITIALIZER rather than
# its contents matters - the issue's own predicate was `= "([^"]*)";`, which a
# value holding an escaped quote does not match, so it under-counted by 6.
FIELD = re.compile(
    r"^    (?:(?:public|private|protected|static|final|volatile|transient|synthetic) )*"
    r'\S+ (\w+) = (".*");$'
)
# `\x0b` - what `PythonUnicodeEscape` emitted for a control Java has no short
# escape for. Java's escape set is \b \t \n \f \r \" \' \\, octal \nnn, and
# \uXXXX. There is no \xNN, so a line carrying one does not compile.
NOT_JAVA = re.compile(r"\\x[0-9a-fA-F]{2}")

# The eleven values, PINNED as literals rather than derived from the oracle
# below: a guard parametrised over the oracle cannot catch an edit OF the oracle.
EXPECTED = {
    "VT": '"\\u000b"',
    "FF": '"\\u000c"',
    "NUL": '"\\u0000"',
    "TAB": '"a\\tb"',
    "NEL": '"' + NEL + '"',
    "DEL": '"a' + DEL + 'b"',
    "C1": '"a' + C1 + 'b"',
    "LSEP": '"' + LSEP + '"',
    "PSEP": '"' + PSEP + '"',
    "QUOTE": '"a\\"b"',
    "APOS": '"a\\\'b"',
    "BACKSLASH": '"a\\\\b"',
    "CJK": '"' + CJK + '"',
    "ASTRAL": '"\\ud83d\\ude00"',
    "EMPTY": '""',
    "MIXED": '"\\n\\u000b\\u000c\\r' + NEL + LSEP + PSEP + '"',
}

# The same eleven as VALUES, for the accessor axis.
VALUES = [
    chr(0x0B),
    chr(0x0C),
    chr(0x00),
    "a\tb",
    NEL,
    "a" + DEL + "b",
    "a" + C1 + "b",
    LSEP,
    PSEP,
    'a"b',
    "a'b",
    "a\\b",
    CJK,
    ASTRAL,
    "",
    "\n" + chr(0x0B) + chr(0x0C) + "\r" + NEL + LSEP + PSEP,
]


def java_literal(value):
    """What `EscapeJavaString` must produce for `value`, from the DOCUMENTED rule.

    An INDEPENDENT oracle: the input comes from `list_class_strings` (the string
    accessor, a different code path from either renderer) and the rule is applied
    here rather than read out of the C++ - decode to the same UTF-16 code units
    ART builds in a `mirror::String`, escape the Java metacharacters, then a unit
    below 0x20 or in the surrogate range becomes `\\uXXXX` and everything else is
    written readably.
    """
    units = value.encode("utf-16-le", "surrogatepass")
    out = ['"']
    for i in range(0, len(units), 2):
        u = units[i] | (units[i + 1] << 8)
        short = {
            0x5C: "\\\\",
            0x22: '\\"',
            0x27: "\\'",
            0x0A: "\\n",
            0x0D: "\\r",
            0x09: "\\t",
        }.get(u)
        if short is not None:
            out.append(short)
        elif u < 0x20 or 0xD800 <= u <= 0xDFFF:
            out.append("\\u%04x" % u)
        else:
            out.append(chr(u))
    out.append('"')
    return "".join(out)


@pytest.fixture(scope="module")
def fixture_class():
    """The fixture's decompiled text, plus its declaration and body literals.

    The premises are ASSERTED rather than assumed: a fixture that stopped
    carrying both renderings of a value would make every case below vacuous.
    """
    assert FIXTURE.is_file(), FIXTURE  # committed
    dk = dexllm.DexKit(str(FIXTURE))
    assert dk.list_classes() == [CLS]
    text = dk.decompile_class(CLS)
    decls = {}
    for line in text.split("\n"):
        m = FIELD.match(line)
        if m:
            decls[m.group(1)] = m.group(2)
    body = re.findall(r'v0_1\[\d+\] = (".*");', text)
    assert len(decls) == len(EXPECTED), sorted(decls)
    assert len(body) == len(EXPECTED), body
    return dk, text, decls, body


@pytest.mark.parametrize("name", sorted(EXPECTED))
def test_a_declaration_renders_the_value_the_way_the_method_body_does(
    name, fixture_class
):
    """The headline: the same value, the same text, in both positions.

    Comparing the two RENDERINGS is the property the issue is about. It is not
    sufficient on its own - a build could satisfy it by making both wrong in the
    same way - which is why the pinned literals below exist too.
    """
    _, _, decls, body = fixture_class
    assert decls[name] in body, (name, decls[name])


@pytest.mark.parametrize("name", sorted(EXPECTED))
def test_a_declaration_renders_the_pinned_literal(name, fixture_class):
    """And that shared text is the RIGHT text, pinned per value."""
    _, _, decls, _ = fixture_class
    assert decls[name] == EXPECTED[name], (name, repr(decls[name]))


@pytest.mark.parametrize("name", sorted(EXPECTED))
def test_a_declaration_matches_the_documented_rule(name, fixture_class):
    """The pinned literal is also what the rule says, derived independently."""
    dk, _, decls, _ = fixture_class
    want = {java_literal(v) for v in dk.list_class_strings(CLS)}
    assert decls[name] in want, (name, repr(decls[name]))


def test_no_declaration_carries_a_backslash_x_escape(fixture_class):
    """`\\xNN` is not Java. FOUR of the fixture's sixteen values reached that arm.

    WHICH four is not obvious, and a correctness reviewer had to compile the
    deleted escaper to settle it: only a RAW byte below 0x20 or DEL reached its
    `append_hex2`, so VT (0x0B), FF (0x0C), DEL (0x7F) and MIXED (which holds two
    of them) produced a `\\xNN` - while NUL and NEL did NOT, because a dex NUL is
    stored `C0 80` and U+0085 is two bytes, so both took the multibyte branch and
    came out `\\u0000` / `\\u0085`. An earlier version of this guard named NUL
    and NEL and omitted MIXED, i.e. it asserted the presence of two values that
    never reached the arm at all.
    """
    _, text, decls, _ = fixture_class
    assert not NOT_JAVA.search(text), text
    # Non-vacuity: the values that USED to produce one must still be present.
    assert {"VT", "FF", "DEL", "MIXED"} <= set(decls)


def test_no_declaration_carries_a_raw_control_character(fixture_class):
    """The Java sibling of `test_smali_never_contains_raw_control_chars`.

    Every unit below 0x20 escapes, so no C0 control may survive into the text
    (newline is the format's own separator and is excluded). Nothing asserted
    this on the Java side, and it is exactly the property the change now leans
    on: the declaration path used to reach ASCII by escaping EVERYTHING.

    Scope, deliberately the same as the smali guard's: C0 only. DEL, the C1
    range and U+0085 / U+2028 / U+2029 are emitted as themselves - see the
    encoding rule in docs/api.md - which is why this asserts `< 0x20` and not
    `iscontrol`.
    """
    _, text, decls, _ = fixture_class
    assert not any(ord(c) < 0x20 and c != "\n" for c in text), repr(text[:400])
    assert {"VT", "FF", "NUL", "MIXED"} <= set(decls)  # values that could violate it
    # DEL and C1 are NOT C0 and ARE written raw - the scope note above, as data.
    assert DEL in decls["DEL"] and C1 in decls["C1"]


@pytest.mark.parametrize(
    "name,fragment",
    [
        ("MIXED", "\\n"),
        ("MIXED", "\\r"),
        ("TAB", "\\t"),
        ("QUOTE", '\\"'),
        ("APOS", "\\'"),
        ("BACKSLASH", "\\\\"),
    ],
)
def test_a_metacharacter_takes_its_SHORT_java_escape(name, fragment, fixture_class):
    """`\\n` / `\\r` / `\\t` must NOT be rendered `\\uXXXX`, and the order is why.

    A Java compiler translates a `\\uXXXX` escape BEFORE it tokenizes (JLS 3.3),
    so rendering LF as `\\u000a` puts a real newline inside the literal and
    leaves it unterminated - the same mechanism dexllm#64 had to defend the `//`
    comment against. `EscapeJavaString`'s short-escape switch runs before
    `AppendUtf16Escaped` for exactly that reason, and the pinned literals cover
    it only implicitly; a correctness reviewer asked for it to be said.
    """
    _, _, decls, _ = fixture_class
    assert fragment in decls[name], (name, repr(decls[name]))


def test_an_empty_initializer_is_still_emitted(fixture_class):
    """The deleted `raw.empty()` branch, guarded rather than only measured.

    `EscapeJavaString` renders an empty value as `""` itself, which is why the
    call site's special case could go - but nothing asserted it. An adversarial
    reviewer replaced the arm with `if (strings[idx].empty()) return {};`, which
    makes `decompile_class` emit `public static final String EMPTY;` - the exact
    dexllm#64 shape this repo states it removed, where a declaration means both
    "no initializer" and "one we could not spell" - and it passed all 38 cases
    and the whole 1341-test suite. It was invisible because the fixture had no
    empty value AND the corpus oracle only validates the declarations that are
    PRESENT, so a declaration that stops being emitted is structurally outside
    it.
    """
    _, text, decls, body = fixture_class
    assert decls["EMPTY"] == '""', repr(decls.get("EMPTY"))
    assert '""' in body
    assert "String EMPTY;" not in text, text


def test_dexllm22_quote_escaping_survives(fixture_class):
    """The reason this arm was last touched: a `"` must not end the literal.

    `PythonUnicodeEscape` escaped the double quote as a deliberate divergence
    from Python's `unicode-escape` (dexllm#22) - without it a crafted value
    appends a fabricated field declaration to the class body. `EscapeJavaString`
    escapes it too, so the property survives the swap; nothing else says so.
    """
    _, text, decls, _ = fixture_class
    assert decls["QUOTE"] == '"a\\"b"'
    assert decls["BACKSLASH"] == '"a\\\\b"'
    # Every declaration line is ONE statement: an unescaped quote would split it.
    for line in text.split("\n"):
        m = FIELD.match(line)
        if m:
            unescaped = re.sub(r"\\.", "", m.group(2))
            assert unescaped.count('"') == 2, line


def test_the_value_accessor_still_returns_the_decoded_value(fixture_class):
    """A rendering change must not move `list_class_strings` (dexllm#29's axis)."""
    dk, _, _, _ = fixture_class
    got = set(dk.list_class_strings(CLS))
    for v in VALUES:
        assert v in got, repr(v)


def test_the_corpus_declarations_all_match_the_documented_rule(loadable_apks):
    """The same oracle over every string field declaration in reach.

    The fixture pins the branches; this pins that nothing else in 27,000 classes
    renders a declaration the rule does not predict. Corpus-gated, with a floor -
    a run that checked only plain ASCII proves nothing.

    Scope note: `loadable_apks` is `*.apk` only, so the corpus's bare `.dex`
    entries are outside it - and one of the three sources that carried a
    `\\xNN` is one (`Annotation_classes.dex`). The committed fixtures are added
    for that reason: they are always present, they are unaffected by a
    `$DEXLLM_TEST_APK` narrowing, and `literal-escapes.dex` is among them.
    """
    fixtures = sorted(
        str(q)
        for q in (pathlib.Path(__file__).resolve().parent / "data").glob("*")
        if q.suffix in (".dex", ".apk")
    )
    checked = interesting = 0
    for path in list(loadable_apks) + fixtures:
        dk = dexllm.DexKit(path)
        for cls in dk.list_classes():
            text = dk.decompile_class(cls)
            decls = [
                m.group(2) for line in text.split("\n") if (m := FIELD.match(line))
            ]
            if not decls:
                continue
            want = {java_literal(v) for v in dk.list_class_strings(cls)}
            for d in decls:
                checked += 1
                if not d.isascii() or "\\u" in d:
                    interesting += 1
                assert d in want, (path, cls, repr(d)[:200])
    require_corpus_shape(
        interesting > 0,
        "string field declaration carrying a non-ASCII or escaped character",
        "every declaration is plain ASCII, so the two escapers cannot disagree "
        "and this test is vacuous",
    )
    assert checked > 0


def test_the_string_arm_has_exactly_one_escaper():
    """SOURCE pin: the `0x17` arm CALLS the method-body escaper.

    A correct but DUPLICATED escaper passes every behavioural case here and
    drifts on the first edit - which is the whole history of this defect, and
    the identity-pin precedent `_argkinds.py` / `_callers.py` set. It is also
    the only level at which "there is no second escaper" is expressible.

    Comments are stripped first: this file's own prose NAMES the deleted escaper
    (as it must - the change is why it is gone), so a substring scan of the raw
    text reports it present. It is the same trap dexllm#32 and dexllm#57 each
    paid for, so the scanner is the one those tests already own rather than a
    fourth reading of the rule. The arm is located inside
    `DecodeEncodedValueText` specifically: `ParseCallSiteArg` further down has a
    `case 0x17:` of its own, it hands the IR a RAW pool string rather than a Java
    literal, and it must not be changed.
    """
    from test_arg_opcode_coverage import _strip_comments

    src = _strip_comments(
        (
            pathlib.Path(__file__).resolve().parents[1]
            / "native"
            / "core_ext"
            / "dexitem_code_source.cpp"
        ).read_text()
    )
    assert "PythonUnicodeEscape" not in src
    fn = src[src.index("EncodedValueText DecodeEncodedValueText(const U1*& p,") :]
    fn = fn[: fn.index("bool ParseCallSiteArg(")]
    arm = fn[fn.index("case 0x17:") :]
    arm = arm[: arm.index("case 0x18:")]
    # The RETURN, not merely a mention: an adversarial reviewer kept the call and
    # wrapped it - `return {DeclarationSafe(EscapeJavaString(...))};` - which
    # re-created dexllm#83's defect for DEL while satisfying a containment check,
    # the whole guard file AND the whole suite.
    assert "return {dexkit::dad::EscapeJavaString(strings[idx])};" in arm, arm
