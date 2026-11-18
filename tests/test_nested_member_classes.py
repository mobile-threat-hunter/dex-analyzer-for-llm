"""dexllm#128 — `decompile_class` renders a PROVEN member class inside its outer.

A member is nested when BOTH sides agree: the outer class lists it in its
`MemberClasses` annotation, and the member's own `InnerClass` (a non-null
name, its `accessFlags`) and `EnclosingClass` annotations prove it is
`Outer$Name` declared in `Outer`. The nested header takes the member's simple
name and its SOURCE modifiers (`static` / `private` / `protected` live there,
not in the class_def), and so do its constructors. Anonymous and local classes
stay out (dexllm#129). Asked for by its own descriptor a member still renders
alone, as before (user decision).

The oracle reads the annotations from the dex bytes, never through the code
under test.
"""

from __future__ import annotations

import re
import zipfile
from pathlib import Path

import pytest
from conftest import require_corpus_shape
from test_member_class_spelling import _Dex, _uleb

import dexllm

ROOT = Path(__file__).resolve().parent.parent
FIXTURE = ROOT / "tests/data/member-classes.dex"

_INNER = b"Ldalvik/annotation/InnerClass;"
_ENCLOSING = b"Ldalvik/annotation/EnclosingClass;"
_MEMBERS = b"Ldalvik/annotation/MemberClasses;"


# ─── an independent reader of the three annotations ────────────────────────
def _annotations(d: _Dex, cdef: int):
    """Yield (type, {name: (value type, value, offset of the value's header)}).

    Unlike `_Dex.system_annotations` this also reads an encoded_array of
    TYPE values, the shape `MemberClasses.value` has, as a list of
    (type_idx, offset of that element's header).
    """
    b, u4 = d.b, d.u4
    ann = u4(cdef + 20)
    if ann == 0 or u4(ann) == 0:
        return
    st = u4(ann)
    for i in range(u4(st)):
        p = u4(st + 4 + 4 * i)
        if b[p] != 2:
            continue
        t, p = _uleb(b, p + 1)
        n, p = _uleb(b, p)
        elems = {}
        for _ in range(n):
            name, p = _uleb(b, p)
            at, h = p, b[p]
            vt, nb = h & 0x1F, (h >> 5) + 1
            if vt == 0x1C:
                count, p = _uleb(b, p + 1)
                vals = []
                for _ in range(count):
                    eh = b[p]
                    enb = (eh >> 5) + 1
                    vals.append((int.from_bytes(b[p + 1 : p + 1 + enb], "little"), p))
                    p += 1 + enb
                elems[d.string(name)] = (vt, vals, at)
            elif vt in (0x1E, 0x1F):
                elems[d.string(name)] = (vt, None, at)
                p += 1
            else:
                v = int.from_bytes(b[p + 1 : p + 1 + nb], "little")
                elems[d.string(name)] = (vt, v, at)
                p += 1 + nb
        yield d.type_name(t), elems


_SOURCE_ONLY = 0x1 | 0x2 | 0x4 | 0x8


def nesting(dex_bytes_list) -> dict[str, list[tuple[str, str, int]]]:
    """outer -> [(member, simple name, header flags)], first-wins.

    The header flags are InnerClass's visibility and `static` over the rest of
    the member's class_def flags."""
    facts: dict[str, dict] = {}
    for raw in dex_bytes_list:
        d = _Dex(raw)
        for cdef in d.class_defs:
            desc = d.type_name(d.u4(cdef)).decode("utf-8", "surrogatepass")
            if desc in facts:
                continue
            f = {"members": [], "name": None, "acc": None, "enc": None}
            f["cdef_acc"] = d.u4(cdef + 4)
            for atype, el in _annotations(d, cdef):
                if atype == _MEMBERS and b"value" in el and el[b"value"][0] == 0x1C:
                    f["members"] = [
                        d.type_name(i).decode("utf-8", "surrogatepass")
                        for i, _ in el[b"value"][1]
                    ]
                elif atype == _INNER:
                    if el.get(b"name", (0,))[0] == 0x17:
                        f["name"] = d.string(el[b"name"][1]).decode(
                            "utf-8", "surrogatepass"
                        )
                    if el.get(b"accessFlags", (0,))[0] == 0x04:
                        f["acc"] = el[b"accessFlags"][1]
                elif atype == _ENCLOSING and el.get(b"value", (0,))[0] == 0x18:
                    f["enc"] = d.type_name(el[b"value"][1]).decode(
                        "utf-8", "surrogatepass"
                    )
            facts[desc] = f
    out: dict[str, list[tuple[str, str, int]]] = {}
    for outer, f in facts.items():
        seen: set[str] = set()
        for m in f["members"]:
            g = facts.get(m)
            if m in seen or g is None:
                continue
            seen.add(m)
            if (
                g["name"]
                and g["acc"] is not None
                and g["enc"] == outer
                and m == outer[:-1] + "$" + g["name"] + ";"
            ):
                # visibility + static from InnerClass, everything else
                # (kind, final, abstract) from the member's class_def
                acc = (g["acc"] & _SOURCE_ONLY) | (g["cdef_acc"] & ~_SOURCE_ONLY)
                out.setdefault(outer, []).append((m, g["name"], acc))
    return out


# DAD's class access order and words (util.cpp kAccessOrder / the class table).
_ORDER = [0x1, 0x4, 0x2, 0x400, 0x8, 0x10, 0x80, 0x40, 0x20, 0x100, 0x800, 0x200]
_ORDER += [0x1000, 0x2000, 0x4000, 0x10000, 0x20000]
_WORDS = {0x1: "public", 0x2: "private", 0x4: "protected", 0x8: "static"}
_WORDS.update({0x10: "final", 0x200: "interface", 0x400: "abstract"})
_WORDS.update({0x1000: "synthetic", 0x2000: "annotation", 0x4000: "enum"})


def _access(acc: int) -> list[str]:
    if acc & 0x200:
        acc &= ~0x400
    return [_WORDS.get(f, f"unkn_{f}") for f in _ORDER if f & acc]


def expected_nested_block(standalone: dict[str, str], member, name, acc) -> str:
    """What the outer must carry for `member`: its standalone text without the
    package line, its header named and modified from InnerClass, its
    constructors named `name`, indented one level, after a blank line."""
    lines = standalone[member].split("\n")
    if lines[0].startswith("package "):
        lines = lines[1:]
    seg = member[1:-1].rsplit("/", 1)[-1]
    m = re.match(
        r"^(.*?)(class |)" + re.escape(seg) + r"((?: extends | implements | \{).*)$",
        lines[0],
    )
    assert m, lines[0]
    kw = "" if acc & 0x200 else "class "
    lines[0] = " ".join(_access(acc)) + " " + kw + name + m.group(3)
    # a method header sits at column 0 in a class's own text
    ctor = re.compile(r"^((?:[a-z][^\n(]*? )?)" + re.escape(seg) + r"\(")
    lines = [ctor.sub(lambda g: g.group(1) + name + "(", ln) for ln in lines]
    assert lines[-1] == ""
    return "\n" + "".join(("    " + ln if ln else "") + "\n" for ln in lines[:-1])


def assert_nesting_agrees(dk, classes, facts) -> int:
    """Every class's text ends with exactly the expected member blocks."""
    standalone = {c: dk.decompile_class(c) for c in classes}
    blocks = 0
    for c in classes:
        want = ""
        for member, name, acc in facts.get(c, []):
            if member in standalone:
                want += expected_nested_block(standalone, member, name, acc)
                blocks += 1
        assert standalone[c].endswith(want + "}\n"), c
    return blocks


# ─── the fixture ───────────────────────────────────────────────────────────
def _outer(path=FIXTURE) -> list[str]:
    return dexllm.DexKit(str(path)).decompile_class("Lmc/Outer;").split("\n")


def test_the_oracle_sees_the_member_classes_the_fixture_declares():
    facts = nesting([FIXTURE.read_bytes()])
    assert facts == {
        "Lmc/Outer;": [
            ("Lmc/Outer$Nested;", "Nested", 0x9),
            ("Lmc/Outer$Inner;", "Inner", 0x1),
        ],
        "Lmc/Outer$Nested;": [("Lmc/Outer$Nested$Deep;", "Deep", 0x9)],
    }


@pytest.mark.parametrize(
    "line",
    [
        "    public static class Nested {",
        "        public static class Deep {",
        "            public static int X;",
        "    public class Inner {",
        "        public int f;",
    ],
)
def test_each_member_is_rendered_inside_its_outer(line):
    assert line in _outer()


@pytest.mark.parametrize(
    "line",
    ["    public Nested()", "        public Deep()", "    public Inner(mc.Outer p1)"],
)
def test_a_nested_constructor_takes_the_simple_name(line):
    assert line in _outer()


def test_no_nested_text_carries_the_dollar_spelling_of_its_own_name():
    lines = _outer()
    assert not [
        ln for ln in lines if re.search(r"\bOuter\$(Nested|Inner|Nested\$Deep)\(", ln)
    ]
    assert not [ln for ln in lines if re.search(r"class Outer\$", ln)]


@pytest.mark.parametrize("name", ["1", "1Loc", "Top", "Nested$1"])
def test_an_unproven_class_is_not_nested(name):
    # anonymous, local, a top-level class named after a member, and an
    # anonymous class inside a member
    assert not [
        ln
        for ln in _outer()
        if re.search(rf"\b(class|interface) {re.escape(name)}\b", ln)
    ]


def test_only_the_asked_for_class_carries_a_package_line():
    assert [ln for ln in _outer() if ln.startswith("package ")] == ["package mc;"]
    assert sum(ln.startswith("package ") for ln in _outer()) == 1


def test_a_member_asked_for_alone_renders_as_before():
    dk = dexllm.DexKit(str(FIXTURE))
    alone = dk.decompile_class("Lmc/Outer$Inner;").split("\n")
    assert alone[:2] == ["package mc;", "public class Outer$Inner {"]
    assert "public Outer$Inner(mc.Outer p1)" in alone


@pytest.mark.parametrize("first", ["outer", "member"])
def test_the_two_renderings_do_not_share_a_cache_entry(first):
    # the nested and the standalone constructor spell differently, so a cached
    # one must not answer for the other, in either order
    dk = dexllm.DexKit(str(FIXTURE))
    calls = {
        "outer": lambda: dk.decompile_class("Lmc/Outer;"),
        "member": lambda: dk.decompile_class("Lmc/Outer$Inner;"),
    }
    calls[first]()
    calls["member" if first == "outer" else "outer"]()
    assert "    public Inner(mc.Outer p1)" in dk.decompile_class("Lmc/Outer;").split(
        "\n"
    )
    assert "public Outer$Inner(mc.Outer p1)" in dk.decompile_class(
        "Lmc/Outer$Inner;"
    ).split("\n")
    assert "public Outer$Inner(mc.Outer p1)" in dk.decompile_method(
        "Lmc/Outer$Inner;-><init>(Lmc/Outer;)V"
    ).split("\n")


def test_a_member_with_members_nests_them_when_asked_for_alone():
    alone = dexllm.DexKit(str(FIXTURE)).decompile_class("Lmc/Outer$Nested;").split("\n")
    assert "    public static class Deep {" in alone
    assert "    public Deep()" in alone


def test_every_nested_block_on_the_fixture_agrees_with_the_annotations():
    dk = dexllm.DexKit(str(FIXTURE))
    blocks = assert_nesting_agrees(
        dk, list(dict.fromkeys(dk.list_classes())), nesting([FIXTURE.read_bytes()])
    )
    assert blocks == 3


# ─── the proof, isolated by craft ──────────────────────────────────────────
def _patch_element(of: str, annotation: bytes, element: bytes, value: int, index=None):
    b = bytearray(FIXTURE.read_bytes())
    d = _Dex(bytes(b))
    for cdef in d.class_defs:
        if d.type_name(d.u4(cdef)).decode() != of:
            continue
        for atype, el in _annotations(d, cdef):
            if atype != annotation:
                continue
            vt, v, at = el[element]
            if index is not None:
                at = v[index][1]
            nb = (b[at] >> 5) + 1
            assert value < 256**nb  # same width, length-preserving
            b[at + 1 : at + 1 + nb] = value.to_bytes(nb, "little")
            return bytes(b)
    raise AssertionError(f"{of} has no {annotation!r}")


def _type(value: bytes) -> int:
    d = _Dex(FIXTURE.read_bytes())
    return next(i for i in range(len(d.type_str)) if d.type_name(i) == value)


def _load(tmp_path, raw: bytes) -> Path:
    p = tmp_path / "crafted.dex"
    p.write_bytes(raw)
    assert dexllm.verify(str(p))[0]["valid"]
    return p


def test_the_header_takes_the_member_source_modifiers(tmp_path):
    # InnerClass says `private static` (0xA); the class_def cannot (a private
    # member's class_def is package-private and never static)
    raw = _patch_element("Lmc/Outer$Nested;", _INNER, b"accessFlags", 0xA)
    assert nesting([raw])["Lmc/Outer;"][0] == ("Lmc/Outer$Nested;", "Nested", 0xA)
    assert "    private static class Nested {" in _outer(_load(tmp_path, raw))


def test_a_member_whose_enclosing_class_is_another_is_not_nested(tmp_path):
    # Outer still LISTS Inner, but Inner says it is declared in `Lmc/Other;`.
    # The dex shares ONE `EnclosingClass(Outer)` item between Nested and Inner,
    # so the craft moves both; the oracle says so and the output must agree.
    raw = _patch_element("Lmc/Outer$Inner;", _ENCLOSING, b"value", _type(b"Lmc/Other;"))
    facts = nesting([raw])
    assert "Lmc/Outer;" not in facts
    path = _load(tmp_path, raw)
    lines = _outer(path)
    assert not [ln for ln in lines if re.search(r"class (Inner|Nested)\b", ln)]
    dk = dexllm.DexKit(str(path))
    assert_nesting_agrees(dk, list(dict.fromkeys(dk.list_classes())), facts)


def test_a_class_the_outer_does_not_list_is_not_nested(tmp_path):
    # Inner's own annotations still prove it a member of Outer; Outer lists
    # Nested twice instead, so Inner is not nested and Nested appears once
    raw = _patch_element(
        "Lmc/Outer;", _MEMBERS, b"value", _type(b"Lmc/Outer$Nested;"), index=1
    )
    assert [m for m, _, _ in nesting([raw])["Lmc/Outer;"]] == ["Lmc/Outer$Nested;"]
    path = _load(tmp_path, raw)
    lines = _outer(path)
    assert sum(ln == "    public static class Nested {" for ln in lines) == 1
    assert not [ln for ln in lines if "class Inner" in ln]
    dk = dexllm.DexKit(str(path))
    assert_nesting_agrees(dk, list(dict.fromkeys(dk.list_classes())), nesting([raw]))


def test_a_listed_class_from_another_package_is_not_nested(tmp_path):
    # Outer lists `Lmc/Sub;`, which proves nothing about Outer
    raw = _patch_element("Lmc/Outer;", _MEMBERS, b"value", _type(b"Lmc/Sub;"), index=0)
    lines = _outer(_load(tmp_path, raw))
    assert not [ln for ln in lines if "class Sub" in ln or "class Nested" in ln]
    assert "    public class Inner {" in lines


# ─── the corpus ────────────────────────────────────────────────────────────
def test_every_nested_block_on_the_corpus_agrees_with_the_annotations(loadable_apks):
    blocks = 0
    for apk in loadable_apks:
        if not zipfile.is_zipfile(apk):
            continue
        z = zipfile.ZipFile(apk)
        raws, i = [], 1
        while (n := "classes.dex" if i == 1 else f"classes{i}.dex") in z.namelist():
            raws.append(z.read(n))
            i += 1
        facts = nesting(raws)
        dk = dexllm.DexKit(str(apk))
        declared = set(dk.list_classes())
        outers = [c for c in facts if c in declared][:60]
        closure = list(
            dict.fromkeys(outers + [m for c in outers for m, _, _ in facts[c]])
        )
        # a member's own members are part of its expected text, so render them too
        while True:
            more = [
                m for c in closure for m, _, _ in facts.get(c, []) if m not in closure
            ]
            if not more:
                break
            closure += list(dict.fromkeys(more))
        blocks += assert_nesting_agrees(dk, closure, facts)
    require_corpus_shape(
        blocks > 0, "a class with proven member classes", "nesting never fired"
    )


def test_a_listed_member_whose_name_is_not_its_descriptor_is_not_nested(tmp_path):
    # Inner's InnerClass names it "Deep": listed by Outer and enclosed in
    # Outer, but `Outer$Inner` is not `Outer$Deep`, so nothing is proven
    d = _Dex(FIXTURE.read_bytes())
    deep = next(i for i in range(len(d.string_off)) if d.string(i) == b"Deep")
    raw = _patch_element("Lmc/Outer$Inner;", _INNER, b"name", deep)
    assert [m for m, _, _ in nesting([raw])["Lmc/Outer;"]] == ["Lmc/Outer$Nested;"]
    path = _load(tmp_path, raw)
    lines = _outer(path)
    assert not [ln for ln in lines if "class Inner" in ln]
    # the real Deep stays where it is, one level inside Nested
    assert not [ln for ln in lines if re.match(r"^    \S.*class Deep \{", ln)]
    dk = dexllm.DexKit(str(path))
    assert_nesting_agrees(dk, list(dict.fromkeys(dk.list_classes())), nesting([raw]))


def test_a_listed_member_of_a_member_is_nested_only_in_its_own_outer(tmp_path):
    # Outer lists `Outer$Nested$Deep`, which is proven a member — of Nested.
    # It belongs one level down, not at Outer's level too.
    raw = _patch_element(
        "Lmc/Outer;", _MEMBERS, b"value", _type(b"Lmc/Outer$Nested$Deep;"), index=0
    )
    assert [m for m, _, _ in nesting([raw])["Lmc/Outer;"]] == ["Lmc/Outer$Inner;"]
    path = _load(tmp_path, raw)
    lines = _outer(path)
    assert not [ln for ln in lines if re.match(r"^    \S.*class Deep \{", ln)]
    dk = dexllm.DexKit(str(path))
    assert_nesting_agrees(dk, list(dict.fromkeys(dk.list_classes())), nesting([raw]))


def test_the_kind_and_final_come_from_the_class_def(tmp_path):
    # InnerClass claims `public static final` (0x19); the class_def is not
    # final, and the nested header must not contradict the standalone one
    raw = _patch_element("Lmc/Outer$Nested;", _INNER, b"accessFlags", 0x19)
    path = _load(tmp_path, raw)
    lines = _outer(path)
    assert "    public static class Nested {" in lines
    dk = dexllm.DexKit(str(path))
    assert dk.decompile_class("Lmc/Outer$Nested;").split("\n")[1] == (
        "public class Outer$Nested {"
    )
    assert_nesting_agrees(dk, list(dict.fromkeys(dk.list_classes())), nesting([raw]))


DEEP = ROOT / "tests/data/deep-members.dex"


def test_a_chain_past_the_depth_limit_says_what_it_left_out():
    dk = dexllm.DexKit(str(DEEP))
    text = dk.decompile_class("Ldm/Chain;")
    lines = text.split("\n")
    headers = [ln for ln in lines if re.search(r"\bclass \w+ \{$", ln)]
    assert len(headers) == 65  # Chain + 64 nested levels
    marker = "// 1 member class(es) not nested: nesting depth limit"
    assert [ln.strip() for ln in lines if "nesting depth limit" in ln] == [marker]
    assert "leaf" not in text
    # the level that was left out is still decompile_class-able on its own
    deepest = max(dk.list_classes(), key=len)
    assert "public static int leaf()" in dk.decompile_class(deepest)
    blocks = assert_nesting_agrees(
        dk,
        [c for c in dict.fromkeys(dk.list_classes()) if c.count("$") >= 2],
        nesting([DEEP.read_bytes()]),
    )
    assert blocks > 0


def test_a_name_containing_a_slash_proves_nothing():
    # A crafted InnerClass name "x/Y" on `Outer$x/Y` would satisfy the
    # descriptor check; no committed dex can carry one, so the refusal is
    # pinned at source level (weaker than a behavioural guard).
    src = (ROOT / "native/core_ext/dexitem_code_source.cpp").read_text()
    body = src[src.index("bool IsProvenMember(") :]
    body = body[: body.index("\n}\n")]
    assert "f.inner_name.find('/') != std::string_view::npos) return false;" in body


# ─── member kinds (tests/data/nested-kinds.dex, authored in smali) ─────────
KINDS = ROOT / "tests/data/nested-kinds.dex"


def _kinds() -> list[str]:
    return dexllm.DexKit(str(KINDS)).decompile_class("Lnk/K;").split("\n")


@pytest.mark.parametrize(
    "line",
    [
        "    public static interface I {",  # abstract is implied, not printed
        "    public static final enum class E extends java.lang.Enum {",
        "    public static interface annotation Ann implements"
        " java.lang.annotation.Annotation {",
        "    private static class P {",
        "    protected class Q {",  # its class_def says public; the source says protected
        "    public abstract static class A {",
    ],
)
def test_each_kind_of_member_gets_its_header(line):
    assert line in _kinds()


def test_a_member_named_like_an_enclosing_class_is_not_nested():
    # `class K { class K }` and `class K { class P { class K } } }` are not Java
    lines = _kinds()
    marker = "// member class K not nested: it has the name of a class enclosing it"
    assert [ln for ln in lines if marker in ln] == [
        "        " + marker,  # inside P, whose outer is K
        "    " + marker,  # K's own member K
    ]
    assert [ln for ln in lines if re.search(r"\bclass K \{", ln)] == [
        "public class K {"
    ]
    dk = dexllm.DexKit(str(KINDS))
    assert "public K$K()" in dk.decompile_class("Lnk/K$K;").split("\n")


def test_the_kind_agrees_with_the_standalone_header():
    dk = dexllm.DexKit(str(KINDS))
    assert dk.decompile_class("Lnk/K$I;").split("\n")[1] == "public interface K$I {"
    assert (
        dk.decompile_class("Lnk/K$A;").split("\n")[1] == "public abstract class K$A {"
    )


def test_a_sibling_member_name_does_not_hide_another():
    # Q and A each declare a member named Z; neither encloses the other
    lines = _kinds()
    assert sum(ln == "        public static class Z {" for ln in lines) == 2
    assert not [ln for ln in lines if "member class Z not nested" in ln]
