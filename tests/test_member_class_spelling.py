"""dexllm#127 — the Java view spells a PROVEN member class with `.`.

A `$` in a class descriptor is a nesting separator only when something says so:
for a class a loaded dex declares, its own `InnerClass` (a non-null name) and
`EnclosingClass` system annotations, with the descriptor spelled exactly
`Outer$Name`; for a framework class, the SDK catalog. Anything unproven keeps
its `$`: an anonymous class (`Outer$1`), a local class (`Outer$1Loc`, which
carries `EnclosingMethod` instead), a top-level class whose name merely
contains `$`. Only the Java text changes; `list_classes`, smali, the AST and
every descriptor-valued API keep the dex spelling, and so does the class
header's own name (an inner class is still emitted as a class of its own).

The oracle here reads the annotations straight from the dex bytes, never
through the code under test.
"""

from __future__ import annotations

import re
import struct
import subprocess
import sys
from pathlib import Path

import pytest
from conftest import require_corpus_shape

import dexllm

ROOT = Path(__file__).resolve().parent.parent
FIXTURE = ROOT / "tests/data/member-classes.dex"

_INNER = b"Ldalvik/annotation/InnerClass;"
_ENCLOSING = b"Ldalvik/annotation/EnclosingClass;"


# ─── an independent reader of the two annotations ──────────────────────────
def _uleb(b: bytes, p: int) -> tuple[int, int]:
    v = s = 0
    while True:
        c = b[p]
        p += 1
        v |= (c & 0x7F) << s
        s += 7
        if not c & 0x80:
            return v, p


class _Dex:
    def __init__(self, b: bytes):
        self.b = b
        u4 = lambda o: struct.unpack_from("<I", b, o)[0]  # noqa: E731
        ns, so, nt, to, nc, co = (
            u4(0x38),
            u4(0x3C),
            u4(0x40),
            u4(0x44),
            u4(0x60),
            u4(0x64),
        )
        self.string_off = [u4(so + 4 * i) for i in range(ns)]
        self.type_str = [u4(to + 4 * i) for i in range(nt)]
        self.class_defs = [co + 32 * i for i in range(nc)]
        self.u4 = u4

    def string(self, i: int) -> bytes:
        _, p = _uleb(self.b, self.string_off[i])
        return self.b[p : self.b.index(0, p)]

    def type_name(self, i: int) -> bytes:
        return self.string(self.type_str[i])

    def system_annotations(self, cdef: int):
        """Yield (annotation type, {element name: (value type, idx, value offset)})."""
        b, u4 = self.b, self.u4
        ann = u4(cdef + 20)
        if ann == 0 or u4(ann) == 0:
            return
        st = u4(ann)
        for i in range(u4(st)):
            p = u4(st + 4 + 4 * i)
            if b[p] != 2:  # VISIBILITY_SYSTEM
                continue
            t, p = _uleb(b, p + 1)
            n, p = _uleb(b, p)
            elems = {}
            for _ in range(n):
                name, p = _uleb(b, p)
                h = b[p]
                vt, nb = h & 0x1F, (h >> 5) + 1
                at = p
                if vt in (0x1E, 0x1F):
                    p += 1
                    v = None
                elif vt in (0x1C, 0x1D):
                    break  # not in these two annotations
                else:
                    v = int.from_bytes(b[p + 1 : p + 1 + nb], "little")
                    p += 1 + nb
                elems[self.string(name)] = (vt, v, at)
            yield self.type_name(t), elems


def proven_members(dex_bytes_list) -> tuple[dict[str, str], set[str]]:
    """(descriptor -> simple name of every proven member, the NESTED set), first-wins.

    A class is nested when it carries an InnerClass annotation (the dex format
    puts one on every class declared inside another).
    """
    out: dict[str, str] = {}
    nested: set[str] = set()
    seen: set[str] = set()
    for raw in dex_bytes_list:
        d = _Dex(raw)
        for cdef in d.class_defs:
            desc = d.type_name(d.u4(cdef)).decode("utf-8", "surrogatepass")
            if desc in seen:
                continue
            seen.add(desc)
            name = enclosing = None
            for atype, el in d.system_annotations(cdef):
                if atype == _INNER:
                    nested.add(desc)
                    if el.get(b"name", (0,))[0] == 0x17:
                        name = d.string(el[b"name"][1]).decode("utf-8", "surrogatepass")
                if atype == _ENCLOSING and el.get(b"value", (0,))[0] == 0x18:
                    enclosing = d.type_name(el[b"value"][1]).decode(
                        "utf-8", "surrogatepass"
                    )
            if name and enclosing and desc == enclosing[:-1] + "$" + name + ";":
                out[desc] = name
    return out, nested


def java_spelling(desc: str, proven: dict[str, str], nested: set[str]) -> str:
    """`Lpkg/A$B;` -> `pkg.A.B` with only proven `$` dotted (no java.lang strip).

    The walk goes outward only while the class is nested; a top-level class
    stops it.
    """
    body = list(desc[1:-1])
    pkg_end = desc.rfind("/") + 1  # index in desc of the simple name
    cur = desc
    while True:
        dollar = cur.rfind("$")
        if dollar < pkg_end + 1 or cur not in nested:
            break
        n = proven.get(cur)
        if n and cur == cur[:dollar] + "$" + n + ";":
            body[dollar - 1] = "."
        cur = cur[:dollar] + ";"
    return "".join(body).replace("/", ".")


def _fixture_session():
    return dexllm.DexKit(str(FIXTURE))


# ─── the fixture ───────────────────────────────────────────────────────────
def test_the_oracle_sees_exactly_the_member_classes_the_fixture_declares():
    proven, nested = proven_members([FIXTURE.read_bytes()])
    assert "Lmc/Outer$Nested$Top;" not in nested and "Lmc/Weird$Name;" not in nested
    assert {"Lmc/Outer$1;", "Lmc/Outer$1Loc;", "Lmc/Outer$Nested$1;"} <= nested
    assert proven == {
        "Lmc/Outer$Inner;": "Inner",
        "Lmc/Outer$Nested;": "Nested",
        "Lmc/Outer$Nested$Deep;": "Deep",
    }


@pytest.mark.parametrize(
    "line",
    [
        "public static int use(mc.Outer.Nested p3, mc.Outer.Nested.Deep p4, "
        "mc.Outer.Inner p5, java.util.Map.Entry p6, Thread.State p7, mc.Weird$Name p8)",
        "public mc.Outer.Inner makeInner()",
        "    return new mc.Outer.Inner(this);",
        "    mc.Outer.Nested.Deep.X = 1;",
        "    return new mc.Outer$1();",
        "    return new mc.Outer$1Loc();",
        "    return (((((v1_0 + mc.Weird$Name.y) + v3_1) + v3_2) + v3_3) + v0);",
    ],
)
def test_the_java_view_spells_each_rule(line):
    assert line in _fixture_session().decompile_class("Lmc/Outer;").split("\n")


def test_a_field_declaration_is_spelled_the_same_way():
    # field types go through the class's field list, not a method pipeline
    lines = _fixture_session().decompile_class("Lmc/Outer;").split("\n")
    assert "    public static mc.Outer.Nested.Deep KEEP;" in lines


def test_a_class_header_names_its_supertypes_the_same_way():
    # the header spells supertypes in full (it never strips java.lang); the
    # member-class rule applies there too
    line = _fixture_session().decompile_class("Lmc/Sub;").split("\n")[1]
    assert line == (
        " class Sub extends mc.Outer.Nested implements java.lang.Thread.UncaughtExceptionHandler {"
    )


def test_an_anonymous_class_in_a_member_keeps_only_its_own_dollar():
    text = _fixture_session().decompile_class("Lmc/Outer$Nested;")
    assert "    return new mc.Outer.Nested$1();" in text.split("\n")


def test_the_class_header_keeps_its_dex_name():
    # Nesting an inner class into its outer is dexllm#128; until then it is a
    # class of its own and `class Outer.Nested` would not be a declaration.
    text = _fixture_session().decompile_class("Lmc/Outer$Nested;")
    assert "public class Outer$Nested {" in text.split("\n")


def test_every_other_view_keeps_the_descriptor():
    dk = _fixture_session()
    assert "Lmc/Outer$Nested$Deep;" in dk.list_classes()
    assert "Lmc/Outer$Nested$Deep;" in dk.render_class_smali("Lmc/Outer;")
    use = next(m for m in dk.list_class_methods("Lmc/Outer;") if "->use(" in m)
    ast = dk.decompile_method_ast(use)
    assert "Lmc/Outer$Nested$Deep;" in ast["param_types"]
    assert "Ljava/util/Map$Entry;" in ast["param_types"]


# ─── the adapter's proof, isolated by craft ────────────────────────────────
def _crafted(annotation: bytes, element: bytes, of: str, to_index: int) -> bytes:
    """The fixture with one annotation element of class `of` repointed."""
    b = bytearray(FIXTURE.read_bytes())
    d = _Dex(bytes(b))
    for cdef in d.class_defs:
        if d.type_name(d.u4(cdef)).decode() != of:
            continue
        for atype, el in d.system_annotations(cdef):
            if atype == annotation:
                vt, v, at = el[element]
                nb = (b[at] >> 5) + 1
                assert to_index < 256**nb  # same width, length-preserving
                b[at + 1 : at + 1 + nb] = to_index.to_bytes(nb, "little")
                return bytes(b)
    raise AssertionError(f"{of} has no {annotation!r}")


def _write(tmp_path, raw: bytes) -> str:
    p = tmp_path / "crafted.dex"
    p.write_bytes(raw)
    assert dexllm.verify(str(p))[0]["valid"]
    return str(p)


def _index_of(table: str, value: bytes) -> int:
    d = _Dex(FIXTURE.read_bytes())
    if table == "string":
        return next(i for i in range(len(d.string_off)) if d.string(i) == value)
    return next(i for i in range(len(d.type_str)) if d.type_name(i) == value)


def test_an_inner_class_name_that_is_not_the_descriptor_proves_nothing(tmp_path):
    # `Outer$Inner` claims the name "Deep": the annotation is about some other
    # spelling, so this one keeps its `$`. The other members are unaffected.
    raw = _crafted(_INNER, b"name", "Lmc/Outer$Inner;", _index_of("string", b"Deep"))
    assert proven_members([raw])[0].get("Lmc/Outer$Inner;") is None
    lines = (
        dexllm.DexKit(_write(tmp_path, raw)).decompile_class("Lmc/Outer;").split("\n")
    )
    assert "public mc.Outer$Inner makeInner()" in lines
    assert any("mc.Outer.Nested.Deep p4" in ln for ln in lines)


def test_an_enclosing_class_that_is_not_the_prefix_proves_nothing(tmp_path):
    # `Lmc/Other;` is as long as `Lmc/Outer;`, so only the content differs
    raw = _crafted(
        _ENCLOSING, b"value", "Lmc/Outer$Inner;", _index_of("type", b"Lmc/Other;")
    )
    assert proven_members([raw])[0].get("Lmc/Outer$Inner;") is None
    lines = (
        dexllm.DexKit(_write(tmp_path, raw)).decompile_class("Lmc/Outer;").split("\n")
    )
    assert "public mc.Outer$Inner makeInner()" in lines


def test_a_null_inner_name_is_anonymous():
    # The fixture's anonymous classes carry a NULL `name`; the pinned lines
    # above show they keep their `$`, and here that the oracle agrees.
    proven, _ = proven_members([FIXTURE.read_bytes()])
    assert "Lmc/Outer$1;" not in proven and "Lmc/Outer$Nested$1;" not in proven


# ─── every spelling agrees with the oracle ─────────────────────────────────
def _assert_spellings_agree(dk, classes, known) -> int:
    """Every token naming a declared `$` class is spelled the oracle's way."""
    targets = [c for c in dict.fromkeys(dk.list_classes()) if "$" in c]
    pats = []
    for c in targets:
        body = re.escape(c[1:-1].replace("/", ".")).replace(r"\$", r"[.$]")
        if c.startswith("Ljava/lang/") and c.count("/") == 2:
            body = r"(?:java\.lang\.)?" + body[len(r"java\.lang\.") :]
        pats.append((c, re.compile(r"(?<![\w$.])" + body + r"(?![\w$])")))
    checked = 0
    for k in classes:
        text = re.sub(r'"(?:\\.|[^"\\])*"', '""', dk.decompile_class(k))
        head, _, rest = text.partition("{")  # the header names the class itself
        for c, pat in pats:
            if c[1:].split("/")[-1].split("$")[0] not in rest:
                continue
            want = java_spelling(c, *known)
            for m in pat.finditer(rest):
                got = m.group(0)
                if c.startswith("Ljava/lang/"):
                    got = (
                        "java.lang." + got if not got.startswith("java.lang.") else got
                    )
                assert got == want, (k, c, m.group(0), want)
                checked += 1
    return checked


def test_every_spelling_on_the_fixture_agrees_with_the_annotations():
    dk = _fixture_session()
    known = proven_members([FIXTURE.read_bytes()])
    assert _assert_spellings_agree(dk, dk.list_classes(), known) >= 10


def test_every_spelling_on_the_corpus_agrees_with_the_annotations(loadable_apks):
    # the largest samples: they carry the most member classes
    apks = sorted(loadable_apks, key=lambda a: -Path(a).stat().st_size)[:2]
    checked = 0
    for apk in apks:
        dk = dexllm.DexKit(apk)
        known = proven_members([d["bytes"] for d in dk.extract_dexes()])
        classes = [c for c in dict.fromkeys(dk.list_classes())][:200]
        checked += _assert_spellings_agree(dk, classes, known)
    require_corpus_shape(
        checked > 0,
        "a declared member class referenced in Java text",
        "the member-class spelling check reached nothing",
    )


def test_a_top_level_class_named_after_a_member_keeps_every_dollar():
    # adversarial-review finding: the walk once dotted the `$` before a proven
    # outer even when the class itself is top-level (`mc.Outer.Nested$Top`)
    lines = _fixture_session().decompile_class("Lmc/Outer;").split("\n")
    assert "    return mc.Outer$Nested$Top.t;" in lines


def test_a_declared_class_without_the_annotations_is_not_proven_by_the_sdk():
    # `android.view.View$OnClickListener` is an SDK member name, but the
    # fixture DECLARES a top-level class by that name: the dex's copy is the
    # one being read, and it carries no annotations.
    lines = _fixture_session().decompile_class("Lmc/Outer;").split("\n")
    assert "    return android.view.View$OnClickListener.z;" in lines


def test_every_method_entry_point_holds_the_oracle():
    # decompile_class has a scope of its own, which would hide a missing
    # per-method one; these three go through the method pipeline alone.
    dk = _fixture_session()
    use = next(m for m in dk.list_class_methods("Lmc/Outer;") if "->use(" in m)
    want = "mc.Outer.Nested.Deep p4"
    assert want in dk.decompile_method(use)
    assert want in dk.decompile_method_with_pc_map(use)["source"]
    assert want in dk.decompile_method_ast(use)["source"]


def test_the_oracle_is_per_thread():
    # The GIL is released during a decompile, so a scope must be visible only
    # to the thread that installed it: a process-wide pointer would let one
    # thread read another's ended scope.
    src = (ROOT / "native/dad_cpp/util.cpp").read_text()
    assert (
        "thread_local const MemberClassNameFn* tl_member_class_names = nullptr;" in src
    )


def test_a_framework_member_is_spelled_from_the_sdk_catalog():
    # A class no loaded dex declares is proven by the SDK list.
    lines = _fixture_session().decompile_class("Lmc/Outer;")
    assert "java.util.Map.Entry p6" in lines and "Thread.State p7" in lines
    assert "Map$Entry" not in lines and "Thread$State" not in lines


# ─── the compiled-in SDK table ─────────────────────────────────────────────
def test_the_sdk_table_is_what_the_generator_produces(tmp_path):
    out = tmp_path / "sdk.inc"
    subprocess.run(
        [sys.executable, str(ROOT / "scripts/gen_sdk_member_classes.py"), str(out)],
        check=True,
    )
    committed = (ROOT / "native/core_ext/sdk_member_classes.inc").read_text()
    assert out.read_text() == committed


def test_the_sdk_table_is_sorted_for_binary_search():
    text = (ROOT / "native/core_ext/sdk_member_classes.inc").read_text()
    descs = re.findall(r'^\{"([^"]+)", "[^"]+"\},$', text, re.M)
    assert len(descs) > 3000
    assert descs == sorted(descs, key=lambda s: s.encode())
    assert (
        "Ljava/util/Map$Entry;" in descs
        and "Landroid/view/View$OnClickListener;" in descs
    )
