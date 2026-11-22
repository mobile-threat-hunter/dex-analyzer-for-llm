"""A handler several catch types share is a multi-catch (dexllm#132).

`Graph::Construct` gave each handler block ONE type, the last one the try
table assigned it, so a handler of three types rendered a clause naming one of
them -- `catch (IllegalAccessException v1)` for a handler of
`ClassNotFoundException`, `InstantiationException` and `IllegalAccessException`.
The clause now names every type the handler catches, in try-table order, as
`catch (A | B | C v)`; the AST carries a `['UnionType', [TypeName, ...]]`; the
catch variable's own type is the join, Throwable.

The fixture is authored smali (`tests/data/multi-catch.smali`).
"""

from __future__ import annotations

import pathlib
import re
import struct

import pytest
from test_catch_types import _sleb, _uleb

import dexllm

DATA = pathlib.Path(__file__).parent / "data"
FIXTURE = DATA / "multi-catch.dex"

CLAUSES = {
    "three()V": [
        "catch (java.io.IOException | IllegalStateException"
        " | ClassNotFoundException v0)"
    ],
    "reversed()V": ["catch (ClassNotFoundException | java.io.IOException v0)"],
    "noVariable()V": ["catch (java.io.IOException | IllegalStateException _)"],
    # a catch-all shares the handler: it catches everything
    "withCatchAll()V": ["catch (Throwable v0)"],
    "single()V": ["catch (java.io.IOException v0)"],
    # two try ranges list the same two types for one handler: each once
    "twoRanges()V": ["catch (java.io.IOException | IllegalStateException v0)"],
    "splitIf()V": ["catch (java.io.IOException | IllegalStateException v0)"],
    "gotoHandler()V": ["catch (java.io.IOException | IllegalStateException _)"],
    # a bare-goto handler into another handler's block: that block catches both
    "gotoIntoHandler()V": [
        "catch (ClassNotFoundException | java.io.IOException | IllegalStateException _)"
    ],
    # a null merged with the variable is a def outside the clause: the
    # parameter would be assigned, so the clause names the join
    "nullThenShared()V": [
        "catch (Throwable v0 /* java.io.IOException | IllegalStateException */)"
    ],
    "reassigned()V": [
        "catch (Throwable v0 /* java.io.IOException | IllegalStateException */)"
    ],
    # Throwable among the types, or a non-reference type (crafted): one
    # Throwable clause, as for a catch-all
    "withThrowable()V": ["catch (Throwable v0)"],
    "gotoIntoCatchAll()V": ["catch (Throwable _)"],
    "reassignedSplit()V": [
        "catch (Throwable v0_1 /* java.io.IOException | IllegalStateException */)"
    ],
    # two shared handlers on one register: each clause is its own parameter
    "twoSharedMerge()V": [
        "catch (java.io.IOException | IllegalStateException v0)",
        "catch (ClassNotFoundException | InterruptedException v0)",
    ],
    "primType()V": ["catch (Throwable v0)"],
    "escapes()Ljava/lang/Object;": [
        "catch (java.io.IOException | IllegalStateException v0_1)"
    ],
}

_CLAUSE = re.compile(r"catch \([^)]*\)")


@pytest.fixture(scope="module")
def dk():
    assert dexllm.verify(str(FIXTURE))[0]["valid"]
    return dexllm.DexKit(str(FIXTURE))


@pytest.mark.parametrize("method", sorted(CLAUSES))
def test_the_clause_names_every_type_the_handler_catches(dk, method):
    text = dk.decompile_method("LM;->" + method)
    assert _CLAUSE.findall(text) == CLAUSES[method], text


def test_two_handlers_stay_two_clauses(dk):
    text = dk.decompile_method("LM;->twoHandlers()V")
    got = sorted(_CLAUSE.findall(text))
    assert got == [
        "catch (IllegalStateException v0_0)",
        "catch (java.io.IOException v0_1)",
    ], text


def test_the_catch_variable_takes_the_join(dk):
    """A null and the shared handler reach one use, so the variable is
    declared outside the clause, with the handler types' join."""
    text = dk.decompile_method("LM;->nullThenShared()V")
    assert "Throwable v0 = null;" in [ln.strip() for ln in text.split("\n")], text


def _ast_catch_decls(node, out):
    if isinstance(node, dict):
        for v in node.values():
            _ast_catch_decls(v, out)
    elif isinstance(node, list):
        if node and node[0] == "TryStatement":
            _ast_catch_decls(node[2], out)
            for decl, body in node[3]:
                out.append(decl)
                _ast_catch_decls(body, out)
            return
        for v in node:
            _ast_catch_decls(v, out)
    return out


def _ast_types(typen):
    if typen[0] == "UnionType":
        return [t[1][0] for t in typen[1]]
    assert typen[0] == "TypeName", typen
    return [typen[1][0]]


def _desc(java):
    if "." not in java:
        java = "java.lang." + java
    return java.replace(".", "/")


@pytest.mark.parametrize("method", sorted(CLAUSES))
def test_the_ast_carries_the_same_types(dk, method):
    """Each emitter spells the clause by itself, so each has its own guard."""
    ast = dk.decompile_method_ast("LM;->" + method)["ast"]
    decls = _ast_catch_decls(ast, [])
    want = []
    for clause in CLAUSES[method]:
        c = re.match(r"catch \(Throwable \S+ /\* (.*) \*/\)$", clause)
        names = (c or re.match(r"catch \((.*) \S+\)$", clause)).group(1).split(" | ")
        want.append([_desc(n) for n in names])
    assert [_ast_types(d[0]) for d in decls] == want
    for d in decls:
        # a single type is a plain TypeName, never a one-element union
        assert d[0][0] == ("UnionType" if len(_ast_types(d[0])) > 1 else "TypeName")


# --- the dex's own try table is the oracle ----------------------------------


def _handlers(b):
    """(class, method_idx) -> {handler address: [types in try-table order]}."""

    def u32(o):
        return struct.unpack_from("<I", b, o)[0]

    sid_o, tid_o, cd_n, cd_o = u32(60), u32(68), u32(96), u32(100)

    def string(i):
        o = u32(sid_o + 4 * i)
        _, o = _uleb(b, o)
        return b[o : b.index(0, o)].decode("utf-8", "replace")

    def typ(i):
        return string(u32(tid_o + 4 * i))

    out = {}
    for k in range(cd_n):
        base = cd_o + 32 * k
        cls, data = typ(u32(base)), u32(base + 24)
        if not data:
            continue
        o = data
        counts = []
        for _ in range(4):
            n, o = _uleb(b, o)
            counts.append(n)
        for _ in range(counts[0] + counts[1]):
            _, o = _uleb(b, o)
            _, o = _uleb(b, o)
        for n in counts[2:]:
            idx = 0
            for _ in range(n):
                d, o = _uleb(b, o)
                idx += d
                _, o = _uleb(b, o)
                code, o = _uleb(b, o)
                if not code:
                    continue
                tries = struct.unpack_from("<H", b, code + 6)[0]
                if not tries:
                    continue
                insns = u32(code + 12)
                tp = code + 16 + insns * 2 + (2 if insns % 2 else 0)
                hbase = tp + tries * 8
                per = {}
                for t in range(tries):
                    p = hbase + struct.unpack_from("<H", b, tp + 8 * t + 6)[0]
                    size, p = _sleb(b, p)
                    for _ in range(abs(size)):
                        ti, p = _uleb(b, p)
                        addr, p = _uleb(b, p)
                        lst = per.setdefault(addr, [])
                        if typ(ti) not in lst:
                            lst.append(typ(ti))
                    if size <= 0:
                        addr, p = _uleb(b, p)
                        per.setdefault(addr, []).append("*")
                out[(cls, idx)] = per
    return out


def _java(desc):
    t = desc[1:-1].replace("/", ".").replace("$", ".")
    return t[10:] if t.startswith("java.lang.") and t.count(".") == 2 else t


@pytest.mark.parametrize(
    "name", ["multi-catch.dex", "method_handles.dex", "catch-types.dex"]
)
def test_every_shared_handler_renders_its_whole_type_list(name):
    """A handler the try table gives two or more types is named, in that
    order, by one multi-catch clause; every clause names only types the
    method's handlers catch."""
    kit = dexllm.DexKit(str(DATA / name))
    shared = 0
    for dex_id in range(kit.dex_count()):
        methods = kit.list_methods_in_dex(dex_id)
        for (cls, idx), per in _handlers(kit.extract_dex(dex_id)["bytes"]).items():
            if kit.locate_class_dex(cls) != dex_id:
                continue
            text = kit.decompile_method(methods[idx])
            # a reassigned parameter keeps its types in a comment
            clauses = [
                (m.group(2) or m.group(1)).split(" | ")
                for m in re.finditer(
                    r"catch \(([^)/]*?) \S+(?: /\* (.*?) \*/)?\)", text
                )
            ]
            allowed = {_java(t) for ts in per.values() for t in ts if t != "*"}
            allowed.add("Throwable")
            for c in clauses:
                assert set(c) <= allowed, (methods[idx], c, allowed)
            for ts in per.values():
                # Throwable or a non-reference type makes it a catch-all
                if len(ts) > 1 and not any(
                    t in ("*", "Ljava/lang/Throwable;") or not t.startswith("L")
                    for t in ts
                ):
                    shared += 1
                    want = [_java(t) for t in ts]
                    # in order, within one clause (a clause can hold more: a
                    # bare-goto handler's list joins its successor's)
                    # ... or a catch-all, when a bare-goto handler fell into one
                    catch_all = any("*" in v for v in per.values())
                    if catch_all and ["Throwable"] in clauses:
                        continue
                    assert any([t for t in c if t in want] == want for c in clauses), (
                        methods[idx],
                        want,
                        clauses,
                    )
    if name != "catch-types.dex":
        assert shared, "the fixture carries no shared handler"


def test_the_issue_repro_names_all_three():
    kit = dexllm.DexKit(str(DATA / "method_handles.dex"))
    text = kit.decompile_method(
        "LExampleJavaJniFuzzer;->fuzzerTestOneInput"
        "(Lcom/code_intelligence/jazzer/api/FuzzedDataProvider;)V"
    )
    assert (
        _CLAUSE.findall(text)
        == [
            "catch (ClassNotFoundException | InstantiationException"
            " | IllegalAccessException v1)"
        ]
        * 2
    ), text


def test_the_class_text_agrees_with_the_method_text(dk):
    cls = dk.decompile_class("LM;")
    for method, clauses in CLAUSES.items():
        for c in clauses:
            assert c in cls, (method, c)
