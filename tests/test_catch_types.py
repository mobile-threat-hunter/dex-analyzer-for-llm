"""A catch variable takes the handler's exception type (dexllm#130).

A `move-exception` def has no rhs, so SplitVariables kept the register's LAST
write as the version's type and the catch clause read
`catch (java.lang.reflect.Method v)`. The previous clamp replaced only a
primitive or array type. Now the version is typed from its handler, and both
emitters spell the clause with the handler type, which is what the catch
clause means. The AST had no clamp at all and rendered `catch (int v)`.

The fixture is authored smali (`tests/data/catch-types.smali`). Every shape in
CLAUSES / DECLARATIONS but `catchAll` renders a wrong catch type on the pre-fix
build; `catchAll` is the control.
"""

from __future__ import annotations

import pathlib
import re
import struct

import pytest

import dexllm

DATA = pathlib.Path(__file__).parent / "data"
FIXTURE = DATA / "catch-types.dex"

# method -> the catch clauses it must render, in order
CLAUSES = {
    # the issue's shape: a Field is the register's last write (split path)
    "field(Ljava/lang/String;)Ljava/lang/reflect/Field;": [
        "catch (NoSuchFieldException v0_2)"
    ],
    # the catch variable is unused, so it never reaches SplitVariables; a
    # String is the last write (the clause rule)
    "deadCatch()Ljava/lang/String;": ["catch (java.io.IOException v0)"],
    "catchAll()Ljava/lang/Object;": ["catch (Throwable v0_1)"],
    # one register, two handlers that merge: each clause names its own
    "mergedHandlers()V": [
        "catch (java.io.IOException v0)",
        "catch (IllegalStateException v0)",
    ],
    "nullThenTwoHandlers()V": [
        "catch (java.io.IOException v0)",
        "catch (IllegalStateException v0)",
    ],
    "nullThenTwoHandlersSplit()V": [
        "catch (java.io.IOException v0_1)",
        "catch (IllegalStateException v0_1)",
    ],
    "primCatch()I": ["catch (java.io.IOException v0)"],
    "stringAndCatch()V": ["catch (java.io.IOException v0_1)"],
    "intAndCatch()V": ["catch (java.io.IOException v0_1)"],
}

# the variable a null and two handler types reach is either exception: the
# declaration names their common type, on the unsplit and the split path
DECLARATIONS = {
    "nullThenTwoHandlers()V": "Throwable v0 = null;",
    "nullThenTwoHandlersSplit()V": "Throwable v0_1 = null;",
    # a real def of another type merged with a handler keeps its own type: the
    # handler type wins only over null (adversarial review: `IOException v0_1 =
    # 7` and `IOException v0_1 = "s"` before this rule)
    "stringAndCatch()V": 'String v0_1 = "s";',
    "intAndCatch()V": "int v0_1 = 7;",
}

_CATCH = re.compile(r"catch \([\w.$\[\]]+ (?:v\w+|_)\)")


@pytest.fixture(scope="module")
def dk():
    assert dexllm.verify(str(FIXTURE))[0]["valid"]
    return dexllm.DexKit(str(FIXTURE))


@pytest.mark.parametrize("method", sorted(CLAUSES))
def test_the_catch_clause_names_the_handler_type(dk, method):
    text = dk.decompile_method("LC;->" + method)
    assert _CATCH.findall(text) == CLAUSES[method], text


@pytest.mark.parametrize("method", sorted(DECLARATIONS))
def test_the_declaration_takes_the_merged_type(dk, method):
    text = dk.decompile_method("LC;->" + method)
    assert DECLARATIONS[method] in [ln.strip() for ln in text.split("\n")], text


def _ast_catch_types(node, out):
    if isinstance(node, dict):
        for v in node.values():
            _ast_catch_types(v, out)
    elif isinstance(node, list):
        if node and node[0] == "TryStatement":
            _ast_catch_types(node[2], out)
            for decl, body in node[3]:
                typen = decl[0]
                if typen[0] == "UnionType":  # dexllm#132
                    out.append(" | ".join(t[1][0] for t in typen[1]))
                else:
                    out.append(typen[1][0])
                _ast_catch_types(body, out)
            return
        for v in node:
            _ast_catch_types(v, out)
    return out


@pytest.mark.parametrize("method", sorted(CLAUSES))
def test_the_ast_names_the_same_types(dk, method):
    """Each emitter spells the clause by itself, so each has its own guard."""
    ast = dk.decompile_method_ast("LC;->" + method)["ast"]
    got = _ast_catch_types(ast, [])
    want = []
    for clause in CLAUSES[method]:
        name = re.match(r"catch \(([\w.$]+)", clause).group(1)
        want.append(
            ("java/lang/" + name) if "." not in name else name.replace(".", "/")
        )
    assert got == want


# --- the dex's own try table is the oracle ----------------------------------


def _uleb(b, o):
    r = s = 0
    while True:
        x = b[o]
        o += 1
        r |= (x & 0x7F) << s
        s += 7
        if x < 0x80:
            return r, o


def _sleb(b, o):
    r = s = 0
    while True:
        x = b[o]
        o += 1
        r |= (x & 0x7F) << s
        s += 7
        if x < 0x80:
            return (r - (1 << s)) if x & 0x40 else r, o


def _handler_types(b):
    """(class, method_idx) -> every type the method's handlers catch."""

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
                if not code or not struct.unpack_from("<H", b, code + 6)[0]:
                    continue
                tries = struct.unpack_from("<H", b, code + 6)[0]
                insns = u32(code + 12)
                p = code + 16 + insns * 2 + (2 if insns % 2 else 0) + tries * 8
                nh, p = _uleb(b, p)
                types = set()
                for _ in range(nh):
                    size, p = _sleb(b, p)
                    for _ in range(abs(size)):
                        ti, p = _uleb(b, p)
                        _, p = _uleb(b, p)
                        types.add(typ(ti))
                    if size <= 0:
                        _, p = _uleb(b, p)
                        types.add("Ljava/lang/Throwable;")
                out[(cls, idx)] = types
    return out


def _java(desc):
    t = desc[1:-1].replace("/", ".").replace("$", ".")
    return t[10:] if t.startswith("java.lang.") and t.count(".") == 2 else t


_FIXTURES = [
    "catch-types.dex",
    "two-tries.dex",
    "method_handles.dex",
    "invoke-custom.dex",
    "cfg-shapes.dex",
]


@pytest.mark.parametrize("name", _FIXTURES)
def test_every_catch_clause_is_a_type_the_try_table_names(name):
    """Every clause type is one the method's own handlers catch.

    A catch-all is `Throwable`. The pre-fix build rendered types the try
    table does not carry at all: `IllegalAccessException` for a handler of
    `ClassNotFoundException` in method_handles.dex, `IOException` for one of
    `Exception` in two-tries.dex.
    """
    path = DATA / name
    kit = dexllm.DexKit(str(path))
    checked = 0
    for dex_id in range(kit.dex_count()):
        raw = kit.extract_dex(dex_id)["bytes"]
        methods = kit.list_methods_in_dex(dex_id)
        for (cls, idx), types in _handler_types(raw).items():
            if kit.locate_class_dex(cls) != dex_id:
                continue
            allowed = {_java(t) for t in types} | {"Throwable"}
            text = kit.decompile_method(methods[idx])
            for m in re.finditer(r"catch \(([\w.$\[\]]+) ", text):
                checked += 1
                assert m.group(1) in allowed, (methods[idx], m.group(1), allowed)
    assert checked, "the fixture renders no catch clause"


def test_the_fixture_carries_every_shape():
    smali = (DATA / "catch-types.smali").read_text()
    for method in CLAUSES:
        assert f".method public static {method}" in smali
