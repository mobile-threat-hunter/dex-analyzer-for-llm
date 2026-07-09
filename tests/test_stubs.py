"""Guard the .pyi type stubs against runtime drift.

The stubs (``_dexkit_core.pyi`` / ``__init__.pyi``) are a typed shadow of the
runtime API. Runtime is the source of truth — these tests fail if a stub
advertises a name the runtime doesn't have, or if a public runtime binding gains
a method/class that was never stubbed (so a new ``.def(...)`` can't silently ship
untyped). All self-contained: no APK needed.
"""

import ast
import pathlib

import dexllm
import dexllm._dexkit_core as C

_PKG = pathlib.Path(dexllm.__file__).parent
_CORE_PYI = _PKG / "_dexkit_core.pyi"
_INIT_PYI = _PKG / "__init__.pyi"
_INIT_PY = _PKG / "__init__.py"


def _module_all(path: pathlib.Path) -> set[str]:
    tree = ast.parse(path.read_text())
    for node in ast.walk(tree):
        if isinstance(node, ast.Assign) and any(
            getattr(t, "id", None) == "__all__" for t in node.targets
        ):
            return {e.value for e in node.value.elts}  # type: ignore[attr-defined]
    raise AssertionError(f"no __all__ in {path}")


def _pyi_toplevel_defs(path: pathlib.Path) -> list[ast.ClassDef | ast.FunctionDef]:
    return [
        n
        for n in ast.parse(path.read_text()).body
        if isinstance(n, (ast.ClassDef, ast.FunctionDef))
    ]


def test_stub_files_exist_and_parse():
    assert (_PKG / "py.typed").is_file()
    for p in (_CORE_PYI, _INIT_PYI):
        ast.parse(p.read_text())  # raises SyntaxError on malformed stub


def test_init_pyi_all_matches_runtime():
    """__init__.pyi __all__ == __init__.py __all__ == the live dexllm.__all__."""
    assert _module_all(_INIT_PYI) == _module_all(_INIT_PY) == set(dexllm.__all__)


def test_init_pyi_reexports_all_resolvable():
    """Every name __init__.pyi advertises resolves on the runtime package."""
    for name in _module_all(_INIT_PYI):
        assert hasattr(dexllm, name), f"__init__.pyi advertises missing {name!r}"


def test_core_pyi_only_declares_real_names():
    """Every public class/func in _dexkit_core.pyi exists on the native module."""
    for node in _pyi_toplevel_defs(_CORE_PYI):
        if node.name.startswith("_"):  # private stub helpers (_MatchType, TypedDicts)
            continue
        assert hasattr(C, node.name), f"stub declares non-existent {node.name!r}"


def test_core_pyi_covers_every_public_binding():
    """Reverse guard: every public class/function the native module exports is
    stubbed — a new .def(...) / py::class_ can't ship untyped."""
    stubbed = {n.name for n in _pyi_toplevel_defs(_CORE_PYI)}
    runtime = {n for n in dir(C) if not n.startswith("_")}
    assert runtime <= stubbed, f"native names missing from stub: {runtime - stubbed}"


def test_dexkit_pyi_covers_every_public_method():
    """Every public DexKit method is in the stub, and the stub invents none."""
    stub_cls = next(
        n
        for n in _pyi_toplevel_defs(_CORE_PYI)
        if isinstance(n, ast.ClassDef) and n.name == "DexKit"
    )
    stub_methods = {
        m.name for m in stub_cls.body if isinstance(m, ast.FunctionDef)
    } - {"__init__"}
    runtime_methods = {m for m in dir(C.DexKit) if not m.startswith("_")}
    assert runtime_methods == stub_methods, (
        f"only in runtime: {runtime_methods - stub_methods} | "
        f"only in stub: {stub_methods - runtime_methods}"
    )


def test_return_class_attrs_match_runtime():
    """Every stubbed return-object class exposes EXACTLY the runtime attributes —
    catches a new py::class_ readonly (or an _enrich.py property) shipping untyped,
    or a stub attr the runtime dropped. Covers the pybind + _enrich union."""
    for node in _pyi_toplevel_defs(_CORE_PYI):
        if not isinstance(node, ast.ClassDef):
            continue
        if node.name.startswith("_") or node.name == "DexKit":
            continue
        stub_attrs = {m.name for m in node.body if isinstance(m, ast.FunctionDef)}
        runtime_attrs = {a for a in dir(getattr(C, node.name)) if not a.startswith("_")}
        assert stub_attrs == runtime_attrs, (
            f"{node.name}: only in stub {stub_attrs - runtime_attrs} | "
            f"only in runtime {runtime_attrs - stub_attrs}"
        )
