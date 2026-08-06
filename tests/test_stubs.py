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
    stub_methods = {m.name for m in stub_cls.body if isinstance(m, ast.FunctionDef)} - {
        "__init__"
    }
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


def test_stub_argument_names_match_the_runtime():
    """The `.pyi` must declare the SAME parameter names as the binding.

    Coverage this file did not have: it checked method presence and return-class
    attributes, never parameter names — so a stub could say `api_descriptor` while
    the binding said `method_descriptor` and a keyword call type-checked but raised
    at runtime. pybind embeds the real signature in `__doc__`'s first line, which
    is the ground truth.
    """
    import re

    stub = ast.parse((_PKG / "_dexkit_core.pyi").read_text())
    dexkit = next(
        n for n in ast.walk(stub) if isinstance(n, ast.ClassDef) and n.name == "DexKit"
    )

    def runtime_params(doc: str):
        m = re.match(r"\w+\((?:self: [^,)]+(?:, )?|self(?:, )?)?([^)]*)\)", doc)
        if not m:
            return None
        body, out, depth, cur = m.group(1), [], 0, ""
        if not body.strip():
            return []
        for ch in body:
            if ch in "[(":
                depth += 1
            elif ch in "])":
                depth -= 1
            if ch == "," and depth == 0:
                out.append(cur)
                cur = ""
            else:
                cur += ch
        out.append(cur)
        return [x.split(":")[0].strip() for x in out if x.strip()]

    checked = 0
    for fn in dexkit.body:
        if not isinstance(fn, ast.FunctionDef) or fn.name.startswith("_"):
            continue
        rt = getattr(dexllm.DexKit, fn.name, None)
        assert (
            rt is not None
        ), f"stub declares DexKit.{fn.name}, runtime does not have it"
        doc = (getattr(rt, "__doc__", "") or "").splitlines()
        if not doc:
            continue
        rt_params = runtime_params(doc[0])
        if rt_params is None:
            continue
        stub_params = [a.arg for a in fn.args.args if a.arg != "self"]
        assert (
            rt_params == stub_params
        ), f"DexKit.{fn.name}: stub {stub_params} != runtime {rt_params}"
        checked += 1
    assert checked >= 20, f"only {checked} signatures compared — the parser regressed"


def test_stub_typeddict_keys_match_the_returned_dict(dk):
    """Every `_XxxTypedDict` in the stub must have exactly the runtime dict's keys.

    A dict-returning API's SHAPE is part of its contract, and nothing else checks
    it: adding a key (dexllm#26 added `source` to the verify rows) or renaming one
    would leave the stub silently wrong for every consumer's type-checker.
    """
    stub = ast.parse((_PKG / "_dexkit_core.pyi").read_text())
    classes = {n.name: n for n in ast.walk(stub) if isinstance(n, ast.ClassDef)}
    cls0 = dk.list_classes()[0]
    m0 = dk.list_class_methods(cls0)[0]
    samples = {
        "_ExtractedDex": dk.extract_dex(0),
        "_VerifyStatus": dk.verify_report()[0],
        "_DecompiledMethodWithPc": dk.decompile_method_with_pc_map(m0),
        "_MethodAstResult": dk.decompile_method_ast(m0),
        "_IdentifyResult": dexllm.identify(dk.apk_path()),
    }
    for name, real in samples.items():
        node = classes.get(name)
        assert node is not None, f"{name} is not declared in the stub"
        declared = {s.target.id for s in node.body if isinstance(s, ast.AnnAssign)}
        assert declared == set(
            real
        ), f"{name}: stub {sorted(declared)} != runtime {sorted(real)}"
