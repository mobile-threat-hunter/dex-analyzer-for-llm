"""A ``java.lang`` SUBPACKAGE keeps its package in the Java view (dexllm#111).

``GetType`` drops the ``java.lang.`` prefix because a class directly in
``java.lang`` is implicitly imported. It used to drop it from every class whose
package merely STARTS with ``java/lang/``, so ``java.lang.reflect.Method``
rendered as ``reflect.Method`` -- a name that resolves to no class. Only a class
directly in ``java.lang`` loses the package now; a nested class keeps its
binary ``$`` (that is a separate decision, recorded in dexllm#111).

The oracle is the dex's own type references (``list_external_type_refs``), a
different code path from the Java emitter, and every case runs on committed
fixtures.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

import dexllm

DATA = Path(__file__).parent / "data"
# The committed fixtures that reference java.lang subpackage types.
CARRIERS = ["invoke-custom.dex", "method_handles.dex", "const-method-handle.dex"]


def _java(dk: dexllm.DexKit) -> str:
    return "\n".join(dk.decompile_class(c) for c in dk.list_classes())


def _sub_types(dk: dexllm.DexKit) -> set[str]:
    """Dotted names of every ``java/lang/<sub>/`` type the dex references."""
    out = set()
    for ref in dk.list_external_type_refs():
        d = ref.descriptor.lstrip("[")
        if d.startswith("Ljava/lang/") and "/" in d[len("Ljava/lang/") : -1]:
            out.add(d[1:-1].replace("/", "."))
    return out


@pytest.mark.parametrize("name", CARRIERS)
def test_a_java_lang_subpackage_type_keeps_its_package(name):
    dk = dexllm.DexKit(str(DATA / name))
    text = _java(dk)
    subs = _sub_types(dk)
    assert subs, f"{name} no longer references a java.lang subpackage type"
    seen = 0
    for full in subs:
        simple = full.rsplit(".", 1)[1]
        # Every package-qualified spelling of this class name must be the full
        # one -- not merely "not the old short form" (a third wrong prefix such
        # as `lang.invoke.X` would pass that).
        pat = r"(?<![\w.$])((?:[a-z]\w*\.)+)" + re.escape(simple) + r"(?![\w$])"
        for m in re.finditer(pat, text):
            prefix = m.group(1)
            if not full.endswith("." + prefix + simple) and prefix + simple != full:
                continue  # another class with the same simple name
            assert prefix + simple == full, f"{full} rendered as {m.group(0)!r}"
            seen += 1
    assert seen, f"no java.lang subpackage type is rendered in {name} at all"


def test_a_class_directly_in_java_lang_still_loses_the_package():
    text = _java(dexllm.DexKit(str(DATA / "invoke-custom.dex")))
    assert "Integer.TYPE" in text
    assert "java.lang.Integer" not in text
    assert "java.lang.String" not in text


def test_the_bootstrap_chain_names_its_classes_in_full():
    text = _java(dexllm.DexKit(str(DATA / "invoke-custom.dex")))
    assert "java.lang.invoke.MethodHandles.lookup()" in text
    assert "java.lang.invoke.MethodType.methodType(" in text
    assert re.search(r"(?<![\w.])invoke\.Method", text) is None


def test_the_ast_and_the_text_spell_it_alike():
    """A type node with a descriptor is the full internal name and never
    stripped; a descriptor-less one (a method-handle constant) goes through
    ``GetType`` and is fixed too. Neither may carry the short form."""
    dk = dexllm.DexKit(str(DATA / "invoke-custom.dex"))
    for m in dk.list_methods():
        if "TestLinkerMethodMinimalArguments;->test" not in m:
            continue
        ast = dk.decompile_method_ast(m)
        if "java/lang/invoke/MethodHandles" in repr(ast["ast"]):
            assert "java.lang.invoke.MethodHandles" in ast["source"]
            assert re.search(r"(?<![\w./])invoke[./]Method", repr(ast["ast"])) is None
            return
    pytest.fail("no AST in the fixture names java/lang/invoke/MethodHandles")
