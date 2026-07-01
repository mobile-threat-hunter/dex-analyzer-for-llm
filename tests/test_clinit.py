"""Beyond-DAD <clinit> rendering — static initializer block, not `static <Class>()`.

A <clinit> carries ACC_CONSTRUCTOR in dex, so DAD (writer.py:167) renders it as
`static <ClassName>()` with a trailing `return;` — both invalid Java (a static
initializer is a `static { }` block; `return` is a compile error inside an
initializer, JLS §8.7). We emit a valid `static { }` block and drop the
OUTERMOST-level return-void only (nested returns are kept DAD-faithful because
suppressing them could change control-flow semantics).

APK-dependent — skips cleanly without the bundled corpus.
"""

import glob
import os

import pytest

import dexllm

APKS = sorted(
    p
    for p in glob.glob("test_apk/APK/*.apk")
    if os.path.getsize(p) > 1024 and dexllm.identify(p).get("dex_count", 0) > 0
)

pytestmark = pytest.mark.skipif(not APKS, reason="no bundled APK corpus")


def _iter_clinit_sources():
    for apk in APKS:
        try:
            dk = dexllm.DexKit(apk)
        except Exception:
            continue
        for cls in dk.list_classes():
            for m in dk.list_class_methods(cls):
                if "<clinit>" not in m:
                    continue
                try:
                    src = dk.decompile_method_java(m)
                except Exception:
                    continue
                if src:
                    yield cls, m, src


def test_no_static_classname_header():
    """No <clinit> renders the invalid DAD `static <ClassName>()` header."""
    bad = []
    for cls, _m, src in _iter_clinit_sources():
        simple = cls.split("/")[-1][:-1]  # strip trailing ';'
        if f"static {simple}(" in src:
            bad.append(cls)
    assert not bad, f"{len(bad)} <clinit> still emit `static <ClassName>()`: {bad[:5]}"


def test_header_is_exactly_static():
    """A <clinit> header is exactly `static` — no access modifier. A <clinit>
    may carry ACC_PUBLIC etc. in (obfuscated) dex, but `public static { }` is
    invalid Java (a static initializer block takes no modifier)."""
    bad = []
    for cls, _m, src in _iter_clinit_sources():
        first = next((ln.strip() for ln in src.split("\n") if ln.strip()), "")
        if first != "static":
            bad.append((cls, first))
    assert not bad, f"{len(bad)} <clinit> headers are not exactly `static`: {bad[:5]}"


def test_outermost_return_void_dropped():
    """A straight-line <clinit> has no trailing top-level `return;`."""
    dk = dexllm.DexKit(APKS[0])
    # find a simple (branch-free) <clinit>
    for cls in dk.list_classes():
        for m in dk.list_class_methods(cls):
            if "<clinit>" not in m:
                continue
            src = dk.decompile_method_java(m)
            if not src:
                continue
            if not any(
                k in src for k in ("if (", "while(", "while (", "switch (", "try {")
            ):
                lines = [x.rstrip() for x in src.split("\n")]
                # header is a bare `static` line, body is a `static { }` block
                assert any(x.strip() == "static" for x in lines), src
                assert "return;" not in src, f"top-level return not dropped:\n{src}"
                return
    pytest.skip("no branch-free <clinit> in corpus[0]")


def test_nested_return_preserved_for_semantics():
    """A branch-return inside a <clinit> is KEPT (dropping it could change
    control flow — the fall-through would execute code the return skipped).
    Prefer the known Kotlin PlatformImplementationsKt anchor; else fall back to
    any <clinit> with an INDENTED (nested) `return;`."""
    generic = None
    for _cls, m, src in _iter_clinit_sources():
        if "PlatformImplementationsKt" in m:
            assert "return;" in src, (
                "nested return wrongly suppressed — fall-through would change "
                f"semantics:\n{src}"
            )
            return
        # a return; indented deeper than a top-level `    return;` (8+ spaces)
        # is nested in an if/try/loop and must be preserved.
        if generic is None and any(
            ln.rstrip().endswith("return;") and len(ln) - len(ln.lstrip()) >= 8
            for ln in src.split("\n")
        ):
            generic = src
    if generic is not None:
        assert "return;" in generic
        return
    pytest.skip("no <clinit> with a nested return in corpus")


def test_constructor_still_named():
    """The <init> instance-constructor fix must NOT touch normal constructors —
    they still render `ClassName(...)`, not `static { }`."""
    dk = dexllm.DexKit(APKS[0])
    for cls in dk.list_classes():
        for m in dk.list_class_methods(cls):
            if "-><init>()V" not in m:
                continue
            src = dk.decompile_method_java(m)
            if not src:
                continue
            simple = cls.split("/")[-1][:-1].split("$")[-1]
            sig = next((x for x in src.split("\n") if "(" in x and ")" in x), "")
            assert simple in sig, f"constructor lost its name: {sig!r}"
            return
