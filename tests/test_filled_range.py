"""`filled-new-array/range` keeps every register of its range (dexllm#97).

DAD's handler (opcode_ins.py:412) passed only the two BOUNDS of the range, so
an array declared with N elements rendered with 2 and the rest became bare
statements nothing read. The oracle here is the smali listing, a different code
path that prints the range as written: for every `/range` site, the array the
decompiler builds must have exactly as many elements as the range is wide.
"""

from __future__ import annotations

import pathlib
import re

import pytest
from conftest import require_corpus_shape

import dexllm

DATA = pathlib.Path(__file__).parent / "data"
RANGE = re.compile(r"filled-new-array/range \{v(\d+) \.\. v(\d+)\}, (\S+)")
PLAIN = re.compile(r"filled-new-array \{([^}]*)\}, (\S+)")


def _widths(smali: str):
    """Element count of every filled-new-array site, in listing order."""
    out = []
    for line in smali.split("\n"):
        m = RANGE.search(line)
        if m:
            out.append(int(m.group(2)) - int(m.group(1)) + 1)
            continue
        m = PLAIN.search(line)
        if m:
            regs = [r for r in m.group(1).split(",") if r.strip()]
            out.append(len(regs))
    return out


def _initializers(node, out):
    if isinstance(node, list):
        if node and node[0] == "ArrayInitializer":
            out.append(len(node[1]))
        for x in node:
            _initializers(x, out)
    return out


def _check(dk, method):
    smali = dk.render_method_smali(method)
    if "fill-array-data" in smali:  # its payload is an initializer too
        return None
    want = _widths(smali)
    if not want:
        return None
    ast = dk.decompile_method_ast(method, include_source=False)["ast"]
    got = _initializers(ast["body"], [])
    assert sorted(got) == sorted(want), (method, want, got)
    return smali


def test_the_fixture_range_keeps_all_fifteen_elements():
    dk = dexllm.DexKit(str(DATA / "negative-statics.dex"))
    method = "LNegativeStatics;->all()[Ljava/lang/Object;"
    assert "filled-new-array/range {v1 .. v15}" in dk.render_method_smali(method)
    assert _check(dk, method) is not None
    text = dk.decompile_method(method)
    # the dropped registers were emitted as statements nothing read
    assert not re.search(r"^\s*\w+\.valueOf\(.*\);$", text, re.M), text
    [line] = [x for x in text.split("\n") if "return new Object[]" in x]
    assert line.count("valueOf(") == 15


@pytest.mark.parametrize("fixture", ["negative-statics.dex", "filled-null.dex"])
def test_every_range_site_in_the_fixtures_matches_its_width(fixture):
    dk = dexllm.DexKit(str(DATA / fixture))
    ranges = 0
    for cls in dk.list_classes():
        for m in dk.list_class_methods(cls):
            smali = _check(dk, m)
            if smali and "filled-new-array/range" in smali:
                ranges += 1
    assert ranges >= 1


def test_every_range_site_in_the_corpus_matches_its_width(loadable_apks):
    ranges = wide = 0
    for apk in loadable_apks:
        dk = dexllm.DexKit(apk)
        for cls in dict.fromkeys(dk.list_classes()):
            if "filled-new-array/range" not in dk.render_class_smali(cls):
                continue
            for m in dk.list_class_methods(cls):
                smali = _check(dk, m)
                if smali:
                    for a, b, _ in RANGE.findall(smali):
                        ranges += 1
                        wide += int(b) - int(a) + 1 > 2
    require_corpus_shape(wide > 0, "a filled-new-array/range wider than 2", "dexllm#97")
    assert ranges >= wide
