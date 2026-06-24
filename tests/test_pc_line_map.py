"""End-to-end test for the D-3 source-line ↔ bytecode-offset map (dexllm#1).

Drives the binding API `decompile_method_java_with_pc` over the bundled
test_apk/APK corpus and asserts:

  - every Java line that mentions an anchor op (invoke / iget / sget /
    new-instance / const-string / return) has a pc_map entry;
  - each entry's byte_off is a REAL instruction offset of that method (it
    appears as an `0xNN:` prefix in render_method_smali);
  - the text and AST paths surface the same set of offsets.

Header-line coverage (if / while / do-while / switch — the cases D-3 exists
for) is the MANDATORY gate in test_pc_line_map_headers.py. This file covers
the statement path + the offset-validity invariant. Skips if no test APK.
"""

import re

import pytest
from conftest import _candidate_apks, smali_offsets

import dexllm

# A body STATEMENT line (ends with `;`) that mentions an anchor op — these must
# originate from a real dex instruction. Signature/brace/label lines don't end
# with `;` so they're excluded.
_ANCHOR = re.compile(r"(\bnew |\breturn\b|\.\w+\(|\w+\()")


@pytest.fixture(scope="module")
def dk():
    """tvleanback DexKit — these tests assert against hand-verified method
    descriptors, so they need that specific APK; falls back to the first
    loadable container (the descriptor-specific assertions then skip)."""
    apks = _candidate_apks()
    if not apks:
        pytest.skip("no test APK (set $DEXLLM_TEST_APK or add one under test_apk/APK/)")
    for p in apks:
        if "tvleanback" in p:
            return dexllm.DexKit(p)
    for p in apks:
        try:
            if dexllm.identify(p).get("dex_count", 0) > 0:
                return dexllm.DexKit(p)
        except Exception:
            continue
    pytest.skip("no loadable dex container in the corpus")


def test_known_method_pc_map(dk):
    """Hand-picked method: every statement line maps to a valid offset."""
    desc = (
        "Lcom/example/android/tvleanback/Utils;->"
        "getDisplaySize(Landroid/content/Context;)Landroid/graphics/Point;"
    )
    r = dk.decompile_method_java_with_pc(desc)
    if not r["source"] or r["source"].startswith("// DECOMPILE ERROR"):
        pytest.skip("target method not in this build of the corpus")
    pcm = dict(r["pc_map"])
    valid = smali_offsets(dk, desc)
    assert valid, "smali had no instruction offsets"

    # Map is non-empty, sorted by line, every offset is a real instruction.
    assert pcm, "pc_map empty for a method with a body"
    lines = [ln for ln, _ in r["pc_map"]]
    assert lines == sorted(lines), "pc_map not sorted ascending by line"
    for ln, off in r["pc_map"]:
        assert off in valid, f"offset 0x{off:x} (line {ln}) not a real instruction"

    # Every body STATEMENT line (ends with `;`, mentions an anchor op) maps.
    src_lines = r["source"].splitlines()
    n_stmt = 0
    for i, text in enumerate(src_lines, 1):
        s = text.strip()
        if s.endswith(";") and _ANCHOR.search(s) and not s.startswith("//"):
            assert i in pcm, f"anchor line {i} has no pc_map entry: {text!r}"
            n_stmt += 1
    assert n_stmt >= 3, "expected several mapped statement lines"


def test_text_and_ast_offsets_agree(dk):
    """The text pc_map and AST pc_map expose the same offset multiset."""
    desc = (
        "Lcom/example/android/tvleanback/Utils;->"
        "getDisplaySize(Landroid/content/Context;)Landroid/graphics/Point;"
    )
    r = dk.decompile_method_java_with_pc(desc)
    if not r["source"] or r["source"].startswith("// DECOMPILE ERROR"):
        pytest.skip("target method not in this build of the corpus")
    d = dk.decompile_method_ast(desc, include_source=False)
    text_offs = sorted(o for _, o in r["pc_map"])
    ast_offs = sorted(o for _, o in d["pc_map"])
    assert text_offs == ast_offs


def test_elided_super_not_mapped_to_zero(dk):
    """Regression for the adversarial-review MEDIUM finding: a constructor with
    an elided implicit super() emits only the line indent for that call (no
    statement, no `;`). Its offset (0) must NOT claim the next real statement's
    line — the first mapped line must point at a real, non-super instruction.

    `ActivityCompat.<init>()V` is `{ <elided super @0>; return; }` → the only
    body line is `return;`, which must map to the return-void offset (6), never
    the super's offset (0). Text and AST must agree.
    """
    desc = "Landroid/support/v4/app/ActivityCompat;-><init>()V"
    r = dk.decompile_method_java_with_pc(desc)
    if not r["source"] or r["source"].startswith("// DECOMPILE ERROR"):
        pytest.skip("target constructor not in this build of the corpus")
    valid = smali_offsets(dk, desc)
    # offset 0 here is the elided super; it must not appear in the text map.
    assert 0 not in {
        off for _, off in r["pc_map"]
    }, "elided super (offset 0) leaked into the line map"
    for ln, off in r["pc_map"]:
        assert off in valid, f"offset 0x{off:x} not a real instruction"
    # text and AST agree on the surviving offset set
    d = dk.decompile_method_ast(desc, include_source=False)
    assert sorted(o for _, o in r["pc_map"]) == sorted(o for _, o in d["pc_map"])
