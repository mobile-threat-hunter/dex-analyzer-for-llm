"""Every gate that records a method reference selects the SAME opcodes (dexllm#61).

"Is this instruction an invoke whose operand is a ``method_ids`` index" is spelled
**four times, by hand, in two files**. They must agree, and what they must agree
ON is not a matter of taste: slicer's own instruction table records, per opcode,
what its ``BBBB`` operand *means*. Selecting on anything else is a guess.

Upstream guessed with the instruction FORMAT, and the guess is wrong in both
directions:

* ``filled-new-array`` (0x24/0x25) carries a **type** index, ``invoke-custom``
  (0xFC/0xFD) a **call_site** index and ``invoke-virtual-quick`` (0xE9/0xEA) a
  **vtable offset** — all three are ``k35c``/``k3rc``, so a format-keyed gate
  records all three as method references; on the bundled corpus
  ``filled-new-array`` alone is 624 sites across 4 sources;
* ``invoke-polymorphic`` (0xFA/0xFB) is ``k45cc``/``k4rcc``, so a format-keyed gate
  misses it — which is dexllm#61: ``find_call_sites_to`` answered 0 for
  ``MethodHandle.invoke`` on a dex that plainly calls it.

The one place that guess survived was never called (it was already dead in the
fork snapshot), so it produced no wrong edge; it was removed in dexllm#61 and its
tombstone is in ``dex_item.h``. These tests exist so the next hand-written gate
cannot reintroduce it, and so a future Dalvik invoke form fails CLOSED rather than
being silently skipped by all four.

The truth is derived from the table, which is a source INDEPENDENT of the gates
under audit — they read a different field of the same rows.

Most of these tests parse source files, so they need no corpus and no built
extension. The later sections drive the BUILT extension against three committed
fixtures — ``invoke-custom.dex`` (two 0xFA sites, in blocks that also carry an
ordinary invoke), ``method_handles.dex`` (16 sites, the only file on which the CFG
mark is not masked) and ``invoke-polymorphic.dex`` (the only carrier of 0xFB, and
of a 45cc with the G nibble in use) — so the behaviour is pinned too, and pinned in
a way that survives the corpus-less CI leg and any ``$DEXLLM_TEST_APK`` narrowing.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest
from conftest import REPO_ROOT
from test_arg_opcode_coverage import _strip_comments

_ROOT = Path(__file__).resolve().parent.parent
_TABLE = (
    _ROOT
    / "vendor/dexkit_core/Core/third_party/slicer/export/slicer/dex_instruction_list.h"
)
_DEX_ITEM = _ROOT / "vendor/dexkit_core/Core/dexkit/dex_item.cpp"
_INVOKE_ARGS = _ROOT / "native/core_ext/invoke_args.cpp"

# The two index kinds whose operand IS a `method_ids` index. Every other kind means
# the operand is something else (a type, a call_site, a vtable offset, a proto, a
# method handle), and recording it as a method reference is a fabricated edge.
_METHOD_INDEX_KINDS = ("kIndexMethodRef", "kIndexMethodAndProtoRef")

# The same set, PINNED. `_METHOD_INDEX_KINDS` is a derivation rule that lives in the
# same file as the assertion it feeds, so the cheapest way past a failure is to widen
# it — adding "kIndexCallSiteRef" would make an invoke-custom gate pass. Pinning does
# not make that impossible, but it makes it a deliberate edit in two places rather
# than a one-line "make the test pass". It is also what turns a NEW Dalvik invoke
# form into a failure instead of a silent extension.
_PINNED_METHOD_INDEX_OPCODES = frozenset(
    {
        0x6E,  # invoke-virtual
        0x6F,  # invoke-super
        0x70,  # invoke-direct
        0x71,  # invoke-static
        0x72,  # invoke-interface
        0x74,  # invoke-virtual/range
        0x75,  # invoke-super/range
        0x76,  # invoke-direct/range
        0x77,  # invoke-static/range
        0x78,  # invoke-interface/range
        0xFA,  # invoke-polymorphic
        0xFB,  # invoke-polymorphic/range
    }
)

_ROW = re.compile(
    r"\s*V\(0x([0-9A-Fa-f]{2}),\s*(\w+),\s*\"([^\"]*)\",\s*(\w+),\s*(\w+),"
)


def _table_method_index_opcodes() -> set[int]:
    """Opcodes whose BBBB is a method_ids index, per slicer's own table."""
    rows = 0
    out: set[int] = set()
    for line in _TABLE.read_text().splitlines():
        m = _ROW.match(line)
        if not m:
            continue
        rows += 1
        op, _enum, _name, _fmt, idx = m.groups()
        if idx in _METHOD_INDEX_KINDS:
            out.add(int(op, 16))
    assert rows == 256, f"the slicer table parsed to {rows} rows, not 256"
    return out


def _opcodes_in_condition(text: str) -> set[int]:
    """Opcodes admitted by conditions over `op` in `text`.

    Handles the two forms the gates use: an inclusive range (`op >= 0xAA && op <=
    0xBB`) and an equality (`op == 0xNN`).

    It REFUSES anything else mentioning `op` in a comparison, because the guard
    cannot do boolean algebra and the failure is not symmetric. An adversarial
    review built `((...) && op != 0xfb)` — a gate that silently drops the range
    form — and the extracted set was still EQUAL to the truth, since the
    `op == 0xfb` literal is right there. An earlier docstring here claimed
    unmodelled clauses were "fail-closed because they can only make the set
    SMALLER"; a NEGATED clause makes it LARGER, so that was false. Refusing is the
    only sound option.
    """
    bad = re.findall(r"op\s*(?:!=|<(?!=)|>(?!=))\s*0x[0-9A-Fa-f]+", text)
    assert not bad, (
        "this gate contains an `op` comparison the guard cannot model "
        f"({bad}); it can hide an exclusion behind a literal that IS present"
    )
    out: set[int] = set()
    for lo, hi in re.findall(
        r"op\s*>=\s*0x([0-9A-Fa-f]+)\s*&&\s*op\s*<=\s*0x([0-9A-Fa-f]+)", text
    ):
        out |= set(range(int(lo, 16), int(hi, 16) + 1))
    out |= {int(h, 16) for h in re.findall(r"op\s*==\s*0x([0-9A-Fa-f]+)", text)}
    return out


def _block_at(src: str, i: int) -> str:
    """The brace-matched block starting at the first `{` at or after `i`."""
    start = src.index("{", i)
    depth = 0
    for k in range(start, len(src)):
        if src[k] == "{":
            depth += 1
        elif src[k] == "}":
            depth -= 1
            if depth == 0:
                return src[start : k + 1]
    raise AssertionError("unbalanced braces — the locator needs updating")


def _statement_around(src: str, i: int) -> str:
    """The statement containing offset `i` (previous `;`/`{`/`}` .. next `;`).

    A gate can be a bare assignment or an assignment guarded by an `if`, and the
    opcodes live in the guard. Taking the statement rather than the assignment is
    what makes `if (op == 0xFC) in.invoke = true;` visible.
    """
    lo = max(src.rfind(c, 0, i) for c in ";{}")
    hi = src.index(";", i)
    return src[lo + 1 : hi + 1]


def _gate_init_cache() -> set[int]:
    """The load-time collector that BUILDS `method_invoking_ids`.

    The WHOLE `if (need_method_invoking)` block, not a slice up to the first write:
    a review added a second collector after that write and the slice never saw it.
    """
    src = _strip_comments(_DEX_ITEM.read_text())
    end = src.index("method_invoking_ptr->emplace_back")
    i = src.rindex("if (need_method_invoking)", 0, end)
    return _opcodes_in_condition(_block_at(src, i))


def _gate_enumerate_invoke_sites() -> set[int]:
    """`EnumerateInvokeSites` — turns a claimed caller into per-site rows.

    Its whole body, for the same reason as above.
    """
    src = _strip_comments(_DEX_ITEM.read_text())
    i = src.index("DexItem::EnumerateInvokeSites(")
    return _opcodes_in_condition(_block_at(src, src.index(")", i)))


def _gate_cfg_invoke_mark() -> set[int]:
    """`BuildCfg`'s per-instruction mark: does this block need the extractor?

    EVERY statement that touches `in.invoke`, unioned — a second one elsewhere in
    the function is a gate too, and reading only the first assignment misses it.
    """
    src = _strip_comments(_INVOKE_ARGS.read_text())
    out: set[int] = set()
    n = 0
    for m in re.finditer(r"in\.invoke\b", src):
        out |= _opcodes_in_condition(_statement_around(src, m.start()))
        n += 1
    assert n, "no `in.invoke` statement found — the locator moved"
    return out


def _gate_arg_extractor() -> set[int]:
    """The arms of the extractor switch that EMIT an invoke site.

    Located structurally — a case group whose BRACE-MATCHED body constructs an
    `InvokeSiteWithArgs` — rather than by comment or by scanning to the first
    `break;`. A review wrote an arm opening with `if (!emit) break;`, which put the
    construction after that first `break;` and made the whole arm invisible: the
    mutant added a fabricating `case 0xFC:` and the entire suite stayed green.
    """
    src = _strip_comments(_INVOKE_ARGS.read_text())
    out: set[int] = set()
    for m in re.finditer(r"((?:\s*case 0x[0-9A-Fa-f]+:)+)\s*\{", src):
        if "InvokeSiteWithArgs site;" in _block_at(src, m.end() - 1):
            out |= {int(hx, 16) for hx in re.findall(r"0x([0-9A-Fa-f]+)", m.group(1))}
    return out


_GATES = (
    ("dex_item.cpp: InitCache method_invoking collector", _gate_init_cache),
    ("dex_item.cpp: EnumerateInvokeSites", _gate_enumerate_invoke_sites),
    ("invoke_args.cpp: BuildCfg invoke mark", _gate_cfg_invoke_mark),
    ("invoke_args.cpp: arg-extractor emit arms", _gate_arg_extractor),
)


def test_the_table_and_the_pinned_set_agree() -> None:
    """The derivation rule and the pinned literal describe the same opcodes.

    Fails in two directions on purpose: widening `_METHOD_INDEX_KINDS` (so a
    call_site or vtable operand would count as a method reference), and a future
    Dalvik invoke form arriving in the table — which must be routed to every gate
    deliberately, not absorbed silently.
    """
    assert _table_method_index_opcodes() == set(_PINNED_METHOD_INDEX_OPCODES)


@pytest.mark.parametrize("name,extract", _GATES, ids=[g[0] for g in _GATES])
def test_a_gate_selects_exactly_the_method_index_opcodes(name, extract) -> None:
    truth = _table_method_index_opcodes()
    actual = extract()
    assert actual, f"{name}: extracted nothing — the locator moved, update this test"
    missing = sorted(hex(o) for o in truth - actual)
    extra = sorted(hex(o) for o in actual - truth)
    assert actual == truth, (
        f"{name} disagrees with slicer's table.\n"
        f"  missing (BBBB IS a method index, gate skips it): {missing}\n"
        f"  extra   (BBBB is NOT a method index, gate records it): {extra}"
    )


def test_no_gate_selects_invokes_by_instruction_format() -> None:
    """The format-keyed predicate dexllm#61 removed does not come back.

    A gate that tests `op_format == k35c` admits `filled-new-array` and
    `invoke-custom`, and misses `invoke-polymorphic` — the whole defect. The
    parametrised test above catches it by its RESULT; this catches it by its shape,
    so the failure names the cause rather than an opcode-set diff.

    Scoped to the two files that carry the gates. Format-keyed code is legitimate
    elsewhere (the smali emitter formats BY format, which is what format is for).
    """
    for path in (_DEX_ITEM, _INVOKE_ARGS):
        src = _strip_comments(path.read_text())
        hits = re.findall(
            r"(?:op_format|ins_formats\s*\[\s*op\s*\])\s*==\s*dex::k3(?:5c|rc)", src
        )
        assert not hits, (
            f"{path.name} selects on instruction format again ({len(hits)} site(s)); "
            "the operand's MEANING is the index type, not the format — see dexllm#61"
        )


def test_the_removed_upstream_function_stays_removed() -> None:
    """`GetInvokeMethodsFromCode` is gone, and its tombstone explains why.

    Deleting a function from a vendored fork leaves no trace unless someone writes
    one, and this repo's convention is an in-source tombstone (dexllm#65 tracks the
    fact that the convention is not otherwise checked). This pins both halves.
    """
    header = _ROOT / "vendor/dexkit_core/Core/dexkit/include/dex_item.h"
    assert "GetInvokeMethodsFromCode" not in _DEX_ITEM.read_text()
    text = header.read_text()
    assert "GetInvokeMethodsFromCode" in text, "the tombstone naming it was removed"
    assert "REMOVED" in text and "dexllm#61" in text


# -- the behaviour, on the container this repo commits -------------------------

_FIXTURE = REPO_ROOT / "tests" / "data" / "invoke-custom.dex"
_MH_INVOKE = (
    "Ljava/lang/invoke/MethodHandle;->invoke([Ljava/lang/Object;)Ljava/lang/Object;"
)
_MH_TYPE = "Ljava/lang/invoke/MethodHandle;->type()Ljava/lang/invoke/MethodType;"


@pytest.fixture(scope="module")
def fixture_dk():
    dexllm = pytest.importorskip("dexllm")
    if not _FIXTURE.is_file():  # pragma: no cover - the file is committed
        pytest.skip("tests/data/invoke-custom.dex missing")
    return dexllm.DexKit(str(_FIXTURE))


def test_a_polymorphic_call_site_is_answered(fixture_dk) -> None:
    """dexllm#61's observable half: the xref used to answer 0 here.

    The fixture calls `MethodHandle.invoke` twice from one method, and the target is
    in `list_external_method_refs()` either way — the dex plainly references it. What
    was missing was the edge, so "who invokes this method handle" was silently
    unanswerable and every consumer built on the caller xref inherited the hole.
    """
    sites = fixture_dk.find_call_sites_to(_MH_INVOKE)
    assert len(sites) == 2, f"expected both invoke-polymorphic sites, got {len(sites)}"
    assert {s.invoke_opcode for s in sites} == {0xFA}
    assert {s.caller_descriptor for s in sites} == {
        "LMain;->TestUninitializedCallSite()V"
    }
    assert {s.bytecode_offset for s in sites} == {0x1E, 0x7A}


def test_a_polymorphic_call_site_resolves_its_arguments(fixture_dk) -> None:
    """The arg extractor reaches it too — and pins the registers it reports.

    The CFG mark decides whether the block runs at all, the emit arm decides whether
    a site is produced, and the caller index decides whether the target is looked up.
    But on THIS fixture the CFG mark is masked (those blocks carry an ordinary invoke
    as well), so reverting it leaves this test green — `test_the_cfg_mark_is_load_bearing`
    is the one that dies. An earlier docstring here claimed "a fix to any two of them
    leaves this at 0", which a review disproved by building exactly that mutant.
    """
    rows = sorted(
        fixture_dk.resolve_call_args(_MH_INVOKE), key=lambda r: r.bytecode_offset
    )
    assert len(rows) == 2
    # The VALUES, not `all(r.args)`. A review swapped `case 0xFA` into the 3rc arm
    # and read the 45cc count from AA instead of the B nibble; both mutants pass a
    # non-emptiness assertion while emitting 48 and 5 fabricated arguments. Ground
    # truth is androguard's own decode of this file: `{v1}` at 0x1e, `{v1,v2,v3}`
    # at 0x7a.
    assert [[a.reg_num for a in r.args] for r in rows] == [[1], [1, 2, 3]]


def test_an_ordinary_invoke_is_unaffected(fixture_dk) -> None:
    """Non-discriminating BY DESIGN — it must hold on both sides of the change.

    It pins the half that was already right, so a fix that widened the gates by
    breaking the ordinary path cannot pass.
    """
    sites = fixture_dk.find_call_sites_to(_MH_TYPE)
    assert len(sites) == 4
    assert {s.invoke_opcode for s in sites} == {0x6E}


def test_no_call_site_carries_an_opcode_that_is_not_a_method_reference(
    fixture_dk,
) -> None:
    """The EXTRA direction, on a dex that has the bait.

    This fixture carries 46 `invoke-custom` sites, whose operand is a `call_site`
    index. A gate that admitted them — which a format-keyed one does — would emit
    rows naming whatever `method_ids` entry that index happens to hit.

    INTERNAL targets are queried as well as external ones, and that is the whole
    test: a call_site index is small, so it lands on a low `method_ids` entry, which
    on any real dex is an app method rather than a framework reference. An
    external-only sweep passed against a mutant that admits `invoke-custom` in every
    gate; widening it to declared methods surfaces 40 fabricated rows on this
    fixture, e.g. "TestBadBootstrapArguments.test() calls Main.<init>()".

    It also needs BOTH the map builder and the site enumerator to be wrong before it
    can fire — a phantom in one alone is filtered by the other — so the per-gate
    source tests above remain the only thing that catches a single-gate slip.
    """
    seen = set()
    targets = [
        # `.signature`, not a `__repr__` slice: this repo has changed `__repr__`
        # twice (dexllm#22, #29), and a malformed descriptor would make every
        # external query return [] while the test still passed on the internal
        # targets alone.
        r.signature
        for r in fixture_dk.list_external_method_refs()
    ]
    targets += [
        m for c in fixture_dk.list_classes() for m in fixture_dk.list_class_methods(c)
    ]
    for desc in targets:
        for s in fixture_dk.find_call_sites_to(desc):
            seen.add(s.invoke_opcode)
    assert seen, "no call site at all — the fixture or the resolver changed"
    assert seen <= set(_PINNED_METHOD_INDEX_OPCODES), (
        f"a call site was reported with opcode(s) {sorted(hex(o) for o in seen - set(_PINNED_METHOD_INDEX_OPCODES))}, "
        "whose operand is not a method_ids index"
    )


# -- the CFG mark, which the invoke-custom fixture cannot show -----------------

_METHOD_HANDLES = REPO_ROOT / "tests" / "data" / "method_handles.dex"
_MH_INVOKE_EXACT = "Ljava/lang/invoke/MethodHandle;->invokeExact([Ljava/lang/Object;)Ljava/lang/Object;"


@pytest.fixture(scope="module")
def polymorphic_dk():
    dexllm = pytest.importorskip("dexllm")
    if not _METHOD_HANDLES.is_file():  # pragma: no cover - the file is committed
        pytest.skip("tests/data/method_handles.dex missing")
    return dexllm.DexKit(str(_METHOD_HANDLES))


def test_every_polymorphic_site_in_the_file_is_answered(polymorphic_dk) -> None:
    """All 16 of them — the issue's own headline number, pinned.

    16 is not a guess: the file renders exactly 16 `invoke-polymorphic` lines, and
    before the fix `find_call_sites_to` answered 0 for both targets while both were
    present in `list_external_method_refs()`.
    """
    invoke = polymorphic_dk.find_call_sites_to(_MH_INVOKE)
    exact = polymorphic_dk.find_call_sites_to(_MH_INVOKE_EXACT)
    assert (len(invoke), len(exact)) == (10, 6)
    assert {s.invoke_opcode for s in invoke + exact} == {0xFA}


def test_the_cfg_mark_is_load_bearing(polymorphic_dk) -> None:
    """This is the ONLY behavioural guard for `BuildCfg`'s invoke mark.

    On `invoke-custom.dex` the two polymorphic sites sit in blocks that also carry an
    ordinary invoke, so the block is marked anyway and reverting the mark is MASKED
    there — measured: `resolve_call_args` stays at 2. Here the same revert takes it
    from 10 to 0, because the extractor never runs on those blocks at all.

    So the assertion is deliberately on `resolve_call_args`, not on
    `find_call_sites_to`: the latter survives that revert (it is fed by a different
    gate) and would make this test pass against the defect.
    """
    rows = polymorphic_dk.resolve_call_args(_MH_INVOKE)
    assert len(rows) == 10, f"the extractor produced {len(rows)} rows, expected 10"
    # Every site here is `invoke-polymorphic {v0, v2, v3}` at 0x4 (androguard oracle).
    assert [[a.reg_num for a in r.args] for r in rows] == [[0, 2, 3]] * 10


# -- 0xFB, and the verifier bound this change made necessary -------------------

_POLY = REPO_ROOT / "tests" / "data" / "invoke-polymorphic.dex"


@pytest.fixture(scope="module")
def range_dk():
    dexllm = pytest.importorskip("dexllm")
    if not _POLY.is_file():  # pragma: no cover - the file is committed
        pytest.skip("tests/data/invoke-polymorphic.dex missing")
    return dexllm.DexKit(str(_POLY))


def test_the_range_form_is_answered_with_its_full_register_window(range_dk) -> None:
    """0xFB — the half that had NO behavioural coverage anywhere in the repo.

    Both reviews found it independently: neither of the other fixtures carries an
    `invoke-polymorphic/range`, the gitignored corpus has none, and dexllm#58's
    verifier guard is 0xFA-only. That left two mutants alive — moving `case 0xFB`
    into the 45cc arm (the source guard sees the arms' UNION, so it passes), and
    excluding 0xFB with a negated clause while leaving its literal in place.

    The register list is the assertion, not the row count: the range form's whole
    contract is `{vC .. vC+vA-1}`, and the arm-swap mutant collapses this 7-register
    window to empty.
    """
    rows = range_dk.resolve_call_args(_MH_INVOKE)
    by_op = {r.invoke_opcode: [a.reg_num for a in r.args] for r in rows}
    assert 0xFB in by_op, "the range form produced no row at all"
    assert by_op[0xFB] == [0, 1, 2, 3, 4, 5, 6]
    # …and the 45cc sibling in the same file uses the G nibble (A=5), which the
    # other two fixtures never exercise.
    assert by_op[0xFA] == [0, 1, 2, 3, 4]


def test_both_polymorphic_forms_reach_the_caller_index(range_dk) -> None:
    sites = range_dk.find_call_sites_to(_MH_INVOKE)
    assert {s.invoke_opcode for s in sites} == {0xFA, 0xFB}


def test_an_out_of_range_polymorphic_method_index_is_rejected(tmp_path) -> None:
    """The bound dexllm#61 was OBLIGED to add, by the verifier's own comment.

    `VerifyInsns` left `kIndexMethodAndProtoRef` unbounded and said so, with the
    condition attached: "that is safe only because nothing dereferences them … so a
    consumer that starts reading them must add the bound in the same change."
    dexllm#61 is that consumer. Without the bound a STRICT-verified dex yields a
    call site whose `callee_descriptor` is empty — a shape that was previously
    reachable only under `lenient=True`.

    Length-preserving: one `u2` (the BBBB of the first 0xFA), so every offset and
    section size is untouched and nothing else can be what rejects.
    """
    import struct

    dexllm = pytest.importorskip("dexllm")
    raw = bytearray(_METHOD_HANDLES.read_bytes())
    off = raw.find(bytes([0xFA, 0x30]))  # `A|G op` unit of an invoke-polymorphic
    if off < 0 or off % 2:  # pragma: no cover - the committed file has one
        pytest.skip("no invoke-polymorphic window found in the fixture")
    assert struct.unpack_from("<H", raw, off + 2)[0] < 0xFFFF
    struct.pack_into("<H", raw, off + 2, 0xFFFF)
    dst = tmp_path / "oob.dex"
    dst.write_bytes(bytes(raw))

    strict = dexllm.verify(str(dst))
    assert not strict[0]["valid"]
    assert "method index" in strict[0]["reason"]
    # lenient skips VerifyInsns wholesale by design, so it still loads — that is the
    # documented GIGO boundary, not a hole this test should close.
    assert dexllm.verify(str(dst), lenient=True)[0]["valid"]
