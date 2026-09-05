"""dexllm#84 — the field cross-reference's rows carry the instruction.

`find_field_read_sites` / `find_field_write_sites` return one `FieldAccessSite`
per `iget*`/`iput*`/`sget*`/`sput*` INSTRUCTION. Before this they were
`find_methods_reading_field` / `find_methods_writing_field` returning bare method
descriptors under the same per-instruction contract, so a method reading the field
four times produced four IDENTICAL strings: the contract held in the COUNT and was
lost in the VALUE, and the instructions were unobtainable at any price.

Two layers, and the matrix says they are complementary:

  * a SOURCE-derived gate check — the enumerator must select exactly the opcodes
    slicer's own table calls `kIndexFieldRef`, which is what makes a FUTURE Dalvik
    field form a failure rather than a silent omission (the dexllm#61 shape);
  * behavioural guards on COMMITTED fixtures, so they run in the corpus-less CI
    leg and under any `$DEXLLM_TEST_APK` narrowing, plus one corpus-gated case for
    the cross-dex shape no committed fixture carries.

Ground truth is `render_method_smali`, which is a different code path from the one
under test: it decodes the instruction stream itself and prints each access at its
own offset.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest
from conftest import require_corpus_shape
from test_arg_opcode_coverage import _strip_comments

_ROOT = Path(__file__).resolve().parent.parent
_TABLE = (
    _ROOT
    / "vendor/dexkit_core/Core/third_party/slicer/export/slicer/dex_instruction_list.h"
)
_EXT = _ROOT / "native/core_ext/dexkit_ext.cpp"
_DATA = Path(__file__).resolve().parent / "data"

# A committed fixture with 21 fields / 187 access sites, static AND instance
# accesses, and nine fields a single method touches more than once.
_RICH = _DATA / "invoke-custom.dex"
# `Jazzer.<clinit>` reads `Integer.TYPE` SEVEN times — the sharpest statement of
# "the duplicates are distinct records" any fixture in the tree offers.
_MANY = _DATA / "method_handles.dex"
_MANY_FIELD = "Ljava/lang/Integer;->TYPE:Ljava/lang/Class;"
_MANY_METHOD = "Lcom/code_intelligence/jazzer/api/Jazzer;-><clinit>()V"

_ROW = re.compile(
    r"\s*V\(0x([0-9A-Fa-f]{2}),\s*(\w+),\s*\"([^\"]*)\",\s*(\w+),\s*(\w+),"
)

# The opcodes whose operand IS a `field_ids` index, PINNED. `kIndexFieldRef` is a
# derivation rule that lives beside the assertion it feeds, so pinning is what
# stops the cheapest way past a failure — widening the rule — and what turns a new
# Dalvik field form into a failure instead of a silent extension. The quick family
# (0xE3..0xF2) is `kIndexFieldOffset`: its operand is a vtable/field OFFSET, and
# recording it as a field reference is the confusion dexllm#61 removed from the
# invoke gates.
_PINNED_FIELD_INDEX_OPCODES = frozenset(range(0x52, 0x6E))
_READ_OPCODES = frozenset(list(range(0x52, 0x59)) + list(range(0x60, 0x67)))
_WRITE_OPCODES = _PINNED_FIELD_INDEX_OPCODES - _READ_OPCODES


def _table_field_index_opcodes() -> set[int]:
    """Opcodes whose operand is a field_ids index, per slicer's own table."""
    rows = 0
    out: set[int] = set()
    for line in _TABLE.read_text().splitlines():
        m = _ROW.match(line)
        if not m:
            continue
        rows += 1
        op, _enum, _name, _fmt, idx = m.groups()
        if idx == "kIndexFieldRef":
            out.add(int(op, 16))
    assert rows == 256, f"the slicer table parsed to {rows} rows, not 256"
    return out


def _gate_enumerate_field_sites() -> set[int]:
    """The opcodes `EnumerateFieldAccessSites` admits, read from the source.

    BOTH halves, because an adversarial reviewer widened the gate at the CALL SITE
    (`if (IsFieldAccessOpcode(op) || (op >= 0xe3 && op <= 0xf2))`) and this parser,
    which read only the helper's body, was blind to it — the mutant passed the whole
    suite while FABRICATING a field write out of a vtable offset.
    """
    src = _strip_comments(_EXT.read_text())
    m = re.search(
        r"constexpr bool IsFieldAccessOpcode\(uint8_t op\)[^\n]*\n?[^\n]*", src
    )
    assert m, "IsFieldAccessOpcode is gone — the field-site gate moved"
    body = m.group(0)
    lo, hi = re.findall(r"op\s*[<>]=\s*0x([0-9a-fA-F]+)", body)
    assert re.search(
        r"op\s*>=\s*0x[0-9a-fA-F]+\s*&&\s*op\s*<=\s*0x[0-9a-fA-F]+", body
    ), (
        f"the gate is no longer a single inclusive range, so this parser cannot "
        f"read it: {body!r}"
    )
    # The enumerator's own condition must be the BARE call — no `||`, no second
    # comparison on `op`, nothing the helper's body cannot express.
    fn = src[src.index("std::vector<FieldSite> EnumerateFieldAccessSites(") :]
    cond = re.search(r"\n *if \((.*)\) \{\n *FieldSite site;", fn)
    assert cond, "the enumerator's admission condition moved — this parser is stale"
    assert (
        cond.group(1).strip() == "IsFieldAccessOpcode(op)"
    ), f"the enumerator admits opcodes its helper does not: {cond.group(1)!r}"
    return set(range(int(lo, 16), int(hi, 16) + 1))


def _read_write_gate() -> set[int]:
    """The opcodes `IsFieldReadOpcode` calls READS, read from the source."""
    src = _strip_comments(_EXT.read_text())
    m = re.search(
        r"constexpr bool IsFieldReadOpcode\(uint8_t op\)\s*\{(.*?)\}", src, re.S
    )
    assert m, "IsFieldReadOpcode is gone — the direction filter moved"
    pairs = re.findall(
        r"op\s*>=\s*0x([0-9a-fA-F]+)\s*&&\s*op\s*<=\s*0x([0-9a-fA-F]+)", m.group(1)
    )
    assert pairs, f"cannot read the read-opcode ranges from {m.group(1)!r}"
    out: set[int] = set()
    for lo, hi in pairs:
        out |= set(range(int(lo, 16), int(hi, 16) + 1))
    return out


# --- the gate, derived twice and pinned --------------------------------------


def test_the_table_and_the_pinned_set_agree() -> None:
    """The pin is a second statement of the same fact, from slicer's own table."""
    assert _table_field_index_opcodes() == set(_PINNED_FIELD_INDEX_OPCODES)


def test_the_field_site_gate_selects_exactly_the_field_index_opcodes() -> None:
    """The enumerator must admit every field-REFERENCE opcode and nothing else.

    Nothing else: a quick form's operand is an OFFSET, so admitting one fabricates
    a field reference out of a vtable slot.
    """
    assert _gate_enumerate_field_sites() == set(_PINNED_FIELD_INDEX_OPCODES)


def test_the_direction_filter_splits_the_gate_exactly() -> None:
    """Reads and writes must PARTITION the gate — no opcode in both or neither."""
    assert _read_write_gate() == set(_READ_OPCODES)
    assert _READ_OPCODES | _WRITE_OPCODES == set(_PINNED_FIELD_INDEX_OPCODES)
    assert not (_READ_OPCODES & _WRITE_OPCODES)


# --- behavioural, on committed fixtures ---------------------------------------


@pytest.fixture(scope="module")
def rich_dk():
    import dexllm

    return dexllm.DexKit(str(_RICH))


@pytest.fixture(scope="module")
def many_dk():
    import dexllm

    return dexllm.DexKit(str(_MANY))


def _smali_accesses(dk, method: str, field: str) -> dict[int, str]:
    """Offset -> mnemonic for every access of `field` in `method`, from the smali.

    Independent of the code under test: the renderer decodes the instruction
    stream itself and prints one line per instruction at its own offset.
    """
    out: dict[int, str] = {}
    for line in dk.render_method_smali(method).splitlines():
        head, _, rest = line.strip().partition(": ")
        if not rest or not head.startswith("0x") or not rest.endswith(field):
            continue
        out[int(head, 16)] = rest.split(" ", 1)[0]
    return out


def test_a_method_accessing_a_field_seven_times_yields_seven_distinct_rows(many_dk):
    """The headline: repeats are DISTINCT records, not one string repeated.

    Pinned as literal offsets, because a guard asserting only "the offsets differ"
    passes against a build that fabricates an increasing counter.
    """
    sites = many_dk.find_field_read_sites(_MANY_FIELD)
    mine = [s for s in sites if s.method_descriptor == _MANY_METHOD]
    assert [s.bytecode_offset for s in mine] == [186, 198, 266, 322, 334, 384, 402]
    assert len({s.bytecode_offset for s in mine}) == 7
    assert {s.method_descriptor for s in mine} == {_MANY_METHOD}, "one method"


def test_every_offset_is_a_real_access_of_that_field(rich_dk):
    """Ground-truthed against the smali: no fabricated offset, no wrong mnemonic."""
    checked = 0
    for fd in rich_dk.list_fields():
        for reading, sites in (
            (True, rich_dk.find_field_read_sites(fd)),
            (False, rich_dk.find_field_write_sites(fd)),
        ):
            for site in sites:
                accesses = _smali_accesses(rich_dk, site.method_descriptor, fd)
                assert site.bytecode_offset in accesses, (
                    f"{site.method_descriptor} reports an access of {fd} at "
                    f"{site.bytecode_offset:#x}; the smali has them only at "
                    f"{sorted(accesses)}"
                )
                mnemonic = accesses[site.bytecode_offset]
                assert (
                    mnemonic.endswith("get")
                    or "get-" in mnemonic
                    or (mnemonic.endswith("put") or "put-" in mnemonic)
                )
                assert ("get" in mnemonic) is reading, (
                    f"{fd} at {site.bytecode_offset:#x} is a {mnemonic} but was "
                    f"reported as a {'read' if reading else 'write'}"
                )
                checked += 1
    assert checked >= 150, f"the fixture yielded only {checked} sites"


def test_the_rows_are_complete_against_the_smali(rich_dk):
    """Not only sound but COMPLETE: every access in the body is reported.

    Without this a build that emits the FIRST access per method passes every other
    assertion here — the exact half-fix the issue is about.
    """
    for fd in rich_dk.list_fields():
        reads = rich_dk.find_field_read_sites(fd)
        writes = rich_dk.find_field_write_sites(fd)
        for method in {s.method_descriptor for s in reads + writes}:
            accesses = _smali_accesses(rich_dk, method, fd)
            reported = {
                s.bytecode_offset
                for s in reads + writes
                if s.method_descriptor == method
            }
            assert reported == set(accesses), (
                f"{method} accesses {fd} at {sorted(accesses)} but the xref "
                f"reports {sorted(reported)}"
            )


def test_a_row_identifies_its_method_by_dex_and_idx(rich_dk):
    """`dex_id` + `method_idx` must resolve to the row's own method_descriptor."""
    by_dex = {d: rich_dk.list_methods_in_dex(d) for d in range(rich_dk.dex_count())}
    seen = 0
    for fd in rich_dk.list_fields():
        for site in rich_dk.find_field_read_sites(fd) + rich_dk.find_field_write_sites(
            fd
        ):
            table = by_dex[site.dex_id]
            assert site.method_idx < len(table)
            assert table[site.method_idx] == site.method_descriptor
            seen += 1
    assert seen >= 150, f"only {seen} rows checked"


def test_every_row_names_the_queried_field(rich_dk):
    """`field_descriptor` is constant across a query's rows — it IS the query."""
    seen = 0
    for fd in rich_dk.list_fields():
        for site in rich_dk.find_field_read_sites(fd) + rich_dk.find_field_write_sites(
            fd
        ):
            assert site.field_descriptor == fd
            seen += 1
    assert seen >= 150


@pytest.mark.parametrize("writes", [False, True])
def test_a_rows_opcode_matches_the_direction_that_produced_it(rich_dk, writes):
    """A read row carries a read opcode and a write row a write one.

    The reverse index only says the method touches the field; the SAME method may
    do both, so the direction has to be decided per SITE. Without that filter a
    read query returns the writes too.
    """
    wanted = _WRITE_OPCODES if writes else _READ_OPCODES
    seen = 0
    for fd in rich_dk.list_fields():
        rows = (
            rich_dk.find_field_write_sites(fd)
            if writes
            else rich_dk.find_field_read_sites(fd)
        )
        for site in rows:
            assert site.opcode in wanted, (
                f"{fd} {'write' if writes else 'read'} row carries " f"{site.opcode:#x}"
            )
            seen += 1
    assert seen >= 10, f"only {seen} {'write' if writes else 'read'} rows"


def test_a_static_access_is_distinguishable_without_resolving_the_field(rich_dk):
    """`opcode` says static-ness, which is half of why the field carries one.

    The fixture holds both an `sget` (0x60..0x66) and an `iget` (0x52..0x58) of
    real fields, so both halves are exercised rather than asserted.
    """
    kinds = set()
    for fd in rich_dk.list_fields():
        for site in rich_dk.find_field_read_sites(fd):
            kinds.add("static" if site.opcode >= 0x60 else "instance")
    assert kinds == {"static", "instance"}, kinds


def test_no_two_rows_are_the_same_record(rich_dk):
    """The point of the change: a repeat must be a DIFFERENT instruction.

    `(dex_id, method_idx, bytecode_offset)` is the row's identity, and two rows
    sharing it would be the old `list[str]` defect with more fields attached.
    Measured 0 such rows over 463,954 — the whole bundled corpus plus every
    committed fixture, the same population the a/b counts.
    """
    for fd in rich_dk.list_fields():
        for rows in (
            rich_dk.find_field_read_sites(fd),
            rich_dk.find_field_write_sites(fd),
        ):
            keys = [(s.dex_id, s.method_idx, s.bytecode_offset) for s in rows]
            assert len(set(keys)) == len(keys), f"{fd}: repeated row identity"


def test_the_rows_are_ordered_by_dex_then_method_then_offset(rich_dk):
    """A documented, deterministic order — the raw index's was insertion order."""
    for fd in rich_dk.list_fields():
        for rows in (
            rich_dk.find_field_read_sites(fd),
            rich_dk.find_field_write_sites(fd),
        ):
            keys = [(s.dex_id, s.method_idx, s.bytecode_offset) for s in rows]
            assert keys == sorted(keys), f"{fd}: rows out of order"


def test_a_quick_opcode_cannot_FABRICATE_a_row_in_a_still_candidate_method(tmp_path):
    """The craft above is decided by the core's INDEX; this one by the GATE.

    An adversarial reviewer built the distinction and it matters: when the retyped
    instruction is a method's ONLY access of the field, the vendored core's own
    collector stops listing the method, so the row disappears whatever the ext-side
    gate does — the guard passes against a widened gate. Here the method
    (`testInstanceFieldAccessors`) writes the field TWICE, so it REMAINS a
    candidate, the enumerator IS consulted, and a gate that admitted the quick form
    would emit a FABRICATED write built from a vtable/field OFFSET reported against
    a real field, which is exactly the dexllm#61 confusion.

    Both `iput-wide` (0x5A) and `iput-wide-quick` (0xE7) are k22c, so the retype
    changes one byte and leaves the width, the register nibbles and the operand
    alone: only the operand's index KIND moves. The instruction is located by its
    own shape — two 0x5A forty bytes apart carrying the SAME operand, UNIQUE in the
    file — rather than by a loose byte scan.
    """
    import struct

    import dexllm

    fd = "LTestInvocationKinds;->instance_field:D"
    raw = bytes(_RICH.read_bytes())
    hits = [
        off
        for off in range(0, len(raw) - 44, 2)
        if raw[off] == 0x5A
        and raw[off + 40] == 0x5A
        and struct.unpack_from("<H", raw, off + 2)[0]
        == struct.unpack_from("<H", raw, off + 42)[0]
    ]
    assert len(hits) == 1, f"the paired-iput-wide window is no longer unique: {hits}"

    control = {
        (x.method_descriptor, x.bytecode_offset)
        for x in dexllm.DexKit(str(_RICH)).find_field_write_sites(fd)
    }
    victim = ("LTestInvocationKinds;->testInstanceFieldAccessors()V", 68)
    assert victim in control, "the fixture no longer holds the craft's target"

    cand = bytearray(raw)
    cand[hits[0] + 40] = 0xE7  # iput-wide -> iput-wide-quick, same format
    path = tmp_path / "quick_write.dex"
    path.write_bytes(cand)
    assert dexllm.verify(str(path))[0]["valid"], "the craft must still verify"

    after = {
        (x.method_descriptor, x.bytecode_offset)
        for x in dexllm.DexKit(str(path)).find_field_write_sites(fd)
    }
    assert after == control - {victim}, (
        "retyping ONE of two writes to a quick form must drop exactly that row and "
        "nothing else; the method stays a candidate, so a gate that admits the "
        f"quick form fabricates it back. got {sorted(after)}"
    )


def test_the_order_holds_when_a_class_is_declared_in_two_dexes():
    """The order is GLOBAL, not per field-location — the pathological case.

    `FieldAccessSites` iterates the field's locations (dex-ascending) and sorts
    within each. When a class is declared with a BODY in two-plus dexes
    (multi-source, `add_dumped_dexes(prefer=True)`, a packer dump), reference-only
    accessors aggregate into the LOWEST declaring dex while a higher one keeps its
    own — so two groups emit and the documented order breaks without a final sort.
    No committed fixture is multi-dex in that way, but loading one TWICE is exactly
    the shape and needs no craft.
    """
    import dexllm

    dk = dexllm.DexKit([str(_RICH), str(_RICH)])
    assert dk.dex_count() == 2
    spanned = 0
    for fd in dk.list_fields():
        for rows in (dk.find_field_read_sites(fd), dk.find_field_write_sites(fd)):
            keys = [(s.dex_id, s.method_idx, s.bytecode_offset) for s in rows]
            assert keys == sorted(keys), f"{fd}: rows out of global order {keys}"
            if len({s.dex_id for s in rows}) > 1:
                spanned += 1
    assert spanned >= 1, (
        "no field's rows spanned both dexes, so the multi-location path was never "
        "exercised and this guard verified nothing"
    )
    # This case is already in order WITHOUT the final sort: two identical sources
    # both DECLARE the class (`type_def_flag` comes from each dex's own
    # `class_defs` and first-wins never clears it), so NEITHER aggregates, each
    # location emits only its own dex, and dex-ascending locations are already
    # globally ascending. It exercises the multi-location path and nothing more —
    # `test_a_three_source_load_breaks_the_per_location_order` is what needs the
    # sort, and an adversarial reviewer had to construct it.


def _strip_one_class_def(raw: bytes, target_cls: str) -> bytes | None:
    """A copy of `raw` that no longer DECLARES `target_cls` but still references it.

    Overwrites the target `class_def` with the LAST one and decrements the count in
    both the header and the map item — length-preserving, so no offset and no
    section size moves, and the result verifies. The class's own `class_data` and
    code items are orphaned rather than removed; nothing walks them, because
    `InitCache` iterates `class_defs`.
    """
    import struct

    b = bytearray(raw)
    sio = struct.unpack_from("<I", b, 60)[0]  # string_ids_off
    tio = struct.unpack_from("<I", b, 68)[0]  # type_ids_off
    cds = struct.unpack_from("<I", b, 96)[0]  # class_defs_size
    cdo = struct.unpack_from("<I", b, 100)[0]  # class_defs_off

    def type_name(ti: int) -> str:
        di = struct.unpack_from("<I", b, tio + ti * 4)[0]
        sd = struct.unpack_from("<I", b, sio + di * 4)[0]
        q = sd
        while b[q] & 0x80:
            q += 1
        q += 1
        return bytes(b[q : b.index(0, q)]).decode("utf-8", "replace")

    for i in range(cds):
        off = cdo + i * 32
        if type_name(struct.unpack_from("<I", b, off)[0]) != target_cls:
            continue
        last = cdo + (cds - 1) * 32
        b[off : off + 32] = b[last : last + 32]
        struct.pack_into("<I", b, 96, cds - 1)
        mo = struct.unpack_from("<I", b, 52)[0]  # map_off
        for k in range(struct.unpack_from("<I", b, mo)[0]):
            e = mo + 4 + k * 12
            if struct.unpack_from("<H", b, e)[0] == 0x0006:  # kDexTypeClassDefItem
                struct.pack_into("<I", b, e + 4, cds - 1)
        return bytes(b)
    return None


def test_a_three_source_load_breaks_the_per_location_order(loadable_apks, tmp_path):
    """The shape that makes the FINAL global sort load-bearing.

    An adversarial reviewer constructed this after an earlier draft of mine called
    it unreachable. `PutCrossRef` aggregates only for a type the dex does NOT
    declare, into the LOWEST declaring dex — so the break needs declaring dexes
    L1 < L2 PLUS a non-declaring REFERENCING dex R > L2: L1's location then emits
    L1's and R's rows while L2's location emits its own, and the two groups leave
    the global order. `[A, A]` supplies no R, which is why the two-source case is
    ordered either way.

    `[A, A, B]`, with B a copy of A that no longer declares the field's class, is
    that shape. Measured on the shipped build the rows are `(0, m, o), (1, m, o),
    (2, m, o)`; with the final sort removed they are `(0, …), (2, …), (1, …)`.

    Corpus-gated: it needs a field declared in one class and accessed from ANOTHER,
    and no committed fixture has one (checked — all four dex fixtures).
    """
    import dexllm

    for apk in loadable_apks:
        try:
            dk = dexllm.DexKit(apk)
        except Exception:
            continue
        for d in range(dk.dex_count()):
            a = tmp_path / f"A{d}.dex"
            a.write_bytes(dk.extract_dex(d)["bytes"])
            try:
                da = dexllm.DexKit(str(a))
            except Exception:
                continue
            declared = set(da.list_classes())
            for fd in da.list_fields():
                cls = fd.split("->")[0]
                if cls not in declared:
                    continue
                rows = da.find_field_read_sites(fd) + da.find_field_write_sites(fd)
                if len(rows) != 1:
                    continue
                if not {r.method_descriptor.split("->")[0] for r in rows} - {cls}:
                    continue  # the accessor must survive removing the declaration
                stripped = _strip_one_class_def(a.read_bytes(), cls)
                if stripped is None:
                    continue
                b = tmp_path / f"B{d}.dex"
                b.write_bytes(stripped)
                if not dexllm.verify(str(b))[0]["valid"]:
                    continue
                db = dexllm.DexKit(str(b))
                if cls in set(db.list_classes()):
                    continue  # B must NOT declare it …
                if not (db.find_field_read_sites(fd) + db.find_field_write_sites(fd)):
                    continue  # … but must still ACCESS it

                three = dexllm.DexKit([str(a), str(a), str(b)])
                assert three.dex_count() == 3
                got = three.find_field_read_sites(fd) + three.find_field_write_sites(fd)
                keys = [(r.dex_id, r.method_idx, r.bytecode_offset) for r in got]
                assert (
                    len({k[0] for k in keys}) == 3
                ), f"the craft did not produce a row per source: {keys}"
                assert keys == sorted(keys), (
                    f"three sources, two of them declaring: rows out of the "
                    f"documented global order — {keys}"
                )
                return
    require_corpus_shape(
        False,
        "field declared in one class and accessed from another",
        "the three-source order craft could not be built, so the final global "
        "sort is unexercised",
    )


def test_the_row_order_is_a_final_global_sort() -> None:
    """SOURCE-level pin, BESIDE the behavioural one — for the properties it cannot see.

    `test_a_three_source_load_breaks_the_per_location_order` is what proves the
    final sort is load-bearing, and it is corpus-gated. This pins the parts a
    behavioural test cannot distinguish: that the sort is STABLE (the key
    uniqueness that would make a plain one a total order is a measured property of
    upstream's clear()-after-move, decided in a thread pool where a dex can be both
    source and target — not a contract), that it is the LAST thing before the
    return, and that it orders by the documented key.

    An earlier draft claimed the break was "unreachable from anything
    constructible here" after four multi-source configurations came back ordered.
    An adversarial reviewer refuted that by constructing it: the shape needs
    declaring dexes L1 < L2 PLUS a NON-declaring referencing dex R > L2, and
    `[A, A]` supplies no R. A source pin cannot see a line that is present and
    wrong; saying so is part of the record, but it is no longer the only thing
    holding this line.
    """
    src = _strip_comments(_EXT.read_text())
    i = src.index("std::vector<FieldAccessSite> FieldAccessSites(")
    body = src[i : src.index("\n}\n", i)]
    tail = body[body.rindex("std::stable_sort(") :]
    assert "out.begin(), out.end()" in tail, "the final sort is not over `out`"
    assert (
        "a.dex_id, a.method_idx, a.bytecode_offset" in tail
    ), "the final sort no longer orders by (dex_id, method_idx, bytecode_offset)"
    assert tail.index("std::stable_sort(") < tail.index(
        "return out;"
    ), "the final sort must precede the return"
    assert "for (" not in tail, "the final sort is no longer the LAST step"


def test_an_unresolvable_field_is_an_empty_page_not_an_error(rich_dk):
    assert rich_dk.find_field_read_sites("Lno/such/Class;->x:I") == []
    assert rich_dk.find_field_write_sites("Lno/such/Class;->x:I") == []


def test_a_quick_field_opcode_is_not_a_field_reference(tmp_path, rich_dk):
    """A crafted quick field opcode must produce NO site, end to end.

    Its operand is an OFFSET, not a field_ids index, so a pipeline that admitted
    one would attribute an access to whatever field that number happens to name.
    No dex in reach carries a quick opcode, so the shape has to be crafted.

    WHAT THIS DOES AND DOES NOT PIN (a correctness reviewer measured it): the
    CANDIDATE accessors come from the vendored core's OWN gate
    (`dex_item.cpp`, `need_method_using_field`), which this change does not touch,
    so a widened gate on the ext side can only ever REMOVE a row, never fabricate
    one — the reviewer built that mutant and confirmed it. This case therefore
    exercises the whole pipeline's treatment of a quick opcode (and would catch a
    CORE-side widening); the ext-side gate is pinned by
    `test_the_field_site_gate_selects_exactly_the_field_index_opcodes`, which is
    what actually kills a widened `IsFieldAccessOpcode`.

    The retype is length-preserving to the byte: `iget-wide` (0x53) and
    `iget-wide-quick` (0xE4) are the SAME format (k22c), so neither the width nor
    the operand layout moves and the only thing that changes is the opcode's index
    KIND. (Width alone would not have forced that choice — k21c and k22c are both
    2 code units, and a reviewer built working k21c->k22c crafts; same-format is
    the stronger property, and it is why this pair is used.) The candidate is
    located by BUILDING it and keeping the one whose crafted dex still verifies and
    loses exactly one read row, so the craft cannot silently land on an unrelated
    byte in the string pool.
    """
    import dexllm

    raw = _RICH.read_bytes()
    before = {
        fd: len(rich_dk.find_field_read_sites(fd)) for fd in rich_dk.list_fields()
    }
    total_before = sum(before.values())

    for off in range(0, len(raw) - 4, 2):
        if raw[off] != 0x53:  # iget-wide
            continue
        cand = bytearray(raw)
        cand[off] = 0xE4  # iget-wide-quick — same format, same width
        p = tmp_path / f"quick_{off}.dex"
        p.write_bytes(cand)
        try:
            if not dexllm.verify(str(p))[0]["valid"]:
                continue
            probe = dexllm.DexKit(str(p))
            after = {
                fd: len(probe.find_field_read_sites(fd)) for fd in probe.list_fields()
            }
        except Exception:
            continue
        if sum(after.values()) != total_before - 1:
            continue
        moved = [fd for fd in before if after.get(fd, 0) != before[fd]]
        assert len(moved) == 1 and after[moved[0]] == before[moved[0]] - 1
        # …and nothing was INVENTED: no field gained a row.
        assert all(after.get(fd, 0) <= before[fd] for fd in before)
        return
    pytest.fail(
        "no iget-wide in the committed fixture could be retyped in place — the "
        "quick-opcode gate is unexercised"
    )


def test_the_typed_layers_carry_the_same_values_as_the_raw_record(rich_dk):
    """The SDK model and the MCP row must not quietly drop a field.

    Each conversion is a hand-written field list, so a dropped or defaulted
    attribute is invisible to a guard that only checks the raw binding — and
    `bytecode_offset` defaulting to 0 satisfies a `>= 0` assertion.
    """
    from dexllm import tools
    from dexllm.sdk.adapter import DexKitAdapter

    session = DexKitAdapter(str(_RICH))
    seen = 0
    for fd in rich_dk.list_fields():
        raw = rich_dk.find_field_read_sites(fd)
        typed = session.find_field_read_sites(fd)
        assert len(typed) == len(raw)
        for r, t in zip(raw, typed):
            assert (
                t.method_descriptor,
                t.dex_id,
                t.method_idx,
                t.field_descriptor,
                t.bytecode_offset,
                t.opcode,
            ) == (
                r.method_descriptor,
                r.dex_id,
                r.method_idx,
                r.field_descriptor,
                r.bytecode_offset,
                r.opcode,
            )
        if raw:
            rows = tools.execute(
                "find_field_read_sites",
                {"field_descriptor": fd, "limit": 10_000},
                rich_dk,
            )["items"]
            assert [x["bytecode_offset"] for x in rows] == [
                r.bytecode_offset for r in raw
            ]
            assert [x["method"] for x in rows] == [r.method_descriptor for r in raw]
        seen += len(raw)
    assert seen >= 100, f"only {seen} rows compared"


# --- the cross-dex shape, which no committed fixture carries ------------------


def test_a_cross_dex_access_is_resolved_in_the_accessors_own_dex(loadable_apks):
    """A field declared in one dex and accessed from another.

    The core AGGREGATES a field's accessors into the declaring dex, tagged with
    their origin, and the accessor references the field through ITS OWN dex's
    `field_ids` entry — so the instruction operand has to be matched against the
    local index. Matching against the declaring dex's index silently drops the row
    or, worse, matches an unrelated field.

    Counted as rows whose `dex_id` differs from `locate_class_dex` of the field's
    class, over the DEDUPLICATED field descriptors: 1,001 on `app-prod-debug.apk`
    and 2,910 on `multiple_locale_appname_test.apk` — exactly half the figure over
    the raw `list_fields()`, which repeats a descriptor once per dex (dexllm#45).
    (An earlier draft published 775 / 1,364 from a `list_fields()[:6000]` CAPPED
    scan, which neither reviewer could re-derive under any predicate.) 0 in any
    committed fixture — including `tests/data/multidex.apk` and
    `multidex-container.dex`, both multi-dex but with no cross-dex access — which is
    why this case is corpus-gated and has NO coverage in the corpus-less CI leg.
    """
    import dexllm

    for apk in loadable_apks:
        try:
            dk = dexllm.DexKit(apk)
        except Exception:
            continue
        if dk.dex_count() < 2:
            continue
        by_dex = {d: dk.list_methods_in_dex(d) for d in range(dk.dex_count())}
        for fd in dk.list_fields()[:4000]:
            home = dk.locate_class_dex(fd.split("->")[0])
            if home < 0:
                continue
            for site in dk.find_field_read_sites(fd):
                if site.dex_id == home:
                    continue
                # the row must identify a method IN ITS OWN dex …
                assert by_dex[site.dex_id][site.method_idx] == site.method_descriptor
                # … and the offset must be a real access of THIS field there.
                accesses = _smali_accesses(dk, site.method_descriptor, fd)
                assert site.bytecode_offset in accesses, (
                    f"cross-dex row for {fd} points at {site.bytecode_offset:#x} in "
                    f"{site.method_descriptor}, whose accesses are {sorted(accesses)}"
                )
                return
    require_corpus_shape(
        False,
        "field accessed from a dex other than the one declaring it",
        "the cross-dex re-resolution is unexercised, so this guard verified nothing",
    )
