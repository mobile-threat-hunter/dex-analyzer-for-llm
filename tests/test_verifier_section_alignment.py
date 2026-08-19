"""dexllm(#62) - a data section's offset must be aligned the way ART aligns it.

`IsDataSectionType` is a 1:1 port of ART `dex_file_verifier.cc:82`, whose false
arm is the header item and the six `*_id` tables and nothing else. This port had
three more in that arm - `kCallSiteIdItem` (ART :92), `kMethodHandleItem` (:93)
and `kMapList` (:94) - and its single consumer is `CheckMap`'s alignment branch,
so a MISALIGNED `call_site_id` / `method_handle` section offset was accepted
where ART rejects it. Never memory safety (dexllm#57's extent bound spans both
sections whatever their alignment, and an unaligned u2/u4 load is harmless on
every supported target) - spec fidelity, and the direction an added check can
get WRONG, which is dexllm#58's whole lesson. Hence the controls below: the
alignment check must be what rejects, and it must not reject anything else.

Every fixture is crafted from `tests/data/invoke-custom.dex`, which this repo
commits, so the guards hold in the corpus-less CI leg and under any
`$DEXLLM_TEST_APK` narrowing. It is the only source that carries BOTH sections -
0 of the gitignored corpus dexes carries either - which is also why the
no-false-reject floor at the bottom walks whatever corpus is present and SKIPS
when it finds no carrier: an environment fact, never a failure (issue #46).

The craft is length-preserving to the byte: it rewrites ONE u4, the section's
offset field inside the map item, leaving the count alone. Keeping the count is
what isolates the check - the extent still fits inside the file, so dexllm#57's
span bound cannot be what rejects.
"""

from __future__ import annotations

import pathlib
import re
import struct

import pytest
from conftest import REPO_ROOT

_FIXTURE = REPO_ROOT / "tests" / "data" / "invoke-custom.dex"

_MAP_OFF = 52  # header field: offset of the map_list

_CALL_SITE_ID = 0x0007
_METHOD_HANDLE = 0x0008
_MAP_LIST = 0x1000

# ART :798 aligns these five to 1 byte and everything else in the data section
# to 4. `string_data` is genuinely unaligned in the fixture, so this list is
# exercised by the pristine file itself, not only by a craft.
_BYTE_ALIGNED = {0x2000, 0x2002, 0x2003, 0x2004, 0x2005}

# ART's WHOLE classification, pinned as a literal: `IsDataSectionType` (:82) plus
# the alignment switch (:791-798). `None` = not a data section, so `CheckMap`
# never checks its alignment; otherwise the required alignment in bytes.
#
# Pinned rather than derived, because a guard parametrised over the production
# predicate cannot catch an EDIT of it - this repo's own recorded lesson. It is
# also the ONLY thing that catches the SYMMETRIC mistake: dexllm#62 removed three
# cases from the false arm, and removing a FOURTH (say `string_id`) is the same
# edit in the other direction, on the same lines, rejecting a dex ART accepts.
_ART_ALIGNMENT = {
    0x0000: None,  # header_item          ART :83
    0x0001: None,  # string_id_item       :84
    0x0002: None,  # type_id_item         :85
    0x0003: None,  # proto_id_item        :86
    0x0004: None,  # field_id_item        :87
    0x0005: None,  # method_id_item       :88
    0x0006: None,  # class_def_item       :89
    0x0007: 4,  # call_site_id_item    :92  <- dexllm#62
    0x0008: 4,  # method_handle_item   :93  <- dexllm#62
    0x1000: 4,  # map_list             :94  <- dexllm#62
    0x1001: 4,  # type_list            :95
    0x1002: 4,  # annotation_set_ref_list :96
    0x1003: 4,  # annotation_set_item  :97
    0x2000: 1,  # class_data_item      :98,  :792
    0x2001: 4,  # code_item            :99
    0x2002: 1,  # string_data_item     :100, :793
    0x2003: 1,  # debug_info_item      :101, :794
    0x2004: 1,  # annotation_item      :102, :795
    0x2005: 1,  # encoded_array_item   :103, :796
    0x2006: 4,  # annotations_directory_item :104
    0xF000: 4,  # hiddenapi_class_data :105
}

# Bytes per entry, for the two fixed-size sections the HEADER does not describe.
_ENTRY = {_CALL_SITE_ID: 4, _METHOD_HANDLE: 8}


def _map_items(raw: bytes) -> list[tuple[int, int, int, int]]:
    """[(offset of the map item, type, count, section offset)], in map order."""
    map_off = struct.unpack_from("<I", raw, _MAP_OFF)[0]
    count = struct.unpack_from("<I", raw, map_off)[0]
    out = []
    for i in range(count):
        item = map_off + 4 + i * 12
        type_, _pad, size, off = struct.unpack_from("<HHII", raw, item)
        out.append((item, type_, size, off))
    return out


def _shift(section_type: int, delta: int, dst: pathlib.Path) -> None:
    """Write the fixture with one section's offset moved by `delta` bytes.

    Asserts the craft's own premises, so a fixture that ever stops offering the
    shape fails loudly here instead of turning a guard vacuous: the section must
    exist, must start out 4-ALIGNED (else the verdict is not attributable to the
    shift), must still END inside the file, and its shifted START must stay below
    the next section's offset (which would otherwise trip the out-of-order check
    and attribute the rejection to the wrong rule).

    Only the START is bounded that way, not the extent - the `+4` control does
    overlap `method_handle` by 4 bytes, which is harmless because these crafts are
    judged by `verify()` and the verifier has no section-overlap rule.
    """
    raw = bytearray(_FIXTURE.read_bytes())
    items = _map_items(raw)
    hit = [x for x in items if x[1] == section_type]
    assert len(hit) == 1, f"section {section_type:#06x} not in the fixture"
    item, _type, size, off = hit[0]
    assert off % 4 == 0, f"section {section_type:#06x} is already misaligned"
    nxt = min([x[3] for x in items if x[3] > off], default=len(raw))
    assert off + delta < nxt, "the shift would collide with the next section"
    assert off + delta + size * _ENTRY.get(section_type, 0) <= len(raw), (
        "the shift would push the EXTENT past the file, so the dexllm#57 span "
        "bound - not alignment - would be what rejects it"
    )
    struct.pack_into("<I", raw, item + 8, off + delta)
    dst.write_bytes(bytes(raw))


def _verify(path: pathlib.Path, *, lenient: bool = False):
    import dexllm

    report = dexllm.verify(str(path), lenient=lenient)
    assert len(report) == 1, report
    return report[0]


# -- the premise ---------------------------------------------------------------


def test_the_uncrafted_fixture_verifies():
    """Non-discriminating BY DESIGN - it pins the baseline every verdict rests on.

    It is not idle: the fixture's `string_data`, `annotation`, `class_data` and
    `encoded_array` sections are all genuinely NOT 4-aligned, so a build that
    aligned every data section to 4 would fail right here.
    """
    row = _verify(_FIXTURE)
    assert row["valid"], row

    items = _map_items(_FIXTURE.read_bytes())
    unaligned = {t for _i, t, _s, off in items if off % 4}
    assert unaligned <= _BYTE_ALIGNED, unaligned
    assert unaligned, "the fixture no longer exercises ART's 1-byte alignment list"


def test_the_fixture_carries_both_sections_aligned():
    """Non-discriminating BY DESIGN - the shape the whole file depends on."""
    items = _map_items(_FIXTURE.read_bytes())
    by_type = {t: (size, off) for _i, t, size, off in items}
    for t in (_CALL_SITE_ID, _METHOD_HANDLE, _MAP_LIST):
        assert t in by_type, f"{t:#06x} missing from the fixture"
        size, off = by_type[t]
        assert size > 0 and off % 4 == 0, (t, size, off)


# -- the fix -------------------------------------------------------------------


@pytest.mark.parametrize("delta", [1, 2, 3])
@pytest.mark.parametrize(
    "section_type",
    [_CALL_SITE_ID, _METHOD_HANDLE],
    ids=["call_site_id", "method_handle"],
)
def test_a_misaligned_section_offset_is_rejected(tmp_path, section_type, delta):
    """ART :798 rejects all six of these; before dexllm#62 this port accepted them."""
    dst = tmp_path / f"misaligned-{section_type:#06x}-{delta}.dex"
    _shift(section_type, delta, dst)
    row = _verify(dst)
    assert not row["valid"], row
    assert row["reason"] == "Misaligned map item", row


@pytest.mark.parametrize(
    "section_type",
    [_CALL_SITE_ID, _METHOD_HANDLE],
    ids=["call_site_id", "method_handle"],
)
def test_a_misaligned_section_is_rejected_leniently_too(tmp_path, section_type):
    """`lenient=True` gates only `VerifyInsns`; this check is in `CheckMap`.

    A packer dump is exactly the population that would carry one, so the mode
    that exists for those dumps must not be the way past the check.
    """
    dst = tmp_path / f"lenient-{section_type:#06x}.dex"
    _shift(section_type, 1, dst)
    row = _verify(dst, lenient=True)
    assert not row["valid"] and row["reason"] == "Misaligned map item", row


@pytest.mark.parametrize(
    "section_type",
    [_CALL_SITE_ID, _METHOD_HANDLE],
    ids=["call_site_id", "method_handle"],
)
def test_a_misaligned_section_refuses_to_load(tmp_path, section_type):
    """The gate is a LOAD gate, not only a `verify()` verdict."""
    import dexllm

    dst = tmp_path / f"load-{section_type:#06x}.dex"
    _shift(section_type, 1, dst)
    with pytest.raises(RuntimeError, match="Misaligned map item"):
        dexllm.DexKit(str(dst))


def test_the_map_lists_own_offset_is_checked(tmp_path):
    """The one case `CheckHeader`'s 4-aligned `map_off` cannot see.

    That check reads the HEADER field; the map_list item's self-referential
    offset is a separate u4 nothing compares against it, so it was accepted
    before dexllm#62 put `kMapList` back in the data arm (ART :94).
    """
    dst = tmp_path / "map-self.dex"
    _shift(_MAP_LIST, 1, dst)
    row = _verify(dst)
    assert not row["valid"] and row["reason"] == "Misaligned map item", row


# -- the whole classification, not only the three cases dexllm#62 touched ------


def _craftable_types() -> list[int]:
    """Every map type in the fixture whose offset can be shifted by one byte.

    A section that is ALREADY unaligned cannot demonstrate anything by being
    misaligned further, and one whose next neighbour is adjacent would trip the
    out-of-order check instead. Both are properties of the sample.
    """
    raw = _FIXTURE.read_bytes()
    items = _map_items(raw)
    out = []
    for _item, type_, _size, off in items:
        if off % 4:
            continue
        nxt = min([x[3] for x in items if x[3] > off], default=len(raw))
        if off + 1 < nxt:
            out.append(type_)
    return out


@pytest.mark.parametrize("section_type", _craftable_types())
def test_every_section_type_is_classified_the_way_ART_classifies_it(
    tmp_path, section_type
):
    """One craft per map type, judged against the pinned table.

    This is the guard that survives an edit in EITHER direction. The tests above
    pin the three cases dexllm#62 removed; this pins the arm as a partition, so
    removing a fourth - `string_id`, whose map offset duplicates a header field
    `CheckHeader` already forces 4-aligned, and which therefore no corpus guard
    can ever reach - fails here and only here.
    """
    assert section_type in _ART_ALIGNMENT, f"unknown map type {section_type:#06x}"
    required = _ART_ALIGNMENT[section_type]

    dst = tmp_path / f"partition-{section_type:#06x}.dex"
    _shift(section_type, 1, dst)
    row = _verify(dst)

    if required in (None, 1):
        assert row["valid"], (f"{section_type:#06x} is not 4-aligned in ART", row)
    else:
        assert not row["valid"] and row["reason"] == "Misaligned map item", (
            f"{section_type:#06x} must be 4-aligned per ART",
            row,
        )


def test_the_pinned_table_covers_every_type_the_verifier_knows():
    """Non-discriminating BY DESIGN for the fix - it keeps the table honest.

    A map type the verifier knows but the table omits would make the guard above
    skip it silently, and the table is the only thing pinning the partition. The
    enum is read from the C++ so a new type cannot be added on one side alone.
    """
    src = (REPO_ROOT / "native" / "core_ext" / "dex_verifier.cpp").read_text()
    enum = src[src.index("enum MapType") : src.index("u4 MapTypeToBitMask(")]
    declared = {
        int(value, 16)
        for _name, value in re.findall(r"(k\w+)\s*=\s*(0x[0-9A-Fa-f]+),", enum)
    }
    assert declared, "the MapType enum could not be parsed"
    assert declared == set(_ART_ALIGNMENT), (
        sorted(hex(t) for t in declared - set(_ART_ALIGNMENT)),
        sorted(hex(t) for t in set(_ART_ALIGNMENT) - declared),
    )


# -- the controls: what the check must NOT do ----------------------------------


@pytest.mark.parametrize(
    "section_type",
    [_CALL_SITE_ID, _METHOD_HANDLE],
    ids=["call_site_id", "method_handle"],
)
def test_a_still_aligned_shift_is_accepted(tmp_path, section_type):
    """Isolation: +4 moves the section but keeps it aligned, so it must pass.

    Without this, a check that rejected any MOVED section - or one that read the
    wrong operand entirely - would satisfy every assertion above.
    """
    dst = tmp_path / f"shift4-{section_type:#06x}.dex"
    _shift(section_type, 4, dst)
    row = _verify(dst)
    assert row["valid"], row


@pytest.mark.parametrize("section_type", sorted(_BYTE_ALIGNED))
def test_a_byte_aligned_section_may_be_misaligned(tmp_path, section_type):
    """ART :798's 1-byte list must survive: these five are aligned to 1, not 4.

    Sections absent from the fixture are skipped - which one a dex carries is a
    property of the sample, not of the verifier.
    """
    items = _map_items(_FIXTURE.read_bytes())
    hit = [x for x in items if x[1] == section_type and x[3] % 4 == 0]
    if not hit:
        pytest.skip(f"the fixture has no 4-aligned {section_type:#06x} section")
    dst = tmp_path / f"byte-{section_type:#06x}.dex"
    _shift(section_type, 1, dst)
    row = _verify(dst)
    assert row["valid"], row


# -- no false reject -----------------------------------------------------------


def test_no_real_source_carrying_such_a_section_is_rejected():
    """The direction an added check fails in (dexllm#58): rejecting valid input.

    The rule IS ART's, so anything Android loads passes - but that is the claim,
    not the evidence. It does NOT take the `loadable_apks` fixture, which skips
    when the corpus is absent: the committed fixture is the only source that
    carries either section, so the one guard that pins "no false reject on a
    carrier" would then not run in the CI leg that has no corpus. The corpus is
    added when present and only widens the population.
    """
    from conftest import _candidate_apks

    import dexllm

    sources = [_FIXTURE]
    for candidate in _candidate_apks():
        try:  # resources-only containers verify to invalid rows by design
            if dexllm.identify(candidate).get("dex_count", 0) > 0:
                sources.append(pathlib.Path(candidate))
        except Exception:  # pragma: no cover - unreadable sample
            continue

    carriers = 0
    for src in sources:
        for row in dexllm.verify(str(src)):
            assert row["valid"], (str(src), row)
        raw = src.read_bytes()
        if raw[:4] != b"dex\n":
            continue
        carriers += any(
            t in (_CALL_SITE_ID, _METHOD_HANDLE) for _i, t, _s, _o in _map_items(raw)
        )

    # NOT `require_corpus_shape`: whether the committed fixture carries the
    # section is environment-INDEPENDENT, so a narrowing must not soften it into
    # a skip. The corpus only ever widens the population above this floor.
    assert carriers, (
        "the committed tests/data/invoke-custom.dex no longer carries a "
        "call_site_id / method_handle section, so nothing here exercises the "
        "sections dexllm#62 is about"
    )
