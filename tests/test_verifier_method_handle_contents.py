"""dexllm#59 — ART's method_handle CONTENTS checks, ported.

`Reader::ParseMethodHandle` (reader.cc :884) reads an entry's TYPE, asks
`ir::MethodHandle::IsField()` which table the index names, and resolves it
through `GetFieldDecl` / `GetMethodDecl`. Before this change the gate checked
neither half: dexllm#57 bounded the section's EXTENT and dexllm#62 its
ALIGNMENT, but ART's `CheckIntraMethodHandleItem`
(`dex_file_verifier.cc:1492`) also rejects a `method_handle_type` past
`kLast` (:1501) and bounds `field_or_method_idx` against field_ids / method_ids
(:1512 / :1521). The residual was never an OOB — `ArrayView`'s own
`SLICER_CHECK_LT` bounds the index against a header-validated table — but it
was a THROW out of the parser rather than a rejection at the gate, which is not
what "`VerifyDex` is the single gate" promises. Note also that `IsField()`
sends everything OUTSIDE 0x00-0x03 to the METHOD table, garbage included, so an
unchecked type silently decided which bound applied.

An added check can only fail in the direction ART's own verifier cannot: by
REJECTING something ART accepts (dexllm#58's lesson). Hence the acceptance
controls below — each names a value the rule must let through, and together
they pin both boundaries exactly.

Every craft rewrites TWO u2 fields of ONE entry of
`tests/data/invoke-custom.dex`, which this repo commits: length-preserving to
the byte, so no offset, section size or neighbouring structure moves and
nothing but the intended operand can be what changed. That also makes every craft
corpus-independent: all but one case runs in the corpus-less CI leg and under
any `$DEXLLM_TEST_APK` narrowing. The exception is the corpus SWEEP at the
bottom, which by definition needs a corpus and skips without one.

WHY THIS FIXTURE. All 32 method handles across all three committed carriers are
kind 4 or 5 (the same census dexllm#67 recorded), so the FIELD branch —
0x00-0x03, bounded against `field_ids` — has no REJECTING input in the repo
without a craft. Its accept path is not craft-only: of the nine carriers in the
whole AOSP tree, three declare a kind 0x03 handle and two of those verify. `invoke-custom.dex` is additionally
the one whose `field_ids_size` (21) is far below its `method_ids_size` (243),
and that GAP is what makes the two table-discrimination guards possible: an
index inside it must be rejected for a field kind and accepted for an invoke
kind, which no single-sided test can say.
"""

from __future__ import annotations

import pathlib
import struct
import subprocess
import sys
import time

import pytest
from conftest import REPO_ROOT, require_corpus_shape

import dexllm

_FIXTURE = REPO_ROOT / "tests" / "data" / "invoke-custom.dex"

_MAP_OFF = 52  # header: offset of the map_list
_FIELD_IDS_SIZE = 80  # header: field_ids_size
_METHOD_IDS_SIZE = 88  # header: method_ids_size
_METHOD_HANDLE = 0x0008  # map item type
_ENTRY = 8  # sizeof(dex::MethodHandle)

# ART `MethodHandleType` (dex_file.h :215-228), pinned as a literal rather than
# read from the production source: a guard parametrised over the thing it guards
# cannot catch an EDIT of it. The slicer names the same nine
# (`METHOD_HANDLE_TYPE_*`, dex_format.h :137-145) and its `IsField()`
# (dex_ir.cc :110) draws the line after 0x03, which is the partition the bound
# depends on.
_FIELD_KINDS = (0x00, 0x01, 0x02, 0x03)  # static-put/get, instance-put/get
_INVOKE_KINDS = (0x04, 0x05, 0x06, 0x07, 0x08)  # static/instance/ctor/direct/interface
# ART kLast == kInvokeInterface. Consumed by the boundary parametrisation below,
# which drives the PRODUCT — a pin whose only other operand is another literal in
# this file proves nothing, which is what the first version of this line did.
_LAST_KIND = 0x08


def _section(raw: bytes) -> tuple[int, int]:
    """(offset, count) of the method_handle section, read from the map."""
    map_off = struct.unpack_from("<I", raw, _MAP_OFF)[0]
    count = struct.unpack_from("<I", raw, map_off)[0]
    for i in range(count):
        kind, _u, size, off = struct.unpack_from("<HHII", raw, map_off + 4 + i * 12)
        if kind == _METHOD_HANDLE:
            return off, size
    raise AssertionError("the fixture no longer declares a method_handle section")


@pytest.fixture(scope="module")
def fixture():
    """The pristine fixture plus the numbers every craft is built from.

    Asserts its own premises: without the section, without at least two entries
    (the last-entry walk guard), and without `field_ids < method_ids` (the two
    table-discrimination guards) the crafts below would be vacuous rather than
    wrong, so a substituted fixture must fail loudly here.
    """
    raw = _FIXTURE.read_bytes()
    off, count = _section(raw)
    n_field = struct.unpack_from("<I", raw, _FIELD_IDS_SIZE)[0]
    n_method = struct.unpack_from("<I", raw, _METHOD_IDS_SIZE)[0]
    assert (
        count >= 2
    ), f"the fixture declares {count} handle(s); the walk guard needs >= 2"
    assert 0 < n_field < n_method, (
        f"field_ids={n_field} method_ids={n_method} — the discrimination guards "
        "need a nonempty gap between the two tables"
    )
    assert off + count * _ENTRY <= len(raw)
    return raw, off, count, n_field, n_method


def _craft(tmp_path, fixture, name, *, kind, idx, entry=0) -> str:
    """Rewrite one entry's type and index in place. Nothing else moves."""
    raw, off, count, _nf, _nm = fixture
    assert entry < count
    b = bytearray(raw)
    struct.pack_into("<H", b, off + entry * _ENTRY + 0, kind)
    struct.pack_into("<H", b, off + entry * _ENTRY + 4, idx)
    assert len(b) == len(raw)
    p = tmp_path / f"{name}.dex"
    p.write_bytes(bytes(b))
    return str(p)


def _verdict(path: str, *, lenient: bool = False) -> tuple[bool, str]:
    rows = dexllm.verify(path, lenient=lenient)
    assert len(rows) == 1, rows
    return rows[0]["valid"], rows[0]["reason"]


# ── premise ──────────────────────────────────────────────────────────────────


def test_the_uncrafted_fixture_verifies(fixture):
    """NON-DISCRIMINATING BY DESIGN — it must hold on both sides of the change.

    It is the premise every craft rests on, and it is not idle: the fixture
    carries 29 real handles, so the pristine file exercises the accepting path
    of the new walk 29 times over.
    """
    valid, reason = _verdict(str(_FIXTURE))
    assert valid, reason


# ── the TYPE half (ART :1501) ────────────────────────────────────────────────


@pytest.mark.parametrize("kind", [_LAST_KIND + 1, 0x0A, 0x10, 0xFF, 0x1234, 0xFFFF])
def test_a_handle_type_past_kLast_is_rejected(tmp_path, fixture, kind):
    """`method_handle_type > kLast` — the check the slicer does NOT make.

    Its `IsField()` is an `if (0x00..0x03) else`, so 0xFFFF resolves against
    `method_ids` and the garbage merely picks a table.
    """
    path = _craft(tmp_path, fixture, f"type_{kind:04x}", kind=kind, idx=0)
    valid, reason = _verdict(path)
    assert not valid, f"type {kind:#06x} accepted"
    assert "method handle type" in reason, reason


@pytest.mark.parametrize("kind", _FIELD_KINDS + _INVOKE_KINDS + (_LAST_KIND,))
def test_every_legal_handle_type_is_accepted(tmp_path, fixture, kind):
    """The acceptance control, over the WHOLE legal set.

    0x08 is the one that matters most — it is exactly `kLast`, so a `>=`
    written where ART writes `>` rejects a dex Android loads. Index 0 is legal
    in both tables (the fixture has 21 fields and 243 methods), so this varies
    only the type.
    """
    path = _craft(tmp_path, fixture, f"ok_type_{kind:02x}", kind=kind, idx=0)
    valid, reason = _verdict(path)
    assert valid, f"legal type {kind:#04x} rejected: {reason}"


# ── the INDEX half (ART :1512 / :1521) ───────────────────────────────────────


@pytest.mark.parametrize("kind", _INVOKE_KINDS)
def test_an_invoke_index_past_method_ids_is_rejected(tmp_path, fixture, kind):
    _raw, _off, _count, _nf, n_method = fixture
    path = _craft(tmp_path, fixture, f"m_oob_{kind:02x}", kind=kind, idx=n_method)
    valid, reason = _verdict(path)
    assert not valid, f"method_idx {n_method} == method_ids_size accepted"
    assert "method_idx" in reason, reason


@pytest.mark.parametrize("kind", _FIELD_KINDS)
def test_a_field_index_past_field_ids_is_rejected(tmp_path, fixture, kind):
    _raw, _off, _count, n_field, _nm = fixture
    path = _craft(tmp_path, fixture, f"f_oob_{kind:02x}", kind=kind, idx=n_field)
    valid, reason = _verdict(path)
    assert not valid, f"field_idx {n_field} == field_ids_size accepted"
    assert "field_idx" in reason, reason


def test_the_last_legal_index_of_each_table_is_accepted(tmp_path, fixture):
    """Pins `>=` on the index (ART `CheckIndex` is `idx >= limit`).

    Without this an off-by-one that accepts `idx == limit` passes every
    rejection guard above, because those craft the limit itself.
    """
    _raw, _off, _count, n_field, n_method = fixture
    for kind, idx, what in (
        (0x00, n_field - 1, "field"),
        (0x04, n_method - 1, "method"),
    ):
        path = _craft(tmp_path, fixture, f"max_{what}", kind=kind, idx=idx)
        valid, reason = _verdict(path)
        assert valid, f"last legal {what} index {idx} rejected: {reason}"


# ── the LENIENT axis ─────────────────────────────────────────────────────────
#
# `lenient=True` exists for a partially-decrypted packer dump: valid structure,
# garbage method bodies. It gates `VerifyInsns` and nothing else, so a check
# living in `CheckMap` must still fire — and a dump is precisely the population
# that would carry a malformed method_handle section, so the mode that exists
# for those dumps must not be the way past this one. Three sibling guard files
# pin the same property (`test_verifier_section_alignment.py` for the SAME map
# section, `test_verifier_type_ids.py` for dexllm#23, and
# `test_verifier_class_data_definer.py` for dexllm#48).
#
# Not hypothetical: gating the call site on `check_insns_` compiles, leaves all
# 39 cases below green, and makes `lenient=True` accept a handle type of
# 0xFFFF. It was a review finding, not a guess.


@pytest.mark.parametrize(
    ("kind", "idx", "needle"),
    [
        (0xFFFF, 0, "method handle type"),
        (0x04, None, "method_idx"),
        (0x00, None, "field_idx"),
    ],
    ids=["bad_type", "method_idx_oob", "field_idx_oob"],
)
def test_a_bad_handle_is_rejected_leniently_too(tmp_path, fixture, kind, idx, needle):
    _raw, _off, _count, n_field, n_method = fixture
    if idx is None:
        idx = n_field if kind <= 0x03 else n_method
    path = _craft(tmp_path, fixture, f"lenient_{kind:04x}", kind=kind, idx=idx)
    valid, reason = _verdict(path, lenient=True)
    assert not valid, f"lenient mode accepted {kind:#06x}/{idx}"
    assert needle in reason, reason


def test_a_legal_handle_still_verifies_leniently(fixture):
    """NON-DISCRIMINATING BY DESIGN: the lenient cases above need the pristine
    fixture to pass in that mode too, or they would prove only that something
    else rejects it."""
    valid, reason = _verdict(str(_FIXTURE), lenient=True)
    assert valid, reason


# ── WHICH table — the two-sided discriminator ────────────────────────────────
#
# One index value, inside [field_ids_size, method_ids_size), read by both
# guards. A bound that always used `method_ids` accepts the first; one that
# always used `field_ids` rejects the second. Neither test alone can say that.


@pytest.mark.parametrize("kind", _FIELD_KINDS)
def test_a_field_handle_is_bounded_against_field_ids(tmp_path, fixture, kind):
    _raw, _off, _count, n_field, n_method = fixture
    idx = (n_field + n_method) // 2
    assert n_field <= idx < n_method
    path = _craft(tmp_path, fixture, f"gap_field_{kind:02x}", kind=kind, idx=idx)
    valid, reason = _verdict(path)
    assert not valid, (
        f"a {kind:#04x} handle took index {idx} — past field_ids_size "
        f"({n_field}) but inside method_ids_size ({n_method}), so the bound "
        "was the wrong table's"
    )
    assert "field_idx" in reason, reason


@pytest.mark.parametrize("kind", _INVOKE_KINDS)
def test_an_invoke_handle_is_bounded_against_method_ids(tmp_path, fixture, kind):
    _raw, _off, _count, n_field, n_method = fixture
    idx = (n_field + n_method) // 2
    path = _craft(tmp_path, fixture, f"gap_invoke_{kind:02x}", kind=kind, idx=idx)
    valid, reason = _verdict(path)
    assert valid, (
        f"a {kind:#04x} handle with index {idx} (< method_ids_size {n_method}) "
        f"was rejected — the bound was field_ids ({n_field}): {reason}"
    )


# ── the whole SECTION, not just its first entry ──────────────────────────────


def test_every_entry_of_the_section_is_walked(tmp_path, fixture):
    """Crafts the LAST entry.

    ART reaches this check once per item because its intra pass ITERATES the
    section; this port fuses the walk into `CheckMap`, where the loop is ours to
    write — so "walks the section" is a property of THIS code and not inherited.
    """
    _raw, _off, count, _nf, _nm = fixture
    path = _craft(tmp_path, fixture, "last_entry", kind=0xFFFF, idx=0, entry=count - 1)
    valid, reason = _verdict(path)
    assert not valid, f"entry {count - 1} of {count} was never inspected"
    assert "method handle type" in reason, reason


# ── the ORDER the walk depends on ────────────────────────────────────────────

_LOAD_PROBE = """
import sys, dexllm
row = dexllm.verify(sys.argv[1])[0]
print("verify", row["valid"], "|", row["reason"])
try:
    dk = dexllm.DexKit(sys.argv[1]); dk.warm_analysis_caches(); print("warm ok")
except Exception as e:
    print("warm RAISED", type(e).__name__)
"""


def test_an_inflated_section_count_is_refused_without_reading_past_the_file(
    tmp_path, fixture
):
    """The extent bound must still be what rejects, and it must run FIRST.

    The walk dereferences `count` entries and the ONLY thing bounding that span
    is dexllm#57's `CheckListSize` immediately above the call. A SUBPROCESS,
    because reading past the image inside the verifier is a SIGSEGV that no
    `try/except` can observe.

    HONEST LIMIT: this does not reliably kill a mutant that moves the walk
    ABOVE the span check. Such a walk stops at the first byte pair that decodes
    to a type > 0x08, which arbitrary trailing data usually supplies within a
    few entries — so whether it faults depends on the file's tail, not on the
    defect. The ORDER is therefore pinned at source level below; this guard
    pins the half that IS deterministic (the verdict, and no signal).
    """
    raw, _off, _count, _nf, _nm = fixture
    map_off = struct.unpack_from("<I", raw, _MAP_OFF)[0]
    n = struct.unpack_from("<I", raw, map_off)[0]
    b = bytearray(raw)
    for i in range(n):
        pos = map_off + 4 + i * 12
        kind = struct.unpack_from("<H", b, pos)[0]
        if kind == _METHOD_HANDLE:
            struct.pack_into("<I", b, pos + 4, 0x0100_0000)  # count, wildly inflated
            break
    else:
        pytest.fail("no method_handle map item to inflate")
    p = tmp_path / "inflated.dex"
    p.write_bytes(bytes(b))

    proc = subprocess.run(
        [sys.executable, "-c", _LOAD_PROBE, str(p)],
        capture_output=True,
        text=True,
        timeout=120,
        cwd=REPO_ROOT,
    )
    assert (
        proc.returncode >= 0
    ), f"killed by signal {-proc.returncode} — the method_handle walk left the image"
    assert "verify False" in proc.stdout, proc.stdout + proc.stderr
    # The REASON, not just the verdict. Dropping `kMethodHandleItem` from
    # `CheckMap`'s `entry` ternary leaves the walk untouched but stops the span
    # bound from applying to it — an adversarial reviewer showed that passes the
    # whole of this file when only the verdict is asserted, because the walk then
    # rejects on the first byte pair decoding to a type > 0x08 and the dex reads
    # "False" either way, having gone past the buffer to get there.
    assert "map section span" in proc.stdout, (
        "the inflated count was not caught by the EXTENT bound — the walk got "
        "there first: " + proc.stdout + proc.stderr
    )


_CHECKMAP_SOURCE = REPO_ROOT / "native" / "core_ext" / "dex_verifier.cpp"


def test_the_contents_walk_follows_the_extent_bound(fixture):
    """SOURCE-level, because nothing behavioural can hold this deterministically.

    `VerifyMethodHandleSection` documents an unchecked precondition — that its
    span is already inside the image — and the only thing establishing it is the
    `CheckListSize(..., "map section span")` a few lines above the call, in the
    SAME loop iteration. Swapping the two compiles, passes every guard in this
    file, and moves an unbounded read into the verifier itself.
    """
    src = _CHECKMAP_SOURCE.read_text()
    body = src[src.index("bool DexVerifier::CheckMap()") :]
    body = body[: body.index("\nbool DexVerifier::")]
    span = body.index('"map section span"')
    call = body.index("VerifyMethodHandleSection(")
    assert span < call, (
        "the method_handle contents walk now runs BEFORE the extent bound that "
        "makes its span safe to dereference"
    )


# ── no false reject ──────────────────────────────────────────────────────────


# The three committed carriers and how many handles each declares. PINNED,
# because the property this guard exists for is that the ACCEPTING path runs on
# real input, and `for path in carriers: assert valid` is satisfied by an empty
# list. A count is what makes it non-vacuous.
_COMMITTED_CARRIERS = {
    "invoke-custom.dex": 29,
    "method_handles.dex": 2,
    "const-method-handle.dex": 1,
}


def test_no_real_carrier_is_rejected():
    """The direction an added check can get wrong is rejecting what ART accepts.

    Corpus-INDEPENDENT on purpose. An earlier cut took the `loadable_apks`
    fixture, which contributed nothing — the loop filters on a `dex\n` magic and
    every corpus APK is a zip, so 0 of 25 survived — while its absence SKIPPED
    the whole test, i.e. the one guard covering the only direction this change
    can fail did not run in the CI leg. A reviewer measured that; the dependency
    is gone.

    The gitignored corpus carries 0 method_handle sections (a raw map-list
    census over 8,360 AOSP files finds 9 carriers in the whole tree, none of
    them a corpus dex), so these three ARE the population.
    """
    walked = 0
    for name, count in sorted(_COMMITTED_CARRIERS.items()):
        path = REPO_ROOT / "tests" / "data" / name
        assert path.exists(), f"{name} is no longer committed"
        off, size = _section(path.read_bytes())
        assert size == count, f"{name} declares {size} handles, expected {count}"
        assert off > 0
        valid, reason = _verdict(str(path))
        assert valid, f"{name} falsely rejected: {reason}"
        valid, reason = _verdict(str(path), lenient=True)
        assert valid, f"{name} falsely rejected leniently: {reason}"
        walked += size
    assert walked == 32, walked


def test_the_corpus_is_swept_for_carriers_and_none_is_rejected(loadable_apks):
    """Corpus-GATED companion, and it sweeps what the earlier cut only claimed to.

    `_candidate_apks` globs `*.apk`, so `loadable_apks` never holds a bare
    `.dex` — the first version of this filtered on a `dex\n` magic and swept
    exactly nothing. It walks each container's EMBEDDED dexes instead.

    If the corpus ever gains a carrier this asserts the right thing rather than
    going red for having found one, and the count it reports is what the
    `_COMMITTED_CARRIERS` strategy above rests on.

    It does NOT assert every row of every container is valid, which an earlier
    cut did. A delta reviewer built the counter-example in minutes: a
    packer-dump-shaped source (a good dex plus a dexllm#62-misaligned sibling)
    is exactly what `lenient=True` / `add_dumped_dexes` / dexllm#25 exist for and
    exactly what an analyst points `$DEXLLM_TEST_APK` at — and the blanket assert
    went RED there, blaming this change for a pre-existing rejection. A container
    with no method_handle section cannot change verdict under this change at all,
    so the assert was unearned as well as harmful (issue #46).
    """
    scanned = 0
    carriers = []
    for path in sorted(set(loadable_apks)):
        dk = dexllm.DexKit(path)
        for entry in dk.extract_dexes():
            raw = entry["bytes"]
            scanned += 1
            if raw[:4] != b"dex\n":
                continue
            try:
                _off, size = _section(raw)
            except AssertionError:
                continue  # no section — the expected shape for a bundled sample
            carriers.append((path, entry["dex_id"], size))

    require_corpus_shape(
        scanned > 0,
        "loadable container with an extractable dex",
        "the without-a-section half of no-false-reject would be unmeasured",
    )
    for path, dex_id, size in carriers:
        rows = [r for r in dexllm.verify(path) if r["dex_id"] == dex_id]
        assert rows and rows[0]["valid"], (path, dex_id, size, rows)


# ── the v41 CONTAINER amplification (adversarial review, HIGH) ───────────────
#
# `ComputeDataRange` gives EVERY slice of a v41 container the whole container as
# its span, while `LogicalDexSlices` strides by `file_size` — so a method_handle
# section SHARED between siblings is walked once per sibling, and `count` is
# bounded by the container rather than by the slice. Un-bounded that is quadratic:
# a reviewer measured 2/4/8/16 MB -> 0.34 / 1.29 / 5.19 / 20.59 s against HEAD's
# 0.00 / 0.01 / 0.02 / 0.04 s, paid BEFORE the rejection, on the load-free public
# `dexllm.verify(path)`.
#
# The fix is a per-IMAGE memo plus an entry budget, threaded by
# `ClassifyImageSlices`. A FIRST fix instead bounded `count` by the slice's own
# `file_size / 8`, and a delta reviewer REFUTED it with the fixture below: the
# crossover was exactly that bound, 70 accepted and 71 rejected, taking the whole
# container with it. Both directions are pinned here now — the memo has NO
# observable output (which is the point: it rejects nothing), so its guard is a
# clock, while the budget and the ACCEPT direction are behavioural.


_V41_HEADER = 120  # a v41 header, the smallest a slice can be
_V41_FIXTURE = REPO_ROOT / "tests" / "data" / "multidex-container.dex"


def _v41_slices(raw: bytes) -> list[tuple[int, int]]:
    out, off = [], 0
    while off + 112 <= len(raw) and raw[off : off + 4] == b"dex\n":
        fs = struct.unpack_from("<I", raw, off + 32)[0]
        out.append((off, fs))
        if fs < 112:
            break
        off += fs
    return out


def _shared_section(
    tmp_path, n_handles: int, *, kind: int = 0x04, idx: int = 0
) -> tuple[pathlib.Path, int]:
    """AOSP's own v41 container plus a method_handle section its slices SHARE.

    Appends `n_handles` legal entries (kind 4, index 0), repurposes slice 0's
    LAST map item (the largest offset, so ascending order holds) to name them,
    and bumps every slice's `container_size`. Nothing else moves. Returns
    (path, slice-0 file_size) — the file_size is what the refuted bound divided.
    """
    base = _V41_FIXTURE.read_bytes()
    body = bytearray(base)
    while len(body) % 4:
        body += b"\x00"
    sec = len(body)
    entry = struct.pack("<HHHH", kind, 0, idx, 0)
    body += entry * n_handles
    container = len(body)
    parts = _v41_slices(base)
    assert len(parts) >= 2, "the fixture is no longer a multi-slice container"
    # EVERY slice names the section — that is what SHARED means, and a fixture
    # patching only slice 0's map would be VACUOUS: the memo would never be
    # consulted, so removing it would change nothing. (It did. Two memo mutants
    # survived the first cut of this guard.)
    #
    # The item repurposed is `string_data` (0x2002), which BOTH slices carry and
    # which `CheckMap`'s required-section tail does NOT require — unlike the
    # last item of slice 1's map, which is the `map_list` itself. It is then
    # MOVED to the end of the item array, because the appended section has the
    # largest offset in the container and the map must stay ascending.
    _STRING_DATA = 0x2002
    seen_maps = set()
    for off, _fs in parts:
        map_off = struct.unpack_from("<I", body, off + _MAP_OFF)[0]
        assert map_off not in seen_maps, "the slices already share one map"
        seen_maps.add(map_off)
        n_map = struct.unpack_from("<I", body, map_off)[0]
        items = [
            bytearray(body[map_off + 4 + i * 12 : map_off + 4 + (i + 1) * 12])
            for i in range(n_map)
        ]
        victim = next(
            it for it in items if struct.unpack_from("<H", it, 0)[0] == _STRING_DATA
        )
        struct.pack_into("<HHII", victim, 0, _METHOD_HANDLE, 0, n_handles, sec)
        items = [it for it in items if it is not victim] + [victim]
        for i, it in enumerate(items):
            body[map_off + 4 + i * 12 : map_off + 4 + (i + 1) * 12] = it
    assert len(seen_maps) == len(parts), "each slice must have its own map"
    for off, _fs in parts:
        struct.pack_into("<I", body, off + 112, container)
    path = tmp_path / f"v41_shared_{n_handles}_{kind}_{idx}.dex"
    path.write_bytes(bytes(body))
    return path, parts[0][1]


def test_the_uncrafted_v41_container_verifies(tmp_path):
    """NON-DISCRIMINATING BY DESIGN — the premise the crafts below rest on."""
    rows = dexllm.verify(str(_V41_FIXTURE))
    assert len(rows) >= 2, rows
    assert all(r["valid"] for r in rows), rows


@pytest.mark.parametrize("n_handles", [29, 70, 71, 138, 400, 4000])
def test_a_v41_container_may_SHARE_a_method_handle_section(tmp_path, n_handles):
    """The ACCEPT direction, and the regression guard for a refuted fix.

    Sharing is what the container format is FOR — this fixture's slice 0 has
    `file_size` 564 and `string_ids_off` 684, i.e. its own id table lives outside
    its own file_size. A bound of `file_size / 8` therefore rejected everything
    past 70 here, and the v41 sibling rule took slice 1 down with it. The
    parametrisation straddles that crossover deliberately: 70 passed even under
    the refuted rule, 71 did not.
    """
    path, file_size = _shared_section(tmp_path, n_handles)
    if n_handles > file_size // _ENTRY:
        assert n_handles > 70, "the fixture's geometry changed; re-derive the crossover"
    rows = dexllm.verify(str(path))
    assert len(rows) >= 2, rows
    assert all(r["valid"] for r in rows), (n_handles, [r["reason"] for r in rows])


def test_a_memo_hit_still_checks_THIS_slice_s_tables(tmp_path):
    """SOUNDNESS of the memo, and the reason it stores maxima instead of a bool.

    The fixture's two slices have DIFFERENT id tables — slice 0 declares 6
    method_ids, slice 1 declares 3 — so a shared section of `kind 4, index 4` is
    legal for the first and out of range for the second. A memo that returned
    "already walked, fine" would accept it for both, which is a hole this change
    would have opened rather than closed. The re-check is O(1) and exactly
    equivalent to re-walking, since "every index < limit" is "max index < limit".
    """
    idx = _memo_split_index()

    path, _fs = _shared_section(tmp_path, 8, kind=0x04, idx=idx)
    rows = dexllm.verify(str(path))
    assert len(rows) >= 2, rows
    assert "method_idx" in rows[1]["reason"], (
        "the second slice accepted an index its own table lacks: " + rows[1]["reason"]
    )
    # Slice 0 goes down too, and that is dexllm#25's sibling rule rather than
    # anything about the memo — a container dex cannot be loaded apart from the
    # siblings it shares a data section with.
    assert not rows[0]["valid"] and "container" in rows[0]["reason"], rows[0]

    # CONTROL: one index lower is legal for BOTH, so the same craft must verify.
    # Without it the assertion above is satisfied by anything that rejects.
    ok, _fs = _shared_section(tmp_path, 8, kind=0x04, idx=idx - 1)
    rows = dexllm.verify(str(ok))
    assert all(r["valid"] for r in rows), (idx - 1, [r["reason"] for r in rows])


def _memo_split_index() -> int:
    """An index legal for the first slice's method table and not the second's."""
    raw = _V41_FIXTURE.read_bytes()
    sizes = []
    for off, _fs in _v41_slices(raw):
        sizes.append(struct.unpack_from("<I", raw, off + 88)[0])  # method_ids_size
    assert len(sizes) >= 2, sizes
    assert sizes[0] > sizes[1], (
        f"the fixture's slices no longer differ the right way: {sizes} — the memo "
        "soundness guard needs slice 0's method table to be the larger"
    )
    return sizes[1]  # >= slice 1's size, < slice 0's


def test_a_shared_section_is_walked_once_not_once_per_sibling(tmp_path):
    """The MEMO, and a clock is the only instrument that can see it.

    The memo changes no verdict and no reason — that is the property, and it is
    why the a/b for this change shows the amplifier unchanged. What it changes is
    that the shared section is walked once instead of once per slice. At a 16 MB
    container the un-memoised walk takes ~20.6 s and the memoised one ~0.04 s, so
    a 5 s ceiling is a >100x margin over the fix and far under the defect. Stated
    as a clock guard rather than dressed up as a structural one.
    """
    path, n_slices, per_slice = _v41_amplifier(tmp_path, 8 * 1024 * 1024)
    assert per_slice > _V41_HEADER // _ENTRY, "the craft is not amplifying"
    assert n_slices > 1000, n_slices
    start = time.perf_counter()
    rows = dexllm.verify(str(path))
    elapsed = time.perf_counter() - start
    assert len(rows) == n_slices, (len(rows), n_slices)
    assert elapsed < 5.0, (
        f"verify() took {elapsed:.2f}s on a {n_slices}-slice v41 container — the "
        "shared section is being walked once per sibling"
    )


def test_overlapping_sections_hit_the_image_entry_budget(tmp_path):
    """The BUDGET, which the memo cannot cover and a clock should not have to.

    The memo keys on (offset, count, field_ids, method_ids), so slices naming
    sections at DIFFERENT offsets each miss it. Real sections occupy disjoint
    bytes, which is why `image / 8` can never be exceeded by a legitimate image;
    overlapping ones count the same bytes many times, and that is exactly what
    this crafts. The budget is the only thing standing between that and the same
    quadratic the memo removed for the shared case.
    """
    path, n_slices, per_slice = _v41_amplifier(
        tmp_path, 2 * 1024 * 1024, distinct_offsets=True
    )
    assert n_slices > 2, n_slices
    rows = dexllm.verify(str(path))
    budgeted = [r for r in rows if "entry budget" in r["reason"]]
    assert budgeted, (
        f"{n_slices} slices x {per_slice} entries at DISTINCT offsets never "
        f"exhausted the image budget: {sorted({r['reason'] for r in rows})}"
    )


_V41_AMP_HEADER = 120


def _v41_amplifier(tmp_path, pad_bytes: int, *, distinct_offsets: bool = False):
    """A v41 container whose extra slices are bare headers.

    With `distinct_offsets` each slice gets its OWN copy of the map naming the
    section at a different byte, which is the variant the memo cannot collapse.
    Returns (path, n_slices, handles_per_slice).

    NOTE this is a FAKED v41 — `header_size` is patched to 120 on a dex whose real
    header is 112 bytes, so the two `container_*` u4s overwrite 8 bytes of slice
    0's type_ids. Harmless for what it measures (the walk happens in `CheckMap`,
    before `CheckIntraSection` would notice, and every slice is rejected the same
    way on both halves) but it is why the ACCEPT direction above uses a REAL
    container instead.
    """
    base = _FIXTURE.read_bytes()
    body = bytearray(base) + bytearray(
        b"\x04\x00\x00\x00\x00\x00\x00\x00" * (pad_bytes // 8)
    )
    sec_off = len(base)
    slice0 = len(body)
    n_slices = (pad_bytes // _V41_AMP_HEADER) or 1
    if distinct_offsets:
        n_slices = min(n_slices, 8)
    body += bytearray(_V41_AMP_HEADER * n_slices)
    map_src = struct.unpack_from("<I", body, _MAP_OFF)[0]
    n_map = struct.unpack_from("<I", body, map_src)[0]
    map_len = 4 + n_map * 12
    map_copies = []
    if distinct_offsets:
        while len(body) % 4:
            body += b"\x00"
        for _k in range(n_slices):
            map_copies.append(len(body))
            body += body[map_src : map_src + map_len]
    container = len(body)

    def point_map(at: int, sec: int, count: int) -> None:
        items = [
            bytearray(body[at + 4 + i * 12 : at + 4 + (i + 1) * 12])
            for i in range(n_map)
        ]
        mh = next(
            it for it in items if struct.unpack_from("<H", it, 0)[0] == _METHOD_HANDLE
        )
        items = [it for it in items if it is not mh] + [mh]
        struct.pack_into("<II", mh, 4, count, sec)
        for i, it in enumerate(items):
            body[at + 4 + i * 12 : at + 4 + (i + 1) * 12] = it

    per_slice = (slice0 - sec_off) // _ENTRY
    point_map(map_src, sec_off, per_slice)
    body[4:8] = b"041\x00"
    struct.pack_into("<I", body, 36, _V41_AMP_HEADER)
    struct.pack_into("<I", body, 32, slice0)
    struct.pack_into("<II", body, 112, container, 0)
    for k in range(n_slices):
        o = slice0 + k * _V41_AMP_HEADER
        body[o : o + _V41_AMP_HEADER] = body[0:_V41_AMP_HEADER]
        struct.pack_into("<I", body, o + 32, _V41_AMP_HEADER)
        struct.pack_into("<II", body, o + 112, container, o)
        if distinct_offsets:
            at = map_copies[k]
            point_map(at, sec_off + 8 * (k + 1), per_slice)
            struct.pack_into("<I", body, o + _MAP_OFF, at)

    path = tmp_path / f"v41_{pad_bytes}_{int(distinct_offsets)}.dex"
    path.write_bytes(bytes(body))
    return path, n_slices + 1, per_slice
