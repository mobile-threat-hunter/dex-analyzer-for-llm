"""dexllm#56 — the annotations subtree is verified, so the walk cannot leave the image.

`class_def.annotations_off` reached the decode path having been checked for
NOTHING: not that it is in range, and not that it points at an
annotations_directory rather than at some other section. Annotations were listed
out of scope on the grounds that the core lazy-parses them — but it does parse
them (`Reader::ExtractAnnotations`, straight off the class_def), so "lazy" meant
"later", not "never".

A 4-byte, offset-preserving repoint therefore yielded a dex `verify()` called
**valid in both strict and lenient mode**, on which the caller/cross-ref family
**SIGSEGV'd** inside the slicer's `ParseAnnotation`. Whether a given craft threw
or corrupted memory was decided by whichever `SLICER_CHECK` happened to fire
first, not by any gate — of the 9 crafts in the issue (3 annotated corpus dexes ×
3 target offsets) all 9 verified valid, 7 threw and 2 died.

Distinct from dexllm#55, which made a *thrown* cache-init failure observable. A
SIGSEGV never unwinds, so no `catch (...)` sees it, `safe.py` guards hangs rather
than crashes, and the decompiler's per-method try/catch is not on this path — which
is why the crash guards below run in a SUBPROCESS with a deadline. An in-process
assertion cannot survive the thing it is asserting about.

Every fixture crafts IN PLACE and length-preserving (a `u4` overwritten with a
`u4`, a byte with a byte), so every offset in the file — and therefore every other
check — is untouched, and each verifies its own premise: the UNMODIFIED dex must
verify valid and load, or the rejection is not attributable to the craft.

Corpus dependency is a SKIP, never a failure (issue #46): "this sample declares an
annotation" is a property of the sample. Of the bundled bare dexes only three carry
any annotation at all, and only one carries a parameter annotation.
"""

import glob
import struct
import subprocess
import sys
from pathlib import Path

import pytest

import dexllm

REPO_ROOT = Path(__file__).resolve().parents[1]


def _u32(raw, off):
    return struct.unpack_from("<I", raw, off)[0]


def _annotation_map(raw):
    """-> (dir offsets, per-member entries, set offsets, item offsets).

    `members` is [(kind, byte offset of the entry's annotations_off)] for the
    three per-member lists, which follow the 16-byte directory header
    contiguously in the order fields, methods, parameters (dex spec; the slicer's
    `ExtractAnnotations` walks them in exactly that order).
    """
    cds_size, cds_off = struct.unpack_from("<II", raw, 0x60)
    dirs, members, sets = [], [], []
    for i in range(cds_size):
        off = _u32(raw, cds_off + i * 32 + 20)
        if off and off not in dirs:
            dirs.append(off)
    for d in dirs:
        ca, fs, ms, ps = struct.unpack_from("<IIII", raw, d)
        if ca:
            sets.append(ca)
        p = d + 16
        for kind, n in (("field", fs), ("method", ms), ("parameter", ps)):
            for _ in range(n):
                members.append((kind, p + 4))
                if kind != "parameter":
                    sets.append(_u32(raw, p + 4))
                else:  # a set_ref_list — its entries are the sets
                    rl = _u32(raw, p + 4)
                    for k in range(_u32(raw, rl)):
                        e = _u32(raw, rl + 4 + 4 * k)
                        if e:
                            sets.append(e)
                p += 8
    items = []
    for s in dict.fromkeys(sets):
        for k in range(_u32(raw, s)):
            items.append(_u32(raw, s + 4 + 4 * k))
    return dirs, members, list(dict.fromkeys(sets)), list(dict.fromkeys(items))


def _bare_dexes():
    for cand in sorted(glob.glob(str(REPO_ROOT / "test_apk" / "APK" / "*.dex"))):
        raw = Path(cand).read_bytes()
        if raw[:4] == b"dex\n":
            yield cand, raw


def _every_dex():
    """Raw bytes of every logical dex in the corpus, bare files and APK members.

    The bare `.dex` are enough for the structural crafts (they are the smallest
    thing that carries each shape), but not for the amplification guard below —
    the largest shared-subtree craft the corpus can produce comes from inside an
    APK, and searching only bare files silently skipped it.
    """
    for _cand, raw in _bare_dexes():
        yield raw
    for apk in sorted(glob.glob(str(REPO_ROOT / "test_apk" / "APK" / "*.apk"))):
        try:
            dk = dexllm.DexKit([apk])
            for i in range(dk.dex_count()):
                raw = dk.extract_dex(i)["bytes"]
                if raw[:4] == b"dex\n":
                    yield raw
        except Exception:  # resources-only container, or one we cannot open
            continue


def _sound_premise(path):
    """The UNMODIFIED source must verify valid and load, else nothing follows."""
    report = dexllm.verify(path)
    return all(r["valid"] for r in report)


def _write(tmp_path, name, raw, src):
    assert _sound_premise(src), f"{src} does not verify clean — bad premise"
    f = tmp_path / name
    f.write_bytes(bytes(raw))
    return str(f)


# ── the issue's own craft: repoint a class_def's annotations_off ──────────────

_REPOINT_MODES = ("header", "map", "shift")


def _repoint(tmp_path, mode, name):
    """Point one class_def's `annotations_off` at something that is not a directory.

    `header` and `map` name a real, in-range item of the WRONG type (exactly what
    ART's `CheckOffsetToTypeMap` exists to reject); `shift` lands mid-item. All
    three are 4-byte overwrites of a 4-byte field.
    """
    for cand, raw in _bare_dexes():
        raw = bytearray(raw)
        map_off = _u32(raw, 0x34)
        cds_size, cds_off = struct.unpack_from("<II", raw, 0x60)
        for i in range(cds_size):
            p = cds_off + i * 32 + 20
            off = _u32(raw, p)
            if not off:
                continue
            struct.pack_into(
                "<I", raw, p, {"header": 0x70, "map": map_off, "shift": off + 2}[mode]
            )
            return _write(tmp_path, name, raw, cand)
    pytest.skip("no bare .dex in the corpus declares a class annotation")


@pytest.mark.parametrize("mode", _REPOINT_MODES)
@pytest.mark.parametrize("lenient", [False, True])
def test_a_repointed_annotations_off_is_rejected(tmp_path, mode, lenient):
    """The verdict, at the verifier — the project's single gate.

    Both modes, because `lenient=True` gates only `VerifyInsns` and a packer dump
    is a first-class load path; the pre-fix build called all 9 crafts valid in
    BOTH. The reason must name an annotation structure, not some invariant the
    repoint also happened to break.
    """
    path = _repoint(tmp_path, mode, f"repoint_{mode}.dex")

    report = dexllm.verify(path, lenient=lenient)
    assert not report[0][
        "valid"
    ], f"a repointed annotations_off ({mode}) must be rejected"
    reason = report[0]["reason"]
    assert "annotation" in reason, reason

    with pytest.raises(Exception):
        dexllm.DexKit(path)


# ── the crash itself: it must not be a signal ────────────────────────────────

_CROSS_REF = """
import sys
import dexllm
try:
    dk = dexllm.DexKit([sys.argv[1]])
    dk.list_classes()
    dk.warm_analysis_caches()
    dk.find_call_sites_to("Ljava/lang/String;->length()I")
    print("LOADED")
except Exception as e:
    print("RAISED", type(e).__name__)
"""


@pytest.mark.parametrize("mode", _REPOINT_MODES)
def test_a_repointed_annotations_off_never_kills_the_process(tmp_path, mode):
    """A SUBPROCESS, because the regression this guards is a SIGSEGV.

    The pre-fix build died with signal 11 here for two of the three modes (which
    of them is decided by what the bytes happen to decode to, not by any check —
    so all three run). A negative returncode IS the regression; a clean rejection
    is the fix. `warm_analysis_caches` / `find_call_sites_to` are the paths the
    issue measured as fatal, while `list_classes` returned normally.
    """
    path = _repoint(tmp_path, mode, f"crash_{mode}.dex")

    p = subprocess.run(
        [sys.executable, "-c", _CROSS_REF, path],
        capture_output=True,
        text=True,
        timeout=120,
        cwd=REPO_ROOT,
    )
    assert p.returncode >= 0, (
        f"killed by signal {-p.returncode} on the {mode} craft — "
        "the annotation walk left the image"
    )
    assert "RAISED" in p.stdout, p.stdout + p.stderr


# ── the offsets INSIDE the subtree ───────────────────────────────────────────


def _zero_member_off(tmp_path, kind, name):
    """Zero the `annotations_off` of one field / method / parameter entry."""
    for cand, raw in _bare_dexes():
        _dirs, members, _sets, _items = _annotation_map(raw)
        for k, pos in members:
            if k != kind:
                continue
            raw = bytearray(raw)
            struct.pack_into("<I", raw, pos, 0)
            return _write(tmp_path, name, raw, cand)
    pytest.skip(f"no bare .dex in the corpus declares a {kind} annotation")


@pytest.mark.parametrize("kind", ["field", "method", "parameter"])
def test_a_zero_member_annotations_off_is_rejected(tmp_path, kind):
    """0 is legal for the CLASS annotations and for nothing else in the directory.

    ART checks these three unconditionally (`:3299` / `:3317` / `:3335`), and
    `CheckOffsetToTypeMap` can never resolve 0. The slicer agrees for two of them
    by throwing (`SLICER_CHECK_NE(annotations, nullptr)`), and for the third it
    does something worse: `ExtractAnnotationSetRefList` has NO zero guard at all,
    so a parameter offset of 0 reads the dex HEADER as a set_ref_list and takes
    its element count from the magic bytes.
    """
    path = _zero_member_off(tmp_path, kind, f"zero_{kind}.dex")

    report = dexllm.verify(path)
    assert not report[0]["valid"], f"a zero {kind} annotations_off must be rejected"
    assert f"{kind}_annotation annotations_off is 0" in report[0]["reason"], report[0][
        "reason"
    ]


def test_a_zero_annotation_set_entry_is_rejected(tmp_path):
    """`ExtractAnnotationItem` SLICER_CHECK_NE(offset, 0)s on this one."""
    for cand, raw in _bare_dexes():
        _dirs, _members, sets, _items = _annotation_map(raw)
        for s in sets:
            if _u32(raw, s) == 0:  # empty set, no entry to zero
                continue
            raw = bytearray(raw)
            struct.pack_into("<I", raw, s + 4, 0)
            path = _write(tmp_path, "zero_set_entry.dex", raw, cand)
            report = dexllm.verify(path)
            assert not report[0]["valid"]
            assert "annotation_set entry offset is 0" in report[0]["reason"], report[0][
                "reason"
            ]
            return
    pytest.skip("no bare .dex in the corpus declares a non-empty annotation_set")


def _param_entries(raw):
    """[(byte offset of a parameter entry's annotations_off, its value)]."""
    out = []
    for kind, pos in _annotation_map(raw)[1]:
        if kind == "parameter":
            out.append((pos, _u32(raw, pos)))
    return out


@pytest.mark.parametrize("mode", _REPOINT_MODES)
def test_a_repointed_parameter_annotations_off_is_rejected(tmp_path, mode):
    """The PARAMETER offset is a set_ref_list, a structure nothing else reaches.

    Added because the mutation matrix found it unguarded: deleting the
    `VerifyAnnotationSetRefList` call entirely left the whole suite green. The
    directory-level repoint above cannot cover it — a set_ref_list is only ever
    named from a parameter entry, so the sets behind it are reachable by no other
    path, and this is also the one offset whose consumer has NO zero guard.
    """
    for cand, raw in _bare_dexes():
        params = _param_entries(raw)
        if not params:
            continue
        pos, off = params[0]
        raw = bytearray(raw)
        struct.pack_into(
            "<I",
            raw,
            pos,
            {"header": 0x70, "map": _u32(raw, 0x34), "shift": off + 2}[mode],
        )
        path = _write(tmp_path, f"repoint_param_{mode}.dex", raw, cand)
        report = dexllm.verify(path)
        assert not report[0][
            "valid"
        ], f"a repointed parameter offset ({mode}) must be rejected"
        assert "annotation" in report[0]["reason"], report[0]["reason"]
        return
    pytest.skip("no bare .dex in the corpus declares a parameter annotation")


_OVERSIZED = 0x7FFFFFFF


@pytest.mark.parametrize(
    "what",
    [
        "annotation_set",
        "annotation_set_ref_list",
        "field_annotations",
        "method_annotations",
    ],
)
def test_an_oversized_annotation_list_is_rejected(tmp_path, what):
    """A count that does not fit is a bound on the VERIFIER's own reads, not only
    on the parser's.

    `set->entries[i]` / the three directory lists are indexed by counts taken
    straight from the file, so without the `CheckListSize` guarding each one the
    verifier walks off the image while deciding whether the image is well formed
    — breaking the contract's first guarantee ("never reads outside [data,
    data+size), never crashes") in the one function that exists to uphold it.
    The matrix found the `annotation_set` case unguarded; the other three are its
    siblings and are pinned for the same reason.

    Each craft is a `u4` overwritten with a `u4`, so nothing moves.
    """
    for cand, raw in _bare_dexes():
        dirs, members, sets, _items = _annotation_map(raw)
        if what == "annotation_set":
            targets = [s for s in sets if _u32(raw, s)]
        elif what == "annotation_set_ref_list":
            targets = [off for _pos, off in _param_entries(raw)]
        else:  # a directory count: fields_size at +4, methods_size at +8
            plus = 4 if what == "field_annotations" else 8
            targets = [d + plus for d in dirs if _u32(raw, d + plus)]
        if not targets:
            continue
        raw = bytearray(raw)
        struct.pack_into("<I", raw, targets[0], _OVERSIZED)
        path = _write(tmp_path, f"oversized_{what}.dex", raw, cand)
        report = dexllm.verify(path)  # must not crash, and must not accept
        assert not report[0]["valid"], f"an oversized {what} count must be rejected"
        assert "List too large" in report[0]["reason"], report[0]["reason"]
        return
    pytest.skip(f"no bare .dex in the corpus has a non-empty {what}")


def test_a_bad_annotation_visibility_is_rejected(tmp_path):
    """ART CheckIntraAnnotationItem :2056 — build/runtime/system, nothing else.

    A one-BYTE craft, so it reaches past the structural offsets entirely: it is
    the leaf of the walk, and nothing before this change looked at it.
    """
    for cand, raw in _bare_dexes():
        _dirs, _members, _sets, items = _annotation_map(raw)
        if not items:
            continue
        raw = bytearray(raw)
        raw[items[0]] = 0x7F
        path = _write(tmp_path, "bad_visibility.dex", raw, cand)
        report = dexllm.verify(path)
        assert not report[0]["valid"]
        assert "Bad annotation visibility" in report[0]["reason"], report[0]["reason"]
        return
    pytest.skip("no bare .dex in the corpus declares an annotation_item")


def _read_uleb(raw, off):
    r = s = 0
    while True:
        x = raw[off]
        off += 1
        r |= (x & 0x7F) << s
        s += 7
        if not (x & 0x80):
            return r, off


def _iter_elements(raw):
    """Yield (header byte offset, type code, payload width) for every element of
    every annotation the class-annotation path reaches.

    Only the FIRST element of each annotation, because the ones after it can only
    be located by decoding the values before them, and a nested array/annotation
    makes that a second parser. One element per annotation is plenty — the corpus
    offers thousands.
    """
    dirs, _members, _sets, _items = _annotation_map(raw)
    for d in dirs:
        ca = _u32(raw, d)
        if not ca:
            continue
        for k in range(_u32(raw, ca)):
            item = _u32(raw, ca + 4 + 4 * k)
            _type_idx, p = _read_uleb(raw, item + 1)  # past the visibility byte
            size, p = _read_uleb(raw, p)
            if size == 0:
                continue
            _name_idx, p = _read_uleb(raw, p)
            yield p, raw[p] & 0x1F, (raw[p] >> 5) + 1


def test_a_bad_encoded_value_type_inside_an_annotation_is_rejected(tmp_path):
    """The CONTENT of the annotation, which is what `ParseAnnotation` walks.

    Added because the matrix found it unguarded: stubbing `VerifyAnnotationItem`
    to check only the visibility byte left the whole suite green — while
    `dex::Reader::ParseAnnotation` is the exact frame the issue's SIGSEGV
    backtrace bottoms out in. Structure without content is not a bound.

    `0x0F` is not one of the 18 encoded_value type codes; only the type bits
    change, so the byte count is untouched.
    """
    for cand, raw in _bare_dexes():
        for pos, _t, _w in _iter_elements(raw):
            raw = bytearray(raw)
            raw[pos] = (raw[pos] & 0xE0) | 0x0F
            path = _write(tmp_path, "bad_value_type.dex", raw, cand)
            report = dexllm.verify(path)
            assert not report[0]["valid"]
            assert "encoded_value bad type code" in report[0]["reason"], report[0][
                "reason"
            ]
            return
    pytest.skip("no bare .dex in the corpus has an annotation element to retype")


# encoded_value type -> the header offset of the id table it indexes.
_INDEXED = {0x17: 0x38, 0x18: 0x40, 0x19: 0x50, 0x1A: 0x58, 0x1B: 0x50}


def test_an_out_of_range_index_inside_an_annotation_is_rejected(tmp_path):
    """An index-carrying element (`STRING`/`TYPE`/`FIELD`/`METHOD`/`ENUM`) whose
    payload is maxed out — the slicer would hand it straight to `GetString` /
    `GetType`.

    The element must be one whose maxed payload actually EXCEEDS its table: an
    index is `arg + 1` bytes, so a 1-byte one tops out at 255 and is a perfectly
    legal string index in any real dex. A first cut ignored that, crafted a
    255 and reported the verifier as broken for accepting it.
    """
    for cand, raw in _bare_dexes():
        for pos, t, w in _iter_elements(raw):
            if t not in _INDEXED or (256**w - 1) < _u32(raw, _INDEXED[t]):
                continue
            raw = bytearray(raw)
            for i in range(w):
                raw[pos + 1 + i] = 0xFF
            path = _write(tmp_path, "bad_value_index.dex", raw, cand)
            report = dexllm.verify(path)
            assert not report[0]["valid"]
            assert "idx" in report[0]["reason"], report[0]["reason"]
            return
    pytest.skip("no bare .dex in the corpus has an out-of-rangeable annotation index")


def test_a_misaligned_annotation_set_is_rejected(tmp_path):
    """The slicer asserts 4-alignment on the directory / set / set_ref_list
    (`SLICER_CHECK_EQ(offset % 4, 0)`), so checking it here turns a throw from
    deep inside the parser into a reject naming the byte."""
    for cand, raw in _bare_dexes():
        _dirs, _members, sets, _items = _annotation_map(raw)
        for s in sets:
            raw = bytearray(raw)
            # +1 keeps it inside the section but breaks the alignment the parser
            # asserts; a u4 overwritten with a u4, so nothing moves.
            for _kind, pos in _annotation_map(raw)[1]:
                if _u32(raw, pos) == s:
                    struct.pack_into("<I", raw, pos, s + 1)
                    path = _write(tmp_path, "misaligned_set.dex", raw, cand)
                    report = dexllm.verify(path)
                    assert not report[0]["valid"]
                    assert "misaligned offset" in report[0]["reason"], report[0][
                        "reason"
                    ]
                    return
    pytest.skip("no bare .dex in the corpus has a member-referenced annotation_set")


def test_a_shared_annotations_subtree_is_walked_once(tmp_path):
    """The walk must be linear in the STRUCTURE, not in the references to it.

    Nothing stops a dex from pointing every class_def at one directory, and this
    walk is reference-driven, so without the per-kind memo it re-walks that
    subtree once per class_def — quadratic, in exactly the way dexllm#20's
    declared-string index was. Measured on the craft below, which the corpus
    itself yields (5,665 class_defs sharing a 1,279-node subtree, length-
    preserving and still verify-valid): 17 ms with the memo, 279 ms without, and
    the gap grows with both factors.

    A RATIO, not a wall-clock budget: both verifies run back to back in this
    process, so machine speed cancels. The craft is required to be genuinely
    amplifying first — on a sample where it is not, the guard would be measuring
    noise.

    The threshold is 5x, and the first cut's 15x was a COIN FLIP that a
    correctness review caught by building the memo-removal mutant and running
    this guard ten times: 5 failed, 5 passed, because the mutant lands at
    14.8-15.1x. The docstring had claimed "~45x without", which was arithmetic on
    two DIFFERENT dexes — the without-memo time of the big shared craft over the
    baseline of a small one. Measured properly, both sides of the ratio being the
    same file: ~0.9x with the memo (the craft walks LESS distinct structure than
    the original), ~15x without. 5x sits an order of magnitude from one side and
    a factor of 3 from the other, which is the margin that was missing.
    """
    import time

    from conftest import corpus_is_narrowed

    best = None
    for raw in _every_dex():
        cds_size, cds_off = struct.unpack_from("<II", raw, 0x60)
        dirs, _members, _sets, _items = _annotation_map(raw)
        fattest = 0
        pick = None
        for d in dirs:
            ca, fs, ms, ps = struct.unpack_from("<IIII", raw, d)
            n = fs + ms + ps + (_u32(raw, ca) if ca else 0)
            if n > fattest:
                fattest, pick = n, d
        if pick and (best is None or cds_size * fattest > best[0]):
            best = (cds_size * fattest, raw, cds_size, cds_off, pick)

    if best is None or best[0] < 500_000:
        if corpus_is_narrowed():
            pytest.skip("the narrowed corpus cannot produce an amplifying craft")
        pytest.skip("no bundled dex yields a large enough shared subtree")

    _work, raw, cds_size, cds_off, pick = best
    # The baseline is the SAME dex unmodified, written out so both sides of the
    # ratio are standalone files verified the same way.
    cand = str(tmp_path / "shared_subtree_base.dex")
    Path(cand).write_bytes(bytes(raw))
    raw = bytearray(raw)
    for i in range(cds_size):
        struct.pack_into("<I", raw, cds_off + i * 32 + 20, pick)
    path = _write(tmp_path, "shared_subtree.dex", raw, cand)
    assert all(r["valid"] for r in dexllm.verify(path)), "the craft must still verify"

    def best_of(p, n=5):
        return min(
            (lambda s: (dexllm.verify(p), time.perf_counter() - s)[1])(
                time.perf_counter()
            )
            for _ in range(n)
        )

    base = best_of(cand)
    shared = best_of(path)
    assert shared < base * 5, (
        f"a shared annotations subtree cost {shared / base:.1f}x the original "
        f"({shared * 1000:.0f}ms vs {base * 1000:.0f}ms) — the walk is re-entering it"
    )


# ── non-discriminating BY DESIGN — these must hold on BOTH sides ─────────────


def test_the_corpus_still_verifies():
    """0 false-reject. Cannot fail pre-fix (the pre-fix verifier checked less), so
    it proves nothing about the fix — it is the guard against the fix being too
    strict, which is the only way this change can break a real user."""
    seen = 0
    for cand, _raw in _bare_dexes():
        assert all(r["valid"] for r in dexllm.verify(cand)), cand
        seen += 1
    for cand in sorted(glob.glob(str(REPO_ROOT / "test_apk" / "APK" / "*.apk"))):
        report = dexllm.verify(cand)
        for r in report:
            # a resources-only container has no dex to verify; that verdict is
            # pre-existing and unrelated
            if "no classes*.dex" in r["reason"]:
                continue
            assert r["valid"], f"{cand}: {r['reason']}"
        seen += 1
    if not seen:
        pytest.skip("no corpus sources to verify")


def test_the_walk_actually_covers_the_corpus_s_annotations():
    """Non-vacuity: the a/b for this change is 0-diff by design, which cannot tell
    "the corpus is well-formed and the walk accepts it" from "the walk is dead".

    The count is what separates them — every directory below is one call the fix
    added, and the fix would be a no-op if it were 0.

    Three outcomes, kept apart: no bare `.dex` at all is the corpus-less CI leg
    and is an ENVIRONMENT fact (skip); dexes that exist but declare no annotation
    goes through `require_corpus_shape`, which fails on the bundled corpus and
    skips under a narrowing; a bundled zero is the regression this pins.
    """
    from conftest import require_corpus_shape

    total = 0
    any_dex = False
    for _cand, raw in _bare_dexes():
        any_dex = True
        dirs, members, sets, items = _annotation_map(raw)
        total += len(dirs) + len(sets) + len(items) + len(members)
    if not any_dex:
        pytest.skip("no bare .dex in the corpus at all")

    require_corpus_shape(
        total > 0,
        "annotation structure in any bare .dex",
        "the fix would be walking nothing",
    )


# ── the directory MEMBER indices (adversarial review, dexllm#56) ─────────────


def _member_entry_bases(raw, kind):
    """-> one list of entry-START byte offsets per per-member LIST of that kind.

    Grouped by list rather than flattened: "the next entry" only means anything
    within one directory's list, and a flat view made the ordering guard below
    skip on the only sample that has the shape (its first two parameter entries
    belong to different directories, so they are not adjacent).
    """
    cds_size, cds_off = struct.unpack_from("<II", raw, 0x60)
    out = []
    seen = set()
    for i in range(cds_size):
        d = _u32(raw, cds_off + i * 32 + 20)
        if not d or d in seen:
            continue
        seen.add(d)
        _ca, fs, ms, ps = struct.unpack_from("<IIII", raw, d)
        p = d + 16
        for k, n in (("field", fs), ("method", ms), ("parameter", ps)):
            if k == kind and n:
                out.append([p + 8 * j for j in range(n)])
            p += 8 * n
    return out


_MEMBER_TABLE = {"field": 0x50, "method": 0x58, "parameter": 0x58}


@pytest.mark.parametrize("kind", ["field", "method", "parameter"])
def test_an_out_of_range_member_index_is_rejected(tmp_path, kind):
    """`CheckIndex` on the three directory member indices — the sole bound on them.

    Added from an adversarial review that CONSTRUCTED the gap: neutering all
    three `CheckIndex` calls left every other guard in this file green, and a
    `classes.dex` whose LAST method-annotation entry carries `method_idx =
    0xFFFFFF00` then verified valid and SIGSEGV'd. The path is the one this whole
    change exists to close — `ExtractAnnotations` → `ParseMethodAnnotation` →
    `GetMethodDecl` → `MethodIds()[idx]`, unbounded in `reader.cc`.

    The LAST entry specifically: the ascending-order check is `i != 0 && last >=
    idx`, so it never fires for a single-entry list nor for an out-of-range value
    at the end, and cannot be mistaken for the bound.
    """
    for cand, raw in _bare_dexes():
        lists = _member_entry_bases(raw, kind)
        if not lists:
            continue
        raw = bytearray(raw)
        struct.pack_into("<I", raw, lists[0][-1], 0xFFFFFF00)
        path = _write(tmp_path, f"bad_{kind}_idx.dex", raw, cand)
        report = dexllm.verify(path)
        assert not report[0]["valid"], f"an out-of-range {kind} index must be rejected"
        assert "Bad index" in report[0]["reason"], report[0]["reason"]
        assert f"{kind} annotation" in report[0]["reason"], report[0]["reason"]
        return
    pytest.skip(f"no bare .dex in the corpus declares a {kind} annotation")


@pytest.mark.parametrize("kind", ["field", "method", "parameter"])
def test_an_out_of_order_member_index_is_rejected(tmp_path, kind):
    """ART's `last_idx >= x && i != 0` ordering rule, which the port mirrors.

    Not a crash bound (the reader never uses ordering to reach memory), but the
    same review showed a mutant deleting it survives everything else — and a
    silently weaker port is exactly what the `// ART :NNNN` anchors exist to
    prevent. Needs a list of at least two entries; the SECOND is set equal to the
    first, which is in range (so no other check can claim the rejection) and
    violates strict ascent.
    """
    for cand, raw in _bare_dexes():
        pair = next(
            (lst for lst in _member_entry_bases(raw, kind) if len(lst) >= 2), None
        )
        if pair is None:
            continue
        raw = bytearray(raw)
        struct.pack_into("<I", raw, pair[1], _u32(raw, pair[0]))
        path = _write(tmp_path, f"unordered_{kind}_idx.dex", raw, cand)
        report = dexllm.verify(path)
        assert not report[0]["valid"], f"an out-of-order {kind} index must be rejected"
        assert "Out-of-order" in report[0]["reason"], report[0]["reason"]
        return
    pytest.skip(f"no bare .dex in the corpus has a {kind} list with two entries")
