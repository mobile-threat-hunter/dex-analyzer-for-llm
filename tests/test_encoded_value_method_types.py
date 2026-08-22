"""dexllm(#57, #63) - every decoder must implement every encoded_value the gate accepts.

`Reader::ParseEncodedValue` implemented 16 of the dex spec's 18 `encoded_value`
type codes. `0x15 METHOD_TYPE` and `0x16 METHOD_HANDLE` - legal since API 26
(`const-method-handle` / `invoke-custom` constants) - fell to its
`SLICER_CHECK(!"unexpected value type")`. The verifier ACCEPTS both, correctly:
rejecting a spec-legal value at the gate would false-reject real apps, which this
repo ranks as strictly worse than a throw (and dexllm#58 is what happens when an
added check gets that wrong). So a genuine dex carrying one **in an annotation**
verified clean, loaded, and then threw the moment anything walked its
annotations - `warm_analysis_caches`, the caller/cross-ref family,
`summarize_capabilities`, `find_*_by_annotation`.

Upstream AOSP's slicer has the SAME gap, so this is not a port: `dex_format.h`
has no constant for either code, and neither does the current
`tools/dexter/slicer` in AOSP.

**The two halves used to resolve differently, and dexllm#72 removed the
asymmetry.** A `METHOD_TYPE` index was bounded by `VerifyDex` (against
`proto_ids_size`) from the start, so resolving it through `GetProto` ran on
verified input; a `METHOD_HANDLE` index was not, and what stopped a crafted one
was `ArrayView`'s own `SLICER_CHECK_LT`, which throws rather than reading out of
range. dexllm#72 ported the two ART checks that close it (`:1204`'s width cap and
`:1212`'s bound against `NumMethodHandles()`), so both indices are now gate-
bounded and the leaf checks are unreachable from a loadable dex.

Consequence, and it is what RETIRED a test vehicle: ART's `NumMethodHandles()` is
0 for a dex with no method_handle section, so on such a dex every `0x16` index is
out of range and the DEX no longer loads at all. `tests/test_cache_init_failure.py`
drove exactly that channel; the guards below moved with it - the section-less
craft is now pinned as a REJECTION, and the SUCCESS path is pinned on
`tests/data/invoke-custom.dex`, which has a real section.

**dexllm#63 closed the SAME gap in the OTHER decoder.** This repo has three
encoded_value decoders. `core_ext/dexitem_code_source.cpp`'s
`DecodeEncodedValueText` (static-field initializers, behind `decompile_class`)
also lacked 0x15/0x16, and its `default:` returned WITHOUT skipping the payload,
so the values after one shifted - a silently wrong constant rather than a throw.
`dexkit_ext.cpp`'s `ScanEncodedValueStrings` (the string surfaces) never carried
it, because its `default:` advances. The guards below therefore come in two
layers: a source-level invariant across the case-per-type decoders, and crafted
dexes that exercise what a case-label check cannot see - whether the payload is
consumed, and how MUCH of it.
"""

from __future__ import annotations

import glob
import pathlib
import re
import struct

import pytest
from conftest import REPO_ROOT, require_corpus_shape

_ENCODED_METHOD_TYPE = 0x15
_ENCODED_METHOD_HANDLE = 0x16
_ENCODED_METHOD = 0x1A

# encoded_value types whose payload is exactly `arg + 1` bytes - the ones a
# retype leaves byte-for-byte the same length.
_SAME_WIDTH = frozenset(
    {0x00, 0x02, 0x03, 0x04, 0x06, 0x10, 0x11, 0x17, 0x18, 0x19, 0x1A, 0x1B}
)

_READER = REPO_ROOT / "vendor/dexkit_core/Core/third_party/slicer/reader.cc"
_FORMAT = (
    REPO_ROOT / "vendor/dexkit_core/Core/third_party/slicer/export/slicer/dex_format.h"
)
_VERIFIER = REPO_ROOT / "native/core_ext/dex_verifier.cpp"
_CORE_EXT = REPO_ROOT / "native/core_ext/dexitem_code_source.cpp"
_DEXKIT_EXT = REPO_ROOT / "native/core_ext/dexkit_ext.cpp"


def _strip_comments(text: str) -> str:
    """Remove // and /* */ comments, scanning left to right.

    Two independent regex passes would be wrong: a `//` line can contain `/*`
    (this repo has hit that trap), so the block and line forms must be resolved
    in one pass, in source order.
    """
    out = []
    i, n = 0, len(text)
    while i < n:
        if text.startswith("//", i):
            j = text.find("\n", i)
            i = n if j < 0 else j
        elif text.startswith("/*", i):
            j = text.find("*/", i + 2)
            i = n if j < 0 else j + 2
        else:
            out.append(text[i])
            i += 1
    return "".join(out)


def _uleb(raw: bytearray, off: int) -> tuple[int, int]:
    value = shift = 0
    while True:
        byte = raw[off]
        off += 1
        value |= (byte & 0x7F) << shift
        shift += 7
        if not byte & 0x80:
            return value, off


def _craft(
    src: pathlib.Path,
    dst: pathlib.Path,
    new_type: int,
    zero_index: bool,
    index: int | None = None,
) -> bool:
    """Retype the first class-annotation element, preserving its width.

    Reached the way the slicer reaches it - class_def -> annotations_directory ->
    class_annotations_off -> set -> item -> the first element's encoded_value
    header. Only the TYPE bits change; the `arg` bits, and therefore the payload
    width, are preserved, so every later offset is untouched.

    `zero_index` additionally zeroes the payload, which turns the value into a
    LEGAL one: index 0 is in range for any table a real dex has.
    """
    raw = bytearray(src.read_bytes())
    if raw[:4] != b"dex\n":
        return False
    u4 = lambda o: struct.unpack_from("<I", raw, o)[0]  # noqa: E731

    defs_size, defs_off = struct.unpack_from("<II", raw, 0x60)
    for i in range(defs_size):
        directory = u4(defs_off + i * 32 + 20)
        if not directory or not u4(directory):
            continue
        class_annotations = u4(directory)
        for k in range(u4(class_annotations)):
            item = u4(class_annotations + 4 + 4 * k)
            p = item + 1  # past the visibility byte
            _type_idx, p = _uleb(raw, p)
            size, p = _uleb(raw, p)
            if size == 0:
                continue
            _name_idx, p = _uleb(raw, p)
            header = raw[p]
            if (header & 0x1F) not in _SAME_WIDTH:
                continue
            arg = header >> 5
            raw[p] = (header & 0xE0) | new_type
            if index is not None:
                for j in range(arg + 1):
                    raw[p + 1 + j] = (index >> (8 * j)) & 0xFF
            elif zero_index:
                for j in range(arg + 1):
                    raw[p + 1 + j] = 0
            dst.write_bytes(bytes(raw))
            return True
    return False


def _crafted(
    tmp_path_factory, new_type: int, zero_index: bool, label: str, expect_valid=True
):
    """Craft on the first bare corpus dex that yields the shape AND the verdict.

    THREE outcomes, kept apart on purpose — the discipline
    `tests/test_cache_init_failure.py` had to learn the hard way, and which an
    adversarial reviewer showed this fixture still lacked:

    * no bare `.dex` at all (the corpus-less CI leg)  -> SKIP, an environment fact
    * bare dexes exist but none carries the shape     -> `require_corpus_shape`
    * the shape exists and the VERDICT is wrong       -> FAIL, always

    Without the third, a product regression is reported as "the #57 fixture can
    no longer be built" — the reviewer's `method_handle_count_ = 0xFFFFFFFFu`
    mutant produced exactly that message. `expect_valid` is the verdict the craft
    must PRODUCE, not a convenience: a `0x16` on a section-less dex verified
    until dexllm#72 and is rejected after it.
    """
    import dexllm

    candidates = sorted(glob.glob(str(REPO_ROOT / "test_apk" / "APK" / "*.dex")))
    if not candidates:
        pytest.skip("no bare .dex in the corpus to craft from")
    out = tmp_path_factory.mktemp("encval") / f"{label}.dex"
    craftable = 0
    for src in candidates:
        if not _craft(pathlib.Path(src), out, new_type, zero_index):
            continue
        craftable += 1
        report = dexllm.verify(str(out))
        if report and all(r["valid"] for r in report) == expect_valid:
            return out
    require_corpus_shape(
        craftable > 0,
        "bare .dex declaring a class annotation whose first element can be "
        f"retyped to {label}",
        "the #57 fixture can no longer be built, so the parser gap is unguarded",
    )
    pytest.fail(
        f"{craftable} crafted dex(es) carry the {label} shape but none verified "
        f"{expect_valid} — the VERDICT moved, which is a fact about the product, "
        "not about the corpus"
    )


@pytest.fixture(scope="module")
def method_type_dex(tmp_path_factory):
    """A dex carrying a LEGAL `METHOD_TYPE` value (proto index 0)."""
    return _crafted(tmp_path_factory, _ENCODED_METHOD_TYPE, True, "method_type")


@pytest.fixture(scope="module")
def method_handle_dex(tmp_path_factory):
    """A dex carrying a `METHOD_HANDLE` value whose index cannot resolve.

    No bundled dex has a method_handle section, so the index is out of range
    whatever it is. Until dexllm#72 that dex VERIFIED and threw later; the fixture
    therefore takes `expect_valid=False` now, and the guard below is INVERTED
    (same treatment dexllm#22's overlong and dexllm#29's lone-surrogate guards
    got when their premise turned out to be false).
    """
    return _crafted(
        tmp_path_factory,
        _ENCODED_METHOD_HANDLE,
        False,
        "method_handle",
        expect_valid=False,
    )


# -- the fix ------------------------------------------------------------------


def test_a_legal_method_type_value_loads_and_warms(method_type_dex):
    """The half that is fully fixed: a spec-legal `METHOD_TYPE` now parses.

    Everything about this value is in range - `VerifyDex` bounds the index
    against `proto_ids_size` and the craft sets it to 0 - so nothing downstream
    has any reason to complain. Before the fix the annotation walk threw
    `unexpected value type` and every cache-warming API was unusable.
    """
    import dexllm

    dk = dexllm.DexKit([str(method_type_dex)])
    assert dk.list_classes()
    dk.warm_analysis_caches()
    dk.find_classes_by_annotation("Ljava/lang/annotation/Retention;")


def test_an_unresolvable_method_handle_index_is_rejected_at_the_gate(
    method_handle_dex,
):
    """INVERTED by dexllm#72 - this used to assert the dex LOADED and then threw.

    ART's `NumMethodHandles()` is 0 for a dex with no method_handle section
    (`dex_file.cc` :159 zero-inits it, :290 assigns it only from a map entry), so
    ART rejects every `0x16` index there and `:1212` says so. Rejecting is
    therefore ART parity, not a false-reject - which is the claim this file used
    to make in the opposite direction.

    The reason is asserted because "rejected" alone would pass on any unrelated
    rejection: the craft is one byte on an otherwise untouched dex, so the ONLY
    thing that can be wrong with it is the value it retyped. Both modes, because
    `check_insns_` gates `VerifyInsns` and nothing else.
    """
    import dexllm

    for lenient in (False, True):
        report = dexllm.verify(str(method_handle_dex), lenient=lenient)
        assert report and not any(r["valid"] for r in report), (lenient, report)
        assert "encoded method_handle idx" in report[0]["reason"], (lenient, report)
    with pytest.raises(RuntimeError):
        dexllm.DexKit([str(method_handle_dex)])


# -- the invariant the gap violated -------------------------------------------


def _reader_case_codes() -> set[int]:
    """Type codes `ParseEncodedValue` has a case for, resolved via dex_format.h.

    Comments are stripped first: a `case` label inside a comment is not a case,
    and counting one is the exact trap dexllm#32's opcode guard recorded ("a
    reviewer reverted 6 fixes with the suite green"). The dexllm#57 delta review
    hit it here too, with a mutant that COMMENTED OUT the METHOD_HANDLE case.
    """
    names = dict(
        re.findall(
            r"constexpr u1 (kEncoded\w+)\s*=\s*(0x[0-9a-fA-F]+);",
            _strip_comments(_FORMAT.read_text()),
        )
    )
    body = _strip_comments(_READER.read_text())
    body = body[body.index("Reader::ParseEncodedValue") :]
    body = body[: body.index("\n}\n")]
    return {
        int(names[m], 16)
        for m in re.findall(r"case dex::(kEncoded\w+):", body)
        if m in names
    }


def _core_ext_case_codes() -> set[int]:
    """Type codes `DecodeEncodedValueText` has a case for.

    The SECOND encoded_value decoder in this repo (dexllm#63). It reads
    static-field initializers for `decompile_class`, is a wholly separate
    implementation from the slicer's, and had the same gap: 0x15 / 0x16 fell to
    its `default:`, which consumed the header byte and left the payload unread,
    so every FOLLOWING value in the same `encoded_array` decoded from the wrong
    offset. Comment-stripped for the same reason as the others.
    """
    body = _strip_comments(_CORE_EXT.read_text())
    # Anchored on the PARAMETER list, not the return type: dexllm#64 changed the
    # latter to a struct, and an anchor that names it would have to move with
    # every such change. This one raises loudly if the definition ever goes away.
    start = re.search(r"\w+ DecodeEncodedValueText\(const U1\*& p", body)
    assert start, "DecodeEncodedValueText's definition moved or was renamed"
    body = body[start.start() :]
    body = body[: body.index("        default:")]
    return {int(c, 16) for c in re.findall(r"case (0x[0-9a-fA-F]{2}):", body)}


def _verifier_accepted_codes() -> set[int]:
    """Type codes `VerifyEncodedValue` does not send to its `default: Fail`.

    Comment-stripped for the same reason as `_reader_case_codes`.
    """
    body = _strip_comments(_VERIFIER.read_text())
    body = body[body.index("bool DexVerifier::VerifyEncodedValue") :]
    body = body[: body.index('default: return Fail("encoded_value bad type code")')]
    return {int(c, 16) for c in re.findall(r"case (0x[0-9a-fA-F]{2}):", body)}


@pytest.mark.parametrize(
    "decoder, codes",
    [
        ("slicer ParseEncodedValue", _reader_case_codes),
        ("core_ext DecodeEncodedValueText", _core_ext_case_codes),
    ],
    ids=["slicer", "core_ext"],
)
def test_every_decoder_implements_every_value_the_verifier_accepts(decoder, codes):
    """The invariant this issue was a violation of, stated once for ALL decoders.

    `VerifyDex` is the documented single gate: whatever it accepts, something
    behind it then decodes. A type code the verifier lets through and a decoder
    does not implement is therefore a dex that verifies, loads, and then either
    throws (the slicer, dexllm#57) or silently mis-decodes everything after it
    (core_ext, dexllm#63 - its `default:` left the payload unread, so the values
    following it in the array shifted by one field).

    Both sides are derived FROM SOURCE, so a future code added to the verifier
    without a decoder FAILS rather than shipping. It was scoped to the slicer
    alone until dexllm#63 fixed the second decoder.

    SCOPED TO THE CASE-PER-TYPE DECODERS, which is narrower than "all". A THIRD
    encoded_value decoder exists - `ScanEncodedValueStrings` in
    `native/core_ext/dexkit_ext.cpp`, behind `list_value_strings` /
    `list_class_strings` / `find_classes_declaring_strings` - and it is
    deliberately NOT listed here: it has cases for only the 5 codes it cares
    about, so the `>= 18` floor would reject it. It is IMMUNE to this bug class
    for a structural reason rather than by enumeration - its `default:` ADVANCES
    by the payload width instead of returning - which is pinned separately by
    `test_the_third_decoder_cannot_desync_by_construction`.
    """
    implemented = codes()
    verifier = _verifier_accepted_codes()
    # Non-vacuity: a degraded parse finds few codes. `>=`, not `==`, so that a
    # legitimately-added 19th code fails on the INVARIANT below with a useful
    # message rather than here on an arithmetic identity.
    assert len(verifier) >= 18, sorted(hex(c) for c in verifier)
    assert len(implemented) >= 18, (decoder, sorted(hex(c) for c in implemented))
    assert verifier - implemented == set(), (
        decoder,
        sorted(hex(c) for c in verifier - implemented),
    )


@pytest.mark.parametrize(
    "path, function",
    [
        (_DEXKIT_EXT, "void ScanEncodedValueStrings"),
        (_CORE_EXT, "EncodedValueText DecodeEncodedValueText"),
        (_CORE_EXT, "bool ParseCallSiteArg"),
    ],
    ids=["ScanEncodedValueStrings", "DecodeEncodedValueText", "ParseCallSiteArg"],
)
def test_a_decoder_cannot_desync_by_construction(path, function):
    """A `default:` that ADVANCES makes the invariant a property of the code.

    `ScanEncodedValueStrings` is the one decoder of the three that never carried
    this bug, and not because it enumerates more codes (it has cases for 5): its
    `default:` advances by the payload width instead of returning, so an
    unhandled code costs a missing VALUE and never a shifted array. Nothing
    pinned that, so reverting it to a bare `return;` would reintroduce dexllm#63
    on `list_class_strings` / `find_classes_declaring_strings` with a green suite
    - a correctness reviewer's finding, since this change is what makes the
    property load-bearing enough to state.

    `ParseCallSiteArg` (dexllm#67, the FOURTH decoder — it reads the bootstrap
    arguments of a call site) belongs to the same family for the same structural
    reason: it implements the kinds a call site may LEGALLY carry rather than all
    18, so the `>= 18` floor of the sibling test would reject it, and its
    `default:` advances. It abandons the whole call site on an unhandled code, so
    a desync is not observable there today - which is exactly why the property
    has to be pinned rather than relied on.

    `DecodeEncodedValueText` was given the same arm by dexllm#63, and it needs
    this guard MORE, not less: its `default:` is unreachable on any loadable dex
    (the gate rejects every code outside the 18), so no runtime test can kill a
    mutant that removes it - verified, the mutant passes the whole file. An
    unreachable defence still has to be pinned somewhere, and source is the only
    place left.
    """
    body = _strip_comments(path.read_text())
    body = body[body.index(function) :]
    body = body[: body.index("\n}\n")]
    tail = body[body.rindex("default:") :]
    assert (
        "ReadIntLE(p, end, nbytes)" in tail or "p += std::min(nbytes, avail)" in tail
    ), (
        function,
        tail,
    )


def test_the_two_new_codes_are_named_and_wired():
    """Pinned as literals, so an edit to the constants is a deliberate one."""
    text = _FORMAT.read_text()
    assert "constexpr u1 kEncodedMethodType     = 0x15;" in text
    assert "constexpr u1 kEncodedMethodHandle   = 0x16;" in text
    assert _ENCODED_METHOD_TYPE in _reader_case_codes()
    assert _ENCODED_METHOD_HANDLE in _reader_case_codes()


# -- no regression ------------------------------------------------------------


def test_the_corpus_still_verifies_and_warms(dk):
    """Non-discriminating BY DESIGN - a no-false-reject / no-new-throw floor.

    The bundled corpus carries no 0x15 or 0x16 at all, so this cannot see the
    fix; what it can see is the fix having broken an ordinary annotation.
    """
    dk.warm_analysis_caches()
    assert dk.list_classes()


# -- what the review found: the index bound was against ATTACKER data ----------

_INVOKE_CUSTOM = REPO_ROOT / "tests" / "data" / "invoke-custom.dex"
_METHOD_HANDLE_MAP_TYPE = 0x0008


def _method_handle_section(raw: bytearray) -> tuple[int, int, int] | None:
    """(map-item offset, declared count, section offset) for method_handle."""
    map_off = struct.unpack_from("<I", raw, 0x34)[0]
    count = struct.unpack_from("<I", raw, map_off)[0]
    for i in range(count):
        base = map_off + 4 + i * 12
        kind, _unused, size, off = struct.unpack_from("<HHII", raw, base)
        if kind == _METHOD_HANDLE_MAP_TYPE:
            return base, size, off
    return None


def _craft_on(
    src: pathlib.Path,
    dst: pathlib.Path,
    new_type: int,
    zero_index: bool,
    index: int | None = None,
):
    """`_craft` against an explicit source, returning the raw bytes it wrote.

    `index` writes the payload explicitly, little-endian over the element's own
    (preserved) width - so a one-byte element can carry 0..255, which is what
    makes the fixture's 29-entry section testable at its boundary.
    """
    if not _craft(src, dst, new_type, zero_index, index):
        return None
    return bytearray(dst.read_bytes())


def test_a_resolvable_method_handle_value_loads_and_warms(tmp_path):
    """The SUCCESS path, which no section-less dex can reach.

    Every other `METHOD_HANDLE` fixture here crafts on a dex with no
    method_handle section, so the index is out of range and the only thing
    exercised is the throw. `tests/data/invoke-custom.dex` HAS one (29 entries),
    so index 0 resolves - `GetMethodHandle` -> `ParseMethodHandle` ->
    `GetFieldDecl`/`GetMethodDecl` all run - and that is what makes a real
    API-26+ dex load instead of throwing. It is the half of dexllm#57 that
    matters, and it was untested until the correctness review said so.
    """
    import dexllm

    dst = tmp_path / "valid_mh.dex"
    assert _craft_on(_INVOKE_CUSTOM, dst, _ENCODED_METHOD_HANDLE, True) is not None
    report = dexllm.verify(str(dst))
    assert report and all(r["valid"] for r in report), report
    dk = dexllm.DexKit([str(dst)])
    assert dk.list_classes()
    dk.warm_analysis_caches()  # resolves the handle; must not throw
    dk.find_classes_by_annotation("Ljava/lang/annotation/Retention;")


def test_an_inflated_method_handle_count_is_rejected_at_the_gate(tmp_path):
    """The CRITICAL an adversarial review constructed and RAN.

    `Reader::MethodHandles()` is `section<MethodHandle>(mi->offset, mi->size)` -
    the count comes straight from the map. `CheckMap` bounded only the map item's
    OFFSET, and the method_handle section is described NOWHERE else (unlike every
    other fixed-size table, whose span `CheckHeader` bounds off the header). So
    `ArrayView::operator[]`'s `SLICER_CHECK_LT` bounded the index against
    attacker-controlled data: an inflated count plus a large `0x16` index read
    ~134 MB past a 2.5 KB file - SIGSEGV on a dex `verify()` called valid, which
    no `catch (...)` can contain. dexllm#57's parser fix is what woke it: before
    it, nothing ever called `GetMethodHandle`.

    The gate now bounds the section's EXTENT, so the dex does not load at all.
    That assertion is exact and holds wherever the read would have landed -
    unlike a crash test, whose reachability depends on the page mapping.
    """
    import dexllm

    raw = bytearray(_INVOKE_CUSTOM.read_bytes())
    section = _method_handle_section(raw)
    assert section is not None, "the fixture must HAVE a method_handle section"
    base, count, _off = section
    assert count > 0, count
    struct.pack_into("<I", raw, base + 4, 0x2000000)  # count: 29 -> 33,554,432
    dst = tmp_path / "inflated_mh.dex"
    dst.write_bytes(bytes(raw))

    report = dexllm.verify(str(dst))
    assert report and not any(r["valid"] for r in report), report
    assert "map section span" in report[0]["reason"], report
    with pytest.raises(RuntimeError):
        dexllm.DexKit([str(dst)])


def test_the_unmodified_fixture_verifies(tmp_path):
    """Non-discriminating BY DESIGN - the premise of the two guards above, and a
    no-false-reject check on the new extent bound against a REAL section."""
    import dexllm

    report = dexllm.verify(str(_INVOKE_CUSTOM))
    assert report and all(r["valid"] for r in report), report
    dk = dexllm.DexKit([str(_INVOKE_CUSTOM)])
    dk.warm_analysis_caches()
    assert dk.list_classes()


_BEAN = REPO_ROOT / "vendor" / "dexkit_core" / "Core" / "dexkit" / "dex_item.cpp"


def test_the_bean_default_arm_assigns_rather_than_falling_through():
    """`AnnotationEncodeValueBean::type` is uninitialised, so `default:` must
    assign.

    A bare `default: break;` leaves an enum member indeterminate for any type
    code the switch does not name - which is `0x19 VALUE_FIELD` (already, before
    this change) and now `0x15`/`0x16` as well. The path is unreachable from
    dexllm - `GetAnnotationEncodeValueBean` is only reached from DexKit's
    Java-facing annotation API, which no binding exposes - so no product-level
    test can reach it and only the source can be pinned. That is why this guard
    exists at all: without it, reverting the arm passes the entire suite.
    """
    body = _strip_comments(_BEAN.read_text())
    start = body.index(
        "AnnotationEncodeValueBean DexItem::GetAnnotationEncodeValueBean"
    )
    end = body.index("\n}\n", start)
    fn = body[start:end]
    assert "default: break;" not in fn, (
        "GetAnnotationEncodeValueBean has a bare `default: break;` again - a type "
        "code it does not name would leave `bean.type` indeterminate"
    )
    # Non-vacuity: the slice must actually be that function, with both switches.
    assert fn.count("switch (encoded_value->type)") == 2, fn.count("switch")
    assert "NullValue" in fn


# -- dexllm#63: the SECOND decoder left the payload unread ---------------------

_CRAFT_CLASS = "LTestLinkerMethodMinimalArguments;"


def _first_static_value(raw: bytes, descriptor: str) -> tuple[int, int]:
    """(offset of the first static value's header byte, declared value count).

    Located by walking `class_defs` rather than hard-coded, so a substituted or
    regenerated fixture fails loudly here instead of being patched at a wrong
    offset. Asserts every shape the crafts need: FOUR values (the bodies index
    `lines[0..3]`, and the desync is only observable through the values that
    FOLLOW the crafted one), a first value that is a 1-byte INT so a retype is
    length-preserving, and a first payload byte small enough to be a legal index
    into `proto_ids` / `method_ids` - without which the 0x15 and 0x1a legs would
    hard-FAIL on `assert row["valid"]` instead of reporting the real reason.
    """

    def uleb(off: int) -> tuple[int, int]:
        value = shift = 0
        while True:
            byte = raw[off]
            off += 1
            value |= (byte & 0x7F) << shift
            shift += 7
            if not byte & 0x80:
                return value, off

    type_ids_off = struct.unpack_from("<I", raw, 0x44)[0]
    string_ids_off = struct.unpack_from("<I", raw, 0x3C)[0]
    defs_size, defs_off = struct.unpack_from("<II", raw, 0x60)

    def descriptor_of(type_idx: int) -> str:
        str_idx = struct.unpack_from("<I", raw, type_ids_off + type_idx * 4)[0]
        data = struct.unpack_from("<I", raw, string_ids_off + str_idx * 4)[0]
        n, q = uleb(data)
        return raw[q : q + n].decode("utf-8", "replace")

    for i in range(defs_size):
        base = defs_off + i * 32
        if descriptor_of(struct.unpack_from("<I", raw, base)[0]) != descriptor:
            continue
        static_values_off = struct.unpack_from("<I", raw, base + 28)[0]
        assert static_values_off, f"{descriptor} has no static_values"
        count, header = uleb(static_values_off)
        assert count >= 4, (
            f"{descriptor} now has {count} static value(s); the bodies index "
            "four, and the desync is only observable through the values that "
            "FOLLOW the crafted one"
        )
        assert raw[header] == 0x04, (
            f"{descriptor}'s first static value is no longer a 1-byte INT "
            f"({raw[header]:#04x}), so a retype would not be length-preserving"
        )
        index = raw[header + 1]
        protos = struct.unpack_from("<I", raw, 0x48)[0]
        methods = struct.unpack_from("<I", raw, 0x58)[0]
        assert index < min(protos, methods), (
            f"{descriptor}'s first payload byte ({index}) is not a legal index "
            f"into proto_ids ({protos}) or method_ids ({methods}), so a retype "
            "would be rejected by the verifier rather than decoded"
        )
        return header, count
    raise AssertionError(f"{descriptor} is not in the fixture")


def _retype_first_static_value(value_type: int, dst: pathlib.Path) -> None:
    """Rewrite 5 bits of ONE byte: the first static value's type code.

    `arg` is left alone, so the payload keeps its width and every later offset,
    section size and `static_values` boundary is untouched - the dex still
    verifies, which is the premise every assertion below rests on.

    CONSEQUENCE, and it is why a second craft exists: the fixture's `arg` is 0,
    so this helper can only ever produce a ONE-byte payload. A decoder that
    hard-codes that width passes every guard built on it - see
    `test_a_multi_byte_index_payload_is_consumed_in_full`.
    """
    raw = bytearray(_INVOKE_CUSTOM.read_bytes())
    header, _count = _first_static_value(bytes(raw), _CRAFT_CLASS)
    raw[header] = (raw[header] & 0xE0) | value_type
    dst.write_bytes(bytes(raw))


def _static_finals(path: pathlib.Path) -> list[str]:
    import dexllm

    src = dexllm.DexKit(str(path)).decompile_class(_CRAFT_CLASS)
    return [line.strip() for line in src.split("\n") if "static final" in line]


@pytest.mark.parametrize(
    "value_type",
    [_ENCODED_METHOD_TYPE, _ENCODED_METHOD_HANDLE, _ENCODED_METHOD],
    ids=["method_type_0x15", "method_handle_0x16", "method_0x1a"],
)
def test_a_no_literal_static_value_does_not_shift_the_values_after_it(
    tmp_path, value_type
):
    """dexllm#63: the payload must be consumed even when nothing is rendered.

    Pre-fix the `default:` arm consumed the header byte only, so the 1-byte
    payload was read as the NEXT value's header: the first following field lost
    its initializer outright and the two after it took their predecessor's
    constant - `FAILURE_TYPE_NONE = 2` for a field that is 0. Silently wrong,
    which is worse than garbled: an analyst gets a confident wrong fact with no
    error anywhere.

    `0x1a` is here because this change MODIFIED it (its advance moved from an
    unbounded `p += nbytes` to `ReadIntLE`) and nothing exercised it - an
    adversarial reviewer built the mutant that drops 0x1a's consume alone and it
    passed the entire suite AND ART's own fuzz corpus.
    """
    dst = tmp_path / f"retyped-{value_type:#04x}.dex"
    _retype_first_static_value(value_type, dst)

    import dexllm

    row = dexllm.verify(str(dst))[0]
    assert row["valid"], row  # the premise: a length-preserving retype still verifies

    lines = _static_finals(dst)
    # The crafted value RENDERS - since dexllm#64 all three of these have a
    # spelling, `= MethodType.methodType(...)` for 0x15 and a trailing `// = ...`
    # comment for the two with no Java expression form. This assertion used to
    # read `endswith("RETURNS_NULL;")`, i.e. "renders nothing", which was the
    # PREMISE of the day rather than the subject of this test; it is inverted
    # rather than deleted, on the dexllm#22 / dexllm#29 / dexllm#45 precedent.
    assert not lines[0].endswith("RETURNS_NULL;"), lines
    # ...and the three that FOLLOW it keep their own values. This is the assertion
    # the fix is about; it is the one that fails pre-dexllm#63.
    assert lines[1].endswith("= 2;"), lines
    assert lines[2].endswith("= 0;"), lines
    assert lines[3].endswith("= 3;"), lines


# The width the guard above CANNOT reach: its craft preserves `arg`, which is 0
# in the fixture, so a decoder hard-coding a 1-byte payload passes it. Both
# reviewers found that hole independently, and it is not academic - a proto index
# >= 256 is ordinary, and the verifier's `idx` lambda does not require a minimal
# encoding, so `arg >= 1` is legal for any of the three.
#
# This replacement array is byte-for-byte the same length as the original
# `04 01 | 04 02 | 04 00 | 04 03` and still declares FOUR values:
#
#     35 01 00   0x15 METHOD_TYPE, arg=1  -> a TWO-byte proto index (= 1)
#     17 02      0x17 STRING,      arg=0  -> string index 2
#     04 03      0x04 INT,         arg=0  -> 3
#     1e         0x1e NULL,        no payload
#
# so the string lands on the SECOND field if and only if the two-byte index was
# consumed in full. That is an assertion about the right answer, not merely a
# difference from some mutant.
_WIDE_ARRAY = bytes([0x35, 0x01, 0x00, 0x17, 0x02, 0x04, 0x03, 0x1E])
_WIDE_STRING_INDEX = 2


def _wide_craft(dst: pathlib.Path) -> str:
    """Write the fixture with the wide-index array spliced in; return the string."""
    raw = bytearray(_INVOKE_CUSTOM.read_bytes())
    header, count = _first_static_value(bytes(raw), _CRAFT_CLASS)
    assert count == 4, count  # the replacement array below declares four values
    original = bytes(raw[header : header + len(_WIDE_ARRAY)])
    assert len(original) == len(_WIDE_ARRAY)
    raw[header : header + len(_WIDE_ARRAY)] = _WIDE_ARRAY
    dst.write_bytes(bytes(raw))

    string_ids_off = struct.unpack_from("<I", bytes(raw), 0x3C)[0]
    data = struct.unpack_from(
        "<I", bytes(raw), string_ids_off + _WIDE_STRING_INDEX * 4
    )[0]
    length = raw[data]  # single-byte uleb for a short string
    assert length < 0x80, "the oracle string's uleb length is not one byte"
    return bytes(raw[data + 1 : data + 1 + length]).decode()


def test_a_multi_byte_index_payload_is_consumed_in_full(tmp_path):
    """The payload WIDTH, which the `arg`-preserving craft cannot express.

    A decoder that consumes one byte instead of `arg + 1` desyncs exactly as
    pre-fix, and the guard above cannot see it. Here the second field's value is
    a STRING whose position depends on the first value's width, so getting the
    width wrong moves it - and the assertion names the string.
    """
    dst = tmp_path / "wide-index.dex"
    expected = _wide_craft(dst)

    import dexllm

    row = dexllm.verify(str(dst))[0]
    assert row["valid"], row

    lines = _static_finals(dst)
    # Renders since dexllm#64 - see the inversion note on the guard above; what
    # this test is ABOUT is the three lines below, which only line up when the
    # full (arg + 1)-byte payload was consumed.
    assert not lines[0].endswith("RETURNS_NULL;"), lines
    assert lines[1].endswith(f'= "{expected}";'), lines
    assert lines[2].endswith("= 3;"), lines
    assert lines[3].endswith("= null;"), lines


def test_the_wide_index_craft_agrees_with_an_INDEPENDENT_decoder(tmp_path):
    """Adjudicated by a decoder that is NOT the one under test.

    `list_class_strings` reads the same `static_values` array through
    `ScanEncodedValueStrings` (dexkit_ext.cpp) - the third decoder, which never
    carried this bug because its `default:` advances. If it reports the string
    and `decompile_class` puts it on the right field, two independent
    implementations agree on where the array's values begin.
    """
    dst = tmp_path / "wide-oracle.dex"
    expected = _wide_craft(dst)

    import dexllm

    reported = dexllm.DexKit(str(dst)).list_class_strings(_CRAFT_CLASS)
    assert expected in reported, (expected, reported)
    # ...and it is genuinely the CRAFT that put it there.
    assert expected not in dexllm.DexKit(str(_INVOKE_CUSTOM)).list_class_strings(
        _CRAFT_CLASS
    )


def test_the_uncrafted_fixture_renders_every_initializer():
    """Non-discriminating BY DESIGN - the baseline the craft is measured against.

    Without it, "the values after the crafted one are 2/0/3" could be asserting
    a coincidence rather than a restoration.
    """
    lines = _static_finals(_INVOKE_CUSTOM)
    assert [line.rsplit("= ", 1)[-1] for line in lines] == [
        "1;",
        "2;",
        "0;",
        "3;",
    ], lines


# -- dexllm#72: the index INTO the section is capped and bounded at the gate ---
#
# ART `CheckEncodedValue`'s `kDexAnnotationMethodHandle` arm rejects
# `value_arg > 3` (:1204) and bounds the decoded index against
# `NumMethodHandles()` (:1212). Both arrive together here, because the arm now
# goes through the shared `idx` lambda like every other index-bearing one.
#
# Every craft below is on the COMMITTED fixture, so these run in the corpus-less
# CI leg and under any `$DEXLLM_TEST_APK` narrowing. The fixture is the only
# source in the repo with a real method_handle section, which is what makes the
# ACCEPT direction testable at all - without it every index is out of range and
# a bound that rejected everything would pass.

_CRAFT_CLASS = "LTestLinkerMethodMinimalArguments;"


def _uleb_bytes(value: int) -> bytes:
    out = bytearray()
    while True:
        b = value & 0x7F
        value >>= 7
        out.append(b | (0x80 if value else 0))
        if not value:
            return bytes(out)


def _class_def_offset(raw: bytes) -> int:
    """Offset of `_CRAFT_CLASS`'s class_def, found by walking the table."""
    type_ids_off = struct.unpack_from("<I", raw, 0x44)[0]
    string_ids_off = struct.unpack_from("<I", raw, 0x3C)[0]
    defs_size, defs_off = struct.unpack_from("<II", raw, 0x60)
    for i in range(defs_size):
        base = defs_off + i * 32
        type_idx = struct.unpack_from("<I", raw, base)[0]
        str_idx = struct.unpack_from("<I", raw, type_ids_off + type_idx * 4)[0]
        data = struct.unpack_from("<I", raw, string_ids_off + str_idx * 4)[0]
        n, q = _uleb(bytearray(raw), data)
        if raw[q : q + n].decode("utf-8", "replace") == _CRAFT_CLASS:
            return base
    raise AssertionError(f"{_CRAFT_CLASS} is not in the fixture")


def _append_static_value(dst: pathlib.Path, value: bytes) -> None:
    """Append a one-element `encoded_array` at EOF and repoint `static_values_off`.

    The in-place craft used everywhere else in this file preserves the element's
    WIDTH, so it can only ever produce `value_arg` values the fixture already
    has - and `value_arg >= 4` is exactly what ART :1204 is about. This one trades
    length-preservation for reach and pays for it by asserting the verdict.
    """
    raw = bytearray(_INVOKE_CUSTOM.read_bytes())
    base = _class_def_offset(bytes(raw))
    while len(raw) % 4:
        raw.append(0)
    new_off = len(raw)
    raw += _uleb_bytes(1) + value
    while len(raw) % 4:  # the slicer's ValidateHeader wants a 4-aligned data_size
        raw.append(0)
    struct.pack_into("<I", raw, base + 28, new_off)
    grown = len(raw) - struct.unpack_from("<I", raw, 0x20)[0]
    struct.pack_into("<I", raw, 0x20, len(raw))  # file_size
    struct.pack_into("<I", raw, 0x68, struct.unpack_from("<I", raw, 0x68)[0] + grown)
    dst.write_bytes(bytes(raw))


def _handle_count() -> int:
    section = _method_handle_section(bytearray(_INVOKE_CUSTOM.read_bytes()))
    assert section is not None, "the fixture must HAVE a method_handle section"
    _base, count, _off = section
    assert count > 1, count  # `count - 1` has to be a DIFFERENT index from 0
    return count


@pytest.mark.parametrize("value_arg", list(range(8)))
def test_a_method_handle_value_wider_than_four_bytes_is_rejected(tmp_path, value_arg):
    """ART :1204. Widths 1..4 are legal; 5..8 are not, and the cut is EXACT.

    Asserting both sides is the point: a bound that rejected every width would
    satisfy the reject half on its own, and `value_arg == 3` is the one that
    says it does not. The payload is zero bytes, i.e. index 0, which resolves on
    this fixture - so the ONLY thing under test is the width.
    """
    import dexllm

    dst = tmp_path / f"mh-width{value_arg}.dex"
    _append_static_value(dst, bytes([(value_arg << 5) | 0x16]) + bytes(value_arg + 1))
    rows = dexllm.verify(str(dst))
    valid = bool(rows and all(r["valid"] for r in rows))
    assert valid == (value_arg <= 3), (value_arg, rows)
    if not valid:
        assert "bad index size" in rows[0]["reason"], rows


@pytest.mark.parametrize("lenient", [False, True])
def test_the_method_handle_index_bound_is_exactly_the_declared_count(tmp_path, lenient):
    """ART :1212, pinned at the boundary in BOTH directions.

    `count - 1` must be ACCEPTED and `count` REJECTED - an off-by-one that admits
    `count` passes any reject-only assertion, and one that rejects `count - 1`
    passes any accept-only one. Both verify modes, because `check_insns_` gates
    `VerifyInsns` and nothing else, and a packer dump is the population most
    likely to carry a malformed value.
    """
    import dexllm

    n = _handle_count()
    for index, want_valid in ((0, True), (n - 1, True), (n, False), (n + 7, False)):
        dst = tmp_path / f"mh-idx{index}-{lenient}.dex"
        # The element's width is PRESERVED, so this craft carries an index < 256
        # - which is why the fixture's 29-entry section is what makes a boundary
        # test possible at all.
        assert (
            _craft_on(_INVOKE_CUSTOM, dst, _ENCODED_METHOD_HANDLE, False, index)
            is not None
        ), index
        rows = dexllm.verify(str(dst), lenient=lenient)
        valid = bool(rows and all(r["valid"] for r in rows))
        assert valid == want_valid, (index, want_valid, lenient, rows)
        if not valid:
            assert "encoded method_handle idx" in rows[0]["reason"], rows


def test_the_carriers_still_verify_and_warm():
    """0 false-reject, on the three committed dexes that HAVE a real section.

    Non-discriminating BY DESIGN in the accept direction - it must hold on both
    sides of dexllm#72 - but it is the only thing standing between a new
    rejection direction and a real API-26+ dex, which is the one way an added
    check can fail (dexllm#58).
    """
    import dexllm

    carriers = [
        REPO_ROOT / "tests" / "data" / "invoke-custom.dex",
        REPO_ROOT / "tests" / "data" / "method_handles.dex",
        REPO_ROOT / "tests" / "data" / "const-method-handle.dex",
    ]
    for path in carriers:
        assert path.is_file(), path
        section = _method_handle_section(bytearray(path.read_bytes()))
        assert section is not None, f"{path.name} must carry a section"
        rows = dexllm.verify(str(path))
        assert rows and all(r["valid"] for r in rows), (path.name, rows)
        dk = dexllm.DexKit([str(path)])
        dk.warm_analysis_caches()
        assert dk.list_classes()


_METHOD_HANDLE_MAP_TYPE_COUNT_OFF = (
    4  # map_item: {u2 type, u2 unused, u4 size, u4 offset}
)


@pytest.mark.parametrize("lenient", [False, True])
def test_a_dex_declaring_no_handles_rejects_every_index(tmp_path, lenient):
    """`count == 0` — the headline property, on a COMMITTED fixture.

    ART's `NumMethodHandles()` is 0 when the map declares no method_handle
    section, so ART rejects every `0x16` index on such a dex; that is the whole
    argument for why closing this at the gate is parity rather than a
    false-reject, and it is what retired the dexllm#55 vehicle.

    Its sibling `test_an_unresolvable_method_handle_index_is_rejected_at_the_gate`
    drives a genuinely section-less bare dex, which the CI leg does not have —
    so this one ZEROES the fixture's own map count instead, which is
    length-preserving (one `u4`), reaches the same `count == 0` state, and runs
    everywhere. Index 0 is the sharpest case: it is in range for ANY nonzero
    count, so a bound that read `> count` instead of `>= count`, or that skipped
    the check when the section is absent, would accept it.
    """
    import dexllm

    raw = bytearray(_INVOKE_CUSTOM.read_bytes())
    section = _method_handle_section(raw)
    assert section is not None, "the fixture must HAVE a method_handle section"
    base, count, _off = section
    assert count > 0, count
    struct.pack_into("<I", raw, base + _METHOD_HANDLE_MAP_TYPE_COUNT_OFF, 0)
    # A 0x16 whose index is 0 — legal on the unmodified fixture, out of range the
    # moment the section declares nothing.
    dst = tmp_path / f"mh-nocount-{lenient}.dex"
    assert _craft_on(_INVOKE_CUSTOM, dst, _ENCODED_METHOD_HANDLE, True) is not None
    patched = bytearray(dst.read_bytes())
    struct.pack_into("<I", patched, base + _METHOD_HANDLE_MAP_TYPE_COUNT_OFF, 0)
    dst.write_bytes(bytes(patched))

    rows = dexllm.verify(str(dst), lenient=lenient)
    assert rows and not any(r["valid"] for r in rows), (lenient, rows)
    assert "encoded method_handle idx" in rows[0]["reason"], rows
    # The premise: zeroing the count alone does NOT make the dex invalid, so the
    # rejection above is attributable to the 0x16 and not to the craft.
    only_count = tmp_path / f"mh-nocount-clean-{lenient}.dex"
    only_count.write_bytes(bytes(raw))
    clean = dexllm.verify(str(only_count), lenient=lenient)
    assert clean and all(r["valid"] for r in clean), (lenient, clean)


_MULTIDEX = REPO_ROOT / "tests" / "data" / "multidex.apk"


def _append_static_value_on(src: bytes, value: bytes, cls: str) -> bytes:
    """`_append_static_value`, against an arbitrary dex and class descriptor."""
    raw = bytearray(src)
    type_ids_off = struct.unpack_from("<I", raw, 0x44)[0]
    string_ids_off = struct.unpack_from("<I", raw, 0x3C)[0]
    defs_size, defs_off = struct.unpack_from("<II", raw, 0x60)
    base = None
    for i in range(defs_size):
        b = defs_off + i * 32
        ti = struct.unpack_from("<I", raw, b)[0]
        si = struct.unpack_from("<I", raw, type_ids_off + ti * 4)[0]
        data = struct.unpack_from("<I", raw, string_ids_off + si * 4)[0]
        n, q = _uleb(raw, data)
        if raw[q : q + n].decode("utf-8", "replace") == cls:
            base = b
            break
    assert base is not None, cls
    while len(raw) % 4:
        raw.append(0)
    new_off = len(raw)
    raw += _uleb_bytes(1) + value
    while len(raw) % 4:
        raw.append(0)
    struct.pack_into("<I", raw, base + 28, new_off)
    grown = len(raw) - struct.unpack_from("<I", raw, 0x20)[0]
    struct.pack_into("<I", raw, 0x20, len(raw))
    struct.pack_into("<I", raw, 0x68, struct.unpack_from("<I", raw, 0x68)[0] + grown)
    return bytes(raw)


@pytest.mark.parametrize("lenient", [False, True])
def test_a_dex_with_no_method_handle_section_at_all_rejects_index_zero(
    tmp_path, lenient
):
    """The INITIALIZER path — `u4 method_handle_count_ = 0;` — and nothing else.

    Its sibling above reaches `count == 0` by ZEROING the fixture's map item,
    which goes through `CheckMap`'s ASSIGNMENT and therefore overwrites whatever
    the member was initialised to. An adversarial reviewer built the one-token
    mutant that separates them — `= 0xFFFFFFFFu` — and it passed the whole
    corpus-less suite twice, restoring the pre-dexllm#72 behaviour exactly, while
    being the very default that makes "0 for a dex with no such section" ART
    parity rather than a false-reject. Only a dex with NO method_handle map item
    at all exercises it.

    `tests/data/multidex.apk` is that dex and it is COMMITTED, so this runs in
    the corpus-less CI leg and under any `$DEXLLM_TEST_APK` narrowing. Index 0 is
    the payload because it is in range for every nonzero count — the sharpest
    value a wrong default can let through.
    """
    import zipfile

    import dexllm

    with zipfile.ZipFile(_MULTIDEX) as z:
        src = z.read("classes.dex")
    assert _method_handle_section(bytearray(src)) is None, "the premise"
    cls = _first_class_with_static_values_slot(src)
    value = bytes([_ENCODED_METHOD_HANDLE]) + bytes([0])  # arg=0, index 0
    dst = tmp_path / f"nosection-{lenient}.dex"
    dst.write_bytes(_append_static_value_on(src, value, cls))

    rows = dexllm.verify(str(dst), lenient=lenient)
    assert rows and not any(r["valid"] for r in rows), (lenient, rows)
    assert "encoded method_handle idx" in rows[0]["reason"], rows

    # The craft itself is sound: the same append with a plain INT verifies, so
    # the rejection is attributable to the 0x16 and not to the surgery.
    ok = tmp_path / f"nosection-ok-{lenient}.dex"
    ok.write_bytes(_append_static_value_on(src, bytes([0x04, 7]), cls))
    clean = dexllm.verify(str(ok), lenient=lenient)
    assert clean and all(r["valid"] for r in clean), (lenient, clean)


def _first_class_with_static_values_slot(src: bytes) -> str:
    """A class descriptor whose class_def this craft may repoint.

    Any class_def will do — `static_values_off` is repointed wholesale, so an
    existing array is replaced rather than appended to. The first one keeps the
    choice deterministic.
    """
    raw = bytearray(src)
    type_ids_off = struct.unpack_from("<I", raw, 0x44)[0]
    string_ids_off = struct.unpack_from("<I", raw, 0x3C)[0]
    defs_size, defs_off = struct.unpack_from("<II", raw, 0x60)
    assert defs_size, "the fixture must declare a class"
    ti = struct.unpack_from("<I", raw, defs_off)[0]
    si = struct.unpack_from("<I", raw, type_ids_off + ti * 4)[0]
    data = struct.unpack_from("<I", raw, string_ids_off + si * 4)[0]
    n, q = _uleb(raw, data)
    return raw[q : q + n].decode("utf-8", "replace")
