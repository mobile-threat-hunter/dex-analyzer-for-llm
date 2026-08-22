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

**The two halves resolve differently, and the asymmetry is the design.** A
`METHOD_TYPE` index is bounded by `VerifyDex` (against `proto_ids_size`), so
resolving it through `GetProto` runs on verified input. A `METHOD_HANDLE` index
is NOT - `method_handle` is out of the verifier's documented scope - so what
stops a crafted one is `ArrayView`'s own `SLICER_CHECK_LT`, which throws rather
than reading out of range. Bringing method_handle into the verifier's scope would
be a new section to validate, with its own false-reject risk, for a value nothing
consumes.

Consequence, and it is deliberate: on a dex with NO method_handle section every
`0x16` index is out of range, so such a value still throws - it just throws from
the index bound now instead of from the missing case. That is the channel
`tests/test_cache_init_failure.py` drives, and it is why fixing this issue did
not take those nine guards away.

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
    src: pathlib.Path, dst: pathlib.Path, new_type: int, zero_index: bool
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
            if zero_index:
                for j in range(arg + 1):
                    raw[p + 1 + j] = 0
            dst.write_bytes(bytes(raw))
            return True
    return False


def _crafted(tmp_path_factory, new_type: int, zero_index: bool, label: str):
    import dexllm

    candidates = sorted(glob.glob(str(REPO_ROOT / "test_apk" / "APK" / "*.dex")))
    if not candidates:
        pytest.skip("no bare .dex in the corpus to craft from")
    out = tmp_path_factory.mktemp("encval") / f"{label}.dex"
    for src in candidates:
        if not _craft(pathlib.Path(src), out, new_type, zero_index):
            continue
        report = dexllm.verify(str(out))
        if report and all(r["valid"] for r in report):
            return out
    require_corpus_shape(
        False,
        "bare .dex declaring a class annotation whose first element can be "
        f"retyped to {label}",
        "the #57 fixture can no longer be built, so the parser gap is unguarded",
    )
    return None  # pragma: no cover - require_corpus_shape raises or skips


@pytest.fixture(scope="module")
def method_type_dex(tmp_path_factory):
    """A dex carrying a LEGAL `METHOD_TYPE` value (proto index 0)."""
    return _crafted(tmp_path_factory, _ENCODED_METHOD_TYPE, True, "method_type")


@pytest.fixture(scope="module")
def method_handle_dex(tmp_path_factory):
    """A dex carrying a `METHOD_HANDLE` value whose index cannot resolve.

    No bundled dex has a method_handle section, so the index is out of range
    whatever it is - which is the point: it separates "the type is not
    implemented" from "this particular index does not resolve".
    """
    return _crafted(tmp_path_factory, _ENCODED_METHOD_HANDLE, False, "method_handle")


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


def test_a_method_handle_value_no_longer_fails_as_an_unknown_type(method_handle_dex):
    """The half that is bounded rather than resolvable, and how to tell.

    The value PARSES now; what it cannot do on this dex is resolve, because
    there is no method_handle section for the index to point into. The
    distinction is observable in the reason, and it is the whole assertion: a
    build that still lacked the case would say "unexpected value type".
    """
    import dexllm

    dk = dexllm.DexKit([str(method_handle_dex)])
    assert dk.list_classes()
    with pytest.raises(RuntimeError) as excinfo:
        dk.warm_analysis_caches()
    reason = str(excinfo.value)
    assert "unexpected value type" not in reason, reason
    assert "SLICER_CHECK_LT" in reason, reason


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


def _craft_on(src: pathlib.Path, dst: pathlib.Path, new_type: int, zero_index: bool):
    """`_craft` against an explicit source, returning the raw bytes it wrote."""
    if not _craft(src, dst, new_type, zero_index):
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
