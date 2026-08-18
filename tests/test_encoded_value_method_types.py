"""dexllm(#57) - the parser must implement every encoded_value the gate accepts.

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
    """Type codes `ParseEncodedValue` has a case for, resolved via dex_format.h."""
    names = dict(
        re.findall(
            r"constexpr u1 (kEncoded\w+)\s*=\s*(0x[0-9a-fA-F]+);", _FORMAT.read_text()
        )
    )
    body = _READER.read_text()
    body = body[body.index("Reader::ParseEncodedValue") :]
    body = body[: body.index("\n}\n")]
    return {
        int(names[m], 16)
        for m in re.findall(r"case dex::(kEncoded\w+):", body)
        if m in names
    }


def _verifier_accepted_codes() -> set[int]:
    """Type codes `VerifyEncodedValue` does not send to its `default: Fail`."""
    body = _VERIFIER.read_text()
    body = body[body.index("bool DexVerifier::VerifyEncodedValue") :]
    body = body[: body.index('default: return Fail("encoded_value bad type code")')]
    return {int(c, 16) for c in re.findall(r"case (0x[0-9a-fA-F]{2}):", body)}


def test_the_parser_implements_every_value_the_verifier_accepts():
    """The invariant this issue was a violation of, stated directly.

    `VerifyDex` is the documented single gate: whatever it accepts, the core
    then parses. A type code the verifier lets through and the parser does not
    implement is therefore a dex that verifies, loads, and throws later - which
    is exactly what 0x15 and 0x16 did. Deriving both sets from source means a
    future code added to one side without the other FAILS rather than shipping.
    """
    reader = _reader_case_codes()
    verifier = _verifier_accepted_codes()
    # Non-vacuity: both parses must have found the whole spec surface.
    assert len(verifier) == 18, sorted(hex(c) for c in verifier)
    assert len(reader) == 18, sorted(hex(c) for c in reader)
    assert verifier - reader == set(), sorted(hex(c) for c in verifier - reader)


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
