r"""dexllm#29 — a string LITERAL may hold a LONE SURROGATE, and it must round-trip.

`VerifyMutf8` checks sequence shape and canonicality, not surrogate PAIRING —
which is exactly what ART's `CheckIntraStringDataItem` does — so a lone surrogate
in a `const-string` operand is legal, loadable input. The asymmetry with
identifiers is correct and deliberate: `IsValidPartOfMemberNameUtf8Slow` accepts a
leading surrogate only when a trailing one follows, so a NAME cannot hold one.

Before the fix the value came back as U+FFFD and `find_*_using_strings` then
missed it silently — the forward and reverse string APIs disagreeing with no
error. The loss was never Python's (`"\ud800"` is a legal `str`); it was
pybind11's strict UTF-8 codec on both sides of the boundary, so the guards below
exercise the ROUND TRIP, not just the decode.
"""

import glob
import struct
from pathlib import Path

import pytest

import dexllm

REPO_ROOT = Path(__file__).resolve().parents[1]

# U+D800 as its standard 3-byte form — exactly the bytes the pool stores, and
# exactly what CPython's `surrogatepass` handler encodes `"\ud800"` to.
_LONE = b"\xed\xa0\x80"


def _uleb(buf, off):
    r = s = 0
    while True:
        x = buf[off]
        off += 1
        r |= (x & 0x7F) << s
        s += 7
        if not (x & 0x80):
            return r, off


def _strings(buf):
    """(index, data_offset, utf16_len, bytes_offset, bytes) for every string_data."""
    n, off0 = struct.unpack_from("<II", buf, 56)
    out = []
    for i in range(n):
        o = struct.unpack_from("<I", buf, off0 + 4 * i)[0]
        ln, d = _uleb(buf, o)
        out.append((i, o, ln, d, bytes(buf[d : buf.index(0, d)])))
    return out


def _codepoints(raw):
    """MUTF-8 bytes → code points, the order ART's string_ids comparator uses."""
    units, p = [], 0
    while p < len(raw):
        c = raw[p]
        if c < 0x80:
            units.append(c)
            p += 1
        elif c & 0xE0 == 0xC0:
            units.append(((c & 0x1F) << 6) | (raw[p + 1] & 0x3F))
            p += 2
        else:
            units.append(
                ((c & 0x0F) << 12) | ((raw[p + 1] & 0x3F) << 6) | (raw[p + 2] & 0x3F)
            )
            p += 3
    out, i = [], 0
    while i < len(units):
        if (
            0xD800 <= units[i] <= 0xDBFF
            and i + 1 < len(units)
            and 0xDC00 <= units[i + 1] <= 0xDFFF
        ):
            out.append(0x10000 + ((units[i] - 0xD800) << 10) + (units[i + 1] - 0xDC00))
            i += 2
        else:
            out.append(units[i])
            i += 1
    return out


def _lcp(a, b):
    n = 0
    while n < len(a) and n < len(b) and a[n] == b[n]:
        n += 1
    return n


def _craft(src, dst, payload=_LONE):
    """Put a lone surrogate inside a VALUE string of `src`, in place.

    Length-preserving: 3 ASCII bytes → the 3-byte lone surrogate, and utf16_len
    drops by 2 (3 units → 1); both ulebs stay one byte, so no offset in the file
    moves. The patch position is past the longest common prefix with BOTH
    string_ids neighbours, so the ART sort order the verifier enforces still
    holds, and the result is asserted loadable before any test uses it.
    """
    dk = dexllm.DexKit(src)
    values = set(dk.list_value_strings())
    buf = bytearray(open(src, "rb").read())
    tbl = _strings(buf)
    for k, (_idx, o, ln, d, raw) in enumerate(tbl):
        if len(raw) < 8 or ln > 0x7F or ln - 2 <= 0 or any(c >= 0x80 for c in raw):
            continue
        if raw.decode() not in values:
            continue
        prev = tbl[k - 1][4] if k else b""
        nxt = tbl[k + 1][4] if k + 1 < len(tbl) else None
        start = max(_lcp(raw, prev), _lcp(raw, nxt) if nxt is not None else 0) + 1
        if start + 3 > len(raw):
            continue
        new = raw[:start] + payload + raw[start + 3 :]
        if nxt is not None and not (
            _codepoints(prev) < _codepoints(new) < _codepoints(nxt)
        ):
            continue
        buf[d : d + len(raw)] = new
        buf[o] = ln - 2
        open(dst, "wb").write(bytes(buf))
        return new
    return None


@pytest.fixture(scope="module")
def lone(tmp_path_factory):
    """(path, raw_bytes, decoded_str) of a dex whose value string holds U+D800."""
    dst = str(tmp_path_factory.mktemp("lone") / "lone.dex")
    for src in sorted(glob.glob(str(REPO_ROOT / "test_apk" / "APK" / "*.dex"))):
        try:
            # A deliberately-malformed corpus dex must SKIP this file, not ERROR.
            new = _craft(src, dst)
        except Exception:  # noqa: BLE001
            continue
        if new is None:
            continue
        if not dexllm.verify(dst)[0]["valid"]:
            continue
        return dst, new, new.decode("utf-8", "surrogatepass")
    pytest.skip("no corpus .dex could carry the crafted lone surrogate")


def test_crafted_dex_is_loadable(lone):
    """A lone surrogate in a LITERAL is legal input — the premise of this file.

    Non-discriminating by design: it must hold both before and after the fix, and
    it is what makes the round-trip guards meaningful rather than vacuous.
    """
    path, _raw, _s = lone
    row = dexllm.verify(path)[0]
    assert row["valid"], row["reason"]
    assert dexllm.DexKit(path).dex_count() == 1


def test_value_string_keeps_the_lone_surrogate(lone):
    """`list_value_strings()` must hand back the surrogate, not U+FFFD.

    The two property assertions are made over the LISTING itself. An earlier
    version pulled the element out with `listed[listed.index(s)]` and asserted on
    that, which `list.index` makes identical to `s` by definition — i.e. still a
    statement about the fixture, the very thing the change claimed to fix.
    """
    path, _raw, s = lone
    listed = dexllm.DexKit(path).list_value_strings()
    assert s in listed, f"{s!r} not in the listing"
    assert any(any(0xD800 <= ord(c) <= 0xDFFF for c in v) for v in listed)
    assert not any("�" in v for v in listed)


def test_class_scoped_accessor_keeps_the_lone_surrogate(lone):
    """`list_class_strings` is the third `decoded_unique` consumer."""
    path, _raw, s = lone
    dk = dexllm.DexKit(path)
    owners = dk.find_classes_using_strings([s], "equals", False)
    assert owners, "fixture string is not loaded by any class"
    listed = dk.list_class_strings(owners[0].descriptor)
    assert s in listed
    assert not any("�" in v for v in listed)


def test_arg_origin_string_value_keeps_the_lone_surrogate(lone):
    """`ResolvedArg.string_value` is a const-string OPERAND — pool CONTENT.

    It was switched from the lossy decode to `content_out` and had no guard: the
    pre-existing dexllm#22 ResolvedArg test filters to NUL / astral literals, which
    are exactly the cases where the two decoders AGREE, so it cannot discriminate.
    """
    path, _raw, s = lone
    dk = dexllm.DexKit(path)
    owners = dk.find_methods_using_strings([s], "equals", False)
    assert owners, "fixture string is not loaded by any method"
    # resolve_call_args takes the CALLEE (it resolves the arguments at every call
    # site TO that API), so walk out of the owner to what it invokes.
    seen = []
    for cs in dk.find_call_sites_from(owners[0].descriptor):
        for site in dk.resolve_call_args(cs.callee_descriptor):
            seen += [a.string_value for a in site.args if a.kind == "ConstString"]
    assert (
        seen
    ), "no ConstString ResolvedArg reached — this guard must not pass vacuously"
    assert s in seen, f"{s!r} not among {len(seen)} ConstString origins"


def test_ast_string_value_keeps_the_lone_surrogate(lone):
    """`AstToPy`'s string case was switched too, and had no guard either."""
    path, _raw, s = lone
    dk = dexllm.DexKit(path)
    owners = dk.find_methods_using_strings([s], "equals", False)
    assert owners, "fixture string is not loaded by any method"
    ast = dk.decompile_method_ast(owners[0].descriptor, False)

    def walk(node):
        if isinstance(node, str):
            yield node
        elif isinstance(node, (list, tuple)):
            for e in node:
                yield from walk(e)
        elif isinstance(node, dict):
            for e in node.values():
                yield from walk(e)

    strings = list(walk(ast["ast"]))
    assert strings, "empty AST — this guard must not pass vacuously"
    assert s in strings, f"{s!r} not among {len(strings)} AST strings"


def test_half_surrogate_query_matches_inside_a_paired_literal(loadable_apks):
    """PINNED, not fixed: MUTF-8 cannot separate a pair from two adjacent halves.

    The pool stores an astral character as a SURROGATE PAIR (CESU-8), so
    ``"\\U000dfffd"`` and the two-half string ``"\\udb3f\\udffd"`` encode to the
    SAME six bytes. A byte-comparing matcher therefore cannot tell them apart, and
    a half-surrogate query matches INSIDE a legitimately-paired literal. Passing
    the halves as `bytes` always did this; dexllm#29 is what puts it in reach of a
    `str`. Asserted here so the semantics are a known property rather than a
    surprise — if a future change makes the matcher character-aligned, this test
    should be updated deliberately, not deleted.
    """
    for src in loadable_apks + sorted(
        glob.glob(str(REPO_ROOT / "test_apk" / "APK" / "*.dex"))
    ):
        try:
            # Same discipline as the `lone` fixture: a malformed corpus dex must
            # make this SKIP, not ERROR (`identify()` does not verify).
            dk = dexllm.DexKit(src)
        except Exception:  # noqa: BLE001
            continue
        astral = [
            v
            for v in dk.list_value_strings()
            if len(v) == 1 and ord(v) > 0xFFFF  # a lone astral char: unambiguous halves
            # ...and LOADED BY A METHOD. A static-init-only literal makes both
            # `equals` counts 0, so the assertion below degenerates to 0 == 0 and
            # the `contains` one fails outright — the test would pass vacuously on
            # one corpus and FAIL on another rather than skip.
            and dk.find_methods_using_strings([v], "equals", False)
        ]
        if astral:
            break
    else:
        pytest.skip("no method-loaded single-astral-character literal in the corpus")

    s = astral[0]
    units = struct.unpack(">2H", s.encode("utf-16-be"))
    halves = "".join(chr(u) for u in units)
    cesu = b"".join(
        bytes([0xE0 | (u >> 12), 0x80 | ((u >> 6) & 0x3F), 0x80 | (u & 0x3F)])
        for u in units
    )
    assert halves != s, "the split form must be a DIFFERENT Python string"
    # ...yet it encodes to exactly the bytes the pool holds for `s`.
    assert halves.encode("utf-8", "surrogatepass") == cesu
    assert dk.find_methods_using_strings([halves[0]], "contains", False)
    n_split = len(dk.find_methods_using_strings([halves], "equals", False))
    n_whole = len(dk.find_methods_using_strings([s], "equals", False))
    assert n_whole > 0, "candidate selection must guarantee a method-loaded literal"
    assert n_split == n_whole  # the pool cannot tell the two apart


def test_listed_value_round_trips_into_the_matchers(lone):
    """The value the forward API returns must find its own origin.

    This is the whole point of the issue: before the fix the listing returned
    U+FFFD and every reverse query on it returned 0 hits, silently.
    """
    path, _raw, s = lone
    dk = dexllm.DexKit(path)
    assert len(dk.find_methods_using_strings([s], "equals", False)) >= 1
    assert len(dk.find_classes_using_strings([s], "equals", False)) >= 1


def test_method_scoped_accessor_round_trips(lone):
    """`list_method_strings` is a forward accessor too, and feeds the same query."""
    path, _raw, s = lone
    dk = dexllm.DexKit(path)
    owners = dk.find_methods_using_strings([s], "equals", False)
    assert owners, "fixture string is not loaded by any method"
    listed = dk.list_method_strings(owners[0].descriptor)
    assert s in listed
    assert (
        len(dk.find_methods_using_strings([listed[listed.index(s)]], "equals", False))
        >= 1
    )


def test_lone_surrogate_query_is_accepted(lone):
    """A `str` carrying a lone surrogate must reach the matcher, not raise.

    pybind11's own caster encodes arguments as strict UTF-8 and rejects one
    outright, so before the fix this was a TypeError before any search ran.
    """
    dk = dexllm.DexKit(lone[0])
    assert len(dk.find_methods_using_strings(["\ud800"], "contains", False)) >= 1
    assert dk.find_classes_declaring_strings(["\ud800"], "contains", False) is not None


def test_bytes_workaround_still_matches(lone):
    """The documented `bytes` path must keep working, byte for byte.

    Non-discriminating by design: it held before the fix and must still hold —
    the point is that closing the `str` path did not disturb it.
    """
    path, raw, _s = lone
    dk = dexllm.DexKit(path)
    assert len(dk.find_methods_using_strings([raw], "equals", False)) >= 1


def test_smali_listing_and_value_accessor_diverge_by_design(lone):
    """The smali route folds the surrogate to U+FFFD; the accessor keeps it.

    Pinned in BOTH directions because it is a deliberate split — smali is display
    text — and because `test_method_strings_match_smali_ground_truth` asserts the
    two are equal, an equality that is now conditional on the absence of a lone
    surrogate rather than unconditional.
    """
    path, _raw, s = lone
    dk = dexllm.DexKit(path)
    owners = dk.find_methods_using_strings([s], "equals", False)
    assert owners, "fixture string is not loaded by any method"
    smali = dk.render_method_smali(owners[0].descriptor)
    assert s in dk.list_method_strings(owners[0].descriptor)
    assert s not in smali
    assert "�" in smali


def test_query_argument_types_are_unchanged(dk):
    """`str` / `bytes` / `bytearray` accepted, anything else a TypeError.

    The acceptance SET is the non-discriminating half — the custom caster replaces
    pybind11's own for these arguments, so this pins that it takes neither more
    nor fewer types. The batch half IS discriminating: a surrogate-bearing VALUE
    must reach the matcher (a TypeError pre-fix) while the batch KEY must still
    raise, because a key is a caller label rather than pool content — the contract
    docs/api.md states and nothing else guarded.
    """
    for ok in ("x", b"x", bytearray(b"x")):
        dk.find_methods_using_strings([ok], "equals", False)
    for bad in (5, None, ["x"], 1.5):
        with pytest.raises(TypeError):
            dk.find_methods_using_strings([bad], "equals", False)
    dk.batch_find_methods_using_strings({"k": ["\ud800"]}, "equals", False)
    with pytest.raises(TypeError):
        dk.batch_find_methods_using_strings({"\ud800": ["x"]}, "equals", False)


def test_bytearray_query_matches_like_bytes(lone):
    """A `bytearray` carrying the pool bytes must match exactly as `bytes` does.

    The acceptance test above only shows `bytearray` is not a TypeError; the arm
    was added by hand, so its VALUE path needs its own check.
    """
    path, raw, _s = lone
    dk = dexllm.DexKit(path)
    n_bytes = len(dk.find_methods_using_strings([raw], "equals", False))
    n_barray = len(dk.find_methods_using_strings([bytearray(raw)], "equals", False))
    assert n_bytes >= 1
    assert n_barray == n_bytes


def test_two_lone_surrogates_no_longer_collapse_in_the_listing(tmp_path):
    """`decoded_unique` dedups on the LOSSLESS text, so two distinct pool strings
    that differ only inside a lone surrogate stay two entries.

    CLAUDE.md first recorded this as an accepted coverage gap on the grounds that
    such a pair "cannot be produced from the corpus" by length- and
    sort-order-preserving crafting. That was WRONG, and a review demonstrated it:
    craft the SAME string twice with different surrogates, then concatenate the
    two dexes into one file — a shape dexllm#25 explicitly supports, and exactly
    what a packer dump looks like. Under the old lossy key both collapse to one
    U+FFFD entry and one of them silently disappears from the listing.
    """
    hi = str(tmp_path / "hi.dex")
    lo = str(tmp_path / "lo.dex")
    for src in sorted(glob.glob(str(REPO_ROOT / "test_apk" / "APK" / "*.dex"))):
        try:
            a = _craft(src, hi, b"\xed\xa0\x80")  # U+D800
            b = _craft(src, lo, b"\xed\xb0\x80")  # U+DC00
        except Exception:  # noqa: BLE001
            continue
        if a and b and dexllm.verify(hi)[0]["valid"] and dexllm.verify(lo)[0]["valid"]:
            break
    else:
        pytest.skip("no corpus .dex could carry the crafted pair")

    cat = str(tmp_path / "cat.dex")
    with open(cat, "wb") as f:
        f.write(open(hi, "rb").read() + open(lo, "rb").read())
    assert all(r["valid"] for r in dexllm.verify(cat)), dexllm.verify(cat)

    dk = dexllm.DexKit(cat)
    assert dk.dex_count() == 2
    sa = a.decode("utf-8", "surrogatepass")
    sb = b.decode("utf-8", "surrogatepass")
    assert sa != sb
    listed = dk.list_value_strings()
    # The lossy key maps both to the same text, so pre-fix exactly one survived.
    assert sa in listed and sb in listed, listed
    # ...and each still resolves to its own dex, not to the other's.
    assert dk.find_methods_using_strings([sa], "equals", False)
    assert dk.find_methods_using_strings([sb], "equals", False)


def test_clean_corpus_values_are_unaffected(dk):
    """A corpus value string still resolves to a method or a declaring class.

    The corpus holds no lone surrogate, so this is the property that must be
    unchanged by the boundary swap (it is the dexllm#19/#20 round trip).
    """
    values = dk.list_value_strings()[:200]
    if not values:
        # $DEXLLM_TEST_APK can point at a dex with no value strings at all (two of
        # the bundled ones have none) — a property of the sample, so SKIP.
        pytest.skip("this dex declares no value strings")
    for s in values:
        found = dk.find_methods_using_strings(
            [s], "equals", False
        ) or dk.find_classes_declaring_strings([s], "equals", False)
        assert found, f"{s!r} resolves to neither a loader nor a declarer"
