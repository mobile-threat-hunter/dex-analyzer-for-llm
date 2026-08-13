"""dexllm#22 (identifier half) — identifiers are pool MUTF-8 and must survive the
Python boundary in BOTH directions.

A dex may legally carry a supplementary-plane (astral) character in a class or
member name: the pool stores it as a SURROGATE PAIR, which is not valid UTF-8, and
the verifier explicitly permits it (`IsValidPartOfMemberNameUtf8Slow` accepts a
leading surrogate followed by a trailing one, mirroring ART). Handing those bytes
to pybind11's strict `str` conversion RAISES `UnicodeDecodeError` — and
`list_classes()` is the entry point for the decompile drivers, the sweep harness
and the MCP tools, so the whole analysis of such a sample died on an exception
naming an encoding rather than a cause.

Decoding alone would be worse than the crash: an identifier is also INPUT to every
identity API, and the matchers compare against raw pool bytes, so a decoded
descriptor handed back in would silently MISS. The guards below therefore exercise
the ROUND TRIP, not just the decode.
"""

import glob
import struct
from pathlib import Path

import pytest

import dexllm

REPO_ROOT = Path(__file__).resolve().parents[1]

# U+10000 as MUTF-8: two 3-byte surrogate halves, 6 bytes — exactly the width of
# the 6 ASCII bytes it replaces, so no offset in the file moves.
_PAIR = b"\xed\xa0\x80\xed\xb0\x80"
_CHAR = "\U00010000"


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
    """(index, id_offset, utf16_len, data_offset, bytes) for every string_data."""
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


def _craft_astral_class(src, dst):
    """Give a DECLARED class an astral character in its simple name, in place.

    Length-preserving: 6 ASCII bytes → the 6-byte surrogate pair, and utf16_len
    drops by 4 (6 units → 2); both ulebs stay one byte, so every offset in the
    file is unchanged and the dex still verifies. The patch position is chosen
    past the longest common prefix with BOTH string_ids neighbours, so the ART
    UTF-16-code-point sort order the verifier enforces still holds.

    Returns (old_descriptor, new_descriptor_bytes) or (None, None).
    """
    buf = bytearray(open(src, "rb").read())
    tbl = _strings(buf)
    cds_size, cds_off = struct.unpack_from("<II", buf, 0x60)
    _ti_size, ti_off = struct.unpack_from("<II", buf, 64)
    declared = {
        struct.unpack_from(
            "<I", buf, ti_off + 4 * struct.unpack_from("<I", buf, cds_off + i * 32)[0]
        )[0]
        for i in range(cds_size)
    }

    for k, (idx, o, ln, d, raw) in enumerate(tbl):
        if idx not in declared or not raw.startswith(b"L") or not raw.endswith(b";"):
            continue
        if any(c >= 0x80 for c in raw) or ln > 0x7F or ln - 4 <= 0:
            continue
        prev = tbl[k - 1][4] if k else b""
        nxt = tbl[k + 1][4] if k + 1 < len(tbl) else None
        start = max(_lcp(raw, prev), _lcp(raw, nxt) if nxt is not None else 0) + 1
        start = max(start, raw.rfind(b"/") + 1, 1)  # inside the simple name
        if start + 6 > len(raw) - 1:
            continue
        new = raw[:start] + _PAIR + raw[start + 6 :]
        if _codepoints(prev) >= _codepoints(new):
            continue
        if nxt is not None and _codepoints(new) >= _codepoints(nxt):
            continue
        buf[d : d + len(raw)] = new
        buf[o] = ln - 4
        open(dst, "wb").write(bytes(buf))
        return raw.decode(), new
    return None, None


def _craft_astral_field_name(src, dst):
    """Give a FIELD an astral character in its name, in place.

    The sibling of :func:`_craft_astral_class`, same length-preserving trick and
    same sort-order care — only the target differs: a string_id reached through
    ``field_ids[i].name_idx`` (header 0x50) rather than through a class_def.

    Returns (old_name, new_name_bytes) or (None, None).
    """
    buf = bytearray(open(src, "rb").read())
    tbl = _strings(buf)
    fi_size, fi_off = struct.unpack_from("<II", buf, 0x50)
    # field_id_item: class_idx(2) type_idx(2) name_idx(4)
    named = {
        struct.unpack_from("<I", buf, fi_off + i * 8 + 4)[0] for i in range(fi_size)
    }

    for k, (idx, o, ln, d, raw) in enumerate(tbl):
        if idx not in named:
            continue
        if any(c >= 0x80 for c in raw) or ln > 0x7F or ln - 4 <= 0:
            continue
        prev = tbl[k - 1][4] if k else b""
        nxt = tbl[k + 1][4] if k + 1 < len(tbl) else None
        start = max(_lcp(raw, prev), _lcp(raw, nxt) if nxt is not None else 0) + 1
        if start + 6 > len(raw):
            continue
        new = raw[:start] + _PAIR + raw[start + 6 :]
        if _codepoints(prev) >= _codepoints(new):
            continue
        if nxt is not None and _codepoints(new) >= _codepoints(nxt):
            continue
        buf[d : d + len(raw)] = new
        buf[o] = ln - 4
        open(dst, "wb").write(bytes(buf))
        return raw.decode(), new
    return None, None


@pytest.fixture(scope="module")
def astral_field_dex(tmp_path_factory):
    """A verify-valid dex whose FIELD name carries a supplementary-plane char."""
    out = tmp_path_factory.mktemp("astralf") / "astral_field.dex"
    for cand in sorted(glob.glob(str(REPO_ROOT / "test_apk" / "APK" / "*.dex"))):
        if open(cand, "rb").read(4) != b"dex\n":
            continue
        old, _new = _craft_astral_field_name(cand, str(out))
        if old is not None:
            return str(out)
    pytest.skip("no bare .dex in the corpus could carry an astral field name")


def test_astral_field_name_is_findable_by_name(astral_field_dex):
    """`find_fields_by_name` encodes its query, like every other NAME matcher.

    The field arm joined the L7 family in dexllm#37, and a new matcher joining it
    WITHOUT the MUTF-8 encode-in is a silent miss, not an error — exactly the
    round-trip defect dexllm#19/#22 exist for. The sibling guard above covers only
    the CLASS matcher, so deleting `ident_in` from the field binding leaves every
    field-search test green; this is the one that goes red.
    """
    dk = dexllm.DexKit(astral_field_dex)
    assert dk.verify_report()[0]["valid"], "the crafted fixture must load"

    fields = [
        f
        for c in dk.list_classes()
        for f in dk.get_class_summary(c).fields
        if _CHAR in f.name
    ]
    assert fields, "fixture carries no astral field name"
    name = fields[0].name

    hits = [h.descriptor for h in dk.find_fields_by_name(name, match_type="equals")]
    assert hits, "an astral field name did not round-trip through the matcher"
    assert all(_CHAR in h for h in hits)

    # …and a substring query that STRADDLES the astral character
    i = name.index(_CHAR)
    frag = name[max(0, i - 1) : i + 2]
    assert hits[0] in [
        h.descriptor for h in dk.find_fields_by_name(frag, match_type="contains")
    ]


@pytest.fixture(scope="module")
def astral_dex(tmp_path_factory):
    """A verify-valid dex whose class name carries a supplementary-plane char."""
    out = tmp_path_factory.mktemp("astral") / "astral.dex"
    for cand in sorted(glob.glob(str(REPO_ROOT / "test_apk" / "APK" / "*.dex"))):
        if open(cand, "rb").read(4) != b"dex\n":
            continue
        old, _new = _craft_astral_class(cand, str(out))
        if old is not None:
            return str(out)
    pytest.skip("no bare .dex in the corpus could carry an astral class name")


def test_astral_identifier_dex_still_verifies(astral_dex):
    """The fixture must be a LOADABLE dex, or the guards below prove nothing.

    A supplementary character in a name is legal per ART's own name rules, so the
    verifier must accept it — if this ever fails, the fixture is malformed rather
    than the API being fixed.
    """
    report = dexllm.verify(astral_dex)
    assert report[0]["valid"], report[0]["reason"]


def test_astral_class_enumerates_and_round_trips(astral_dex):
    """list_classes → list_class_methods → the identity APIs, on decoded text.

    This is the whole point of the decode-OUT / encode-IN PAIR: the descriptor the
    caller receives must be the descriptor the caller can hand back.
    """
    dk = dexllm.DexKit(astral_dex)

    classes = dk.list_classes()  # raised UnicodeDecodeError before the fix
    astral = [c for c in classes if any(ord(ch) > 0xFFFF for ch in c)]
    assert astral, f"fixture carries no astral class descriptor: {classes}"
    cls = astral[0]
    assert _CHAR in cls

    methods = dk.list_class_methods(cls)
    assert methods, "the decoded descriptor did not resolve back to its class"
    assert all(m.startswith(cls + "->") for m in methods)

    # Every identity API must accept the decoded descriptor.
    assert dk.locate_class_dex(cls) >= 0
    assert dk.get_class_summary(cls).descriptor == cls
    assert cls in dk.render_class_smali(cls)
    for m in methods:
        assert dk.render_method_smali(m).startswith(m)
        assert dk.decompile_method_ast(m, False)["cls_name"] == cls

    # …and the descriptor must appear decoded in the whole-dex listings too.
    assert any(_CHAR in d for d in dk.list_methods())


def test_astral_identifier_is_findable_by_name(astral_dex):
    """Closes the residual dexllm#19 recorded but could not fix.

    The NAME matchers compare against raw pool bytes, so a query carrying an
    astral character only matches once it is MUTF-8-encoded at the boundary. The
    residual was unobservable before because enumerating such a class raised
    first.
    """
    dk = dexllm.DexKit(astral_dex)
    cls = next(c for c in dk.list_classes() if _CHAR in c)

    assert [m.descriptor for m in dk.find_classes_by_name(cls, "equals", False)] == [
        cls
    ]
    # a substring query that STRADDLES the astral character
    frag = cls[1 : cls.index(_CHAR) + 2]
    assert cls in [
        m.descriptor for m in dk.find_classes_by_name(frag, "contains", False)
    ]


def test_astral_dex_sweeps_is_productive_not_merely_quiet(astral_dex):
    """A driver-shaped pass: every call must PRODUCE, not just fail to raise.

    "No exception" is the wrong success criterion here — a descriptor that decodes
    but no longer re-encodes to its pool bytes returns empty everywhere and raises
    nothing, which is the silent-miss outcome this whole design exists to avoid.
    So assert output, not survival.
    """
    dk = dexllm.DexKit(astral_dex)
    classes = dk.list_classes()
    assert classes
    for c in classes:
        assert dk.locate_class_dex(c) >= 0, c
        assert dk.render_class_smali(c), c
        assert dk.decompile_class(c), c
        methods = dk.list_class_methods(c)
        assert methods, c
        for m in methods:
            assert dk.render_method_smali(m), m
            dk.decompile_method(m)  # may legitimately be empty (abstract/native)
            dk.list_method_strings(m)


def test_every_enumerated_class_resolves_back(loadable_apks):
    """The round-trip invariant the decode/encode pair rests on, corpus-wide.

    `locate_class_dex` re-encodes the descriptor and looks it up against the raw
    pool bytes, so this fails for ANY identifier whose decode is not exactly
    invertible — the one failure mode that produces no exception and no output.
    Cheap enough to run over every bundled container.
    """
    for p in loadable_apks:
        dk = dexllm.DexKit(p)
        for c in dk.list_classes():
            assert dk.locate_class_dex(c) >= 0, (p, c)


def test_astral_type_in_a_field_initializer_decompiles(tmp_path):
    """A `static final X F = Astral.class;` initializer must not re-raise.

    `decompile_class` sanitises each identifier at its append site, and the field
    INITIALIZER is one of them: only the STRING arm (0x17) of
    `DecodeEncodedValueText` is pre-escaped — the TYPE (0x18) and FIELD/ENUM
    (0x19/0x1b) arms emit RAW pool identifiers. That append was missed when the
    whole-text pass was replaced by per-component sanitising, and the astral
    class-NAME fixture cannot reach it (its dex has no such initializer).
    """
    src = "test_apk/APK/classes.dex"
    if not (REPO_ROOT / src).exists():
        pytest.skip(f"{src} not in the corpus")
    b = bytearray(open(REPO_ROOT / src, "rb").read())
    tbl = _strings(b)
    tn, toff = struct.unpack_from("<II", b, 64)

    # 1. an astral character in some TYPE descriptor (length-preserving)
    astral_type = None
    for t in range(tn):
        sidx = struct.unpack_from("<I", b, toff + 4 * t)[0]
        _i, o, ln, d, s = tbl[sidx]
        if any(c >= 0x80 for c in s) or ln > 0x7F or ln - 4 <= 0:
            continue
        if not s.startswith(b"L") or not s.endswith(b";"):
            continue
        prev = tbl[sidx - 1][4] if sidx else b""
        nxt = tbl[sidx + 1][4] if sidx + 1 < len(tbl) else b""
        start = max(_lcp(s, prev), _lcp(s, nxt)) + 1
        start = max(start, s.rfind(b"/") + 1, 1)
        if start + 6 > len(s) - 1:
            continue
        b[d : d + len(s)] = s[:start] + _PAIR + s[start + 6 :]
        b[o] = ln - 4
        astral_type = t
        break
    if astral_type is None or astral_type >= 0x10000:
        pytest.skip("no patchable ASCII type descriptor with a 2-byte index")

    # 2. retype a 2-byte VALUE_STRING initializer to VALUE_TYPE at that type
    cds_size, cds_off = struct.unpack_from("<II", b, 0x60)
    hit = False
    for i in range(cds_size):
        sv = struct.unpack_from("<I", b, cds_off + 32 * i + 28)[0]
        if not sv:
            continue
        _size, p = _uleb(b, sv)
        hdr = b[p]
        if (hdr & 0x1F) == 0x17 and ((hdr >> 5) & 7) == 1:
            b[p] = (1 << 5) | 0x18
            struct.pack_into("<H", b, p + 1, astral_type)
            hit = True
            break
    if not hit:
        pytest.skip("no 2-byte VALUE_STRING initializer to retype")

    f = tmp_path / "init_astral.dex"
    f.write_bytes(bytes(b))
    assert dexllm.verify(str(f))[0]["valid"]
    dk = dexllm.DexKit(str(f))
    rendered = 0
    for c in dk.list_classes():
        text = dk.decompile_class(c)  # raised before the initializer was sanitised
        if "\U00010000" in text:
            rendered += 1
    # Non-vacuous: the astral type must actually appear in an initializer. Matched
    # as the readable CHARACTER, not `\ud800\udc00`: a field TYPE is an IDENTIFIER,
    # and dexllm#28 renders those readably so one symbol has one spelling across
    # the Java, smali and list_classes() views. What this test guards is unchanged
    # — that the initializer append site is sanitised at all, which is what raised.
    assert rendered, "the crafted initializer never reached the output"


def test_overlong_identifier_is_rejected_not_silently_canonicalised(tmp_path):
    """The one shape where decode/encode is NOT an inverse must not load.

    A non-NUL OVERLONG decodes to a canonical character that re-encodes to the
    CANONICAL bytes, which are not the pool bytes. Left loadable, such a class
    enumerated fine and then resolved to nothing in every identity API — no
    exception anywhere, i.e. a 3-byte class-hiding primitive. ART rejects the
    encoding (`CheckIntraStringDataItem`, "Illegal representation"); dexllm#22
    ported that check, so the round trip cannot be broken this way.
    """
    src = None
    for cand in sorted(glob.glob(str(REPO_ROOT / "test_apk" / "APK" / "*.dex"))):
        raw = bytearray(open(cand, "rb").read())
        if raw[:4] != b"dex\n":
            continue
        for _i, o, ln, d, s in _strings(raw):
            # A pure-ASCII declared-class-looking name with 3 spare bytes.
            if s.startswith(b"L") and s.endswith(b";") and len(s) > 8 and ln <= 0x7F:
                if any(c >= 0x80 for c in s):
                    continue
                raw[d + 2 : d + 5] = (
                    b"\xe0\x83\xa9"  # overlong U+00E9 (canonical: C3 A9)
                )
                raw[o] = ln - 2  # 3 bytes collapse to 1 code unit
                src = raw
                break
        if src is not None:
            break
    if src is None:
        pytest.skip("no patchable ASCII class descriptor in the corpus")

    f = tmp_path / "overlong_ident.dex"
    f.write_bytes(bytes(src))
    report = dexllm.verify(str(f))
    assert not report[0]["valid"], "an overlong identifier must be rejected at load"
    assert "representation" in report[0]["reason"], report[0]["reason"]


def test_const_string_arg_origin_decodes(loadable_apks):
    """`ArgOrigin.string_value` is a const-string OPERAND — pool bytes like any
    other, and it RAISED for the same reason the identifiers did.

    Corpus-reproducible (an embedded NUL, `C0 80`), so this is a value check, not
    a reasoned one — it asserts the decoded VALUE, since a decoder returning
    U+FFFD or `''` for everything would satisfy a mere does-not-raise probe.
    Absence from the corpus is a SKIP, not a failure (that is a property of the
    sample, not of the code).
    """
    sources = list(loadable_apks) + [
        p for p in sorted(glob.glob(str(REPO_ROOT / "test_apk" / "APK" / "*.dex")))
    ]
    for p in sources:
        try:
            dk = dexllm.DexKit(p)
        except (
            Exception
        ):  # noqa: BLE001 - unloadable containers are not this test's subject
            continue
        for ref in dk.list_external_method_refs(False)[:40]:
            for site in dk.resolve_call_args(ref.signature):  # raised before the fix
                for arg in site.args:
                    if arg.kind != "ConstString":
                        continue
                    v = arg.string_value
                    if "\x00" not in v and not any(ord(c) > 0xFFFF for c in v):
                        continue
                    # The decoded value must be the real one, not a placeholder:
                    # it round-trips back to the method that loads it.
                    assert "�" not in v, (p, repr(v))
                    found = dk.find_methods_using_strings([v], "equals", False)
                    assert site.caller_descriptor in [m.descriptor for m in found], (
                        p,
                        repr(v),
                        site.caller_descriptor,
                    )
                    return
    pytest.skip("no NUL/astral const-string operand in this corpus")
