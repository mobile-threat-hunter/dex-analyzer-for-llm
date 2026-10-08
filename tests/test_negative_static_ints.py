"""dexllm#91 — a SHORT / INT / LONG static initializer is SIGN-extended.

The dex spec stores an integer-family `encoded_value` in `value_arg + 1` bytes
and sign-extends SHORT / INT / LONG from there; CHAR is the one member that is
ZERO-extended. `DecodeEncodedValueText` read all four unsigned (ported from
androguard's `_getintvalue`), so `decompile_class` printed `-1` stored in one
byte as `255`, `0xff000000` as `4278190080` and `Long.MIN_VALUE` as
`9223372036854775808` — wrong VALUES, and the small ones carry nothing that
marks them wrong.

`tests/data/negative-statics.dex` is AUTHORED (source beside it): one value per
branch, at the byte widths d8 actually chooses, with positive controls whose top
encoded byte has its high bit set (`128` = `80 00`, `255L` = `ff 00`) and a CHAR
whose single byte is `0x80` — the case a sign-extending CHAR would turn into
`-128`. No committed fixture carried a negative static initializer before it.
"""

from __future__ import annotations

import os
import re
import struct

import pytest
from conftest import REPO_ROOT, require_corpus_shape
from test_static_float_justification import _decoder_case_body, _strip_comments

_FIXTURE = REPO_ROOT / "tests" / "data" / "negative-statics.dex"
_CLASS = "LNegativeStatics;"

# What Java says each field holds — a LITERAL, so an edit of the rule cannot
# silently move the expectation with it. LONG values still lack the `L` suffix
# (dexllm#92); that is the same on both sides of this change and is pinned here
# so #92 updates it deliberately.
_EXPECTED = {
    "SHORT_MINUS_ONE": "-1",
    "SHORT_MIN": "-32768",
    "INT_MINUS_ONE": "-1",
    "INT_MINUS_128": "-128",
    "INT_PLUS_128": "128",
    "INT_ALPHA_MASK": "-16777216",
    "INT_MIN": "-2147483648",
    "INT_MAX": "2147483647",
    "LONG_MINUS_ONE": "-1",
    "LONG_MIN": "-9223372036854775808",
    "LONG_MINUS_2_32": "-4294967296",
    "LONG_PLUS_255": "255",
    "CHAR_0X80": "128",
    "CHAR_MAX": "65535",
    "BYTE_MINUS_ONE": "-0x1",
}

_DECL = re.compile(r"^\s+.*\bstatic (?:final )?\S+ (\w+) = (.+);$")


def _decls(text: str) -> dict[str, str]:
    # `\n`, never splitlines() — the decompile_class contract (dexllm#83).
    return {m[1]: m[2] for line in text.split("\n") if (m := _DECL.match(line))}


@pytest.fixture(scope="module")
def fixture_decls():
    dexllm = pytest.importorskip("dexllm")
    assert dexllm.verify(str(_FIXTURE))[0]["valid"]
    return _decls(dexllm.DexKit(str(_FIXTURE)).decompile_class(_CLASS))


def test_the_fixture_declares_every_branch(fixture_decls) -> None:
    """Premise: every pinned field is rendered, and nothing else is."""
    assert set(fixture_decls) == set(_EXPECTED)


@pytest.mark.parametrize("field", sorted(_EXPECTED))
def test_each_static_initializer_renders_its_signed_value(fixture_decls, field) -> None:
    assert fixture_decls[field] == _EXPECTED[field]


# -- an independent byte-level oracle ----------------------------------------


def _uleb(b: bytes, o: int) -> tuple[int, int]:
    r = s = 0
    while True:
        x = b[o]
        o += 1
        r |= (x & 0x7F) << s
        if not x & 0x80:
            return r, o
        s += 7


def _skip(b: bytes, o: int):
    """Advance past one encoded_value; return the leaf for an integer member."""
    h = b[o]
    o += 1
    vt, n = h & 0x1F, (h >> 5) + 1
    if vt == 0x1C:
        cnt, o = _uleb(b, o)
        for _ in range(cnt):
            o, _ = _skip(b, o)
        return o, None
    if vt == 0x1D:
        _, o = _uleb(b, o)
        cnt, o = _uleb(b, o)
        for _ in range(cnt):
            _, o = _uleb(b, o)
            o, _ = _skip(b, o)
        return o, None
    if vt in (0x1E, 0x1F):
        return o, None
    raw = int.from_bytes(b[o : o + n], "little")
    return o + n, (vt, raw, n)


def _oracle(b: bytes) -> dict[str, dict[str, str]]:
    """{class descriptor: {field name: expected text}} for every SHORT / CHAR /
    INT / LONG static value, read from the dex BYTES and never through dexllm.

    Walks `class_defs` -> `class_data` (static field indices, delta-encoded) in
    lockstep with `static_values`, then resolves each name through `field_ids`.
    """

    def u4(o):
        return struct.unpack_from("<I", b, o)[0]

    osid, otid, ofid, ncd, ocd = u4(60), u4(68), u4(84), u4(96), u4(100)

    def string(i):
        _, so = _uleb(b, u4(osid + 4 * i))
        return b[so : b.index(b"\0", so)].decode("utf-8", "replace")

    out: dict[str, dict[str, str]] = {}
    for i in range(ncd):
        cd = ocd + 32 * i
        data, sv = u4(cd + 24), u4(cd + 28)
        if not sv or not data:
            continue
        nsf, o = _uleb(b, data)
        for _ in range(3):
            _, o = _uleb(b, o)
        fidx, f = [], 0
        for _ in range(nsf):
            d, o = _uleb(b, o)
            _, o = _uleb(b, o)
            f += d
            fidx.append(f)
        cnt, o = _uleb(b, sv)
        cls = string(u4(otid + 4 * u4(cd)))
        for k in range(min(cnt, len(fidx))):
            o, leaf = _skip(b, o)
            if not leaf or leaf[0] not in (0x02, 0x03, 0x04, 0x06):
                continue
            vt, raw, n = leaf
            val = raw
            if vt != 0x03 and raw >> (8 * n - 1):
                val = raw - (1 << (8 * n))
            name = string(u4(ofid + 8 * fidx[k] + 4))
            out.setdefault(cls, {})[name] = str(val)
    return out


def test_the_oracle_agrees_with_the_pinned_table() -> None:
    """The oracle reads the fixture to the same table — so it is not vacuous."""
    want = {k: v for k, v in _EXPECTED.items() if not k.startswith("BYTE_")}
    assert _oracle(_FIXTURE.read_bytes())[_CLASS] == want


def test_every_corpus_integer_initializer_matches_the_byte_level_oracle(
    loadable_apks,
) -> None:
    """Field-precise, over every loadable source: each SHORT / CHAR / INT / LONG
    static the bytes declare renders exactly its (sign-extended) value.

    Scope, stated: `loadable_apks` is the `.apk` corpus, so the bundled bare
    `.dex` files are not walked here (the a/b recorded in CLAUDE.md covered
    them), and nested ARRAY / ANNOTATION integers are not oracle-checked — the
    corpus carries none, and they go through the same arm."""
    dexllm = pytest.importorskip("dexllm")
    checked = negative = 0
    mismatches = []
    for apk in loadable_apks:
        try:
            dk = dexllm.DexKit(str(apk))
        except Exception:  # pragma: no cover - non-container
            continue
        seen: set[str] = set()
        for did in range(dk.dex_count()):
            b = dk.extract_dex(did)["bytes"]
            if b[:4] != b"dex\n":
                continue
            for cls, fields in _oracle(b).items():
                if cls in seen:  # first-wins, like every descriptor-keyed API
                    continue
                seen.add(cls)
                got = _decls(dk.decompile_class(cls))
                for name, want in fields.items():
                    if name not in got:
                        continue  # a field the class does not declare under that name
                    checked += 1
                    negative += want.startswith("-")
                    if got[name] != want:
                        mismatches.append(
                            (os.path.basename(apk), cls, name, got[name], want)
                        )
    # The values it checked are asserted FIRST, so a narrowed sample with
    # integer statics but no negatives still checks them before it skips.
    assert not mismatches, (len(mismatches), checked, mismatches[:10])
    require_corpus_shape(
        negative > 0,
        "a negative SHORT / INT / LONG static initializer",
        "the bundled corpus carries ~1,076",
    )


# -- the rule is read ONCE ----------------------------------------------------


def test_the_signed_arms_share_the_call_site_decoders_sign_extension() -> None:
    """SHORT / INT / LONG must CALL `SignExtend` (the rule ParseCallSiteArg
    already uses) and must not re-derive it; CHAR must not sign-extend.

    A correct DUPLICATE passes every behavioural case and drifts on the first
    edit — the dexllm#70 lesson for this same file.
    """
    # Whitespace-normalised and word-bounded, so a re-wrap or a reformat is not
    # a false failure and `MySignExtend(` does not satisfy it.
    signed = re.sub(r"\s+", "", _decoder_case_body("0x06"))
    assert re.search(
        r"\bSignExtend\(ReadIntLE\(p,end,nbytes\),nbytes\)", signed
    ), signed
    char = re.sub(r"\s+", "", _decoder_case_body("0x03"))
    assert "SignExtend" not in char and "ReadIntLE(p,end,nbytes)" in char, char

    # 0x02 and 0x04 are bare labels falling through into the 0x06 arm.
    text = _strip_comments(
        (REPO_ROOT / "native" / "core_ext" / "dexitem_code_source.cpp").read_text()
    )
    fn = text[text.index("DecodeEncodedValueText(const U1*& p") :]
    labels = fn[fn.index("case 0x02:") : fn.index("case 0x06:")]
    assert re.fullmatch(r"case 0x02:\s*case 0x04:\s*", labels), labels
