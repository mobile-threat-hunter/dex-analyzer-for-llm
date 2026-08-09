r"""dexllm#28 — an IDENTIFIER renders readably in Java text, like everywhere else.

The Java text path claims ART code-unit fidelity: it emits the exact UTF-16 units
`mirror::String` holds, so a surrogate/control unit becomes `\uXXXX`. That claim
is about string CONTENT. Applying it to identifiers made one class read two ways
in a single session — `A𐀀sTest` from `list_classes()` and the smali listing,
`A\ud800\udc00sTest` in decompiled Java — which breaks correlation for an analyst
or an LLM reading the views side by side, and for pasting a class name into a
hooking script. It was also inconsistent: a BMP identifier (`A한ysisTest`) always
rendered readably, surviving by unit count rather than by rule.

So identifiers now combine a valid surrogate PAIR into its code point, while
string literals keep the per-unit rendering. A LONE surrogate still escapes in
both — it has no UTF-8 form (and the verifier rejects one in a name anyway).
"""

import glob
import struct
from pathlib import Path

import pytest

import dexllm

REPO_ROOT = Path(__file__).resolve().parents[1]

_PAIR = b"\xed\xa0\x80\xed\xb0\x80"  # U+10000 as MUTF-8: two 3-byte halves
_CHAR = "\U00010000"
_BMP = "한".encode()  # 3 bytes, ONE UTF-16 unit — the control case


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
    n, off0 = struct.unpack_from("<II", buf, 56)
    out = []
    for i in range(n):
        o = struct.unpack_from("<I", buf, off0 + 4 * i)[0]
        ln, d = _uleb(buf, o)
        out.append((i, o, ln, d, bytes(buf[d : buf.index(0, d)])))
    return out


def _codepoints(raw):
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


def _craft_class_name(src, dst, payload):
    """Put `payload` inside a DECLARED class's simple name, in place.

    Length-preserving (payload replaces the same number of ASCII bytes), utf16_len
    adjusted, and the patch position is past the longest common prefix with both
    string_ids neighbours so the ART sort order still holds.
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
    n = len(payload)
    for k, (idx, o, ln, d, raw) in enumerate(tbl):
        if idx not in declared or not raw.startswith(b"L") or not raw.endswith(b";"):
            continue
        if any(c >= 0x80 for c in raw) or ln > 0x7F:
            continue
        units = 2 if n == 6 else 1  # a pair is 2 UTF-16 units, a BMP char is 1
        if ln - (n - units) <= 0:
            continue
        prev = tbl[k - 1][4] if k else b""
        nxt = tbl[k + 1][4] if k + 1 < len(tbl) else None
        start = max(_lcp(raw, prev), _lcp(raw, nxt) if nxt is not None else 0) + 1
        start = max(start, raw.rfind(b"/") + 1, 1)
        if start + n > len(raw) - 1:
            continue
        new = raw[:start] + payload + raw[start + n :]
        if nxt is not None and not (
            _codepoints(prev) < _codepoints(new) < _codepoints(nxt)
        ):
            continue
        buf[d : d + len(raw)] = new
        buf[o] = ln - (n - units)
        open(dst, "wb").write(bytes(buf))
        return new
    return None


def _crafted(tmp_path, payload, name):
    dst = str(tmp_path / name)
    for src in sorted(glob.glob(str(REPO_ROOT / "test_apk" / "APK" / "*.dex"))):
        try:
            new = _craft_class_name(src, dst, payload)
        except Exception:  # noqa: BLE001
            continue
        if new and dexllm.verify(dst)[0]["valid"]:
            return dst
    pytest.skip(f"no corpus .dex could carry the crafted {name}")


def _views(path):
    """(descriptor, first smali line, the type-declaration line) for the odd class.

    The header is matched STRUCTURALLY, not by the substring "class": an interface
    header carries no `class` token (decompiler.cpp emits it only when
    `!is_interface`), and a field initializer rendered as `pkg.Cls.class` contains
    the substring — so the naive match could pick the wrong line or IndexError on a
    corpus whose first craftable declared type happens to be an interface.
    """
    dk = dexllm.DexKit(path)
    cls = [c for c in dk.list_classes() if any(ord(ch) > 0x7F for ch in c)][0]
    simple = cls[1:-1].split("/")[-1]
    header = [
        ln
        for ln in dk.decompile_class(cls).splitlines()
        if ln.rstrip().endswith("{") and (" class " in ln or " interface " in ln)
    ]
    if not header:
        pytest.skip(f"no type-declaration header emitted for {cls!r}")
    assert simple in cls
    return cls, dk.render_class_smali(cls).splitlines()[0], header[0].strip()


def test_astral_identifier_reads_the_same_in_all_three_views(tmp_path):
    """The point of the change: one symbol, one spelling.

    The only DISCRIMINATING test here — verified to fail against a pre-fix
    rebuild. The other three must hold on both sides by design: the BMP control
    shows the old behaviour was inconsistent, and the two literal guards pin the
    half of the fidelity claim that was NOT narrowed.
    """
    desc, smali, java = _views(_crafted(tmp_path, _PAIR, "astral.dex"))
    simple = desc[1:-1].split("/")[-1]
    assert _CHAR in desc, repr(desc)
    assert _CHAR in smali, repr(smali)
    assert _CHAR in java, repr(java)
    assert simple in java, (simple, java)  # the SAME text, not merely both astral
    assert "\\ud800" not in java, repr(java)


def test_bmp_identifier_is_unchanged(tmp_path):
    """The control: a BMP identifier always rendered readably and must still.

    Non-discriminating by design — it holds on both sides of the change, and is
    what shows the old behaviour was inconsistent rather than principled.
    """
    desc, smali, java = _views(_crafted(tmp_path, _BMP, "bmp.dex"))
    assert "한" in desc and "한" in smali and "한" in java
    assert desc[1:-1].split("/")[-1] in java


def test_ast_identifier_fields_and_source_agree(tmp_path):
    """`decompile_method_ast` spelled one class two ways INSIDE ONE dict.

    Its `cls_name` came through the binding's `ident_out` (which combines a pair,
    so it was already readable) while its `source` carried the Java text with
    `\\uXXXX`. So the inconsistency was not merely across APIs — a single returned
    value disagreed with itself. A review called this the strongest argument for
    the change, and nothing covered it.
    """
    dk = dexllm.DexKit(_crafted(tmp_path, _PAIR, "astral_ast.dex"))
    cls = [c for c in dk.list_classes() if any(ord(ch) > 0x7F for ch in c)][0]
    methods = dk.list_class_methods(cls)
    assert methods, cls
    ast = dk.decompile_method_ast(methods[0])
    assert _CHAR in ast["cls_name"], ast["cls_name"]
    assert _CHAR in ast["source"], ast["source"]
    assert "\\ud800" not in ast["source"]
    # ...and the text API agrees with the AST's own copy of it.
    assert ast["source"] == dk.decompile_method(methods[0])


def _astral_literal_method(loadable_apks):
    """(dk, literal, owning method) for a corpus astral literal a METHOD loads.

    Searched across the corpus rather than taken from the default `dk` fixture:
    that APK has no astral literal, so binding these to it made both literal
    guards SKIP — leaving the half of the README claim that was NOT narrowed
    completely unguarded.
    """
    for src in loadable_apks + sorted(
        glob.glob(str(REPO_ROOT / "test_apk" / "APK" / "*.dex"))
    ):
        try:
            dk = dexllm.DexKit(src)
        except Exception:  # noqa: BLE001
            continue
        for s in sorted(
            (v for v in dk.list_value_strings() if any(ord(c) > 0xFFFF for c in v)),
            key=len,
        ):
            owners = dk.find_methods_using_strings([s], "equals", False)
            if owners:
                return dk, s, owners[0].descriptor
    pytest.skip("no method-loaded astral literal in the corpus")


def test_string_literals_keep_the_art_code_units(loadable_apks):
    """A LITERAL is `mirror::String` CONTENT — the fidelity claim still holds there.

    This is the half of the README claim that was NOT narrowed, so a change that
    made identifiers readable by relaxing the literal escaper would fail here.
    """
    dk, s, method = _astral_literal_method(loadable_apks)
    src = dk.decompile_method(method)
    # A failed body would make the escape-absence assertions below pass for the
    # wrong reason (and a corpus change could make that a spurious red).
    assert src and not src.startswith("// DECOMPILE ERROR"), method
    astral = [c for c in s if ord(c) > 0xFFFF]
    assert astral
    for ch in astral:
        hi, lo = struct.unpack(">2H", ch.encode("utf-16-be"))
        # the ART code units, as the Writer's per-unit escaper emits them
        assert f"\\u{hi:04x}\\u{lo:04x}" in src, (ch, method)
        # ...and NOT combined into the readable character, which is what the
        # identifier path now does and the literal path deliberately does not.
        assert ch not in src, (ch, method)


def test_astral_literal_method_decompiles_without_raising(loadable_apks):
    """The real guard on the emitter: it must not produce un-decodable bytes.

    An earlier version asserted `all(not 0xD800 <= ord(c) <= 0xDFFF ...)` over the
    returned `str` and called that "no raw surrogate reaches the text". That can
    never fail: `decompile_method` returns through pybind11's DEFAULT (strict
    UTF-8) caster, so a raw surrogate byte sequence RAISES at the call and can
    never become a code point in the result. The observable property is the
    absence of that raise, so assert it directly — and pin that the method really
    carries the astral literal, so it is not a guard on an empty body.
    """
    dk, s, method = _astral_literal_method(loadable_apks)
    src = dk.decompile_method(method)  # raises if any byte is not valid UTF-8
    assert src and not src.startswith("// DECOMPILE ERROR"), method
    assert any(ord(c) > 0xFFFF for c in s)
