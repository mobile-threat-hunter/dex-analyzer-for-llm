"""dexllm#23 — every `type_id` descriptor is syntax-checked (ART CheckInterTypeIdItem).

The port validated a descriptor only where ANOTHER id table referenced it
(`field_id.class_idx`/`type_idx`, `method_id.class_idx`, and the class_def
class/super/interface set), so a type used ONLY as a proto return/parameter type
or as an instruction operand (`const-class`, `new-instance`, `check-cast`,
`new-array`, …) could hold arbitrary bytes and still pass `VerifyDex`.

That is reachable in OUTPUT: the smali renderer emits type names unescaped, so a
same-length payload carrying `"` and a newline forged a whole instruction line in
a listing handed to an analyst or to an LLM through the MCP tools. Member NAMES
were never affected (`IsValidMemberName` rejects `"`, `\\` and control characters,
and it IS applied to `field_id.name_idx` / `method_id.name_idx`).
"""

import glob
import struct
from pathlib import Path

import pytest

import dexllm

REPO_ROOT = Path(__file__).resolve().parents[1]


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
        _ln, d = _uleb(buf, o)
        out.append((d, bytes(buf[d : buf.index(0, d)])))
    return out


def _guarded_type_idxs(buf):
    """type_idx values ALREADY reached by a pre-dexllm#23 descriptor check.

    Those are the ones referenced from field_id (class/type), method_id (class)
    and class_def (class/super/interfaces). A forgery there would be rejected by
    the OLD verifier too, so the guard below must avoid them or it proves nothing.
    """
    g = set()
    fn, foff = struct.unpack_from("<II", buf, 80)
    for i in range(fn):
        c, t = struct.unpack_from("<HH", buf, foff + 8 * i)
        g.update((c, t))
    mn, moff = struct.unpack_from("<II", buf, 88)
    for i in range(mn):
        g.add(struct.unpack_from("<H", buf, moff + 8 * i)[0])
    cn, coff = struct.unpack_from("<II", buf, 0x60)
    for i in range(cn):
        # ClassDef: class_idx @+0, access_flags @+4, superclass_idx @+8. Reading
        # (+0, +4) as the pair would take access flags for a type index — missing
        # every real superclass, so _forge could target one the OLD verifier
        # already rejected (`class_def: invalid superclass`) and the test would
        # stop discriminating.
        cls = struct.unpack_from("<I", buf, coff + 32 * i)[0]
        sup = struct.unpack_from("<I", buf, coff + 32 * i + 8)[0]
        g.update((cls, sup))
        ioff = struct.unpack_from("<I", buf, coff + 32 * i + 12)[0]
        if ioff:
            size = struct.unpack_from("<I", buf, ioff)[0]
            for k in range(size):
                g.add(struct.unpack_from("<H", buf, ioff + 4 + 2 * k)[0])
    return g


def _proto_reachable_type_idxs(buf):
    """type_idx values a method signature RENDERS — return + parameter types.

    Preferring one of these makes the forgery demonstrate the actual output
    channel (`FormatMethodRef` writes them into the listing), not merely the
    verifier verdict.
    """
    r = set()
    mn, moff = struct.unpack_from("<II", buf, 88)
    _pn, poff = struct.unpack_from("<II", buf, 72)
    for i in range(mn):
        proto = struct.unpack_from("<H", buf, moff + 8 * i + 2)[0]
        _sh, ret, params = struct.unpack_from("<III", buf, poff + 12 * proto)
        r.add(ret)
        if params:
            size = struct.unpack_from("<I", buf, params)[0]
            for k in range(size):
                r.add(struct.unpack_from("<H", buf, params + 4 + 2 * k)[0])
    return r


def _lcp(a, b):
    n = 0
    while n < len(a) and n < len(b) and a[n] == b[n]:
        n += 1
    return n


def _forge(raw):
    """Forge a smali instruction line into a type descriptor, in place.

    Targets a type_idx NOT covered by the old checks (so the forgery is exactly
    the dexllm#23 channel), and patches only past the longest common prefix with
    both string_ids neighbours, so byte length, utf16_len and the ART sort order
    are all unchanged and the dex is otherwise valid.

    Returns (patched_bytes, payload) or (None, None).
    """
    buf = bytearray(raw)
    tbl = _strings(buf)
    guarded = _guarded_type_idxs(buf)
    rendered = _proto_reachable_type_idxs(buf)
    tn, toff = struct.unpack_from("<II", buf, 64)

    # Proto-reachable candidates first: unguarded AND actually written into a
    # rendered method signature, i.e. the full dexllm#23 channel end to end.
    for t in sorted(range(tn), key=lambda x: (x not in rendered, x)):
        if t in guarded:
            continue
        sidx = struct.unpack_from("<I", buf, toff + 4 * t)[0]
        d, s = tbl[sidx]
        if any(c >= 0x80 for c in s):
            continue
        prev = tbl[sidx - 1][1] if sidx else b""
        nxt = tbl[sidx + 1][1] if sidx + 1 < len(tbl) else None
        p = max(_lcp(s, prev), _lcp(s, nxt) if nxt is not None else 0) + 1
        n = len(s) - p
        if n < 16:
            continue
        payload = (b'";\n    0x0: nop\n' + b"Z" * n)[:n]
        buf[d + p : d + len(s)] = payload
        return bytes(buf), payload
    return None, None


def _forged_dex(tmp_path, name):
    for cand in sorted(glob.glob(str(REPO_ROOT / "test_apk" / "APK" / "*.dex"))):
        raw = open(cand, "rb").read()
        if raw[:4] != b"dex\n":
            continue
        patched, payload = _forge(raw)
        if patched is None:
            continue
        f = tmp_path / name
        f.write_bytes(patched)
        return str(f), payload
    pytest.skip("no bare .dex in the corpus has a forgeable proto-only type descriptor")


def test_forged_type_descriptor_is_rejected(tmp_path):
    """A type descriptor carrying `"` and a newline must not load at all.

    Rejecting at the verifier is where the project's stated safety contract lives
    ("a load-time structural verifier is the single gate"), so this asserts the
    VERDICT — not that the renderer happened to escape it downstream.
    """
    path, _payload = _forged_dex(tmp_path, "forged_type.dex")

    report = dexllm.verify(path)
    assert not report[0]["valid"], "a forged type descriptor must be rejected"
    # Specifically the new per-type_id check, not some incidental invariant the
    # forgery also happened to break.
    assert "type_id" in report[0]["reason"], report[0]["reason"]

    # …and the load path must refuse it too, not just the standalone probe.
    with pytest.raises(Exception):
        dexllm.DexKit(path)


def test_forged_type_descriptor_is_rejected_leniently_too(tmp_path):
    """lenient=True skips only VerifyInsns — the descriptor check still applies.

    Packer dumps are a first-class mode, so the channel must not reopen there.
    """
    path, _payload = _forged_dex(tmp_path, "forged_type_lenient.dex")
    report = dexllm.verify(path, lenient=True)
    assert not report[0]["valid"]
    assert "type_id" in report[0]["reason"], report[0]["reason"]


def test_type_id_check_does_not_false_reject_the_corpus():
    """Zero false-reject: ART runs this exact check, so anything Android loads passes.

    A new verifier check that rejects a real app is far worse than the gap it
    closes, so this asserts every bundled container still verifies clean.
    """
    checked = 0
    for p in sorted(
        glob.glob(str(REPO_ROOT / "test_apk" / "APK" / "*.apk"))
        + glob.glob(str(REPO_ROOT / "test_apk" / "APK" / "*.dex"))
    ):
        try:
            if dexllm.identify(p).get("dex_count", 0) == 0:
                continue
        except Exception:  # noqa: BLE001
            continue
        for v in dexllm.verify(p):
            assert v["valid"], (p, v["dex_id"], v["reason"])
            checked += 1
    if not checked:
        pytest.skip("no loadable dex container in the corpus")
