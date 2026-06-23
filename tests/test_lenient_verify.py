"""Lenient (ART-structural-equivalent) verification for runtime-dumped dexes.

`DexKit(src, lenient=True)` skips the load verifier's instruction-operand checks
(VerifyInsns — the one part beyond ART's structural DexFileVerifier) so a
structurally-valid dex whose method bodies are garbage still loads. That is exactly
what a packer's runtime-dumped, partially-decrypted dex looks like (only the
currently-executing methods are decrypted), and exactly what ART loads — it defers
instruction validity to the runtime method_verifier, which packers skip. Header,
ids, and code_item BOUNDS are still verified. See [[project-packer-analysis-direction]].
"""

import glob
import struct
import zipfile
from pathlib import Path

import pytest

import dexllm

REPO = Path(__file__).resolve().parents[1]


def _uleb(b, p):
    r = s = 0
    while True:
        x = b[p]
        p += 1
        r |= (x & 0x7F) << s
        if not (x & 0x80):
            return r, p
        s += 7


def _garbage_code_dex(raw: bytearray):
    """Overwrite the first code_item's insns[] with 0xFF (garbage instructions),
    leaving all structure (header/ids/class_data/code_item header) intact."""
    cds_size = struct.unpack_from("<I", raw, 0x60)[0]
    cds_off = struct.unpack_from("<I", raw, 0x64)[0]
    for i in range(cds_size):
        class_data_off = struct.unpack_from("<I", raw, cds_off + i * 32 + 24)[0]
        if class_data_off == 0:
            continue
        p = class_data_off
        sf, p = _uleb(raw, p)
        inf, p = _uleb(raw, p)
        dm, p = _uleb(raw, p)
        vm, p = _uleb(raw, p)
        for _ in range(sf + inf):
            _, p = _uleb(raw, p)
            _, p = _uleb(raw, p)
        for _ in range(dm + vm):
            _, p = _uleb(raw, p)
            _, p = _uleb(raw, p)
            code_off, p = _uleb(raw, p)
            if code_off:
                insns_size = struct.unpack_from("<I", raw, code_off + 12)[0]
                if insns_size > 2:
                    for k in range(insns_size * 2):
                        raw[code_off + 16 + k] = 0xFF
                    return True
    return False


@pytest.fixture(scope="module")
def garbage_dex(tmp_path_factory):
    apks = sorted(glob.glob(str(REPO / "test_apk" / "APK" / "*.apk")))
    for apk in apks:
        try:
            with zipfile.ZipFile(apk) as z:
                if "classes.dex" not in z.namelist():
                    continue
                raw = bytearray(z.read("classes.dex"))
        except Exception:
            continue
        if _garbage_code_dex(raw):
            p = tmp_path_factory.mktemp("lenient") / "garbage.dex"
            p.write_bytes(bytes(raw))
            return str(p)
    pytest.skip("could not craft a garbage-code dex from the corpus")


def test_strict_rejects_garbage_instructions(garbage_dex):
    # default (strict) verification catches the invalid instruction operands.
    with pytest.raises(Exception):
        dexllm.DexKit(garbage_dex)


def test_lenient_loads_structurally_valid_dump(garbage_dex):
    # lenient=True (ART-structural-equivalent) loads it — the structure is intact,
    # only the method bodies are garbage (the partial-decrypt dump case).
    dk = dexllm.DexKit(garbage_dex, lenient=True)
    assert dk.list_classes()  # classes are recovered
    assert dk.verify_report()[0]["valid"]


def test_lenient_in_multisource(garbage_dex):
    # lenient applies across a multi-source load too (dump first, apk second).
    apk = next(
        (
            a
            for a in sorted(glob.glob(str(REPO / "test_apk" / "APK" / "*.apk")))
            if dexllm.identify(a)["dex_count"] > 0
        ),
        None,
    )
    if apk is None:
        pytest.skip("no APK with a dex")
    dk = dexllm.DexKit([garbage_dex, apk], lenient=True)
    assert dk.dex_count() >= 2


def test_lenient_does_not_relax_structure():
    # lenient only drops VerifyInsns — a structurally-broken dex (bad magic) is
    # still rejected.
    with pytest.raises(Exception):
        import tempfile

        f = tempfile.NamedTemporaryFile(suffix=".dex", delete=False)
        f.write(b"NOTDEX\n" + b"\x00" * 200)
        f.close()
        dexllm.DexKit(f.name, lenient=True)
