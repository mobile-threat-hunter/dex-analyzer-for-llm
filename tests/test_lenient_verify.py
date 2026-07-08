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


# --- OOB instruction-operand operands under lenient (regression) -------------
# lenient skips VerifyInsns, so a crafted const-string / field / invoke operand
# whose index is out of range reaches the core's cross-ref builders. Those
# indices must be bounded at collection (dex_item.cpp) or they OOB-index the
# string pool / field_get_method_ids / method_caller_ids → SEGV. The 0xFF
# garbage dex above does NOT exercise this (0xFF is an invalid opcode, never
# collected); these craft VALID opcodes with OOB operands.

# (opcode bytes for insns[0], little-endian) — each a complete, well-formed
# instruction whose operand index is far out of range.
_OOB_OPERANDS = {
    # const-string/jumbo vAA, idx32=0x7FFFFFFF  → OOB string pool (SEGV vector)
    "const_string_jumbo": (bytes([0x1B, 0x00, 0xFF, 0xFF, 0xFF, 0x7F]), 3),
    # sget v0, field@0xFFFF → OOB field_get_method_ids at load-time cross-ref
    "sget_field": (bytes([0x60, 0x00, 0xFF, 0xFF]), 2),
    # invoke-static {}, meth@0xFFFF → OOB method_caller_ids at load-time cross-ref
    "invoke_method": (bytes([0x71, 0x00, 0xFF, 0xFF, 0x00, 0x00]), 3),
}


def _oob_operand_dex(raw: bytearray, payload: bytes, min_units: int) -> bool:
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
                if insns_size >= min_units:
                    raw[code_off + 16 : code_off + 16 + len(payload)] = payload
                    return True
    return False


@pytest.fixture(scope="module")
def _base_classes_dex():
    for apk in sorted(glob.glob(str(REPO / "test_apk" / "APK" / "*.apk"))):
        try:
            with zipfile.ZipFile(apk) as z:
                if "classes.dex" in z.namelist():
                    return bytearray(z.read("classes.dex"))
        except Exception:
            continue
    pytest.skip("no classes.dex in corpus")


@pytest.mark.parametrize("kind", list(_OOB_OPERANDS))
def test_lenient_oob_operand_does_not_crash(kind, _base_classes_dex, tmp_path_factory):
    """A VALID opcode with an out-of-range operand index, loaded lenient, must not
    crash any analysis path that consumes that index (the cross-ref builders)."""
    payload, min_units = _OOB_OPERANDS[kind]
    raw = bytearray(_base_classes_dex)
    if not _oob_operand_dex(raw, payload, min_units):
        pytest.skip("no suitable code_item")
    path = tmp_path_factory.mktemp("oob") / f"{kind}.dex"
    path.write_bytes(bytes(raw))

    # strict rejects it (VerifyInsns catches the OOB operand) — proves the craft.
    with pytest.raises(Exception):
        dexllm.DexKit(str(path))

    # lenient loads + every consumer of the index survives (was SEGV pre-fix).
    dk = dexllm.DexKit(str(path), lenient=True)
    dk.list_value_strings()
    dk.find_methods_using_strings(["http"], match_type="contains")
    methods = [m for c in dk.list_classes() for m in dk.list_class_methods(c)]
    for c in dk.list_classes():
        dk.decompile_class_java(c)  # load-time cross-ref + decompile
    # resolve_call_args + find_call_sites_from_method both walk AnalyzeMethodInvokes →
    # BuildMethodSignature on the raw invoke operand — the same lenient OOB surface (an
    # out-of-range callee method_idx must yield a bounded "" descriptor, never a crash).
    for m in methods:
        dk.resolve_call_args(m)
        dk.find_call_sites_from_method(m)
    assert dexllm.extract_iocs(dk, with_xref=True, xref_limit=10) is not None


def test_lenient_does_not_relax_structure():
    # lenient only drops VerifyInsns — a structurally-broken dex (bad magic) is
    # still rejected.
    with pytest.raises(Exception):
        import tempfile

        f = tempfile.NamedTemporaryFile(suffix=".dex", delete=False)
        f.write(b"NOTDEX\n" + b"\x00" * 200)
        f.close()
        dexllm.DexKit(f.name, lenient=True)
