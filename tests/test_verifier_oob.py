"""Regression: VerifyDex must reject crafted ID-table overruns without OOB.

An ID-table's header field is an element COUNT; the verifier indexes the table by
`i * sizeof(item)` (ClassDef = 32 bytes). A crafted dex whose count fits as BYTES
but whose `count * sizeof` overruns the file used to OOB-read inside the verifier
(uncatchable SEGV). VerifyDex now bounds the byte span via CheckListSize. These
tests craft exactly that "passes the byte-count gate but overruns the span" case
and assert a clean rejection (RuntimeError), not a crash.
"""

import glob
import struct
import zipfile
from pathlib import Path

import pytest

import dexllm

REPO = Path(__file__).resolve().parents[1]

# dex header field offsets (u4 LE)
_OFF = {
    "string_ids_size": 0x38,
    "type_ids_size": 0x40,
    "proto_ids_size": 0x48,
    "field_ids_size": 0x50,
    "method_ids_size": 0x58,
    "class_defs_size": 0x60,
    "class_defs_off": 0x64,
}
_ELEM = {  # sizeof(item) for each table
    "string_ids_size": 4,
    "type_ids_size": 4,
    "proto_ids_size": 12,
    "field_ids_size": 8,
    "method_ids_size": 8,
    "class_defs_size": 32,
}


def _base_dex():
    for apk in sorted(glob.glob(str(REPO / "test_apk" / "APK" / "*.apk"))):
        try:
            with zipfile.ZipFile(apk) as z:
                if "classes.dex" in z.namelist():
                    return z.read("classes.dex")
        except Exception:
            continue
    return None


@pytest.fixture(scope="module")
def base_dex():
    d = _base_dex()
    if not d:
        pytest.skip("no bundled APK with classes.dex")
    return d


@pytest.mark.parametrize(
    "field", ["string_ids_size", "type_ids_size", "field_ids_size", "class_defs_size"]
)
def test_inflated_id_table_count_rejected_not_crashed(base_dex, tmp_path, field):
    b = bytearray(base_dex)
    fsize = len(b)
    cd_off = struct.unpack_from("<I", b, _OFF["class_defs_off"])[0]
    avail = fsize - cd_off
    elem = _ELEM[field]
    # count that PASSES the byte-count gate (count <= avail) but whose span
    # (count * elem) overruns the file — the exact OOB-trigger class.
    count = avail // 2
    assert count <= avail and count * elem > avail
    struct.pack_into("<I", b, _OFF[field], count)
    p = tmp_path / "oob.dex"
    p.write_bytes(bytes(b))
    # Must reject (or otherwise refuse to load) — never crash the process.
    with pytest.raises(Exception):
        dk = dexllm.DexKit(str(p))
        dk.list_classes()  # force full use if it somehow loaded


def test_valid_dex_still_loads(base_dex, tmp_path):
    p = tmp_path / "ok.dex"
    p.write_bytes(base_dex)
    dk = dexllm.DexKit(str(p))
    assert dk.list_classes()  # the byte-span check is a no-op on valid input
