"""Load-free ``verify(path)`` — the verify() sibling of identify().

Runs the DexVerifier over a path's dex(es) WITHOUT constructing a DexKit and
returns one verdict per dex. The load-bearing contract: for a loadable source
the verdicts are byte-identical to ``DexKit(path).verify_report()`` (same
VerifyDex call, same dex_id assignment), and unlike construction it NEVER throws
— a malformed / unopenable / non-dex path is reported as a ``valid=False``
verdict.
"""

from __future__ import annotations

import struct
import subprocess
import sys
from pathlib import Path

import pytest

import dexllm
from dexllm import sdk
from dexllm.sdk.ports import ContainerProbePort


def _forge_store_overread_zip(path: Path, declared_size: int = 50_000_000) -> None:
    """A zip with one STORE ``classes.dex`` whose central-directory comp_size is
    huge (``declared_size``) while the actual stored data is 4 bytes. The loader
    validates the local-header span but not ``data_offset + comp_size``, so the
    STORE memcpy in GetUncompressData used to overread the mmap → OOB → SIGBUS.
    """
    name = b"classes.dex"
    data = b"dex\n"
    lfh = (
        struct.pack(
            "<IHHHHHIIIHH", 0x04034B50, 20, 0, 0, 0, 0, 0,
            declared_size, declared_size, len(name), 0,
        )
        + name
        + data
    )
    cd_off = len(lfh)
    cdh = (
        struct.pack(
            "<IHHHHHHIIIHHHHHII", 0x02014B50, 20, 20, 0, 0, 0, 0, 0,
            declared_size, declared_size, len(name), 0, 0, 0, 0, 0, 0,
        )
        + name
    )
    eocd = struct.pack(
        "<IHHHHIIH", 0x06054B50, 0, 0, 1, 1, len(cdh), cd_off, 0
    )
    path.write_bytes(lfh + cdh + eocd)


def test_verify_matches_verify_report(loadable_apks):
    """verify(path) is byte-identical to DexKit(path).verify_report() (strict)."""
    for apk in loadable_apks:
        report = dexllm.verify(apk)
        loaded = dexllm.DexKit(apk).verify_report()
        assert report == loaded, apk
        # every dex of a loadable container is structurally valid; the ids of the
        # accepted dexes are the running 0-based sequence.
        assert report, apk
        valid_ids = [r["dex_id"] for r in report if r["valid"]]
        assert valid_ids == list(range(len(valid_ids))), apk


def test_verify_lenient_matches_report(loadable_apks):
    """The lenient toggle threads through: verify(p, lenient=True) == loaded."""
    apk = loadable_apks[0]
    report = dexllm.verify(apk, lenient=True)
    loaded = dexllm.DexKit([apk], lenient=True).verify_report()
    assert report == loaded


def test_verify_never_throws_on_missing_file():
    """An unopenable path is a valid=False verdict, not an exception."""
    report = dexllm.verify("/nonexistent/does/not/exist.dex")
    assert report == [
        {
            "dex_id": -1,
            "name": "/nonexistent/does/not/exist.dex",
            "valid": False,
            "reason": "cannot open (file not found or empty)",
        }
    ]


def test_verify_never_throws_on_non_dex(tmp_path: Path):
    """A file that is neither a .dex nor a zip is rejected without raising."""
    p = tmp_path / "notes.txt"
    p.write_bytes(b"hello, this is not a dex or a zip\n")
    report = dexllm.verify(str(p))
    assert len(report) == 1
    assert report[0]["valid"] is False
    assert report[0]["dex_id"] == -1
    assert "neither a .dex" in report[0]["reason"]


def test_verify_malformed_dex_rejects_and_load_throws(tmp_path: Path):
    """A malformed .dex → valid=False verdict; and it THROWS when actually loaded
    (verify is the non-throwing preview of what construction would reject)."""
    p = tmp_path / "bad.dex"
    # valid magic, truncated/garbage body
    p.write_bytes(b"dex\n035\x00" + b"\x00" * 20)
    report = dexllm.verify(str(p))
    assert len(report) == 1
    assert report[0]["valid"] is False
    assert report[0]["reason"]  # a specific structural reason
    # construction rejects the same input by throwing
    with pytest.raises(Exception):
        dexllm.DexKit(str(p))


def test_verify_crafted_store_overread_does_not_crash(tmp_path: Path):
    """Regression: a crafted STORE zip entry with a huge declared comp_size must
    not OOB-read (SIGBUS/SEGV) during extraction — verify() reports it, in-process
    (a crash would take the whole process down, so run it in a subprocess and
    assert a clean exit + the rejection verdict)."""
    evil = tmp_path / "evil.apk"
    _forge_store_overread_zip(evil)
    # identify still classifies it as a 1-dex zip (the overread is in extraction)
    assert dexllm.identify(str(evil))["dex_count"] == 1
    proc = subprocess.run(
        [
            sys.executable,
            "-c",
            "import dexllm,sys;"
            "r=dexllm.verify(sys.argv[1]);"
            "assert r==[{'dex_id':-1,'name':'classes.dex','valid':False,"
            "'reason':'decompression failed'}], r;"
            "print('OK')",
            str(evil),
        ],
        capture_output=True,
        text=True,
    )
    assert proc.returncode == 0, (
        f"verify() crashed on crafted zip (rc={proc.returncode}): "
        f"{proc.stdout}{proc.stderr}"
    )
    assert "OK" in proc.stdout


def test_constructor_rejects_crafted_store_overread(tmp_path: Path):
    """The same crafted zip must make construction RAISE (not crash) — the load
    boundary shares the hardened extraction path."""
    evil = tmp_path / "evil.apk"
    _forge_store_overread_zip(evil)
    proc = subprocess.run(
        [
            sys.executable,
            "-c",
            "import dexllm,sys\n"
            "try:\n"
            "    dexllm.DexKit(sys.argv[1]); print('NOTHROW')\n"
            "except RuntimeError:\n"
            "    print('RAISED')\n",
            str(evil),
        ],
        capture_output=True,
        text=True,
    )
    assert proc.returncode == 0, f"construction crashed (rc={proc.returncode})"
    assert "RAISED" in proc.stdout


def test_verify_multidex_per_dex(loadable_apks):
    """A multidex container yields one verdict per classes*.dex (ascending ids)."""
    multidex = next(
        (a for a in loadable_apks if dexllm.identify(a)["dex_count"] > 1), None
    )
    if multidex is None:
        pytest.skip("no multidex container in the corpus")
    report = dexllm.verify(multidex)
    assert len(report) == dexllm.identify(multidex)["dex_count"]
    assert [r["dex_id"] for r in report] == list(range(len(report)))
    assert all(r["valid"] for r in report)


# ── SDK typed surface ──────────────────────────────────────────────────────────


def test_sdk_verify_typed(loadable_apks):
    """sdk.verify returns a typed DexVerifyStatus tuple == the model form of the
    loaded verify_report."""
    apk = loadable_apks[0]
    statuses = sdk.verify(apk)
    assert isinstance(statuses, tuple)
    assert all(isinstance(s, sdk.DexVerifyStatus) for s in statuses)
    assert statuses == sdk.open_apk(apk).verify_report()


def test_sdk_verify_lenient_kwonly(loadable_apks):
    """lenient is keyword-only on the SDK surface (mirrors open_apk)."""
    apk = loadable_apks[0]
    assert sdk.verify(apk, lenient=True) == tuple(
        sdk.DexVerifyStatus(**r) for r in dexllm.verify(apk, lenient=True)
    )


def test_container_probe_conforms_to_port():
    """ContainerProbe implements ContainerProbePort (identify + verify)."""
    probe = sdk.ContainerProbe()
    assert isinstance(probe, ContainerProbePort)
    # the method form agrees with the functional form
    report_missing = probe.verify("/nope.dex")
    assert report_missing[0].valid is False
