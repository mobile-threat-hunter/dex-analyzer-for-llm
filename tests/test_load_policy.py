"""Load policy and in-memory inputs (dexllm#119, dexllm#120).

Three things a session now says about itself, and the inputs that need them:

* ``art_open`` per verdict row -- whether ART's open of the SOURCE yields that
  dex. ART opens a zip's ``classes.dex``, ``classes2.dex``, ... in order and
  stops at the first one it cannot open, keeping the ones before it
  (``DexFileLoader::Open`` + ``OatFileManager::OpenDexFilesFromOat``,
  android-16.0.0_r4); it opens each class-path element on its own
  (``DexPathList.makeDexElements``); and it reads ONE dex from a file whose
  header is not a v41 container. A dexllm-only rejection (``VerifyInsns``) is not
  an ART failure; a header checksum ART would refuse is.
* ``mode`` -- ``"isolated"`` (default) loads every dex that verifies,
  ``"runtime"`` only the ``art_open`` ones.
* ``load_status()`` -- ``complete`` / ``matches_art`` / ``rejected``, so a
  partial session cannot pass for a whole one.

Every craft is built from committed fixtures, so the file runs corpus-less.
"""

from __future__ import annotations

import mmap
import pathlib
import struct
import subprocess
import sys
import zipfile
import zlib

import pytest
from test_lenient_verify import _garbage_code_dex

import dexllm
import dexllm.sdk as sdk

DATA = pathlib.Path(__file__).parent / "data"
MULTIDEX = DATA / "multidex.apk"
CONTAINER = DATA / "multidex-container.dex"

with zipfile.ZipFile(MULTIDEX) as _z:
    D0 = _z.read("classes.dex")  # declares Lcom/foobar/foo/Foobar;
    D1 = _z.read("classes2.dex")  # declares Lcom/blafoo/bar/Blafoo;
FOO = "Lcom/foobar/foo/Foobar;"
BLA = "Lcom/blafoo/bar/Blafoo;"


def _fix_checksum(b: bytes) -> bytes:
    b = bytearray(b)
    size = struct.unpack_from("<I", b, 32)[0]
    struct.pack_into("<I", b, 8, zlib.adler32(bytes(b[12:size])))
    return bytes(b)


def _bad_magic(b: bytes) -> bytes:
    """Rejected by every check ART runs: the magic."""
    return b"xex\n" + b[4:]


def _bad_checksum(b: bytes) -> bytes:
    """Verifies -- the gate does not read the checksum -- but ART refuses it."""
    b = bytearray(b)
    b[8] ^= 1
    return bytes(b)


def _insns_only(b: bytes) -> bytes:
    """Rejected by the strict gate's VerifyInsns only, which ART's STRUCTURAL
    verifier does not run: ART opens this dex."""
    raw = bytearray(b)
    assert _garbage_code_dex(raw), "the fixture lost its code item"
    return _fix_checksum(bytes(raw))


def _apk(tmp_path, name, *entries) -> str:
    p = tmp_path / name
    with zipfile.ZipFile(p, "w") as z:
        for i, data in enumerate(entries):
            z.writestr("classes%s.dex" % ("" if i == 0 else i + 1), data)
    return str(p)


def _rows(dk_or_rows):
    rows = (
        dk_or_rows.verify_report()
        if hasattr(dk_or_rows, "verify_report")
        else dk_or_rows
    )
    return [(r["name"], r["valid"], r["art_open"]) for r in rows]


# ── the crafts mean what they say ────────────────────────────────────────────


def test_the_crafts_hit_the_check_they_are_named_for():
    """Premises, asserted rather than assumed: each craft is rejected (or
    accepted) for the reason the cases below rely on."""
    assert dexllm.verify_bytes(D0)[0]["art_open"] is True
    # Alone, a broken magic is not even sniffed as a dex; as a zip member or an
    # explicit image it reaches the verifier, which is where the cases use it.
    [m] = dexllm.DexKit.from_dex_images(
        [("x.dex", D0), ("m.dex", _bad_magic(D0))]
    ).verify_report()[1:]
    assert not m["valid"] and not m["art_open"] and m["reason"] == "Bad file magic"
    [c] = dexllm.verify_bytes(_bad_checksum(D0))
    assert c["valid"] and not c["art_open"]
    assert c["art_deviations"] and "checksum" in c["art_deviations"][0]
    [s] = dexllm.verify_bytes(_insns_only(D0))
    assert not s["valid"] and s["reason"].startswith("code: ") and s["art_open"]
    [lenient] = dexllm.verify_bytes(_insns_only(D0), lenient=True)
    assert lenient["valid"] and lenient["art_deviations"] == []


# ── dexllm#120: a rejected classes.dex ───────────────────────────────────────


def test_a_rejected_main_dex_shifts_first_wins_and_says_so(tmp_path):
    """The issue's own fixture: classes.dex corrupt, classes2.dex valid, both
    declaring the same class. Isolated mode loads classes2.dex as dex 0 -- the
    pre-#120 behaviour, kept -- and load_status() now says the view is partial
    AND not the device's."""
    apk = _apk(tmp_path, "dup.apk", _bad_magic(D1), D1)
    dk = dexllm.DexKit(apk)
    assert dk.dex_count() == 1
    assert dk.locate_class_dex(BLA) == 0
    assert dk.extract_dex(0)["entry"] == "classes2.dex"
    assert _rows(dk) == [("classes.dex", False, False), ("classes2.dex", True, False)]
    st = dk.load_status()
    assert st["mode"] == "isolated" and st["loaded_dex_count"] == 1
    assert st["complete"] is False and st["matches_art"] is False
    assert [r["name"] for r in st["rejected"]] == ["classes.dex"]


def test_runtime_mode_refuses_what_the_device_would_not_open(tmp_path):
    """ART opens nothing from that apk, so runtime mode loads nothing -- and the
    message says the dex after it VERIFIED, rather than "failed verification"."""
    apk = _apk(tmp_path, "dup.apk", _bad_magic(D1), D1)
    with pytest.raises(RuntimeError, match=r"ART's open of .* yields no dex") as e:
        dexllm.DexKit(apk, mode="runtime")
    assert "classes.dex: Bad file magic" in str(e.value)
    assert "mode='isolated'" in str(e.value)


def test_runtime_keeps_the_prefix_and_stops_at_the_first_failure(tmp_path):
    apk = _apk(tmp_path, "mid.apk", D0, _bad_magic(D0), D1)
    iso = dexllm.DexKit(apk)
    run = dexllm.DexKit(apk, mode="runtime")
    assert iso.dex_count() == 2 and run.dex_count() == 1
    assert set(iso.list_classes()) == {FOO, BLA}
    assert run.list_classes() == [FOO]
    want = [("classes.dex", True, True), ("classes2.dex", False, False)]
    assert _rows(iso) == want + [("classes3.dex", True, False)]
    assert _rows(run) == want + [("classes3.dex", False, False)]
    assert run.verify_report()[2]["reason"].startswith("not opened: ART stops a source")
    assert iso.load_status()["matches_art"] is False
    assert run.load_status()["matches_art"] is True
    assert run.load_status()["complete"] is False


def test_a_checksum_ART_refuses_ends_the_sequence_but_not_the_load(tmp_path):
    """The gate keeps not reading the checksum (no new rejection), but ART's open
    fails on it, so it is an ART failure for the sequence."""
    apk = _apk(tmp_path, "ck.apk", _bad_checksum(D0), D1)
    iso = dexllm.DexKit(apk)
    assert iso.dex_count() == 2
    assert _rows(iso) == [("classes.dex", True, False), ("classes2.dex", True, False)]
    assert "checksum" in iso.verify_report()[0]["art_deviations"][0]
    with pytest.raises(RuntimeError, match="yields no dex"):
        dexllm.DexKit(apk, mode="runtime")


def test_a_dexllm_only_rejection_does_not_end_the_sequence(tmp_path):
    """VerifyInsns is not part of ART's structural verifier: ART opens that dex
    and the ones after it, so runtime mode still loads classes2.dex -- while the
    rejected dex stays rejected (the gate is the safety contract)."""
    apk = _apk(tmp_path, "insns.apk", _insns_only(D0), D1)
    for mode in ("isolated", "runtime"):
        dk = dexllm.DexKit(apk, mode=mode)
        assert _rows(dk) == [("classes.dex", False, True), ("classes2.dex", True, True)]
        assert dk.list_classes() == [BLA]
        assert dk.load_status()["matches_art"] is False  # ART would also have dex 0
    lenient = dexllm.DexKit(apk, lenient=True, mode="runtime")
    assert lenient.dex_count() == 2 and lenient.load_status()["matches_art"] is True


def test_a_valid_apk_is_the_same_in_both_modes():
    for mode in ("isolated", "runtime"):
        dk = dexllm.DexKit(str(MULTIDEX), mode=mode)
        assert dk.dex_count() == 2
        assert _rows(dk) == [("classes.dex", True, True), ("classes2.dex", True, True)]
        st = dk.load_status()
        assert st == {
            "mode": mode,
            "complete": True,
            "matches_art": True,
            "loaded_dex_count": 2,
            "rejected": [],
        }


def test_a_v41_container_is_one_open_and_a_v35_concatenation_is_not(tmp_path):
    """ART follows a v41 container's chain but reads ONE dex from a file whose
    header is older; dexllm's concatenated-dump split loads the rest anyway in
    isolated mode, and says ART would not."""
    cont = dexllm.DexKit(str(CONTAINER), mode="runtime")
    assert cont.dex_count() == 2 and all(r["art_open"] for r in cont.verify_report())
    cat = tmp_path / "cat.dex"
    cat.write_bytes(D0 + D1)
    iso = dexllm.DexKit(str(cat))
    run = dexllm.DexKit(str(cat), mode="runtime")
    assert iso.dex_count() == 2 and run.dex_count() == 1
    assert [r["art_open"] for r in iso.verify_report()] == [True, False]
    assert "ART stops reading an image after a dex" in run.verify_report()[1]["reason"]
    # the bytes after a v35 dex are not a failure: the next SOURCE still opens
    nxt = dexllm.DexKit([str(cat), str(MULTIDEX)], mode="runtime")
    assert nxt.dex_count() == 3


def test_verify_matches_the_session_in_both_modes(tmp_path):
    apk = _apk(tmp_path, "mid.apk", D0, _bad_magic(D0), D1)
    for mode in ("isolated", "runtime"):
        assert (
            dexllm.verify(apk, mode=mode)
            == dexllm.DexKit(apk, mode=mode).verify_report()
        )


def test_an_unknown_mode_is_refused():
    with pytest.raises(ValueError, match="'isolated' or 'runtime'"):
        dexllm.DexKit(str(MULTIDEX), mode="device")
    with pytest.raises(ValueError):
        dexllm.verify(str(MULTIDEX), mode="")


# ── dexllm#119: a list of sources ─────────────────────────────────────────────


def test_one_bad_source_no_longer_costs_the_others(tmp_path):
    """The #119 comment's isolated case. Pre-#119 the whole list raised."""
    ok = tmp_path / "ok.dex"
    ok.write_bytes(D0)
    bad = tmp_path / "bad.dex"
    bad.write_bytes(_bad_magic(D1))
    ok2 = tmp_path / "ok2.dex"
    ok2.write_bytes(D1)
    for mode in ("isolated", "runtime"):  # class-path elements are independent
        dk = dexllm.DexKit([str(ok), str(bad), str(ok2)], mode=mode)
        assert dk.dex_count() == 2 and set(dk.list_classes()) == {FOO, BLA}
        assert [r["valid"] for r in dk.verify_report()] == [True, False, True]
        assert dk.load_status()["complete"] is False
    # source_info stays one row per sources() entry, the rejected one included
    assert len(dk.source_info()) == len(dk.sources()) == 3


def test_a_list_that_yields_nothing_still_raises(tmp_path):
    bad = tmp_path / "bad.dex"
    bad.write_bytes(_bad_magic(D1))
    with pytest.raises(RuntimeError, match=r"^dexllm: '.*bad.dex' is neither a .dex"):
        dexllm.DexKit([str(bad)])  # one source: its own message, as before
    with pytest.raises(RuntimeError, match="none of the 2 sources") as e:
        dexllm.DexKit([str(bad), str(tmp_path / "missing.dex")])
    assert "is neither a .dex" in str(e.value) and "cannot open" in str(e.value)


# ── dexllm#119: bytes ─────────────────────────────────────────────────────────


@pytest.mark.parametrize(
    "fixture", sorted(p.name for p in DATA.glob("*.dex")) + ["multidex.apk"]
)
def test_bytes_and_path_give_the_same_session(fixture):
    path = str(DATA / fixture)
    data = (DATA / fixture).read_bytes()
    a = dexllm.DexKit(path, lenient=True)
    b = dexllm.DexKit.from_bytes(data, lenient=True, source=path)
    assert a.verify_report() == b.verify_report()
    assert a.list_classes() == b.list_classes()
    assert a.dex_count() == b.dex_count()
    for i in range(a.dex_count()):
        assert a.extract_dex(i) == b.extract_dex(i)
    for c in a.list_classes()[:5]:
        assert a.decompile_class(c) == b.decompile_class(c)
    assert dexllm.verify(path, lenient=True) == dexllm.verify_bytes(
        data, lenient=True, source=path
    )
    probe = dexllm.identify(path)
    assert dexllm.identify_bytes(data, source=path) == {**probe, "in_memory": True}
    assert b.source_info() == [{**probe, "in_memory": True}]


def test_the_session_owns_its_bytes():
    """Requirement 3: release or mutate the buffer, then query."""
    buf = bytearray(MULTIDEX.read_bytes())
    dk = dexllm.DexKit.from_bytes(buf, source="m.apk")
    buf[:] = b"\0" * len(buf)
    del buf
    assert set(dk.list_classes()) == {FOO, BLA}
    assert dk.extract_dex(1)["bytes"] == D1
    view = memoryview(bytearray(D0))
    dk2 = dexllm.DexKit.from_dex_images([("classes.dex", view)])
    view.release()
    assert dk2.list_classes() == [FOO]


def test_bytes_labels_are_what_every_row_reports():
    dk = dexllm.DexKit.from_bytes(MULTIDEX.read_bytes(), source="sample.apk")
    assert dk.sources() == ["sample.apk"]
    assert {r["source"] for r in dk.verify_report()} == {"sample.apk"}
    assert dk.extract_dex(0)["source"] == "sample.apk"
    with pytest.raises(ValueError, match="loaded from bytes"):
        dexllm.add_dumped_dexes(dk, str(DATA / "invoke-custom.dex"))


def test_dex_images_keep_the_callers_order_and_names():
    dk = dexllm.DexKit.from_dex_images([("b.dex", D1), ("a.dex", D0)], source="emb")
    assert [dk.extract_dex(i)["entry"] for i in range(2)] == ["b.dex", "a.dex"]
    assert dk.locate_class_dex(BLA) == 0 and dk.locate_class_dex(FOO) == 1
    assert dk.source_info() == [
        {
            "format": "images",
            "is_apk": False,
            "has_manifest": False,
            "dex_count": 2,
            "source": "emb",
            "in_memory": True,
        }
    ]
    # first-wins follows the caller's order for a duplicated class
    dup = dexllm.DexKit.from_dex_images([("x.dex", D1), ("y.dex", D1)])
    assert dup.locate_class_dex(BLA) == 0


def test_dex_images_are_one_sequence(tmp_path):
    """The #119 comment's two acceptance cases: [ok, bad, ok]."""
    imgs = [("a.dex", D0), ("b.dex", _bad_magic(D0)), ("c.dex", D1)]
    iso = dexllm.DexKit.from_dex_images(imgs)
    run = dexllm.DexKit.from_dex_images(imgs, mode="runtime")
    assert set(iso.list_classes()) == {FOO, BLA}
    assert run.list_classes() == [FOO]
    assert [r["valid"] for r in run.verify_report()] == [True, False, False]
    assert "(b.dex: Bad file magic)" in run.verify_report()[2]["reason"]
    # the same bytes give the same reason inside a zip and as an image
    zipped = dexllm.DexKit(
        _apk(tmp_path, "z.apk", D0, _bad_magic(D0), D1), mode="runtime"
    )
    assert [r["reason"] for r in zipped.verify_report()] == [
        r["reason"].replace("b.dex", "classes2.dex") for r in run.verify_report()
    ]


def test_bad_bytes_inputs_are_refused_clearly():
    with pytest.raises(RuntimeError, match="empty buffer"):
        dexllm.DexKit.from_bytes(b"")
    with pytest.raises(TypeError):
        dexllm.DexKit.from_bytes("not bytes")  # a str is not a buffer
    with pytest.raises(TypeError, match=r"\(name: str, data: bytes\) pair"):
        dexllm.DexKit.from_dex_images([D0])
    with pytest.raises(ValueError, match="no dex images"):
        dexllm.DexKit.from_dex_images([])
    assert dexllm.verify_bytes(b"")[0]["reason"] == "empty buffer"
    assert dexllm.identify_bytes(b"PK\3\4junk")["format"] == "unknown"


@pytest.mark.skipif(sys.platform != "linux", reason="lazy anonymous mmap")
def test_an_image_past_four_gib_is_refused_not_truncated():
    """Requirement 6. An anonymous mapping is not touched until read, so the
    4 GiB buffer costs no memory -- and must be refused before the copy."""
    big = mmap.mmap(-1, 1 << 32)
    try:
        with pytest.raises(ValueError, match="too large"):
            dexllm.DexKit.from_bytes(big)
        with pytest.raises(ValueError, match="too large"):
            dexllm.verify_bytes(big)
    finally:
        big.close()


def test_malformed_bytes_never_crash():
    """Through the bytes form: truncations and byte flips of every committed
    fixture, judged by EXIT STATUS (a SIGSEGV is invisible to try/except)."""
    script = r"""
import pathlib, random, dexllm
rng = random.Random(119)
blobs = [p.read_bytes() for p in sorted(pathlib.Path(%r).glob("*.dex"))]
blobs.append(pathlib.Path(%r).read_bytes())
n = 0
for b in blobs:
    for k in range(25):
        x = bytearray(b)
        if k %% 5 == 0:
            x = x[: rng.randrange(1, len(x))]
        else:
            for _ in range(rng.randrange(1, 8)):
                i = rng.randrange(len(x))
                x[i] = rng.randrange(256)
        for lenient in (False, True):
            dexllm.verify_bytes(bytes(x), lenient=lenient, mode="runtime")
            try:
                dk = dexllm.DexKit.from_bytes(bytes(x), lenient=lenient)
                dk.list_classes()
                dk.load_status()
            except (RuntimeError, ValueError):
                pass
        n += 1
print(n)
""" % (str(DATA), str(MULTIDEX))
    r = subprocess.run(
        [sys.executable, "-c", script], capture_output=True, text=True, timeout=600
    )
    assert r.returncode == 0, (r.returncode, r.stderr[-2000:])
    assert int(r.stdout.strip()) >= 25 * 10


# ── the typed layer ───────────────────────────────────────────────────────────


def test_the_sdk_carries_the_same_facts(tmp_path):
    apk = _apk(tmp_path, "mid.apk", D0, _bad_magic(D0), D1)
    s = sdk.open_apk(apk, mode="runtime")
    st = s.load_status()
    assert isinstance(st, sdk.LoadStatus) and st.mode == "runtime"
    assert not st.complete and st.matches_art and st.loaded_dex_count == 1
    assert [r.name for r in st.rejected] == ["classes2.dex", "classes3.dex"]
    assert [r.art_open for r in s.verify_report()] == [True, False, False]
    assert sdk.verify(apk, mode="runtime") == s.verify_report()
    b = sdk.open_bytes(pathlib.Path(apk).read_bytes(), source="x", mode="runtime")
    assert b.source_info()[0].in_memory is True
    assert (
        sdk.verify_bytes(pathlib.Path(apk).read_bytes(), mode="runtime", source=apk)
        == s.verify_report()
    )
    imgs = sdk.open_dex_images([("a.dex", D0), ("b.dex", D1)])
    assert imgs.load_status().loaded_dex_count == 2


def test_add_dumped_dexes_keeps_the_session_mode(tmp_path):
    apk = _apk(tmp_path, "mid.apk", D0, _bad_magic(D0), D1)
    dump = tmp_path / "dump.dex"
    dump.write_bytes(D1)
    dk = dexllm.DexKit(apk, mode="runtime")
    assert dexllm.add_dumped_dexes(dk, str(dump)).load_status()["mode"] == "runtime"


def test_a_runtime_rejected_container_slice_takes_its_siblings_with_it(tmp_path):
    """The v41 sibling rule runs AFTER the sequence rule. A container dex cannot
    be copied out on its own (its offsets address the container), so when
    runtime mode refuses the SECOND slice -- here for a checksum ART would
    reject -- the first one, which ART would open, cannot load either. Running
    the sibling rule first would hand the core a copied-out container dex."""
    b = bytearray(CONTAINER.read_bytes())
    first = struct.unpack_from("<I", b, 32)[0]
    assert b[first : first + 4] == b"dex\n" and b[first + 4 : first + 7] == b"041"
    b[first + 8] ^= 1  # slice 1's stored checksum
    p = tmp_path / "container.dex"
    p.write_bytes(bytes(b))
    iso = dexllm.DexKit(str(p))
    assert iso.dex_count() == 2
    assert [r["art_open"] for r in iso.verify_report()] == [True, False]
    rows = dexllm.verify(str(p), mode="runtime")
    assert [(r["valid"], r["art_open"]) for r in rows] == [
        (False, True),
        (False, False),
    ]
    assert "v41 container" in rows[0]["reason"]
    with pytest.raises(RuntimeError):
        dexllm.DexKit(str(p), mode="runtime")


def test_an_entry_that_does_not_decompress_ends_the_sequence():
    """ART fails such an entry too (kExtractToMemoryError), so it ends the source
    exactly like a dex that does not verify. Built in memory: the middle entry's
    deflate stream is overwritten, so inflating it fails."""
    import io

    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", compression=zipfile.ZIP_DEFLATED) as o:
        o.writestr("classes.dex", D0)
        o.writestr("classes2.dex", D0)
        o.writestr("classes3.dex", D1)
    b = bytearray(buf.getvalue())
    second = b.find(b"PK\x03\x04", b.find(b"PK\x03\x04") + 4)
    name_len = int.from_bytes(b[second + 26 : second + 28], "little")
    extra_len = int.from_bytes(b[second + 28 : second + 30], "little")
    data = second + 30 + name_len + extra_len
    b[data : data + 40] = b"\xff" * 40
    iso = dexllm.verify_bytes(bytes(b))
    assert [(r["name"], r["valid"], r["art_open"]) for r in iso] == [
        ("classes.dex", True, True),
        ("classes2.dex", False, False),
        ("classes3.dex", True, False),
    ]
    assert iso[1]["reason"] == "decompression failed"
    run = dexllm.DexKit.from_bytes(bytes(b), mode="runtime")
    assert run.list_classes() == [FOO]
    assert "(classes2.dex: decompression failed)" in run.verify_report()[2]["reason"]


def test_an_empty_image_ends_the_sequence():
    imgs = [("a.dex", D0), ("b.dex", b""), ("c.dex", D1)]
    iso = dexllm.DexKit.from_dex_images(imgs)
    assert [(r["valid"], r["art_open"]) for r in iso.verify_report()] == [
        (True, True),
        (False, False),
        (True, False),
    ]
    assert iso.verify_report()[1]["reason"] == "empty image"
    run = dexllm.DexKit.from_dex_images(imgs, mode="runtime")
    assert run.list_classes() == [FOO]
    assert "(b.dex: empty image)" in run.verify_report()[2]["reason"]


# ── adversarial-review findings (each a repro that passed the first cut) ────


def test_a_container_ends_the_image_at_its_last_entry(tmp_path):
    """ART reads past a v41 dex only while it is NOT its container's last entry
    (IsDexContainerLastEntry). Two containers back to back: ART opens the first
    container's two dexes and stops; the first cut called all four art_open and
    loaded four in runtime mode."""
    c = CONTAINER.read_bytes()
    p = tmp_path / "cc.dex"
    p.write_bytes(c + c)
    rows = dexllm.verify(str(p))
    assert [r["art_open"] for r in rows] == [True, True, False, False]
    run = dexllm.DexKit(str(p), mode="runtime")
    # salvaged per CONTAINER: the first container is copied out whole
    assert run.dex_count() == 2 and run.load_status()["matches_art"] is True
    assert [
        (run.extract_dex(i)["offset"], run.extract_dex(i)["size"]) for i in range(2)
    ] == [
        (0, 564),
        (564, len(c) - 564),
    ]
    assert dexllm.DexKit(str(p)).dex_count() == 4  # isolated: unchanged


def test_a_dex_after_a_container_is_not_part_of_the_open(tmp_path):
    """The trailing dex is never read by ART, so its bad checksum must not end
    the source -- classes2.dex still opens. The first cut broke the sequence on
    it and runtime mode raised; it also rejected the two container dexes that
    art_open itself called True."""
    apk = _apk(tmp_path, "trail.apk", CONTAINER.read_bytes() + _bad_checksum(D0), D1)
    rows = dexllm.verify(apk)
    assert [(r["name"], r["art_open"]) for r in rows] == [
        ("classes.dex", True),
        ("classes.dex", True),
        ("classes.dex", False),
        ("classes2.dex", True),
    ]
    run = dexllm.DexKit(apk, mode="runtime")
    assert run.dex_count() == 3 and run.load_status()["matches_art"] is True
    assert BLA in run.list_classes()


def test_a_container_entry_that_does_not_fit_ends_the_sequence(tmp_path):
    """A non-last v41 entry promises another one; when the image cannot hold it,
    ART's open fails there. The first cut gave it no row and called the session
    complete."""
    b = bytearray(CONTAINER.read_bytes())
    first = struct.unpack_from("<I", b, 32)[0]
    struct.pack_into("<I", b, first + 32, 0xFFFFFF00)  # slice 1's file_size
    apk = _apk(tmp_path, "trunc.apk", bytes(b), D1)
    rows = dexllm.verify(apk)
    assert [(r["valid"], r["art_open"]) for r in rows] == [
        (True, True),
        (False, False),
        (True, False),
    ]
    assert "does not fit the image" in rows[1]["reason"]
    dk = dexllm.DexKit(apk)
    assert (
        dk.load_status()["complete"] is False
        and dk.load_status()["matches_art"] is False
    )
    assert dexllm.DexKit(apk, mode="runtime").list_classes() == dk.list_classes()[:1]


def test_a_zip_with_a_duplicate_entry_is_one_ART_refuses(tmp_path):
    """libziparchive refuses an archive with two entries of one name
    (kDuplicateEntry). dexllm's reader still loads the last copy in isolated
    mode, and now says ART would not."""
    p = tmp_path / "dup.apk"
    with pytest.warns(UserWarning):
        with zipfile.ZipFile(p, "w") as z:
            z.writestr("classes.dex", D0)
            z.writestr("classes.dex", D1)
    iso = dexllm.DexKit(str(p))
    assert [r["art_open"] for r in iso.verify_report()] == [False]
    assert iso.load_status()["matches_art"] is False
    with pytest.raises(RuntimeError, match="duplicate zip entry 'classes.dex'"):
        dexllm.DexKit(str(p), mode="runtime")


def test_add_dumped_dexes_still_refuses_a_dump_that_loads_nothing(tmp_path):
    """A list source that yields nothing is a row since #119 -- but for
    add_dumped_dexes that would mean analysing without the dump, unaware."""
    dk = dexllm.DexKit(str(MULTIDEX))
    with pytest.raises(RuntimeError, match="yielded no dex: cannot open"):
        dexllm.add_dumped_dexes(dk, str(tmp_path / "typo.dex"))
    bad = tmp_path / "bad.dex"
    bad.write_bytes(
        _insns_only(D0)
    )  # strict rejects it; the default lenient=True loads it
    assert dexllm.add_dumped_dexes(dk, str(bad)).dex_count() == 3
    with pytest.raises(RuntimeError, match="yielded no dex: code: "):
        dexllm.add_dumped_dexes(dk, str(bad), lenient=False)


def test_the_mcp_verify_report_carries_the_load_status(tmp_path):
    from dexllm import tools

    apk = _apk(tmp_path, "dup.apk", _bad_magic(D1), D1)
    out = tools.execute("verify_report", {}, dexllm.DexKit(apk))
    assert out["load_status"]["matches_art"] is False
    assert [r["art_open"] for r in out["dexes"]] == [False, False]


def test_runtime_does_not_call_a_verified_dex_a_verification_failure():
    """Correctness review C3: a bare dex whose only fault is its checksum is
    refused in runtime mode, and the message must not say it failed dexllm's
    verifier."""
    with pytest.raises(RuntimeError) as e:
        dexllm.DexKit.from_bytes(_bad_checksum(D0), mode="runtime")
    assert "failed dex verification" not in str(e.value)
    assert "passed dexllm's verifier" in str(e.value)


def test_a_zero_length_entry_reads_like_an_empty_image():
    """Correctness review C4: one input, one reason, whichever path it takes."""
    import io

    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as o:
        o.writestr("classes.dex", D0)
        o.writestr("classes2.dex", b"")
    zipped = dexllm.verify_bytes(buf.getvalue())[1]
    image = dexllm.DexKit.from_dex_images(
        [("a.dex", D0), ("b.dex", b"")]
    ).verify_report()[1]
    assert zipped["reason"] == image["reason"] == "empty image"


def test_a_container_whose_range_holds_another_dex_is_not_salvaged(tmp_path):
    """A container is copied out only when its range holds exactly its own
    entries. Here both entries claim a container_size that also covers the v35
    dex after them, and a rejected dex at the end forces the salvage path:
    copying the "container" would hand the core that v35 dex twice (the load
    then refuses itself as unverified). The container is rejected instead and
    the v35 dex loads on its own."""
    b = bytearray(CONTAINER.read_bytes())
    total = len(b) + len(D0)
    first = struct.unpack_from("<I", b, 32)[0]
    for off in (0, first):
        struct.pack_into("<I", b, off + 0x70, total)  # container_size
    p = tmp_path / "overlap.dex"
    p.write_bytes(bytes(b) + D0 + _bad_magic(D1))
    rows = dexllm.verify(str(p))
    assert [r["valid"] for r in rows] == [False, False, True, False]
    assert "v41 container" in rows[0]["reason"]
    dk = dexllm.DexKit(str(p))
    assert dk.list_classes() == [FOO] and dk.extract_dex(0)["offset"] == total - len(D0)
