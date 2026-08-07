"""dexllm#25/#27 — the structural gate runs per LOGICAL dex, not per file.

`DexKit::AddImage` runs `ParseLogicalDexOffsets`, so ONE image becomes as many
dexes as it carries embedded headers. `CollectSource` verified the image once, at
offset 0, and handed the whole thing over — so every later logical dex was parsed
by the core without `VerifyDex` ever having seen it. That contradicts the safety
contract `native/core_ext/dex_verifier.h` states ("the single gate … before the
core parses any dex"), which the 0-crash sweep and the ASan results rest on, and
it is reachable from the first-class packer workflow: a concatenated multi-dex
dump is exactly what unpackers produce.

The same walk gives `verify_report()` a row per logical dex carrying its REAL
dex_id (#27): it used to be `out.size()`, the load-order IMAGE index, which drifts
by the split count as soon as one source is concatenated.
"""

import struct
import subprocess
import sys
import zipfile
from pathlib import Path

import pytest

import dexllm

REPO_ROOT = Path(__file__).resolve().parents[1]


def _corrupt(dex: bytes) -> bytes:
    """A dex the verifier rejects, of the SAME length as the original.

    `type_ids_off` far past the file — a header-level rejection, so it does not
    depend on any deeper check staying where it is. Length-preserving so the
    caller can reason about the concatenated layout.
    """
    b = bytearray(dex)
    struct.pack_into("<I", b, 64, 0xFFFFFFF0)
    return bytes(b)


@pytest.fixture(scope="module")
def one_dex(loadable_apks):
    """One well-formed classes.dex lifted out of the corpus."""
    for p in loadable_apks:
        if not zipfile.is_zipfile(p):
            continue
        with zipfile.ZipFile(p) as z:
            names = [n for n in z.namelist() if n.endswith(".dex")]
            if names:
                return z.read(names[0])
    pytest.skip("no zip apk with a dex in the corpus")


def test_the_fixture_is_rejected_on_its_own(one_dex, tmp_path):
    """Non-discriminating by design: it only establishes that the corrupted dex
    IS rejected standalone, so the 'rejected when concatenated' assertions below
    are about WHERE the gate runs and not about the payload."""
    p = tmp_path / "alone.dex"
    p.write_bytes(_corrupt(one_dex))
    verdicts = dexllm.verify(str(p))
    assert [r["valid"] for r in verdicts] == [False]
    assert verdicts[0]["reason"]


def test_a_concatenated_tail_is_verified_not_waved_through(one_dex, tmp_path):
    """THE dexllm#25 bug. A dex the verifier rejects standalone was ACCEPTED when
    concatenated behind a valid one, and the core parsed it anyway."""
    cat = tmp_path / "concat.dex"
    cat.write_bytes(one_dex + _corrupt(one_dex))

    rows = dexllm.verify(str(cat))
    assert len(rows) == 2, "one verdict per LOGICAL dex"
    assert rows[0]["valid"] and not rows[1]["valid"]
    assert rows[1]["dex_id"] == -1  # rejected dexes never occupy an id

    dk = dexllm.DexKit(str(cat))
    assert dk.dex_count() == 1, "the unverified tail must not reach the core"
    assert dk.verify_report() == rows, "load path and load-free path agree"


def test_verify_rows_carry_the_real_dex_id(one_dex, tmp_path):
    """dexllm#27 — the id in a verdict row is the dex_id the session hands out.

    Before the fix it was the load-order image index, so a concatenated source
    (one image, several dex_ids) made every later row name the wrong dex.
    """
    cat = tmp_path / "cat.dex"
    cat.write_bytes(one_dex + one_dex)
    other = tmp_path / "other.dex"
    other.write_bytes(one_dex)

    dk = dexllm.DexKit([str(cat), str(other)])
    rows = dk.verify_report()
    assert [r["dex_id"] for r in rows] == list(range(dk.dex_count()))
    # ...and each id's row names the source that dex really came from.
    by_id = {r["dex_id"]: r["source"] for r in rows}
    for d in dk.extract_dexes():
        assert by_id[d["dex_id"]] == d["source"]
    assert by_id[2] == str(other), "the third dex_id is the second source"


def test_survivors_of_a_partially_bad_container_still_load(one_dex, tmp_path):
    """Per-logical-dex rejection, not per-file: a packer dump whose middle dex is
    garbage must still yield the ones that verify — and each must be the right
    bytes, with the offset it had in the original container."""
    bad = _corrupt(one_dex)
    src = tmp_path / "salvage.dex"
    src.write_bytes(one_dex + bad + one_dex)

    dk = dexllm.DexKit(str(src))
    assert [r["valid"] for r in dk.verify_report()] == [True, False, True]
    assert dk.dex_count() == 2

    d0, d1 = dk.extract_dexes()
    assert d0["bytes"] == one_dex and d1["bytes"] == one_dex
    assert (d0["offset"], d1["offset"]) == (0, 2 * len(one_dex))
    assert d0["source"] == d1["source"] == str(src)
    assert dk.list_classes_in_dex(0) and dk.list_classes_in_dex(1)


def test_a_zip_entry_that_is_itself_concatenated_is_gated(loadable_apks, tmp_path):
    """The zip branch splits too — `GetUncompressData` yields the whole entry, and
    the core walks its embedded headers exactly the same way."""
    apk = next((p for p in loadable_apks if zipfile.is_zipfile(p)), None)
    if apk is None:
        pytest.skip("no zip apk in the corpus")
    out = tmp_path / "concat_in_zip.apk"
    with zipfile.ZipFile(apk) as z, zipfile.ZipFile(out, "w") as w:
        for it in z.infolist():
            data = z.read(it.filename)
            if it.filename == "classes.dex":
                data = data + _corrupt(data)
            w.writestr(it, data)

    rows = dexllm.verify(str(out))
    tail = [r for r in rows if r["name"] == "classes.dex"]
    assert len(tail) == 2 and tail[0]["valid"] and not tail[1]["valid"]
    dk = dexllm.DexKit(str(out))
    assert dk.verify_report() == rows


def test_an_unverified_logical_dex_cannot_crash_the_search_family(one_dex, tmp_path):
    """The concrete harm, end to end: a concatenated dex whose tail has an intact
    header but a garbage body used to reach the core, fail to build a `DexItem`,
    and SIGSEGV in the search loops that dereference the resulting null.

    Here the tail is stopped by the gate (`dex_count() == 1` is what proves it) —
    the null-`DexItem` path itself is covered directly by
    `test_a_dex_the_verifier_accepts_but_the_parser_rejects_is_refused`.

    Run out-of-process: a regression here kills the interpreter, so an in-process
    assertion would take the whole suite down instead of reporting.
    """
    tail = bytearray(one_dex)
    for i in range(112, len(tail)):
        tail[i] = 0xAA  # header intact (file_size correct), body destroyed
    src = tmp_path / "garbage_tail.dex"
    src.write_bytes(one_dex + bytes(tail))

    prog = (
        "import dexllm,sys\n"
        f"dk = dexllm.DexKit({str(src)!r})\n"
        "assert dk.dex_count() == 1, dk.dex_count()\n"
        "dk.find_classes_by_name('a')\n"
        "dk.list_classes()\n"
        "print('OK')\n"
    )
    r = subprocess.run([sys.executable, "-c", prog], capture_output=True, text=True)
    assert r.returncode == 0, f"rc={r.returncode} (SIGSEGV is -11)\n{r.stderr[-2000:]}"
    assert "OK" in r.stdout


def test_the_gate_and_the_core_agree_on_the_split_over_the_whole_corpus(loadable_apks):
    """The gate mirrors `ParseLogicalDexOffsets`; a drift between the two would
    silently reopen the bug. `AssertLoadedDexesWereVerified` refuses the load when
    they disagree, so this asserts the mirror holds on every corpus container —
    and that every accepted row corresponds to a dex that really loaded.

    Non-discriminating by design (it must hold on both sides of the fix); it is
    the invariant stated as a property rather than as a fixture.
    """
    for p in loadable_apks:
        dk = dexllm.DexKit(p)
        accepted = [r for r in dk.verify_report() if r["valid"]]
        assert [r["dex_id"] for r in accepted] == list(range(dk.dex_count())), p


@pytest.fixture(scope="module")
def small_dex():
    """The smallest bare `.dex` in the corpus — the payload for the tests that
    need MANY logical dexes in one image."""
    import glob
    import os

    cands = sorted(glob.glob(str(REPO_ROOT / "test_apk" / "APK" / "*.dex")), key=os.path.getsize)
    if not cands:
        pytest.skip("no bare .dex in the corpus")
    data = Path(cands[0]).read_bytes()
    if not dexllm.verify(cands[0])[0]["valid"]:
        pytest.skip(f"{cands[0]} does not verify")
    return data


def _parser_poison(dex: bytes) -> bytes:
    """A dex `VerifyDex` ACCEPTS but the slicer's own reader rejects.

    `link_size`/`link_off` are outside every check ART's structural verifier makes
    beyond "the span is in the file", so the dex passes the gate — and the
    `DexItem` constructor then throws inside `AddImage`'s ThreadPool lambda, where
    the exception is SWALLOWED and a null `unique_ptr` is left in `dex_items`.
    That null is what the core's search loops dereference.
    """
    b = bytearray(dex)
    struct.pack_into("<II", b, 44, 4, 0x70)  # link_size = 4, link_off = 0x70
    return bytes(b)


def test_a_dex_the_verifier_accepts_but_the_parser_rejects_is_refused(small_dex, tmp_path):
    """`AssertLoadedDexesWereVerified`, on its own. The gate cannot promise that
    everything it accepts also PARSES — so the load is re-checked afterwards, and a
    null `DexItem` becomes a Python exception instead of a later SIGSEGV."""
    p = tmp_path / "poison.dex"
    p.write_bytes(_parser_poison(small_dex))

    rows = dexllm.verify(str(p))
    assert rows[0]["valid"], (
        "premise broken: the payload must PASS the verifier for this test to be "
        "about the post-load check; pick another parser-only defect"
    )
    with pytest.raises(RuntimeError, match="could not be parsed"):
        dexllm.DexKit(str(p))


def test_more_logical_dexes_than_the_core_can_address_are_refused(small_dex, tmp_path):
    """The core addresses a dex by `uint16_t`, so a dex_id above 65535 wraps on
    every later lookup — which silently inspects a DIFFERENT dex and made the null
    scan above hand back a false all-clear (adversarial review, CONFIRMED with
    65536 valid dexes plus one the parser rejects). The gate refuses the excess.
    """
    n = 65537
    if len(small_dex) * n > 128 * 1024 * 1024:
        pytest.skip("smallest corpus dex too large to build a 65537-dex image")
    img = tmp_path / "many.dex"
    img.write_bytes(small_dex * (n - 1) + _parser_poison(small_dex))

    dk = dexllm.DexKit(str(img))
    assert dk.dex_count() == 65536
    rows = dk.verify_report()
    assert len(rows) == n
    refused = [r for r in rows if not r["valid"]]
    assert len(refused) == 1 and "at most 65536" in refused[0]["reason"]
    # the one that did not fit is the parser-poisoned tail, so nothing that could
    # have produced a null DexItem was loaded
    dk.find_classes_by_name("a")


def test_the_addressable_limit_is_a_session_total_not_a_per_image_one(small_dex, tmp_path):
    """The counter runs across SOURCES, not within one image: `DexKit([...])` keeps
    handing out ids, so many small sources can exceed the range in aggregate. A
    per-image cap would leave that axis open."""
    if len(small_dex) * 65535 > 128 * 1024 * 1024:
        pytest.skip("smallest corpus dex too large to build a 65535-dex image")
    big = tmp_path / "big.dex"
    big.write_bytes(small_dex * 65535)  # one short of the range
    tail = tmp_path / "tail.dex"
    tail.write_bytes(small_dex * 2)  # a SECOND source that straddles the boundary

    dk = dexllm.DexKit([str(big), str(tail)])
    assert dk.dex_count() == 65536
    rows = dk.verify_report()
    assert len(rows) == 65537
    refused = [r for r in rows if not r["valid"]]
    # the boundary is crossed INSIDE the second source: its first dex fits, its
    # second does not. Only a session-wide counter can produce that split.
    assert [r["source"] for r in refused] == [str(tail)]
    assert "at most 65536" in refused[0]["reason"]
    assert [r["dex_id"] for r in rows if r["source"] == str(tail)] == [65535, -1]


V41_SAMPLE = Path.home() / "Project/aosp/art/test/dexdump/multidex-container.dex"


@pytest.mark.skipif(
    not V41_SAMPLE.is_file(), reason="needs an AOSP checkout for a v41 container sample"
)
def test_v41_container_verifies_every_dex_against_the_container():
    """A v41 container's dexes SHARE one data section, so their offsets are
    relative to the container, not to the dex. Verifying such a dex against its
    own `file_size` slice would reject a well-formed file, and verifying the
    second one from its own header would resolve every offset in the wrong place
    — so `VerifyDex` derives the span the way ART's `DexFile::GetDataRange` does.

    Before this change the container's second dex was never verified at all.
    """
    rows = dexllm.verify(str(V41_SAMPLE))
    assert [(r["dex_id"], r["valid"]) for r in rows] == [(0, True), (1, True)]

    dk = dexllm.DexKit(str(V41_SAMPLE))
    assert dk.dex_count() == 2
    assert sorted(dk.list_classes()) == ["LMain;", "LSecond;"]
    # each dex_id resolves to its own header offset inside the shared container
    assert [d["offset"] for d in dk.extract_dexes()] == [0, 564]
