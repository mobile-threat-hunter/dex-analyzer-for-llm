"""Multi-source loading with priority by order (packer / runtime-unpack workflow).

`DexKit([source1, source2, ...])` loads sources in order; earlier sources get
lower dex_ids, and class resolution is first-wins (lowest dex_id), so the FIRST
source wins a class collision. For a packer, list the decrypted/dumped dex BEFORE
the original apk to make the unpacked class win — mirroring ART, where the packer
orders the decrypted dex first. See [[project-packer-analysis-direction]].
"""

import glob
import zipfile
from pathlib import Path

import pytest

import dexllm

REPO = Path(__file__).resolve().parents[1]


def _extract_classes_dex(apk: str, dest: Path) -> Path:
    with zipfile.ZipFile(apk) as z:
        dest.write_bytes(z.read("classes.dex"))
    return dest


@pytest.fixture(scope="module")
def two_dexes(tmp_path_factory):
    """classes.dex from two distinct bundled APKs (so they share some classes)."""
    apks = sorted(glob.glob(str(REPO / "test_apk" / "APK" / "*.apk")))
    usable = []
    for apk in apks:
        try:
            with zipfile.ZipFile(apk) as z:
                if "classes.dex" in z.namelist():
                    usable.append(apk)
        except Exception:
            continue
    if len(usable) < 2:
        pytest.skip("need two bundled APKs with classes.dex")
    d = tmp_path_factory.mktemp("msrc")
    a = _extract_classes_dex(usable[0], d / "a.dex")
    b = _extract_classes_dex(usable[1], d / "b.dex")
    return str(a), str(b)


def test_multisource_loads_all(two_dexes):
    a, b = two_dexes
    dk = dexllm.DexKit([a, b])
    assert dk.dex_count() == 2
    assert dk.apk_path() == a  # first source reported


def test_each_source_is_indexed(two_dexes):
    # a class unique to source A resolves to dex 0; one unique to B to dex 1 —
    # proving BOTH sources are loaded and cross-indexed (cache consistency).
    a, b = two_dexes
    ca = set(dexllm.DexKit(a).list_classes())
    cb = set(dexllm.DexKit(b).list_classes())
    only_a = sorted(ca - cb)
    only_b = sorted(cb - ca)
    if not (only_a and only_b):
        pytest.skip("sources fully overlap")
    dk = dexllm.DexKit([a, b])
    assert dk.locate_class_dex(only_a[0]) == 0
    assert dk.locate_class_dex(only_b[0]) == 1


def test_first_source_wins_collision(two_dexes):
    # a class present in BOTH with differing bodies must decompile to the FIRST
    # source's version; reversing the order flips the winner (first-wins).
    a, b = two_dexes
    dka, dkb = dexllm.DexKit(a), dexllm.DexKit(b)
    shared = sorted(set(dka.list_classes()) & set(dkb.list_classes()))
    target = ja = jb = None
    for c in shared:
        try:
            x, y = dka.decompile_class(c), dkb.decompile_class(c)
        except Exception:
            continue
        if x and y and x != y:
            target, ja, jb = c, x, y
            break
    if target is None:
        pytest.skip("no shared class with differing bodies")

    assert dexllm.DexKit([a, b]).decompile_class(target) == ja  # a wins
    assert dexllm.DexKit([b, a]).decompile_class(target) == jb  # b wins


def test_empty_sources_rejected():
    with pytest.raises(Exception):
        dexllm.DexKit([])


def test_a_bad_source_in_a_list_is_a_row_not_an_error(two_dexes):
    """dexllm#119: one unopenable source no longer costs the others. It is a
    valid=False row, the session says it is incomplete, and only a list in
    which NO source yields a dex raises (inverted from the pre-#119 guard)."""
    a, _ = two_dexes
    missing = "/nonexistent/dexllm/missing.dex"
    dk = dexllm.DexKit([a, missing])
    assert dk.dex_count() == dexllm.DexKit(a).dex_count()
    [row] = [r for r in dk.verify_report() if r["source"] == missing]
    assert not row["valid"] and row["dex_id"] == -1 and "cannot open" in row["reason"]
    assert dk.load_status()["complete"] is False
    with pytest.raises(RuntimeError, match="none of the 2 sources"):
        dexllm.DexKit([missing, missing + "2"])
