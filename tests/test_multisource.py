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
            x, y = dka.decompile_class_java(c), dkb.decompile_class_java(c)
        except Exception:
            continue
        if x and y and x != y:
            target, ja, jb = c, x, y
            break
    if target is None:
        pytest.skip("no shared class with differing bodies")

    assert dexllm.DexKit([a, b]).decompile_class_java(target) == ja  # a wins
    assert dexllm.DexKit([b, a]).decompile_class_java(target) == jb  # b wins


def test_empty_sources_rejected():
    with pytest.raises(Exception):
        dexllm.DexKit([])


def test_bad_source_in_list_rejected(two_dexes):
    a, _ = two_dexes
    with pytest.raises(Exception):
        dexllm.DexKit([a, "/nonexistent/dexllm/missing.dex"])
