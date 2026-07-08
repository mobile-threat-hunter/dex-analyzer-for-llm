"""dexllm.add_dumped_dexes — merge runtime-dumped dexes into a fresh analysis.

The unpack workflow's last step: given the loaded apk and a runtime-dumped (decrypted)
dex, return a new DexKit with the dump merged in and winning class collisions (the
unpacked body), partial-decrypt dumps accepted via lenient verification.
See [[project-packer-analysis-direction]].
"""

import glob
import zipfile
from pathlib import Path

import pytest

import dexllm

REPO = Path(__file__).resolve().parents[1]


def _classes_dex(apk, dest):
    with zipfile.ZipFile(apk) as z:
        dest.write_bytes(z.read("classes.dex"))
    return str(dest)


@pytest.fixture(scope="module")
def apk_and_dump(tmp_path_factory):
    """An apk + a 'dumped' classes.dex from a DIFFERENT apk (shares some classes)."""
    apks = [
        a
        for a in sorted(glob.glob(str(REPO / "test_apk" / "APK" / "*.apk")))
        if dexllm.identify(a)["dex_count"] > 0 and zipfile.is_zipfile(a)
    ]
    if len(apks) < 2:
        pytest.skip("need two APKs with classes.dex")
    d = tmp_path_factory.mktemp("packer")
    dump = _classes_dex(apks[1], d / "dump.dex")
    return apks[0], dump


def test_sources_accessor(apk_and_dump):
    apk, _ = apk_and_dump
    dk = dexllm.DexKit(apk)
    assert dk.sources() == [apk]


def test_add_dumped_dexes_prepends_and_rebuilds(apk_and_dump):
    apk, dump = apk_and_dump
    dk = dexllm.DexKit(apk)
    merged = dexllm.add_dumped_dexes(dk, dump)
    assert merged.sources()[0] == dump  # dump is first → first-wins
    assert merged.sources()[-1] == apk
    assert merged.dex_count() == dk.dex_count() + 1


def test_dump_wins_collision_with_prefer(apk_and_dump):
    apk, dump = apk_and_dump
    dk = dexllm.DexKit(apk)
    dk_dump = dexllm.DexKit(dump)
    shared = sorted(
        set(dexllm.DexKit(apk).list_classes()) & set(dk_dump.list_classes())
    )
    target = None
    for c in shared:
        try:
            a, b = dexllm.DexKit(apk).decompile_class_java(
                c
            ), dk_dump.decompile_class_java(c)
        except Exception:
            continue
        if a and b and a != b:
            target = c
            break
    if target is None:
        pytest.skip("no shared class with differing bodies")
    # prefer=True (default): dump wins; prefer=False: original apk wins
    assert dexllm.add_dumped_dexes(dk, dump).decompile_class_java(
        target
    ) == dk_dump.decompile_class_java(target)
    assert dexllm.add_dumped_dexes(dk, dump, prefer=False).decompile_class_java(
        target
    ) == dexllm.DexKit(apk).decompile_class_java(target)


def test_accepts_str_or_list(apk_and_dump):
    apk, dump = apk_and_dump
    dk = dexllm.DexKit(apk)
    assert dexllm.add_dumped_dexes(dk, dump).dex_count() == dk.dex_count() + 1
    assert dexllm.add_dumped_dexes(dk, [dump]).dex_count() == dk.dex_count() + 1


def test_accepts_pathlike(apk_and_dump):
    apk, dump = apk_and_dump
    dk = dexllm.DexKit(apk)
    # a single Path, and an iterable of Paths, are both accepted (os.fspath)
    assert dexllm.add_dumped_dexes(dk, Path(dump)).dex_count() == dk.dex_count() + 1
    assert dexllm.add_dumped_dexes(dk, [Path(dump)]).dex_count() == dk.dex_count() + 1


def test_empty_dumps_rejected(apk_and_dump):
    apk, _ = apk_and_dump
    dk = dexllm.DexKit(apk)
    with pytest.raises(ValueError):
        dexllm.add_dumped_dexes(dk, [])
    with pytest.raises(ValueError):
        dexllm.add_dumped_dexes(dk, "")  # empty string must not reach the loader
