"""Pytest fixtures for the dexllm Python suite.

APK-dependent tests use the `dk` fixture, which resolves a test APK from
(in order) $DEXLLM_TEST_APK, then any file under test_apk/APK/. If none is
found, those tests are skipped (the C++ parity suites under tests/parity are
the self-contained, APK-free regression gate).
"""

import glob
import os
import re
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]

# `0xNN:` instruction-offset prefix in render_method_smali output.
_SMALI_OFF = re.compile(r"^\s*0x([0-9a-fA-F]+):")


@pytest.fixture(autouse=True)
def _no_ambient_data_override(monkeypatch):
    """Neutralise ``$DEXLLM_DATA_DIR`` for every test unless one opts in.

    The data-override channel (issue #33) is process-wide and resolved per call,
    so a developer who exports it for their own triage would otherwise make the
    catalog and provider-dataset tests read THEIR files — and those tests assert
    on bundled values, so the suite goes red with hard AssertionErrors that read
    as real regressions. An environment fact must produce a skip or no effect,
    never a failure; the corpus fixtures below follow the same rule.

    A test that wants an override sets it itself (``monkeypatch.setenv``), which
    still works — this only removes what was inherited from the shell.
    """
    monkeypatch.delenv("DEXLLM_DATA_DIR", raising=False)
    from dexllm import datadir

    datadir.clear_data_caches()


def _candidate_apks():
    """Candidate APK paths, best-effort. $DEXLLM_TEST_APK wins; otherwise scan
    test_apk/APK/ (skipping empty placeholders)."""
    env = os.environ.get("DEXLLM_TEST_APK")
    if env and os.path.isfile(env):
        return [env]
    return [
        h
        for h in sorted(glob.glob(str(REPO_ROOT / "test_apk" / "APK" / "*.apk")))
        if os.path.getsize(h) > 1024
    ]


def smali_offsets(dk, desc):
    """Set of valid byte offsets for a method, parsed from its smali (the
    `0xNN:` prefixes). Shared by the D-3 pc-map tests."""
    offs = set()
    for line in dk.render_method_smali(desc).splitlines():
        m = _SMALI_OFF.match(line)
        if m:
            offs.add(int(m.group(1), 16))
    return offs


@pytest.fixture(scope="session")
def loadable_apks():
    """Every candidate APK that actually carries decompilable dex (0-dex /
    resources-only containers filtered via identify()). Skips if none."""
    import dexllm

    out = []
    for p in _candidate_apks():
        try:
            if dexllm.identify(p).get("dex_count", 0) > 0:
                out.append(p)
        except Exception:
            continue
    if not out:
        pytest.skip("no loadable dex container in the corpus")
    return out


@pytest.fixture(scope="session")
def _loaded():
    """First candidate APK that loads with decompilable classes → (path, DexKit)."""
    import dexllm

    candidates = _candidate_apks()
    if not candidates:
        pytest.skip("no test APK (set $DEXLLM_TEST_APK or add one under test_apk/APK/)")
    for p in candidates:
        try:
            inst = dexllm.DexKit(p)
        except Exception:
            continue
        if inst.list_classes():
            return p, inst
    pytest.skip(f"no candidate APK had decompilable classes ({len(candidates)} tried)")


@pytest.fixture(scope="session")
def apk_path(_loaded):
    return _loaded[0]


@pytest.fixture(scope="session")
def dk(_loaded):
    return _loaded[1]


@pytest.fixture(scope="session")
def sample_method(dk):
    """First internal method that decompiles to a non-empty body."""
    for cls in dk.list_classes():
        for m in dk.list_class_methods(cls):
            if dk.decompile_method(m):
                return m
    pytest.skip("no decompilable method in APK")
