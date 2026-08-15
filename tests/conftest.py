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


def corpus_is_narrowed():
    """True when ``$DEXLLM_TEST_APK`` actually resolved to a file.

    The suite is then looking at ONE sample the developer chose, not the bundled
    corpus. A dangling override does not narrow anything (``_candidate_apks``
    ignores it), so it must not soften a floor either.
    """
    env = os.environ.get("DEXLLM_TEST_APK")
    return bool(env and os.path.isfile(env))


def require_corpus_shape(present, shape, regression):
    """Non-vacuity floor for a guard that would otherwise pass without firing.

    Several guards scan the corpus for evidence that a production pass RAN — a
    `switch` header carrying a pc_map entry, a `boolean v = false;`, a
    constant-only indicator. A count of zero on the bundled corpus means the
    pass stopped firing and must FAIL; the same zero under a $DEXLLM_TEST_APK
    narrowing only means the chosen sample has no such code, and an environment
    fact must produce a skip, never a failure (this module's own rule, and
    issue #46).

    `shape` names what the corpus must carry; `regression` says what a bundled
    failure would mean.
    """
    if present:
        return
    if corpus_is_narrowed():
        pytest.skip(f"the narrowed corpus carries no {shape}")
    pytest.fail(f"no {shape} in the bundled corpus — {regression}")


def smali_offsets(dk, desc):
    """Set of valid byte offsets for a method, parsed from its smali (the
    `0xNN:` prefixes). Shared by the D-3 pc-map tests."""
    offs = set()
    for line in dk.render_method_smali(desc).splitlines():
        m = _SMALI_OFF.match(line)
        if m:
            offs.add(int(m.group(1), 16))
    return offs


def raw_param_names(fn):
    """Parameter names of a pybind11 method, or None when none can be read.

    `inspect.signature` refuses a pybind11 `instancemethod`, but pybind writes the
    `py::arg()` names into the first docstring line — and those names ARE what a
    keyword call resolves against, so this is the runtime truth rather than the
    `.pyi` shadow. Shared by the dexllm#44 argument-name audits, which treat a
    None (an overload set, a stripped docstring) as a hard failure: a parser that
    quietly returns nothing would make the whole audit vacuous.
    """
    doc = (fn.__doc__ or "").splitlines()
    if not doc or "Overloaded function" in (fn.__doc__ or ""):
        return None
    line, start = doc[0], doc[0].find("(")
    if start < 0 or "->" not in line:
        return None
    depth, end = 0, -1
    for i in range(start, len(line)):
        depth += line[i] in "([{"
        depth -= line[i] in ")]}"
        if depth == 0:
            end = i
            break
    if end < 0:
        return None
    names, depth, cur = [], 0, ""
    for c in line[start + 1 : end] + ",":
        depth += c in "([{"
        depth -= c in ")]}"
        if c == "," and depth == 0:
            token = cur.split(":")[0].split("=")[0].strip()
            if token and token not in ("self", "*", "/"):
                names.append(token)
            cur = ""
        else:
            cur += c
    return names


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
    """First internal method with a CODE ITEM that decompiles to a non-empty body.

    Truthy decompiler output is not enough: an abstract method decompiles to
    ``public abstract String suggest();`` — a signature, no body — so an APK
    whose first class is an annotation interface (hello-world.apk) handed every
    consumer a bodyless method and four tests failed on an environment fact
    (issue #46). ``.registers`` is smali's marker for a present ``code_item``,
    which is INDEPENDENT of the ``{``-in-source / non-null-AST properties the
    consumers assert — so this selection does not make them tautological.
    """
    for cls in dk.list_classes():
        for m in dk.list_class_methods(cls):
            if ".registers" not in dk.render_method_smali(m):
                continue
            if dk.decompile_method(m):
                return m
    pytest.skip("no method with a code item decompiles in this APK")
