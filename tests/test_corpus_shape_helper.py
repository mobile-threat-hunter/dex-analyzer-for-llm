"""The non-vacuity floor helper itself (issue #46).

`conftest.require_corpus_shape` is load-bearing for a dozen guards that assert a
production pass ACTUALLY FIRED (a `switch` header with a pc_map entry, a
`boolean v = false;`, a constant-only IOC). If it ever degraded to an
unconditional skip, all of them would go silently soft while the suite stayed
green — the exact failure mode those floors exist to prevent. So the helper's
two-way behaviour is pinned here rather than left implicit in its callers.

APK-free: this only exercises the decision, not the corpus.
"""

import pytest
from conftest import corpus_is_narrowed, require_corpus_shape


def test_a_present_shape_is_a_no_op(monkeypatch):
    monkeypatch.delenv("DEXLLM_TEST_APK", raising=False)
    require_corpus_shape(True, "anything", "would be a regression")


def test_a_missing_shape_fails_on_the_bundled_corpus(monkeypatch):
    """No override → a zero count means the pass stopped firing. Hard failure."""
    monkeypatch.delenv("DEXLLM_TEST_APK", raising=False)
    with pytest.raises(pytest.fail.Exception) as e:
        require_corpus_shape(False, "`(Type) v` cast", "the cast pass is off")
    assert "the cast pass is off" in str(e.value)


def test_a_missing_shape_skips_under_a_narrowing(monkeypatch, tmp_path):
    """$DEXLLM_TEST_APK points the suite at ONE sample the developer chose; that
    sample legitimately has no `switch`, no boolean literal, no IOC constant."""
    sample = tmp_path / "sample.apk"
    sample.write_bytes(b"not really an apk")
    monkeypatch.setenv("DEXLLM_TEST_APK", str(sample))
    assert corpus_is_narrowed()
    with pytest.raises(pytest.skip.Exception):
        require_corpus_shape(False, "`switch` header", "the header hook is broken")


def test_a_dangling_override_does_not_soften_the_floor(monkeypatch, tmp_path):
    """A path that does not exist narrows nothing — `_candidate_apks` ignores it
    and the bundled corpus runs — so the floor must stay hard."""
    monkeypatch.setenv("DEXLLM_TEST_APK", str(tmp_path / "gone.apk"))
    assert not corpus_is_narrowed()
    with pytest.raises(pytest.fail.Exception):
        require_corpus_shape(False, "anything", "still a regression")
