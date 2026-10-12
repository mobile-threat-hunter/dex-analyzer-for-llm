"""The indicator scanners cross-reference every value in ONE batched pass (dexllm#98).

``extract_iocs`` and ``detect_content_providers`` used to run one
``find_methods_using_strings`` query per value — a full method scan each, so
the xref step was linear in the number of indicators, and the single-query path
never reaches the core's Aho-Corasick trie. They now share
``dexllm._xref.methods_loading_each``, which issues one
``batch_find_methods_using_strings`` call.

Every case runs on a COMMITTED fixture (``tests/data/invoke-custom.dex``, 103
value strings), so they hold in the corpus-less CI leg and under any
``$DEXLLM_TEST_APK`` narrowing.
"""

from __future__ import annotations

from pathlib import Path

import pytest

import dexllm
from dexllm._xref import methods_loading_each

FIXTURE = Path(__file__).parent / "data" / "invoke-custom.dex"


class _Recording:
    """Delegates to a real DexKit and counts the two xref calls."""

    def __init__(self, dk, *, strings=None, forbid_single=False, batch_raises=None):
        self._dk = dk
        self._strings = strings
        self._forbid_single = forbid_single
        self._batch_raises = batch_raises
        self.batch_calls: list[dict] = []
        self.single_calls = 0
        self.declaring_calls = 0

    def __getattr__(self, name):
        return getattr(self._dk, name)

    def list_value_strings(self):
        return (
            self._strings
            if self._strings is not None
            else self._dk.list_value_strings()
        )

    def batch_find_methods_using_strings(self, query_map, **kw):
        self.batch_calls.append(dict(query_map))
        if self._batch_raises is not None:
            raise self._batch_raises
        return self._dk.batch_find_methods_using_strings(query_map, **kw)

    def find_classes_declaring_strings(self, values, **kw):
        self.declaring_calls += 1
        return self._dk.find_classes_declaring_strings(values, **kw)

    def find_methods_using_strings(self, values, **kw):
        self.single_calls += 1
        assert not self._forbid_single, "the per-value loop ran"
        return self._dk.find_methods_using_strings(values, **kw)


@pytest.fixture(scope="module")
def dk():
    return dexllm.DexKit(str(FIXTURE))


@pytest.fixture(scope="module")
def values(dk):
    vs = [v for v in dk.list_value_strings() if v]
    # Short substrings overlap many literals AND each other, which is where a
    # trie and a per-value compare could disagree; repeats test per-occurrence.
    vals = vs[:60] + [v[:2] for v in vs[:20] if len(v) >= 2] + vs[:3]
    assert len(vals) > 60, "premise: the fixture carries value strings"
    return vals


def _one_by_one(dk, vals):
    return [
        [
            m.descriptor
            for m in dk.find_methods_using_strings(
                [v], match_type="contains", ignore_case=False
            )
        ]
        for v in vals
    ]


def test_one_batch_call_answers_every_value_exactly_as_the_loop_did(dk, values):
    """Same methods, same ORDER, per value — and one call, zero single queries."""
    rec = _Recording(dk, forbid_single=True)
    got = methods_loading_each(rec, values)
    assert len(rec.batch_calls) == 1
    assert len(rec.batch_calls[0]) == len(values)  # repeats get their own key
    assert got == _one_by_one(dk, values)
    assert sum(map(len, got)) > len(values), "premise: the values actually hit code"


def test_a_repeated_value_is_answered_per_occurrence(dk, values):
    got = methods_loading_each(dk, [values[0], values[1], values[0]])
    assert got[0] == got[2] and got[0], got


def test_a_lone_surrogate_value_still_takes_the_batch(dk):
    """Batch KEYS are not MUTF-8-encoded (dexllm#29); keying by position keeps a
    lone-surrogate value from making the batch raise and fall back."""
    rec = _Recording(dk, forbid_single=True)
    assert methods_loading_each(rec, ["\ud800", "bsm("]) == _one_by_one(
        dk, ["\ud800", "bsm("]
    )
    assert len(rec.batch_calls) == 1


def test_no_values_issues_no_query(dk):
    rec = _Recording(dk, forbid_single=True)
    assert methods_loading_each(rec, []) == []
    assert rec.batch_calls == []


def test_a_failing_batch_falls_back_to_the_per_value_loop(dk, values):
    rec = _Recording(dk, batch_raises=RuntimeError("batch broke"))
    assert methods_loading_each(rec, values[:10]) == _one_by_one(dk, values[:10])
    assert rec.single_calls == 10


def test_a_dead_xref_layer_still_propagates_through_the_fallback():
    """dexllm#55: batch AND single raising is the layer being unavailable, not one
    bad query — it must surface, not become every value with no methods."""

    class _Dead:
        def batch_find_methods_using_strings(self, *a, **k):
            raise RuntimeError("dex cache init failed: crafted")

        def find_methods_using_strings(self, *a, **k):
            raise RuntimeError("dex cache init failed: crafted")

    with pytest.raises(RuntimeError, match="cache init failed"):
        methods_loading_each(_Dead(), ["a", "b"])


def test_one_bad_query_after_a_good_one_is_still_contained():
    class _Flaky:
        def batch_find_methods_using_strings(self, *a, **k):
            raise RuntimeError("batch broke")

        def find_methods_using_strings(self, vals, **k):
            if vals == ["bad"]:
                raise RuntimeError("one bad query")
            return []

    assert methods_loading_each(_Flaky(), ["ok", "bad", "ok"]) == [[], [], []]


_INDICATORS = [
    "https://evil.example.com/gate.php",
    "http://203.0.113.7/x",
    "ops@evil.example.com",
]


def test_extract_iocs_issues_one_batch_and_no_single_query(dk):
    rec = _Recording(
        dk, strings=dk.list_value_strings() + _INDICATORS, forbid_single=True
    )
    out = dexllm.extract_iocs(rec, with_xref=True)
    assert len(rec.batch_calls) == 1
    queried = sorted(v for vs in rec.batch_calls[0].values() for v in vs)
    reported = sorted(r["value"] for rows in out.values() for r in rows)
    assert queried == reported and len(reported) >= 3


def test_extract_iocs_spends_the_xref_budget_highest_signal_first(dk):
    from dexllm.ioc import _XREF_PRIORITY

    rec = _Recording(
        dk, strings=dk.list_value_strings() + _INDICATORS, forbid_single=True
    )
    out = dexllm.extract_iocs(rec, with_xref=True, xref_limit=1)
    (only,) = [v for vs in rec.batch_calls[0].values() for v in vs]
    ordered = [r["value"] for cat in _XREF_PRIORITY for r in out[cat]]
    assert only == ordered[0], (only, ordered)
    assert only == "203.0.113.7"  # ips outrank urls; pinned so the order is a literal
    for cat in out:  # every value past the budget carries no location at all
        for r in out[cat]:
            if r["value"] != only:
                assert r["methods"] == [] and r["declared_in"] == [], r
    # The declaration xref is budgeted too: one lookup, for the one value. It is
    # counted rather than read off the rows because the fixture declares none of
    # these indicators, so an over-spent budget would still report [] there.
    assert rec.declaring_calls == 1
    assert dexllm.extract_iocs(rec, with_xref=False)  # still produced, no query
    assert len(rec.batch_calls) == 1 and rec.declaring_calls == 1


def test_detect_content_providers_issues_one_batch(dk):
    rec = _Recording(
        dk,
        strings=["content://sms/inbox", "content://call_log/calls"],
        forbid_single=True,
    )
    rows = dexllm.detect_content_providers(rec, with_xref=True)
    assert len(rows) >= 2 and len(rec.batch_calls) == 1
    assert sorted(v for vs in rec.batch_calls[0].values() for v in vs) == sorted(
        r["uri"] for r in rows
    )


def test_detect_content_providers_spends_its_xref_budget_in_uri_order(dk):
    rec = _Recording(
        dk,
        strings=["content://sms/inbox", "content://call_log/calls"],
        forbid_single=True,
    )
    rows = dexllm.detect_content_providers(rec, with_xref=True, xref_limit=1)
    assert [list(q.values()) for q in rec.batch_calls] == [[[rows[0]["uri"]]]]
    assert all(r["methods"] == [] for r in rows[1:]) and len(rows) >= 2
    assert dexllm.detect_content_providers(rec, with_xref=False)
    assert len(rec.batch_calls) == 1


# --- a class declared in more than one loaded dex (the packer workflow) -------


@pytest.fixture(scope="module")
def dk_twice():
    """The fixture loaded twice: every class is declared in two dexes, which is
    what ``add_dumped_dexes`` produces when the dump carries the original's classes."""
    return dexllm.DexKit([str(FIXTURE), str(FIXTURE)])


def test_a_class_declared_twice_is_reported_once_like_the_loop(dk_twice, values):
    raw = dk_twice.batch_find_methods_using_strings(
        {"k": [values[0]]}, match_type="contains", ignore_case=False
    )["k"]
    assert len({m.dex_id for m in raw}) == 2, "premise: the raw batch repeats per dex"
    got = methods_loading_each(dk_twice, values)
    assert got == _one_by_one(dk_twice, values)
    assert all(len(ms) == len(set(ms)) for ms in got)


def test_add_dumped_dexes_session_reports_each_method_once(dk, values):
    session = dexllm.add_dumped_dexes(dk, [str(FIXTURE)])
    assert methods_loading_each(session, values) == _one_by_one(session, values)


def test_an_empty_value_is_answered_without_the_batch(dk):
    rec = _Recording(dk)
    assert methods_loading_each(rec, ["", "bsm("]) == _one_by_one(dk, ["", "bsm("])
    assert rec.batch_calls == []


@pytest.mark.parametrize(
    "limit, want",
    [(0, 0), (-3, 0), (1, 1), (1.5, 2), (2.5, 3), (0.5, 1), (10**9, 7), (True, 1)],
)
def test_the_budget_is_the_countdown_both_scanners_always_ran(limit, want):
    """``while budget > 0: budget -= 1`` — a fractional limit rounds UP."""
    from dexllm._xref import budgeted

    assert budgeted(limit, 7) == want


def test_the_budget_handles_inf_nan_and_a_string_as_the_countdown_did():
    from dexllm._xref import budgeted

    assert budgeted(float("inf"), 7) == 7
    assert budgeted(float("nan"), 7) == 0
    with pytest.raises(TypeError):
        budgeted("5", 7)


def test_both_scanners_round_a_fractional_budget_up(dk):
    rec = _Recording(dk, strings=dk.list_value_strings() + _INDICATORS)
    dexllm.extract_iocs(rec, with_xref=True, xref_limit=1.5)
    rec2 = _Recording(
        dk, strings=["content://sms/inbox", "content://call_log/calls", "content://mms"]
    )
    dexllm.detect_content_providers(rec2, with_xref=True, xref_limit=1.5)
    assert [len(q) for q in rec.batch_calls + rec2.batch_calls] == [2, 2]


# --- the same class declared in two dexes with DIFFERENT bodies ---------------
#
# Loading one file twice gives identical bodies, where keeping dex 0 only, keeping
# the LAST occurrence and sorting all coincide with the right rule. A variant whose
# const-string operands point at other pool strings separates them: the class's
# body in one dex loads strings the other does not.


def _code_items(raw):
    """(class, method name) -> code_off for every method with code, from raw bytes."""
    import struct

    def u4(o):
        return struct.unpack_from("<I", raw, o)[0]

    def uleb(p):
        r = sh = 0
        while True:
            b = raw[p]
            p += 1
            r |= (b & 0x7F) << sh
            sh += 7
            if b < 0x80:
                return r, p

    cd_n, cd_o = u4(96), u4(100)
    out = []
    for c in range(cd_n):
        cdo = u4(cd_o + 32 * c + 24)
        if not cdo:
            continue
        sf, p = uleb(cdo)
        inf, p = uleb(p)
        dm, p = uleb(p)
        vm, p = uleb(p)
        for _ in range(sf + inf):
            _, p = uleb(p)
            _, p = uleb(p)
        for cnt in (dm, vm):
            idx = 0
            for _ in range(cnt):
                d, p = uleb(p)
                idx += d
                _, p = uleb(p)
                co, p = uleb(p)
                if co:
                    out.append((idx, co))
    return out


@pytest.fixture(scope="module")
def variant(tmp_path_factory, dk):
    """invoke-custom.dex with every second const-string repointed at another string."""
    import re
    import struct

    raw = bytearray(FIXTURE.read_bytes())
    n_strings = struct.unpack_from("<I", raw, 56)[0]
    by_idx = {i: d for i, d in enumerate(dk.list_methods_in_dex(0))}
    patched = 0
    for k, (midx, code_off) in enumerate(_code_items(bytes(raw))):
        smali = dk.render_method_smali(by_idx[midx])
        for m in re.finditer(r"0x([0-9a-f]+): const-string v\d+, ", smali):
            at = code_off + 16 + int(m.group(1), 16) + 2
            if raw[at - 2] != 0x1A:
                continue
            if (patched + k) % 2 == 0:
                cur = struct.unpack_from("<H", raw, at)[0]
                struct.pack_into("<H", raw, at, (cur * 7 + 3) % n_strings)
            patched += 1
    assert patched > 20, "premise: the fixture has const-string sites to repoint"
    path = tmp_path_factory.mktemp("xref98") / "variant.dex"
    path.write_bytes(bytes(raw))
    assert all(r["valid"] for r in dexllm.verify(str(path))), "the craft must verify"
    return path


def _session_values(session):
    vs = [v for v in session.list_value_strings() if v]
    return vs + [v[:3] for v in vs if len(v) >= 3]


@pytest.mark.parametrize("shape", ["variant_first", "original_first", "dumped"])
def test_differing_bodies_resolve_exactly_like_the_loop(shape, variant):
    if shape == "variant_first":
        session = dexllm.DexKit([str(variant), str(FIXTURE)])
    elif shape == "original_first":
        session = dexllm.DexKit([str(FIXTURE), str(variant)])
    else:
        session = dexllm.add_dumped_dexes(dexllm.DexKit(str(FIXTURE)), [str(variant)])
    vals = _session_values(session)
    loop = _one_by_one(session, vals)
    # premise: some answer comes ONLY from the second dex's body
    raw = session.batch_find_methods_using_strings(
        {str(i): [v] for i, v in enumerate(vals)},
        match_type="contains",
        ignore_case=False,
    )
    assert any(
        raw[str(i)] and {m.dex_id for m in raw[str(i)]} == {1} for i in range(len(vals))
    )
    assert methods_loading_each(session, vals) == loop


def test_two_different_fixtures_in_one_session_resolve_like_the_loop():
    session = dexllm.DexKit([str(FIXTURE.parent / "method_handles.dex"), str(FIXTURE)])
    vals = _session_values(session)
    assert methods_loading_each(session, vals) == _one_by_one(session, vals)


# --- every ROW carries the answer for ITS OWN value ----------------------------
#
# The injected indicators above occur in no code, so their rows are all `[]` and
# any pairing of values to answers would pass. These feed the fixture's own value
# strings — which DO hit code — through the scanners' classifiers.


def _hitting(dk, values, n=12):
    loop = _one_by_one(dk, values)
    picked = [v for v, ms in zip(values, loop) if ms][:n]
    assert len(picked) >= 6, "premise: the fixture has strings that hit code"
    return picked


def test_every_ioc_row_carries_its_own_methods(dk, values, monkeypatch):
    import dexllm.ioc as ioc

    picked = _hitting(dk, values)
    buckets = {cat: set() for cat in ioc.IOC_CATEGORIES}
    for i, v in enumerate(picked):  # spread across categories, priority order mixes
        buckets[ioc.IOC_CATEGORIES[i % len(ioc.IOC_CATEGORIES)]].add(v)
    monkeypatch.setattr(ioc, "_scan_value_strings", lambda *a, **k: buckets)
    out = ioc.extract_iocs(dk, with_xref=True, denoise=False)
    rows = [r for cat in out for r in out[cat]]
    assert len(rows) == len(picked)
    for r in rows:
        assert r["methods"] == _one_by_one(dk, [r["value"]])[0], r["value"]
    assert len({tuple(r["methods"]) for r in rows}) > 1, "answers must differ"


def test_every_provider_row_carries_its_own_methods(dk, values, monkeypatch):
    import dexllm.providers as providers

    picked = sorted(_hitting(dk, values))
    monkeypatch.setattr(
        providers, "match_content_uris", lambda *a, **k: [(v, "x") for v in picked]
    )
    rows = providers.detect_content_providers(dk, with_xref=True)
    assert [r["uri"] for r in rows] == picked
    for r in rows:
        assert r["methods"] == _one_by_one(dk, [r["uri"]])[0], r["uri"]
    assert len({tuple(r["methods"]) for r in rows}) > 1, "answers must differ"
