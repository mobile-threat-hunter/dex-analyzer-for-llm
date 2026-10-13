"""The const-string cross-reference shared by the indicator scanners.

``extract_iocs`` and ``detect_content_providers`` both answer "which methods load
this string" for a LIST of values. Each used to run one
``find_methods_using_strings`` query per value, i.e. one full scan of every
method per value, so the cost grew linearly with the number of values — and
the single-query path never reaches the core's Aho-Corasick trie at all (its
prefilter plan is gated on a composite matcher, which a plain ``using_strings``
list never is). ``batch_find_methods_using_strings`` builds ONE trie for every
value and walks the methods once (dexllm#98).

The two shapes return the same methods in the same order. The batch used to
lack one step — ``DexKit::FindMethod`` drops a descriptor it has already seen,
while ``BatchFindMethodUsingStrings`` concatenated every dex's hits, so a class
declared in several loaded dexes (an ``add_dumped_dexes`` packer session) had
its methods listed once per dex. That first-wins dedupe lived here until
dexllm#106 moved it into ``DexKitExt``, so every batch caller (raw, SDK, MCP)
gets it; this helper no longer repeats it. The orders coincide because the
single path walks ``method_ids`` in index order — sorted by class, a
verifier-enforced ordering — while the batch walks classes by type_idx and each
class's sorted ``class_method_ids``, both merging dexes in dex_id order.
"""

from __future__ import annotations

from typing import Any


def _descriptor(m: Any) -> str:
    return m.descriptor if hasattr(m, "descriptor") else str(m)


def budgeted(limit: Any, available: int) -> int:
    """How many of ``available`` values a ``xref_limit`` of ``limit`` cross-references.

    Exactly the countdown both scanners always ran — ``while budget > 0: budget -= 1``
    — so a fractional limit rounds UP (1.5 -> 2), ``inf`` covers everything, ``nan``
    covers nothing, and a non-number raises the ``TypeError`` it always raised.
    """
    n, budget = 0, limit
    while n < available and budget > 0:
        n += 1
        budget -= 1
    return n


def methods_loading_each(dk: Any, values: list[str]) -> list[list[str]]:
    """Return, for each of ``values``, the methods whose code loads a string containing it.

    ``out[i]`` answers ``values[i]``, with the semantics of
    ``dk.find_methods_using_strings([values[i]], match_type="contains",
    ignore_case=False)``.

    One batch call does the work. The batch is keyed by POSITION, not by value:
    a batch key is a caller label that is not MUTF-8-encoded (dexllm#29), so a
    value carrying a lone surrogate would make a value-keyed call raise, and a
    value repeated in ``values`` gets an answer per occurrence either way.

    If the batch call raises, the per-value loop runs instead. That keeps the
    containment the loop always had — one bad query must not abort a report —
    and its exception: a failure before ANY query has worked is the whole
    cross-reference layer being unavailable (dexllm#55: a dex whose cache init
    fails RAISES here), and swallowing it would hand back every value with no
    methods and no error, which reads as "this string appears in no code".
    """
    if not values:
        return []
    # An EMPTY value is never batched: the batch's keyword path asserts that "" is
    # an Equal matcher (a DEXKIT_CHECK that aborts in a non-NDEBUG build, which no
    # fallback can contain). The per-value loop answers it as find_methods does.
    if "" in values:
        return _one_by_one(dk, values)
    try:
        found = dk.batch_find_methods_using_strings(
            {str(i): [v] for i, v in enumerate(values)},
            match_type="contains",
            ignore_case=False,
        )
        return [[_descriptor(m) for m in found[str(i)]] for i in range(len(values))]
    except Exception:  # noqa: BLE001 — fall back to the per-value loop below
        return _one_by_one(dk, values)


def _one_by_one(dk: Any, values: list[str]) -> list[list[str]]:
    out: list[list[str]] = []
    ever_worked = False
    for value in values:
        try:
            hits = dk.find_methods_using_strings(
                [value], match_type="contains", ignore_case=False
            )
            out.append([_descriptor(m) for m in hits])
            ever_worked = True
        except Exception:  # noqa: BLE001
            if not ever_worked:
                raise
            out.append([])
    return out
