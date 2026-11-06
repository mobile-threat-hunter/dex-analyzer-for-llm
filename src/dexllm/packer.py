"""Packer / runtime-unpack helpers.

A packed app decrypts its real dex at runtime; static analysis sees only the stub.
The unpack workflow is: load the apk → (detect packing) → dump the decrypted dex with
an external dynamic tool → re-analyze with the dump merged in. :func:`add_dumped_dexes`
is the last step — it returns a fresh analysis loaded from the dump(s) + the original
sources, with the dumps loaded FIRST so first-wins makes the unpacked classes win the
collision against the original (stub) ones (the same order the packer arranges at
runtime; ART consults the decrypted dex first).
"""

from __future__ import annotations

import os
from typing import TYPE_CHECKING

from ._dexkit_core import DexKit

if TYPE_CHECKING:
    from collections.abc import Iterable

__all__ = ["add_dumped_dexes"]


def add_dumped_dexes(
    dk: DexKit,
    dumps: str | os.PathLike | Iterable[str | os.PathLike],
    *,
    prefer: bool = True,
    lenient: bool = True,
) -> DexKit:
    """Re-analyze with runtime-dumped dex(es) merged in — a clean rebuild.

    Returns a NEW ``DexKit`` loaded from ``dumps`` plus ``dk``'s original sources.
    This is the "갱신 재분석" step of the unpack workflow: it rebuilds from scratch
    (full, consistent caches; no mid-life mutation), so keep the returned handle and
    discard the old one.

    Args:
        dk: The current analysis (the loaded apk).
        dumps: One path, or an iterable of paths, to runtime-dumped dex files.
        prefer: When True (default), load the dumps BEFORE the original sources so
            first-wins makes an unpacked class win a descriptor collision against the
            original (stub) class — the packer/unpack intent. Set False to keep the
            original winning (dumps only add classes the apk lacks).
        lenient: When True (default), skip instruction-operand checks so a
            partially-decrypted dump — valid structure, garbage method bodies —
            still loads, exactly as ART loads it, and accept value strings out of
            order (ART rejects that; reported in ``art_deviations``, dexllm#112).

    Returns:
        A new ``DexKit`` over the combined, ordered source set, in the original
        session's ``mode``.

    Raises:
        ValueError: no dump paths, or ``dk`` was loaded from bytes
            (``DexKit.from_bytes`` / ``from_dex_images``), whose sources cannot be
            re-read.
        RuntimeError: a dump yields no dex (missing, not a dex, or rejected by
            the verifier) -- unlike a plain ``DexKit([...])``, where such a source
            is only a ``valid=False`` row.
    """
    if isinstance(dumps, (str, os.PathLike)):
        paths = [os.fspath(dumps)]
    else:
        paths = [os.fspath(p) for p in dumps]
    if not paths or not all(paths):
        raise ValueError("add_dumped_dexes: no (non-empty) dump paths given")
    # The rebuild re-reads dk's sources from disk, which bytes input never had:
    # its sources() are caller labels (dexllm#119). Refuse rather than open a
    # file that happens to share a label's name.
    in_memory = [i["source"] for i in dk.source_info() if i["in_memory"]]
    if in_memory:
        raise ValueError(
            "add_dumped_dexes: the session was loaded from bytes "
            f"({', '.join(in_memory)}), so it cannot be rebuilt from its sources; "
            "rebuild it with DexKit.from_dex_images, listing the dumps before the "
            "session's own dexes (extract_dex(i) returns their bytes and entry names)"
        )
    original = list(dk.sources())
    order = paths + original if prefer else original + paths
    # Keep the session's load mode: a runtime-view session stays one (#120).
    rebuilt = DexKit(order, lenient=lenient, mode=dk.load_status()["mode"])
    # A list source that yields nothing is a row, not an error (dexllm#119), but
    # a dump that loaded nothing defeats the call: analysing without it, unaware,
    # is the failure this verb exists to prevent. Raise as it did before #119.
    for path in paths:
        rows = [r for r in rebuilt.verify_report() if r["source"] == path]
        if not any(r["valid"] for r in rows):
            reasons = "; ".join(r["reason"] for r in rows) or "no dex"
            raise RuntimeError(
                f"add_dumped_dexes: dump '{path}' yielded no dex: {reasons}"
            )
    return rebuilt
