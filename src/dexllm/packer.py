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
        lenient: When True (default), verify in ART-structural-equivalent mode
            (skip instruction-operand checks) so a partially-decrypted dump — valid
            structure, garbage method bodies — still loads, exactly as ART loads it.

    Returns:
        A new ``DexKit`` over the combined, ordered source set.
    """
    if isinstance(dumps, (str, os.PathLike)):
        paths = [os.fspath(dumps)]
    else:
        paths = [os.fspath(p) for p in dumps]
    if not paths or not all(paths):
        raise ValueError("add_dumped_dexes: no (non-empty) dump paths given")
    original = list(dk.sources())
    order = paths + original if prefer else original + paths
    return DexKit(order, lenient=lenient)
