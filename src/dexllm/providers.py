"""content:// provider query-URI detection.

The `content://` URIs that ``ContentResolver.query()/insert()/update()/delete()``
take are the real handles for SMS / contacts / call-log / calendar — the surface
``READ_SMS`` / ``READ_CONTACTS`` / ``READ_CALL_LOG`` actually gate, and invisible
to the ``@RequiresPermission`` signature map (the ``Uri`` is assembled at runtime,
so a static call-signature scan never sees it). This module recovers them
statically: it matches the app's value-strings against a bundled AOSP-derived
provider-URI dataset and ties each hit back to the referencing method(s).

Issue #13 — the dataset (``data/content_uris.json``) and the join live in the
engine (single source of truth) so the WASM and pybind bindings, and any future
consumer, share ONE implementation instead of re-forking the data + logic. The C++
port (``native/core_ext/ioc.cpp`` `DetectContentProviders`) mirrors this, verified
byte-identical (``tests/test_ioc_native.py``).

Match semantics (mirrors dexllm-web #16's ``detectProviders``): a dataset URI is a
hit iff it occurs as a SUBSTRING of some value-string; the ``family`` comes from the
dataset, the ``methods`` xref from the same L7 search the network IoCs use.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from ._dexkit_core import DexKit

__all__ = [
    "detect_content_providers",
    "load_content_uris",
    "match_content_uris",
]

_DATA_PATH = Path(__file__).parent / "data" / "content_uris.json"
_CACHE: dict[str, dict[str, Any]] | None = None


def load_content_uris() -> dict[str, dict[str, Any]]:
    """Return the bundled ``content://`` URI -> {"classes","family"} dataset (cached)."""
    global _CACHE
    if _CACHE is None:
        _CACHE = json.loads(_DATA_PATH.read_text())
    return _CACHE


def match_content_uris(strings: list[str]) -> list[tuple[str, str]]:
    """Return the (uri, family) dataset hits over ``strings``, sorted by URI.

    A dataset URI is a hit iff it occurs as a substring of some string (the #16
    ``detectProviders`` semantics). Factored out so the C++ port
    (``_detect_providers_from_strings``) can be diff-tested on crafted strings.
    """
    dataset = load_content_uris()
    candidates = [s for s in strings if "content://" in s]
    hits: list[tuple[str, str]] = []
    for uri in sorted(dataset):
        if any(uri in s for s in candidates):
            hits.append((uri, dataset[uri]["family"]))
    return hits


def detect_content_providers(
    dk: DexKit, *, with_xref: bool = True, xref_limit: int = 300
) -> list[dict[str, Any]]:
    """Find bundled provider ``content://`` URIs referenced by the app's strings.

    Args:
        dk: a loaded ``dexllm.DexKit`` instance.
        with_xref: attach referencing method descriptors to each hit (one L7 search
            per hit), the "where in the code" view.
        xref_limit: cap on the number of hits cross-referenced (sorted by URI).

    Returns:
        A list of ``{"uri": str, "family": str, "methods": list[str]}`` sorted by
        URI. A dataset URI is included iff it appears as a substring of some
        value-string.
    """
    hits = match_content_uris(dk.list_value_strings())

    budget = xref_limit
    result: list[dict[str, Any]] = []
    for uri, family in hits:  # already sorted by URI
        methods: list[str] = []
        if with_xref and budget > 0:
            try:
                found = dk.find_methods_using_strings(
                    [uri], match_type="contains", ignore_case=False
                )
                methods = [
                    m.descriptor if hasattr(m, "descriptor") else str(m) for m in found
                ]
            except Exception:  # noqa: BLE001 — one bad query must not abort the report
                methods = []
            budget -= 1
        result.append({"uri": uri, "family": family, "methods": methods})
    return result
