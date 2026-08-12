"""content:// provider query-URI detection.

The `content://` URIs that ``ContentResolver.query()/insert()/update()/delete()``
take are the real handles for SMS / contacts / call-log / calendar — the surface
``READ_SMS`` / ``READ_CONTACTS`` / ``READ_CALL_LOG`` actually gate, and invisible
to the ``@RequiresPermission`` signature map (the ``Uri`` is assembled at runtime,
so a static call-signature scan never sees it). This module recovers them
statically: it matches the app's value-strings against a bundled AOSP-derived
provider-URI dataset and ties each hit back to the referencing method(s).

Issue #13 — the dataset (``data/content_uris.json``) and the join are the
canonical Python implementation dexllm's API uses. (A WASM consumer that needs
in-browser detection must vendor its own engine; dexllm no longer carries a C++
mirror of this pure-Python logic.)

Match semantics (mirrors dexllm-web #16's ``detectProviders``): a dataset URI is a
hit iff it occurs as a SUBSTRING of some value-string; the ``family`` comes from the
dataset, the ``methods`` xref from the same L7 search the network IoCs use.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import TYPE_CHECKING, Any

from .datadir import load_data_json

if TYPE_CHECKING:
    from ._dexkit_core import DexKit

__all__ = [
    "detect_content_providers",
    "load_content_uris",
    "match_content_uris",
]

_DATA_FILE = "content_uris.json"


def _validate(obj: Any, path: Path) -> None:
    """Reject a malformed override loudly, naming the file (issue #33).

    Only the shape ``detect_content_providers`` actually relies on is checked — a
    mapping of URI to an entry carrying ``family``. ``classes`` is deliberately NOT
    required: nothing on this path reads it (the match is over the URI keys and the
    report carries ``uri``/``family``/``methods``), so an override may omit it. A
    user-supplied file is untrusted input on the analysis path, and the alternative
    is a bare ``KeyError`` raised from inside a cached loader.
    """
    if not isinstance(obj, dict):
        raise ValueError(f"{path} must be a JSON object mapping URI -> entry")
    for uri, entry in obj.items():
        # An empty key is a substring of EVERY candidate, so it would report a hit
        # against every `content://` string the app holds — a whole-report failure
        # from one degenerate row, and the one input shape the match loop cannot
        # defend itself against.
        if not uri:
            raise ValueError(f"{path} has an empty URI key")
        if not isinstance(entry, dict) or "family" not in entry:
            raise ValueError(f"{path}: entry {uri!r} must be an object with 'family'")
        if not isinstance(entry["family"], str):
            raise ValueError(f"{path}: entry {uri!r} has a non-string 'family'")


def load_content_uris(
    *, data_dir: str | os.PathLike | None = None
) -> dict[str, dict[str, Any]]:
    """Return the ``content://`` URI -> {"classes","family"} dataset (cached).

    Honours ``data_dir`` / ``$DEXLLM_DATA_DIR`` (else the bundled file) — see
    :mod:`dexllm.datadir`. The ``family`` labels are hand judgement, which is why
    this file is in the override channel.
    """
    return load_data_json(_DATA_FILE, data_dir=data_dir, validate=_validate)


def match_content_uris(
    strings: list[str], *, data_dir: str | os.PathLike | None = None
) -> list[tuple[str, str]]:
    """Return the (uri, family) dataset hits over ``strings``, sorted by URI.

    A dataset URI is a hit iff it occurs as a substring of some string (the #16
    ``detectProviders`` semantics). Factored out so the match can be unit-tested on
    crafted strings without a DexKit.
    """
    dataset = load_content_uris(data_dir=data_dir)
    candidates = [s for s in strings if "content://" in s]
    hits: list[tuple[str, str]] = []
    for uri in sorted(dataset):
        if any(uri in s for s in candidates):
            hits.append((uri, dataset[uri]["family"]))
    return hits


def detect_content_providers(
    dk: DexKit,
    *,
    with_xref: bool = True,
    xref_limit: int = 300,
    data_dir: str | os.PathLike | None = None,
) -> list[dict[str, Any]]:
    """Find provider ``content://`` URIs referenced by the app's strings.

    Args:
        dk: a loaded ``dexllm.DexKit`` instance.
        with_xref: attach referencing method descriptors to each hit (one L7 search
            per hit), the "where in the code" view.
        xref_limit: cap on the number of hits cross-referenced (sorted by URI).
        data_dir: directory holding a replacement ``content_uris.json`` (else
            ``$DEXLLM_DATA_DIR``, else the bundled dataset) — see
            :mod:`dexllm.datadir`.

    Returns:
        A list of ``{"uri": str, "family": str, "methods": list[str]}`` sorted by
        URI. A dataset URI is included iff it appears as a substring of some
        value-string.
    """
    hits = match_content_uris(dk.list_value_strings(), data_dir=data_dir)

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
