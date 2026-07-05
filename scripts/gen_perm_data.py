#!/usr/bin/env python3
"""Regenerate the bundled permission→API + protection-level tables.

Issue #14 — the permission-caller analysis (Python + the C++/WASM engine port)
covers the FULL AOSP permission→API surface across all protection levels, not just
the dangerous slice. This produces the two committed source-of-truth files from an
[aosp_data_set](https://github.com/mobile-threat-hunter/aosp_data_set) checkout:

  * ``src/dexllm/data/perm_api.json``    — {permission: [api signature, …]} for
    every permission with ≥1 real member-ref API (metalava table, `_REF`-filtered).
  * ``src/dexllm/data/perm_levels.json`` — {permission: level bucket} (PERM_LEVELS).

The dangerous slice is DERIVED from these at runtime (``dangerous_*`` filter to the
``dangerous`` bucket), so there is one bundled source of truth.

Usage (point at an aosp_data_set directory, or set $DEXLLM_AOSP_DATASET):
    python scripts/gen_perm_data.py /path/to/aosp_data_set
"""
from __future__ import annotations

import json
import os
import pathlib
import sys

from dexllm.dangerous_api import _level_bucket, _load_perm_api_map_cached

DATA = (
    pathlib.Path(__file__).resolve().parent.parent / "src" / "dexllm" / "data"
)


def main() -> None:
    root = sys.argv[1] if len(sys.argv) > 1 else os.environ.get("DEXLLM_AOSP_DATASET")
    if not root:
        sys.exit(
            "usage: gen_perm_data.py <aosp_data_set_dir>  (or set $DEXLLM_AOSP_DATASET)"
        )
    full = _load_perm_api_map_cached(root)  # {perm: (apis,)} — sorted, _REF-filtered
    perms = json.loads((pathlib.Path(root) / "permissions.json").read_text())
    raw_level = {
        p["name"]: str(p.get("protectionLevel", ""))
        for p in perms
        if isinstance(p, dict) and "name" in p
    }

    perm_api = {perm: list(full[perm]) for perm in sorted(full)}
    perm_levels = {perm: _level_bucket(raw_level.get(perm, "")) for perm in sorted(full)}

    (DATA / "perm_api.json").write_text(
        json.dumps(perm_api, sort_keys=True, ensure_ascii=False)
    )
    (DATA / "perm_levels.json").write_text(
        json.dumps(perm_levels, sort_keys=True, ensure_ascii=False)
    )
    from collections import Counter

    dist = Counter(perm_levels.values())
    print(
        f"wrote perm_api.json ({len(perm_api)} perms, "
        f"{sum(len(v) for v in perm_api.values())} APIs) + perm_levels.json "
        f"(levels: {dict(dist)})"
    )


if __name__ == "__main__":
    main()
