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

from dexllm.dangerous_api import (
    _REF,
    _level_bucket,
    _load_perm_api_map_cached,
    _parse_api,
)

DATA = (
    pathlib.Path(__file__).resolve().parent.parent / "src" / "dexllm" / "data"
)


def _merge_runtime(
    full: dict[str, tuple[str, ...]], root: str
) -> dict[str, tuple[str, ...]]:
    """Merge the AOSP runtime-ENFORCEMENT public-API bridge
    (``runtime_perm_api_by_perm.json``) into the metalava ``@RequiresPermission``
    table. Those APIs (e.g. ``SmsManager#copyMessageToIcc`` → SEND_SMS) are
    runtime-enforced but carry no ``@RequiresPermission`` annotation, so metalava
    misses them. Their sigs are arity-only (``Class#method(Nargs)``), matched on
    (class, method, arity) via the sentinel in ``_parse_api``.

    Dedup is GLOBAL by (class, method): a runtime sig is added ONLY when the method
    appears NOWHERE in metalava. This guarantees the merge is strictly ADDITIVE — no
    existing metalava method's overload/arity map is perturbed (so its matching is
    byte-identical), while genuinely-new runtime-only methods are picked up. The
    complementary ``enforced_perms_by_perm.json`` is NOT merged: it lists INTERNAL
    framework service impls (``IccSmsInterfaceManager`` …) an app never calls, so
    they can never match an app call site.

    TRADE-OFF (deliberate, adversarial-review): global (class, method) dedup DROPS a
    genuinely-new runtime ARITY of a method metalava only PARTIALLY covers (metalava
    ``foo(String)`` + runtime ``foo(2args)`` → the 2-arg overload is skipped). On the
    current dataset that is 8 sigs. Keeping them would require (class, method, ARITY)
    dedup, which can perturb an existing lone metalava method's ``total<=1`` match →
    breaking the additive guarantee. The 8 lost sigs are a safe FALSE-NEGATIVE (missed
    coverage, never a mis-attribution); additivity is worth more than 8 arity variants.
    Runtime sigs are validated by the same ``_REF`` structural filter as metalava.
    """
    rt_file = pathlib.Path(root) / "runtime_perm_api_by_perm.json"
    if not rt_file.is_file():
        return full
    runtime = json.loads(rt_file.read_text())
    metalava_methods = set()
    for sigs in full.values():
        for sig in sigs:
            c, m, t = _parse_api(sig)
            if t is not None:
                metalava_methods.add((c, m))
    out = {perm: list(sigs) for perm, sigs in full.items()}
    added = 0
    for perm in sorted(runtime):
        for sig in runtime[perm]:
            if not _REF.match(sig):
                continue  # same structural filter metalava's loader applies
            c, m, t = _parse_api(sig)
            if t is None or (c, m) in metalava_methods:
                continue  # not a call ref, or metalava already authoritative
            out.setdefault(perm, []).append(sig)
            added += 1
    print(f"  merged {added} runtime-enforced APIs (metalava-missing methods)")
    return {perm: tuple(sorted(set(sigs))) for perm, sigs in out.items()}


def main() -> None:
    root = sys.argv[1] if len(sys.argv) > 1 else os.environ.get("DEXLLM_AOSP_DATASET")
    if not root:
        sys.exit(
            "usage: gen_perm_data.py <aosp_data_set_dir>  (or set $DEXLLM_AOSP_DATASET)"
        )
    full = _load_perm_api_map_cached(root)  # {perm: (apis,)} — sorted, _REF-filtered
    full = _merge_runtime(full, root)  # + runtime-enforcement bridge (additive)
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
