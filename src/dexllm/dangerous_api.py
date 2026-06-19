"""Map an APK's referenced framework APIs back to the dangerous permissions they gate.

Android's runtime-sensitive APIs carry ``@RequiresPermission`` annotations; AOSP's
permission inventory (https://github.com/mobile-threat-hunter/aosp_data_set) scrapes
those into a permission -> API map. This module joins that map against the APIs an
APK actually references (its external method refs) to answer two triage questions:

  - which **dangerous** permissions does the APK exercise *through real API calls*
    (not just `<uses-permission>` claims)? -> :func:`dangerous_permission_apis`
  - **who** in the code calls those gated APIs? -> :func:`dangerous_permission_callers`

The permission -> API table ships bundled (``data/dangerous_perm_api.json``, the
dangerous slice of the AOSP dataset). Point ``dataset_path`` (or ``$DEXLLM_AOSP_DATASET``)
at a checkout of the full dataset to use a fresher / wider table.
"""

from __future__ import annotations

import json
import os
import re
from functools import lru_cache
from pathlib import Path
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from ._dexkit_core import DexKit

__all__ = ["dangerous_permission_apis", "dangerous_permission_callers"]

_BUNDLED = Path(__file__).parent / "data" / "dangerous_perm_api.json"

# A clean API ref `pkg.Class#methodName` — guards against extraction noise.
_REF = re.compile(r"^([A-Za-z_][\w.$]*)#([A-Za-z_$][\w$]*)(?:\(\))?$")


@lru_cache(maxsize=8)
def _load_dangerous_map(dataset_path: str | None) -> dict[str, tuple[str, ...]]:
    """Load the dangerous-permission -> API map.

    With no ``dataset_path`` (and no ``$DEXLLM_AOSP_DATASET``), the bundled slim
    table is used. Otherwise the full AOSP dataset at that directory is read and
    the dangerous slice is computed live from ``permissions.json`` +
    ``perm_api_by_perm.json``.
    """
    root = dataset_path or os.environ.get("DEXLLM_AOSP_DATASET")
    if not root:
        raw = json.loads(_BUNDLED.read_text())
        return {perm: tuple(apis) for perm, apis in raw.items()}

    base = Path(root)
    perms = json.loads((base / "permissions.json").read_text())
    dangerous = {
        p["name"]
        for p in perms
        if "dangerous" in str(p.get("protectionLevel", "")).lower()
    }
    table = json.loads((base / "perm_api_by_perm.json").read_text())
    out: dict[str, tuple[str, ...]] = {}
    for perm in sorted(dangerous):
        refs = sorted(
            {
                f"{m.group(1)}#{m.group(2)}"
                for r in table.get(perm, [])
                if (m := _REF.match(r))
            }
        )
        if refs:
            out[perm] = tuple(refs)
    return out


def _external_method_index(dk: DexKit) -> dict[tuple[str, str], list[Any]]:
    """Index the APK's external method refs by ``(java_class, method_name)``."""
    idx: dict[tuple[str, str], list[Any]] = {}
    for ref in dk.list_external_method_refs(False):
        idx.setdefault((ref.java_class, ref.name), []).append(ref)
    return idx


def _split(api: str) -> tuple[str, str]:
    """``pkg.Class#method`` -> ``(pkg.Class, method)``."""
    cls, _, method = api.partition("#")
    return cls, method


def dangerous_permission_apis(
    dk: DexKit, *, dataset_path: str | None = None
) -> dict[str, list[str]]:
    """Return the dangerous-permission framework APIs this APK actually references.

    For each dangerous permission whose gated APIs appear among the APK's external
    method refs, return the list of those used APIs (``pkg.Class#method``). A
    permission with no referenced API is omitted — this reflects real API usage,
    not ``<uses-permission>`` declarations.

    Args:
        dk: A loaded ``dexllm.DexKit`` instance.
        dataset_path: Optional directory of the full AOSP dataset to override the
            bundled table (else ``$DEXLLM_AOSP_DATASET``, else bundled).

    Returns:
        ``{permission: [used api, ...]}``, each list sorted, only non-empty perms.
    """
    table = _load_dangerous_map(dataset_path)
    used_keys = set(_external_method_index(dk))
    result: dict[str, list[str]] = {}
    for perm, apis in table.items():
        used = sorted(a for a in apis if _split(a) in used_keys)
        if used:
            result[perm] = used
    return result


def dangerous_permission_callers(
    dk: DexKit, *, dataset_path: str | None = None
) -> dict[str, list[dict[str, Any]]]:
    """Return the dangerous-permission APIs this APK uses, each with its callers.

    Like :func:`dangerous_permission_apis` but resolves every used API to its full
    Dalvik descriptor(s) and the methods that invoke it (the "who in the code uses
    this permission" view).

    Args:
        dk: A loaded ``dexllm.DexKit`` instance.
        dataset_path: Optional dataset override (see :func:`dangerous_permission_apis`).

    Returns:
        ``{permission: [{"api", "descriptors", "callers"}, ...]}`` — ``descriptors``
        are the resolved ``Lcls;->name(proto)ret`` forms, ``callers`` the distinct
        caller method descriptors. Only perms/APIs with ≥1 caller are included.
    """
    table = _load_dangerous_map(dataset_path)
    index = _external_method_index(dk)
    result: dict[str, list[dict[str, Any]]] = {}
    for perm, apis in table.items():
        rows: list[dict[str, Any]] = []
        for api in apis:
            refs = index.get(_split(api))
            if not refs:
                continue
            descriptors: list[str] = []
            callers: set[str] = set()
            for ref in refs:
                desc = f"{ref.class_descriptor}->{ref.name}{ref.proto}"
                descriptors.append(desc)
                for site in dk.find_call_sites_to_api(desc):
                    callers.add(site.caller_descriptor)
            if callers:
                rows.append(
                    {
                        "api": api,
                        "descriptors": sorted(set(descriptors)),
                        "callers": sorted(callers),
                    }
                )
        if rows:
            result[perm] = rows
    return result
