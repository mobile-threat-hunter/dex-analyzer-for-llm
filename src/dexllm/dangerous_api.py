"""Map an APK's referenced framework APIs back to the dangerous permissions they gate.

Android's runtime-sensitive APIs carry ``@RequiresPermission`` annotations; AOSP's
permission inventory (https://github.com/mobile-threat-hunter/aosp_data_set) scrapes
those into a permission -> API map. This module joins that map against the APIs an
APK actually references (its external method refs) to answer two triage questions:

  - which **dangerous** permissions does the APK exercise *through real API calls*
    (not just `<uses-permission>` claims)? -> :func:`dangerous_permission_apis`
  - **who** in the code calls those gated APIs? -> :func:`dangerous_permission_api_callers`

The dataset entries carry the full Java signature
(``android.location.LocationManager#getLastKnownLocation(@NonNull String provider)``),
so overloads that differ in their permission requirement are matched precisely:
when a ``(class, method)`` has more than one dataset overload, the dex reference's
parameter types must agree; when there is only one overload the name alone matches
(so a signature-parser edge case can never drop a real hit).

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

__all__ = ["dangerous_permission_apis", "dangerous_permission_api_callers"]

_BUNDLED = Path(__file__).parent / "data" / "dangerous_perm_api.json"

# A dataset entry is `pkg.Class#member`, optionally followed by a `(signature)`.
_REF = re.compile(r"^[A-Za-z_][\w.$]*#[A-Za-z_$][\w$]*")

# Caller classes that are bundled framework / official-library code. A dangerous
# API call from here is library plumbing (e.g. androidx permission helpers,
# Play-services location) rather than the app's own behaviour — `app_only` filters
# them out. Descriptor-prefix form for cheap caller_descriptor matching.
_FRAMEWORK_CALLER_PREFIXES = (
    "Landroidx/",
    "Landroid/support/",
    "Landroid/arch/",
    "Lkotlin/",
    "Lkotlinx/",
    "Ljava/",
    "Ljavax/",
    "Ldalvik/",
    "Lcom/google/android/",
    "Lcom/google/common/",
    "Lcom/google/gson/",
)


def _is_framework_caller(descriptor: str) -> bool:
    """Return True if a caller belongs to bundled framework / official-library code."""
    return descriptor.startswith(_FRAMEWORK_CALLER_PREFIXES)


# ── signature normalisation ─────────────────────────────────────────────────
# Both sides are reduced to a tuple of SIMPLE type names (generics erased, last
# `.`/`$`/`/` segment) so a Dalvik proto and a Java source signature compare equal
# without resolving the dataset's unqualified type names to packages.
_DALVIK_PRIM = {
    "I": "int",
    "J": "long",
    "Z": "boolean",
    "D": "double",
    "F": "float",
    "B": "byte",
    "S": "short",
    "C": "char",
    "V": "void",
}
_JAVA_MODIFIERS = {"final"}


def _simple_name(type_str: str) -> str:
    """`java.util.function.Consumer` / `Outer$Inner` -> last identifier segment."""
    return type_str.replace("/", ".").replace("$", ".").rsplit(".", 1)[-1]


def _dalvik_param_types(proto: str) -> tuple[str, ...]:
    """Dalvik proto ``(...)ret`` -> tuple of simple param type names."""
    open_p = proto.find("(")
    close_p = proto.find(")")
    if open_p < 0 or close_p < open_p:
        return ()
    inner = proto[open_p + 1 : close_p]
    out: list[str] = []
    i, n = 0, len(inner)
    while i < n:
        dims = 0
        while i < n and inner[i] == "[":
            dims += 1
            i += 1
        if i >= n:
            break
        c = inner[i]
        if c == "L":
            j = inner.find(";", i)
            if j < 0:
                break
            out.append(_simple_name(inner[i + 1 : j]) + "[]" * dims)
            i = j + 1
        else:
            out.append(_DALVIK_PRIM.get(c, c) + "[]" * dims)
            i += 1
    return tuple(out)


def _split_top_level(params: str) -> list[str]:
    """Split a Java parameter list on top-level commas (respecting <> nesting)."""
    parts: list[str] = []
    depth = 0
    cur = ""
    for ch in params:
        if ch == "<":
            depth += 1
            cur += ch
        elif ch == ">":
            depth -= 1
            cur += ch
        elif ch == "," and depth == 0:
            parts.append(cur)
            cur = ""
        else:
            cur += ch
    if cur.strip():
        parts.append(cur)
    return parts


def _java_param_simple(param: str) -> str:
    """One Java param decl (`@NonNull Consumer<Location> cb`) -> simple type (`Consumer`)."""
    toks = [
        t for t in param.split() if not t.startswith("@") and t not in _JAVA_MODIFIERS
    ]
    if not toks:
        return ""
    # The parameter name is the last token; everything before it is the type.
    type_str = " ".join(toks[:-1]) if len(toks) >= 2 else toks[0]
    type_str = re.sub(r"<.*>", "", type_str).strip()  # erase generics (dex erases too)
    arr = ""
    while type_str.endswith("[]"):
        arr += "[]"
        type_str = type_str[:-2].strip()
    if type_str.endswith("..."):  # varargs are arrays in the descriptor
        arr += "[]"
        type_str = type_str[:-3].strip()
    return _simple_name(type_str) + arr


def _parse_api(entry: str) -> tuple[str, str, tuple[str, ...] | None]:
    """``pkg.Class#method(params)`` -> ``(class, method, simple-param-types)``.

    Param types are None for a field/constant entry (no ``(...)``) — those can
    never match a method-call reference.
    """
    cls, _, rest = entry.partition("#")
    if "(" not in rest:
        return cls, rest, None
    name = rest[: rest.index("(")]
    params = rest[rest.index("(") + 1 : rest.rindex(")")]
    if not params.strip():
        return cls, name, ()
    return cls, name, tuple(_java_param_simple(p) for p in _split_top_level(params))


def _load_dangerous_map(dataset_path: str | None) -> dict[str, tuple[str, ...]]:
    """Load the dangerous-permission -> API map.

    With no ``dataset_path`` (and no ``$DEXLLM_AOSP_DATASET``), the bundled slim
    table is used. Otherwise the full AOSP dataset at that directory is read and
    the dangerous slice is computed live. The ``$DEXLLM_AOSP_DATASET`` env var is
    resolved here (not inside the cache) so a later change to it is honoured.
    """
    return _load_dangerous_map_cached(
        dataset_path or os.environ.get("DEXLLM_AOSP_DATASET") or ""
    )


@lru_cache(maxsize=8)
def _load_dangerous_map_cached(root: str) -> dict[str, tuple[str, ...]]:
    """Load and cache the map, keyed on the resolved dataset root (``""`` = bundled).

    Each value is the tuple of full ``pkg.Class#method(signature)`` entries gating
    that permission.
    """
    if not root:
        raw = json.loads(_BUNDLED.read_text())
        return {perm: tuple(apis) for perm, apis in raw.items()}

    base = Path(root)
    perm_file = base / "permissions.json"
    api_file = base / "perm_api_by_perm.json"
    if not perm_file.is_file() or not api_file.is_file():
        raise FileNotFoundError(
            f"AOSP dataset at {root!r} must contain permissions.json + "
            f"perm_api_by_perm.json"
        )
    perms = json.loads(perm_file.read_text())
    if not isinstance(perms, list):
        raise ValueError(f"{perm_file} must be a JSON list of permission entries")
    dangerous = {
        p["name"]
        for p in perms
        if isinstance(p, dict)
        and "name" in p
        and "dangerous" in str(p.get("protectionLevel", "")).lower()
    }
    table = json.loads(api_file.read_text())
    if not isinstance(table, dict):
        raise ValueError(
            f"{api_file} must be a JSON object mapping permission -> [apis]"
        )
    out: dict[str, tuple[str, ...]] = {}
    for perm in sorted(dangerous):
        refs = sorted({r for r in table.get(perm, []) if _REF.match(r)})
        if refs:
            out[perm] = tuple(refs)
    return out


def _external_method_index(dk: DexKit) -> dict[tuple[str, str], list[Any]]:
    """Index the APK's external method refs by ``(java_class, method_name)``."""
    idx: dict[tuple[str, str], list[Any]] = {}
    for ref in dk.list_external_method_refs(False):
        idx.setdefault((ref.java_class, ref.name), []).append(ref)
    return idx


def _overload_counts(table: dict[str, tuple[str, ...]]) -> dict[tuple[str, str], int]:
    """``{(class, method): #distinct dataset signatures}`` — drives the ambiguity check."""
    seen: dict[tuple[str, str], set[tuple[str, ...]]] = {}
    for sigs in table.values():
        for sig in sigs:
            cls, method, types = _parse_api(sig)
            if types is None:
                continue
            seen.setdefault((cls, method), set()).add(types)
    return {k: len(v) for k, v in seen.items()}


def _ref_matches(ref: Any, types: tuple[str, ...], single_overload: bool) -> bool:
    """Whether a dex ref realises the dataset signature.

    With a single dataset overload, match on ``(class, method)`` alone so a
    signature-parser edge case can't drop a real hit; with multiple overloads,
    require the simple-param-type lists to agree so the specific gated overload is
    the one actually referenced.
    """
    return single_overload or _dalvik_param_types(ref.proto) == types


def dangerous_permission_apis(
    dk: DexKit, *, dataset_path: str | None = None
) -> dict[str, list[str]]:
    """Return the dangerous-permission framework APIs this APK actually references.

    For each dangerous permission whose gated APIs appear among the APK's external
    method refs, return the list of those used APIs as full signatures
    (``pkg.Class#method(params)``). A permission with no referenced API is omitted —
    this reflects real API usage, not ``<uses-permission>`` declarations.

    Args:
        dk: A loaded ``dexllm.DexKit`` instance.
        dataset_path: Optional directory of the full AOSP dataset to override the
            bundled table (else ``$DEXLLM_AOSP_DATASET``, else bundled).

    Returns:
        ``{permission: [used api signature, ...]}``, each list sorted, only
        non-empty perms.
    """
    table = _load_dangerous_map(dataset_path)
    index = _external_method_index(dk)
    overloads = _overload_counts(table)
    result: dict[str, list[str]] = {}
    for perm, sigs in table.items():
        used: list[str] = []
        for sig in sigs:
            cls, method, types = _parse_api(sig)
            if types is None:
                continue
            refs = index.get((cls, method))
            if not refs:
                continue
            single = overloads.get((cls, method), 0) <= 1
            if any(_ref_matches(r, types, single) for r in refs):
                used.append(sig)
        if used:
            result[perm] = sorted(used)
    return result


def dangerous_permission_api_callers(
    dk: DexKit, *, dataset_path: str | None = None, app_only: bool = True
) -> dict[str, list[dict[str, Any]]]:
    """Return the dangerous-permission APIs this APK uses, each with its callers.

    Like :func:`dangerous_permission_apis` but resolves every used API to its full
    Dalvik descriptor(s) and the methods that invoke it (the "who in the code uses
    this permission" view). Overloads are disambiguated as in
    :func:`dangerous_permission_apis`, so only the referenced overload's call sites
    are attributed.

    Args:
        dk: A loaded ``dexllm.DexKit`` instance.
        dataset_path: Optional dataset override (see :func:`dangerous_permission_apis`).
        app_only: When True (default), drop callers that are bundled framework /
            official-library code (``androidx.*``, ``android.support.*``, ``kotlin.*``,
            ``com.google.android.*``, …) — such a call is library plumbing, not the
            app's own behaviour. Set False to keep every caller. An API whose only
            callers are framework code is omitted under ``app_only``.

    Returns:
        ``{permission: [{"api", "descriptors", "callers"}, ...]}`` — ``api`` is the
        full signature, ``descriptors`` the resolved ``Lcls;->name(proto)ret`` forms
        of the matched overload, ``callers`` the distinct caller method descriptors.
        Only perms/APIs with ≥1 (kept) caller are included.
    """
    table = _load_dangerous_map(dataset_path)
    index = _external_method_index(dk)
    overloads = _overload_counts(table)
    result: dict[str, list[dict[str, Any]]] = {}
    for perm, sigs in table.items():
        rows: list[dict[str, Any]] = []
        for sig in sigs:
            cls, method, types = _parse_api(sig)
            if types is None:
                continue
            refs = index.get((cls, method))
            if not refs:
                continue
            single = overloads.get((cls, method), 0) <= 1
            matched = [r for r in refs if _ref_matches(r, types, single)]
            if not matched:
                continue
            descriptors: list[str] = []
            callers: set[str] = set()
            for ref in matched:
                desc = f"{ref.class_descriptor}->{ref.name}{ref.proto}"
                descriptors.append(desc)
                for site in dk.find_call_sites_to_api(desc):
                    caller = site.caller_descriptor
                    if app_only and _is_framework_caller(caller):
                        continue
                    callers.add(caller)
            if callers:
                rows.append(
                    {
                        "api": sig,
                        "descriptors": sorted(set(descriptors)),
                        "callers": sorted(callers),
                    }
                )
        if rows:
            result[perm] = rows
    return result
