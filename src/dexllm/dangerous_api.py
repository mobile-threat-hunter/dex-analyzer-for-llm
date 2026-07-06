"""Map an APK's referenced framework APIs back to the dangerous permissions they gate.

Android's runtime-sensitive APIs carry ``@RequiresPermission`` annotations; AOSP's
permission inventory (https://github.com/mobile-threat-hunter/aosp_data_set) scrapes
those into a permission -> API map. This module joins that map against the APIs an
APK actually references (its external method refs) to answer two triage questions:

  - which **dangerous** permissions does the APK exercise *through real API calls*
    (not just `<uses-permission>` claims)? -> :func:`dangerous_permission_apis`
  - **who** in the code calls those gated APIs? -> :func:`dangerous_permission_api_callers`

The dataset entries carry the full method signature
(``android.location.LocationManager#getLastKnownLocation(String)`` — AOSP's clean
metalava-extracted form: fully-qualified types, no annotations or param names), so
overloads that differ in their permission requirement are matched precisely: arity
(param count) is the primary, parse-robust discriminator and exact simple-type
matching is the tiebreak when a ``(class, method)`` has several overloads of the same
arity; a lone overload (of its arity) matches on name alone, so a signature edge case
can never drop a real hit.

The full permission -> API table + protection-level buckets ship bundled
(``data/perm_api.json`` — all levels — + ``data/perm_levels.json``); the dangerous
slice is DERIVED from them (single source of truth). Point ``dataset_path`` (or
``$DEXLLM_AOSP_DATASET``) at a checkout of the full AOSP dataset to use a fresher
table, or regenerate the bundled files with ``scripts/gen_perm_data.py``.
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

__all__ = [
    "dangerous_permission_apis",
    "dangerous_permission_api_callers",
    "permission_api_callers",
    "PERM_LEVELS",
]

# The full permission→API surface + its protection levels (issue #14). The
# dangerous slice is DERIVED from these (a `dangerous` filter), so there is one
# bundled source of truth, not a separate committed dangerous file.
_BUNDLED_PERM_API = Path(__file__).parent / "data" / "perm_api.json"
_BUNDLED_PERM_LEVELS = Path(__file__).parent / "data" / "perm_levels.json"

# Canonical protection-level buckets (Android's raw protectionLevel is a
# `base|flag|flag` string; we bucket by base). Order = the web panel's grouping.
PERM_LEVELS = ("dangerous", "signature", "internal", "normal", "other")


def _level_bucket(raw: str) -> str:
    """Bucket a raw AOSP ``protectionLevel`` (e.g. ``signature|privileged``) to a base.

    `dangerous` wins if present (matches the historical substring filter — no other
    level contains that token); then any `signature*` base, `internal`, `normal`,
    else `other` (incl. an unknown/absent level).
    """
    toks = [t.strip().lower() for t in str(raw).split("|")]
    if "dangerous" in toks:
        return "dangerous"
    if any(t.startswith("signature") for t in toks):
        return "signature"
    if "internal" in toks:
        return "internal"
    if "normal" in toks:
        return "normal"
    return "other"


# A dataset entry is `pkg.Class#member`, optionally followed by a `(signature)` that
# runs to the end. Anchored so a malformed scrape (e.g. a stray Kotlin source line
# `MediaSessions#val mediaRouter2: ... = if (Flags...`) — member name followed by
# junk rather than `(` or end — is rejected instead of stored and later mis-parsed.
_REF = re.compile(r"^[\w.$]+#[A-Za-z_$][\w$]*(\(.*\))?$")

# The AOSP runtime-enforcement bridge (runtime_perm_api_by_perm.json) records a
# public API by param COUNT, not types: `Class#method(Nargs)`. We represent each
# such param as this sentinel — a token no real Dalvik simple type equals. It only
# supplies the ARITY: _ref_matches consults it purely to disambiguate a genuine
# MULTI-overload method (an ambiguous same-arity overload is skipped, since the
# sentinel never compares equal to a real type — fail-closed, never mis-matched). A
# LONE runtime method matches on name alone (the `total<=1` short-circuit — the same
# recall-over-precision behaviour metalava's lone full-typed overloads already have),
# so its declared arity is not a gate. Printable ASCII + not a codegen-blob delimiter.
_ARITY_ONLY = "*"
_ARITY_ONLY_RE = re.compile(r"\s*(\d+)args\s*")
_MAX_ARITY = 256  # Dalvik caps a method at 255 args; a larger N is malformed → inert

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


# Kotlin primitive/type aliases -> the Java/Dalvik name a Kotlin source signature
# compiles to, so a Kotlin-style dataset entry's `Int` compares equal to the dex
# proto's `int` (`I`). Only consulted as a same-arity-overload tiebreak.
_KOTLIN_ALIASES = {
    "Int": "int",
    "Long": "long",
    "Short": "short",
    "Byte": "byte",
    "Char": "char",
    "Boolean": "boolean",
    "Float": "float",
    "Double": "double",
    "Unit": "void",
    "Any": "Object",
}


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


# `@Foo`, `@Foo(...)`, `@pkg.Outer.Foo (...)` — a parameter annotation (the name may
# be dotted/qualified), optionally with a (non-nested) argument list. Stripped whole
# so its inner `=`/`,` can't leak into the type or be miscounted as a param separator.
_ANNOTATION = re.compile(r"@[\w.]+\s*(\([^()]*\))?")


def _split_top_level(params: str) -> list[str]:
    """Split a parameter list on top-level commas (respecting <>, (), [] nesting)."""
    parts: list[str] = []
    depth = 0
    cur = ""
    for ch in params:
        if ch in "<([":
            depth += 1
        elif ch in ">)]":
            depth = max(0, depth - 1)
        if ch == "," and depth == 0:
            parts.append(cur)
            cur = ""
        else:
            cur += ch
    if cur.strip():
        parts.append(cur)
    return parts


def _param_simple(param: str) -> str:
    """One param decl -> simple type. Annotations are already stripped upstream.

    Handles both Java order (`Consumer<Location> cb`) and Kotlin order
    (`cb: Consumer<Location>`), generics, arrays and varargs.
    """
    # Erase generics FIRST — a wildcard like `<? extends X>` contains spaces that
    # would otherwise be mistaken for a `Type name` boundary (metalava types carry
    # no param name, so the last whitespace token must NOT be dropped for them).
    p = re.sub(r"<.*>", "", param).strip()
    # Count + strip array markers wherever they sit — `int[] x`, `int x[]` (C-style),
    # and varargs `int...` all denote an array and the brackets can attach to the
    # type OR the (raw-fallback) param name.
    dims = p.count("[]") + (1 if "..." in p else 0)
    p = p.replace("[]", " ").replace("...", " ").strip()
    if ":" in p:
        # Kotlin `name: Type` — the type is after the (last top-level) colon.
        type_str = p.rsplit(":", 1)[-1].strip()
    else:
        toks = [t for t in p.split() if t not in _JAVA_MODIFIERS]
        if not toks:
            return ""
        # Java `Type name` -> drop the trailing param name; a bare metalava type is
        # a single token and is kept as-is.
        type_str = " ".join(toks[:-1]) if len(toks) >= 2 else toks[0]
    type_str = type_str.rstrip("?").strip()  # Kotlin nullable `String?` -> String
    base = _simple_name(type_str)
    return _KOTLIN_ALIASES.get(base, base) + "[]" * dims


def _parse_api(entry: str) -> tuple[str, str, tuple[str, ...] | None]:
    """``pkg.Class#method(params)`` -> ``(class, method, simple-param-types)``.

    Param types are None for a field/constant entry (no ``(...)``) — those can
    never match a method-call reference.
    """
    cls, _, rest = entry.partition("#")
    cls = cls.replace("$", ".")  # canonicalise inner-class sep to match the dex side
    open_p = rest.find("(")
    close_p = rest.rfind(")")
    if open_p < 0 or close_p < open_p:
        # No balanced `(...)` — a field/constant (or malformed entry); not a call.
        return cls, rest, None
    name = rest[:open_p]
    # NOTE: a constructor entry `Class#SimpleName(...)` keeps its literal name here;
    # _external_method_index aliases the dex `<init>` ref under the class simple name
    # so they match. We deliberately do NOT rewrite name to `<init>` — that would
    # make a static method coincidentally named like its class miss its real ref.
    # Strip annotations (incl their `(...)` args) FIRST so an annotation's inner
    # `=`/`,` can't leak into a type or be miscounted as a parameter separator.
    params = _ANNOTATION.sub(" ", rest[open_p + 1 : close_p])
    if not params.strip():
        return cls, name, ()
    # Runtime-enforcement bridge sig `method(Nargs)` — arity only, no types. Emit N
    # sentinels so arity matches but a real type never does (see _ARITY_ONLY). N is
    # capped (a >255-arg method can't exist in Dalvik, so a larger N never matches a
    # real ref and the cap just bounds the allocation against a malformed dataset).
    m = _ARITY_ONLY_RE.fullmatch(params)
    if m:
        return cls, name, (_ARITY_ONLY,) * min(int(m.group(1)), _MAX_ARITY)
    return cls, name, tuple(_param_simple(p) for p in _split_top_level(params))


def _resolve_root(dataset_path: str | None) -> str:
    """Resolve the dataset root (explicit arg, then env, then bundled ``""``)."""
    return dataset_path or os.environ.get("DEXLLM_AOSP_DATASET") or ""


@lru_cache(maxsize=8)
def _load_perm_api_map_cached(root: str) -> dict[str, tuple[str, ...]]:
    """Return the full permission -> API map (all protection levels), cached by root.

    ``root == ""`` reads the bundled ``perm_api.json``; otherwise the full metalava
    table at ``root`` is read and each perm's APIs filtered to real member refs.
    """
    if not root:
        raw = json.loads(_BUNDLED_PERM_API.read_text())
        return {perm: tuple(apis) for perm, apis in raw.items()}

    base = Path(root)
    # Prefer the metalava-extracted table (clean canonical signatures); fall back
    # to the raw scrape for older dataset checkouts.
    api_file = base / "perm_api_metalava_by_perm.json"
    if not api_file.is_file():
        api_file = base / "perm_api_by_perm.json"
    if not api_file.is_file():
        raise FileNotFoundError(
            f"AOSP dataset at {root!r} must contain "
            f"perm_api_metalava_by_perm.json (or perm_api_by_perm.json)"
        )
    table = json.loads(api_file.read_text())
    if not isinstance(table, dict):
        raise ValueError(
            f"{api_file} must be a JSON object mapping permission -> [apis]"
        )
    out: dict[str, tuple[str, ...]] = {}
    for perm in sorted(table):
        refs = sorted({r for r in table[perm] if _REF.match(r)})
        if refs:
            out[perm] = tuple(refs)
    return out


@lru_cache(maxsize=8)
def _load_perm_levels_cached(root: str) -> dict[str, str]:
    """Permission -> canonical protection-level bucket, cached by root.

    ``root == ""`` reads the bundled ``perm_levels.json``; otherwise it is computed
    from the dataset's ``permissions.json`` protectionLevel via :func:`_level_bucket`.
    """
    if not root:
        return dict(json.loads(_BUNDLED_PERM_LEVELS.read_text()))
    perm_file = Path(root) / "permissions.json"
    if not perm_file.is_file():
        raise FileNotFoundError(
            f"AOSP dataset at {root!r} must contain permissions.json"
        )
    perms = json.loads(perm_file.read_text())
    if not isinstance(perms, list):
        raise ValueError(f"{perm_file} must be a JSON list of permission entries")
    return {
        p["name"]: _level_bucket(p.get("protectionLevel", ""))
        for p in perms
        if isinstance(p, dict) and "name" in p
    }


def _load_dangerous_map(dataset_path: str | None) -> dict[str, tuple[str, ...]]:
    """Return the dangerous-permission -> API map (dangerous slice of the full table).

    Derived from the full map + level buckets (single source of truth), so no
    separate dangerous file is committed. Honours ``dataset_path`` /
    ``$DEXLLM_AOSP_DATASET`` (else bundled).
    """
    root = _resolve_root(dataset_path)
    full = _load_perm_api_map_cached(root)
    levels = _load_perm_levels_cached(root)
    return {p: full[p] for p in full if levels.get(p) == "dangerous"}


def _load_full_map(dataset_path: str | None) -> dict[str, tuple[str, ...]]:
    """Return the full permission -> API map (all levels)."""
    return _load_perm_api_map_cached(_resolve_root(dataset_path))


def _load_levels(dataset_path: str | None) -> dict[str, str]:
    """Return the permission -> level bucket map."""
    return _load_perm_levels_cached(_resolve_root(dataset_path))


def _external_method_index(dk: DexKit) -> dict[tuple[str, str], list[Any]]:
    """Index the APK's external method refs by ``(java_class, method_name)``."""
    idx: dict[tuple[str, str], list[Any]] = {}
    for ref in dk.list_external_method_refs(False):
        # canonicalise inner-class `$` -> `.` to match _parse_api's class key.
        cls = ref.java_class.replace("$", ".")
        idx.setdefault((cls, ref.name), []).append(ref)
        # The dataset writes a constructor as `Class#SimpleName(...)` (the dex
        # ref name is `<init>`). Alias each ctor ref under the class simple name
        # so that dataset key matches without rewriting the dataset side.
        if ref.name == "<init>":
            idx.setdefault((cls, cls.rsplit(".", 1)[-1]), []).append(ref)
    return idx


def _overload_index(
    table: dict[str, tuple[str, ...]],
) -> dict[tuple[str, str], dict[int, int]]:
    """``{(class, method): {arity: #distinct overloads of that arity}}``.

    Drives the ambiguity check: a method with one overload — or one overload of a
    given arity — needs no signature parsing to disambiguate.
    """
    # Dedup by the full signature STRING, not the reduced simple-type tuple: two
    # distinct overloads can reduce to the same simple tuple (e.g. java.util.Date
    # vs java.sql.Date -> ('Date',)). Counting tuples would collapse them to one,
    # wrongly firing the single-overload short-circuit in _ref_matches and matching
    # any same-arity call. (A signature may repeat across perms via anyOf — the set
    # of strings dedups those correctly.)
    seen: dict[tuple[str, str], set[str]] = {}
    for sigs in table.values():
        for sig in sigs:
            cls, method, types = _parse_api(sig)
            if types is None:
                continue
            seen.setdefault((cls, method), set()).add(sig)
    out: dict[tuple[str, str], dict[int, int]] = {}
    for cm, sig_set in seen.items():
        arity: dict[int, int] = {}
        for sig in sig_set:
            n = len(_parse_api(sig)[2] or ())
            arity[n] = arity.get(n, 0) + 1
        out[cm] = arity
    return out


def _ref_matches(ref: Any, types: tuple[str, ...], arity_map: dict[int, int]) -> bool:
    """Whether a dex ref realises the dataset signature `types`.

    Arity (parameter count) is the primary, parse-robust discriminator; exact
    simple-type matching is only the tiebreak when the method has more than one
    overload of the same arity. A lone overload (or a lone overload of this arity)
    matches on arity alone, so a signature-parser edge case can't drop a real hit.
    """
    total = sum(arity_map.values())
    if total <= 1:
        return True  # single overload: name match is unambiguous
    ref_types = _dalvik_param_types(ref.proto)
    if len(ref_types) != len(types):
        return False  # different arity → different overload
    if arity_map.get(len(types), 0) <= 1:
        return True  # unique arity among the overloads — types need not be parsed
    return ref_types == types


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
    # Overload disambiguation uses the FULL table's overload set — an overload set is
    # a property of the (class, method), so knowing every overload (not just those
    # under a dangerous perm) is strictly more precise, and keeps this consistent with
    # permission_api_callers filtered to dangerous. Corpus-neutral on real APKs.
    overloads = _overload_index(_load_full_map(dataset_path))
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
            arity_map = overloads.get((cls, method), {})
            if any(_ref_matches(r, types, arity_map) for r in refs):
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
    # Full-table overload set (see dangerous_permission_apis) — consistent with
    # permission_api_callers(levels={"dangerous"}); corpus-neutral on real APKs.
    overloads = _overload_index(_load_full_map(dataset_path))
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
            arity_map = overloads.get((cls, method), {})
            matched = [r for r in refs if _ref_matches(r, types, arity_map)]
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


def _rows_for_perm(
    dk: DexKit,
    sigs: tuple[str, ...],
    index: dict[tuple[str, str], list[Any]],
    overloads: dict[tuple[str, str], dict[int, int]],
    app_only: bool,
) -> list[dict[str, Any]]:
    """Resolve one permission's used APIs to ``[{api, descriptors, callers}]`` rows.

    The shared join used by :func:`dangerous_permission_api_callers` and
    :func:`permission_api_callers` — overload-disambiguated matching, then the
    distinct callers of each matched overload (framework callers dropped under
    ``app_only``). Only APIs with ≥1 kept caller yield a row.
    """
    rows: list[dict[str, Any]] = []
    for sig in sigs:
        cls, method, types = _parse_api(sig)
        if types is None:
            continue
        refs = index.get((cls, method))
        if not refs:
            continue
        arity_map = overloads.get((cls, method), {})
        matched = [r for r in refs if _ref_matches(r, types, arity_map)]
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
    return rows


def permission_api_callers(
    dk: DexKit,
    *,
    app_only: bool = True,
    levels: "set[str] | None" = None,
    dataset_path: str | None = None,
) -> list[dict[str, Any]]:
    """Return every permission's used APIs + callers, across ALL protection levels.

    The full-surface generalisation of :func:`dangerous_permission_api_callers`
    (issue #14): it joins the **full** AOSP permission→API table (not just the
    dangerous slice) against the APK's references and returns each permission group
    with its real ``protectionLevel`` bucket (see :data:`PERM_LEVELS`).

    Args:
        dk: A loaded ``dexllm.DexKit`` instance.
        app_only: Drop framework/library callers (as in the dangerous variant).
        levels: If given, keep only permissions whose level bucket is in this set
            (e.g. ``{"dangerous", "signature"}``); ``None`` = all levels.
        dataset_path: Optional dataset override (else ``$DEXLLM_AOSP_DATASET``, else
            bundled).

    Returns:
        A list of ``{"perm", "protectionLevel", "rows": [{"api", "descriptors",
        "callers"}]}`` sorted by permission — the same shape the C++ / WASM
        ``permission_callers`` binding returns. Only perms/APIs with ≥1 kept caller.
    """
    table = _load_full_map(dataset_path)
    level_map = _load_levels(dataset_path)
    index = _external_method_index(dk)
    overloads = _overload_index(table)
    want = set(levels) if levels is not None else None
    result: list[dict[str, Any]] = []
    for perm in table:  # bundled perm_api.json is sorted by permission
        lvl = level_map.get(perm, "other")
        if want is not None and lvl not in want:
            continue
        rows = _rows_for_perm(dk, table[perm], index, overloads, app_only)
        if rows:
            result.append({"perm": perm, "protectionLevel": lvl, "rows": rows})
    return result
