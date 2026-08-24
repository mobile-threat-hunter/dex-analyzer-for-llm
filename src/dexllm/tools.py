"""LLM-friendly tool surface over dexllm.

This module is the single source of truth for the dexkit analysis tools
exposed to an LLM (Claude, etc.). Both the MCP server and the FastAPI
backend import from here.

Each tool has three parts:
  1. A JSON-Schema dict (Anthropic API / MCP format) under TOOL_DEFINITIONS
  2. A pure Python executor `execute(name, args, dk) -> dict`
  3. LLM-friendly serialization — pagination, truncation, structured output

Design notes
------------
- All list-returning tools accept `offset` / `limit` and report `total`
  + `next_offset` so the LLM can paginate without blowing context.
- All decompile tools accept `max_chars` (default 4000) and report
  `truncated` + `full_chars` so the LLM can request more if needed.
- All decompile calls go through `safe_decompile_*` wrappers with a
  10s deadline. A hung method emits a `// TIMEOUT` marker but the call
  always returns.
- ClassMatch / MethodMatch result objects are reduced to descriptor
  strings + a few useful fields. The LLM rarely needs the full object.
- The caller is responsible for opening / caching the `DexKit` instance.
  Tools that touch the APK take a `DexKit` object via the `dk` param to
  `execute`. The `apk_path` field in tool schemas is the user-facing
  reference the LLM uses to disambiguate; the transport (MCP / FastAPI)
  maps it to a DexKit instance.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any, Callable

from ._argkinds import ARG_VALUE_ATTR_BY_KIND
from .descriptors import require_member_descriptor, require_type_descriptor
from .safe import (
    DEFAULT_TIMEOUT_S,
    is_timeout_marker,
    safe_decompile_class,
    safe_decompile_method,
)

if TYPE_CHECKING:
    from ._dexkit_core import DexKit

DEFAULT_LIST_LIMIT = 100
DEFAULT_DECOMPILE_CHARS = 4000
DEFAULT_CLASS_CHARS = 8000


# ─── Serialization helpers ────────────────────────────────────────────────


def _paginate(items: list, offset: int = 0, limit: int = DEFAULT_LIST_LIMIT) -> dict:
    """Build the standard list-response shape for tools.

    `offset` is clamped to [0, total] and `limit` to >= 1 so a caller can never
    poison `next_offset` (negative offset, or limit=0 -> next_offset==offset,
    which would loop forever).
    """
    total = len(items)
    offset = max(0, min(int(offset), total))
    limit = max(1, int(limit))
    end = min(offset + limit, total)
    return {
        "total": total,
        "offset": offset,
        "limit": limit,
        "items": items[offset:end],
        "next_offset": end if end < total else None,
    }


def _truncate(text: str, max_chars: int) -> dict:
    """Build the standard text-response shape for decompile/render tools."""
    max_chars = max(0, int(max_chars))  # negative would drop trailing content
    full = len(text)
    if full <= max_chars:
        return {"text": text, "truncated": False, "full_chars": full}
    return {
        "text": text[:max_chars]
        + f"\n// ... TRUNCATED ({full - max_chars} more chars; pass max_chars=N for more)",
        "truncated": True,
        "full_chars": full,
    }


def _match_to_desc(m: Any) -> str:
    """ClassMatch / MethodMatch → just the descriptor string the LLM cares about."""
    if hasattr(m, "descriptor"):
        return m.descriptor
    if hasattr(m, "class_name"):
        return m.class_name
    return str(m)


def _filter_pattern(items: list[str], pattern: str | None) -> list[str]:
    """Filter `items` by DexKit-style SimilarRegex, not a full regex engine.

    The SAME semantics as the tool surface's ``match_type='regex'``.
    Mirrors the core's ``ConvertSimilarRegex`` (dex_item_matcher.cpp): only the
    ``^`` (prefix) and ``$`` (suffix) anchors are meaningful, the rest of the
    pattern is a LITERAL substring — ``^X`` startswith, ``X$`` endswith, ``^X$``
    equals, else ``X`` contains. There is no backtracking engine, so a
    catastrophic pattern like ``(.*)*Z`` is just a literal substring search
    (finds nothing, no match) — ReDoS is impossible by construction, and the
    filter behaves consistently with `find_classes_by_name(match_type='regex')`.
    """
    if not pattern:
        return items
    anchor_start = pattern.startswith("^")
    anchor_end = pattern.endswith("$")
    core = pattern[1 if anchor_start else 0 : len(pattern) - 1 if anchor_end else None]
    if anchor_start and anchor_end:
        return [x for x in items if x == core]
    if anchor_start:
        return [x for x in items if x.startswith(core)]
    if anchor_end:
        return [x for x in items if x.endswith(core)]
    return [x for x in items if core in x]


# ─── Tool implementations ─────────────────────────────────────────────────
# Each impl takes (dk: DexKit, **args) and returns a JSON-serialisable dict.


def _t_list_classes(
    dk: DexKit,
    pattern: str | None = None,
    offset: int = 0,
    limit: int = DEFAULT_LIST_LIMIT,
) -> dict:
    items = _filter_pattern(dk.list_classes(), pattern)
    return _paginate(items, offset, limit)


def _t_list_class_methods(dk: DexKit, class_descriptor: str) -> dict:
    require_type_descriptor(class_descriptor)
    return {
        "class": class_descriptor,
        "methods": dk.list_class_methods(class_descriptor),
    }


def _t_decompile_method(
    dk: DexKit, method_descriptor: str, max_chars: int = DEFAULT_DECOMPILE_CHARS
) -> dict:
    require_member_descriptor(method_descriptor)
    out = safe_decompile_method(dk, method_descriptor, timeout=DEFAULT_TIMEOUT_S)
    if is_timeout_marker(out):
        return {"descriptor": method_descriptor, "error": "timeout", "text": out}
    return {"descriptor": method_descriptor, **_truncate(out, max_chars)}


def _t_decompile_class(
    dk: DexKit, class_descriptor: str, max_chars: int = DEFAULT_CLASS_CHARS
) -> dict:
    require_type_descriptor(class_descriptor)
    out = safe_decompile_class(dk, class_descriptor, timeout=DEFAULT_TIMEOUT_S)
    if is_timeout_marker(out):
        return {"descriptor": class_descriptor, "error": "timeout", "text": out}
    return {"descriptor": class_descriptor, **_truncate(out, max_chars)}


def _t_find_classes_by_name(
    dk: DexKit,
    name: str,
    match_type: str = "contains",
    ignore_case: bool = False,
    limit: int = 50,
    offset: int = 0,
) -> dict:
    hits = dk.find_classes_by_name(name, match_type=match_type, ignore_case=ignore_case)
    items = [_match_to_desc(h) for h in hits]
    return _paginate(items, offset, limit)


def _t_find_classes_by_super(
    dk: DexKit,
    super_class: str,
    match_type: str = "equals",
    limit: int = 50,
    offset: int = 0,
) -> dict:
    hits = dk.find_classes_by_super(super_class, match_type=match_type)
    return _paginate([_match_to_desc(h) for h in hits], offset, limit)


def _t_find_classes_implementing(
    dk: DexKit,
    interface_class: str,
    match_type: str = "equals",
    limit: int = 50,
    offset: int = 0,
) -> dict:
    hits = dk.find_classes_implementing(interface_class, match_type=match_type)
    return _paginate([_match_to_desc(h) for h in hits], offset, limit)


def _t_find_classes_by_annotation(
    dk: DexKit,
    annotation_class: str,
    match_type: str = "equals",
    limit: int = 50,
    offset: int = 0,
) -> dict:
    hits = dk.find_classes_by_annotation(annotation_class, match_type=match_type)
    return _paginate([_match_to_desc(h) for h in hits], offset, limit)


def _t_find_classes_using_strings(
    dk: DexKit,
    strings: list[str],
    match_type: str = "contains",
    ignore_case: bool = False,
    limit: int = 50,
    offset: int = 0,
) -> dict:
    hits = dk.find_classes_using_strings(
        strings, match_type=match_type, ignore_case=ignore_case
    )
    return _paginate([_match_to_desc(h) for h in hits], offset, limit)


def _t_find_classes_declaring_strings(
    dk: DexKit,
    strings: list[str],
    match_type: str = "contains",
    ignore_case: bool = False,
    limit: int = 50,
    offset: int = 0,
) -> dict:
    """Classes that DECLARE the strings as static-field constants (dexllm#20)."""
    hits = dk.find_classes_declaring_strings(
        strings, match_type=match_type, ignore_case=ignore_case
    )
    return _paginate([_match_to_desc(h) for h in hits], offset, limit)


def _t_find_methods_by_name(
    dk: DexKit,
    name: str,
    match_type: str = "contains",
    declaring_class: str = "",
    ignore_case: bool = False,
    limit: int = 50,
    offset: int = 0,
) -> dict:
    hits = dk.find_methods_by_name(
        name,
        match_type=match_type,
        declaring_class=declaring_class,
        ignore_case=ignore_case,
    )
    return _paginate([_match_to_desc(h) for h in hits], offset, limit)


def _t_find_fields_by_name(
    dk: DexKit,
    name: str,
    match_type: str = "contains",
    declaring_class: str = "",
    ignore_case: bool = False,
    limit: int = 50,
    offset: int = 0,
) -> dict:
    hits = dk.find_fields_by_name(
        name,
        match_type=match_type,
        declaring_class=declaring_class,
        ignore_case=ignore_case,
    )
    return _paginate([_match_to_desc(h) for h in hits], offset, limit)


def _t_find_methods_using_strings(
    dk: DexKit,
    strings: list[str],
    match_type: str = "contains",
    ignore_case: bool = False,
    limit: int = 50,
    offset: int = 0,
) -> dict:
    hits = dk.find_methods_using_strings(
        strings, match_type=match_type, ignore_case=ignore_case
    )
    return _paginate([_match_to_desc(h) for h in hits], offset, limit)


def _t_find_call_sites_to(
    dk: DexKit, method_descriptor: str, limit: int = 50, offset: int = 0
) -> dict:
    require_member_descriptor(method_descriptor)
    sites = dk.find_call_sites_to(method_descriptor)
    items = []
    for s in sites:
        items.append(
            {
                "caller": s.caller_descriptor,
                "callee": s.callee_descriptor,
                "bytecode_offset": s.bytecode_offset,
            }
        )
    return _paginate(items, offset, limit)


def _dex_name_map(dk: DexKit) -> dict[int, str]:
    """Map each LOADED dex_id to its file name (``classes.dex`` / …) via verify_report.

    A dex that failed structural verification is reported by verify_report with
    ``dex_id == -1`` — the SAME sentinel an external (referenced-but-not-declared) class
    carries. So the map excludes ``dex_id < 0`` entries; a lookup for an external class
    then correctly misses (→ None / "") instead of picking up a rejected dex's name.
    """
    return {r["dex_id"]: r["name"] for r in dk.verify_report() if r["dex_id"] >= 0}


def _t_get_class_summary(dk: DexKit, class_descriptor: str) -> dict:
    require_type_descriptor(class_descriptor)
    s = dk.get_class_summary(class_descriptor)
    return {
        "descriptor": class_descriptor,
        "dex_id": s.dex_id,
        "dex_name": _dex_name_map(dk).get(s.dex_id) or None,
        "superclass": s.superclass_descriptor or None,
        "interfaces": list(s.interface_descriptors),
        "method_count": len(list(s.methods)),
        "field_count": len(list(s.fields)),
        "access_flags": s.access_flags,
    }


def _t_render_method_smali(
    dk: DexKit, method_descriptor: str, max_chars: int = DEFAULT_DECOMPILE_CHARS
) -> dict:
    require_member_descriptor(method_descriptor)
    out = dk.render_method_smali(method_descriptor)
    return {"descriptor": method_descriptor, **_truncate(out, max_chars)}


def _t_summarize_capabilities(
    dk: DexKit, limit: int = 50, app_only: bool = True
) -> dict:
    """Bounded, LLM-friendly capability summary.

    Returns top permissions/categories, the cross-domain `flags` rollup, and the
    `limit` most-TOUCHED APIs (invoke sites plus field reads, dexllm#36). The raw report's per-caller sets (`by_caller`,
    `ApiHit.callers`) can be huge on a large APK, so they are intentionally
    omitted here to keep the response within the model's context.

    `app_only` (default True) counts only the app's own callers — without it the
    numbers largely measure which libraries the APK bundles (dexllm#49). Since
    the per-caller sets are omitted here, this tool alone cannot show WHO called
    an API, so a model that needs the library view asks for `app_only=False` and
    compares. `dropped_touches` / `dropped_apis` say what the filter removed, so
    an all-zero payload is readable as "only libraries do this" rather than as
    "this APK does none of it".

    `categories` is one axis (domain / behaviour), so one call site is never
    counted twice under two names for the same concern — an API that genuinely
    spans two domains does count once in each. `flags` is the orthogonal axis a
    domain tag cannot express (today only `IDENTIFIER` — the API provably returns
    a device/user identifier), and it rolls up across domains, so it answers
    "does this app harvest identifiers" in a way no single category can.
    """
    from .capability import summarize_capabilities

    # Coerced, and it is the COERCED value that is echoed below. `app_only` is
    # advertised as a boolean and mcp validates an advertised tool's arguments,
    # but `execute` is also the in-process dispatcher for the HTTP / agent loop
    # and validates nothing — so a model's `"false"` (a common JSON-boolean slip)
    # arrives as a truthy string, filters, and would otherwise be echoed back
    # verbatim: the payload would AFFIRM the wrong belief, which is the one thing
    # the echo exists to prevent. The sibling `limit` is coerced two lines down
    # for the same reason.
    app_only = bool(app_only)
    rep = summarize_capabilities(dk, app_only=app_only)
    limit = max(1, int(limit))
    # …by TOUCHES, so a field entry ranks by the count it actually fills. Sorting
    # on `call_site_count` alone would sink every field entry to the bottom with a
    # 0 it is not supposed to have (dexllm#36).
    # A TOTAL order: touches descending, then signature. `sorted` is stable, so
    # without the tie-break the ranking followed `entries` iteration order — and
    # re-serialising the catalog (as dexllm#36 did) silently reordered `top_apis`
    # on 16 of 32 corpus sources without any count changing.
    hits = sorted(
        rep.api_hits,
        key=lambda h: (-(h.call_site_count + h.field_access_count), h.api_descriptor),
    )
    return {
        # Echoed, because every count below depends on it and the per-caller sets
        # that would reveal the mode are omitted here — a model comparing two
        # sessions' numbers must be able to see it was not comparing two modes.
        "app_only": app_only,
        # …and WHAT IT COST. Without these an all-zero payload is byte-identical
        # to "this APK exercises none of the catalog", and the caller sets that
        # would otherwise reveal the difference are omitted here to bound
        # context. On the corpus 11 of the 17 sources that report anything at all
        # report nothing under the default — and the system prompt tells the
        # model to start here to orient, so a bare zero is the worst answer.
        "dropped_touches": rep.dropped_touches,
        "dropped_apis": rep.dropped_apis,
        "total_call_sites": rep.total_call_sites,
        # Separate, not folded into the line above: a call site is an invoke
        # instruction and a field access is a reading method (dexllm#36).
        "total_field_accesses": rep.total_field_accesses,
        "matched_apis": rep.matched_apis,
        "catalog_size": rep.catalog_size,
        # The tag vocabulary is versioned and has changed (0.2 normalised it), so a
        # model that learned the old names needs the signal that it did.
        "catalog_version": rep.catalog_version,
        "top_permissions": rep.top_permissions(20),
        "top_categories": rep.top_categories(20),
        "flags": dict(rep.flags),
        # `descriptor`, NOT `api`: the sibling `dangerous_permission_api_callers`
        # tool already spells `api` for the AOSP DATASET form
        # (`android.location.LocationManager#getLastKnownLocation(String)`) and
        # spells the Dalvik form `descriptors` in the same dict. One key, two
        # grammars, on the surface an LLM reads — the dexllm#38 shape, reached
        # through the `api_signature` spelling this issue removed (dexllm#68).
        "api_hits": [
            {
                "descriptor": h.api_descriptor,
                "permissions": h.permissions,
                "categories": h.categories,
                "flags": h.flags,
                "call_sites": h.call_site_count,
                "field_accesses": h.field_access_count,
            }
            for h in hits[:limit]
        ],
        "api_hits_total": len(rep.api_hits),
        "api_hits_truncated": len(rep.api_hits) > limit,
    }


def _t_extract_iocs(
    dk: DexKit,
    with_xref: bool = True,
    xref_limit: int = 300,
) -> dict:
    """Extract static network indicators (C2 / IOC) from the app's dex value-strings.

    Recovers the URLs, IPs, domains, emails, and onion addresses embedded in the
    app's dex value-strings — the VirusTotal "contacted addresses" view, but static
    and with each indicator tied to its location (when with_xref).

    Each row is ``{value, methods, declared_in}``. ``methods`` are the call sites that
    LOAD the indicator; ``declared_in`` are the classes that DECLARE it as a
    static-field constant. An indicator kept only as a constant is loaded by no code,
    so ``methods`` is EMPTY and ``declared_in`` is its only location — do not read an
    empty ``methods`` as "this indicator is not used anywhere".
    """
    from .ioc import IOC_CATEGORIES, extract_iocs

    iocs = extract_iocs(
        dk,
        with_xref=with_xref,
        xref_limit=int(xref_limit),
    )
    return {
        "indicators": iocs,
        "counts": {cat: len(iocs[cat]) for cat in IOC_CATEGORIES},
    }


def _t_dangerous_permission_apis(dk: DexKit) -> dict:
    """Dangerous-permission framework APIs the APK actually references.

    Joins the AOSP @RequiresPermission permission->API map against the APK's
    external method refs: which dangerous permissions are exercised through real
    API calls (stronger than a <uses-permission> declaration).
    """
    from .dangerous_api import dangerous_permission_apis

    apis = dangerous_permission_apis(dk)
    return {
        "permissions": apis,
        "counts": {perm: len(v) for perm, v in apis.items()},
    }


def _t_dangerous_permission_api_callers(dk: DexKit, app_only: bool = True) -> dict:
    """Dangerous-permission APIs the APK uses, each with the methods that call them."""
    from .dangerous_api import dangerous_permission_api_callers

    return {"permissions": dangerous_permission_api_callers(dk, app_only=app_only)}


# ─── xref / dataflow / literal tools ──────────────────────────────────────


def _arg_to_compact(index: int, a: Any) -> dict:
    """One ArgOrigin → a compact ``{index, kind, value}`` dict.

    The resolved constant / field descriptor / callee descriptor / param-slot,
    without the raw multi-field struct.
    `index` is the position in the invoke's argument list: for an INSTANCE method
    index 0 is the receiver, so a 3-param instance call's Java params sit at 1/2/3.
    `value` is the literal for a const kind; the field/method DESCRIPTOR for a
    FieldRead/MethodReturn (the value is NOT followed — that is a separate hop);
    `pN` for a Parameter; None for ConstNull/Unknown.

    An Unknown whose tracked definition a control-flow merge DISCARDED carries
    ``"crossed_branch": True``. Read it as *not proven*, not as *no value* — and not
    as a proven pair of values either: the merged edges may genuinely disagree, or one
    of them simply carried nothing because it came from outside the analysis window.
    The key is named for the raw ``ArgOrigin.crossed_branch`` it mirrors; an earlier
    ``varies_by_path`` claimed the stronger reading the flag does not support
    (dexllm#32).
    """
    try:
        # Parameter first: this view renders it as `pN`, so it does NOT read the
        # shared map's raw `parameter_index` (dexllm#68).
        if a.kind == "Parameter":
            value: Any = f"p{a.parameter_index}"
        elif (attr := ARG_VALUE_ATTR_BY_KIND.get(a.kind)) is not None:
            # A const-string / descriptor field is raw dex MUTF-8; pybind's strict
            # UTF-8 decode can raise on a surrogate-pair / embedded-null string. Keep
            # that contained to THIS arg instead of failing the whole call.
            value = getattr(a, attr)
        else:  # ConstNull, Unknown
            value = None
    except UnicodeDecodeError:
        value = "<undecodable MUTF-8>"
    out = {"index": index, "kind": a.kind, "value": value}
    if getattr(a, "crossed_branch", False):
        out["crossed_branch"] = True
    return out


def _t_resolve_call_args(
    dk: DexKit,
    method_descriptor: str,
    depth: int = 2,
    limit: int = 50,
    offset: int = 0,
) -> dict:
    require_member_descriptor(method_descriptor)
    # `depth` is int()-coerced for the same reason `limit` is: tools.execute is also
    # the in-process dispatcher for the HTTP / agent loop and validates nothing, so a
    # JSON string would otherwise reach the binding.
    sites = dk.resolve_call_args(method_descriptor, int(depth))
    items = [
        {
            "caller": s.caller_descriptor,
            "callee": s.callee_descriptor,
            "bytecode_offset": s.bytecode_offset,
            "args": [_arg_to_compact(i, a) for i, a in enumerate(s.args)],
        }
        for s in sites
    ]
    return _paginate(items, offset, limit)


def _t_find_call_sites_from(
    dk: DexKit, method_descriptor: str, limit: int = 50, offset: int = 0
) -> dict:
    require_member_descriptor(method_descriptor)
    sites = dk.find_call_sites_from(method_descriptor)
    items = [
        {
            "caller": s.caller_descriptor,
            "callee": s.callee_descriptor,
            "bytecode_offset": s.bytecode_offset,
        }
        for s in sites
    ]
    return _paginate(items, offset, limit)


def _t_find_methods_reading_field(
    dk: DexKit, field_descriptor: str, limit: int = 50, offset: int = 0
) -> dict:
    require_member_descriptor(field_descriptor)
    return _paginate(dk.find_methods_reading_field(field_descriptor), offset, limit)


def _t_find_methods_writing_field(
    dk: DexKit, field_descriptor: str, limit: int = 50, offset: int = 0
) -> dict:
    require_member_descriptor(field_descriptor)
    return _paginate(dk.find_methods_writing_field(field_descriptor), offset, limit)


def _t_find_type_references(
    dk: DexKit, type_descriptor: str, limit: int = 50, offset: int = 0
) -> dict:
    require_type_descriptor(type_descriptor)
    tr = dk.find_type_references(type_descriptor)
    limit = max(1, int(limit))
    offset = max(0, int(offset))

    def _cap(seq: Any) -> dict:
        lst = list(seq)
        end = min(offset + limit, len(lst))
        # same offset applied to each of the three lists so a high-fan-in type
        # (String/Object) stays fully page-able, not silently capped
        return {
            "total": len(lst),
            "offset": offset,
            "items": lst[offset:end],
            "next_offset": end if end < len(lst) else None,
        }

    return {
        "type": type_descriptor,
        "fields": _cap(tr.fields),
        "methods_returning": _cap(tr.methods_returning),
        "methods_with_param": _cap(tr.methods_with_param),
    }


def _t_find_methods_using_int_literals(
    dk: DexKit, values: list[int], limit: int = 50, offset: int = 0
) -> dict:
    if (
        not values
    ):  # an empty literal set matches EVERY method — not what a caller wants
        return _paginate([], offset, limit)
    hits = dk.find_methods_using_int_literals(values)
    return _paginate([_match_to_desc(h) for h in hits], offset, limit)


def _t_find_methods_using_double_literals(
    dk: DexKit, values: list[float], limit: int = 50, offset: int = 0
) -> dict:
    if not values:  # empty set would match all methods
        return _paginate([], offset, limit)
    hits = dk.find_methods_using_double_literals(values)
    return _paginate([_match_to_desc(h) for h in hits], offset, limit)


# ─── strings / smali / providers ──────────────────────────────────────────


def _t_list_value_strings(
    dk: DexKit,
    pattern: str | None = None,
    offset: int = 0,
    limit: int = DEFAULT_LIST_LIMIT,
) -> dict:
    """List the app's value-strings (const-string + static VALUE_STRING; the IOC feed).

    ``pattern`` is DexKit SimilarRegex (^prefix / suffix$ / substring); paginated.
    """
    items = _filter_pattern(dk.list_value_strings(), pattern)
    return _paginate(items, offset, limit)


def _t_list_class_strings(
    dk: DexKit,
    class_descriptor: str,
    offset: int = 0,
    limit: int = DEFAULT_LIST_LIMIT,
) -> dict:
    """List the value-strings one class carries (code const-strings + static init).

    Paginated like every other list tool — a resource-heavy `<clinit>` can carry
    tens of KB of literals, which would otherwise blow past the context budget the
    tool exists to protect.
    """
    require_type_descriptor(class_descriptor)
    return {
        "class": class_descriptor,
        **_paginate(dk.list_class_strings(class_descriptor), offset, limit),
    }


def _t_list_method_strings(
    dk: DexKit,
    method_descriptor: str,
    offset: int = 0,
    limit: int = DEFAULT_LIST_LIMIT,
) -> dict:
    """List the value-strings one method loads (its const-string operands)."""
    require_member_descriptor(method_descriptor)
    return {
        "method": method_descriptor,
        **_paginate(dk.list_method_strings(method_descriptor), offset, limit),
    }


def _t_render_class_smali(
    dk: DexKit, class_descriptor: str, max_chars: int = DEFAULT_CLASS_CHARS
) -> dict:
    require_type_descriptor(class_descriptor)
    out = dk.render_class_smali(class_descriptor)
    return {"descriptor": class_descriptor, **_truncate(out, max_chars)}


def _t_detect_content_providers(
    dk: DexKit, with_xref: bool = True, xref_limit: int = 300
) -> dict:
    from .providers import detect_content_providers

    provs = detect_content_providers(
        dk, with_xref=with_xref, xref_limit=int(xref_limit)
    )
    return {"providers": provs, "count": len(provs)}


# ─── container / verification / AST / batch ───────────────────────────────


def _t_identify(dk: DexKit) -> dict:
    """Content probe of the session's primary source, plus the loaded totals.

    Every key here means what it means on ``dexllm.identify(path)`` — including
    ``dex_count``, which is the PRIMARY SOURCE's own dex count. The loaded totals
    are separate keys that say so (dexllm#38).

    Before that, this tool overwrote ``dex_count`` with the union across all
    LOADED dexes, so one key carried two meanings depending on which layer you
    read it from: `dexllm.identify(x)` said 1 while the tool said 2. It agreed
    whenever the loader produced exactly one dex per source, which is the common
    case and why it went unnoticed — and it disagreed for a multi-source load AND
    for a single CONCATENATED source, i.e. a packer dump, the case the field
    matters most for.

    The probe keys come from the session's LOAD-TIME record (dexllm#42), not from
    a fresh read of the path. Re-probing made a source deleted after the load — a
    dump in a temp dir, which is exactly what `add_dumped_dexes` is for — report
    `format: "unknown", dex_count: 0` for a session that still works, and 0 is the
    documented "resources-only container, nothing to analyse" sentinel. An
    orienting tool emitting that for a live session is a confident wrong answer.

    `source` says WHICH source the shared keys describe. Without it they name an
    unnamed one of N — `add_dumped_dexes` puts the DUMP first, so a packer session
    describes a bare dex and reports `is_apk: False` for a session whose real
    subject is an APK. dexllm#26 drew the same lesson for `extract_dex`: bytes
    alone cannot say which file they came from.
    """
    # [0] is the primary source; the constructor refuses an empty source list, so
    # a session always has one.
    info = dict(dk.source_info()[0])
    # ...and the session-level facts, under names that cannot be mistaken for the
    # per-container ones. `verify_report` carries the per-dex list, with sources.
    info["loaded_dex_count"] = dk.dex_count()
    info["source_count"] = len(dk.sources())
    return info


def _t_verify_report(dk: DexKit) -> dict:
    """Per-dex structural-verification verdict (the load-time VerifyDex results)."""
    return {"dexes": dk.verify_report()}


def _t_decompile_method_ast(
    dk: DexKit,
    method_descriptor: str,
    include_source: bool = False,
    max_chars: int = 20000,
) -> dict:
    """Return the DAD nested-list AST + signature for a method (structural).

    For programmatic consumers — prefer decompile_method for reading (the Java TEXT
    is more compact). `include_source=False` (default) omits the Java text. The AST
    tree is bounded like the decompile tools: if it serialises beyond `max_chars`,
    `ast` is dropped and `ast_omitted` explains (raise `max_chars` or use
    decompile_method) — the signature/pc_map stay.
    """
    import json

    require_member_descriptor(method_descriptor)
    res = dict(
        dk.decompile_method_ast(method_descriptor, include_source=include_source)
    )
    ast_chars = len(json.dumps(res.get("ast")))
    if ast_chars > max(0, int(max_chars)):
        res["ast"] = None
        res["ast_omitted"] = (
            f"AST too large ({ast_chars} chars > max_chars={max_chars}); "
            "raise max_chars, or use decompile_method for the Java text"
        )
    return res


def _t_batch_find_methods_using_strings(
    dk: DexKit,
    query_map: dict,
    match_type: str = "contains",
    ignore_case: bool = False,
    limit: int = 50,
) -> dict:
    """Batch string search: {group: [strings]} -> {group: {total, items, truncated}}.

    One Aho-Corasick scan (cheaper than N separate find_methods_using_strings calls).
    Each group's hits are capped at `limit` (with total/truncated) so a broad query —
    or an empty group (C++ empty-set = vacuous match-all, exactly as the single find
    tool) — can't dump the whole method table while `total` stays honest. A non-list
    value is rejected by the binding as a clean {error}. Mirrors the single find
    tool's tool-layer bounding (pagination), so behaviour is consistent.
    """
    limit = max(1, int(limit))
    res = dk.batch_find_methods_using_strings(
        query_map, match_type=match_type, ignore_case=ignore_case
    )
    out: dict = {g: {"total": 0, "items": [], "truncated": False} for g in query_map}
    for g, hits in res.items():
        descs = [_match_to_desc(h) for h in hits]
        out[g] = {
            "total": len(descs),
            "items": descs[:limit],
            "truncated": len(descs) > limit,
        }
    return out


# ─── Tool catalog (Anthropic API / MCP JSON-Schema) ───────────────────────

TOOL_IMPLS: dict[str, Callable] = {
    "extract_iocs": _t_extract_iocs,
    "dangerous_permission_apis": _t_dangerous_permission_apis,
    "dangerous_permission_api_callers": _t_dangerous_permission_api_callers,
    "identify": _t_identify,
    "verify_report": _t_verify_report,
    "list_classes": _t_list_classes,
    "list_class_methods": _t_list_class_methods,
    "list_value_strings": _t_list_value_strings,
    "list_class_strings": _t_list_class_strings,
    "list_method_strings": _t_list_method_strings,
    "decompile_method": _t_decompile_method,
    "decompile_method_ast": _t_decompile_method_ast,
    "decompile_class": _t_decompile_class,
    "render_class_smali": _t_render_class_smali,
    "detect_content_providers": _t_detect_content_providers,
    "batch_find_methods_using_strings": _t_batch_find_methods_using_strings,
    "find_classes_by_name": _t_find_classes_by_name,
    "find_classes_by_super": _t_find_classes_by_super,
    "find_classes_implementing": _t_find_classes_implementing,
    "find_classes_by_annotation": _t_find_classes_by_annotation,
    "find_classes_using_strings": _t_find_classes_using_strings,
    "find_classes_declaring_strings": _t_find_classes_declaring_strings,
    "find_methods_by_name": _t_find_methods_by_name,
    "find_fields_by_name": _t_find_fields_by_name,
    "find_methods_using_strings": _t_find_methods_using_strings,
    "find_call_sites_to": _t_find_call_sites_to,
    "resolve_call_args": _t_resolve_call_args,
    "find_call_sites_from": _t_find_call_sites_from,
    "find_methods_reading_field": _t_find_methods_reading_field,
    "find_methods_writing_field": _t_find_methods_writing_field,
    "find_type_references": _t_find_type_references,
    "find_methods_using_int_literals": _t_find_methods_using_int_literals,
    "find_methods_using_double_literals": _t_find_methods_using_double_literals,
    "get_class_summary": _t_get_class_summary,
    "render_method_smali": _t_render_method_smali,
    "summarize_capabilities": _t_summarize_capabilities,
}

# NOTE: the tool catalog carries NO deprecated aliases. An alias would not be a
# transparent one — mcp validates arguments against the inputSchema of the tool it
# ADVERTISES, so a call under an unadvertised name skips schema validation
# entirely (Server.call_tool no-ops and logs a warning) and a malformed argument
# degrades from a protocol-level error to an in-band {"error": ...}. Renaming a
# tool outright keeps `TOOL_DEFINITIONS` ≡ `TOOL_IMPLS` exact and every advertised
# name validated. Aliases are kept on the Python API (raw DexKit + sdk adapter),
# which is where released names actually need protecting.


TOOL_DEFINITIONS: list[dict] = [
    {
        "name": "list_classes",
        "description": (
            "List every class descriptor declared in the APK (e.g. "
            "'Lcom/foo/Bar;'). Supports regex `pattern` filter and "
            "`offset`/`limit` pagination. Use this first to discover what's "
            "in the APK before drilling into a specific class."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "pattern": {
                    "type": "string",
                    "description": "optional SimilarRegex filter (^prefix / suffix$ / else substring)",
                },
                "offset": {"type": "integer", "default": 0},
                "limit": {
                    "type": "integer",
                    "default": DEFAULT_LIST_LIMIT,
                    "maximum": 1000,
                },
            },
        },
    },
    {
        "name": "list_class_methods",
        "description": "Return full Dalvik method descriptors for every method declared in the class.",
        "input_schema": {
            "type": "object",
            "properties": {
                "class_descriptor": {
                    "type": "string",
                    "description": "e.g. 'Lcom/foo/Bar;'",
                },
            },
            "required": ["class_descriptor"],
        },
    },
    {
        "name": "decompile_method",
        "description": (
            "Decompile a single method to Java text. Pass the full Dalvik "
            "descriptor (e.g. 'Lcom/foo/Bar;->doIt(Ljava/lang/String;)V'). "
            "Output is truncated to `max_chars`; request more with a larger "
            "value if needed."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "method_descriptor": {"type": "string"},
                "max_chars": {"type": "integer", "default": DEFAULT_DECOMPILE_CHARS},
            },
            "required": ["method_descriptor"],
        },
    },
    {
        "name": "decompile_class",
        "description": (
            "Decompile a whole class to full Java text (package, header, "
            "fields, methods). Output is truncated to `max_chars`."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "class_descriptor": {"type": "string"},
                "max_chars": {"type": "integer", "default": DEFAULT_CLASS_CHARS},
            },
            "required": ["class_descriptor"],
        },
    },
    {
        "name": "find_classes_by_name",
        "description": "Find classes whose name matches a query string.",
        "input_schema": {
            "type": "object",
            "properties": {
                "name": {"type": "string"},
                "match_type": {
                    "type": "string",
                    "enum": ["equals", "contains", "starts_with", "ends_with", "regex"],
                    "default": "contains",
                },
                "ignore_case": {"type": "boolean", "default": False},
                "limit": {"type": "integer", "default": 50},
                "offset": {"type": "integer", "default": 0},
            },
            "required": ["name"],
        },
    },
    {
        "name": "find_classes_by_super",
        "description": "Find classes whose direct superclass matches the query.",
        "input_schema": {
            "type": "object",
            "properties": {
                "super_class": {
                    "type": "string",
                    "description": "e.g. 'Landroid/app/Activity;'",
                },
                "match_type": {"type": "string", "default": "equals"},
                "limit": {"type": "integer", "default": 50},
                "offset": {"type": "integer", "default": 0},
            },
            "required": ["super_class"],
        },
    },
    {
        "name": "find_classes_implementing",
        "description": "Find classes that implement the given interface.",
        "input_schema": {
            "type": "object",
            "properties": {
                "interface_class": {"type": "string"},
                "match_type": {"type": "string", "default": "equals"},
                "limit": {"type": "integer", "default": 50},
                "offset": {"type": "integer", "default": 0},
            },
            "required": ["interface_class"],
        },
    },
    {
        "name": "find_classes_by_annotation",
        "description": "Find classes carrying the given annotation.",
        "input_schema": {
            "type": "object",
            "properties": {
                "annotation_class": {"type": "string"},
                "match_type": {"type": "string", "default": "equals"},
                "limit": {"type": "integer", "default": 50},
                "offset": {"type": "integer", "default": 0},
            },
            "required": ["annotation_class"],
        },
    },
    {
        "name": "find_classes_using_strings",
        "description": "Find classes whose bytecode references any of the given string literals.",
        "input_schema": {
            "type": "object",
            "properties": {
                "strings": {"type": "array", "items": {"type": "string"}},
                "match_type": {"type": "string", "default": "contains"},
                "ignore_case": {"type": "boolean", "default": False},
                "limit": {"type": "integer", "default": 50},
                "offset": {"type": "integer", "default": 0},
            },
            "required": ["strings"],
        },
    },
    {
        "name": "find_classes_declaring_strings",
        "description": (
            "Find classes that DECLARE the given strings as static-field constants. "
            "Use this when find_classes_using_strings returns nothing for a string you "
            "know is in the app: `using` searches the const-string BYTECODE index, so a "
            "`static final String` the app never loads (an API constant, a BuildConfig "
            "field, a hardcoded URL kept only as a constant) is invisible to it. There "
            "is no method-level version — a constant belongs to a class, not a method."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "strings": {"type": "array", "items": {"type": "string"}},
                "match_type": {"type": "string", "default": "contains"},
                "ignore_case": {"type": "boolean", "default": False},
                "limit": {"type": "integer", "default": 50},
                "offset": {"type": "integer", "default": 0},
            },
            "required": ["strings"],
        },
    },
    {
        "name": "find_methods_by_name",
        "description": "Find methods whose name matches a query (optionally constrained to a declaring class).",
        "input_schema": {
            "type": "object",
            "properties": {
                "name": {"type": "string"},
                "match_type": {"type": "string", "default": "contains"},
                "declaring_class": {"type": "string", "default": ""},
                "ignore_case": {"type": "boolean", "default": False},
                "limit": {"type": "integer", "default": 50},
                "offset": {"type": "integer", "default": 0},
            },
            "required": ["name"],
        },
    },
    {
        "name": "find_fields_by_name",
        "description": "Find fields whose name matches a query (optionally constrained to a declaring class). With declaring_class the hits are declarations: a field a subclass merely inherits is not a hit under that subclass. Without it every match is kept, references included — use that form to find where an inherited field is touched, since its declaration is often in the framework and outside every loaded dex.",
        "input_schema": {
            "type": "object",
            "properties": {
                "name": {"type": "string"},
                "match_type": {"type": "string", "default": "contains"},
                "declaring_class": {"type": "string", "default": ""},
                "ignore_case": {"type": "boolean", "default": False},
                "limit": {"type": "integer", "default": 50},
                "offset": {"type": "integer", "default": 0},
            },
            "required": ["name"],
        },
    },
    {
        "name": "find_methods_using_strings",
        "description": "Find methods whose bytecode references any of the given string literals.",
        "input_schema": {
            "type": "object",
            "properties": {
                "strings": {"type": "array", "items": {"type": "string"}},
                "match_type": {"type": "string", "default": "contains"},
                "ignore_case": {"type": "boolean", "default": False},
                "limit": {"type": "integer", "default": 50},
                "offset": {"type": "integer", "default": 0},
            },
            "required": ["strings"],
        },
    },
    {
        "name": "find_call_sites_to",
        "description": (
            "Every call site invoking the given API method descriptor — "
            "e.g. 'Landroid/telephony/TelephonyManager;->getDeviceId()Ljava/lang/String;'. "
            "The CALLER direction (reverse of find_call_sites_from): the "
            "callee is the API you asked about, so what varies per row is the "
            "caller and its bytecode_offset. Use this to trace usage of "
            "sensitive APIs (PII, crypto, network, file IO)."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "method_descriptor": {"type": "string"},
                "limit": {"type": "integer", "default": 50},
                "offset": {"type": "integer", "default": 0},
            },
            "required": ["method_descriptor"],
        },
    },
    {
        "name": "resolve_call_args",
        "description": (
            "Like find_call_sites_to, but ALSO resolves the ARGUMENT VALUES "
            "passed at each call site (intra-method dataflow). Each arg is "
            "{index, kind, value}: a literal for a const (kind ConstInt/"
            "ConstString/...), the field/method descriptor for FieldRead/"
            "MethodReturn (the value is NOT followed further), or pN for a "
            "Parameter. For an INSTANCE method index 0 is the receiver, so the "
            "Java params start at index 1. Use this to match value-specific "
            "patterns — e.g. setComponentEnabledSetting(*, 2, 1) (icon-hide): "
            "args[2].value==2 and args[3].value==1. A value defined across a "
            "branch, or from a field/method/param, shows its kind, not the int. "
            "An Unknown arg carrying `crossed_branch` means a definition was "
            "DISCARDED at a merge — treat it as unproven, not as absent. "
            "`depth` bounds the search to the call's own basic block plus that "
            "many predecessor levels above it (0 = that block alone); raise it "
            "when arguments come back Unknown, at proportionate cost."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "method_descriptor": {"type": "string"},
                "depth": {"type": "integer", "default": 2},
                "limit": {"type": "integer", "default": 50},
                "offset": {"type": "integer", "default": 0},
            },
            "required": ["method_descriptor"],
        },
    },
    {
        "name": "find_call_sites_from",
        "description": (
            "The CALLEE direction: every method the given method invokes (the "
            "forward edge of find_call_sites_to). Returns {caller, callee, "
            "bytecode_offset} per invoke — 'caller' is the SAME on every row (it "
            "is the method you asked about); 'callee' and the offset are what "
            "vary. Use to see what a suspicious method actually does."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "method_descriptor": {"type": "string"},
                "limit": {"type": "integer", "default": 50},
                "offset": {"type": "integer", "default": 0},
            },
            "required": ["method_descriptor"],
        },
    },
    {
        "name": "find_methods_reading_field",
        "description": (
            "Methods that READ a field (iget/sget). Pass the field descriptor "
            "'Lcom/foo/Bar;->f:I'. Returns caller method descriptors, one "
            "entry per read INSTRUCTION - a method reading it twice appears twice."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "field_descriptor": {"type": "string"},
                "limit": {"type": "integer", "default": 50},
                "offset": {"type": "integer", "default": 0},
            },
            "required": ["field_descriptor"],
        },
    },
    {
        "name": "find_methods_writing_field",
        "description": (
            "Methods that WRITE a field (iput/sput). Pass the field descriptor "
            "'Lcom/foo/Bar;->f:I'. Returns caller method descriptors, one "
            "entry per write INSTRUCTION - a method writing it twice appears twice."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "field_descriptor": {"type": "string"},
                "limit": {"type": "integer", "default": 50},
                "offset": {"type": "integer", "default": 0},
            },
            "required": ["field_descriptor"],
        },
    },
    {
        "name": "find_type_references",
        "description": (
            "Where a type is used: fields declared of it, methods returning it, "
            "and methods taking it as a parameter. Pass the type descriptor "
            "'Ljava/lang/String;'. Each of the three lists pages by `limit`/"
            "`offset` (same offset applied to all three)."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "type_descriptor": {"type": "string"},
                "limit": {"type": "integer", "default": 50},
                "offset": {"type": "integer", "default": 0},
            },
            "required": ["type_descriptor"],
        },
    },
    {
        "name": "find_methods_using_int_literals",
        "description": (
            "Methods whose bytecode loads any of the given integer constants — "
            "useful for magic numbers, ports, opcodes, flag values (e.g. the "
            "COMPONENT_ENABLED_STATE_DISABLED=2 used by icon-hide)."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "values": {
                    "type": "array",
                    "items": {"type": "integer"},
                    "minItems": 1,
                },
                "limit": {"type": "integer", "default": 50},
                "offset": {"type": "integer", "default": 0},
            },
            "required": ["values"],
        },
    },
    {
        "name": "find_methods_using_double_literals",
        "description": (
            "Methods whose bytecode loads any of the given double/float "
            "constants — useful for magic floating-point constants."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "values": {
                    "type": "array",
                    "items": {"type": "number"},
                    "minItems": 1,
                },
                "limit": {"type": "integer", "default": 50},
                "offset": {"type": "integer", "default": 0},
            },
            "required": ["values"],
        },
    },
    {
        "name": "get_class_summary",
        "description": "Class header info: the declaring dex (dex_id + dex_name, e.g. 'classes2.dex'), superclass, interfaces, method count, field count, access flags. On an internal class `method_count` / `field_count` count what it DECLARES — a field it merely inherits is not counted (use list_fields to see references); an external class declares nothing here, so its counts are the references other classes make. `access_flags` is null when UNKNOWN — an external class (one no loaded dex declares) has no modifiers to read; null is NOT 0, which in dex means package-private. Cheaper than decompile_class when you only need structure.",
        "input_schema": {
            "type": "object",
            "properties": {
                "class_descriptor": {"type": "string"},
            },
            "required": ["class_descriptor"],
        },
    },
    {
        "name": "render_method_smali",
        "description": "baksmali-style raw bytecode for one method. Use when Java decompile is unclear or for low-level inspection.",
        "input_schema": {
            "type": "object",
            "properties": {
                "method_descriptor": {"type": "string"},
                "max_chars": {"type": "integer", "default": DEFAULT_DECOMPILE_CHARS},
            },
            "required": ["method_descriptor"],
        },
    },
    {
        "name": "summarize_capabilities",
        "description": (
            "High-level capability summary for the APK — what permissions, "
            "network endpoints, crypto APIs, dynamic-loading patterns, "
            "and sensitive system APIs the app touches. Good first probe "
            "to orient analysis before drilling into specific classes. "
            "Results carry two independent axes: `top_categories` / per-hit "
            "`categories` is the domain-or-behaviour axis (TELEPHONY, REFLECTION, "
            "PROCESS_EXEC, …), and `flags` is the cross-domain concern axis "
            "(today only IDENTIFIER — the API returns a device/user identifier), "
            "which rolls up across domains. `catalog_version` identifies the tag "
            "vocabulary: it changed at 0.2, so do not assume pre-0.2 tag names. "
            "Counts are of call sites in the dex, not executions, and by default "
            "only the app's OWN callers are counted — set `app_only` false to "
            "include bundled libraries (androidx / kotlin / play-services), which "
            "answers 'what does this APK bundle' rather than 'what does this app "
            "do'. `dropped_touches` / `dropped_apis` report what that filter "
            "removed, so an all-zero result with a nonzero `dropped_touches` "
            "means only bundled libraries reach these APIs — NOT that the app "
            "does none of this."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "limit": {
                    "type": "integer",
                    "default": 50,
                    "description": "max api_hits to return (by call-site count)",
                },
                "app_only": {
                    "type": "boolean",
                    "default": True,
                    "description": (
                        "count only the app's own callers, dropping bundled "
                        "framework/library plumbing (default true)"
                    ),
                },
            },
        },
    },
    {
        "name": "extract_iocs",
        "description": (
            "Static C2 / network-IOC extraction — the URLs, IPs, domains, "
            "emails, and .onion addresses embedded in the app's dex strings, "
            "like VirusTotal's contacted-addresses view but recovered "
            "statically (no execution). Each indicator is tied to the "
            "class/method that references it (with_xref). Framework package "
            "names that look like hosts are denoised out. Use early in triage "
            "to surface command-and-control / exfiltration endpoints."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "with_xref": {
                    "type": "boolean",
                    "default": True,
                    "description": "attach referencing method descriptors to each indicator",
                },
                "xref_limit": {
                    "type": "integer",
                    "default": 300,
                    "description": "cap on indicators cross-referenced (cost bound)",
                },
            },
        },
    },
    {
        "name": "dangerous_permission_apis",
        "description": (
            "Which DANGEROUS Android permissions the APK exercises through real "
            "framework API calls (not just <uses-permission> claims). Joins AOSP's "
            "@RequiresPermission permission->API map against the APK's referenced "
            "APIs. Returns {permission: [pkg.Class#method, ...]} for the gated APIs "
            "actually used. Strong behavioural signal for triage."
        ),
        "input_schema": {"type": "object", "properties": {}},
    },
    {
        "name": "dangerous_permission_api_callers",
        "description": (
            "Like dangerous_permission_apis, but also returns WHO calls each gated "
            "API — the caller method descriptors — so you can jump straight to the "
            "code that uses a dangerous permission (e.g. which method reads "
            "location or phone state). By default callers from bundled framework / "
            "official-library code (androidx, kotlin, play-services, …) are filtered "
            "out so you see the app's own usage; pass app_only=false to keep them."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "app_only": {
                    "type": "boolean",
                    "default": True,
                    "description": "drop framework/official-library callers (androidx, kotlin, …)",
                }
            },
        },
    },
    {
        "name": "list_value_strings",
        "description": (
            "Every distinct string the app LOADS as a value (const-string + static "
            "VALUE_STRING initializers), MUTF-8 decoded, deduplicated — the IOC feed "
            "and the place to eyeball hardcoded URLs, keys, commands, class names for "
            "reflection, etc. Optional SimilarRegex `pattern` filter (^/$ + substring); paginated. Excludes "
            "identifier/metadata pool entries (type/method/field names)."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "pattern": {
                    "type": "string",
                    "description": "optional SimilarRegex filter (^prefix / suffix$ / else substring)",
                },
                "offset": {"type": "integer", "default": 0},
                "limit": {
                    "type": "integer",
                    "default": DEFAULT_LIST_LIMIT,
                    "maximum": 1000,
                },
            },
        },
    },
    {
        "name": "list_class_strings",
        "description": (
            "The value-strings ONE class carries — the const-string operands of its "
            "declared methods plus its static-field VALUE_STRING initializers, "
            "deduplicated and paginated. The forward direction of "
            "find_classes_using_strings, and the cheap way to see a class's literals "
            "(C2 host, provider URI, key, MIME type) without pulling a whole smali "
            "listing or decompile into context. Declared-only: no superclass walk. "
            "Note: a static-init string is NOT in the reverse index, so feeding it "
            "back to find_classes_using_strings can return nothing — that is expected, "
            "not a missing class."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "class_descriptor": {
                    "type": "string",
                    "description": "e.g. 'Lcom/foo/Bar;'",
                },
                "offset": {"type": "integer", "default": 0},
                "limit": {
                    "type": "integer",
                    "default": DEFAULT_LIST_LIMIT,
                    "maximum": 1000,
                },
            },
            "required": ["class_descriptor"],
        },
    },
    {
        "name": "list_method_strings",
        "description": (
            "The value-strings ONE method loads — its const-string/jumbo operands, "
            "deduplicated and paginated. The forward direction of "
            "find_methods_using_strings: use "
            "it after find_call_sites_to / permission_callers to see what "
            "literals a suspicious method carries, without decompiling it. Bytecode "
            "only — a `static final String` shows up in list_class_strings instead. "
            "Empty for an external / abstract / native method."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "method_descriptor": {
                    "type": "string",
                    "description": "e.g. 'Lcom/foo/Bar;->doIt(Ljava/lang/String;)V'",
                },
                "offset": {"type": "integer", "default": 0},
                "limit": {
                    "type": "integer",
                    "default": DEFAULT_LIST_LIMIT,
                    "maximum": 1000,
                },
            },
            "required": ["method_descriptor"],
        },
    },
    {
        "name": "render_class_smali",
        "description": (
            "baksmali-style raw bytecode for a WHOLE class (the class counterpart of "
            "render_method_smali). Truncated to `max_chars`."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "class_descriptor": {"type": "string"},
                "max_chars": {"type": "integer", "default": DEFAULT_CLASS_CHARS},
            },
            "required": ["class_descriptor"],
        },
    },
    {
        "name": "detect_content_providers",
        "description": (
            "Bundled `content://` provider URIs the app references (from its "
            "value-strings), each tied to the referencing method (with_xref). Surfaces "
            "provider access — contacts, SMS, call log, calendar, downloads — a common "
            "data-exfiltration / recon signal in triage."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "with_xref": {
                    "type": "boolean",
                    "default": True,
                    "description": "attach the referencing method to each provider",
                },
                "xref_limit": {
                    "type": "integer",
                    "default": 300,
                    "description": "cap on providers cross-referenced (cost bound)",
                },
            },
        },
    },
    {
        "name": "identify",
        "description": (
            "What the session's primary source WAS, as recorded when it was "
            "LOADED — not a fresh read of the path, so it stays right after the "
            "file is gone (a dumped dex in a temp dir routinely is): "
            "{format, is_apk, has_manifest, dex_count, source} — identical in "
            "meaning to dexllm.identify(path), so dex_count is THAT container's "
            "own count and source says which of the session's sources these "
            "describe — plus loaded_dex_count (dexes actually loaded — differs "
            "from dex_count only for a multi-source load or a concatenated / "
            "packer dump) and source_count (how many sources the session was "
            "built from). Quick orientation on what is loaded and how much of "
            "it; verify_report lists the dexes individually, with their source. "
            "To ask about a path on disk instead, that is dexllm.identify(path)."
        ),
        "input_schema": {"type": "object", "properties": {}},
    },
    {
        "name": "verify_report",
        "description": (
            "Per-dex structural-verification verdict from the load-time gate: a list "
            "of {dex_id, name, valid, reason}. All valid on a cleanly-loaded APK; a "
            "reason string appears for a dex that failed structural checks."
        ),
        "input_schema": {"type": "object", "properties": {}},
    },
    {
        "name": "decompile_method_ast",
        "description": (
            "The DAD nested-list AST (+ signature) for one method — structural data "
            "for programmatic use. Prefer decompile_method for READING (Java text is "
            "more compact); use this when you need the tree. include_source=false "
            "(default) omits the Java text. Can be large for a big method."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "method_descriptor": {"type": "string"},
                "include_source": {"type": "boolean", "default": False},
                "max_chars": {"type": "integer", "default": 20000},
            },
            "required": ["method_descriptor"],
        },
    },
    {
        "name": "batch_find_methods_using_strings",
        "description": (
            "Batch string search in one Aho-Corasick scan — pass "
            "{group_name: [strings]} and get {group_name: [method descriptors]}. "
            "Cheaper than N separate find_methods_using_strings calls when probing "
            "several string sets (e.g. ROOT_CHECK / REFLECTION / DEBUG buckets)."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "query_map": {
                    "type": "object",
                    "additionalProperties": {
                        "type": "array",
                        "items": {"type": "string"},
                        "minItems": 1,
                    },
                    "description": "{group: [strings]}",
                },
                "match_type": {
                    "type": "string",
                    "enum": ["equals", "contains", "starts_with", "ends_with", "regex"],
                    "default": "contains",
                },
                "ignore_case": {"type": "boolean", "default": False},
                "limit": {"type": "integer", "default": 50},
            },
            "required": ["query_map"],
        },
    },
]


def execute(name: str, args: dict, dk: DexKit) -> dict:
    """Dispatch a tool call. Returns a JSON-serialisable dict.

    On unknown tool: returns {"error": "..."}. Implementation exceptions
    surface as {"error": "<ExceptionType>: <msg>"} so the LLM can decide
    what to do next (rather than the tool loop crashing the conversation).
    """
    impl = TOOL_IMPLS.get(name)
    if impl is None:
        return {"error": f"unknown tool: {name}"}
    try:
        return impl(dk, **(args or {}))
    except TypeError as e:
        return {"error": f"bad arguments to {name}: {e}"}
    except Exception as e:
        return {"error": f"{type(e).__name__}: {e}"}


def tool_definitions() -> list[dict]:
    """Return the tool catalog.

    The Anthropic Messages API accepts this directly as the `tools=` argument;
    MCP serves the same entries via the `list_tools` protocol method.
    """
    return TOOL_DEFINITIONS
