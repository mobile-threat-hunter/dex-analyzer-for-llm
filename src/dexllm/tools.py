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

import re
from typing import TYPE_CHECKING, Any, Callable

from .safe import (
    DEFAULT_TIMEOUT_S,
    is_timeout_marker,
    safe_decompile_class_java,
    safe_decompile_method_java,
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


# A nested unbounded quantifier — an unbounded quantifier (* + or {n,}, ending in
# * + or }) closing a group, immediately re-quantified by * + or { — is the classic
# catastrophic-backtracking (ReDoS) shape: '(a+)+', '(.*)*', '(a*)+', '(a+){2,}'.
# Python `re` holds the GIL while matching, so a thread/deadline can't interrupt a
# spin (unlike the GIL-releasing C++ decompile that safe.py guards); reject the
# pattern structurally up front instead. Escaped literals ('\+\)\+') don't match
# (the quantifier chars aren't adjacent to the ')'). Not a complete ReDoS solver
# (overlapping-alternation like '(a|a)*' slips through), but it blocks the
# reliably-triggerable, content-agnostic patterns; a rejected pattern → clean error.
_NESTED_QUANTIFIER = re.compile(r"[*+}]\)[*+{]")


def _filter_pattern(items: list[str], pattern: str | None) -> list[str]:
    if not pattern:
        return items
    if _NESTED_QUANTIFIER.search(pattern):
        raise ValueError(
            "pattern rejected: a nested unbounded quantifier (e.g. '(a+)+', '(.*)*') "
            "risks catastrophic backtracking (ReDoS) — simplify `pattern`"
        )
    rx = re.compile(pattern)  # an invalid regex raises re.error → caught by execute()
    return [x for x in items if rx.search(x)]


_PRIM_DESCS = set("VZBSCIJFD")


def _norm_type(t: str) -> str:
    """Convert a dotted/smali type to a Dalvik descriptor, IDEMPOTENTLY.

    'java.lang.String' / 'java/lang/String' → 'Ljava/lang/String;'; an
    already-descriptor form ('Lx;', '[I', a primitive 'I') is returned unchanged.
    So the descriptor-taking tools accept the same lenient forms the search family
    does, instead of silently returning empty on a dotted input.
    """
    if not t or t[0] in "L[" or (len(t) == 1 and t in _PRIM_DESCS):
        return t
    from .descriptors import java_to_descriptor

    try:
        return java_to_descriptor(t)
    except Exception:
        return t  # leave malformed input for the C++ layer to reject/empty


def _norm_member_desc(desc: str) -> str:
    """Normalise the CLASS (and, for a field, the type) of a member descriptor.

    'android.util.Log->d(...)I' → 'Landroid/util/Log;->d(...)I';
    'java.lang.Foo->x:int' → 'Ljava/lang/Foo;->x:I'. A method's `(proto)ret` is left
    as-is (callers copy it in descriptor form from list_class_methods / find_* output);
    a bare class/type with no '->' is normalised whole.
    """
    if "->" not in desc:
        return _norm_type(desc)
    cls, rest = desc.split("->", 1)
    cls = _norm_type(cls)
    if "(" not in rest and ":" in rest:  # a field: name:type (not a method proto)
        name, typ = rest.rsplit(":", 1)
        rest = f"{name}:{_norm_type(typ)}"
    return f"{cls}->{rest}"


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
    return {
        "class": class_descriptor,
        "methods": dk.list_class_methods(class_descriptor),
    }


def _t_decompile_method(
    dk: DexKit, method_descriptor: str, max_chars: int = DEFAULT_DECOMPILE_CHARS
) -> dict:
    out = safe_decompile_method_java(dk, method_descriptor, timeout=DEFAULT_TIMEOUT_S)
    if is_timeout_marker(out):
        return {"descriptor": method_descriptor, "error": "timeout", "text": out}
    return {"descriptor": method_descriptor, **_truncate(out, max_chars)}


def _t_decompile_class(
    dk: DexKit, class_descriptor: str, max_chars: int = DEFAULT_CLASS_CHARS
) -> dict:
    out = safe_decompile_class_java(dk, class_descriptor, timeout=DEFAULT_TIMEOUT_S)
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


def _t_find_call_sites_to_api(
    dk: DexKit, api_descriptor: str, limit: int = 50, offset: int = 0
) -> dict:
    api_descriptor = _norm_member_desc(api_descriptor)
    sites = dk.find_call_sites_to_api(api_descriptor)
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


def _t_get_class_summary(dk: DexKit, class_descriptor: str) -> dict:
    s = dk.get_class_summary(class_descriptor)
    return {
        "descriptor": class_descriptor,
        "superclass": s.superclass_descriptor or None,
        "interfaces": list(s.interface_descriptors),
        "method_count": len(list(s.methods)),
        "field_count": len(list(s.fields)),
        "access_flags": s.access_flags,
    }


def _t_render_method_smali(
    dk: DexKit, method_descriptor: str, max_chars: int = DEFAULT_DECOMPILE_CHARS
) -> dict:
    out = dk.render_method_smali(method_descriptor)
    return {"descriptor": method_descriptor, **_truncate(out, max_chars)}


def _t_capability_report(dk: DexKit, limit: int = 50) -> dict:
    """Bounded, LLM-friendly capability summary.

    Returns top permissions/categories and the `limit` most-invoked APIs. The
    raw report's per-caller sets (`by_caller`, `ApiHit.callers`) can be huge on
    a large APK, so they are intentionally omitted here to keep the response
    within the model's context.
    """
    from .capability import summarize_capabilities

    rep = summarize_capabilities(dk)
    limit = max(1, int(limit))
    hits = sorted(rep.api_hits, key=lambda h: h.call_site_count, reverse=True)
    return {
        "total_call_sites": rep.total_call_sites,
        "matched_apis": rep.matched_apis,
        "catalog_size": rep.catalog_size,
        "top_permissions": rep.top_permissions(20),
        "top_categories": rep.top_categories(20),
        "api_hits": [
            {
                "api": h.api_signature,
                "permissions": h.permissions,
                "categories": h.categories,
                "call_sites": h.call_site_count,
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
    and with each indicator tied to the referencing method (when with_xref).
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

_ARG_VALUE_FIELD = {
    "ConstString": "string_value",
    "ConstInt": "int_value",
    "ConstWide": "int_value",
    "ConstClass": "class_descriptor",
    "NewInstance": "class_descriptor",
    "NewArray": "class_descriptor",
    "FieldRead": "field_signature",
    "MethodReturn": "method_signature",
}


def _arg_to_compact(index: int, a: Any) -> dict:
    """One ArgOrigin → a compact ``{index, kind, value}`` dict.

    The resolved constant / field-sig / callee-sig / param-slot, without the raw
    multi-field struct.
    `index` is the position in the invoke's argument list: for an INSTANCE method
    index 0 is the receiver, so a 3-param instance call's Java params sit at 1/2/3.
    `value` is the literal for a const kind; the field/method signature for a
    FieldRead/MethodReturn (the value is NOT followed — that is a separate hop);
    `pN` for a Parameter; None for ConstNull/Unknown.
    """
    field = _ARG_VALUE_FIELD.get(a.kind)
    try:
        if field is not None:
            # A const-string / descriptor field is raw dex MUTF-8; pybind's strict
            # UTF-8 decode can raise on a surrogate-pair / embedded-null string. Keep
            # that contained to THIS arg instead of failing the whole call.
            value: Any = getattr(a, field)
        elif a.kind == "Parameter":
            value = f"p{a.parameter_index}"
        else:  # ConstNull, Unknown
            value = None
    except UnicodeDecodeError:
        value = "<undecodable MUTF-8>"
    return {"index": index, "kind": a.kind, "value": value}


def _t_resolve_call_args(
    dk: DexKit, api_descriptor: str, limit: int = 50, offset: int = 0
) -> dict:
    api_descriptor = _norm_member_desc(api_descriptor)
    sites = dk.resolve_call_args(api_descriptor)
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


def _t_find_call_sites_from_method(
    dk: DexKit, method_descriptor: str, limit: int = 50, offset: int = 0
) -> dict:
    method_descriptor = _norm_member_desc(method_descriptor)
    sites = dk.find_call_sites_from_method(method_descriptor)
    items = [
        {
            "caller": s.caller_descriptor,
            "callee": s.callee_descriptor,
            "bytecode_offset": s.bytecode_offset,
        }
        for s in sites
    ]
    return _paginate(items, offset, limit)


def _t_find_field_read_methods(
    dk: DexKit, field_descriptor: str, limit: int = 50, offset: int = 0
) -> dict:
    field_descriptor = _norm_member_desc(field_descriptor)
    return _paginate(dk.find_field_read_methods(field_descriptor), offset, limit)


def _t_find_field_write_methods(
    dk: DexKit, field_descriptor: str, limit: int = 50, offset: int = 0
) -> dict:
    field_descriptor = _norm_member_desc(field_descriptor)
    return _paginate(dk.find_field_write_methods(field_descriptor), offset, limit)


def _t_find_type_references(
    dk: DexKit, type_descriptor: str, limit: int = 50, offset: int = 0
) -> dict:
    type_descriptor = _norm_type(type_descriptor)
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

    Regex `pattern` filters the list; paginated.
    """
    items = _filter_pattern(dk.list_value_strings(), pattern)
    return _paginate(items, offset, limit)


def _t_render_class_smali(
    dk: DexKit, class_descriptor: str, max_chars: int = DEFAULT_CLASS_CHARS
) -> dict:
    out = dk.render_class_smali(_norm_type(class_descriptor))
    return {"descriptor": class_descriptor, **_truncate(out, max_chars)}


def _t_detect_content_providers(
    dk: DexKit, with_xref: bool = True, xref_limit: int = 300
) -> dict:
    from .providers import detect_content_providers

    provs = detect_content_providers(
        dk, with_xref=with_xref, xref_limit=int(xref_limit)
    )
    return {"providers": provs, "count": len(provs)}


# ─── Tool catalog (Anthropic API / MCP JSON-Schema) ───────────────────────

TOOL_IMPLS: dict[str, Callable] = {
    "extract_iocs": _t_extract_iocs,
    "dangerous_permission_apis": _t_dangerous_permission_apis,
    "dangerous_permission_api_callers": _t_dangerous_permission_api_callers,
    "list_classes": _t_list_classes,
    "list_class_methods": _t_list_class_methods,
    "list_value_strings": _t_list_value_strings,
    "decompile_method": _t_decompile_method,
    "decompile_class": _t_decompile_class,
    "render_class_smali": _t_render_class_smali,
    "detect_content_providers": _t_detect_content_providers,
    "find_classes_by_name": _t_find_classes_by_name,
    "find_classes_by_super": _t_find_classes_by_super,
    "find_classes_implementing": _t_find_classes_implementing,
    "find_classes_by_annotation": _t_find_classes_by_annotation,
    "find_classes_using_strings": _t_find_classes_using_strings,
    "find_methods_by_name": _t_find_methods_by_name,
    "find_methods_using_strings": _t_find_methods_using_strings,
    "find_call_sites_to_api": _t_find_call_sites_to_api,
    "resolve_call_args": _t_resolve_call_args,
    "find_call_sites_from_method": _t_find_call_sites_from_method,
    "find_field_read_methods": _t_find_field_read_methods,
    "find_field_write_methods": _t_find_field_write_methods,
    "find_type_references": _t_find_type_references,
    "find_methods_using_int_literals": _t_find_methods_using_int_literals,
    "find_methods_using_double_literals": _t_find_methods_using_double_literals,
    "get_class_summary": _t_get_class_summary,
    "render_method_smali": _t_render_method_smali,
    "capability_report": _t_capability_report,
}


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
                    "description": "optional regex to filter descriptors",
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
        "name": "find_call_sites_to_api",
        "description": (
            "Every call site invoking the given API method descriptor — "
            "e.g. 'Landroid/telephony/TelephonyManager;->getDeviceId()Ljava/lang/String;'. "
            "Returns caller method descriptors. Use this to trace usage of "
            "sensitive APIs (PII, crypto, network, file IO)."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "api_descriptor": {"type": "string"},
                "limit": {"type": "integer", "default": 50},
                "offset": {"type": "integer", "default": 0},
            },
            "required": ["api_descriptor"],
        },
    },
    {
        "name": "resolve_call_args",
        "description": (
            "Like find_call_sites_to_api, but ALSO resolves the ARGUMENT VALUES "
            "passed at each call site (intra-method dataflow). Each arg is "
            "{index, kind, value}: a literal for a const (kind ConstInt/"
            "ConstString/...), the field/method signature for FieldRead/"
            "MethodReturn (the value is NOT followed further), or pN for a "
            "Parameter. For an INSTANCE method index 0 is the receiver, so the "
            "Java params start at index 1. Use this to match value-specific "
            "patterns — e.g. setComponentEnabledSetting(*, 2, 1) (icon-hide): "
            "args[2].value==2 and args[3].value==1. A value defined across a "
            "branch, or from a field/method/param, shows its kind, not the int."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "api_descriptor": {"type": "string"},
                "limit": {"type": "integer", "default": 50},
                "offset": {"type": "integer", "default": 0},
            },
            "required": ["api_descriptor"],
        },
    },
    {
        "name": "find_call_sites_from_method",
        "description": (
            "The CALLEE direction: every method the given method invokes (the "
            "forward edge of find_call_sites_to_api). Returns {caller, callee, "
            "bytecode_offset} per invoke. Use to see what a suspicious method "
            "actually does."
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
        "name": "find_field_read_methods",
        "description": (
            "Methods that READ a field (iget/sget). Pass the field descriptor "
            "'Lcom/foo/Bar;->f:I'. Returns caller method descriptors."
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
        "name": "find_field_write_methods",
        "description": (
            "Methods that WRITE a field (iput/sput). Pass the field descriptor "
            "'Lcom/foo/Bar;->f:I'. Returns caller method descriptors."
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
        "description": "Class header info: superclass, interfaces, method count, field count, access flags. Cheaper than decompile_class when you only need structure.",
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
        "name": "capability_report",
        "description": (
            "High-level capability summary for the APK — what permissions, "
            "network endpoints, crypto APIs, dynamic-loading patterns, "
            "and sensitive system APIs the app touches. Good first probe "
            "to orient analysis before drilling into specific classes."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "limit": {
                    "type": "integer",
                    "default": 50,
                    "description": "max api_hits to return (by call-site count)",
                }
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
            "reflection, etc. Optional regex `pattern` filters; paginated. Excludes "
            "identifier/metadata pool entries (type/method/field names)."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "pattern": {
                    "type": "string",
                    "description": "optional regex to filter the strings",
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
