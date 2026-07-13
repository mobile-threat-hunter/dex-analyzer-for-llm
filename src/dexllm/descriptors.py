"""Dalvik descriptor parsing helpers.

DEX uses JVM-style descriptors: class types are "Lpkg/Cls;", primitives are
single chars (V/Z/B/S/C/I/J/F/D), arrays prefix with '['. Method protos look
like "(II)Ljava/lang/String;".

This module provides pure-Python converters between the wire form and
human-readable Java forms.
"""

from __future__ import annotations

from collections.abc import Iterable
from typing import List, Tuple

_PRIMITIVE = {
    "V": "void",
    "Z": "boolean",
    "B": "byte",
    "S": "short",
    "C": "char",
    "I": "int",
    "J": "long",
    "F": "float",
    "D": "double",
}
_PRIMITIVE_INV = {v: k for k, v in _PRIMITIVE.items()}


def descriptor_to_java(descriptor: str) -> str:
    """Convert a Dalvik type descriptor to a Java-style name.

    Examples
    --------
    >>> descriptor_to_java("Landroid/util/Log;")
    'android.util.Log'
    >>> descriptor_to_java("[I")
    'int[]'
    >>> descriptor_to_java("[[Ljava/lang/String;")
    'java.lang.String[][]'
    >>> descriptor_to_java("V")
    'void'
    """
    n_arr = 0
    while descriptor.startswith("["):
        n_arr += 1
        descriptor = descriptor[1:]
    if descriptor in _PRIMITIVE:
        base = _PRIMITIVE[descriptor]
    elif descriptor.startswith("L") and descriptor.endswith(";"):
        base = descriptor[1:-1].replace("/", ".")
    else:
        base = descriptor  # malformed; return as-is
    return base + "[]" * n_arr


def java_to_descriptor(java_name: str) -> str:
    """Inverse of descriptor_to_java. Accepts "android.util.Log", "int", "java.lang.String[]"."""
    n_arr = 0
    while java_name.endswith("[]"):
        n_arr += 1
        java_name = java_name[:-2]
    if java_name in _PRIMITIVE_INV:
        base = _PRIMITIVE_INV[java_name]
    else:
        base = "L" + java_name.replace(".", "/") + ";"
    return "[" * n_arr + base


def _split_proto_params(params: str) -> Iterable[str]:
    """Yield individual parameter descriptors from a proto's '(...)' body."""
    i = 0
    n = len(params)
    while i < n:
        start = i
        while i < n and params[i] == "[":
            i += 1
        if i >= n:
            # trailing '[' with no base type — malformed. Raise (consistent with
            # the truncated-'L' case below) instead of silently dropping the param.
            raise ValueError(f"malformed proto params: dangling array in {params!r}")
        c = params[i]
        if c == "L":
            end = params.index(";", i)
            yield params[start : end + 1]
            i = end + 1
        else:
            # primitive
            yield params[start : i + 1]
            i += 1


def parse_proto(proto: str) -> Tuple[List[str], str]:
    """Split a proto descriptor into (parameter_descriptors, return_descriptor).

    >>> parse_proto("(II)Ljava/lang/String;")
    (['I', 'I'], 'Ljava/lang/String;')
    >>> parse_proto("()V")
    ([], 'V')
    >>> parse_proto("(Landroid/content/Context;[Ljava/lang/String;I)Z")
    (['Landroid/content/Context;', '[Ljava/lang/String;', 'I'], 'Z')
    """
    if not proto.startswith("("):
        raise ValueError(f"not a proto descriptor: {proto!r}")
    close = proto.index(")")
    params_body = proto[1:close]
    ret_desc = proto[close + 1 :]
    return list(_split_proto_params(params_body)), ret_desc


def pretty_proto(proto: str) -> str:
    """Java-style readable proto: '(int, java.lang.String) -> boolean'."""
    params, ret = parse_proto(proto)
    return (
        "("
        + ", ".join(descriptor_to_java(p) for p in params)
        + ") -> "
        + descriptor_to_java(ret)
    )


def method_ref_java(class_descriptor: str, name: str, proto: str) -> str:
    """Render '`android.util.Log.d(java.lang.String, java.lang.String) -> int`'."""
    params, ret = parse_proto(proto)
    cls = descriptor_to_java(class_descriptor)
    args = ", ".join(descriptor_to_java(p) for p in params)
    return f"{cls}.{name}({args}) -> {descriptor_to_java(ret)}"


def signature(class_descriptor: str, name: str, proto: str) -> str:
    """Build the wire-form API signature accepted by find_call_sites_to_api."""
    return f"{class_descriptor}->{name}{proto}"


# ── descriptor-identity validation ───────────────────────────────────────────
# The xref / decompile / inspect APIs consume a Dalvik descriptor IDENTITY (the
# canonical L-form emitted by list_* / find_* output), unlike the name-SEARCH
# family which takes a fuzzy name query (DexKit's own two concepts). A non-descriptor
# input (a dotted 'java.lang.String' or a bare name) doesn't resolve — the C++ returns
# a SILENT empty, an LLM misreads as "no usages". These validators turn that into a
# clear error instead. Structural check only (does NOT verify the entity exists — a
# valid-but-external descriptor still passes and yields an empty result as intended).
#
# Whitespace is intentionally rejected in the class/arrow region. One C++ identity
# path (LocateMethod, the decompile route) strips ALL whitespace before parsing
# (androguard's proto form has spaces), but the call-site / field paths
# (ParseApiDescriptor, LocateField) do NOT — so a leading-space class would silently
# resolve on decompile yet silently-empty on find_call_sites. Rejecting whitespace in
# the class/arrow region here keeps every identity surface consistent; the canonical
# spaceless form the validators point to (list_* / find_* output) always works.

_PRIM_DESCS = frozenset("VZBSCIJFD")


def is_type_descriptor(t: str) -> bool:
    """Return True if ``t`` is a Dalvik type descriptor (``Lcls;``, ``[...``, primitive)."""
    return bool(t) and (
        (t[0] == "L" and t[-1] == ";")
        or t[0] == "["
        or (len(t) == 1 and t in _PRIM_DESCS)
    )


def is_member_descriptor(desc: str) -> bool:
    """Return True if ``desc`` is a Dalvik member descriptor.

    ``Lcls;->name(proto)ret`` (method) or ``Lcls;->name:type`` (field).
    """
    if "->" not in desc:
        return False
    cls, rest = desc.split("->", 1)
    if not is_type_descriptor(cls):
        return False
    if "(" in rest:  # a method: name(proto)ret — proto/ret trusted (copied verbatim)
        return True
    if ":" in rest:  # a field: name:type — the type must itself be a descriptor
        return is_type_descriptor(rest.rsplit(":", 1)[1])
    return False


def require_type_descriptor(t: str) -> str:
    """Return ``t`` if it is a type descriptor, else raise a guiding ValueError."""
    if not is_type_descriptor(t):
        raise ValueError(
            f"expected a Dalvik type descriptor like 'Ljava/lang/String;' "
            f"(or '[I' / 'I'), got {t!r} — use the descriptor form from "
            f"list_classes / find_* output, not a dotted/Java name"
        )
    return t


def require_member_descriptor(desc: str) -> str:
    """Return ``desc`` if it is a member descriptor, else raise a guiding ValueError."""
    if not is_member_descriptor(desc):
        raise ValueError(
            f"expected a Dalvik member descriptor like "
            f"'Lcom/foo/Bar;->m(Ljava/lang/String;)V' or 'Lcom/foo/Bar;->f:I', "
            f"got {desc!r} — use the descriptor form from list_class_methods / "
            f"find_* output, not a dotted/Java name"
        )
    return desc
