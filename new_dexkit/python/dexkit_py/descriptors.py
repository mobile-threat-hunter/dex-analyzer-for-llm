"""Dalvik descriptor parsing helpers.

DEX uses JVM-style descriptors: class types are "Lpkg/Cls;", primitives are
single chars (V/Z/B/S/C/I/J/F/D), arrays prefix with '['. Method protos look
like "(II)Ljava/lang/String;".

This module provides pure-Python converters between the wire form and
human-readable Java forms.
"""

from __future__ import annotations

from typing import Iterable, List, Optional, Tuple

_PRIMITIVE = {
    "V": "void", "Z": "boolean", "B": "byte", "S": "short",
    "C": "char", "I": "int",     "J": "long", "F": "float", "D": "double",
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
            return
        c = params[i]
        if c == "L":
            end = params.index(";", i)
            yield params[start:end + 1]
            i = end + 1
        else:
            # primitive
            yield params[start:i + 1]
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
    ret_desc = proto[close + 1:]
    return list(_split_proto_params(params_body)), ret_desc


def pretty_proto(proto: str) -> str:
    """Java-style readable proto: '(int, java.lang.String) -> boolean'."""
    params, ret = parse_proto(proto)
    return (
        "(" + ", ".join(descriptor_to_java(p) for p in params) + ") -> "
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
