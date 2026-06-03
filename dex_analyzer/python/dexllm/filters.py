"""Filter / lookup helpers on top of the L1 external-reference results."""

from __future__ import annotations

from typing import Iterable, List, Optional

from . import descriptors as _d


def filter_method_refs(
    refs,
    *,
    class_descriptor: Optional[str] = None,
    class_prefix: Optional[str] = None,
    name: Optional[str] = None,
    name_contains: Optional[str] = None,
    proto: Optional[str] = None,
    return_type: Optional[str] = None,
) -> List:
    """Filter ExternalMethodRef list by class/name/signature criteria."""
    out = []
    for m in refs:
        if class_descriptor and m.class_descriptor != class_descriptor: continue
        if class_prefix and not m.class_descriptor.startswith(class_prefix): continue
        if name and m.name != name: continue
        if name_contains and name_contains not in m.name: continue
        if proto and m.proto != proto: continue
        if return_type:
            _, ret = _d.parse_proto(m.proto)
            if ret != return_type: continue
        out.append(m)
    return out


def filter_field_refs(
    refs,
    *,
    class_descriptor: Optional[str] = None,
    class_prefix: Optional[str] = None,
    name: Optional[str] = None,
    type_descriptor: Optional[str] = None,
) -> List:
    """Filter ExternalFieldRef list."""
    out = []
    for f in refs:
        if class_descriptor and f.class_descriptor != class_descriptor: continue
        if class_prefix and not f.class_descriptor.startswith(class_prefix): continue
        if name and f.name != name: continue
        if type_descriptor and f.type != type_descriptor: continue
        out.append(f)
    return out


def filter_type_refs(
    refs,
    *,
    descriptor: Optional[str] = None,
    prefix: Optional[str] = None,
    contains: Optional[str] = None,
) -> List:
    """Filter ExternalTypeRef list."""
    out = []
    for t in refs:
        if descriptor and t.descriptor != descriptor: continue
        if prefix and not t.descriptor.startswith(prefix): continue
        if contains and contains not in t.descriptor: continue
        out.append(t)
    return out


def find_call_sites_to_ref(dk, ref) -> List:
    """Convenience: takes an ExternalMethodRef and returns its call sites.

    Equivalent to dk.find_call_sites_to_api(ref.signature).
    """
    if not hasattr(ref, "signature") or not hasattr(ref, "proto"):
        raise TypeError(f"expected ExternalMethodRef, got {type(ref).__name__}")
    return dk.find_call_sites_to_api(ref.signature)
