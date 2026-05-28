"""dexkit_py — Python wrapper around LuckyPray DexKit.

Surfaces the native `DexKit` class plus higher-level Python facades
(descriptor helpers, L1 ref filters, L3 capability summary). The Java
decompiler is being built as a faithful C++ port of androguard's DAD in
``new_dexkit/dad_cpp/``; the `decompile_*` family currently returns a
stub message until per-module porting lands.
"""

from ._dexkit_core import (
    ArgOrigin,
    CallSite,
    DexKit,
    ExternalFieldRef,
    ExternalMethodRef,
    ExternalTypeRef,
    ResolvedCallSite,
    is_framework_descriptor,
)
# Import side-effect: attach .java_class/.parameters/.return_type/etc.
# properties onto the native ref classes.
from . import _enrich  # noqa: F401

from . import descriptors
from .capability import (
    ApiHit,
    CapabilityReport,
    summarize_capabilities,
)
from .descriptors import (
    descriptor_to_java,
    java_to_descriptor,
    method_ref_java,
    parse_proto,
    pretty_proto,
    signature,
)
from .filters import (
    filter_field_refs,
    filter_method_refs,
    filter_type_refs,
    find_call_sites_to_ref,
)
from .format import format_class, format_class_summary

__all__ = [
    "ApiHit",
    "ArgOrigin",
    "CallSite",
    "CapabilityReport",
    "DexKit",
    "ExternalFieldRef",
    "ExternalMethodRef",
    "ExternalTypeRef",
    "ResolvedCallSite",
    "descriptor_to_java",
    "descriptors",
    "filter_field_refs",
    "filter_method_refs",
    "filter_type_refs",
    "find_call_sites_to_ref",
    "format_class",
    "format_class_summary",
    "is_framework_descriptor",
    "java_to_descriptor",
    "method_ref_java",
    "parse_proto",
    "pretty_proto",
    "signature",
    "summarize_capabilities",
]
__version__ = "0.0.1"
