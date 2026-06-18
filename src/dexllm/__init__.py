"""dexllm — LLM-facing DEX/APK static analyzer.

A pybind11 wrapper around LuckyPray DexKit Core with an embedded, fully
ported DAD-aligned Java decompiler (C++ port of androguard's DAD in
``native/dad_cpp/``). Surfaces:

- the native ``DexKit`` class: decompile (method/class/AST/smali), search
  (L1-L7: by name/string/annotation/super/API call-site), enumeration,
  and external-API reference listing;
- higher-level Python facades (descriptor helpers, ref filters, capability
  summary, ``safe_*`` timeout wrappers);
- ``dexllm.tools`` — a shared tool catalog reused by the MCP server
  (``python -m dexllm.mcp_server``) and the FastAPI/SSE backend
  (``uvicorn dexllm.server:app``).

The decompiler is complete: ``decompile_method_java`` / ``decompile_class_java``
return DAD-quality Java, and ``decompile_method_ast`` returns the full DAD
``dast.py`` nested AST. Install LLM extras with ``pip install -e .[all]``.
"""

# Import side-effect: attach .java_class/.parameters/.return_type/etc.
# properties onto the native ref classes.
from . import (
    _enrich,  # noqa: F401
    descriptors,
)
from . import tools as tools  # noqa: F401 — public sub-module for LLM integrations
from ._dexkit_core import (
    ArgOrigin,
    CallSite,
    DexKit,
    ExternalFieldRef,
    ExternalMethodRef,
    ExternalTypeRef,
    ResolvedCallSite,
    identify,
    is_framework_descriptor,
)
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
from .safe import (
    DEFAULT_TIMEOUT_S,
    is_timeout_marker,
    safe_decompile_class_java,
    safe_decompile_method_java,
)

__all__ = [
    "ApiHit",
    "ArgOrigin",
    "CallSite",
    "CapabilityReport",
    "DEFAULT_TIMEOUT_S",
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
    "identify",
    "is_framework_descriptor",
    "is_timeout_marker",
    "java_to_descriptor",
    "method_ref_java",
    "parse_proto",
    "pretty_proto",
    "safe_decompile_class_java",
    "safe_decompile_method_java",
    "signature",
    "summarize_capabilities",
]
__version__ = "0.1.5"
