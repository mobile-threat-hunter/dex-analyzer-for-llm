"""Typed shadow of the ``import dexllm`` top-level surface.

Mirrors ``src/dexllm/__init__.py`` exactly — the same re-exports and the same
``__all__``. Each name is re-exported from its runtime source, so its type comes
from that source (``_dexkit_core.pyi`` for the native names, the submodules'
inline annotations for the pure-Python helpers). Only names the runtime actually
exports appear here.
"""

from . import descriptors as descriptors
from . import tools as tools
from ._dexkit_core import (
    ArgOrigin as ArgOrigin,
)
from ._dexkit_core import (
    CallSite as CallSite,
)
from ._dexkit_core import (
    DexKit as DexKit,
)
from ._dexkit_core import (
    ExternalFieldRef as ExternalFieldRef,
)
from ._dexkit_core import (
    ExternalMethodRef as ExternalMethodRef,
)
from ._dexkit_core import (
    ExternalTypeRef as ExternalTypeRef,
)
from ._dexkit_core import (
    ResolvedCallSite as ResolvedCallSite,
)
from ._dexkit_core import (
    identify as identify,
)
from ._dexkit_core import (
    is_framework_descriptor as is_framework_descriptor,
)
from ._dexkit_core import (
    verify as verify,
)
from .capability import (
    ApiHit as ApiHit,
)
from .capability import (
    CapabilityReport as CapabilityReport,
)
from .capability import (
    summarize_capabilities as summarize_capabilities,
)
from .dangerous_api import (
    PERM_LEVELS as PERM_LEVELS,
)
from .dangerous_api import (
    dangerous_permission_api_callers as dangerous_permission_api_callers,
)
from .dangerous_api import (
    dangerous_permission_apis as dangerous_permission_apis,
)
from .dangerous_api import (
    permission_api_callers as permission_api_callers,
)
from .descriptors import (
    descriptor_to_java as descriptor_to_java,
)
from .descriptors import (
    java_to_descriptor as java_to_descriptor,
)
from .descriptors import (
    method_ref_java as method_ref_java,
)
from .descriptors import (
    parse_proto as parse_proto,
)
from .descriptors import (
    pretty_proto as pretty_proto,
)
from .descriptors import (
    signature as signature,
)
from .filters import (
    filter_field_refs as filter_field_refs,
)
from .filters import (
    filter_method_refs as filter_method_refs,
)
from .filters import (
    filter_type_refs as filter_type_refs,
)
from .filters import (
    find_call_sites_to_ref as find_call_sites_to_ref,
)
from .format import (
    format_class as format_class,
)
from .format import (
    format_class_summary as format_class_summary,
)
from .ioc import (
    IOC_CATEGORIES as IOC_CATEGORIES,
)
from .ioc import (
    extract_iocs as extract_iocs,
)
from .packer import add_dumped_dexes as add_dumped_dexes
from .providers import detect_content_providers as detect_content_providers
from .safe import (
    DEFAULT_TIMEOUT_S as DEFAULT_TIMEOUT_S,
)
from .safe import (
    is_timeout_marker as is_timeout_marker,
)
from .safe import (
    safe_decompile_class_java as safe_decompile_class_java,
)
from .safe import (
    safe_decompile_method_java as safe_decompile_method_java,
)

__version__: str

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
    "add_dumped_dexes",
    "descriptor_to_java",
    "descriptors",
    "filter_field_refs",
    "filter_method_refs",
    "filter_type_refs",
    "IOC_CATEGORIES",
    "PERM_LEVELS",
    "dangerous_permission_apis",
    "dangerous_permission_api_callers",
    "permission_api_callers",
    "detect_content_providers",
    "extract_iocs",
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
    "verify",
]
