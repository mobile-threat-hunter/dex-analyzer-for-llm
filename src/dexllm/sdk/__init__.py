"""Typed SDK for embedding dexllm as a domain service.

A structural interface so other code consumes dexllm through stable typed
contracts, not as a bag of dict/struct returns. Built internally with a
hexagonal (ports & adapters) layout:

  - :mod:`.model` — frozen dataclasses for every value crossing a boundary.
  - :mod:`.ports` — ``@runtime_checkable`` Protocol use cases (the inbound ports).
  - :mod:`.adapter` — :class:`DexKitAdapter` implementing them over ``dexllm.DexKit``.

Typical use::

    from dexllm.sdk import open_apk, identify, DexAnalysisUseCase

    session: DexAnalysisUseCase = open_apk("app.apk")
    for group in session.permission_callers(app_only=True):
        print(group.permission, group.protection_level)
    ioc = session.extract_iocs()
    method = session.decompile_method("Lcom/x/Y;->m(I)V")
"""

from __future__ import annotations

from .adapter import ContainerProbe, DexKitAdapter, identify, open_apk, verify
from .model import (
    ApiCallers,
    ApiUsage,
    CallSite,
    CapabilityReport,
    ClassInfo,
    ClassRef,
    ContainerInfo,
    ContentProviderUse,
    DecompiledClass,
    DecompiledMethod,
    DexVerifyStatus,
    ExternalFieldRef,
    ExternalMethodRef,
    ExternalTypeRef,
    ExtractedDex,
    FieldInfo,
    FieldRef,
    Indicator,
    IocReport,
    MethodAst,
    MethodInfo,
    MethodRef,
    PermissionCallers,
    ResolvedArg,
    ResolvedCallSite,
    SourceLocation,
    StatementLocation,
    TypeReferences,
)
from .ports import (
    CacheControlPort,
    CapabilityPort,
    ClassInspectionPort,
    ContainerProbePort,
    ContentProviderPort,
    CrossReferencePort,
    DecompilationPort,
    DexAnalysisUseCase,
    DexExtractionPort,
    EnumerationPort,
    IndicatorExtractionPort,
    MatchType,
    PermissionAnalysisPort,
    SearchPort,
)

__all__ = [
    # factories / adapters
    "open_apk",
    "identify",
    "verify",
    "DexKitAdapter",
    "ContainerProbe",
    # ports
    "DexAnalysisUseCase",
    "ContainerProbePort",
    "DecompilationPort",
    "EnumerationPort",
    "DexExtractionPort",
    "ClassInspectionPort",
    "CrossReferencePort",
    "SearchPort",
    "PermissionAnalysisPort",
    "IndicatorExtractionPort",
    "CapabilityPort",
    "ContentProviderPort",
    "CacheControlPort",
    # search
    "MatchType",
    "ClassRef",
    "MethodRef",
    # models
    "ContainerInfo",
    "DexVerifyStatus",
    "ExtractedDex",
    "SourceLocation",
    "StatementLocation",
    "DecompiledMethod",
    "DecompiledClass",
    "MethodAst",
    "MethodInfo",
    "ExternalMethodRef",
    "ExternalFieldRef",
    "ExternalTypeRef",
    "ClassInfo",
    "FieldInfo",
    "FieldRef",
    "ResolvedArg",
    "CallSite",
    "ResolvedCallSite",
    "TypeReferences",
    "ApiCallers",
    "PermissionCallers",
    "Indicator",
    "IocReport",
    "ApiUsage",
    "CapabilityReport",
    "ContentProviderUse",
]
