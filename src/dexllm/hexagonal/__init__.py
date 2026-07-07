"""Hexagonal (ports & adapters) API for dexllm.

A typed, structural interface so other code consumes dexllm as a domain service,
not as a bag of dict/struct returns:

  - :mod:`.model` — frozen dataclasses for every value crossing a boundary.
  - :mod:`.ports` — ``@runtime_checkable`` Protocol use cases (the inbound ports).
  - :mod:`.adapter` — :class:`DexKitAdapter` implementing them over ``dexllm.DexKit``.

Typical use::

    from dexllm.hexagonal import open_apk, identify, DexAnalysisUseCase

    session: DexAnalysisUseCase = open_apk("app.apk")
    for group in session.permission_callers(app_only=True):
        print(group.permission, group.protection_level)
    ioc = session.extract_iocs()
    method = session.decompile_method("Lcom/x/Y;->m(I)V")
"""

from __future__ import annotations

from .adapter import ContainerProbe, DexKitAdapter, identify, open_apk
from .model import (
    ArgOrigin,
    CallSite,
    CapabilityHit,
    CapabilityReport,
    ContainerInfo,
    ContentProviderUse,
    DecompiledClass,
    DecompiledMethod,
    DexVerifyStatus,
    ExternalMethodRef,
    Indicator,
    IocReport,
    MethodAst,
    PermissionCallerGroup,
    PermissionCallerRow,
    ResolvedCallSite,
    SourceLocation,
    StatementLocation,
)
from .ports import (
    CapabilityPort,
    ContainerProbePort,
    ContentProviderPort,
    CrossReferencePort,
    DecompilationPort,
    DexAnalysisUseCase,
    EnumerationPort,
    IndicatorExtractionPort,
    PermissionAnalysisPort,
)

__all__ = [
    # factories / adapters
    "open_apk",
    "identify",
    "DexKitAdapter",
    "ContainerProbe",
    # ports
    "DexAnalysisUseCase",
    "ContainerProbePort",
    "DecompilationPort",
    "EnumerationPort",
    "CrossReferencePort",
    "PermissionAnalysisPort",
    "IndicatorExtractionPort",
    "CapabilityPort",
    "ContentProviderPort",
    # models
    "ContainerInfo",
    "DexVerifyStatus",
    "SourceLocation",
    "StatementLocation",
    "DecompiledMethod",
    "DecompiledClass",
    "MethodAst",
    "ExternalMethodRef",
    "ArgOrigin",
    "CallSite",
    "ResolvedCallSite",
    "PermissionCallerRow",
    "PermissionCallerGroup",
    "Indicator",
    "IocReport",
    "CapabilityHit",
    "CapabilityReport",
    "ContentProviderUse",
]
