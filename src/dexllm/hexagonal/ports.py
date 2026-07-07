"""Inbound ports (use-case interfaces) for the dexllm hexagonal API.

Each is a ``@runtime_checkable`` :class:`typing.Protocol` — a structural contract
a consumer programs against without importing the concrete adapter. Ports are
split by concern; :class:`DexAnalysisUseCase` is the full session-bound surface a
loaded APK/dex source exposes (the adapter implements it). Argument and return
types are the typed domain models in :mod:`dexllm.hexagonal.model`.

``@runtime_checkable`` lets ``isinstance(x, DecompilationPort)`` verify a duck-typed
object at runtime (method presence only — Protocols don't check signatures).
"""

from __future__ import annotations

from typing import Protocol, runtime_checkable

from .model import (
    CallSite,
    CapabilityReport,
    ContainerInfo,
    ContentProviderUse,
    DangerousApiUsage,
    DecompiledClass,
    DecompiledMethod,
    DexVerifyStatus,
    ExternalMethodRef,
    IocReport,
    MethodAst,
    PermissionCallerGroup,
    ResolvedCallSite,
)


@runtime_checkable
class ContainerProbePort(Protocol):
    """Content-based container identification, without loading."""

    def identify(self, path: str) -> ContainerInfo:
        """Probe a file by content (dex magic / zip central directory)."""
        ...


@runtime_checkable
class DecompilationPort(Protocol):
    """Java / AST decompilation of a loaded source's methods and classes."""

    def decompile_method(self, method_descriptor: str) -> DecompiledMethod:
        """Decompile one method to Java text."""
        ...

    def decompile_method_with_pc_map(self, method_descriptor: str) -> DecompiledMethod:
        """Decompile one method plus a source-line ↔ bytecode-offset map."""
        ...

    def decompile_class(self, class_descriptor: str) -> DecompiledClass:
        """Decompile a whole class to Java text."""
        ...

    def decompile_method_ast(
        self, method_descriptor: str, *, include_source: bool = True
    ) -> MethodAst:
        """Return a method's structured AST (+ source unless disabled)."""
        ...


@runtime_checkable
class EnumerationPort(Protocol):
    """Class / method / string / external-reference enumeration."""

    def list_classes(self) -> tuple[str, ...]:
        """Every class descriptor declared in any loaded dex."""
        ...

    def list_class_methods(self, class_descriptor: str) -> tuple[str, ...]:
        """Every declared method descriptor of the given class."""
        ...

    def list_value_strings(self) -> tuple[str, ...]:
        """Every distinct string the app loads as a value (the IOC feed)."""
        ...

    def list_external_method_refs(
        self, *, framework_only: bool = True
    ) -> tuple[ExternalMethodRef, ...]:
        """Framework / library methods the app references but does not define."""
        ...

    def verify_report(self) -> tuple[DexVerifyStatus, ...]:
        """Per-loaded-dex structural-verification verdicts."""
        ...


@runtime_checkable
class CrossReferencePort(Protocol):
    """Caller / argument cross-reference for an API."""

    def find_call_sites(self, api_descriptor: str) -> tuple[CallSite, ...]:
        """Every call site invoking the given API descriptor."""
        ...

    def resolve_call_args(self, api_descriptor: str) -> tuple[ResolvedCallSite, ...]:
        """Call sites of the API with each argument's resolved origin."""
        ...


@runtime_checkable
class PermissionAnalysisPort(Protocol):
    """Permission → gated-API → caller analysis over the bundled AOSP data."""

    def permission_callers(
        self, *, app_only: bool = True
    ) -> tuple[PermissionCallerGroup, ...]:
        """Permissions the app exercises through real API calls, with callers."""
        ...

    def dangerous_permission_apis(self) -> tuple[DangerousApiUsage, ...]:
        """Dangerous-permission gated APIs the app references (no callers)."""
        ...


@runtime_checkable
class IndicatorExtractionPort(Protocol):
    """Static network-IOC extraction from the app's value strings."""

    def extract_iocs(
        self, *, denoise: bool = True, with_xref: bool = True
    ) -> IocReport:
        """Recover URLs / IPs / domains / emails / onion indicators."""
        ...


@runtime_checkable
class CapabilityPort(Protocol):
    """Capability summarisation over the bundled capability catalog."""

    def summarize_capabilities(self) -> CapabilityReport:
        """Summarize the app's capability profile (matched APIs, permissions)."""
        ...


@runtime_checkable
class ContentProviderPort(Protocol):
    """``content://`` provider-URI detection."""

    def detect_content_providers(
        self, *, with_xref: bool = True
    ) -> tuple[ContentProviderUse, ...]:
        """Return provider URIs the app references (sms / contacts / call-log)."""
        ...


@runtime_checkable
class DexAnalysisUseCase(
    DecompilationPort,
    EnumerationPort,
    CrossReferencePort,
    PermissionAnalysisPort,
    IndicatorExtractionPort,
    CapabilityPort,
    ContentProviderPort,
    Protocol,
):
    """The full inbound use-case surface of one loaded APK / dex source.

    Composes every session-bound port; the adapter (:class:`~dexllm.hexagonal.adapter.DexKitAdapter`)
    implements it over a ``dexllm.DexKit``. Also exposes the construction sources
    and the loaded dex count.
    """

    @property
    def sources(self) -> tuple[str, ...]:
        """The source paths this session was constructed from."""
        ...

    def dex_count(self) -> int:
        """Return the number of dexes loaded into this session."""
        ...
