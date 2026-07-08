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

from collections.abc import Mapping, Sequence
from typing import Literal, Protocol, runtime_checkable

from .model import (
    CallSite,
    CapabilityReport,
    ClassInfo,
    ClassMatch,
    ContainerInfo,
    ContentProviderUse,
    DecompiledClass,
    DecompiledMethod,
    DexVerifyStatus,
    ExternalFieldRef,
    ExternalMethodRef,
    ExternalTypeRef,
    FieldInfo,
    IocReport,
    MethodAst,
    MethodMatch,
    PermissionCallerGroup,
    ResolvedCallSite,
    TypeReferences,
)

# The five name/descriptor match modes DexKit's search accepts.
MatchType = Literal["equals", "contains", "starts_with", "ends_with", "regex"]


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

    def render_method_smali(self, method_descriptor: str) -> str:
        """Render one method as baksmali-style smali (``""`` if unknown/external)."""
        ...

    def render_class_smali(self, class_descriptor: str) -> str:
        """Render a whole class as baksmali-style smali (``""`` if external)."""
        ...


@runtime_checkable
class EnumerationPort(Protocol):
    """Class / method / string / external-reference enumeration."""

    def list_classes(self) -> tuple[str, ...]:
        """Every class descriptor declared in any loaded dex."""
        ...

    def list_classes_in_dex(self, dex_id: int) -> tuple[str, ...]:
        """Every class descriptor declared in one specific loaded dex.

        The per-dex view of :meth:`list_classes` — for multidex attribution (which
        ``classes*.dex`` a class lives in). Empty for an out-of-range ``dex_id``.
        """
        ...

    def list_class_methods(self, class_descriptor: str) -> tuple[str, ...]:
        """Every declared method descriptor of the given class."""
        ...

    def list_field_descriptors(self) -> tuple[str, ...]:
        """Every field descriptor (``Lcls;->name:Type``) across all loaded dexes.

        The dex id-table references (declared + referenced) — exactly the
        concatenation of :meth:`list_field_descriptors_in_dex` over every dex.
        """
        ...

    def list_field_descriptors_in_dex(self, dex_id: int) -> tuple[str, ...]:
        """Every field descriptor of one specific loaded dex (empty if out of range)."""
        ...

    def list_method_descriptors(self) -> tuple[str, ...]:
        """Every method descriptor (``Lcls;->name(proto)ret``) across all loaded dexes.

        The dex id-table references (declared + referenced) — exactly the
        concatenation of :meth:`list_method_descriptors_in_dex` over every dex.
        """
        ...

    def list_method_descriptors_in_dex(self, dex_id: int) -> tuple[str, ...]:
        """Every method descriptor of one specific loaded dex (empty if out of range)."""
        ...

    def list_value_strings(self) -> tuple[str, ...]:
        """Every distinct string the app loads as a value (the IOC feed)."""
        ...

    def list_external_method_refs(
        self, *, framework_only: bool = True
    ) -> tuple[ExternalMethodRef, ...]:
        """Framework / library methods the app references but does not define."""
        ...

    def list_external_field_refs(
        self, *, framework_only: bool = True
    ) -> tuple[ExternalFieldRef, ...]:
        """Framework / library fields the app references but does not define."""
        ...

    def list_external_type_refs(
        self, *, framework_only: bool = True
    ) -> tuple[ExternalTypeRef, ...]:
        """Framework / library types the app references but does not declare."""
        ...

    def verify_report(self) -> tuple[DexVerifyStatus, ...]:
        """Per-loaded-dex structural-verification verdicts."""
        ...


@runtime_checkable
class DexExtractionPort(Protocol):
    """Raw per-dex byte extraction from a loaded source (container concern).

    Distinct from enumeration (which lists descriptors/strings) — this yields the
    raw dex image, the packer/dump-analysis primitive.
    """

    def extract_dex_bytes(self, dex_id: int) -> bytes:
        """Return the raw bytes of one loaded dex (its own ``file_size`` slice).

        The logical dex's own slice — ``header_off`` is applied, so a
        concatenated / packer container yields THIS dex, not the shared image.
        Empty ``bytes`` for an out-of-range ``dex_id``. Feeds a runtime-decrypted
        dex back into analysis via ``add_dumped_dexes``.
        """
        ...


@runtime_checkable
class CrossReferencePort(Protocol):
    """Caller ↔ callee (method) + read/write (field) cross-reference."""

    def find_call_sites(self, api_descriptor: str) -> tuple[CallSite, ...]:
        """Every call site invoking the given API descriptor (its CALLERS)."""
        ...

    def find_call_sites_from_method(
        self, method_descriptor: str
    ) -> tuple[CallSite, ...]:
        """Every call site INSIDE the given method — the methods it invokes (CALLEES).

        The forward direction of :meth:`find_call_sites`: each :class:`CallSite` fixes
        the caller (this method) and varies ``callee_descriptor``. Empty for an
        external / bodyless / unresolved method.
        """
        ...

    def resolve_call_args(self, api_descriptor: str) -> tuple[ResolvedCallSite, ...]:
        """Call sites of the API with each argument's resolved origin."""
        ...

    def find_field_readers(self, field_descriptor: str) -> tuple[str, ...]:
        """Descriptors of methods that READ (iget*/sget*) the given field.

        ``field_descriptor`` is the ``Lcls;->name:Type`` form; empty if the field
        isn't declared in a loaded dex.
        """
        ...

    def find_field_writers(self, field_descriptor: str) -> tuple[str, ...]:
        """Descriptors of methods that WRITE (iput*/sput*) the given field."""
        ...

    def find_type_references(self, type_descriptor: str) -> TypeReferences:
        """Signature-position references to a ``Lpkg/Cls;`` type.

        Fields of the type + methods returning it + methods taking it as a param
        (NOT call/instruction xref). Empty lists if the type isn't referenced.
        """
        ...


@runtime_checkable
class SearchPort(Protocol):
    """DexKit's L1–L7 static search over classes and methods.

    Find classes / methods by name, hierarchy, annotation, referenced strings, or
    numeric literals. Each hit is a light :class:`ClassMatch` / :class:`MethodMatch`
    (descriptor + dex location). ``match_type`` is one of :data:`MatchType`. The
    ``batch_*`` forms run many string queries at once over a shared Aho-Corasick
    trie (far faster than N single calls) and return a mapping keyed by query key.
    """

    def find_classes_by_name(
        self,
        name: str,
        *,
        match_type: MatchType = "contains",
        ignore_case: bool = False,
    ) -> tuple[ClassMatch, ...]:
        """Find classes whose name matches ``name`` under ``match_type``."""
        ...

    def find_classes_by_super(
        self, super_class: str, *, match_type: MatchType = "equals"
    ) -> tuple[ClassMatch, ...]:
        """Find classes whose direct superclass matches ``super_class``."""
        ...

    def find_classes_implementing(
        self, interface_class: str, *, match_type: MatchType = "equals"
    ) -> tuple[ClassMatch, ...]:
        """Find classes that declare the given interface."""
        ...

    def find_classes_by_annotation(
        self, annotation_class: str, *, match_type: MatchType = "equals"
    ) -> tuple[ClassMatch, ...]:
        """Find classes annotated with ``annotation_class`` (obfuscated name ok)."""
        ...

    def find_classes_using_strings(
        self,
        strings: Sequence[str],
        *,
        match_type: MatchType = "contains",
        ignore_case: bool = False,
    ) -> tuple[ClassMatch, ...]:
        """Find classes whose bytecode references ALL of ``strings``."""
        ...

    def find_methods_by_name(
        self,
        name: str,
        *,
        match_type: MatchType = "contains",
        declaring_class: str = "",
        ignore_case: bool = False,
    ) -> tuple[MethodMatch, ...]:
        """Find methods by name, optionally scoped to a declaring class."""
        ...

    def find_methods_by_annotation(
        self, annotation_class: str, *, match_type: MatchType = "equals"
    ) -> tuple[MethodMatch, ...]:
        """Find methods annotated with ``annotation_class``."""
        ...

    def find_methods_using_strings(
        self,
        strings: Sequence[str],
        *,
        match_type: MatchType = "contains",
        ignore_case: bool = False,
    ) -> tuple[MethodMatch, ...]:
        """Find methods whose body references ALL of ``strings``."""
        ...

    def find_methods_using_int_literals(
        self, values: Sequence[int]
    ) -> tuple[MethodMatch, ...]:
        """Find methods whose body contains ALL of the given int literals."""
        ...

    def find_methods_using_double_literals(
        self, values: Sequence[float]
    ) -> tuple[MethodMatch, ...]:
        """Find methods whose body contains ALL of the given double literals."""
        ...

    def batch_find_classes_using_strings(
        self,
        query_map: Mapping[str, Sequence[str]],
        *,
        match_type: MatchType = "contains",
        ignore_case: bool = False,
    ) -> Mapping[str, tuple[ClassMatch, ...]]:
        """Run many class-by-strings queries at once; result keyed by query key."""
        ...

    def batch_find_methods_using_strings(
        self,
        query_map: Mapping[str, Sequence[str]],
        *,
        match_type: MatchType = "contains",
        ignore_case: bool = False,
    ) -> Mapping[str, tuple[MethodMatch, ...]]:
        """Run many method-by-strings queries at once; result keyed by query key."""
        ...


@runtime_checkable
class ClassInspectionPort(Protocol):
    """Fine-grained per-class inspection (the decomposition of a class summary).

    Split by concern — metadata, fields, and methods
    (:meth:`EnumerationPort.list_class_methods`) are separate queries, so a consumer
    that only wants one does not pull the whole class blob.
    """

    def class_info(self, class_descriptor: str) -> ClassInfo:
        """Class metadata (superclass, interfaces, access, source) — no members."""
        ...

    def class_fields(self, class_descriptor: str) -> tuple[FieldInfo, ...]:
        """Return the class's declared fields (name, type, access flags)."""
        ...

    def locate_class_dex(self, class_descriptor: str) -> int:
        """Return the id of the dex that DECLARES the class, or ``-1`` if external.

        The cheap dex-attribution lookup: it resolves only the declaring dex, unlike
        :meth:`class_info` which builds the whole class summary just to read
        ``.dex_id``. Use this when only the dex location is needed.
        """
        ...


@runtime_checkable
class PermissionAnalysisPort(Protocol):
    """Permission → gated-API → caller analysis over the bundled AOSP data."""

    def permission_callers(
        self, *, app_only: bool = True
    ) -> tuple[PermissionCallerGroup, ...]:
        """Return every permission the app exercises through real API calls.

        Covers ALL protection levels — each :class:`PermissionCallerGroup` is tagged
        with its ``protection_level`` (dangerous / signature / internal / normal /
        other) and carries the gated APIs + the app methods that call them. This is
        the full permission surface. ``app_only`` drops framework/library callers.

        The dangerous-only slice is a one-liner filter::

            [g for g in session.permission_callers(app_only=False)
             if g.protection_level == "dangerous"]
        """
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
class CacheControlPort(Protocol):
    """Session cache / lifecycle control — the operational (non-analysis) knobs.

    A long-lived embedder uses these to bound memory, free it between analyses, and
    warm caches before a latency-sensitive batch. Separated from the analysis ports
    so an analysis-only consumer never sees them.
    """

    def decompiler_cache_capacity(self) -> int:
        """Return the decompiled-method LRU capacity (entries; 0 = unbounded)."""
        ...

    def set_decompiler_cache_capacity(self, capacity: int) -> None:
        """Set the decompiled-method LRU capacity (0 disables eviction)."""
        ...

    def decompiler_cache_size(self) -> int:
        """Return the number of methods currently cached."""
        ...

    def clear_decompiler_cache(self) -> None:
        """Evict every cached decompiled method (free memory)."""
        ...

    def warm_analysis_caches(self) -> None:
        """Eagerly warm the upstream L2/L4 caches (else built lazily on first use)."""
        ...


@runtime_checkable
class DexAnalysisUseCase(
    DecompilationPort,
    EnumerationPort,
    DexExtractionPort,
    ClassInspectionPort,
    CrossReferencePort,
    SearchPort,
    PermissionAnalysisPort,
    IndicatorExtractionPort,
    CapabilityPort,
    ContentProviderPort,
    CacheControlPort,
    Protocol,
):
    """The full inbound use-case surface of one loaded APK / dex source.

    Composes every session-bound port; the adapter (:class:`~dexllm.hexagonal.adapter.DexKitAdapter`)
    implements it over a ``dexllm.DexKit``. Also exposes the construction sources,
    the primary source ``apk_path`` (= ``sources[0]``), and the loaded dex count.
    """

    @property
    def sources(self) -> tuple[str, ...]:
        """The source paths this session was constructed from."""
        ...

    @property
    def apk_path(self) -> str:
        """The primary (first) source path — ``sources[0]``.

        A convenience for the common single-source case; equal to ``sources[0]``.
        """
        ...

    def dex_count(self) -> int:
        """Return the number of dexes loaded into this session."""
        ...
