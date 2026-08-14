"""Inbound ports (use-case interfaces) for the dexllm SDK.

Each is a ``@runtime_checkable`` :class:`typing.Protocol` — a structural contract
a consumer programs against without importing the concrete adapter. Ports are
split by concern; :class:`DexAnalysisUseCase` is the full session-bound surface a
loaded APK/dex source exposes (the adapter implements it). Argument and return
types are the typed domain models in :mod:`dexllm.sdk.model`.

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
    ExtractedDex,
    FieldInfo,
    FieldMatch,
    IocReport,
    MethodAst,
    MethodInfo,
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

    def verify(
        self, path: str, *, lenient: bool = False
    ) -> tuple[DexVerifyStatus, ...]:
        """Structurally verify a path's dex(es) without loading.

        One verdict per dex; byte-identical to ``verify_report`` after loading
        the same source. Never raises — a malformed / unopenable / non-dex path
        is reported as a ``valid=False`` verdict.
        """
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

    def list_fields(self) -> tuple[str, ...]:
        """Every field descriptor (``Lcls;->name:Type``) across all loaded dexes.

        The dex id-table references (declared + referenced) — exactly the
        concatenation of :meth:`list_fields_in_dex` over every dex.
        """
        ...

    def list_fields_in_dex(self, dex_id: int) -> tuple[str, ...]:
        """Every field descriptor of one specific loaded dex (empty if out of range)."""
        ...

    def list_methods(self) -> tuple[str, ...]:
        """Every method descriptor (``Lcls;->name(proto)ret``) across all loaded dexes.

        The dex id-table references (declared + referenced) — exactly the
        concatenation of :meth:`list_methods_in_dex` over every dex.
        """
        ...

    def list_methods_in_dex(self, dex_id: int) -> tuple[str, ...]:
        """Every method descriptor of one specific loaded dex (empty if out of range)."""
        ...

    def list_value_strings(self) -> tuple[str, ...]:
        """Every distinct string the app loads as a value (the IOC feed)."""
        ...

    def list_class_strings(self, class_descriptor: str) -> tuple[str, ...]:
        """Every value-string one class carries (the class-scoped forward accessor).

        The union over the class's DECLARED methods' ``const-string`` operands
        (ascending ``method_idx``, no superclass walk) followed by its static-field
        ``VALUE_STRING`` initializers. Deduplicated, first-occurrence order.
        Empty if the class is not declared in any loaded dex.

        A static-init string is not in the reverse (const-string) index, so it is not
        findable via ``find_classes_using_strings`` — use
        ``find_classes_declaring_strings``. See docs/api.md's round-trip caveat.
        """
        ...

    def list_method_strings(self, method_descriptor: str) -> tuple[str, ...]:
        """Every value-string one method loads (its ``const-string`` operands).

        Bytecode only: a ``static final String`` is a class-level EncodedValue, so
        it is reported by :meth:`list_class_strings` instead. Deduplicated,
        first-occurrence order. Empty for an external / abstract / native method.
        """
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

    def extract_dex(self, dex_id: int) -> ExtractedDex:
        """Return one loaded dex's bytes together with its provenance.

        ``data`` is the logical dex's own slice — ``header_off`` is applied, so a
        concatenated / packer container yields THIS dex, not the shared image —
        and ``source`` / ``entry`` / ``offset`` say where it came from, which
        nothing else can answer: the verify report's ``name`` is only the entry
        name for a zip member, and a concatenated source has no report row at all
        for its second logical dex. Empty ``data`` and ``dex_id == -1`` for an
        out-of-range ``dex_id``. Feeds a runtime-decrypted dex back into analysis
        via ``add_dumped_dexes``.
        """
        ...

    def extract_dexes(self) -> tuple[ExtractedDex, ...]:
        """Return every loaded dex, in ``dex_id`` order — the dump-the-container form.

        ``len()`` equals ``dex_count()``. A separate PLURAL name rather than an
        optional ``dex_id``: a signature whose RETURN TYPE changes with its
        argument forces every caller to branch, and this is the same all-vs-one
        axis ``list_classes()`` / ``list_classes_in_dex(dex_id)`` already draws.
        It COPIES every dex's bytes, so prefer :meth:`extract_dex` for one.
        """
        ...


@runtime_checkable
class CrossReferencePort(Protocol):
    """Caller ↔ callee (method) + read/write (field) cross-reference."""

    def find_call_sites_to(self, method_descriptor: str) -> tuple[CallSite, ...]:
        """Every call site invoking the given method — its CALLERS.

        The REVERSE edge, so ``callee_descriptor`` is FIXED (the queried API) on
        every returned :class:`CallSite` and the ``caller_*`` fields vary. One
        entry per invoke INSTRUCTION — a caller that invokes the API twice
        appears twice. ``bytecode_offset`` is an offset inside the caller.
        """
        ...

    def find_call_sites_from(self, method_descriptor: str) -> tuple[CallSite, ...]:
        """Every call site INSIDE the given method — the methods it invokes (CALLEES).

        The FORWARD edge of :meth:`find_call_sites_to`, so the ``caller_*`` fields
        are FIXED (this method) on every returned :class:`CallSite` and
        ``callee_descriptor`` varies. Empty for an external / bodyless /
        unresolved method.
        """
        ...

    def resolve_call_args(self, method_descriptor: str) -> tuple[ResolvedCallSite, ...]:
        """Call sites of the method with each argument's resolved origin.

        Same reverse direction (and same fixed/varying fields) as
        :meth:`find_call_sites_to`, plus ``args``.
        """
        ...

    def find_methods_reading_field(self, field_descriptor: str) -> tuple[str, ...]:
        """Descriptors of methods that READ (iget*/sget*) the given field.

        ``field_descriptor`` is the ``Lcls;->name:Type`` form; empty if the field
        isn't declared in a loaded dex.

        One entry per access INSTRUCTION, not per method (the same semantics as
        :class:`CallSite`), so a method with two ``iget``s of the field appears
        twice. Wrap in ``set()`` when you want distinct methods.
        """
        ...

    def find_methods_writing_field(self, field_descriptor: str) -> tuple[str, ...]:
        """Descriptors of methods that WRITE (iput*/sput*) the given field.

        Same per-instruction (undeduplicated) semantics as
        :meth:`find_methods_reading_field`.
        """
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

    def find_classes_declaring_strings(
        self,
        strings: Sequence[str],
        *,
        match_type: MatchType = "contains",
        ignore_case: bool = False,
    ) -> tuple[ClassMatch, ...]:
        """Find classes that DECLARE all of ``strings`` as static-field constants.

        The declaration-side counterpart of :meth:`find_classes_using_strings`, which
        searches the ``const-string`` bytecode index and therefore cannot see a
        ``static final String`` the app never loads. Same match semantics. There is no
        method-level analogue — an ``EncodedValue`` belongs to a class, not a method.
        """
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

    def find_fields_by_name(
        self,
        name: str,
        *,
        match_type: MatchType = "contains",
        declaring_class: str = "",
        ignore_case: bool = False,
    ) -> tuple[FieldMatch, ...]:
        """Find fields by name, optionally scoped to a declaring class."""
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

    Split by concern — metadata, fields and methods are separate queries, so a
    consumer that only wants one does not pull the whole class blob.
    :meth:`EnumerationPort.list_class_methods` remains the descriptor-only view of
    the same members.
    """

    def class_info(self, class_descriptor: str) -> ClassInfo:
        """Class metadata (superclass, interfaces, access, source) — no members."""
        ...

    def class_fields(self, class_descriptor: str) -> tuple[FieldInfo, ...]:
        """Return the class's fields (name, type, access flags).

        The list is keyed on the dex ``field_ids`` table, so it also holds
        inherited fields the class only REFERENCES; those carry
        ``access_flags`` ``None`` (UNKNOWN) while the declaring class reports the
        real modifier for the same field (dexllm#41).
        """
        ...

    def class_methods(self, class_descriptor: str) -> tuple[MethodInfo, ...]:
        """Return the class's declared methods (name, proto, access flags).

        The symmetric twin of :meth:`class_fields`, and the only way to reach a
        method's MODIFIERS without leaving the SDK:
        :meth:`EnumerationPort.list_class_methods` returns descriptors, which
        carry no access flags (dexllm#37).

        On an EXTERNAL class the two diverge: this reports the members
        reconstructed from other classes' ``method_ids`` references (with
        ``access_flags`` ``None`` — UNKNOWN, since there is no ``class_data`` to
        read them from), while ``list_class_methods`` returns nothing because the
        class declares nothing here. Reading a modifier off such a member raises
        ``TypeError`` rather than answering 0, which in dex is a legal value
        (dexllm#41); check :attr:`ClassInfo.is_internal` first.
        """
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

    Composes every session-bound port; the adapter (:class:`~dexllm.sdk.adapter.DexKitAdapter`)
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
