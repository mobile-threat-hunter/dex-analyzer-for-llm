"""Outbound adapter: implement the SDK ports over ``dexllm.DexKit``.

:class:`DexKitAdapter` wraps one loaded ``DexKit`` and converts every raw return
(pybind objects, plain dicts) into the typed domain models, so it satisfies
:class:`~dexllm.sdk.ports.DexAnalysisUseCase`. :func:`open_apk` is the
factory; :func:`identify` is the load-free container probe. The underlying
``DexKit`` is reachable via :pyattr:`DexKitAdapter.raw` as an escape hatch.
"""

from __future__ import annotations

import os
from collections.abc import Mapping, Sequence
from types import MappingProxyType
from typing import Any, Union

import dexllm

from .._argkinds import ARG_VALUE_ATTR_BY_KIND
from ..descriptors import require_member_descriptor, require_type_descriptor
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
    TlsTrustComponent,
    TypeReferences,
)
from .ports import MatchType

# A single apk/dex path or a sequence of them; each element accepts anything
# os.fspath understands (str or os.PathLike, e.g. pathlib.Path).
SourceLike = Union[str, "os.PathLike[str]"]
Sources = Union[SourceLike, "list[SourceLike]", "tuple[SourceLike, ...]"]

# ── raw → model converters ────────────────────────────────────────────────────


def _to_arg(a: object) -> ResolvedArg:
    """Convert a pybind ResolvedArg to the typed model (only the kind's field set)."""
    field = ARG_VALUE_ATTR_BY_KIND.get(a.kind)  # type: ignore[attr-defined]
    kw = {field: getattr(a, field)} if field else {}
    return ResolvedArg(
        kind=a.kind,  # type: ignore[attr-defined]
        register_index=a.register_index,  # type: ignore[attr-defined]
        crossed_branch=a.crossed_branch,  # type: ignore[attr-defined]
        **kw,
    )


def _to_ext_ref(r: object) -> ExternalMethodRef:
    """Convert a pybind ExternalMethodRef to the typed model."""
    return ExternalMethodRef(
        class_descriptor=r.class_descriptor,  # type: ignore[attr-defined]
        name=r.name,  # type: ignore[attr-defined]
        proto=r.proto,  # type: ignore[attr-defined]
        java_class=r.java_class,  # type: ignore[attr-defined]
        java_signature=r.java_signature,  # type: ignore[attr-defined]
        descriptor=r.descriptor,  # type: ignore[attr-defined]
        return_type=r.return_type,  # type: ignore[attr-defined]
        parameters=tuple(r.parameters),  # type: ignore[attr-defined]
        is_constructor=r.is_constructor,  # type: ignore[attr-defined]
        is_static_initializer=r.is_static_initializer,  # type: ignore[attr-defined]
        referenced_in_dex_ids=tuple(r.referenced_in_dex_ids),  # type: ignore[attr-defined]
    )


def _to_ext_field_ref(r: object) -> ExternalFieldRef:
    """Convert a pybind external field ref to the typed model."""
    return ExternalFieldRef(
        class_descriptor=r.class_descriptor,  # type: ignore[attr-defined]
        name=r.name,  # type: ignore[attr-defined]
        type=r.type,  # type: ignore[attr-defined]
        java_class=r.java_class,  # type: ignore[attr-defined]
        java_type=r.java_type,  # type: ignore[attr-defined]
        java_signature=r.java_signature,  # type: ignore[attr-defined]
        descriptor=r.descriptor,  # type: ignore[attr-defined]
        referenced_in_dex_ids=tuple(r.referenced_in_dex_ids),  # type: ignore[attr-defined]
    )


def _to_ext_type_ref(r: object) -> ExternalTypeRef:
    """Convert a pybind external type ref to the typed model."""
    return ExternalTypeRef(
        descriptor=r.descriptor,  # type: ignore[attr-defined]
        java_type=r.java_type,  # type: ignore[attr-defined]
        referenced_in_dex_ids=tuple(r.referenced_in_dex_ids),  # type: ignore[attr-defined]
    )


def _str_seq(strings: Sequence[str]) -> list[str]:
    """Coerce a sequence of strings to a list, rejecting a bare str / bytes.

    A bare ``str`` IS a ``Sequence[str]`` (of characters), so ``list("http")`` would
    silently become ``["h", "t", "t", "p"]`` and the search would AND four
    single-character substrings — a plausibly-wrong result with no error. Guard it.
    """
    if isinstance(strings, (str, bytes)):
        raise TypeError(
            "expected a sequence of strings, got a bare "
            f"{type(strings).__name__}; wrap it in a list, e.g. ['...']"
        )
    return list(strings)


def _to_class_ref(r: object) -> ClassRef:
    """Convert a pybind ClassRef to the typed model."""
    return ClassRef(
        class_idx=r.class_idx,  # type: ignore[attr-defined]
        descriptor=r.descriptor,  # type: ignore[attr-defined]
        dex_id=r.dex_id,  # type: ignore[attr-defined]
    )


def _to_method_ref(r: object) -> MethodRef:
    """Convert a pybind MethodRef to the typed model."""
    return MethodRef(
        method_idx=r.method_idx,  # type: ignore[attr-defined]
        descriptor=r.descriptor,  # type: ignore[attr-defined]
        dex_id=r.dex_id,  # type: ignore[attr-defined]
    )


def _to_field_ref(r: object) -> FieldRef:
    """Convert a pybind FieldRef to the typed model."""
    return FieldRef(
        field_idx=r.field_idx,  # type: ignore[attr-defined]
        descriptor=r.descriptor,  # type: ignore[attr-defined]
        dex_id=r.dex_id,  # type: ignore[attr-defined]
    )


def _to_indicators(items: "list[dict]") -> tuple[Indicator, ...]:
    """Convert an extract_iocs indicator list to a tuple of typed Indicators."""
    return tuple(
        Indicator(
            value=d["value"],
            methods=tuple(d.get("methods", ())),
            declared_in=tuple(d.get("declared_in", ())),
        )
        for d in items
    )


# ── adapter ───────────────────────────────────────────────────────────────────


class DexKitAdapter:
    """Session-bound adapter implementing :class:`DexAnalysisUseCase`.

    Construct with a single apk/dex path or a list of sources (earlier sources get
    lower dex_ids; first-wins on a class collision). ``lenient`` runs the load-time
    verifier in ART-structural-equivalent mode for partially-decrypted dumps.
    """

    def __init__(self, sources: Sources, *, lenient: bool = False) -> None:
        """Load ``sources`` into a ``DexKit`` (see the class docstring for order).

        Accepts a single path or a sequence of paths; each may be a ``str`` or any
        ``os.PathLike`` (e.g. ``pathlib.Path``), normalised via ``os.fspath``.
        """
        if isinstance(sources, (str, os.PathLike)):
            src_list = [os.fspath(sources)]
        else:
            src_list = [os.fspath(s) for s in sources]
        if len(src_list) == 1 and not lenient:
            self._dk = dexllm.DexKit(src_list[0])
        else:
            self._dk = dexllm.DexKit(src_list, lenient=lenient)
        self._dex_names: dict[int, str] | None = None  # lazy dex_id → file-name map

    def _dex_name(self, dex_id: int) -> str:
        """Map a dex_id to its file name (``classes.dex`` / …); ``""`` if unknown.

        Excludes ``dex_id < 0``: verify_report tags a REJECTED (unverifiable) dex with
        ``dex_id == -1``, the same sentinel an external class uses — filtering it keeps
        an external class's dex_name empty instead of a rejected dex's file name.
        """
        if self._dex_names is None:
            self._dex_names = {
                r["dex_id"]: r["name"]
                for r in self._dk.verify_report()
                if r["dex_id"] >= 0
            }
        return self._dex_names.get(dex_id, "")

    # -- escape hatch / session metadata --

    @property
    def raw(self) -> "dexllm.DexKit":
        """Return the underlying ``dexllm.DexKit`` (advanced / L7 search access).

        This is the low-level primitive and is NOT descriptor-validated: an identity
        call made through it (e.g. ``adapter.raw.find_call_sites_to("android.util.Log->d")``
        with a dotted name) bypasses the ``require_*`` guards and returns the raw
        silent-empty instead of a guiding error. Use the adapter's own methods for the
        validated contract; reach for ``.raw`` only when you intentionally want the
        unguarded binding.
        """
        return self._dk

    @property
    def sources(self) -> tuple[str, ...]:
        """Return the source paths this session was constructed from."""
        return tuple(self._dk.sources())

    @property
    def apk_path(self) -> str:
        """Return the primary (first) source path — equal to ``sources[0]``."""
        return self._dk.apk_path()

    def dex_count(self) -> int:
        """Return the number of dexes loaded into this session."""
        return self._dk.dex_count()

    # -- DecompilationPort --

    def decompile_method(self, method_descriptor: str) -> DecompiledMethod:
        """Decompile one method to Java text."""
        require_member_descriptor(method_descriptor)
        src = self._dk.decompile_method(method_descriptor)
        return DecompiledMethod(
            descriptor=method_descriptor, source=src, found=bool(src)
        )

    def decompile_method_with_pc_map(self, method_descriptor: str) -> DecompiledMethod:
        """Decompile one method plus a source-line ↔ bytecode-offset map."""
        require_member_descriptor(method_descriptor)
        r = self._dk.decompile_method_with_pc_map(method_descriptor)
        return DecompiledMethod(
            descriptor=method_descriptor,
            source=r["source"],
            found=bool(r["source"]),
            pc_map=tuple(
                SourceLocation(line=line, byte_offset=off) for line, off in r["pc_map"]
            ),
        )

    def decompile_class(self, class_descriptor: str) -> DecompiledClass:
        """Decompile a whole class to Java text."""
        require_type_descriptor(class_descriptor)
        return DecompiledClass(
            descriptor=class_descriptor,
            source=self._dk.decompile_class(class_descriptor),
        )

    def decompile_method_ast(
        self, method_descriptor: str, *, include_source: bool = True
    ) -> MethodAst:
        """Return a method's structured AST (+ source unless disabled)."""
        require_member_descriptor(method_descriptor)
        r = self._dk.decompile_method_ast(
            method_descriptor, include_source=include_source
        )
        return MethodAst(
            found=r["found"],
            class_descriptor=r["class_descriptor"],
            name=r["name"],
            proto=r["proto"],
            return_type=r["return_type"],
            param_types=tuple(r["param_types"]),
            access_flags=tuple(r["access_flags"]),
            source=r["source"],
            ast=r["ast"],
            pc_map=tuple(
                StatementLocation(statement_index=seq, byte_offset=off)
                for seq, off in r["pc_map"]
            ),
        )

    def render_method_smali(self, method_descriptor: str) -> str:
        """Render one method as baksmali-style smali (empty if unknown/external)."""
        require_member_descriptor(method_descriptor)
        return self._dk.render_method_smali(method_descriptor)

    def render_class_smali(self, class_descriptor: str) -> str:
        """Render a whole class as baksmali-style smali (empty if external)."""
        require_type_descriptor(class_descriptor)
        return self._dk.render_class_smali(class_descriptor)

    # -- EnumerationPort --

    def list_classes(self) -> tuple[str, ...]:
        """Return every class descriptor declared in any loaded dex."""
        return tuple(self._dk.list_classes())

    def list_classes_in_dex(self, dex_id: int) -> tuple[str, ...]:
        """Return every class descriptor declared in one specific loaded dex."""
        return tuple(self._dk.list_classes_in_dex(dex_id))

    def list_class_methods(self, class_descriptor: str) -> tuple[str, ...]:
        """Return every declared method descriptor of the given class."""
        require_type_descriptor(class_descriptor)
        return tuple(self._dk.list_class_methods(class_descriptor))

    def list_fields(self) -> tuple[str, ...]:
        """Return every field descriptor across all loaded dexes."""
        return tuple(self._dk.list_fields())

    def list_fields_in_dex(self, dex_id: int) -> tuple[str, ...]:
        """Return every field descriptor of one specific loaded dex."""
        return tuple(self._dk.list_fields_in_dex(dex_id))

    def list_methods(self) -> tuple[str, ...]:
        """Return every method descriptor across all loaded dexes."""
        return tuple(self._dk.list_methods())

    def list_methods_in_dex(self, dex_id: int) -> tuple[str, ...]:
        """Return every method descriptor of one specific loaded dex."""
        return tuple(self._dk.list_methods_in_dex(dex_id))

    def list_value_strings(self) -> tuple[str, ...]:
        """Return every distinct string the app loads as a value."""
        return tuple(self._dk.list_value_strings())

    def list_class_strings(self, class_descriptor: str) -> tuple[str, ...]:
        """Return the value-strings the given class carries."""
        require_type_descriptor(class_descriptor)
        return tuple(self._dk.list_class_strings(class_descriptor))

    def list_method_strings(self, method_descriptor: str) -> tuple[str, ...]:
        """Return the value-strings the given method loads."""
        require_member_descriptor(method_descriptor)
        return tuple(self._dk.list_method_strings(method_descriptor))

    def list_external_method_refs(
        self, *, framework_only: bool = True
    ) -> tuple[ExternalMethodRef, ...]:
        """Return framework / library methods the app references but doesn't define."""
        return tuple(
            _to_ext_ref(r) for r in self._dk.list_external_method_refs(framework_only)
        )

    def list_external_field_refs(
        self, *, framework_only: bool = True
    ) -> tuple[ExternalFieldRef, ...]:
        """Return framework / library fields the app references but doesn't define."""
        return tuple(
            _to_ext_field_ref(r)
            for r in self._dk.list_external_field_refs(framework_only)
        )

    def list_external_type_refs(
        self, *, framework_only: bool = True
    ) -> tuple[ExternalTypeRef, ...]:
        """Return framework / library types the app references but doesn't declare."""
        return tuple(
            _to_ext_type_ref(r)
            for r in self._dk.list_external_type_refs(framework_only)
        )

    def verify_report(self) -> tuple[DexVerifyStatus, ...]:
        """Return per-loaded-dex structural-verification verdicts."""
        return _to_verify_statuses(self._dk.verify_report())

    def source_info(self) -> tuple[ContainerInfo, ...]:
        """Return what each construction source was, probed once at load."""
        return tuple(_container_info(row) for row in self._dk.source_info())

    # -- DexExtractionPort --

    def extract_dexes(self) -> tuple[ExtractedDex, ...]:
        """Return every loaded dex in dex_id order (copies all of their bytes)."""
        return tuple(self._to_extracted(d) for d in self._dk.extract_dexes())

    def extract_dex(self, dex_id: int) -> ExtractedDex:
        """Return one loaded dex's bytes together with where it came from."""
        return self._to_extracted(self._dk.extract_dex(dex_id))

    @staticmethod
    def _to_extracted(d: Mapping[str, Any]) -> ExtractedDex:
        """Convert one raw extract_dex dict to the typed model."""
        return ExtractedDex(
            dex_id=d["dex_id"],
            data=d["bytes"],
            source=d["source"],
            entry=d["entry"],
            offset=d["offset"],
            size=d["size"],
        )

    # -- CrossReferencePort --

    def find_call_sites_to(self, method_descriptor: str) -> tuple[CallSite, ...]:
        """Return every call site invoking the given method (its callers).

        Reverse edge: callee_descriptor is fixed, the caller_* fields vary.
        """
        require_member_descriptor(method_descriptor)
        return tuple(
            CallSite(
                caller_descriptor=s.caller_descriptor,
                caller_dex_id=s.caller_dex_id,
                caller_method_idx=s.caller_method_idx,
                callee_descriptor=s.callee_descriptor,
                bytecode_offset=s.bytecode_offset,
                invoke_opcode=s.invoke_opcode,
            )
            for s in self._dk.find_call_sites_to(method_descriptor)
        )

    def find_call_sites_from(self, method_descriptor: str) -> tuple[CallSite, ...]:
        """Return the call sites inside the method — the methods it invokes (callees).

        Forward edge: the caller_* fields are fixed (this method), callee varies.
        """
        require_member_descriptor(method_descriptor)
        return tuple(
            CallSite(
                caller_descriptor=s.caller_descriptor,
                caller_dex_id=s.caller_dex_id,
                caller_method_idx=s.caller_method_idx,
                callee_descriptor=s.callee_descriptor,
                bytecode_offset=s.bytecode_offset,
                invoke_opcode=s.invoke_opcode,
            )
            for s in self._dk.find_call_sites_from(method_descriptor)
        )

    def resolve_call_args(
        self, method_descriptor: str, depth: int = 2
    ) -> tuple[ResolvedCallSite, ...]:
        """Return call sites of the method with each argument's resolved origin.

        ``depth`` is the basic-block window: the call's own block plus that many
        predecessor levels above it.
        """
        require_member_descriptor(method_descriptor)
        return tuple(
            ResolvedCallSite(
                caller_descriptor=s.caller_descriptor,
                caller_dex_id=s.caller_dex_id,
                caller_method_idx=s.caller_method_idx,
                callee_descriptor=s.callee_descriptor,
                bytecode_offset=s.bytecode_offset,
                invoke_opcode=s.invoke_opcode,
                args=tuple(_to_arg(a) for a in s.args),
            )
            for s in self._dk.resolve_call_args(method_descriptor, depth)
        )

    def find_methods_reading_field(self, field_descriptor: str) -> tuple[str, ...]:
        """Return descriptors of methods that READ (iget*/sget*) the given field."""
        require_member_descriptor(field_descriptor)
        return tuple(self._dk.find_methods_reading_field(field_descriptor))

    def find_methods_writing_field(self, field_descriptor: str) -> tuple[str, ...]:
        """Return descriptors of methods that WRITE (iput*/sput*) the given field."""
        require_member_descriptor(field_descriptor)
        return tuple(self._dk.find_methods_writing_field(field_descriptor))

    def find_type_references(self, type_descriptor: str) -> TypeReferences:
        """Return signature-position references to the given type."""
        require_type_descriptor(type_descriptor)
        r = self._dk.find_type_references(type_descriptor)
        return TypeReferences(
            fields=tuple(r.fields),
            methods_returning=tuple(r.methods_returning),
            methods_with_param=tuple(r.methods_with_param),
        )

    # -- SearchPort --

    def find_classes_by_name(
        self,
        name: str,
        *,
        match_type: MatchType = "contains",
        ignore_case: bool = False,
    ) -> tuple[ClassRef, ...]:
        """Find classes whose name matches ``name`` under ``match_type``."""
        return tuple(
            _to_class_ref(m)
            for m in self._dk.find_classes_by_name(name, match_type, ignore_case)
        )

    def find_classes_by_super(
        self, super_class: str, *, match_type: MatchType = "equals"
    ) -> tuple[ClassRef, ...]:
        """Find classes whose direct superclass matches ``super_class``."""
        return tuple(
            _to_class_ref(m)
            for m in self._dk.find_classes_by_super(super_class, match_type)
        )

    def find_classes_implementing(
        self, interface_class: str, *, match_type: MatchType = "equals"
    ) -> tuple[ClassRef, ...]:
        """Find classes that declare the given interface."""
        return tuple(
            _to_class_ref(m)
            for m in self._dk.find_classes_implementing(interface_class, match_type)
        )

    def find_classes_by_annotation(
        self, annotation_class: str, *, match_type: MatchType = "equals"
    ) -> tuple[ClassRef, ...]:
        """Find classes annotated with ``annotation_class``."""
        return tuple(
            _to_class_ref(m)
            for m in self._dk.find_classes_by_annotation(annotation_class, match_type)
        )

    def find_classes_using_strings(
        self,
        strings: Sequence[str],
        *,
        match_type: MatchType = "contains",
        ignore_case: bool = False,
    ) -> tuple[ClassRef, ...]:
        """Find classes whose bytecode references ALL of ``strings``."""
        return tuple(
            _to_class_ref(m)
            for m in self._dk.find_classes_using_strings(
                _str_seq(strings), match_type, ignore_case
            )
        )

    def find_classes_declaring_strings(
        self,
        strings: Sequence[str],
        *,
        match_type: MatchType = "contains",
        ignore_case: bool = False,
    ) -> tuple[ClassRef, ...]:
        """Find classes that DECLARE ALL of ``strings`` as static-field constants."""
        return tuple(
            _to_class_ref(m)
            for m in self._dk.find_classes_declaring_strings(
                _str_seq(strings), match_type, ignore_case
            )
        )

    def find_methods_by_name(
        self,
        name: str,
        *,
        match_type: MatchType = "contains",
        declaring_class: str = "",
        ignore_case: bool = False,
    ) -> tuple[MethodRef, ...]:
        """Find methods by name, optionally scoped to a declaring class."""
        return tuple(
            _to_method_ref(m)
            for m in self._dk.find_methods_by_name(
                name, match_type, declaring_class, ignore_case
            )
        )

    def find_fields_by_name(
        self,
        name: str,
        *,
        match_type: MatchType = "contains",
        declaring_class: str = "",
        ignore_case: bool = False,
    ) -> tuple[FieldRef, ...]:
        """Find fields by name, optionally scoped to a declaring class."""
        return tuple(
            _to_field_ref(f)
            for f in self._dk.find_fields_by_name(
                name, match_type, declaring_class, ignore_case
            )
        )

    def find_methods_by_annotation(
        self, annotation_class: str, *, match_type: MatchType = "equals"
    ) -> tuple[MethodRef, ...]:
        """Find methods annotated with ``annotation_class``."""
        return tuple(
            _to_method_ref(m)
            for m in self._dk.find_methods_by_annotation(annotation_class, match_type)
        )

    def find_methods_using_strings(
        self,
        strings: Sequence[str],
        *,
        match_type: MatchType = "contains",
        ignore_case: bool = False,
    ) -> tuple[MethodRef, ...]:
        """Find methods whose body references ALL of ``strings``."""
        return tuple(
            _to_method_ref(m)
            for m in self._dk.find_methods_using_strings(
                _str_seq(strings), match_type, ignore_case
            )
        )

    def find_methods_using_int_literals(
        self, values: Sequence[int]
    ) -> tuple[MethodRef, ...]:
        """Find methods whose body contains ALL of the given int literals."""
        return tuple(
            _to_method_ref(m)
            for m in self._dk.find_methods_using_int_literals(list(values))
        )

    def find_methods_using_double_literals(
        self, values: Sequence[float]
    ) -> tuple[MethodRef, ...]:
        """Find methods whose body contains ALL of the given double literals."""
        return tuple(
            _to_method_ref(m)
            for m in self._dk.find_methods_using_double_literals(list(values))
        )

    def batch_find_classes_using_strings(
        self,
        query_map: Mapping[str, Sequence[str]],
        *,
        match_type: MatchType = "contains",
        ignore_case: bool = False,
    ) -> Mapping[str, tuple[ClassRef, ...]]:
        """Run many class-by-strings queries at once; result keyed by query key."""
        raw = self._dk.batch_find_classes_using_strings(
            {k: _str_seq(v) for k, v in query_map.items()}, match_type, ignore_case
        )
        return MappingProxyType(
            {k: tuple(_to_class_ref(m) for m in v) for k, v in raw.items()}
        )

    def batch_find_methods_using_strings(
        self,
        query_map: Mapping[str, Sequence[str]],
        *,
        match_type: MatchType = "contains",
        ignore_case: bool = False,
    ) -> Mapping[str, tuple[MethodRef, ...]]:
        """Run many method-by-strings queries at once; result keyed by query key."""
        raw = self._dk.batch_find_methods_using_strings(
            {k: _str_seq(v) for k, v in query_map.items()}, match_type, ignore_case
        )
        return MappingProxyType(
            {k: tuple(_to_method_ref(m) for m in v) for k, v in raw.items()}
        )

    # -- ClassInspectionPort --

    def class_info(self, class_descriptor: str) -> ClassInfo:
        """Return the class's metadata (superclass, interfaces, access, source)."""
        require_type_descriptor(class_descriptor)
        s = self._dk.get_class_summary(class_descriptor)
        return ClassInfo(
            descriptor=s.descriptor,
            dex_id=s.dex_id,
            is_internal=s.is_internal,
            access_flags=s.access_flags,
            superclass_descriptor=s.superclass_descriptor,
            interface_descriptors=tuple(s.interface_descriptors),
            source_file=s.source_file,
            dex_name=self._dex_name(s.dex_id),
        )

    def class_fields(self, class_descriptor: str) -> tuple[FieldInfo, ...]:
        """Return the class's declared fields (name, type, access flags)."""
        require_type_descriptor(class_descriptor)
        s = self._dk.get_class_summary(class_descriptor)
        return tuple(
            FieldInfo(
                name=f.name,
                type=f.type,
                access_flags=f.access_flags,
                class_descriptor=f.class_descriptor,
                descriptor=f.descriptor,
            )
            for f in s.fields
        )

    def class_methods(self, class_descriptor: str) -> tuple[MethodInfo, ...]:
        """Return the class's declared methods (name, proto, access flags)."""
        require_type_descriptor(class_descriptor)
        s = self._dk.get_class_summary(class_descriptor)
        return tuple(
            MethodInfo(
                name=m.name,
                proto=m.proto,
                access_flags=m.access_flags,
                class_descriptor=m.class_descriptor,
                descriptor=m.descriptor,
            )
            for m in s.methods
        )

    def locate_class_dex(self, class_descriptor: str) -> int:
        """Return the id of the dex that declares the class, or -1 if external."""
        require_type_descriptor(class_descriptor)
        return self._dk.locate_class_dex(class_descriptor)

    # -- PermissionAnalysisPort --

    def permission_callers(
        self, *, app_only: bool = True
    ) -> tuple[PermissionCallers, ...]:
        """Return permissions the app exercises through real API calls, with callers."""
        return tuple(
            PermissionCallers(
                permission=g["perm"],
                protection_level=g["protectionLevel"],
                apis=tuple(
                    ApiCallers(
                        api=row["api"],
                        descriptors=tuple(row["descriptors"]),
                        callers=tuple(row["callers"]),
                    )
                    for row in g["apis"]
                ),
            )
            for g in self._dk.permission_callers(app_only)
        )

    # -- IndicatorExtractionPort --

    def extract_iocs(
        self, *, denoise: bool = True, with_xref: bool = True
    ) -> IocReport:
        """Recover URLs / IPs / domains / emails / onion indicators."""
        r = dexllm.extract_iocs(self._dk, denoise=denoise, with_xref=with_xref)
        return IocReport(
            urls=_to_indicators(r["urls"]),
            ips=_to_indicators(r["ips"]),
            domains=_to_indicators(r["domains"]),
            emails=_to_indicators(r["emails"]),
            onion=_to_indicators(r["onion"]),
        )

    # -- CapabilityPort --

    def summarize_capabilities(self, *, app_only: bool = True) -> CapabilityReport:
        """Summarize the app's capability profile (matched APIs, permissions).

        ``app_only`` (default True) counts only the app's own callers, dropping
        bundled framework / library plumbing — see
        :func:`dexllm.summarize_capabilities` for the predicate and its blind
        spots. False counts every caller.
        """
        c = dexllm.summarize_capabilities(self._dk, app_only=app_only)
        return CapabilityReport(
            catalog_version=c.catalog_version,
            catalog_size=c.catalog_size,
            matched_apis=c.matched_apis,
            total_call_sites=c.total_call_sites,
            permissions=dict(c.permissions),
            categories=dict(c.categories),
            flags=dict(c.flags),
            api_usages=tuple(
                ApiUsage(
                    api_descriptor=h.api_descriptor,
                    call_site_count=h.call_site_count,
                    permissions=tuple(h.permissions),
                    categories=tuple(h.categories),
                    flags=tuple(h.flags),
                    # sorted, not bare tuple(): these come from a `set`, so the
                    # order would follow per-process string hashing. dexllm#35 made
                    # multi-valued `by_caller` entries the normal case (they were
                    # rare when the values were permissions), which turned a corner
                    # case into a routine one.
                    callers=tuple(sorted(h.callers)),
                    field_access_count=h.field_access_count,
                )
                for h in c.api_usages
            ),
            by_caller={k: tuple(sorted(v)) for k, v in c.by_caller.items()},
            total_field_accesses=c.total_field_accesses,
            dropped_touches=c.dropped_touches,
            dropped_apis=c.dropped_apis,
        )

    # -- ContentProviderPort --

    def detect_content_providers(
        self, *, with_xref: bool = True
    ) -> tuple[ContentProviderUse, ...]:
        """Return provider URIs the app references (sms / contacts / call-log)."""
        return tuple(
            ContentProviderUse(
                uri=p["uri"], family=p["family"], methods=tuple(p["methods"])
            )
            for p in dexllm.detect_content_providers(self._dk, with_xref=with_xref)
        )

    # -- TlsTrustPort --

    def detect_permissive_tls(
        self, *, with_xref: bool = True
    ) -> tuple[TlsTrustComponent, ...]:
        """Return the app's TLS trust components, each with a proven verdict."""
        return tuple(
            TlsTrustComponent(
                class_descriptor=t["class_descriptor"],
                interface_descriptor=t["interface_descriptor"],
                kind=t["kind"],
                method_descriptor=t["method_descriptor"],
                verdict=t["verdict"],
                reason=t["reason"],
                constructed_in=tuple(t["constructed_in"]),
            )
            for t in dexllm.detect_permissive_tls(self._dk, with_xref=with_xref)
        )

    # -- CacheControlPort --

    def decompiler_cache_capacity(self) -> int:
        """Return the decompiled-method LRU capacity (entries; 0 = unbounded)."""
        return self._dk.decompiler_cache_capacity()

    def set_decompiler_cache_capacity(self, capacity: int) -> None:
        """Set the decompiled-method LRU capacity (0 disables eviction)."""
        self._dk.set_decompiler_cache_capacity(capacity)

    def decompiler_cache_size(self) -> int:
        """Return the number of methods currently cached."""
        return self._dk.decompiler_cache_size()

    def clear_decompiler_cache(self) -> None:
        """Evict every cached decompiled method (free memory)."""
        self._dk.clear_decompiler_cache()

    def warm_analysis_caches(self) -> None:
        """Eagerly warm the upstream L2/L4 caches (else built lazily on first use)."""
        self._dk.warm_analysis_caches()


def _to_verify_statuses(
    rows: Sequence[Mapping[str, Any]],
) -> tuple[DexVerifyStatus, ...]:
    """Convert raw {dex_id, name, valid, reason, source} rows to the typed model."""
    return tuple(
        DexVerifyStatus(
            dex_id=x["dex_id"],
            name=x["name"],
            valid=x["valid"],
            reason=x["reason"],
            # x["source"], not .get(): the raw layer always emits it, so a
            # missing key is a regression that should raise, not degrade to "".
            source=x["source"],
        )
        for x in rows
    )


def _container_info(row: Mapping[str, Any]) -> ContainerInfo:
    """Convert one probe dict to the typed model.

    Shared by the on-demand probe and the session's load-time record, which
    return the same keys and must therefore produce the same model.
    """
    return ContainerInfo(
        source=row["source"],
        format=row["format"],
        is_apk=row["is_apk"],
        has_manifest=row["has_manifest"],
        dex_count=row["dex_count"],
    )


def _to_container_info(path: SourceLike) -> ContainerInfo:
    """Probe a file by content (no load) and convert to the typed model."""
    return _container_info(dexllm.identify(os.fspath(path)))


class ContainerProbe:
    """Adapter implementing :class:`~dexllm.sdk.ports.ContainerProbePort`.

    A stateless probe (no load); the module-level :func:`identify` is the
    convenience function over the same logic.
    """

    def identify(self, path: str) -> ContainerInfo:
        """Probe a file by content (dex magic / zip central directory)."""
        return _to_container_info(path)

    def verify(
        self, path: str, *, lenient: bool = False
    ) -> tuple[DexVerifyStatus, ...]:
        """Structurally verify a path's dex(es) without loading (no raise)."""
        return _to_verify_statuses(dexllm.verify(os.fspath(path), lenient))


# ── factories ─────────────────────────────────────────────────────────────────


def open_apk(sources: Sources, *, lenient: bool = False) -> DexKitAdapter:
    """Open an apk / dex source (or list of sources) as a typed analysis session.

    Returns a :class:`DexKitAdapter`, which satisfies
    :class:`~dexllm.sdk.ports.DexAnalysisUseCase`.
    """
    return DexKitAdapter(sources, lenient=lenient)


def identify(path: SourceLike) -> ContainerInfo:
    """Probe a file by content (no load); the functional form of ``ContainerProbe``."""
    return _to_container_info(path)


def verify(path: SourceLike, *, lenient: bool = False) -> tuple[DexVerifyStatus, ...]:
    """Structurally verify a path's dex(es) without loading (no raise).

    The functional form of :meth:`ContainerProbe.verify`. One verdict per dex,
    byte-identical to loading the source and reading ``verify_report``.
    """
    return _to_verify_statuses(dexllm.verify(os.fspath(path), lenient))
