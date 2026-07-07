"""Outbound adapter: implement the hexagonal ports over ``dexllm.DexKit``.

:class:`DexKitAdapter` wraps one loaded ``DexKit`` and converts every raw return
(pybind objects, plain dicts) into the typed domain models, so it satisfies
:class:`~dexllm.hexagonal.ports.DexAnalysisUseCase`. :func:`open_apk` is the
factory; :func:`identify` is the load-free container probe. The underlying
``DexKit`` is reachable via :pyattr:`DexKitAdapter.raw` as an escape hatch.
"""

from __future__ import annotations

import os
from typing import Union

import dexllm

from .model import (
    ArgOrigin,
    CallSite,
    CapabilityHit,
    CapabilityReport,
    ClassInfo,
    ContainerInfo,
    ContentProviderUse,
    DecompiledClass,
    DecompiledMethod,
    DexVerifyStatus,
    ExternalMethodRef,
    FieldInfo,
    Indicator,
    IocReport,
    MethodAst,
    PermissionCallerGroup,
    PermissionCallerRow,
    ResolvedCallSite,
    SourceLocation,
    StatementLocation,
    TypeReferences,
)

# A single apk/dex path or a sequence of them; each element accepts anything
# os.fspath understands (str or os.PathLike, e.g. pathlib.Path).
SourceLike = Union[str, "os.PathLike[str]"]
Sources = Union[SourceLike, "list[SourceLike]", "tuple[SourceLike, ...]"]

# ── raw → model converters ────────────────────────────────────────────────────

# The argument field carried by each ArgOrigin kind (only that field is meaningful;
# the rest are pybind defaults, so we map by kind for clean, minimal models).
_ARG_FIELD_BY_KIND = {
    "ConstString": "string_value",
    "ConstInt": "int_value",
    "ConstWide": "int_value",
    "ConstClass": "class_descriptor",
    "NewInstance": "class_descriptor",
    "NewArray": "class_descriptor",
    "FieldRead": "field_signature",
    "MethodReturn": "method_signature",
    "Parameter": "parameter_index",
}


def _to_arg(a: object) -> ArgOrigin:
    """Convert a pybind ArgOrigin to the typed model (only the kind's field set)."""
    field = _ARG_FIELD_BY_KIND.get(a.kind)  # type: ignore[attr-defined]
    kw = {field: getattr(a, field)} if field else {}
    return ArgOrigin(kind=a.kind, reg_num=a.reg_num, **kw)  # type: ignore[attr-defined]


def _to_ext_ref(r: object) -> ExternalMethodRef:
    """Convert a pybind ExternalMethodRef to the typed model."""
    return ExternalMethodRef(
        class_descriptor=r.class_descriptor,  # type: ignore[attr-defined]
        name=r.name,  # type: ignore[attr-defined]
        proto=r.proto,  # type: ignore[attr-defined]
        java_class=r.java_class,  # type: ignore[attr-defined]
        java_signature=r.java_signature,  # type: ignore[attr-defined]
        signature=r.signature,  # type: ignore[attr-defined]
        return_type=r.return_type,  # type: ignore[attr-defined]
        parameters=tuple(r.parameters),  # type: ignore[attr-defined]
        is_constructor=r.is_constructor,  # type: ignore[attr-defined]
        is_static_initializer=r.is_static_initializer,  # type: ignore[attr-defined]
        referenced_in_dex_ids=tuple(r.referenced_in_dex_ids),  # type: ignore[attr-defined]
    )


def _to_indicators(items: "list[dict]") -> tuple[Indicator, ...]:
    """Convert an extract_iocs indicator list to a tuple of typed Indicators."""
    return tuple(
        Indicator(value=d["value"], methods=tuple(d.get("methods", ()))) for d in items
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

    # -- escape hatch / session metadata --

    @property
    def raw(self) -> "dexllm.DexKit":
        """Return the underlying ``dexllm.DexKit`` (advanced / L7 search access)."""
        return self._dk

    @property
    def sources(self) -> tuple[str, ...]:
        """Return the source paths this session was constructed from."""
        return tuple(self._dk.sources())

    def dex_count(self) -> int:
        """Return the number of dexes loaded into this session."""
        return self._dk.dex_count()

    # -- DecompilationPort --

    def decompile_method(self, method_descriptor: str) -> DecompiledMethod:
        """Decompile one method to Java text."""
        src = self._dk.decompile_method_java(method_descriptor)
        return DecompiledMethod(
            descriptor=method_descriptor, source=src, found=bool(src)
        )

    def decompile_method_with_pc_map(self, method_descriptor: str) -> DecompiledMethod:
        """Decompile one method plus a source-line ↔ bytecode-offset map."""
        r = self._dk.decompile_method_java_with_pc(method_descriptor)
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
        return DecompiledClass(
            descriptor=class_descriptor,
            source=self._dk.decompile_class_java(class_descriptor),
        )

    def decompile_method_ast(
        self, method_descriptor: str, *, include_source: bool = True
    ) -> MethodAst:
        """Return a method's structured AST (+ source unless disabled)."""
        r = self._dk.decompile_method_ast(
            method_descriptor, include_source=include_source
        )
        return MethodAst(
            found=r["found"],
            class_name=r["cls_name"],
            name=r["name"],
            proto=r["proto"],
            return_type=r["ret_type"],
            param_types=tuple(r["params_type"]),
            access_flags=r["access"],
            source=r["source"],
            ast=r["ast"],
            pc_map=tuple(
                StatementLocation(statement_index=seq, byte_offset=off)
                for seq, off in r["pc_map"]
            ),
        )

    # -- EnumerationPort --

    def list_classes(self) -> tuple[str, ...]:
        """Return every class descriptor declared in any loaded dex."""
        return tuple(self._dk.list_classes())

    def list_classes_in_dex(self, dex_id: int) -> tuple[str, ...]:
        """Return every class descriptor declared in one specific loaded dex."""
        return tuple(self._dk.list_classes_in_dex(dex_id))

    def list_class_methods(self, class_descriptor: str) -> tuple[str, ...]:
        """Return every declared method descriptor of the given class."""
        return tuple(self._dk.list_class_methods(class_descriptor))

    def list_all_field_descriptors(self) -> tuple[str, ...]:
        """Return every declared field descriptor across all loaded dexes."""
        return tuple(self._dk.list_all_field_descriptors())

    def list_all_method_descriptors(self) -> tuple[str, ...]:
        """Return every declared method descriptor across all loaded dexes."""
        return tuple(self._dk.list_all_method_descriptors())

    def list_value_strings(self) -> tuple[str, ...]:
        """Return every distinct string the app loads as a value."""
        return tuple(self._dk.list_value_strings())

    def list_external_method_refs(
        self, *, framework_only: bool = True
    ) -> tuple[ExternalMethodRef, ...]:
        """Return framework / library methods the app references but doesn't define."""
        return tuple(
            _to_ext_ref(r) for r in self._dk.list_external_method_refs(framework_only)
        )

    def verify_report(self) -> tuple[DexVerifyStatus, ...]:
        """Return per-loaded-dex structural-verification verdicts."""
        return tuple(
            DexVerifyStatus(
                dex_id=x["dex_id"],
                name=x["name"],
                valid=x["valid"],
                reason=x["reason"],
            )
            for x in self._dk.verify_report()
        )

    # -- DexExtractionPort --

    def extract_dex_bytes(self, dex_id: int) -> bytes:
        """Return the raw bytes of one loaded dex (its own file_size slice)."""
        return self._dk.extract_dex_bytes(dex_id)

    # -- CrossReferencePort --

    def find_call_sites(self, api_descriptor: str) -> tuple[CallSite, ...]:
        """Return every call site invoking the given API descriptor."""
        return tuple(
            CallSite(
                caller_descriptor=s.caller_descriptor,
                caller_dex_id=s.caller_dex_id,
                caller_method_idx=s.caller_method_idx,
                callee_descriptor=s.callee_descriptor,
                bytecode_offset=s.bytecode_offset,
                invoke_opcode=s.invoke_opcode,
            )
            for s in self._dk.find_call_sites_to_api(api_descriptor)
        )

    def resolve_call_args(self, api_descriptor: str) -> tuple[ResolvedCallSite, ...]:
        """Return call sites of the API with each argument's resolved origin."""
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
            for s in self._dk.resolve_call_args(api_descriptor)
        )

    def find_field_readers(self, field_descriptor: str) -> tuple[str, ...]:
        """Return descriptors of methods that READ (iget*/sget*) the given field."""
        return tuple(self._dk.find_field_read_methods(field_descriptor))

    def find_field_writers(self, field_descriptor: str) -> tuple[str, ...]:
        """Return descriptors of methods that WRITE (iput*/sput*) the given field."""
        return tuple(self._dk.find_field_write_methods(field_descriptor))

    def find_type_references(self, type_descriptor: str) -> TypeReferences:
        """Return signature-position references to the given type."""
        r = self._dk.find_type_references(type_descriptor)
        return TypeReferences(
            fields=tuple(r.fields),
            methods_returning=tuple(r.methods_returning),
            methods_with_param=tuple(r.methods_with_param),
        )

    # -- ClassInspectionPort --

    def class_info(self, class_descriptor: str) -> ClassInfo:
        """Return the class's metadata (superclass, interfaces, access, source)."""
        s = self._dk.get_class_summary(class_descriptor)
        return ClassInfo(
            descriptor=s.descriptor,
            dex_id=s.dex_id,
            is_internal=s.is_internal,
            access_flags=s.access_flags,
            superclass=s.superclass_descriptor,
            interfaces=tuple(s.interface_descriptors),
            source_file=s.source_file,
        )

    def class_fields(self, class_descriptor: str) -> tuple[FieldInfo, ...]:
        """Return the class's declared fields (name, type, access flags)."""
        s = self._dk.get_class_summary(class_descriptor)
        return tuple(
            FieldInfo(name=f.name, type=f.type, access_flags=f.access_flags)
            for f in s.fields
        )

    # -- PermissionAnalysisPort --

    def permission_callers(
        self, *, app_only: bool = True
    ) -> tuple[PermissionCallerGroup, ...]:
        """Return permissions the app exercises through real API calls, with callers."""
        return tuple(
            PermissionCallerGroup(
                permission=g["perm"],
                protection_level=g["protectionLevel"],
                rows=tuple(
                    PermissionCallerRow(
                        api=row["api"],
                        descriptors=tuple(row["descriptors"]),
                        callers=tuple(row["callers"]),
                    )
                    for row in g["rows"]
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

    def summarize_capabilities(self) -> CapabilityReport:
        """Summarize the app's capability profile (matched APIs, permissions)."""
        c = dexllm.summarize_capabilities(self._dk)
        return CapabilityReport(
            catalog_version=c.catalog_version,
            catalog_size=c.catalog_size,
            matched_apis=c.matched_apis,
            total_call_sites=c.total_call_sites,
            permissions=dict(c.permissions),
            categories=dict(c.categories),
            api_hits=tuple(
                CapabilityHit(
                    api_signature=h.api_signature,
                    call_site_count=h.call_site_count,
                    permissions=tuple(h.permissions),
                    categories=tuple(h.categories),
                    callers=tuple(h.callers),
                )
                for h in c.api_hits
            ),
            by_caller={k: tuple(v) for k, v in c.by_caller.items()},
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


def _to_container_info(path: SourceLike) -> ContainerInfo:
    """Probe a file by content (no load) and convert to the typed model."""
    r = dexllm.identify(os.fspath(path))
    return ContainerInfo(
        format=r["format"],
        is_apk=r["is_apk"],
        has_manifest=r["has_manifest"],
        dex_count=r["dex_count"],
    )


class ContainerProbe:
    """Adapter implementing :class:`~dexllm.hexagonal.ports.ContainerProbePort`.

    A stateless probe (no load); the module-level :func:`identify` is the
    convenience function over the same logic.
    """

    def identify(self, path: str) -> ContainerInfo:
        """Probe a file by content (dex magic / zip central directory)."""
        return _to_container_info(path)


# ── factories ─────────────────────────────────────────────────────────────────


def open_apk(sources: Sources, *, lenient: bool = False) -> DexKitAdapter:
    """Open an apk / dex source (or list of sources) as a hexagonal analysis session.

    Returns a :class:`DexKitAdapter`, which satisfies
    :class:`~dexllm.hexagonal.ports.DexAnalysisUseCase`.
    """
    return DexKitAdapter(sources, lenient=lenient)


def identify(path: SourceLike) -> ContainerInfo:
    """Probe a file by content (no load); the functional form of ``ContainerProbe``."""
    return _to_container_info(path)
