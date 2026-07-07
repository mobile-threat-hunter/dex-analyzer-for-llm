"""Typed domain models for the dexllm hexagonal API.

The value objects that cross every port boundary. Each is a frozen dataclass with
an accurate type on every field, mirroring the raw dexllm return shapes 1:1. The
adapter converts pybind objects / plain dicts into these, so a consumer programs
against *types* — not against dict keys or C++ struct attributes.

Immutability: ``frozen=True`` blocks attribute rebinding; sequence fields are
tuples and the ``Mapping`` fields (``CapabilityReport.permissions/categories/
by_caller``, ``MethodAst.ast``) are wrapped in a read-only ``MappingProxyType`` at
construction, so a model can't be mutated in place. (``MethodAst.ast`` is a
read-only view of the DAD nested-list AST; the *nested* structure inside it is the
engine's own data.)

Hashability: the value-object models (only tuple/scalar fields) are hashable. The
two models that carry a ``Mapping`` — ``CapabilityReport`` and ``MethodAst`` — are
frozen but NOT hashable (a ``Mapping`` is not hashable), so do not use them as a
set member / dict key.
"""

from __future__ import annotations

from dataclasses import dataclass
from types import MappingProxyType
from typing import Any, Mapping, Optional

# ── loading / probe ──────────────────────────────────────────────────────────


@dataclass(frozen=True)
class ContainerInfo:
    """Content-based probe of a file (no load).

    ``format`` is ``"dex" | "zip" | "unknown"``; ``is_apk`` iff a zip carrying an
    AndroidManifest.xml.

    Example (real, a2dp.Vol_137.apk)::

        ContainerInfo(format='zip', is_apk=True, has_manifest=True, dex_count=1)
    """

    format: str
    is_apk: bool
    has_manifest: bool
    dex_count: int


@dataclass(frozen=True)
class DexVerifyStatus:
    """One loaded dex's structural-verification verdict.

    ``reason`` is empty when ``valid``; a rejected dex never reached the core.

    Example (real)::

        DexVerifyStatus(dex_id=0, name='classes.dex', valid=True, reason='')
    """

    dex_id: int
    name: str
    valid: bool
    reason: str


# ── decompilation ────────────────────────────────────────────────────────────


@dataclass(frozen=True)
class SourceLocation:
    r"""One entry of a source-line ↔ dex-bytecode-offset map.

    ``line`` is a 1-based index into ``source.split("\n")`` (only ``\n`` delimits
    — do not use ``str.splitlines()``).

    Example (real, Utils#getDisplaySize)::

        SourceLocation(line=4, byte_offset=24)
    """

    line: int
    byte_offset: int


@dataclass(frozen=True)
class StatementLocation:
    """One entry of a statement-index ↔ dex-bytecode-offset map (the AST path).

    ``statement_index`` is a post-order-DFS statement sequence number — NOT a
    source line (that is why it is a distinct model from :class:`SourceLocation`).

    Example (real, Utils#getDisplaySize)::

        StatementLocation(statement_index=0, byte_offset=24)
    """

    statement_index: int
    byte_offset: int


@dataclass(frozen=True)
class DecompiledMethod:
    """Java text of one method.

    ``found`` here means non-empty Java ``source`` was produced: it is False (and
    ``source`` empty) for an external / framework reference, and — unlike
    :attr:`MethodAst.found`, which reports whether the method was *located* — also
    False on the rare located-but-empty emit. ``pc_map`` is populated only by the
    with-pc-map decompile; empty otherwise.

    Example (real, Utils#getDisplaySize; source abbreviated, newlines shown as ⏎)::

        DecompiledMethod(
            descriptor='Lcom/example/.../Utils;->getDisplaySize(...)Landroid/graphics/Point;',
            source='public static android.graphics.Point getDisplaySize('
                   'android.content.Context p4) ⏎ { ⏎     android.view.Display v0 = ...',
            found=True,
            pc_map=(SourceLocation(line=4, byte_offset=24), ...))
    """

    descriptor: str
    source: str
    found: bool
    pc_map: tuple[SourceLocation, ...] = ()


@dataclass(frozen=True)
class DecompiledClass:
    """Full Java text of one class (package + header + fields + method bodies).

    Example (real; source abbreviated)::

        DecompiledClass(
            descriptor='La2dp/Vol/ALauncher;',
            source='package a2dp.Vol; ⏎ public class ALauncher extends ... { ... }')
    """

    descriptor: str
    source: str


@dataclass(frozen=True)
class MethodAst:
    """A method's signature components + Java source + the DAD nested-list AST.

    ``ast`` is ``{triple, flags, ret, params, comments, body}`` — or ``None`` when
    the method was not found / failed (check :attr:`found`). ``pc_map`` is a
    statement-index ↔ byte-offset map kept out of ``ast`` so the tree matches
    androguard. Holds a ``Mapping`` (``ast``), so this model is immutable but NOT
    hashable.

    Example (real, Fragment#getId)::

        MethodAst(found=True, class_name='Landroid/support/v4/app/Fragment;',
                  name='getId', proto='()I', return_type='I', param_types=(),
                  access_flags=..., source='public int getId() { ... }',
                  ast={'triple': (...), 'body': [...]}, pc_map=(...,))
    """

    found: bool
    class_name: str
    name: str
    proto: str
    return_type: str
    param_types: tuple[str, ...]
    access_flags: int
    source: str
    ast: Optional[Mapping[str, Any]]
    pc_map: tuple[StatementLocation, ...]

    def __post_init__(self) -> None:
        """Wrap ``ast`` in a read-only view so the model can't be mutated."""
        if self.ast is not None and not isinstance(self.ast, MappingProxyType):
            object.__setattr__(self, "ast", MappingProxyType(dict(self.ast)))


# ── enumeration ──────────────────────────────────────────────────────────────


@dataclass(frozen=True)
class ExternalMethodRef:
    """A method whose declaring class is not defined in any loaded dex.

    That is, a framework / library API the app references.

    Example (real, a2dp.Vol_137.apk)::

        ExternalMethodRef(
            class_descriptor='Landroid/accessibilityservice/AccessibilityServiceInfo;',
            name='getCanRetrieveWindowContent', proto='()Z',
            java_class='android.accessibilityservice.AccessibilityServiceInfo',
            java_signature='android.accessibilityservice.AccessibilityServiceInfo.'
                           'getCanRetrieveWindowContent() -> boolean',
            signature='Landroid/accessibilityservice/AccessibilityServiceInfo;->'
                      'getCanRetrieveWindowContent()Z',
            return_type='Z', parameters=(), is_constructor=False,
            is_static_initializer=False, referenced_in_dex_ids=(0,))
    """

    class_descriptor: str
    name: str
    proto: str
    java_class: str
    java_signature: str
    signature: str
    return_type: str
    parameters: tuple[str, ...]
    is_constructor: bool
    is_static_initializer: bool
    referenced_in_dex_ids: tuple[int, ...]


# ── class inspection ─────────────────────────────────────────────────────────
# Fine-grained decomposition of a class (the C++ get_class_summary bundles all of
# these — class metadata + fields + methods — into one object; the hexagonal layer
# splits it so a consumer depends only on what it needs). Methods stay on
# EnumerationPort.list_class_methods.


@dataclass(frozen=True)
class FieldInfo:
    """One declared field of a class: name, dex type descriptor, access flags.

    Its full descriptor is ``f"{class_descriptor}->{name}:{type}"``.

    Example (real, a2dp.Vol StoreLoc.DB)::

        FieldInfo(name='DB', type='La2dp/Vol/DeviceDB;', access_flags=2)
    """

    name: str
    type: str
    access_flags: int


@dataclass(frozen=True)
class ClassInfo:
    """A class's metadata (no field/method bodies — those are separate queries).

    ``is_internal`` is False for a class only REFERENCED (not declared) in a loaded
    dex — such an external class has ``dex_id=-1``, ``superclass=""`` and (via
    ``class_fields``) fields deduped + sorted by (name, type) rather than in declared
    order. ``source_file`` may be empty.

    Example (real, a2dp.Vol StoreLoc)::

        ClassInfo(descriptor='La2dp/Vol/StoreLoc;', dex_id=0, is_internal=True,
                  access_flags=1, superclass='Landroid/app/Service;',
                  interfaces=(), source_file='StoreLoc.java')
    """

    descriptor: str
    dex_id: int
    is_internal: bool
    access_flags: int
    superclass: str
    interfaces: tuple[str, ...]
    source_file: str


# ── cross-reference ──────────────────────────────────────────────────────────


@dataclass(frozen=True)
class ArgOrigin:
    """The provenance of one invoke argument register.

    Basic-block-scoped forward simulation; only the field(s) relevant to ``kind``
    are set. ``kind`` is one of ConstString / ConstInt / ConstWide / ConstClass /
    ConstNull / FieldRead / MethodReturn / Parameter / NewInstance / NewArray /
    Unknown.

    Example (real, the first arg of a Log.d call in a2dp.Vol)::

        ArgOrigin(kind='ConstString', reg_num=1, string_value='A2DP Volume')
    """

    kind: str
    reg_num: int
    string_value: Optional[str] = None
    int_value: Optional[int] = None
    class_descriptor: Optional[str] = None
    field_signature: Optional[str] = None
    method_signature: Optional[str] = None
    parameter_index: Optional[int] = None


@dataclass(frozen=True)
class CallSite:
    """One bytecode call site invoking the queried API.

    Example (real, a call to Log.d in a2dp.Vol)::

        CallSite(caller_descriptor='La2dp/Vol/MyApplication;->onCreate()V',
                 caller_dex_id=0, caller_method_idx=278,
                 callee_descriptor='Landroid/util/Log;->d(...)I',
                 bytecode_offset=14, invoke_opcode=113)
    """

    caller_descriptor: str
    caller_dex_id: int
    caller_method_idx: int
    callee_descriptor: str
    bytecode_offset: int
    invoke_opcode: int


@dataclass(frozen=True)
class ResolvedCallSite:
    """A call site plus a resolved :class:`ArgOrigin` per argument register.

    Example (real, the same Log.d call — args resolved)::

        ResolvedCallSite(caller_descriptor='La2dp/Vol/MyApplication;->onCreate()V',
                         caller_dex_id=0, caller_method_idx=278,
                         callee_descriptor='Landroid/util/Log;->d(...)I',
                         bytecode_offset=14, invoke_opcode=113,
                         args=(ArgOrigin(kind='ConstString', reg_num=1,
                                         string_value='A2DP Volume'), ...))
    """

    caller_descriptor: str
    caller_dex_id: int
    caller_method_idx: int
    callee_descriptor: str
    bytecode_offset: int
    invoke_opcode: int
    args: tuple[ArgOrigin, ...]


@dataclass(frozen=True)
class TypeReferences:
    """Signature-position references to a type (not call/instruction xref).

    Where a ``Lpkg/Cls;`` type appears as a field type, a method return type, or a
    method parameter — each a tuple of the member descriptors.

    Example (real, a2dp.Vol — references to android.location.Location)::

        TypeReferences(
            fields=('La2dp/Vol/StoreLoc;->l:Landroid/location/Location;',),
            methods_returning=('Landroid/location/LocationManager;->'
                               'getLastKnownLocation(Ljava/lang/String;)'
                               'Landroid/location/Location;',),
            methods_with_param=('La2dp/Vol/StoreLoc$2;->onLocationChanged('
                                'Landroid/location/Location;)V',))
    """

    fields: tuple[str, ...]
    methods_returning: tuple[str, ...]
    methods_with_param: tuple[str, ...]


# ── permission analysis ──────────────────────────────────────────────────────


@dataclass(frozen=True)
class PermissionCallerRow:
    """One gated API under a permission, plus the app methods that call it.

    ``api`` is the AOSP dataset signature (e.g. ``android.telephony.SmsManager#
    sendTextMessage(...)``; runtime-enforcement-bridge entries are arity-only,
    ``...#method(Nargs)``). ``descriptors`` are the matching dex method descriptors
    the app references; ``callers`` are the app methods that invoke them.

    Example (real, a2dp.Vol under ACCESS_COARSE_LOCATION)::

        PermissionCallerRow(
            api='android.location.LocationManager#getLastKnownLocation(String)',
            descriptors=('Landroid/location/LocationManager;->'
                         'getLastKnownLocation(Ljava/lang/String;)Landroid/location/Location;',),
            callers=('La2dp/Vol/StoreLoc;->grabGPS()V',))
    """

    api: str
    descriptors: tuple[str, ...]
    callers: tuple[str, ...]


@dataclass(frozen=True)
class PermissionCallerGroup:
    """A permission, its protection-level bucket, and its referenced gated APIs.

    Each row has a (kept) caller. ``protection_level`` is the Android
    ``protectionLevel`` bucketed to its base — one of:

    - ``dangerous`` — needs runtime user consent; touches private data / sensitive
      device functions (CAMERA, READ_SMS, ACCESS_FINE_LOCATION, RECORD_AUDIO). The
      primary triage signal that an app handles sensitive data.
    - ``normal`` — auto-granted at install, low risk (INTERNET, ACCESS_NETWORK_STATE,
      VIBRATE).
    - ``signature`` — granted only to apps signed with the SAME key as the declarer;
      a normal third-party app CANNOT hold it (platform/OEM only). A non-system app
      *referencing* such an API (MANAGE_USERS, STATUS_BAR_SERVICE, INTERACT_ACROSS_
      USERS) is a notable signal — privilege probing, repackaged system code, or a
      library false positive.
    - ``internal`` — granted by internal flags (role / installer), not by signature
      or consent (Android 12+); not obtainable by a normal app.
    - ``other`` — no / unknown ``protectionLevel`` in the dataset (catch-all).

    Example (real, a2dp.Vol)::

        PermissionCallerGroup(
            permission='android.permission.ACCESS_COARSE_LOCATION',
            protection_level='dangerous',
            rows=(PermissionCallerRow(api='android.location.LocationManager#'
                                          'getLastKnownLocation(String)', ...), ...))
    """

    permission: str
    protection_level: str
    rows: tuple[PermissionCallerRow, ...]


# ── indicators (IOC) ─────────────────────────────────────────────────────────


@dataclass(frozen=True)
class Indicator:
    """One network indicator with the app methods that reference it.

    ``methods`` is empty when extracted without cross-reference.

    Example (real, tvleanback — a domain in an ExoPlayer string)::

        Indicator(value='dolby.com',
                  methods=('Lcom/google/android/exoplayer2/source/dash/manifest/'
                           'DashManifestParser;->parseAudioChannelConfiguration('
                           'Lorg/xmlpull/v1/XmlPullParser;)I', ...))
    """

    value: str
    methods: tuple[str, ...] = ()


@dataclass(frozen=True)
class IocReport:
    """Static network indicators recovered from the app's value strings.

    Defang-aware and public-suffix-validated.

    Example (real, tvleanback)::

        IocReport(urls=(), ips=(),
                  domains=(Indicator(value='dolby.com', methods=(...)),),
                  emails=(), onion=())
    """

    urls: tuple[Indicator, ...]
    ips: tuple[Indicator, ...]
    domains: tuple[Indicator, ...]
    emails: tuple[Indicator, ...]
    onion: tuple[Indicator, ...]


# ── capabilities ─────────────────────────────────────────────────────────────


@dataclass(frozen=True)
class CapabilityHit:
    """One capability-catalog API the app exercises.

    Carries its call-site count and the permissions / categories it maps to.

    Example (real, a2dp.Vol)::

        CapabilityHit(
            api_signature='Landroid/location/LocationManager;->'
                          'getLastKnownLocation(Ljava/lang/String;)Landroid/location/Location;',
            call_site_count=1,
            permissions=('android.permission.ACCESS_FINE_LOCATION',
                         'android.permission.ACCESS_COARSE_LOCATION'),
            categories=('LOCATION',), callers=(...))
    """

    api_signature: str
    call_site_count: int
    permissions: tuple[str, ...]
    categories: tuple[str, ...]
    callers: tuple[str, ...]


@dataclass(frozen=True)
class CapabilityReport:
    """The app's capability profile.

    Matched catalog APIs, aggregate permission / category counts, and a caller →
    permissions map. Holds ``Mapping`` fields, so this model is immutable (the
    mappings are read-only views) but NOT hashable.

    Example (real, a2dp.Vol)::

        CapabilityReport(catalog_version='0.1-seed', catalog_size=45,
                         matched_apis=10, total_call_sites=56,
                         permissions={'android.permission.ACCESS_FINE_LOCATION': 1, ...},
                         categories={'LOCATION': 1, ...},
                         api_hits=(CapabilityHit(...), ...),
                         by_caller={'La2dp/Vol/StoreLoc;->grabGPS()V': (...)})
    """

    catalog_version: str
    catalog_size: int
    matched_apis: int
    total_call_sites: int
    permissions: Mapping[str, int]
    categories: Mapping[str, int]
    api_hits: tuple[CapabilityHit, ...]
    by_caller: Mapping[str, tuple[str, ...]]

    def __post_init__(self) -> None:
        """Wrap the mapping fields in read-only views so the model is immutable."""
        for f in ("permissions", "categories", "by_caller"):
            v = getattr(self, f)
            if not isinstance(v, MappingProxyType):
                object.__setattr__(self, f, MappingProxyType(dict(v)))


# ── content providers ────────────────────────────────────────────────────────


@dataclass(frozen=True)
class ContentProviderUse:
    """A ``content://`` provider URI the app references, plus the methods using it.

    The runtime-assembled surface invisible to the ``@RequiresPermission`` map.
    ``family`` is e.g. sms / contacts / call-log / calendar.

    Example (shape; ``uri`` / ``family`` are framework constants, caller illustrative)::

        ContentProviderUse(uri='content://com.android.contacts', family='contacts',
                           methods=('Lcom/example/app/ContactReader;->load(...)...',))
    """

    uri: str
    family: str
    methods: tuple[str, ...]
