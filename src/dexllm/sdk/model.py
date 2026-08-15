"""Typed domain models for the dexllm SDK.

The value objects that cross every port boundary. Each is a frozen dataclass with
an accurate type on every field, mirroring the raw dexllm return shapes 1:1. The
adapter converts pybind objects / plain dicts into these, so a consumer programs
against *types* — not against dict keys or C++ struct attributes.

Immutability: ``frozen=True`` blocks attribute rebinding; sequence fields are
tuples and the ``Mapping`` fields (``CapabilityReport.permissions/categories/
flags/by_caller``, ``MethodAst.ast``) are wrapped in a read-only ``MappingProxyType`` at
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
    """Content-based probe of a container.

    ``format`` is ``"dex" | "zip" | "unknown"``; ``is_apk`` iff a zip carrying an
    AndroidManifest.xml. ``source`` is the path the other fields describe, so a
    probe result can say what it is about — the same reason ``ExtractedDex``
    carries its provenance (dexllm#26).

    Returned two ways, with one meaning: :func:`dexllm.sdk.identify` probes a path
    on demand, and :meth:`~dexllm.sdk.ports.EnumerationPort.source_info` reports
    what a session recorded at LOAD (dexllm#42) — the latter stays true after the
    file is gone.

    Example (real, a2dp.Vol_137.apk)::

        ContainerInfo(format='zip', is_apk=True, has_manifest=True, dex_count=1,
                      source='a2dp.Vol_137.apk')
    """

    format: str
    is_apk: bool
    has_manifest: bool
    dex_count: int
    source: str


@dataclass(frozen=True)
class DexVerifyStatus:
    """One loaded dex's structural-verification verdict.

    ``reason`` is empty when ``valid``; a rejected dex never reached the core.

    ``name`` is the file path for a bare ``.dex`` but only the entry name for a
    zip member, so it cannot say WHICH source a ``classes.dex`` came from in a
    multi-source session — ``source`` always names the constructor argument
    (dexllm#26).

    Example (real)::

        DexVerifyStatus(dex_id=0, name='classes.dex', valid=True, reason='',
                        source='app.apk')
    """

    dex_id: int
    name: str
    valid: bool
    reason: str
    source: str = ""


@dataclass(frozen=True, slots=True)
class ExtractedDex:
    """One loaded dex's bytes together with where it came from (dexllm#26).

    ``source`` is the path handed to the session and ``entry`` the member inside
    it (empty when the source IS the dex). ``offset`` is this logical dex's start
    within the LOADED IMAGE — the decompressed ``entry`` when ``entry`` is set,
    otherwise the file at ``source``. It is nonzero only for a concatenated /
    packer-dump container, which is split into several ``dex_id`` over one image,
    so one source can back several entries here; a packer apk whose
    ``classes.dex`` is two concatenated dexes has ``entry`` set AND a nonzero
    ``offset``, so slicing the ``.apk`` file at that offset is meaningless.

    ``data`` is spelled ``bytes`` on the raw ``DexKit.extract_dex`` dict — a
    ``bytes: bytes`` dataclass field would shadow the builtin inside its own
    annotation scope, so the typed model renames it.

    ``data`` is empty and ``dex_id`` is ``-1`` for an out-of-range id — and
    ONLY for that. A logical dex the core could not construct (a packer dump
    whose second dex has an intact header but an undecrypted body) is a real,
    in-range dex: it keeps its own ``dex_id`` with empty ``data`` and unknown
    ``source``, so check ``size`` rather than treating an empty row as an
    argument error.

    Example (real)::

        ExtractedDex(dex_id=1, source='app.apk', entry='classes2.dex',
                     offset=0, size=672)      # len(data) == size
    """

    dex_id: int
    data: bytes
    source: str
    entry: str
    offset: int
    size: int


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
    access_flags: tuple[
        str, ...
    ]  # decoded modifier names, e.g. ("public", "constructor")
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


@dataclass(frozen=True)
class ExternalFieldRef:
    """A field whose declaring class is not defined in any loaded dex.

    That is, a framework / library field the app reads or writes. Its full
    descriptor is ``signature`` (``Lcls;->name:Type``).

    Example (real, a2dp.Vol_137.apk)::

        ExternalFieldRef(
            class_descriptor='Landroid/app/ActivityManager$RunningAppProcessInfo;',
            name='pid', type='I',
            java_class='android.app.ActivityManager$RunningAppProcessInfo',
            java_type='int',
            java_signature='android.app.ActivityManager$RunningAppProcessInfo.pid : int',
            signature='Landroid/app/ActivityManager$RunningAppProcessInfo;->pid:I',
            referenced_in_dex_ids=(0,))
    """

    class_descriptor: str
    name: str
    type: str
    java_class: str
    java_type: str
    java_signature: str
    signature: str
    referenced_in_dex_ids: tuple[int, ...]


@dataclass(frozen=True)
class ExternalTypeRef:
    """A type referenced by the app but not declared in any loaded dex.

    That is, a framework / library class the app touches (as a field/param/return
    type, superclass, instanceof, etc.).

    Example (real, a2dp.Vol_137.apk)::

        ExternalTypeRef(
            descriptor='Landroid/accessibilityservice/AccessibilityServiceInfo;',
            java_name='android.accessibilityservice.AccessibilityServiceInfo',
            referenced_in_dex_ids=(0,))
    """

    descriptor: str
    java_name: str
    referenced_in_dex_ids: tuple[int, ...]


# ── search (L1–L7) ─────────────────────────────────────────────────────────────
# DexKit's headline capability: fast static class/method search. A hit is a light
# match record — the descriptor plus its dex location (the index id is stable within
# the loaded session, e.g. for a follow-up decompile / xref).


@dataclass(frozen=True)
class ClassMatch:
    """One class hit from a search query: descriptor + dex location.

    Example (real, a2dp.Vol_137.apk)::

        ClassMatch(class_id=6, descriptor='La2dp/Vol/ALauncher;', dex_id=0)
    """

    class_id: int
    descriptor: str
    dex_id: int


@dataclass(frozen=True)
class MethodMatch:
    """One method hit from a search query: descriptor + dex location.

    Example (real, a2dp.Vol_137.apk)::

        MethodMatch(method_id=1,
                    descriptor='La2dp/Vol/ALauncher;->onBind(Landroid/content/Intent;)'
                               'Landroid/os/IBinder;',
                    dex_id=0)
    """

    method_id: int
    descriptor: str
    dex_id: int


@dataclass(frozen=True)
class FieldMatch:
    """One field hit from a search query: descriptor + dex location.

    The field arm of the search family. Its raw counterpart was a registered but
    UNPRODUCIBLE type until dexllm#37 built ``find_fields_by_name`` — so unlike
    :class:`ClassMatch` / :class:`MethodMatch` this model is new rather than a
    rename.

    Example (real, a2dp.Vol_137.apk)::

        FieldMatch(field_id=520,
                   descriptor='La2dp/Vol/StoreLoc;->DB:La2dp/Vol/DeviceDB;',
                   dex_id=0)
    """

    field_id: int
    descriptor: str
    dex_id: int


# ── class inspection ─────────────────────────────────────────────────────────
# Fine-grained decomposition of a class (the C++ get_class_summary bundles all of
# these — class metadata + fields + methods — into one object; the SDK layer
# splits it so a consumer depends only on what it needs) — metadata, fields and
# methods are three queries. EnumerationPort.list_class_methods remains the
# descriptor-only view of the same members.


@dataclass(frozen=True)
class FieldInfo:
    """One declared field of a class: name, dex type descriptor, access flags.

    Its full descriptor is ``f"{class_descriptor}->{name}:{type}"``.

    ``access_flags`` is ``None`` when UNKNOWN — every field of an EXTERNAL class,
    which has no ``class_data`` to read modifiers from. See :class:`MethodInfo`
    for why it is not ``0``.

    On an INTERNAL class every entry is DECLARED there, so its flags are known.
    An inherited field the class only REFERENCES is not listed (dexllm#45); reach
    those through ``list_fields()``, which is the whole ``field_ids`` table —
    ``[f for f in dk.list_fields() if f.startswith(cls + "->")]``. That is a
    superset of the declarations, and across a MULTIDEX session it repeats a
    descriptor once per dex holding the entry, so wrap it in ``set()`` to count.

    Example (real, a2dp.Vol StoreLoc.DB)::

        FieldInfo(name='DB', type='La2dp/Vol/DeviceDB;', access_flags=2)
    """

    name: str
    type: str
    access_flags: Optional[int]


@dataclass(frozen=True)
class MethodInfo:
    """One declared method of a class: name, proto, access flags.

    The symmetric twin of :class:`FieldInfo`, and the reason
    :meth:`ClassInspectionPort.class_methods` exists — before dexllm#37 a
    consumer needing a method modifier (``ACC_NATIVE``, ``ACC_ABSTRACT``,
    ``ACC_SYNTHETIC``, ``ACC_DECLARED_SYNCHRONIZED``) had to leave the SDK for
    the raw ``get_class_summary``, even though the identical question about a
    FIELD was already served.

    ``access_flags`` is the **raw dex bit-field**: a Java ``synchronized`` method
    reads ``0x20000`` (``ACC_DECLARED_SYNCHRONIZED``), not ``0x20`` — see
    [api.md](../../../docs/api.md#classsummary). That is the whole point of exposing
    it here rather than the decoded names, which
    :attr:`MethodAst.access_flags` already carries.

    **On an EXTERNAL class (one no loaded dex declares) ``access_flags`` is
    ``None``**, because there is no ``class_data`` to read them from — the members
    are reconstructed from the ``method_ids`` references other classes make. It is
    NOT 0: in dex 0 is a legal, common value (package-private, non-static,
    non-final — 5.1% of the test corpus's methods, 8.7% of its fields, 34.9% of its
    classes), so reporting 0 would make "unknown" and a real declaration the same
    value and read the whole framework surface as package-private (dexllm#41).
    ``m.access_flags & ACC_NATIVE`` therefore raises ``TypeError`` on an external
    member instead of quietly answering "no".

    ``class_methods`` still reports members for an external class where
    :meth:`EnumerationPort.list_class_methods` returns nothing (the former lists
    what was OBSERVED, the latter what a loaded dex DECLARES), so the two agree
    only for internal classes.

    Its full descriptor is ``f"{class_descriptor}->{name}{proto}"``.

    Example (real, a2dp.Vol AppChooser)::

        MethodInfo(name='onCreate', proto='(Landroid/os/Bundle;)V', access_flags=4)

    Example (real, the EXTERNAL android.app.Activity)::

        MethodInfo(name='onCreate', proto='(Landroid/os/Bundle;)V', access_flags=None)
    """

    name: str
    proto: str
    access_flags: Optional[int]


@dataclass(frozen=True)
class ClassInfo:
    """A class's metadata (no field/method bodies — those are separate queries).

    ``is_internal`` is False for a class only REFERENCED (not declared) in a loaded
    dex — such an external class has ``dex_id=-1``, ``dex_name=""``, ``superclass=""``,
    ``access_flags=None`` (UNKNOWN, not 0 — see :class:`MethodInfo`) and (via
    ``class_fields``) fields deduped + sorted by (name, type) rather than in
    declared order. ``source_file`` may be empty. ``dex_name`` is the declaring dex's
    file name (``classes.dex`` / ``classes2.dex`` / …, from ``verify_report``); ``""``
    for an external class.

    Example (real, a2dp.Vol StoreLoc)::

        ClassInfo(descriptor='La2dp/Vol/StoreLoc;', dex_id=0, dex_name='classes.dex',
                  is_internal=True, access_flags=1, superclass='Landroid/app/Service;',
                  interfaces=(), source_file='StoreLoc.java')
    """

    descriptor: str
    dex_id: int
    is_internal: bool
    access_flags: Optional[int]
    superclass: str
    interfaces: tuple[str, ...]
    source_file: str
    dex_name: str = ""


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
    #: ``Unknown`` only: a control-flow merge discarded this register's definition —
    #: the value depends on which path reached the call, or the analyzer stopped at a
    #: loop header / catch handler. ``Unknown`` with this False means "never tracked"
    #: (arithmetic, array load, …). Never treat a ``varies-by-path`` argument as a
    #: constant: the site has more than one possible value.
    crossed_branch: bool = False


@dataclass(frozen=True)
class CallSite:
    """One bytecode invoke edge — a ``caller`` method calling a ``callee`` method.

    **Which half is fixed depends on the direction that produced it**, because the
    same model serves both queries:

    - ``find_call_sites_to(X)`` → ``callee_descriptor`` is constant (``X``) and the
      ``caller_*`` fields vary — "who calls X".
    - ``find_call_sites_from(M)`` → the ``caller_*`` fields are constant (``M``) on every
      element and ``callee_descriptor`` varies — "what M calls". The repeated
      caller is the queried method, not a per-site value.

    ``bytecode_offset`` is ALWAYS an offset into the CALLER's instruction stream
    (so it varies in both directions) — the same base ``render_method_smali``
    prints, i.e. relative to ``insns``, NOT to the start of the ``code_item``
    struct. ``caller_method_idx`` is a **dex-local** ``method_ids`` index —
    meaningful only paired with ``caller_dex_id``, not a stable global id.

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

    Produced only by ``resolve_call_args(X)``, i.e. the same reverse direction as
    ``find_call_sites_to``: ``callee_descriptor`` is constant and the ``caller_*`` fields
    vary. Field semantics are otherwise :class:`CallSite`'s.

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
    """One network indicator, with where it lives in the app.

    ``methods`` are the call sites that LOAD it (const-string xref); ``declared_in``
    are the classes that DECLARE it as a static-field constant. An indicator kept only
    as a constant has no call site at all, so ``declared_in`` is its only location
    (dexllm#20). Both are empty when extracted without cross-reference.

    Example (real, tvleanback — a domain in an ExoPlayer string)::

        Indicator(value='dolby.com',
                  methods=('Lcom/google/android/exoplayer2/source/dash/manifest/'
                           'DashManifestParser;->parseAudioChannelConfiguration('
                           'Lorg/xmlpull/v1/XmlPullParser;)I', ...))
    """

    value: str
    methods: tuple[str, ...] = ()
    declared_in: tuple[str, ...] = ()


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

    Carries its touch count, the permissions it maps to, and the catalog's two
    metadata axes: ``categories`` (domain / behaviour) and ``flags`` (cross-domain
    concerns a domain tag cannot express, today only ``IDENTIFIER``).

    **Which counter is populated follows the catalog key's form.** A METHOD entry
    fills ``call_site_count`` (invoke instructions); a FIELD entry — how an app
    reaches contacts / call log / calendar, by reading a ``CONTENT_URI`` constant —
    fills ``field_access_count`` (read instructions, NOT deduplicated by method)
    and leaves the other 0. Both are instruction counts, so summing them is
    meaningful; they are separate so ``call_site_count`` keeps exactly the value a
    consumer already reads.

    Example (real, a2dp.Vol)::

        CapabilityHit(
            api_signature='Landroid/location/LocationManager;->'
                          'getLastKnownLocation(Ljava/lang/String;)Landroid/location/Location;',
            call_site_count=1,
            permissions=('android.permission.ACCESS_FINE_LOCATION',
                         'android.permission.ACCESS_COARSE_LOCATION'),
            categories=('LOCATION',), flags=(), callers=(...))
    """

    api_signature: str
    call_site_count: int
    permissions: tuple[str, ...]
    categories: tuple[str, ...]
    flags: tuple[str, ...]
    callers: tuple[str, ...]
    # Appended: READ INSTRUCTIONS against a FIELD-descriptor entry (dexllm#36).
    # 0 for a method entry, and `call_site_count` is 0 for a field one. Both are
    # instruction counts, so summing them is meaningful; they are separate to keep
    # `call_site_count`'s released meaning intact, not because the units differ.
    field_access_count: int = 0


@dataclass(frozen=True)
class CapabilityReport:
    """The app's capability profile.

    Matched catalog APIs, aggregate permission / category / flag counts, and a
    caller → catalog-APIs map. Holds ``Mapping`` fields, so this model is immutable
    (the mappings are read-only views) but NOT hashable.

    ``by_caller`` is the transpose of ``CapabilityHit.callers`` — which method in
    this app invokes which catalog API. It held ``{permissions}`` until dexllm#35,
    and was built inside the permission loop, so an API declaring none contributed
    no callers at all; every REFLECTION / PROCESS_EXEC / DYNAMIC_LOAD /
    NATIVE_CODE / CRYPTO / WEBVIEW / STORAGE entry is permission-less, as are 6
    domain entries incl. the ANDROID_ID read, and the index covered 17 of the
    corpus's 317 distinct callers (5.4%). Both views are derivable from
    ``api_hits``, so this is a convenience index rather than new information; the
    value is signatures because that is the more primary view, and because the
    FIELD only derives one way — ``{p for a in by_caller[c] for p in
    by_api[a].permissions}`` recovers the old value, a permission set could not
    recover an API.

    ``categories`` is a single axis (domain / behaviour), so one call site is never
    counted twice under two names for the same concern; ``flags`` is the orthogonal
    cross-domain axis (``IDENTIFIER``).

    Example (real, tvleanback)::

        CapabilityReport(catalog_version='0.2', catalog_size=42,
                         matched_apis=10, total_call_sites=86,
                         permissions={'android.permission.INTERNET': 3, ...},
                         categories={'REFLECTION': 73, ...}, flags={},
                         api_hits=(CapabilityHit(...), ...),
                         by_caller={'Landroid/arch/lifecycle/ClassesInfoCache$'
                                    'MethodReference;->invokeCallback(...)':
                                    ('Ljava/lang/reflect/Method;->invoke(...)',)})
    """

    catalog_version: str
    catalog_size: int
    matched_apis: int
    total_call_sites: int
    permissions: Mapping[str, int]
    categories: Mapping[str, int]
    flags: Mapping[str, int]
    api_hits: tuple[CapabilityHit, ...]
    by_caller: Mapping[str, tuple[str, ...]]
    # Appended (dexllm#36). docs/sdk.md documents the inequality
    # `sum(categories.values()) >= total_call_sites + total_field_accesses`, which
    # was unexpressible on this layer until this field existed: without it the only
    # available form is the WEAKER `>= total_call_sites`, and a matched field entry
    # makes that read as slack where there is none.
    total_field_accesses: int = 0

    def __post_init__(self) -> None:
        """Wrap the mapping fields in read-only views so the model is immutable."""
        for f in ("permissions", "categories", "flags", "by_caller"):
            v = getattr(self, f)
            if not isinstance(v, MappingProxyType):
                object.__setattr__(self, f, MappingProxyType(dict(v)))


# ── content providers ────────────────────────────────────────────────────────


@dataclass(frozen=True)
class ContentProviderUse:
    """A ``content://`` provider URI the app references, plus the methods using it.

    The runtime-assembled surface invisible to the ``@RequiresPermission`` map.
    ``family`` is e.g. sms / contacts / calllog / calendar.

    Example (shape; ``uri`` / ``family`` are framework constants, caller illustrative)::

        ContentProviderUse(uri='content://com.android.contacts', family='contacts',
                           methods=('Lcom/example/app/ContactReader;->load(...)...',))
    """

    uri: str
    family: str
    methods: tuple[str, ...]
