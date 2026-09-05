"""Typed stub for the pybind11 native module ``dexllm._dexkit_core``.

The native extension carries no static type information, so this ``.pyi`` is the
typed shadow of the API bound in ``native/binding/module.cpp``
(``PYBIND11_MODULE(_dexkit_core, m)``) plus the Python-side convenience
properties attached in ``src/dexllm/_enrich.py``.

Runtime is the source of truth. When a binding changes, update module.cpp first,
then reflect the added/removed/renamed ``.def(...)`` / ``py::class_`` attribute
here. Do not advertise names the runtime does not export.

Every ``Example`` below is REAL output, captured against
``test_apk/APK/com.example.android.tvleanback.apk`` — not illustrative. The
shared prologue for all of them::

    import dexllm
    dk = dexllm.DexKit("app.apk")

Descriptors are Dalvik form throughout: ``Lpkg/Cls;`` for a type,
``Lpkg/Cls;->name(args)Ret`` for a method, ``Lpkg/Cls;->name:Type`` for a field.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Any, TypedDict, overload

# ── dict-returning shapes (structural contracts) ─────────────────────────────

class _IdentifyResult(TypedDict):
    format: str
    is_apk: bool
    has_manifest: bool
    dex_count: int
    source: str  # the path the keys above describe (dexllm#26/#42)

class _VerifyStatus(TypedDict):
    dex_id: int
    name: str  # entry name for a zip member, file path for a bare .dex
    valid: bool
    reason: str
    source: str  # the path handed to the constructor (dexllm#26)

class _ExtractedDex(TypedDict):
    bytes: bytes
    dex_id: int  # -1 ONLY when out of range; an in-range dex the core could
    #              not construct keeps its id with empty bytes (check `size`)
    source: str  # the path handed to the constructor
    entry: str  # zip member; "" when the source IS the dex
    offset: int  # start within the LOADED IMAGE (the decompressed `entry`
    #              when `entry` is set, else the file at `source`)
    size: int

class _DecompiledMethodWithPc(TypedDict):
    source: str
    pc_map: list[tuple[int, int]]  # (line_1based, byte_off)

class _MethodAstResult(TypedDict):
    found: bool
    # dexllm#69 §4 — the KEYS say what every other record on every layer says.
    # The C++ struct fields behind them keep DAD's own spellings (`cls_name`,
    # `ret_type`, `params_type`, `access`), which are part of the port's `// DAD:`
    # 1:1 traceability; the key is the API, the field is the port.
    class_descriptor: str
    name: str
    proto: str
    return_type: str
    param_types: list[str]
    access_flags: list[str]
    source: str
    ast: dict[str, Any] | None  # None for an external / not-found method
    pc_map: list[tuple[int, int]]  # (statement_seq, byte_off)

class _ApiCallers(TypedDict):
    api: str
    descriptors: list[str]
    callers: list[str]

class _PermissionCallers(TypedDict):
    # `perm` / `protectionLevel` are the raw layer's own spellings and the SDK
    # renames both (`permission` / `protection_level`); `protectionLevel` is also
    # the only camelCase key in the API. Measured by dexllm#69 but NOT in the
    # decisions it lists, so it is recorded rather than changed here.
    perm: str
    protectionLevel: str
    apis: list[_ApiCallers]

# ── module-level functions ───────────────────────────────────────────────────

def identify(path: str) -> _IdentifyResult:
    """Probe a container WITHOUT loading it — cheap pre-filter for a sweep.

    Detects by content, not extension, so a disguised APK still reports
    ``is_apk``. ``dex_count == 0`` means a resources-only container, which
    ``DexKit(...)`` would reject by raising.

    Example::

        >>> dexllm.identify("app.apk")
        {'format': 'zip', 'is_apk': True, 'has_manifest': True, 'dex_count': 1,
         'source': 'app.apk'}
    """

def verify(path: str, lenient: bool = ...) -> list[_VerifyStatus]:
    """Structural verdict per dex, load-free — and it NEVER raises.

    Same VerifyDex call and dex_id assignment as ``DexKit(path).verify_report()``,
    so the verdicts match for a loadable source; unlike construction, a malformed
    or non-dex path comes back as ``valid=False`` instead of an exception.

    Example::

        >>> dexllm.verify("app.apk")
        [{'dex_id': 0, 'name': 'classes.dex', 'valid': True, 'reason': '', 'source': 'app.apk'}]
    """

def is_framework_descriptor(descriptor: str) -> bool:
    """Report whether a TYPE is Android/JDK framework — the reference filter.

    This is the rule behind ``list_external_*(framework_only=)``: it answers
    "is this referenced type framework code". It is NOT the ``app_only``
    CALLER predicate the Python APIs use (``dexllm._callers``), and the two
    prefix sets deliberately differ — this one has ``Landroid/``, ``Lorg/json/``,
    ``Lsun/``, ``Llibcore/`` and no ``Landroidx/``, so
    ``is_framework_descriptor("Landroidx/core/app/ActivityCompat;")`` is False
    while that class IS a bundled-library caller. Different questions, different
    sets; do not use one to predict the other.

    Example::

        >>> dexllm.is_framework_descriptor("Landroid/app/Activity;")
        True
    """

# ── pybind return-object classes (read-only) ─────────────────────────────────

class ExternalTypeRef:
    @property
    def descriptor(self) -> str: ...
    @property
    def referenced_in_dex_ids(self) -> list[int]: ...
    # attached by _enrich.py
    @property
    def java_type(self) -> str: ...

class ExternalMethodRef:
    @property
    def class_descriptor(self) -> str: ...
    @property
    def name(self) -> str: ...
    @property
    def proto(self) -> str: ...
    @property
    def descriptor(self) -> str: ...
    @property
    def referenced_in_dex_ids(self) -> list[int]: ...
    # attached by _enrich.py
    @property
    def java_class(self) -> str: ...
    @property
    def parameters(self) -> list[str]: ...
    @property
    def return_type(self) -> str: ...
    @property
    def java_signature(self) -> str: ...
    @property
    def is_constructor(self) -> bool: ...
    @property
    def is_static_initializer(self) -> bool: ...

class ExternalFieldRef:
    @property
    def class_descriptor(self) -> str: ...
    @property
    def name(self) -> str: ...
    @property
    def type(self) -> str: ...
    @property
    def referenced_in_dex_ids(self) -> list[int]: ...
    # attached by _enrich.py
    @property
    def java_class(self) -> str: ...
    @property
    def java_type(self) -> str: ...
    @property
    def descriptor(self) -> str: ...
    @property
    def java_signature(self) -> str: ...

class ClassRef:
    @property
    def descriptor(self) -> str: ...
    @property
    def dex_id(self) -> int: ...
    @property
    def class_idx(self) -> int: ...

class MethodRef:
    @property
    def descriptor(self) -> str: ...
    @property
    def dex_id(self) -> int: ...
    @property
    def method_idx(self) -> int: ...

class FieldRef:
    @property
    def descriptor(self) -> str: ...
    @property
    def dex_id(self) -> int: ...
    @property
    def field_idx(self) -> int: ...

class FieldInfo:
    @property
    def name(self) -> str: ...
    @property
    def type(self) -> str: ...
    @property
    def access_flags(self) -> int | None:
        """Raw dex access flags, or ``None`` when UNKNOWN (dexllm#41).

        ``None`` on every member of an EXTERNAL class (one no loaded dex declares,
        so there is no ``class_data``). It is not reported as 0 because 0 is a
        legal dex value — package-private, non-static, non-final — held by 8.7% of
        the test corpus's fields.

        An INTERNAL class's fields are the ones it DECLARES, so their flags are
        always known: an inherited field it only REFERENCES is not listed
        (dexllm#45), even though the dex ``field_ids`` table groups that reference
        under it. Read those from ``list_fields()``, which is the whole table.
        """

    @property
    def class_descriptor(self) -> str:
        """The class this member is DECLARED on (dexllm#69 §3)."""

    @property
    def descriptor(self) -> str:
        """The IDENTITY string the xref / decompile APIs consume.

        Every other member-shaped record already carried one — ``MethodRef``,
        ``ExternalMethodRef``, ``ClassSummary`` — and ``*Info`` was the only one
        without, so a caller reading ``class_methods()`` had to re-assemble it by
        hand. COMPUTED from ``class_descriptor`` + the member's own name.
        """

class MethodInfo:
    @property
    def name(self) -> str: ...
    @property
    def proto(self) -> str: ...
    @property
    def access_flags(self) -> int | None:
        """Raw dex access flags — no ``java.lang.reflect.Modifier`` normalization.

        A method declared ``synchronized`` in Java carries
        ``ACC_DECLARED_SYNCHRONIZED`` (0x20000), not ``ACC_SYNCHRONIZED`` (0x20);
        in dex 0x20 means JNI ``synchronized native``.

        ``None`` when UNKNOWN — every member of an EXTERNAL class, which has no
        ``class_data`` to read modifiers from (dexllm#41). Not 0: that is a legal
        dex value (package-private, non-static, non-final) held by 5.1% of the
        test corpus's methods, so 0 would make the two indistinguishable. A
        DECLARED method always knows its flags (``class_method_ids`` is built from
        ``class_data``); the field side has one more unknown case — see
        :class:`FieldInfo`.
        """

    @property
    def class_descriptor(self) -> str:
        """The class this member is DECLARED on (dexllm#69 §3)."""

    @property
    def descriptor(self) -> str:
        """The IDENTITY string the xref / decompile APIs consume.

        Every other member-shaped record already carried one — ``MethodRef``,
        ``ExternalMethodRef``, ``ClassSummary`` — and ``*Info`` was the only one
        without, so a caller reading ``class_methods()`` had to re-assemble it by
        hand. COMPUTED from ``class_descriptor`` + the member's own name.
        """

class ClassSummary:
    @property
    def descriptor(self) -> str: ...
    @property
    def is_internal(self) -> bool: ...
    @property
    def dex_id(self) -> int: ...
    @property
    def access_flags(self) -> int | None:
        """The class's own raw dex access flags, ``None`` when UNKNOWN (dexllm#41).

        ``None`` for an EXTERNAL class — 34.9% of the corpus's declared classes
        carry a genuine 0 (package-private), so 0 cannot also mean "unknown".
        """

    @property
    def superclass_descriptor(self) -> str: ...
    @property
    def interface_descriptors(self) -> list[str]: ...
    @property
    def fields(self) -> list[FieldInfo]: ...
    @property
    def methods(self) -> list[MethodInfo]: ...
    @property
    def source_file(self) -> str: ...

class ResolvedArg:
    # The raw pybind object populates every field (empty-string / 0 default when
    # the ``kind`` does not carry it); the typed dexllm.sdk.ResolvedArg is the
    # derived, Optional-narrowed view.
    @property
    def kind(self) -> str: ...
    @property
    def register_index(self) -> int: ...
    @property
    def string_value(self) -> str: ...
    @property
    def int_value(self) -> int: ...
    @property
    def class_descriptor(self) -> str: ...
    @property
    def field_descriptor(self) -> str: ...
    @property
    def method_descriptor(self) -> str: ...
    @property
    def parameter_index(self) -> int: ...
    @property
    def crossed_branch(self) -> bool: ...

class CallSite:
    """One invoke edge; which half is FIXED depends on the producing direction.

    find_call_sites_to(X) fixes callee_descriptor and varies caller_*;
    find_call_sites_from(M) fixes caller_* and varies callee_descriptor.
    bytecode_offset is always an offset into the CALLER's instruction stream.
    One entry per invoke INSTRUCTION — a caller that invokes the target twice
    appears twice.
    """

    @property
    def caller_dex_id(self) -> int: ...
    @property
    def caller_method_idx(self) -> int:
        """Dex-LOCAL method_ids index — meaningful only with caller_dex_id."""

    @property
    def caller_descriptor(self) -> str: ...
    @property
    def callee_descriptor(self) -> str: ...
    @property
    def bytecode_offset(self) -> int: ...
    @property
    def invoke_opcode(self) -> int: ...

class FieldAccessSite:
    """One field-access INSTRUCTION — an ``iget*``/``iput*``/``sget*``/``sput*``.

    The field cross-reference's row, and the sibling of :class:`CallSite`. It does
    NOT reuse that record's ``caller_*`` prefix: an ``iget`` calls nothing, so
    spelling the accessor a "caller" would give one word two grammars.

    ``dex_id`` is the dex of the ACCESSING METHOD — which is what makes
    ``method_idx`` meaningful — and may DIFFER from the dex that declares the
    field, since a field is referenced across dexes.
    """

    @property
    def method_descriptor(self) -> str:
        """The method performing the access."""

    @property
    def dex_id(self) -> int:
        """The ACCESSING method's dex; the field's own dex may differ."""

    @property
    def method_idx(self) -> int:
        """Dex-LOCAL method_ids index — meaningful only with dex_id."""

    @property
    def field_descriptor(self) -> str:
        """The accessed field; constant across one query's rows."""

    @property
    def bytecode_offset(self) -> int:
        """Offset into the method's ``insns`` — the base render_method_smali prints."""

    @property
    def opcode(self) -> int:
        """0x52..0x6D. Says the direction AND whether the access is static."""

class ResolvedCallSite:
    """A CallSite plus a resolved origin per argument.

    Only resolve_call_args produces it, so callee_descriptor is fixed and the
    caller_* fields vary.
    """

    @property
    def caller_dex_id(self) -> int: ...
    @property
    def caller_method_idx(self) -> int:
        """Dex-LOCAL method_ids index — meaningful only with caller_dex_id."""

    @property
    def caller_descriptor(self) -> str: ...
    @property
    def callee_descriptor(self) -> str: ...
    @property
    def bytecode_offset(self) -> int: ...
    @property
    def invoke_opcode(self) -> int: ...
    @property
    def args(self) -> list[ResolvedArg]: ...

class TypeReferences:
    @property
    def fields(self) -> list[str]: ...
    @property
    def methods_returning(self) -> list[str]: ...
    @property
    def methods_with_param(self) -> list[str]: ...

# ── the engine ───────────────────────────────────────────────────────────────

class DexKit:
    """A loaded APK / dex. Every query below is a method on this object.

    The source is identified by CONTENT, not extension, so a disguised or
    extension-less APK loads; a non-dex/non-zip file, or a zip with no
    ``classes*.dex``, raises. Each dex passes the structural verifier before the
    parser sees it.

    Example::

        >>> dk = dexllm.DexKit("app.apk")                  # one apk or bare .dex
        >>> dk = dexllm.DexKit(["dump.dex", "app.apk"])    # unpacked dex wins
        >>> dk = dexllm.DexKit("partial.dex", lenient=True)

    ``sources`` are loaded IN ORDER — earlier sources get lower dex_ids and win a
    class-name collision, so list a runtime-dumped dex BEFORE the original APK
    (this mirrors ART). ``lenient=True`` verifies in ART-structural-equivalent
    mode, so a partially-decrypted dump (valid structure, garbage method bodies)
    still loads; header/ids/code_item bounds stay verified either way.
    """

    @overload
    def __init__(self, apk_path: str, lenient: bool = False) -> None: ...
    @overload
    def __init__(self, sources: Sequence[str], lenient: bool = False) -> None: ...

    # load / container
    def dex_count(self) -> int:
        """Count the loaded dexes. Example: ``dk.dex_count()`` -> ``1``."""

    def apk_path(self) -> str:
        """Return the first construction source (back-compat; prefer ``sources()``)."""

    def sources(self) -> list[str]:
        """Return the construction sources in load order — earlier ones get lower dex_ids.

        Example: ``dk.sources()`` -> ``['app.apk']``. After
        ``add_dumped_dexes(dk, ['dump.dex'])`` -> ``['dump.dex', 'app.apk']``.
        """

    def source_info(self) -> list[_IdentifyResult]:
        """Report what each construction source WAS, probed once at LOAD (#42).

        One entry per :meth:`sources` entry, in the same order, carrying the same
        keys :func:`identify` returns. A session FACT: it stays true after the
        file is deleted, which a dumped dex in a temp directory routinely is.
        Re-probing the path would answer ``dex_count: 0`` — the documented
        "nothing to analyse" sentinel — for a session that still works.

        Example::

            dk.source_info()[0]["is_apk"]   # -> True
        """

    def verify_report(self) -> list[_VerifyStatus]:
        """Per-dex structural verdict from the load-time gate.

        A fully-rejected container raises at construction instead, so a reachable
        ``valid=False`` here means a sibling dex in the same APK was rejected.

        Example::

            >>> dk.verify_report()
            [{'dex_id': 0, 'name': 'classes.dex', 'valid': True, 'reason': '', 'source': 'app.apk'}]
        """

    def locate_class_dex(self, class_descriptor: str) -> int:
        """dex_id declaring the class, or -1 if it is only referenced.

        Example: ``dk.locate_class_dex("Lcom/example/android/tvleanback/Utils;")``
        -> ``0``.
        """
    # enumeration (all-dex + per-dex)
    def list_classes(self) -> list[str]:
        """Every DECLARED class descriptor, all dexes.

        Example::

            >>> dk.list_classes()[:2]
            ['Landroid/arch/core/internal/FastSafeIterableMap;',
             'Landroid/arch/core/internal/SafeIterableMap$1;']
        """

    def list_classes_in_dex(self, dex_id: int) -> list[str]:
        """``list_classes`` scoped to one dex — use with ``locate_class_dex``."""

    def list_class_methods(self, class_descriptor: str) -> list[str]:
        """Full descriptors of the class's declared methods (no superclass walk).

        Example::

            >>> dk.list_class_methods("Lcom/example/android/tvleanback/Utils;")[:2]
            ['Lcom/example/android/tvleanback/Utils;-><init>()V',
             'Lcom/example/android/tvleanback/Utils;->convertDpToPixel(Landroid/content/Context;I)I']
        """

    def list_fields(self) -> list[str]:
        """Every field descriptor in the field_ids pool (declared AND referenced).

        Example::

            >>> dk.list_fields()[:1]
            ['Landroid/app/Notification$Action;->actionIntent:Landroid/app/PendingIntent;']
        """

    def list_fields_in_dex(self, dex_id: int) -> list[str]:
        """``list_fields`` scoped to one dex."""

    def list_methods(self) -> list[str]:
        """Every method descriptor in the method_ids pool (declared AND referenced).

        Example::

            >>> dk.list_methods()[:1]
            ['Landroid/accessibilityservice/AccessibilityServiceInfo;->getCanRetrieveWindowContent()Z']
        """

    def list_methods_in_dex(self, dex_id: int) -> list[str]:
        """``list_methods`` scoped to one dex."""

    def list_value_strings(self) -> list[str]:
        """Every distinct string the app LOADS as a value — the IOC feed.

        ``const-string``/``jumbo`` operands plus static-field ``VALUE_STRING``
        initializers, deduplicated. Excludes identifier/metadata pool entries
        (type, method and field names, shorty, source files).

        Example::

            >>> [s for s in dk.list_value_strings() if s.startswith("http")][:1]
            ['http://schemas.android.com/apk/res/android']
        """

    def list_class_strings(self, class_descriptor: str) -> list[str]:
        """List the strings this class loads.

        The union over its declared methods, then its own static-field
        ``VALUE_STRING`` initializers. ``[]`` (never raises) for an unknown or
        external class.

        Example::

            >>> dk.list_class_strings("Lcom/example/android/tvleanback/Utils;")
            ['window']
        """

    def list_method_strings(self, method_descriptor: str) -> list[str]:
        """List the strings this method body loads.

        Bytecode-only — a ``static final String`` is a class-level EncodedValue
        and appears in ``list_class_strings`` instead. ``[]`` for an abstract,
        native or unknown method.

        Example::

            >>> dk.list_method_strings(
            ...     "Lcom/example/android/tvleanback/Utils;"
            ...     "->getDisplaySize(Landroid/content/Context;)Landroid/graphics/Point;")
            ['window']
        """

    def extract_dex(self, dex_id: int) -> _ExtractedDex:
        r"""Extract one dex's bytes AND where it came from — dump an unpacked dex.

        ``source``/``entry`` are what identify it: two sources in one session can
        both carry a ``classes.dex``, and a concatenated container has no
        ``verify_report`` row at all for its second logical dex. ``offset`` is that
        dex's start within the LOADED IMAGE — the decompressed ``entry`` when
        ``entry`` is set, otherwise the file at ``source``; do not slice a zip
        ``source`` at it.

        Example::

            >>> d = dk.extract_dex(0)
            >>> d["bytes"][:4], d["size"], d["entry"]
            (b'dex\\n', 5472720, 'classes.dex')
        """

    def extract_dexes(self) -> list[_ExtractedDex]:
        """Every loaded dex in ``dex_id`` order — the dump-the-container form.

        ``len()`` equals ``dex_count()``. Separate PLURAL name rather than an
        optional ``dex_id``, so the return type never depends on the argument.
        COPIES every dex's bytes; use ``extract_dex(i)`` for one.

        Example::

            >>> [(d["dex_id"], d["entry"], d["size"]) for d in dk.extract_dexes()]
            [(0, 'classes.dex', 5472720)]
        """
    # class inspection / external refs
    def get_class_summary(self, class_descriptor: str) -> ClassSummary:
        """Class metadata + declared fields and methods in one call.

        For an INTERNAL class, ``fields`` / ``methods`` are what its own
        ``class_data`` declares; an inherited field it only REFERENCES is not among
        them (dexllm#45), and is in ``list_fields()``, the whole ``field_ids``
        table.

        For a class only REFERENCED (not declared) in a loaded dex the result has
        ``is_internal=False``, ``dex_id=-1`` and ``access_flags=None`` — on the
        class AND on every member, which are reconstructed from the ``method_ids``
        / ``field_ids`` entries other classes reference, so their modifiers are
        genuinely unknown rather than 0 (dexllm#41).

        Example::

            >>> s = dk.get_class_summary("Lcom/example/android/tvleanback/Utils;")
            >>> s.dex_id, s.is_internal, s.access_flags, s.superclass_descriptor
            (0, True, 1, 'Ljava/lang/Object;')
            >>> s.source_file, len(s.fields), len(s.methods)
            ('Utils.java', 0, 5)
            >>> [(m.name, m.proto) for m in s.methods][:2]
            [('<init>', '()V'), ('convertDpToPixel', '(Landroid/content/Context;I)I')]
        """

    def list_external_type_refs(
        self, framework_only: bool = True
    ) -> list[ExternalTypeRef]:
        """Types referenced but not declared here — the app's outward surface.

        Example::

            >>> t = dk.list_external_type_refs()[0]
            >>> t.descriptor, t.java_type, t.referenced_in_dex_ids
            ('Landroid/accessibilityservice/AccessibilityServiceInfo;',
             'android.accessibilityservice.AccessibilityServiceInfo', [0])
        """

    def list_external_method_refs(
        self, framework_only: bool = True
    ) -> list[ExternalMethodRef]:
        """Methods called but not declared here — what ``permission_callers`` joins on.

        Example::

            >>> m = dk.list_external_method_refs()[0]
            >>> m.class_descriptor, m.name, m.proto
            ('Landroid/accessibilityservice/AccessibilityServiceInfo;',
             'getCanRetrieveWindowContent', '()Z')
        """

    def list_external_field_refs(
        self, framework_only: bool = True
    ) -> list[ExternalFieldRef]:
        """Fields touched but not declared here.

        Example::

            >>> f = dk.list_external_field_refs()[0]
            >>> f.descriptor
            'Landroid/app/Notification$Action;->actionIntent:Landroid/app/PendingIntent;'
        """
    # cross-reference
    def find_call_sites_to(self, method_descriptor: str) -> list[CallSite]:
        """Call sites invoking the API — its CALLERS (callee fixed, caller varies).

        Example::

            >>> c = dk.find_call_sites_to(
            ...     "Landroid/content/Context;"
            ...     "->getSystemService(Ljava/lang/String;)Ljava/lang/Object;")[0]
            >>> c.caller_descriptor
            'Landroid/support/v14/preference/SwitchPreference;->syncViewIfAccessibilityEnabled(Landroid/view/View;)V'
            >>> c.bytecode_offset, c.invoke_opcode, c.caller_dex_id
            (14, 110, 0)
        """

    def find_call_sites_from(self, method_descriptor: str) -> list[CallSite]:
        """Call sites inside the method — its CALLEES (caller fixed, callee varies).

        Example::

            >>> [(c.callee_descriptor, c.bytecode_offset)
            ...  for c in dk.find_call_sites_from(
            ...      "Lcom/example/android/tvleanback/Utils;"
            ...      "->getDisplaySize(Landroid/content/Context;)Landroid/graphics/Point;")]
            [('Landroid/content/Context;->getSystemService(Ljava/lang/String;)Ljava/lang/Object;', 6),
             ('Landroid/view/WindowManager;->getDefaultDisplay()Landroid/view/Display;', 18), ...]
        """

    def resolve_call_args(
        self, method_descriptor: str, depth: int = 2
    ) -> list[ResolvedCallSite]:
        """``find_call_sites_to`` plus each argument's resolved origin.

        The analysis is BASIC-BLOCK WINDOWED: ``depth`` is how many predecessor
        levels of blocks are searched above the call site's own block, and nothing
        outside that window is looked at. ``depth=0`` is the call's own block alone;
        the default 2 adds two levels above it. Raising it resolves more arguments
        and costs more; a value defined further back reads as ``Unknown``.

        Within the window the analysis is join-aware: a definition is reported only
        if EVERY edge reaching the call carries it, otherwise the origin is
        ``Unknown`` with ``crossed_branch=True``. This is what makes an argument
        rule ("which call sites pass state 2?") trustworthy. An edge from outside
        the window carries nothing and tombstones the same way.

        Example::

            >>> r = dk.resolve_call_args(
            ...     "Landroid/content/Context;"
            ...     "->getSystemService(Ljava/lang/String;)Ljava/lang/Object;")[0]
            >>> [(a.kind, a.string_value, a.crossed_branch) for a in r.args]
            [('MethodReturn', '', False), ('ConstString', 'accessibility', False)]
        """

    def find_field_read_sites(self, field_descriptor: str) -> list[FieldAccessSite]:
        """Every site that READS the field — one row per ``iget*``/``sget*``.

        NOT deduplicated: one row per READ INSTRUCTION, like ``CallSite``. Unlike
        the ``list[str]`` these returned before dexllm#84, the duplicates are now
        DISTINCT records — they differ in ``bytecode_offset``. For the old value,
        deduplicated, use ``{s.method_descriptor for s in ...}``.

        Example — the method below holds two ``iget-object`` of the field::

            >>> [s.bytecode_offset for s in dk.find_field_read_sites(
            ...     "Lcom/google/android/exoplayer2/ui/DefaultTimeBar;"
            ...     "->touchPosition:Landroid/graphics/Point;")]
            [42, 96]
        """

    def find_field_write_sites(self, field_descriptor: str) -> list[FieldAccessSite]:
        """Every site that WRITES the field — the taint-source half of the pair.

        Same per-INSTRUCTION rows as ``find_field_read_sites``, with an
        ``iput*``/``sput*`` opcode. The field above has a single ``iput``, so its
        write list holds one row against the read list's two.
        """

    def find_type_references(self, type_descriptor: str) -> TypeReferences:
        """Where a TYPE appears: as a field type, a return type, a parameter type.

        Example::

            >>> t = dk.find_type_references("Landroid/graphics/Point;")
            >>> t.fields[:1]
            ['Lcom/google/android/exoplayer2/ui/DefaultTimeBar;->touchPosition:Landroid/graphics/Point;']
            >>> t.methods_returning[:1]
            ['Lcom/example/android/tvleanback/Utils;->getDisplaySize(Landroid/content/Context;)Landroid/graphics/Point;']
        """
    # search (L1–L7)
    #
    # ``match_type`` is one of "contains" (default) / "equals" / "starts_with" /
    # "ends_with" / "similar_regex"; an unrecognised value falls back to
    # "contains" (the dexllm.sdk layer narrows this to a Literal). String-CONTENT
    # queries are MUTF-8-encoded at the binding, so a literal containing NUL or a
    # supplementary code point matches.
    def find_classes_by_name(
        self,
        name: str,
        match_type: str = "contains",
        ignore_case: bool = False,
    ) -> list[ClassRef]:
        """Search class NAMES. Accepts dotted or Dalvik form.

        Example::

            >>> [c.descriptor for c in dk.find_classes_by_name("tvleanback/Utils")]
            ['Lcom/example/android/tvleanback/Utils$MediaDimensions;',
             'Lcom/example/android/tvleanback/Utils;']
        """

    def find_classes_using_strings(
        self,
        strings: Sequence[str | bytes | bytearray],
        match_type: str = "contains",
        ignore_case: bool = False,
    ) -> list[ClassRef]:
        """Classes whose CODE loads all of these strings (``const-string`` index).

        Cannot see a ``static final String`` that is declared but never loaded —
        that is ``find_classes_declaring_strings``. An empty query returns EVERY
        class here (upstream's keyword path), unlike the declaring variant.

        Example::

            >>> [c.descriptor for c in dk.find_classes_using_strings(["window"])][:1]
            ['Landroid/support/v4/util/PatternsCompat;']
        """

    def find_classes_declaring_strings(
        self,
        strings: Sequence[str | bytes | bytearray],
        match_type: str = "contains",
        ignore_case: bool = False,
    ) -> list[ClassRef]:
        """Classes DECLARING all of these as static-field constants.

        The declaration-side counterpart of ``find_classes_using_strings`` — the
        only way to locate an indicator kept solely in a constant. An EMPTY query
        returns nothing.

        Example::

            >>> [c.descriptor for c in dk.find_classes_declaring_strings(["http"])][:1]
            ['Landroid/support/v4/content/res/TypedArrayUtils;']
        """

    def find_methods_using_strings(
        self,
        strings: Sequence[str | bytes | bytearray],
        match_type: str = "contains",
        ignore_case: bool = False,
    ) -> list[MethodRef]:
        """Methods whose body loads all of these strings.

        Example::

            >>> [m.descriptor for m in dk.find_methods_using_strings(["accessibility"])][:1]
            ['Landroid/support/v14/preference/SwitchPreference;->syncViewIfAccessibilityEnabled(Landroid/view/View;)V']
        """

    def batch_find_classes_using_strings(
        self,
        query_map: Mapping[str, Sequence[str | bytes | bytearray]],
        match_type: str = "contains",
        ignore_case: bool = False,
    ) -> dict[str, list[ClassRef]]:
        """Many labelled queries in one pass — one shared index build, not N.

        Example::

            >>> r = dk.batch_find_classes_using_strings({"ui": ["window"]})
            >>> [c.descriptor for c in r["ui"]][:1]
            ['Landroid/support/v17/leanback/widget/GuidedActionsStylist;']
        """

    def batch_find_methods_using_strings(
        self,
        query_map: Mapping[str, Sequence[str | bytes | bytearray]],
        match_type: str = "contains",
        ignore_case: bool = False,
    ) -> dict[str, list[MethodRef]]:
        """Method-scoped ``batch_find_classes_using_strings``."""

    def find_methods_by_name(
        self,
        name: str,
        match_type: str = "contains",
        declaring_class: str = "",
        ignore_case: bool = False,
    ) -> list[MethodRef]:
        """Search method NAMES, optionally narrowed to a declaring class.

        Example::

            >>> [m.descriptor for m in dk.find_methods_by_name("getDisplaySize")][:1]
            ['Lcom/example/android/tvleanback/Utils;->getDisplaySize(Landroid/content/Context;)Landroid/graphics/Point;']
        """

    def find_fields_by_name(
        self,
        name: str,
        match_type: str = "contains",
        declaring_class: str = "",
        ignore_case: bool = False,
    ) -> list[FieldRef]:
        """Search field NAMES, optionally narrowed to a declaring class.

        The field arm of the L7 search family, completing the class/method/field
        symmetry the match types already named (dexllm#37: ``FieldRef`` was a
        public type nothing could produce).

        With a ``declaring_class`` only DECLARATIONS match — a field REFERENCE the
        dex groups under a subclass that merely inherits it is not a hit under that
        subclass (dexllm#45), so ``declaring_class`` means what it says. WITHOUT
        one, references are kept, which is what the name-search family does:
        ``find_methods_by_name`` is likewise declaration-only when scoped and not
        when unscoped. Use the unscoped form to find where an inherited field is
        touched under an app class.

        Neither form searches the WHOLE id table: an entry grouped under a class no
        loaded dex declares is never a hit (a pre-existing property of the
        ``find_*_by_name`` family), so a field spelled under a framework class is
        reachable only through ``list_fields()``.

        Example::

            >>> [f.descriptor for f in dk.find_fields_by_name("mTitle", match_type="equals")][:1]
            ['Landroid/support/app/recommendation/ContentRecommendation;->mTitle:Ljava/lang/String;']
        """

    def find_classes_by_annotation(
        self, annotation_class: str, match_type: str = "equals"
    ) -> list[ClassRef]:
        """Classes carrying the annotation.

        Example::

            >>> [c.descriptor
            ...  for c in dk.find_classes_by_annotation("Ljava/lang/Deprecated;")][:1]
            ['Landroid/support/v17/leanback/widget/OnChildSelectedListener;']
        """

    def find_methods_by_annotation(
        self, annotation_class: str, match_type: str = "equals"
    ) -> list[MethodRef]:
        """Method-scoped ``find_classes_by_annotation``."""

    def find_classes_by_super(
        self, super_class: str, match_type: str = "equals"
    ) -> list[ClassRef]:
        """Direct subclasses (one level — not a transitive hierarchy walk).

        Example::

            >>> [c.descriptor
            ...  for c in dk.find_classes_by_super("Landroid/app/Activity;")][:1]
            ['Lcom/example/android/tvleanback/mobile/MobileWelcomeActivity;']
        """

    def find_classes_implementing(
        self, interface_class: str, match_type: str = "equals"
    ) -> list[ClassRef]:
        """Classes declaring the interface.

        Example::

            >>> [c.descriptor
            ...  for c in dk.find_classes_implementing("Ljava/lang/Runnable;")][:1]
            ['Landroid/support/v14/preference/PreferenceFragment$2;']
        """

    def find_methods_using_int_literals(self, values: Sequence[int]) -> list[MethodRef]:
        """Methods whose body materializes all of these int constants.

        Useful for magic numbers (a port, an XOR key, a state code). ``[]`` when
        no method carries every value.
        """

    def find_methods_using_double_literals(
        self, values: Sequence[float]
    ) -> list[MethodRef]:
        """Float/double counterpart of ``find_methods_using_int_literals``.

        Example::

            >>> [m.descriptor
            ...  for m in dk.find_methods_using_double_literals([0.5])][:1]
            ['Landroid/support/graphics/drawable/AnimatorInflaterCompat;->setupObjectAnimator(Landroid/animation/ValueAnimator;Landroid/content/res/TypedArray;IFLorg/xmlpull/v1/XmlPullParser;)V']
        """
    # decompile / smali
    def decompile_method(self, method_descriptor: str) -> str:
        """Java text. The suffixed variants add structure to the SAME output.

        ``""`` for an external ref (no body in any loaded dex). Results are LRU
        cached; the GIL is released, so this parallelizes across threads. In
        batch code use ``dexllm.safe_decompile_method`` (a wall-clock deadline).

        Example::

            >>> print(dk.decompile_method(
            ...     "Lcom/example/android/tvleanback/Utils;"
            ...     "->convertDpToPixel(Landroid/content/Context;I)I"))
            public static int convertDpToPixel(android.content.Context p2, int p3)
            {
                return Math.round((((float) p3) * p2.getResources().getDisplayMetrics().density));
            }
        """

    def decompile_method_with_pc_map(
        self, method_descriptor: str
    ) -> _DecompiledMethodWithPc:
        r"""Decompile, and also map each source line to a dex byte offset (smali sync).

        ``line`` is a 1-based index into ``source.split("\\n")`` — ONLY ``\\n``
        delimits a line. Do NOT use ``splitlines()``: a string literal may carry a
        raw U+2028/U+2029/U+0085 that it splits on but the counter does not, which
        desyncs the map. Lines with no source op (braces, ``while(true)``) are
        omitted; condition / loop / switch header lines ARE mapped. Uncached.

        Example::

            >>> dk.decompile_method_with_pc_map(
            ...     "Lcom/example/android/tvleanback/Utils;"
            ...     "->convertDpToPixel(Landroid/content/Context;I)I")["pc_map"]
            [(4, 32)]
        """

    def decompile_class(self, class_descriptor: str) -> str:
        r"""Decompile a whole class: package, header, fields, method bodies.

        Example::

            >>> dk.decompile_class(
            ...     "Lcom/example/android/tvleanback/Utils;").split("\\n")[:2]
            ['package com.example.android.tvleanback;', 'public class Utils {']
        """

    def decompile_method_ast(
        self, method_descriptor: str, include_source: bool = True
    ) -> _MethodAstResult:
        """Signature parts + the structured AST (+ the same Java text by default).

        ``source`` is byte-identical to ``decompile_method``; pass
        ``include_source=False`` to skip that emit pass (~1.7x faster, ``source``
        comes back empty). ``access_flags`` is decoded modifier NAMES off the raw dex
        bits, so a Java ``synchronized`` method reads ``declared_synchronized``.

        Example::

            >>> a = dk.decompile_method_ast(
            ...     "Lcom/example/android/tvleanback/Utils;"
            ...     "->convertDpToPixel(Landroid/content/Context;I)I",
            ...     include_source=False)
            >>> a["return_type"], a["param_types"], a["access_flags"]
            ('I', ['Landroid/content/Context;', 'I'], ['public', 'static'])
            >>> sorted(a["ast"])
            ['body', 'comments', 'flags', 'params', 'ret', 'triple']
        """

    def render_method_smali(self, method_descriptor: str) -> str:
        """Disassembly, one instruction per line prefixed with its byte offset.

        Those ``0xNN:`` prefixes are the offsets ``decompile_method_with_pc_map``
        maps to.

        Example::

            >>> print(dk.render_method_smali(
            ...     "Lcom/example/android/tvleanback/Utils;"
            ...     "->convertDpToPixel(Landroid/content/Context;I)I"))
            Lcom/example/android/tvleanback/Utils;->convertDpToPixel(Landroid/content/Context;I)I
                .registers 4
                0x0: invoke-virtual {v2}, Landroid/content/Context;->getResources()Landroid/content/res/Resources;
                0x6: move-result-object v1
                ...
        """

    def render_class_smali(self, class_descriptor: str) -> str:
        """``render_method_smali`` for every declared method, under a class header.

        The ``.field`` lines are the class's own ``class_data`` entries, as
        baksmali emits them — an inherited field it only references gets no line
        (dexllm#45).
        """
    # permissions
    def permission_callers(self, app_only: bool = True) -> list[_PermissionCallers]:
        """Dangerous-permission APIs the app calls, grouped by permission.

        Joins AOSP's permission->API map against this APK's external method refs,
        then attaches the calling methods. ``app_only=True`` drops bundled
        framework/library callers (androidx, kotlin, play-services).

        Example::

            >>> [(g["perm"], g["protectionLevel"], len(g["apis"]))
            ...  for g in dk.permission_callers()][:2]
            [('android.permission.ACCESS_NETWORK_STATE', 'normal', 1),
             ('android.permission.INTERACT_ACROSS_USERS', 'signature', 4)]
        """
    # caches / lifecycle — actions are verb-first, read-only accessors are nouns
    def warm_analysis_caches(self) -> None:
        """Build the cross-ref indexes up front instead of on first query.

        Pays the one-time cost where you choose it — useful before timing a
        query, or before fanning out across threads.
        """

    def clear_decompiler_cache(self) -> None:
        """Drop every cached decompile result (frees memory; does not reset caps)."""

    def set_decompiler_cache_capacity(self, capacity: int) -> None:
        """LRU cap in methods. Default 4096; ``0`` means unbounded.

        Example: ``dk.set_decompiler_cache_capacity(0)`` before a whole-APK sweep.
        """

    def decompiler_cache_size(self) -> int:
        """Methods currently cached — grows with each distinct ``decompile_method``.

        Example::

            >>> dk.decompiler_cache_size()                    # fresh session
            0
            >>> _ = dk.decompile_method(some_descriptor)
            >>> dk.decompiler_cache_capacity(), dk.decompiler_cache_size()
            (4096, 1)
        """

    def decompiler_cache_capacity(self) -> int:
        """Return the configured cap (``0`` = unbounded)."""
