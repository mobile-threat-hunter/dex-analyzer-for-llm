"""Component-subclass detection — every class that CAN be used as a component.

An Android component is a class the FRAMEWORK instantiates by name:
``AppComponentFactory`` does ``(Activity) cl.loadClass(name).newInstance()``
(``AppComponentFactory.java:97``, and likewise for Service / BroadcastReceiver /
ContentProvider / Application), ``ActivityThread`` does it for a BackupAgent
and an Instrumentation, ``LoadedApk`` for the AppComponentFactory itself, and
``AppZygoteInit`` checks ``ZygotePreload.class.isAssignableFrom`` — nine base
types in all, eight classes and one interface. So "can this class be used as a
component" is a question about the class's INHERITANCE CHAIN, and this module
answers it by walking that chain for every class the loaded dexes declare.

**The question is deliberately the SUPERSET, not the manifest.** The manifest
says which classes the app REGISTERS; it does not say which classes COULD be
registered, and the two differ in both directions. Measured on the bundled
corpus (22 loadable APKs, 21 with a manifest; every component-naming attribute
on the seven component elements counted as a declaration): the walk yields
**279** rows, the manifests declare **98** of them, and the other 181 are not
noise — abstract classes (58, chain nodes) — and, a separate statistic over
ALL rows, 53 are an intermediate of another row (23 of them abstract), library classes bundled but not registered (90 — `FileProvider`
in nine APKs, where the SAME bytes are a declared component in a tenth, so no
property of the class decides it), and app classes constructed in code (33,
every one an anonymous ``BroadcastReceiver`` handed to ``registerReceiver`` — a
LIVE component the manifest never names). Which of those is interesting is the
consumer's call; this module reports all of them and annotates each. Six root
kinds occur on the corpus (activity 119, receiver 75, service 63, provider 11,
application 4, app_component_factory 4).

**The framework half of the chain is never in the dex, so a table supplies it.**
A dex walk from ``Landroid/app/Service;`` finds only classes whose parent is IN
a loaded dex. An app class ``extends android.service.media.MediaBrowserService``
names a parent no dex declares, and the walk stops there — measured, 25 such
classes across the corpus (``MediaBrowserService`` 6, ``PreferenceActivity`` 5,
``ListActivity`` 4, ``IntentService`` 4, …), 0 of them reachable from the five
class roots a naive walk would start at, and a name heuristic cannot stand in
(``AccessibilityNodeProvider``, ``ViewOutlineProvider``, ``VolumeProvider`` and
``ResultReceiver`` are direct parents on the same corpus and NOT components). The
bundled ``component_bases.json`` is aosp_data_set's layer 13 (issue #7): the
transitive ``extends`` closure of the nine roots across the public + system +
module-lib SDK (152 classes), with the manifest-attribute → base-type table and
the full SDK class list. androidx intermediates (``AppCompatActivity``,
``JobIntentService``, ``GlanceAppWidgetReceiver``) need no table: they are
bundled into the dex, and their chains end at a framework class.

## What a row says

One row per class DECLARED in a loaded dex whose superclass chain, or declared
interface chain, reaches a root:

* ``chain_descriptors`` — the class itself, then every superclass up to the
  root, framework intermediates included (``[LMyTile;,
  Landroid/service/quicksettings/TileService;, Landroid/app/Service;]``). For an
  interface root it is the class, then the declared interface chain. A row
  carries ONE root: the superclass chain is consulted first, and the interface
  root (``ZygotePreload``) only when the superclass chain reaches no class root
  — so ``class C extends Activity implements ZygotePreload`` is an ``activity``
  row, which is the kind that decides how the framework instantiates it.
* ``resolution`` — ``"resolved"`` when the chain reaches a root, and
  ``"unresolved"`` when it leaves the loaded dexes at a parent that is in NO
  loaded dex AND not in the SDK catalog: a hidden-API base, a ``uses-library``
  class, a split-APK or packer-dump remnant. Such a class is reported — its
  parent may well be a component base — with ``root_kind == ""`` and the
  unknown parent as the chain's last element. A parent that IS a known SDK
  class but not a component base (``android.view.View``, ``java.lang.Thread``)
  ends the walk with no row: that class is resolved NOT to be a candidate.
  The distinction needs the SDK list; without it the two cases look identical.
* ``is_abstract`` — an abstract class cannot be instantiated, so it is a chain
  NODE rather than a component; reported so the chain is visible.
* ``is_instantiable`` — whether the framework's ``newInstance()`` would
  succeed, which is ART's own predicate (``java_lang_Class.cc``
  ``Class_newInstance``): not abstract, the CLASS public (the caller is
  ``android.app.AppComponentFactory``, another package, so a package-private
  class is refused with ``IllegalAccessException`` even with a public
  constructor — ``:890``), and a public zero-argument constructor (``:900``,
  ``:925``). A class failing it cannot be a MANIFEST component; it can still be
  constructed in code, and the anonymous receivers are exactly that shape.
* ``constructed_in`` (``with_xref``) — the methods that call one of the class's
  constructors OTHER than a subclass's own ``<init>`` chaining ``super()`` and
  the class's OWN ``<init>`` delegating ``this(...)``. A non-empty list is the
  dynamic-registration shape; a class whose only constructor callers are its
  subclasses is a chain node. Stated bound: the exclusion is by the CALLER's
  shape, not by reading its body, so a subclass constructor that also does
  ``new Base()`` hides that construction, and a factory method on the class
  itself (``static Base create() { return new Base(); }``) is kept.

Nothing here reads ``AndroidManifest.xml``, BY DESIGN: dexllm extracts what
the dex can say, and the manifest join — which of these candidates the app
REGISTERS — is the job of a separate manifest tool (axmllm) that consumes
this list. That is why the rows are the superset and are annotated rather
than filtered: a downstream selector needs every candidate, not dexllm's
guess at which ones matter. dexllm#54 was closed on that decision.

## What it does not reach, stated rather than discovered

* A component the manifest names DIRECTLY with no app subclass —
  ``<activity android:name="android.app.AliasActivity">`` with
  ``hasCode="false"``, AOSP's own ``development/samples/AliasActivity`` — has no
  class_def anywhere, so no dex walk can see it. That is a manifest fact.
* A descriptor declared in several loaded dexes (multidex, or a packer session
  holding the dump and the original) is reported ONCE, from its first-wins
  declaration, exactly as every descriptor-keyed API resolves it.
* A class the TABLE knows is judged by the table even when a loaded dex also
  declares it (an app bundling its own copy of a framework class): the walk
  consults ``bases`` before the dex, so the framework chain is the one
  reported. 0 corpus incidence; stated as the decision it is.
* ``is_instantiable`` is conservative for a class in package ``android.app``:
  ART's ``CanAccess`` would let the framework caller reach a package-private
  class there, and this says no. Crafted-only in an app dex; a packer dump can
  ship ``android.*`` classes.
* ``depth`` in the bundled table counts API-VISIBLE classes only: two framework
  chains pass through the hidden ``android.window.WindowProviderService``, so
  ``InputMethodService``'s chain is one shorter than the bytecode's.
"""

from __future__ import annotations

import json
from functools import lru_cache
from pathlib import Path
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from ._dexkit_core import DexKit

__all__ = [
    "RESOLVED",
    "UNRESOLVED",
    "find_component_subclasses",
    "interface_root_paths",
    "load_component_bases",
]

RESOLVED = "resolved"
UNRESOLVED = "unresolved"

_BUNDLED = Path(__file__).parent / "data" / "component_bases.json"
_ACC_PUBLIC = 0x1
_ACC_INTERFACE = 0x200
_ACC_ABSTRACT = 0x400


@lru_cache(maxsize=1)
def load_component_bases() -> dict[str, Any]:
    """Return the bundled component-base table (``component_bases.json``).

    Mechanical AOSP extraction (aosp_data_set layer 13), so like ``perm_api.json``
    it is NOT in the ``data_dir`` override channel — a fresher snapshot is a
    re-run of ``scripts/gen_component_data.py``. Keys: ``roots`` (descriptor →
    ``root_kind`` / ``kind`` / ``manifest_attrs``), ``bases`` (every class in the
    closure, roots at depth 0, descriptor → ``root`` / ``root_kind`` / ``depth`` /
    ``direct_super`` / ``abstract`` / ``api_surface`` / ``has_public_noarg_ctor``),
    ``manifest_attrs`` and ``sdk_classes``.
    """
    data = json.loads(_BUNDLED.read_text())
    for key in ("roots", "bases", "sdk_classes", "manifest_attrs"):
        if key not in data:
            raise ValueError(f"{_BUNDLED} is missing {key!r}")
    data["_sdk_set"] = frozenset(data["sdk_classes"])
    return data


def _framework_tail(bases: dict[str, dict], first: str) -> list[str]:
    """``first`` and every table ancestor up to its root, in order."""
    tail = [first]
    cur = first
    while bases[cur]["depth"] > 0:
        cur = bases[cur]["direct_super"]
        tail.append(cur)
    return tail


def interface_root_paths(
    interfaces_of: dict[str, list[str]], iface_roots: frozenset[str] | set[str]
) -> dict[str, list[str]]:
    """Return one path ``[iface, ..., root]`` per declared type reaching an interface root.

    Keyed by the type; the type itself is excluded from its path. A breadth-first
    walk FROM the roots over the reversed ``implements`` edges, with a parent
    pointer per type, rather than a memoised DFS from each type — and that is
    the point twice over. A DFS that memoises ``None`` for a type it abandoned
    because the path led back into its own ancestor stack records a wrong
    answer: ``X implements Z``, ``Z implements X, R`` — entering at ``Z`` reaches
    ``R`` and leaves ``X`` memoised as unreachable, which it is not. And a
    per-type fixed point that MATERIALISES every path is quadratic in time and
    memory on a long interface chain (measured: 8,000 types → 7 s / 257 MB),
    which the gate does not refuse. The reverse BFS is O(types + edges) and
    holds one pointer per type; a path is built on demand from the pointers.

    Interface cycles are invalid Java and ART refuses them at link time, but
    the structural verifier this project ports does not, so a crafted dex can
    carry one and the answer must not depend on the order the walk happened to
    visit it in. Pure — takes the declared ``implements`` map, so the cycle
    case is testable without a dex.

    The path recorded is a SHORTEST one (fewest interfaces between the type and
    a root); among equally short routes the one reached first wins, which is
    decided by the roots' sorted order and then by the order the types were
    enumerated in. Deterministic for one input; a type with two routes of
    different length takes the shorter whatever its declaration order says.
    """
    rev: dict[str, list[str]] = {}
    for desc, ifaces in interfaces_of.items():
        for i in ifaces:
            rev.setdefault(i, []).append(desc)
    parent: dict[str, str] = {}
    frontier = sorted(r for r in iface_roots if r in rev)
    while frontier:
        nxt: list[str] = []
        for i in frontier:
            for desc in rev.get(i, ()):
                if desc in parent or desc in iface_roots:
                    continue
                parent[desc] = i
                nxt.append(desc)
        frontier = nxt
    out: dict[str, list[str]] = {}
    for desc in parent:
        path = []
        cur = desc
        while cur in parent:
            cur = parent[cur]
            path.append(cur)
        out[desc] = path
    return out


def find_component_subclasses(
    dk: DexKit, *, with_xref: bool = True
) -> list[dict[str, Any]]:
    """Find every declared class whose inheritance chain reaches a component base.

    Args:
        dk: a loaded ``dexllm.DexKit`` instance.
        with_xref: fill ``constructed_in`` — the methods calling one of the
            class's constructors, EXCLUDING a subclass's own ``<init>`` (that is
            ``super()``, a chain edge, not a construction). One call-site query
            per constructor of each candidate.

    Returns:
        One row per candidate class, DEDUPLICATED by descriptor (first-wins
        across loaded dexes) and sorted by descriptor::

            {"descriptor": "Lcom/app/MyTile;",
             "dex_id": 0,
             "root_descriptor": "Landroid/app/Service;",   # "" when unresolved
             "root_kind": "service",                       # "" when unresolved
             "chain_descriptors": ["Lcom/app/MyTile;",
                                   "Landroid/service/quicksettings/TileService;",
                                   "Landroid/app/Service;"],
             "resolution": "resolved",                     # or "unresolved"
             "is_abstract": False,
             "is_instantiable": True,
             "constructed_in": []}

        A row is NOT a claim that the class is registered anywhere — see the
        module docstring for what the superset contains and why it is the
        deliverable.
    """
    table = load_component_bases()
    bases: dict[str, dict] = table["bases"]
    roots: dict[str, dict] = table["roots"]
    sdk: frozenset[str] = table["_sdk_set"]
    iface_roots = {d for d, r in roots.items() if r["kind"] == "interface"}

    # First-wins by descriptor: list_class_headers() is one row per DECLARATION.
    hdr: dict[str, Any] = {}
    for h in dk.list_class_headers():
        hdr.setdefault(h.descriptor, h)

    # --- interface edge: a declared-interface chain reaching an interface root,
    #     as a fixed point over every declared type (cycle-safe, order-free)
    iface_paths = interface_root_paths(
        {d: list(h.interface_descriptors) for d, h in hdr.items()}, iface_roots
    )

    # --- superclass edge, memoised: a chain's tail is shared by every subclass.
    #     The memo is path-independent: single inheritance gives each class ONE
    #     parent, so its answer cannot depend on where the walk entered — except
    #     inside a superclass cycle, where every member is "none" unless its own
    #     interfaces resolve it (the fallback below, path-independent itself).
    #     ("none", ) | ("resolved", root, kind, tail) | ("unresolved", tail)
    memo: dict[str, tuple] = {}

    def classify(desc: str, stack: frozenset[str]) -> tuple:
        if desc in memo:
            return memo[desc]
        h = hdr[desc]
        out: tuple = ("none",)
        p = h.superclass_descriptor
        if not p:
            out = ("none",)  # kNoIndex: java.lang.Object's own shape
        elif p in bases:
            b = bases[p]
            out = ("resolved", b["root"], b["root_kind"], _framework_tail(bases, p))
        elif p in hdr:
            if p in stack:
                out = ("none",)  # a superclass cycle: malformed, not a candidate
            else:
                r = classify(p, stack | {p})
                if r[0] == "resolved":
                    out = ("resolved", r[1], r[2], [p] + r[3])
                elif r[0] == "unresolved":
                    out = ("unresolved", [p] + r[1])
        elif p in sdk:
            # a known SDK class that is not a component base — including
            # java.lang.Object itself, which the catalog carries, so a plain
            # `extends Object` ends here (the guard file pins Object's presence)
            out = ("none",)
        else:
            out = ("unresolved", [p])
        # The interface root is a FALLBACK: a class root says how the framework
        # instantiates the class, so it wins when both hold (documented above).
        if out[0] != "resolved":
            ip = iface_paths.get(desc)
            if ip is not None:
                root = ip[-1]
                out = ("resolved", root, roots[root]["root_kind"], ip)
        memo[desc] = out
        return out

    rows: list[dict[str, Any]] = []
    for desc in sorted(hdr):
        h = hdr[desc]
        if h.access_flags & _ACC_INTERFACE:
            continue  # an interface is a type, never a component
        r = classify(desc, frozenset({desc}))
        if r[0] == "none":
            continue
        if r[0] == "resolved":
            root_desc, root_kind, tail = r[1], r[2], r[3]
            resolution = RESOLVED
        else:
            root_desc, root_kind, tail = "", "", r[1]
            resolution = UNRESOLVED
        rows.append(
            {
                "descriptor": desc,
                "dex_id": int(h.dex_id),
                "root_descriptor": root_desc,
                "root_kind": root_kind,
                "chain_descriptors": [desc] + list(tail),
                "resolution": resolution,
                "is_abstract": bool(h.access_flags & _ACC_ABSTRACT),
                "is_instantiable": _is_instantiable(dk, h),
                "constructed_in": _constructed_in(dk, hdr, desc) if with_xref else [],
            }
        )
    return rows


def _is_instantiable(dk: DexKit, h: Any) -> bool:
    """Whether the framework's ``newInstance()`` would succeed on this class.

    ART's ``Class_newInstance`` (``art/runtime/native/java_lang_Class.cc``) refuses
    an interface, an abstract class, a class the CALLER cannot access — the
    caller is ``android.app.AppComponentFactory``, so that means a non-public
    class (``:890``) — and a class with no public zero-argument constructor
    (``:900`` / ``:925``). All four halves, or the field is a half-answer.
    """
    flags = h.access_flags
    if flags & (_ACC_ABSTRACT | _ACC_INTERFACE) or not flags & _ACC_PUBLIC:
        return False
    summary = dk.get_class_summary(h.descriptor)
    for m in summary.methods:
        if m.name != "<init>" or not m.descriptor.endswith("-><init>()V"):
            continue
        mf = m.access_flags
        if mf is not None and mf & _ACC_PUBLIC:
            return True
    return False


def _constructed_in(dk: DexKit, hdr: dict[str, Any], desc: str) -> list[str]:
    """Methods calling a constructor of ``desc`` that are not a subclass's ``super()``.

    A ``<init>`` of a class whose declared superclass is ``desc`` reaches
    ``desc``'s constructor through ``invoke-direct`` exactly like ``new`` does,
    and so does ``desc``'s own ``<init>`` delegating ``this(...)``; the call-site
    index cannot tell them apart, the caller's identity can — by its SHAPE, not
    its body, which is the stated bound in the module docstring.
    """
    seen: list[str] = []
    for m in dk.list_class_methods(desc):
        if "-><init>(" not in m:
            continue
        for site in dk.find_call_sites_to(m):
            caller = site.caller_descriptor
            caller_cls, _, member = caller.partition("->")
            if member.startswith("<init>("):
                if caller_cls == desc:
                    continue  # this(...) delegation between the class's own ctors
                ch = hdr.get(caller_cls)
                if ch is not None and ch.superclass_descriptor == desc:
                    continue  # super() from a subclass: a chain edge
            if caller not in seen:
                seen.append(caller)
    return sorted(seen)
