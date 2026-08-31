"""Permissive-TLS component detection — the trust decision, not the call that installs it.

An app that disables certificate or hostname validation does it by handing the
platform an OBJECT, and the interesting fact is what that object DECIDES. The
call that installs it is not a reliable handle: through OkHttp it is
``Lokhttp3/OkHttpClient$Builder;->hostnameVerifier(...)``, bundled app code with
no framework spelling, so no curated call-site key can name it (dexllm#53).
The object itself always has one — it must implement ``javax.net.ssl``'s own
interface — so this module names the INTERFACE and reads the BODY.

That makes the detector library-agnostic in the direction it does reach: OkHttp,
the legacy Apache stack, Volley, Retrofit and a raw ``HttpsURLConnection`` all
hand over an object typed by these interfaces, and nothing third-party is shipped
in a dataset that would then have to be versioned against a library the app
chooses. What it does NOT reach is a class that declares neither interface —
which is a real population, not a corner: see the bounds.

It answers a DIFFERENT, more specific question than a call-site key — **not a
strictly stronger one**, and an adversarial review refuted the stronger claim by
construction. :func:`dexllm.summarize_capabilities`' ``CUSTOM_TLS_TRUST``
(dexllm#52) reports that the app SUPPLIES its own trust decision;
``SSLContext#init`` is curated, so even the OkHttp TrustManager path is reported.
It cannot say the decision accepts everything, which is what this says. But a
trust manager written ``extends X509ExtendedTrustManager`` declares no interface
at all, so on that shape #52 answers and this does not — see the bounds. They are
read together, not one instead of the other.

## What is proven, and what a negative means

Two components, both platform interfaces:

* ``javax.net.ssl.HostnameVerifier`` — permissive iff ``verify`` is exactly a
  constant 1 loaded into a register and returned. Every hostname passes.
* ``javax.net.ssl.X509TrustManager`` — permissive iff ``checkServerTrusted`` is
  exactly ``return-void`` AND that method is the one the platform would call.
  The method signals rejection by THROWING, so a body that cannot throw accepts
  every chain.

**The second clause is not pedantry — without it the detector ACCUSES a correct
app.** ART's Conscrypt does not call the 2-argument ``checkServerTrusted``
directly: ``Platform.checkServerTrusted`` casts to ``X509ExtendedTrustManager``
when it can, and otherwise DUCK-TYPES its way to a 3-argument overload
(``…, Socket)`` or ``…, String)``), reaching the 2-argument one only when neither
exists. So a manager whose 2-argument body is empty while a 3-argument sibling
pins a hostname is CORRECT, and calling it permissive is a false accusation — an
adversarial review built exactly that from ordinary compiled Java. A trust-manager
row is therefore declined when the class declares ANY other ``checkServerTrusted``,
or when its superclass is not ``java.lang.Object`` (an overload may be INHERITED,
and ``Class#getMethod`` — what the duck-typing uses — searches the whole
hierarchy, which a per-class member list cannot see). Both directions are
conservative: they can only lose a finding.

The verifier half needs no such clause. ``HostnameVerifier`` declares one method,
nothing in the platform duck-types it, and an unrelated ``verify`` overload on the
same class is not reachable AS the verifier — so the asymmetry is the mechanism,
not an oversight.

Both predicates are whole-body EQUALITY against a two- or one-instruction shape,
read off ``render_method_smali`` — the bytecode, the fewest layers between the
claim and the dex. Anything else is ``not_proven``, which means **not proven
permissive**, never "proven safe": a verifier that logs and then returns true is
permissive and is reported ``not_proven``, because proving it needs real dataflow.
The verdict is a string rather than a bool for that reason — ``permissive=False``
reads as a clean bill of health, and this analysis cannot issue one (the
dexllm#41 rule that ignorance is representable). Every implementor is reported
whatever its verdict, so "this app carries a custom TLS trust component" stays
legible even where the body is beyond the predicate.

## Bounds, stated rather than discovered

* ``checkClientTrusted`` is deliberately NOT checked. An empty one is what a
  CLIENT is supposed to have — it authenticates nobody — so checking it would
  report every well-behaved app. Only the server-side decision is a finding.
* ``find_classes_implementing`` matches a class that DECLARES the interface, so a
  trust-all reached any other way is INVISIBLE, and two of those shapes are
  ordinary rather than exotic: a class ``extends
  javax.net.ssl.X509ExtendedTrustManager`` (the API-24+ form AOSP's own
  ``TrustManagerImpl`` / ``RootTrustManager`` use, and the one Conscrypt drives
  the extended overloads through) declares no interface at all; and an
  implementor of a SUB-interface (the legacy Apache ``X509HostnameVerifier``
  extends ``javax.net.ssl.HostnameVerifier``) declares the sub-interface, not
  this one. A subclass of an app's own permissive abstract base is the same bound
  one level down. All three are conservative — a missed finding, never a false
  one — and closing them is dexllm#78, which needs the 3-overload rule above
  rather than one more interface name.
* A class that is ITSELF an interface is skipped. A sub-interface DECLARES the
  platform one, so it would otherwise be reported as a component carrying
  ``not_proven`` / "the method has no instructions" — a row that reads as "we
  looked and found nothing" while standing in for the implementor that was never
  examined.
* A class is a dex fact. It is reported whether or not it is ever installed;
  ``constructed_in`` is what separates a live one from dead code, and an empty
  tuple is not proof of either (a verifier reached only through reflection has
  no constructor call site).
* A descriptor DECLARED in several loaded dexes yields one row, not one per
  declaration — an ordinary multidex app, and the norm for a packer session where
  the dump and the original both carry the class. The body read is the first-wins
  one every descriptor-keyed API resolves.
"""

from __future__ import annotations

import re
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from ._dexkit_core import DexKit

__all__ = [
    "NOT_PROVEN",
    "PERMISSIVE",
    "classify_tls_method",
    "detect_permissive_tls",
]

PERMISSIVE = "permissive"
NOT_PROVEN = "not_proven"

#: ``kind`` -> ``(interface descriptor, member, proto)``. Two static rows, so a
#: record type for them would be an abstraction over single-use data; the kind is
#: the key because it is what :func:`classify_tls_method` dispatches on.
#: ``tests/test_permissive_tls.py`` pins it as a LITERAL — a guard parametrised
#: over this table cannot catch an EDIT of it.
_COMPONENTS: dict[str, tuple[str, str, str]] = {
    "hostname_verifier": (
        "Ljavax/net/ssl/HostnameVerifier;",
        "verify",
        "(Ljava/lang/String;Ljavax/net/ssl/SSLSession;)Z",
    ),
    "trust_manager": (
        "Ljavax/net/ssl/X509TrustManager;",
        "checkServerTrusted",
        "([Ljava/security/cert/X509Certificate;Ljava/lang/String;)V",
    ),
}

# `render_method_smali` emits the descriptor, then `    .registers N`, then one
# `    0xNN: <mnemonic> <operands>` line per instruction — and NOTHING else (no
# try/catch markers, no labels), so an instruction list read off it is the whole
# body. A method with no code item emits `    # (no code item)` instead.
_INSN = re.compile(r"^\s+0x[0-9a-f]+: (.+)$")
_HEADER = re.compile(r"^\s+(\.registers \d+|# \(no code item\))$")

# The int 1 in a register. `const/high16` cannot encode it (its operand is the
# HIGH half), and the three that can all render the literal in decimal —
# `dex_item.cpp` formats k11n / k21s / k31i with `<< "#" << (int32_t)`.
_CONST_ONE = re.compile(r"^const(?:/4|/16)? (v\d+), #1$")
_RETURN = re.compile(r"^return (v\d+)$")


def _body_instructions(smali: str) -> list[str] | None:
    """Return the instruction texts of a ``render_method_smali`` body.

    ``[]`` for a body with no instructions — an abstract or native method, and
    also a method the class does not declare, where ``render_method_smali``
    answers with the empty string.

    ``None`` when a line is neither a known header nor an instruction — i.e. the
    rendering is not the one this module was written against. The caller treats
    that as ``not_proven``, so an unrecognised format can only lose a finding,
    never invent one. ``tests/test_permissive_tls.py`` pins the rendering as a
    literal so a format change fails loudly instead of silently emptying every
    verdict.
    """
    out: list[str] = []
    for line in smali.split("\n")[1:]:  # line 0 is the method descriptor
        if not line.strip():
            continue
        if _HEADER.match(line):
            continue
        m = _INSN.match(line)
        if m is None:
            return None
        out.append(m.group(1).strip())
    return out


def classify_tls_method(kind: str, smali: str) -> tuple[str, str]:
    """Return ``(verdict, reason)`` for one component method's rendered body.

    Pure — takes the smali TEXT, not a DexKit — so the predicate that decides
    whether an app disables TLS validation is unit-testable on crafted bodies,
    including the ones no dex in reach carries. (The
    :func:`dexllm.providers.match_content_uris` precedent.)

    Args:
        kind: ``"hostname_verifier"`` or ``"trust_manager"``.
        smali: the output of ``dk.render_method_smali`` for that component's
            method.

    Returns:
        ``("permissive", reason)`` only when the body is EXACTLY the accept-all
        shape; ``("not_proven", reason)`` otherwise — which means the analysis
        could not prove permissiveness, not that the component validates.

    Raises:
        ValueError: for a ``kind`` this module does not check. A silent
            ``not_proven`` there would read as "this app does not do this".
    """
    if kind not in _COMPONENTS:
        raise ValueError(f"unknown TLS component kind: {kind!r}")

    body = _body_instructions(smali)
    if body is None:
        return NOT_PROVEN, "body could not be read as instructions"
    if not body:
        return NOT_PROVEN, "the method has no instructions"

    if kind == "trust_manager":
        if body == ["return-void"]:
            return PERMISSIVE, "checkServerTrusted body is empty, so it cannot throw"
        return NOT_PROVEN, f"checkServerTrusted body is {len(body)} instructions"

    if len(body) == 2:
        const, ret = _CONST_ONE.match(body[0]), _RETURN.match(body[1])
        if const and ret and const.group(1) == ret.group(1):
            return PERMISSIVE, "verify returns the constant true"
    return NOT_PROVEN, f"verify body is {len(body)} instructions"


def detect_permissive_tls(
    dk: DexKit, *, with_xref: bool = True
) -> list[dict[str, Any]]:
    """Find TLS trust components the app declares, and say which accept everything.

    Args:
        dk: a loaded ``dexllm.DexKit`` instance.
        with_xref: fill ``constructed_in`` — the methods calling one of the
            class's constructors, i.e. where the component is created. One search
            per constructor; the population is classes implementing two
            interfaces, so it is small and takes no cap.

    Returns:
        One row per implementing class — DEDUPLICATED by descriptor, since a
        class may be declared in several loaded dexes and the body read is the
        first-wins one every descriptor-keyed API resolves — sorted by
        ``(class_descriptor, method_descriptor)``::

            {"class_descriptor": "LFoo;",
             "interface_descriptor": "Ljavax/net/ssl/HostnameVerifier;",
             "kind": "hostname_verifier",
             "method_descriptor": "LFoo;->verify(...)Z",
             "verdict": "permissive",       # or "not_proven"
             "reason": "verify returns the constant true",
             "constructed_in": ["LBar;->build()V"]}

        ``verdict == "not_proven"`` is the absence of a proof, not a clean bill
        of health — see the module docstring.
    """
    rows: list[dict[str, Any]] = []
    for kind, (interface, member, proto) in _COMPONENTS.items():
        # A descriptor can be DECLARED in more than one loaded dex — an ordinary
        # multidex app, and the norm for a packer session, where the dump and the
        # original both carry it. `find_classes_implementing` reports one hit per
        # DECLARATION, while everything downstream is descriptor-keyed and
        # resolves first-wins, so without this the report would carry N identical
        # rows for one component and the MCP `count` would say N.
        seen: set[str] = set()
        for cls in dk.find_classes_implementing(interface):
            cd = cls.descriptor
            if cd in seen:
                continue
            seen.add(cd)
            md = f"{cd}->{member}{proto}"
            blocked = _class_level_block(dk, kind, cd, member)
            if blocked == _NOT_A_COMPONENT:
                continue
            verdict, reason = classify_tls_method(kind, dk.render_method_smali(md))
            if blocked and verdict == PERMISSIVE:
                verdict, reason = NOT_PROVEN, blocked
            rows.append(
                {
                    "class_descriptor": cd,
                    "interface_descriptor": interface,
                    "kind": kind,
                    "method_descriptor": md,
                    "verdict": verdict,
                    "reason": reason,
                    "constructed_in": _constructed_in(dk, cd) if with_xref else [],
                }
            )
    rows.sort(key=lambda r: (r["class_descriptor"], r["method_descriptor"]))
    return rows


#: Sentinel: this class is not a component at all and yields no row.
_NOT_A_COMPONENT = "\0skip"

_OBJECT = "Ljava/lang/Object;"
_TM_PROTO = _COMPONENTS["trust_manager"][2]
_ACC_INTERFACE = 0x200


def _class_level_block(
    dk: DexKit, kind: str, class_descriptor: str, member: str
) -> str | None:
    """Why this class cannot be PROVEN permissive from its method body alone.

    ``None`` to proceed, a reason string to downgrade a ``permissive`` verdict, or
    :data:`_NOT_A_COMPONENT` to emit no row. Separate from
    :func:`classify_tls_method` so that predicate stays PURE — the body rule is
    about instructions, these are facts about the CLASS.

    Two things it decides:

    * an INTERFACE declaring the platform interface is a type, not a component
      (the legacy Apache ``X509HostnameVerifier`` is one), and reporting it puts
      a ``not_proven`` row where the real implementor's answer belongs;
    * a trust manager whose 2-argument ``checkServerTrusted`` is not the method
      the platform calls. Conscrypt's ``Platform.checkServerTrusted`` prefers an
      ``X509ExtendedTrustManager`` cast and then DUCK-TYPES a 3-argument
      overload, so an empty 2-argument body beside a pinning 3-argument sibling
      is a CORRECT trust manager. The declared-sibling test sees the common
      shape; the superclass test covers the INHERITED one, which a per-class
      member list structurally cannot (``Class#getMethod`` searches the whole
      hierarchy). Both only ever lose a finding.
    """
    info = dk.get_class_summary(class_descriptor)
    flags = getattr(info, "access_flags", None)
    if flags is not None and flags & _ACC_INTERFACE:
        return _NOT_A_COMPONENT
    if kind != "trust_manager":
        return None
    others = [
        m
        for m in dk.list_class_methods(class_descriptor)
        if m.split("->", 1)[-1].startswith(member + "(")
        and f"{member}{_TM_PROTO}" not in m
    ]
    if others:
        return (
            "checkServerTrusted has another overload, which Conscrypt "
            "duck-types in preference to this one"
        )
    sup = getattr(info, "superclass_descriptor", _OBJECT)
    if sup and sup != _OBJECT:
        return (
            f"the class extends {sup}, which may declare the overload "
            f"Conscrypt duck-types in preference to this one"
        )
    return None


def _constructed_in(dk: DexKit, class_descriptor: str) -> list[str]:
    """Methods calling one of ``class_descriptor``'s constructors, deduplicated."""
    seen: list[str] = []
    for m in dk.list_class_methods(class_descriptor):
        if "-><init>(" not in m:
            continue
        for site in dk.find_call_sites_to(m):
            if site.caller_descriptor not in seen:
                seen.append(site.caller_descriptor)
    return sorted(seen)
