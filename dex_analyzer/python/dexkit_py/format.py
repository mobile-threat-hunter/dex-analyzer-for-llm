"""Java-source-style pretty printers for ClassSummary and friends."""

from __future__ import annotations

from typing import Iterable, List

from . import descriptors as _d

# Dex/JVM access-flag bits, masked to what makes sense for classes/members.
_ACC_PUBLIC       = 0x0001
_ACC_PRIVATE      = 0x0002
_ACC_PROTECTED    = 0x0004
_ACC_STATIC       = 0x0008
_ACC_FINAL        = 0x0010
_ACC_SYNCHRONIZED = 0x0020
_ACC_VOLATILE     = 0x0040  # field
_ACC_BRIDGE       = 0x0040  # method (overloaded with VOLATILE)
_ACC_TRANSIENT    = 0x0080  # field
_ACC_VARARGS      = 0x0080  # method
_ACC_NATIVE       = 0x0100
_ACC_INTERFACE    = 0x0200
_ACC_ABSTRACT     = 0x0400
_ACC_STRICT       = 0x0800
_ACC_SYNTHETIC    = 0x1000
_ACC_ANNOTATION   = 0x2000
_ACC_ENUM         = 0x4000


def _class_modifiers(flags: int) -> str:
    parts = []
    if flags & _ACC_PUBLIC:    parts.append("public")
    if flags & _ACC_PRIVATE:   parts.append("private")
    if flags & _ACC_PROTECTED: parts.append("protected")
    if flags & _ACC_FINAL:     parts.append("final")
    if flags & _ACC_ABSTRACT:  parts.append("abstract")
    if flags & _ACC_SYNTHETIC: parts.append("/*synthetic*/")
    return " ".join(parts)


def _class_keyword(flags: int) -> str:
    if flags & _ACC_ANNOTATION: return "@interface"
    if flags & _ACC_ENUM:       return "enum"
    if flags & _ACC_INTERFACE:  return "interface"
    return "class"


def format_class_summary(summary, *, indent: str = "    ") -> str:
    """Render a ClassSummary as Java-source-style header + member listing.

    For external classes, modifiers are omitted (we only know what we observed).
    """
    if not summary.descriptor:
        return "// (empty summary — class not found)"

    java_cls = _d.descriptor_to_java(summary.descriptor)
    super_desc = summary.superclass_descriptor
    interfaces = list(summary.interface_descriptors)

    out: List[str] = []
    if summary.is_internal:
        modifiers = _class_modifiers(summary.access_flags)
        keyword = _class_keyword(summary.access_flags)
        head = f"{(modifiers + ' ') if modifiers else ''}{keyword} {java_cls}"
        if super_desc and super_desc not in ("Ljava/lang/Object;", ""):
            head += f" extends {_d.descriptor_to_java(super_desc)}"
        if interfaces:
            kind = "extends" if (summary.access_flags & _ACC_INTERFACE) else "implements"
            head += f" {kind} " + ", ".join(_d.descriptor_to_java(i) for i in interfaces)
        head += f"   // dex {summary.dex_id}"
        if summary.source_file:
            head += f", {summary.source_file}"
        out.append(head + " {")
    else:
        out.append(f"// EXTERNAL — referenced but not defined in any loaded dex")
        out.append(f"class {java_cls} {{")

    # Fields
    if summary.fields:
        out.append(f"{indent}// {len(summary.fields)} field(s)")
        for f in summary.fields:
            out.append(
                f"{indent}{_d.descriptor_to_java(f.type)} {f.name};"
            )
        out.append("")

    # Methods
    if summary.methods:
        out.append(f"{indent}// {len(summary.methods)} method(s)")
        for m in summary.methods:
            params, ret = _d.parse_proto(m.proto)
            args = ", ".join(_d.descriptor_to_java(p) for p in params)
            name = m.name
            # render <init>/<clinit> as constructor / static init
            if name == "<init>":
                line = f"{indent}{java_cls.split('.')[-1]}({args});"
            elif name == "<clinit>":
                line = f"{indent}static {{ /* <clinit> */ }}"
            else:
                line = f"{indent}{_d.descriptor_to_java(ret)} {name}({args});"
            out.append(line)

    out.append("}")
    return "\n".join(out)


def format_class(dk, descriptor: str, **kwargs) -> str:
    """Convenience wrapper: dk.get_class_summary(descriptor) + format."""
    return format_class_summary(dk.get_class_summary(descriptor), **kwargs)
