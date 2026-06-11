"""Attach Python-side convenience properties to native ref classes.

pybind11 doesn't let us add methods to a bound class after the module is
imported via normal `def` syntax, but we *can* monkey-patch its dict by
walking the type and installing attrs. This file does that for the L1 ref
types so callers get `.java_class`, `.parameters`, etc. on the same objects.
"""

from __future__ import annotations

from . import descriptors as _d
from ._dexkit_core import (
    ExternalFieldRef,
    ExternalMethodRef,
    ExternalTypeRef,
)


def _patch_method_ref() -> None:
    cls = ExternalMethodRef

    def java_class(self: ExternalMethodRef) -> str:
        return _d.descriptor_to_java(self.class_descriptor)

    def parameters(self: ExternalMethodRef) -> list:
        params, _ = _d.parse_proto(self.proto)
        return params

    def return_type(self: ExternalMethodRef) -> str:
        _, ret = _d.parse_proto(self.proto)
        return ret

    def java_signature(self: ExternalMethodRef) -> str:
        return _d.method_ref_java(self.class_descriptor, self.name, self.proto)

    def is_constructor(self: ExternalMethodRef) -> bool:
        return self.name == "<init>"

    def is_static_initializer(self: ExternalMethodRef) -> bool:
        return self.name == "<clinit>"

    # pybind11 types support setting attributes through __dict__ on the metaclass
    cls.java_class = property(java_class)
    cls.parameters = property(parameters)
    cls.return_type = property(return_type)
    cls.java_signature = property(java_signature)
    cls.is_constructor = property(is_constructor)
    cls.is_static_initializer = property(is_static_initializer)


def _patch_field_ref() -> None:
    cls = ExternalFieldRef
    cls.java_class = property(lambda s: _d.descriptor_to_java(s.class_descriptor))
    cls.java_type = property(lambda s: _d.descriptor_to_java(s.type))
    cls.signature = property(lambda s: f"{s.class_descriptor}->{s.name}:{s.type}")
    cls.java_signature = property(
        lambda s: f"{_d.descriptor_to_java(s.class_descriptor)}.{s.name} : "
        f"{_d.descriptor_to_java(s.type)}"
    )


def _patch_type_ref() -> None:
    cls = ExternalTypeRef
    cls.java_name = property(lambda s: _d.descriptor_to_java(s.descriptor))


_patch_method_ref()
_patch_field_ref()
_patch_type_ref()
