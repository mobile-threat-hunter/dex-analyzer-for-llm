"""Which `ResolvedArg` attribute each `kind` fills — ONE definition.

`tools.py` (the MCP compact view) and `sdk/adapter.py` (the typed model) each
carried a private copy of this map, so a rename on either side had to be applied
by hand in two places. dexllm#68 renamed two of its values
(`field_signature` / `method_signature` -> `field_descriptor` /
`method_descriptor`), which made "must change in lockstep" live rather than
theoretical — so they share this object instead, the `_callers.py` precedent from
dexllm#49. `test_the_arg_kind_attribute_map_has_one_definition` asserts object
IDENTITY, not equal contents: a correct COPY passes any behavioural test and
drifts on the first edit.

A kind absent from this map carries no value attribute at all (`ConstNull`,
`Unknown`).
"""

from __future__ import annotations

from types import MappingProxyType

#: ``ResolvedArg.kind`` -> the attribute holding that kind's value. Read-only, so
#: a consumer cannot mutate the map both layers share.
ARG_VALUE_ATTR_BY_KIND = MappingProxyType(
    {
        "ConstString": "string_value",
        "ConstInt": "int_value",
        "ConstWide": "int_value",
        "ConstClass": "class_descriptor",
        "NewInstance": "class_descriptor",
        "NewArray": "class_descriptor",
        "FieldRead": "field_descriptor",
        "MethodReturn": "method_descriptor",
        # The MCP view renders this one as `pN` rather than reading the raw int,
        # so it consults the map only after its own Parameter branch.
        "Parameter": "parameter_index",
    }
)
