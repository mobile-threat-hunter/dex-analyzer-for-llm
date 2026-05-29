// util.h — C++ port of androguard DAD util.py
// DAD: androguard/decompiler/util.py
//
// This module corresponds to androguard's DAD <util.py>. Every function below
// carries a `// DAD: util.py:<lineno> <concept>` comment in the .cpp.
//
// PORT STATUS:
//   Ported (self-contained):
//     - TYPE_DESCRIPTOR / ACCESS_FLAGS_CLASSES / ACCESS_FLAGS_FIELDS /
//       ACCESS_FLAGS_METHODS / ACCESS_ORDER / TYPE_LEN  (data tables)
//     - get_access_class / get_access_method / get_access_field
//     - get_type_size
//     - get_type
//     - get_params_type
//   Ported (graph-dependent):
//     - build_path     — needs graph.h (Graph + Node)            [util_graph.h]
//     - common_dom     — needs node.h (Node) + idom map type     [util_graph.h]
//   Deferred:
//     - merge_inner    — needs class object with add_subclass()
//     - create_png     — graphviz output (likely skipped in C++ port entirely)

#pragma once

#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

namespace dexkit::dad {

// Lookup tables — externalised constants ported from util.py module-level dicts.
// DAD: util.py:30 TYPE_DESCRIPTOR — Dalvik primitive descriptor → Java type name.
std::string_view LookupTypeDescriptor(char primitive) noexcept;

// DAD: util.py:104 TYPE_LEN — register slot count for wide types (J/D = 2).
unsigned LookupTypeLen(char primitive) noexcept;

// DAD: util.py:110 get_access_class — class access-flag bits → ordered keyword list.
std::vector<std::string> GetAccessClass(uint32_t access);

// DAD: util.py:118 get_access_method — method access-flag bits → ordered keyword list.
std::vector<std::string> GetAccessMethod(uint32_t access);

// DAD: util.py:126 get_access_field — field access-flag bits → ordered keyword list.
std::vector<std::string> GetAccessField(uint32_t access);

// DAD: util.py:198 get_type_size — register slot count for a type descriptor (J/D = 2 else 1).
unsigned GetTypeSize(std::string_view param) noexcept;

// DAD: util.py:205 get_type — Dalvik type descriptor → human Java type string.
//
// Production behavior: strips the "java/lang/" prefix properly (real prefix
// strip, not Python char-set strip). So both `Ljava/lang/Override;` → "Override"
// and `Ljava/lang/annotation/Foo;` → "annotation.Foo".
//
// DAD upstream has a bug here: `atype[1:-1].lstrip('java/lang/')` is a
// char-set strip, mangling `Ljava/lang/annotation/Foo;` into "otation.Foo".
// The bug-compatible variant lives in `GetTypeDADFaithful` and is used by
// parity tests only.
//
// `size` is used only when atype begins with '[' (array). Pass UINT32_MAX
// to defer to the default `T[]` rendering; any other value emits `T[N]`.
std::string GetType(std::string_view atype, uint32_t size = UINT32_MAX);

// DAD-faithful variant of GetType — preserves the `lstrip('java/lang/')`
// char-set quirk for byte-identical comparison against androguard DAD output.
// Production code MUST NOT call this; use `GetType` instead. Parity tests
// call this to verify our port still matches DAD's exact (buggy) output.
std::string GetTypeDADFaithful(std::string_view atype, uint32_t size = UINT32_MAX);

// DAD: util.py:227 get_params_type — method descriptor → parameter type list.
//
// QUIRK (faithful to DAD): the original `descriptor.split(')')[0][1:].split()`
// uses whitespace-split on a parameter chunk that contains no whitespace,
// returning the entire chunk as a single element rather than parsing
// individual type descriptors. We replicate this behaviour for IR-building
// code paths that need DAD parity (invoke handlers etc.).
std::vector<std::string> GetParamsType(std::string_view descriptor);

// Non-DAD: proper Dalvik descriptor parser. Splits "(IL.../X;[I)V" into
// ["I", "L.../X;", "[I"]. Used by Writer for method signature emission so
// multi-arg methods produce correct Java output (DAD's quirky version above
// would emit them as one concatenated parameter).
std::vector<std::string> ParseParamsType(std::string_view proto);

}  // namespace dexkit::dad
