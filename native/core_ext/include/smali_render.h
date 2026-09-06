// dexllm — baksmali-style smali rendering for a DexKit DexItem.
//
// This is NOT upstream DexKit code.  None of these functions exists upstream
// under any name; they were written for dexllm and lived inside
// `vendor/dexkit_core/Core/dexkit/dex_item.cpp` only because that is where they
// were first written.  dexllm#80 moved them here, which is the standing
// direction this repo records in docs/dexkit-vendor-divergences.md: **a dexllm
// analysis belongs outside `vendor/`**, where it can be tested, reviewed and
// rebased without colliding with upstream on every rebase.  dexllm#32 did the
// same for the 858-line L4 argument-origin analysis (see invoke_args.h).
//
// The move was possible because the whole input is PUBLIC: nine private members
// were read in the moved span and every one already had an accessor
// (`GetReader`, `GetTypeNames`, `GetStrings`, `GetMethodCode`,
// `GetTypeDefFlags`, `GetTypeDefIdx`, `GetClassFieldIds`, `GetClassMethodIds`,
// `GetFieldAccessFlagsDeclared`).  Those accessors are themselves dexllm
// extension hooks in the vendored header (divergence D8, treatment PERMANENT),
// so moving the renderer out SHRINKS D12 and leaves D8 exactly where it was.
//
// `core_ext` including DexKit headers is not a boundary violation: only
// `dad_cpp` is required to stay DexKit-free.  But this header is PUBLIC on
// `dexkit_ext`, which `dexkit_dad` links, so INCLUDING `dex_item.h` here would
// put a DexKit type in reach of every `dad_cpp` TU -- a review CONSTRUCTED
// exactly that (a dad_cpp probe naming `dexkit::DexItem` compiled, and the same
// probe fails at HEAD) while `scripts/check_dad_boundary.sh` still reported
// clean, because its FORBIDDEN pattern matches include TEXT and not the
// transitive route.  A FORWARD DECLARATION is all these signatures need, and it
// keeps the property `CMakeLists.txt` states about the PRIVATE include dir:
// no public header of `dexkit_ext` needs `${DEXKIT_CORE_ROOT}/Core/dexkit`.
// The .cpp includes the real header.

#pragma once

#include <cstdint>
#include <string>

namespace dexkit {
class DexItem;
}

namespace dexkit::ext {

// Baksmali-style text for ONE method body.  `indent` is prepended to every line
// after the signature.  Empty string for an out-of-range index; a method with no
// code item (abstract / native) renders its signature and `# (no code item)`.
[[nodiscard]] std::string RenderMethodSmali(const DexItem& item,
                                           uint32_t method_idx,
                                           const std::string& indent = "    ");

// Baksmali-style text for a whole class: `.class` / `.super` / `.source` /
// `.implements`, then the fields the class DECLARES (dexllm#45 — the grouped
// index is keyed on the whole `field_ids` table, so an inherited REFERENCE would
// otherwise be listed as a declaration), then every declared method's body.
// Empty string for a type this dex does not define.
[[nodiscard]] std::string RenderClassSmali(const DexItem& item,
                                           uint32_t type_idx);

}  // namespace dexkit::ext
