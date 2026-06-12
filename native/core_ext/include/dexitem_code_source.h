// dexitem_code_source.h — production IDexCodeSource that bridges to DexKit's
// DexItem(s). Lives in core_ext (DexKit-side) so dad_cpp stays
// dependency-free of DexKit Core internals.
//
// THREAD-SAFETY: read-only after DexKit warm-up (InitBaseCache). All
// returned string_views point into DexItem-owned tables (strings,
// type_names, MethodIds[].name_idx → strings, etc.) which live for the
// DexKit process lifetime.

#pragma once

#include <mutex>
#include <optional>
#include <string>
#include <unordered_map>

#include "dex_code_source.h"
#include "dexkit.h"

namespace dexkit::ext {

class DexItemCodeSource : public dexkit::dad::IDexCodeSource {
public:
    explicit DexItemCodeSource(dexkit::DexKit& core);

    // ─── IDexCodeSource overrides ─────────────────────────────────────────
    std::optional<MethodLocator>
    LocateMethod(std::string_view descriptor) override;
    std::vector<MethodLocator>
    LocateClassMethods(std::string_view class_descriptor) override;
    uint32_t           GetMethodAccessFlags(uint16_t, uint32_t) override;
    std::string_view   GetMethodClassName(uint16_t, uint32_t) override;
    std::string_view   GetMethodName(uint16_t, uint32_t) override;
    std::string        GetMethodProto(uint16_t, uint32_t) override;
    const dex::Code*   GetMethodCode(uint16_t, uint32_t) override;
    std::pair<const uint8_t*, const uint8_t*>
                       GetDexImageRange(uint16_t) override;
    std::string_view   GetString(uint16_t, uint32_t) override;
    std::string_view   GetTypeName(uint16_t, uint32_t) override;
    std::array<std::string_view, 3>
                       GetMethodRefTriple(uint16_t, uint32_t) override;
    std::array<std::string_view, 3>
                       GetFieldRefTriple(uint16_t, uint32_t) override;
    std::optional<ClassInfo>
                       GetClassInfo(std::string_view class_descriptor) override;
    FieldInfo          GetFieldInfo(uint16_t, uint32_t) override;

private:
    // Per-(dex_id, proto_idx) proto descriptor cache. Strings are owned by
    // the map and returned as string_views; pointer-stable (unordered_map
    // node pointers never move).
    std::string_view GetProtoCached(uint16_t dex_id, uint32_t proto_idx);

    dexkit::DexKit& core_;
    std::mutex proto_cache_mutex_;
    std::unordered_map<uint64_t, std::string> proto_cache_;
    static uint64_t ProtoKey(uint16_t dex_id, uint32_t proto_idx) {
        return (static_cast<uint64_t>(dex_id) << 32) | proto_idx;
    }
};

}  // namespace dexkit::ext
