// mock_code_source.h — test-only IDexCodeSource implementation.
//
// Used by builder parity tests to feed hand-crafted dex::Code without
// needing a real APK. Test fixtures construct fake `dex::Code` over a byte
// buffer and register canned metadata. All string_views returned point into
// MockCodeSource-owned storage (deque<string>) which is pointer-stable.

#pragma once

#include <array>
#include <cstdint>
#include <cstring>
#include <deque>
#include <memory>
#include <string>
#include <string_view>
#include <unordered_map>
#include <vector>

#include "dex_code_source.h"
#include "slicer/dex_format.h"

namespace dexkit::dad::testing {

// Fixed-layout fake `dex::Code` over a flat byte buffer. Owns the buffer.
class FakeCodeItem {
public:
    // Build with explicit insns code-units. Optional try_blocks + handler bytes.
    static std::unique_ptr<FakeCodeItem> Make(
        uint16_t registers_size, uint16_t ins_size, uint16_t outs_size,
        const std::vector<dex::u2>& insns,
        const std::vector<dex::TryBlock>& tries = {},
        const std::vector<uint8_t>& handlers = {});

    const dex::Code* code() const {
        return reinterpret_cast<const dex::Code*>(buffer_.data());
    }

private:
    FakeCodeItem() = default;
    std::vector<uint8_t> buffer_;   // owns the full Code layout
};

class MockCodeSource : public IDexCodeSource {
public:
    // ─── Registration API (called by test setup) ─────────────────────────
    void RegisterMethod(uint16_t dex_id, uint32_t method_idx,
                        uint32_t access_flags,
                        std::string cls_name,
                        std::string name,
                        std::string proto,
                        std::unique_ptr<FakeCodeItem> code = nullptr);

    // Const-pool registration; returns the assigned index for use in bytecode.
    uint32_t RegisterString(uint16_t dex_id, std::string s);
    uint32_t RegisterType(uint16_t dex_id, std::string descriptor);
    uint32_t RegisterMethodRef(uint16_t dex_id,
                               std::string cls, std::string name,
                               std::string proto);
    uint32_t RegisterFieldRef(uint16_t dex_id,
                              std::string cls, std::string name,
                              std::string type);

    // ─── IDexCodeSource overrides ────────────────────────────────────────
    uint32_t GetMethodAccessFlags(uint16_t dex_id, uint32_t midx) override;
    std::string_view GetMethodClassName(uint16_t, uint32_t) override;
    std::string_view GetMethodName(uint16_t, uint32_t) override;
    std::string GetMethodProto(uint16_t, uint32_t) override;
    const dex::Code* GetMethodCode(uint16_t, uint32_t) override;
    std::string_view GetString(uint16_t, uint32_t) override;
    std::string_view GetTypeName(uint16_t, uint32_t) override;
    std::array<std::string_view, 3>
        GetMethodRefTriple(uint16_t, uint32_t) override;
    std::array<std::string_view, 3>
        GetFieldRefTriple(uint16_t, uint32_t) override;

private:
    // string_view stability: pointer-stable storage (deque, not vector).
    struct DexPool {
        std::deque<std::string> strings;
        std::deque<std::string> types;
        std::deque<std::array<std::string, 3>> methods;
        std::deque<std::array<std::string, 3>> fields;
    };
    struct MethodEntry {
        uint32_t access_flags = 0;
        std::string cls_name;
        std::string name;
        std::string proto;
        std::unique_ptr<FakeCodeItem> code;
    };

    DexPool& pool(uint16_t dex_id) { return pools_[dex_id]; }

    std::unordered_map<uint16_t, DexPool> pools_;
    std::unordered_map<uint64_t, MethodEntry> methods_;
    // Key encoding: (dex_id << 32) | method_idx.
    static uint64_t MethodKey(uint16_t d, uint32_t m) {
        return (static_cast<uint64_t>(d) << 32) | m;
    }
};

}  // namespace dexkit::dad::testing
