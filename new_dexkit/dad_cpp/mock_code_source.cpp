// mock_code_source.cpp — implementations for test-only mock.

#include "mock_code_source.h"

#include <cstring>
#include <stdexcept>

namespace dexkit::dad::testing {

namespace {

// Round up to 4-byte alignment.
size_t Align4(size_t off) { return (off + 3) & ~size_t{3}; }

}  // namespace

// ============================================================================
// FakeCodeItem
// ============================================================================

std::unique_ptr<FakeCodeItem> FakeCodeItem::Make(
    uint16_t registers_size, uint16_t ins_size, uint16_t outs_size,
    const std::vector<dex::u2>& insns,
    const std::vector<dex::TryBlock>& tries,
    const std::vector<uint8_t>& handlers) {

    auto item = std::unique_ptr<FakeCodeItem>(new FakeCodeItem());

    // Layout:
    //   dex::Code (16 bytes header)
    //   u2 insns[insns_size]               (insns_size * 2 bytes)
    //   [u2 padding to 4-byte align if tries_size > 0]
    //   dex::TryBlock tries[tries_size]    (8 bytes each)
    //   uleb128 handlers_size  + bytes
    //
    // dex::Code is a flexible-array struct: header is 16 bytes, then insns[].
    // We'll write header + insns first, then pad to 4-byte align, then tries +
    // handlers.

    const size_t header_size = sizeof(dex::Code);  // 16 bytes
    const size_t insns_bytes = insns.size() * sizeof(dex::u2);

    size_t total = header_size + insns_bytes;
    if (!tries.empty()) {
        total = Align4(total);
        total += tries.size() * sizeof(dex::TryBlock);
        total += handlers.size();
    }

    item->buffer_.assign(total, 0);
    auto* hdr = reinterpret_cast<dex::Code*>(item->buffer_.data());
    hdr->registers_size = registers_size;
    hdr->ins_size = ins_size;
    hdr->outs_size = outs_size;
    hdr->tries_size = static_cast<uint16_t>(tries.size());
    hdr->debug_info_off = 0;
    hdr->insns_size = static_cast<uint32_t>(insns.size());

    // Copy insns
    if (!insns.empty()) {
        std::memcpy(item->buffer_.data() + header_size, insns.data(),
                    insns_bytes);
    }

    if (!tries.empty()) {
        size_t tries_off = Align4(header_size + insns_bytes);
        std::memcpy(item->buffer_.data() + tries_off, tries.data(),
                    tries.size() * sizeof(dex::TryBlock));
        size_t handlers_off = tries_off + tries.size() * sizeof(dex::TryBlock);
        if (!handlers.empty()) {
            std::memcpy(item->buffer_.data() + handlers_off, handlers.data(),
                        handlers.size());
        }
    }

    return item;
}

// ============================================================================
// MockCodeSource
// ============================================================================

void MockCodeSource::RegisterMethod(uint16_t dex_id, uint32_t method_idx,
                                    uint32_t access_flags,
                                    std::string cls_name,
                                    std::string name,
                                    std::string proto,
                                    std::unique_ptr<FakeCodeItem> code) {
    MethodEntry e;
    e.access_flags = access_flags;
    e.cls_name = std::move(cls_name);
    e.name = std::move(name);
    e.proto = std::move(proto);
    e.code = std::move(code);
    methods_[MethodKey(dex_id, method_idx)] = std::move(e);
}

uint32_t MockCodeSource::RegisterString(uint16_t dex_id, std::string s) {
    auto& p = pool(dex_id);
    uint32_t idx = static_cast<uint32_t>(p.strings.size());
    p.strings.push_back(std::move(s));
    return idx;
}

uint32_t MockCodeSource::RegisterType(uint16_t dex_id, std::string descriptor) {
    auto& p = pool(dex_id);
    uint32_t idx = static_cast<uint32_t>(p.types.size());
    p.types.push_back(std::move(descriptor));
    return idx;
}

uint32_t MockCodeSource::RegisterMethodRef(uint16_t dex_id,
                                           std::string cls,
                                           std::string name,
                                           std::string proto) {
    auto& p = pool(dex_id);
    uint32_t idx = static_cast<uint32_t>(p.methods.size());
    p.methods.push_back({std::move(cls), std::move(name), std::move(proto)});
    return idx;
}

uint32_t MockCodeSource::RegisterFieldRef(uint16_t dex_id,
                                          std::string cls,
                                          std::string name,
                                          std::string type) {
    auto& p = pool(dex_id);
    uint32_t idx = static_cast<uint32_t>(p.fields.size());
    p.fields.push_back({std::move(cls), std::move(name), std::move(type)});
    return idx;
}

uint32_t MockCodeSource::GetMethodAccessFlags(uint16_t d, uint32_t m) {
    auto it = methods_.find(MethodKey(d, m));
    return it == methods_.end() ? 0 : it->second.access_flags;
}

std::string_view MockCodeSource::GetMethodClassName(uint16_t d, uint32_t m) {
    auto it = methods_.find(MethodKey(d, m));
    if (it == methods_.end())
        throw std::runtime_error("mock: unknown method " + std::to_string(m));
    return it->second.cls_name;
}

std::string_view MockCodeSource::GetMethodName(uint16_t d, uint32_t m) {
    auto it = methods_.find(MethodKey(d, m));
    if (it == methods_.end()) throw std::runtime_error("mock: unknown method");
    return it->second.name;
}

std::string MockCodeSource::GetMethodProto(uint16_t d, uint32_t m) {
    auto it = methods_.find(MethodKey(d, m));
    if (it == methods_.end()) throw std::runtime_error("mock: unknown method");
    return it->second.proto;
}

const dex::Code* MockCodeSource::GetMethodCode(uint16_t d, uint32_t m) {
    auto it = methods_.find(MethodKey(d, m));
    if (it == methods_.end() || !it->second.code) return nullptr;
    return it->second.code->code();
}

std::string_view MockCodeSource::GetString(uint16_t d, uint32_t idx) {
    auto& p = pool(d);
    if (idx >= p.strings.size())
        throw std::runtime_error("mock: string idx out of range");
    return p.strings[idx];
}

std::string_view MockCodeSource::GetTypeName(uint16_t d, uint32_t idx) {
    auto& p = pool(d);
    if (idx >= p.types.size())
        throw std::runtime_error("mock: type idx out of range");
    return p.types[idx];
}

std::array<std::string_view, 3>
MockCodeSource::GetMethodRefTriple(uint16_t d, uint32_t idx) {
    auto& p = pool(d);
    if (idx >= p.methods.size())
        throw std::runtime_error("mock: method ref idx out of range");
    const auto& t = p.methods[idx];
    return {t[0], t[1], t[2]};
}

std::array<std::string_view, 3>
MockCodeSource::GetFieldRefTriple(uint16_t d, uint32_t idx) {
    auto& p = pool(d);
    if (idx >= p.fields.size())
        throw std::runtime_error("mock: field ref idx out of range");
    const auto& t = p.fields[idx];
    return {t[0], t[1], t[2]};
}

}  // namespace dexkit::dad::testing
