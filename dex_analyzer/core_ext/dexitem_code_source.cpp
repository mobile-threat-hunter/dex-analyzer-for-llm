// dexitem_code_source.cpp — IDexCodeSource implementation over DexKit.

#include "dexitem_code_source.h"

#include <stdexcept>
#include <string>
#include <utility>

#include "dex_item.h"
#include "slicer/dex_format.h"
#include "slicer/reader.h"

namespace dexkit::ext {

namespace {

// Mirrors core_ext/dexkit_ext.cpp:BuildProtoDescriptor — produces the
// "(args)Ret" raw descriptor for a proto id.
std::string BuildProto(const dexkit::DexItem& item,
                       const dex::ProtoId& proto_id) {
    const auto& type_names = item.GetTypeNames();
    const auto& reader = item.GetReader();
    std::string out;
    out += '(';
    if (proto_id.parameters_off != 0) {
        const auto* type_list =
            reader.dataPtr<dex::TypeList>(proto_id.parameters_off);
        if (type_list != nullptr && type_list->size > 0) {
            for (uint32_t i = 0; i < type_list->size; ++i) {
                out += std::string(type_names[type_list->list[i].type_idx]);
            }
        }
    }
    out += ')';
    out += std::string(type_names[proto_id.return_type_idx]);
    return out;
}

DexItem* SafeGetDexItem(dexkit::DexKit& core, uint16_t dex_id) {
    if (dex_id >= core.GetDexNum()) return nullptr;
    return core.GetDexItem(dex_id);
}

}  // namespace

DexItemCodeSource::DexItemCodeSource(dexkit::DexKit& core) : core_(core) {}

std::optional<dexkit::dad::IDexCodeSource::MethodLocator>
DexItemCodeSource::LocateMethod(std::string_view descriptor) {
    // Parse "Lcls;->name(proto)Ret". Strip whitespace first — androguard's
    // EncodedMethod.get_descriptor() inserts spaces between args ("(LA; LB;)V")
    // while our internal proto is spaceless ("(LA;LB;)V"). Types themselves
    // contain no whitespace, so stripping all whitespace is safe.
    std::string normalized;
    normalized.reserve(descriptor.size());
    for (char c : descriptor) {
        if (c != ' ' && c != '\t' && c != '\n' && c != '\r') normalized += c;
    }
    std::string_view ndesc{normalized};
    auto arrow = ndesc.find("->");
    if (arrow == std::string_view::npos) return std::nullopt;
    std::string_view class_desc = ndesc.substr(0, arrow);
    std::string_view rest = ndesc.substr(arrow + 2);
    auto open = rest.find('(');
    if (open == std::string_view::npos) return std::nullopt;
    std::string_view name = rest.substr(0, open);
    std::string_view proto = rest.substr(open);

    auto [dex_item, type_idx] = core_.GetClassDeclaredPair(class_desc);
    if (dex_item == nullptr) return std::nullopt;

    const auto& reader = dex_item->GetReader();
    const auto& strings = dex_item->GetStrings();
    const auto method_ids = reader.MethodIds();
    const auto proto_ids = reader.ProtoIds();
    for (size_t i = 0; i < method_ids.size(); ++i) {
        const auto& m = method_ids[i];
        if (m.class_idx != type_idx) continue;
        if (strings[m.name_idx] != name) continue;
        if (BuildProto(*dex_item, proto_ids[m.proto_idx]) != proto) continue;
        return dexkit::dad::IDexCodeSource::MethodLocator{
            dex_item->GetDexId(), static_cast<uint32_t>(i)};
    }
    return std::nullopt;
}

std::vector<dexkit::dad::IDexCodeSource::MethodLocator>
DexItemCodeSource::LocateClassMethods(std::string_view class_descriptor) {
    std::vector<dexkit::dad::IDexCodeSource::MethodLocator> out;
    auto [dex_item, type_idx] = core_.GetClassDeclaredPair(class_descriptor);
    if (dex_item == nullptr) return out;
    const auto& class_method_ids = dex_item->GetClassMethodIds(type_idx);
    out.reserve(class_method_ids.size());
    for (uint32_t midx : class_method_ids) {
        out.push_back({dex_item->GetDexId(), midx});
    }
    return out;
}

uint32_t DexItemCodeSource::GetMethodAccessFlags(uint16_t dex_id,
                                                 uint32_t midx) {
    DexItem* item = SafeGetDexItem(core_, dex_id);
    if (!item) return 0;
    // DAD-aligned decompilation needs the RAW access flags (with
    // declared_synchronized bit intact). The default GetMethodAccessFlags
    // applies a Java-Modifier-compat transform that drops the
    // declared_synchronized bit; use the raw vector here.
    const auto& flags = item->GetMethodRawAccessFlags();
    return midx < flags.size() ? flags[midx] : 0;
}

std::string_view DexItemCodeSource::GetMethodClassName(uint16_t dex_id,
                                                       uint32_t midx) {
    DexItem* item = SafeGetDexItem(core_, dex_id);
    if (!item) return {};
    const auto& reader = item->GetReader();
    const auto& type_names = item->GetTypeNames();
    const auto method_ids = reader.MethodIds();
    if (midx >= method_ids.size()) return {};
    return type_names[method_ids[midx].class_idx];
}

std::string_view DexItemCodeSource::GetMethodName(uint16_t dex_id,
                                                  uint32_t midx) {
    DexItem* item = SafeGetDexItem(core_, dex_id);
    if (!item) return {};
    const auto& reader = item->GetReader();
    const auto& strings = item->GetStrings();
    const auto method_ids = reader.MethodIds();
    if (midx >= method_ids.size()) return {};
    return strings[method_ids[midx].name_idx];
}

std::string DexItemCodeSource::GetMethodProto(uint16_t dex_id,
                                              uint32_t midx) {
    DexItem* item = SafeGetDexItem(core_, dex_id);
    if (!item) return {};
    const auto& reader = item->GetReader();
    const auto method_ids = reader.MethodIds();
    if (midx >= method_ids.size()) return {};
    const auto& proto_id = reader.ProtoIds()[method_ids[midx].proto_idx];
    return BuildProto(*item, proto_id);
}

const dex::Code* DexItemCodeSource::GetMethodCode(uint16_t dex_id,
                                                  uint32_t midx) {
    DexItem* item = SafeGetDexItem(core_, dex_id);
    if (!item) return nullptr;
    return item->GetMethodCode(midx);
}

std::string_view
DexItemCodeSource::GetProtoCached(uint16_t dex_id, uint32_t proto_idx) {
    uint64_t key = ProtoKey(dex_id, proto_idx);
    {
        std::lock_guard lock(proto_cache_mutex_);
        auto it = proto_cache_.find(key);
        if (it != proto_cache_.end()) return it->second;
    }
    DexItem* item = SafeGetDexItem(core_, dex_id);
    if (!item) return {};
    const auto& proto_id = item->GetReader().ProtoIds()[proto_idx];
    std::string proto = BuildProto(*item, proto_id);
    std::lock_guard lock(proto_cache_mutex_);
    auto [it, _] = proto_cache_.emplace(key, std::move(proto));
    return it->second;
}

std::string_view DexItemCodeSource::GetString(uint16_t dex_id, uint32_t idx) {
    DexItem* item = SafeGetDexItem(core_, dex_id);
    if (!item) return {};
    const auto& strings = item->GetStrings();
    if (idx >= strings.size()) return {};
    return strings[idx];
}

std::string_view DexItemCodeSource::GetTypeName(uint16_t dex_id, uint32_t idx) {
    DexItem* item = SafeGetDexItem(core_, dex_id);
    if (!item) return {};
    const auto& type_names = item->GetTypeNames();
    if (idx >= type_names.size()) return {};
    return type_names[idx];
}

std::array<std::string_view, 3>
DexItemCodeSource::GetMethodRefTriple(uint16_t dex_id, uint32_t midx) {
    DexItem* item = SafeGetDexItem(core_, dex_id);
    if (!item) return {{}};
    const auto& reader = item->GetReader();
    const auto& type_names = item->GetTypeNames();
    const auto& strings = item->GetStrings();
    const auto method_ids = reader.MethodIds();
    if (midx >= method_ids.size()) return {{}};
    const auto& m = method_ids[midx];
    // Build proto on the fly. Proto returned by value (string), stored on
    // DexItem? No — we'd need stable storage. Workaround: stash protos in a
    // per-source cache. For now we return a static-thread-local string.
    // SAFER alternative: return the original Smali "(args)Ret" via DexItem
    // helper. DexItem doesn't expose this. We pre-cache here.
    //
    // Simplest correct path: keep a per-DexItem proto cache in this
    // adapter. Allocate on first call, return string_view into it.
    std::array<std::string_view, 3> out;
    out[0] = type_names[m.class_idx];
    out[1] = strings[m.name_idx];
    out[2] = GetProtoCached(dex_id, m.proto_idx);
    return out;
}

std::array<std::string_view, 3>
DexItemCodeSource::GetFieldRefTriple(uint16_t dex_id, uint32_t fidx) {
    DexItem* item = SafeGetDexItem(core_, dex_id);
    if (!item) return {{}};
    const auto& reader = item->GetReader();
    const auto& type_names = item->GetTypeNames();
    const auto& strings = item->GetStrings();
    const auto field_ids = reader.FieldIds();
    if (fidx >= field_ids.size()) return {{}};
    const auto& f = field_ids[fidx];
    return {type_names[f.class_idx], strings[f.name_idx], type_names[f.type_idx]};
}

// DAD: decompile.py:269 DvClass.__init__ — supplies metadata used by
// get_source() to emit the package / class header / interface list.
std::optional<dexkit::dad::IDexCodeSource::ClassInfo>
DexItemCodeSource::GetClassInfo(std::string_view class_descriptor) {
    auto [item, type_idx] = core_.GetClassDeclaredPair(class_descriptor);
    if (item == nullptr) return std::nullopt;
    uint32_t class_def_idx = item->GetTypeDefIdx(type_idx);
    if (class_def_idx == dex::kNoIndex) return std::nullopt;

    const auto& reader = item->GetReader();
    const auto& type_names = item->GetTypeNames();
    const auto class_defs = reader.ClassDefs();
    if (class_def_idx >= class_defs.size()) return std::nullopt;
    const auto& cdef = class_defs[class_def_idx];

    ClassInfo info;
    info.dex_id = item->GetDexId();
    info.type_idx = type_idx;
    info.access_flags = cdef.access_flags;
    if (cdef.superclass_idx != dex::kNoIndex) {
        info.superclass = type_names[cdef.superclass_idx];
    }
    if (cdef.interfaces_off != 0) {
        const auto* type_list =
            reader.dataPtr<dex::TypeList>(cdef.interfaces_off);
        if (type_list != nullptr) {
            info.interfaces.reserve(type_list->size);
            for (uint32_t i = 0; i < type_list->size; ++i) {
                info.interfaces.push_back(
                    type_names[type_list->list[i].type_idx]);
            }
        }
    }
    // field_ids: class_field_ids[type_idx] is already indexed in InitBaseCache.
    info.field_ids = item->GetClassFieldIds(type_idx);
    return info;
}

// DAD: decompile.py:367 DvClass.get_source — per-field name + type + access.
// init_text is left empty for now (Phase 1): DvClass emits `Type name;`
// when there's no compile-time initializer, which is valid Java. EncodedValue
// decoding (String/byte/primitive/...) is a deferred follow-up.
dexkit::dad::IDexCodeSource::FieldInfo
DexItemCodeSource::GetFieldInfo(uint16_t dex_id, uint32_t fidx) {
    FieldInfo info;
    DexItem* item = SafeGetDexItem(core_, dex_id);
    if (!item) return info;
    const auto& reader = item->GetReader();
    const auto& strings = item->GetStrings();
    const auto& type_names = item->GetTypeNames();
    const auto field_ids = reader.FieldIds();
    if (fidx >= field_ids.size()) return info;
    const auto& f = field_ids[fidx];
    info.name = strings[f.name_idx];
    info.type = type_names[f.type_idx];
    const auto& access = item->GetFieldAccessFlags();
    if (fidx < access.size()) info.access_flags = access[fidx];
    return info;
}

}  // namespace dexkit::ext
