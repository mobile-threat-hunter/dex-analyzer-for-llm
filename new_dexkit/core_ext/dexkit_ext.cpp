#include "dexkit_ext.h"

#include <algorithm>
#include <array>
#include <map>
#include <set>
#include <string>
#include <string_view>
#include <utility>

#include "analyze.h"  // kMethodInvoking et al.
#include "dexitem_code_source.h"  // for GetCodeSource()
#include "schema/querys_generated.h"
#include "schema/matchers_generated.h"
#include "schema/results_generated.h"
#include "schema/encode_value_generated.h"

namespace dexkit::ext {

namespace {

// Normalise class name input to upstream's expected form: "com/x/Y" or
// "com.x.Y". Strips the "L...;" descriptor wrapper if present so callers can
// pass either form interchangeably.
std::string NormaliseClassNamePattern(std::string_view in) {
    if (in.size() >= 2 && in.front() == 'L' && in.back() == ';') {
        return std::string(in.substr(1, in.size() - 2));
    }
    return std::string(in);
}

dexkit::schema::StringMatchType ParseStringMatchType(std::string_view s) {
    if (s == "equals" || s == "equal") return dexkit::schema::StringMatchType::Equal;
    if (s == "contains")               return dexkit::schema::StringMatchType::Contains;
    if (s == "starts_with" || s == "startswith" || s == "start_with") return dexkit::schema::StringMatchType::StartWith;
    if (s == "ends_with" || s == "endswith" || s == "end_with")       return dexkit::schema::StringMatchType::EndWith;
    if (s == "regex" || s == "similar_regex")                          return dexkit::schema::StringMatchType::SimilarRegex;
    return dexkit::schema::StringMatchType::Contains;  // default
}

// Parse a flatbuffer ClassMetaArrayHolder result into POD ClassMatch vector.
std::vector<ClassMatch> ParseClassMetaArray(
    const dexkit::schema::ClassMetaArrayHolder* holder) {
    std::vector<ClassMatch> out;
    if (holder == nullptr || holder->classes() == nullptr) return out;
    for (const auto* cls : *holder->classes()) {
        ClassMatch m;
        m.dex_id = cls->dex_id();
        m.class_id = cls->id();
        if (cls->dex_descriptor()) m.descriptor = cls->dex_descriptor()->str();
        out.push_back(std::move(m));
    }
    return out;
}

std::vector<MethodMatch> ParseMethodMetaArray(
    const dexkit::schema::MethodMetaArrayHolder* holder) {
    std::vector<MethodMatch> out;
    if (holder == nullptr || holder->methods() == nullptr) return out;
    for (const auto* m : *holder->methods()) {
        MethodMatch mm;
        mm.dex_id = m->dex_id();
        mm.method_id = m->id();
        if (m->dex_descriptor()) mm.descriptor = m->dex_descriptor()->str();
        out.push_back(std::move(mm));
    }
    return out;
}

}  // namespace

namespace {

// Stable framework prefixes. Tested by IsFrameworkDescriptor() and used as
// the default filter in ListExternal* APIs.
constexpr std::array<std::string_view, 12> kFrameworkPrefixes = {
    "Landroid/", "Ljava/",     "Ljavax/",  "Lkotlin/",
    "Lkotlinx/", "Lorg/json/", "Lorg/xml/", "Lorg/w3c/",
    "Ldalvik/",  "Llibcore/",  "Lsun/",    "Lcom/google/android/",
};

// Strip leading '[' from an array type and return the element descriptor so
// "[[Landroid/foo/Bar;" → "Landroid/foo/Bar;" for prefix matching. Returns
// the unwrapped view, which may be a single-char primitive (e.g. "I") if the
// input was "[I" or "[[I".
std::string_view UnwrapArray(std::string_view d) {
    while (!d.empty() && d.front() == '[') {
        d.remove_prefix(1);
    }
    return d;
}

// True iff descriptor refers to a real (object) class, not a primitive type or
// an array of primitives. Class descriptors are "L...;"; primitives are single
// characters from {V,Z,B,S,C,I,J,F,D}.
bool IsClassDescriptor(std::string_view d) {
    auto u = UnwrapArray(d);
    return u.size() >= 2 && u.front() == 'L' && u.back() == ';';
}

// Build "(II)Ljava/lang/String;" from a ProtoId's parameters + return type.
// parameters_off == 0 in dex means "no parameters" — must NOT dereference, as
// dataPtr() returns base+0 (pointing into the dex header), giving garbage size.
std::string BuildProtoDescriptor(const dexkit::DexItem& item,
                                 const dex::ProtoId& proto_id) {
    const auto& type_names = item.GetTypeNames();
    const auto& reader = item.GetReader();
    std::string out;
    out += '(';
    if (proto_id.parameters_off != 0) {
        const auto* type_list =
            reader.dataPtr<dex::TypeList>(proto_id.parameters_off);
        if (type_list != nullptr && type_list->size > 0) {
            const auto* item_ptr = &type_list->list[0];
            for (uint32_t i = 0; i < type_list->size; ++i, ++item_ptr) {
                out += std::string(type_names[item_ptr->type_idx]);
            }
        }
    }
    out += ')';
    out += std::string(type_names[proto_id.return_type_idx]);
    return out;
}

// Generic body used by all three ListExternal* methods. The Visitor decides
// per-dex what to collect; this routine handles the shared traversal logic.
//
// NOTE: upstream DexKit::GetDexItem() does NOT bound-check — must use
// GetDexNum() as the loop bound.
template <typename Visitor>
void ForEachExternalRef(const dexkit::DexKit& core, Visitor&& visit) {
    const int dex_num = const_cast<dexkit::DexKit&>(core).GetDexNum();
    for (int i = 0; i < dex_num; ++i) {
        auto* item = const_cast<dexkit::DexKit&>(core).GetDexItem(
            static_cast<uint16_t>(i));
        if (item == nullptr) continue;
        visit(*item, static_cast<uint16_t>(i));
    }
}

}  // namespace

bool IsFrameworkDescriptor(std::string_view descriptor) {
    auto d = UnwrapArray(descriptor);
    return std::any_of(
        kFrameworkPrefixes.begin(), kFrameworkPrefixes.end(),
        [&](std::string_view p) { return d.size() >= p.size() && d.substr(0, p.size()) == p; });
}

std::vector<ExternalTypeRef>
DexKitExt::ListExternalTypeRefs(bool framework_only) const {
    // descriptor → set of dex ids it appears in
    std::map<std::string, std::set<uint16_t>> bucket;

    ForEachExternalRef(*core_, [&](const dexkit::DexItem& item, uint16_t /*loop_id*/) {
        const auto& type_names = item.GetTypeNames();
        const uint16_t real_dex_id = item.GetDexId();
        for (size_t type_idx = 0; type_idx < type_names.size(); ++type_idx) {
            std::string_view desc = type_names[type_idx];
            if (desc.empty()) continue;
            // Skip primitives and primitive-array types — they have no class_def
            // by definition and are not interesting as "external references".
            if (!IsClassDescriptor(desc)) continue;
            // Skip if declared anywhere in the loaded app.
            if (const_cast<dexkit::DexKit&>(*core_)
                    .GetClassDeclaredPair(desc).first != nullptr) {
                continue;
            }
            if (framework_only && !IsFrameworkDescriptor(desc)) continue;
            bucket[std::string(desc)].insert(real_dex_id);
        }
    });

    std::vector<ExternalTypeRef> out;
    out.reserve(bucket.size());
    for (auto& [desc, dex_ids] : bucket) {
        ExternalTypeRef ref;
        ref.descriptor = desc;
        ref.referenced_in_dex_ids.assign(dex_ids.begin(), dex_ids.end());
        out.push_back(std::move(ref));
    }
    return out;
}

std::vector<ExternalMethodRef>
DexKitExt::ListExternalMethodRefs(bool framework_only) const {
    // (class_descriptor, name, proto) → set of dex ids
    using Key = std::tuple<std::string, std::string, std::string>;
    std::map<Key, std::set<uint16_t>> bucket;

    ForEachExternalRef(*core_, [&](const dexkit::DexItem& item, uint16_t dex_id) {
        const auto& reader = item.GetReader();
        const auto& type_names = item.GetTypeNames();
        const auto& strings = item.GetStrings();
        const auto method_ids = reader.MethodIds();
        const auto proto_ids = reader.ProtoIds();
        for (size_t m_idx = 0; m_idx < method_ids.size(); ++m_idx) {
            const auto& m = method_ids[m_idx];
            std::string_view cls_desc = type_names[m.class_idx];
            if (const_cast<dexkit::DexKit&>(*core_)
                    .GetClassDeclaredPair(cls_desc).first != nullptr) {
                continue;
            }
            if (framework_only && !IsFrameworkDescriptor(cls_desc)) continue;
            std::string proto = BuildProtoDescriptor(item, proto_ids[m.proto_idx]);
            Key key{std::string(cls_desc), std::string(strings[m.name_idx]),
                    std::move(proto)};
            bucket[std::move(key)].insert(dex_id);
        }
    });

    std::vector<ExternalMethodRef> out;
    out.reserve(bucket.size());
    for (auto& [key, dex_ids] : bucket) {
        ExternalMethodRef ref;
        ref.class_descriptor = std::get<0>(key);
        ref.name = std::get<1>(key);
        ref.proto = std::get<2>(key);
        ref.referenced_in_dex_ids.assign(dex_ids.begin(), dex_ids.end());
        out.push_back(std::move(ref));
    }
    return out;
}

std::vector<ExternalFieldRef>
DexKitExt::ListExternalFieldRefs(bool framework_only) const {
    using Key = std::tuple<std::string, std::string, std::string>;
    std::map<Key, std::set<uint16_t>> bucket;

    ForEachExternalRef(*core_, [&](const dexkit::DexItem& item, uint16_t dex_id) {
        const auto& reader = item.GetReader();
        const auto& type_names = item.GetTypeNames();
        const auto& strings = item.GetStrings();
        const auto field_ids = reader.FieldIds();
        for (size_t f_idx = 0; f_idx < field_ids.size(); ++f_idx) {
            const auto& f = field_ids[f_idx];
            std::string_view cls_desc = type_names[f.class_idx];
            if (const_cast<dexkit::DexKit&>(*core_)
                    .GetClassDeclaredPair(cls_desc).first != nullptr) {
                continue;
            }
            if (framework_only && !IsFrameworkDescriptor(cls_desc)) continue;
            Key key{std::string(cls_desc), std::string(strings[f.name_idx]),
                    std::string(type_names[f.type_idx])};
            bucket[std::move(key)].insert(dex_id);
        }
    });

    std::vector<ExternalFieldRef> out;
    out.reserve(bucket.size());
    for (auto& [key, dex_ids] : bucket) {
        ExternalFieldRef ref;
        ref.class_descriptor = std::get<0>(key);
        ref.name = std::get<1>(key);
        ref.type = std::get<2>(key);
        ref.referenced_in_dex_ids.assign(dex_ids.begin(), dex_ids.end());
        out.push_back(std::move(ref));
    }
    return out;
}

DexKitExt::DexKitExt(const std::string& apk_path)
    : apk_path_(apk_path),
      core_(std::make_unique<dexkit::DexKit>(apk_path)) {}

DexKitExt::~DexKitExt() = default;

DexItemCodeSource& DexKitExt::GetCodeSource() {
    if (!code_source_) {
        code_source_ = std::make_unique<DexItemCodeSource>(*core_);
    }
    return *code_source_;
}

int DexKitExt::DexCount() const { return core_->GetDexNum(); }

int DexKitExt::LocateClassDex(std::string_view class_descriptor) const {
    auto [dex_item, type_idx] = core_->GetClassDeclaredPair(class_descriptor);
    if (dex_item == nullptr) return -1;
    return static_cast<int>(dex_item->GetDexId());
}

std::vector<std::string> DexKitExt::ListClasses() const {
    std::vector<std::string> out;
    auto& mut = const_cast<dexkit::DexKit&>(*core_);
    const int n = core_->GetDexNum();
    for (int i = 0; i < n; ++i) {
        auto* item = mut.GetDexItem(static_cast<uint16_t>(i));
        if (!item) continue;
        const auto& type_names = item->GetTypeNames();
        const auto& flags = item->GetTypeDefFlags();
        for (size_t type_idx = 0; type_idx < flags.size(); ++type_idx) {
            if (!flags[type_idx]) continue;
            out.emplace_back(type_names[type_idx]);
        }
    }
    return out;
}

std::vector<std::string>
DexKitExt::ListClassMethods(std::string_view class_descriptor) const {
    std::vector<std::string> out;
    auto& mut = const_cast<dexkit::DexKit&>(*core_);
    auto [dex_item, type_idx] = mut.GetClassDeclaredPair(class_descriptor);
    if (dex_item == nullptr) return out;
    const auto& reader = dex_item->GetReader();
    const auto& strings = dex_item->GetStrings();
    const auto& type_names = dex_item->GetTypeNames();
    const auto method_ids = reader.MethodIds();
    const auto proto_ids = reader.ProtoIds();
    const auto& class_method_ids = dex_item->GetClassMethodIds(type_idx);
    out.reserve(class_method_ids.size());
    for (uint32_t midx : class_method_ids) {
        const auto& m = method_ids[midx];
        std::string desc;
        desc.append(type_names[m.class_idx].data(),
                    type_names[m.class_idx].size());
        desc += "->";
        desc.append(strings[m.name_idx].data(), strings[m.name_idx].size());
        // proto (args)ret
        const auto& proto = proto_ids[m.proto_idx];
        desc += '(';
        if (proto.parameters_off != 0) {
            const auto* type_list =
                reader.dataPtr<dex::TypeList>(proto.parameters_off);
            if (type_list != nullptr && type_list->size > 0) {
                for (uint32_t k = 0; k < type_list->size; ++k) {
                    desc.append(type_names[type_list->list[k].type_idx]);
                }
            }
        }
        desc += ')';
        desc.append(type_names[proto.return_type_idx]);
        out.push_back(std::move(desc));
    }
    return out;
}

std::string
DexKitExt::RenderClassSmali(std::string_view class_descriptor) const {
    auto [dex_item, type_idx] =
        const_cast<dexkit::DexKit&>(*core_).GetClassDeclaredPair(class_descriptor);
    if (dex_item == nullptr) return {};
    return dex_item->RenderClassSmali(type_idx);
}

std::string
DexKitExt::RenderMethodSmali(std::string_view method_descriptor) const {
    // Parse method descriptor "Lcls;->name(args)Ret"
    auto arrow = method_descriptor.find("->");
    if (arrow == std::string_view::npos) return {};
    std::string_view class_desc = method_descriptor.substr(0, arrow);
    std::string_view rest = method_descriptor.substr(arrow + 2);
    auto open = rest.find('(');
    if (open == std::string_view::npos) return {};
    std::string_view name = rest.substr(0, open);
    std::string_view proto = rest.substr(open);

    auto [dex_item, type_idx] =
        const_cast<dexkit::DexKit&>(*core_).GetClassDeclaredPair(class_desc);
    if (dex_item == nullptr) return {};

    // Find method_idx within this dex
    const auto& reader = dex_item->GetReader();
    const auto& strings = dex_item->GetStrings();
    const auto method_ids = reader.MethodIds();
    const auto proto_ids = reader.ProtoIds();
    for (size_t i = 0; i < method_ids.size(); ++i) {
        const auto& m = method_ids[i];
        if (m.class_idx != type_idx) continue;
        if (strings[m.name_idx] != name) continue;
        if (BuildProtoDescriptor(*dex_item, proto_ids[m.proto_idx]) != proto) continue;
        return dex_item->RenderMethodSmali(static_cast<uint32_t>(i));
    }
    return {};
}

namespace {

// Parse "Lpkg/Cls;->name(args)Ret;" into (class_desc, name, proto).
// Returns false on malformed input.
bool ParseApiDescriptor(std::string_view api,
                        std::string_view& class_desc,
                        std::string_view& name,
                        std::string_view& proto) {
    auto arrow = api.find("->");
    if (arrow == std::string_view::npos) return false;
    class_desc = api.substr(0, arrow);
    std::string_view rest = api.substr(arrow + 2);
    auto open = rest.find('(');
    if (open == std::string_view::npos) return false;
    name = rest.substr(0, open);
    proto = rest.substr(open);
    return !class_desc.empty() && !name.empty() && !proto.empty();
}

// Find type_idx of descriptor in this dex's TypeIds table, or kNoIndex.
uint32_t FindTypeIdx(const dexkit::DexItem& item, std::string_view desc) {
    const auto& type_names = item.GetTypeNames();
    for (size_t i = 0; i < type_names.size(); ++i) {
        if (type_names[i] == desc) return static_cast<uint32_t>(i);
    }
    return dex::kNoIndex;
}

// Find method_idx of (class_idx, name, proto) in this dex, or kNoIndex.
uint32_t FindMethodIdx(const dexkit::DexItem& item, uint32_t class_idx,
                       std::string_view name, std::string_view proto) {
    const auto& reader = item.GetReader();
    const auto& strings = item.GetStrings();
    const auto method_ids = reader.MethodIds();
    const auto proto_ids = reader.ProtoIds();
    for (size_t i = 0; i < method_ids.size(); ++i) {
        const auto& m = method_ids[i];
        if (m.class_idx != class_idx) continue;
        if (strings[m.name_idx] != name) continue;
        if (BuildProtoDescriptor(item, proto_ids[m.proto_idx]) != proto) continue;
        return static_cast<uint32_t>(i);
    }
    return dex::kNoIndex;
}

// Build "Lcom/x/Y;->foo(I)V" for a method_idx in a given dex.
std::string BuildMethodSignature(const dexkit::DexItem& item, uint32_t method_idx) {
    const auto& reader = item.GetReader();
    const auto& type_names = item.GetTypeNames();
    const auto& strings = item.GetStrings();
    const auto& m = reader.MethodIds()[method_idx];
    std::string out;
    out += std::string(type_names[m.class_idx]);
    out += "->";
    out += std::string(strings[m.name_idx]);
    out += BuildProtoDescriptor(item, reader.ProtoIds()[m.proto_idx]);
    return out;
}

}  // namespace

namespace {

void FillInternalClassSummary(const dexkit::DexItem& item,
                              uint32_t type_idx,
                              ClassSummary& out) {
    const auto& reader = item.GetReader();
    const auto& type_names = item.GetTypeNames();
    const auto& strings = item.GetStrings();
    uint32_t class_def_idx = item.GetTypeDefIdx(type_idx);
    if (class_def_idx == dex::kNoIndex) return;
    const auto& class_def = reader.ClassDefs()[class_def_idx];

    out.is_internal = true;
    out.dex_id = static_cast<int16_t>(item.GetDexId());
    out.access_flags = class_def.access_flags;
    out.superclass_descriptor = std::string(type_names[class_def.superclass_idx]);
    if (class_def.source_file_idx != dex::kNoIndex) {
        out.source_file = std::string(strings[class_def.source_file_idx]);
    }
    // Interfaces (interfaces_off=0 means none, just like proto parameters_off).
    if (class_def.interfaces_off != 0) {
        const auto* iface_list =
            reader.dataPtr<dex::TypeList>(class_def.interfaces_off);
        if (iface_list != nullptr) {
            for (uint32_t i = 0; i < iface_list->size; ++i) {
                out.interface_descriptors.emplace_back(
                    std::string(type_names[iface_list->list[i].type_idx]));
            }
        }
    }
    // Methods declared on this class.
    const auto& method_ids = reader.MethodIds();
    const auto& proto_ids = reader.ProtoIds();
    const auto& method_flags = item.GetMethodAccessFlags();
    for (uint32_t method_idx : item.GetClassMethodIds(type_idx)) {
        const auto& m = method_ids[method_idx];
        ClassMemberMethod cm;
        cm.name = std::string(strings[m.name_idx]);
        cm.proto = BuildProtoDescriptor(item, proto_ids[m.proto_idx]);
        cm.access_flags = (method_idx < method_flags.size())
                              ? method_flags[method_idx] : 0u;
        out.methods.push_back(std::move(cm));
    }
    // Fields declared on this class.
    const auto& field_ids = reader.FieldIds();
    const auto& field_flags = item.GetFieldAccessFlags();
    for (uint32_t field_idx : item.GetClassFieldIds(type_idx)) {
        const auto& f = field_ids[field_idx];
        ClassMemberField cf;
        cf.name = std::string(strings[f.name_idx]);
        cf.type = std::string(type_names[f.type_idx]);
        cf.access_flags = (field_idx < field_flags.size())
                              ? field_flags[field_idx] : 0u;
        out.fields.push_back(std::move(cf));
    }
}

void FillExternalClassSummary(const dexkit::DexKit& core,
                              std::string_view descriptor,
                              ClassSummary& out) {
    out.is_internal = false;
    out.dex_id = -1;
    // Aggregate (name, proto) and (name, type) tuples seen across all dexes
    // that reference the class — dedup by signature.
    std::set<std::pair<std::string, std::string>> method_keys;
    std::set<std::pair<std::string, std::string>> field_keys;

    const int dex_num = const_cast<dexkit::DexKit&>(core).GetDexNum();
    for (int i = 0; i < dex_num; ++i) {
        auto* item_ptr = const_cast<dexkit::DexKit&>(core)
                             .GetDexItem(static_cast<uint16_t>(i));
        if (item_ptr == nullptr) continue;
        const auto& item = *item_ptr;
        uint32_t cls_type_idx = FindTypeIdx(item, descriptor);
        if (cls_type_idx == dex::kNoIndex) continue;

        const auto& reader = item.GetReader();
        const auto& strings = item.GetStrings();
        const auto& type_names = item.GetTypeNames();
        for (size_t m_idx = 0; m_idx < reader.MethodIds().size(); ++m_idx) {
            const auto& m = reader.MethodIds()[m_idx];
            if (m.class_idx != cls_type_idx) continue;
            method_keys.emplace(std::string(strings[m.name_idx]),
                                BuildProtoDescriptor(item, reader.ProtoIds()[m.proto_idx]));
        }
        for (size_t f_idx = 0; f_idx < reader.FieldIds().size(); ++f_idx) {
            const auto& f = reader.FieldIds()[f_idx];
            if (f.class_idx != cls_type_idx) continue;
            field_keys.emplace(std::string(strings[f.name_idx]),
                               std::string(type_names[f.type_idx]));
        }
    }
    for (auto& [name, proto] : method_keys) {
        ClassMemberMethod cm;
        cm.name = name;
        cm.proto = proto;
        out.methods.push_back(std::move(cm));
    }
    for (auto& [name, type] : field_keys) {
        ClassMemberField cf;
        cf.name = name;
        cf.type = type;
        out.fields.push_back(std::move(cf));
    }
}

}  // namespace

ClassSummary
DexKitExt::GetClassSummary(std::string_view descriptor) const {
    ClassSummary out;
    out.descriptor = std::string(descriptor);

    auto [dex_item, type_idx] =
        const_cast<dexkit::DexKit&>(*core_).GetClassDeclaredPair(descriptor);
    if (dex_item != nullptr) {
        FillInternalClassSummary(*dex_item, type_idx, out);
    } else {
        FillExternalClassSummary(*core_, descriptor, out);
        // External classes returning empty (no refs anywhere) → descriptor stays
        // set, but is_internal=false and members are empty. Caller can check.
    }
    return out;
}

// =================== L7: Find/Match wrappers ===================
//
// These build FlatBuffer queries against the upstream schema, dispatch via
// core_->FindXxx, and convert results back to POD vectors. The matcher tree
// can be deeply nested in upstream; we expose the most common shapes.

std::vector<ClassMatch>
DexKitExt::FindClassesByName(std::string_view name,
                             std::string_view match_type,
                             bool ignore_case) {
    flatbuffers::FlatBufferBuilder fbb;
    auto name_matcher = dexkit::schema::CreateStringMatcher(
        fbb, fbb.CreateString(NormaliseClassNamePattern(name)),
        ParseStringMatchType(match_type), ignore_case);
    // ClassMatcher positional args: smali_source, class_name, access_flags,
    // super_class, interfaces, annotations, fields, methods, using_strings, ...
    auto class_matcher = dexkit::schema::CreateClassMatcher(
        fbb, 0, name_matcher);
    auto find = dexkit::schema::CreateFindClass(
        fbb, 0, 0, false, 0, false, class_matcher);
    fbb.Finish(find);
    auto query = ::flatbuffers::GetRoot<dexkit::schema::FindClass>(
        fbb.GetBufferPointer());
    auto result = core_->FindClass(query);
    auto holder = ::flatbuffers::GetRoot<dexkit::schema::ClassMetaArrayHolder>(
        result->GetBufferPointer());
    return ParseClassMetaArray(holder);
}

std::vector<ClassMatch>
DexKitExt::FindClassesUsingStrings(const std::vector<std::string>& strings,
                                   std::string_view match_type,
                                   bool ignore_case) {
    flatbuffers::FlatBufferBuilder fbb;
    auto type = ParseStringMatchType(match_type);
    std::vector<flatbuffers::Offset<dexkit::schema::StringMatcher>> sms;
    sms.reserve(strings.size());
    for (const auto& s : strings) {
        sms.push_back(dexkit::schema::CreateStringMatcher(
            fbb, fbb.CreateString(s), type, ignore_case));
    }
    auto using_strings = fbb.CreateVector(sms);
    auto class_matcher = dexkit::schema::CreateClassMatcher(
        fbb, 0, 0, 0, 0, 0, 0, 0, 0, using_strings);
    auto find = dexkit::schema::CreateFindClass(
        fbb, 0, 0, false, 0, false, class_matcher);
    fbb.Finish(find);
    auto query = ::flatbuffers::GetRoot<dexkit::schema::FindClass>(
        fbb.GetBufferPointer());
    auto result = core_->FindClass(query);
    auto holder = ::flatbuffers::GetRoot<dexkit::schema::ClassMetaArrayHolder>(
        result->GetBufferPointer());
    return ParseClassMetaArray(holder);
}

std::vector<MethodMatch>
DexKitExt::FindMethodsUsingStrings(const std::vector<std::string>& strings,
                                   std::string_view match_type,
                                   bool ignore_case) {
    flatbuffers::FlatBufferBuilder fbb;
    auto type = ParseStringMatchType(match_type);
    std::vector<flatbuffers::Offset<dexkit::schema::StringMatcher>> sms;
    sms.reserve(strings.size());
    for (const auto& s : strings) {
        sms.push_back(dexkit::schema::CreateStringMatcher(
            fbb, fbb.CreateString(s), type, ignore_case));
    }
    auto using_strings = fbb.CreateVector(sms);
    // MethodMatcher positional args: method_name, access_flags, declaring_class,
    // return_type, parameters, annotations, op_codes, using_strings, ...
    auto method_matcher = dexkit::schema::CreateMethodMatcher(
        fbb, 0, 0, 0, 0, 0, 0, 0, using_strings);
    auto find = dexkit::schema::CreateFindMethod(
        fbb, 0, 0, false, 0, 0, false, method_matcher);
    fbb.Finish(find);
    auto query = ::flatbuffers::GetRoot<dexkit::schema::FindMethod>(
        fbb.GetBufferPointer());
    auto result = core_->FindMethod(query);
    auto holder = ::flatbuffers::GetRoot<dexkit::schema::MethodMetaArrayHolder>(
        result->GetBufferPointer());
    return ParseMethodMetaArray(holder);
}

std::map<std::string, std::vector<ClassMatch>>
DexKitExt::BatchFindClassesUsingStrings(
    const std::map<std::string, std::vector<std::string>>& query_map,
    std::string_view match_type, bool ignore_case) {
    flatbuffers::FlatBufferBuilder fbb;
    auto type = ParseStringMatchType(match_type);
    std::vector<flatbuffers::Offset<dexkit::schema::BatchUsingStringsMatcher>> entries;
    entries.reserve(query_map.size());
    for (const auto& [key, strs] : query_map) {
        std::vector<flatbuffers::Offset<dexkit::schema::StringMatcher>> sms;
        sms.reserve(strs.size());
        for (const auto& s : strs) {
            sms.push_back(dexkit::schema::CreateStringMatcher(
                fbb, fbb.CreateString(s), type, ignore_case));
        }
        entries.push_back(dexkit::schema::CreateBatchUsingStringsMatcher(
            fbb, fbb.CreateString(key), fbb.CreateVector(sms)));
    }
    auto matchers = fbb.CreateVector(entries);
    auto find = dexkit::schema::CreateBatchFindClassUsingStrings(
        fbb, 0, 0, false, 0, matchers);
    fbb.Finish(find);
    auto query = ::flatbuffers::GetRoot<dexkit::schema::BatchFindClassUsingStrings>(
        fbb.GetBufferPointer());
    auto result = core_->BatchFindClassUsingStrings(query);
    auto holder = ::flatbuffers::GetRoot<dexkit::schema::BatchClassMetaArrayHolder>(
        result->GetBufferPointer());

    std::map<std::string, std::vector<ClassMatch>> out;
    if (holder == nullptr || holder->items() == nullptr) return out;
    for (const auto* item : *holder->items()) {
        std::string key = item->union_key() ? item->union_key()->str() : "";
        std::vector<ClassMatch> ms;
        if (item->classes()) {
            for (const auto* cls : *item->classes()) {
                ClassMatch m;
                m.dex_id = cls->dex_id();
                m.class_id = cls->id();
                if (cls->dex_descriptor()) m.descriptor = cls->dex_descriptor()->str();
                ms.push_back(std::move(m));
            }
        }
        out.emplace(std::move(key), std::move(ms));
    }
    return out;
}

std::map<std::string, std::vector<MethodMatch>>
DexKitExt::BatchFindMethodsUsingStrings(
    const std::map<std::string, std::vector<std::string>>& query_map,
    std::string_view match_type, bool ignore_case) {
    flatbuffers::FlatBufferBuilder fbb;
    auto type = ParseStringMatchType(match_type);
    std::vector<flatbuffers::Offset<dexkit::schema::BatchUsingStringsMatcher>> entries;
    entries.reserve(query_map.size());
    for (const auto& [key, strs] : query_map) {
        std::vector<flatbuffers::Offset<dexkit::schema::StringMatcher>> sms;
        sms.reserve(strs.size());
        for (const auto& s : strs) {
            sms.push_back(dexkit::schema::CreateStringMatcher(
                fbb, fbb.CreateString(s), type, ignore_case));
        }
        entries.push_back(dexkit::schema::CreateBatchUsingStringsMatcher(
            fbb, fbb.CreateString(key), fbb.CreateVector(sms)));
    }
    auto matchers = fbb.CreateVector(entries);
    auto find = dexkit::schema::CreateBatchFindMethodUsingStrings(
        fbb, 0, 0, false, 0, 0, matchers);
    fbb.Finish(find);
    auto query = ::flatbuffers::GetRoot<dexkit::schema::BatchFindMethodUsingStrings>(
        fbb.GetBufferPointer());
    auto result = core_->BatchFindMethodUsingStrings(query);
    auto holder = ::flatbuffers::GetRoot<dexkit::schema::BatchMethodMetaArrayHolder>(
        result->GetBufferPointer());

    std::map<std::string, std::vector<MethodMatch>> out;
    if (holder == nullptr || holder->items() == nullptr) return out;
    for (const auto* item : *holder->items()) {
        std::string key = item->union_key() ? item->union_key()->str() : "";
        std::vector<MethodMatch> ms;
        if (item->methods()) {
            for (const auto* m : *item->methods()) {
                MethodMatch mm;
                mm.dex_id = m->dex_id();
                mm.method_id = m->id();
                if (m->dex_descriptor()) mm.descriptor = m->dex_descriptor()->str();
                ms.push_back(std::move(mm));
            }
        }
        out.emplace(std::move(key), std::move(ms));
    }
    return out;
}

std::vector<MethodMatch>
DexKitExt::FindMethodsByName(std::string_view name,
                             std::string_view match_type,
                             std::string_view declaring_class,
                             bool ignore_case) {
    flatbuffers::FlatBufferBuilder fbb;
    auto type = ParseStringMatchType(match_type);

    auto name_matcher = dexkit::schema::CreateStringMatcher(
        fbb, fbb.CreateString(std::string(name)), type, ignore_case);

    flatbuffers::Offset<dexkit::schema::ClassMatcher> declaring_offset = 0;
    if (!declaring_class.empty()) {
        auto cls_name_matcher = dexkit::schema::CreateStringMatcher(
            fbb, fbb.CreateString(NormaliseClassNamePattern(declaring_class)),
            dexkit::schema::StringMatchType::Equal, false);
        declaring_offset = dexkit::schema::CreateClassMatcher(
            fbb, 0, cls_name_matcher);
    }

    auto method_matcher = dexkit::schema::CreateMethodMatcher(
        fbb, name_matcher, 0, declaring_offset);
    auto find = dexkit::schema::CreateFindMethod(
        fbb, 0, 0, false, 0, 0, false, method_matcher);
    fbb.Finish(find);
    auto query = ::flatbuffers::GetRoot<dexkit::schema::FindMethod>(
        fbb.GetBufferPointer());
    auto result = core_->FindMethod(query);
    auto holder = ::flatbuffers::GetRoot<dexkit::schema::MethodMetaArrayHolder>(
        result->GetBufferPointer());
    return ParseMethodMetaArray(holder);
}

// Build a single-element AnnotationsMatcher whose annotation type's class_name
// is `annotation_class`. Reusable for ClassMatcher.annotations and
// MethodMatcher.annotations slots.
//
// Implementation note: upstream's Analyze() collects Equal class_name patterns
// from sub-matchers into `declare_class`, which then restricts the search to
// classes named that pattern (the annotation class, not the target). To avoid
// this trap, we always use Contains for the annotation type — and supply a
// trailing ';' so Contains matches the full descriptor "L...;" form precisely
// in practice. For "equals" semantics callers should pass the full descriptor
// (e.g. "Lkotlin/Metadata;") which Contains will match uniquely.
static flatbuffers::Offset<dexkit::schema::AnnotationsMatcher>
BuildSingleAnnotationsMatcher(flatbuffers::FlatBufferBuilder& fbb,
                              std::string_view annotation_class,
                              std::string_view /*match_type — ignored*/) {
    // Normalise to smali path form, then wrap with L...; on caller's behalf
    // so Contains pinpoints the exact descriptor.
    std::string base = NormaliseClassNamePattern(annotation_class);
    std::string pattern = "L" + base + ";";
    auto cls_name_matcher = dexkit::schema::CreateStringMatcher(
        fbb, fbb.CreateString(pattern),
        dexkit::schema::StringMatchType::Contains, false);
    auto anno_class_matcher = dexkit::schema::CreateClassMatcher(
        fbb, 0, cls_name_matcher);
    auto anno_matcher = dexkit::schema::CreateAnnotationMatcher(
        fbb, anno_class_matcher);
    return dexkit::schema::CreateAnnotationsMatcher(
        fbb,
        fbb.CreateVector(std::vector<flatbuffers::Offset<dexkit::schema::AnnotationMatcher>>{anno_matcher}),
        dexkit::schema::MatchType::Contains);
}

std::vector<ClassMatch>
DexKitExt::FindClassesByAnnotation(std::string_view annotation_class,
                                   std::string_view match_type) {
    flatbuffers::FlatBufferBuilder fbb;
    auto annotations = BuildSingleAnnotationsMatcher(fbb, annotation_class, match_type);
    // ClassMatcher: smali_source, class_name, access_flags, super_class,
    //               interfaces, annotations(6), fields, methods, ...
    auto class_matcher = dexkit::schema::CreateClassMatcher(
        fbb, 0, 0, 0, 0, 0, annotations);
    auto find = dexkit::schema::CreateFindClass(
        fbb, 0, 0, false, 0, false, class_matcher);
    fbb.Finish(find);
    auto query = ::flatbuffers::GetRoot<dexkit::schema::FindClass>(fbb.GetBufferPointer());
    auto result = core_->FindClass(query);
    auto holder = ::flatbuffers::GetRoot<dexkit::schema::ClassMetaArrayHolder>(
        result->GetBufferPointer());
    return ParseClassMetaArray(holder);
}

std::vector<MethodMatch>
DexKitExt::FindMethodsByAnnotation(std::string_view annotation_class,
                                   std::string_view match_type) {
    flatbuffers::FlatBufferBuilder fbb;
    auto annotations = BuildSingleAnnotationsMatcher(fbb, annotation_class, match_type);
    // MethodMatcher: method_name, access_flags, declaring_class, return_type,
    //                parameters, annotations(6), op_codes, using_strings, ...
    auto method_matcher = dexkit::schema::CreateMethodMatcher(
        fbb, 0, 0, 0, 0, 0, annotations);
    auto find = dexkit::schema::CreateFindMethod(
        fbb, 0, 0, false, 0, 0, false, method_matcher);
    fbb.Finish(find);
    auto query = ::flatbuffers::GetRoot<dexkit::schema::FindMethod>(fbb.GetBufferPointer());
    auto result = core_->FindMethod(query);
    auto holder = ::flatbuffers::GetRoot<dexkit::schema::MethodMetaArrayHolder>(
        result->GetBufferPointer());
    return ParseMethodMetaArray(holder);
}

std::vector<ClassMatch>
DexKitExt::FindClassesBySuperclass(std::string_view super_class_name,
                                   std::string_view match_type) {
    flatbuffers::FlatBufferBuilder fbb;
    auto super_name_matcher = dexkit::schema::CreateStringMatcher(
        fbb, fbb.CreateString(NormaliseClassNamePattern(super_class_name)),
        ParseStringMatchType(match_type), false);
    auto super_class_matcher = dexkit::schema::CreateClassMatcher(
        fbb, 0, super_name_matcher);
    // ClassMatcher: smali_source(1), class_name(2), access_flags(3), super_class(4)
    auto class_matcher = dexkit::schema::CreateClassMatcher(
        fbb, 0, 0, 0, super_class_matcher);
    auto find = dexkit::schema::CreateFindClass(
        fbb, 0, 0, false, 0, false, class_matcher);
    fbb.Finish(find);
    auto query = ::flatbuffers::GetRoot<dexkit::schema::FindClass>(fbb.GetBufferPointer());
    auto result = core_->FindClass(query);
    auto holder = ::flatbuffers::GetRoot<dexkit::schema::ClassMetaArrayHolder>(
        result->GetBufferPointer());
    return ParseClassMetaArray(holder);
}

std::vector<ClassMatch>
DexKitExt::FindClassesImplementing(std::string_view interface_class_name,
                                   std::string_view match_type) {
    flatbuffers::FlatBufferBuilder fbb;
    auto iface_name_matcher = dexkit::schema::CreateStringMatcher(
        fbb, fbb.CreateString(NormaliseClassNamePattern(interface_class_name)),
        ParseStringMatchType(match_type), false);
    auto iface_class_matcher = dexkit::schema::CreateClassMatcher(
        fbb, 0, iface_name_matcher);
    auto interfaces_matcher = dexkit::schema::CreateInterfacesMatcher(
        fbb,
        fbb.CreateVector(std::vector<flatbuffers::Offset<dexkit::schema::ClassMatcher>>{iface_class_matcher}),
        dexkit::schema::MatchType::Contains);
    // ClassMatcher: ..., interfaces(5), ...
    auto class_matcher = dexkit::schema::CreateClassMatcher(
        fbb, 0, 0, 0, 0, interfaces_matcher);
    auto find = dexkit::schema::CreateFindClass(
        fbb, 0, 0, false, 0, false, class_matcher);
    fbb.Finish(find);
    auto query = ::flatbuffers::GetRoot<dexkit::schema::FindClass>(fbb.GetBufferPointer());
    auto result = core_->FindClass(query);
    auto holder = ::flatbuffers::GetRoot<dexkit::schema::ClassMetaArrayHolder>(
        result->GetBufferPointer());
    return ParseClassMetaArray(holder);
}

std::vector<MethodMatch>
DexKitExt::FindMethodsUsingIntLiterals(const std::vector<int64_t>& values) {
    flatbuffers::FlatBufferBuilder fbb;
    std::vector<dexkit::schema::Number> types;
    std::vector<flatbuffers::Offset<void>> vals;
    types.reserve(values.size());
    vals.reserve(values.size());
    for (auto v : values) {
        // Mask to int32_t to match dex int storage (so 0xCAFEBABE works
        // identically to its signed-32 interpretation -889275714).
        types.push_back(dexkit::schema::Number::EncodeValueInt);
        vals.push_back(dexkit::schema::CreateEncodeValueInt(
            fbb, static_cast<int32_t>(v)).Union());
    }
    auto types_vec = fbb.CreateVector(types);
    auto vals_vec = fbb.CreateVector(vals);
    // MethodMatcher: ..., using_numbers_type(10), using_numbers(11), ...
    auto method_matcher = dexkit::schema::CreateMethodMatcher(
        fbb, 0, 0, 0, 0, 0, 0, 0, 0, 0, types_vec, vals_vec);
    auto find = dexkit::schema::CreateFindMethod(
        fbb, 0, 0, false, 0, 0, false, method_matcher);
    fbb.Finish(find);
    auto query = ::flatbuffers::GetRoot<dexkit::schema::FindMethod>(fbb.GetBufferPointer());
    auto result = core_->FindMethod(query);
    auto holder = ::flatbuffers::GetRoot<dexkit::schema::MethodMetaArrayHolder>(
        result->GetBufferPointer());
    return ParseMethodMetaArray(holder);
}

std::vector<MethodMatch>
DexKitExt::FindMethodsUsingDoubleLiterals(const std::vector<double>& values) {
    flatbuffers::FlatBufferBuilder fbb;
    std::vector<dexkit::schema::Number> types;
    std::vector<flatbuffers::Offset<void>> vals;
    types.reserve(values.size());
    vals.reserve(values.size());
    for (auto v : values) {
        types.push_back(dexkit::schema::Number::EncodeValueDouble);
        vals.push_back(dexkit::schema::CreateEncodeValueDouble(fbb, v).Union());
    }
    auto types_vec = fbb.CreateVector(types);
    auto vals_vec = fbb.CreateVector(vals);
    auto method_matcher = dexkit::schema::CreateMethodMatcher(
        fbb, 0, 0, 0, 0, 0, 0, 0, 0, 0, types_vec, vals_vec);
    auto find = dexkit::schema::CreateFindMethod(
        fbb, 0, 0, false, 0, 0, false, method_matcher);
    fbb.Finish(find);
    auto query = ::flatbuffers::GetRoot<dexkit::schema::FindMethod>(fbb.GetBufferPointer());
    auto result = core_->FindMethod(query);
    auto holder = ::flatbuffers::GetRoot<dexkit::schema::MethodMetaArrayHolder>(
        result->GetBufferPointer());
    return ParseMethodMetaArray(holder);
}

void DexKitExt::WarmAnalysisCaches() {
    if (analysis_caches_warm_) return;
    // For L2 we need kMethodInvoking populated. InitFullCache warms everything;
    // safest and matches upstream's intended pattern. Subsequent L4/L6 work can
    // reuse the same warm state.
    core_->InitFullCache();
    analysis_caches_warm_ = true;
}

namespace {

const char* ArgKindName(dexkit::DexItem::ArgKind k) {
    using K = dexkit::DexItem::ArgKind;
    switch (k) {
        case K::ConstString:  return "ConstString";
        case K::ConstInt:     return "ConstInt";
        case K::ConstWide:    return "ConstWide";
        case K::ConstClass:   return "ConstClass";
        case K::ConstNull:    return "ConstNull";
        case K::FieldRead:    return "FieldRead";
        case K::MethodReturn: return "MethodReturn";
        case K::Parameter:    return "Parameter";
        case K::NewInstance:  return "NewInstance";
        case K::NewArray:     return "NewArray";
        default:              return "Unknown";
    }
}

// Build "Lcls;->name:Type" for a field_idx in a given dex.
std::string BuildFieldSignature(const dexkit::DexItem& item, uint32_t field_idx) {
    const auto& reader = item.GetReader();
    const auto& type_names = item.GetTypeNames();
    const auto& strings = item.GetStrings();
    const auto field_ids = reader.FieldIds();
    if (field_idx >= field_ids.size()) return {};
    const auto& f = field_ids[field_idx];
    std::string out;
    out += std::string(type_names[f.class_idx]);
    out += "->";
    out += std::string(strings[f.name_idx]);
    out += ':';
    out += std::string(type_names[f.type_idx]);
    return out;
}

ArgOrigin ConvertArg(const dexkit::DexItem& item,
                     const dexkit::DexItem::InvokeArg& src) {
    ArgOrigin o;
    o.kind = ArgKindName(src.kind);
    o.reg_num = src.reg_num;
    const auto& reader = item.GetReader();
    const auto& strings = item.GetStrings();
    const auto& type_names = item.GetTypeNames();
    using K = dexkit::DexItem::ArgKind;
    switch (src.kind) {
        case K::ConstString:
            if (src.string_idx < strings.size())
                o.string_value = std::string(strings[src.string_idx]);
            break;
        case K::ConstInt:
        case K::ConstWide:
            o.int_value = src.int_value;
            break;
        case K::ConstClass:
        case K::NewInstance:
        case K::NewArray:
            if (src.type_idx < type_names.size())
                o.class_descriptor = std::string(type_names[src.type_idx]);
            break;
        case K::FieldRead:
            o.field_signature = BuildFieldSignature(item, src.field_idx);
            break;
        case K::MethodReturn:
            o.method_signature =
                BuildMethodSignature(item, src.method_idx);
            break;
        case K::Parameter:
            o.parameter_index = src.parameter_index;
            break;
        case K::ConstNull:
        case K::Unknown:
        default:
            break;
    }
    return o;
}

}  // namespace

std::vector<ResolvedCallSite>
DexKitExt::ResolveCallArgs(std::string_view api_descriptor) {
    std::vector<ResolvedCallSite> out;

    std::string_view target_class, target_name, target_proto;
    if (!ParseApiDescriptor(api_descriptor, target_class, target_name, target_proto)) {
        return out;
    }

    WarmAnalysisCaches();

    const int dex_num = core_->GetDexNum();
    for (int i = 0; i < dex_num; ++i) {
        auto* item_ptr = core_->GetDexItem(static_cast<uint16_t>(i));
        if (item_ptr == nullptr) continue;
        const auto& item = *item_ptr;

        uint32_t cls_type_idx = FindTypeIdx(item, target_class);
        if (cls_type_idx == dex::kNoIndex) continue;
        uint32_t target_method_idx =
            FindMethodIdx(item, cls_type_idx, target_name, target_proto);
        if (target_method_idx == dex::kNoIndex) continue;

        const auto& invoking = item.GetMethodInvokingIds();
        for (size_t caller_idx = 0; caller_idx < invoking.size(); ++caller_idx) {
            bool any_match = false;
            for (uint32_t callee_idx : invoking[caller_idx]) {
                if (callee_idx == target_method_idx) { any_match = true; break; }
            }
            if (!any_match) continue;

            auto sites = item.AnalyzeMethodInvokes(static_cast<uint32_t>(caller_idx));
            std::string caller_sig =
                BuildMethodSignature(item, static_cast<uint32_t>(caller_idx));
            for (const auto& s : sites) {
                if (s.method_idx != target_method_idx) continue;
                ResolvedCallSite cs;
                cs.caller_dex_id = item.GetDexId();
                cs.caller_method_idx = static_cast<uint32_t>(caller_idx);
                cs.caller_descriptor = caller_sig;
                cs.callee_descriptor = std::string(api_descriptor);
                cs.bytecode_offset = static_cast<int32_t>(s.bytecode_offset);
                cs.invoke_opcode = s.opcode;
                cs.args.reserve(s.args.size());
                for (const auto& a : s.args) {
                    cs.args.push_back(ConvertArg(item, a));
                }
                out.push_back(std::move(cs));
            }
        }
    }
    return out;
}

std::vector<CallSite>
DexKitExt::FindCallSitesToApi(std::string_view api_descriptor) {
    std::vector<CallSite> out;

    std::string_view target_class, target_name, target_proto;
    if (!ParseApiDescriptor(api_descriptor, target_class, target_name, target_proto)) {
        return out;  // malformed input → empty result
    }

    WarmAnalysisCaches();

    const int dex_num = core_->GetDexNum();
    for (int i = 0; i < dex_num; ++i) {
        auto* item_ptr = core_->GetDexItem(static_cast<uint16_t>(i));
        if (item_ptr == nullptr) continue;
        const auto& item = *item_ptr;

        // Step 1: does this dex even reference the target class?
        uint32_t cls_type_idx = FindTypeIdx(item, target_class);
        if (cls_type_idx == dex::kNoIndex) continue;

        // Step 2: locate the exact method_idx within this dex's MethodIds.
        uint32_t target_method_idx =
            FindMethodIdx(item, cls_type_idx, target_name, target_proto);
        if (target_method_idx == dex::kNoIndex) continue;

        // Step 3: scan caller→callees map for this target. method_invoking_ids
        // gives us only candidate callers; the per-site offsets come from
        // walking each candidate's bytecode (L2.5).
        const auto& invoking = item.GetMethodInvokingIds();
        for (size_t caller_idx = 0; caller_idx < invoking.size(); ++caller_idx) {
            bool any_match = false;
            for (uint32_t callee_idx : invoking[caller_idx]) {
                if (callee_idx == target_method_idx) { any_match = true; break; }
            }
            if (!any_match) continue;

            // Walk caller's instruction stream to recover each invoke's
            // byte_offset + invoke_opcode.
            auto sites = item.EnumerateInvokeSites(static_cast<uint32_t>(caller_idx));
            std::string caller_sig =
                BuildMethodSignature(item, static_cast<uint32_t>(caller_idx));
            for (const auto& s : sites) {
                if (s.method_idx != target_method_idx) continue;
                CallSite cs;
                cs.caller_dex_id = item.GetDexId();
                cs.caller_method_idx = static_cast<uint32_t>(caller_idx);
                cs.caller_descriptor = caller_sig;
                cs.callee_descriptor = std::string(api_descriptor);
                cs.bytecode_offset = static_cast<int32_t>(s.bytecode_offset);
                cs.invoke_opcode = s.opcode;
                out.push_back(std::move(cs));
            }
        }
    }
    return out;
}

}  // namespace dexkit::ext
