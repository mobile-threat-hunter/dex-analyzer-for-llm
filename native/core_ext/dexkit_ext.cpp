#include "dexkit_ext.h"

#include <algorithm>
#include <array>
#include <cstring>  // memcmp (raw-dex magic sniff)
#include <map>
#include <set>
#include <stdexcept>
#include <string>
#include <string_view>
#include <unordered_set>
#include <utility>

#include "analyze.h"  // kMethodInvoking et al.
#include "dex_verifier.h"  // VerifyDex — load-boundary structural gate
#include "dexitem_code_source.h"  // for GetCodeSource()
#include "mmap.h"  // dexkit::MemMap (raw-dex load path)
#include "schema/querys_generated.h"
#include "zip_archive.h"  // dexkit::ZipArchive (PK/central-dir container probe)
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
// PRECONDITION: the DexItem was loaded through DexKitExt, i.e. its dex passed
// dexkit::ext::VerifyDex — so the type_list type_idx values and return_type_idx
// are in range and the indexing below is unchecked by design (the load-boundary
// verifier owns that bound; see native/core_ext/dex_verifier.h).
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

namespace {

// A standard .dex starts with the magic "dex\n" (0x64 0x65 0x78 0x0a); a
// zip/apk/jar starts with "PK". The core's apk_path constructor only opens
// zip containers, so we sniff the header and load a bare .dex directly via
// AddImage (which mmaps the file and parses its logical dex offsets).
bool LooksLikeRawDex(const dexkit::MemMap& map) {
    return map.ok() && map.len() >= 4 && std::memcmp(map.data(), "dex\n", 4) == 0;
}

// Count the sequential classes.dex / classes2.dex / ... entries the loader would
// actually pick up. Mirrors DexKit::AddZipPath's "stop at the first gap" rule so
// the reported dex_count equals what gets loaded.
int CountClassesDex(const dexkit::ZipArchive& za) {
    int count = 0;
    for (int idx = 1;; ++idx) {
        auto name = "classes" + (idx == 1 ? std::string() : std::to_string(idx)) + ".dex";
        if (za.Find(name) == nullptr) break;
        ++count;
    }
    return count;
}

// One content-based classification of a path, shared by Identify() (which
// reports) and the constructor (which loads) so the detection rule lives in ONE
// place and the two can't drift. `map` is always populated — even when not ok —
// so the caller can distinguish "can't open (missing/empty)" from "opened but not
// a recognized container". `za` (held for the zip load path) borrows `map`, so it
// is declared after `map` → destroyed before it.
struct Probe {
    std::unique_ptr<dexkit::MemMap> map;
    std::unique_ptr<dexkit::ZipArchive> za;
    std::string format = "unknown";  // "dex" | "zip" | "unknown"
    int dex_count = 0;
    bool has_manifest = false;
};

Probe ProbeContainer(const std::string& path) {
    Probe p;
    p.map = std::make_unique<dexkit::MemMap>(path);
    if (!p.map->ok()) return p;  // unknown: missing or empty
    if (LooksLikeRawDex(*p.map)) {
        p.format = "dex";
        p.dex_count = 1;
        return p;
    }
    // Not a raw .dex — prove a zip/apk by content (PK signature + parseable
    // central directory), not by extension.
    p.za = dexkit::ZipArchive::Open(*p.map);
    if (!p.za) return p;  // unknown: not a zip either
    p.format = "zip";
    p.has_manifest = p.za->Find("AndroidManifest.xml") != nullptr;
    p.dex_count = CountClassesDex(*p.za);
    return p;
}

}  // namespace

ContainerInfo DexKitExt::Identify(const std::string& path) {
    Probe p = ProbeContainer(path);
    ContainerInfo info;
    info.format = p.format;
    info.dex_count = p.dex_count;
    info.has_manifest = p.has_manifest;
    info.is_apk = p.has_manifest;  // a zip carrying an AndroidManifest.xml
    return info;
}

void DexKitExt::CollectSource(const std::string& path, bool check_insns,
                             std::vector<std::unique_ptr<dexkit::MemMap>>& out) {
    Probe p = ProbeContainer(path);  // one content-based classification

    if (p.format == "unknown") {
        if (!p.map->ok()) {  // ProbeContainer always sets map; ok() distinguishes
            throw std::runtime_error(
                "dexllm: cannot open '" + path + "' (file not found or empty)");
        }
        throw std::runtime_error(
            "dexllm: '" + path + "' is neither a .dex (no 'dex\\n' magic) nor a "
            "zip/apk container (no PK signature / invalid central directory)");
    }

    if (p.format == "dex") {
        // Structural gate (DexVerifier) BEFORE the core parses the image — a
        // malformed dex is screened out here so the core/slicer never touch it.
        auto vr = VerifyDex(reinterpret_cast<const uint8_t*>(p.map->data()),
                            p.map->len(), check_insns);
        verify_status_.push_back(
            {static_cast<int>(out.size()), path, vr.ok, vr.reason});
        if (!vr.ok) {
            throw std::runtime_error(
                "dexllm: '" + path + "' failed dex verification: " + vr.reason);
        }
        out.push_back(std::move(p.map));
        return;
    }

    // p.format == "zip": extract each classes*.dex, verify at the load boundary,
    // and feed only structurally-valid dexes to the core via AddImage. This
    // replaces the core's internal zip loader (DexKit(apk_path) → AddZipPath) so a
    // malformed dex is screened out *before* the core parses it — no vendored-core
    // change. A rejected dex is recorded (verify_report) and skipped; sibling
    // dexes in the multidex still load (per-dex rejection).
    if (p.dex_count == 0) {
        throw std::runtime_error(
            "dexllm: zip container '" + path + "' has no classes*.dex to decompile "
            "(AndroidManifest.xml " + (p.has_manifest ? "present" : "absent") + ")");
    }
    const size_t before = out.size();
    for (int idx = 1; idx <= p.dex_count; ++idx) {
        auto name = "classes" + (idx == 1 ? std::string() : std::to_string(idx)) + ".dex";
        const auto* entry = p.za->Find(name);
        if (entry == nullptr) continue;  // counted by ProbeContainer; defensive
        auto mm = p.za->GetUncompressData(*entry);
        if (!mm.ok()) {
            verify_status_.push_back({-1, name, false, "decompression failed"});
            continue;
        }
        auto vr = VerifyDex(reinterpret_cast<const uint8_t*>(mm.data()), mm.len(),
                            check_insns);
        if (!vr.ok) {
            verify_status_.push_back({-1, name, false, vr.reason});
            continue;
        }
        verify_status_.push_back({static_cast<int>(out.size()), name, true, {}});
        out.push_back(std::make_unique<dexkit::MemMap>(std::move(mm)));
    }
    if (out.size() == before) {
        throw std::runtime_error(
            "dexllm: all " + std::to_string(p.dex_count) + " dex(es) in '" + path +
            "' failed verification");
    }
}

DexKitExt::DexKitExt(const std::string& apk_path, bool lenient)
    : apk_path_(apk_path), sources_{apk_path} {
    core_ = std::make_unique<dexkit::DexKit>();
    std::vector<std::unique_ptr<dexkit::MemMap>> valid_dexes;
    CollectSource(apk_path, /*check_insns=*/!lenient, valid_dexes);
    core_->AddImage(std::move(valid_dexes));
}

DexKitExt::DexKitExt(const std::vector<std::string>& sources, bool lenient)
    : apk_path_(sources.empty() ? std::string{} : sources.front()),
      sources_(sources) {
    if (sources.empty()) {
        throw std::runtime_error("dexllm: no dex sources given");
    }
    core_ = std::make_unique<dexkit::DexKit>();
    // Load sources in order — earlier sources get lower dex_ids, so first-wins
    // resolution prefers them (load a decrypted/dumped dex first to win).
    std::vector<std::unique_ptr<dexkit::MemMap>> valid_dexes;
    for (const auto& src : sources) {
        CollectSource(src, /*check_insns=*/!lenient, valid_dexes);
    }
    core_->AddImage(std::move(valid_dexes));
}

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

namespace {

// Minimal leb/int readers for the static-values EncodedArray scan. Bounded:
// never read past `end` (the mmap tail). Mirrors the byte layout the tested
// DecodeEncodedValueText uses, but collects string indices instead of text.
uint64_t ScanUleb(const uint8_t*& p, const uint8_t* end) {
    uint64_t result = 0;
    int shift = 0;
    while (p < end && shift < 64) {
        uint8_t b = *p++;
        result |= static_cast<uint64_t>(b & 0x7f) << shift;
        if ((b & 0x80) == 0) break;
        shift += 7;
    }
    return result;
}
uint64_t ScanIntLE(const uint8_t*& p, const uint8_t* end, size_t nbytes) {
    uint64_t v = 0;
    for (size_t i = 0; i < nbytes && p < end; ++i) v |= static_cast<uint64_t>(*p++) << (i * 8);
    return v;
}

// Collect VALUE_STRING (0x17) string indices from one encoded_value, recursing
// into ARRAY (0x1c) and ANNOTATION (0x1d). All other types only advance the
// cursor by their fixed payload (idx/number = value_arg+1 bytes; NULL/BOOLEAN 0).
void ScanEncodedValueStrings(const uint8_t*& p, const uint8_t* end,
                             std::vector<uint32_t>& out) {
    if (p >= end) return;
    uint8_t header = *p++;
    uint8_t value_arg = (header >> 5) & 0x07;
    uint8_t value_type = header & 0x1F;
    size_t nbytes = static_cast<size_t>(value_arg) + 1;
    switch (value_type) {
        case 0x17:  // STRING
            out.push_back(static_cast<uint32_t>(ScanIntLE(p, end, nbytes)));
            return;
        case 0x1c: {  // ARRAY
            uint64_t sz = ScanUleb(p, end);
            for (uint64_t i = 0; i < sz && p < end; ++i) ScanEncodedValueStrings(p, end, out);
            return;
        }
        case 0x1d: {  // ANNOTATION — type_idx, size, size*(name_idx, value)
            (void)ScanUleb(p, end);
            uint64_t sz = ScanUleb(p, end);
            for (uint64_t i = 0; i < sz && p < end; ++i) {
                (void)ScanUleb(p, end);  // name_idx
                ScanEncodedValueStrings(p, end, out);
            }
            return;
        }
        case 0x1e:  // NULL
        case 0x1f:  // BOOLEAN — value encoded in value_arg, no payload bytes
            return;
        default: {  // BYTE/SHORT/CHAR/INT/LONG/FLOAT/DOUBLE/TYPE/FIELD/METHOD/ENUM
            size_t avail = static_cast<size_t>(p < end ? end - p : 0);
            p += std::min(nbytes, avail);
            return;
        }
    }
}

}  // namespace

std::vector<std::string> DexKitExt::ListValueStrings() const {
    std::vector<std::string> out;
    std::unordered_set<std::string_view> seen;
    auto& mut = const_cast<dexkit::DexKit&>(*core_);
    const int n = core_->GetDexNum();
    for (int i = 0; i < n; ++i) {
        auto* item = mut.GetDexItem(static_cast<uint16_t>(i));
        if (!item) continue;
        const auto& strings = item->GetStrings();
        const auto& reader = item->GetReader();
        auto add = [&](uint32_t sid) {
            if (sid < strings.size() && seen.insert(strings[sid]).second)
                out.emplace_back(strings[sid]);
        };
        // (a) const-string / const-string-jumbo — union over every method's code.
        // GetUsingStrings is the public accessor (lazy-builds the const-string
        // index per method if needed) and hands back the strings directly.
        const uint32_t method_count = reader.MethodIds().size();
        for (uint32_t m = 0; m < method_count; ++m)
            for (std::string_view s : item->GetUsingStrings(m))
                if (seen.insert(s).second) out.emplace_back(s);
        // (b) static-field-initializer EncodedValue VALUE_STRING (0x17).
        const uint8_t* mmap_end = nullptr;
        if (auto* img = item->GetImage())
            mmap_end = reinterpret_cast<const uint8_t*>(img->data()) + img->len();
        for (const auto& cdef : reader.ClassDefs()) {
            if (cdef.static_values_off == 0) continue;
            const uint8_t* p = reader.dataPtr<uint8_t>(cdef.static_values_off);
            if (!p) continue;
            const uint8_t* end = mmap_end ? mmap_end : p + (1u << 20);
            if (p >= end) continue;
            uint64_t count = ScanUleb(p, end);
            std::vector<uint32_t> ids;
            for (uint64_t k = 0; k < count && p < end; ++k)
                ScanEncodedValueStrings(p, end, ids);
            for (uint32_t sid : ids) add(sid);
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
        desc += BuildProtoDescriptor(*dex_item, proto_ids[m.proto_idx]);
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

// (method_idx resolution is now indexed — see FindMethodIdxIndexed + ApiResolveIndex.)

// Build "Lcom/x/Y;->foo(I)V" for a method_idx in a given dex.
std::string BuildMethodSignature(const dexkit::DexItem& item, uint32_t method_idx) {
    const auto& reader = item.GetReader();
    const auto& type_names = item.GetTypeNames();
    const auto& strings = item.GetStrings();
    // Bound the index (mirrors BuildFieldSignature). method_idx can be a raw
    // invoke operand (ArgOrigin MethodReturn → last_invoke_callee), which lenient
    // mode leaves unvalidated; an OOB index here would OOB-read MethodIds().
    if (method_idx >= reader.MethodIds().size()) return {};
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

void DexKitExt::EnsureApiResolveIndex() {
    // Lazy one-shot build guarded by a plain bool (no mutex), matching the sibling
    // WarmAnalysisCaches. THREAD-SAFETY PRECONDITION: every caller-analysis entry
    // point (find_call_sites_to_api / resolve_call_args / permission_callers) is
    // bound WITHOUT py::gil_scoped_release, so the GIL serializes them and this
    // build runs exactly once with no data race. The
    // decompile paths that DO release the GIL never touch api_resolve_index_. If any
    // caller-analysis binding is ever given gil_scoped_release, this build (and
    // WarmAnalysisCaches) must first gain a std::once_flag / mutex.
    if (api_resolve_index_built_) return;
    const int dex_num = core_->GetDexNum();
    api_resolve_index_.resize(static_cast<size_t>(dex_num));
    for (int i = 0; i < dex_num; ++i) {
        auto* item_ptr = core_->GetDexItem(static_cast<uint16_t>(i));
        if (item_ptr == nullptr) continue;
        const auto& item = *item_ptr;
        auto& idx = api_resolve_index_[static_cast<size_t>(i)];

        // type_name → type_idx (unique; emplace keeps the first/lowest idx, matching
        // FindTypeIdx's first-match). Keys are string_views into the dex mmap, which
        // outlives this index (DexItem lifetime == DexKit lifetime).
        const auto& type_names = item.GetTypeNames();
        idx.type_to_idx.reserve(type_names.size());
        for (size_t t = 0; t < type_names.size(); ++t)
            idx.type_to_idx.emplace(type_names[t], static_cast<uint32_t>(t));

        // class_idx → its method_idxs, in ascending method_idx order (method_ids are
        // spec-sorted, so pushing in index order keeps each list ascending). Covers
        // ALL method refs, incl. referenced-only framework methods (unlike the core's
        // class_method_ids, which holds only methods with a ClassData body).
        const auto method_ids = item.GetReader().MethodIds();
        for (size_t m = 0; m < method_ids.size(); ++m)
            idx.class_methods[method_ids[m].class_idx].push_back(
                static_cast<uint32_t>(m));
    }
    api_resolve_index_built_ = true;
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

// O(1) counterparts of FindTypeIdx / FindMethodIdx using a prebuilt ApiResolveIndex
// (see dexkit_ext.h). Byte-identical to the linear scans: the type map is an exact
// bijection (unique descriptors) and the per-class method list is ascending, so the
// first name+proto match equals FindMethodIdx's first ascending match.
uint32_t FindTypeIdxIndexed(const ApiResolveIndex& idx, std::string_view desc) {
    auto it = idx.type_to_idx.find(desc);
    return it == idx.type_to_idx.end() ? dex::kNoIndex : it->second;
}
uint32_t FindMethodIdxIndexed(const dexkit::DexItem& item, const ApiResolveIndex& idx,
                              uint32_t class_idx, std::string_view name,
                              std::string_view proto) {
    auto it = idx.class_methods.find(class_idx);
    if (it == idx.class_methods.end()) return dex::kNoIndex;
    const auto& reader = item.GetReader();
    const auto& strings = item.GetStrings();
    const auto method_ids = reader.MethodIds();
    const auto proto_ids = reader.ProtoIds();
    for (uint32_t mi : it->second) {  // ascending → first match = FindMethodIdx contract
        const auto& m = method_ids[mi];
        if (strings[m.name_idx] != name) continue;
        if (BuildProtoDescriptor(item, proto_ids[m.proto_idx]) != proto) continue;
        return mi;
    }
    return dex::kNoIndex;
}

// One resolved caller of a target API: the dex the caller LIVES in, its method_idx
// there, and the target's method_idx IN THAT dex (for the per-site filter).
struct CallerRef {
    const dexkit::DexItem* item;
    uint32_t caller_idx;
    uint32_t local_target;
};

// Resolve every caller of the target API across all dexes via the callee→callers
// REVERSE index (O(callers), not the old O(all-methods) scan), honouring DexKit's
// cross-dex aggregation: BuildCrossRefAggregates MOVES an app-declared method's
// callers into its DECLARING dex — tagged with their SOURCE dex_id — and clears the
// source list. So each caller entry (origin_dex, caller_idx) must be walked in its
// ORIGIN dex, with the target re-resolved to that dex's own method_idx (mirroring
// DexItem::GetCallMethods' ori_dex_id branch). For a framework/undeclared target no
// aggregation happens (each dex keeps its own callers, origin == that dex), so this
// reduces to the old per-dex behaviour. Emission order matches the old full scan:
// dexes ascending, then (origin_dex, caller_idx) ascending.
std::vector<CallerRef> CollectApiCallers(dexkit::DexKit* core,
                                         const std::vector<ApiResolveIndex>& resolve_index,
                                         std::string_view target_class,
                                         std::string_view target_name,
                                         std::string_view target_proto) {
    std::vector<CallerRef> out;
    const int dex_num = core->GetDexNum();
    for (int i = 0; i < dex_num; ++i) {
        auto* item_ptr = core->GetDexItem(static_cast<uint16_t>(i));
        if (item_ptr == nullptr) continue;
        const auto& item = *item_ptr;
        if (static_cast<size_t>(i) >= resolve_index.size()) continue;
        const auto& idx = resolve_index[i];

        uint32_t cls_type_idx = FindTypeIdxIndexed(idx, target_class);
        if (cls_type_idx == dex::kNoIndex) continue;
        uint32_t target_method_idx =
            FindMethodIdxIndexed(item, idx, cls_type_idx, target_name, target_proto);
        if (target_method_idx == dex::kNoIndex) continue;

        const auto& caller_index = item.GetMethodCallerIds();
        if (target_method_idx >= caller_index.size()) continue;
        // Dedup by (origin_dex, caller_idx) — the raw index lists a caller once per
        // invoke site; ascending order matches the old per-dex ascending scan.
        std::vector<std::pair<uint16_t, uint32_t>> callers(
            caller_index[target_method_idx].begin(),
            caller_index[target_method_idx].end());
        std::sort(callers.begin(), callers.end());
        callers.erase(std::unique(callers.begin(), callers.end()), callers.end());

        // Cross-dex callers share their origin dex's target method_idx — resolve it
        // ONCE per origin group (callers are sorted by origin_dex), not per caller.
        int cached_origin = -1;
        const dexkit::DexItem* cached_item = nullptr;
        uint32_t cached_target = dex::kNoIndex;
        for (const auto& [origin_dex, caller_idx] : callers) {
            if (origin_dex == item.GetDexId()) {
                out.push_back({&item, caller_idx, target_method_idx});
                continue;
            }
            // Cross-dex caller: walk it in its OWN dex, filtering on the target's
            // method_idx as seen from THAT dex (the caller invoked the target via
            // its own dex's method ref).
            if (origin_dex != cached_origin) {
                cached_origin = origin_dex;
                cached_item = core->GetDexItem(origin_dex);
                cached_target = dex::kNoIndex;
                if (cached_item != nullptr &&
                    origin_dex < resolve_index.size()) {
                    const auto& oidx = resolve_index[origin_dex];
                    uint32_t oct = FindTypeIdxIndexed(oidx, target_class);
                    if (oct != dex::kNoIndex)
                        cached_target = FindMethodIdxIndexed(*cached_item, oidx, oct,
                                                             target_name, target_proto);
                }
            }
            if (cached_item == nullptr || cached_target == dex::kNoIndex) continue;
            out.push_back({cached_item, caller_idx, cached_target});
        }
    }
    // Final global order = (caller's LIVING dex, caller_idx) — exactly the old
    // forward scan's order (dex-ascending outer loop, caller-ascending inner). Within
    // one declaring/framework group the emission is already in this order, so this is
    // a no-op for the common single-declaring-dex and framework targets. It only
    // reorders the pathological case a single per-group emission cannot: a class
    // declared with a body in TWO+ dexes (multi-source / add_dumped_dexes(prefer) /
    // packer dump), where reference-only callers aggregate into the LOWEST declaring
    // dex while a higher declaring dex keeps its own — two groups emit, breaking the
    // global (living-dex, caller_idx) order. Sorting here makes list order a stable
    // contract matching the pre-redesign scan in ALL cases (keys are unique — each
    // caller is emitted once — so a plain sort is a total order).
    std::sort(out.begin(), out.end(), [](const CallerRef& a, const CallerRef& b) {
        uint32_t da = a.item->GetDexId(), db = b.item->GetDexId();
        if (da != db) return da < db;
        return a.caller_idx < b.caller_idx;
    });
    return out;
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
    EnsureApiResolveIndex();

    for (const auto& cr : CollectApiCallers(core_.get(), api_resolve_index_, target_class,
                                            target_name, target_proto)) {
        const auto& item = *cr.item;
        auto sites = item.AnalyzeMethodInvokes(cr.caller_idx);
        std::string caller_sig = BuildMethodSignature(item, cr.caller_idx);
        for (const auto& s : sites) {
            if (s.method_idx != cr.local_target) continue;
            ResolvedCallSite cs;
            cs.caller_dex_id = item.GetDexId();
            cs.caller_method_idx = cr.caller_idx;
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
    EnsureApiResolveIndex();

    // The callee→callers reverse index gives the target's callers directly
    // (O(callers), not the old O(all-methods) scan); CollectApiCallers resolves each
    // caller in its own dex (honouring cross-dex aggregation) via api_resolve_index_
    // (O(1) target lookup). Walk each caller's bytecode for the per-site byte_offset
    // + opcode → identical output.
    for (const auto& cr : CollectApiCallers(core_.get(), api_resolve_index_, target_class,
                                            target_name, target_proto)) {
        const auto& item = *cr.item;
        auto sites = item.EnumerateInvokeSites(cr.caller_idx);
        std::string caller_sig = BuildMethodSignature(item, cr.caller_idx);
        for (const auto& s : sites) {
            if (s.method_idx != cr.local_target) continue;
            CallSite cs;
            cs.caller_dex_id = item.GetDexId();
            cs.caller_method_idx = cr.caller_idx;
            cs.caller_descriptor = caller_sig;
            cs.callee_descriptor = std::string(api_descriptor);
            cs.bytecode_offset = static_cast<int32_t>(s.bytecode_offset);
            cs.invoke_opcode = s.opcode;
            out.push_back(std::move(cs));
        }
    }
    return out;
}

std::vector<CallSite>
DexKitExt::FindCallSitesFromMethod(std::string_view method_descriptor) {
    std::vector<CallSite> out;

    std::string_view cls, name, proto;
    if (!ParseApiDescriptor(method_descriptor, cls, name, proto)) return out;

    // The method's body (and its invoke instructions) lives in the dex that DECLARES
    // its class (first-wins). An external / bodyless method has no callees here.
    const int dex_id = LocateClassDex(cls);
    if (dex_id < 0) return out;
    auto* item_ptr = core_->GetDexItem(static_cast<uint16_t>(dex_id));
    if (item_ptr == nullptr) return out;
    const auto& item = *item_ptr;

    EnsureApiResolveIndex();  // FindTypeIdxIndexed / FindMethodIdxIndexed use it
    if (static_cast<size_t>(dex_id) >= api_resolve_index_.size()) return out;
    const auto& idx = api_resolve_index_[dex_id];

    uint32_t cls_type_idx = FindTypeIdxIndexed(idx, cls);
    if (cls_type_idx == dex::kNoIndex) return out;
    uint32_t m_idx = FindMethodIdxIndexed(item, idx, cls_type_idx, name, proto);
    if (m_idx == dex::kNoIndex) return out;

    // Walk the method's own invoke sites (the forward index of FindCallSitesToApi):
    // each site's method_idx is the callee IN THIS DEX. Per-invoke (not deduped),
    // mirroring FindCallSitesToApi's per-site output.
    std::string caller_sig = BuildMethodSignature(item, m_idx);
    for (const auto& s : item.AnalyzeMethodInvokes(m_idx)) {
        CallSite cs;
        cs.caller_dex_id = item.GetDexId();
        cs.caller_method_idx = m_idx;
        cs.caller_descriptor = caller_sig;
        cs.callee_descriptor = BuildMethodSignature(item, s.method_idx);
        cs.bytecode_offset = static_cast<int32_t>(s.bytecode_offset);
        cs.invoke_opcode = s.opcode;
        out.push_back(std::move(cs));
    }
    return out;
}

namespace {

// Locate a field descriptor `Lcls;->name:Type` → (dex_id, field_idx), or (-1, 0).
// Mirrors the WASM binding's LocateField: find the class's living dex (first-wins),
// then match the field against BuildFieldSignature across the class's field_ids.
std::pair<int, uint32_t> LocateField(DexKitExt& ext, std::string_view fd) {
    const auto arrow = fd.find("->");
    if (arrow == std::string_view::npos) return {-1, 0};
    const std::string cls(fd.substr(0, arrow));
    const int dex_id = ext.LocateClassDex(cls);
    if (dex_id < 0) return {-1, 0};
    auto* item = ext.core().GetDexItem(static_cast<uint16_t>(dex_id));
    if (item == nullptr) return {-1, 0};
    const auto& type_names = item->GetTypeNames();
    for (uint32_t type_idx = 0; type_idx < type_names.size(); ++type_idx) {
        if (type_names[type_idx] != cls) continue;
        for (uint32_t fid : item->GetClassFieldIds(type_idx)) {
            const std::string sig = BuildFieldSignature(*item, fid);
            if (std::string_view(sig) == fd) return {dex_id, fid};
        }
        break;  // type descriptors are unique — only one class matches
    }
    return {-1, 0};
}

// Readers (FieldGetMethods, writers=false) / writers (FieldPutMethods) of a field.
// THREAD-SAFETY PRECONDITION (same as the caller-analysis path): the exposed
// entry points (find_field_read_methods / find_field_write_methods) are bound
// WITHOUT py::gil_scoped_release, so the GIL serializes this lazy WarmAnalysisCaches
// warmup and the lazy GetMethodDescriptor population it feeds. Do NOT add
// gil_scoped_release to those bindings without adding a std::once_flag / mutex here.
std::vector<std::string> FieldAccessMethods(DexKitExt& ext, std::string_view fd,
                                            bool writers) {
    const auto loc = LocateField(ext, fd);
    if (loc.first < 0) return {};
    ext.WarmAnalysisCaches();  // field_get/put_method_ids need the full cache
    auto* item = ext.core().GetDexItem(static_cast<uint16_t>(loc.first));
    if (item == nullptr) return {};
    std::vector<std::string> out;
    const auto beans = writers ? item->FieldPutMethods(loc.second)
                               : item->FieldGetMethods(loc.second);
    out.reserve(beans.size());
    for (const auto& bean : beans) out.emplace_back(bean.dex_descriptor);
    return out;
}

}  // namespace

std::vector<std::string>
DexKitExt::FindFieldReadMethods(std::string_view field_descriptor) {
    return FieldAccessMethods(*this, field_descriptor, /*writers=*/false);
}

std::vector<std::string>
DexKitExt::FindFieldWriteMethods(std::string_view field_descriptor) {
    return FieldAccessMethods(*this, field_descriptor, /*writers=*/true);
}

TypeReferences DexKitExt::FindTypeReferences(std::string_view type_descriptor) {
    // Mirrors the WASM binding's findTypeReferences: a signature-position type xref
    // (fields OF the type, methods RETURNING it, methods TAKING it as a param). Scans
    // every dex — a type is referenced from other dexes too. Uses the shared
    // BuildFieldSignature / BuildMethodSignature so descriptors match every other API.
    TypeReferences out;
    const int dex_num = core_->GetDexNum();
    for (int d = 0; d < dex_num; ++d) {
        auto* item = core_->GetDexItem(static_cast<uint16_t>(d));
        if (item == nullptr) continue;
        const auto& type_names = item->GetTypeNames();
        uint32_t type_idx = dex::kNoIndex;
        for (uint32_t i = 0; i < type_names.size(); ++i) {
            if (type_names[i] == type_descriptor) { type_idx = i; break; }
        }
        if (type_idx == dex::kNoIndex) continue;
        const auto& reader = item->GetReader();
        const auto field_ids = reader.FieldIds();
        for (uint32_t fid = 0; fid < field_ids.size(); ++fid) {
            if (field_ids[fid].type_idx == type_idx)
                out.fields.push_back(BuildFieldSignature(*item, fid));
        }
        const auto method_ids = reader.MethodIds();
        const auto proto_ids = reader.ProtoIds();
        for (uint32_t mid = 0; mid < method_ids.size(); ++mid) {
            const auto& pdef = proto_ids[method_ids[mid].proto_idx];
            const bool returns = (pdef.return_type_idx == type_idx);
            bool param = false;
            if (pdef.parameters_off != 0) {
                const auto* tl = reader.dataPtr<dex::TypeList>(pdef.parameters_off);
                if (tl != nullptr)
                    for (uint32_t k = 0; k < tl->size; ++k)
                        if (tl->list[k].type_idx == type_idx) { param = true; break; }
            }
            if (!returns && !param) continue;
            std::string sig = BuildMethodSignature(*item, mid);
            if (returns) out.methods_returning.push_back(sig);
            if (param) out.methods_with_param.push_back(std::move(sig));
        }
    }
    return out;
}

std::vector<std::string> DexKitExt::ListClassesInDex(int dex_id) const {
    std::vector<std::string> out;
    if (dex_id < 0 || dex_id >= core_->GetDexNum()) return out;
    auto* item = core_->GetDexItem(static_cast<uint16_t>(dex_id));
    if (item == nullptr) return out;
    const auto& type_names = item->GetTypeNames();
    const auto& flags = item->GetTypeDefFlags();  // declared-in-this-dex types
    out.reserve(flags.size());
    for (std::size_t t = 0; t < flags.size(); ++t)
        if (flags[t]) out.emplace_back(type_names[t]);
    return out;
}

std::vector<std::string> DexKitExt::ListFieldDescriptorsInDex(int dex_id) const {
    std::vector<std::string> out;
    if (dex_id < 0 || dex_id >= core_->GetDexNum()) return out;
    auto* item = core_->GetDexItem(static_cast<uint16_t>(dex_id));
    if (item == nullptr) return out;
    const auto field_ids = item->GetReader().FieldIds();
    out.reserve(field_ids.size());
    for (uint32_t fid = 0; fid < field_ids.size(); ++fid)
        out.push_back(BuildFieldSignature(*item, fid));
    return out;
}

std::vector<std::string> DexKitExt::ListFieldDescriptors() const {
    std::vector<std::string> out;
    for (int d = 0; d < core_->GetDexNum(); ++d) {
        auto per_dex = ListFieldDescriptorsInDex(d);
        out.insert(out.end(), std::make_move_iterator(per_dex.begin()),
                   std::make_move_iterator(per_dex.end()));
    }
    return out;
}

std::vector<std::string> DexKitExt::ListMethodDescriptorsInDex(int dex_id) const {
    std::vector<std::string> out;
    if (dex_id < 0 || dex_id >= core_->GetDexNum()) return out;
    auto* item = core_->GetDexItem(static_cast<uint16_t>(dex_id));
    if (item == nullptr) return out;
    const auto method_ids = item->GetReader().MethodIds();
    out.reserve(method_ids.size());
    for (uint32_t mid = 0; mid < method_ids.size(); ++mid)
        out.push_back(BuildMethodSignature(*item, mid));
    return out;
}

std::vector<std::string> DexKitExt::ListMethodDescriptors() const {
    std::vector<std::string> out;
    for (int d = 0; d < core_->GetDexNum(); ++d) {
        auto per_dex = ListMethodDescriptorsInDex(d);
        out.insert(out.end(), std::make_move_iterator(per_dex.begin()),
                   std::make_move_iterator(per_dex.end()));
    }
    return out;
}

std::vector<uint8_t> DexKitExt::GetDexBytes(int dex_id) const {
    if (dex_id < 0 || dex_id >= core_->GetDexNum()) return {};
    auto* item = core_->GetDexItem(static_cast<uint16_t>(dex_id));
    if (item == nullptr) return {};
    auto* img = item->GetImage();
    if (img == nullptr) return {};
    // Return THIS logical dex's slice, not the whole mapped image: a concatenated /
    // packer-dump container is split into logical dexes that SHARE one MemMap, each at
    // its own header_off. The reader base (dataPtr<u1>(0) == image + header_off) is the
    // dex start and header->file_size is its length; using img->data()/img->len()
    // would over-return and mis-attribute sibling dexes. (The WASM extractDexBytes has
    // this same omission — fix deferred to the web side.) Clamp to the mapped span as a
    // defensive net (VerifyDex already bounds file_size).
    const auto& reader = item->GetReader();
    const auto* hdr = reader.Header();
    if (hdr == nullptr) return {};
    // Header() sits at the reader base (image + header_off) = this dex's first byte.
    const auto* base = reinterpret_cast<const uint8_t*>(hdr);
    const auto* map_base = reinterpret_cast<const uint8_t*>(img->data());
    std::size_t n = hdr->file_size;
    if (base >= map_base) {
        const std::size_t avail = img->len() - static_cast<std::size_t>(base - map_base);
        if (n > avail) n = avail;
    }
    return std::vector<uint8_t>(base, base + n);
}

}  // namespace dexkit::ext
