#include "dexkit_ext.h"

#include "invoke_args.h"
#include "smali_render.h"

#include <algorithm>
#include <array>
#include <cstdio>   // snprintf (checksum deviation text)
#include <cstring>  // memcmp (raw-dex magic sniff)
#include <functional>
#include <map>
#include <set>
#include <stdexcept>
#include <string>
#include <string_view>
#include <tuple>
#include <unordered_map>
#include <unordered_set>
#include <utility>

#include "analyze.h"  // kMethodInvoking et al.
#include "dex_verifier.h"  // VerifyDex — load-boundary structural gate
#include "dexitem_code_source.h"  // for GetCodeSource()
#include "mmap.h"  // dexkit::MemMap (raw-dex load path)
#include "slicer/dex_format.h"  // dex::Header (logical-dex split mirror)
#include "schema/querys_generated.h"
#include "zip_archive.h"  // dexkit::ZipArchive (PK/central-dir container probe)
#include "utils/byte_code_util.h"  // ReadShort — dexllm#84 field-site walk
#include "utils/opcode_util.h"  // GetBytecodeWidth — ditto
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

// One entry per DESCRIPTOR, the first one wins (dexllm#106). A class declared in
// more than one loaded dex — an `add_dumped_dexes` packer session, an overlapping
// multi-source load — is one class to the analyst, and every descriptor-keyed API
// resolves it first-wins in dex_id order (DexKit::PutDeclaredClass). The core
// agrees for two of its five searches: DexKit::FindMethod and DexKit::FindField
// drop a descriptor they have already seen (`declared_set`), while
// DexKit::FindClass and both BatchFind*UsingStrings concatenate every dex's hits,
// so they listed such a class (or its methods) once per declaring dex. Applied to
// MATCHED results in result order, which is dex_id order, exactly as FindMethod's
// declared_set is — a dex whose copy of the class does not match contributes
// nothing, so the winner is the first dex whose copy DOES. An empty descriptor
// (never produced for a resolvable id) is kept rather than collapsed.
template <class Ref>
void KeepFirstPerDescriptor(std::vector<Ref>& refs) {
    std::unordered_set<std::string> seen;
    size_t w = 0;
    for (size_t r = 0; r < refs.size(); ++r) {
        if (!refs[r].descriptor.empty() && !seen.insert(refs[r].descriptor).second)
            continue;
        if (w != r) refs[w] = std::move(refs[r]);
        ++w;
    }
    refs.resize(w);
}

// Parse a flatbuffer ClassMetaArrayHolder result into POD ClassRef vector.
// Every FindClass-backed search goes through here, so the dexllm#106 dedupe is
// applied once for all of them (by name / super / interface / annotation /
// using strings).
std::vector<ClassRef> ParseClassMetaArray(
    const dexkit::schema::ClassMetaArrayHolder* holder) {
    std::vector<ClassRef> out;
    if (holder == nullptr || holder->classes() == nullptr) return out;
    for (const auto* cls : *holder->classes()) {
        ClassRef m;
        m.dex_id = cls->dex_id();
        m.class_idx = cls->id();
        if (cls->dex_descriptor()) m.descriptor = cls->dex_descriptor()->str();
        out.push_back(std::move(m));
    }
    KeepFirstPerDescriptor(out);
    return out;
}

std::vector<MethodRef> ParseMethodMetaArray(
    const dexkit::schema::MethodMetaArrayHolder* holder) {
    std::vector<MethodRef> out;
    if (holder == nullptr || holder->methods() == nullptr) return out;
    for (const auto* m : *holder->methods()) {
        MethodRef mm;
        mm.dex_id = m->dex_id();
        mm.method_idx = m->id();
        if (m->dex_descriptor()) mm.descriptor = m->dex_descriptor()->str();
        out.push_back(std::move(mm));
    }
    return out;
}

std::vector<FieldRef> ParseFieldMetaArray(
    const dexkit::schema::FieldMetaArrayHolder* holder) {
    std::vector<FieldRef> out;
    if (holder == nullptr || holder->fields() == nullptr) return out;
    for (const auto* f : *holder->fields()) {
        FieldRef fm;
        fm.dex_id = f->dex_id();
        fm.field_idx = f->id();
        if (f->dex_descriptor()) fm.descriptor = f->dex_descriptor()->str();
        out.push_back(std::move(fm));
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

// One content-based classification of a source, shared by Identify() (which
// reports) and the loader (which loads) so the detection rule lives in ONE
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

// The one place a Probe becomes a reported ContainerInfo, so Identify() (which
// reports a path) and the loader (which records what it loaded) cannot drift
// — the same single-rule discipline Probe itself exists for.
ContainerInfo ContainerInfoFrom(const std::string& path, const struct Probe& p);

// The probe over an image already in memory — a file mapped from a path, or
// bytes the caller handed over (dexllm#119). One rule for both.
Probe ProbeMap(std::unique_ptr<dexkit::MemMap> map) {
    Probe p;
    p.map = std::move(map);
    if (!p.map || !p.map->ok()) {  // unknown: missing or empty
        if (!p.map) p.map = std::make_unique<dexkit::MemMap>();
        return p;
    }
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

Probe ProbeContainer(const std::string& path) {
    return ProbeMap(std::make_unique<dexkit::MemMap>(path));
}

ContainerInfo ContainerInfoFrom(const std::string& path, const Probe& p) {
    ContainerInfo info;
    info.source = path;
    info.format = p.format;
    info.has_manifest = p.has_manifest;
    info.is_apk = p.has_manifest;  // a zip carrying an AndroidManifest.xml
    info.dex_count = p.dex_count;
    return info;
}

// One logical dex inside an image, with its load-boundary verdict.
struct LogicalSlice {
    uint32_t offset = 0;
    uint32_t size = 0;
    bool ok = false;
    // A v41 CONTAINER dex addresses a data section shared with its siblings, so
    // it is only meaningful as part of the whole image — it cannot be copied out
    // on its own the way a v35-40 dex can.
    bool self_contained = true;
    // dexllm#120: ART's raw-image loop stops after this dex
    // (DexFile::IsDexContainerLastEntry — `End() == container end`). True for a
    // v35-v40 dex, whose container IS itself, and for a v41 dex whose
    // `container_off + file_size == container_size`.
    bool last_entry = true;
    // The byte range of the container this dex belongs to — itself for a
    // v35-v40 dex. Survivors of a partially-rejected image are copied out per
    // CONTAINER, so a container dex keeps the bytes its offsets address.
    uint32_t container_begin = 0;
    uint64_t container_end = 0;
    std::string reason;
    std::vector<std::string> art_deviations;  // dexllm#112
    // dexllm#120. `art_own`: this dex on its own passes every check ART's open
    // runs that this port implements — the LENIENT verdict (VerifyInsns is not
    // part of ART's structural verifier), no art_deviation, a matching header
    // checksum. `art_reason` says why not. `art_open` adds the sequence rule.
    bool art_own = false;
    std::string art_reason;
    bool art_open = false;
};

// MIRROR of the core's ParseLogicalDexOffsets (vendor/dexkit_core/Core/dexkit/
// dexkit.cpp) — the rule AddImage will apply to this image. The gate must split
// the image exactly the way the core does, or a dex the core parses is one the
// verifier never saw (dexllm#25). The mirror is checked at run time by
// AssertLoadedDexesWereVerified, which refuses the load if the two disagree.
//
// Note it does NOT require the "dex\n" magic at each offset — trailing garbage
// after a short file_size can therefore produce a bogus slice. That is fine here
// precisely because every slice is now verified: VerifyDex's CheckHeader rejects
// it on the magic.
std::vector<LogicalSlice> LogicalDexSlices(const uint8_t* base, size_t n) {
    std::vector<LogicalSlice> slices;
    size_t off = 0;
    while (true) {
        if (off + sizeof(dex::Header) > n) break;
        const auto* header = reinterpret_cast<const dex::Header*>(base + off);
        uint32_t sz = header->file_size;
        if (sz < sizeof(dex::Header) || off + sz > n) break;
        LogicalSlice s;
        s.offset = static_cast<uint32_t>(off);
        s.size = sz;
        s.self_contained = header->header_size < dex::Header::kV41Size;
        s.last_entry = s.self_contained ||
                       uint64_t{header->ContainerOff()} + sz == header->ContainerSize();
        const uint32_t in_container = header->ContainerOff();
        s.container_begin = in_container <= off ? static_cast<uint32_t>(off - in_container)
                                                : static_cast<uint32_t>(off);
        s.container_end = s.self_contained ? uint64_t{s.offset} + sz
                                           : uint64_t{s.container_begin} + header->ContainerSize();
        slices.push_back(s);
        off += sz;
        if (off >= n) break;
    }
    return slices;
}

std::string JoinReasons(const std::vector<std::string>& v) {
    std::string out;
    for (const auto& s : v) {
        if (!out.empty()) out += "; ";
        out += s;
    }
    return out;
}

// The verdict for every logical dex of one image, on its own. Shared by the
// load path and the load-free Verify(), which is documented to produce
// byte-identical rows — so every rule that decides a verdict lives HERE (and in
// ClassifySourceImage below), not in one of the two callers.
std::vector<LogicalSlice> ClassifyImageSlices(const uint8_t* base, size_t n,
                                              bool check_insns) {
    auto slices = LogicalDexSlices(base, n);
    // ONE state for the whole image (dexllm#59). A v41 container is verified once
    // per slice with the container as its span, so a method_handle section shared
    // between siblings would otherwise be walked once per sibling — quadratic in
    // the container, measured at 20.59 s for 16 MB. The state carries the memo
    // that collapses the repeat and the budget that bounds the rest. The lenient
    // re-verify below gets a state of its own for the same reason.
    VerifyImageState image_state;
    VerifyImageState lenient_state;
    for (auto& s : slices) {
        // The WHOLE image plus this dex's header offset — a v41 container dex
        // addresses a data section shared with its siblings, so the verifier
        // needs the container, not the slice (see VerifyDex).
        auto vr = VerifyDex(base, n, check_insns, s.offset, &image_state);
        s.ok = vr.ok;
        s.reason = vr.reason;
        s.art_deviations = vr.art_deviations;

        // dexllm#120 — what ART's open would make of this dex. A strict
        // rejection may be a check ART's structural verifier does not run
        // (VerifyInsns), so a strict reject is re-judged leniently. Only rejected
        // slices pay for it.
        bool lenient_ok = vr.ok;
        std::string lenient_reason = vr.reason;
        std::vector<std::string> lenient_devs = vr.art_deviations;
        if (check_insns && !vr.ok) {
            auto lv = VerifyDex(base, n, /*check_insns=*/false, s.offset, &lenient_state);
            lenient_ok = lv.ok;
            lenient_reason = lv.reason;
            lenient_devs = lv.art_deviations;
        }
        // ART checks the adler32 on open (DexFileLoader, kVerifyChecksum); the
        // gate deliberately does not (dex_verifier.h). Reported, never rejected.
        // LogicalDexSlices put [offset, offset + file_size) inside the image.
        const auto* h = reinterpret_cast<const dex::Header*>(base + s.offset);
        const uint32_t computed = dex::ComputeChecksum(h);
        if (computed != h->checksum) {
            char buf[96];
            std::snprintf(buf, sizeof(buf),
                          "header checksum 0x%08x does not match the adler32 "
                          "0x%08x ART computes on open",
                          h->checksum, computed);
            s.art_deviations.emplace_back(buf);
            lenient_devs.emplace_back(buf);
        }
        s.art_own = lenient_ok && lenient_devs.empty();
        if (!s.art_own) s.art_reason = lenient_ok ? JoinReasons(lenient_devs) : lenient_reason;
    }
    return slices;
}

// Where one source's ART open has got to (dexllm#120). ART stops a source at the
// first dex it cannot open; every dex after it is not part of what it yields.
// Threaded through every image of ONE source, fresh for each source.
struct ArtSequence {
    LoadMode mode = LoadMode::Isolated;
    bool broken = false;
    std::string why;  // "<name>: <reason>" of the dex that ended the sequence
    void Break(const std::string& name, const std::string& reason) {
        if (broken) return;
        broken = true;
        why = name + ": " + reason;
    }
};

// ClassifyImageSlices, then the two rules that need more than one dex: the ART
// sequence (dexllm#120) and the v41 sibling rule.
//
// `missing_entry` is set when ART would read one MORE container entry than the
// image yields — the last slice is a v41 entry that is not its container's last,
// and the split could not produce the next one. ART's open fails there, so the
// sequence ends; the caller reports it as a row of its own. It is not a slice:
// nothing can be loaded from it and it must not drive the sibling rule.
std::vector<LogicalSlice> ClassifySourceImage(const uint8_t* base, size_t n,
                                              bool check_insns, const std::string& name,
                                              ArtSequence& seq,
                                              std::string* missing_entry) {
    auto slices = ClassifyImageSlices(base, n, check_insns);
    if (slices.empty()) {
        // Too short for a header or a file_size that does not fit: ART's open of
        // this entry fails too, and that ends the source.
        seq.Break(name, "no logical dex in image");
        return slices;
    }
    bool image_ended = false;
    for (size_t i = 0; i < slices.size(); ++i) {
        auto& s = slices[i];
        const std::string label =
            slices.size() > 1 ? name + " @" + std::to_string(s.offset) : name;
        std::string not_opened;
        if (i > 0 && slices[i - 1].last_entry) image_ended = true;
        if (seq.broken) {
            not_opened = "not opened: ART stops a source at the first dex it cannot "
                         "open (" + seq.why + ")";
        } else if (image_ended) {
            // ART reads past a dex only while it is a v41 container entry that is
            // not its container's last (DexFileLoader::Open, IsDexContainerLastEntry):
            // the bytes after are not part of what it opens. Not a failure — the
            // source does not end here, the image does.
            not_opened = "not opened: ART stops reading an image after a dex that is "
                         "not followed by an entry of the same v41 container, and "
                         "this one comes after it";
        } else if (!s.art_own) {
            seq.Break(label, s.art_reason);
            not_opened = "ART would not open this dex: " + s.art_reason;
        }
        s.art_open = not_opened.empty();
        if (seq.mode == LoadMode::Runtime && s.ok && !s.art_open) {
            s.ok = false;
            s.reason = not_opened;
        }
    }
    const auto& tail = slices.back();
    if (!seq.broken && !image_ended && !tail.last_entry && missing_entry != nullptr) {
        const uint32_t next = tail.offset + tail.size;
        *missing_entry = "the v41 container entry expected at offset " +
                         std::to_string(next) +
                         " (the previous entry is not its container's last) does not "
                         "fit the image; ART's open fails there";
        seq.Break(name + " @" + std::to_string(next), "container entry does not fit");
    }
    size_t rejected = 0;
    for (const auto& s : slices) rejected += s.ok ? 0 : 1;
    if (rejected != 0) {
        // A rejected slice means the image cannot be handed to the core whole —
        // the survivors are copied out (the load path), a v41 dex together with
        // the rest of ITS container, since its offsets address the container. So
        // a container survives only whole: if one of its dexes is rejected, or its
        // range holds a dex of another container, or it does not fit the image,
        // reject all of it rather than load one that would read the wrong bytes.
        // A rejected dex elsewhere in the image does not cost it anything
        // (dexllm#120 — before, any rejection took every container dex with it).
        // O(n log n): slices are in offset order (LogicalDexSlices walks forward),
        // so the dexes inside one container's range are a contiguous run, and the
        // container is whole iff that run is exactly its own members and none of
        // them is rejected. A quadratic all-pairs scan here cost 60x on a crafted
        // 69,906-slice container (CI's amplification guard caught it).
        std::map<uint32_t, std::vector<size_t>> members;  // container_begin → indices
        for (size_t i = 0; i < slices.size(); ++i) {
            if (!slices[i].self_contained) members[slices[i].container_begin].push_back(i);
        }
        std::vector<bool> bad(slices.size(), false);
        auto first_at = [&](uint64_t off) {  // first slice whose offset >= off
            size_t lo = 0, hi = slices.size();
            while (lo < hi) {
                const size_t mid = lo + (hi - lo) / 2;
                if (slices[mid].offset < off) lo = mid + 1; else hi = mid;
            }
            return lo;
        };
        for (const auto& [begin, idx] : members) {
            const auto& c = slices[idx.front()];
            bool whole = c.container_end <= n;
            for (size_t i : idx) whole = whole && slices[i].ok;
            const size_t lo = first_at(begin), hi = first_at(c.container_end);
            // every slice in [lo, hi) must be a member: members are sorted, so
            // count those inside the run and compare with its length
            const auto in_lo = std::lower_bound(idx.begin(), idx.end(), lo);
            const auto in_hi = std::lower_bound(idx.begin(), idx.end(), hi);
            const auto inside = static_cast<size_t>(in_hi - in_lo);
            // ...and every member must lie in it, or the copy would leave one out
            if (inside != hi - lo || inside != idx.size()) whole = false;
            if (!whole) for (size_t i : idx) bad[i] = true;
        }
        for (size_t i = 0; i < slices.size(); ++i) {
            if (slices[i].ok && bad[i]) {
                slices[i].ok = false;
                slices[i].reason =
                    "another dex in this v41 container failed verification, and a "
                    "container dex cannot be loaded apart from its siblings";
            }
        }
    }
    return slices;
}

// How many dexes a session can address at all. `DexKit::GetDexItem(uint16_t)` —
// and the core's dex_id plumbing generally — is uint16_t, so 65535 is the last
// reachable id. Refusing the excess here is what keeps "an accepted row is a dex
// the session really loaded" true: an id past the range WRAPS on every later
// lookup and silently reaches a DIFFERENT dex, which is how a null DexItem slipped
// past AssertLoadedDexesWereVerified and still SEGV'd (adversarial review,
// CONFIRMED with 65536 valid dexes plus one the parser rejects). Same
// bounded-refusal posture as kMaxDeclaredIds / gt_budget — unreachable for real
// input, deterministic and loud for crafted input.
constexpr int kMaxLoadedDexes = 1 << 16;

DexVerifyStatus RejectRow(const std::string& name, const std::string& reason,
                          const std::string& source) {
    DexVerifyStatus r;
    r.dex_id = -1;
    r.name = name;
    r.valid = false;
    r.reason = reason;
    r.source = source;
    r.art_open = false;
    return r;
}

// One verdict row per logical dex, giving each accepted one the next real dex_id.
// Returns how many were accepted, and downgrades any slice it had to refuse so
// the caller's salvage path cannot load one anyway.
size_t EmitSliceVerdicts(std::vector<LogicalSlice>& slices,
                         const std::string& name, const std::string& source,
                         int& next_dex_id, std::vector<DexVerifyStatus>& report) {
    if (slices.empty()) {
        // Too short to hold a header, or a file_size that does not fit — the core
        // would build no DexItem at all, so this is a rejection with a reason
        // rather than a silent empty load.
        report.push_back(RejectRow(name,
                                   "no logical dex in image (truncated header or a "
                                   "file_size that does not fit the image)",
                                   source));
        return 0;
    }
    size_t accepted = 0;
    for (auto& s : slices) {
        if (s.ok && next_dex_id >= kMaxLoadedDexes) {
            s.ok = false;
            s.reason =
                "too many logical dexes in this session (the core addresses a "
                "dex_id as uint16_t, so at most 65536 can be loaded)";
        }
        DexVerifyStatus r;
        r.name = name;
        r.source = source;
        r.art_open = s.art_open;
        if (s.ok) {
            r.dex_id = next_dex_id++;
            r.valid = true;
            r.art_deviations = s.art_deviations;
            ++accepted;
        } else {
            r.dex_id = -1;
            r.valid = false;
            r.reason = s.reason;
        }
        report.push_back(std::move(r));
    }
    return accepted;
}

// Copy one logical dex out of a shared image into an image of its own, so the
// core can be handed the survivors of a partially-bad container without also
// being handed the rejected slice. Only reached when a slice failed — an
// all-verified image is moved through untouched.
std::unique_ptr<dexkit::MemMap> CopySlice(const uint8_t* base, uint32_t size) {
    auto mm = std::make_unique<dexkit::MemMap>(size);
    if (!mm->ok()) return nullptr;  // allocation failed
    std::memcpy(mm->data(), base, size);
    return mm;
}

// Receives an image with at least one accepted slice, so the loader can keep it.
// Verify() passes none and keeps nothing.
using ImageSink = std::function<void(std::unique_ptr<dexkit::MemMap> image,
                                     const std::string& entry, const std::string& name,
                                     const std::vector<LogicalSlice>& slices,
                                     size_t accepted)>;

// In Runtime mode a source can yield nothing while dexes in it VERIFY — they
// come after the one ART cannot open. "failed verification" would be false
// then, so say what happened and that Isolated mode would load them.
void NoteRuntimeTruncation(const ArtSequence& seq, const std::string& source,
                           const std::vector<DexVerifyStatus>& report, size_t first_row,
                           std::string& failure) {
    if (seq.mode != LoadMode::Runtime || !seq.broken) return;
    size_t skipped = 0;
    bool art_refused = false;  // a dex that VERIFIED, refused only for ART's sake
    for (size_t i = first_row; i < report.size(); ++i) {
        if (report[i].reason.rfind("not opened: ART stops", 0) == 0) ++skipped;
        if (report[i].reason.rfind("ART would not open this dex", 0) == 0) art_refused = true;
    }
    if (skipped == 0 && art_refused) {
        failure = "dexllm: ART's open of '" + source + "' yields no dex (" + seq.why +
                  "); the dex passed dexllm's verifier — mode='isolated' loads it";
        return;
    }
    if (skipped == 0) return;
    failure = "dexllm: ART's open of '" + source + "' yields no dex (" + seq.why +
              "); " + std::to_string(skipped) +
              " dex(es) after it were not opened — mode='isolated' judges each dex "
              "on its own";
}

// The walk over ONE source, shared by the loader and the load-free Verify() so
// the two produce the same rows by construction. Rows go to `report`, accepted
// images to `sink`. Never throws for a verdict; `failure` gets the one-line
// reason when the source yields no dex at all (the constructor's error message).
//
// dexllm#25: the core's AddImage runs ParseLogicalDexOffsets, so ONE image can
// become several dexes — verifying the image once (at offset 0) let every later
// logical dex reach the core unverified, which is exactly the input a packer dump
// produces. So every image is classified per LOGICAL dex.
size_t WalkSource(Probe& p, const std::string& source, bool in_memory, bool check_insns,
                  LoadMode mode, int& next_dex_id, std::vector<DexVerifyStatus>& report,
                  const ImageSink& sink, std::string& failure) {
    ArtSequence seq;
    seq.mode = mode;
    const size_t first_row = report.size();
    auto one_image = [&](std::unique_ptr<dexkit::MemMap> image, const std::string& entry,
                         const std::string& name, std::string* first_reject) {
        const auto* base = reinterpret_cast<const uint8_t*>(image->data());
        std::string missing;
        auto slices =
            ClassifySourceImage(base, image->len(), check_insns, name, seq, &missing);
        const size_t accepted = EmitSliceVerdicts(slices, name, source, next_dex_id, report);
        if (!missing.empty()) report.push_back(RejectRow(name, missing, source));
        if (first_reject != nullptr && first_reject->empty()) {
            for (const auto& s : slices) {
                if (!s.ok) { *first_reject = s.reason; break; }
            }
            if (slices.empty()) *first_reject = report.back().reason;
        }
        if (accepted != 0 && sink) sink(std::move(image), entry, name, slices, accepted);
        return accepted;
    };

    if (p.format == "unknown") {
        // Not openable, or neither a raw .dex nor a zip/apk. ART's class path
        // skips such an element; so does a multi-source session (dexllm#119).
        const bool opened = p.map && p.map->ok();
        report.push_back(RejectRow(
            source,
            opened      ? std::string("neither a .dex (no 'dex\\n' magic) nor a "
                                      "zip/apk container (no PK signature / invalid "
                                      "central directory)")
            : in_memory ? std::string("empty buffer")
                        : std::string("cannot open (file not found or empty)"),
            source));
        failure = opened
                      ? "dexllm: '" + source + "' is neither a .dex (no 'dex\\n' magic) "
                        "nor a zip/apk container (no PK signature / invalid central "
                        "directory)"
                  : in_memory ? "dexllm: '" + source + "' is an empty buffer"
                              : "dexllm: cannot open '" + source + "' (file not found or empty)";
        return 0;
    }

    if (p.format == "dex") {
        // Structural gate (DexVerifier) BEFORE the core parses the image — a
        // malformed dex is screened out here so the core/slicer never touch it.
        std::string reason;
        const size_t accepted = one_image(std::move(p.map), std::string{}, source, &reason);
        if (accepted == 0) {
            failure = "dexllm: '" + source + "' failed dex verification: " + reason;
            NoteRuntimeTruncation(seq, source, report, first_row, failure);
        }
        return accepted;
    }

    // p.format == "zip": extract each classes*.dex, verify at the load boundary,
    // and feed only structurally-valid dexes to the core via AddImage. This
    // replaces the core's internal zip loader (DexKit(apk_path) → AddZipPath) so a
    // malformed dex is screened out *before* the core parses it — no vendored-core
    // change. In Isolated mode a rejected dex is recorded (verify_report) and
    // skipped while its siblings still load (per-dex rejection); in Runtime mode
    // the dexes after it are not opened, as on a device (dexllm#120).
    if (p.dex_count == 0) {
        report.push_back(RejectRow(
            source,
            std::string("zip container has no classes*.dex (AndroidManifest.xml ") +
                (p.has_manifest ? "present" : "absent") + ")",
            source));
        failure = "dexllm: zip container '" + source + "' has no classes*.dex to "
                  "decompile (AndroidManifest.xml " +
                  (p.has_manifest ? "present" : "absent") + ")";
        return 0;
    }
    {
        // libziparchive refuses an archive with two central-directory entries of
        // one name (zip_cd_entry_map.cc, kDuplicateEntry), so ART opens nothing
        // from it. dexllm's reader keeps the LAST record and loads; say ART would
        // not (dexllm#120). A known anti-analysis trick.
        std::set<std::string_view> names;
        for (const auto& e : p.za->GetEntries()) {
            if (!names.insert(e.name).second) {
                seq.Break(source, "duplicate zip entry '" + std::string(e.name) +
                                      "' (ART's zip reader refuses the archive)");
                break;
            }
        }
    }
    size_t accepted = 0;
    for (int idx = 1; idx <= p.dex_count; ++idx) {
        auto name = "classes" + (idx == 1 ? std::string() : std::to_string(idx)) + ".dex";
        const auto* entry = p.za->Find(name);
        if (entry == nullptr) continue;  // counted by ProbeContainer; defensive
        if (entry->uncomp_size == 0) {
            // A zero-length entry: the same reason from_dex_images gives an empty
            // image, so one input reads the same either way (ART fails it too).
            report.push_back(RejectRow(name, "empty image", source));
            seq.Break(name, "empty image");
            continue;
        }
        auto mm = p.za->GetUncompressData(*entry);
        if (!mm.ok()) {
            // ART fails this entry too (kExtractToMemoryError), ending the source.
            report.push_back(RejectRow(name, "decompression failed", source));
            seq.Break(name, "decompression failed");
            continue;
        }
        accepted += one_image(std::make_unique<dexkit::MemMap>(std::move(mm)), name, name,
                              nullptr);
    }
    if (accepted == 0) {
        failure = "dexllm: all " + std::to_string(p.dex_count) + " dex(es) in '" + source +
                  "' failed verification";
        NoteRuntimeTruncation(seq, source, report, first_row, failure);
    }
    return accepted;
}

}  // namespace

LoadMode ParseLoadMode(const std::string& mode) {
    if (mode == "isolated") return LoadMode::Isolated;
    if (mode == "runtime") return LoadMode::Runtime;
    throw std::invalid_argument("dexllm: mode must be 'isolated' or 'runtime', got '" +
                                mode + "'");
}

const char* LoadModeName(LoadMode mode) {
    return mode == LoadMode::Runtime ? "runtime" : "isolated";
}

ContainerInfo DexKitExt::Identify(const std::string& path) {
    return ContainerInfoFrom(path, ProbeContainer(path));
}

// Copy caller bytes into an image the session owns (dexllm#119). MemMap's length
// is uint32_t, so anything that does not fit is refused rather than truncated.
std::unique_ptr<dexkit::MemMap> OwnedImageCopy(const uint8_t* data, size_t len) {
    if (len > UINT32_MAX) {
        throw std::invalid_argument("dexllm: an in-memory image of " + std::to_string(len) +
                                    " bytes is too large (the limit is 4 GiB - 1)");
    }
    if (len == 0) return std::make_unique<dexkit::MemMap>();  // reported as empty
    auto mm = std::make_unique<dexkit::MemMap>(static_cast<uint32_t>(len));
    if (!mm->ok()) {
        throw std::runtime_error("dexllm: cannot allocate " + std::to_string(len) +
                                 " bytes for an in-memory image");
    }
    std::memcpy(mm->data(), data, len);
    return mm;
}

ContainerInfo DexKitExt::IdentifyBytes(const uint8_t* data, size_t len,
                                       const std::string& source) {
    auto info = ContainerInfoFrom(source, ProbeMap(OwnedImageCopy(data, len)));
    info.in_memory = true;
    return info;
}

std::vector<DexVerifyStatus> DexKitExt::Verify(const std::string& path,
                                               bool check_insns, LoadMode mode) {
    // Load-free: the loader's walk with no sink — every verdict collected, never
    // throwing, never retaining the mmap, never AddImage. The same walk is what
    // makes a loadable path's verdicts byte-identical to VerifyReport().
    std::vector<DexVerifyStatus> report;
    Probe p = ProbeContainer(path);
    int next_dex_id = 0;
    std::string failure;
    WalkSource(p, path, /*in_memory=*/false, check_insns, mode, next_dex_id, report, nullptr,
               failure);
    return report;
}

std::vector<DexVerifyStatus> DexKitExt::VerifyBytes(const uint8_t* data, size_t len,
                                                    const std::string& source,
                                                    bool check_insns, LoadMode mode) {
    std::vector<DexVerifyStatus> report;
    Probe p = ProbeMap(OwnedImageCopy(data, len));
    int next_dex_id = 0;
    std::string failure;
    WalkSource(p, source, /*in_memory=*/true, check_insns, mode, next_dex_id, report,
               nullptr, failure);
    return report;
}

size_t DexKitExt::CollectInput(LoadInput& input, bool check_insns,
                               std::vector<std::unique_ptr<dexkit::MemMap>>& out,
                               std::string& failure) {
    const std::string& source = input.source;
    // Keep the accepted images. When every logical dex of an image verified it is
    // handed over whole — the ordinary path, no copy; otherwise the survivors are
    // copied into images of their own so a rejected slice cannot be reached.
    ImageSink sink = [&](std::unique_ptr<dexkit::MemMap> image, const std::string& entry,
                         const std::string& name, const std::vector<LogicalSlice>& slices,
                         size_t accepted) {
        if (accepted == slices.size()) {
            image_origin_[image.get()] = {source, entry, 0};
            out.push_back(std::move(image));
            return;
        }
        const auto* base = reinterpret_cast<const uint8_t*>(image->data());
        std::set<uint32_t> containers_copied;
        for (const auto& s : slices) {
            if (!s.ok) continue;
            // A v41 dex is copied with the whole of its container (the sibling
            // rule guaranteed every dex in that range is accepted and it fits), so
            // the core splits the copy into exactly those dexes.
            uint32_t from = s.offset;
            uint32_t size = s.size;
            if (!s.self_contained) {
                if (!containers_copied.insert(s.container_begin).second) continue;
                from = s.container_begin;
                size = static_cast<uint32_t>(s.container_end - s.container_begin);
            }
            auto copy = CopySlice(base + from, size);
            if (copy == nullptr) {
                // Out of memory. Throwing rather than dropping the slice keeps the
                // verdict rows (already emitted, with their dex_ids) true: a dex
                // reported as accepted is one the session actually loaded.
                throw std::runtime_error(
                    "dexllm: cannot allocate " + std::to_string(size) +
                    " bytes to salvage the verified dex at offset " +
                    std::to_string(from) + " of '" + name + "'");
            }
            // `base_offset` keeps the reported provenance offset the same value it
            // would have had if the whole container had verified.
            image_origin_[copy.get()] = {source, entry, from};
            out.push_back(std::move(copy));
        }
    };

    if (!input.dex_images.empty()) {
        // dexllm#119 — an explicit dex list: one source, one multidex sequence, in
        // the caller's order and under the caller's entry names.
        ContainerInfo info;
        info.format = "images";
        info.dex_count = static_cast<int>(input.dex_images.size());
        info.source = source;
        info.in_memory = true;
        source_info_.push_back(info);
        size_t accepted = 0;
        ArtSequence seq;
        seq.mode = mode_;
        const size_t first_row = verify_status_.size();
        for (auto& [name, image] : input.dex_images) {
            if (!image || !image->ok()) {
                // Anything else goes through the verifier, so the same bytes give
                // the same reason here as they do inside a zip.
                verify_status_.push_back(RejectRow(name, "empty image", source));
                seq.Break(name, "empty image");
                continue;
            }
            const auto* base = reinterpret_cast<const uint8_t*>(image->data());
            std::string missing;
            auto slices =
                ClassifySourceImage(base, image->len(), check_insns, name, seq, &missing);
            const size_t n =
                EmitSliceVerdicts(slices, name, source, next_dex_id_, verify_status_);
            if (!missing.empty()) verify_status_.push_back(RejectRow(name, missing, source));
            if (n != 0) sink(std::move(image), name, name, slices, n);
            accepted += n;
        }
        if (accepted == 0) {
            failure = "dexllm: none of the " + std::to_string(input.dex_images.size()) +
                      " dex image(s) of '" + source + "' passed verification";
            NoteRuntimeTruncation(seq, source, verify_status_, first_row, failure);
        }
        return accepted;
    }

    const bool in_memory = input.image != nullptr;
    Probe p = in_memory ? ProbeMap(std::move(input.image)) : ProbeContainer(source);
    // Keep what the probe found, so a session can answer "what was this source"
    // from memory rather than re-reading a path that may be gone (dexllm#42).
    ContainerInfo info = ContainerInfoFrom(source, p);
    info.in_memory = in_memory;
    source_info_.push_back(info);
    return WalkSource(p, source, in_memory, check_insns, mode_, next_dex_id_, verify_status_,
                      sink, failure);
}

void DexKitExt::AssertLoadedDexesWereVerified(size_t accepted) const {
    const int n = core_->GetDexNum();
    // Bounded by EmitSliceVerdicts' kMaxLoadedDexes, so the uint16_t below cannot
    // wrap. Checked rather than assumed: a wrap would make the null-item scan read
    // a DIFFERENT dex and hand back a false all-clear.
    if (n < 0 || n > kMaxLoadedDexes) {
        throw std::runtime_error(
            "dexllm: internal error — " + std::to_string(n) +
            " dexes loaded, past the addressable range");
    }
    if (n != static_cast<int>(accepted)) {
        throw std::runtime_error(
            "dexllm: internal error — the core parsed " + std::to_string(n) +
            " dex(es) but " + std::to_string(accepted) +
            " were verified at the load boundary; refusing to run on an "
            "unverified dex");
    }
    auto& mut = const_cast<dexkit::DexKit&>(*core_);
    for (int i = 0; i < n; ++i) {
        if (mut.GetDexItem(static_cast<uint16_t>(i)) == nullptr) {
            throw std::runtime_error(
                "dexllm: dex " + std::to_string(i) +
                " passed structural verification but could not be parsed");
        }
    }
}

namespace {

std::vector<LoadInput> PathInputs(const std::vector<std::string>& paths) {
    std::vector<LoadInput> inputs(paths.size());
    for (size_t i = 0; i < paths.size(); ++i) inputs[i].source = paths[i];
    return inputs;
}

}  // namespace

DexKitExt::DexKitExt(const std::string& apk_path, bool lenient, LoadMode mode)
    : DexKitExt(PathInputs({apk_path}), lenient, mode) {}

DexKitExt::DexKitExt(const std::vector<std::string>& sources, bool lenient, LoadMode mode)
    : DexKitExt(PathInputs(sources), lenient, mode) {}

DexKitExt::DexKitExt(std::vector<LoadInput> inputs, bool lenient, LoadMode mode)
    : mode_(mode) {
    if (inputs.empty()) {
        throw std::runtime_error("dexllm: no dex sources given");
    }
    for (const auto& in : inputs) sources_.push_back(in.source);
    apk_path_ = sources_.front();
    core_ = std::make_unique<dexkit::DexKit>();
    // Load sources in order — earlier sources get lower dex_ids, so first-wins
    // resolution prefers them (load a decrypted/dumped dex first to win). A
    // source that yields nothing is rows, not an error (dexllm#119): ART's class
    // path suppresses a failed element the same way.
    std::vector<std::unique_ptr<dexkit::MemMap>> valid_dexes;
    size_t accepted = 0;
    std::vector<std::string> failures;
    for (auto& in : inputs) {
        std::string failure;
        accepted += CollectInput(in, /*check_insns=*/!lenient, valid_dexes, failure);
        if (!failure.empty()) failures.push_back(std::move(failure));
    }
    if (accepted == 0) {
        // One source: its own message, exactly as before. Several: all of them.
        if (failures.size() == 1) throw std::runtime_error(failures.front());
        std::string msg = "dexllm: none of the " + std::to_string(inputs.size()) +
                          " sources yielded a dex that passed verification";
        for (const auto& f : failures) msg += "\n  " + f;
        throw std::runtime_error(msg);
    }
    core_->AddImage(std::move(valid_dexes));
    AssertLoadedDexesWereVerified(accepted);
}

LoadStatus DexKitExt::GetLoadStatus() const {
    LoadStatus st;
    st.mode = LoadModeName(mode_);
    st.loaded_dex_count = DexCount();
    for (const auto& r : verify_status_) {
        if (!r.valid) {
            st.complete = false;
            st.rejected.push_back(r);
        }
        if (r.valid != r.art_open) st.matches_art = false;
    }
    return st;
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

std::vector<ClassHeader> DexKitExt::ListClassHeaders() const {
    std::vector<ClassHeader> out;
    auto& mut = const_cast<dexkit::DexKit&>(*core_);
    const int n = core_->GetDexNum();
    for (int i = 0; i < n; ++i) {
        auto* item = mut.GetDexItem(static_cast<uint16_t>(i));
        if (!item) continue;
        const auto& reader = item->GetReader();
        const auto& type_names = item->GetTypeNames();
        const auto& flags = item->GetTypeDefFlags();
        const auto class_defs = reader.ClassDefs();
        for (size_t type_idx = 0; type_idx < flags.size(); ++type_idx) {
            if (!flags[type_idx]) continue;
            const uint32_t def_idx = item->GetTypeDefIdx(
                static_cast<uint32_t>(type_idx));
            if (def_idx == dex::kNoIndex || def_idx >= class_defs.size()) continue;
            const auto& cdef = class_defs[def_idx];
            ClassHeader h;
            h.descriptor = std::string(type_names[type_idx]);
            h.dex_id = static_cast<uint16_t>(item->GetDexId());
            h.class_idx = static_cast<uint32_t>(type_idx);
            h.access_flags = cdef.access_flags;
            // kNoIndex is java.lang.Object's own shape; an app class_def always
            // names a superclass, and the gate bounds the index it names.
            if (cdef.superclass_idx != dex::kNoIndex &&
                cdef.superclass_idx < type_names.size()) {
                h.superclass_descriptor = std::string(type_names[cdef.superclass_idx]);
            }
            // Same walk as FillInternalClassSummary: interfaces_off == 0 means
            // none; the type_list it names is verified by the gate.
            if (cdef.interfaces_off != 0) {
                const auto* ifaces = reader.dataPtr<dex::TypeList>(cdef.interfaces_off);
                if (ifaces != nullptr) {
                    for (uint32_t k = 0; k < ifaces->size; ++k) {
                        const uint32_t t = ifaces->list[k].type_idx;
                        if (t < type_names.size())
                            h.interface_descriptors.emplace_back(std::string(type_names[t]));
                    }
                }
            }
            out.push_back(std::move(h));
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
// `depth` mirrors `DecodeEncodedValueText`'s (dexllm#71): the gate's kMaxDepth
// bounds this walk only in lockstep, and on a desync a run of 0x1c bytes is one
// stack frame per byte.
constexpr int kScanMaxDepth = 16;

void ScanEncodedValueStrings(const uint8_t*& p, const uint8_t* end,
                             std::vector<uint32_t>& out, int depth = 0) {
    if (p >= end) return;
    if (depth > kScanMaxDepth) return;
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
            for (uint64_t i = 0; i < sz && p < end; ++i) ScanEncodedValueStrings(p, end, out, depth + 1);
            return;
        }
        case 0x1d: {  // ANNOTATION — type_idx, size, size*(name_idx, value)
            (void)ScanUleb(p, end);
            uint64_t sz = ScanUleb(p, end);
            for (uint64_t i = 0; i < sz && p < end; ++i) {
                (void)ScanUleb(p, end);  // name_idx
                ScanEncodedValueStrings(p, end, out, depth + 1);
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

// Collect the static-field EncodedValue VALUE_STRING (0x17) string ids of ONE
// class_def. Bounded by the mapped image tail (the encoded_array is an unbounded
// leb stream; VerifyEncodedArrayAt caps the nesting depth at load).
// ONE copy shared by ListValueStrings (app-wide) and ListClassStrings (one class)
// — the documented "class strings ⊆ value strings" invariant requires the two
// scans to be identical, so they must not be two drifting copies.
void ScanClassDefStaticStrings(const dexkit::DexItem& item,
                               const dex::ClassDef& cdef,
                               std::vector<uint32_t>& ids) {
    if (cdef.static_values_off == 0) return;
    const auto& reader = item.GetReader();
    const uint8_t* p = reader.dataPtr<uint8_t>(cdef.static_values_off);
    if (p == nullptr) return;
    const uint8_t* mmap_end = nullptr;
    if (auto* img = item.GetImage())
        mmap_end = reinterpret_cast<const uint8_t*>(img->data()) + img->len();
    const uint8_t* end = mmap_end ? mmap_end : p + (1u << 20);
    if (p >= end) return;
    uint64_t count = ScanUleb(p, end);
    for (uint64_t k = 0; k < count && p < end; ++k)
        ScanEncodedValueStrings(p, end, ids);
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
        for (const auto& cdef : reader.ClassDefs()) {
            std::vector<uint32_t> ids;
            ScanClassDefStaticStrings(*item, cdef, ids);
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
    return ext::RenderClassSmali(*dex_item, type_idx);
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
        return ext::RenderMethodSmali(*dex_item, static_cast<uint32_t>(i));
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
std::string BuildMethodDescriptor(const dexkit::DexItem& item, uint32_t method_idx) {
    const auto& reader = item.GetReader();
    const auto& type_names = item.GetTypeNames();
    const auto& strings = item.GetStrings();
    // Bound the index (mirrors BuildFieldDescriptor). method_idx can be a raw
    // invoke operand (ResolvedArg MethodReturn → last_invoke_callee), which lenient
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

// dexllm#107 — is the method at (item, method_idx) a SHADOWED copy? When a class is
// declared in more than one loaded dex (an add_dumped_dexes packer session, or any
// multi-source load whose sources overlap), it resolves to ONE of them: the
// first-wins declaring dex, i.e. what LocateClassDex / decompile_* answer. A
// method body in any other dex's copy never executes under that order, so a site
// inside it is shadowed. "Under that order" is the bound: dexllm models runtime
// resolution as load order (add_dumped_dexes(prefer=True) puts the dump first);
// a runtime whose class loader orders the dexes differently resolves differently.
// It is still REPORTED — the copies can differ (a partial dump, an undecrypted
// original), so a site present only in the shadowed copy is real evidence about
// the app — and marked, so a consumer that counts executable sites
// (summarize_capabilities) can leave it out.
//
// The caller has a body in `item`, so its class is declared there; a dex with no
// declaring entry at all (nullptr) cannot shadow it, so that answers false.
bool IsShadowedMethod(dexkit::DexKit& core, const dexkit::DexItem& item,
                      uint32_t method_idx) {
    const auto& ids = item.GetReader().MethodIds();
    if (method_idx >= ids.size()) return false;
    const auto& type_names = item.GetTypeNames();
    const uint32_t cls = ids[method_idx].class_idx;
    if (cls >= type_names.size()) return false;
    auto [owner, type_idx] = core.GetClassDeclaredPair(type_names[cls]);
    (void)type_idx;
    return owner != nullptr && owner->GetDexId() != item.GetDexId();
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
    // The gate admits kNoIndex here (dex_verifier.cpp CheckInterSection: it
    // bounds superclass_idx only when it is not kNoIndex), so a crafted class_def
    // that verifies VALID can carry one; reading type_names[0xFFFFFFFF] was an
    // unchecked OOB on this line until the ListClassHeaders review found it.
    if (class_def.superclass_idx != dex::kNoIndex &&
        class_def.superclass_idx < type_names.size()) {
        out.superclass_descriptor = std::string(type_names[class_def.superclass_idx]);
    }
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
        MethodInfo cm;
        cm.name = std::string(strings[m.name_idx]);
        cm.proto = BuildProtoDescriptor(item, proto_ids[m.proto_idx]);
        // A method reaches this loop only from `class_method_ids`, which is built
        // inside the class_data loops, so its flags were always written.
        if (method_idx < method_flags.size()) {
            cm.access_flags = method_flags[method_idx];
        }
        out.methods.push_back(std::move(cm));
    }
    // Fields declared on this class.
    const auto& field_ids = reader.FieldIds();
    const auto& field_flags = item.GetFieldAccessFlags();
    const auto& field_declared = item.GetFieldAccessFlagsDeclared();
    for (uint32_t field_idx : item.GetClassFieldIds(type_idx)) {
        // UNLIKE the methods above, this loop walks `class_field_ids`, which is
        // keyed on the whole `field_ids` table — so it also yields INHERITED
        // fields this class only REFERENCES (dexllm#41 reported their flags as
        // UNKNOWN; dexllm#45 drops the entries themselves, because a member list
        // that names a declaration the class does not have is wrong whatever it
        // says about its modifiers). The reference view is not lost: it is
        // `list_fields()` filtered by the `Lcls;->` prefix — that is the whole
        // `field_ids` table, so it is a superset, and across a multidex session it
        // repeats a descriptor once per dex holding the entry (dedupe to count).
        if (field_idx >= field_declared.size() || !field_declared[field_idx]) continue;
        const auto& f = field_ids[field_idx];
        FieldInfo cf;
        cf.name = std::string(strings[f.name_idx]);
        cf.type = std::string(type_names[f.type_idx]);
        // Declared here, so the flag slot was written. The bound is UNREACHABLE
        // today — both vectors are sized from `field_ids_size` three lines apart
        // (dex_item.cpp:160/163), so passing the `field_declared` bound above
        // implies this one — and is kept only as a leaf guard. It must never
        // become live: an internal class's fields are documented as having known
        // flags, and taking this branch would emit one with `access_flags` unset.
        if (field_idx < field_flags.size()) {
            cf.access_flags = field_flags[field_idx];
        }
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
    // access_flags stays EMPTY on every member (and on the class itself): there is
    // no class_data here, only the references other classes make (dexllm#41).
    for (auto& [name, proto] : method_keys) {
        MethodInfo cm;
        cm.name = name;
        cm.proto = proto;
        out.methods.push_back(std::move(cm));
    }
    for (auto& [name, type] : field_keys) {
        FieldInfo cf;
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
    // dexllm#69 §3 — stamp the declaring class on every member, in ONE place
    // rather than at each of the four construction sites, so a future third fill
    // path cannot ship members whose `descriptor` property silently reads
    // `->name(proto)ret` with no class in front of it.
    for (auto& m : out.methods) m.class_descriptor = out.descriptor;
    for (auto& f : out.fields) f.class_descriptor = out.descriptor;
    return out;
}

// =================== L7: Find/Match wrappers ===================
//
// These build FlatBuffer queries against the upstream schema, dispatch via
// core_->FindXxx, and convert results back to POD vectors. The matcher tree
// can be deeply nested in upstream; we expose the most common shapes.

std::vector<ClassRef>
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

std::vector<ClassRef>
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

void DexKitExt::EnsureDeclaredStringIndex() {
    // Lazy one-shot, guarded by a plain bool — same pattern and same GIL precondition
    // as EnsureApiResolveIndex (its only caller does not release the GIL).
    if (declared_string_index_built_) return;
    const int dex_num = core_->GetDexNum();

    // Built into a LOCAL and published atomically. Appending straight into the member
    // would, after a mid-build throw (bad_alloc — reachable via the amplification
    // below), leave a PARTIAL index that the next call appends to again, duplicating
    // every already-indexed class for the lifetime of the instance.
    std::vector<std::vector<DeclaredStrings>> built(
        static_cast<size_t>(dex_num < 0 ? 0 : dex_num));
    size_t total_ids = 0;
    for (int i = 0; i < dex_num; ++i) {
        auto* item = core_->GetDexItem(static_cast<uint16_t>(i));
        if (item == nullptr) continue;
        auto& out = built[static_cast<size_t>(i)];
        const auto& reader = item->GetReader();
        const auto class_defs = reader.ClassDefs();
        for (uint32_t ci = 0; ci < class_defs.size(); ++ci) {
            std::vector<uint32_t> ids;
            ScanClassDefStaticStrings(*item, class_defs[ci], ids);
            if (ids.empty()) continue;
            // One encoded_array may legitimately repeat a string id, and a crafted dex
            // can repeat it thousands of times — dedup before storing.
            std::sort(ids.begin(), ids.end());
            ids.erase(std::unique(ids.begin(), ids.end()), ids.end());
            // erase() does not release capacity: a class_def sharing a crafted
            // 100k-entry encoded_array would keep a 400 KB buffer holding ~256 ids,
            // ×4135 class_defs = 1.6 GB of pure slack (measured). Shrink before
            // retaining — the budget below counts LOGICAL ids and would not catch it.
            ids.shrink_to_fit();
            total_ids += ids.size();
            if (total_ids > kMaxDeclaredIds) {
                // `static_values_off` is NOT required to be unique across class_defs
                // (the structural verifier only checks that the array PARSES), so a
                // valid dex can point every class_def at one huge array and make a
                // retained index quadratic — measured 5.7 MB dex → 1.6 GB RSS, reached
                // straight from extract_iocs. Stop retaining and fall back to scanning
                // per query (same results, bounded memory, slower on that input only).
                declared_string_index_.clear();
                declared_string_index_disabled_ = true;
                declared_string_index_built_ = true;
                return;
            }
            out.push_back({class_defs[ci].class_idx, std::move(ids)});
        }
    }
    declared_string_index_ = std::move(built);
    declared_string_index_built_ = true;
}

std::vector<ClassRef>
DexKitExt::FindClassesDeclaringStrings(const std::vector<std::string>& strings,
                                       std::string_view match_type,
                                       bool ignore_case) {
    std::vector<ClassRef> out;
    // Empty query returns nothing. This DIVERGES from the `using` family, where an
    // empty matcher list is vacuously true and returns every class; returning
    // everything for "find classes declaring []" is a footgun, so it is deliberate
    // (documented in the header, the binding docstring and docs/api.md).
    if (strings.empty()) return out;

    // Build the query matchers ONCE, then compare with the core's own
    // DexItem::IsStringMatched so the semantics (kmp, ignore_case, SimilarRegex
    // ^prefix / suffix$) are byte-identical to find_classes_using_strings.
    flatbuffers::FlatBufferBuilder fbb;
    auto type = ParseStringMatchType(match_type);
    std::vector<flatbuffers::Offset<dexkit::schema::StringMatcher>> sms;
    sms.reserve(strings.size());
    for (const auto& s : strings)
        sms.push_back(dexkit::schema::CreateStringMatcher(
            fbb, fbb.CreateString(s), type, ignore_case));
    auto vec = fbb.CreateVector(sms);
    fbb.Finish(vec);
    const auto* matchers = ::flatbuffers::GetRoot<
        ::flatbuffers::Vector<::flatbuffers::Offset<dexkit::schema::StringMatcher>>>(
        fbb.GetBufferPointer());

    // ALL query strings must match (each by SOME declared string of the class) — the
    // match_all=true default of the sibling matchers.
    auto consider = [&](const dexkit::DexItem& item, uint32_t type_idx,
                        const std::vector<uint32_t>& ids) {
        const auto& pool = item.GetStrings();
        for (::flatbuffers::uoffset_t q = 0; q < matchers->size(); ++q) {
            bool any = false;
            for (uint32_t sid : ids) {
                if (sid >= pool.size()) continue;
                if (dexkit::DexItem::IsStringMatched(pool[sid], matchers->Get(q))) {
                    any = true;
                    break;
                }
            }
            if (!any) return;
        }
        const auto& type_names = item.GetTypeNames();
        ClassRef m;
        m.dex_id = item.GetDexId();
        m.class_idx = type_idx;
        if (type_idx < type_names.size())
            m.descriptor = std::string(type_names[type_idx]);
        out.push_back(std::move(m));
    };

    EnsureDeclaredStringIndex();
    if (!declared_string_index_disabled_) {
        for (size_t d = 0; d < declared_string_index_.size(); ++d) {
            auto* item = core_->GetDexItem(static_cast<uint16_t>(d));
            if (item == nullptr) continue;
            for (const auto& entry : declared_string_index_[d])
                consider(*item, entry.type_idx, entry.string_ids);
        }
        KeepFirstPerDescriptor(out);  // dexllm#106 — one row per declared class
        return out;
    }
    // Index refused (crafted amplification) — scan per query instead, discarding each
    // class's ids like ListValueStrings does. Identical results, bounded memory.
    const int dex_num = core_->GetDexNum();
    for (int i = 0; i < dex_num; ++i) {
        auto* item = core_->GetDexItem(static_cast<uint16_t>(i));
        if (item == nullptr) continue;
        const auto class_defs = item->GetReader().ClassDefs();
        for (uint32_t ci = 0; ci < class_defs.size(); ++ci) {
            std::vector<uint32_t> ids;
            ScanClassDefStaticStrings(*item, class_defs[ci], ids);
            if (ids.empty()) continue;
            consider(*item, class_defs[ci].class_idx, ids);
        }
    }
    KeepFirstPerDescriptor(out);
    return out;
}

std::vector<MethodRef>
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

std::map<std::string, std::vector<ClassRef>>
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

    std::map<std::string, std::vector<ClassRef>> out;
    if (holder == nullptr || holder->items() == nullptr) return out;
    for (const auto* item : *holder->items()) {
        std::string key = item->union_key() ? item->union_key()->str() : "";
        std::vector<ClassRef> ms;
        if (item->classes()) {
            for (const auto* cls : *item->classes()) {
                ClassRef m;
                m.dex_id = cls->dex_id();
                m.class_idx = cls->id();
                if (cls->dex_descriptor()) m.descriptor = cls->dex_descriptor()->str();
                ms.push_back(std::move(m));
            }
        }
        out.emplace(std::move(key), std::move(ms));
    }
    // Same ORDER as find_classes_using_strings (dexllm#106). DexKit::FindClass walks
    // each dex's class_defs in index order; DexItem::BatchFindClassUsingStrings walks
    // type_idx order instead, and the two differ wherever a class_def precedes a
    // lower type_idx (a superclass must be defined before its subclasses, so
    // class_defs are not sorted by type). Re-key each hit by (dex_id, class_def
    // position) — a stable sort, so equal keys keep their order — then apply the
    // same first-wins dedupe as the single path.
    std::map<uint32_t, std::vector<uint32_t>> class_def_pos;  // dex_id -> by type_idx
    auto pos_of = [&](const ClassRef& c) -> uint32_t {
        auto it = class_def_pos.find(c.dex_id);
        if (it == class_def_pos.end()) {
            std::vector<uint32_t> pos;
            if (auto* item = core_->GetDexItem(static_cast<uint16_t>(c.dex_id))) {
                pos.assign(item->GetTypeNames().size(), UINT32_MAX);
                const auto defs = item->GetReader().ClassDefs();
                for (uint32_t i = 0; i < defs.size(); ++i)
                    if (defs[i].class_idx < pos.size()) pos[defs[i].class_idx] = i;
            }
            it = class_def_pos.emplace(c.dex_id, std::move(pos)).first;
        }
        return c.class_idx < it->second.size() ? it->second[c.class_idx] : UINT32_MAX;
    };
    for (auto& [key, ms] : out) {
        std::stable_sort(ms.begin(), ms.end(), [&](const ClassRef& a, const ClassRef& b) {
            if (a.dex_id != b.dex_id) return a.dex_id < b.dex_id;
            return pos_of(a) < pos_of(b);
        });
        KeepFirstPerDescriptor(ms);
    }
    return out;
}

std::map<std::string, std::vector<MethodRef>>
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

    std::map<std::string, std::vector<MethodRef>> out;
    if (holder == nullptr || holder->items() == nullptr) return out;
    for (const auto* item : *holder->items()) {
        std::string key = item->union_key() ? item->union_key()->str() : "";
        std::vector<MethodRef> ms;
        if (item->methods()) {
            for (const auto* m : *item->methods()) {
                MethodRef mm;
                mm.dex_id = m->dex_id();
                mm.method_idx = m->id();
                if (m->dex_descriptor()) mm.descriptor = m->dex_descriptor()->str();
                ms.push_back(std::move(mm));
            }
        }
        // dexllm#106: FindMethod drops an already-seen descriptor, the batch does
        // not. Its ORDER already matches (method_ids are sorted by class, which is
        // the order class_method_ids walks), so only the dedupe is needed.
        KeepFirstPerDescriptor(ms);
        out.emplace(std::move(key), std::move(ms));
    }
    return out;
}

std::vector<MethodRef>
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

std::vector<FieldRef>
DexKitExt::FindFieldsByName(std::string_view name,
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

    // FieldMatcher positional args: field_name, access_flags, declaring_class, …
    auto field_matcher = dexkit::schema::CreateFieldMatcher(
        fbb, name_matcher, 0, declaring_offset);
    // FindField positional args: search_packages, exclude_packages,
    // ignore_packages_case, in_classes, in_fields, find_first, matcher
    auto find = dexkit::schema::CreateFindField(
        fbb, 0, 0, false, 0, 0, false, field_matcher);
    fbb.Finish(find);
    auto query = ::flatbuffers::GetRoot<dexkit::schema::FindField>(
        fbb.GetBufferPointer());
    auto result = core_->FindField(query);
    auto holder = ::flatbuffers::GetRoot<dexkit::schema::FieldMetaArrayHolder>(
        result->GetBufferPointer());
    auto matches = ParseFieldMetaArray(holder);
    // dexllm #45: the core scans `class_field_ids`, which is keyed on the whole
    // `field_ids` table, and its declaring-class matcher reads the same
    // `field_id.class_idx` — so an INHERITED field reference matched under the
    // subclass that only references it, and `declaring_class` did not mean
    // declaring. Drop those, so a SCOPED query answers with declarations.
    //
    // ONLY when scoped. An UNSCOPED query keeps references, because that is what
    // the L7 name-search family does — `find_methods_by_name` is declaration-only
    // in its `declaring_class` fast path and NOT without one, so filtering here
    // unconditionally would have made the field arm the odd one out rather than
    // the symmetric one. It also loses real answers: the declaration of an
    // inherited field is often in the FRAMEWORK, so an unconditional filter took
    // `find_fields_by_name("rightMargin")` to 0 hits on the bundled corpus — the
    // app's own accesses, gone. Listing a class's MEMBERS (the other two #45
    // surfaces) and SEARCHING the id tables by name are different questions; only
    // the first is answered with declarations alone.
    //
    // Note neither form scans the whole `field_ids` table: `try_match_field`
    // (dex_item_find.cpp) gates on `type_def_flag[field_def.class_idx]`, so an
    // entry grouped under a class no loaded dex declares is never a hit. That is
    // pre-existing and unchanged here; `list_fields()` is what enumerates those.
    //
    // Filtered HERE, not in the vendored matcher, so upstream FindField semantics
    // are untouched.
    if (!declaring_class.empty()) {
        std::erase_if(matches, [this](const FieldRef& fm) {
            auto* item = core_->GetDexItem(fm.dex_id);
            if (item == nullptr) return true;
            const auto& declared = item->GetFieldAccessFlagsDeclared();
            return fm.field_idx >= declared.size() || !declared[fm.field_idx];
        });
    }
    return matches;
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

std::vector<ClassRef>
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

std::vector<MethodRef>
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

std::vector<ClassRef>
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

std::vector<ClassRef>
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

std::vector<MethodRef>
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

std::vector<MethodRef>
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
    // point (find_call_sites_to / find_call_sites_from — and their deprecated
    // _to_api / _from_method aliases — / resolve_call_args /
    // permission_callers / list_method_strings) is
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

// The L4 analysis moved out of the vendored core (dexllm#32), so its two inputs --
// the decoded code item and the end of the image it lives in -- are read here through
// DexItem's public accessors and handed over.
std::vector<dexkit::ext::InvokeSiteWithArgs>
AnalyzeInvokesOf(const dexkit::DexItem& item, uint32_t method_idx, uint32_t depth) {
    const dex::Code* code = item.GetMethodCode(method_idx);
    if (code == nullptr) return {};
    const dex::u1* img_end = nullptr;
    if (const MemMap* img = item.GetImage())
        img_end = reinterpret_cast<const dex::u1*>(img->data()) + img->len();
    return dexkit::ext::AnalyzeInvokes(code, img_end, depth);
}

const char* ArgKindName(dexkit::ext::ArgKind k) {
    using K = dexkit::ext::ArgKind;
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
std::string BuildFieldDescriptor(const dexkit::DexItem& item, uint32_t field_idx) {
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

ResolvedArg ConvertArg(const dexkit::DexItem& item,
                       const dexkit::ext::InvokeArg& src) {
    ResolvedArg o;
    o.kind = ArgKindName(src.kind);
    o.register_index = src.reg_num;
    o.crossed_branch = src.crossed_branch;
    const auto& reader = item.GetReader();
    const auto& strings = item.GetStrings();
    const auto& type_names = item.GetTypeNames();
    using K = dexkit::ext::ArgKind;
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
            o.field_descriptor = BuildFieldDescriptor(item, src.field_idx);
            break;
        case K::MethodReturn:
            o.method_descriptor =
                BuildMethodDescriptor(item, src.method_idx);
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
DexKitExt::ResolveCallArgs(std::string_view api_descriptor, uint32_t depth) {
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
        auto sites = AnalyzeInvokesOf(item, cr.caller_idx, depth);
        std::string caller_desc = BuildMethodDescriptor(item, cr.caller_idx);
        const bool shadowed = IsShadowedMethod(*core_, item, cr.caller_idx);
        for (const auto& s : sites) {
            if (s.method_idx != cr.local_target) continue;
            ResolvedCallSite cs;
            cs.caller_dex_id = item.GetDexId();
            cs.caller_method_idx = cr.caller_idx;
            cs.caller_descriptor = caller_desc;
            cs.callee_descriptor = std::string(api_descriptor);
            cs.bytecode_offset = static_cast<int32_t>(s.bytecode_offset);
            cs.invoke_opcode = s.opcode;
            cs.shadowed = shadowed;
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
        auto sites = ext::EnumerateInvokeSites(item.GetMethodCode(cr.caller_idx));
        std::string caller_desc = BuildMethodDescriptor(item, cr.caller_idx);
        const bool shadowed = IsShadowedMethod(*core_, item, cr.caller_idx);
        for (const auto& s : sites) {
            if (s.method_idx != cr.local_target) continue;
            CallSite cs;
            cs.caller_dex_id = item.GetDexId();
            cs.caller_method_idx = cr.caller_idx;
            cs.caller_descriptor = caller_desc;
            cs.callee_descriptor = std::string(api_descriptor);
            cs.bytecode_offset = static_cast<int32_t>(s.bytecode_offset);
            cs.invoke_opcode = s.opcode;
            cs.shadowed = shadowed;
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
    std::string caller_desc = BuildMethodDescriptor(item, m_idx);
    // Only the site identity is used here, never the arguments, so the window is the
    // call's own block: depth 0 is the cheapest way to ask for exactly that.
    for (const auto& s : AnalyzeInvokesOf(item, m_idx, /*depth=*/0)) {
        CallSite cs;
        cs.caller_dex_id = item.GetDexId();
        cs.caller_method_idx = m_idx;
        cs.caller_descriptor = caller_desc;
        cs.callee_descriptor = BuildMethodDescriptor(item, s.method_idx);
        cs.bytecode_offset = static_cast<int32_t>(s.bytecode_offset);
        cs.invoke_opcode = s.opcode;
        out.push_back(std::move(cs));
    }
    return out;
}

std::vector<std::string>
DexKitExt::ListMethodStrings(std::string_view method_descriptor) {
    std::vector<std::string> out;

    std::string_view cls, name, proto;
    if (!ParseApiDescriptor(method_descriptor, cls, name, proto)) return out;

    // The body lives in the dex that DECLARES the class (first-wins); an external
    // method has none. Same resolution path as FindCallSitesFromMethod.
    const int dex_id = LocateClassDex(cls);
    if (dex_id < 0) return out;
    auto* item = core_->GetDexItem(static_cast<uint16_t>(dex_id));
    if (item == nullptr) return out;

    EnsureApiResolveIndex();
    if (static_cast<size_t>(dex_id) >= api_resolve_index_.size()) return out;
    const auto& idx = api_resolve_index_[static_cast<size_t>(dex_id)];
    uint32_t cls_type_idx = FindTypeIdxIndexed(idx, cls);
    if (cls_type_idx == dex::kNoIndex) return out;
    uint32_t m_idx = FindMethodIdxIndexed(*item, idx, cls_type_idx, name, proto);
    if (m_idx == dex::kNoIndex) return out;

    // GetUsingStrings is the public const-string index accessor (lazy-builds per
    // method); an abstract / native method has no code_item → empty list.
    std::unordered_set<std::string_view> seen;
    for (std::string_view s : item->GetUsingStrings(m_idx))
        if (seen.insert(s).second) out.emplace_back(s);
    return out;
}

std::vector<std::string>
DexKitExt::ListClassStrings(std::string_view class_descriptor) {
    std::vector<std::string> out;
    auto [item, type_idx] = core_->GetClassDeclaredPair(class_descriptor);
    if (item == nullptr) return out;

    std::unordered_set<std::string_view> seen;
    // (a) const-string / jumbo over the class's DECLARED methods, in ascending
    // method_idx order (class_method_ids is sorted — dex_item.cpp:237 — so this is
    // the dex's per-class method order, NOT source declaration order).
    for (uint32_t m_idx : item->GetClassMethodIds(type_idx))
        for (std::string_view s : item->GetUsingStrings(m_idx))
            if (seen.insert(s).second) out.emplace_back(s);

    // (b) this class's static-field EncodedValue VALUE_STRING (0x17) initializers —
    // the same scan ListValueStrings runs app-wide, scoped to one class_def.
    // Gate on type_def_flag, not on GetTypeDefIdx()==kNoIndex: type_def_idx is
    // value-initialised to 0, so a type with no class_def in this dex would read
    // ClassDefs()[0] — a DIFFERENT class's static values (RenderClassSmali /
    // dex_item.cpp:1650 gate the same way). GetClassDeclaredPair already implies
    // the flag today; this keeps the read correct if that ever loosens.
    if (!item->GetTypeDefFlags()[type_idx]) return out;
    const auto& cdef = item->GetReader().ClassDefs()[item->GetTypeDefIdx(type_idx)];
    std::vector<uint32_t> ids;
    ScanClassDefStaticStrings(*item, cdef, ids);
    const auto& strings = item->GetStrings();
    for (uint32_t sid : ids)
        if (sid < strings.size() && seen.insert(strings[sid]).second)
            out.emplace_back(strings[sid]);
    return out;
}

namespace {

// Locate a field descriptor `Lcls;->name:Type` → (dex_id, field_idx), or (-1, 0).
// Every (dex_id, field_id) whose signature is `fd`, across ALL loaded dexes.
//
// dexllm#36 replaced a "find the class's living dex, then look there" lookup that
// was wrong twice over:
//
//  * it began with `LocateClassDex(cls)`, which resolves only classes DECLARED in
//    a loaded dex — so a FRAMEWORK field returned nothing on every possible input.
//    `list_fields()` hands out those very descriptors, so the library could not
//    xref one it had just produced: a2dp.Vol reads
//    `ContactsContract$PhoneLookup;->CONTENT_FILTER_URI` with a plain `sget-object`
//    and the lookup answered `[]`. That silence is also what made the capability
//    catalog's field entries inert, i.e. the same defect the catalog change fixes,
//    one layer down.
//  * it stopped at ONE dex. A field_id lives in the dex whose CODE references it,
//    so in a multidex app a read from `classes2.dex` is invisible to a lookup that
//    only searched the declaring class's dex — even for an app class.
//
// The index this feeds was never the limitation: `field_get_method_ids` is sized
// to the WHOLE `field_ids` table and populated from `method_using_field_ids`, so
// external field_ids are recorded like any other. Only the gate above blocked it.
//
// It walks the reader's OWN `field_ids` table rather than `class_field_ids`,
// because the latter is emptied for exactly the classes that matter here: the
// core swaps `class_field_ids[type_idx]` into `pending_cross_ref_field_ids` for
// every type the dex does not DECLARE (dex_item.cpp, the `type_def_flag` loop),
// which is the cross-ref aggregation machinery. So the grouped index is empty for
// every framework class, while the raw table always has the entry — and the
// `field_get_method_ids` this ultimately reads is sized to that same raw table.
//
// Cost: one pass over `field_ids` per dex, narrowed by comparing the class part
// first so the signature is only built for a candidate of the right class.
std::vector<std::pair<int, uint32_t>> LocateFields(DexKitExt& ext,
                                                   std::string_view fd) {
    std::vector<std::pair<int, uint32_t>> out;
    const auto arrow = fd.find("->");
    if (arrow == std::string_view::npos) return out;
    const std::string_view cls = fd.substr(0, arrow);
    for (int dex_id = 0; dex_id < ext.DexCount(); ++dex_id) {
        auto* item = ext.core().GetDexItem(static_cast<uint16_t>(dex_id));
        if (item == nullptr) continue;
        const auto& type_names = item->GetTypeNames();
        const auto& field_ids = item->GetReader().FieldIds();
        for (uint32_t fid = 0; fid < field_ids.size(); ++fid) {
            const auto class_idx = field_ids[fid].class_idx;
            if (class_idx >= type_names.size() || type_names[class_idx] != cls) {
                continue;
            }
            if (std::string_view(BuildFieldDescriptor(*item, fid)) == fd) {
                out.emplace_back(dex_id, fid);
                break;  // field_ids are unique per (class, name, type)
            }
        }
    }
    return out;
}

// One field-access site inside a method body: the operand's field_ids index, the
// byte offset within `insns`, and the opcode. The field analogue of
// ext::EnumerateInvokeSites, which used to be DexItem::EnumerateInvokeSites and
// is why this was written HERE rather than beside it: that function sat inside
// the 558-line dexllm block in the vendored file, and a sibling there would have
// grown exactly the pile dexllm#80 existed to shrink. dexllm#80 TOOK it, so the
// argument is spent — both now live under native/core_ext/, and if this ever
// grows past a struct it belongs beside its invoke sibling in invoke_args.cpp.
struct FieldSite {
    uint32_t field_idx;
    uint32_t bytecode_offset;
    uint8_t opcode;
};

// 0x52..0x6D is EXACTLY slicer's `kIndexFieldRef` set — 28 contiguous opcodes,
// formats k21c and k22c, both carrying the field index in code unit 1 — and is the
// same gate InitCache's own collector uses (dex_item.cpp, `need_method_using_field`).
// The quick forms stay OUT: 0xE3-0xE8 / 0xEB-0xF2 are `kIndexFieldOffset` and
// 0xE9/0xEA are `kIndexVtableOffset` (the two are NOT one range — a correctness
// reviewer caught this comment claiming they were), so their operand is an OFFSET
// rather than a field_ids index, which is precisely the confusion dexllm#61 removed
// from the invoke gates. tests/test_field_access_sites.py derives the set from the
// table and pins it.
constexpr bool IsFieldAccessOpcode(uint8_t op) { return op >= 0x52 && op <= 0x6d; }
constexpr bool IsFieldReadOpcode(uint8_t op) {
    return (op >= 0x52 && op <= 0x58) || (op >= 0x60 && op <= 0x66);
}

std::vector<FieldSite> EnumerateFieldAccessSites(const dexkit::DexItem& item,
                                                 uint32_t method_idx) {
    std::vector<FieldSite> out;
    const auto* code = item.GetMethodCode(method_idx);
    if (code == nullptr) return out;  // native / abstract
    const dex::u2* base = code->insns;
    const dex::u2* p = base;
    const dex::u2* end_p = base + code->insns_size;
    while (p < end_p) {
        const auto op = static_cast<uint8_t>(*p);
        const dex::u2* ptr = p;
        const size_t width = GetBytecodeWidth(ptr++);
        if (width == 0) break;  // malformed / payload
        if (IsFieldAccessOpcode(op)) {
            FieldSite site;
            site.field_idx = ReadShort(ptr);
            site.bytecode_offset = static_cast<uint32_t>((p - base) * 2);
            site.opcode = op;
            out.push_back(site);
        }
        p += width;
    }
    return out;
}

// Every READ (writers=false) or WRITE site of a field, as per-INSTRUCTION rows.
//
// Two steps, the same shape FindCallSitesToApi uses: the core's field->accessors
// reverse index supplies the CANDIDATE methods (O(accessors), not a scan of every
// method), then each candidate's body is walked for the offset and opcode the
// index does not keep. Before dexllm#84 only the first step ran and the result was
// the accessor's descriptor repeated once per instruction.
//
// THREAD-SAFETY PRECONDITION (same as the caller-analysis path): the exposed entry
// points (find_field_read_sites / find_field_write_sites) are bound WITHOUT
// py::gil_scoped_release, so the GIL serializes this lazy WarmAnalysisCaches warmup
// and the lazy GetMethodDescriptor population it feeds. Do NOT add
// gil_scoped_release to those bindings without adding a std::once_flag / mutex here.
std::vector<FieldAccessSite> FieldAccessSites(DexKitExt& ext, std::string_view fd,
                                              bool writers) {
    const auto locs = LocateFields(ext, fd);
    if (locs.empty()) return {};
    ext.WarmAnalysisCaches();  // field_get/put_method_ids need the full cache

    // dex_id -> that dex's OWN field_idx for this descriptor. A cross-dex accessor
    // references the field through ITS dex's field_ids entry, so the instruction
    // operand has to be matched against the LOCAL index rather than the declaring
    // dex's — the same re-resolution CollectApiCallers performs for a cross-dex
    // caller. (The core aggregates a field's accessors into the declaring dex,
    // tagged with their origin dex; the source list is cleared, so iterating every
    // location below unions without double-counting.)
    std::unordered_map<uint16_t, uint32_t> local_field;
    for (const auto& [dex_id, fid] : locs)
        local_field.emplace(static_cast<uint16_t>(dex_id), fid);

    std::vector<FieldAccessSite> out;
    for (const auto& [dex_id, fid] : locs) {
        auto* item = ext.core().GetDexItem(static_cast<uint16_t>(dex_id));
        if (item == nullptr) continue;
        const auto& index = writers ? item->GetFieldPutMethodIds()
                                    : item->GetFieldGetMethodIds();
        if (fid >= index.size()) continue;

        // Dedup by (origin_dex, method_idx): the raw index lists an accessor once
        // per ACCESS INSTRUCTION, and the body walk below re-derives every one of
        // those instructions — so without this each site would be emitted as many
        // times as the method accesses the field.
        //
        // The sort is what makes `std::unique` correct, and it is NOT redundant
        // with the final one below: `unique` collapses only ADJACENT equal
        // elements. Dropping it happens to be output-identical today, because
        // InitCache appends a field's entries per (class_def, method) and
        // aggregation appends whole source lists, so one method's entries are
        // contiguous by construction (measured: 0 interleaved runs corpus-wide) —
        // but that is an INCIDENTAL guarantee of how the core builds the index,
        // not a contract, so the dedup does not lean on it.
        std::vector<std::pair<uint16_t, uint32_t>> accessors(index[fid].begin(),
                                                             index[fid].end());
        std::sort(accessors.begin(), accessors.end());
        accessors.erase(std::unique(accessors.begin(), accessors.end()),
                        accessors.end());

        for (const auto& [origin_dex, m_idx] : accessors) {
            auto* owner = (origin_dex == item->GetDexId())
                              ? item
                              : ext.core().GetDexItem(origin_dex);
            if (owner == nullptr) continue;
            const auto local = local_field.find(origin_dex);
            if (local == local_field.end()) continue;  // no field_id there to match
            std::string method_desc = BuildMethodDescriptor(*owner, m_idx);
            const bool shadowed = IsShadowedMethod(ext.core(), *owner, m_idx);
            for (const auto& s : EnumerateFieldAccessSites(*owner, m_idx)) {
                if (s.field_idx != local->second) continue;
                // The index only says the method reads (or writes) the field; the
                // SAME method may do both, so the direction is decided per site.
                if (IsFieldReadOpcode(s.opcode) == writers) continue;
                FieldAccessSite fs;
                fs.method_descriptor = method_desc;
                fs.dex_id = static_cast<uint16_t>(owner->GetDexId());
                fs.method_idx = m_idx;
                fs.field_descriptor = std::string(fd);
                fs.bytecode_offset = static_cast<int32_t>(s.bytecode_offset);
                fs.opcode = s.opcode;
                fs.shadowed = shadowed;
                out.push_back(std::move(fs));
            }
        }
    }
    // Final global order = (accessor's dex, its method_idx, the offset), which is
    // what every layer documents. The loop above emits in that order WITHIN one
    // location, and the shape that could break it ACROSS locations — a class
    // declared with a body in TWO+ dexes (multi-source / add_dumped_dexes(prefer) /
    // packer dump) so that reference-only accessors aggregate into the LOWEST
    // declaring dex while a higher one keeps its own — was NOT reproducible: two
    // independent sweeps (mine over 4 constructed multi-source sessions, a
    // reviewer's over 314,878 queries with this sort REMOVED) found 0 out-of-order
    // results. So this is a defence for a case neither of us could construct, kept
    // for the same reason and in the same position as CollectApiCallers' own final
    // sort, and it is pinned at SOURCE level only (see
    // test_the_row_order_is_a_final_global_sort, which says so).
    //
    // `stable_sort`, not `sort`: the keys are unique on every input measured (0
    // repeated row identities over 463,954 rows across the bundled corpus AND the
    // committed fixtures), but that uniqueness is a consequence of upstream
    // clear()ing a source list after moving it — decided in a thread pool where a
    // dex can be both source and target — so it is a measured property rather than
    // a contract. A stable sort costs nothing and does not lean on it.
    std::stable_sort(out.begin(), out.end(), [](const FieldAccessSite& a,
                                                const FieldAccessSite& b) {
        return std::tie(a.dex_id, a.method_idx, a.bytecode_offset)
             < std::tie(b.dex_id, b.method_idx, b.bytecode_offset);
    });
    return out;
}

}  // namespace

std::vector<FieldAccessSite>
DexKitExt::FindFieldReadSites(std::string_view field_descriptor) {
    return FieldAccessSites(*this, field_descriptor, /*writers=*/false);
}

std::vector<FieldAccessSite>
DexKitExt::FindFieldWriteSites(std::string_view field_descriptor) {
    return FieldAccessSites(*this, field_descriptor, /*writers=*/true);
}

TypeReferences DexKitExt::FindTypeReferences(std::string_view type_descriptor) {
    // Mirrors the WASM binding's findTypeReferences: a signature-position type xref
    // (fields OF the type, methods RETURNING it, methods TAKING it as a param). Scans
    // every dex — a type is referenced from other dexes too. Uses the shared
    // BuildFieldDescriptor / BuildMethodDescriptor so descriptors match every other API.
    //
    // Each descriptor is listed ONCE, in first-occurrence (dex_id) order (dexllm#108).
    // The scan walks every dex's REFERENCE tables (field_ids / method_ids), and any
    // two dexes that both reference a member — ordinary multidex, or a class
    // declared in two loaded dexes — each carry an entry for it, so the lists used
    // to repeat the same string. A row carries no dex id, so a repeat said nothing;
    // dropping it loses no descriptor, including one only a non-resolving copy
    // references.
    TypeReferences out;
    int contributing = 0;
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
        ++contributing;
        const auto& reader = item->GetReader();
        const auto field_ids = reader.FieldIds();
        for (uint32_t fid = 0; fid < field_ids.size(); ++fid) {
            if (field_ids[fid].type_idx == type_idx)
                out.fields.push_back(BuildFieldDescriptor(*item, fid));
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
            std::string sig = BuildMethodDescriptor(*item, mid);
            if (returns && param) out.methods_returning.push_back(sig);
            else if (returns) out.methods_returning.push_back(std::move(sig));
            if (param) out.methods_with_param.push_back(std::move(sig));
        }
    }
    // One dex cannot repeat a descriptor: its field_ids / method_ids are sorted and
    // unique, which the structural verifier enforces in both modes. So the
    // de-duplication runs only when two or more dexes contributed, and a single-dex
    // session pays nothing for it. In place, first occurrence kept: a view is taken
    // of an element only once it is in its final slot, which nothing moves again.
    if (contributing > 1) {
        auto dedupe = [](std::vector<std::string>& v) {
            std::unordered_set<std::string_view> seen;
            seen.reserve(v.size());
            size_t w = 0;
            for (size_t r = 0; r < v.size(); ++r) {
                if (seen.count(v[r])) continue;
                if (w != r) v[w] = std::move(v[r]);
                seen.insert(v[w]);
                ++w;
            }
            v.resize(w);
        };
        dedupe(out.fields);
        dedupe(out.methods_returning);
        dedupe(out.methods_with_param);
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
        out.push_back(BuildFieldDescriptor(*item, fid));
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
        out.push_back(BuildMethodDescriptor(*item, mid));
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

// The byte span of ONE logical dex inside its (possibly shared) image. Shared by
// GetDexBytes and GetDexOrigin so `size` and `len(bytes)` cannot disagree — they
// used to compute it separately, and the clamp sat inside the `base >= map_base`
// guard in one and outside it in the other (unreachable today, since DexItem
// builds its reader at `image + header_off` with an unsigned offset, but a
// duplicated invariant is one edit away from drifting).
//
// A concatenated / packer-dump container is split into logical dexes that SHARE
// one MemMap, each at its own header_off. The reader base (== Header()) is this
// dex's first byte and header->file_size its length; using img->data()/img->len()
// would over-return and mis-attribute siblings. (The WASM extractDexBytes has the
// same omission — fix deferred to the web side.) The clamp to the mapped span is
// a defensive net; VerifyDex already bounds file_size.
static bool LogicalDexSpan(const dexkit::DexItem& item, const dexkit::MemMap& img,
                           const uint8_t*& base_out, std::size_t& size_out) {
    const auto* hdr = item.GetReader().Header();
    if (hdr == nullptr) return false;
    const auto* base = reinterpret_cast<const uint8_t*>(hdr);
    const auto* map_base = reinterpret_cast<const uint8_t*>(img.data());
    if (base < map_base) return false;
    std::size_t n = hdr->file_size;
    const std::size_t avail = img.len() - static_cast<std::size_t>(base - map_base);
    if (n > avail) n = avail;
    base_out = base;
    size_out = n;
    return true;
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
    const uint8_t* base = nullptr;
    std::size_t n = 0;
    if (!LogicalDexSpan(*item, *img, base, n)) return {};
    return std::vector<uint8_t>(base, base + n);
}

// Provenance of one loaded dex (dexllm#26). Resolved through the IMAGE rather
// than by index: `AddImage` runs ParseLogicalDexOffsets, so a concatenated /
// packer-dump source becomes SEVERAL dex_ids over one image and the load-order
// index is not the dex_id. `offset` is this logical dex's start within that
// image — 0 for the ordinary one-dex-per-source case.
DexOrigin DexKitExt::GetDexOrigin(int dex_id) const {
    DexOrigin o;
    // dex_id == -1 must mean OUT OF RANGE and nothing else — that is what the
    // model documents, and what a caller branches on. So stamp it as soon as the
    // id is in range, BEFORE the null-item bail: a logical dex whose DexItem
    // failed to construct (a packer dump whose second dex has an intact header
    // but an undecrypted body) is a real, in-range dex we simply cannot read, and
    // reporting it as -1 made extract_dexes() emit a row that read as "you asked
    // for a bad id" in the MIDDLE of the list. It now identifies itself, with
    // empty bytes and unknown source.
    if (dex_id < 0 || dex_id >= core_->GetDexNum()) return o;
    o.dex_id = dex_id;
    auto* item = core_->GetDexItem(static_cast<uint16_t>(dex_id));
    if (item == nullptr) return o;
    auto* img = item->GetImage();
    if (img == nullptr) return o;
    uint32_t base_offset = 0;
    auto it = image_origin_.find(img);
    if (it != image_origin_.end()) {
        o.source = it->second.source;
        o.entry = it->second.entry;
        base_offset = it->second.base_offset;
    }
    const uint8_t* base = nullptr;
    std::size_t n = 0;
    if (!LogicalDexSpan(*item, *img, base, n)) return o;
    // Offset in the container this dex was READ FROM. `base_offset` is 0 unless
    // the image is a salvaged single-slice copy (a sibling logical dex failed
    // verification), which makes the two cases agree.
    o.offset = base_offset + static_cast<uint32_t>(
        base - reinterpret_cast<const uint8_t*>(img->data()));
    o.size = static_cast<uint32_t>(n);
    return o;
}

}  // namespace dexkit::ext
