// analysis.cpp — see analysis.h. C++ port of dexllm.dangerous_api's join.

#include "analysis.h"

#include <algorithm>
#include <array>
#include <map>
#include <set>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include "api_ref.h"
#include "dexkit_ext.h"
#include "gen/android_api_data.h"
#include "gen/perm_api_data.h"

namespace dexkit::ext {
namespace {

// "Lpkg/Cls$Inner;" -> "pkg.Cls.Inner" (both '/' and '$' → '.'), matching the
// Python index key `ref.java_class.replace("$", ".")`. Non-class descriptors are
// not expected here (a method's declaring class is always Lcls;).
std::string ClassToDotted(std::string_view d) {
    if (d.size() >= 2 && d.front() == 'L' && d.back() == ';')
        d = d.substr(1, d.size() - 2);
    std::string out(d);
    for (char& c : out)
        if (c == '/' || c == '$') c = '.';
    return out;
}

// Last identifier segment of a type path: "java/util/List" / "Foo$Bar" -> the
// tail after the last '/', '.', or '$'. Mirrors dangerous_api._simple_name.
std::string SimpleName(std::string_view s) {
    size_t pos = s.find_last_of("/.$");
    return std::string(pos == std::string_view::npos ? s : s.substr(pos + 1));
}

// Dalvik proto "(...)ret" -> simple param type names. Port of
// dangerous_api._dalvik_param_types (array dims → trailing "[]").
const std::array<std::pair<char, const char*>, 9> kPrim = {{
    {'I', "int"}, {'J', "long"}, {'Z', "boolean"}, {'D', "double"},
    {'F', "float"}, {'B', "byte"}, {'S', "short"}, {'C', "char"}, {'V', "void"},
}};
std::string PrimName(char c) {
    for (const auto& [k, v] : kPrim)
        if (k == c) return v;
    return std::string(1, c);
}
std::vector<std::string> DalvikParamTypes(const std::string& proto) {
    std::vector<std::string> out;
    size_t open_p = proto.find('(');
    size_t close_p = proto.find(')');
    if (open_p == std::string::npos || close_p == std::string::npos ||
        close_p < open_p)
        return out;
    std::string inner = proto.substr(open_p + 1, close_p - open_p - 1);
    size_t i = 0, n = inner.size();
    while (i < n) {
        int dims = 0;
        while (i < n && inner[i] == '[') { ++dims; ++i; }
        if (i >= n) break;
        char c = inner[i];
        std::string base;
        if (c == 'L') {
            size_t j = inner.find(';', i);
            if (j == std::string::npos) break;
            base = SimpleName(inner.substr(i + 1, j - i - 1));
            i = j + 1;
        } else {
            base = PrimName(c);
            ++i;
        }
        for (int d = 0; d < dims; ++d) base += "[]";
        out.push_back(std::move(base));
    }
    return out;
}

const std::array<std::string_view, 11> kFrameworkPrefixes = {{
    "Landroidx/", "Landroid/support/", "Landroid/arch/", "Lkotlin/",
    "Lkotlinx/", "Ljava/", "Ljavax/", "Ldalvik/", "Lcom/google/android/",
    "Lcom/google/common/", "Lcom/google/gson/",
}};
bool IsFrameworkCaller(const std::string& desc) {
    for (std::string_view p : kFrameworkPrefixes)
        if (desc.size() >= p.size() &&
            std::string_view(desc).substr(0, p.size()) == p)
            return true;
    return false;
}

// Whether a dex ref realises the dataset signature `types`. Port of
// dangerous_api._ref_matches: arity is the primary discriminator; exact simple-
// type comparison only as a tiebreak among ≥2 same-arity overloads.
bool RefMatches(const ExternalMethodRef& ref,
                const std::vector<std::string>& types,
                const std::map<int, int>& arity_map) {
    int total = 0;
    for (const auto& [a, c] : arity_map) { (void)a; total += c; }
    if (total <= 1) return true;
    auto ref_types = DalvikParamTypes(ref.proto);
    if (ref_types.size() != types.size()) return false;
    auto it = arity_map.find(static_cast<int>(types.size()));
    if (it == arity_map.end() || it->second <= 1) return true;
    return ref_types == types;
}

}  // namespace

std::vector<PermCallerGroup> PermissionCallers(DexKitExt& ext, bool app_only) {
    // Index the APK's external method refs by (java_class_dotted, method_name),
    // aliasing every <init> under the class simple name (the dataset writes a ctor
    // as `Class#SimpleName(...)`). Mirrors dangerous_api._external_method_index.
    std::map<std::pair<std::string, std::string>, std::vector<ExternalMethodRef>>
        index;
    for (auto& ref : ext.ListExternalMethodRefs(/*framework_only=*/false)) {
        std::string cls = ClassToDotted(ref.class_descriptor);
        index[{cls, ref.name}].push_back(ref);
        if (ref.name == "<init>") {
            std::string simple = SimpleName(cls);
            index[{cls, simple}].push_back(ref);
        }
    }

    const auto& entries = gen::PermApiEntries();
    const auto& overloads = gen::OverloadCounts();

    std::vector<PermCallerGroup> result;
    // entries are emitted grouped/sorted by perm; walk and split on perm change.
    std::string cur_perm;
    PermCallerGroup* group = nullptr;
    for (const auto& e : entries) {
        if (e.perm != cur_perm) {
            cur_perm = e.perm;
            group = nullptr;   // opened lazily only if a row survives
        }
        auto refs_it = index.find({e.cls, e.method});
        if (refs_it == index.end()) continue;

        std::map<int, int> arity_map;
        auto ov = overloads.find({e.cls, e.method});
        if (ov != overloads.end()) arity_map = ov->second;

        std::set<std::string> descriptors;
        std::set<std::string> callers;
        for (const auto& ref : refs_it->second) {
            if (!RefMatches(ref, e.param_types, arity_map)) continue;
            std::string desc =
                ref.class_descriptor + "->" + ref.name + ref.proto;
            descriptors.insert(desc);
            for (const auto& site : ext.FindCallSitesToApi(desc)) {
                if (app_only && IsFrameworkCaller(site.caller_descriptor))
                    continue;
                callers.insert(site.caller_descriptor);
            }
        }
        if (callers.empty()) continue;   // no (kept) caller → drop the API

        if (!group) {
            result.push_back({e.perm, e.level, {}});  // real protection-level bucket
            group = &result.back();
        }
        PermCallerRow row;
        row.api = e.sig;
        row.descriptors.assign(descriptors.begin(), descriptors.end());
        row.callers.assign(callers.begin(), callers.end());
        group->rows.push_back(std::move(row));
    }
    return result;
}

CapabilityReport SummarizeCapabilities(DexKitExt& ext) {
    CapabilityReport r;
    r.catalog_version = std::string(gen::kCapabilityCatalogVersion);
    r.catalog_size = static_cast<int>(gen::CapabilityCatalog().size());

    // caller -> set of permissions, built as sorted sets then flattened.
    std::map<std::string, std::set<std::string>> by_caller;
    for (const auto& e : gen::CapabilityCatalog()) {  // JSON/catalog order
        auto sites = ext.FindCallSitesToApi(e.api_signature);
        if (sites.empty()) continue;  // matches summarize_capabilities' `if not sites`

        CapabilityApiHit hit;
        hit.api_signature = e.api_signature;
        hit.permissions = e.permissions;
        hit.categories = e.categories;
        hit.call_site_count = static_cast<int>(sites.size());

        std::set<std::string> callers;
        for (const auto& s : sites) {
            ++r.total_call_sites;
            callers.insert(s.caller_descriptor);
            for (const auto& perm : e.permissions) {
                ++r.permissions[perm];
                by_caller[s.caller_descriptor].insert(perm);
            }
            for (const auto& cat : e.categories) ++r.categories[cat];
        }
        hit.callers.assign(callers.begin(), callers.end());  // sorted
        r.api_hits.push_back(std::move(hit));
    }
    for (auto& [caller, perms] : by_caller)
        r.by_caller[caller].assign(perms.begin(), perms.end());
    r.matched_apis = static_cast<int>(r.api_hits.size());
    return r;
}

}  // namespace dexkit::ext
