// dexkit_ext.h — thin extension over dexkit::DexKit that exposes data
// to the in-process DexKit-DAD decompiler and (future) Android API analysis.

#pragma once

#include <memory>
#include <string>
#include <string_view>
#include <vector>

#include "api_ref.h"
#include "dexkit.h"  // upstream LuckyPray DexKit

namespace dexkit::ext {

class DexKitExt {
public:
    explicit DexKitExt(const std::string& apk_path);
    ~DexKitExt();

    DexKitExt(const DexKitExt&) = delete;
    DexKitExt& operator=(const DexKitExt&) = delete;

    // Lazy-construct + return the IDexCodeSource adapter for the Decompiler.
    // Lifetime: same as this DexKitExt instance.
    class DexItemCodeSource& GetCodeSource();

    [[nodiscard]] int DexCount() const;
    [[nodiscard]] const std::string& GetApkPath() const { return apk_path_; }

    // Locate which dex_id defines the given class descriptor; -1 if not declared
    // in any loaded dex (i.e. external Android API or app-external reference).
    [[nodiscard]] int LocateClassDex(std::string_view class_descriptor) const;

    // L8 — class/method enumeration for DAD-aligned decompilation drivers
    // (replaces androguard's AnalyzeAPK→get_classes / cls.get_methods walk).
    // Returns descriptors of every class defined in any loaded dex, in
    // type-id order. External-only refs (no class_def in any dex) excluded.
    [[nodiscard]] std::vector<std::string> ListClasses() const;

    // For each declared method of the given class descriptor, returns the
    // full Dalvik method descriptor `Lcls;->name(proto)ret`. Empty if class
    // is not declared in any loaded dex.
    [[nodiscard]] std::vector<std::string>
    ListClassMethods(std::string_view class_descriptor) const;

    // L1 — external reference enumeration. "External" means the descriptor's
    // class is not declared in any loaded dex. When framework_only is true,
    // results are further filtered to standard framework prefixes (android.*,
    // java.*, kotlin.*, ...) so user-extracted system code is excluded.
    [[nodiscard]] std::vector<ExternalTypeRef>
    ListExternalTypeRefs(bool framework_only = true) const;

    [[nodiscard]] std::vector<ExternalMethodRef>
    ListExternalMethodRefs(bool framework_only = true) const;

    [[nodiscard]] std::vector<ExternalFieldRef>
    ListExternalFieldRefs(bool framework_only = true) const;

    // L2 — return every call site that invokes the API described by
    // "Lpkg/Cls;->name(args)Ret;". Triggers a lazy warmup of upstream
    // caches (kMethodInvoking) on first call; subsequent calls are fast.
    [[nodiscard]] std::vector<CallSite>
    FindCallSitesToApi(std::string_view api_descriptor);

    // L1.5 — produce a single-class summary suitable for Java-source-style
    // rendering. Works for both internal and external classes (see ClassSummary
    // docs). Returns a default-constructed ClassSummary with descriptor="" if
    // the class isn't referenced anywhere in the loaded APK.
    [[nodiscard]] ClassSummary GetClassSummary(std::string_view descriptor) const;

    // L7 — Find/Match wrappers over upstream's matcher engine. These build
    // FlatBuffer queries, invoke upstream FindClass/FindMethod/etc., and
    // convert the FlatBuffer results back to POD vectors for clean Python
    // binding. match_type: "equals" | "contains" | "starts_with" | "ends_with" | "regex".

    // Find classes whose name (Java-style or descriptor) matches a pattern.
    [[nodiscard]] std::vector<ClassMatch>
    FindClassesByName(std::string_view name,
                      std::string_view match_type = "contains",
                      bool ignore_case = false);

    // Find classes whose bytecode uses the given strings.
    // If match_all is true (default) the class must contain ALL strings;
    // otherwise ANY match suffices.
    [[nodiscard]] std::vector<ClassMatch>
    FindClassesUsingStrings(const std::vector<std::string>& strings,
                            std::string_view match_type = "contains",
                            bool ignore_case = false);

    // Find methods whose body uses the given strings.
    [[nodiscard]] std::vector<MethodMatch>
    FindMethodsUsingStrings(const std::vector<std::string>& strings,
                            std::string_view match_type = "contains",
                            bool ignore_case = false);

    // Batch class-by-strings query: {key → [strings]}. Returns {key → matches}.
    // Far faster than running N independent FindClassesUsingStrings calls
    // (upstream uses a shared Aho-Corasick trie internally).
    [[nodiscard]] std::map<std::string, std::vector<ClassMatch>>
    BatchFindClassesUsingStrings(
        const std::map<std::string, std::vector<std::string>>& query_map,
        std::string_view match_type = "contains",
        bool ignore_case = false);

    // Batch method-by-strings query.
    [[nodiscard]] std::map<std::string, std::vector<MethodMatch>>
    BatchFindMethodsUsingStrings(
        const std::map<std::string, std::vector<std::string>>& query_map,
        std::string_view match_type = "contains",
        bool ignore_case = false);

    // Find methods by name (optionally scoped to a declaring class).
    [[nodiscard]] std::vector<MethodMatch>
    FindMethodsByName(std::string_view name,
                      std::string_view match_type = "contains",
                      std::string_view declaring_class = "",
                      bool ignore_case = false);

    // Annotation-based search. annotation_class is matched against the
    // annotation's declared class descriptor (e.g. "Lkotlin/Metadata;").
    [[nodiscard]] std::vector<ClassMatch>
    FindClassesByAnnotation(std::string_view annotation_class,
                            std::string_view match_type = "equals");

    [[nodiscard]] std::vector<MethodMatch>
    FindMethodsByAnnotation(std::string_view annotation_class,
                            std::string_view match_type = "equals");

    // Structural class queries.
    [[nodiscard]] std::vector<ClassMatch>
    FindClassesBySuperclass(std::string_view super_class_name,
                            std::string_view match_type = "equals");

    [[nodiscard]] std::vector<ClassMatch>
    FindClassesImplementing(std::string_view interface_class_name,
                            std::string_view match_type = "equals");

    // Numeric literal matchers. The two flavors map to upstream's
    // EncodeValueInt and EncodeValueDouble (the most common cases).
    // Accepts arbitrary Python ints; values are masked to int32_t before
    // being put into EncodeValueInt (matches dex int storage semantics, so
    // 0xCAFEBABE passed from Python matches the same value in dex as
    // -889275714 in two's-complement).
    [[nodiscard]] std::vector<MethodMatch>
    FindMethodsUsingIntLiterals(const std::vector<int64_t>& values);

    [[nodiscard]] std::vector<MethodMatch>
    FindMethodsUsingDoubleLiterals(const std::vector<double>& values);

    // L4 — for every call site that invokes the given API, walk the caller's
    // bytecode and resolve each argument register to a ConstString / ConstInt /
    // ConstClass / Parameter / FieldRead / MethodReturn / Unknown origin via
    // basic-block-scoped forward register simulation.
    [[nodiscard]] std::vector<ResolvedCallSite>
    ResolveCallArgs(std::string_view api_descriptor);

    // L5 — baksmali-style text rendering. RenderMethod returns empty string
    // for unknown / native / abstract methods. RenderClass returns empty if
    // the class isn't declared in any loaded dex (external).
    [[nodiscard]] std::string
    RenderMethodSmali(std::string_view method_descriptor) const;

    [[nodiscard]] std::string
    RenderClassSmali(std::string_view class_descriptor) const;

    // Eager warm-up of upstream analysis caches needed for L2/L4. Optional;
    // FindCallSitesToApi calls this internally if not already warmed.
    void WarmAnalysisCaches();

    // Access to the underlying upstream DexKit (for advanced callers; binding
    // layer should prefer the typed methods above).
    dexkit::DexKit& core() { return *core_; }

private:
    std::string apk_path_;
    std::unique_ptr<dexkit::DexKit> core_;
    bool analysis_caches_warm_ = false;
    std::unique_ptr<DexItemCodeSource> code_source_;  // lazy-constructed
};

// Public for testing/customisation: returns true if the descriptor is a
// standard Android/Java framework type (Landroid/, Ljava/, Lkotlin/, ...).
[[nodiscard]] bool IsFrameworkDescriptor(std::string_view descriptor);

}  // namespace dexkit::ext
