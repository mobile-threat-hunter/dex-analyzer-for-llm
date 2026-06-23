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

// Lightweight container probe — identifies a file by content (dex magic + zip
// central directory / PK signature), NOT by its extension. Lets callers verify
// a disguised .apk (wrong/absent extension) before loading, the way a malware
// analyst inspects the magic bytes rather than trusting the filename.
struct ContainerInfo {
    std::string format;         // "dex" | "zip" | "unknown"
    bool has_manifest = false;  // AndroidManifest.xml present (zip only)
    bool is_apk = false;        // zip container that carries an AndroidManifest.xml
    int dex_count = 0;          // sequential classes*.dex (zip) or 1 (raw .dex)
};

// Per-dex structural-verification verdict (DexVerifier at the load boundary).
// A rejected dex is never handed to the core, so it contributes no
// classes/methods; `reason` names the first structural violation (ART
// DexFileVerifier-style). `name` is the source entry (e.g. "classes2.dex") or
// the file path for a raw .dex.
struct DexVerifyStatus {
    int dex_id = 0;
    std::string name;
    bool valid = true;
    std::string reason;         // empty when valid
};

class DexKitExt {
public:
    // Content-based probe; performs no load. Safe on any path. Returns
    // format=="unknown" when the file is missing/empty or is neither a raw
    // .dex nor a valid zip/apk container.
    static ContainerInfo Identify(const std::string& path);

    explicit DexKitExt(const std::string& apk_path);

    // Multi-source load with PRIORITY BY ORDER. Each source (a raw .dex or a
    // zip/apk) is verified and loaded in turn, so sources earlier in the list get
    // lower dex_ids. Because class resolution is first-wins (lowest dex_id), the
    // FIRST source wins a class-descriptor collision — load a runtime-decrypted /
    // dumped dex BEFORE the original apk to make the unpacked class win (mirrors
    // ART, where the packer orders the decrypted dex first). apk_path() reports
    // the first source. Throws if no source yields a structurally-valid dex.
    explicit DexKitExt(const std::vector<std::string>& sources);

    ~DexKitExt();

    DexKitExt(const DexKitExt&) = delete;
    DexKitExt& operator=(const DexKitExt&) = delete;

    // Lazy-construct + return the IDexCodeSource adapter for the Decompiler.
    // Lifetime: same as this DexKitExt instance.
    class DexItemCodeSource& GetCodeSource();

    [[nodiscard]] int DexCount() const;
    [[nodiscard]] const std::string& GetApkPath() const { return apk_path_; }

    // Structural-verification report, one entry per dex the loader considered.
    // Rejected dexes (valid==false) were screened out at the load boundary with
    // a specific reason and never reached the core.
    [[nodiscard]] const std::vector<DexVerifyStatus>& VerifyReport() const {
        return verify_status_;
    }

    // Locate which dex_id defines the given class descriptor; -1 if not declared
    // in any loaded dex (i.e. external Android API or app-external reference).
    [[nodiscard]] int LocateClassDex(std::string_view class_descriptor) const;

    // L8 — class/method enumeration for DAD-aligned decompilation drivers
    // (replaces androguard's AnalyzeAPK→get_classes / cls.get_methods walk).
    // Returns descriptors of every class defined in any loaded dex, in
    // type-id order. External-only refs (no class_def in any dex) excluded.
    [[nodiscard]] std::vector<std::string> ListClasses() const;

    // Every distinct string the app loads as a VALUE — a `const-string`/
    // `const-string/jumbo` (0x1a/0x1b) bytecode operand, or a static-field
    // EncodedValue VALUE_STRING (0x17, incl. nested in arrays). Raw MUTF-8,
    // deduplicated; the caller decodes to UTF-8. Excludes identifier/metadata
    // strings (type descriptors, method/field names, shorty, source files, debug
    // names) that make up most of the raw pool — the foundation for static IOC /
    // C2 extraction without package denoising. Strings come from each DexItem's
    // string pool (process-lifetime), copied to owned std::string here so the
    // result outlives the call. (Annotation-embedded 0x17 omitted: framework
    // metadata, never an app data value.)
    [[nodiscard]] std::vector<std::string> ListValueStrings() const;

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
    // Verify + collect the structurally-valid dex(es) of ONE source (raw .dex or
    // zip/apk) onto the end of `out`, recording per-dex verdicts in verify_status_
    // with the running combined dex_id. Throws if the source can't be opened or
    // isn't a dex/zip container; per-dex verify failures are recorded and skipped.
    void CollectSource(const std::string& path,
                       std::vector<std::unique_ptr<dexkit::MemMap>>& out);

    std::string apk_path_;
    std::unique_ptr<dexkit::DexKit> core_;
    bool analysis_caches_warm_ = false;
    std::unique_ptr<DexItemCodeSource> code_source_;  // lazy-constructed
    std::vector<DexVerifyStatus> verify_status_;      // load-boundary verdicts
};

// Public for testing/customisation: returns true if the descriptor is a
// standard Android/Java framework type (Landroid/, Ljava/, Lkotlin/, ...).
[[nodiscard]] bool IsFrameworkDescriptor(std::string_view descriptor);

}  // namespace dexkit::ext
