// analysis.h — high-level security analysis over a loaded DexKitExt.
//
// Issue #13: expose the engine's finished, data-bundled analysis (permission
// callers / IoC / capabilities) as a SINGLE source of truth callable from BOTH
// the pybind11 (Python) and embind (WASM) bindings, so consumers stop
// re-implementing the join and forking the AOSP datasets. The datasets are
// embedded via build-time codegen (native/core_ext/gen/*.h) — no runtime JSON,
// no shipped data files.
//
// This is a faithful C++ port of the Python public API's join logic; the intricate
// Java/Kotlin signature normalisation is done ONCE, at codegen time, by the same
// Python code the Python path uses (scripts/gen_perm_api_data.py), so the two
// paths cannot drift on the normalisation.

#pragma once

#include <string>
#include <utility>
#include <vector>

namespace dexkit::ext {

class DexKitExt;

// One dataset API and who calls it, within one permission.
struct PermCallerRow {
    std::string api;                       // the full dataset signature (pkg.Class#m(params))
    std::vector<std::string> descriptors;  // resolved Lcls;->name(proto) overload(s) matched
    std::vector<std::string> callers;      // distinct caller method descriptors
};

// A dangerous permission and the used, called APIs gating it.
struct PermCallerGroup {
    std::string perm;
    std::string protection_level;          // always "dangerous" (bundled slice)
    std::vector<PermCallerRow> rows;
};

// Mirror of dexllm.dangerous_api.dangerous_permission_api_callers (bundled data).
// For each dangerous permission whose gated APIs are actually referenced by the
// APK's external method refs, resolve each used API to its matched overload
// descriptor(s) and the methods that invoke it. `app_only` (default true) drops
// callers that are bundled framework / official-library code (androidx / kotlin /
// java / com.google.android …); an API whose only callers are framework code is
// omitted. Groups/rows with no kept caller are omitted. Deterministic (sorted).
std::vector<PermCallerGroup> PermissionCallers(DexKitExt& ext, bool app_only = true);

// ---------------------------------------------------------------------------
// IoC extraction (issue #13) — C++ port of dexllm.ioc.extract_iocs, so the WASM
// (embind) and pybind bindings share ONE implementation over the bundled public-
// suffix data (public_suffix.cpp / gen/psl_data.h) instead of dexllm-web
// re-implementing the scan + shipping its own PSL copy. Byte-identical to the
// Python path (verified by a full-corpus differential test).

// One network indicator and the methods that reference it (the "where in code"
// xref). Mirrors a Python `{"value": ..., "methods": [...]}` row.
struct IocIndicator {
    std::string value;
    std::vector<std::string> methods;  // referencing method descriptors (may be empty)
};

// Network indicators bucketed by category, in dexllm.ioc.IOC_CATEGORIES order.
// Each list is sorted by value; the `methods` xref is populated highest-signal
// category first within an overall budget (mirrors extract_iocs's _XREF_PRIORITY).
struct IocResult {
    std::vector<IocIndicator> urls;
    std::vector<IocIndicator> ips;
    std::vector<IocIndicator> domains;
    std::vector<IocIndicator> emails;
    std::vector<IocIndicator> onion;
};

// Mirror of dexllm.ioc.extract_iocs. Scans ext.ListValueStrings() with the same
// refang + bounded regexes, validates bare domains against the bundled PSL, and
// (with_xref) attaches referencing methods via FindMethodsUsingStrings. `denoise`
// drops residual identifier hosts (dex package prefixes, xmlns authorities);
// `xref_limit` caps the number of cross-referenced indicators.
IocResult ExtractIocs(DexKitExt& ext, bool with_xref = true, bool denoise = true,
                      int xref_limit = 300);

// Test seam: run ONLY the scanners (refang + the five patterns + PSL validation +
// URL-host fold, denoise off, no xref) over a SUPPLIED string list — no DexKit
// needed. Lets a unit test inject crafted strings into a byte-identical
// differential against the Python scan (the corpus gate cannot inject strings).
// Returns each category's sorted values (IocIndicator.methods empty).
IocResult IocScanStrings(const std::vector<std::string>& strings);

// One content:// provider-URI hit: a bundled dataset URI referenced by the app,
// its provider `family`, and the referencing methods (xref).
struct ProviderHit {
    std::string uri;
    std::string family;
    std::vector<std::string> methods;
};

// Mirror of dexllm.providers.detect_content_providers (issue #13). A bundled
// content:// URI (gen/content_uris_data.h) is reported iff it occurs as a
// SUBSTRING of some value-string; `family` comes from the dataset and (with_xref)
// `methods` from the same L7 search the network IoCs use. Sorted by URI.
std::vector<ProviderHit> DetectContentProviders(DexKitExt& ext,
                                                bool with_xref = true,
                                                int xref_limit = 300);

// Test seam: the content:// substring match over a SUPPLIED string list (no xref).
// Returns (uri, family) hits sorted by URI, mirroring providers.match_content_uris.
std::vector<std::pair<std::string, std::string>> DetectProvidersFromStrings(
    const std::vector<std::string>& strings);

}  // namespace dexkit::ext
