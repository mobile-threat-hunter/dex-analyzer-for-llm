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

}  // namespace dexkit::ext
