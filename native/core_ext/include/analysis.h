// analysis.h — high-level security analysis over a loaded DexKitExt.
//
// Permission-caller analysis (issue #14): the permission -> gated-API -> caller
// join over the bundled AOSP data, exposed as a C++ engine port callable from BOTH
// the pybind11 (Python) and embind (WASM) bindings so consumers share ONE
// implementation. The dataset is embedded via build-time codegen
// (native/core_ext/gen/perm_api_data.h) — no runtime JSON.
//
// This is a faithful C++ port of dexllm.dangerous_api's join; the intricate
// Java/Kotlin signature normalisation is done ONCE, at codegen time, by the same
// Python code the Python path uses (scripts/gen_perm_api_data.py), so the two
// paths cannot drift on the normalisation.
//
// (The IoC / content-provider / capability C++ engine ports were removed: dexllm's
// own API uses the canonical pure-Python dexllm.ioc / providers / capability, so
// the C++ mirrors were web-only. A WASM consumer must vendor its own engine.)

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

// A permission and the used, called APIs gating it.
struct PermCallerGroup {
    std::string perm;
    std::string protection_level;          // bucket: dangerous/signature/internal/normal/other
    std::vector<PermCallerRow> rows;
};

// Mirror of dexllm.dangerous_api.permission_api_callers (bundled data) — the FULL
// permission surface across ALL protection levels (issue #14), each group carrying
// its real `protection_level` bucket. For each permission whose gated APIs are
// referenced by the APK's external method refs, resolve each used API to its matched
// overload descriptor(s) and the methods that invoke it. `app_only` (default true)
// drops callers that are bundled framework / official-library code (androidx /
// kotlin / java / com.google.android …); an API whose only callers are framework
// code is omitted. Groups/rows with no kept caller are omitted. Deterministic.
std::vector<PermCallerGroup> PermissionCallers(DexKitExt& ext, bool app_only = true);

}  // namespace dexkit::ext
