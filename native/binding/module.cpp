// pybind11 entry point for the dexllm Python package.
//
// Wires Python → DexKitExt → DexKit Core, plus the dad_cpp Decompiler stub.
// The decompile_* family currently returns a stub message; real output lands
// as `native/dad_cpp/` is ported from androguard DAD (see CLAUDE.md).

#include <pybind11/pybind11.h>
#include <pybind11/stl.h>

#include <map>
#include <string>
#include <vector>

#include "api_ref.h"
#include "decompiler.h"
#include "dexitem_code_source.h"
#include "dexkit_ext.h"

namespace py = pybind11;

namespace {

// Decode dex MUTF-8 → standard UTF-8 so pybind11's strict UTF-8 str decode
// accepts it. Lone surrogates (invalid in UTF-8) become U+FFFD.
std::string DecodeMutf8ForPy(std::string_view raw) {
    std::string out;
    out.reserve(raw.size());
    const uint8_t* p = reinterpret_cast<const uint8_t*>(raw.data());
    const uint8_t* end = p + raw.size();
    auto emit_cp = [&](uint32_t cp) {
        if (cp >= 0xD800 && cp <= 0xDFFF) cp = 0xFFFD;  // lone surrogate
        if (cp < 0x80) {
            out += static_cast<char>(cp);
        } else if (cp < 0x800) {
            out += static_cast<char>(0xC0 | (cp >> 6));
            out += static_cast<char>(0x80 | (cp & 0x3F));
        } else if (cp < 0x10000) {
            out += static_cast<char>(0xE0 | (cp >> 12));
            out += static_cast<char>(0x80 | ((cp >> 6) & 0x3F));
            out += static_cast<char>(0x80 | (cp & 0x3F));
        } else {
            out += static_cast<char>(0xF0 | (cp >> 18));
            out += static_cast<char>(0x80 | ((cp >> 12) & 0x3F));
            out += static_cast<char>(0x80 | ((cp >> 6) & 0x3F));
            out += static_cast<char>(0x80 | (cp & 0x3F));
        }
    };
    while (p < end) {
        uint8_t c = *p;
        if (c < 0x80) { out += static_cast<char>(c); ++p; continue; }
        uint32_t cp = 0; size_t n = 0;
        if ((c & 0xE0) == 0xC0) { cp = c & 0x1F; n = 2; }
        else if ((c & 0xF0) == 0xE0) { cp = c & 0x0F; n = 3; }
        else if ((c & 0xF8) == 0xF0) { cp = c & 0x07; n = 4; }
        else { emit_cp(0xFFFD); ++p; continue; }
        if (p + n > end) { emit_cp(0xFFFD); ++p; continue; }
        bool bad = false;
        for (size_t i = 1; i < n; ++i) {
            if ((p[i] & 0xC0) != 0x80) { bad = true; break; }
            cp = (cp << 6) | (p[i] & 0x3F);
        }
        if (bad) { emit_cp(0xFFFD); ++p; continue; }
        if (cp >= 0xD800 && cp <= 0xDBFF && p + n + 3 <= end &&
            (p[n] & 0xF0) == 0xE0 && (p[n + 1] & 0xC0) == 0x80 &&
            (p[n + 2] & 0xC0) == 0x80) {
            uint32_t lo = ((p[n] & 0x0F) << 12) | ((p[n + 1] & 0x3F) << 6) |
                          (p[n + 2] & 0x3F);
            if (lo >= 0xDC00 && lo <= 0xDFFF) {
                emit_cp(0x10000 + ((cp - 0xD800) << 10) + (lo - 0xDC00));
                p += n + 3;
                continue;
            }
        }
        emit_cp(cp);
        p += n;
    }
    return out;
}

// Recursively convert a dad::AstValue into native Python objects (mirroring
// DAD's nested-list AST: lists/tuples → list, None → None, ints, bools, strs).
py::object AstToPy(const dexkit::dad::AstValue& v) {
    using K = dexkit::dad::AstValue::Kind;
    switch (v.kind()) {
        case K::Null: return py::none();
        case K::Bool: return py::bool_(v.as_bool());
        case K::Int:  return py::int_(v.as_int());
        case K::Str:  return py::str(DecodeMutf8ForPy(v.as_str()));
        case K::Arr: {
            py::list out;
            for (const auto& e : v.as_arr()) out.append(AstToPy(e));
            return std::move(out);
        }
        case K::Obj: {
            py::dict out;
            for (const auto& kv : v.as_obj())
                out[py::str(kv.first)] = AstToPy(kv.second);
            return std::move(out);
        }
    }
    return py::none();
}

class PyDexKit {
public:
    explicit PyDexKit(const std::string& apk_path)
        : ext_(apk_path),
          decompiler_(std::make_unique<dexkit::dad::Decompiler>(
              ext_.GetCodeSource())) {}

    int dex_count() const { return ext_.DexCount(); }
    const std::string& apk_path() const { return ext_.GetApkPath(); }
    int locate_class_dex(const std::string& descriptor) const {
        return ext_.LocateClassDex(descriptor);
    }
    std::vector<std::string> list_classes() const {
        return ext_.ListClasses();
    }
    py::list verify_report() const {
        py::list out;
        for (const auto& s : ext_.VerifyReport()) {
            py::dict d;
            d["dex_id"] = s.dex_id;
            d["name"] = s.name;
            d["valid"] = s.valid;
            d["reason"] = s.reason;
            out.append(std::move(d));
        }
        return out;
    }
    std::vector<std::string>
    list_class_methods(const std::string& class_descriptor) const {
        return ext_.ListClassMethods(class_descriptor);
    }

    std::vector<dexkit::ext::ExternalTypeRef>
    list_external_type_refs(bool framework_only) const {
        return ext_.ListExternalTypeRefs(framework_only);
    }
    std::vector<dexkit::ext::ExternalMethodRef>
    list_external_method_refs(bool framework_only) const {
        return ext_.ListExternalMethodRefs(framework_only);
    }
    std::vector<dexkit::ext::ExternalFieldRef>
    list_external_field_refs(bool framework_only) const {
        return ext_.ListExternalFieldRefs(framework_only);
    }

    std::vector<dexkit::ext::CallSite>
    find_call_sites_to_api(const std::string& api_descriptor) {
        return ext_.FindCallSitesToApi(api_descriptor);
    }
    void warm_analysis_caches() { ext_.WarmAnalysisCaches(); }
    dexkit::ext::ClassSummary
    get_class_summary(const std::string& descriptor) const {
        return ext_.GetClassSummary(descriptor);
    }

    // L7 — Find/Match wrappers
    std::vector<dexkit::ext::ClassMatch>
    find_classes_by_name(const std::string& name,
                         const std::string& match_type,
                         bool ignore_case) {
        return ext_.FindClassesByName(name, match_type, ignore_case);
    }
    std::vector<dexkit::ext::ClassMatch>
    find_classes_using_strings(const std::vector<std::string>& strings,
                               const std::string& match_type,
                               bool ignore_case) {
        return ext_.FindClassesUsingStrings(strings, match_type, ignore_case);
    }
    std::vector<dexkit::ext::MethodMatch>
    find_methods_using_strings(const std::vector<std::string>& strings,
                               const std::string& match_type,
                               bool ignore_case) {
        return ext_.FindMethodsUsingStrings(strings, match_type, ignore_case);
    }
    std::map<std::string, std::vector<dexkit::ext::ClassMatch>>
    batch_find_classes_using_strings(
        const std::map<std::string, std::vector<std::string>>& q,
        const std::string& match_type, bool ignore_case) {
        return ext_.BatchFindClassesUsingStrings(q, match_type, ignore_case);
    }
    std::map<std::string, std::vector<dexkit::ext::MethodMatch>>
    batch_find_methods_using_strings(
        const std::map<std::string, std::vector<std::string>>& q,
        const std::string& match_type, bool ignore_case) {
        return ext_.BatchFindMethodsUsingStrings(q, match_type, ignore_case);
    }
    std::vector<dexkit::ext::MethodMatch>
    find_methods_by_name(const std::string& name,
                         const std::string& match_type,
                         const std::string& declaring_class,
                         bool ignore_case) {
        return ext_.FindMethodsByName(name, match_type, declaring_class, ignore_case);
    }
    std::vector<dexkit::ext::ClassMatch>
    find_classes_by_annotation(const std::string& a, const std::string& mt) {
        return ext_.FindClassesByAnnotation(a, mt);
    }
    std::vector<dexkit::ext::MethodMatch>
    find_methods_by_annotation(const std::string& a, const std::string& mt) {
        return ext_.FindMethodsByAnnotation(a, mt);
    }
    std::vector<dexkit::ext::ClassMatch>
    find_classes_by_super(const std::string& s, const std::string& mt) {
        return ext_.FindClassesBySuperclass(s, mt);
    }
    std::vector<dexkit::ext::ClassMatch>
    find_classes_implementing(const std::string& i, const std::string& mt) {
        return ext_.FindClassesImplementing(i, mt);
    }
    std::vector<dexkit::ext::MethodMatch>
    find_methods_using_int_literals(const std::vector<int64_t>& vs) {
        return ext_.FindMethodsUsingIntLiterals(vs);
    }
    std::vector<dexkit::ext::MethodMatch>
    find_methods_using_double_literals(const std::vector<double>& vs) {
        return ext_.FindMethodsUsingDoubleLiterals(vs);
    }
    std::vector<dexkit::ext::ResolvedCallSite>
    resolve_call_args(const std::string& api_descriptor) {
        return ext_.ResolveCallArgs(api_descriptor);
    }
    std::string render_method_smali(const std::string& descriptor) const {
        return ext_.RenderMethodSmali(descriptor);
    }
    std::string render_class_smali(const std::string& descriptor) const {
        return ext_.RenderClassSmali(descriptor);
    }
    // Both decompile_method_java and decompile_method route through the
    // new dad_cpp Decompiler. The `_java` suffix is preserved for API
    // back-compat with existing tooling (sweep script, /dexkit-* skills).
    std::string decompile_method_java(const std::string& descriptor) const {
        return decompiler_->DecompileMethod(descriptor);
    }
    std::string decompile_class_java(const std::string& descriptor) const {
        return decompiler_->DecompileClass(descriptor);
    }

    std::string decompile_class(const std::string& descriptor) {
        return decompiler_->DecompileClass(descriptor);
    }
    std::string decompile_method(const std::string& descriptor) {
        return decompiler_->DecompileMethod(descriptor);
    }
    py::dict decompile_method_ast(const std::string& descriptor,
                                  bool include_source) {
        auto ast = decompiler_->DecompileMethodAst(descriptor, include_source);
        py::dict out;
        out["found"] = ast.found;
        out["cls_name"] = ast.cls_name;
        out["name"] = ast.name;
        out["proto"] = ast.proto;
        out["ret_type"] = ast.ret_type;
        out["params_type"] = ast.params_type;
        out["access"] = ast.access;
        out["source"] = ast.source;
        // Full nested AST (DAD dast.py get_ast): {triple, flags, ret, params,
        // comments, body}. None if the method was not found / failed.
        out["ast"] = AstToPy(ast.ast);
        return out;
    }
    void decompiler_clear_cache() { decompiler_->ClearCache(); }
    std::size_t decompiler_cache_size() const { return decompiler_->CacheSize(); }
    void decompiler_set_cache_capacity(std::size_t cap) {
        decompiler_->SetCacheCapacity(cap);
    }
    std::size_t decompiler_cache_capacity() const {
        return decompiler_->CacheCapacity();
    }

private:
    dexkit::ext::DexKitExt ext_;
    std::unique_ptr<dexkit::dad::Decompiler> decompiler_;
};

}  // namespace

PYBIND11_MODULE(_dexkit_core, m) {
    m.doc() = "dexllm native module (L1)";

    // Content-based container probe (no load). Identifies a file by its magic
    // bytes / zip central directory rather than its extension, so a disguised
    // .apk can be proven before loading.
    m.def(
        "identify",
        [](const std::string& path) {
            auto info = dexkit::ext::DexKitExt::Identify(path);
            py::dict d;
            d["format"] = info.format;        // "dex" | "zip" | "unknown"
            d["is_apk"] = info.is_apk;        // zip carrying an AndroidManifest.xml
            d["has_manifest"] = info.has_manifest;
            d["dex_count"] = info.dex_count;  // classes*.dex count (zip) or 1 (dex)
            return d;
        },
        py::arg("path"),
        "Probe a file by content (dex magic / PK zip signature + AndroidManifest.xml) "
        "without loading it. Returns {format, is_apk, has_manifest, dex_count}.");

    py::class_<dexkit::ext::ExternalTypeRef>(m, "ExternalTypeRef")
        .def_readonly("descriptor", &dexkit::ext::ExternalTypeRef::descriptor)
        .def_readonly("referenced_in_dex_ids",
                      &dexkit::ext::ExternalTypeRef::referenced_in_dex_ids)
        .def("__repr__", [](const dexkit::ext::ExternalTypeRef& r) {
            return "ExternalTypeRef(" + r.descriptor + ")";
        });

    py::class_<dexkit::ext::ExternalMethodRef>(m, "ExternalMethodRef")
        .def_readonly("class_descriptor",
                      &dexkit::ext::ExternalMethodRef::class_descriptor)
        .def_readonly("name", &dexkit::ext::ExternalMethodRef::name)
        .def_readonly("proto", &dexkit::ext::ExternalMethodRef::proto)
        .def_readonly("referenced_in_dex_ids",
                      &dexkit::ext::ExternalMethodRef::referenced_in_dex_ids)
        .def_property_readonly("signature",
            [](const dexkit::ext::ExternalMethodRef& r) {
                return r.class_descriptor + "->" + r.name + r.proto;
            })
        // The decomposed views below are computed in Python via descriptors.py
        // to keep parsing logic in one place; Python-side properties are added
        // by __init_subclass__ shim in __init__.py once the class is imported.
        .def("__repr__", [](const dexkit::ext::ExternalMethodRef& r) {
            return "ExternalMethodRef(" + r.class_descriptor + "->" + r.name +
                   r.proto + ")";
        });

    py::class_<dexkit::ext::ClassMatch>(m, "ClassMatch")
        .def_readonly("descriptor", &dexkit::ext::ClassMatch::descriptor)
        .def_readonly("dex_id", &dexkit::ext::ClassMatch::dex_id)
        .def_readonly("class_id", &dexkit::ext::ClassMatch::class_id)
        .def("__repr__", [](const dexkit::ext::ClassMatch& c) {
            return "ClassMatch(" + c.descriptor + " in dex " +
                   std::to_string(c.dex_id) + ")";
        });

    py::class_<dexkit::ext::MethodMatch>(m, "MethodMatch")
        .def_readonly("descriptor", &dexkit::ext::MethodMatch::descriptor)
        .def_readonly("dex_id", &dexkit::ext::MethodMatch::dex_id)
        .def_readonly("method_id", &dexkit::ext::MethodMatch::method_id)
        .def("__repr__", [](const dexkit::ext::MethodMatch& m) {
            return "MethodMatch(" + m.descriptor + " in dex " +
                   std::to_string(m.dex_id) + ")";
        });

    py::class_<dexkit::ext::FieldMatch>(m, "FieldMatch")
        .def_readonly("descriptor", &dexkit::ext::FieldMatch::descriptor)
        .def_readonly("dex_id", &dexkit::ext::FieldMatch::dex_id)
        .def_readonly("field_id", &dexkit::ext::FieldMatch::field_id);

    py::class_<dexkit::ext::ClassMemberField>(m, "ClassMemberField")
        .def_readonly("name", &dexkit::ext::ClassMemberField::name)
        .def_readonly("type", &dexkit::ext::ClassMemberField::type)
        .def_readonly("access_flags", &dexkit::ext::ClassMemberField::access_flags)
        .def("__repr__", [](const dexkit::ext::ClassMemberField& f) {
            return "ClassMemberField(" + f.name + ":" + f.type + ")";
        });

    py::class_<dexkit::ext::ClassMemberMethod>(m, "ClassMemberMethod")
        .def_readonly("name", &dexkit::ext::ClassMemberMethod::name)
        .def_readonly("proto", &dexkit::ext::ClassMemberMethod::proto)
        .def_readonly("access_flags", &dexkit::ext::ClassMemberMethod::access_flags)
        .def("__repr__", [](const dexkit::ext::ClassMemberMethod& mm) {
            return "ClassMemberMethod(" + mm.name + mm.proto + ")";
        });

    py::class_<dexkit::ext::ClassSummary>(m, "ClassSummary")
        .def_readonly("descriptor", &dexkit::ext::ClassSummary::descriptor)
        .def_readonly("is_internal", &dexkit::ext::ClassSummary::is_internal)
        .def_readonly("dex_id", &dexkit::ext::ClassSummary::dex_id)
        .def_readonly("access_flags", &dexkit::ext::ClassSummary::access_flags)
        .def_readonly("superclass_descriptor",
                      &dexkit::ext::ClassSummary::superclass_descriptor)
        .def_readonly("interface_descriptors",
                      &dexkit::ext::ClassSummary::interface_descriptors)
        .def_readonly("fields", &dexkit::ext::ClassSummary::fields)
        .def_readonly("methods", &dexkit::ext::ClassSummary::methods)
        .def_readonly("source_file", &dexkit::ext::ClassSummary::source_file)
        .def("__repr__", [](const dexkit::ext::ClassSummary& s) {
            return "ClassSummary(" + s.descriptor +
                   (s.is_internal ? ", internal, dex=" + std::to_string(s.dex_id)
                                  : ", external") + ", fields=" +
                   std::to_string(s.fields.size()) + ", methods=" +
                   std::to_string(s.methods.size()) + ")";
        });

    py::class_<dexkit::ext::ArgOrigin>(m, "ArgOrigin")
        .def_readonly("kind",             &dexkit::ext::ArgOrigin::kind)
        .def_readonly("reg_num",          &dexkit::ext::ArgOrigin::reg_num)
        .def_readonly("string_value",     &dexkit::ext::ArgOrigin::string_value)
        .def_readonly("int_value",        &dexkit::ext::ArgOrigin::int_value)
        .def_readonly("class_descriptor", &dexkit::ext::ArgOrigin::class_descriptor)
        .def_readonly("field_signature",  &dexkit::ext::ArgOrigin::field_signature)
        .def_readonly("method_signature", &dexkit::ext::ArgOrigin::method_signature)
        .def_readonly("parameter_index",  &dexkit::ext::ArgOrigin::parameter_index)
        .def("__repr__", [](const dexkit::ext::ArgOrigin& a) {
            std::string body;
            if      (a.kind == "ConstString") body = "\"" + a.string_value + "\"";
            else if (a.kind == "ConstInt" || a.kind == "ConstWide") body = std::to_string(a.int_value);
            else if (a.kind == "ConstClass" || a.kind == "NewInstance" || a.kind == "NewArray")
                body = a.class_descriptor;
            else if (a.kind == "FieldRead")    body = a.field_signature;
            else if (a.kind == "MethodReturn") body = a.method_signature;
            else if (a.kind == "Parameter")    body = "#" + std::to_string(a.parameter_index);
            return "ArgOrigin(" + a.kind + (body.empty() ? "" : " " + body) + ")";
        });

    py::class_<dexkit::ext::ResolvedCallSite>(m, "ResolvedCallSite")
        .def_readonly("caller_dex_id",     &dexkit::ext::ResolvedCallSite::caller_dex_id)
        .def_readonly("caller_method_idx", &dexkit::ext::ResolvedCallSite::caller_method_idx)
        .def_readonly("caller_descriptor", &dexkit::ext::ResolvedCallSite::caller_descriptor)
        .def_readonly("callee_descriptor", &dexkit::ext::ResolvedCallSite::callee_descriptor)
        .def_readonly("bytecode_offset",   &dexkit::ext::ResolvedCallSite::bytecode_offset)
        .def_readonly("invoke_opcode",     &dexkit::ext::ResolvedCallSite::invoke_opcode)
        .def_readonly("args",              &dexkit::ext::ResolvedCallSite::args)
        .def("__repr__", [](const dexkit::ext::ResolvedCallSite& c) {
            return "ResolvedCallSite(" + c.caller_descriptor + " -> " +
                   c.callee_descriptor + ", args=" +
                   std::to_string(c.args.size()) + ")";
        });

    py::class_<dexkit::ext::CallSite>(m, "CallSite")
        .def_readonly("caller_dex_id", &dexkit::ext::CallSite::caller_dex_id)
        .def_readonly("caller_method_idx", &dexkit::ext::CallSite::caller_method_idx)
        .def_readonly("caller_descriptor", &dexkit::ext::CallSite::caller_descriptor)
        .def_readonly("callee_descriptor", &dexkit::ext::CallSite::callee_descriptor)
        .def_readonly("bytecode_offset", &dexkit::ext::CallSite::bytecode_offset)
        .def_readonly("invoke_opcode", &dexkit::ext::CallSite::invoke_opcode)
        .def("__repr__", [](const dexkit::ext::CallSite& c) {
            return "CallSite(" + c.caller_descriptor + " -> " + c.callee_descriptor + ")";
        });

    py::class_<dexkit::ext::ExternalFieldRef>(m, "ExternalFieldRef")
        .def_readonly("class_descriptor",
                      &dexkit::ext::ExternalFieldRef::class_descriptor)
        .def_readonly("name", &dexkit::ext::ExternalFieldRef::name)
        .def_readonly("type", &dexkit::ext::ExternalFieldRef::type)
        .def_readonly("referenced_in_dex_ids",
                      &dexkit::ext::ExternalFieldRef::referenced_in_dex_ids)
        .def("__repr__", [](const dexkit::ext::ExternalFieldRef& r) {
            return "ExternalFieldRef(" + r.class_descriptor + "->" + r.name +
                   ":" + r.type + ")";
        });

    py::class_<PyDexKit>(m, "DexKit")
        .def(py::init<const std::string&>(), py::arg("apk_path"),
             "Load a DEX source. Accepts a zip container (.apk/.jar/.zip — all "
             "classes*.dex inside are loaded) or a bare .dex file (detected by "
             "its 'dex\\n' magic). The arg keeps the name apk_path for "
             "backward compatibility.")
        .def("dex_count", &PyDexKit::dex_count)
        .def("apk_path", &PyDexKit::apk_path)
        .def("locate_class_dex", &PyDexKit::locate_class_dex,
             py::arg("class_descriptor"),
             "Return dex_id where the class is declared, or -1 if external.")
        .def("list_classes", &PyDexKit::list_classes,
             "L8: Return every class descriptor declared in any loaded dex "
             "(e.g. `Lcom/foo/Bar;`). Replaces androguard's "
             "AnalyzeAPK→get_classes for decompile drivers.")
        .def("verify_report", &PyDexKit::verify_report,
             "Structural-verification report, one dict per dex considered at "
             "load: {dex_id, name, valid, reason}. A dex with valid==False was "
             "screened out at the load boundary (DexVerifier — AOSP "
             "DexFileVerifier criteria port) with a specific reason.")
        .def("list_class_methods", &PyDexKit::list_class_methods,
             py::arg("class_descriptor"),
             "L8: Return full Dalvik method descriptors "
             "(`Lcls;->name(proto)ret`) for every method declared on the "
             "given class. Empty if the class isn't declared in any loaded dex.")
        .def("list_external_type_refs", &PyDexKit::list_external_type_refs,
             py::arg("framework_only") = true,
             "L1: enumerate type references not defined in any loaded dex.")
        .def("list_external_method_refs", &PyDexKit::list_external_method_refs,
             py::arg("framework_only") = true,
             "L1: enumerate method references whose declaring class is external.")
        .def("list_external_field_refs", &PyDexKit::list_external_field_refs,
             py::arg("framework_only") = true,
             "L1: enumerate field references whose declaring class is external.")
        .def("get_class_summary", &PyDexKit::get_class_summary,
             py::arg("descriptor"),
             "L1.5: return ClassSummary with declared members + class header info "
             "(superclass/interfaces/source_file). Works for both internal and "
             "external classes; for external, members reflect aggregated refs "
             "across all loaded dexes.")
        // L7 — Find/Match wrappers over upstream's matcher engine.
        .def("find_classes_by_name", &PyDexKit::find_classes_by_name,
             py::arg("name"), py::arg("match_type") = "contains",
             py::arg("ignore_case") = false,
             "Find classes whose name matches the pattern. match_type: "
             "equals/contains/starts_with/ends_with/regex.")
        .def("find_classes_using_strings", &PyDexKit::find_classes_using_strings,
             py::arg("strings"), py::arg("match_type") = "contains",
             py::arg("ignore_case") = false,
             "Find classes whose bytecode references all of the given strings.")
        .def("find_methods_using_strings", &PyDexKit::find_methods_using_strings,
             py::arg("strings"), py::arg("match_type") = "contains",
             py::arg("ignore_case") = false,
             "Find methods whose body references all of the given strings.")
        .def("batch_find_classes_using_strings",
             &PyDexKit::batch_find_classes_using_strings,
             py::arg("query_map"), py::arg("match_type") = "contains",
             py::arg("ignore_case") = false,
             "Batch class-by-strings query. Far faster than calling "
             "find_classes_using_strings N times (shared Aho-Corasick trie).")
        .def("batch_find_methods_using_strings",
             &PyDexKit::batch_find_methods_using_strings,
             py::arg("query_map"), py::arg("match_type") = "contains",
             py::arg("ignore_case") = false,
             "Batch method-by-strings query.")
        .def("find_methods_by_name", &PyDexKit::find_methods_by_name,
             py::arg("name"), py::arg("match_type") = "contains",
             py::arg("declaring_class") = "",
             py::arg("ignore_case") = false,
             "Find methods by name, optionally scoped to a declaring class "
             "descriptor (e.g. 'Lcom/x/Y;').")
        .def("find_classes_by_annotation", &PyDexKit::find_classes_by_annotation,
             py::arg("annotation_class"), py::arg("match_type") = "equals",
             "Find classes annotated with the given annotation class. "
             "NOTE: ProGuard/R8-obfuscated APKs rename annotation classes too "
             "— e.g. Lkotlin/Metadata; becomes LX/07xj; — so use the actual "
             "obfuscated descriptor present in this dex (visible via the "
             "Annotation Set dumps). Returns 0 hits for original names that "
             "no longer exist in the obfuscated APK.")
        .def("find_methods_by_annotation", &PyDexKit::find_methods_by_annotation,
             py::arg("annotation_class"), py::arg("match_type") = "equals",
             "Find methods annotated with the given annotation class. See "
             "find_classes_by_annotation note about obfuscated annotation names.")
        .def("find_classes_by_super", &PyDexKit::find_classes_by_super,
             py::arg("super_class"), py::arg("match_type") = "equals",
             "Find classes whose direct superclass matches the given name.")
        .def("find_classes_implementing", &PyDexKit::find_classes_implementing,
             py::arg("interface_class"), py::arg("match_type") = "equals",
             "Find classes that implement (declare) the given interface.")
        .def("find_methods_using_int_literals",
             &PyDexKit::find_methods_using_int_literals,
             py::arg("values"),
             "Find methods whose body contains all of the given int literals.")
        .def("find_methods_using_double_literals",
             &PyDexKit::find_methods_using_double_literals,
             py::arg("values"),
             "Find methods whose body contains all of the given double literals.")
        .def("resolve_call_args", &PyDexKit::resolve_call_args,
             py::arg("api_descriptor"),
             "L4: for every call site invoking the given API, return a "
             "ResolvedCallSite whose .args list contains an ArgOrigin per "
             "argument register (ConstString / ConstInt / ConstClass / "
             "Parameter / FieldRead / MethodReturn / Unknown). Basic-block-"
             "scoped forward register simulation.")
        .def("render_method_smali", &PyDexKit::render_method_smali,
             py::arg("method_descriptor"),
             "L5: baksmali-style text rendering of a single method body. "
             "Returns empty string if the method isn't found or has no code item.")
        .def("render_class_smali", &PyDexKit::render_class_smali,
             py::arg("class_descriptor"),
             "L5: baksmali-style text rendering of a whole class — header, "
             "fields, and every declared method's body. Internal classes only.")
        .def("decompile_method_java",
             [](const PyDexKit& self, const std::string& desc) {
                 py::gil_scoped_release release;
                 return self.decompile_method_java(desc);
             },
             py::arg("method_descriptor"),
             "Decompile a single method to Java via DAD C++ port. "
             "Releases the GIL during execution to allow true parallel "
             "decompilation. Alias of decompile_method.")
        .def("decompile_class_java",
             [](const PyDexKit& self, const std::string& desc) {
                 py::gil_scoped_release release;
                 return self.decompile_class_java(desc);
             },
             py::arg("class_descriptor"),
             "Decompile a whole class to Java via DAD C++ port. "
             "Releases the GIL during execution. Alias of decompile_class.")
        .def("decompile_method_ast", &PyDexKit::decompile_method_ast,
             py::arg("method_descriptor"), py::arg("include_source") = true,
             "Return a structured method dict: "
             "{cls_name, name, proto, ret_type, params_type, access, source, "
             "found, ast}. `ast` is the full nested AST from DAD's dast.py "
             "JSONWriter: {triple, flags, ret, params, comments, body}. "
             "`source` is the equivalent Java text — pass include_source=False "
             "to skip its (separate) pipeline run when only the AST is needed.")
        .def("find_call_sites_to_api", &PyDexKit::find_call_sites_to_api,
             py::arg("api_descriptor"),
             "L2: every call site invoking the given API (\"Lpkg/Cls;->name(args)Ret;\"). "
             "First call warms upstream analysis caches (may take a few seconds).")
        .def("warm_analysis_caches", &PyDexKit::warm_analysis_caches,
             "Eagerly warm upstream caches needed for L2/L4 (otherwise lazy).")
        .def("decompile_class", &PyDexKit::decompile_class,
             py::arg("class_descriptor"))
        .def("decompile_method", &PyDexKit::decompile_method,
             py::arg("method_descriptor"))
        .def("decompiler_clear_cache", &PyDexKit::decompiler_clear_cache)
        .def("decompiler_cache_size", &PyDexKit::decompiler_cache_size)
        .def("decompiler_set_cache_capacity",
             &PyDexKit::decompiler_set_cache_capacity, py::arg("cap"),
             "Set the LRU cache capacity for decompiled methods (0 disables eviction).")
        .def("decompiler_cache_capacity",
             &PyDexKit::decompiler_cache_capacity,
             "Get the current LRU cache capacity.");

    m.def("is_framework_descriptor", &dexkit::ext::IsFrameworkDescriptor,
          py::arg("descriptor"),
          "Returns true if the descriptor uses a known framework prefix "
          "(Landroid/, Ljava/, Lkotlin/, ...).");
}
