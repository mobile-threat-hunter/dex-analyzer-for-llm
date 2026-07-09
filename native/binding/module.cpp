// pybind11 entry point for the dexllm Python package.
//
// Wires Python → DexKitExt → DexKit Core, plus the dad_cpp Decompiler stub.
// The decompile_* family currently returns a stub message; real output lands
// as `native/dad_cpp/` is ported from androguard DAD (see CLAUDE.md).

#include <pybind11/pybind11.h>
#include <pybind11/stl.h>

#include <map>
#include <string>
#include <unordered_set>
#include <vector>

#include "analysis.h"
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
    explicit PyDexKit(const std::string& apk_path, bool lenient = false)
        : ext_(apk_path, lenient),
          decompiler_(std::make_unique<dexkit::dad::Decompiler>(
              ext_.GetCodeSource())) {}

    // Multi-source load: sources are loaded in order, earlier ones get lower
    // dex_ids → first-wins prefers them. Load a decrypted/dumped dex first to
    // make the unpacked class win a collision (packer / runtime-unpack workflow).
    explicit PyDexKit(const std::vector<std::string>& sources, bool lenient = false)
        : ext_(sources, lenient),
          decompiler_(std::make_unique<dexkit::dad::Decompiler>(
              ext_.GetCodeSource())) {}

    int dex_count() const { return ext_.DexCount(); }
    const std::string& apk_path() const { return ext_.GetApkPath(); }
    std::vector<std::string> sources() const { return ext_.GetSources(); }
    int locate_class_dex(const std::string& descriptor) const {
        return ext_.LocateClassDex(descriptor);
    }
    std::vector<std::string> list_classes() const {
        return ext_.ListClasses();
    }
    // Every distinct string the app loads AS DATA — const-string (0x1a/0x1b)
    // operands + static VALUE_STRING (0x17) initializers — MUTF-8 → UTF-8 decoded.
    // Identifier/metadata pool entries (type/method/field names, shorty, source
    // files) are excluded. Foundation for static IOC / C2 extraction. We dedup on
    // the DECODED text so two byte sequences that decode alike (e.g. both → U+FFFD
    // via the lone-surrogate fallback) collapse — honouring the "deduplicated"
    // contract.
    py::list list_value_strings() const {
        py::list out;
        std::unordered_set<std::string> seen;
        for (const auto& s : ext_.ListValueStrings()) {
            std::string decoded = DecodeMutf8ForPy(s);
            if (seen.insert(decoded).second) {
                out.append(py::str(decoded));
            }
        }
        return out;
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
    std::vector<dexkit::ext::CallSite>
    find_call_sites_from_method(const std::string& method_descriptor) {
        return ext_.FindCallSitesFromMethod(method_descriptor);
    }
    std::vector<std::string>
    find_field_read_methods(const std::string& field_descriptor) {
        return ext_.FindFieldReadMethods(field_descriptor);
    }
    std::vector<std::string>
    find_field_write_methods(const std::string& field_descriptor) {
        return ext_.FindFieldWriteMethods(field_descriptor);
    }
    dexkit::ext::TypeReferences
    find_type_references(const std::string& type_descriptor) {
        return ext_.FindTypeReferences(type_descriptor);
    }
    std::vector<std::string> list_classes_in_dex(int dex_id) const {
        return ext_.ListClassesInDex(dex_id);
    }
    std::vector<std::string> list_field_descriptors() const {
        return ext_.ListFieldDescriptors();
    }
    std::vector<std::string> list_field_descriptors_in_dex(int dex_id) const {
        return ext_.ListFieldDescriptorsInDex(dex_id);
    }
    std::vector<std::string> list_method_descriptors() const {
        return ext_.ListMethodDescriptors();
    }
    std::vector<std::string> list_method_descriptors_in_dex(int dex_id) const {
        return ext_.ListMethodDescriptorsInDex(dex_id);
    }
    py::bytes extract_dex_bytes(int dex_id) const {
        const auto v = ext_.GetDexBytes(dex_id);
        return py::bytes(reinterpret_cast<const char*>(v.data()), v.size());
    }
    void warm_analysis_caches() { ext_.WarmAnalysisCaches(); }

    // Issue #13 — engine-side permission→API→callers join (bundled data). Mirrors
    // dexllm.dangerous_api.dangerous_permission_api_callers; the same C++ join
    // backs the WASM binding, so both consumers share one implementation + data.
    py::list permission_callers(bool app_only) {
        py::list out;
        for (const auto& g : dexkit::ext::PermissionCallers(ext_, app_only)) {
            py::dict gd;
            gd["perm"] = g.perm;
            gd["protectionLevel"] = g.protection_level;
            py::list rows;
            for (const auto& r : g.rows) {
                py::dict rd;
                rd["api"] = r.api;
                rd["descriptors"] = py::cast(r.descriptors);
                rd["callers"] = py::cast(r.callers);
                rows.append(rd);
            }
            gd["rows"] = rows;
            out.append(gd);
        }
        return out;
    }

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
    // Java text decompile via the dad_cpp Decompiler facade. The `_java` suffix
    // is the stable public name (sweep script, /dexkit-* skills, the SDK layer, tests);
    // GIL is released at the binding site for true parallel decompilation.
    std::string decompile_method_java(const std::string& descriptor) const {
        return decompiler_->DecompileMethod(descriptor);
    }
    // D-3 (dexllm#1) — Java text + (line ↔ dex byte offset) map for smali
    // sync. Returns {"source": str, "pc_map": [[line, byte_off], ...]}.
    py::dict decompile_method_java_with_pc(const std::string& descriptor) const {
        dexkit::dad::Decompiler::DecompiledMethodWithMap r;
        {
            py::gil_scoped_release release;  // same as decompile_method_java
            r = decompiler_->DecompileMethodWithPcMap(descriptor);
        }
        py::dict out;
        out["source"] = r.source;
        py::list pc;
        for (const auto& [line, off] : r.pc_map)
            pc.append(py::make_tuple(line, off));
        out["pc_map"] = std::move(pc);
        return out;
    }
    std::string decompile_class_java(const std::string& descriptor) const {
        return decompiler_->DecompileClass(descriptor);
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
        // D-3 — sidechannel (statement_seq ↔ dex byte offset) map; kept out of
        // `ast` so the tree stays byte-identical to androguard.
        py::list astpc;
        for (const auto& [seq, off] : ast.ast_pc_map)
            astpc.append(py::make_tuple(seq, off));
        out["pc_map"] = std::move(astpc);
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

    py::class_<dexkit::ext::TypeReferences>(m, "TypeReferences")
        .def_readonly("fields", &dexkit::ext::TypeReferences::fields)
        .def_readonly("methods_returning",
                      &dexkit::ext::TypeReferences::methods_returning)
        .def_readonly("methods_with_param",
                      &dexkit::ext::TypeReferences::methods_with_param)
        .def("__repr__", [](const dexkit::ext::TypeReferences& t) {
            return "TypeReferences(fields=" + std::to_string(t.fields.size()) +
                   ", returning=" + std::to_string(t.methods_returning.size()) +
                   ", param=" + std::to_string(t.methods_with_param.size()) + ")";
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
        .def(py::init<const std::string&, bool>(), py::arg("apk_path"),
             py::arg("lenient") = false,
             "Load a DEX source. Accepts a zip container (.apk/.jar/.zip — all "
             "classes*.dex inside are loaded) or a bare .dex file (detected by "
             "its 'dex\\n' magic). The arg keeps the name apk_path for "
             "backward compatibility. lenient=True verifies in ART-structural-"
             "equivalent mode (skips instruction-operand checks) so a runtime-"
             "dumped, partially-decrypted dex still loads.")
        .def(py::init<const std::vector<std::string>&, bool>(), py::arg("sources"),
             py::arg("lenient") = false,
             "Load MULTIPLE sources with PRIORITY BY ORDER. Each source (a bare "
             ".dex or a zip/apk) is loaded in turn, so sources earlier in the list "
             "get lower dex_ids. Class resolution is first-wins (lowest dex_id), so "
             "the FIRST source wins a class collision — for a packer/runtime-unpack "
             "workflow, list a decrypted/dumped dex BEFORE the original apk to make "
             "the unpacked class win (mirrors ART, where the packer orders the "
             "decrypted dex first). Each dex still passes the load-time verifier; "
             "lenient=True uses ART-structural-equivalent verification for "
             "partially-decrypted dumps.")
        .def("dex_count", &PyDexKit::dex_count)
        .def("apk_path", &PyDexKit::apk_path)
        .def("sources", &PyDexKit::sources,
             "The source list this instance was loaded from (length 1 for a single "
             "apk/dex). Used by dexllm.add_dumped_dexes to rebuild with extra dexes.")
        .def("locate_class_dex", &PyDexKit::locate_class_dex,
             py::arg("class_descriptor"),
             "Return dex_id where the class is declared, or -1 if external.")
        .def("list_classes", &PyDexKit::list_classes,
             "L8: Return every class descriptor declared in any loaded dex "
             "(e.g. `Lcom/foo/Bar;`). Replaces androguard's "
             "AnalyzeAPK→get_classes for decompile drivers.")
        .def("list_value_strings", &PyDexKit::list_value_strings,
             "Return every distinct string the app loads as DATA — const-string/"
             "jumbo (0x1a/0x1b) operands + static-field VALUE_STRING (0x17) "
             "initializers (MUTF-8 → UTF-8 decoded, deduplicated). Excludes "
             "identifier/metadata pool entries (type/method/field names, shorty, "
             "source files). Foundation for static IOC / C2 extraction — see "
             "dexllm.extract_iocs. (Annotation-embedded 0x17 omitted.)")
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
             "decompilation.")
        .def("decompile_method_java_with_pc",
             &PyDexKit::decompile_method_java_with_pc,
             py::arg("method_descriptor"),
             "Decompile a method to Java plus a source-line ↔ dex bytecode "
             "offset map for smali sync. Returns {'source': str, 'pc_map': "
             "[(line_1based, byte_off), ...]} (one entry per line, "
             "first-anchor-wins; lines with no source op omitted). 'line' is a "
             "1-based index into source.split('\\n') — only '\\n' (0x0A) "
             "delimits a line; do NOT use Python str.splitlines() / a "
             "Unicode-line-aware split (a string literal may contain a raw "
             "U+2028/U+2029/U+0085 that those split on but this counter does "
             "not). GIL released during execution.")
        .def("decompile_class_java",
             [](const PyDexKit& self, const std::string& desc) {
                 py::gil_scoped_release release;
                 return self.decompile_class_java(desc);
             },
             py::arg("class_descriptor"),
             "Decompile a whole class to Java via DAD C++ port. "
             "Releases the GIL during execution.")
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
        .def("find_call_sites_from_method", &PyDexKit::find_call_sites_from_method,
             py::arg("method_descriptor"),
             "L2 (forward direction): every call site INSIDE the given method — the "
             "methods it invokes (callees). Each CallSite fixes the caller and varies "
             "callee_descriptor. Empty for an external / bodyless / unresolved method.")
        .def("find_field_read_methods", &PyDexKit::find_field_read_methods,
             py::arg("field_descriptor"),
             "L2.5: descriptors of every method that READS (iget*/sget*) the given "
             "field (\"Lpkg/Cls;->name:Type\"), from the core's field_get_method_ids "
             "reverse index. Empty if the field isn't declared in a loaded dex. "
             "Warms the analysis caches on first use.")
        .def("find_field_write_methods", &PyDexKit::find_field_write_methods,
             py::arg("field_descriptor"),
             "L2.5: descriptors of every method that WRITES (iput*/sput*) the given "
             "field (\"Lpkg/Cls;->name:Type\"). Companion to find_field_read_methods.")
        .def("find_type_references", &PyDexKit::find_type_references,
             py::arg("type_descriptor"),
             "L2.5: signature-position type xref for \"Lpkg/Cls;\" — a TypeReferences "
             "with .fields (fields of this type), .methods_returning, and "
             ".methods_with_param (methods taking it as a parameter). Scans all dexes.")
        .def("list_classes_in_dex", &PyDexKit::list_classes_in_dex,
             py::arg("dex_id"),
             "Descriptors of every class DECLARED in the given loaded dex (0-based). "
             "list_classes() is the union across all dexes; this is one dex.")
        .def("list_field_descriptors", &PyDexKit::list_field_descriptors,
             "Every field descriptor (\"Lcls;->name:Type\") across all loaded dexes "
             "(the dex id-table references: declared + referenced). Exactly the "
             "concatenation of list_field_descriptors_in_dex over every dex.")
        .def("list_field_descriptors_in_dex",
             &PyDexKit::list_field_descriptors_in_dex, py::arg("dex_id"),
             "Field descriptors of ONE loaded dex (0-based); empty if out of range. "
             "The per-dex form of list_field_descriptors().")
        .def("list_method_descriptors", &PyDexKit::list_method_descriptors,
             "Every method descriptor (\"Lcls;->name(proto)ret\") across all loaded "
             "dexes (the dex id-table references: declared + referenced). Exactly the "
             "concatenation of list_method_descriptors_in_dex over every dex.")
        .def("list_method_descriptors_in_dex",
             &PyDexKit::list_method_descriptors_in_dex, py::arg("dex_id"),
             "Method descriptors of ONE loaded dex (0-based); empty if out of range. "
             "The per-dex form of list_method_descriptors().")
        .def("extract_dex_bytes", &PyDexKit::extract_dex_bytes, py::arg("dex_id"),
             "Raw bytes of the given loaded dex image; empty bytes if dex_id is out "
             "of range.")
        .def("warm_analysis_caches", &PyDexKit::warm_analysis_caches,
             "Eagerly warm upstream caches needed for L2/L4 (otherwise lazy).")
        .def("permission_callers", &PyDexKit::permission_callers,
             py::arg("app_only") = true,
             "Issue #13/#14: permission → used API → callers across ALL protection "
             "levels (each group's real protectionLevel bucket), over the bundled "
             "AOSP data. C++ engine join shared with the WASM binding; mirrors "
             "dexllm.permission_api_callers.")
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
