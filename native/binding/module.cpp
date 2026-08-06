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
#include "mutf8.h"

namespace py = pybind11;

namespace {

// Decode dex MUTF-8 → standard UTF-8 so pybind11's strict UTF-8 str decode
// accepts it. Lone surrogates (invalid in UTF-8) become U+FFFD. The body now
// lives in the shared codec (dexllm#22) so the smali renderer decodes an
// identifier exactly as this boundary does.
inline std::string DecodeMutf8ForPy(std::string_view raw) {
    return dexkit::dad::mutf8::Mutf8ToUtf8Lossy(raw);
}

// dexllm#22 — the two halves of the identifier boundary. An IDENTIFIER (a class
// descriptor, a member name, a proto) is dex string-pool MUTF-8 exactly like a
// string literal is, so handing it to pybind raw RAISES for the one form UTF-8
// cannot express: a supplementary-plane character, which dex stores as a
// SURROGATE PAIR and the verifier explicitly permits in a name. That is not a
// corner case of one call — list_classes() is the entry point for the decompile
// drivers, the sweep harness and the MCP tools, so the whole analysis of such a
// sample died on an exception naming an encoding rather than a cause.
//
// Decoding alone would be worse than the crash: identifiers are also INPUT to
// every identity API (decompile_method(descriptor), render_method_smali, …), and
// the matchers compare against raw pool bytes, so a decoded descriptor handed
// back in would silently miss instead of loudly failing. The two directions are
// therefore applied as a PAIR, `ident_out` on the way out and `ident_in` on the
// way in — the same pairing dexllm#19 established for string content. For every
// identifier a verified dex can hold the two are exact inverses (a surrogate pair
// decodes to one code point and re-encodes to the same pair), so the round trip
// list_classes → list_class_methods → decompile/render holds.
inline py::str ident_out(const std::string& raw) {
    return py::str(DecodeMutf8ForPy(raw));
}
inline py::list ident_out(const std::vector<std::string>& raw) {
    py::list out;
    for (const auto& s : raw) out.append(py::str(DecodeMutf8ForPy(s)));
    return out;
}
inline std::string ident_in(const std::string& utf8) {
    return dexkit::dad::mutf8::Utf8ToMutf8(utf8);
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

// dexllm#19 — a string QUERY arrives from Python as UTF-8, but the matchers compare
// against the raw MUTF-8 bytes of the dex string pool. The two differ for exactly two
// things (NUL, and a supplementary code point, which dex stores as a surrogate pair),
// so a literal containing either could never match — including one this very library
// had just handed the caller back. Encode the query at the boundary, once, for every
// content matcher. Identifier/NAME matchers are deliberately NOT converted — not
// because normalisation prevents it, but because that path is unreachable anyway: a
// dex CAN carry a supplementary-plane identifier (the verifier allows a surrogate
// pair in a member name), but enumerating such a class already raises
// UnicodeDecodeError in `list_classes()`, so the whole name path is broken for it
// independently of this. Recorded as a known residual, not as a fixed case; the
// corpus has 0 non-ASCII identifiers.
std::vector<std::string> to_mutf8_query(const std::vector<std::string>& q) {
    std::vector<std::string> out;
    out.reserve(q.size());
    for (const auto& s : q) out.push_back(dexkit::dad::mutf8::Utf8ToMutf8(s));
    return out;
}
std::map<std::string, std::vector<std::string>> to_mutf8_query(
    const std::map<std::string, std::vector<std::string>>& q) {
    std::map<std::string, std::vector<std::string>> out;
    for (const auto& [k, v] : q) out.emplace(k, to_mutf8_query(v));
    return out;
}

// MUTF-8 → UTF-8 decode a raw string list, preserving order and dropping
// duplicates of the DECODED text (two byte sequences that decode alike — e.g.
// both → U+FFFD via the lone-surrogate fallback — collapse). Shared by every
// string-listing accessor so they honour one "deduplicated" contract.
py::list decoded_unique(const std::vector<std::string>& raw) {
    py::list out;
    std::unordered_set<std::string> seen;
    for (const auto& s : raw) {
        std::string decoded = DecodeMutf8ForPy(s);
        if (seen.insert(decoded).second) {
            out.append(py::str(decoded));
        }
    }
    return out;
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
        return ext_.LocateClassDex(ident_in(descriptor));
    }
    py::list list_classes() const {
        return ident_out(ext_.ListClasses());
    }
    // Every distinct string the app loads AS DATA — const-string (0x1a/0x1b)
    // operands + static VALUE_STRING (0x17) initializers — MUTF-8 → UTF-8 decoded.
    // Identifier/metadata pool entries (type/method/field names, shorty, source
    // files) are excluded. Foundation for static IOC / C2 extraction. We dedup on
    // the DECODED text so two byte sequences that decode alike (e.g. both → U+FFFD
    // via the lone-surrogate fallback) collapse — honouring the "deduplicated"
    // contract.
    py::list list_value_strings() const {
        return decoded_unique(ext_.ListValueStrings());
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
    py::list list_class_methods(const std::string& class_descriptor) const {
        return ident_out(ext_.ListClassMethods(ident_in(class_descriptor)));
    }

    // Forward string accessors (the code→strings direction). Same MUTF-8 decode +
    // dedup-on-DECODED-text contract as list_value_strings, so two raw byte
    // sequences that decode alike collapse to one entry.
    py::list list_method_strings(const std::string& method_descriptor) {
        return decoded_unique(ext_.ListMethodStrings(ident_in(method_descriptor)));
    }
    py::list list_class_strings(const std::string& class_descriptor) {
        return decoded_unique(ext_.ListClassStrings(ident_in(class_descriptor)));
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
        return ext_.FindCallSitesToApi(ident_in(api_descriptor));
    }
    std::vector<dexkit::ext::CallSite>
    find_call_sites_from_method(const std::string& method_descriptor) {
        return ext_.FindCallSitesFromMethod(ident_in(method_descriptor));
    }
    py::list find_field_read_methods(const std::string& field_descriptor) {
        return ident_out(ext_.FindFieldReadMethods(ident_in(field_descriptor)));
    }
    py::list find_field_write_methods(const std::string& field_descriptor) {
        return ident_out(ext_.FindFieldWriteMethods(ident_in(field_descriptor)));
    }
    dexkit::ext::TypeReferences
    find_type_references(const std::string& type_descriptor) {
        return ext_.FindTypeReferences(ident_in(type_descriptor));
    }
    py::list list_classes_in_dex(int dex_id) const {
        return ident_out(ext_.ListClassesInDex(dex_id));
    }
    py::list list_field_descriptors() const {
        return ident_out(ext_.ListFieldDescriptors());
    }
    py::list list_field_descriptors_in_dex(int dex_id) const {
        return ident_out(ext_.ListFieldDescriptorsInDex(dex_id));
    }
    py::list list_method_descriptors() const {
        return ident_out(ext_.ListMethodDescriptors());
    }
    py::list list_method_descriptors_in_dex(int dex_id) const {
        return ident_out(ext_.ListMethodDescriptorsInDex(dex_id));
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
                rd["api"] = r.api;  // bundled AOSP table, not pool bytes
                rd["descriptors"] = ident_out(r.descriptors);
                rd["callers"] = ident_out(r.callers);
                rows.append(rd);
            }
            gd["rows"] = rows;
            out.append(gd);
        }
        return out;
    }

    dexkit::ext::ClassSummary
    get_class_summary(const std::string& descriptor) const {
        return ext_.GetClassSummary(ident_in(descriptor));
    }

    // L7 — Find/Match wrappers
    std::vector<dexkit::ext::ClassMatch>
    find_classes_by_name(const std::string& name,
                         const std::string& match_type,
                         bool ignore_case) {
        // dexllm#22: the NAME matchers compare against raw pool bytes too, so the
        // query needs the same encode-IN as a descriptor. This is what closes the
        // residual dexllm#19 recorded but could not fix — an astral identifier was
        // unfindable because enumerating it raised before you could search for it.
        return ext_.FindClassesByName(ident_in(name), match_type, ignore_case);
    }
    std::vector<dexkit::ext::ClassMatch>
    find_classes_using_strings(const std::vector<std::string>& strings,
                               const std::string& match_type,
                               bool ignore_case) {
        return ext_.FindClassesUsingStrings(to_mutf8_query(strings), match_type, ignore_case);
    }
    std::vector<dexkit::ext::ClassMatch>
    find_classes_declaring_strings(const std::vector<std::string>& strings,
                                   const std::string& match_type,
                                   bool ignore_case) {
        return ext_.FindClassesDeclaringStrings(to_mutf8_query(strings), match_type, ignore_case);
    }
    std::vector<dexkit::ext::MethodMatch>
    find_methods_using_strings(const std::vector<std::string>& strings,
                               const std::string& match_type,
                               bool ignore_case) {
        return ext_.FindMethodsUsingStrings(to_mutf8_query(strings), match_type, ignore_case);
    }
    std::map<std::string, std::vector<dexkit::ext::ClassMatch>>
    batch_find_classes_using_strings(
        const std::map<std::string, std::vector<std::string>>& q,
        const std::string& match_type, bool ignore_case) {
        return ext_.BatchFindClassesUsingStrings(to_mutf8_query(q), match_type, ignore_case);
    }
    std::map<std::string, std::vector<dexkit::ext::MethodMatch>>
    batch_find_methods_using_strings(
        const std::map<std::string, std::vector<std::string>>& q,
        const std::string& match_type, bool ignore_case) {
        return ext_.BatchFindMethodsUsingStrings(to_mutf8_query(q), match_type, ignore_case);
    }
    std::vector<dexkit::ext::MethodMatch>
    find_methods_by_name(const std::string& name,
                         const std::string& match_type,
                         const std::string& declaring_class,
                         bool ignore_case) {
        return ext_.FindMethodsByName(ident_in(name), match_type,
                                      ident_in(declaring_class), ignore_case);
    }
    std::vector<dexkit::ext::ClassMatch>
    find_classes_by_annotation(const std::string& a, const std::string& mt) {
        return ext_.FindClassesByAnnotation(ident_in(a), mt);
    }
    std::vector<dexkit::ext::MethodMatch>
    find_methods_by_annotation(const std::string& a, const std::string& mt) {
        return ext_.FindMethodsByAnnotation(ident_in(a), mt);
    }
    std::vector<dexkit::ext::ClassMatch>
    find_classes_by_super(const std::string& s, const std::string& mt) {
        return ext_.FindClassesBySuperclass(ident_in(s), mt);
    }
    std::vector<dexkit::ext::ClassMatch>
    find_classes_implementing(const std::string& i, const std::string& mt) {
        return ext_.FindClassesImplementing(ident_in(i), mt);
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
        return ext_.ResolveCallArgs(ident_in(api_descriptor));
    }
    // The rendered listing decodes its identifiers inside the renderer (so a
    // decoded identifier is escaped like every other character, not materialised
    // into the assembled text afterwards — see EscapeSmaliString), hence no
    // ident_out here: the returned text is already valid UTF-8.
    std::string render_method_smali(const std::string& descriptor) const {
        return ext_.RenderMethodSmali(ident_in(descriptor));
    }
    std::string render_class_smali(const std::string& descriptor) const {
        return ext_.RenderClassSmali(ident_in(descriptor));
    }
    // Java text decompile via the dad_cpp Decompiler facade. These C++ members
    // keep their historical `_java` names; the PYTHON-visible spelling is
    // `decompile_method` / `decompile_class` / `decompile_method_with_pc_map`.
    // GIL is released at the binding site for true parallel decompilation.
    std::string decompile_method_java(const std::string& descriptor) const {
        return decompiler_->DecompileMethod(ident_in(descriptor));
    }
    // D-3 (dexllm#1) — Java text + (line ↔ dex byte offset) map for smali
    // sync. Returns {"source": str, "pc_map": [[line, byte_off], ...]}.
    py::dict decompile_method_java_with_pc(const std::string& descriptor) const {
        dexkit::dad::Decompiler::DecompiledMethodWithMap r;
        const std::string raw_desc = ident_in(descriptor);
        {
            py::gil_scoped_release release;  // as in the C++ decompile_method_java above
            r = decompiler_->DecompileMethodWithPcMap(raw_desc);
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
        return decompiler_->DecompileClass(ident_in(descriptor));
    }

    py::dict decompile_method_ast(const std::string& descriptor,
                                  bool include_source) {
        auto ast = decompiler_->DecompileMethodAst(ident_in(descriptor),
                                                   include_source);
        py::dict out;
        out["found"] = ast.found;
        // Signature components are pool identifiers — decoded like every other
        // identifier. (`source` is already sanitised by the decompiler.)
        out["cls_name"] = ident_out(ast.cls_name);
        out["name"] = ident_out(ast.name);
        out["proto"] = ident_out(ast.proto);
        out["ret_type"] = ident_out(ast.ret_type);
        out["params_type"] = ident_out(ast.params_type);
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

    // Load-free structural verification (the verify() sibling of identify()).
    // Runs the DexVerifier over a path's dex(es) without constructing a DexKit.
    // Never throws — a bad/unopenable/non-dex file is reported as a valid=False
    // verdict with a reason. For a loadable source the verdicts are byte-
    // identical to DexKit(path).verify_report(). lenient=True runs the ART-
    // structural-equivalent mode (VerifyInsns skipped).
    m.def(
        "verify",
        [](const std::string& path, bool lenient) {
            auto report = dexkit::ext::DexKitExt::Verify(path, /*check_insns=*/!lenient);
            py::list out;
            for (const auto& s : report) {
                py::dict d;
                d["dex_id"] = s.dex_id;
                d["name"] = s.name;
                d["valid"] = s.valid;
                d["reason"] = s.reason;
                out.append(std::move(d));
            }
            return out;
        },
        py::arg("path"), py::arg("lenient") = false,
        "Structurally verify a .dex / apk's dex(es) without loading (the verify() "
        "sibling of identify()). Returns a list of {dex_id, name, valid, reason} — "
        "one per dex — byte-identical to DexKit(path).verify_report() for a loadable "
        "source. Never throws: a malformed / unopenable / non-dex path is reported as "
        "a valid=False verdict. lenient=True skips VerifyInsns (ART-structural mode).");

    // Every identifier-valued attribute below is exposed through ident_out
    // (dexllm#22) rather than def_readonly: the field holds raw pool MUTF-8, and
    // pybind's automatic std::string → str conversion is strict UTF-8, so a
    // supplementary-plane identifier would RAISE on attribute access. Behaviour
    // is unchanged for ASCII (the decoder's fast path returns the input as-is).
    py::class_<dexkit::ext::ExternalTypeRef>(m, "ExternalTypeRef")
        .def_property_readonly("descriptor",
            [](const dexkit::ext::ExternalTypeRef& r) {
                return ident_out(r.descriptor);
            })
        .def_readonly("referenced_in_dex_ids",
                      &dexkit::ext::ExternalTypeRef::referenced_in_dex_ids)
        .def("__repr__", [](const dexkit::ext::ExternalTypeRef& r) {
            return "ExternalTypeRef(" + DecodeMutf8ForPy(r.descriptor) + ")";
        });

    py::class_<dexkit::ext::ExternalMethodRef>(m, "ExternalMethodRef")
        .def_property_readonly("class_descriptor",
            [](const dexkit::ext::ExternalMethodRef& r) {
                return ident_out(r.class_descriptor);
            })
        .def_property_readonly("name",
            [](const dexkit::ext::ExternalMethodRef& r) {
                return ident_out(r.name);
            })
        .def_property_readonly("proto",
            [](const dexkit::ext::ExternalMethodRef& r) {
                return ident_out(r.proto);
            })
        .def_readonly("referenced_in_dex_ids",
                      &dexkit::ext::ExternalMethodRef::referenced_in_dex_ids)
        // Decode each component, THEN join: decoding the concatenation could pair
        // a trailing surrogate half with the next component's leading one.
        .def_property_readonly("signature",
            [](const dexkit::ext::ExternalMethodRef& r) {
                return py::str(DecodeMutf8ForPy(r.class_descriptor) + "->" +
                               DecodeMutf8ForPy(r.name) +
                               DecodeMutf8ForPy(r.proto));
            })
        // The decomposed views below are computed in Python via descriptors.py
        // to keep parsing logic in one place; Python-side properties are added
        // by __init_subclass__ shim in __init__.py once the class is imported.
        .def("__repr__", [](const dexkit::ext::ExternalMethodRef& r) {
            return "ExternalMethodRef(" + DecodeMutf8ForPy(r.class_descriptor) +
                   "->" + DecodeMutf8ForPy(r.name) + DecodeMutf8ForPy(r.proto) +
                   ")";
        });

    py::class_<dexkit::ext::ClassMatch>(m, "ClassMatch")
        .def_property_readonly("descriptor",
            [](const dexkit::ext::ClassMatch& c) {
                return ident_out(c.descriptor);
            })
        .def_readonly("dex_id", &dexkit::ext::ClassMatch::dex_id)
        .def_readonly("class_id", &dexkit::ext::ClassMatch::class_id)
        .def("__repr__", [](const dexkit::ext::ClassMatch& c) {
            return "ClassMatch(" + DecodeMutf8ForPy(c.descriptor) + " in dex " +
                   std::to_string(c.dex_id) + ")";
        });

    py::class_<dexkit::ext::MethodMatch>(m, "MethodMatch")
        .def_property_readonly("descriptor",
            [](const dexkit::ext::MethodMatch& m) {
                return ident_out(m.descriptor);
            })
        .def_readonly("dex_id", &dexkit::ext::MethodMatch::dex_id)
        .def_readonly("method_id", &dexkit::ext::MethodMatch::method_id)
        .def("__repr__", [](const dexkit::ext::MethodMatch& m) {
            return "MethodMatch(" + DecodeMutf8ForPy(m.descriptor) + " in dex " +
                   std::to_string(m.dex_id) + ")";
        });

    py::class_<dexkit::ext::FieldMatch>(m, "FieldMatch")
        .def_property_readonly("descriptor",
            [](const dexkit::ext::FieldMatch& f) {
                return ident_out(f.descriptor);
            })
        .def_readonly("dex_id", &dexkit::ext::FieldMatch::dex_id)
        .def_readonly("field_id", &dexkit::ext::FieldMatch::field_id);

    py::class_<dexkit::ext::ClassMemberField>(m, "ClassMemberField")
        .def_property_readonly("name",
            [](const dexkit::ext::ClassMemberField& f) {
                return ident_out(f.name);
            })
        .def_property_readonly("type",
            [](const dexkit::ext::ClassMemberField& f) {
                return ident_out(f.type);
            })
        .def_readonly("access_flags", &dexkit::ext::ClassMemberField::access_flags)
        .def("__repr__", [](const dexkit::ext::ClassMemberField& f) {
            return "ClassMemberField(" + DecodeMutf8ForPy(f.name) + ":" +
                   DecodeMutf8ForPy(f.type) + ")";
        });

    py::class_<dexkit::ext::ClassMemberMethod>(m, "ClassMemberMethod")
        .def_property_readonly("name",
            [](const dexkit::ext::ClassMemberMethod& mm) {
                return ident_out(mm.name);
            })
        .def_property_readonly("proto",
            [](const dexkit::ext::ClassMemberMethod& mm) {
                return ident_out(mm.proto);
            })
        .def_readonly("access_flags", &dexkit::ext::ClassMemberMethod::access_flags)
        .def("__repr__", [](const dexkit::ext::ClassMemberMethod& mm) {
            return "ClassMemberMethod(" + DecodeMutf8ForPy(mm.name) +
                   DecodeMutf8ForPy(mm.proto) + ")";
        });

    py::class_<dexkit::ext::ClassSummary>(m, "ClassSummary")
        .def_property_readonly("descriptor",
            [](const dexkit::ext::ClassSummary& s) {
                return ident_out(s.descriptor);
            })
        .def_readonly("is_internal", &dexkit::ext::ClassSummary::is_internal)
        .def_readonly("dex_id", &dexkit::ext::ClassSummary::dex_id)
        .def_readonly("access_flags", &dexkit::ext::ClassSummary::access_flags)
        .def_property_readonly("superclass_descriptor",
            [](const dexkit::ext::ClassSummary& s) {
                return ident_out(s.superclass_descriptor);
            })
        .def_property_readonly("interface_descriptors",
            [](const dexkit::ext::ClassSummary& s) {
                return ident_out(s.interface_descriptors);
            })
        .def_readonly("fields", &dexkit::ext::ClassSummary::fields)
        .def_readonly("methods", &dexkit::ext::ClassSummary::methods)
        // source_file is a pool string like any other identifier-adjacent entry.
        .def_property_readonly("source_file",
            [](const dexkit::ext::ClassSummary& s) {
                return ident_out(s.source_file);
            })
        .def("__repr__", [](const dexkit::ext::ClassSummary& s) {
            return "ClassSummary(" + DecodeMutf8ForPy(s.descriptor) +
                   (s.is_internal ? ", internal, dex=" + std::to_string(s.dex_id)
                                  : ", external") + ", fields=" +
                   std::to_string(s.fields.size()) + ", methods=" +
                   std::to_string(s.methods.size()) + ")";
        });

    py::class_<dexkit::ext::ArgOrigin>(m, "ArgOrigin")
        .def_readonly("kind",             &dexkit::ext::ArgOrigin::kind)
        .def_readonly("reg_num",          &dexkit::ext::ArgOrigin::reg_num)
        // string_value is a const-string OPERAND — pool bytes exactly like an
        // identifier, and it raised for the same reason (dexllm#22).
        .def_property_readonly("string_value",
            [](const dexkit::ext::ArgOrigin& a) {
                return ident_out(a.string_value);
            })
        .def_readonly("int_value",        &dexkit::ext::ArgOrigin::int_value)
        .def_property_readonly("class_descriptor",
            [](const dexkit::ext::ArgOrigin& a) {
                return ident_out(a.class_descriptor);
            })
        .def_property_readonly("field_signature",
            [](const dexkit::ext::ArgOrigin& a) {
                return ident_out(a.field_signature);
            })
        .def_property_readonly("method_signature",
            [](const dexkit::ext::ArgOrigin& a) {
                return ident_out(a.method_signature);
            })
        .def_readonly("parameter_index",  &dexkit::ext::ArgOrigin::parameter_index)
        .def_readonly("crossed_branch",   &dexkit::ext::ArgOrigin::crossed_branch)
        .def("__repr__", [](const dexkit::ext::ArgOrigin& a) {
            std::string body;
            if      (a.kind == "ConstString")
                body = "\"" + DecodeMutf8ForPy(a.string_value) + "\"";
            else if (a.kind == "ConstInt" || a.kind == "ConstWide") body = std::to_string(a.int_value);
            else if (a.kind == "ConstClass" || a.kind == "NewInstance" || a.kind == "NewArray")
                body = DecodeMutf8ForPy(a.class_descriptor);
            else if (a.kind == "FieldRead")    body = DecodeMutf8ForPy(a.field_signature);
            else if (a.kind == "MethodReturn") body = DecodeMutf8ForPy(a.method_signature);
            else if (a.kind == "Parameter")    body = "#" + std::to_string(a.parameter_index);
            else if (a.crossed_branch)         body = "(varies per path)";
            return "ArgOrigin(" + a.kind + (body.empty() ? "" : " " + body) + ")";
        });

    py::class_<dexkit::ext::ResolvedCallSite>(m, "ResolvedCallSite")
        .def_readonly("caller_dex_id",     &dexkit::ext::ResolvedCallSite::caller_dex_id)
        .def_readonly("caller_method_idx", &dexkit::ext::ResolvedCallSite::caller_method_idx)
        .def_property_readonly("caller_descriptor",
            [](const dexkit::ext::ResolvedCallSite& c) {
                return ident_out(c.caller_descriptor);
            })
        .def_property_readonly("callee_descriptor",
            [](const dexkit::ext::ResolvedCallSite& c) {
                return ident_out(c.callee_descriptor);
            })
        .def_readonly("bytecode_offset",   &dexkit::ext::ResolvedCallSite::bytecode_offset)
        .def_readonly("invoke_opcode",     &dexkit::ext::ResolvedCallSite::invoke_opcode)
        .def_readonly("args",              &dexkit::ext::ResolvedCallSite::args)
        .def("__repr__", [](const dexkit::ext::ResolvedCallSite& c) {
            return "ResolvedCallSite(" + DecodeMutf8ForPy(c.caller_descriptor) +
                   " -> " + DecodeMutf8ForPy(c.callee_descriptor) + ", args=" +
                   std::to_string(c.args.size()) + ")";
        });

    py::class_<dexkit::ext::CallSite>(m, "CallSite")
        .def_readonly("caller_dex_id", &dexkit::ext::CallSite::caller_dex_id)
        .def_readonly("caller_method_idx", &dexkit::ext::CallSite::caller_method_idx)
        .def_property_readonly("caller_descriptor",
            [](const dexkit::ext::CallSite& c) {
                return ident_out(c.caller_descriptor);
            })
        .def_property_readonly("callee_descriptor",
            [](const dexkit::ext::CallSite& c) {
                return ident_out(c.callee_descriptor);
            })
        .def_readonly("bytecode_offset", &dexkit::ext::CallSite::bytecode_offset)
        .def_readonly("invoke_opcode", &dexkit::ext::CallSite::invoke_opcode)
        .def("__repr__", [](const dexkit::ext::CallSite& c) {
            return "CallSite(" + DecodeMutf8ForPy(c.caller_descriptor) + " -> " +
                   DecodeMutf8ForPy(c.callee_descriptor) + ")";
        });

    py::class_<dexkit::ext::TypeReferences>(m, "TypeReferences")
        .def_property_readonly("fields",
            [](const dexkit::ext::TypeReferences& t) {
                return ident_out(t.fields);
            })
        .def_property_readonly("methods_returning",
            [](const dexkit::ext::TypeReferences& t) {
                return ident_out(t.methods_returning);
            })
        .def_property_readonly("methods_with_param",
            [](const dexkit::ext::TypeReferences& t) {
                return ident_out(t.methods_with_param);
            })
        .def("__repr__", [](const dexkit::ext::TypeReferences& t) {
            return "TypeReferences(fields=" + std::to_string(t.fields.size()) +
                   ", returning=" + std::to_string(t.methods_returning.size()) +
                   ", param=" + std::to_string(t.methods_with_param.size()) + ")";
        });

    py::class_<dexkit::ext::ExternalFieldRef>(m, "ExternalFieldRef")
        .def_property_readonly("class_descriptor",
            [](const dexkit::ext::ExternalFieldRef& r) {
                return ident_out(r.class_descriptor);
            })
        .def_property_readonly("name",
            [](const dexkit::ext::ExternalFieldRef& r) {
                return ident_out(r.name);
            })
        .def_property_readonly("type",
            [](const dexkit::ext::ExternalFieldRef& r) {
                return ident_out(r.type);
            })
        .def_readonly("referenced_in_dex_ids",
                      &dexkit::ext::ExternalFieldRef::referenced_in_dex_ids)
        .def("__repr__", [](const dexkit::ext::ExternalFieldRef& r) {
            return "ExternalFieldRef(" + DecodeMutf8ForPy(r.class_descriptor) +
                   "->" + DecodeMutf8ForPy(r.name) + ":" +
                   DecodeMutf8ForPy(r.type) + ")";
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
        .def("list_method_strings", &PyDexKit::list_method_strings,
             py::arg("method_descriptor"),
             "L8 (forward of find_methods_using_strings): the value-strings THIS "
             "method loads — its `const-string`/`jumbo` operands, MUTF-8 → UTF-8 "
             "decoded, deduplicated, first-occurrence order. Bytecode only: a "
             "`static final String` is a class-level EncodedValue, so it shows up "
             "in list_class_strings instead. Empty for an external / abstract / "
             "native / unknown method (no body).")
        .def("list_class_strings", &PyDexKit::list_class_strings,
             py::arg("class_descriptor"),
             "L8 (forward of find_classes_using_strings): the value-strings THIS "
             "class carries — the union over its DECLARED methods' const-strings "
             "(ascending method_idx, no superclass walk) followed by its static-field "
             "VALUE_STRING (0x17) initializers. MUTF-8 → UTF-8 decoded, "
             "deduplicated. Empty if the class isn't declared in any loaded dex.")
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
             py::arg("class_descriptor"),
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
        .def("find_classes_declaring_strings",
             &PyDexKit::find_classes_declaring_strings,
             py::arg("strings"), py::arg("match_type") = "contains",
             py::arg("ignore_case") = false,
             "L7 (declaration side of find_classes_using_strings): find classes that "
             "DECLARE all of the given strings as static-field constants "
             "(EncodedValue VALUE_STRING). `using` searches the const-string bytecode "
             "index, so a `static final String` the app never loads is invisible to "
             "it — this finds it. Same match semantics (match_type / ignore_case). "
             "No method-level analogue exists: an EncodedValue belongs to a class, "
             "not to a method.")
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
             py::arg("method_descriptor"),  // same value as find_call_sites_to
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
        .def("decompile_method",
             [](const PyDexKit& self, const std::string& desc) {
                 py::gil_scoped_release release;
                 return self.decompile_method_java(desc);
             },
             py::arg("method_descriptor"),
             "Decompile a single method to Java via DAD C++ port. "
             "Releases the GIL during execution to allow true parallel "
             "decompilation. The decompile_* family always produces Java — the "
             "suffixed variants add structure to the SAME decompilation "
             "(_with_pc_map adds an offset map, _ast adds the structured tree "
             "and carries this text in its 'source'); a different output form "
             "is a different verb (render_*_smali).")
        .def("decompile_method_with_pc_map",
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
        .def("decompile_class",
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
        // The argument is a METHOD descriptor in both directions — the method
        // name carries the role (_to = the callee you are looking for callers of,
        // _from = the caller whose callees you want), so the parameter names what
        // it IS. `api_descriptor` said "framework API", which is only the common
        // case and is not what the value is.
        .def("find_call_sites_to", &PyDexKit::find_call_sites_to_api,
             py::arg("method_descriptor"),
             "L2 (reverse direction): every call site invoking the given API "
             "(\"Lpkg/Cls;->name(args)Ret;\") — its CALLERS. Each CallSite fixes "
             "callee_descriptor (the queried API) and varies the caller_* fields; "
             "one entry per invoke INSTRUCTION, so a caller that invokes twice "
             "appears twice. First call warms upstream analysis caches (may take a "
             "few seconds).")
        .def("find_call_sites_from", &PyDexKit::find_call_sites_from_method,
             py::arg("method_descriptor"),
             "L2 (forward direction): every call site INSIDE the given method — the "
             "methods it invokes (callees). Each CallSite fixes the caller_* fields "
             "(the queried method) and varies callee_descriptor. Empty for an "
             "external / bodyless / unresolved method.")
        .def("find_methods_reading_field", &PyDexKit::find_field_read_methods,
             py::arg("field_descriptor"),
             "L2.5: descriptors of every method that READS (iget*/sget*) the given "
             "field (\"Lpkg/Cls;->name:Type\"), from the core's field_get_method_ids "
             "reverse index. Empty if the field isn't declared in a loaded dex. "
             "Warms the analysis caches on first use.")
        .def("find_methods_writing_field", &PyDexKit::find_field_write_methods,
             py::arg("field_descriptor"),
             "L2.5: descriptors of every method that WRITES (iput*/sput*) the given "
             "field (\"Lpkg/Cls;->name:Type\"). Companion to "
             "find_methods_reading_field.")
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
        // Cache control: an ACTION is verb-first, a read-only accessor is a noun —
        // the scheme the already-verb-first `warm_analysis_caches` was following.
        .def("clear_decompiler_cache", &PyDexKit::decompiler_clear_cache,
             "Drop every cached decompiled method.")
        .def("set_decompiler_cache_capacity",
             &PyDexKit::decompiler_set_cache_capacity, py::arg("capacity"),
             "Set the LRU cache capacity for decompiled methods (0 disables eviction).")
        .def("decompiler_cache_size", &PyDexKit::decompiler_cache_size)
        .def("decompiler_cache_capacity",
             &PyDexKit::decompiler_cache_capacity,
             "Get the current LRU cache capacity.");

    m.def("is_framework_descriptor", &dexkit::ext::IsFrameworkDescriptor,
          py::arg("descriptor"),
          "Returns true if the descriptor uses a known framework prefix "
          "(Landroid/, Ljava/, Lkotlin/, ...).");
}
