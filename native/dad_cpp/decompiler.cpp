// decompiler.cpp — DexKit-DAD facade. End-to-end pipeline:
//   descriptor → MethodSnapshot → DvMethod → Java text (cached).

#include "decompiler.h"

#include <exception>
#include <string>
#include <utility>

#include "decompile.h"
#include "method_snapshot.h"
#include "mutf8.h"
#include "util.h"

namespace dexkit::dad {

namespace {

// Sanitize the decompiled source so it's valid UTF-8 for Python's strict
// decoder, WITHOUT mangling readable text. Identifiers (class/method/field
// names) reach the output as raw dex MUTF-8 — not routed through the Writer's
// string escaper — so a whole-output pass cleans them here. We decode to the
// SAME UTF-16 code units ART builds (mutf8::Mutf8ToUtf16) and render each unit
// as text: BMP non-surrogate → readable UTF-8 (so 연결 / 中文 stay legible),
// surrogate/control → `\uXXXX` (supplementary chars stay surrogate PAIRS,
// matching ART's mirror::String, and never the raw 0xED bytes pybind11's strict
// decode rejects). Already-emitted ASCII and the Writer's proper-UTF-8 string
// bytes decode 1:1, so this is idempotent over them.
std::string SanitizeUtf8(std::string_view in) {
    std::string out;
    out.reserve(in.size());
    const uint8_t* p = reinterpret_cast<const uint8_t*>(in.data());
    const size_t len = in.size();
    size_t i = 0;
    while (i < len) {
        if (p[i] < 0x80) {
            // Native ASCII — including the structural '\n'/' ' that lay out the
            // Java source and the `\uXXXX` escapes the Writer already emitted —
            // passes through verbatim (do NOT escape these control bytes).
            out += static_cast<char>(p[i]);
            ++i;
            continue;
        }
        // Maximal run of non-ASCII bytes: a MUTF-8 multibyte sequence is a lead
        // byte (>= 0xC0) plus continuation bytes (0x80-0xBF), all >= 0x80, so a
        // run boundary never splits a sequence. Decode it via the shared ART
        // decoder and escape per UTF-16 code unit (surrogate/control → \uXXXX,
        // BMP → readable UTF-8).
        const size_t start = i;
        while (i < len && p[i] >= 0x80) ++i;
        for (uint16_t u : mutf8::Mutf8ToUtf16(in.substr(start, i - start))) {
            mutf8::AppendUtf16Escaped(out, u);
        }
    }
    return out;
}

}  // namespace

Decompiler::Decompiler(IDexCodeSource& source) : source_(source) {}
Decompiler::~Decompiler() = default;

bool Decompiler::LocateMethod(std::string_view descriptor,
                               uint16_t& dex_id, uint32_t& method_idx) {
    auto loc = source_.LocateMethod(descriptor);
    if (!loc) return false;
    dex_id = loc->dex_id;
    method_idx = loc->method_idx;
    return true;
}

std::string Decompiler::RunPipeline(
    uint16_t dex_id, uint32_t method_idx,
    std::vector<std::pair<uint32_t, uint32_t>>* pc_map) {
    std::string result;
    try {
        auto snap = MethodSnapshotBuilder::BuildShared(
            source_, dex_id, method_idx);
        DvMethod dv(snap);
        dv.Process();
        result = dv.GetSource();
        if (pc_map) *pc_map = dv.GetPcMap();
    } catch (const std::exception& e) {
        result = std::string("// DECOMPILE ERROR: ") + e.what() + "\n";
    }
    // Sanitize: non-ASCII MUTF-8 (incl. 0xED surrogate halves strict UTF-8
    // rejects) → readable UTF-8 / \uXXXX so Python's strict decoder accepts it.
    // Preserves '\n', so any captured pc_map line numbers stay valid.
    return SanitizeUtf8(result);
}

std::string Decompiler::DecompileMethod(std::string_view descriptor) {
    const std::string key(descriptor);
    {
        // Shared-lock fast path: hit moves entry to LRU front (which mutates
        // the list, so we need a unique_lock on hit).
        std::unique_lock<std::shared_mutex> lock(cache_mutex_);
        auto it = cache_index_.find(std::string_view{key});
        if (it != cache_index_.end()) {
            cache_list_.splice(cache_list_.begin(), cache_list_, it->second);
            return it->second->second;
        }
    }
    uint16_t dex_id;
    uint32_t method_idx;
    if (!LocateMethod(descriptor, dex_id, method_idx)) return {};

    std::string result = RunPipeline(dex_id, method_idx, /*pc_map=*/nullptr);
    {
        std::unique_lock<std::shared_mutex> lock(cache_mutex_);
        // Race: another caller may have inserted while we were decompiling.
        auto it = cache_index_.find(std::string_view{key});
        if (it != cache_index_.end()) {
            cache_list_.splice(cache_list_.begin(), cache_list_, it->second);
            return it->second->second;
        }
        cache_list_.emplace_front(key, result);
        // string_view into the stored key; std::list nodes are address-stable
        // for their lifetime, so this view remains valid until eviction.
        cache_index_.emplace(std::string_view{cache_list_.front().first},
                             cache_list_.begin());
        // Evict LRU tail if over capacity (0 disables).
        while (cache_capacity_ != 0 &&
               cache_list_.size() > cache_capacity_) {
            cache_index_.erase(std::string_view{cache_list_.back().first});
            cache_list_.pop_back();
        }
    }
    return result;
}

// D-3 (dexllm#1) — text + (line ↔ offset) map. Uncached (the LRU stores
// strings only; the map recompute is cheap). Shares RunPipeline with the
// cached DecompileMethod so the build/process/sanitize path can't drift.
Decompiler::DecompiledMethodWithMap
Decompiler::DecompileMethodWithPcMap(std::string_view descriptor) {
    DecompiledMethodWithMap out;
    uint16_t dex_id;
    uint32_t method_idx;
    if (!LocateMethod(descriptor, dex_id, method_idx)) return out;
    out.source = RunPipeline(dex_id, method_idx, &out.pc_map);
    return out;
}

Decompiler::MethodAst
Decompiler::DecompileMethodAst(std::string_view descriptor, bool include_source) {
    MethodAst ast;
    uint16_t dex_id;
    uint32_t method_idx;
    if (!LocateMethod(descriptor, dex_id, method_idx)) {
        ast.found = false;
        return ast;
    }
    // Build snapshot for signature metadata + run the full nested-AST emit
    // (DAD dast.py JSONWriter). The snapshot is cheap; the pipeline is the
    // same one DecompileMethod runs, but emits AstValue instead of text.
    try {
        auto snap = MethodSnapshotBuilder::BuildShared(source_, dex_id, method_idx);
        ast.cls_name = snap->meta.cls_name;
        ast.name = snap->meta.name;
        ast.proto = snap->meta.proto;
        ast.ret_type = snap->meta.ret_type;
        ast.params_type = snap->meta.params_type;
        ast.access = snap->meta.access;
        DvMethod dv(snap);
        ast.ast = dv.ProcessAst();
        ast.ast_pc_map = dv.GetPcMap();  // D-3 — (statement_seq ↔ offset)
    } catch (...) {
        // Pipeline failure → still return partial signature data + text body.
    }
    // Optional second pipeline for the Java text body (cached). Skipped when
    // the caller only needs the AST.
    if (include_source) ast.source = DecompileMethod(descriptor);
    ast.found = true;
    return ast;
}

// DAD: decompile.py:354 DvClass.get_source — emits full Java class text
// (package + class header + fields + methods + closing brace). Replaces the
// earlier "method-body dump" form. inner-class handling is not auto-detected
// (DAD also hard-codes `self.inner = False`). Field initializer rendering
// (EncodedValue → text) is a Phase-2 follow-up; FieldInfo.init_text is
// currently always empty so fields emit as `Type name;`.
std::string Decompiler::DecompileClass(std::string_view class_descriptor) {
    auto info_opt = source_.GetClassInfo(class_descriptor);
    if (!info_opt) {
        // Class not defined in this dex (external ref / wrong descriptor).
        // Matches DAD's effective behavior on ExternalMethod refs.
        return {};
    }
    const auto& info = *info_opt;

    auto slash_to_dot = [](std::string s) {
        for (char& c : s) if (c == '/') c = '.';
        return s;
    };

    // Parse package + name from "Lcom/foo/Bar;".
    std::string_view body = class_descriptor;
    if (body.size() >= 2 && body.front() == 'L' && body.back() == ';') {
        body = body.substr(1, body.size() - 2);
    }
    std::string package, name;
    auto last_slash = body.rfind('/');
    if (last_slash != std::string_view::npos) {
        package = slash_to_dot(std::string{body.substr(0, last_slash)});
        name.assign(body.substr(last_slash + 1));
    } else {
        name.assign(body);
    }

    uint32_t access = info.access_flags;
    constexpr uint32_t kAccInterface = 0x200;
    constexpr uint32_t kAccAbstract  = 0x400;
    bool is_interface = (access & kAccInterface) != 0;
    // DAD: interface implies abstract — strip the abstract bit for cleaner output.
    if (is_interface) access &= ~kAccAbstract;
    auto access_list = GetAccessClass(access);

    // DAD: `prototype = '%s class %s' % (' '.join(access), name)` for class,
    // `'%s %s'` for interface. Note: `' '.join([])` is empty, but the literal
    // space in `'%s %s'` still appears — so package-private interface emits
    // ` interface Foo` with a leading space. Match byte-for-byte.
    std::string access_joined;
    for (size_t i = 0; i < access_list.size(); ++i) {
        if (i > 0) access_joined += ' ';
        access_joined += access_list[i];
    }
    std::string prototype = access_joined;
    prototype += ' ';
    if (!is_interface) prototype += "class ";
    prototype += name;

    // extends — Object is implicit and omitted (DAD convention).
    if (!info.superclass.empty() &&
        info.superclass != "Ljava/lang/Object;") {
        std::string sc{info.superclass.substr(1, info.superclass.size() - 2)};
        prototype += " extends ";
        prototype += slash_to_dot(sc);
    }
    // implements
    if (!info.interfaces.empty()) {
        prototype += " implements ";
        for (size_t i = 0; i < info.interfaces.size(); ++i) {
            if (i > 0) prototype += ", ";
            std::string_view iv = info.interfaces[i];
            prototype += slash_to_dot(std::string{iv.substr(1, iv.size() - 2)});
        }
    }

    std::string out;
    if (!package.empty()) {
        out += "package ";
        out += package;
        out += ";\n";
    }
    out += prototype;
    out += " {\n";

    // Fields — DAD: decompile.py:367.
    for (size_t i = 0; i < info.field_ids.size(); ++i) {
        uint32_t fidx = info.field_ids[i];
        auto finfo = source_.GetFieldInfo(info.dex_id, fidx);
        auto facc = GetAccessField(finfo.access_flags);
        out += "    ";
        for (const auto& a : facc) {
            out += a;
            out += ' ';
        }
        out += GetType(finfo.type);
        out += ' ';
        out.append(finfo.name);
        // Initializer: ClassInfo carries the parsed static_values_off text
        // (Phase 2). GetFieldInfo's per-call init_text is left as a future
        // hook for non-class-context lookups.
        const std::string& init =
            (i < info.field_init_texts.size() && !info.field_init_texts[i].empty())
                ? info.field_init_texts[i] : finfo.init_text;
        if (!init.empty()) {
            out += " = ";
            out += init;
        }
        out += ";\n";
    }

    // Methods — reuse the existing per-method decompile path.
    auto methods = source_.LocateClassMethods(class_descriptor);
    for (const auto& loc : methods) {
        auto cls = source_.GetMethodClassName(loc.dex_id, loc.method_idx);
        auto mname = source_.GetMethodName(loc.dex_id, loc.method_idx);
        auto proto = source_.GetMethodProto(loc.dex_id, loc.method_idx);
        std::string method_descriptor;
        method_descriptor.append(cls.data(), cls.size());
        method_descriptor += "->";
        method_descriptor.append(mname.data(), mname.size());
        method_descriptor += proto;
        try {
            out += DecompileMethod(method_descriptor);
        } catch (const std::exception& e) {
            out += "// METHOD ERROR (";
            out += method_descriptor;
            out += "): ";
            out += e.what();
            out += "\n";
        }
    }

    out += "}\n";
    return out;
}

void Decompiler::ClearCache() {
    std::unique_lock<std::shared_mutex> lock(cache_mutex_);
    cache_index_.clear();
    cache_list_.clear();
}

std::size_t Decompiler::CacheSize() const {
    std::shared_lock<std::shared_mutex> lock(cache_mutex_);
    return cache_list_.size();
}

void Decompiler::SetCacheCapacity(std::size_t cap) {
    std::unique_lock<std::shared_mutex> lock(cache_mutex_);
    cache_capacity_ = cap;
    while (cache_capacity_ != 0 && cache_list_.size() > cache_capacity_) {
        cache_index_.erase(std::string_view{cache_list_.back().first});
        cache_list_.pop_back();
    }
}

std::size_t Decompiler::CacheCapacity() const {
    std::shared_lock<std::shared_mutex> lock(cache_mutex_);
    return cache_capacity_;
}

}  // namespace dexkit::dad
