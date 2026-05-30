// decompiler.cpp — DexKit-DAD facade. End-to-end pipeline:
//   descriptor → MethodSnapshot → DvMethod → Java text (cached).

#include "decompiler.h"

#include <exception>
#include <string>
#include <utility>

#include "decompile.h"
#include "method_snapshot.h"
#include "util.h"

namespace dexkit::dad {

namespace {

// Sanitize a string so it's valid UTF-8 for Python's strict decoder.
// Dex strings (and identifiers derived from them) are MUTF-8: supplementary
// codepoints are encoded as 3-byte surrogates (0xED prefix) which strict
// UTF-8 rejects. Replace any non-ASCII byte sequence's actual codepoint
// with a Java \uXXXX escape so the output is pure ASCII.
std::string SanitizeUtf8(std::string_view in) {
    std::string out;
    out.reserve(in.size());
    const uint8_t* p = reinterpret_cast<const uint8_t*>(in.data());
    const uint8_t* end = p + in.size();
    auto emit_u = [&](uint32_t cp) {
        char buf[8];
        std::snprintf(buf, sizeof(buf), "\\u%04x", cp);
        out += buf;
    };
    while (p < end) {
        uint8_t c = *p;
        if (c < 0x80) { out += static_cast<char>(c); ++p; continue; }
        uint32_t cp = 0;
        size_t n = 0;
        if ((c & 0xE0) == 0xC0) { cp = c & 0x1F; n = 2; }
        else if ((c & 0xF0) == 0xE0) { cp = c & 0x0F; n = 3; }
        else if ((c & 0xF8) == 0xF0) { cp = c & 0x07; n = 4; }
        else { emit_u(c); ++p; continue; }
        if (p + n > end) { emit_u(c); ++p; continue; }
        bool ok = true;
        for (size_t i = 1; i < n; ++i) {
            uint8_t t = p[i];
            if ((t & 0xC0) != 0x80) { ok = false; break; }
            cp = (cp << 6) | (t & 0x3F);
        }
        if (!ok) { emit_u(c); ++p; continue; }
        // Always escape — including surrogate halves (D800-DFFF) which are
        // the actual culprit.
        emit_u(cp);
        p += n;
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

    std::string result;
    try {
        auto snap = MethodSnapshotBuilder::BuildShared(
            source_, dex_id, method_idx);
        DvMethod dv(snap);
        dv.Process();
        result = dv.GetSource();
    } catch (const std::exception& e) {
        result = std::string("// DECOMPILE ERROR: ") + e.what() + "\n";
    }
    // Sanitize: convert any non-ASCII byte sequence into Java \uXXXX escape
    // so Python's strict UTF-8 decoder accepts the result. Dex MUTF-8 may
    // contain surrogate halves (0xED prefix) which strict UTF-8 rejects.
    result = SanitizeUtf8(result);
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

Decompiler::MethodAst
Decompiler::DecompileMethodAst(std::string_view descriptor) {
    MethodAst ast;
    uint16_t dex_id;
    uint32_t method_idx;
    if (!LocateMethod(descriptor, dex_id, method_idx)) {
        ast.found = false;
        return ast;
    }
    // Build snapshot for signature metadata (already cheap; same call DAD
    // pipeline runs at decompile entry).
    try {
        auto snap = MethodSnapshotBuilder::BuildShared(source_, dex_id, method_idx);
        ast.cls_name = snap->meta.cls_name;
        ast.name = snap->meta.name;
        ast.proto = snap->meta.proto;
        ast.ret_type = snap->meta.ret_type;
        ast.params_type = snap->meta.params_type;
        ast.access = snap->meta.access;
    } catch (...) {
        // Snapshot failure → still attempt the decompile for partial data.
    }
    ast.source = DecompileMethod(descriptor);
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

    std::string prototype;
    for (const auto& a : access_list) {
        prototype += a;
        prototype += ' ';
    }
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
    for (uint32_t fidx : info.field_ids) {
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
        if (!finfo.init_text.empty()) {
            out += " = ";
            out += finfo.init_text;
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
