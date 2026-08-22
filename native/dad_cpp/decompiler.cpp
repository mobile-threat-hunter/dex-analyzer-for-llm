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
// SAME UTF-16 code units ART builds (mutf8::Mutf8ToUtf16) and render the run as
// IDENTIFIER text: BMP non-surrogate → readable UTF-8 (so 연결 / 中文 stay
// legible), a valid surrogate PAIR → its combined code point, also readable
// (dexllm#28), and a lone surrogate or control → `\uXXXX` (never the raw 0xED
// bytes pybind11's strict decode rejects).
//
// The pair combining is what this pass does NOT share with the Writer's string
// escaper, deliberately: a string LITERAL keeps ART's exact code units, because
// reproducing what `mirror::String` holds is the claim there. An identifier is a
// source symbol, and rendering it as `\ud800\udc00` made the same class read two
// ways across the Java text, the smali listing and `list_classes()` — a
// correlation failure for the analyst or LLM reading them side by side, and one
// that a BMP identifier never had.
//
// WHY THIS PASS CANNOT CHANGE A LITERAL — the invariant is NOT "literals are
// already ASCII by the time they get here". They are not: `EscapeJavaString`
// emits every BMP non-surrogate unit as READABLE UTF-8, so literal text reaches
// this function as raw non-ASCII bytes and IS decoded and re-encoded by it (one
// real corpus method carries 602 such characters, U+00A0 through U+D7FF among
// them). What actually holds is that the Writer escapes every SURROGATE unit to
// ASCII first, so no surrogate unit can exist in the byte stream — and the only
// other way one could appear, a 4-byte UTF-8 lead, has no producer before this
// pass (`AppendUtf8Bmp` tops out at 0xEF, and VerifyMutf8 rejects a >= 0xF0 lead
// in the pool). So the pair branch can only ever fire on raw pool CESU-8, which
// is exactly the identifier append sites. A change to `EscapeJavaString` that let
// a surrogate unit or a 4-byte sequence through would silently break that, which
// is why the real invariant is written out rather than assumed.
//
// Already-emitted ASCII and the Writer's proper-UTF-8 string bytes decode 1:1,
// so this is idempotent over them.
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
        mutf8::AppendUtf16AsIdentifier(out,
                                       mutf8::Mutf8ToUtf16(in.substr(start, i - start)));
    }
    return out;
}

// Make text safe to place in a `//` comment.
//
// TWO properties, and the second is not obvious. A comment runs to end of line,
// so anything a consumer treats as a line break forges a line — and `\n` is the
// smallest part of that: Python's `str.splitlines()` also breaks on VT, FF, FS,
// GS, RS, NEL, U+2028 and U+2029. And a JAVA compiler translates a `\uXXXX`
// escape BEFORE it recognises comments at all (JLS 3.3), so an escape is a line
// break too — including one this function emits itself.
//
// So the invariant is: THE RESULT CONTAINS NO BACKSLASH. Escapes are written
// `<U+XXXX>`, and a backslash in the input becomes `<U+005C>`. With no `\` in
// the text there is no eligible unicode escape, and a `//` comment cannot be
// terminated by anything. An earlier version escaped as `\uXXXX` and so
// re-forged the very line it had just folded: a delta reviewer took this
// function's OWN `[lf]` guard case, ran the output through javac, and got the
// fabricated `static final String PWNED` field back. Verified here too.
//
// The escaped set is every CONTROL character (C0, DEL, C1) plus the three
// Unicode line separators plus the backslash. C1 belongs for the same reason C0
// does and is reachable for the same reason: ART's
// `IsValidPartOfMemberNameUtf8Slow` has `case 0x00: return leading >= 0x00a0`,
// so a member NAME may not hold one, and before dexllm#64 nothing else could put
// one on a declaration line. 0x9B is the 8-bit CSI, i.e. an escape introducer.
//
// Bidi and invisible FORMAT characters are deliberately NOT escaped: the SAME
// validator ALLOWS U+2066-U+2069 (the bidi isolates — `0x2066 & 0xfff8` is
// 0x2060, which matches no case, so `return true`) and U+FEFF in a member name,
// so they already reach a declaration line through `SanitizeUtf8(finfo.name)`.
// That class is pre-existing and closing it is a change of its own.
//
// None of this is covered by `SanitizeUtf8`: its ASCII fast path passes every
// byte below 0x80 verbatim — which is what lets the Writer's own newlines and
// indentation survive — and its multibyte path renders a BMP separator READABLY
// (dexllm#28), right for an identifier and wrong here. It still runs FIRST,
// because it is what turns raw MUTF-8 into valid UTF-8; dropping it re-opens the
// dexllm#22 raise (a lone surrogate in an annotation element name).
//
// A `/* … */` comment could NOT be secured at all: a string literal inside a
// rendered array carries `*` and `/` through unescaped, so `*/` is injectable.
std::string CommentSafe(std::string_view in) {
    std::string out;
    out.reserve(in.size());
    auto escape = [&out](uint32_t cp) {
        char buf[12];
        std::snprintf(buf, sizeof(buf), "<U+%04X>", cp);
        out += buf;
    };
    const uint8_t* p = reinterpret_cast<const uint8_t*>(in.data());
    for (size_t i = 0, n = in.size(); i < n; ++i) {
        const uint8_t c = p[i];
        if (c < 0x20 || c == 0x7F || c == '\\') {   // C0, DEL, backslash
            escape(c);
        } else if (c == 0xC2 && i + 1 < n && p[i + 1] <= 0x9F) {
            escape(p[i + 1]);                       // C1 (U+0080-U+009F), NEL included
            ++i;
        } else if (c == 0xE2 && i + 2 < n && p[i + 1] == 0x80 &&
                   (p[i + 2] == 0xA8 || p[i + 2] == 0xA9)) {
            escape(p[i + 2] == 0xA8 ? 0x2028 : 0x2029);  // LINE / PARAGRAPH SEP
            i += 2;
        } else {
            out += static_cast<char>(c);
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
        dv.SetIsAssignable([this](std::string_view sub, std::string_view super) {
            return source_.IsAssignable(sub, super);
        });
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
        dv.SetIsAssignable([this](std::string_view sub, std::string_view super) {
            return source_.IsAssignable(sub, super);
        });
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
    // dexllm#22 — every identifier below is RAW pool MUTF-8, so it is sanitised
    // AT ITS SOURCE, the same discipline `SmaliIdent` follows in the renderer. A
    // single pass over the ASSEMBLED text would be the variant an earlier review
    // rejected: `SanitizeUtf8` escapes only controls and surrogates, so decoding
    // after assembly could in principle MATERIALISE a structural character that
    // was never escaped. Sanitising each component makes that structurally
    // impossible instead of relying on the descriptor validators to have rejected
    // it. (Method bodies appended later are already sanitised by RunPipeline.)
    std::string package, name;
    auto last_slash = body.rfind('/');
    if (last_slash != std::string_view::npos) {
        package = SanitizeUtf8(slash_to_dot(std::string{body.substr(0, last_slash)}));
        name = SanitizeUtf8(body.substr(last_slash + 1));
    } else {
        name = SanitizeUtf8(body);
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
        prototype += SanitizeUtf8(slash_to_dot(sc));
    }
    // implements
    if (!info.interfaces.empty()) {
        prototype += " implements ";
        for (size_t i = 0; i < info.interfaces.size(); ++i) {
            if (i > 0) prototype += ", ";
            std::string_view iv = info.interfaces[i];
            prototype += SanitizeUtf8(slash_to_dot(std::string{iv.substr(1, iv.size() - 2)}));
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
        out += SanitizeUtf8(GetType(finfo.type));
        out += ' ';
        out += SanitizeUtf8(finfo.name);
        // Initializer: ClassInfo carries the parsed static_values_off text
        // (Phase 2). GetFieldInfo's per-call init_text is left as a future
        // hook for non-class-context lookups.
        const std::string& init =
            (i < info.field_init_texts.size() && !info.field_init_texts[i].empty())
                ? info.field_init_texts[i] : finfo.init_text;
        if (!init.empty()) {
            out += " = ";
            // Sanitised like every other component: an initializer is NOT always
            // pre-escaped text. Only the STRING arm (0x17) goes through
            // PythonUnicodeEscape; the TYPE (0x18) and FIELD/ENUM (0x19/0x1b)
            // arms of DecodeEncodedValueText emit RAW pool identifiers, so a
            // `static final Class F = Astral.class;` re-raised at the pybind
            // boundary. Found by the delta review — the earlier whole-text pass
            // covered this append incidentally, so removing it needed the seventh
            // site too. Identity for the ASCII/pre-escaped cases.
            out += SanitizeUtf8(init);
        }
        out += ";";
        // dexllm#64 — a value with no Java expression form rides as a trailing
        // comment instead of being DROPPED, which made `Type name;` mean both
        // "no initializer" and "an initializer we could not spell".
        if (i < info.field_init_comments.size() &&
            !info.field_init_comments[i].empty()) {
            out += "  // = ";
            out += CommentSafe(SanitizeUtf8(info.field_init_comments[i]));
        }
        out += "\n";
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
            // Raw pool bytes — the ONE identifier append after the method-body
            // loop starts, so it needs its own sanitize (dexllm#22 review C2).
            out += SanitizeUtf8(method_descriptor);
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
