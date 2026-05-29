// util.cpp — DAD util.py port.
// See include/util.h for status and per-function DAD references.
//
// DAD: androguard/decompiler/util.py

#include "util.h"

#include <array>
#include <unordered_map>

namespace dexkit::dad {

namespace {

// DAD: util.py:30 TYPE_DESCRIPTOR
const std::unordered_map<char, std::string_view>& TypeDescriptorTable() {
    static const std::unordered_map<char, std::string_view> kTable = {
        {'V', "void"},   {'Z', "boolean"}, {'B', "byte"},
        {'S', "short"},  {'C', "char"},    {'I', "int"},
        {'J', "long"},   {'F', "float"},   {'D', "double"},
    };
    return kTable;
}

// DAD: util.py:42 ACCESS_FLAGS_CLASSES
const std::unordered_map<uint32_t, std::string_view>& AccessFlagsClassesTable() {
    static const std::unordered_map<uint32_t, std::string_view> kTable = {
        {0x1, "public"},    {0x2, "private"},   {0x4, "protected"},
        {0x8, "static"},    {0x10, "final"},    {0x200, "interface"},
        {0x400, "abstract"},{0x1000, "synthetic"},
        {0x2000, "annotation"}, {0x4000, "enum"},
    };
    return kTable;
}

// DAD: util.py:55 ACCESS_FLAGS_FIELDS
const std::unordered_map<uint32_t, std::string_view>& AccessFlagsFieldsTable() {
    static const std::unordered_map<uint32_t, std::string_view> kTable = {
        {0x1, "public"},   {0x2, "private"},  {0x4, "protected"},
        {0x8, "static"},   {0x10, "final"},   {0x40, "volatile"},
        {0x80, "transient"}, {0x1000, "synthetic"}, {0x4000, "enum"},
    };
    return kTable;
}

// DAD: util.py:67 ACCESS_FLAGS_METHODS
const std::unordered_map<uint32_t, std::string_view>& AccessFlagsMethodsTable() {
    static const std::unordered_map<uint32_t, std::string_view> kTable = {
        {0x1, "public"},    {0x2, "private"},   {0x4, "protected"},
        {0x8, "static"},    {0x10, "final"},    {0x20, "synchronized"},
        {0x40, "bridge"},   {0x80, "varargs"},  {0x100, "native"},
        {0x400, "abstract"},{0x800, "strictfp"},{0x1000, "synthetic"},
        {0x10000, "constructor"}, {0x20000, "declared_synchronized"},
    };
    return kTable;
}

// DAD: util.py:84 ACCESS_ORDER — canonical bit emission order.
constexpr std::array<uint32_t, 17> kAccessOrder = {
    0x1,   0x4,   0x2,   0x400, 0x8,   0x10,  0x80,  0x40,  0x20,
    0x100, 0x800, 0x200, 0x1000,0x2000,0x4000,0x10000,0x20000,
};

// DAD: util.py:104 TYPE_LEN
const std::unordered_map<char, unsigned>& TypeLenTable() {
    static const std::unordered_map<char, unsigned> kTable = {
        {'J', 2}, {'D', 2},
    };
    return kTable;
}

// Shared helper for get_access_*: walk ACCESS_ORDER, for each set bit look
// up the per-kind table, fall back to "unkn_<flag>".
std::vector<std::string> GetAccessImpl(
        uint32_t access,
        const std::unordered_map<uint32_t, std::string_view>& table) {
    std::vector<std::string> out;
    out.reserve(8);
    for (uint32_t flag : kAccessOrder) {
        if ((flag & access) == 0) continue;
        auto it = table.find(flag);
        if (it != table.end()) {
            out.emplace_back(it->second);
        } else {
            out.emplace_back("unkn_" + std::to_string(flag));
        }
    }
    return out;
}

}  // namespace

// DAD: util.py:30 TYPE_DESCRIPTOR lookup.
std::string_view LookupTypeDescriptor(char primitive) noexcept {
    const auto& t = TypeDescriptorTable();
    auto it = t.find(primitive);
    return (it != t.end()) ? it->second : std::string_view{};
}

// DAD: util.py:104 TYPE_LEN lookup, default 1.
unsigned LookupTypeLen(char primitive) noexcept {
    const auto& t = TypeLenTable();
    auto it = t.find(primitive);
    return (it != t.end()) ? it->second : 1u;
}

// DAD: util.py:110 get_access_class.
std::vector<std::string> GetAccessClass(uint32_t access) {
    return GetAccessImpl(access, AccessFlagsClassesTable());
}

// DAD: util.py:118 get_access_method.
std::vector<std::string> GetAccessMethod(uint32_t access) {
    return GetAccessImpl(access, AccessFlagsMethodsTable());
}

// DAD: util.py:126 get_access_field.
std::vector<std::string> GetAccessField(uint32_t access) {
    return GetAccessImpl(access, AccessFlagsFieldsTable());
}

// DAD: util.py:198 get_type_size — TYPE_LEN.get(param, 1).
unsigned GetTypeSize(std::string_view param) noexcept {
    if (param.empty()) return 1;
    return LookupTypeLen(param.front());
}

// DAD: util.py:205 get_type — fixed variant.
//
// Strips the "java/lang/" prefix as a proper prefix (not char-set).
// DAD upstream has a char-set strip bug; the bug-compatible variant for
// parity testing lives in `GetTypeDADFaithful` below.
std::string GetType(std::string_view atype, uint32_t size) {
    if (atype.empty()) return std::string{atype};
    if (atype.size() == 1) {
        auto sv = LookupTypeDescriptor(atype.front());
        if (!sv.empty()) return std::string{sv};
    }
    char head = atype.front();
    if (head == 'L') {
        if (atype.size() < 2 || atype.back() != ';') {
            return std::string{atype};
        }
        std::string body{atype.substr(1, atype.size() - 2)};
        constexpr std::string_view kJavaLang = "java/lang/";
        if (body.size() >= kJavaLang.size() &&
            body.compare(0, kJavaLang.size(), kJavaLang) == 0) {
            body.erase(0, kJavaLang.size());
        }
        for (char& c : body) {
            if (c == '/') c = '.';
        }
        return body;
    }
    if (head == '[') {
        std::string inner = GetType(atype.substr(1));
        if (size == UINT32_MAX) {
            return inner + "[]";
        }
        return inner + "[" + std::to_string(size) + "]";
    }
    return std::string{atype};
}

// DAD: util.py:205 get_type — bug-compatible variant for parity tests.
//
// Preserves the `atype[1:-1].lstrip('java/lang/')` char-set strip bug so
// parity tests can verify byte-identical output against androguard DAD.
// Production code MUST use `GetType` instead.
std::string GetTypeDADFaithful(std::string_view atype, uint32_t size) {
    if (atype.empty()) return std::string{atype};
    if (atype.size() == 1) {
        auto sv = LookupTypeDescriptor(atype.front());
        if (!sv.empty()) return std::string{sv};
    }
    char head = atype.front();
    if (head == 'L') {
        if (atype.size() < 2 || atype.back() != ';') {
            return std::string{atype};
        }
        std::string body{atype.substr(1, atype.size() - 2)};
        if (atype.size() >= 10 &&
            atype.compare(0, 10, "Ljava/lang") == 0) {
            static const std::string kStripSet = "java/lng";
            size_t i = 0;
            while (i < body.size() &&
                   kStripSet.find(body[i]) != std::string::npos) {
                ++i;
            }
            body.erase(0, i);
        }
        for (char& c : body) {
            if (c == '/') c = '.';
        }
        return body;
    }
    if (head == '[') {
        std::string inner = GetTypeDADFaithful(atype.substr(1));
        if (size == UINT32_MAX) {
            return inner + "[]";
        }
        return inner + "[" + std::to_string(size) + "]";
    }
    return std::string{atype};
}

// DAD: util.py:227 get_params_type.
//
// Faithful to DAD's quirk: `descriptor.split(')')[0][1:].split()` ends up
// whitespace-splitting a no-whitespace string, so the whole parameter chunk
// returns as a single list element (or [] when empty).
std::vector<std::string> GetParamsType(std::string_view descriptor) {
    auto rparen = descriptor.find(')');
    if (rparen == std::string_view::npos) return {};
    if (rparen == 0) return {};
    // [1:] drops the leading '('.
    auto params = descriptor.substr(1, rparen - 1);
    if (params.empty()) return {};
    return {std::string{params}};
}

// Proper Dalvik descriptor parser — used by Writer for signature emission.
// Splits "(IL.../X;[I)V" into ["I", "L.../X;", "[I"].
std::vector<std::string> ParseParamsType(std::string_view proto) {
    std::vector<std::string> out;
    auto rparen = proto.find(')');
    if (rparen == std::string_view::npos) return out;
    if (rparen <= 1) return out;
    std::string_view body = proto.substr(1, rparen - 1);  // strip ( and )
    size_t i = 0;
    while (i < body.size()) {
        size_t start = i;
        // Skip array dimensions (each '[' is part of the same descriptor).
        while (i < body.size() && body[i] == '[') ++i;
        if (i >= body.size()) break;
        char c = body[i];
        if (c == 'L') {
            // Object type: L<name>; — find the ';'.
            size_t end = body.find(';', i);
            if (end == std::string_view::npos) { ++i; break; }
            out.emplace_back(body.substr(start, end - start + 1));
            i = end + 1;
        } else {
            // Primitive: single char.
            out.emplace_back(body.substr(start, i - start + 1));
            ++i;
        }
    }
    return out;
}

}  // namespace dexkit::dad
