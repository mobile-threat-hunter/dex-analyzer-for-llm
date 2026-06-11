// dexitem_code_source.cpp — IDexCodeSource implementation over DexKit.

#include "dexitem_code_source.h"

#include <cmath>
#include <cstring>
#include <stdexcept>
#include <string>
#include <utility>

#include "dex_item.h"
#include "slicer/dex_format.h"
#include "slicer/reader.h"
#include "util.h"  // dad::GetType — for TYPE/ENUM EncodedValue rendering

namespace dexkit::ext {

namespace {

// Mirrors core_ext/dexkit_ext.cpp:BuildProtoDescriptor — produces the
// "(args)Ret" raw descriptor for a proto id.
std::string BuildProto(const dexkit::DexItem& item,
                       const dex::ProtoId& proto_id) {
    const auto& type_names = item.GetTypeNames();
    const auto& reader = item.GetReader();
    std::string out;
    out += '(';
    if (proto_id.parameters_off != 0) {
        const auto* type_list =
            reader.dataPtr<dex::TypeList>(proto_id.parameters_off);
        if (type_list != nullptr && type_list->size > 0) {
            for (uint32_t i = 0; i < type_list->size; ++i) {
                out += std::string(type_names[type_list->list[i].type_idx]);
            }
        }
    }
    out += ')';
    out += std::string(type_names[proto_id.return_type_idx]);
    return out;
}

DexItem* SafeGetDexItem(dexkit::DexKit& core, uint16_t dex_id) {
    if (dex_id >= core.GetDexNum()) return nullptr;
    return core.GetDexItem(dex_id);
}

// ─── Encoded value / array byte-stream parsers ────────────────────────────
// dex spec: https://source.android.com/docs/core/runtime/dex-format#encoded-value
// We mirror androguard `EncodedValue` (core/dex/__init__.py:1781) and
// `DvClass.get_source` (decompile.py:354) to produce byte-identical text.

using U1 = dex::u1;

uint32_t ReadULEB128(const U1*& p, const U1* end) {
    uint32_t result = 0;
    uint32_t shift = 0;
    while (p < end) {
        uint8_t b = *p++;
        result |= static_cast<uint32_t>(b & 0x7F) << shift;
        if ((b & 0x80) == 0) return result;
        shift += 7;
        if (shift >= 32) break;
    }
    return result;
}

// Read N bytes (little-endian) as a plain unsigned 64-bit integer.
// androguard `_getintvalue` does the same (no sign extension), so DAD
// emits the unsigned value verbatim — we follow that for byte-identical
// matching even when the result isn't valid Java.
uint64_t ReadIntLE(const U1*& p, const U1* end, size_t nbytes) {
    uint64_t v = 0;
    for (size_t i = 0; i < nbytes && p < end; ++i) {
        v |= static_cast<uint64_t>(*p++) << (8 * i);
    }
    return v;
}

// String escape mimicking Python `str.encode("unicode-escape")` for the
// subset of characters DAD actually emits in field initializers. Printable
// ASCII passes through except the standard backslash escapes; everything
// else becomes \\xNN or \\uNNNN.
std::string PythonUnicodeEscape(std::string_view s) {
    std::string out;
    out.reserve(s.size() + 2);
    auto append_hex2 = [&](uint8_t v) {
        char buf[5];
        std::snprintf(buf, sizeof(buf), "\\x%02x", v);
        out += buf;
    };
    auto append_hex4 = [&](uint32_t cp) {
        char buf[8];
        std::snprintf(buf, sizeof(buf), "\\u%04x", cp);
        out += buf;
    };
    const uint8_t* p = reinterpret_cast<const uint8_t*>(s.data());
    const uint8_t* end = p + s.size();
    while (p < end) {
        uint8_t c = *p;
        if (c == '\\') { out += "\\\\"; ++p; continue; }
        if (c == '\'') { out += "\\'";  ++p; continue; }
        if (c == '\n') { out += "\\n";  ++p; continue; }
        if (c == '\r') { out += "\\r";  ++p; continue; }
        if (c == '\t') { out += "\\t";  ++p; continue; }
        if (c >= 0x20 && c < 0x7F) { out += static_cast<char>(c); ++p; continue; }
        if (c < 0x80) { append_hex2(c); ++p; continue; }
        // Decode UTF-8 to a codepoint, then emit \\uXXXX.
        uint32_t cp = 0; size_t n = 0;
        if      ((c & 0xE0) == 0xC0) { cp = c & 0x1F; n = 2; }
        else if ((c & 0xF0) == 0xE0) { cp = c & 0x0F; n = 3; }
        else if ((c & 0xF8) == 0xF0) { cp = c & 0x07; n = 4; }
        else { append_hex2(c); ++p; continue; }
        if (p + n > end) { append_hex2(c); ++p; continue; }
        bool ok = true;
        ++p;
        for (size_t i = 1; i < n; ++i, ++p) {
            uint8_t cc = *p;
            if ((cc & 0xC0) != 0x80) { ok = false; break; }
            cp = (cp << 6) | (cc & 0x3F);
        }
        if (!ok) { append_hex2(c); continue; }
        if (cp <= 0xFFFF) append_hex4(cp);
        else {
            // Surrogate pair (DAD's Python repr does the same)
            uint32_t v = cp - 0x10000;
            append_hex4(0xD800 | (v >> 10));
            append_hex4(0xDC00 | (v & 0x3FF));
        }
    }
    return out;
}

// Decode a single EncodedValue and produce DAD-equivalent text. Returns
// empty string for value types we don't render (TYPE/FIELD/METHOD/ENUM/
// ARRAY/ANNOTATION/FLOAT/DOUBLE) — DAD emits `str(<wrapped object>)` for
// these but the result is rarely valid Java and varies by androguard
// version, so we conservatively skip.
//
// p advances past the consumed bytes regardless.
std::string DecodeEncodedValueText(const U1*& p,
                                   const U1* end,
                                   const dexkit::DexItem& item) {
    if (p >= end) return {};
    U1 header = *p++;
    uint8_t value_arg = (header >> 5) & 0x07;
    uint8_t value_type = header & 0x1F;
    size_t nbytes = static_cast<size_t>(value_arg) + 1;
    switch (value_type) {
        case 0x00: {  // BYTE — 1 byte, treated as signed for `hex()` output
            uint64_t raw = ReadIntLE(p, end, 1);
            int8_t v = static_cast<int8_t>(raw & 0xFF);
            char buf[16];
            if (v < 0) std::snprintf(buf, sizeof(buf), "-0x%x", -static_cast<int>(v));
            else       std::snprintf(buf, sizeof(buf), "0x%x", static_cast<int>(v));
            return buf;
        }
        case 0x02:   // SHORT
        case 0x03:   // CHAR
        case 0x04:   // INT
        case 0x06: { // LONG — androguard reads all of these as LE unsigned
            uint64_t v = ReadIntLE(p, end, nbytes);
            return std::to_string(v);
        }
        case 0x10: {  // FLOAT — 32-bit IEEE754, "zero-extended to the right"
            // Per dex spec (and androguard `_unpack_value`): payload bytes go
            // to the LSB end of the 4-byte buffer; the high (MSB) end is
            // zero-padded. So `padded[0..size-1] = stored, padded[size..3] = 0`,
            // then reinterpret little-endian as float.
            //
            // We diverge from DAD here (DAD reads it as LE unsigned and emits
            // the resulting huge integer, which isn't valid Java). DAD's
            // `_getintvalue` has `# TODO: parse floats/doubles correctly`.
            uint8_t buf[4] = {0};
            size_t n = std::min<size_t>(nbytes, 4);
            for (size_t i = 0; i < n && p < end; ++i) buf[i] = *p++;
            // Consume any excess bytes the encoder claimed (shouldn't happen
            // for well-formed dex, but keep the cursor honest).
            if (nbytes > 4) p += (nbytes - 4);
            uint32_t bits = 0;
            for (int i = 0; i < 4; ++i) bits |= static_cast<uint32_t>(buf[i]) << (i * 8);
            float f;
            std::memcpy(&f, &bits, 4);
            if (std::isnan(f)) return std::string("Float.NaN");
            if (std::isinf(f)) return f > 0 ? std::string("Float.POSITIVE_INFINITY")
                                            : std::string("Float.NEGATIVE_INFINITY");
            char buffer[40];
            // %.9g is the round-trip precision for IEEE754 binary32.
            std::snprintf(buffer, sizeof(buffer), "%.9gf", static_cast<double>(f));
            return std::string(buffer);
        }
        case 0x11: {  // DOUBLE — 64-bit IEEE754, "zero-extended to the right"
            uint8_t buf[8] = {0};
            size_t n = std::min<size_t>(nbytes, 8);
            for (size_t i = 0; i < n && p < end; ++i) buf[i] = *p++;
            if (nbytes > 8) p += (nbytes - 8);
            uint64_t bits = 0;
            for (int i = 0; i < 8; ++i) bits |= static_cast<uint64_t>(buf[i]) << (i * 8);
            double d;
            std::memcpy(&d, &bits, 8);
            if (std::isnan(d)) return std::string("Double.NaN");
            if (std::isinf(d)) return d > 0 ? std::string("Double.POSITIVE_INFINITY")
                                            : std::string("Double.NEGATIVE_INFINITY");
            char buffer[48];
            // %.17g is the round-trip precision for IEEE754 binary64.
            std::snprintf(buffer, sizeof(buffer), "%.17g", d);
            return std::string(buffer);
        }
        case 0x17: {  // STRING
            uint64_t idx = ReadIntLE(p, end, nbytes);
            const auto& strings = item.GetStrings();
            if (idx >= strings.size()) return std::string("\"\"");
            std::string_view raw = strings[idx];
            if (raw.empty()) return std::string("\"\"");
            return std::string("\"") + PythonUnicodeEscape(raw) + "\"";
        }
        case 0x18: {  // TYPE — class literal "pkg.Cls.class" or "int[].class"
            uint64_t idx = ReadIntLE(p, end, nbytes);
            const auto& type_names = item.GetTypeNames();
            if (idx >= type_names.size()) return {};
            // dad::GetType handles primitives (V/Z/B/.../J → void/boolean/...),
            // reference types ("Lpkg/Cls;" → "pkg.Cls"), and arrays.
            return dexkit::dad::GetType(type_names[idx]) + ".class";
        }
        case 0x19:   // FIELD — constant field reference: "Cls.NAME"
        case 0x1b: { // ENUM  — same shape; semantically an enum constant.
            uint64_t idx = ReadIntLE(p, end, nbytes);
            const auto& reader = item.GetReader();
            const auto& strings = item.GetStrings();
            const auto& type_names = item.GetTypeNames();
            const auto field_ids = reader.FieldIds();
            if (idx >= field_ids.size()) return {};
            const auto& f = field_ids[idx];
            std::string out;
            out += dexkit::dad::GetType(type_names[f.class_idx]);
            out += '.';
            out.append(strings[f.name_idx]);
            return out;
        }
        case 0x1a: {  // METHOD — no Java literal form (method reflection isn't
                      // a valid initializer expression). Skip.
            p += nbytes;
            return {};
        }
        case 0x1c: {  // ARRAY — skip body
            uint32_t sz = ReadULEB128(p, end);
            for (uint32_t i = 0; i < sz && p < end; ++i) {
                (void)DecodeEncodedValueText(p, end, item);
            }
            return {};
        }
        case 0x1d: {  // ANNOTATION — skip (complex; DAD doesn't emit anyway)
            // type_idx (uleb128), size (uleb128), then size * (name_idx + value)
            (void)ReadULEB128(p, end);
            uint32_t sz = ReadULEB128(p, end);
            for (uint32_t i = 0; i < sz && p < end; ++i) {
                (void)ReadULEB128(p, end);  // name_idx
                (void)DecodeEncodedValueText(p, end, item);
            }
            return {};
        }
        case 0x1e:   // NULL — DAD emits the Python literal "None" (value=None,
                     // but the EncodedValue wrapper is truthy so the
                     // initializer is still written). "None" is not valid Java.
                     // Production fix (same precedent as the float/double
                     // IEEE754 decode — this decoder lives in core_ext, not the
                     // parity-tested dad_cpp surface, so no *DADFaithful sibling):
                     // emit spec-correct "null".
            return std::string("null");
        case 0x1f:   // BOOLEAN — DAD emits the Python literals "True"/"False",
                     // which are not valid Java. Production fix: emit the Java
                     // literals "true"/"false".
            return value_arg ? std::string("true") : std::string("false");
        default:
            return {};
    }
}

// Walk ClassData to recover the declaration-order field_idx lists for the
// class. DAD emits static fields first, then instance fields (mirroring the
// ClassData layout). `class_field_ids` from DexItem isn't guaranteed to be
// in this order, so we re-derive it here.
struct OrderedFields {
    std::vector<uint32_t> static_ids;
    std::vector<uint32_t> instance_ids;
};
OrderedFields ParseClassFieldOrder(const dexkit::DexItem& item,
                                   const dex::ClassDef& cdef) {
    OrderedFields out;
    if (cdef.class_data_off == 0) return out;
    const auto& reader = item.GetReader();
    const U1* data = reader.dataPtr<U1>(cdef.class_data_off);
    if (!data) return out;
    const U1* data_end = data + (1u << 20);  // generous mmap cap per class

    uint32_t static_n   = ReadULEB128(data, data_end);
    uint32_t instance_n = ReadULEB128(data, data_end);
    (void)ReadULEB128(data, data_end);   // direct_methods_size
    (void)ReadULEB128(data, data_end);   // virtual_methods_size

    auto read_field_list = [&](uint32_t n, std::vector<uint32_t>& dst) {
        dst.reserve(n);
        uint32_t cur = 0;
        for (uint32_t i = 0; i < n; ++i) {
            uint32_t diff = ReadULEB128(data, data_end);
            (void)ReadULEB128(data, data_end);   // access_flags
            cur = (i == 0) ? diff : (cur + diff);
            dst.push_back(cur);
        }
    };
    read_field_list(static_n,   out.static_ids);
    read_field_list(instance_n, out.instance_ids);
    return out;
}

// Decode the EncodedArray @ static_values_off and pair each value with the
// matching static field_idx (positional). Returns field_idx → init text;
// fields without an EncodedValue entry (or with unsupported value types)
// are simply absent from the map.
std::unordered_map<uint32_t, std::string>
DecodeStaticInitMap(const dexkit::DexItem& item,
                    const dex::ClassDef& cdef,
                    const std::vector<uint32_t>& static_field_idxs) {
    std::unordered_map<uint32_t, std::string> init_map;
    if (cdef.static_values_off == 0 || static_field_idxs.empty()) {
        return init_map;
    }
    const auto& reader = item.GetReader();
    const U1* sv = reader.dataPtr<U1>(cdef.static_values_off);
    if (!sv) return init_map;
    const U1* sv_end = sv + (1u << 20);
    uint32_t value_count = ReadULEB128(sv, sv_end);
    if (value_count > static_field_idxs.size()) {
        value_count = static_field_idxs.size();
    }
    init_map.reserve(value_count);
    for (uint32_t i = 0; i < value_count; ++i) {
        std::string text = DecodeEncodedValueText(sv, sv_end, item);
        if (!text.empty()) init_map.emplace(static_field_idxs[i], std::move(text));
    }
    return init_map;
}

}  // namespace

DexItemCodeSource::DexItemCodeSource(dexkit::DexKit& core) : core_(core) {}

std::optional<dexkit::dad::IDexCodeSource::MethodLocator>
DexItemCodeSource::LocateMethod(std::string_view descriptor) {
    // Parse "Lcls;->name(proto)Ret". Strip whitespace first — androguard's
    // EncodedMethod.get_descriptor() inserts spaces between args ("(LA; LB;)V")
    // while our internal proto is spaceless ("(LA;LB;)V"). Types themselves
    // contain no whitespace, so stripping all whitespace is safe.
    std::string normalized;
    normalized.reserve(descriptor.size());
    for (char c : descriptor) {
        if (c != ' ' && c != '\t' && c != '\n' && c != '\r') normalized += c;
    }
    std::string_view ndesc{normalized};
    auto arrow = ndesc.find("->");
    if (arrow == std::string_view::npos) return std::nullopt;
    std::string_view class_desc = ndesc.substr(0, arrow);
    std::string_view rest = ndesc.substr(arrow + 2);
    auto open = rest.find('(');
    if (open == std::string_view::npos) return std::nullopt;
    std::string_view name = rest.substr(0, open);
    std::string_view proto = rest.substr(open);

    auto [dex_item, type_idx] = core_.GetClassDeclaredPair(class_desc);
    if (dex_item == nullptr) return std::nullopt;

    const auto& reader = dex_item->GetReader();
    const auto& strings = dex_item->GetStrings();
    const auto method_ids = reader.MethodIds();
    const auto proto_ids = reader.ProtoIds();
    for (size_t i = 0; i < method_ids.size(); ++i) {
        const auto& m = method_ids[i];
        if (m.class_idx != type_idx) continue;
        if (strings[m.name_idx] != name) continue;
        if (BuildProto(*dex_item, proto_ids[m.proto_idx]) != proto) continue;
        return dexkit::dad::IDexCodeSource::MethodLocator{
            dex_item->GetDexId(), static_cast<uint32_t>(i)};
    }
    return std::nullopt;
}

std::vector<dexkit::dad::IDexCodeSource::MethodLocator>
DexItemCodeSource::LocateClassMethods(std::string_view class_descriptor) {
    std::vector<dexkit::dad::IDexCodeSource::MethodLocator> out;
    auto [dex_item, type_idx] = core_.GetClassDeclaredPair(class_descriptor);
    if (dex_item == nullptr) return out;
    const auto& class_method_ids = dex_item->GetClassMethodIds(type_idx);
    out.reserve(class_method_ids.size());
    for (uint32_t midx : class_method_ids) {
        out.push_back({dex_item->GetDexId(), midx});
    }
    return out;
}

uint32_t DexItemCodeSource::GetMethodAccessFlags(uint16_t dex_id,
                                                 uint32_t midx) {
    DexItem* item = SafeGetDexItem(core_, dex_id);
    if (!item) return 0;
    // DAD-aligned decompilation needs the RAW access flags (with
    // declared_synchronized bit intact). The default GetMethodAccessFlags
    // applies a Java-Modifier-compat transform that drops the
    // declared_synchronized bit; use the raw vector here.
    const auto& flags = item->GetMethodRawAccessFlags();
    return midx < flags.size() ? flags[midx] : 0;
}

std::string_view DexItemCodeSource::GetMethodClassName(uint16_t dex_id,
                                                       uint32_t midx) {
    DexItem* item = SafeGetDexItem(core_, dex_id);
    if (!item) return {};
    const auto& reader = item->GetReader();
    const auto& type_names = item->GetTypeNames();
    const auto method_ids = reader.MethodIds();
    if (midx >= method_ids.size()) return {};
    return type_names[method_ids[midx].class_idx];
}

std::string_view DexItemCodeSource::GetMethodName(uint16_t dex_id,
                                                  uint32_t midx) {
    DexItem* item = SafeGetDexItem(core_, dex_id);
    if (!item) return {};
    const auto& reader = item->GetReader();
    const auto& strings = item->GetStrings();
    const auto method_ids = reader.MethodIds();
    if (midx >= method_ids.size()) return {};
    return strings[method_ids[midx].name_idx];
}

std::string DexItemCodeSource::GetMethodProto(uint16_t dex_id,
                                              uint32_t midx) {
    DexItem* item = SafeGetDexItem(core_, dex_id);
    if (!item) return {};
    const auto& reader = item->GetReader();
    const auto method_ids = reader.MethodIds();
    if (midx >= method_ids.size()) return {};
    const auto& proto_id = reader.ProtoIds()[method_ids[midx].proto_idx];
    return BuildProto(*item, proto_id);
}

const dex::Code* DexItemCodeSource::GetMethodCode(uint16_t dex_id,
                                                  uint32_t midx) {
    DexItem* item = SafeGetDexItem(core_, dex_id);
    if (!item) return nullptr;
    return item->GetMethodCode(midx);
}

std::string_view
DexItemCodeSource::GetProtoCached(uint16_t dex_id, uint32_t proto_idx) {
    uint64_t key = ProtoKey(dex_id, proto_idx);
    {
        std::lock_guard lock(proto_cache_mutex_);
        auto it = proto_cache_.find(key);
        if (it != proto_cache_.end()) return it->second;
    }
    DexItem* item = SafeGetDexItem(core_, dex_id);
    if (!item) return {};
    const auto& proto_id = item->GetReader().ProtoIds()[proto_idx];
    std::string proto = BuildProto(*item, proto_id);
    std::lock_guard lock(proto_cache_mutex_);
    auto [it, _] = proto_cache_.emplace(key, std::move(proto));
    return it->second;
}

std::string_view DexItemCodeSource::GetString(uint16_t dex_id, uint32_t idx) {
    DexItem* item = SafeGetDexItem(core_, dex_id);
    if (!item) return {};
    const auto& strings = item->GetStrings();
    if (idx >= strings.size()) return {};
    return strings[idx];
}

std::string_view DexItemCodeSource::GetTypeName(uint16_t dex_id, uint32_t idx) {
    DexItem* item = SafeGetDexItem(core_, dex_id);
    if (!item) return {};
    const auto& type_names = item->GetTypeNames();
    if (idx >= type_names.size()) return {};
    return type_names[idx];
}

std::array<std::string_view, 3>
DexItemCodeSource::GetMethodRefTriple(uint16_t dex_id, uint32_t midx) {
    DexItem* item = SafeGetDexItem(core_, dex_id);
    if (!item) return {{}};
    const auto& reader = item->GetReader();
    const auto& type_names = item->GetTypeNames();
    const auto& strings = item->GetStrings();
    const auto method_ids = reader.MethodIds();
    if (midx >= method_ids.size()) return {{}};
    const auto& m = method_ids[midx];
    // Build proto on the fly. Proto returned by value (string), stored on
    // DexItem? No — we'd need stable storage. Workaround: stash protos in a
    // per-source cache. For now we return a static-thread-local string.
    // SAFER alternative: return the original Smali "(args)Ret" via DexItem
    // helper. DexItem doesn't expose this. We pre-cache here.
    //
    // Simplest correct path: keep a per-DexItem proto cache in this
    // adapter. Allocate on first call, return string_view into it.
    std::array<std::string_view, 3> out;
    out[0] = type_names[m.class_idx];
    out[1] = strings[m.name_idx];
    out[2] = GetProtoCached(dex_id, m.proto_idx);
    return out;
}

std::array<std::string_view, 3>
DexItemCodeSource::GetFieldRefTriple(uint16_t dex_id, uint32_t fidx) {
    DexItem* item = SafeGetDexItem(core_, dex_id);
    if (!item) return {{}};
    const auto& reader = item->GetReader();
    const auto& type_names = item->GetTypeNames();
    const auto& strings = item->GetStrings();
    const auto field_ids = reader.FieldIds();
    if (fidx >= field_ids.size()) return {{}};
    const auto& f = field_ids[fidx];
    return {type_names[f.class_idx], strings[f.name_idx], type_names[f.type_idx]};
}

// DAD: decompile.py:269 DvClass.__init__ — supplies metadata used by
// get_source() to emit the package / class header / interface list.
std::optional<dexkit::dad::IDexCodeSource::ClassInfo>
DexItemCodeSource::GetClassInfo(std::string_view class_descriptor) {
    auto [item, type_idx] = core_.GetClassDeclaredPair(class_descriptor);
    if (item == nullptr) return std::nullopt;
    uint32_t class_def_idx = item->GetTypeDefIdx(type_idx);
    if (class_def_idx == dex::kNoIndex) return std::nullopt;

    const auto& reader = item->GetReader();
    const auto& type_names = item->GetTypeNames();
    const auto class_defs = reader.ClassDefs();
    if (class_def_idx >= class_defs.size()) return std::nullopt;
    const auto& cdef = class_defs[class_def_idx];

    ClassInfo info;
    info.dex_id = item->GetDexId();
    info.type_idx = type_idx;
    info.access_flags = cdef.access_flags;
    if (cdef.superclass_idx != dex::kNoIndex) {
        info.superclass = type_names[cdef.superclass_idx];
    }
    if (cdef.interfaces_off != 0) {
        const auto* type_list =
            reader.dataPtr<dex::TypeList>(cdef.interfaces_off);
        if (type_list != nullptr) {
            info.interfaces.reserve(type_list->size);
            for (uint32_t i = 0; i < type_list->size; ++i) {
                info.interfaces.push_back(
                    type_names[type_list->list[i].type_idx]);
            }
        }
    }
    // Field ordering: DAD's DvClass emits static fields first, then instance
    // fields, in ClassData declaration order. DexItem's `class_field_ids`
    // doesn't preserve that grouping — re-derive it from ClassData.
    auto fields = ParseClassFieldOrder(*item, cdef);
    info.field_ids.reserve(fields.static_ids.size() + fields.instance_ids.size());
    info.field_ids.insert(info.field_ids.end(),
                          fields.static_ids.begin(), fields.static_ids.end());
    info.field_ids.insert(info.field_ids.end(),
                          fields.instance_ids.begin(), fields.instance_ids.end());

    // Decode static-field initializers (EncodedArray @ static_values_off);
    // result is parallel to field_ids and stays empty for fields with no
    // compile-time init or unsupported value types (FLOAT/DOUBLE/TYPE/...).
    auto init_map = DecodeStaticInitMap(*item, cdef, fields.static_ids);
    info.field_init_texts.assign(info.field_ids.size(), std::string{});
    for (size_t i = 0; i < info.field_ids.size(); ++i) {
        auto it = init_map.find(info.field_ids[i]);
        if (it != init_map.end()) info.field_init_texts[i] = it->second;
    }
    return info;
}

// DAD: decompile.py:367 DvClass.get_source — per-field name + type + access.
// init_text is left empty for now (Phase 1): DvClass emits `Type name;`
// when there's no compile-time initializer, which is valid Java. EncodedValue
// decoding (String/byte/primitive/...) is a deferred follow-up.
dexkit::dad::IDexCodeSource::FieldInfo
DexItemCodeSource::GetFieldInfo(uint16_t dex_id, uint32_t fidx) {
    FieldInfo info;
    DexItem* item = SafeGetDexItem(core_, dex_id);
    if (!item) return info;
    const auto& reader = item->GetReader();
    const auto& strings = item->GetStrings();
    const auto& type_names = item->GetTypeNames();
    const auto field_ids = reader.FieldIds();
    if (fidx >= field_ids.size()) return info;
    const auto& f = field_ids[fidx];
    info.name = strings[f.name_idx];
    info.type = type_names[f.type_idx];
    const auto& access = item->GetFieldAccessFlags();
    if (fidx < access.size()) info.access_flags = access[fidx];
    return info;
}

}  // namespace dexkit::ext
