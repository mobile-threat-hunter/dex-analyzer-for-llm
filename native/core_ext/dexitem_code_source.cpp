// dexitem_code_source.cpp — IDexCodeSource implementation over DexKit.

#include "dexitem_code_source.h"

#include <algorithm>
#include <cmath>
#include <cstring>
#include <stdexcept>
#include <string>
#include <unordered_set>
#include <utility>
#include <vector>

#include "dex_item.h"
#include "mmap.h"  // dexkit::MemMap (GetDexImageRange bounds)
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
    // Indices come from the (possibly corrupt) proto/type tables — bound every
    // type-name lookup against the table size to avoid an OOB vector read.
    auto type_name = [&](uint32_t idx) -> std::string_view {
        return idx < type_names.size() ? type_names[idx] : std::string_view{};
    };
    std::string out;
    out += '(';
    if (proto_id.parameters_off != 0) {
        const auto* type_list =
            reader.dataPtr<dex::TypeList>(proto_id.parameters_off);
        if (type_list != nullptr) {
            uint32_t n = type_list->size;
            // `size` is read from the image; clamp so list[n] can't run off the
            // mmap on a corrupt parameters_off / size.
            if (auto* img = item.GetImage()) {
                const auto* img_end =
                    reinterpret_cast<const uint8_t*>(img->data()) + img->len();
                const auto* list0 =
                    reinterpret_cast<const uint8_t*>(type_list->list);
                size_t maxn = list0 <= img_end
                                  ? static_cast<size_t>(img_end - list0) /
                                        sizeof(type_list->list[0])
                                  : 0;
                if (n > maxn) n = static_cast<uint32_t>(maxn);
            }
            for (uint32_t i = 0; i < n; ++i) {
                out += std::string(type_name(type_list->list[i].type_idx));
            }
        }
    }
    out += ')';
    out += std::string(type_name(proto_id.return_type_idx));
    return out;
}

DexItem* SafeGetDexItem(dexkit::DexKit& core, uint16_t dex_id) {
    if (dex_id >= core.GetDexNum()) return nullptr;
    return core.GetDexItem(dex_id);
}

// PRECONDITION: every DexItem reaching this adapter was structurally validated
// at load by dexkit::ext::VerifyDex (see native/core_ext/dex_verifier.h — the
// single malformed-dex safety gate). So secondary dex-table indices (a verified
// field_id's class_idx/name_idx/type_idx, method_id's class_idx, etc.) are
// in-range by construction; we index the string / type-name tables directly. The
// old SafeAt() bounds-checked accessor was removed as redundant with the verifier.
// Indices from EXTERNAL callers (the `*idx` parameters below) are NOT covered by
// the verifier and keep their own `if (idx >= table.size())` guards.

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
//
// dexllm#22 — with ONE deliberate divergence from `unicode-escape`: the DOUBLE
// quote is escaped as well. Python's codec escapes `'` and not `"` because its
// repr is single-quoted; the caller here wraps the result in DOUBLE quotes to
// build a JAVA literal, so a `"` in the value TERMINATED that literal early —
// 9 lines of real corpus output are invalid Java (`= "<?xml version="1.0" …>";`)
// and a crafted value could append a whole fabricated field declaration to the
// class body that `decompile_class` hands an analyst or an LLM. The method-body
// emitter (`EscapeJavaString`) and the smali emitter (`EscapeSmaliString`) both
// already escape it; this path was the outlier.
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
        if (c == '"')  { out += "\\\""; ++p; continue; }  // dexllm#22 — see above
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
            // for well-formed dex), clamped so the cursor never passes `end`.
            if (nbytes > 4)
                p += std::min<size_t>(nbytes - 4, p < end ? (end - p) : 0);
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
            if (nbytes > 8)
                p += std::min<size_t>(nbytes - 8, p < end ? (end - p) : 0);
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
            // idx validated in-range by VerifyEncodedValue (static_values gate).
            std::string_view raw = strings[idx];
            if (raw.empty()) return std::string("\"\"");
            return std::string("\"") + PythonUnicodeEscape(raw) + "\"";
        }
        case 0x18: {  // TYPE — class literal "pkg.Cls.class" or "int[].class"
            uint64_t idx = ReadIntLE(p, end, nbytes);
            const auto& type_names = item.GetTypeNames();
            // idx validated in-range by VerifyEncodedValue (static_values gate).
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
            // idx validated in-range by VerifyEncodedValue (static_values gate);
            // a verified field_id's class_idx/name_idx are in-range by CheckIntra.
            const auto& f = field_ids[idx];
            std::string out;
            out += dexkit::dad::GetType(type_names[f.class_idx]);
            out += '.';
            out.append(strings[f.name_idx]);
            return out;
        }
        case 0x15:   // METHOD_TYPE   — an index into proto_ids
        case 0x16:   // METHOD_HANDLE — an index into the method_handle section
        case 0x1a: { // METHOD        — an index into method_ids
            // All three are (arg+1)-byte indices with NO Java literal form: a
            // MethodType / MethodHandle / method reference cannot be written as
            // an initializer expression, so rendering one would put invalid Java
            // into a field declaration. Returning {} tells the caller "no
            // initializer" — but the payload MUST still be consumed, or every
            // following value in the same encoded_array decodes from the wrong
            // offset.
            //
            // The width the merged body must survive is NOT uniform: 0x15 and
            // 0x1a go through VerifyEncodedValue's `idx` lambda, which rejects
            // arg > 3, but 0x16 uses `skip(arg + 1)` with no arg cap, so an
            // EIGHT-byte "index" passes the gate. ReadIntLE reads (arg+1) bytes
            // into a uint64 in every case, so the consumption matches the gate's
            // for all three and cannot overflow.
            //
            // KNOWN COST, deliberate and pre-existing for 0x1a/0x1c/0x1d: the
            // caller cannot tell "this field has no initializer" from "this
            // field's initializer is unrenderable", and decompile_class is the
            // ONLY surface that reads static values at all (render_class_smali
            // emits none), so the dropped constant is not recoverable elsewhere.
            // Both reviewers raised it; dexllm#63 scopes rendering OUT by its own
            // terms ("whether to RENDER anything is a separate question"), and it
            // sits against this repo's own make-ignorance-representable precedent
            // (dexllm#41, dexllm#49). A marker comment or a MethodType rendered
            // through proto_ids would close it — a separate decision, not a
            // silent one. 0x15/0x16 were missing entirely and fell to `default:`,
            // which consumed only the header byte (dexllm#63); they are legal
            // since API 26 and VerifyEncodedValue accepts both, so the invariant
            // "whatever the gate accepts, every decoder behind it handles" was
            // broken here exactly as dexllm#57 broke it in the slicer's decoder.
            //
            // ReadIntLE rather than `p += nbytes` (which is what 0x1a did on its
            // own): it is the `end`-bounded advance every other payload read in
            // this file uses. Forced by the merge rather than chosen — the three
            // share one body — and strictly safer, since the unbounded form
            // could form a pointer past `end` on input this decoder does not
            // itself validate.
            (void)ReadIntLE(p, end, nbytes);
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
            // An unknown type code costs a missing RENDER; it must not cost a
            // DESYNC. `nbytes` is the (arg+1) width of every fixed-payload
            // encoded_value, so advancing by it keeps the cursor on a value
            // boundary for anything the gate might accept in future — the same
            // structural defence `ScanEncodedValueStrings` (dexkit_ext.cpp), the
            // THIRD encoded_value decoder in this repo, already has, and the
            // reason that one never carried this bug while this one did.
            // Unreachable today: `VerifyEncodedValue` rejects every code outside
            // the 18 the switch now covers, and `static_values_off` is verified.
            // Defence in depth for the NEXT code, not a fix for a live path.
            (void)ReadIntLE(p, end, nbytes);
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
    const U1* data_end = data + (1u << 20);  // generous cap per class
    if (auto* img = item.GetImage()) {       // clamp to the real mmap end
        const U1* mmap_end =
            reinterpret_cast<const U1*>(img->data()) + img->len();
        if (mmap_end < data_end) data_end = mmap_end;
    }

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
    if (auto* img = item.GetImage()) {       // clamp to the real mmap end
        const U1* mmap_end =
            reinterpret_cast<const U1*>(img->data()) + img->len();
        if (mmap_end < sv_end) sv_end = mmap_end;
    }
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


// ─── dexllm#67 — call-site reading (invoke-custom's operand) ─────────────
//
// Read WITHOUT touching the vendored slicer. `Reader` exposes no call-site
// accessor, and the issue assumed one had to be added; it does not, because
// the section is a `u4` array found through the map and this file already
// reads raw sections that way (`BuildProto`'s type_list, the static_values
// walk). One fewer entry for the pile dexllm#65 records as uncataloguable.
//
// EVERYTHING READ HERE IS UNVERIFIED. `VerifyDex` bounds the call_site_id
// section's EXTENT (dexllm#57's `CheckMap`) and nothing else — ART's
// `CheckInterCallSiteIdItem` is not ported — so `data_off`, the element type
// codes and every index inside are attacker-controlled. Each is bounded here,
// which is the reader tier the safety contract permits (dexllm#66's
// precedent); a failure reports `ok == false` rather than guessing.
constexpr uint16_t kMapCallSiteIdItem = 0x0007;

// method_handle_type codes (dex spec §method_handle_item). 0x00-0x03 name a
// FIELD, 0x04 and up name a METHOD.
constexpr uint16_t kMhFirstMethodKind = 0x04;
constexpr uint16_t kMhInvokeConstructor = 0x06;

// The mapping's bounds for one logical dex, as a SIZE so an offset is bounded
// before a pointer is formed from it. Upper end is the real mmap end, which is
// the same clamp `BuildProto` and the static_values walk already use.
struct ImageSpan {
    const U1* base = nullptr;
    size_t avail = 0;
    explicit operator bool() const { return base != nullptr; }
};

ImageSpan SpanOf(const dexkit::DexItem& item) {
    dexkit::MemMap* img = item.GetImage();
    if (img == nullptr || !img->ok()) return {};
    // The base every offset in this dex resolves against — the slicer's own
    // `image_`. NOT `dataPtr<U1>(0)`: its guard is
    // `SLICER_CHECK_GE(offset, header_->data_off && …)`, which rejects offset 0
    // outright.
    //
    // `Header()` alone is WRONG for a v41 CONTAINER slice, and the slicer proves
    // it: `Reader`'s ctor sets `header_ = ptr<Header>(0)` (the SLICE) and only
    // then `ValidateHeader` does `image_ -= header_->ContainerOff()` — so the
    // header address is slice-relative while every offset is container-relative.
    // On AOSP's own `multidex-container.dex` the second slice sits at +564 with
    // `map_off` 1332 in a 1468-byte container, so a slice-based span rejects its
    // own map; a container geometry where the sum lands back in range would read
    // ANOTHER slice's bytes and could fabricate a bootstrap chain from them.
    // (Found by a correctness reviewer, with that measurement.)
    const dex::Header* hdr = item.GetReader().Header();
    if (hdr == nullptr) return {};
    const U1* base = reinterpret_cast<const U1*>(hdr) - hdr->ContainerOff();
    const U1* img_end = reinterpret_cast<const U1*>(img->data()) + img->len();
    if (base == nullptr || base >= img_end) return {};
    return {base, static_cast<size_t>(img_end - base)};
}

// (offset, count) of one map section, or nullopt when the map does not carry
// it — which is the ordinary case: a dex with no invoke-custom has no
// call_site_id section at all.
std::optional<std::pair<uint32_t, uint32_t>>
FindMapSection(const dexkit::DexItem& item, uint16_t want_type) {
    const dex::Header* hdr = item.GetReader().Header();
    ImageSpan span = SpanOf(item);
    if (hdr == nullptr || !span) return std::nullopt;
    if (hdr->map_off >= span.avail ||
        span.avail - hdr->map_off < sizeof(uint32_t)) {
        return std::nullopt;
    }
    const U1* mp = span.base + hdr->map_off;
    uint32_t nitems;
    std::memcpy(&nitems, mp, sizeof(nitems));
    const size_t room = span.avail - hdr->map_off - sizeof(uint32_t);
    if (nitems > room / sizeof(dex::MapItem)) return std::nullopt;
    for (uint32_t i = 0; i < nitems; ++i) {
        dex::MapItem mi;
        std::memcpy(&mi, mp + sizeof(uint32_t) + i * sizeof(dex::MapItem),
                    sizeof(mi));
        if (mi.type == want_type) return std::make_pair(mi.offset, mi.size);
    }
    return std::nullopt;
}

// uleb128, bounded. A truncated stream stops at `end` and yields what it read,
// which the caller then fails on (the element count will not be satisfiable).
uint32_t ReadULeb128(const U1*& p, const U1* end) {
    uint32_t result = 0;
    for (unsigned shift = 0; shift < 32 && p < end; shift += 7) {
        U1 b = *p++;
        result |= static_cast<uint32_t>(b & 0x7F) << shift;
        if ((b & 0x80) == 0) break;
    }
    return result;
}

// Sign-extend the low `nbytes` of a little-endian payload, which is what an
// encoded BYTE/SHORT/INT/LONG is (CHAR is the one unsigned member and its
// caller masks instead).
int64_t SignExtend(uint64_t v, size_t nbytes) {
    if (nbytes == 0 || nbytes >= 8) return static_cast<int64_t>(v);
    const unsigned shift = static_cast<unsigned>(64 - 8 * nbytes);
    return static_cast<int64_t>(v << shift) >> shift;  // arithmetic, C++20
}

// A float/double payload is "zero-extended to the RIGHT" (dex spec): the stored
// bytes are the MOST significant ones and the omitted low-order bytes are the
// zeros. ART reads them the same way (`EncodedArrayValueIterator` ->
// `ReadUnsignedInt(..., fill_on_right = true)`), so a 2-byte `80 3F` is
// 0x3F800000 = 1.0f and NOT the 0x00003F80 denormal a left-justified read gives.
//
// KNOWN DIVERGENCE, deliberate: `DecodeEncodedValueText` in this same file
// left-justifies, so a short-encoded static float initializer renders as a
// denormal (corpus-manifest — `FloatingActionButtonImpl.SHOW_SCALE = 1f` reads
// `2.27795078e-41f`). That is a pre-existing defect of its own with its own
// blast radius (382 initializers across the corpus) and is NOT fixed here; this
// decoder is written correctly rather than bug-compatibly.
double DecodeEncodedFloat(uint64_t raw, size_t nbytes) {
    uint32_t bits = nbytes >= 4
                        ? static_cast<uint32_t>(raw)
                        : static_cast<uint32_t>(raw << (8 * (4 - nbytes)));
    float f;
    std::memcpy(&f, &bits, sizeof(f));
    return static_cast<double>(f);
}

double DecodeEncodedDouble(uint64_t raw, size_t nbytes) {
    uint64_t bits = nbytes >= 8 ? raw : (raw << (8 * (8 - nbytes)));
    double d;
    std::memcpy(&d, &bits, sizeof(d));
    return d;
}

// One `method_handle_item`, resolved to (owner, member, signature) + its kind.
// The section's EXTENT is verifier-bounded (dexllm#57's `CheckMap`); the INDEX
// inside it is not, so it is bounded here, and the member index is bounded by
// `Get*RefTriple` itself.
bool ResolveMethodHandle(DexItemCodeSource& src, const dexkit::DexItem& item,
                         uint16_t dex_id, uint32_t mh_idx,
                         dad::IDexCodeSource::CallSiteArg& out) {
    const auto handles = item.GetReader().MethodHandles();
    if (mh_idx >= handles.size()) return false;
    const dex::MethodHandle& mh = handles[mh_idx];
    const auto triple =
        mh.method_handle_type >= kMhFirstMethodKind
            ? src.GetMethodRefTriple(dex_id, mh.field_or_method_id)
            : src.GetFieldRefTriple(dex_id, mh.field_or_method_id);
    if (triple[0].empty() || triple[1].empty()) return false;
    out.kind = dad::IDexCodeSource::CallSiteArg::Kind::Handle;
    out.ival = mh.method_handle_type;
    out.text = std::string(triple[0]);
    out.member = std::string(triple[1]);
    out.sig = std::string(triple[2]);
    return true;
}

// One encoded_value of a call_site's array, as a TYPED value.
//
// Returns false for a type code that has no faithful Java literal, which makes
// the whole call site unresolved. `p` is advanced past the payload EITHER WAY,
// so the parse cannot desync — the dexllm#63 property, and the reason this
// decoder belongs to the `ScanEncodedValueStrings` family rather than the
// case-per-type one (it implements the codes a call site may legally carry,
// not all 18).
bool ParseCallSiteArg(const U1*& p, const U1* end,
                      DexItemCodeSource& src, const dexkit::DexItem& item,
                      uint16_t dex_id,
                      dad::IDexCodeSource::CallSiteArg& out) {
    using Kind = dad::IDexCodeSource::CallSiteArg::Kind;
    if (p >= end) return false;
    const U1 header = *p++;
    const size_t nbytes = static_cast<size_t>((header >> 5) & 0x07) + 1;
    switch (header & 0x1F) {
        case 0x03: {  // CHAR — the ONE unsigned member: zero-extended, never
                      // sign-extended (ART reads it with `ReadUnsignedInt`).
                      // Masking a sign-extended value cannot undo the damage —
                      // a 1-byte 0x80 becomes 0xFF80 = 65408 instead of 128,
                      // which d8 emits for any char in 128..255.
            out.kind = Kind::Int;
            out.ival = static_cast<int64_t>(ReadIntLE(p, end, nbytes) & 0xFFFF);
            return true;
        }
        case 0x00:   // BYTE
        case 0x02:   // SHORT
        case 0x04: { // INT — signed
            out.kind = Kind::Int;
            out.ival = SignExtend(ReadIntLE(p, end, nbytes), nbytes);
            return true;
        }
        case 0x06: {  // LONG
            out.kind = Kind::Long;
            out.ival = SignExtend(ReadIntLE(p, end, nbytes), nbytes);
            return true;
        }
        case 0x10: {  // FLOAT — zero-extended to the RIGHT, like every other
            out.kind = Kind::Float;  // encoded float in this file.
            out.dval = DecodeEncodedFloat(ReadIntLE(p, end, nbytes), nbytes);
            return true;
        }
        case 0x11: {  // DOUBLE
            out.kind = Kind::Double;
            out.dval = DecodeEncodedDouble(ReadIntLE(p, end, nbytes), nbytes);
            return true;
        }
        case 0x17: {  // STRING
            uint64_t idx = ReadIntLE(p, end, nbytes);
            out.kind = Kind::String;
            out.text = std::string(src.GetString(dex_id, static_cast<uint32_t>(idx)));
            return true;
        }
        case 0x18: {  // TYPE — a class literal
            uint64_t idx = ReadIntLE(p, end, nbytes);
            out.kind = Kind::Class;
            out.text = std::string(src.GetTypeName(dex_id, static_cast<uint32_t>(idx)));
            return !out.text.empty();
        }
        case 0x15: {  // METHOD_TYPE — a proto index (dexllm#57 named the code)
            uint64_t idx = ReadIntLE(p, end, nbytes);
            out.kind = Kind::Proto;
            out.text = std::string(src.GetProto(dex_id, static_cast<uint32_t>(idx)));
            return !out.text.empty();
        }
        case 0x16: {  // METHOD_HANDLE — an index into the method_handle section
            uint64_t idx = ReadIntLE(p, end, nbytes);
            return ResolveMethodHandle(src, item, dex_id,
                                       static_cast<uint32_t>(idx), out);
        }
        case 0x1E:   // NULL — not a legal bootstrap argument (the dex spec
                     // lists the primitive, String, Class, MethodType and
                     // MethodHandle forms and nothing else), and it carries no
                     // payload, so there is nothing to skip.
            return false;
        case 0x1F:   // BOOLEAN — the value is the arg nibble, no payload
            out.kind = Kind::Bool;
            out.ival = (header >> 5) & 0x01;
            return true;
        default:
            // ENUM / FIELD / METHOD / ARRAY / ANNOTATION: not a legal call-site
            // argument, and none has a faithful Java literal. Advance anyway so
            // this decoder cannot desync (the ARRAY/ANNOTATION payload is not
            // `arg+1` bytes, but the caller abandons the whole call site here,
            // so nothing reads on).
            (void)ReadIntLE(p, end, nbytes);
            return false;
    }
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
            static_cast<uint16_t>(dex_item->GetDexId()), static_cast<uint32_t>(i)};
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
        out.push_back({static_cast<uint16_t>(dex_item->GetDexId()), midx});
    }
    return out;
}

uint32_t DexItemCodeSource::GetMethodAccessFlags(uint16_t dex_id,
                                                 uint32_t midx) {
    DexItem* item = SafeGetDexItem(core_, dex_id);
    if (!item) return 0;
    // DAD-aligned decompilation needs the dex's own bits (declared_synchronized
    // intact) so the Writer can emit that modifier like androguard does.
    // GetMethodAccessFlags is exactly that — the Java-Modifier-compat rewrite
    // upstream used to apply here was removed (see dex_item.h).
    const auto& flags = item->GetMethodAccessFlags();
    return midx < flags.size() ? flags[midx] : 0;
}

std::string_view DexItemCodeSource::GetMethodClassName(uint16_t dex_id,
                                                       uint32_t midx) {
    DexItem* item = SafeGetDexItem(core_, dex_id);
    if (!item) return {};
    const auto& reader = item->GetReader();
    const auto& type_names = item->GetTypeNames();
    const auto method_ids = reader.MethodIds();
    if (midx >= method_ids.size()) return {};  // external caller index — guarded
    return type_names[method_ids[midx].class_idx];
}

std::string_view DexItemCodeSource::GetMethodName(uint16_t dex_id,
                                                  uint32_t midx) {
    DexItem* item = SafeGetDexItem(core_, dex_id);
    if (!item) return {};
    const auto& reader = item->GetReader();
    const auto& strings = item->GetStrings();
    const auto method_ids = reader.MethodIds();
    if (midx >= method_ids.size()) return {};  // external caller index — guarded
    return strings[method_ids[midx].name_idx];
}

std::string DexItemCodeSource::GetMethodProto(uint16_t dex_id,
                                              uint32_t midx) {
    DexItem* item = SafeGetDexItem(core_, dex_id);
    if (!item) return {};
    const auto& reader = item->GetReader();
    const auto method_ids = reader.MethodIds();
    if (midx >= method_ids.size()) return {};
    const auto proto_ids = reader.ProtoIds();
    uint32_t pidx = method_ids[midx].proto_idx;
    if (pidx >= proto_ids.size()) return {};
    return BuildProto(*item, proto_ids[pidx]);
}

// dexllm#60: one proto by PROTO index. GetMethodProto above takes a METHOD index
// and reaches the proto through it; invoke-polymorphic's second operand names a
// proto directly. Routed through the same pointer-stable cache GetMethodRefTriple
// uses, so the result outlives any snapshot and needs no owned copy — and the
// cache already bounds `proto_idx`, which matters here because VerifyInsns
// deliberately does NOT bound the proto half of a polymorphic operand (dexllm#61).
std::string_view DexItemCodeSource::GetProto(uint16_t dex_id, uint32_t pidx) {
    return GetProtoCached(dex_id, pidx);
}

const dex::Code* DexItemCodeSource::GetMethodCode(uint16_t dex_id,
                                                  uint32_t midx) {
    DexItem* item = SafeGetDexItem(core_, dex_id);
    if (!item) return nullptr;
    return item->GetMethodCode(midx);
}

std::pair<const uint8_t*, const uint8_t*>
DexItemCodeSource::GetDexImageRange(uint16_t dex_id) {
    DexItem* item = SafeGetDexItem(core_, dex_id);
    if (!item) return {nullptr, nullptr};
    dexkit::MemMap* img = item->GetImage();
    if (!img || !img->ok()) return {nullptr, nullptr};
    const uint8_t* base = reinterpret_cast<const uint8_t*>(img->data());
    return {base, base + img->len()};
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
    const auto proto_ids = item->GetReader().ProtoIds();
    if (proto_idx >= proto_ids.size()) return {};
    std::string proto = BuildProto(*item, proto_ids[proto_idx]);
    std::lock_guard lock(proto_cache_mutex_);
    auto [it, _] = proto_cache_.emplace(key, std::move(proto));
    return it->second;
}

// dexllm#67 — resolve `call_site_ids[idx]`. See the helper block above for why
// nothing here trusts the verifier beyond the section's extent.
dad::IDexCodeSource::CallSiteInfo
DexItemCodeSource::GetCallSite(uint16_t dex_id, uint32_t call_site_idx) {
    // Every failure path returns a PRISTINE result, never the half-filled one:
    // the bootstrap is resolved before the name is checked, so returning `out`
    // would hand a consumer a real bootstrap beside an empty name and an empty
    // call type — which renders as a plausible, and entirely fabricated,
    // `bsm(lookup(), "", methodType(Void.TYPE))`. `ok == false` must mean
    // nothing was learned.
    CallSiteInfo out;
    DexItem* item = SafeGetDexItem(core_, dex_id);
    if (item == nullptr) return {};
    ImageSpan span = SpanOf(*item);
    if (!span) return {};

    auto section = FindMapSection(*item, kMapCallSiteIdItem);
    if (!section) return {};
    const uint32_t cs_off = section->first;
    const uint32_t cs_size = section->second;
    if (call_site_idx >= cs_size) return {};
    if (cs_off >= span.avail ||
        (span.avail - cs_off) / sizeof(uint32_t) < cs_size) {
        return {};
    }
    uint32_t data_off;
    std::memcpy(&data_off,
                span.base + cs_off + call_site_idx * sizeof(uint32_t),
                sizeof(data_off));
    if (data_off == 0 || data_off >= span.avail) return {};

    // encoded_array_item: uleb128 size, then `size` encoded_values.
    const U1* p = span.base + data_off;
    const U1* end = span.base + span.avail;
    const uint32_t count = ReadULeb128(p, end);
    // ART's CheckInterCallSiteIdItem requires the three fixed elements; fewer
    // is a malformed call site, and there is nothing to model without them.
    if (count < 3) return {};

    CallSiteArg e0;
    if (!ParseCallSiteArg(p, end, *this, *item, dex_id, e0)) return {};
    if (e0.kind != CallSiteArg::Kind::Handle) return {};
    out.bootstrap = {e0.text, e0.member, e0.sig};

    CallSiteArg e1;
    if (!ParseCallSiteArg(p, end, *this, *item, dex_id, e1)) return {};
    if (e1.kind != CallSiteArg::Kind::String) return {};
    out.name = e1.text;

    CallSiteArg e2;
    if (!ParseCallSiteArg(p, end, *this, *item, dex_id, e2)) return {};
    if (e2.kind != CallSiteArg::Kind::Proto) return {};
    out.proto = e2.text;

    // Bound the reserve by what could physically remain: `count` is a uleb128
    // read straight out of the image, so a crafted one can claim 2^32-1
    // elements that the parse below would fail on only after the allocation.
    const size_t remaining = static_cast<size_t>(end - p);
    out.args.reserve(std::min<size_t>(count - 3, remaining));
    for (uint32_t i = 3; i < count; ++i) {
        CallSiteArg a;
        if (!ParseCallSiteArg(p, end, *this, *item, dex_id, a)) return {};
        out.args.push_back(std::move(a));
    }
    out.ok = true;
    return out;
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
    if (fidx >= field_ids.size()) return {{}};  // external caller index — guarded
    const auto& f = field_ids[fidx];
    return {type_names[f.class_idx], strings[f.name_idx],
            type_names[f.type_idx]};
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
            uint32_t n = type_list->size;
            if (auto* img = item->GetImage()) {  // clamp size to the mmap
                const auto* img_end =
                    reinterpret_cast<const uint8_t*>(img->data()) + img->len();
                const auto* list0 =
                    reinterpret_cast<const uint8_t*>(type_list->list);
                size_t maxn = list0 <= img_end
                                  ? static_cast<size_t>(img_end - list0) /
                                        sizeof(type_list->list[0])
                                  : 0;
                if (n > maxn) n = static_cast<uint32_t>(maxn);
            }
            info.interfaces.reserve(n);
            for (uint32_t i = 0; i < n; ++i) {
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

// Sound (partial) dex-hierarchy assignability — see IDexCodeSource::IsAssignable.
// A bounded BFS up `sub`'s superclass + transitively-implemented interfaces;
// returns true on the first match, false when `sub`'s chain is exhausted or exits
// the loaded dex (a framework ancestor we cannot see). Never a false positive.
bool DexItemCodeSource::IsAssignable(std::string_view sub,
                                     std::string_view super) {
    if (sub == super) return true;
    if (sub.empty() || super.empty()) return false;
    const bool sub_ref = sub.front() == 'L' || sub.front() == '[';
    if (!sub_ref) return false;                         // primitives: exact only
    if (super == "Ljava/lang/Object;") return true;     // any reference <: Object
    if (sub.front() == '[') return false;               // arrays: no covariance
    std::unordered_set<std::string> seen;
    std::vector<std::string> stack{std::string(sub)};
    while (!stack.empty()) {
        std::string cur = std::move(stack.back());
        stack.pop_back();
        if (!seen.insert(cur).second) continue;
        auto info = GetClassInfo(cur);
        if (!info) continue;      // not in the loaded dex — cannot traverse
        if (!info->superclass.empty()) {
            if (info->superclass == super) return true;
            stack.emplace_back(info->superclass);
        }
        for (auto iface : info->interfaces) {
            if (iface == super) return true;
            stack.emplace_back(iface);
        }
    }
    return false;
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
    if (fidx >= field_ids.size()) return info;  // external caller index — guarded
    const auto& f = field_ids[fidx];
    info.name = strings[f.name_idx];
    info.type = type_names[f.type_idx];
    const auto& access = item->GetFieldAccessFlags();
    if (fidx < access.size()) info.access_flags = access[fidx];
    return info;
}

}  // namespace dexkit::ext
