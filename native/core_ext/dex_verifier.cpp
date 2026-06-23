// dex_verifier.cpp — see dex_verifier.h for THE safety contract (read that first).
//
// STATUS — all four ART DexFileVerifier phases implemented:
//   CheckHeader        — IMPLEMENTED  (ART :617)
//   CheckMap           — IMPLEMENTED  (ART :738)
//   CheckIntraSection  — IMPLEMENTED  (ART :2450) — ids/string_data/type_list/
//                        class_def/class_data/code_item (VerifyCodeItem == ART
//                        CheckIntraCodeItem :1726) + VerifyInsns (see below)
//   CheckInterSection  — IMPLEMENTED  (ART :3477) — id ordering/uniqueness +
//                        descriptor syntax + class_def semantics
// VerifyInsns is the ONE deliberate non-port: instruction-operand bounds anchored
// to the Dalvik bytecode spec via slicer VerifyFlags, NOT ART dex_file_verifier
// (which omits per-insn checks — those are the runtime method_verifier). Full
// rationale + scope line + out-of-scope list are in dex_verifier.h.
//
// ART primitive → local helper map:
//   CheckListSize           :543  -> CheckListSize
//   CheckValidOffsetAndSize :583  -> CheckValidOffsetAndSize
//   CheckIndex                    -> CheckIndex
//   CheckSizeLimit                -> CheckSizeLimit
//   DECODE_(UN)SIGNED_CHECKED     -> ReadUleb / ReadSleb

#include "dex_verifier.h"

#include <cstring>
#include <exception>
#include <vector>

#include "slicer/dex_bytecode.h"  // VerifyInsns: decode + VerifyFlags/IndexType
#include "slicer/dex_format.h"

namespace dexkit::ext {

namespace {

using dex::u1;
using dex::u2;
using dex::u4;
using dex::s4;

// ── dex map_item type codes (not in slicer/dex_format.h) ──────────────────────
enum MapType : u2 {
    kHeaderItem               = 0x0000,
    kStringIdItem             = 0x0001,
    kTypeIdItem               = 0x0002,
    kProtoIdItem              = 0x0003,
    kFieldIdItem              = 0x0004,
    kMethodIdItem             = 0x0005,
    kClassDefItem             = 0x0006,
    kCallSiteIdItem           = 0x0007,
    kMethodHandleItem         = 0x0008,
    kMapList                  = 0x1000,
    kTypeListItem             = 0x1001,
    kAnnotationSetRefList     = 0x1002,
    kAnnotationSetItem        = 0x1003,
    kClassDataItem            = 0x2000,
    kCodeItem                 = 0x2001,
    kStringDataItem           = 0x2002,
    kDebugInfoItem            = 0x2003,
    kAnnotationItem           = 0x2004,
    kEncodedArrayItem         = 0x2005,
    kAnnotationsDirectoryItem = 0x2006,
    kHiddenapiClassData       = 0xF000,
};

// ART MapTypeToBitMask: a unique bit per known map type, 0 for unknown.
u4 MapTypeToBitMask(u2 type) {
    switch (type) {
        case kHeaderItem:               return 1u << 0;
        case kStringIdItem:             return 1u << 1;
        case kTypeIdItem:               return 1u << 2;
        case kProtoIdItem:              return 1u << 3;
        case kFieldIdItem:              return 1u << 4;
        case kMethodIdItem:             return 1u << 5;
        case kClassDefItem:             return 1u << 6;
        case kCallSiteIdItem:           return 1u << 7;
        case kMethodHandleItem:         return 1u << 8;
        case kMapList:                  return 1u << 9;
        case kTypeListItem:             return 1u << 10;
        case kAnnotationSetRefList:     return 1u << 11;
        case kAnnotationSetItem:        return 1u << 12;
        case kClassDataItem:            return 1u << 13;
        case kCodeItem:                 return 1u << 14;
        case kStringDataItem:           return 1u << 15;
        case kDebugInfoItem:            return 1u << 16;
        case kAnnotationItem:           return 1u << 17;
        case kEncodedArrayItem:         return 1u << 18;
        case kAnnotationsDirectoryItem: return 1u << 19;
        case kHiddenapiClassData:       return 1u << 20;
        default:                        return 0;
    }
}

// ART IsDataSectionType: index sections (header, map_list, the *_id tables) are
// not in the data section; everything else (lists, class_data, code, strings,
// debug, annotations, encoded_array, hiddenapi) is.
bool IsDataSectionType(u2 type) {
    switch (type) {
        case kHeaderItem:
        case kStringIdItem:
        case kTypeIdItem:
        case kProtoIdItem:
        case kFieldIdItem:
        case kMethodIdItem:
        case kClassDefItem:
        case kCallSiteIdItem:
        case kMethodHandleItem:
        case kMapList:
            return false;
        default:
            return true;
    }
}

bool IsAligned(u4 off, size_t align) {
    return align == 0 || (off & (align - 1)) == 0;
}

// ─── MUTF-8 → UTF-16 code-point comparison ────────────────────────────────────
// Lifted VERBATIM from AOSP ART art/libdexfile/dex/utf-inl.h (Apache-2.0, same
// license as the vendored slicer). dex string_ids are sorted by UTF-16
// code-point value, which differs from raw MUTF-8 byte order for supplementary
// (surrogate-pair) characters — so a naive memcmp would false-reject valid
// dexes. Using ART's exact comparator makes our ordering verdict byte-identical
// to ART's. dex_file_verifier.cc:2720 uses this for CheckInterStringIdItem.
inline uint16_t GetTrailingUtf16Char(uint32_t maybe_pair) {
    return static_cast<uint16_t>(maybe_pair >> 16);
}
inline uint16_t GetLeadingUtf16Char(uint32_t maybe_pair) {
    return static_cast<uint16_t>(maybe_pair & 0x0000FFFF);
}
inline uint32_t GetUtf16FromUtf8(const char** utf8_data_in) {
    const uint8_t one = *(*utf8_data_in)++;
    if ((one & 0x80) == 0) return one;                                  // 1-byte
    const uint8_t two = *(*utf8_data_in)++;
    if ((one & 0x20) == 0) return ((one & 0x1f) << 6) | (two & 0x3f);   // 2-byte
    const uint8_t three = *(*utf8_data_in)++;
    if ((one & 0x10) == 0) {                                            // 3-byte
        return ((one & 0x0f) << 12) | ((two & 0x3f) << 6) | (three & 0x3f);
    }
    const uint8_t four = *(*utf8_data_in)++;                            // 4-byte → surrogate pair
    const uint32_t code_point = ((one & 0x0f) << 18) | ((two & 0x3f) << 12) |
                                ((three & 0x3f) << 6) | (four & 0x3f);
    uint32_t surrogate_pair = 0;
    surrogate_pair |= ((code_point >> 10) + 0xd7c0) & 0xffff;
    surrogate_pair |= ((code_point & 0x03ff) + 0xdc00) << 16;
    return surrogate_pair;
}
inline int CompareModifiedUtf8ToModifiedUtf8AsUtf16CodePointValues(const char* utf8_1,
                                                                   const char* utf8_2) {
    uint32_t c1, c2;
    do {
        c1 = static_cast<uint8_t>(*utf8_1);
        c2 = static_cast<uint8_t>(*utf8_2);
        if (c1 == 0) return (c2 == 0) ? 0 : -1;
        if (c2 == 0) return 1;
        c1 = GetUtf16FromUtf8(&utf8_1);
        c2 = GetUtf16FromUtf8(&utf8_2);
    } while (c1 == c2);
    const uint32_t leading = GetLeadingUtf16Char(c1) - GetLeadingUtf16Char(c2);
    if (leading != 0) return static_cast<int>(leading);
    return GetTrailingUtf16Char(c1) - GetTrailingUtf16Char(c2);
}

// ── descriptor / member-name validators (ART descriptors_names.cc) ────────────
// Pure leaves, ported readably with anchors (NOT verbatim opaque lifts). Used by
// CheckInterSection's field/method/class_def descriptor + name checks. They walk
// a NUL-terminated buffer safely because every string they receive was already
// MUTF-8 + length + NUL validated by VerifyStringData (CheckIntraSection).

// ART descriptors_names.cc:234 — valid-low-ascii bit vector for member names.
constexpr uint32_t kMemberValidLowAscii[4] = {
    0x00000000,  // 00..1f control: none valid
    0x03ff2011,  // 20..3f: ' ', '0'..'9', '$', '-'
    0x87fffffe,  // 40..5f: 'A'..'Z', '_'
    0x07fffffe,  // 60..7f: 'a'..'z'
};

// ART descriptors_names.cc:244 — multibyte path of IsValidPartOfMemberNameUtf8.
bool IsValidPartOfMemberNameUtf8Slow(const char** p) {
    const uint32_t pair = GetUtf16FromUtf8(p);
    const uint16_t leading = GetLeadingUtf16Char(pair);
    if (GetTrailingUtf16Char(pair) != 0) return true;  // 4-byte → supplementary, valid
    switch (leading >> 8) {
        case 0x00: return leading >= 0x00a0;  // exclude C1 control chars
        case 0xd8: case 0xd9: case 0xda: case 0xdb: {
            const uint32_t pair2 = GetUtf16FromUtf8(p);
            const uint16_t trailing = GetLeadingUtf16Char(pair2);
            return GetTrailingUtf16Char(pair2) == 0 && 0xdc00 <= trailing && trailing <= 0xdfff;
        }
        case 0xdc: case 0xdd: case 0xde: case 0xdf: return false;  // lone trailing surrogate
        case 0x20: case 0xff:
            switch (leading & 0xfff8) {
                case 0x2008: return leading <= 0x200a;
                case 0x2028: return leading == 0x202f;
                case 0xfff0: case 0xfff8: return false;
            }
            return true;
        default: return true;
    }
}

// ART descriptors_names.cc:323 IsValidPartOfMemberNameUtf8.
bool IsValidPartOfMemberNameUtf8(const char** p) {
    uint8_t c = static_cast<uint8_t>(**p);
    if (c <= 0x7f) {
        ++(*p);
        return (kMemberValidLowAscii[c >> 5] & (1u << (c & 0x1f))) != 0;
    }
    return IsValidPartOfMemberNameUtf8Slow(p);
}

// ART descriptors_names.cc:338 IsValidMemberName.
bool IsValidMemberName(const char* s) {
    bool angle = false;
    if (*s == '\0') return false;
    if (*s == '<') { angle = true; ++s; }
    for (;;) {
        if (*s == '\0') return !angle;
        if (*s == '>') return angle && s[1] == '\0';
        if (!IsValidPartOfMemberNameUtf8(&s)) return false;
    }
}

// ART descriptors_names.cc:367/477 IsValidClassName<kDescriptor,'/'> specialised
// to the JNI descriptor form dex type descriptors always take ('/' separator).
bool IsValidDescriptor(const char* s) {
    int array = 0;
    while (*s == '[') { ++array; ++s; }
    if (array > 255) return false;  // arrays: max 255 dimensions
    switch (*s++) {
        case 'B': case 'C': case 'D': case 'F': case 'I':
        case 'J': case 'S': case 'Z': return *s == '\0';
        case 'V': return array == 0 && *s == '\0';  // void: no arrays
        case 'L': break;                            // class name follows
        default: return false;
    }
    bool sep_or_first = true;  // at start, or just after a '/'
    for (;;) {
        switch (static_cast<uint8_t>(*s)) {
            case '\0': return false;                    // premature end of descriptor
            case ';': return !sep_or_first && s[1] == '\0';
            case '/':
                if (sep_or_first) return false;         // leading or doubled separator
                sep_or_first = true; ++s; break;
            case '.': return false;                     // wrong separator for JNI form
            default:
                if (!IsValidPartOfMemberNameUtf8(&s)) return false;
                sep_or_first = false; break;
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// DexVerifier — mirrors ART's DexFileVerifier class (one phase per method).
// ─────────────────────────────────────────────────────────────────────────────
class DexVerifier {
public:
    DexVerifier(const u1* data, size_t size, bool check_insns = true)
        : begin_(data), size_(size), check_insns_(check_insns) {}

    bool Verify() {
        if (begin_ == nullptr || size_ < dex::Header::kV40Size) {
            return Fail("Empty or truncated file");
        }
        header_ = reinterpret_cast<const dex::Header*>(begin_);
        return CheckHeader() && CheckMap() && CheckIntraSection() &&
               CheckInterSection();
    }

    const std::string& reason() const { return reason_; }

private:
    // ── helpers ───────────────────────────────────────────────────────────────
    bool Fail(std::string m) {
        if (reason_.empty()) reason_ = std::move(m);
        return false;
    }
    const u1* EndOfFile() const { return begin_ + size_; }
    const u1* OffsetToPtr(u4 off) const { return begin_ + off; }

    // ART CheckListSize (:543) — `count` elements of `elem` bytes fit from
    // `start` to end-of-file without overflow.
    bool CheckListSize(const void* start, size_t count, size_t elem,
                       const char* label) {
        const u1* p = reinterpret_cast<const u1*>(start);
        if (p < begin_ || p > EndOfFile()) {
            return Fail(std::string("List out of file: ") + label);
        }
        size_t off = static_cast<size_t>(p - begin_);
        size_t max_elements = (size_ - off) / elem;
        if (max_elements < count) {
            return Fail(std::string("List too large: ") + label);
        }
        return true;
    }

    // ART CheckValidOffsetAndSize (:583) — overflow-safe section bound check.
    bool CheckValidOffsetAndSize(u4 offset, u4 size, size_t align,
                                 const char* label) {
        if (size == 0) {
            if (offset != 0) return Fail(std::string("Offset nonzero for empty ") + label);
            return true;
        }
        if (size_ <= offset) return Fail(std::string("Offset past file for ") + label);
        if (size_ - offset < size) return Fail(std::string("Section past file for ") + label);
        if (!IsAligned(offset, align)) return Fail(std::string("Misaligned offset for ") + label);
        return true;
    }

    // ART CheckSizeLimit — table count under a ceiling (type/proto ids < 65536).
    bool CheckSizeLimit(u4 size, u4 limit, const char* label) {
        if (size > limit) return Fail(std::string("Too many ") + label);
        return true;
    }

    // ART CheckIndex — idx < limit.
    bool CheckIndex(u4 idx, u4 limit, const char* label) {
        if (idx >= limit) return Fail(std::string("Bad index: ") + label);
        return true;
    }

    // Bounded uleb128 / sleb128 (ART DECODE_*_CHECKED_FROM).
    bool ReadUleb(const u1** pp, u4* out) {
        const u1* p = *pp;
        u4 result = 0;
        for (int i = 0; i < 5; ++i) {
            if (p >= EndOfFile()) return false;
            u1 b = *p++;
            result |= static_cast<u4>(b & 0x7f) << (7 * i);
            if ((b & 0x80) == 0) { *pp = p; *out = result; return true; }
        }
        return false;
    }
    bool ReadSleb(const u1** pp, s4* out) {
        const u1* p = *pp;
        s4 result = 0;
        int i = 0;
        u1 b;
        do {
            if (i >= 5 || p >= EndOfFile()) return false;
            b = *p++;
            result |= static_cast<s4>(b & 0x7f) << (7 * i);
            ++i;
        } while (b & 0x80);
        int shift = 7 * i;
        if (shift < 32 && (b & 0x40)) result |= -(static_cast<s4>(1) << shift);
        *pp = p; *out = result; return true;
    }

    // ── phases ────────────────────────────────────────────────────────────────
    bool CheckHeader();        // ART :617  (implemented)
    bool CheckMap();           // ART :738  (implemented)
    bool CheckIntraSection();  // ART :2450
    bool CheckInterSection();  // ART :3477

    // ── intra-section item validators (phase ③) ──────────────────────────────
    bool VerifyMutf8(const u1* p, u4 utf16_len);
    bool VerifyStringData(u4 off);
    bool VerifyTypeList(u4 off, const char* who);
    bool VerifyCodeItem(u4 off);
    bool VerifyInsns(const u2* insns, u4 insns_size, u2 registers_size);
    bool VerifyClassData(u4 off);
    bool VerifyEncodedArrayAt(u4 off);              // ART CheckEncodedArray :1225
    bool VerifyEncodedValue(const u1** pp, int depth);  // ART CheckEncodedValue :1049
    bool VerifyClassDefs();  // ART CheckInterClassDefItem :2935
    // ART FindFirstClassDataDefiner :3070 — class_idx of class_data's first
    // member (field, else method), or dex::kNoIndex if empty. `off` already
    // validated by VerifyClassData in CheckIntraSection.
    bool FindFirstClassDataDefiner(u4 off, u4* out);
    template <class T>
    const T* TableAt(u4 off, u4 i) const {
        return reinterpret_cast<const T*>(begin_ + off) + i;
    }
    // Pointer to the MUTF-8 content of string `idx` (past the uleb length).
    // Safe to call only after CheckIntraSection validated all string_data.
    const char* StringContent(u4 idx) const {
        const u1* p = begin_ + TableAt<dex::StringId>(header_->string_ids_off, idx)->string_data_off;
        while ((*p & 0x80) != 0) ++p;  // skip uleb continuation bytes
        ++p;                            // skip uleb final byte
        return reinterpret_cast<const char*>(p);
    }
    // Descriptor string of type `type_idx` (its type_id.descriptor_idx → string).
    // Safe after CheckIntraSection validated type_ids + string_data.
    const char* TypeDesc(u4 type_idx) const {
        return StringContent(TableAt<dex::TypeId>(header_->type_ids_off, type_idx)->descriptor_idx);
    }
    // ART VerifyTypeDescriptor — descriptor of `type_idx` is a valid descriptor
    // whose leading char satisfies `pred`. `type_idx` must already be in range.
    template <class Pred>
    bool VerifyTypeDescriptor(u4 type_idx, const char* err, Pred pred) {
        const char* d = TypeDesc(type_idx);
        if (!IsValidDescriptor(d) || !pred(d[0])) return Fail(err);
        return true;
    }
    const dex::TypeList* ProtoParams(u4 proto_idx) const {
        u4 off = TableAt<dex::ProtoId>(header_->proto_ids_off, proto_idx)->parameters_off;
        return off == 0 ? nullptr : reinterpret_cast<const dex::TypeList*>(begin_ + off);
    }

    const u1* begin_;
    size_t size_;
    bool check_insns_ = true;  // false = ART-structural-equivalent (skip VerifyInsns)
    const dex::Header* header_ = nullptr;
    std::string reason_;
};

bool DexVerifier::CheckHeader() {
    // magic + version
    if (std::memcmp(header_->magic, "dex\n", 4) != 0) return Fail("Bad file magic");
    u4 version = header_->GetVersion();
    if (version < dex::Header::kMinVersion || version > dex::Header::kMaxVersion) {
        return Fail("Unknown dex version");
    }

    const size_t header_size =
        (version >= dex::Header::kV41) ? dex::Header::kV41Size : dex::Header::kV40Size;
    const u4 file_size = header_->file_size;
    if (file_size < header_size) return Fail("Bad file size (too small)");
    if (file_size > size_) return Fail("Bad file size (past image)");
    if (header_->header_size != header_size) return Fail("Bad header size");
    if (header_->endian_tag != dex::kEndianConstant) return Fail("Unexpected endian_tag");
    // adler32: intentionally not verified (policy).

    // Every section offset/size inside the file (ART CheckHeader section block).
    // CheckValidOffsetAndSize validates each ID table's offset alignment + that
    // the offset is in-file, but its `size` argument is an element COUNT, so it
    // only proves `off + count <= file` BYTES. The tables are then indexed by
    // `i * sizeof(item)` (ClassDef is 32 bytes), so the BYTE SPAN must be bounded
    // separately with CheckListSize (overflow-safe via division) — otherwise a
    // crafted dex whose count fits as bytes but `count*sizeof` overruns the file
    // would OOB-read inside the verifier itself.
    return CheckValidOffsetAndSize(header_->link_off, header_->link_size, 0, "link") &&
           CheckValidOffsetAndSize(header_->map_off, sizeof(dex::MapList), 4, "map") &&
           CheckValidOffsetAndSize(header_->string_ids_off, header_->string_ids_size, 4, "string-ids") &&
           CheckListSize(OffsetToPtr(header_->string_ids_off), header_->string_ids_size, sizeof(dex::StringId), "string-ids span") &&
           CheckValidOffsetAndSize(header_->type_ids_off, header_->type_ids_size, 4, "type-ids") &&
           CheckListSize(OffsetToPtr(header_->type_ids_off), header_->type_ids_size, sizeof(dex::TypeId), "type-ids span") &&
           CheckSizeLimit(header_->type_ids_size, dex::kNoIndex - 1, "type-ids") &&
           CheckValidOffsetAndSize(header_->proto_ids_off, header_->proto_ids_size, 4, "proto-ids") &&
           CheckListSize(OffsetToPtr(header_->proto_ids_off), header_->proto_ids_size, sizeof(dex::ProtoId), "proto-ids span") &&
           CheckSizeLimit(header_->proto_ids_size, dex::kNoIndex - 1, "proto-ids") &&
           CheckValidOffsetAndSize(header_->field_ids_off, header_->field_ids_size, 4, "field-ids") &&
           CheckListSize(OffsetToPtr(header_->field_ids_off), header_->field_ids_size, sizeof(dex::FieldId), "field-ids span") &&
           CheckValidOffsetAndSize(header_->method_ids_off, header_->method_ids_size, 4, "method-ids") &&
           CheckListSize(OffsetToPtr(header_->method_ids_off), header_->method_ids_size, sizeof(dex::MethodId), "method-ids span") &&
           CheckValidOffsetAndSize(header_->class_defs_off, header_->class_defs_size, 4, "class-defs") &&
           CheckListSize(OffsetToPtr(header_->class_defs_off), header_->class_defs_size, sizeof(dex::ClassDef), "class-defs span") &&
           CheckValidOffsetAndSize(header_->data_off, header_->data_size, 0, "data");
}

bool DexVerifier::CheckMap() {
    const auto* map = reinterpret_cast<const dex::MapList*>(OffsetToPtr(header_->map_off));
    if (!CheckListSize(map, 1, sizeof(dex::MapList), "maplist content")) return false;

    const dex::MapItem* item = map->list;
    const u4 count = map->size;
    if (!CheckListSize(item, count, sizeof(dex::MapItem), "map size")) return false;

    u4 last_offset = 0;
    u4 used_bits = 0;
    for (u4 i = 0; i < count; ++i, ++item) {
        if (i != 0 && last_offset >= item->offset) return Fail("Out of order map item");
        if (item->offset >= size_) return Fail("Map item past end of file");
        if (IsDataSectionType(item->type)) {
            size_t align = (item->type == kClassDataItem || item->type == kStringDataItem ||
                            item->type == kDebugInfoItem || item->type == kAnnotationItem ||
                            item->type == kEncodedArrayItem) ? 1u : 4u;
            if (!IsAligned(item->offset, align)) return Fail("Misaligned map item");
        }
        u4 bit = MapTypeToBitMask(item->type);
        if (bit == 0) return Fail("Unknown map section type");
        if (used_bits & bit) return Fail("Duplicate map section");
        used_bits |= bit;
        last_offset = item->offset;
    }

    // Required sections present (ART CheckMap tail).
    auto require = [&](MapType t, u4 off, u4 sz, const char* name) {
        if ((used_bits & MapTypeToBitMask(t)) == 0 && (off != 0 || sz != 0)) {
            return Fail(std::string("Map missing ") + name);
        }
        return true;
    };
    if ((used_bits & MapTypeToBitMask(kHeaderItem)) == 0) return Fail("Map missing header");
    if ((used_bits & MapTypeToBitMask(kMapList)) == 0) return Fail("Map missing map_list");
    return require(kStringIdItem, header_->string_ids_off, header_->string_ids_size, "string_ids") &&
           require(kTypeIdItem, header_->type_ids_off, header_->type_ids_size, "type_ids") &&
           require(kProtoIdItem, header_->proto_ids_off, header_->proto_ids_size, "proto_ids") &&
           require(kFieldIdItem, header_->field_ids_off, header_->field_ids_size, "field_ids") &&
           require(kMethodIdItem, header_->method_ids_off, header_->method_ids_size, "method_ids") &&
           require(kClassDefItem, header_->class_defs_off, header_->class_defs_size, "class_defs");
}

// Modified UTF-8 validation (dex string_data): 1-byte 0x01–0x7F; 2-byte
// 0xC0–0xDF + continuation (overlong NUL 0xC0 0x80 legal); 3-byte 0xE0–0xEF +
// 2 continuations (surrogates legal); no 4-byte form. Each sequence is one
// UTF-16 code unit; count must equal utf16_len; NUL terminator within image.
bool DexVerifier::VerifyMutf8(const u1* p, u4 utf16_len) {
    const u1* end = EndOfFile();
    u4 units = 0;
    while (true) {
        if (p >= end) return Fail("string_data not NUL-terminated within image");
        u1 b = *p++;
        if (b == 0x00) break;
        if (b < 0x80) {
            // 1-byte
        } else if (b < 0xC0) {
            return Fail("string_data invalid MUTF-8 lead byte");
        } else if (b < 0xE0) {
            if (p >= end || (*p++ & 0xC0) != 0x80) return Fail("string_data bad MUTF-8 2-byte seq");
        } else if (b < 0xF0) {
            if (p >= end || (*p++ & 0xC0) != 0x80) return Fail("string_data bad MUTF-8 3-byte seq");
            if (p >= end || (*p++ & 0xC0) != 0x80) return Fail("string_data bad MUTF-8 3-byte seq");
        } else {
            return Fail("string_data invalid MUTF-8 lead byte");
        }
        ++units;
    }
    if (units != utf16_len) return Fail("string_data length mismatch");
    return true;
}

bool DexVerifier::VerifyStringData(u4 off) {
    const u1* p = OffsetToPtr(off);
    if (off == 0 || p < begin_ || p >= EndOfFile()) return Fail("string_data offset out of range");
    u4 utf16_len;
    if (!ReadUleb(&p, &utf16_len)) return Fail("string_data bad length uleb");
    return VerifyMutf8(p, utf16_len);
}

// TypeList at `off` (relative to begin_): u4 size, then size*TypeItem(u2), each
// type_idx < type_ids. off==0 means absent.
bool DexVerifier::VerifyTypeList(u4 off, const char* who) {
    if (off == 0) return true;
    const u1* p = OffsetToPtr(off);
    if (p < begin_ || !CheckListSize(p, 1, sizeof(dex::TypeList), who)) return false;
    const auto* tl = reinterpret_cast<const dex::TypeList*>(p);
    if (!CheckListSize(tl->list, tl->size, sizeof(dex::TypeItem), who)) return false;
    for (u4 i = 0; i < tl->size; ++i) {
        if (tl->list[i].type_idx >= header_->type_ids_size) {
            return Fail(std::string(who) + ": type_list type_idx out of range");
        }
    }
    return true;
}

// Code item (ART CheckIntraCodeItem :1726 + CheckAndGetHandlerOffsets :884).
bool DexVerifier::VerifyCodeItem(u4 off) {
    const u1* end = EndOfFile();
    const u1* base = OffsetToPtr(off);
    if (base < begin_ || !CheckListSize(base, 1, sizeof(dex::Code), "code")) return false;
    const auto* code = reinterpret_cast<const dex::Code*>(base);

    if (code->ins_size > code->registers_size) return Fail("code: ins_size > registers_size");
    if (code->outs_size > 5 && code->outs_size > code->registers_size) {
        return Fail("code: outs_size > registers_size");
    }
    const u4 insns_size = code->insns_size;
    const u2 tries_size = code->tries_size;
    const u1* insns = base + sizeof(dex::Code);
    if (!CheckListSize(insns, insns_size, sizeof(u2), "insns")) return false;
    // VerifyInsns (operand bounds) is beyond ART's structural verifier; skip it in
    // ART-structural-equivalent mode so a partially-decrypted dump (garbage method
    // bodies, valid structure) passes — exactly what ART loads. The insns byte
    // span is still bounded by CheckListSize above.
    if (check_insns_ &&
        !VerifyInsns(reinterpret_cast<const u2*>(insns), insns_size,
                     code->registers_size)) {
        return false;
    }
    const u1* insns_end = insns + static_cast<size_t>(insns_size) * sizeof(u2);
    if (tries_size == 0) return true;

    const u1* try_items = insns_end;
    if (insns_size & 1u) {
        if (!CheckListSize(try_items, 1, sizeof(u2), "try padding")) return false;
        if (*reinterpret_cast<const u2*>(try_items) != 0) return Fail("code: non-zero try padding");
        try_items += sizeof(u2);
    }
    if (!CheckListSize(try_items, tries_size, sizeof(dex::TryBlock), "try_items")) return false;
    const u1* handlers_base =
        try_items + static_cast<size_t>(tries_size) * sizeof(dex::TryBlock);

    const u1* p = handlers_base;
    u4 handlers_size = 0;
    if (!ReadUleb(&p, &handlers_size)) return Fail("code: bad handlers_size");
    if (handlers_size == 0 || handlers_size >= 65536) return Fail("code: handlers_size out of range");

    // Record handler offsets while validating the handler list.
    std::vector<u4> handler_offsets;
    handler_offsets.reserve(handlers_size);
    for (u4 i = 0; i < handlers_size; ++i) {
        u4 offset = static_cast<u4>(p - handlers_base);
        s4 size;
        if (!ReadSleb(&p, &size)) return Fail("code: bad handler size");
        if (size < -65536 || size > 65536) return Fail("code: handler size out of range");
        bool catch_all = size <= 0;
        if (catch_all) size = -size;
        handler_offsets.push_back(offset);
        while (size-- > 0) {
            u4 type_idx, addr;
            if (!ReadUleb(&p, &type_idx)) return Fail("code: bad handler type_idx");
            if (type_idx >= header_->type_ids_size) return Fail("code: handler type_idx out of range");
            if (!ReadUleb(&p, &addr)) return Fail("code: bad handler addr");
            if (addr >= insns_size) return Fail("code: handler addr out of range");
        }
        if (catch_all) {
            u4 addr;
            if (!ReadUleb(&p, &addr)) return Fail("code: bad catch_all addr");
            if (addr >= insns_size) return Fail("code: catch_all addr out of range");
        }
    }
    const auto* ti = reinterpret_cast<const dex::TryBlock*>(try_items);
    u4 last_addr = 0;
    for (u2 t = 0; t < tries_size; ++t, ++ti) {
        if (ti->start_addr < last_addr) return Fail("code: out-of-order try_item");
        if (ti->start_addr >= insns_size) return Fail("code: try_item start out of range");
        u4 j = 0;
        for (; j < handlers_size; ++j) if (ti->handler_off == handler_offsets[j]) break;
        if (j == handlers_size) return Fail("code: bogus handler offset");
        last_addr = ti->start_addr + ti->insn_count;
        if (last_addr > insns_size) return Fail("code: try_item insn_count out of range");
    }
    return true;
}

// VerifyInsns — instruction-operand bounds. NOT an ART dex_file_verifier port:
// ART's structural verifier omits per-instruction checks (those are the 6032-line
// runtime method_verifier). This is OUR bounded checker, anchored to the Dalvik
// bytecode spec via the slicer's VerifyFlags/IndexType tables — the SAME tables
// the core uses to decode, so verifier and core agree on operand layout. See
// dex_verifier.h "ONE DELIBERATE DIVERGENCE" for the full rationale + scope line
// (layout/bounds only; type/dataflow semantics are out of scope). Crash-proof:
// SafeWidth bounds every step before any decode.
bool DexVerifier::VerifyInsns(const u2* insns, u4 insns_size, u2 registers_size) {
    const u2* const end = insns + insns_size;

    // Code units GetWidthFromBytecode dereferences for a payload size field
    // (packed/sparse read p[1] = 2 units; fill-array reads p[1..3] = 4 units); a
    // regular opcode reads only p[0]. Mirrors method_snapshot_builder SafeWidth.
    auto header_units = [](u2 first) -> size_t {
        if (first == dex::kPackedSwitchSignature ||
            first == dex::kSparseSwitchSignature) return 2;
        if (first == dex::kArrayDataSignature) return 4;
        return 1;
    };
    auto check_reg = [&](u4 v) -> bool { return v < registers_size; };

    for (const u2* p = insns; p < end;) {
        // Bounded width: guard the payload size-field read, then the full insn.
        if (static_cast<size_t>(end - p) < header_units(*p)) {
            return Fail("code: truncated instruction/payload header");
        }
        size_t w = dex::GetWidthFromBytecode(p);
        if (w == 0 || static_cast<size_t>(end - p) < w) {
            return Fail("code: instruction extends past insns");
        }

        const u2 first = *p;
        // Payload pseudo-instructions carry no operands to bound here; their
        // offset is validated at the owning branch (below) and their contents are
        // clamped where parsed.
        if (first != dex::kPackedSwitchSignature &&
            first != dex::kSparseSwitchSignature &&
            first != dex::kArrayDataSignature) {
            const dex::Opcode op = dex::OpcodeFromBytecode(first);
            const dex::Instruction d = dex::DecodeInstruction(p);
            const dex::VerifyFlags vf = dex::GetVerifyFlagsFromOpcode(op);

            // Register operands. A kVerifyReg* bit is set only when that field is
            // truly a register; index/branch fields use distinct bits.
            if ((vf & dex::kVerifyRegA) && !check_reg(d.vA))
                return Fail("code: vA register out of range");
            if ((vf & dex::kVerifyRegAWide) && !check_reg(d.vA + 1))
                return Fail("code: vA wide register out of range");
            if ((vf & dex::kVerifyRegB) && !check_reg(d.vB))
                return Fail("code: vB register out of range");
            if ((vf & dex::kVerifyRegBWide) && !check_reg(d.vB + 1))
                return Fail("code: vB wide register out of range");
            if ((vf & dex::kVerifyRegC) && !check_reg(d.vC))
                return Fail("code: vC register out of range");
            if ((vf & dex::kVerifyRegCWide) && !check_reg(d.vC + 1))
                return Fail("code: vC wide register out of range");
            if (vf & (dex::kVerifyVarArg | dex::kVerifyVarArgNonZero)) {
                // d.vA = arg count (<= 5); args in d.arg[0..vA-1].
                for (u4 k = 0; k < d.vA && k < 5; ++k) {
                    if (!check_reg(d.arg[k])) return Fail("code: vararg register out of range");
                }
            }
            if (vf & (dex::kVerifyVarArgRange | dex::kVerifyVarArgRangeNonZero)) {
                // range regs vC .. vC+vA-1.
                if (d.vA > 0 &&
                    static_cast<uint64_t>(d.vC) + d.vA - 1 >= registers_size) {
                    return Fail("code: vararg-range register out of range");
                }
            }

            // Index operand — only the kinds the const-pool path dereferences
            // (matches method_snapshot_builder ResolveConstRef: pick vC for
            // k22c/k22cs, else vB). Out-of-table index → reject so the core never
            // asks the slicer for a nonexistent id.
            const dex::InstructionFormat fmt = dex::GetFormatFromOpcode(op);
            const u4 ridx = (fmt == dex::k22c || fmt == dex::k22cs) ? d.vC : d.vB;
            switch (dex::GetIndexTypeFromOpcode(op)) {
                case dex::kIndexStringRef:
                    if (ridx >= header_->string_ids_size) return Fail("code: string index out of range");
                    break;
                case dex::kIndexTypeRef:
                    if (ridx >= header_->type_ids_size) return Fail("code: type index out of range");
                    break;
                case dex::kIndexFieldRef:
                    if (ridx >= header_->field_ids_size) return Fail("code: field index out of range");
                    break;
                case dex::kIndexMethodRef:
                    if (ridx >= header_->method_ids_size) return Fail("code: method index out of range");
                    break;
                default:
                    break;  // proto/callsite/methodhandle/none — not dereferenced
            }

            // Branch / switch / array-data target — relative code-unit offset by
            // format (DecodeInstruction sign-extends into the noted field). Target
            // must land inside insns[]. k31t covers packed-switch / sparse-switch
            // / fill-array-data (offset → payload); k31c shares decode but is
            // const-string/jumbo (a string index, handled above), excluded by the
            // exact-format match.
            int64_t off_units = 0;
            bool has_target = true;
            switch (fmt) {
                case dex::k10t: case dex::k20t: case dex::k30t:
                    off_units = static_cast<int32_t>(d.vA); break;
                case dex::k21t: case dex::k31t:
                    off_units = static_cast<int32_t>(d.vB); break;
                case dex::k22t:
                    off_units = static_cast<int32_t>(d.vC); break;
                default:
                    has_target = false; break;
            }
            if (has_target) {
                int64_t tgt = static_cast<int64_t>(p - insns) + off_units;
                if (tgt < 0 || tgt >= static_cast<int64_t>(insns_size)) {
                    return Fail("code: branch/switch target out of range");
                }
            }
        }
        p += w;
    }
    return true;
}

// class_data_item (ART CheckIntraClassDataItem): uleb counts, then encoded
// fields/methods with cumulative idx bounds + code_off → code_item.
bool DexVerifier::VerifyClassData(u4 off) {
    const u1* p = OffsetToPtr(off);
    if (p < begin_ || p >= EndOfFile()) return Fail("class_data offset out of range");
    u4 static_fields, instance_fields, direct_methods, virtual_methods;
    if (!ReadUleb(&p, &static_fields) || !ReadUleb(&p, &instance_fields) ||
        !ReadUleb(&p, &direct_methods) || !ReadUleb(&p, &virtual_methods)) {
        return Fail("class_data bad counts");
    }
    auto walk_fields = [&](u4 n) -> bool {
        u4 idx = 0;
        for (u4 i = 0; i < n; ++i) {
            u4 diff, access;
            if (!ReadUleb(&p, &diff) || !ReadUleb(&p, &access)) return Fail("class_data bad encoded_field");
            idx += diff;
            if (idx >= header_->field_ids_size) return Fail("class_data field idx out of range");
        }
        return true;
    };
    if (!walk_fields(static_fields) || !walk_fields(instance_fields)) return false;
    auto walk_methods = [&](u4 n) -> bool {
        u4 idx = 0;
        for (u4 i = 0; i < n; ++i) {
            u4 diff, access, code_off;
            if (!ReadUleb(&p, &diff) || !ReadUleb(&p, &access) || !ReadUleb(&p, &code_off)) {
                return Fail("class_data bad encoded_method");
            }
            idx += diff;
            if (idx >= header_->method_ids_size) return Fail("class_data method idx out of range");
            if (code_off != 0 && !VerifyCodeItem(code_off)) return false;
        }
        return true;
    };
    return walk_methods(direct_methods) && walk_methods(virtual_methods);
}

// encoded_array_item (ART CheckEncodedArray :1225 + CheckEncodedValue :1049).
// Walks the recursive encoded_value TLV, bounding the byte cursor and validating
// every embedded string/type/field/method/proto index against its table. Recursion
// is depth-capped (a malicious deeply-nested array/annotation can't blow the
// stack). Once this owns static_values, the decoder's inline index checks +
// dexitem SafeAt on the field-ref path become redundant.
bool DexVerifier::VerifyEncodedArrayAt(u4 off) {
    // encoded_array_item is a bare (uleb size, then `size` encoded_values) — NOT
    // wrapped in a 0x1c value header (that header only appears for a *nested*
    // array value). Mirrors ART CheckEncodedArray :1225.
    const u1* p = OffsetToPtr(off);
    if (p < begin_ || p >= EndOfFile()) return Fail("encoded_array offset out of range");
    u4 size;
    if (!ReadUleb(&p, &size)) return Fail("encoded_array bad size");
    for (u4 i = 0; i < size; ++i) {
        if (!VerifyEncodedValue(&p, 0)) return false;
    }
    return true;
}

bool DexVerifier::VerifyEncodedValue(const u1** pp, int depth) {
    constexpr int kMaxDepth = 16;  // array/annotation nesting cap (anti stack-overflow)
    if (depth > kMaxDepth) return Fail("encoded_value nested too deep");
    if (*pp >= EndOfFile()) return Fail("encoded_value truncated header");

    const u1 header = *(*pp)++;
    const u4 type = header & 0x1f;
    const u4 arg = static_cast<u4>(header >> 5);

    // Advance the cursor by `n` payload bytes, bounded.
    auto skip = [&](u4 n) -> bool {
        if (static_cast<size_t>(EndOfFile() - *pp) < n) return Fail("encoded_value truncated payload");
        *pp += n;
        return true;
    };
    // Read an (arg+1)-byte little-endian index, then bound it against `limit`.
    auto idx = [&](u4 limit, const char* what) -> bool {
        if (arg > 3) return Fail("encoded_value bad index size");
        u4 v = 0;
        for (u4 i = 0; i <= arg; ++i) {
            if (*pp >= EndOfFile()) return Fail("encoded_value truncated index");
            v |= static_cast<u4>(*(*pp)++) << (8 * i);
        }
        if (v >= limit) return Fail(what);
        return true;
    };

    switch (type) {
        case 0x00: return arg == 0 ? skip(1) : Fail("encoded byte size");          // BYTE
        case 0x02: case 0x03: return arg <= 1 ? skip(arg + 1) : Fail("encoded short/char size");
        case 0x04: case 0x10: return arg <= 3 ? skip(arg + 1) : Fail("encoded int/float size");
        case 0x06: case 0x11: return skip(arg + 1);                                // LONG/DOUBLE (≤8)
        case 0x15: return idx(header_->proto_ids_size, "encoded method_type idx");
        case 0x16: return skip(arg + 1);  // METHOD_HANDLE: consume; idx not dereferenced (out of scope)
        case 0x17: return idx(header_->string_ids_size, "encoded string idx");
        case 0x18: return idx(header_->type_ids_size, "encoded type idx");
        case 0x19: case 0x1b: return idx(header_->field_ids_size, "encoded field/enum idx");
        case 0x1a: return idx(header_->method_ids_size, "encoded method idx");
        case 0x1e: return arg == 0 ? true : Fail("encoded null arg");              // NULL
        case 0x1f: return arg <= 1 ? true : Fail("encoded boolean size");          // BOOLEAN (in arg)
        case 0x1c: {                                                               // ARRAY
            if (arg != 0) return Fail("encoded array arg");
            u4 size;
            if (!ReadUleb(pp, &size)) return Fail("encoded_array bad size");
            for (u4 i = 0; i < size; ++i) {
                if (!VerifyEncodedValue(pp, depth + 1)) return false;
            }
            return true;
        }
        case 0x1d: {                                                               // ANNOTATION
            if (arg != 0) return Fail("encoded annotation arg");
            u4 type_idx, size;
            if (!ReadUleb(pp, &type_idx)) return Fail("encoded_annotation bad type");
            if (type_idx >= header_->type_ids_size) return Fail("encoded_annotation type idx");
            if (!ReadUleb(pp, &size)) return Fail("encoded_annotation bad size");
            for (u4 i = 0; i < size; ++i) {
                u4 name_idx;
                if (!ReadUleb(pp, &name_idx)) return Fail("encoded_annotation bad name");
                if (name_idx >= header_->string_ids_size) return Fail("encoded_annotation name idx");
                if (!VerifyEncodedValue(pp, depth + 1)) return false;
            }
            return true;
        }
        default: return Fail("encoded_value bad type code");
    }
}

// ── CheckIntraSection (ART :2450) ────────────────────────────────────────────
// Per-item internal structure: string_data(MUTF-8), type/proto/field/method id
// index validity, type_list, class_def + class_data + code_item (incl. VerifyInsns
// instruction-operand bounds). These are the items InitBaseCache and the decompile
// path dereference. Out of scope (see dex_verifier.h): encoded_array(static
// values), annotations, debug_info, call_site/method_handle — lazy-parsed.
bool DexVerifier::CheckIntraSection() {
    const u4 string_count = header_->string_ids_size;
    const u4 type_count = header_->type_ids_size;
    const u4 proto_count = header_->proto_ids_size;

    // string_data
    for (u4 i = 0; i < string_count; ++i) {
        if (!VerifyStringData(TableAt<dex::StringId>(header_->string_ids_off, i)->string_data_off)) {
            return false;
        }
    }
    // type_id.descriptor_idx
    for (u4 i = 0; i < type_count; ++i) {
        if (TableAt<dex::TypeId>(header_->type_ids_off, i)->descriptor_idx >= string_count) {
            return Fail("type_id.descriptor_idx out of range");
        }
    }
    // proto_id
    for (u4 i = 0; i < proto_count; ++i) {
        const auto* pr = TableAt<dex::ProtoId>(header_->proto_ids_off, i);
        if (pr->shorty_idx >= string_count) return Fail("proto_id.shorty_idx out of range");
        if (pr->return_type_idx >= type_count) return Fail("proto_id.return_type_idx out of range");
        if (!VerifyTypeList(pr->parameters_off, "proto_id")) return false;
    }
    // field_id
    for (u4 i = 0; i < header_->field_ids_size; ++i) {
        const auto* f = TableAt<dex::FieldId>(header_->field_ids_off, i);
        if (f->class_idx >= type_count) return Fail("field_id.class_idx out of range");
        if (f->type_idx >= type_count) return Fail("field_id.type_idx out of range");
        if (f->name_idx >= string_count) return Fail("field_id.name_idx out of range");
    }
    // method_id
    for (u4 i = 0; i < header_->method_ids_size; ++i) {
        const auto* m = TableAt<dex::MethodId>(header_->method_ids_off, i);
        if (m->class_idx >= type_count) return Fail("method_id.class_idx out of range");
        if (m->proto_idx >= proto_count) return Fail("method_id.proto_idx out of range");
        if (m->name_idx >= string_count) return Fail("method_id.name_idx out of range");
    }
    // class_def + class_data + code
    for (u4 c = 0; c < header_->class_defs_size; ++c) {
        const auto* cd = TableAt<dex::ClassDef>(header_->class_defs_off, c);
        if (cd->class_idx >= type_count) return Fail("class_def.class_idx out of range");
        if (cd->superclass_idx != dex::kNoIndex && cd->superclass_idx >= type_count) {
            return Fail("class_def.superclass_idx out of range");
        }
        if (cd->source_file_idx != dex::kNoIndex && cd->source_file_idx >= string_count) {
            return Fail("class_def.source_file_idx out of range");
        }
        if (!VerifyTypeList(cd->interfaces_off, "class_def.interfaces")) return false;
        if (cd->class_data_off != 0 && !VerifyClassData(cd->class_data_off)) return false;
        if (cd->static_values_off != 0 && !VerifyEncodedArrayAt(cd->static_values_off)) {
            return false;
        }
    }
    return true;
}

// ── CheckInterSection (ART :3477) ────────────────────────────────────────────
// Cross-ref checks mirroring ART CheckInter*IdItem (:2710–2933) + class_def
// (:2935): id ordering/uniqueness (string ordering via the verbatim ART UTF-16
// comparator), field/method/class_def descriptor-syntax + member-name validity
// (VerifyTypeDescriptor + IsValidMemberName/IsValidDescriptor), and class_def
// semantics in VerifyClassDefs. Out of scope (see dex_verifier.h): proto
// shorty-match, call_site/method_handle inter-checks, annotations definer-match,
// and intra encoded_array/annotations/debug_info — lazy-parsed / not dereferenced.
bool DexVerifier::CheckInterSection() {
    // string_ids: strictly increasing by UTF-16 code-point value (ART :2720).
    for (u4 i = 1; i < header_->string_ids_size; ++i) {
        if (CompareModifiedUtf8ToModifiedUtf8AsUtf16CodePointValues(
                StringContent(i - 1), StringContent(i)) >= 0) {
            return Fail("Out-of-order string_ids");
        }
    }
    // type_ids: strictly increasing descriptor_idx (ART :2749).
    for (u4 i = 1; i < header_->type_ids_size; ++i) {
        if (TableAt<dex::TypeId>(header_->type_ids_off, i - 1)->descriptor_idx >=
            TableAt<dex::TypeId>(header_->type_ids_off, i)->descriptor_idx) {
            return Fail("Out-of-order type_ids");
        }
    }
    // proto_ids: by return_type_idx, then parameter type_idx list (ART :2804).
    for (u4 i = 1; i < header_->proto_ids_size; ++i) {
        const auto* prev = TableAt<dex::ProtoId>(header_->proto_ids_off, i - 1);
        const auto* cur = TableAt<dex::ProtoId>(header_->proto_ids_off, i);
        if (prev->return_type_idx > cur->return_type_idx) return Fail("Out-of-order proto_ids");
        if (prev->return_type_idx < cur->return_type_idx) continue;
        const auto* pt = ProtoParams(i - 1);
        const auto* ct = ProtoParams(i);
        u4 pn = pt ? pt->size : 0, cn = ct ? ct->size : 0;
        bool decided = false;
        u4 k = 0;
        for (; k < pn && k < cn; ++k) {
            u2 pidx = pt->list[k].type_idx, cidx = ct->list[k].type_idx;
            if (pidx < cidx) { decided = true; break; }
            if (pidx > cidx) return Fail("Out-of-order proto_id arguments");
        }
        if (!decided && k >= cn) return Fail("Out-of-order proto_id arguments");
    }
    // field_ids: per-item class/type descriptor + member-name validity (ART :2842)
    // then (class_idx, name_idx, type_idx) strictly increasing (ART :2867).
    for (u4 i = 0; i < header_->field_ids_size; ++i) {
        const auto* c = TableAt<dex::FieldId>(header_->field_ids_off, i);
        if (!VerifyTypeDescriptor(c->class_idx, "field_id: invalid class descriptor",
                                  [](char d) { return d == 'L'; })) return false;
        if (!VerifyTypeDescriptor(c->type_idx, "field_id: invalid type descriptor",
                                  [](char d) { return d != 'V'; })) return false;
        if (!IsValidMemberName(StringContent(c->name_idx))) return Fail("field_id: invalid name");
        if (i == 0) continue;
        const auto* p = TableAt<dex::FieldId>(header_->field_ids_off, i - 1);
        if (p->class_idx > c->class_idx) return Fail("Out-of-order field_ids");
        if (p->class_idx < c->class_idx) continue;
        if (p->name_idx > c->name_idx) return Fail("Out-of-order field_ids");
        if (p->name_idx < c->name_idx) continue;
        if (p->type_idx >= c->type_idx) return Fail("Out-of-order field_ids");
    }
    // method_ids: per-item class descriptor + member-name validity (ART :2889)
    // then (class_idx, name_idx, proto_idx) strictly increasing (ART :2913).
    for (u4 i = 0; i < header_->method_ids_size; ++i) {
        const auto* c = TableAt<dex::MethodId>(header_->method_ids_off, i);
        if (!VerifyTypeDescriptor(c->class_idx, "method_id: invalid class descriptor",
                                  [](char d) { return d == 'L' || d == '['; })) return false;
        if (!IsValidMemberName(StringContent(c->name_idx))) return Fail("method_id: invalid name");
        if (i == 0) continue;
        const auto* p = TableAt<dex::MethodId>(header_->method_ids_off, i - 1);
        if (p->class_idx > c->class_idx) return Fail("Out-of-order method_ids");
        if (p->class_idx < c->class_idx) continue;
        if (p->name_idx > c->name_idx) return Fail("Out-of-order method_ids");
        if (p->name_idx < c->name_idx) continue;
        if (p->proto_idx >= c->proto_idx) return Fail("Out-of-order method_ids");
    }
    return VerifyClassDefs();
}

// ART CheckInterClassDefItem :2935 — class_def cross-ref semantics: class /
// superclass / interface are class types, no self-inheritance, no duplicate class
// def, "defined after superclass/interface" ordering, no duplicate interface, and
// class_data definer-match. Descriptor validity reuses the ART descriptor leaves.
// (Out of scope, documented in dex_verifier.h: proto shorty-match, call_site /
// method_handle inter-checks, annotations definer-match — lazy / not dereferenced.)
bool DexVerifier::VerifyClassDefs() {
    constexpr u4 kNotDefined = 0xffffffffu;
    const u4 type_count = header_->type_ids_size;
    // Which class_def (by position) defines each type_idx — for dup + ordering.
    std::vector<u4> defined_at(type_count, kNotDefined);

    for (u4 c = 0; c < header_->class_defs_size; ++c) {
        const auto* cd = TableAt<dex::ClassDef>(header_->class_defs_off, c);
        const u4 cls = cd->class_idx;  // < type_count (CheckIntraSection)
        if (!VerifyTypeDescriptor(cls, "class_def: invalid class descriptor",
                                  [](char d) { return d == 'L'; })) return false;
        if (defined_at[cls] != kNotDefined) return Fail("Duplicate class definition");

        if (cd->superclass_idx != dex::kNoIndex) {
            if (cd->superclass_idx == cls) return Fail("Class is its own superclass");
            if (!VerifyTypeDescriptor(cd->superclass_idx, "class_def: invalid superclass",
                                      [](char d) { return d == 'L'; })) return false;
            const u4 s = cd->superclass_idx;  // < type_count (CheckIntraSection)
            if (defined_at[s] != kNotDefined && defined_at[s] > c) {
                return Fail("Class defined before its superclass");
            }
        }

        if (cd->interfaces_off != 0) {
            // interfaces_off + every type_idx validated by VerifyTypeList (intra).
            const auto* il = reinterpret_cast<const dex::TypeList*>(begin_ + cd->interfaces_off);
            for (u4 i = 0; i < il->size; ++i) {
                const u4 it = il->list[i].type_idx;
                if (it == cls) return Fail("Class implements itself");
                if (!VerifyTypeDescriptor(it, "class_def: invalid interface",
                                          [](char d) { return d == 'L'; })) return false;
                for (u4 j = 0; j < i; ++j) {
                    if (il->list[j].type_idx == it) return Fail("Duplicate interface");
                }
            }
        }

        if (cd->class_data_off != 0) {
            u4 definer;
            if (!FindFirstClassDataDefiner(cd->class_data_off, &definer)) return false;
            if (definer != dex::kNoIndex && definer != cls) {
                return Fail("class_data_item defines members of another class");
            }
        }
        defined_at[cls] = c;
    }
    return true;
}

bool DexVerifier::FindFirstClassDataDefiner(u4 off, u4* out) {
    const u1* p = OffsetToPtr(off);
    u4 sf, inf, dm, vm;
    if (!ReadUleb(&p, &sf) || !ReadUleb(&p, &inf) ||
        !ReadUleb(&p, &dm) || !ReadUleb(&p, &vm)) {
        return Fail("class_data bad counts");
    }
    if (sf != 0 || inf != 0) {
        u4 diff, access;
        if (!ReadUleb(&p, &diff) || !ReadUleb(&p, &access)) return Fail("class_data bad field");
        if (diff >= header_->field_ids_size) return Fail("class_data field idx out of range");
        *out = TableAt<dex::FieldId>(header_->field_ids_off, diff)->class_idx;
        return true;
    }
    if (dm != 0 || vm != 0) {
        u4 diff, access, code_off;
        if (!ReadUleb(&p, &diff) || !ReadUleb(&p, &access) || !ReadUleb(&p, &code_off)) {
            return Fail("class_data bad method");
        }
        if (diff >= header_->method_ids_size) return Fail("class_data method idx out of range");
        *out = TableAt<dex::MethodId>(header_->method_ids_off, diff)->class_idx;
        return true;
    }
    *out = dex::kNoIndex;
    return true;
}

}  // namespace

DexVerifyResult VerifyDex(const u1* data, size_t size, bool check_insns) {
    try {
        DexVerifier v(data, size, check_insns);
        if (v.Verify()) return {true, {}};
        return {false, v.reason()};
    } catch (const std::exception& e) {
        // VerifyInsns decodes instructions via the slicer (GetWidthFromBytecode /
        // DecodeInstruction) — the one place the verifier uses slicer *logic* — and
        // those throw `SLICER_CHECK` on malformed bytecode (e.g. an invalid 35c arg
        // count). Catch any such throw and report it as a rejection so VerifyDex
        // itself is total: it returns {ok,reason} and never propagates / crashes.
        return {false, std::string("malformed dex: ") + e.what()};
    }
}

}  // namespace dexkit::ext
