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
#include <unordered_set>
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

// ART :82 — the false arm is EXACTLY ART's: the header item and the six *_id
// tables. Everything else, INCLUDING kCallSiteIdItem (:92), kMethodHandleItem
// (:93) and kMapList (:94), is a data-section type. Those three used to sit in
// the false arm here (dexllm#62), with a comment that justified the divergence by
// misstating ART; the single consumer is CheckMap's alignment branch, so the
// observable cost was that a MISALIGNED call_site_id / method_handle section
// offset was accepted where ART rejects it. Never memory safety — the extent
// bound in CheckMap spans both sections whatever their alignment, and an
// unaligned u2/u4 load is harmless on every supported target — so this is spec
// fidelity, and it is the direction an added check can get WRONG (dexllm#58), not
// a crash fix. kMapList is NOT the no-op it first looked like — the a/b measured
// it: CheckHeader's CheckValidOffsetAndSize(map_off, ..., 4, "map") runs first and
// covers the HEADER field, but the map_list item's own SELF-REFERENTIAL offset is
// a separate u4 that nothing compared against it, so misaligning that one is
// accepted pre-fix and rejected now (27 crafted sources). Real input is unaffected
// (the two agree in every dex a compiler emits), which is why the corpus half of
// the a/b is flat.
//
// ART calls this predicate in TWO more places, and NEITHER is ported:
//   * :775 — the same CheckMap block, where it also gates the data_items_left
//     budget (:777): the SUM of every data section's item COUNT bounded by the
//     data segment's byte size. It guards nothing here. This port is
//     REFERENCE-driven and reads item->size for exactly the two fixed-size
//     sections the header does not describe, where CheckMap's per-section
//     byte-span bound is strictly TIGHTER than a running item budget; for every
//     variable-length section the count is never consumed at all. Adding it
//     would be a pure new rejection direction with no reachable defect behind it.
//   * :2354 — CheckIntraSectionIterate, which rejects a data-section item at
//     offset 0 (:2356) and populates offset_to_type_map_. Both belong to ART's
//     MAP-driven intra pass, which this port does not have at all (see
//     dex_verifier.h's out-of-scope list). Widening the predicate here does NOT
//     bring them with it — it only means ART applies them to three more types
//     than this port does.
// Catalogued as B2b in docs/aosp-oob-divergences.md (B2, this alignment gap, is
// CLOSED there).
bool IsDataSectionType(u2 type) {
    switch (type) {
        case kHeaderItem:
        case kStringIdItem:
        case kTypeIdItem:
        case kProtoIdItem:
        case kFieldIdItem:
        case kMethodIdItem:
        case kClassDefItem:
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
    DexVerifier(const u1* image, size_t image_size, size_t header_off,
                bool check_insns = true, VerifyImageState* img_state = nullptr)
        : image_(image), image_size_(image_size), header_off_(header_off),
          check_insns_(check_insns),
          img_state_(img_state != nullptr ? img_state : &owned_state_) {
        // A caller that threads no state gets one of its own, which is exactly
        // the single-slice case. The budget is seeded from the IMAGE, not the
        // slice, and only the FIRST verifier over a given state seeds it —
        // ClassifyImageSlices reuses one state across an image's slices, so the
        // total stays O(image / 8) rather than resetting per slice.
        if (img_state_->method_handle_entries_left == 0 &&
            img_state_->walked_method_handles.empty()) {
            img_state_->method_handle_entries_left =
                image_size / sizeof(dex::MethodHandle) + 1;
        }
    }

    bool Verify() {
        if (image_ == nullptr || header_off_ > image_size_) {
            return Fail("Empty or truncated file");
        }
        // ART CheckHeader (:619) computes its `size` as
        // `container->End() - dex_file_->Begin()` — the bytes from THIS dex's
        // header to the end of the file. That is the bound for `file_size`; the
        // bound for section OFFSETS is the data range below, which is a different
        // span for a v41 container.
        avail_ = image_size_ - header_off_;
        if (avail_ < dex::Header::kV40Size) return Fail("Empty or truncated file");
        header_ = reinterpret_cast<const dex::Header*>(image_ + header_off_);
        if (!ComputeDataRange()) return false;
        return CheckHeader() && CheckMap() && CheckIntraSection() &&
               CheckInterSection();
    }

    const std::string& reason() const { return reason_; }

private:
    // ART DexFile::GetDataRange (dex_file.cc :240) — the byte range every dex
    // offset in this header is relative to, and the bound `size_` all the
    // CheckValidOffsetAndSize / CheckListSize checks use (ART's DataBegin() /
    // DataSize(), which is what its verifier is constructed with).
    //
    // A standard v35-40 dex: the dex itself, bounded by its own file_size — so a
    // section may not reach past this dex even when more bytes follow it in the
    // container (that is what let a concatenated dex's tail go unchecked).
    //
    // A v41 CONTAINER dex: the whole container, with this header sitting at
    // `container_off` inside it — sibling dexes deliberately SHARE one data
    // section, so `string_ids_off` legitimately points past this dex's file_size.
    // Verifying such a dex against its own slice would reject a well-formed file
    // (AOSP art/test/dexdump/multidex-container.dex), and verifying the second
    // one against its own header would resolve every offset in the wrong place.
    bool ComputeDataRange() {
        if (avail_ >= dex::Header::kV41Size &&
            header_->header_size >= dex::Header::kV41Size) {
            const u4 hoff = header_->ContainerOff();
            // ART lets `data -= header_offset` underflow and clamps after. We are
            // handed the image base explicitly, so an underflow is a rejection:
            // a container that begins before the image cannot be verified.
            if (hoff > header_off_) return Fail("Dex container starts before the image");
            const size_t base_off = header_off_ - hoff;
            // ART CLAMPS a container_size that runs past the file
            // (`std::min(size, container->End() - data)`); we reject it. Clamping
            // would let a crafted `container_size` pass the gate and then be
            // refused by the slicer's own ValidateHeader
            // (`SLICER_CHECK_LE(ContainerSize() - ContainerOff(), size)`) — i.e.
            // `verify()` would call a dex loadable that the loader then throws on,
            // breaking the documented verify()/verify_report() equality. A real
            // container_size never exceeds the container.
            if (header_->ContainerSize() > image_size_ - base_off) {
                return Fail("Dex container size is past the image");
            }
            begin_ = image_ + base_off;
            size_ = header_->ContainerSize();
        } else {
            begin_ = image_ + header_off_;
            size_ = std::min<size_t>(header_->file_size, avail_);
        }
        return true;
    }

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
    // ART CheckIntraMethodHandleItem :1492 — fused into CheckMap for the same
    // reason the annotations subtree fused into CheckIntraSection (dexllm#56):
    // ART reaches it by ITERATING the map's sections, and this port has no such
    // pass. The map item is in hand there, so that is where the walk goes.
    bool VerifyMethodHandleSection(u4 off, u4 count);  // dexllm#59

    // ── intra-section item validators (phase ③) ──────────────────────────────
    bool VerifyMutf8(const u1* p, u4 utf16_len);
    bool VerifyStringData(u4 off);
    bool VerifyTypeList(u4 off, const char* who);
    bool VerifyCodeItem(u4 off);
    bool VerifyInsns(const u2* insns, u4 insns_size, u2 registers_size);
    bool VerifyClassData(u4 off);
    bool VerifyEncodedArrayAt(u4 off);              // ART CheckEncodedArray :1225
    bool VerifyEncodedValue(const u1** pp, int depth);  // ART CheckEncodedValue :1049
    // ── annotations subtree (dexllm#56) ──────────────────────────────────────
    // ART splits these across its two phases: the item structure in
    // CheckIntraAnnotationsDirectoryItem :2111 / CheckIntraAnnotationItem :2056 /
    // the CheckList cases for annotation_set(_ref_list) :2284/:2290, and the
    // offsets between them in CheckInterAnnotationsDirectoryItem :3276 (which
    // resolves each through CheckOffsetToTypeMap :2564). This port is
    // REFERENCE-driven where ART is MAP-driven, so the two halves fuse into one
    // recursive walk from class_def.annotations_off — the same shape
    // VerifyClassData / VerifyEncodedArrayAt / VerifyTypeList already use for
    // the other class_def offsets. See the header's OUT OF SCOPE note for what
    // that costs (offset_to_type_map_ is not ported, here or anywhere).
    bool VerifyAnnotationsDirectory(u4 off);
    bool VerifyAnnotationSet(u4 off);
    bool VerifyAnnotationSetRefList(u4 off);
    bool VerifyAnnotationItem(u4 off);
    // A bare encoded_annotation (no 0x1d value header). Shared by the 0x1d
    // ARRAY-element form and by annotation_item, which stores it raw.
    bool VerifyEncodedAnnotation(const u1** pp, int depth);
    // 4-aligned, in-image header of a fixed-size annotation struct. The
    // alignment is not cosmetic: the slicer asserts it (reader.cc
    // ExtractAnnotations / ExtractAnnotationSet / ExtractAnnotationSetRefList
    // each SLICER_CHECK_EQ(offset % 4, 0)), so checking it here turns a throw
    // from deep inside the parser into a reject with a byte-level reason.
    bool AnnotationStructAt(u4 off, size_t sz, const char* who, const u1** out);
    bool VerifyClassDefs();  // ART CheckInterClassDefItem :2935
    // ART CheckInterClassDataItem :3208 — EVERY member a class_data declares
    // must name `cls` as its defining class. ART loops all fields (:3226) and
    // all methods (:3244), and re-checks per member in CheckClassDataItemField
    // :934 / CheckClassDataItemMethod :961; this port used to read only the
    // FIRST member (`FindFirstClassDataDefiner`, defined :2579, called :3070),
    // so a crafted class_data could declare another class's members as long as
    // its first entry was its own — dexllm#48. Only the DEFINER half of that ART
    // function is ported: member access-flag validation, CheckStaticFieldTypes
    // :1289, and the orphan-class_data check are not. `off` already validated by
    // VerifyClassData in CheckIntraSection.
    bool CheckClassDataDefiners(u4 off, u4 cls);
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

    const u1* image_;      // the whole loaded image (a file, or one zip entry)
    size_t image_size_;
    size_t header_off_;    // where THIS logical dex's header sits in the image
    size_t avail_ = 0;     // image_size_ - header_off_ (ART CheckHeader's `size`)
    const u1* begin_ = nullptr;  // ART DataBegin() — the base every offset is off
    size_t size_ = 0;            // ART DataSize()  — and the bound for them
    bool check_insns_ = true;  // false = ART-structural-equivalent (skip VerifyInsns)
    VerifyImageState owned_state_;  // used when the caller threads none
    VerifyImageState* img_state_;   // per-IMAGE scratch (dexllm#59)
    const dex::Header* header_ = nullptr;
    std::string reason_;
    // ART's NumMethodHandles() (dex_file.cc :290, zero-inited at :159) — the
    // map's method_handle count, carried forward by CheckMap so
    // VerifyEncodedValue's 0x16 arm can bound its index (ART :1212). 0 means the
    // dex declares no such section, which is ART's own value for that case and
    // rejects every 0x16 index.
    u4 method_handle_count_ = 0;
    // Annotation offsets already walked, per structure kind. The slicer memoises
    // the same way (reader.cc annotations_directories_ / annotation_sets_ /
    // annotations_), so this matches what it actually parses — and it is what
    // keeps the walk LINEAR: nothing stops a dex from pointing every class_def
    // at one directory, or every set entry at one item, and re-walking a shared
    // subtree per reference is quadratic in exactly the way dexllm#20's declared-
    // string index was. Per-kind because one offset may legally be reachable as
    // two different structures.
    std::unordered_set<u4> seen_ann_dir_, seen_ann_set_, seen_ann_ref_, seen_ann_item_;
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
    // ART bounds file_size by the bytes remaining from this header to the end of
    // the file (`container->End() - Begin()`), NOT by the data range — for a v41
    // container those differ.
    if (file_size > avail_) return Fail("Bad file size (past image)");
    if (header_->header_size != header_size) return Fail("Bad header size");
    if (header_->endian_tag != dex::kEndianConstant) return Fail("Unexpected endian_tag");
    // adler32: intentionally not verified (policy).

    // ART :670 — the v41 container fields must be self-consistent.
    if (version >= dex::Header::kV41) {
        const u4 container_size = header_->ContainerSize();
        const u4 container_off = header_->ContainerOff();
        if (container_size <= container_off) return Fail("Dex container is too small");
        if (file_size > container_size - container_off) {
            return Fail("Header file_size is past multi-dex size");
        }
    }

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
        // ART :785 — the switch naming the five variable-length item types that
        // align to 1; every other data-section type aligns to 4, which since
        // dexllm#62 includes call_site_id and method_handle (ART :92/:93). The
        // rejection itself is :798.
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
        // EXTENT, not just the start, for the two fixed-size sections the HEADER
        // does not describe (dexllm#57 review). ART bounds both too, in TWO places,
        // and this port reached NEITHER — the first rationale written here claimed
        // ART's own CheckMap does not bound them, which is backwards:
        //   * ART's CheckMap DOES, because its IsDataSectionType (:82) returns true
        //     for both (:92/:93), which subjects them to the data_items_left budget
        //     (:777) and the 4-byte alignment check (:798). The alignment half is
        //     ported as of dexllm#62 (the loop above now reaches both); the budget
        //     is deliberately not — see IsDataSectionType's comment for why it
        //     guards nothing in a reference-driven port.
        //   * ART's intra pass does too, via CheckIntraSectionIterate (:2199,
        //     entered for both at :2529-2530): CheckListSize(ptr_, 1,
        //     sizeof(CallSiteIdItem)) at :2265, and the same call opening
        //     CheckIntraMethodHandleItem at :1493. This port is REFERENCE-driven
        //     and never walks those sections, so it never got there either.
        // The bound below is the stronger of ART's two (a per-section byte span
        // rather than a running item budget); putting it here, where the map item
        // is already in hand, is the same intra/inter fusion the dexllm#56
        // annotation walk used.
        // Every other fixed-size table has its span bounded by CheckHeader's
        // CheckListSize off the header's own size/off pair; method_handle and
        // call_site_id exist ONLY in the map, so `item->size` is the sole
        // statement of how long they are — and
        // `Reader::MethodHandles()` builds an ArrayView straight from it
        // (`section<MethodHandle>(mi->offset, mi->size)`). Unbounded, that made
        // ArrayView's own SLICER_CHECK_LT bound an index against ATTACKER data:
        // an inflated count plus a large METHOD_HANDLE encoded_value index read
        // ~134 MB past a 2.5 KB file. A verify()-valid dex, a SIGSEGV, and no
        // catch(...) sees it — the defect class dexllm#56 closed, which the
        // dexllm#57 parser fix woke up by calling GetMethodHandle at all.
        // Variable-length sections cannot be bounded this way (their `size` is an
        // item count over items of differing length); each is validated where it
        // is parsed instead.
        const size_t entry = item->type == kMethodHandleItem ? sizeof(dex::MethodHandle)
                           : item->type == kCallSiteIdItem   ? sizeof(u4)
                                                             : 0;
        if (entry != 0 &&
            !CheckListSize(OffsetToPtr(item->offset), item->size, entry, "map section span")) {
            return false;
        }
        // method_handle CONTENTS (dexllm#59). ORDER MATTERS: the walk below
        // dereferences every entry of the section, and the ONLY thing that has
        // bounded that span is the CheckListSize immediately above — so the two
        // must stay adjacent and in this order. call_site_id has no analogue:
        // its contents stay out of scope and are bounded at the reader
        // (dexllm#67 GetCallSite), which the header records as a decision.
        if (item->type == kMethodHandleItem) {
            if (!VerifyMethodHandleSection(item->offset, item->size)) return false;
            // ART's NumMethodHandles(), carried forward for VerifyEncodedValue's
            // 0x16 arm (ART :1212). Duplicate map sections are rejected above, so
            // one item is the whole statement of this section's length.
            method_handle_count_ = item->size;
        }
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

// ── VerifyMethodHandleSection (ART CheckIntraMethodHandleItem :1492) ─────────
// The CONTENTS of the method_handle section: each entry's TYPE must name a real
// handle kind, and its `field_or_method_id` must index the table that kind
// implies. dexllm#57 ported only this function's opening CheckListSize (as the
// section EXTENT bound in CheckMap); dexllm#59 ports the rest.
//
// The residual was never an OOB — every path bounds the index eventually — but
// it was NOT simply "a throw", which is what dexllm#59 was filed saying. Measured
// on crafted entries of `tests/data/invoke-custom.dex`, in a subprocess judged by
// exit status: 0 signals and 0 exceptions on every craft. What actually happened
// splits by WHICH half is wrong and WHICH reader runs:
//   * a TYPE past kLast never throws anywhere. `IsField()` (dex_ir.cc :110) is
//     four equality tests against 0x00-0x03 with no else-branch check, so 0xFFFF
//     simply falls through to the method table, and the
//     Writer renders by the same partition — so a handle asserting an UNDEFINED
//     kind decompiled BYTE-IDENTICALLY to a legal invoke-static one. A fabricated
//     fact with nothing anywhere to mark it, and the half the issue never named.
//   * an out-of-range INDEX throws only through the slicer (GetFieldDecl /
//     GetMethodDecl, where ArrayView's SLICER_CHECK_LT bounds it). Through
//     dexllm#67's ResolveMethodHandle — the invoke-custom and static-initializer
//     path, written after this issue was filed — it is bounded and returns false,
//     so the site renders NOTHING: 2 bootstrap lines silently vanished from the
//     decompiled class. Refusing beats inventing, but only at the gate is it
//     visible at all.
//
// COST, and the bound is NOT free — an adversarial review measured that. The
// first version of this comment said "the CheckListSize above makes count * 8 <=
// file size, so no work budget is needed (contrast the dexllm#56 annotation memo,
// where one subtree is reachable from every class_def)". For ONE dex per image
// that is true. For a **v41 CONTAINER** it is exactly backwards, and the contrast
// it invokes is an identity: ComputeDataRange sets `size_` to ContainerSize() for
// EVERY slice, while LogicalDexSlices strides by `file_size` — so `count` is
// bounded by the CONTAINER while the number of slices is the container divided by
// a 120-byte v41 header, and one section is reachable from every sibling. Measured on
// a crafted container whose extra slices are bare headers reusing the shared map:
// 2/4/8/16 MB -> 0.34 / 1.29 / 5.19 / 20.59 s, quadrupling per doubling, where
// HEAD pays 0.00 / 0.01 / 0.02 / 0.04 s. Every slice is REJECTED either way and
// for the same reason, so the delta is nothing but this walk — and the work is
// paid BEFORE the rejection, which turns `dexllm.verify(path)`'s "always returns
// a verdict" into "may take an hour" on a 256 MB upload.
//
// The fix is per-IMAGE, not per-slice, because the repetition is what is
// quadratic: the SAME section, re-walked once per sibling. A memo keyed on the
// BYTES — (offset, count) — collapses that to a single walk, and a per-image
// ENTRY BUDGET seeded from the image size bounds the variant the memo cannot
// see, N slices each naming a DIFFERENT overlapping section. Together the total
// is O(image / 8) however the slices are arranged.
//
// Keying on the bytes rather than on (bytes + this dex's table sizes) is the
// part that had to be MEASURED: siblings have their OWN id tables, so a key
// carrying them misses on exactly the case the memo exists for, and a
// legitimate 400-handle shared section was then rejected by the budget. What
// the memo stores instead is the two MAXIMA the walk found, so a later slice
// re-checks its own tables in O(1) — exactly equivalent, because "every index
// < limit" is "max index < limit". Dropping that re-check would accept a
// section legal for one sibling and out of range for another; the fixture's two
// slices declare 6 and 3 method_ids, which is what pins it.
//
// ART has no analogue of either half. Its `data_items_left` budget (:751,
// unported as B2b) is seeded at :731 from `dex_file_->Begin()` to `EndOfFile()`
// for a v41 dex — a GEOMETRIC span, not `header_->data_size_`, so no craft is
// involved and an early slice's budget is ~the whole container. ART is quadratic
// here too. (An earlier draft of this comment said the seed was a per-dex
// `data_size` a slice could inflate; both delta reviewers read AOSP and
// disproved it. The conclusion held, the reason did not.)
//
// A FIRST fix bounded `count` by the slice's own `file_size / 8` instead, and a
// delta review REFUTED it by construction: starting from AOSP's own
// multidex-container.dex, appending a shared method_handle section and nothing
// else, the crossover is exactly `file_size / 8` — 70 entries accepted, 71
// rejected, and the v41 sibling rule then takes the WHOLE container down. Its
// justification ("N distinct handles imply id tables of at least 8N bytes inside
// file_size") assumed handles are DISTINCT, which nothing enforces, and assumed
// the tables are INSIDE file_size, which is exactly what a v41 container does not
// guarantee — in that same AOSP sample slice 0 has file_size 564 and
// string_ids_off 684. Sharing is the point of the format. The memo needs no such
// argument because it rejects nothing.
bool DexVerifier::VerifyMethodHandleSection(u4 off, u4 count) {
    const auto key = std::make_pair(off, count);
    const auto seen = img_state_->walked_method_handles.find(key);
    if (seen != img_state_->walked_method_handles.end()) {
        // Already walked for this image, so only the two table bounds can differ
        // — and they are decided by the maxima, which the first walk recorded.
        if (seen->second.field_ids > header_->field_ids_size) {
            return Fail("Bad index: method_handle_item field_idx");
        }
        if (seen->second.method_ids > header_->method_ids_size) {
            return Fail("Bad index: method_handle_item method_idx");
        }
        return true;
    }
    if (count > img_state_->method_handle_entries_left) {
        return Fail("method_handle sections exceed the image's entry budget");
    }
    img_state_->method_handle_entries_left -= count;
    VerifyImageState::HandleSectionNeeds needs{0, 0};
    // Precondition (asserted by construction at the single call site): the span
    // [off, off + count * sizeof(dex::MethodHandle)) lies inside the image, and
    // `off` is 4-aligned (dexllm#62 put kMethodHandleItem back in ART's own
    // IsDataSectionType, so CheckMap's alignment branch reaches it).
    const u1* p = OffsetToPtr(off);
    for (u4 i = 0; i < count; ++i, p += sizeof(dex::MethodHandle)) {
        const auto* mh = reinterpret_cast<const dex::MethodHandle*>(p);
        // ART :1501 — `> MethodHandleType::kLast`, which is kInvokeInterface
        // (dex_file.h :227). The slicer names the same nine constants, and using
        // ITS spelling ties the check to the table the core actually consults.
        if (mh->method_handle_type > dex::METHOD_HANDLE_TYPE_INVOKE_INTERFACE) {
            return Fail("Bad method handle type");
        }
        // ART :1508-1524 — 0x00-0x03 are the field accessors and 0x04-0x08 the
        // invokers; ir::MethodHandle::IsField() (dex_ir.cc :110) partitions the
        // same way, which is what makes this the bound the reader will use.
        const bool is_field =
            mh->method_handle_type <= dex::METHOD_HANDLE_TYPE_INSTANCE_GET;
        if (!CheckIndex(mh->field_or_method_id,
                        is_field ? header_->field_ids_size : header_->method_ids_size,
                        is_field ? "method_handle_item field_idx"
                                 : "method_handle_item method_idx")) {
            return false;
        }
        u4& hi = is_field ? needs.field_ids : needs.method_ids;
        hi = std::max<u4>(hi, static_cast<u4>(mh->field_or_method_id) + 1u);
    }
    img_state_->walked_method_handles.emplace(key, needs);
    return true;
}

// Modified UTF-8 validation (dex string_data) — ART CheckIntraStringDataItem
// :1838: 1-byte 0x01–0x7F; 2-byte 0xC0–0xDF + continuation; 3-byte 0xE0–0xEF +
// 2 continuations (surrogates legal); no 4-byte form. A sequence must also be
// CANONICAL — the encoded NUL `C0 80` is the single legal below-0x80 form, and
// every other overlong is rejected as ART's "Illegal representation" (:1897,
// :1922). Each sequence is one UTF-16 code unit; count must equal utf16_len;
// NUL terminator within image.
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
            if (p >= end) return Fail("string_data bad MUTF-8 2-byte seq");
            u1 b2 = *p++;
            if ((b2 & 0xC0) != 0x80) return Fail("string_data bad MUTF-8 2-byte seq");
            // ART :1897 — "Illegal representation": a non-NUL OVERLONG. `C0 80`
            // is the one legal 2-byte form below 0x80 (MUTF-8's encoded NUL);
            // anything else that decodes below 0x80 is a non-canonical spelling
            // of a 1-byte character. See the block comment at the 3-byte arm.
            u2 v2 = static_cast<u2>(((b & 0x1F) << 6) | (b2 & 0x3F));
            if (v2 != 0 && v2 < 0x80) return Fail("string_data illegal MUTF-8 representation");
        } else if (b < 0xF0) {
            if (p >= end) return Fail("string_data bad MUTF-8 3-byte seq");
            u1 b2 = *p++;
            if ((b2 & 0xC0) != 0x80) return Fail("string_data bad MUTF-8 3-byte seq");
            if (p >= end) return Fail("string_data bad MUTF-8 3-byte seq");
            u1 b3 = *p++;
            if ((b3 & 0xC0) != 0x80) return Fail("string_data bad MUTF-8 3-byte seq");
            // ART :1922 — same "Illegal representation" rule for the 3-byte form.
            //
            // dexllm#22/#23 — these two checks were MISSING, and the omission was
            // documented backwards ("VerifyMutf8 checks lead/continuation shape
            // only, as ART does" — ART rejects overlongs right here). It matters
            // beyond ART parity: a decoded identifier is handed to Python and a
            // caller-supplied one is encoded back, and canonical re-encoding
            // cannot reproduce an overlong — so an overlong descriptor enumerated
            // fine and then resolved to NOTHING everywhere, silently (a 3-byte
            // class-hiding primitive). Rejecting the input at the single gate
            // makes the decode/encode pair a genuine bijection over every dex
            // that can load, and makes the smali "decode identifiers, don't
            // escape them" argument structural rather than incidental: no
            // multibyte sequence can decode to a structural character any more.
            u2 v3 = static_cast<u2>(((b & 0x0F) << 12) | ((b2 & 0x3F) << 6) | (b3 & 0x3F));
            if (v3 < 0x800) return Fail("string_data illegal MUTF-8 representation");
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
            const dex::InstructionFormat fmt = dex::GetFormatFromOpcode(op);

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
                // WHERE THE ARGUMENT REGISTERS LIVE IS FORMAT-DEPENDENT, and reading
                // d.arg[] for both formats is dexllm#58: 45cc (invoke-polymorphic,
                // the only non-35c varargs form) carries a SECOND index — proto@HHHH
                // — which DecodeInstruction parks in d.arg[4] (dex_bytecode.cc k45cc),
                // while its first argument register goes to d.vC. So the window was
                // SHIFTED BY ONE at every arity: vC unchecked at the front (0xFA's
                // flags carry no kVerifyRegC either), one slot too many at the end.
                // At A == 5 that extra slot IS the proto index, which is where the
                // shift stopped being cosmetic and REJECTED a spec-legal dex (an
                // AOSP dexter testdata dex, two sites, proto 82/91 vs 5 registers);
                // below 5 it read an unused nibble, which a compiler zeroes.
                // Corollary: the proto index used to be bounded here BY ACCIDENT and
                // now is bounded by nothing — consistent with the index-operand scope
                // below, and nothing dereferences it. 35c fills arg[0..vA-1]
                // with the registers and mirrors the first into vC, so it reads
                // straight. 4rcc takes the RANGE branch below and never touches arg[].
                // The branch is COMPLETE, not a heuristic: kVerifyVarArg[NonZero]
                // appears on exactly two formats in the slicer's own table — k35c
                // (8 opcodes) and k45cc (0xFA alone). A third would be a silent
                // hole, so tests/test_verifier_invoke_polymorphic.py re-derives
                // that enumeration from dex_instruction_list.h and fails on one.
                const u4 regs45[5] = {d.vC, d.arg[0], d.arg[1], d.arg[2], d.arg[3]};
                for (u4 k = 0; k < d.vA && k < 5; ++k) {
                    const u4 reg = (fmt == dex::k45cc) ? regs45[k] : d.arg[k];
                    if (!check_reg(reg)) return Fail("code: vararg register out of range");
                }
            }
            if (vf & (dex::kVerifyVarArgRange | dex::kVerifyVarArgRangeNonZero)) {
                // range regs vC .. vC+vA-1.
                if (d.vA > 0 &&
                    static_cast<uint64_t>(d.vC) + d.vA - 1 >= registers_size) {
                    return Fail("code: vararg-range register out of range");
                }
            }

            // Index operand — the kinds something dereferences. Out-of-table index
            // → reject so the core never asks the slicer for a nonexistent id.
            // `ridx` matches method_snapshot_builder's ResolveConstRef (vC for
            // k22c/k22cs, else vB).
            //
            // kIndexMethodAndProtoRef (invoke-polymorphic, 0xFA/0xFB) is bounded
            // HERE rather than in the default arm because dexllm#61 taught the
            // invoke collectors to read it: this comment used to say those
            // collectors "gate on the 0x6E-0x72 / 0x74-0x78 opcodes, so a consumer
            // that starts reading them must add the bound in the same change" —
            // dexllm#61 is that consumer. Without the bound a STRICT-verified dex
            // yields a call site whose callee_descriptor is empty (constructed: one
            // 0xFA's BBBB patched to 0xFFFF in method_handles.dex verifies valid and
            // `find_call_sites_from` reports the site with no callee). Only the
            // METHOD half is bounded; the proto index sits in arg[4], is not `ridx`,
            // and is still dereferenced by nothing.
            //
            // The PROTO half (arg[4], not `ridx`) has TWO readers now — dexllm#60's
            // smali arms, which render "<bad-proto-idx>" for an out-of-range index,
            // and its IR arms, which CANNOT signal that way (an unresolved proto
            // silently becomes the method's declaration). The second reader is why
            // it is bounded just above rather than left to the readers; the
            // asymmetry this comment used to describe did not survive it.
            //
            // kIndexMethodHandleRef stays in the default arm on the ORIGINAL
            // terms: nothing dereferences it (dexllm#66's smali arm renders only
            // a `method_handle@N` LABEL, which reads no table).
            //
            // kIndexCallSiteRef DOES have a reader since dexllm#67 —
            // `ResolveConstRef` resolves it and `DexItemCodeSource::GetCallSite`
            // walks the entry — so "nothing dereferences them" is no longer true
            // for it. The rule is unchanged and is satisfied AT THE READER, which
            // the rule permits: `GetCallSite` bounds `call_site_idx` against the
            // section size before forming any pointer, and every offset and index
            // inside the entry against the image and the id tables. It is left
            // here rather than bounded above because the section is optional (a
            // dex with no invoke-custom has no `call_site_ids` at all), so the
            // bound belongs where the section is looked up. The invoke GATES
            // still exclude 0xFC/0xFD, for the separate dexllm#61 reason that a
            // call-site index is not a method reference.
            //
            // kIndexProtoRef (const-method-type, 0xFF) DOES have a reader now —
            // dexllm#66 renders it through FormatProto — so this comment no longer
            // says "nothing reads them" for it. The rule is unchanged and is
            // satisfied at the READER, which the rule permits: FormatProto bounds
            // the index itself and yields the distinguishable `<bad-proto-idx>`,
            // and it is the ONLY reader. That is exactly where the polymorphic
            // proto stood before dexllm#60's IR half added a SECOND reader that
            // could not signal — which is what moved that one, and only that one,
            // to the gate. A future second reader of 0xFF's operand moves this one
            // too, in the same change.
            //
            // Same rule as before — a consumer that starts reading one bounds it in
            // the same change, here or at the reader.
            // dexllm#60 (IR half): the PROTO operand of a polymorphic invoke is now
            // read by a SECOND consumer — the IR builder — and unlike the smali
            // renderer it cannot yield a distinguishable value: an unresolvable
            // proto makes BuildMethodRef fall back to the method's DECLARATION,
            // and `MethodHandle.invoke` declares one Object parameter, so a
            // 4-argument call silently renders with ONE. That is the wrong-ANSWER
            // shape dexllm#61 bounded the method half for. Bounded here on the
            // same terms; `<bad-proto-idx>` is now unreachable on strict input,
            // exactly like `<bad-method-idx>`.
            if (fmt == dex::k45cc || fmt == dex::k4rcc) {
                if (d.arg[4] >= header_->proto_ids_size) {
                    return Fail("code: proto index out of range");
                }
            }

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
                case dex::kIndexMethodAndProtoRef:  // dexllm#61 — see above
                    if (ridx >= header_->method_ids_size) return Fail("code: method index out of range");
                    break;
                default:
                    // callsite/methodhandle/none — not dereferenced. proto is
                    // read by ONE reader that bounds it itself (dexllm#66, above).
                    break;
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
        // METHOD_HANDLE — ART :1204 (the `value_arg > 3` width cap) and :1212
        // (the index against NumMethodHandles()) arrive TOGETHER here, because
        // the shared `idx` lambda is both. Until dexllm#72 this arm was
        // `skip(arg + 1)`: it consumed the payload and checked neither half, so
        // it was the ONE arm where an EIGHT-byte "index" was gate-legal (an
        // asymmetry dexllm#71's lockstep guard had to be parametrised around)
        // and the index reached the readers unbounded.
        //
        // `method_handle_count_` is ART's NumMethodHandles(): the count lives
        // ONLY in the map (it is not a header field), so CheckMap carries it
        // forward — which is why porting this had to wait for the section
        // itself to be in scope, and why the ORDER of the two passes is load-
        // bearing (CheckMap runs before CheckIntraSection, where encoded values
        // are walked). 0 when the dex declares no method_handle section, which
        // is exactly ART (dex_file.cc :159 zero-inits num_method_handles_ and
        // :290 assigns it only from a kDexTypeMethodHandleItem map entry) and
        // means every 0x16 index on such a dex is rejected. That is not a
        // false-reject: it is what ART does with the same bytes — and it is
        // what retired tests/test_cache_init_failure.py's vehicle, which was
        // built on the belief that closing this at the gate WOULD be one.
        case 0x16: return idx(method_handle_count_, "encoded method_handle idx");
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
        case 0x1d:                                                                 // ANNOTATION
            if (arg != 0) return Fail("encoded annotation arg");
            return VerifyEncodedAnnotation(pp, depth);
        default: return Fail("encoded_value bad type code");
    }
}

// encoded_annotation (ART CheckEncodedAnnotation :1177) — a bare
// (uleb type_idx, uleb size, then `size` × (uleb name_idx, encoded_value)). The
// 0x1d value header above only wraps it when it is NESTED inside another value;
// annotation_item stores this form raw, exactly as encoded_array_item stores a
// bare array. `depth` is the CALLER's depth: elements recurse one deeper, so the
// kMaxDepth cap in VerifyEncodedValue bounds this walk too.
bool DexVerifier::VerifyEncodedAnnotation(const u1** pp, int depth) {
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

// ── annotations subtree (dexllm#56) ──────────────────────────────────────────
// Reached from class_def.annotations_off. Before this, that offset was checked by
// NOTHING — not that it is in range, and not that it points at an annotations_
// directory rather than at some other section — because annotations were listed
// out of scope on the grounds that the core lazy-parses them. It does parse them
// (Reader::ExtractAnnotations, off the class_def), so "lazy" meant "later", not
// "never", and a 4-byte repoint yielded a dex verify() called valid on which the
// slicer's ParseAnnotation walked off the end: SIGSEGV, which no catch(...) sees.
//
// The walk below covers EXACTLY what reader.cc dereferences, in the same order:
//   ExtractAnnotations      -> directory header, class_annotations_off, 3 lists
//   ParseField/MethodAnnotation -> each annotations_off -> ExtractAnnotationSet
//   ParseParamAnnotation    -> annotations_off -> ExtractAnnotationSetRefList
//   ExtractAnnotationSet    -> entries[i] -> ExtractAnnotationItem
//   ExtractAnnotationItem   -> visibility byte + ParseAnnotation (encoded_annotation)
// so a dex that passes cannot make that parser leave the image.
bool DexVerifier::AnnotationStructAt(u4 off, size_t sz, const char* who, const u1** out) {
    if ((off & 3u) != 0) return Fail(std::string(who) + ": misaligned offset");
    const u1* p = OffsetToPtr(off);
    if (p < begin_ || !CheckListSize(p, 1, sz, who)) return false;
    *out = p;
    return true;
}

// ART CheckIntraAnnotationsDirectoryItem :2111 + CheckInterAnnotationsDirectoryItem
// :3276 (see the declaration comment for why they fuse here).
bool DexVerifier::VerifyAnnotationsDirectory(u4 off) {
    if (!seen_ann_dir_.insert(off).second) return true;
    const u1* p;
    if (!AnnotationStructAt(off, sizeof(dex::AnnotationsDirectoryItem),
                            "annotations_directory", &p)) {
        return false;
    }
    const auto* dir = reinterpret_cast<const dex::AnnotationsDirectoryItem*>(p);
    // Only the CLASS annotations may be absent (ART :3283 guards this one on != 0,
    // and ExtractAnnotationSet(0) returns nullptr). The three per-member offsets
    // below may not — ART checks them unconditionally, and the slicer's
    // SLICER_CHECK_NE(annotations, nullptr) agrees.
    if (dir->class_annotations_off != 0 && !VerifyAnnotationSet(dir->class_annotations_off)) {
        return false;
    }

    // The three lists follow the header contiguously, in this order.
    const auto* fa = reinterpret_cast<const dex::FieldAnnotationsItem*>(dir + 1);
    if (!CheckListSize(fa, dir->fields_size, sizeof(dex::FieldAnnotationsItem),
                       "field_annotations list")) {
        return false;
    }
    u4 last = 0;
    for (u4 i = 0; i < dir->fields_size; ++i, ++fa) {
        if (!CheckIndex(fa->field_idx, header_->field_ids_size, "field annotation")) return false;
        if (i != 0 && last >= fa->field_idx) {
            return Fail("Out-of-order field_idx for annotation");
        }
        last = fa->field_idx;
        if (fa->annotations_off == 0) return Fail("field_annotation annotations_off is 0");
        if (!VerifyAnnotationSet(fa->annotations_off)) return false;
    }

    const auto* ma = reinterpret_cast<const dex::MethodAnnotationsItem*>(fa);
    if (!CheckListSize(ma, dir->methods_size, sizeof(dex::MethodAnnotationsItem),
                       "method_annotations list")) {
        return false;
    }
    last = 0;
    for (u4 i = 0; i < dir->methods_size; ++i, ++ma) {
        if (!CheckIndex(ma->method_idx, header_->method_ids_size, "method annotation")) return false;
        if (i != 0 && last >= ma->method_idx) {
            return Fail("Out-of-order method_idx for annotation");
        }
        last = ma->method_idx;
        if (ma->annotations_off == 0) return Fail("method_annotation annotations_off is 0");
        if (!VerifyAnnotationSet(ma->annotations_off)) return false;
    }

    const auto* pa = reinterpret_cast<const dex::ParameterAnnotationsItem*>(ma);
    if (!CheckListSize(pa, dir->parameters_size, sizeof(dex::ParameterAnnotationsItem),
                       "parameter_annotations list")) {
        return false;
    }
    last = 0;
    for (u4 i = 0; i < dir->parameters_size; ++i, ++pa) {
        if (!CheckIndex(pa->method_idx, header_->method_ids_size, "parameter annotation method")) {
            return false;
        }
        if (i != 0 && last >= pa->method_idx) {
            return Fail("Out-of-order method_idx for annotation");
        }
        last = pa->method_idx;
        // Non-zero is load-bearing here, not just ART parity: unlike
        // ExtractAnnotationSet, ExtractAnnotationSetRefList has NO zero guard, so
        // offset 0 reads the dex HEADER as a set_ref_list and takes its `size`
        // from the magic bytes.
        if (pa->annotations_off == 0) return Fail("parameter_annotation annotations_off is 0");
        if (!VerifyAnnotationSetRefList(pa->annotations_off)) return false;
    }
    return true;
}

// annotation_set_item — ART verifies it as CheckList(sizeof(uint32_t)) :2290,
// i.e. a u4 count then that many u4 offsets, each an annotation_item (:3186).
bool DexVerifier::VerifyAnnotationSet(u4 off) {
    if (!seen_ann_set_.insert(off).second) return true;
    const u1* p;
    if (!AnnotationStructAt(off, sizeof(dex::AnnotationSetItem), "annotation_set", &p)) {
        return false;
    }
    const auto* set = reinterpret_cast<const dex::AnnotationSetItem*>(p);
    if (!CheckListSize(set->entries, set->size, sizeof(u4), "annotation_set entries")) return false;
    for (u4 i = 0; i < set->size; ++i) {
        // ExtractAnnotationItem SLICER_CHECK_NE(offset, 0), and ART's
        // CheckOffsetToTypeMap can never resolve 0 either.
        if (set->entries[i] == 0) return Fail("annotation_set entry offset is 0");
        if (!VerifyAnnotationItem(set->entries[i])) return false;
    }
    return true;
}

// annotation_set_ref_list — ART CheckList(sizeof(AnnotationSetRefItem)) :2284.
bool DexVerifier::VerifyAnnotationSetRefList(u4 off) {
    if (!seen_ann_ref_.insert(off).second) return true;
    const u1* p;
    if (!AnnotationStructAt(off, sizeof(dex::AnnotationSetRefList), "annotation_set_ref_list",
                            &p)) {
        return false;
    }
    const auto* rl = reinterpret_cast<const dex::AnnotationSetRefList*>(p);
    if (!CheckListSize(rl->list, rl->size, sizeof(dex::AnnotationSetRefItem),
                       "annotation_set_ref_list entries")) {
        return false;
    }
    for (u4 i = 0; i < rl->size; ++i) {
        // 0 IS legal here and means "this parameter carries no annotations" —
        // ExtractAnnotationSetRefList skips such an entry. The asymmetry with the
        // three offsets above is the slicer's, and ART's.
        u4 e = rl->list[i].annotations_off;
        if (e != 0 && !VerifyAnnotationSet(e)) return false;
    }
    return true;
}

// ART CheckIntraAnnotationItem :2056 — a visibility byte then a bare
// encoded_annotation. Byte-aligned (ART's kDexTypeAnnotationItem is in the
// 1-align group), so this one does NOT go through AnnotationStructAt.
bool DexVerifier::VerifyAnnotationItem(u4 off) {
    if (!seen_ann_item_.insert(off).second) return true;
    const u1* p = OffsetToPtr(off);
    if (p < begin_ || !CheckListSize(p, 1, sizeof(u1), "annotation_item")) return false;
    const u1 vis = *p++;
    if (vis != dex::kVisibilityBuild && vis != dex::kVisibilityRuntime &&
        vis != dex::kVisibilitySystem) {
        return Fail("Bad annotation visibility");
    }
    return VerifyEncodedAnnotation(&p, 0);
}

// ── CheckIntraSection (ART :2450) ────────────────────────────────────────────
// Per-item internal structure: string_data(MUTF-8), type/proto/field/method id
// index validity, type_list, class_def + class_data + code_item (incl. VerifyInsns
// instruction-operand bounds). These are the items InitBaseCache and the decompile
// path dereference, plus the encoded_array and annotations subtrees the slicer's
// Reader walks off a class_def. Out of scope (see dex_verifier.h): debug_info,
// call_site/method_handle.
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
        if (cd->annotations_off != 0 && !VerifyAnnotationsDirectory(cd->annotations_off)) {
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
    // type_ids: per-item descriptor syntax (ART CheckInterTypeIdItem :2735), then
    // strictly increasing descriptor_idx (ART :2749).
    //
    // dexllm#23 — the per-item half was missing. Descriptors were validated only
    // where ANOTHER id table referenced them (field_id class/type, method_id
    // class, class_def class/super/interfaces), so a type used ONLY as a proto
    // return/parameter type or as an instruction operand (const-class,
    // new-instance, check-cast, new-array, …) could hold arbitrary bytes and
    // still pass. That is reachable in output: the smali renderer emits type
    // names unescaped, so a same-length payload carrying `"` and newline forged a
    // whole instruction line in a listing handed to an analyst or an LLM. ART has
    // no leading-char constraint here — any valid descriptor shape will do.
    for (u4 i = 0; i < header_->type_ids_size; ++i) {
        if (!VerifyTypeDescriptor(i, "type_id: invalid type descriptor",
                                  [](char) { return true; })) {
            return false;
        }
        if (i == 0) continue;
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

        if (cd->class_data_off != 0 && !CheckClassDataDefiners(cd->class_data_off, cls)) {
            return false;
        }
        defined_at[cls] = c;
    }
    return true;
}

bool DexVerifier::CheckClassDataDefiners(u4 off, u4 cls) {
    // The INDEX checks below are repeated from VerifyClassData (ART's helpers do
    // the same). Its OFFSET check is NOT repeated: `off` is a precondition, met
    // because CheckIntraSection runs first and calls VerifyClassData over the
    // same class_defs table with the same `!= 0` condition — including under
    // `lenient`, which gates only VerifyInsns. Nothing is unsafe if that ever
    // changed: `begin_ + u4` cannot underflow and ReadUleb bounds every byte
    // against EndOfFile, so a wild `off` ends in "class_data bad counts".
    const u1* p = OffsetToPtr(off);
    u4 sf, inf, dm, vm;
    if (!ReadUleb(&p, &sf) || !ReadUleb(&p, &inf) ||
        !ReadUleb(&p, &dm) || !ReadUleb(&p, &vm)) {
        return Fail("class_data bad counts");
    }
    // Each of the four lists restarts its delta chain at 0 (dex spec:
    // `field_idx_diff` / `method_idx_diff` are relative to the previous element
    // of the SAME list, the first being absolute).
    auto fields = [&](u4 n) -> bool {
        u4 idx = 0;
        for (u4 i = 0; i < n; ++i) {
            u4 diff, access;
            if (!ReadUleb(&p, &diff) || !ReadUleb(&p, &access)) {
                return Fail("class_data bad field");
            }
            idx += diff;
            if (idx >= header_->field_ids_size) {
                return Fail("class_data field idx out of range");
            }
            if (TableAt<dex::FieldId>(header_->field_ids_off, idx)->class_idx != cls) {
                return Fail("Mismatched defining class for class_data_item field");
            }
        }
        return true;
    };
    auto methods = [&](u4 n) -> bool {
        u4 idx = 0;
        for (u4 i = 0; i < n; ++i) {
            u4 diff, access, code_off;
            if (!ReadUleb(&p, &diff) || !ReadUleb(&p, &access) ||
                !ReadUleb(&p, &code_off)) {
                return Fail("class_data bad method");
            }
            idx += diff;
            if (idx >= header_->method_ids_size) {
                return Fail("class_data method idx out of range");
            }
            if (TableAt<dex::MethodId>(header_->method_ids_off, idx)->class_idx != cls) {
                return Fail("Mismatched defining class for class_data_item method");
            }
        }
        return true;
    };
    // An EMPTY class_data declares nothing, so there is nothing to mismatch —
    // ART notes such an item may even be shared between classes.
    return fields(sf) && fields(inf) && methods(dm) && methods(vm);
}

}  // namespace

DexVerifyResult VerifyDex(const u1* data, size_t size, bool check_insns,
                          size_t header_off, VerifyImageState* image) {
    try {
        DexVerifier v(data, size, header_off, check_insns, image);
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
