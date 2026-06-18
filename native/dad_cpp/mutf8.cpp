// mutf8.cpp — MUTF-8 decode ported 1:1 from AOSP ART.
// Reference: art/libdexfile/dex/utf-inl.h (GetUtf16FromUtf8,
// GetLeadingUtf16Char, GetTrailingUtf16Char) and utf.cc
// (ConvertModifiedUtf8ToUtf16). AOSP is a spec reference, not a runtime dep.

#include "mutf8.h"

#include <cstdio>

namespace dexkit::dad::mutf8 {

namespace {

// ART utf-inl.h:24 GetTrailingUtf16Char — high 16 bits of the maybe-pair.
inline uint16_t GetTrailingUtf16Char(uint32_t maybe_pair) {
    return static_cast<uint16_t>(maybe_pair >> 16);
}
// ART utf-inl.h:28 GetLeadingUtf16Char — low 16 bits of the maybe-pair.
inline uint16_t GetLeadingUtf16Char(uint32_t maybe_pair) {
    return static_cast<uint16_t>(maybe_pair & 0x0000FFFF);
}

// ART utf-inl.h:32 GetUtf16FromUtf8 — bounded port.
//
// ART advances `*data` past one MUTF-8 sequence and returns either one UTF-16
// unit (in the low 16 bits, trailing == 0) or a surrogate pair (leading in low,
// trailing in high). ART reads continuation bytes without bounds checks because
// its input is NUL-terminated and structurally valid; we are length-delimited,
// so we additionally take `end` and validate. On a truncated or malformed
// sequence we consume ONE byte and return it as a lone unit — the caller (an
// escape/encode wrapper) renders it safely — instead of reading past `end`.
//
// The decode arithmetic below (1/2/3-byte assembly and the 4-byte→surrogate-pair
// split at utf-inl.h:59-67) is ART 1:1.
inline uint32_t GetUtf16FromUtf8(const uint8_t** data, const uint8_t* end) {
    const uint8_t one = *(*data)++;
    if ((one & 0x80) == 0) {
        return one;  // one-byte encoding
    }
    // Helper: a valid continuation byte exists at the cursor.
    auto cont = [&]() -> bool { return *data < end && (**data & 0xC0) == 0x80; };

    if (!cont()) return one;  // truncated/invalid → lone byte (divergence)
    const uint8_t two = *(*data)++;
    if ((one & 0x20) == 0) {
        return ((one & 0x1f) << 6) | (two & 0x3f);  // two-byte encoding
    }

    if (!cont()) return one;
    const uint8_t three = *(*data)++;
    if ((one & 0x10) == 0) {
        return ((one & 0x0f) << 12) | ((two & 0x3f) << 6) | (three & 0x3f);
    }

    // Four-byte encoding → surrogate pair (ART utf-inl.h:50-69).
    if (!cont()) return one;
    const uint8_t four = *(*data)++;
    const uint32_t code_point = ((one & 0x0f) << 18) | ((two & 0x3f) << 12)
                              | ((three & 0x3f) << 6) | (four & 0x3f);
    uint32_t surrogate_pair = 0;
    surrogate_pair |= ((code_point >> 10) + 0xd7c0) & 0xffff;
    surrogate_pair |= ((code_point & 0x03ff) + 0xdc00) << 16;
    return surrogate_pair;
}

}  // namespace

// ART utf.cc:95 ConvertModifiedUtf8ToUtf16 (byte-count variant) — bounded.
std::vector<uint16_t> Mutf8ToUtf16(std::string_view raw) {
    std::vector<uint16_t> units;
    units.reserve(raw.size());
    const uint8_t* p = reinterpret_cast<const uint8_t*>(raw.data());
    const uint8_t* end = p + raw.size();
    while (p < end) {
        const uint32_t ch = GetUtf16FromUtf8(&p, end);
        const uint16_t leading = GetLeadingUtf16Char(ch);
        const uint16_t trailing = GetTrailingUtf16Char(ch);
        units.push_back(leading);
        if (trailing != 0) {
            units.push_back(trailing);
        }
    }
    return units;
}

namespace {
// Append one BMP code point (< 0x10000) as UTF-8.
inline void AppendUtf8Bmp(std::string& out, uint32_t cp) {
    if (cp < 0x80) {
        out += static_cast<char>(cp);
    } else if (cp < 0x800) {
        out += static_cast<char>(0xC0 | (cp >> 6));
        out += static_cast<char>(0x80 | (cp & 0x3F));
    } else {
        out += static_cast<char>(0xE0 | (cp >> 12));
        out += static_cast<char>(0x80 | ((cp >> 6) & 0x3F));
        out += static_cast<char>(0x80 | (cp & 0x3F));
    }
}
}  // namespace

std::string Utf16ToUtf8(const std::vector<uint16_t>& units) {
    std::string out;
    out.reserve(units.size());
    for (size_t i = 0; i < units.size(); ++i) {
        const uint16_t u = units[i];
        // Combine a valid high+low surrogate pair into one 4-byte code point.
        if (u >= 0xD800 && u <= 0xDBFF && i + 1 < units.size() &&
            units[i + 1] >= 0xDC00 && units[i + 1] <= 0xDFFF) {
            const uint32_t cp =
                0x10000 + ((u - 0xD800) << 10) + (units[i + 1] - 0xDC00);
            out += static_cast<char>(0xF0 | (cp >> 18));
            out += static_cast<char>(0x80 | ((cp >> 12) & 0x3F));
            out += static_cast<char>(0x80 | ((cp >> 6) & 0x3F));
            out += static_cast<char>(0x80 | (cp & 0x3F));
            ++i;
            continue;
        }
        // Lone surrogate or BMP unit: emit its 1-3 byte form (a lone surrogate
        // yields a 3-byte sequence, preserving the historical dast behavior).
        AppendUtf8Bmp(out, u);
    }
    return out;
}

std::string Mutf8ToUtf8(std::string_view raw) {
    return Utf16ToUtf8(Mutf8ToUtf16(raw));
}

void AppendUtf16Escaped(std::string& out, uint16_t unit) {
    if (unit < 0x20 || (unit >= 0xD800 && unit <= 0xDFFF)) {
        char buf[8];
        std::snprintf(buf, sizeof(buf), "\\u%04x", unit);
        out += buf;
    } else {
        AppendUtf8Bmp(out, unit);
    }
}

}  // namespace dexkit::dad::mutf8
