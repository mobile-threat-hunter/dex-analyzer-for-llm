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

// dexllm#22 — the decoder the pybind boundary needs: like Mutf8ToUtf8 except that
// anything with no UTF-8 form (a LONE surrogate, a malformed/truncated sequence)
// collapses to U+FFFD instead of being emitted raw, so the result is ALWAYS valid
// UTF-8 and pybind11's strict str conversion cannot raise. Body moved verbatim
// from the binding's private DecodeMutf8ForPy so the smali renderer and the
// binding decode identically (an identifier must read the same in a listing and
// in list_classes()); the ASCII fast path is the only addition — identifiers are
// overwhelmingly ASCII and this now runs per identifier, not per method.
std::string Mutf8ToUtf8Lossy(std::string_view raw) {
    bool ascii = true;
    for (unsigned char c : raw) {
        if (c >= 0x80) {
            ascii = false;
            break;
        }
    }
    if (ascii) return std::string(raw);

    std::string out;
    out.reserve(raw.size());
    const uint8_t* p = reinterpret_cast<const uint8_t*>(raw.data());
    const uint8_t* end = p + raw.size();
    auto emit_cp = [&](uint32_t cp) {
        // Anything with no UTF-8 form becomes U+FFFD, so the "always valid UTF-8"
        // contract holds unconditionally: a lone surrogate, and (review-hardened)
        // a value above U+10FFFF, which the 4-byte branch below can still produce
        // from a malformed lead. Unreachable from a dex pool — VerifyMutf8 rejects
        // any lead >= 0xF0 in string_data — but this is a public codec entry with
        // an absolute promise, so it must not depend on its callers.
        if ((cp >= 0xD800 && cp <= 0xDFFF) || cp > 0x10FFFF) cp = 0xFFFD;
        if (cp < 0x10000) {
            AppendUtf8Bmp(out, cp);
        } else {
            out += static_cast<char>(0xF0 | (cp >> 18));
            out += static_cast<char>(0x80 | ((cp >> 12) & 0x3F));
            out += static_cast<char>(0x80 | ((cp >> 6) & 0x3F));
            out += static_cast<char>(0x80 | (cp & 0x3F));
        }
    };
    while (p < end) {
        uint8_t c = *p;
        if (c < 0x80) { out += static_cast<char>(c); ++p; continue; }
        uint32_t cp = 0; size_t n = 0;
        if ((c & 0xE0) == 0xC0) { cp = c & 0x1F; n = 2; }
        else if ((c & 0xF0) == 0xE0) { cp = c & 0x0F; n = 3; }
        else if ((c & 0xF8) == 0xF0) { cp = c & 0x07; n = 4; }
        else { emit_cp(0xFFFD); ++p; continue; }
        if (p + n > end) { emit_cp(0xFFFD); ++p; continue; }
        bool bad = false;
        for (size_t i = 1; i < n; ++i) {
            if ((p[i] & 0xC0) != 0x80) { bad = true; break; }
            cp = (cp << 6) | (p[i] & 0x3F);
        }
        if (bad) { emit_cp(0xFFFD); ++p; continue; }
        if (cp >= 0xD800 && cp <= 0xDBFF && p + n + 3 <= end &&
            (p[n] & 0xF0) == 0xE0 && (p[n + 1] & 0xC0) == 0x80 &&
            (p[n + 2] & 0xC0) == 0x80) {
            uint32_t lo = ((p[n] & 0x0F) << 12) | ((p[n + 1] & 0x3F) << 6) |
                          (p[n + 2] & 0x3F);
            if (lo >= 0xDC00 && lo <= 0xDFFF) {
                emit_cp(0x10000 + ((cp - 0xD800) << 10) + (lo - 0xDC00));
                p += n + 3;
                continue;
            }
        }
        emit_cp(cp);
        p += n;
    }
    return out;
}

std::string Utf8ToMutf8(std::string_view utf8) {
    // Fast path: MUTF-8 differs from UTF-8 only for NUL and for supplementary code
    // points (4-byte lead 0xF0-0xF4). Neither present → the bytes are already MUTF-8.
    bool needs = false;
    for (unsigned char c : utf8) {
        if (c == 0x00 || c >= 0xF0) {
            needs = true;
            break;
        }
    }
    if (!needs) return std::string(utf8);

    std::string out;
    out.reserve(utf8.size() + 8);
    const auto* p = reinterpret_cast<const uint8_t*>(utf8.data());
    const auto* end = p + utf8.size();
    while (p < end) {
        uint8_t c = *p;
        if (c == 0x00) {  // NUL → the two-byte MUTF-8 form
            out += static_cast<char>(0xC0);
            out += static_cast<char>(0x80);
            ++p;
        } else if (c < 0xF0) {  // ASCII / 2-byte / 3-byte: identical in both encodings
            out += static_cast<char>(c);
            ++p;
        } else if (c <= 0xF4 && p + 4 <= end && (p[1] & 0xC0) == 0x80 &&
                   (p[2] & 0xC0) == 0x80 && (p[3] & 0xC0) == 0x80 &&
                   ((static_cast<uint32_t>(c & 0x07u) << 18) |
                    (static_cast<uint32_t>(p[1] & 0x3Fu) << 12) |
                    (static_cast<uint32_t>(p[2] & 0x3Fu) << 6) |
                    static_cast<uint32_t>(p[3] & 0x3Fu)) >= 0x10000) {
            // A WELL-FORMED supplementary sequence → the surrogate PAIR, each half as
            // its own 3-byte sequence (CESU-8), which is how dex stores it. The lead
            // is restricted to F0-F4 and the value to >= 0x10000 on purpose: pybind
            // accepts `bytes` for these arguments, so malformed input DOES arrive
            // here, and a looser branch would SYNTHESISE bytes — an over-long
            // `F0 80 80 80` became a raw NUL (which no dex pool can contain), and
            // `F0 80 81 9E` became `^`, silently turning a Contains query into
            // StartWith. Anything not well-formed now falls through untouched, the
            // same "malformed passes through" posture the decoder takes.
            uint32_t cp = ((c & 0x07u) << 18) | ((p[1] & 0x3Fu) << 12) |
                          ((p[2] & 0x3Fu) << 6) | (p[3] & 0x3Fu);
            p += 4;
            cp -= 0x10000;
            AppendUtf8Bmp(out, static_cast<uint16_t>(0xD800 + (cp >> 10)));
            AppendUtf8Bmp(out, static_cast<uint16_t>(0xDC00 + (cp & 0x3FF)));
        } else {  // truncated / over-long / out-of-range: pass the byte through
            out += static_cast<char>(c);
            ++p;
        }
    }
    return out;
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
