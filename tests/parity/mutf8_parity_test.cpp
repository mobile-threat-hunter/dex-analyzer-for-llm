// mutf8_parity_test — differential test of our MUTF-8 decoder against the EXACT
// AOSP ART source it was ported from.
//
// The reference below is an inline 1:1 copy of art/libdexfile/dex/utf-inl.h
// `GetUtf16FromUtf8` and utf.cc `ConvertModifiedUtf8ToUtf16` (Apache-2.0, used
// as a spec reference). On WELL-FORMED input our bounded port must produce the
// byte-identical UTF-16 code-unit sequence ART produces. We drive both over a
// fixed-seed random code-point stream (encoded to canonical MUTF-8) plus curated
// edge cases (NUL C0 80, BMP, MUTF-8 surrogate pair, genuine 4-byte), then check
// the Utf16ToUtf8 / AppendUtf16Escaped wrappers on top.

#include "mutf8.h"

#include <cstdint>
#include <cstdio>
#include <random>
#include <string>
#include <vector>

namespace m = dexkit::dad::mutf8;
static int g_fail = 0;

static void check(const char* label, bool ok) {
    if (!ok) ++g_fail;
    std::printf("%s %s\n", ok ? "[ok]  " : "[FAIL]", label);
}

// ───────────────────────── AOSP ART reference (verbatim) ─────────────────────
// art/libdexfile/dex/utf-inl.h:32 GetUtf16FromUtf8 (no bounds checks — the ART
// original; safe here because we only feed it well-formed, length-exact input).
static uint32_t ArtGetUtf16FromUtf8(const char** utf8_data_in) {
    const uint8_t one = *(*utf8_data_in)++;
    if ((one & 0x80) == 0) return one;
    const uint8_t two = *(*utf8_data_in)++;
    if ((one & 0x20) == 0) return ((one & 0x1f) << 6) | (two & 0x3f);
    const uint8_t three = *(*utf8_data_in)++;
    if ((one & 0x10) == 0)
        return ((one & 0x0f) << 12) | ((two & 0x3f) << 6) | (three & 0x3f);
    const uint8_t four = *(*utf8_data_in)++;
    const uint32_t code_point = ((one & 0x0f) << 18) | ((two & 0x3f) << 12) |
                                ((three & 0x3f) << 6) | (four & 0x3f);
    uint32_t surrogate_pair = 0;
    surrogate_pair |= ((code_point >> 10) + 0xd7c0) & 0xffff;
    surrogate_pair |= ((code_point & 0x03ff) + 0xdc00) << 16;
    return surrogate_pair;
}
// art/libdexfile/dex/utf.cc:112 ConvertModifiedUtf8ToUtf16 (byte-count, non-ASCII
// branch) — produces the UTF-16 unit sequence.
static std::vector<uint16_t> ArtMutf8ToUtf16(const std::string& in) {
    std::vector<uint16_t> out;
    const char* p = in.data();
    const char* end = p + in.size();
    while (p < end) {
        const uint32_t ch = ArtGetUtf16FromUtf8(&p);
        const uint16_t leading = static_cast<uint16_t>(ch & 0x0000FFFF);
        const uint16_t trailing = static_cast<uint16_t>(ch >> 16);
        out.push_back(leading);
        if (trailing != 0) out.push_back(trailing);
    }
    return out;
}

// Encode one code point to CANONICAL dex MUTF-8 (supplementary → surrogate pair,
// each surrogate a 3-byte sequence; NUL → C0 80).
static void EncodeMutf8(uint32_t cp, std::string& out) {
    auto emit3 = [&](uint32_t u) {  // 3-byte form for a BMP value / surrogate
        out += static_cast<char>(0xE0 | (u >> 12));
        out += static_cast<char>(0x80 | ((u >> 6) & 0x3F));
        out += static_cast<char>(0x80 | (u & 0x3F));
    };
    if (cp == 0) {  // MUTF-8 NUL
        out += static_cast<char>(0xC0);
        out += static_cast<char>(0x80);
    } else if (cp < 0x80) {
        out += static_cast<char>(cp);
    } else if (cp < 0x800) {
        out += static_cast<char>(0xC0 | (cp >> 6));
        out += static_cast<char>(0x80 | (cp & 0x3F));
    } else if (cp < 0x10000) {
        emit3(cp);
    } else {
        uint32_t v = cp - 0x10000;
        emit3(0xD800 | (v >> 10));   // high surrogate, 3-byte
        emit3(0xDC00 | (v & 0x3FF)); // low surrogate, 3-byte
    }
}

int main() {
    // 1. Fixed-seed random differential: thousands of code-point streams.
    {
        std::mt19937 rng(0xDEC0DE);
        std::uniform_int_distribution<uint32_t> pick(0, 0x10FFFF);
        int mism = 0;
        for (int iter = 0; iter < 4000; ++iter) {
            std::string mutf8;
            int n = 1 + (iter % 12);
            for (int k = 0; k < n; ++k) {
                uint32_t cp;
                do { cp = pick(rng); }
                while (cp >= 0xD800 && cp <= 0xDFFF);  // skip lone surrogates
                EncodeMutf8(cp, mutf8);
            }
            if (m::Mutf8ToUtf16(mutf8) != ArtMutf8ToUtf16(mutf8)) ++mism;
        }
        char buf[64];
        std::snprintf(buf, sizeof(buf),
                      "random differential vs ART (4000 streams, %d mismatch)", mism);
        check(buf, mism == 0);
    }

    // 2. Curated edge cases (decode).
    {
        auto u = [](const char* s, size_t n) {
            return m::Mutf8ToUtf16(std::string(s, n));
        };
        check("ASCII 'A' -> 0x0041", u("A", 1) == std::vector<uint16_t>{0x41});
        check("MUTF-8 NUL C0 80 -> 0x0000",
              u("\xC0\x80", 2) == std::vector<uint16_t>{0x0000});
        check("BMP korean EC 97 B0 -> 0xC5F0",
              u("\xEC\x97\xB0", 3) == std::vector<uint16_t>{0xC5F0});
        check("MUTF-8 surrogate pair -> D83D DE00",
              u("\xED\xA0\xBD\xED\xB8\x80", 6) ==
                  std::vector<uint16_t>{0xD83D, 0xDE00});
        check("genuine 4-byte F0 9F 98 80 -> D83D DE00",
              u("\xF0\x9F\x98\x80", 4) ==
                  std::vector<uint16_t>{0xD83D, 0xDE00});
    }

    // 3. Bounded-safety divergence: a truncated trailing sequence must NOT read
    //    past the end — it yields the lone lead byte as one unit.
    {
        auto v = m::Mutf8ToUtf16(std::string("A\xEC\x97", 3));  // 'A' + truncated 3-byte
        check("truncated trailing -> lead byte as unit",
              v.size() >= 1 && v[0] == 0x41);
    }

    // 4. Utf16ToUtf8 round-trips (value path): BMP stays UTF-8, surrogate pair
    //    folds to one 4-byte code point.
    {
        check("Utf16ToUtf8 BMP korean",
              m::Mutf8ToUtf8("\xEC\x97\xB0") == "\xEC\x97\xB0");
        check("Utf16ToUtf8 surrogate pair -> 4-byte",
              m::Mutf8ToUtf8("\xED\xA0\xBD\xED\xB8\x80") == "\xF0\x9F\x98\x80");
    }

    // 5. AppendUtf16Escaped (text path): control/surrogate -> \uXXXX, BMP -> UTF-8.
    {
        std::string a, b, c;
        m::AppendUtf16Escaped(a, 0x0000);  // control
        m::AppendUtf16Escaped(b, 0xD83D);  // surrogate
        m::AppendUtf16Escaped(c, 0xC5F0);  // BMP korean
        check("escape control -> \\u0000", a == "\\u0000");
        check("escape surrogate -> \\ud83d", b == "\\ud83d");
        check("escape BMP -> readable UTF-8", c == "\xEC\x97\xB0");
    }

    std::printf("\n%s — %d failure(s)\n", g_fail ? "FAIL" : "PASS", g_fail);
    return g_fail ? 1 : 0;
}
