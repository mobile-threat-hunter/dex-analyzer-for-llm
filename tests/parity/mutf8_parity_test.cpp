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
        // Real-corpus regression: U+DFFFD stored dex-canonically as two 3-byte
        // MUTF-8 sequences (a surrogate pair) must stay two units — verified
        // against the actual AOSP utf-inl.h source (docs/dexkit-vs-art-dex-handling.md).
        check("U+DFFFD pair ED AC BF ED BF BD -> DB3F DFFD",
              u("\xED\xAC\xBF\xED\xBF\xBD", 6) ==
                  std::vector<uint16_t>{0xDB3F, 0xDFFD});
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

    // 6. Utf8ToMutf8 (dexllm#19) — the query-encode direction. The property that
    //    matters for matching: encoding the DECODED form of a pool string must
    //    reproduce the pool bytes, so a caller can feed a returned string straight
    //    back into a byte-comparing matcher.
    {
        std::mt19937 rng(0xF19E19);
        std::uniform_int_distribution<uint32_t> pick(0, 0x10FFFF);
        int mism = 0;
        for (int iter = 0; iter < 4000; ++iter) {
            std::string pool;  // as the dex string pool would hold it
            int n = 1 + (iter % 12);
            for (int k = 0; k < n; ++k) {
                uint32_t cp;
                do { cp = pick(rng); }
                while (cp >= 0xD800 && cp <= 0xDFFF);  // lone surrogates: see below
                EncodeMutf8(cp, pool);
            }
            // pool --(what the API hands the caller)--> UTF-8 --(this)--> pool
            if (m::Utf8ToMutf8(m::Mutf8ToUtf8(pool)) != pool) ++mism;
        }
        char buf[80];
        std::snprintf(buf, sizeof(buf),
                      "round-trip pool->UTF-8->pool (4000 streams, %d mismatch)", mism);
        check(buf, mism == 0);

        // The two encodings that actually differ, explicitly.
        check("encode NUL -> C0 80", m::Utf8ToMutf8(std::string("\0", 1)) ==
                                         std::string("\xC0\x80", 2));
        check("encode astral -> surrogate PAIR (CESU-8), not 4-byte UTF-8",
              m::Utf8ToMutf8("\xF0\x9F\x98\x80") ==
                  std::string("\xED\xA0\xBD\xED\xB8\x80"));
        // Everything else must pass through untouched (the fast path).
        check("ASCII passthrough", m::Utf8ToMutf8("Exif") == "Exif");
        check("BMP passthrough (korean)", m::Utf8ToMutf8("\xEC\x97\xB0") == "\xEC\x97\xB0");
        check("empty passthrough", m::Utf8ToMutf8("").empty());
        // A truncated 4-byte sequence must not read past the end or hang.
        check("truncated 4-byte lead is passed through",
              m::Utf8ToMutf8(std::string("\xF0\x9F", 2)) == std::string("\xF0\x9F", 2));
        // pybind accepts `bytes` for the query arguments, so ill-formed input DOES
        // reach the encoder. It must pass such bytes through rather than synthesise
        // different valid ones — an over-long `F0 80 80 80` previously became a RAW
        // NUL (impossible in a dex pool) and `F0 80 81 9E` became `^`, which silently
        // turns a Contains query into StartWith.
        check("over-long 4-byte is passed through, not folded to NUL",
              m::Utf8ToMutf8(std::string("\xF0\x80\x80\x80", 4)) ==
                  std::string("\xF0\x80\x80\x80", 4));
        check("over-long 4-byte does not synthesise a regex anchor",
              m::Utf8ToMutf8(std::string("\xF0\x80\x81\x9E", 4)) ==
                  std::string("\xF0\x80\x81\x9E", 4));
        check("out-of-range lead (>F4) is passed through",
              m::Utf8ToMutf8(std::string("\xF5\x80\x80\x80", 4)) ==
                  std::string("\xF5\x80\x80\x80", 4));
        check("5-byte lead is not mis-decoded as 4-byte",
              m::Utf8ToMutf8(std::string("\xF8\x80\x80\x80", 4)) ==
                  std::string("\xF8\x80\x80\x80", 4));
        // A LONE surrogate round-trips through the CODEC (Utf16ToUtf8 keeps its raw
        // 3-byte form) — the encoder is not the lossy step. The residual of dexllm#19
        // sits one layer up, at the pybind boundary: DecodeMutf8ForPy must replace a
        // lone surrogate with U+FFFD because a Python `str` cannot hold one, and
        // U+FFFD cannot be encoded back. So such a pool string stays unmatchable
        // FROM PYTHON, while the C++ codec itself is a faithful inverse.
        check("lone surrogate round-trips through the codec itself",
              m::Utf8ToMutf8(m::Mutf8ToUtf8(std::string("\xED\xA0\xBD", 3))) ==
                  std::string("\xED\xA0\xBD", 3));
    }

    // 7. Mutf8ToUtf8Lossy (dexllm#22) — the decoder the pybind boundary uses. Its
    //    contract is absolute ("the result is ALWAYS valid UTF-8"), because a
    //    single invalid byte reaching py::str RAISES instead of returning a value.
    //    So assert the contract itself over arbitrary bytes, not just agreement
    //    with the ART decoder on well-formed input. It is a second, non-ART
    //    decoder in this module, which is exactly why it needs its own coverage.
    {
        auto valid_utf8 = [](const std::string& s) {
            const auto* p = reinterpret_cast<const uint8_t*>(s.data());
            const auto* e = p + s.size();
            while (p < e) {
                uint32_t cp;
                size_t n;
                if (*p < 0x80) { ++p; continue; }
                else if ((*p & 0xE0) == 0xC0) { cp = *p & 0x1F; n = 2; }
                else if ((*p & 0xF0) == 0xE0) { cp = *p & 0x0F; n = 3; }
                else if ((*p & 0xF8) == 0xF0) { cp = *p & 0x07; n = 4; }
                else return false;
                if (p + n > e) return false;
                for (size_t i = 1; i < n; ++i) {
                    if ((p[i] & 0xC0) != 0x80) return false;
                    cp = (cp << 6) | (p[i] & 0x3F);
                }
                if (cp > 0x10FFFF) return false;
                if (cp >= 0xD800 && cp <= 0xDFFF) return false;  // no raw surrogate
                p += n;
            }
            return true;
        };

        std::mt19937 rng(0x105591);
        std::uniform_int_distribution<int> byte(0, 255);
        int bad = 0;
        for (int iter = 0; iter < 4000; ++iter) {
            std::string raw;
            int n = 1 + (iter % 24);
            for (int k = 0; k < n; ++k) raw += static_cast<char>(byte(rng));
            if (!valid_utf8(m::Mutf8ToUtf8Lossy(raw))) ++bad;
        }
        char buf[92];
        std::snprintf(buf, sizeof(buf),
                      "Mutf8ToUtf8Lossy output is valid UTF-8 (4000 random streams, %d bad)",
                      bad);
        check(buf, bad == 0);

        // The specific shapes that could escape: an out-of-range 4-byte value and
        // a 0xF5-0xF7 lead both encode above U+10FFFF, which py::str rejects.
        check("F7 BF BF BF -> replacement, not a >U+10FFFF sequence",
              valid_utf8(m::Mutf8ToUtf8Lossy(std::string("\xF7\xBF\xBF\xBF", 4))));
        check("F4 90 80 80 (U+110000) -> replacement",
              valid_utf8(m::Mutf8ToUtf8Lossy(std::string("\xF4\x90\x80\x80", 4))));
        check("lone surrogate -> U+FFFD",
              m::Mutf8ToUtf8Lossy(std::string("\xED\xA0\xBD", 3)) == "\xEF\xBF\xBD");
        check("surrogate PAIR -> one code point",
              m::Mutf8ToUtf8Lossy(std::string("\xED\xA0\xBD\xED\xB8\x80", 6)) ==
                  "\xF0\x9F\x98\x80");
        check("ASCII fast path is the identity", m::Mutf8ToUtf8Lossy("Lcom/foo/Bar;") ==
                                                     "Lcom/foo/Bar;");
        // Agreement with the ART path on everything a VERIFIED dex can hold — the
        // property that keeps a rendered identifier and list_classes() consistent.
        {
            std::mt19937 r2(0x5EED22);
            std::uniform_int_distribution<uint32_t> pick(0, 0x10FFFF);
            int mism = 0;
            for (int iter = 0; iter < 2000; ++iter) {
                std::string pool;
                for (int k = 0, n = 1 + (iter % 10); k < n; ++k) {
                    uint32_t cp;
                    do { cp = pick(r2); }
                    while (cp >= 0xD800 && cp <= 0xDFFF);
                    EncodeMutf8(cp, pool);
                }
                if (m::Mutf8ToUtf8Lossy(pool) != m::Mutf8ToUtf8(pool)) ++mism;
            }
            char b2[96];
            std::snprintf(b2, sizeof(b2),
                          "Lossy == ART decode on verifier-legal input (2000 streams, %d mismatch)",
                          mism);
            check(b2, mism == 0);
        }
    }

    // 8. AppendUtf16AsIdentifier (dexllm#28) — the identifier renderer. It differs
    // from the per-unit AppendUtf16Escaped in EXACTLY one way: a valid surrogate
    // PAIR is combined into its readable code point. Everything else must be
    // byte-identical, which is what makes the whole-corpus a/b a property rather
    // than a one-off measurement (the corpus has no non-ASCII identifier at all,
    // so it cannot exercise this on its own).
    {
        auto per_unit = [](const std::vector<uint16_t>& u) {
            std::string s;
            for (uint16_t x : u) m::AppendUtf16Escaped(s, x);
            return s;
        };
        auto ident = [](const std::vector<uint16_t>& u) {
            std::string s;
            m::AppendUtf16AsIdentifier(s, u);
            return s;
        };
        // Same predicate section 7 uses: well-formed UTF-8 with NO raw surrogate.
        auto ok_utf8 = [](const std::string& s) {
            const auto* p = reinterpret_cast<const uint8_t*>(s.data());
            const auto* e = p + s.size();
            while (p < e) {
                uint32_t cp; size_t n;
                if (*p < 0x80) { ++p; continue; }
                else if ((*p & 0xE0) == 0xC0) { cp = *p & 0x1F; n = 2; }
                else if ((*p & 0xF0) == 0xE0) { cp = *p & 0x0F; n = 3; }
                else if ((*p & 0xF8) == 0xF0) { cp = *p & 0x07; n = 4; }
                else return false;
                if (p + n > e) return false;
                for (size_t i = 1; i < n; ++i) {
                    if ((p[i] & 0xC0) != 0x80) return false;
                    cp = (cp << 6) | (p[i] & 0x3F);
                }
                if (cp > 0x10FFFF) return false;
                if (cp >= 0xD800 && cp <= 0xDFFF) return false;
                p += n;
            }
            return true;
        };

        // 8a. A valid pair combines; the per-unit path escapes it.
        {
            std::vector<uint16_t> pair{0xD800, 0xDC00};
            check("identifier: a valid pair becomes the readable code point",
                  ident(pair) == "\xF0\x90\x80\x80");
            check("identifier: the per-unit path still escapes it",
                  per_unit(pair) == "\\ud800\\udc00");
        }

        // 8b. Everything a pair is NOT must render exactly as before. A lone
        // surrogate has no UTF-8 form, so it must keep escaping — the verifier
        // makes it unreachable through a name, so this is the only coverage.
        {
            const std::vector<std::vector<uint16_t>> cases = {
                {0xD800},                  // lone high
                {0xDC00},                  // lone low
                {0xDC00, 0xD800},          // low then high — NOT a pair
                {0xD800, 0xD800},          // high then high
                {0xD800, 0x0041},          // high then ASCII
                {0xD800, 0xD800, 0xDC00},  // lone high, then a real pair
                {0x0000}, {0x001F}, {0x0020}, {0x007F},
                {0xAC00}, {0x4E2D}, {0xFFFF},
                {},
            };
            int mism = 0;
            for (const auto& c : cases) {
                std::string a = ident(c), b = per_unit(c);
                // Identical unless the case contains a valid pair (only the last
                // two of the surrogate cases do).
                bool has_pair = false;
                for (size_t i = 0; i + 1 < c.size(); ++i)
                    if (c[i] >= 0xD800 && c[i] <= 0xDBFF &&
                        c[i + 1] >= 0xDC00 && c[i + 1] <= 0xDFFF) has_pair = true;
                if (!has_pair && a != b) ++mism;
                if (has_pair && a == b) ++mism;
            }
            check("identifier: differs from per-unit ONLY where a valid pair exists",
                  mism == 0);
        }

        // 8c. Randomised: over streams with no valid pair the two are identical,
        // and every output is well-formed UTF-8 (no raw surrogate can escape).
        {
            std::mt19937 r(0x1DEA28);
            std::uniform_int_distribution<int> len(0, 12);
            std::uniform_int_distribution<uint32_t> unit(0, 0xFFFF);
            int mism = 0, invalid = 0, pairs = 0;
            for (int iter = 0; iter < 20000; ++iter) {
                std::vector<uint16_t> u;
                for (int k = 0, n = len(r); k < n; ++k)
                    u.push_back(static_cast<uint16_t>(unit(r)));
                bool has_pair = false;
                for (size_t i = 0; i + 1 < u.size(); ++i)
                    if (u[i] >= 0xD800 && u[i] <= 0xDBFF &&
                        u[i + 1] >= 0xDC00 && u[i + 1] <= 0xDFFF) has_pair = true;
                const std::string a = ident(u);
                if (has_pair) { ++pairs; } else if (a != per_unit(u)) { ++mism; }
                if (!ok_utf8(a)) ++invalid;
            }
            char b[128];
            std::snprintf(b, sizeof(b),
                          "identifier: byte-identical on no-pair streams (20000, %d mismatch, "
                          "%d with a pair, %d invalid UTF-8)", mism, pairs, invalid);
            check(b, mism == 0 && invalid == 0 && pairs > 0);
        }
    }

    std::printf("\n%s — %d failure(s)\n", g_fail ? "FAIL" : "PASS", g_fail);
    return g_fail ? 1 : 0;
}
