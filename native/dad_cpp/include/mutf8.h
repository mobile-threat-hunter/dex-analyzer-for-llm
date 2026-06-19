// mutf8.h — MUTF-8 (dex modified UTF-8) decode, ported 1:1 from AOSP ART.
//
// Dex strings and identifiers are MUTF-8: NUL is encoded as the two bytes
// `C0 80`, and a supplementary (astral) code point is encoded as a SURROGATE
// PAIR — two independent 3-byte `0xED…` sequences — not a single 4-byte UTF-8
// sequence. ART decodes this into a UTF-16 `mirror::String` (see
// art/libdexfile/dex/utf-inl.h `GetUtf16FromUtf8` and utf.cc
// `ConvertModifiedUtf8ToUtf16`). To make our decompiled text carry the EXACT
// same code units ART sees, the single decoder here is a faithful port of that
// ART logic; the three call sites (writer's string escaper, decompiler's
// whole-output sanitizer, dast's AST string value) sit on top of it.
//
// AOSP is used here as a SPEC REFERENCE, not a runtime dependency (same posture
// as the DexFileVerifier port). The decode math is ART 1:1 with `// ART :NNNN`
// anchors in mutf8.cpp; the one deliberate divergence is bounds safety — ART's
// `GetUtf16FromUtf8` reads continuation bytes from a NUL-terminated, structurally
// valid stream without bounds checks, whereas we run on length-delimited input
// and validate defensively (a truncated/malformed sequence yields the lead byte
// as a lone code unit rather than reading past the end).

#ifndef DEXKIT_DAD_MUTF8_H_
#define DEXKIT_DAD_MUTF8_H_

#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

namespace dexkit::dad::mutf8 {

// Decode MUTF-8 bytes into UTF-16 code units, exactly as ART builds a
// mirror::String. A 1/2/3-byte sequence yields one unit; a (non-canonical for
// dex) genuine 4-byte sequence yields a surrogate PAIR (two units). A MUTF-8
// surrogate-pair encoding (two 3-byte sequences) naturally yields the same two
// surrogate units, one per sequence. A malformed/truncated lead byte yields
// that raw byte as one unit (the caller decides how to render it).
std::vector<uint16_t> Mutf8ToUtf16(std::string_view raw);

// Re-encode UTF-16 code units as standard UTF-8, combining a valid surrogate
// pair into one 4-byte code point (the in-memory code point Python's str holds).
// A lone surrogate is emitted as its raw 3-byte form (preserving the historical
// dast behavior). Used by the AST string-value path, which needs the decoded
// VALUE, not Java source text.
std::string Utf16ToUtf8(const std::vector<uint16_t>& units);

// Convenience: MUTF-8 → standard UTF-8 (Mutf8ToUtf16 ∘ Utf16ToUtf8).
std::string Mutf8ToUtf8(std::string_view raw);

// Append one UTF-16 code unit to `out` as Java SOURCE TEXT: a Unicode CONTROL
// char (category Cc — C0 0x00–0x1F, DEL 0x7F, C1 0x80–0x9F) or a surrogate
// (0xD800–0xDFFF) becomes a `\uXXXX` escape — the only valid, pybind11-decodable
// text form — and any other BMP unit becomes readable UTF-8 (so 연결 / 中文 /
// identifiers stay legible). Escaping the C1 range matters for binary blobs
// stored as strings (e.g. an embedded DER certificate), where raw C1 bytes are
// invisible and make the literal look truncated. A supplementary char, already
// split into a surrogate pair by Mutf8ToUtf16, is emitted as `😀`.
void AppendUtf16Escaped(std::string& out, uint16_t unit);

}  // namespace dexkit::dad::mutf8

#endif  // DEXKIT_DAD_MUTF8_H_
