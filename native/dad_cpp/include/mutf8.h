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

// MUTF-8 → standard UTF-8, LOSSY where UTF-8 has no form: a lone surrogate and a
// malformed/truncated sequence both become U+FFFD (Mutf8ToUtf8 emits them raw,
// which is NOT valid UTF-8). Use this at any boundary that hands bytes to
// pybind11's strict `str` conversion — a raw pool string reaching it unchanged
// RAISES UnicodeDecodeError instead of returning a value (dexllm#22). It is the
// exact inverse of Utf8ToMutf8 for everything a verified dex can hold: a
// surrogate PAIR (supplementary code point) round-trips, so a descriptor decoded
// on the way out and re-encoded on the way in still finds its class.
std::string Mutf8ToUtf8Lossy(std::string_view raw);

// Standard UTF-8 → MUTF-8: the INVERSE direction, for turning a caller-supplied
// query (a Python `str`, which pybind11 hands over as UTF-8) into the bytes the dex
// string pool actually holds, so a byte-comparing matcher can find it. Only two
// things change — NUL becomes `C0 80`, and a supplementary code point's 4-byte UTF-8
// form becomes the two 3-byte surrogate halves — so ASCII and BMP text pass through
// untouched (and the implementation returns the input unchanged when it contains
// neither, which is the overwhelming majority).
//
// Every string a LOADABLE dex can hold round-trips: `Utf8ToMutf8(Mutf8ToUtf8(x)) == x`
// for every verifier-legal pool string, which is what makes the decode/encode pairs at
// the binding genuine bijections. Both residuals dexllm#19 recorded here are now closed,
// for different reasons — one at the verifier, one at the boundary — and each is kept
// below because the reasoning is what stops them being reintroduced:
//   * a LONE surrogate — NO LONGER A RESIDUAL (dexllm#29). The codec always
//     round-tripped it (Utf16ToUtf8 keeps the raw 3-byte form, and this function's
//     fast path passes it through); the loss was pybind11's STRICT UTF-8 codec on
//     both sides of the boundary, which rejects an unpaired surrogate on the way in
//     and forced the U+FFFD replacement on the way out. The binding now does those
//     two conversions itself with CPython's `surrogatepass` handler for string
//     CONTENT, so a literal carrying one round-trips. Identifiers keep the lossy
//     decode: the verifier rejects a lone surrogate in a NAME, so the case cannot
//     arise there.
//   * a non-NUL OVERLONG encoding (`C0 81`, `E0 80 81`, …). NO LONGER REACHABLE:
//     VerifyMutf8 used to accept these — documented as "ART does the same", which
//     was simply wrong (ART's CheckIntraStringDataItem rejects both forms as an
//     "Illegal representation", dex_file_verifier.cc:1897/:1922) — and the two
//     checks are now ported, so such a dex does not load at all. That is what
//     makes the identifier decode/encode pair (dexllm#22) a genuine bijection:
//     canonical re-encoding cannot reproduce an overlong, so leaving it loadable
//     meant an identifier that enumerated fine and then resolved to nothing.
// Malformed input bytes are passed through unchanged (the decoder's posture): pybind
// accepts `bytes` for the query arguments, so ill-formed input does reach here and
// must not be silently rewritten into different, valid bytes.
std::string Utf8ToMutf8(std::string_view utf8);

// Append one UTF-16 code unit to `out` as Java SOURCE TEXT: a control char
// (< 0x20) or a surrogate (0xD800–0xDFFF) becomes a `\uXXXX` escape — the only
// valid, pybind11-decodable text form — and any other BMP unit becomes readable
// UTF-8 (so 연결 / 中文 / identifiers stay legible). A supplementary char,
// already split into a surrogate pair by Mutf8ToUtf16, is therefore emitted as
// `😀` — exactly the pair ART keeps in memory.
void AppendUtf16Escaped(std::string& out, uint16_t unit);

// Append a whole UTF-16 run as an IDENTIFIER in Java source text (dexllm#28).
// Same rules as AppendUtf16Escaped except that a VALID surrogate pair is combined
// into its code point and emitted readably, so `𐀀` renders as `𐀀` rather than as
// `𐀀`. A lone surrogate and a control char still escape.
//
// The split is deliberate and is the scope of the ART code-unit-fidelity claim:
// a string LITERAL is `mirror::String` CONTENT, where reproducing ART's exact
// units is the point, and it keeps the per-unit escaper. An identifier is a
// source SYMBOL, not string content — and the code-unit rendering made the same
// class read two ways across the Java, smali and list_classes() views, which
// breaks correlation for the analyst/LLM consuming them side by side. It was also
// arbitrary: a BMP identifier (`한`) already rendered readably, surviving by unit
// count rather than by rule.
void AppendUtf16AsIdentifier(std::string& out, const std::vector<uint16_t>& units);

}  // namespace dexkit::dad::mutf8

#endif  // DEXKIT_DAD_MUTF8_H_
