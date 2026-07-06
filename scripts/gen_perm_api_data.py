#!/usr/bin/env python3
"""Codegen: embed the full permission→API table (all levels) into a C++ header.

Issue #13/#14 — the WASM binding needs the permission-caller analysis with the AOSP
data BUNDLED (single source of truth = the engine's ``src/dexllm/data``). Rather
than re-implement the intricate Java/Kotlin signature normalisation in C++, we run
the EXISTING Python normaliser (``dangerous_api._parse_api`` / ``_param_simple`` /
``_overload_index``) here at build time and emit a header with the dataset already
reduced to ``(perm, class_dotted, method, simple-param-types)`` plus the overload
arity map. The C++ join (``native/core_ext/analysis.cpp``) then only has to parse
Dalvik protos (simple) and compare — the hard normalisation is done once, in one
place, by the same code the Python path uses.

Regenerate after src/dexllm/data/perm_api.json changes (via scripts/gen_perm_data.py):
    python scripts/gen_perm_api_data.py
The generated header is committed (checked in) so the build needs no Python.
"""
from __future__ import annotations

import pathlib

from dexllm.dangerous_api import (
    _load_full_map,
    _load_levels,
    _overload_index,
    _parse_api,
)

OUT = (
    pathlib.Path(__file__).resolve().parent.parent
    / "native"
    / "core_ext"
    / "gen"
    / "perm_api_data.h"
)


# Blob delimiters (ASCII control chars that never appear in Java/Kotlin signatures
# or simple param-type names — all printable ASCII). RS between entries, FS between
# an entry's fields, PS between an entry's param types (or an overload's arity pairs).
RS, FS, PS = "\x1e", "\x1f", "\x1d"


def _cpp_str(s: str) -> str:
    return '"' + s.replace("\\", "\\\\").replace('"', '\\"') + '"'


def _cpp_escape_blob(s: str) -> str:
    """Escape a blob chunk into a C++ string-literal body, operating on the string's
    UTF-8 BYTES (0-255) — so the decoded literal is the exact byte sequence the old
    `_cpp_str` + UTF-8 file write produced (a non-ASCII char's multi-byte UTF-8 is
    reproduced byte-for-byte), keeping the table byte-identical AND correct for any
    Unicode. Delimiter bytes RS/FS/PS and any non-printable become FIXED 3-digit
    octal (`\\NNN`, max `\\377`) — 3 digits is unambiguous (a C++ octal escape reads
    at most 3, so a following data digit can't be absorbed); `"`/`\\` are escaped;
    printable ASCII passes through. Working on bytes (not codepoints) also avoids the
    `\\10000` 5-digit misparse a codepoint > 0o777 would produce."""
    out = []
    for b in s.encode("utf-8"):
        if b == 0x1E:      # RS
            out.append("\\036")
        elif b == 0x1F:    # FS
            out.append("\\037")
        elif b == 0x1D:    # PS
            out.append("\\035")
        elif b == 0x22:    # "
            out.append('\\"')
        elif b == 0x5C:    # backslash
            out.append("\\\\")
        elif 0x20 <= b <= 0x7E:
            out.append(chr(b))
        else:              # control / any UTF-8 continuation or lead byte (0x80+)
            out.append(f"\\{b:03o}")
    return "".join(out)


def _emit_blob(lines: list, name: str, records: list, byte_budget: int = 4000) -> None:
    """Emit `static const char <name>[] = "..." "...";` — the records RS-joined,
    split into adjacent string literals (C++ concatenates them) at RECORD boundaries
    so no escape sequence is ever split. One passive data segment at link time — no
    global constructors / relocations (the whole point vs the old initializer list).
    Chunked by RAW byte budget (not record count) so each emitted literal stays well
    under MSVC's 16380-byte-per-literal cap (C2026) for the deferred Windows port —
    gcc/clang/emscripten have no such limit."""
    lines.append(f"static const char {name}[] =")
    if not records:
        lines.append('    "";')
        return
    chunks: list[list[str]] = []
    cur: list[str] = []
    cur_bytes = 0
    for rec in records:
        rb = len(rec.encode("utf-8")) + 1  # +1 for the RS separator
        if cur and cur_bytes + rb > byte_budget:
            chunks.append(cur)
            cur, cur_bytes = [], 0
        cur.append(rec)
        cur_bytes += rb
    if cur:
        chunks.append(cur)
    for gi, group in enumerate(chunks):
        raw = RS.join(group)
        if gi != len(chunks) - 1:
            raw += RS  # separator to the next chunk's first record
        term = ";" if gi == len(chunks) - 1 else ""
        lines.append(f'    "{_cpp_escape_blob(raw)}"{term}')


def _decode_cpp_literal(esc: str) -> bytes:
    """Decode a C++ string-literal body (as the compiler would) back to bytes —
    resolving `\\NNN` octal (≤3 digits), `\\"`, `\\\\`, and raw chars. The inverse of
    _cpp_escape_blob; used only by the build-time round-trip self-check."""
    out = bytearray()
    i, n = 0, len(esc)
    while i < n:
        c = esc[i]
        if c == "\\":
            nxt = esc[i + 1]
            if nxt == '"':
                out.append(0x22); i += 2
            elif nxt == "\\":
                out.append(0x5C); i += 2
            elif nxt in "01234567":
                j, k = i + 1, 0
                while j < n and k < 3 and esc[j] in "01234567":
                    j += 1; k += 1
                out.append(int(esc[i + 1 : j], 8) & 0xFF); i = j
            else:  # not emitted by _cpp_escape_blob
                out.append(ord(nxt)); i += 2
        else:
            out.append(ord(c)); i += 1
    return bytes(out)


def _roundtrip_records(records: list) -> list:
    """Simulate the FULL C++ path — compiler decode of the emitted literal, then the
    runtime BlobSplit(RS)/BlobSplit(FS) parse — and return the reconstructed field
    lists (str). Chunk boundaries are irrelevant: adjacent C++ literals concatenate to
    the same bytes as one literal, so escaping the RS-joined blob whole is faithful.
    Asserting the result reconstructs the source makes "byte-identical to the old
    initializer table" a BUILD-ENFORCED invariant (catches non-ASCII escape drift, the
    lone-empty-param arity collapse, and any future field-shape bug), not merely an
    empirical corpus property."""
    blob = RS.join(records)
    decoded = _decode_cpp_literal(_cpp_escape_blob(blob))
    assert decoded == blob.encode("utf-8"), "escape/decode is not byte-identical"
    return [[f.decode("utf-8") for f in rec.split(b"\x1f")] for rec in decoded.split(b"\x1e")]


def main() -> None:
    table = _load_full_map(None)  # bundled FULL perm→API map (all levels, issue #14)
    levels = _load_levels(None)  # perm → protection-level bucket
    # Lock the ordering contract (adversarial-review): the C++ join returns groups
    # in this iteration order, while the Python API returns them in the bundled
    # JSON's insertion order. They agree ONLY while the JSON is perm-sorted; assert
    # it here so a future unsorted edit fails the codegen loudly instead of silently
    # diverging the two paths' group order.
    keys = list(table)
    assert keys == sorted(keys), (
        "perm_api.json must be sorted by permission key so the C++ and Python group "
        "orders match; re-run scripts/gen_perm_data.py."
    )
    overloads = _overload_index(table)

    # Flatten to method-call entries only (field/constant entries — types is None —
    # can never match a call ref, so they are dropped here, matching the Python
    # join which skips them). Each entry carries its permission's level bucket.
    entries: list[tuple[str, str, str, str, str, tuple[str, ...]]] = []
    for perm in sorted(table):
        level = levels.get(perm, "other")
        for sig in table[perm]:
            cls, method, types = _parse_api(sig)
            if types is None:
                continue
            entries.append((perm, level, cls, method, sig, types))

    # Build the two flat blobs. Assert no payload contains a delimiter (would
    # corrupt the parse) — Java sigs / simple type names are all printable ASCII.
    ctrl = (RS, FS, PS)

    def _clean(s: str, where: str) -> str:
        assert not any(c in s for c in ctrl), f"delimiter char in {where}: {s!r}"
        return s

    perm_records: list[str] = []
    for perm, level, cls, method, sig, types in entries:
        params = PS.join(_clean(t, "param") for t in types)
        fields = [
            _clean(perm, "perm"),
            _clean(level, "level"),
            _clean(cls, "cls"),
            _clean(method, "method"),
            _clean(sig, "sig"),
            params,
        ]
        perm_records.append(FS.join(fields))

    overload_records: list[str] = []
    for (cls, method), arity in sorted(overloads.items()):
        pairs = PS.join(f"{a}:{c}" for a, c in sorted(arity.items()))
        overload_records.append(
            FS.join([_clean(cls, "ov-cls"), _clean(method, "ov-method"), pairs])
        )

    # BUILD-ENFORCED round-trip: decode the emitted literals + run the generated
    # parser (simulated) and assert it reconstructs `entries` / `overloads` EXACTLY.
    # This is what makes "byte-identical to the old initializer table" a guarantee of
    # the encoding, not just an empirical corpus property — it fails loudly at codegen
    # time on a non-ASCII escape drift or the lone-empty-param `('',)` arity collapse.
    pr = _roundtrip_records(perm_records)
    assert len(pr) == len(entries), (len(pr), len(entries))
    for got, (perm, level, cls, method, sig, types) in zip(pr, entries):
        got_types = tuple(got[5].split(PS)) if len(got) > 5 and got[5] != "" else ()
        assert len(got) >= 6 and (
            got[0], got[1], got[2], got[3], got[4], got_types
        ) == (perm, level, cls, method, sig, tuple(types)), (
            f"perm-entry round-trip mismatch (encoding cannot represent this row "
            f"faithfully — e.g. a lone empty param): {sig!r}"
        )
    orr = _roundtrip_records(overload_records)
    exp_ov = sorted(overloads.items())
    assert len(orr) == len(exp_ov), (len(orr), len(exp_ov))
    for got, ((cls, method), arity) in zip(orr, exp_ov):
        got_arity: dict[int, int] = {}
        if len(got) > 2 and got[2] != "":
            for pair in got[2].split(PS):
                a, c = pair.split(":")
                got_arity[int(a)] = int(c)
        assert len(got) >= 3 and (got[0], got[1], got_arity) == (
            cls,
            method,
            dict(sorted(arity.items())),
        ), f"overload round-trip mismatch: {cls}#{method}"

    lines: list[str] = []
    lines.append("// GENERATED by scripts/gen_perm_api_data.py — DO NOT EDIT.")
    lines.append(
        "// Source: src/dexllm/data/perm_api.json + perm_levels.json (full AOSP surface)."
    )
    lines.append("//")
    lines.append(
        "// The dataset's Java/Kotlin signatures are pre-normalised to simple param"
    )
    lines.append(
        "// types by the SAME code the Python API uses (dangerous_api._parse_api);"
    )
    lines.append(
        "// the C++ join only parses Dalvik protos + compares. See the codegen doc."
    )
    lines.append("//")
    lines.append(
        "// The table is emitted as a flat delimited BLOB (one string literal =\n"
        "// one passive data segment) parsed once at first use, NOT as ~5k C++\n"
        "// aggregate initializers — that form drove Emscripten wasm-opt into a\n"
        "// ~45GB / multi-hour blowup (issue #15). Delimiters: RS(\\036) between\n"
        "// entries, FS(\\037) between fields, PS(\\035) between an entry's param\n"
        "// types / an overload's arity pairs. Byte-identical table to the old form."
    )
    lines.append("#pragma once")
    lines.append("#include <map>")
    lines.append("#include <string>")
    lines.append("#include <string_view>")
    lines.append("#include <utility>")
    lines.append("#include <vector>")
    lines.append("")
    lines.append("namespace dexkit::ext::gen {")
    lines.append("")
    lines.append("struct PermApiEntry {")
    lines.append("    std::string perm;")
    lines.append("    std::string level;    // protection-level bucket (dangerous/signature/…)")
    lines.append("    std::string cls;      // Java dotted, inner-class '.' separated")
    lines.append("    std::string method;   // dex name (a ctor keeps its class simple name)")
    lines.append("    std::string sig;      // the full dataset signature (output 'api' field)")
    lines.append("    std::vector<std::string> param_types;  // simple names; empty = 0-arity")
    lines.append("};")
    lines.append("")
    _emit_blob(lines, "kPermApiBlob", perm_records)
    lines.append("")
    _emit_blob(lines, "kOverloadBlob", overload_records)
    lines.append("")
    lines.append("namespace detail {")
    lines.append(
        "// Split `s` on `sep` into views over the same storage (no copies). Returns"
    )
    lines.append("// one (possibly empty) view per field; an empty `s` → one empty view.")
    lines.append(
        "inline std::vector<std::string_view> BlobSplit(std::string_view s, char sep) {"
    )
    lines.append("    std::vector<std::string_view> out;")
    lines.append("    std::size_t start = 0;")
    lines.append("    while (true) {")
    lines.append("        std::size_t p = s.find(sep, start);")
    lines.append("        if (p == std::string_view::npos) { out.push_back(s.substr(start)); break; }")
    lines.append("        out.push_back(s.substr(start, p - start));")
    lines.append("        start = p + 1;")
    lines.append("    }")
    lines.append("    return out;")
    lines.append("}")
    lines.append("}  // namespace detail")
    lines.append("")
    lines.append("// All perm → method-call API entries across every protection level")
    lines.append("// (field/constant entries dropped — they can't match a call ref). Parsed")
    lines.append("// once from kPermApiBlob; identical vector to the old initializer form.")
    lines.append("inline const std::vector<PermApiEntry>& PermApiEntries() {")
    lines.append("    static const std::vector<PermApiEntry> kE = [] {")
    lines.append("        std::vector<PermApiEntry> v;")
    lines.append("        std::string_view blob(kPermApiBlob, sizeof(kPermApiBlob) - 1);")
    lines.append("        if (blob.empty()) return v;")
    lines.append("        for (std::string_view rec : detail::BlobSplit(blob, '\\036')) {")
    lines.append("            auto f = detail::BlobSplit(rec, '\\037');  // 6 fields")
    lines.append("            if (f.size() < 6) continue;  // malformed guard (never on our data)")
    lines.append("            PermApiEntry e;")
    lines.append("            e.perm = std::string(f[0]);")
    lines.append("            e.level = std::string(f[1]);")
    lines.append("            e.cls = std::string(f[2]);")
    lines.append("            e.method = std::string(f[3]);")
    lines.append("            e.sig = std::string(f[4]);")
    lines.append("            if (!f[5].empty())")
    lines.append("                for (std::string_view p : detail::BlobSplit(f[5], '\\035'))")
    lines.append("                    e.param_types.emplace_back(p);")
    lines.append("            v.push_back(std::move(e));")
    lines.append("        }")
    lines.append("        return v;")
    lines.append("    }();")
    lines.append("    return kE;")
    lines.append("}")
    lines.append("")
    lines.append("// (class, method) -> {arity -> #distinct-signature overloads}. Drives the")
    lines.append("// overload-ambiguity check: a lone overload (or lone of an arity) matches on")
    lines.append("// arity alone, so a param-parse edge case can't drop a real hit. Parsed once")
    lines.append("// from kOverloadBlob; identical map to the old initializer form.")
    lines.append(
        "inline const std::map<std::pair<std::string, std::string>, "
        "std::map<int, int>>&"
    )
    lines.append("OverloadCounts() {")
    lines.append(
        "    static const std::map<std::pair<std::string, std::string>, "
        "std::map<int, int>> kO = [] {"
    )
    lines.append(
        "        std::map<std::pair<std::string, std::string>, std::map<int, int>> m;"
    )
    lines.append("        std::string_view blob(kOverloadBlob, sizeof(kOverloadBlob) - 1);")
    lines.append("        if (blob.empty()) return m;")
    lines.append("        for (std::string_view rec : detail::BlobSplit(blob, '\\036')) {")
    lines.append("            auto f = detail::BlobSplit(rec, '\\037');  // cls, method, pairs")
    lines.append("            if (f.size() < 3) continue;")
    lines.append("            std::map<int, int> am;")
    lines.append("            if (!f[2].empty())")
    lines.append("                for (std::string_view pr : detail::BlobSplit(f[2], '\\035')) {")
    lines.append("                    std::size_t c = pr.find(':');")
    lines.append("                    if (c == std::string_view::npos) continue;")
    lines.append(
        "                    am[std::stoi(std::string(pr.substr(0, c)))] ="
    )
    lines.append("                        std::stoi(std::string(pr.substr(c + 1)));")
    lines.append("                }")
    lines.append("            m[{std::string(f[0]), std::string(f[1])}] = std::move(am);")
    lines.append("        }")
    lines.append("        return m;")
    lines.append("    }();")
    lines.append("    return kO;")
    lines.append("}")
    lines.append("")
    lines.append("}  // namespace dexkit::ext::gen")
    lines.append("")

    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text("\n".join(lines))
    print(
        f"wrote {OUT} — {len(entries)} entries, {len(overloads)} (class,method) keys"
    )


if __name__ == "__main__":
    main()
