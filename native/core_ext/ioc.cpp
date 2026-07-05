// ioc.cpp — see analysis.h (IoC section). C++ port of dexllm.ioc.extract_iocs.
//
// Issue #13. The Python path's five extraction regexes are hand-BOUNDED (ReDoS-
// safe) and two use look-behind (IPv4, email) — which neither std::regex
// (ECMAScript) nor a byte-oriented engine can express — so we port them as small,
// linear hand-scanners that reproduce Python `re`'s leftmost / greedy-with-
// backtrack semantics EXACTLY. The full-corpus differential test
// (tests/test_ioc_native.py) is the parity gate: C++ ExtractIocs must be
// byte-identical to Python extract_iocs.
//
// Unicode note: Python runs these over `str` (code points); we run over UTF-8
// bytes. Every capturing class in the patterns is an explicit ASCII range, and
// real IoC values are ASCII, so the only semantic touch-points are the `\b`
// word-boundary and `\s` inside the URL body. Those decode the adjacent code
// point and consult the codegen'd Unicode `\w` / `\s` range tables
// (gen/word_ranges.h, emitted from Python `re` itself), so they match Python
// exactly — not a heuristic. The `_MAX_SCAN` cap is likewise applied in code
// points (not bytes) to match Python's `raw[:_MAX_SCAN]`.

#include "analysis.h"

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <set>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include "dexkit_ext.h"
#include "gen/content_uris_data.h"
#include "gen/word_ranges.h"
#include "public_suffix.h"

namespace dexkit::ext {
namespace {

// --- ASCII class predicates. The scanners' captured classes ([A-Za-z], [0-9],
// [A-Za-z0-9._%+-], …) are all explicit ASCII ranges in the Python patterns, so
// they are correct byte-wise regardless of Unicode mode. Only `\b` (word
// boundary) and the URL body's `\s` are Unicode-sensitive — those decode a code
// point and consult the codegen'd `\w` / `\s` tables (see file header).
inline bool IsDigit(unsigned char c) { return c >= '0' && c <= '9'; }
inline bool IsAlpha(unsigned char c) {
    return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z');
}
inline bool IsAlnum(unsigned char c) { return IsAlpha(c) || IsDigit(c); }
inline char Lower(unsigned char c) {
    return (c >= 'A' && c <= 'Z') ? static_cast<char>(c + 32) : static_cast<char>(c);
}

// --- UTF-8 decode + Unicode \w/\s classification (Python `re` ground truth). --
struct Cp {
    char32_t cp;
    size_t len;
};
// Decode the code point starting at byte i. Malformed UTF-8 -> {byte, 1} (an
// isolated non-word byte), keeping the scan safe and progressing.
Cp DecodeCpAt(std::string_view s, size_t i) {
    unsigned char c = static_cast<unsigned char>(s[i]);
    if (c < 0x80) return {c, 1};
    size_t len;
    char32_t cp;
    if ((c & 0xE0) == 0xC0) { len = 2; cp = c & 0x1F; }
    else if ((c & 0xF0) == 0xE0) { len = 3; cp = c & 0x0F; }
    else if ((c & 0xF8) == 0xF0) { len = 4; cp = c & 0x07; }
    else return {c, 1};
    if (i + len > s.size()) return {c, 1};
    for (size_t k = 1; k < len; ++k) {
        unsigned char cc = static_cast<unsigned char>(s[i + k]);
        if ((cc & 0xC0) != 0x80) return {c, 1};
        cp = (cp << 6) | (cc & 0x3F);
    }
    return {cp, len};
}
// Decode the code point ending just before byte i (walk back over continuations).
Cp DecodeCpBefore(std::string_view s, size_t i) {
    size_t start = i - 1;
    while (start > 0 && (static_cast<unsigned char>(s[start]) & 0xC0) == 0x80 &&
           (i - 1 - start) < 3)
        --start;
    Cp d = DecodeCpAt(s, start);
    if (d.len == i - start) return d;
    return {static_cast<unsigned char>(s[i - 1]), 1};  // malformed -> lone byte
}
template <size_t N>
bool InRanges(char32_t cp,
              const std::array<std::pair<char32_t, char32_t>, N>& ranges) {
    size_t lo = 0, hi = N;
    while (lo < hi) {
        size_t mid = lo + (hi - lo) / 2;
        if (cp < ranges[mid].first) hi = mid;
        else if (cp > ranges[mid].second) lo = mid + 1;
        else return true;
    }
    return false;
}
inline bool IsWordCp(char32_t cp) { return InRanges(cp, gen::kWordRanges); }
inline bool IsSpaceCp(char32_t cp) { return InRanges(cp, gen::kSpaceRanges); }

// Boundary `\b` at byte position i within [0,n]: Unicode word-status of the code
// point ending at i differs from the one starting at i (out-of-range = non-word).
inline bool WordBoundary(std::string_view s, size_t i) {
    bool before = i > 0 && IsWordCp(DecodeCpBefore(s, i).cp);
    bool after = i < s.size() && IsWordCp(DecodeCpAt(s, i).cp);
    return before != after;
}

// --- _refang: literal, sequential replace-all (ioc.py _DEFANG order) ---------
const std::array<std::pair<std::string_view, std::string_view>, 15> kDefang = {{
    {"[.]", "."}, {"(.)", "."}, {"{.}", "."}, {"[dot]", "."}, {"(dot)", "."},
    {" dot ", "."}, {"[:]", ":"}, {"[://]", "://"}, {"[at]", "@"}, {"(at)", "@"},
    {" at ", "@"}, {"hxxps", "https"}, {"hxxp", "http"}, {"fxp", "ftp"},
    {"\\", "/"},
}};
std::string Refang(std::string_view in) {
    std::string s(in);
    for (const auto& [marker, repl] : kDefang) {
        if (s.find(marker) == std::string::npos) continue;
        std::string out;
        out.reserve(s.size());
        size_t pos = 0;
        while (true) {
            size_t hit = s.find(marker, pos);
            if (hit == std::string::npos) {
                out.append(s, pos, std::string::npos);
                break;
            }
            out.append(s, pos, hit - pos);
            out.append(repl);
            pos = hit + marker.size();
        }
        s.swap(out);
    }
    return s;
}

// --- scanners: each returns the match end (exclusive) or 0 for "no match at i".
// (0 is safe as a sentinel — a real match ends at > i >= start.)

// _URL: \b(?:https?|ftp|wss?)://[^\s"'<>\\]+   (IGNORECASE). rstrip handled by caller.
size_t MatchUrl(std::string_view s, size_t i) {
    if (!WordBoundary(s, i)) return 0;
    const size_t n = s.size();
    size_t j = i;  // scheme end
    auto lc = [&](size_t k) { return k < n ? Lower(static_cast<unsigned char>(s[k])) : '\0'; };
    if (lc(i) == 'h' && lc(i + 1) == 't' && lc(i + 2) == 't' && lc(i + 3) == 'p') {
        j = i + 4;
        if (lc(j) == 's') ++j;  // https? — greedy 's'
    } else if (lc(i) == 'f' && lc(i + 1) == 't' && lc(i + 2) == 'p') {
        j = i + 3;
    } else if (lc(i) == 'w' && lc(i + 1) == 's') {
        j = i + 2;
        if (lc(j) == 's') ++j;  // wss?
    } else {
        return 0;
    }
    if (s.substr(j, 3) != "://") return 0;  // substr clamps near end -> safe
    size_t k = j + 3;
    while (k < n) {  // [^\s"'<>\\]+ — \s is Unicode; the excluded chars are ASCII
        Cp d = DecodeCpAt(s, k);
        char32_t cp = d.cp;
        if (cp == '"' || cp == '\'' || cp == '<' || cp == '>' || cp == '\\' ||
            IsSpaceCp(cp))
            break;
        k += d.len;
    }
    return k > j + 3 ? k : 0;  // [^...]+ requires >= 1
}

// _EMAIL: (?<![LOCAL])[LOCAL]{1,64}@[DOM]{1,253}\.[A-Za-z]{2,24}\b
//   LOCAL = [A-Za-z0-9._%+-], DOM = [A-Za-z0-9.-]
// Returns {start, end} of the match (start < i possible — local runs left of '@').
struct Span { size_t start, end; };
bool IsLocal(unsigned char c) {
    return IsAlnum(c) || c == '.' || c == '_' || c == '%' || c == '+' || c == '-';
}
bool IsDom(unsigned char c) { return IsAlnum(c) || c == '.' || c == '-'; }
// Attempt an email whose '@' is at position `at`. Returns match Span or {0,0}.
Span MatchEmailAt(std::string_view s, size_t at) {
    const size_t n = s.size();
    // local: maximal LOCAL run ending at at-1; lookbehind is satisfied at the run
    // start (char before is non-LOCAL / BOS). {1,64} => run length in [1,64].
    size_t ls = at;
    while (ls > 0 && IsLocal(static_cast<unsigned char>(s[ls - 1]))) --ls;
    size_t llen = at - ls;
    if (llen < 1 || llen > 64) return {0, 0};
    // domain part [A-Za-z0-9.-]{1,253} greedy, backtrack to leave `.[A-Za-z]{2,24}\b`.
    size_t rstart = at + 1;
    size_t rmax = rstart;
    while (rmax < n && IsDom(static_cast<unsigned char>(s[rmax]))) ++rmax;
    size_t run = rmax - rstart;  // full [A-Za-z0-9.-] run length
    if (run < 1) return {0, 0};
    size_t dl_hi = std::min<size_t>(run, 253);
    for (size_t dl = dl_hi; dl >= 1; --dl) {
        size_t dot = rstart + dl;  // domain_part = [rstart, dot)
        if (dot >= n || s[dot] != '.') continue;
        // TLD [A-Za-z]{2,24} greedy from dot+1, then \b.
        size_t t = dot + 1;
        size_t tmax = t;
        while (tmax < n && IsAlpha(static_cast<unsigned char>(s[tmax])) &&
               tmax - t < 24)
            ++tmax;
        for (size_t te = tmax; te >= t + 2; --te) {
            if (WordBoundary(s, te)) return {ls, te};
        }
    }
    return {0, 0};
}

// _IPV4 octet: 25[0-5]|2[0-4]\d|1?\d?\d — returns digit count consumed (0 = none).
size_t MatchOctet(std::string_view s, size_t i) {
    const size_t n = s.size();
    auto d = [&](size_t k) { return k < n && IsDigit(static_cast<unsigned char>(s[k])); };
    // 25[0-5]
    if (i + 2 < n && s[i] == '2' && s[i + 1] == '5' && s[i + 2] >= '0' &&
        s[i + 2] <= '5')
        return 3;
    // 2[0-4]\d
    if (i + 2 < n && s[i] == '2' && s[i + 1] >= '0' && s[i + 1] <= '4' && d(i + 2))
        return 3;
    // 1?\d?\d — optional '1', optional digit, mandatory digit; greedy-longest.
    // A leading '1' can serve as the literal `1?` (enabling a 3rd digit) or, if no
    // digit follows, as the mandatory `\d` itself (a lone "1"). A non-'1' digit
    // start reaches at most 2 digits (\d?\d).
    if (i < n && s[i] == '1') {
        if (d(i + 1) && d(i + 2)) return 3;  // "1" + \d? + \d
        if (d(i + 1)) return 2;              // "1" + \d
        return 1;                            // lone "1" (as mandatory \d)
    }
    if (d(i)) {
        if (d(i + 1)) return 2;  // \d? + \d
        return 1;                // \d
    }
    return 0;
}
// _IPV4 whole: (?<!\d)(?<!\d\.) OCT (\. OCT){3} (:port)? (?!\.?\d)
size_t MatchIpv4(std::string_view s, size_t i) {
    const size_t n = s.size();
    // look-behind: not preceded by \d, and not by \d\. .
    if (i > 0 && IsDigit(static_cast<unsigned char>(s[i - 1]))) return 0;
    if (i >= 2 && s[i - 1] == '.' &&
        IsDigit(static_cast<unsigned char>(s[i - 2])))
        return 0;
    size_t p = i;
    for (int oct = 0; oct < 4; ++oct) {
        size_t consumed = MatchOctet(s, p);
        if (consumed == 0) return 0;
        p += consumed;
        if (oct < 3) {
            if (p >= n || s[p] != '.') return 0;
            ++p;
        }
    }
    // `(?::\d{1,5})? (?!\.?\d)`. The optional port group is BACKTRACKABLE: greedy
    // tries it present (longest \d{1,5} first), and if the trailing look-ahead then
    // fails it drops digits — and finally the whole group — retrying the look-ahead
    // each time. So a bare quad still matches when the port is oversized/dot-followed
    // (e.g. "1.2.3.4:123456" -> "1.2.3.4"). Try each candidate end greedily; return
    // the first whose look-ahead holds.
    auto lookahead_ok = [&](size_t pe) {
        if (pe >= n) return true;  // end of string -> \.?\d cannot match
        size_t la = pe;
        if (s[la] == '.') ++la;
        return !(la < n && IsDigit(static_cast<unsigned char>(s[la])));
    };
    size_t base = p;  // position just after the 4th octet
    if (base < n && s[base] == ':') {
        size_t maxd = 0;
        while (base + 1 + maxd < n && maxd < 5 &&
               IsDigit(static_cast<unsigned char>(s[base + 1 + maxd])))
            ++maxd;
        for (size_t d = maxd; d >= 1; --d)  // port present, greedy \d{1,5} then shrink
            if (lookahead_ok(base + 1 + d)) return base + 1 + d;
    }
    return lookahead_ok(base) ? base : 0;  // port absent (group dropped)
}

// _ONION: \b[a-z2-7]{16}(?:[a-z2-7]{40})?\.onion\b   (IGNORECASE)
size_t MatchOnion(std::string_view s, size_t i) {
    if (!WordBoundary(s, i)) return 0;
    const size_t n = s.size();
    auto b32 = [&](size_t k) {
        char c = k < n ? Lower(static_cast<unsigned char>(s[k])) : '\0';
        return (c >= 'a' && c <= 'z') || (c >= '2' && c <= '7');
    };
    for (size_t k = i; k < i + 16; ++k)
        if (!b32(k)) return 0;
    size_t p = i + 16;
    // optional 40 more base32 chars (v3). Greedy: take the group if all 40 present.
    bool has40 = true;
    for (size_t k = p; k < p + 40; ++k)
        if (!b32(k)) { has40 = false; break; }
    if (has40) p += 40;
    // ".onion" (case-insensitive) then \b
    static const char kOnion[] = ".onion";
    for (size_t k = 0; k < 6; ++k) {
        if (p + k >= n) return 0;
        if (Lower(static_cast<unsigned char>(s[p + k])) != kOnion[k]) return 0;
    }
    size_t end = p + 6;
    return WordBoundary(s, end) ? end : 0;
}

// _HOST_CANDIDATE: \b(?:[a-z0-9][a-z0-9-]{0,62}\.){1,32}[a-z]{2,24}\b (IGNORECASE)
size_t MatchHost(std::string_view s, size_t i) {
    if (!WordBoundary(s, i)) return 0;
    const size_t n = s.size();
    auto alnum = [&](size_t k) {
        return k < n && IsAlnum(static_cast<unsigned char>(s[k]));
    };
    auto labelch = [&](size_t k) {  // [a-z0-9-]
        return k < n && (IsAlnum(static_cast<unsigned char>(s[k])) || s[k] == '-');
    };
    // Greedily parse label groups "[alnum][a-z0-9-]{0,62}\." — record end of each
    // label group so we can backtrack the {1,32} for the final TLD.
    std::vector<size_t> group_ends;  // positions just after each '.'
    size_t p = i;
    while (group_ends.size() < 32) {
        if (!alnum(p)) break;
        size_t q = p + 1;
        while (q < n && (q - (p + 1)) < 62 && labelch(q)) ++q;  // [a-z0-9-]{0,62}
        if (q >= n || s[q] != '.') break;                       // need '.'
        group_ends.push_back(q + 1);
        p = q + 1;
    }
    // Try the most label groups first (greedy {1,32}); final TLD [a-z]{2,24}\b.
    for (size_t g = group_ends.size(); g >= 1; --g) {
        size_t start = group_ends[g - 1];  // TLD starts after the g-th '.'
        size_t t = start, tmax = start;
        while (tmax < n && IsAlpha(static_cast<unsigned char>(s[tmax])) &&
               tmax - t < 24)
            ++tmax;
        for (size_t te = tmax; te >= t + 2; --te) {
            if (WordBoundary(s, te)) return te;
        }
    }
    return 0;
}

// --- denoise sets (ioc.py) ---------------------------------------------------
const std::set<std::string_view> kNonhostSuffixes = {
    "name", "one", "group", "read", "support", "secure", "info", "run",
    "google", "ms", "java", "type", "prod", "build", "now", "new", "win",
    "men", "review", "country", "kim", "mov", "zip", "foo", "bar",
};
const std::set<std::string_view> kNamespaceHosts = {
    "schemas.android.com", "schemas.xmlsoap.org", "schemas.microsoft.com",
    "schemas.openxmlformats.org", "xmlpull.org", "www.xmlpull.org", "www.w3.org",
    "w3.org", "java.sun.com", "ns.adobe.com", "purl.org",
};
const std::set<std::string_view> kDropRoots = {
    // RDN roots
    "com", "org", "net", "edu", "gov", "mil", "int",
    // platform roots
    "android", "androidx", "java", "javax", "kotlin", "kotlinx", "dalvik", "sun",
    "junit",
};

std::string ToLower(std::string_view s) {
    std::string out(s);
    for (char& c : out) c = Lower(static_cast<unsigned char>(c));
    return out;
}

// ioc.py _valid_domain: PSL-registered AND suffix's last label not a word-gTLD.
bool ValidDomain(std::string_view host) {
    SuffixResult r = PublicSuffixExtract(host);
    if (!r.HasRegisteredDomain()) return false;
    return kNonhostSuffixes.find(r.SuffixLastLabel()) == kNonhostSuffixes.end();
}

// ioc.py _dex_package_prefixes: dotted package prefixes from type descriptors.
bool IsPkgLabel(std::string_view lbl) {  // [a-z0-9_$]+ (already lowercased)
    if (lbl.empty()) return false;
    for (char c : lbl) {
        unsigned char u = static_cast<unsigned char>(c);
        if (!(IsAlnum(u) || u == '_' || u == '$')) return false;
    }
    return true;
}
void AddPackagePrefixes(std::string_view desc, std::set<std::string>& pkgs) {
    std::string_view core = desc;
    while (!core.empty() && core.front() == '[') core.remove_prefix(1);  // lstrip('[')
    if (!(core.size() >= 2 && core.front() == 'L' && core.back() == ';' &&
          core.find('/') != std::string_view::npos))
        return;
    core = core.substr(1, core.size() - 2);  // strip L...;
    // labels = lower(split('/'))[:-1]  (drop the class simple name)
    std::vector<std::string> labels;
    size_t start = 0;
    std::vector<std::string_view> parts;
    while (true) {
        size_t slash = core.find('/', start);
        if (slash == std::string_view::npos) {
            parts.push_back(core.substr(start));
            break;
        }
        parts.push_back(core.substr(start, slash - start));
        start = slash + 1;
    }
    if (parts.size() < 2) return;  // no package labels (need >=1 after dropping tail)
    parts.pop_back();  // [:-1]
    for (auto p : parts) {
        std::string lbl = ToLower(p);
        if (!IsPkgLabel(lbl)) return;  // any bad label -> skip whole descriptor
        labels.push_back(std::move(lbl));
    }
    std::string acc;
    for (size_t k = 0; k < labels.size(); ++k) {
        if (k) acc.push_back('.');
        acc += labels[k];
        pkgs.insert(acc);
    }
}

// ioc.py _is_package_like
bool IsPackageLike(const std::string& host, const std::set<std::string>& pkgs) {
    if (kNamespaceHosts.find(host) != kNamespaceHosts.end()) return true;
    if (pkgs.find(host) != pkgs.end()) return true;
    std::string_view first = host;
    size_t dot = first.find('.');
    if (dot != std::string_view::npos) first = first.substr(0, dot);
    return kDropRoots.find(first) != kDropRoots.end();
}

// ioc.py _host_of: bare host of a scheme-qualified URL (no userinfo/port).
std::string HostOf(const std::string& url) {
    size_t sep = url.find("://");
    if (sep == std::string::npos) return "";
    std::string rest = url.substr(sep + 3);
    // authority = rest up to first '/', '?', '#'
    size_t cut = rest.find_first_of("/?#");
    std::string authority = cut == std::string::npos ? rest : rest.substr(0, cut);
    // drop userinfo: rsplit('@',1)[-1]
    size_t at = authority.rfind('@');
    if (at != std::string::npos) authority = authority.substr(at + 1);
    if (!authority.empty() && authority.front() == '[') {  // IPv6 literal
        size_t close = authority.find(']');
        if (close != std::string::npos) return ToLower(authority.substr(1, close - 1));
    }
    size_t colon = authority.find(':');
    if (colon != std::string::npos) authority = authority.substr(0, colon);
    return ToLower(authority);
}

// Is `h` a dotted-quad IPv4 in full (ioc.py `_IPV4.fullmatch(h)`)?
bool IsIpv4Full(std::string_view h) {
    if (h.empty()) return false;
    size_t end = MatchIpv4(h, 0);
    return end == h.size();
}

constexpr size_t kMaxScan = 65536;

// Byte length of the first `max_cp` code points of `s` (all of `s` if it has
// fewer). Python caps with `raw[:_MAX_SCAN]` — a CODE-POINT slice — so the C++
// cap must count code points, not bytes, to keep the scan window identical on
// multibyte input.
size_t CapByteLen(std::string_view s, size_t max_cp) {
    size_t i = 0, cp = 0;
    while (i < s.size() && cp < max_cp) {
        i += DecodeCpAt(s, i).len;
        ++cp;
    }
    return i;
}

// Shared scan: refang + the five scanners + PSL domain validation + URL-host fold,
// into the five value sets. Backs both ExtractIocs (denoise from the dex's package
// prefixes) and the IocScanStrings test seam (denoise off).
void CollectBuckets(const std::vector<std::string>& strings, bool denoise,
                    const std::set<std::string>& dex_packages,
                    std::set<std::string>& urls, std::set<std::string>& ips,
                    std::set<std::string>& domains, std::set<std::string>& emails,
                    std::set<std::string>& onion) {
    for (const std::string& raw : strings) {
        std::string_view sv0(raw);
        std::string_view capped = sv0.substr(0, CapByteLen(sv0, kMaxScan));
        std::string s = Refang(capped);
        std::string_view sv(s);
        const size_t n = sv.size();

        // URLs (finditer, non-overlapping leftmost).
        for (size_t i = 0; i < n;) {
            size_t end = MatchUrl(sv, i);
            if (end) {
                std::string url(sv.substr(i, end - i));
                while (!url.empty()) {  // rstrip(".,);\"'")
                    char c = url.back();
                    if (c == '.' || c == ',' || c == ')' || c == ';' || c == '"' ||
                        c == '\'')
                        url.pop_back();
                    else
                        break;
                }
                if (!(denoise &&
                      kNamespaceHosts.find(HostOf(url)) != kNamespaceHosts.end()))
                    urls.insert(url);
                i = end;
            } else {
                ++i;
            }
        }
        // Emails — iterate '@'.
        {
            size_t last_end = 0;
            for (size_t a = 0; a < n; ++a) {
                if (sv[a] != '@') continue;
                Span m = MatchEmailAt(sv, a);
                if (m.end > m.start && m.start >= last_end) {
                    emails.insert(std::string(sv.substr(m.start, m.end - m.start)));
                    last_end = m.end;
                }
            }
        }
        // IPv4.
        for (size_t i = 0; i < n;) {
            size_t end = MatchIpv4(sv, i);
            if (end) {
                ips.insert(std::string(sv.substr(i, end - i)));
                i = end;
            } else {
                ++i;
            }
        }
        // Onion.
        for (size_t i = 0; i < n;) {
            size_t end = MatchOnion(sv, i);
            if (end) {
                onion.insert(ToLower(sv.substr(i, end - i)));
                i = end;
            } else {
                ++i;
            }
        }
        // Bare domains (host candidate -> PSL-validated -> denoised).
        for (size_t i = 0; i < n;) {
            size_t end = MatchHost(sv, i);
            if (end) {
                std::string host = ToLower(sv.substr(i, end - i));
                i = end;
                if (host.size() >= 6 &&
                    host.compare(host.size() - 6, 6, ".onion") == 0)
                    continue;  // its own category
                if (!ValidDomain(host)) continue;
                if (denoise && IsPackageLike(host, dex_packages)) continue;
                domains.insert(std::move(host));
            } else {
                ++i;
            }
        }
    }

    // A URL's own host is a high-confidence domain — fold it in (post-denoise),
    // bypassing the word-gTLD gate (a scheme proves intent; PSL structure only).
    for (const std::string& u : urls) {
        std::string h = HostOf(u);
        if (h.find('.') == std::string::npos) continue;
        if (IsIpv4Full(h)) continue;
        if (h.size() >= 6 && h.compare(h.size() - 6, 6, ".onion") == 0) continue;
        if (!PublicSuffixExtract(h).HasRegisteredDomain()) continue;
        if (denoise && IsPackageLike(h, dex_packages)) continue;
        domains.insert(h);
    }
}

}  // namespace

IocResult ExtractIocs(DexKitExt& ext, bool with_xref, bool denoise,
                      int xref_limit) {
    std::vector<std::string> strings = ext.ListValueStrings();

    std::set<std::string> dex_packages;
    if (denoise) {
        for (const auto& c : ext.ListClasses()) AddPackagePrefixes(c, dex_packages);
        for (const auto& t : ext.ListExternalTypeRefs(/*framework_only=*/false))
            AddPackagePrefixes(t.descriptor, dex_packages);
    }

    std::set<std::string> urls, ips, domains, emails, onion;
    CollectBuckets(strings, denoise, dex_packages, urls, ips, domains, emails,
                   onion);

    // Cross-reference, highest-signal category first, within one budget. Mirrors
    // extract_iocs's _XREF_PRIORITY = onion, ips, domains, emails, urls.
    int budget = xref_limit;
    auto build = [&](const std::set<std::string>& bucket) {
        std::vector<IocIndicator> rows;
        rows.reserve(bucket.size());
        for (const std::string& value : bucket) {  // std::set already sorted
            IocIndicator ind;
            ind.value = value;
            if (with_xref && budget > 0) {
                // Mirror extract_iocs's per-query try/except: a throwing L7 query
                // yields empty methods but STILL spends the budget and continues
                // the report (one bad indicator must not abort it).
                try {
                    for (const auto& m : ext.FindMethodsUsingStrings(
                             {value}, /*match_type=*/"contains",
                             /*ignore_case=*/false))
                        ind.methods.push_back(m.descriptor);
                } catch (...) {
                    ind.methods.clear();
                }
                --budget;
            }
            rows.push_back(std::move(ind));
        }
        return rows;
    };
    // Populate in priority order so the budget is spent highest-signal first...
    IocResult result;
    result.onion = build(onion);
    result.ips = build(ips);
    result.domains = build(domains);
    result.emails = build(emails);
    result.urls = build(urls);
    return result;
}

IocResult IocScanStrings(const std::vector<std::string>& strings) {
    std::set<std::string> urls, ips, domains, emails, onion;
    CollectBuckets(strings, /*denoise=*/false, /*dex_packages=*/{}, urls, ips,
                   domains, emails, onion);
    auto to_rows = [](const std::set<std::string>& b) {
        std::vector<IocIndicator> rows;
        rows.reserve(b.size());
        for (const std::string& v : b) rows.push_back({v, {}});
        return rows;
    };
    IocResult r;
    r.urls = to_rows(urls);
    r.ips = to_rows(ips);
    r.domains = to_rows(domains);
    r.emails = to_rows(emails);
    r.onion = to_rows(onion);
    return r;
}

std::vector<std::pair<std::string, std::string>> DetectProvidersFromStrings(
    const std::vector<std::string>& strings) {
    // Fast filter: only the value-strings that mention content:// at all.
    std::vector<const std::string*> candidates;
    for (const std::string& s : strings)
        if (s.find("content://") != std::string::npos) candidates.push_back(&s);

    // A dataset URI (kContentUris is sorted) is a hit iff it is a substring of some
    // candidate. Iterating the sorted array yields hits already in URI order,
    // matching the Python path's sorted iteration.
    std::vector<std::pair<std::string, std::string>> hits;
    for (const auto& [uri, family] : gen::kContentUris) {
        for (const std::string* s : candidates) {
            if (s->find(uri) != std::string::npos) {
                hits.emplace_back(std::string(uri), std::string(family));
                break;
            }
        }
    }
    return hits;
}

std::vector<ProviderHit> DetectContentProviders(DexKitExt& ext, bool with_xref,
                                                int xref_limit) {
    int budget = xref_limit;
    std::vector<ProviderHit> result;
    for (auto& [uri, family] : DetectProvidersFromStrings(ext.ListValueStrings())) {
        ProviderHit ph;
        ph.uri = uri;
        ph.family = family;
        if (with_xref && budget > 0) {
            try {
                for (const auto& m : ext.FindMethodsUsingStrings(
                         {uri}, /*match_type=*/"contains", /*ignore_case=*/false))
                    ph.methods.push_back(m.descriptor);
            } catch (...) {
                ph.methods.clear();
            }
            --budget;
        }
        result.push_back(std::move(ph));
    }
    return result;
}

}  // namespace dexkit::ext
