// public_suffix.h — Mozilla public-suffix lookup for IoC domain validation.
//
// Issue #13: a faithful C++ port of tldextract's suffix resolution
// (include_psl_private_domains = False), so the engine's IoC path
// (extract_iocs's _valid_domain + URL-host fold) validates bare domains
// identically from BOTH the pybind and embind bindings, over the SAME bundled
// public-suffix set (native/core_ext/gen/psl_data.h).
//
// The trie is keyed on ASCII (xn--) labels and the input host must be lowercase
// ASCII — see gen_psl_data.py for why this is provably equivalent to tldextract's
// unicode-trie + punycode-decoding-input for every ASCII host we can see (a dex
// value-string is scanned by an ASCII-only host regex).

#pragma once

#include <string>
#include <string_view>

namespace dexkit::ext {

// Mirror of tldextract's ExtractResult, restricted to the two fields the IoC path
// reads. `suffix` = the matched public suffix ("" if none); `domain` = the single
// registrable label immediately under it ("" if none). `top_domain_under_public_
// suffix` (= domain + "." + suffix) is non-empty iff BOTH are non-empty.
struct SuffixResult {
    std::string suffix;
    std::string domain;

    // tldextract's `top_domain_under_public_suffix` truthiness.
    [[nodiscard]] bool HasRegisteredDomain() const {
        return !suffix.empty() && !domain.empty();
    }
    // The last label of the suffix ("com" of "co.uk"'s "uk", "os.name"'s "name") —
    // the word-gTLD-collision gate in extract_iocs keys on this.
    [[nodiscard]] std::string_view SuffixLastLabel() const {
        size_t pos = suffix.rfind('.');
        return pos == std::string::npos ? std::string_view(suffix)
                                        : std::string_view(suffix).substr(pos + 1);
    }
};

// Resolve `host` (must be lowercase ASCII, dot-separated, no scheme/port/userinfo)
// against the bundled public-suffix list. Faithful port of tldextract's
// `_PublicSuffixListTLDExtractor.suffix_index` + the suffix/domain slicing in
// `_extract_netloc` (the IP-literal special cases are intentionally omitted — the
// IoC callers pre-filter IPs, so host never triggers them).
SuffixResult PublicSuffixExtract(std::string_view host);

}  // namespace dexkit::ext
