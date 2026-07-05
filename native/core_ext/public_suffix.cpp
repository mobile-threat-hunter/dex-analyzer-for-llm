// public_suffix.cpp — see public_suffix.h. Port of tldextract's suffix_index.

#include "public_suffix.h"

#include <cstdint>
#include <string>
#include <string_view>
#include <unordered_map>
#include <vector>

#include "gen/psl_data.h"

namespace dexkit::ext {
namespace {

// Reversed-label trie of the public-suffix set (tldextract's `Trie`). Wildcard and
// exception rules are stored as ordinary labels "*" and "!<label>" so the walk can
// probe for them, exactly as tldextract does.
struct TrieNode {
    std::unordered_map<std::string_view, uint32_t> matches;  // label -> node index
    bool end = false;
};

class SuffixTrie {
   public:
    SuffixTrie() {
        nodes_.emplace_back();  // root at index 0
        for (std::string_view suffix : gen::kPublicSuffixes) AddSuffix(suffix);
    }

    // Faithful port of `_PublicSuffixListTLDExtractor.suffix_index`: returns the
    // index of the first public-suffix label in `labels`, or -1 for no match.
    // (include_psl_private_domains = False → the single, public trie.)
    [[nodiscard]] int SuffixIndex(const std::vector<std::string_view>& labels) const {
        const int n = static_cast<int>(labels.size());
        int suffix_idx = n;
        int label_idx = n;
        uint32_t node = 0;  // root
        for (int i = n - 1; i >= 0; --i) {
            std::string_view label = labels[i];  // already lowercase ASCII
            const auto& matches = nodes_[node].matches;
            auto it = matches.find(label);
            if (it != matches.end()) {
                --label_idx;
                node = it->second;
                if (nodes_[node].end) suffix_idx = label_idx;
                continue;
            }
            // No exact child. A wildcard "*" makes the current label part of the
            // suffix unless a "!<label>" exception cancels it.
            auto wild = matches.find("*");
            if (wild != matches.end()) {
                std::string exc = "!";
                exc.append(label);
                bool is_exception = matches.find(exc) != matches.end();
                return is_exception ? label_idx : label_idx - 1;
            }
            break;
        }
        return suffix_idx == n ? -1 : suffix_idx;
    }

   private:
    void AddSuffix(std::string_view suffix) {
        // Split on '.', reverse, walk/create. tldextract's `Trie.add_suffix`.
        std::vector<std::string_view> labels;
        size_t start = 0;
        while (true) {
            size_t dot = suffix.find('.', start);
            if (dot == std::string_view::npos) {
                labels.push_back(suffix.substr(start));
                break;
            }
            labels.push_back(suffix.substr(start, dot - start));
            start = dot + 1;
        }
        uint32_t node = 0;
        for (auto it = labels.rbegin(); it != labels.rend(); ++it) {
            auto& matches = nodes_[node].matches;
            auto found = matches.find(*it);
            if (found != matches.end()) {
                node = found->second;
            } else {
                uint32_t child = static_cast<uint32_t>(nodes_.size());
                nodes_.emplace_back();
                // The label view aliases the constexpr kPublicSuffixes storage
                // (static duration) — safe to key the map on.
                nodes_[node].matches.emplace(*it, child);
                node = child;
            }
        }
        nodes_[node].end = true;
    }

    std::vector<TrieNode> nodes_;
};

const SuffixTrie& Trie() {
    static const SuffixTrie kTrie;
    return kTrie;
}

}  // namespace

SuffixResult PublicSuffixExtract(std::string_view host) {
    // tldextract's `lenient_netloc` strips trailing FQDN-root dots ("evil.com." ->
    // "evil.com"); a scheme-qualified URL's `_host_of` can hand us one. (Leading /
    // interior dots are preserved.) Input is already lowercase ASCII, so the unicode
    // ideographic-dot normalisation tldextract also does can't apply.
    while (!host.empty() && host.back() == '.') host.remove_suffix(1);

    std::vector<std::string_view> labels;
    size_t start = 0;
    while (true) {
        size_t dot = host.find('.', start);
        if (dot == std::string_view::npos) {
            labels.push_back(host.substr(start));
            break;
        }
        labels.push_back(host.substr(start, dot - start));
        start = dot + 1;
    }

    int idx = Trie().SuffixIndex(labels);
    if (idx < 0) {
        // No public suffix — tldextract's `_extract_netloc` elif branch sets
        // `domain = labels[-1]`, `suffix = ""` (so `top_domain_under_public_suffix`
        // is still empty; the IoC callers reject it either way).
        SuffixResult none;
        if (!labels.empty()) none.domain.assign(labels.back());
        return none;
    }

    const int n = static_cast<int>(labels.size());
    SuffixResult r;
    // suffix = ".".join(labels[idx:])
    for (int i = idx; i < n; ++i) {
        if (i > idx) r.suffix.push_back('.');
        r.suffix.append(labels[i]);
    }
    // domain = labels[idx-1] if idx > 0 else ""
    if (idx > 0) r.domain.assign(labels[idx - 1]);
    return r;
}

}  // namespace dexkit::ext
