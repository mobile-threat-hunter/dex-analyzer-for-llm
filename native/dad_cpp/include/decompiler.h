// decompiler.h — entry point for DexKit-DAD.
// DAD: androguard/decompiler/decompiler.py (facade only — DAD's
// DecompilerDAD itself doesn't contain logic; it delegates to DvMachine).
//
// The `Decompiler` class is the C++ façade exposed via pybind11. Each call
// to DecompileMethod resolves the descriptor, builds a MethodSnapshot via
// the IDexCodeSource, runs DvMethod, and caches the result.

#pragma once

#include <cstddef>
#include <cstdint>
#include <list>
#include <mutex>
#include <shared_mutex>
#include <string>
#include <string_view>
#include <unordered_map>
#include <utility>
#include <vector>

#include "dast.h"
#include "dex_code_source.h"

namespace dexkit::dad {

class Decompiler {
public:
    // `source` is borrowed; caller ensures lifetime exceeds Decompiler.
    explicit Decompiler(IDexCodeSource& source);
    ~Decompiler();

    Decompiler(const Decompiler&) = delete;
    Decompiler& operator=(const Decompiler&) = delete;

    // Returns Java source for a single method given its Smali descriptor
    // (e.g., "Lcom/X;->foo(I)V"). Returns empty string if not found.
    // Throws on malformed dex / decompilation errors.
    std::string DecompileMethod(std::string_view method_descriptor);

    // Decompiles every method of the class. Methods that throw are reported
    // as `// ERROR: <msg>` comments.
    std::string DecompileClass(std::string_view class_descriptor);

    // D-3 (dexllm#1) — Java source plus a (line ↔ dex byte offset) map for
    // smali ↔ Java cursor sync. pc_map is sorted ascending by line, one entry
    // per line (first-anchor-wins), lines with no source op omitted. NOT
    // cached (the text LRU stores strings only); recompute is cheap. Returns
    // {"", {}} if the descriptor isn't found.
    struct DecompiledMethodWithMap {
        std::string source;
        std::vector<std::pair<uint32_t, uint32_t>> pc_map;
    };
    DecompiledMethodWithMap DecompileMethodWithPcMap(
        std::string_view method_descriptor);

    // Minimal AST for a method: signature components + body source.
    // Downstream tools get structured signature data without needing a
    // Java parser; the body remains as decompiled text for now. (Full
    // nested-AST port of DAD's dast.py is deferred — see CLAUDE.md.)
    struct MethodAst {
        std::string cls_name;                   // "Lcom/X;" raw smali
        std::string name;
        std::string proto;                      // "(I)V" raw
        std::string ret_type;                   // "V" / "I" / "Lcom/X;"
        std::vector<std::string> params_type;   // ["I", "Lcom/X;"]
        std::vector<std::string> access;        // ["public","static",...]
        std::string source;                     // decompiled Java text body
        bool found = false;                     // false if descriptor not found
        // Full nested AST — DAD dast.py get_ast() dict
        // {triple, flags, ret, params, comments, body}. Null if not found.
        AstValue ast;
        // D-3 (dexllm#1) — sidechannel (statement_seq ↔ dex byte offset) map.
        // Kept out of `ast` so the tree stays byte-identical to androguard;
        // key = post-order DFS statement index (see JSONWriter::pc_map).
        std::vector<std::pair<uint32_t, uint32_t>> ast_pc_map;
    };
    // `include_source` controls whether the Java text `source` field is also
    // populated. The text requires a SECOND full pipeline run (the AST and
    // text emitters both mutate the graph, so they can't share one). AST-only
    // consumers should pass false to skip that redundant work.
    MethodAst DecompileMethodAst(std::string_view method_descriptor,
                                 bool include_source = true);

    // Cache control. The cache is an LRU bounded by `cache_capacity_` entries
    // (default 4096). Larger APKs evict cold methods; 0 disables eviction.
    void ClearCache();
    std::size_t CacheSize() const;
    void SetCacheCapacity(std::size_t cap);
    std::size_t CacheCapacity() const;

    static constexpr std::size_t kDefaultCacheCapacity = 4096;

private:
    bool LocateMethod(std::string_view descriptor,
                      uint16_t& dex_id, uint32_t& method_idx);

    // D-3 — shared decompile body: build snapshot → DvMethod::Process →
    // SanitizeUtf8. Fills *pc_map (line ↔ offset) when non-null. Used by the
    // cached DecompileMethod (map ignored) and the uncached
    // DecompileMethodWithPcMap (map returned), so the two can't drift.
    std::string RunPipeline(uint16_t dex_id, uint32_t method_idx,
                            std::vector<std::pair<uint32_t, uint32_t>>* pc_map);

    // LRU bookkeeping: list nodes hold (key, value); map keys are
    // string_views into the list's key strings so we don't double-store the
    // descriptor. std::list iterators are stable except on their own erase,
    // and string memory inside a node is stable for the node's lifetime.
    using CacheList = std::list<std::pair<std::string, std::string>>;

    IDexCodeSource& source_;
    mutable std::shared_mutex cache_mutex_;
    CacheList cache_list_;
    std::unordered_map<std::string_view, CacheList::iterator> cache_index_;
    std::size_t cache_capacity_ = kDefaultCacheCapacity;
};

}  // namespace dexkit::dad
