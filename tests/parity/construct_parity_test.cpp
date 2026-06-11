// Parity test for build_node_from_block + Construct.
// End-to-end: hand-craft a snapshot, run Construct, verify the resulting
// Graph has correct typed BasicBlocks + edges + numbering.
#include "method_snapshot.h"
#include "mock_code_source.h"
#include "basic_blocks.h"
#include "graph.h"
#include "slicer/dex_bytecode.h"
#include <cstdio>
#include <memory>

namespace dad = dexkit::dad;
namespace mck = dexkit::dad::testing;
static int g_fail = 0;

template <typename A, typename B>
static void check(const char* label, A got, B want) {
    bool eq = (got == want);
    if (!eq) ++g_fail;
    std::printf("%s %-46s got=%-16lld want=%lld\n",
                eq ? "[ok]  " : "[FAIL]", label,
                static_cast<long long>(got), static_cast<long long>(want));
}

static void check_str(const char* label, const std::string& got,
                      const char* want) {
    bool eq = (got == want);
    if (!eq) ++g_fail;
    std::printf("%s %-46s got=%-30s want=%s\n",
                eq ? "[ok]  " : "[FAIL]", label, got.c_str(), want);
}

int main() {
    using namespace dad;

    // ============================================================
    // Test 1: trivial return-void → 1 ReturnBlock
    // ============================================================
    {
        mck::MockCodeSource src;
        std::vector<dex::u2> insns = {0x000e};
        auto code = mck::FakeCodeItem::Make(1, 0, 0, insns);
        src.RegisterMethod(0, 1, 1, "Lcom/X;", "f", "()V", std::move(code));
        auto snap = MethodSnapshotBuilder::Build(src, 0, 1);
        Vmap vm; GenInvokeRetName ret;
        auto g = Construct(*snap, vm, ret);
        check("[trivial] graph size", static_cast<int>(g->size()), 1);
        check("[trivial] entry is ReturnBlock",
              dynamic_cast<ReturnBlock*>(g->entry) != nullptr, true);
        check("[trivial] exit is set", g->exit != nullptr, true);
        check_str("[trivial] entry.ToString",
                  g->entry->IsInterval() ? "" : dynamic_cast<BasicBlock*>(g->entry)->ToString(),
                  "1-Return(B@0x0000)");
    }

    // ============================================================
    // Test 2: if-eqz branch → CondBlock with true/false wired
    // ============================================================
    {
        mck::MockCodeSource src;
        std::vector<dex::u2> insns = {
            0x0012,             // const/4 v0, #0
            0x0038, 0x0004,     // if-eqz v0, +4 cu  (target byte 10)
            0x1012,             // const/4 v0, #1
            0x000f,             // return v0
            0x0012,             // const/4 v0, #0
            0x000f,             // return v0
        };
        auto code = mck::FakeCodeItem::Make(1, 0, 0, insns);
        src.RegisterMethod(0, 2, 1, "Lcom/X;", "g", "(I)I", std::move(code));
        auto snap = MethodSnapshotBuilder::Build(src, 0, 2);
        Vmap vm; GenInvokeRetName ret;
        auto g = Construct(*snap, vm, ret);
        check("[if] 3 nodes", static_cast<int>(g->size()), 3);
        check("[if] entry is CondBlock",
              dynamic_cast<CondBlock*>(g->entry) != nullptr, true);
        auto* cb = dynamic_cast<CondBlock*>(g->entry);
        check("[if] cb->true_branch set", cb->true_branch != nullptr, true);
        check("[if] cb->false_branch set", cb->false_branch != nullptr, true);
        check("[if] true != false", cb->true_branch != cb->false_branch, true);
        // true_branch corresponds to byte_off 10 (B@0x000A)
        check("[if] true is ReturnBlock",
              dynamic_cast<ReturnBlock*>(cb->true_branch) != nullptr, true);
        check("[if] false is ReturnBlock",
              dynamic_cast<ReturnBlock*>(cb->false_branch) != nullptr, true);
    }

    // ============================================================
    // Test 3: linear chain → simplify-eligible (but we don't simplify here)
    //   v0 = const 1; v1 = v0; return v1
    //   12 10       (const/4 v0, #1)
    //   01 10       (move v0, v1)  — actually move format: 01 ba = move vb, va
    //                 0x0001, encoded vA=0, vB=1 → move v0, v1 = "v0 = v1"
    //   0f 00       (return v0)
    // ============================================================
    {
        mck::MockCodeSource src;
        std::vector<dex::u2> insns = {
            0x1012,   // const/4 v0, #1
            0x1001,   // move v1, v0  (vA=1, vB=0 → "v1 = v0")
            0x000f,   // return v0
        };
        auto code = mck::FakeCodeItem::Make(2, 0, 0, insns);
        src.RegisterMethod(0, 3, 1, "Lcom/X;", "h", "()I", std::move(code));
        auto snap = MethodSnapshotBuilder::Build(src, 0, 3);
        Vmap vm; GenInvokeRetName ret;
        auto g = Construct(*snap, vm, ret);
        check("[chain] 1 node (no branches)", static_cast<int>(g->size()), 1);
        check("[chain] entry is ReturnBlock",
              dynamic_cast<ReturnBlock*>(g->entry) != nullptr, true);
        // Block should contain 3 IR instructions (const, move, return).
        auto* bb = dynamic_cast<BasicBlock*>(g->entry);
        check("[chain] 3 IR ins",
              static_cast<int>(bb->get_ins().size()), 3);
    }

    // ============================================================
    // Test 4: native method → empty graph
    // ============================================================
    {
        mck::MockCodeSource src;
        src.RegisterMethod(0, 4, 0x100, "Lcom/X;", "n", "()V", nullptr);
        auto snap = MethodSnapshotBuilder::Build(src, 0, 4);
        Vmap vm; GenInvokeRetName ret;
        auto g = Construct(*snap, vm, ret);
        check("[native] empty graph", static_cast<int>(g->size()), 0);
        check("[native] entry nullptr", g->entry == nullptr, true);
    }

    std::printf("\n%s — %d failure(s)\n", g_fail ? "FAIL" : "PASS", g_fail);
    return g_fail ? 1 : 0;
}
