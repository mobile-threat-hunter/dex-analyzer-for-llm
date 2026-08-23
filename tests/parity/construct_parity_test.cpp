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
#include <stdexcept>

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

    // ============================================================
    // Test 5 (dexllm#73): a code item with NO decodable instruction
    // ============================================================
    // `insns_size == 0` is accepted by ART's STRUCTURAL verifier (it is the
    // runtime method_verifier that rejects a zero-opcode code item), so it
    // reaches the builder. No instruction -> no leader -> no block, and an
    // entry_block_id claiming block 0 then made Construct's bfs seed read
    // `snap.blocks[0]` on an empty vector. Real-world exemplar: AOSP
    // art/tools/fuzzer/class-verifier-corpus/b391844326.dex.
    {
        mck::MockCodeSource src;
        auto code = mck::FakeCodeItem::Make(4, 2, 2, /*insns=*/{});
        src.RegisterMethod(0, 5, 1, "Lcom/X;", "empty", "()V", std::move(code));
        auto snap = MethodSnapshotBuilder::Build(src, 0, 5);
        check("[no-insns] no blocks", static_cast<int>(snap->blocks.size()), 0);
        check("[no-insns] entry_block_id is nullopt",
              snap->entry_block_id.has_value(), false);
        Vmap vm; GenInvokeRetName ret;
        auto g = Construct(*snap, vm, ret);
        check("[no-insns] empty graph", static_cast<int>(g->size()), 0);
        check("[no-insns] entry nullptr", g->entry == nullptr, true);
    }

    // ============================================================
    // Test 6 (dexllm#73): a body that is nothing but a payload
    // ============================================================
    // DecodeAllInsns SKIPS payload markers, so a well-formed packed-switch
    // payload occupying the whole body also yields zero instructions with
    // `insns_size != 0`. Same empty-blocks state, reached a second way — a fix
    // keyed on `insns_size == 0` alone would miss it.
    {
        mck::MockCodeSource src;
        // packed-switch-payload: ident 0x0100, size 1, first_key 0, 1 target.
        std::vector<dex::u2> insns = {0x0100, 0x0001, 0x0000, 0x0000,
                                      0x0000, 0x0000};
        auto code = mck::FakeCodeItem::Make(2, 0, 0, insns);
        src.RegisterMethod(0, 6, 1, "Lcom/X;", "payload", "()V", std::move(code));
        auto snap = MethodSnapshotBuilder::Build(src, 0, 6);
        check("[payload-only] no blocks",
              static_cast<int>(snap->blocks.size()), 0);
        check("[payload-only] entry_block_id is nullopt",
              snap->entry_block_id.has_value(), false);
        Vmap vm; GenInvokeRetName ret;
        auto g = Construct(*snap, vm, ret);
        check("[payload-only] empty graph", static_cast<int>(g->size()), 0);
    }

    // ============================================================
    // Test 6b (dexllm#73): payload-only body WITH a try table
    // ============================================================
    // Stage 3 seeds a leader per try-range START, so this shape DOES produce a
    // block — with an empty `ins` span. That is why the builder's predicate is
    // `ins_storage`, not `blocks`: keyed on `blocks` this rendered an empty
    // `try { } catch { }` for a method carrying no instruction at all.
    {
        mck::MockCodeSource src;
        std::vector<dex::u2> insns = {0x0100, 0x0001, 0x0000, 0x0000,
                                      0x0000, 0x0000};
        std::vector<dex::TryBlock> tries(1);
        tries[0].start_addr = 0;
        tries[0].insn_count = 6;
        tries[0].handler_off = 1;  // past the uleb handlers_size prefix
        // one catch-all handler: handlers_size=1, size=0 (catch_all), addr=0
        std::vector<uint8_t> handlers = {0x01, 0x00, 0x00};
        auto code = mck::FakeCodeItem::Make(2, 0, 0, insns, tries, handlers);
        src.RegisterMethod(0, 8, 1, "Lcom/X;", "ptry", "()V", std::move(code));
        auto snap = MethodSnapshotBuilder::Build(src, 0, 8);
        check("[payload+try] blocks NON-empty",
              static_cast<int>(snap->blocks.size()) > 0, true);
        check("[payload+try] no instructions",
              static_cast<int>(snap->ins_storage.size()), 0);
        check("[payload+try] entry_block_id is nullopt",
              snap->entry_block_id.has_value(), false);
        Vmap vm; GenInvokeRetName ret;
        auto g = Construct(*snap, vm, ret);
        check("[payload+try] empty graph", static_cast<int>(g->size()), 0);
    }

    // ============================================================
    // Test 7 (dexllm#73): Construct REFUSES a promise it cannot keep
    // ============================================================
    // The two tests above pin the builder; this one pins the reader side, which
    // the builder can no longer reach — a hand-built snapshot is the only way to
    // break the entry_block_id promise now. Without the check this does not
    // fail, it SEGVs the whole binary. It throws rather than returning an empty
    // graph because reaching it means a producer lied, not that the input has a
    // legitimate no-CFG shape (which Test 5/6 cover); the per-method catch
    // reports that instead of emitting a method that reads as abstract.
    //
    // TWO fixtures, and the second is the load-bearing one: with `blocks` EMPTY
    // the committed bound `id >= blocks.size()` and the strictly weaker
    // `blocks.empty()` agree, so an empty-blocks case alone cannot tell them
    // apart. A NON-empty `blocks` with an out-of-range id separates them — and
    // that is also the shape where the unguarded `nodes[bid] = raw` is a genuine
    // out-of-range WRITE rather than a null deref.
    {
        MethodSnapshot snap;                 // no blocks at all
        snap.entry_block_id = 0;             // ...but a promise that block 0 exists
        Vmap vm; GenInvokeRetName ret;
        std::string why;
        try { Construct(snap, vm, ret); } catch (const std::exception& e) { why = e.what(); }
        check_str("[bad-entry empty] refused by the bound", why,
                  "Construct: entry_block_id names no block");
    }
    {
        mck::MockCodeSource src;
        std::vector<dex::u2> insns = {0x000e};
        auto code = mck::FakeCodeItem::Make(1, 0, 0, insns);
        src.RegisterMethod(0, 7, 1, "Lcom/X;", "one", "()V", std::move(code));
        auto built = MethodSnapshotBuilder::Build(src, 0, 7);
        check("[bad-entry short] one block", static_cast<int>(built->blocks.size()), 1);
        built->entry_block_id = 7;           // in a 1-block snapshot: out of range
        Vmap vm; GenInvokeRetName ret;
        std::string why;
        try { Construct(*built, vm, ret); } catch (const std::exception& e) { why = e.what(); }
        // The MESSAGE, not merely "something threw": with the bound weakened to
        // `blocks.empty()` this snapshot walks past it and the out-of-range read
        // happens to throw from elsewhere, so the boolean form accepted the
        // mutant. Verified against it.
        check_str("[bad-entry short] refused by the bound", why,
                  "Construct: entry_block_id names no block");
    }

    std::printf("\n%s — %d failure(s)\n", g_fail ? "FAIL" : "PASS", g_fail);
    return g_fail ? 1 : 0;
}
