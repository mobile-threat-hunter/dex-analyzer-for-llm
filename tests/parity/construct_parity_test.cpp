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
    // Test 6c (dexllm#73): the entry is SEEDED into `seen`, so a back edge
    // targeting it does not build it twice
    // ============================================================
    // dexllm#73 simplified `if (*entry < seen.size()) seen[*entry] = 1;` to a
    // bare `seen[*entry] = 1;` on the strength of the new top-of-function
    // bound. The comment explains the line's BOUND; its PURPOSE is the seed —
    // without it, a child edge back to the entry re-enqueues it and the block
    // is built a second time. An adversarial reviewer deleted the line and it
    // survived ctest, the corpus-less suite AND a narrowed run, while changing
    // decompiled output on two unmodified AOSP dexes. `goto -1` back to unit 0
    // is the smallest input that has the shape.
    {
        mck::MockCodeSource src;
        std::vector<dex::u2> insns = {0x0012, 0xFF28};  // const/4 v0,#0 ; goto -1
        auto code = mck::FakeCodeItem::Make(1, 0, 0, insns);
        src.RegisterMethod(0, 9, 1, "Lcom/X;", "selfloop", "()V", std::move(code));
        auto snap = MethodSnapshotBuilder::Build(src, 0, 9);
        check("[self-loop] one block", static_cast<int>(snap->blocks.size()), 1);
        Vmap vm; GenInvokeRetName ret;
        auto g = Construct(*snap, vm, ret);
        // Exactly one node: without the seed the entry is enqueued twice and
        // BuildNodeFromBlock runs again, so the graph carries a duplicate.
        check("[self-loop] entry built exactly once",
              static_cast<int>(g->size()), 1);
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

    // ============================================================
    // Test 7 (dexllm#75): a leader BELOW the first instruction
    // ============================================================
    // The builder named block 0 the entry, and block 0's span starts at the
    // lowest LEADER — which is the first instruction only when nothing else is
    // seeded below it. A code item that opens with a payload (DecodeAllInsns
    // skips those) plus any leader inside that payload makes block 0 an EMPTY
    // span, ComputeChildEdges gives it no successor, and the whole body was
    // dropped. Two routes, because they are seeded by different stages and only
    // one of them needs a try table; both must reach the same entry.
    //
    // These are the C++ half of a two-layer matrix: they pin the ABI contract
    // (`entry_block_id`, `entry_not_at_offset_zero`) that no Python assertion
    // can see, while tests/test_entry_block.py pins what the two emitters
    // RENDER. Neither layer alone kills every mutant.
    {
        // 7a — a plain BRANCH TARGET at 0, no try table anywhere. VerifyInsns
        // bounds a branch target's RANGE and does not require it to be an
        // instruction boundary, so this is gate-legal.
        mck::MockCodeSource src;
        std::vector<dex::u2> insns = {
            0x0100, 0x0000, 0x0000, 0x0000,  // units 0-3: packed-switch payload
            0x0038, 0xFFFC,                  // unit 4: if-eqz v0, -4  → unit 0
            0x000e,                          // unit 6: return-void
        };
        auto code = mck::FakeCodeItem::Make(1, 0, 0, insns);
        src.RegisterMethod(0, 20, 1, "Lcom/X;", "br", "()V", std::move(code));
        auto snap = MethodSnapshotBuilder::Build(src, 0, 20);
        check("[entry br] first instruction at byte 8",
              static_cast<int>(snap->ins_storage.front().byte_off), 8);
        check("[entry br] block 0 carries no instruction",
              static_cast<int>(snap->blocks[0].ins.size()), 0);
        check("[entry br] entry is NOT block 0",
              snap->entry_block_id.value_or(999) != 0u, true);
        check("[entry br] entry block starts at the first instruction",
              static_cast<int>(snap->blocks[*snap->entry_block_id].start_byte), 8);
        check("[entry br] entry block HAS instructions",
              static_cast<int>(snap->blocks[*snap->entry_block_id].ins.size()) > 0,
              true);
        check("[entry br] marked as not-at-offset-0",
              snap->entry_not_at_offset_zero, true);
        Vmap vm; GenInvokeRetName ret;
        auto g = Construct(*snap, vm, ret);
        check("[entry br] the body survives", static_cast<int>(g->size()) > 1, true);
    }
    {
        // 7b — the same shape reached through a try-range START at 0 (stage 3).
        mck::MockCodeSource src;
        std::vector<dex::u2> insns = {
            0x0100, 0x0000, 0x0000, 0x0000,  // units 0-3: packed-switch payload
            0x1012,                          // unit 4: const/4 v0, #1
            0x000e,                          // unit 5: return-void
        };
        std::vector<dex::TryBlock> tries(1);
        tries[0].start_addr = 0;
        tries[0].insn_count = 6;
        tries[0].handler_off = 1;
        std::vector<uint8_t> handlers = {0x01, 0x00, 0x05};
        auto code = mck::FakeCodeItem::Make(2, 0, 0, insns, tries, handlers);
        src.RegisterMethod(0, 21, 1, "Lcom/X;", "tr", "()V", std::move(code));
        auto snap = MethodSnapshotBuilder::Build(src, 0, 21);
        check("[entry try] block 0 carries no instruction",
              static_cast<int>(snap->blocks[0].ins.size()), 0);
        check("[entry try] entry is NOT block 0",
              snap->entry_block_id.value_or(999) != 0u, true);
        check("[entry try] entry block starts at the first instruction",
              static_cast<int>(snap->blocks[*snap->entry_block_id].start_byte), 8);
        check("[entry try] entry block HAS instructions",
              static_cast<int>(snap->blocks[*snap->entry_block_id].ins.size()) > 0,
              true);
        check("[entry try] marked as not-at-offset-0",
              snap->entry_not_at_offset_zero, true);
        Vmap vm; GenInvokeRetName ret;
        auto g = Construct(*snap, vm, ret);
        // `> 1`, not `> 0`: Construct always builds the entry node, and here the
        // empty block 0 additionally carries an exception edge, so the graph is
        // size 2 even PRE-FIX — a correctness review built the entry-reverted
        // mutant and watched this very check report `got=1 want=1` while the
        // Python probe showed the body dropped. A check whose label is "the body
        // survives" must not pass against the build in which it does not.
        check("[entry try] the body survives", static_cast<int>(g->size()) > 1, true);
    }
    {
        // 7c — a leading payload with NOTHING seeded inside it. Block 0 already
        // held the first instruction, so the ENTRY does not move; only the
        // marker fires. This is what separates the two predicates: keying the
        // marker on `entry_block_id != 0` would leave this case silent.
        mck::MockCodeSource src;
        std::vector<dex::u2> insns = {
            0x0100, 0x0000, 0x0000, 0x0000,
            0x1012, 0x000e,
        };
        auto code = mck::FakeCodeItem::Make(1, 0, 0, insns);
        src.RegisterMethod(0, 22, 1, "Lcom/X;", "po", "()V", std::move(code));
        auto snap = MethodSnapshotBuilder::Build(src, 0, 22);
        check("[entry payload-only] one block",
              static_cast<int>(snap->blocks.size()), 1);
        check("[entry payload-only] entry IS block 0",
              static_cast<int>(snap->entry_block_id.value_or(999)), 0);
        check("[entry payload-only] still marked",
              snap->entry_not_at_offset_zero, true);
    }
    {
        // 7d — the control: an ordinary body. Entry at block 0, unmarked. A
        // marker emitted unconditionally would append the comment to every
        // method in every APK and pass every assertion above.
        mck::MockCodeSource src;
        std::vector<dex::u2> insns = {0x1012, 0x000e};
        auto code = mck::FakeCodeItem::Make(1, 0, 0, insns);
        src.RegisterMethod(0, 23, 1, "Lcom/X;", "ok", "()V", std::move(code));
        auto snap = MethodSnapshotBuilder::Build(src, 0, 23);
        check("[entry normal] entry IS block 0",
              static_cast<int>(snap->entry_block_id.value_or(999)), 0);
        check("[entry normal] unmarked", snap->entry_not_at_offset_zero, false);
        check("[entry normal] block 0 has instructions",
              static_cast<int>(snap->blocks[0].ins.size()) > 0, true);
    }


    // ============================================================
    // Test 8 (dexllm#77): a block whose LEADER is not an instruction boundary
    // ============================================================
    // A leader only has to be an in-range BYTE OFFSET, so it can point into a
    // payload (which DecodeAllInsns skips) or into the tail of a multi-unit
    // instruction. `SplitIntoBlocks` looked the span up at the START ALONE, so
    // such a block came back EMPTY even when instructions lie inside it — they
    // belonged to no block at all — and `ComputeChildEdges` skipped every empty
    // block, leaving it with no successor. These properties live on the
    // snapshot ABI and NO Python assertion can see them: the surviving mutant a
    // correctness review built (take the LAST instruction in the span rather
    // than the first) is exactly this layer.
    {
        // 8a — the span BEGINS off a boundary and carries TWO instructions.
        //   0 if-eqz v0,+7 -> 14 (inside the payload at 8..16)
        //   4 const/4 v0 | 6 nop | 8..16 payload | 16 const/4 v1 | 18 return
        // The block starting at 14 must hold BOTH 16 and 18, and must be read
        // from the FIRST of them.
        mck::MockCodeSource src;
        std::vector<dex::u2> insns = {0x0038, 0x0007, 0x1012, 0x0000,
                                      0x0100, 0x0000, 0x0000, 0x0000,
                                      0x3112, 0x0111};
        auto code = mck::FakeCodeItem::Make(2, 0, 0, insns);
        src.RegisterMethod(0, 24, 1, "Lcom/X;", "pair", "()V", std::move(code));
        auto snap = MethodSnapshotBuilder::Build(src, 0, 24);
        const RawBlock* b = nullptr;
        for (const auto& blk : snap->blocks)
            if (blk.start_byte == 14) b = &blk;
        check("[leader pair] a block starts at 14", b != nullptr, true);
        if (b) {
            check("[leader pair] it is marked off-boundary",
                  b->starts_off_instruction, true);
            check("[leader pair] it holds TWO instructions",
                  static_cast<int>(b->ins.size()), 2);
            check("[leader pair] read from the FIRST one",
                  static_cast<int>(b->ins.front().byte_off), 16);
            check("[leader pair] and not past the span",
                  static_cast<int>(b->ins.back().byte_off), 18);
        }
    }
    {
        // 8b — a span that is payload bytes END TO END stays empty and gets
        // EXACTLY ONE fall-through edge to the block after it.
        //   0 const/4 | 2 if-eqz v0,+3 -> 8 (inside the payload at 6..14)
        //   6..14 payload | 14 const/4 | 16 return-void
        mck::MockCodeSource src;
        std::vector<dex::u2> insns = {0x1012, 0x0038, 0x0003,
                                      0x0100, 0x0000, 0x0000, 0x0000,
                                      0x1012, 0x000e};
        auto code = mck::FakeCodeItem::Make(2, 0, 0, insns);
        src.RegisterMethod(0, 25, 1, "Lcom/X;", "empty", "()V", std::move(code));
        auto snap = MethodSnapshotBuilder::Build(src, 0, 25);
        const RawBlock* b = nullptr;
        uint32_t at14 = UINT32_MAX;
        for (uint32_t i = 0; i < snap->blocks.size(); ++i) {
            if (snap->blocks[i].start_byte == 8) b = &snap->blocks[i];
            if (snap->blocks[i].start_byte == 14) at14 = i;
        }
        check("[leader empty] a block starts at 8", b != nullptr, true);
        check("[leader empty] a block starts at 14", at14 != UINT32_MAX, true);
        if (b) {
            check("[leader empty] it holds NO instruction",
                  static_cast<int>(b->ins.size()), 0);
            check("[leader empty] it is marked off-boundary",
                  b->starts_off_instruction, true);
            check("[leader empty] exactly one successor",
                  static_cast<int>(b->childs.size()), 1);
            if (b->childs.size() == 1) {
                check("[leader empty] and it falls FORWARD to 14",
                      static_cast<int>(b->childs[0].target_block_id),
                      static_cast<int>(at14));
                check("[leader empty] as a fall-through",
                      b->childs[0].kind == ChildEdge::Kind::Fallthrough, true);
            }
        }
        // The marker is qualified by bfs REACHABILITY: this block IS reached
        // (both arms of the if enter it), so the graph carries the flag.
        Vmap vm; GenInvokeRetName ret;
        auto g = Construct(*snap, vm, ret);
        check("[leader empty] the built graph is marked",
              g->control_enters_non_instruction, true);
    }
    {
        // 8c — the CONTROL: the same body with the branch landing on a real
        // boundary. Nothing off-boundary, nothing marked, no synthetic edge.
        mck::MockCodeSource src;
        std::vector<dex::u2> insns = {0x1012, 0x0038, 0x0006,
                                      0x0000, 0x0000, 0x0000, 0x0000,
                                      0x1012, 0x000e};
        auto code = mck::FakeCodeItem::Make(2, 0, 0, insns);
        src.RegisterMethod(0, 26, 1, "Lcom/X;", "ctl", "()V", std::move(code));
        auto snap = MethodSnapshotBuilder::Build(src, 0, 26);
        bool any_off = false;
        for (const auto& blk : snap->blocks)
            if (blk.starts_off_instruction) any_off = true;
        check("[leader control] no block is off-boundary", any_off, false);
        Vmap vm; GenInvokeRetName ret;
        auto g = Construct(*snap, vm, ret);
        check("[leader control] the graph is unmarked",
              g->control_enters_non_instruction, false);
    }
    {
        // 8d — an off-boundary leader in DEAD code marks NOTHING. The flag is
        // the raw structural fact on the block; the GRAPH's flag additionally
        // requires the bfs to have built it, so a block no control reaches
        // cannot make the method claim a reinterpretation that never happened.
        //   0 const/4 | 2 return-void | 4 if-eqz v0,+3 -> 10 (in the payload)
        //   8..16 payload | 16 return-void          (everything after 2 is dead)
        mck::MockCodeSource src;
        std::vector<dex::u2> insns = {0x1012, 0x000e, 0x0038, 0x0003,
                                      0x0100, 0x0000, 0x0000, 0x0000,
                                      0x000e};
        auto code = mck::FakeCodeItem::Make(2, 0, 0, insns);
        src.RegisterMethod(0, 27, 1, "Lcom/X;", "dead", "()V", std::move(code));
        auto snap = MethodSnapshotBuilder::Build(src, 0, 27);
        bool any_off = false;
        for (const auto& blk : snap->blocks)
            if (blk.starts_off_instruction) any_off = true;
        check("[leader dead] the block IS off-boundary in the snapshot",
              any_off, true);
        Vmap vm; GenInvokeRetName ret;
        auto g = Construct(*snap, vm, ret);
        check("[leader dead] but the built graph is NOT marked",
              g->control_enters_non_instruction, false);
    }

    {
        // 8e — an empty block that is an EXCEPTION-HANDLER entry gets NO
        // successor. Control reaches a handler on a THROW, and the fall-through
        // models LINEAR flow; a handler address landing in a payload would
        // otherwise "continue" into the region it protects, whose catch edge
        // leads straight back to it — a cycle the structured emit walk cannot
        // terminate on, which turns a method HEAD renders into
        // `// DECOMPILE ERROR: structured emit recursion too deep`
        // (found by an adversarial review on a STRICT-verify-valid dex).
        //   0 const/4 | 2 if-eqz v0,+6 -> 14 | 6..14 payload | 14 const/4
        //   | 16 return-void ; try[0..2) with a catch-all handler at unit 5
        //   (byte 10) — INSIDE the payload, and nothing branches there.
        mck::MockCodeSource src;
        std::vector<dex::u2> insns = {0x1012, 0x0038, 0x0006,
                                      0x0100, 0x0000, 0x0000, 0x0000,
                                      0x1012, 0x000e};
        std::vector<dex::TryBlock> tries(1);
        tries[0].start_addr = 0;
        tries[0].insn_count = 1;
        tries[0].handler_off = 1;
        std::vector<uint8_t> handlers = {0x01, 0x00, 0x05};
        auto code = mck::FakeCodeItem::Make(2, 0, 0, insns, tries, handlers);
        src.RegisterMethod(0, 28, 1, "Lcom/X;", "hdl", "()V", std::move(code));
        auto snap = MethodSnapshotBuilder::Build(src, 0, 28);
        const RawBlock* b = nullptr;
        for (const auto& blk : snap->blocks)
            if (blk.start_byte == 10) b = &blk;
        check("[leader handler] a block starts at the handler addr",
              b != nullptr, true);
        if (b) {
            check("[leader handler] it holds NO instruction",
                  static_cast<int>(b->ins.size()), 0);
            check("[leader handler] and gets NO successor",
                  static_cast<int>(b->childs.size()), 0);
        }
    }
    {
        // 8f — a leader EQUAL to insns_byte_size makes a block whose span is
        // empty in both directions (`start == end`). `FindBlockIdForByteOff`
        // looks its own `end_byte` up and finds ITSELF, so an unguarded
        // fall-through is a SELF-EDGE and the writer fabricates a
        // `while(true) { }` the bytecode does not contain. Reachable under
        // `lenient=True` (strict VerifyInsns bounds a branch target below
        // insns_size, but ComputeLeaders inserts the target with no bound of
        // its own), which is the packer-dump mode.
        //   0 const/4 | 2 if-eqz v0,+3 -> 8 == insns_byte_size | 6 return-void
        mck::MockCodeSource src;
        std::vector<dex::u2> insns = {0x1012, 0x0038, 0x0003, 0x000e};
        auto code = mck::FakeCodeItem::Make(2, 0, 0, insns);
        src.RegisterMethod(0, 29, 1, "Lcom/X;", "selfedge", "()V", std::move(code));
        auto snap = MethodSnapshotBuilder::Build(src, 0, 29);
        const RawBlock* b = nullptr;
        for (const auto& blk : snap->blocks)
            if (blk.start_byte == 8) b = &blk;
        check("[leader selfedge] a block starts at insns_byte_size",
              b != nullptr, true);
        if (b) {
            check("[leader selfedge] its span is empty",
                  static_cast<int>(b->end_byte), 8);
            check("[leader selfedge] and it gets NO successor",
                  static_cast<int>(b->childs.size()), 0);
        }
    }

    std::printf("\n%s — %d failure(s)\n", g_fail ? "FAIL" : "PASS", g_fail);
    return g_fail ? 1 : 0;
}
