// writer.h — C++ port of androguard DAD writer.py
// DAD: androguard/decompiler/writer.py
//
// Emits Java source from a structured CFG + IR. Uses dynamic_cast-based
// dispatch in `EmitExpr` rather than the Visitor pattern — DAD's Python
// duck-typed visit_X dispatch becomes a switch on IRForm subtype here.
// Output parity is the contract; how we dispatch is implementation detail.
//
// PORT STATUS: ported (subset of writer.py — block structure + common
//   expressions). Full DAD parity (47 visit methods + buffer2 extended
//   output) deferred.

#pragma once

#include <memory>
#include <ostream>
#include <sstream>
#include <string>
#include <unordered_set>
#include <vector>

#include "basic_blocks.h"
#include "graph.h"
#include "instruction.h"
#include "method_snapshot.h"
#include "node.h"

namespace dexkit::dad {

class WriterImpl;  // visitor.cpp-side impl, friend below

class Writer {
public:
    // `snap` and `graph` are borrowed; caller ensures lifetime.
    Writer(const MethodSnapshot* snap, const Graph* graph);

    friend class WriterImpl;

    // Top-level entry — emits the full method (signature + body).
    void WriteMethod();

    // Final source string.
    std::string str() const { return buffer_.str(); }

    // D-3 (dexllm#1) — (java_line_1based, dex_byte_offset) pairs harvested as a
    // side-effect of WriteMethod. One entry per line (first-anchor-wins). Lines
    // with no underlying RawIns (closing braces, `while(true)`, blank lines)
    // simply don't appear. Observe-only — never mutates buffer_, so DAD-faithful
    // text output stays byte-identical.
    const std::vector<std::pair<uint32_t, uint32_t>>& pc_map() const {
        return pc_map_;
    }

private:
    // ─── Node-level emission ─────────────────────────────────────────────
    void VisitNode(NodeBase* node);
    void EmitStatement(StatementBlock* stmt);
    void EmitReturn(ReturnBlock* ret);
    void EmitThrow(ThrowBlock* thr);
    void EmitIf(CondBlock* cond);
    void EmitLoop(LoopBlock* loop);
    void EmitSwitch(SwitchBlock* sw);
    void EmitTry(TryBlock* tb);

    // ─── IR-level emission ───────────────────────────────────────────────
    // Emits a statement form (no trailing semicolon — VisitIns adds it).
    void VisitIns(const IRFormPtr& ins);
    // Emits an expression form.
    void EmitExpr(IRForm* op);

    // ─── Utilities ───────────────────────────────────────────────────────
    void WriteIndent();
    void Write(std::string_view s) {
        buffer_ << s;
        // D-3 — track the current 1-based output line for pc_map harvesting.
        for (char c : s)
            if (c == '\n') ++current_line_;
    }

    // D-3 — record (line ↔ ir's dex offset). First-anchor-wins: skips when ir
    // is synthesized (UINT32_MAX) or `line` already has an entry. `line` is
    // passed explicitly so statement callers can stamp the line where the node
    // STARTED emitting (current_line_ may have advanced past it after a trailing
    // newline). Header callers pass current_line_ (they emit on the spot).
    void RecordLineAt(uint32_t line, const IRForm* ir) {
        if (!ir || ir->source_byte_off == UINT32_MAX) return;
        if (!pc_map_.empty() && pc_map_.back().first == line) return;
        pc_map_.emplace_back(line, ir->source_byte_off);
    }
    void RecordLine(const IRForm* ir) { RecordLineAt(current_line_, ir); }
    // D-3 — representative offset-bearing IR for a condition/loop/switch header.
    // Mirrors dast.cpp get_cond_block's short-circuit/loop dispatch so compound
    // `(a && b) || c` headers resolve through Condition::get_ins() (concats arms)
    // instead of the empty BasicBlock::ins on a ShortCircuitBlock.
    const IRForm* CondReprIns(CondBlock* node);
    void IncIndent(int n = 1) { indent_ += 4 * n; }
    void DecIndent(int n = 1) { indent_ -= 4 * n; }
    std::string Space() const { return std::string(indent_, ' '); }
    void EndIns() { Write(";\n"); }

    // Compute Java type from Dalvik descriptor — wraps util::GetType.
    std::string JavaType(std::string_view desc);

    // Resolve IRForm from var_map by id; nullptr if missing.
    IRForm* MapGet(const IRForm* owner, const std::string& key);

    // ─── State ───────────────────────────────────────────────────────────
    const MethodSnapshot* snap_;
    const Graph* graph_;
    std::ostringstream buffer_;
    int indent_ = 0;
    int depth_ = 0;  // VisitNode recursion depth (stack-overflow guard)

    // D-3 — pc_map harvest state.
    uint32_t current_line_ = 1;
    std::vector<std::pair<uint32_t, uint32_t>> pc_map_;

    // Structural follow stacks (DAD: writer.loop_follow / if_follow / ...).
    std::vector<NodeBase*> loop_follow_{nullptr};
    std::vector<NodeBase*> if_follow_{nullptr};
    std::vector<NodeBase*> switch_follow_{nullptr};
    std::vector<NodeBase*> latch_node_{nullptr};
    std::vector<NodeBase*> try_follow_{nullptr};
    std::unordered_set<NodeBase*> visited_;
    NodeBase* next_case_ = nullptr;
    bool need_break_ = true;
    bool is_constructor_ = false;
    // Beyond-DAD: <clinit> (static initializer) carries ACC_CONSTRUCTOR in dex,
    // so DAD renders it as `static <ClassName>()` with a trailing `return;` —
    // both invalid Java (a static init is a `static { }` block; `return` is a
    // compile error inside an initializer, JLS §8.7). Set in WriteMethod;
    // consumed by the header emission and visit_return_void.
    bool is_clinit_ = false;
    // TAIL POSITION — true while emitting a statement whose completion ends the
    // method with no further code on any path (structural, tracked through the
    // Emit* recursion, NOT via indent). A <clinit>'s return-void is dropped iff
    // it is in tail position: fall-through is then equivalent to `return`, and
    // `return` is illegal in an initializer (JLS §8.7). Propagated true through
    // the top-level statement chain and into if/else branches whose `if` has NO
    // follow (the if is itself the tail); set false inside loops / switch / try
    // and non-tail branches, so a genuinely-early return (code executes after it)
    // is KEPT DAD-faithful. Only READ when is_clinit_, so non-<clinit> output is
    // byte-identical regardless of this flag.
    bool tail_pos_ = false;
    // DAD: writer.py: self.skip — set by visit_invoke when ThisParam.<init>()
    // is elided. Consumed by the NEXT write_ind which suppresses its indent.
    // Lives on Writer (persistent) so it carries across VisitIns calls.
    bool skip_ = false;
};

// String-literal escape helper (DAD: writer.py:757). Public for Writer-free
// callers (e.g., tests that format Java literals directly).
std::string EscapeJavaString(std::string_view raw);

}  // namespace dexkit::dad
