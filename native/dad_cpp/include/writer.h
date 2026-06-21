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
    void Write(std::string_view s) { buffer_ << s; }
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
    // DAD: writer.py: self.skip — set by visit_invoke when ThisParam.<init>()
    // is elided. Consumed by the NEXT write_ind which suppresses its indent.
    // Lives on Writer (persistent) so it carries across VisitIns calls.
    bool skip_ = false;
};

// String-literal escape helper (DAD: writer.py:757). Public for Writer-free
// callers (e.g., tests that format Java literals directly).
std::string EscapeJavaString(std::string_view raw);

}  // namespace dexkit::dad
