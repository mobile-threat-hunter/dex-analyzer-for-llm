// dast.h — C++ port of androguard DAD dast.py
// DAD: androguard/decompiler/dast.py
//
// dast.py is "a simplified version of writer.py that outputs an AST instead of
// source code" (its module docstring). The JSONWriter walks the same structured
// CFG + IR as writer.py's Writer, but instead of emitting Java text it builds a
// nested-list AST tagged with type strings (`['IfStatement', ...]`,
// `['Literal', ...]`, ...) and returns it from get_ast() as a dict.
//
// The nested-list/tuple structure is represented here by `AstValue` — a small
// JSON value tree (null / bool / int / string / array / ordered-object). DAD's
// Python tuples and lists both serialize to JSON arrays, so we model both as
// AstValue::Arr; the only object is the top-level get_ast() dict.
//
// PORT STATUS: full port — JSONWriter with all visit_* node methods, visit_ins,
// visit_expr (40+ IR-form branches), and the literal/factory helpers. Every
// method carries a `// DAD: dast.py:<lineno> <concept>` comment in dast.cpp.

#pragma once

#include <cstdint>
#include <memory>
#include <string>
#include <utility>
#include <vector>

#include "basic_blocks.h"
#include "graph.h"
#include "instruction.h"
#include "method_snapshot.h"
#include "node.h"

namespace dexkit::dad {

// ─────────────────────────────────────────────────────────────────────────────
// AstValue — minimal JSON value tree mirroring DAD's nested-list AST.
// ─────────────────────────────────────────────────────────────────────────────
class AstValue {
public:
    enum class Kind { Null, Bool, Int, Str, Arr, Obj };

    AstValue() : kind_(Kind::Null) {}

    static AstValue Null() { return AstValue(); }
    static AstValue Bool(bool b) { AstValue v; v.kind_ = Kind::Bool; v.b_ = b; return v; }
    static AstValue Int(int64_t i) { AstValue v; v.kind_ = Kind::Int; v.i_ = i; return v; }
    static AstValue Str(std::string s) {
        AstValue v; v.kind_ = Kind::Str; v.s_ = std::move(s); return v;
    }
    static AstValue Arr(std::vector<AstValue> a = {}) {
        AstValue v; v.kind_ = Kind::Arr; v.arr_ = std::move(a); return v;
    }
    static AstValue Obj() { AstValue v; v.kind_ = Kind::Obj; return v; }

    Kind kind() const noexcept { return kind_; }
    bool is_null() const noexcept { return kind_ == Kind::Null; }

    bool as_bool() const noexcept { return b_; }
    int64_t as_int() const noexcept { return i_; }
    const std::string& as_str() const noexcept { return s_; }
    const std::vector<AstValue>& as_arr() const noexcept { return arr_; }
    const std::vector<std::pair<std::string, AstValue>>& as_obj() const noexcept {
        return obj_;
    }

    // Array mutation (used while building scopes / statement blocks).
    void push_back(AstValue v) { arr_.push_back(std::move(v)); }
    AstValue& at(std::size_t idx) { return arr_.at(idx); }

    // Object insertion (ordered, used only for the top-level get_ast() dict).
    void set(std::string key, AstValue v) {
        obj_.emplace_back(std::move(key), std::move(v));
    }

    // JSON serialization (ensure_ascii, matching Python json.dumps default).
    // Used by the C++ parity test; the pybind11 path converts to py objects
    // and lets Python serialize instead.
    std::string dump() const {
        std::string out;
        Dump(out);
        return out;
    }

private:
    void Dump(std::string& out) const;

    Kind kind_;
    bool b_ = false;
    int64_t i_ = 0;
    std::string s_;
    std::vector<AstValue> arr_;
    std::vector<std::pair<std::string, AstValue>> obj_;
};

// ─────────────────────────────────────────────────────────────────────────────
// JSONWriter — DAD: dast.py:25. AST-emitting sibling of Writer.
// ─────────────────────────────────────────────────────────────────────────────
class JSONWriter {
public:
    // `snap` and `graph` are borrowed; caller ensures lifetime. `graph` may be
    // null (abstract / native / external-ref method) → body is null.
    JSONWriter(const MethodSnapshot* snap, const Graph* graph);

    // DAD: dast.py:63 get_ast — returns the method AST dict
    // {triple, flags, ret, params, comments, body}. Mutating (sets declared
    // flags, swaps branches), so run on a freshly-built graph.
    AstValue get_ast();

private:
    // ── node-level visitors (DAD dast.py:120-330) ───────────────────────────
    void visit_node(NodeBase* node);
    void visit_loop_node(LoopBlock* loop);
    void visit_cond_node(CondBlock* cond);
    void visit_switch_node(SwitchBlock* sw);
    void visit_statement_node(StatementBlock* stmt);
    void visit_try_node(TryBlock* tb);
    void visit_return_node(ReturnBlock* ret);
    void visit_throw_node(ThrowBlock* thr);

    // ── condition helpers (DAD dast.py:101-118) ─────────────────────────────
    AstValue visit_condition(Condition& cond);          // _visit_condition
    AstValue get_cond_block(CondBlock* node);            // get_cond(node)
    AstValue get_cond_operand(Condition::Operand* op);   // get_cond(cond.condN)

    // ── statement / expression (DAD dast.py:332-593) ────────────────────────
    void visit_ins(const IRFormPtr& op);
    AstValue ins_to_stmt(IRForm* op, bool is_ctor);      // _visit_ins
    AstValue write_inplace_if_possible(IRForm* lhs, IRForm* rhs);
    AstValue visit_expr(IRForm* op);
    // visit_expr, but if `operand` is an integer Constant in an F/D context (a
    // raw-IEEE-bits float/double const), emit the reinterpreted literal —
    // mirrors writer.cpp emit_fp_const_typed so the AST agrees with the text
    // path. `_fp` takes the sibling binary operand; `_fp_typed` the target type
    // directly (e.g. a method param type).
    AstValue visit_expr_fp(IRForm* operand, IRForm* sib);
    AstValue visit_expr_fp_typed(IRForm* operand, std::string_view target);
    AstValue visit_arr_data(const std::vector<int64_t>& value);
    AstValue visit_decl(Variable* var, AstValue init = AstValue::Null());

    // ── context stack (DAD's `with self as body:` pattern) ──────────────────
    static AstValue statement_block();    // ['BlockStatement', null, []]
    void add(AstValue v);                 // append to current block
    template <class F> AstValue scope(F&& body);  // with self as scope: ...

    // var_map lookup helper: op.var_map[key] → IRForm* (null if missing).
    static IRForm* MapGet(const IRForm* owner, const std::string& key);

    // ── State (DAD dast.py:30-40) ───────────────────────────────────────────
    const MethodSnapshot* snap_;
    const Graph* graph_;
    std::vector<AstValue> context_;
    std::vector<NodeBase*> loop_follow_{nullptr};
    std::vector<NodeBase*> if_follow_{nullptr};
    std::vector<NodeBase*> switch_follow_{nullptr};
    std::vector<NodeBase*> latch_node_{nullptr};
    std::vector<NodeBase*> try_follow_{nullptr};
    std::unordered_set<NodeBase*> visited_nodes_;
    NodeBase* next_case_ = nullptr;
    bool need_break_ = true;
    bool constructor_ = false;
};

// DAD: dast.py:639 parse_descriptor — Dalvik descriptor → TypeName / Dummy AST.
// Exposed for the parity test.
AstValue ParseDescriptor(std::string_view desc);

}  // namespace dexkit::dad
