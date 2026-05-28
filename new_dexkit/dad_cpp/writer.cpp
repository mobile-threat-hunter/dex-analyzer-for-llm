// writer.cpp — DAD-faithful Java emission via Visitor pattern.
//
// Each visit_X method is a 1:1 port of androguard/decompiler/writer.py.
// IRForm::Accept(Visitor&) calls into these visit_X overrides, mirroring
// DAD's `op.visit(self)` dispatch.

#include "writer.h"

#include <algorithm>
#include <cstdio>
#include <cstdlib>
#include <sstream>
#include <string>

#include "opcode_ins.h"  // Op::EQUAL etc.
#include "util.h"
#include "visitor.h"

namespace dexkit::dad {

namespace {

std::string_view StripClassDesc(std::string_view d) {
    if (d.size() >= 2 && d.front() == 'L' && d.back() == ';') {
        return d.substr(1, d.size() - 2);
    }
    return d;
}

}  // namespace

// ============================================================================
// EscapeJavaString
// ============================================================================
std::string EscapeJavaString(std::string_view raw) {
    // Dex strings are MUTF-8 (modified UTF-8): NUL as C0 80, and supplementary
    // chars encoded as surrogate pairs (each surrogate as 3 bytes with 0xED
    // prefix). pybind11 returns std::string→Python str via strict UTF-8 decode
    // which REJECTS the 0xED-prefixed surrogates. To stay safe, decode MUTF-8
    // and re-emit every non-ASCII codepoint as a Java \uXXXX escape (which is
    // always valid UTF-8 ASCII).
    std::string out;
    out.reserve(raw.size() + 2);
    out += '"';
    const uint8_t* p = reinterpret_cast<const uint8_t*>(raw.data());
    const uint8_t* end = p + raw.size();
    auto emit_u = [&](uint32_t cp) {
        char buf[8];
        std::snprintf(buf, sizeof(buf), "\\u%04x", cp);
        out += buf;
    };
    while (p < end) {
        uint8_t c = *p;
        if (c == '\\')      { out += "\\\\"; ++p; continue; }
        if (c == '"')       { out += "\\\""; ++p; continue; }
        // DAD writer.py:766 escapes single-quote in string literals too.
        // Java doesn't require it but DAD always emits `\'` — match for parity.
        if (c == '\'')      { out += "\\'";  ++p; continue; }
        if (c == '\n')      { out += "\\n";  ++p; continue; }
        if (c == '\r')      { out += "\\r";  ++p; continue; }
        if (c == '\t')      { out += "\\t";  ++p; continue; }
        if (c < 0x20)       { emit_u(c); ++p; continue; }
        if (c < 0x80)       { out += static_cast<char>(c); ++p; continue; }
        // Non-ASCII MUTF-8 sequence — decode codepoint and re-emit as \uXXXX.
        uint32_t cp = 0;
        size_t n = 0;
        if ((c & 0xE0) == 0xC0 && p + 1 < end + 1) {           // 110xxxxx
            cp = (c & 0x1F);
            n = 2;
        } else if ((c & 0xF0) == 0xE0 && p + 2 < end + 1) {    // 1110xxxx
            cp = (c & 0x0F);
            n = 3;
        } else if ((c & 0xF8) == 0xF0 && p + 3 < end + 1) {    // 11110xxx
            cp = (c & 0x07);
            n = 4;
        } else {
            // Invalid leading byte — emit as raw escape to avoid UTF-8 error.
            emit_u(c);
            ++p;
            continue;
        }
        if (p + n > end) { emit_u(c); ++p; continue; }
        for (size_t i = 1; i < n; ++i) {
            uint8_t t = p[i];
            if ((t & 0xC0) != 0x80) { cp = c; n = 1; break; }
            cp = (cp << 6) | (t & 0x3F);
        }
        emit_u(cp);
        p += n;
    }
    out += '"';
    return out;
}

// ============================================================================
// Writer — full DAD-aligned implementation.
//
// Class derives from Visitor so visit_X overrides actually dispatch through
// the IR's Accept methods. Block-level Emit* methods stay as direct dispatch
// since BasicBlock::Visit isn't yet wired.
// ============================================================================

// Helper: forward Writer's Visitor interface onto its EmitExpr replacement.
class WriterImpl : public Visitor {
public:
    explicit WriterImpl(Writer* w) : w_(w) {}

    // ─── primitive emission ──────────────────────────────────────────────
    void write(std::string_view s) override { w_->Write(s); }
    void inc_ind(int n) override { w_->IncIndent(n); }
    void dec_ind(int n) override { w_->DecIndent(n); }
    void end_ins() override { w_->EndIns(); }
    void write_ind() override { w_->WriteIndent(); }

    // ─── visit_decl: DAD writer.py:452 ────────────────────────────────────
    void visit_decl(Variable* var) override {
        if (!var) return;
        if (var->declared) return;
        std::string vt = var->get_type();
        if (vt.empty()) vt = "unknownType";
        w_->WriteIndent();
        w_->Write(GetType(vt));
        w_->Write(" v");
        std::string nm = var->name;
        if (!nm.empty() && nm.front() == 'v') nm.erase(0, 1);
        w_->Write(nm);
        w_->EndIns();
        var->declared = true;
    }

    // ─── visit_constant: DAD writer.py:461 (split per overload) ──────────
    void visit_constant_int(int64_t value) override {
        w_->Write(std::to_string(value));
    }
    void visit_constant_double(double value) override {
        char buf[64];
        std::snprintf(buf, sizeof(buf), "%g", value);
        w_->Write(buf);
    }
    void visit_constant_string(std::string_view value) override {
        // DAD: visit_constant uses `string()` (escape) for str instances.
        // The "true"/"false" bool case passes a Python str already.
        // Heuristic: if value is "true"/"false" emit as-is; else escape.
        if (value == "true" || value == "false") {
            w_->Write(value);
        } else {
            w_->Write(EscapeJavaString(value));
        }
    }

    // ─── visit_base_class: DAD writer.py:468 ─────────────────────────────
    void visit_base_class(std::string_view cls) override {
        // DAD writes raw class name. Render dotted Java form.
        if (cls.empty()) return;
        // For raw "Lcom/X;" / "[I" etc., apply GetType. For pre-stripped
        // names (e.g., from BaseClass.cls which already underwent get_type),
        // emit as-is. Heuristic: if starts with 'L' and ends with ';',
        // apply GetType; otherwise emit raw.
        if (cls.size() >= 2 && cls.front() == 'L' && cls.back() == ';') {
            w_->Write(GetType(cls));
        } else {
            w_->Write(cls);
        }
    }

    // ─── visit_variable: DAD writer.py:472 ───────────────────────────────
    void visit_variable(Variable* var) override {
        if (!var) return;
        if (!var->declared) {
            std::string vt = var->get_type();
            if (vt.empty()) vt = "unknownType";
            w_->Write(GetType(vt));
            w_->Write(" ");
            var->declared = true;
        }
        // DAD: 'v%s' % var.name where var.name is just the register number.
        // In our port, Variable.name == Variable.v_ == "v3" (full string).
        // Strip leading 'v' to avoid double-prefix.
        std::string nm = var->name;
        if (!nm.empty() && nm.front() == 'v') nm.erase(0, 1);
        w_->Write("v");
        w_->Write(nm);
    }

    // ─── visit_param: DAD writer.py:484 ──────────────────────────────────
    void visit_param(std::string_view name, std::string_view /*type_desc*/) override {
        w_->Write("p");
        // DAD's param value is an int register; our `name` is "vN" string.
        // Strip the leading 'v' if present so output is "pN".
        if (!name.empty() && name.front() == 'v') name.remove_prefix(1);
        w_->Write(name);
    }

    void visit_this() override { w_->Write("this"); }
    void visit_super() override { w_->Write("super"); }

    // DAD: writer.py:357 visit_short_circuit_condition.
    // cond1/cond2 are Condition::Operand* (passed as void* through the
    // Visitor interface to avoid basic_blocks.h ↔ visitor.h dependency).
    void visit_short_circuit_condition(bool isnot, bool isand,
                                        void* c1_p, void* c2_p) override {
        auto* cond1 = static_cast<Condition::Operand*>(c1_p);
        auto* cond2 = static_cast<Condition::Operand*>(c2_p);
        if (isnot && cond1) cond1->neg();
        w_->Write("(");
        if (cond1) cond1->visit_cond(*this);
        w_->Write(isand ? ") && (" : ") || (");
        if (cond2) cond2->visit_cond(*this);
        w_->Write(")");
    }

    // ─── visit_assign: DAD writer.py:494 ─────────────────────────────────
    void visit_assign(IRForm* lhs, IRForm* rhs) override {
        if (lhs != nullptr) {
            return write_inplace_if_possible(lhs, rhs);
        }
        w_->WriteIndent();
        visit_ins(rhs);
        // DAD: if not self.skip: self.end_ins(). skip lives on Writer now.
        if (!w_->skip_) w_->EndIns();
    }

    // ─── visit_move_result: DAD writer.py:502 ────────────────────────────
    void visit_move_result(IRForm* lhs, IRForm* rhs) override {
        write_ind_visit_end(lhs, " = ", rhs);
    }

    // ─── visit_move: DAD writer.py:505 ───────────────────────────────────
    void visit_move(IRForm* lhs, IRForm* rhs) override {
        if (lhs != rhs) write_inplace_if_possible(lhs, rhs);
    }

    // ─── visit_astore: DAD writer.py:509 ─────────────────────────────────
    void visit_astore(IRForm* array, IRForm* index, IRForm* rhs) override {
        w_->WriteIndent();
        visit_ins(array);
        w_->Write("[");
        visit_ins(index);
        w_->Write("] = ");
        visit_ins(rhs);
        w_->EndIns();
    }

    // ─── visit_put_static: DAD writer.py:518 ─────────────────────────────
    void visit_put_static(std::string_view cls, std::string_view name,
                          IRForm* rhs) override {
        w_->WriteIndent();
        w_->Write(cls);
        w_->Write(".");
        w_->Write(name);
        w_->Write(" = ");
        visit_ins(rhs);
        w_->EndIns();
    }

    // ─── visit_put_instance: DAD writer.py:524 ───────────────────────────
    void visit_put_instance(IRForm* lhs, std::string_view name,
                            IRForm* rhs) override {
        w_->WriteIndent();
        visit_ins(lhs);
        w_->Write(".");
        w_->Write(name);
        w_->Write(" = ");
        visit_ins(rhs);
        w_->EndIns();
    }

    // ─── visit_new: DAD writer.py:535 ────────────────────────────────────
    void visit_new(std::string_view atype, NewInstance* /*data*/) override {
        w_->Write("new ");
        w_->Write(GetType(atype));
    }

    // ─── visit_invoke: DAD writer.py:542 ─────────────────────────────────
    void visit_invoke(std::string_view name, IRForm* base,
                      const std::vector<std::string>& /*ptype*/,
                      std::string_view /*rtype*/,
                      const std::vector<IRForm*>& args,
                      InvokeInstruction* invokeInstr) override {
        if (auto* tp = dynamic_cast<ThisParam*>(base)) {
            if (name == "<init>") {
                if (constructor_ && args.empty()) {
                    // DAD: skip the implicit `this()` super-call.
                    w_->skip_ = true;
                    return;
                }
                // DAD writer.py:548-552 — if target class differs from base's
                // own type, this is a super-call. Set the super flag so
                // ThisParam::Accept emits "super" instead of "this".
                if (invokeInstr) {
                    std::string base_type_java = GetType(tp->get_type());
                    if (base_type_java != invokeInstr->cls()) {
                        tp->super_flag = true;
                    }
                }
            }
        }
        visit_ins(base);
        if (name != "<init>") {
            w_->Write(".");
            w_->Write(name);
        }
        w_->Write("(");
        bool first = true;
        for (IRForm* arg : args) {
            if (!first) w_->Write(", ");
            first = false;
            visit_ins(arg);
        }
        w_->Write(")");
    }

    void visit_return_void() override {
        w_->WriteIndent();
        w_->Write("return");
        w_->EndIns();
    }
    void visit_return(IRForm* arg) override {
        w_->WriteIndent();
        w_->Write("return ");
        visit_ins(arg);
        w_->EndIns();
    }
    void visit_nop() override {}

    void visit_switch(IRForm* arg) override { visit_ins(arg); }

    void visit_check_cast(IRForm* arg, std::string_view atype) override {
        w_->Write("((");
        w_->Write(atype);
        w_->Write(") ");
        visit_ins(arg);
        w_->Write(")");
    }

    void visit_aload(IRForm* array, IRForm* index) override {
        visit_ins(array);
        w_->Write("[");
        visit_ins(index);
        w_->Write("]");
    }
    void visit_alength(IRForm* array) override {
        visit_ins(array);
        w_->Write(".length");
    }
    void visit_new_array(std::string_view atype, IRForm* size) override {
        // DAD: get_type(atype[1:]) — strip leading '[' from "[I" → "I" → "int".
        std::string_view inner = atype;
        if (!inner.empty() && inner.front() == '[') inner.remove_prefix(1);
        w_->Write("new ");
        w_->Write(GetType(inner));
        w_->Write("[");
        visit_ins(size);
        w_->Write("]");
    }
    void visit_filled_new_array(std::string_view atype, int /*size*/,
                                const std::vector<IRForm*>& args) override {
        w_->Write("new ");
        w_->Write(GetType(atype));
        w_->Write(" {");
        for (size_t i = 0; i < args.size(); ++i) {
            visit_ins(args[i]);
            if (i + 1 < args.size()) w_->Write(", ");
        }
        w_->Write("})");
    }

    void visit_fill_array(IRForm* array, FillArrayExpression* owner) override {
        w_->WriteIndent();
        visit_ins(array);
        w_->Write(" = {");
        if (owner) {
            const auto& values = owner->value();
            for (size_t i = 0; i < values.size(); ++i) {
                if (i > 0) w_->Write(", ");
                w_->Write(std::to_string(values[i]));
            }
        }
        w_->Write("}");
        w_->EndIns();
    }

    void visit_move_exception(Variable* var,
                              MoveExceptionExpression* data) override {
        if (!var) return;
        var->declared = true;
        // Variable's type can be empty if SplitVariables replaced it without
        // copying over the exception type (only the original var got the
        // type set by MoveExceptionExpression ctor). Fall back to the
        // MoveException's own `type` field, which always holds the catch
        // type from the snapshot's exception handler.
        std::string vt = var->get_type();
        if (vt.empty() && data) vt = data->get_type();
        if (vt.empty()) vt = "unknownType";
        w_->Write(GetType(vt));
        w_->Write(" v");
        std::string nm = var->name;
        if (!nm.empty() && nm.front() == 'v') nm.erase(0, 1);
        w_->Write(nm);
    }

    void visit_monitor_enter(IRForm* ref) override {
        w_->WriteIndent();
        w_->Write("synchronized(");
        visit_ins(ref);
        w_->Write(") {\n");
        w_->IncIndent();
    }
    void visit_monitor_exit(IRForm* /*ref*/) override {
        w_->DecIndent();
        w_->WriteIndent();
        w_->Write("}\n");
    }

    void visit_throw(IRForm* ref) override {
        w_->WriteIndent();
        w_->Write("throw ");
        visit_ins(ref);
        w_->EndIns();
    }

    void visit_binary_expression(std::string_view op, IRForm* arg1,
                                  IRForm* arg2) override {
        w_->Write("(");
        visit_ins(arg1);
        w_->Write(" ");
        w_->Write(op);
        w_->Write(" ");
        visit_ins(arg2);
        w_->Write(")");
    }
    void visit_unary_expression(std::string_view op, IRForm* arg) override {
        w_->Write("(");
        w_->Write(op);
        w_->Write(" ");
        visit_ins(arg);
        w_->Write(")");
    }
    void visit_cast(std::string_view op, IRForm* arg) override {
        w_->Write("(");
        w_->Write(op);
        w_->Write(" ");
        visit_ins(arg);
        w_->Write(")");
    }
    void visit_cond_expression(std::string_view op, IRForm* arg1,
                                IRForm* arg2) override {
        visit_ins(arg1);
        w_->Write(" ");
        w_->Write(op);
        w_->Write(" ");
        visit_ins(arg2);
    }
    void visit_condz_expression(std::string_view op, IRForm* arg) override {
        // DAD writer.py:727-730 — if condz wraps a BinaryCompExpression (long
        // cmp / float cmpl,g / double cmpl,g), swap its op to the actual
        // comparison operator (==, !=, <, >, etc.) and emit `a OP b` instead
        // of the meaningless `(cmp a b) OP 0`. Required to produce valid
        // Java (the literal `cmp` operator doesn't exist in Java).
        if (auto* bce = dynamic_cast<BinaryCompExpression*>(arg)) {
            bce->set_op(op);
            visit_ins(arg);
            return;
        }
        if (!arg) return;
        std::string atype = arg->get_type();
        if (atype == "Z") {
            if (op == Op::EQUAL) w_->Write("!");
            visit_ins(arg);
        } else {
            visit_ins(arg);
            if (!atype.empty() && std::string("VBSCIJFD").find(atype[0]) != std::string::npos) {
                w_->Write(" ");
                w_->Write(op);
                w_->Write(" 0");
            } else {
                w_->Write(" ");
                w_->Write(op);
                w_->Write(" null");
            }
        }
    }
    void visit_get_instance(IRForm* arg, std::string_view name,
                            std::string_view /*ftype*/) override {
        visit_ins(arg);
        w_->Write(".");
        w_->Write(name);
    }
    void visit_get_static(std::string_view cls, std::string_view name) override {
        w_->Write(cls);
        w_->Write(".");
        w_->Write(name);
    }

private:
    // Helpers ported from DAD writer.py.

    void end_ins_or_noop() { if (!w_->skip_) w_->EndIns(); }

    void write_ind_visit_end(IRForm* lhs, std::string_view sep, IRForm* rhs = nullptr) {
        w_->WriteIndent();
        visit_ins(lhs);
        w_->Write(sep);
        if (rhs) visit_ins(rhs);
        w_->EndIns();
    }

    // DAD: writer.py:136 write_inplace_if_possible — recognize x = x op y patterns.
    void write_inplace_if_possible(IRForm* lhs, IRForm* rhs) {
        auto* bin = dynamic_cast<BinaryExpression*>(rhs);
        if (bin) {
            IRForm* arg1 = MapGet(bin, bin->arg1_id());
            IRForm* arg2 = MapGet(bin, bin->arg2_id());
            if (arg1 == lhs) {
                // post-inc/dec for ±1
                auto* cst = dynamic_cast<Constant*>(arg2);
                if (cst && (bin->op() == "+" || bin->op() == "-")
                    && cst->get_int_value() == 1) {
                    write_ind_visit_end(lhs, std::string(bin->op()) + bin->op());
                    return;
                }
                // compound: lhs OP= arg2
                w_->WriteIndent();
                visit_ins(lhs);
                w_->Write(" ");
                w_->Write(bin->op());
                w_->Write("= ");
                visit_ins(arg2);
                w_->EndIns();
                return;
            }
        }
        write_ind_visit_end(lhs, " = ", rhs);
    }

    static IRForm* MapGet(const IRForm* owner, const std::string& key) {
        if (!owner) return nullptr;
        auto it = owner->var_map.find(key);
        return it == owner->var_map.end() ? nullptr : it->second.get();
    }

    Writer* w_;
public:
    bool constructor_ = false;
};

// ============================================================================
// Writer public API
// ============================================================================

Writer::Writer(const MethodSnapshot* snap, const Graph* graph)
    : snap_(snap), graph_(graph) {}

void Writer::WriteIndent() {
    // DAD: writer.py:77 write_ind — if skip is set, consume it and emit no
    // indent (the skip flag was set by a prior visit that elided itself).
    if (skip_) { skip_ = false; return; }
    Write(Space());
}

std::string Writer::JavaType(std::string_view desc) { return GetType(desc); }

IRForm* Writer::MapGet(const IRForm* owner, const std::string& key) {
    if (!owner) return nullptr;
    auto it = owner->var_map.find(key);
    return it == owner->var_map.end() ? nullptr : it->second.get();
}

void Writer::WriteMethod() {
    if (!snap_) return;
    const MethodMeta& m = snap_->meta;

    std::vector<std::string> mods;
    is_constructor_ = false;
    for (const auto& a : m.access) {
        if (a == "constructor") { is_constructor_ = true; continue; }
        mods.push_back(a);
    }
    Write("\n");
    Write(Space());
    if (!mods.empty()) {
        for (size_t i = 0; i < mods.size(); ++i) {
            if (i > 0) Write(" ");
            Write(mods[i]);
        }
        Write(" ");
    }
    if (is_constructor_) {
        std::string cls_desc(StripClassDesc(m.cls_name));
        auto slash = cls_desc.rfind('/');
        Write(slash == std::string::npos ? cls_desc : cls_desc.substr(slash + 1));
    } else {
        Write(JavaType(m.ret_type));
        Write(" ");
        Write(m.name);
    }
    Write("(");
    bool is_static = std::find(m.access.begin(), m.access.end(), "static")
                     != m.access.end();
    // Parse the proto independently — meta.params_type is already built from
    // ParseParamsType so we could reuse it, but doing the parse here keeps
    // Writer self-contained and unaffected if a future refactor changes
    // meta.params_type semantics.
    auto parsed_params = ParseParamsType(m.proto);
    if (!parsed_params.empty()) {
        int start = static_cast<int>(snap_->registers_size)
                  - static_cast<int>(snap_->ins_size);
        if (!is_static) ++start;  // skip 'this' register
        int num_param = 0;
        for (size_t i = 0; i < parsed_params.size(); ++i) {
            if (i > 0) Write(", ");
            int reg = start + num_param;
            Write(JavaType(parsed_params[i]));
            Write(" p" + std::to_string(reg));
            num_param += static_cast<int>(GetTypeSize(parsed_params[i]));
        }
    }
    Write(")");

    if (!graph_ || !graph_->entry) {
        Write(";\n");
        return;
    }
    Write("\n");
    Write(Space());
    Write("{\n");
    IncIndent();
    VisitNode(graph_->entry);
    DecIndent();
    Write(Space());
    Write("}\n");
}

void Writer::VisitNode(NodeBase* node) {
    if (!node) return;
    if (node == if_follow_.back() || node == switch_follow_.back() ||
        node == loop_follow_.back() || node == latch_node_.back() ||
        node == try_follow_.back()) return;
    auto* nn = dynamic_cast<Node*>(node);
    if (nn && !nn->type.is_return() && visited_.count(node)) return;
    visited_.insert(node);

    auto* bb = dynamic_cast<BasicBlock*>(node);
    if (bb) {
        // var_to_declare: emit `Type vN;` for undeclared variables.
        WriterImpl wi(this);
        for (const auto& var : bb->var_to_declare) {
            wi.visit_decl(dynamic_cast<Variable*>(var.get()));
        }
    }

    if (auto* x = dynamic_cast<StatementBlock*>(node)) { EmitStatement(x); return; }
    if (auto* x = dynamic_cast<ReturnBlock*>(node))    { EmitReturn(x); return; }
    if (auto* x = dynamic_cast<ThrowBlock*>(node))     { EmitThrow(x); return; }
    if (auto* x = dynamic_cast<LoopBlock*>(node))      { EmitLoop(x); return; }
    if (auto* x = dynamic_cast<CondBlock*>(node))      { EmitIf(x); return; }
    if (auto* x = dynamic_cast<SwitchBlock*>(node))    { EmitSwitch(x); return; }
    if (auto* x = dynamic_cast<TryBlock*>(node))       { EmitTry(x); return; }
}

void Writer::EmitStatement(StatementBlock* stmt) {
    auto sucs = graph_->sucs(stmt);
    for (const auto& ins : stmt->get_ins()) VisitIns(ins);
    if (sucs.size() == 1) {
        if (sucs[0] == loop_follow_.back()) {
            WriteIndent(); Write("break"); EndIns();
        } else if (sucs[0] == next_case_) {
            need_break_ = false;
        } else {
            VisitNode(sucs[0]);
        }
    }
}

void Writer::EmitReturn(ReturnBlock* ret) {
    need_break_ = false;
    for (const auto& ins : ret->get_ins()) VisitIns(ins);
}

void Writer::EmitThrow(ThrowBlock* thr) {
    for (const auto& ins : thr->get_ins()) VisitIns(ins);
}

void Writer::EmitIf(CondBlock* cond) {
    if (cond->false_branch == cond->true_branch) {
        // DAD writer.py:285-306 — when both branches point to the same code,
        // emit a comment explaining the situation, the commented condition,
        // then the body inline, then a closing comment. This documents the
        // unreachable-else without producing dead Java.
        WriteIndent();
        Write("// Both branches of the condition point to the same code.\n");
        WriteIndent();
        Write("// if (");
        WriterImpl wi(this); wi.constructor_ = is_constructor_;
        cond->visit_cond(wi);
        Write(") {\n");
        IncIndent();
        VisitNode(cond->true_branch);
        DecIndent();
        WriteIndent();
        Write("// }\n");
        return;
    }
    NodeBase* follow = nullptr;
    auto it = cond->follow.find("if");
    if (it != cond->follow.end()) follow = it->second;

    // DAD: writer.py:319-326 — if the true branch goes straight to the follow
    // (or to next_case inside a switch body), negate the condition and swap
    // branches so we emit `if (cond) { body }` instead of
    // `if (!cond) { } else { body }`. Also fires for the `cond.num > true.num`
    // ordering heuristic (true branch would be a backward jump).
    if (follow != nullptr && cond->true_branch != nullptr) {
        bool true_is_follow = (cond->true_branch == follow);
        bool true_is_next_case = (cond->true_branch == next_case_);
        bool backward_true = cond->num > cond->true_branch->num;
        if (true_is_follow || true_is_next_case || backward_true) {
            cond->neg();
            std::swap(cond->true_branch, cond->false_branch);
        }
    }

    WriteIndent();
    Write("if (");
    WriterImpl wi(this); wi.constructor_ = is_constructor_;
    cond->visit_cond(wi);
    Write(") {\n");
    IncIndent();
    if (cond->true_branch && cond->true_branch != follow) {
        if_follow_.push_back(follow);
        VisitNode(cond->true_branch);
        if_follow_.pop_back();
    }
    DecIndent();
    // DAD writer.py:335-340 — emit else only when (a) follow is NOT one of
    // the branches AND (b) cond.false has not already been visited. The
    // visited check matters because visit_node(cond.true) may have walked
    // into cond.false through normal successor edges; emitting else then
    // would either duplicate code or produce an empty `} else { }`.
    bool is_else = !(follow == cond->true_branch ||
                     follow == cond->false_branch);
    if (is_else && cond->false_branch &&
        cond->false_branch != cond->true_branch &&
        !visited_.count(cond->false_branch)) {
        WriteIndent(); Write("} else {\n");
        IncIndent();
        if_follow_.push_back(follow);
        VisitNode(cond->false_branch);
        if_follow_.pop_back();
        DecIndent();
    }
    WriteIndent(); Write("}\n");
    if (follow) VisitNode(follow);
}

void Writer::EmitLoop(LoopBlock* loop) {
    NodeBase* follow = nullptr;
    auto fit = loop->follow.find("loop");
    if (fit != loop->follow.end()) follow = fit->second;
    WriterImpl wi(this); wi.constructor_ = is_constructor_;

    if (loop->looptype.is_pretest()) {
        // DAD: writer.py:241-243 — if true branch is the loop exit, negate
        // the cond and swap so the body lives in true_branch.
        if (loop->true_branch != nullptr && loop->true_branch == follow) {
            loop->neg();
            std::swap(loop->true_branch, loop->false_branch);
        }
        WriteIndent(); Write("while (");
        // DAD writer.py:246 loop.visit_cond(self) — dispatches to either
        // CondBlock (single ins) or Condition (short-circuit composite).
        // Previously we only handled cond_block path which made composite
        // loop conds emit as empty `while () {}`.
        loop->visit_cond(wi);
        Write(") {\n");
        IncIndent();
        loop_follow_.push_back(follow);
        VisitNode(loop->true_branch);
        loop_follow_.pop_back();
        DecIndent();
        WriteIndent(); Write("}\n");
    } else if (loop->looptype.is_endless()) {
        WriteIndent(); Write("while (true) {\n");
        IncIndent();
        loop_follow_.push_back(follow);
        if (loop->cond_block) VisitNode(loop->cond_block);
        VisitNode(loop->latch);
        loop_follow_.pop_back();
        DecIndent();
        WriteIndent(); Write("}\n");
    } else {
        WriteIndent(); Write("do {\n");
        IncIndent();
        loop_follow_.push_back(follow);
        latch_node_.push_back(loop->latch);
        if (loop->cond_block) VisitNode(loop->cond_block);
        latch_node_.pop_back();
        loop_follow_.pop_back();
        DecIndent();
        WriteIndent(); Write("} while (");
        if (auto* latch_cond = dynamic_cast<CondBlock*>(loop->latch)) {
            if (!latch_cond->get_ins().empty())
                latch_cond->get_ins().back()->Accept(wi);
        }
        Write(");\n");
    }
    if (follow) VisitNode(follow);
}

void Writer::EmitSwitch(SwitchBlock* sw) {
    auto lins = sw->get_ins();
    WriterImpl wi(this); wi.constructor_ = is_constructor_;
    for (size_t i = 0; i + 1 < lins.size(); ++i) VisitIns(lins[i]);
    WriteIndent(); Write("switch (");
    if (!lins.empty()) lins.back()->Accept(wi);
    Write(") {\n");
    IncIndent();
    NodeBase* follow = nullptr;
    auto sit = sw->follow.find("switch");
    if (sit != sw->follow.end()) follow = sit->second;
    switch_follow_.push_back(follow);
    for (size_t i = 0; i < sw->cases.size(); ++i) {
        NodeBase* case_node = sw->cases[i];
        if (visited_.count(case_node)) continue;
        next_case_ = (i + 1 < sw->cases.size()) ? sw->cases[i + 1] : nullptr;
        auto keys_it = sw->node_to_case.find(case_node);
        if (keys_it != sw->node_to_case.end()) {
            for (int64_t k : keys_it->second) {
                WriteIndent();
                Write("case " + std::to_string(k) + ":\n");
            }
        }
        IncIndent();
        VisitNode(case_node);
        if (need_break_) { WriteIndent(); Write("break"); EndIns(); }
        else need_break_ = true;
        DecIndent();
    }
    if (sw->default_case && sw->default_case != follow) {
        WriteIndent(); Write("default:\n");
        IncIndent(); VisitNode(sw->default_case); DecIndent();
    }
    switch_follow_.pop_back();
    DecIndent();
    WriteIndent(); Write("}\n");
    if (follow) VisitNode(follow);
}

void Writer::EmitTry(TryBlock* tb) {
    WriteIndent(); Write("try {\n");
    IncIndent();
    try_follow_.push_back(tb->try_follow);
    VisitNode(tb->try_start);
    DecIndent();
    WriteIndent(); Write("}");
    for (NodeBase* catch_n : tb->catch_nodes) {
        auto* catch_block = dynamic_cast<CatchBlock*>(catch_n);
        if (!catch_block) continue;
        Write(" catch (");
        // DAD basic_blocks.py:302 visit_exception — if `exception_ins` is set
        // (a MoveExceptionExpression bound to a Variable), visit it so the
        // catch variable is declared as `Type vN`; otherwise write the raw
        // type string. Previously we always wrote `Type _` which dropped the
        // variable name and left subsequent uses (e.g. `throw vN`) typed as
        // `unknownType`.
        if (catch_block->exception_ins) {
            WriterImpl wi(this); wi.constructor_ = is_constructor_;
            catch_block->exception_ins->Accept(wi);
        } else {
            std::string ctype = catch_block->catch_type.empty()
                ? std::string("Ljava/lang/Throwable;")
                : catch_block->catch_type;
            Write(JavaType(ctype));
            Write(" _");
        }
        Write(") {\n");
        IncIndent();
        VisitNode(catch_block->catch_start);
        DecIndent();
        WriteIndent(); Write("}");
    }
    Write("\n");
    try_follow_.pop_back();
    if (tb->try_follow) VisitNode(tb->try_follow);
}

void Writer::VisitIns(const IRFormPtr& ins) {
    if (!ins) return;
    IRForm* op = ins.get();
    if (dynamic_cast<NopExpression*>(op)) return;
    WriterImpl wi(this);
    wi.constructor_ = is_constructor_;
    op->Accept(wi);
}

// Kept for backwards-compat; new path uses WriterImpl via VisitIns.
void Writer::EmitExpr(IRForm* op) {
    if (!op) return;
    WriterImpl wi(this);
    wi.constructor_ = is_constructor_;
    op->Accept(wi);
}

}  // namespace dexkit::dad
