// writer.cpp — DAD-faithful Java emission via Visitor pattern.
//
// Each visit_X method is a 1:1 port of androguard/decompiler/writer.py.
// IRForm::Accept(Visitor&) calls into these visit_X overrides, mirroring
// DAD's `op.visit(self)` dispatch.

#include "writer.h"

#include <algorithm>
#include <cmath>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <sstream>
#include <stdexcept>
#include <string>

#include "dataflow.h"  // ScopeEscapingDefs (dexllm#122)
#include "mutf8.h"
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

// Beyond-DAD return-literal helpers. The Java float/double literal style mirrors
// the EncodedValue IEEE754 formatter in core_ext (Float.NaN / %.9gf round-trip,
// Double.NaN / %.17g) so static-field and method-return float/double rendering
// agree. Used by visit_return when a F/D method returns the raw IEEE bits as an
// integer constant.
std::string FormatFloatLiteral(float f) {
    if (std::isnan(f)) return "Float.NaN";
    if (std::isinf(f)) {
        return f > 0 ? "Float.POSITIVE_INFINITY" : "Float.NEGATIVE_INFINITY";
    }
    char buf[40];
    std::snprintf(buf, sizeof(buf), "%.9gf", static_cast<double>(f));
    return buf;
}
std::string FormatDoubleLiteral(double d) {
    if (std::isnan(d)) return "Double.NaN";
    if (std::isinf(d)) {
        return d > 0 ? "Double.POSITIVE_INFINITY" : "Double.NEGATIVE_INFINITY";
    }
    char buf[48];
    std::snprintf(buf, sizeof(buf), "%.17g", d);
    return buf;
}

}  // namespace

// ============================================================================
// FormatLongLiteral (dexllm#92 — see writer.h)
// ============================================================================
std::string FormatLongLiteral(int64_t value) {
    return std::to_string(value) + "L";
}

// ============================================================================
// EscapeJavaString
// ============================================================================
std::string EscapeJavaString(std::string_view raw) {
    // Dex strings are MUTF-8. We decode them to the SAME UTF-16 code units ART
    // builds in a mirror::String (mutf8::Mutf8ToUtf16), then render each unit as
    // Java source text: a BMP non-surrogate becomes readable UTF-8 (연결, 中文),
    // a surrogate or control char becomes a `\uXXXX` escape (so a supplementary
    // char stays the `😀`-style surrogate PAIR ART keeps in memory). This
    // diverges from DAD (writer.py:757 `string()` ASCII-escapes everything via
    // `unicode-escape`) but is far more useful for a triage tool reading e.g.
    // localized phishing strings, agrees with the AST path (dast.cpp), and is
    // valid UTF-8 for pybind11. Java-source metacharacters are escaped first.
    std::string out;
    out.reserve(raw.size() + 2);
    out += '"';
    for (uint16_t u : mutf8::Mutf8ToUtf16(raw)) {
        switch (u) {
            case '\\': out += "\\\\"; continue;
            case '"':  out += "\\\""; continue;
            // DAD writer.py:766 escapes single-quote in string literals too.
            // Java doesn't require it but DAD always emits `\'` — match for parity.
            case '\'': out += "\\'";  continue;
            case '\n': out += "\\n";  continue;
            case '\r': out += "\\r";  continue;
            case '\t': out += "\\t";  continue;
            default: break;
        }
        mutf8::AppendUtf16Escaped(out, u);
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

// dexllm#132: `A | B | C`, the type part of a multi-catch clause, in
// try-table order.
static std::string MultiCatchText(const std::vector<std::string>& alts) {
    std::string out;
    for (size_t i = 0; i < alts.size(); ++i) {
        if (i) out += " | ";
        out += GetType(alts[i]);
    }
    return out;
}

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
        w_->Write(GetType(declared_type(vt)));
        w_->Write(" v");
        std::string nm = var->name;
        if (!nm.empty() && nm.front() == 'v') nm.erase(0, 1);
        w_->Write(nm);
        NoteWrittenName(w_->snap_->meta.cls_name, "v" + nm);  // dexllm#129
        w_->EndIns();
        var->declared = true;
    }

    // ─── visit_constant: DAD writer.py:461 (split per overload) ──────────
    void visit_constant_int(int64_t value) override {
        w_->Write(std::to_string(value));
    }
    void visit_constant_long(int64_t value) override {
        w_->Write(FormatLongLiteral(value));
    }
    void visit_constant_double(double value) override {
        // dexllm#67: `%g` is six significant figures — `Double.MAX_VALUE` printed
        // `1.79769e+308`, and the AST (which renders the same node through
        // `PyFloatRepr`) disagreed with it. Use the round-trip formatter the
        // return-literal and EncodedValue paths already use, which also renders
        // NaN/±Inf as valid Java instead of `nan`/`inf`. Unreachable before this
        // change: every `const*` opcode builds an INTEGER-typed Constant.
        w_->Write(FormatDoubleLiteral(value));
    }
    void visit_constant_float(float value) override {
        w_->Write(FormatFloatLiteral(value));
    }
    void visit_constant_string(std::string_view value) override {
        // DAD writer.py:734 visit_constant → `string(cst)` ALWAYS quotes/escapes
        // a str constant. A const-string whose value is "true"/"false" is still a
        // String literal (e.g. `Boolean.parseBoolean("true")`) — quote it. The
        // boolean (type "Z") path is visit_constant_bool, kept separate.
        w_->Write(EscapeJavaString(value));
    }
    void visit_constant_bool(bool value) override {
        w_->Write(value ? "true" : "false");
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
            w_->Write(GetType(declared_type(vt)));
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
        NoteWrittenName(w_->snap_->meta.cls_name, "v" + nm);  // dexllm#129
    }

    // ─── visit_param: DAD writer.py:484 ──────────────────────────────────
    void visit_param(std::string_view name, std::string_view /*type_desc*/) override {
        w_->Write("p");
        // DAD's param value is an int register; our `name` is "vN" string.
        // Strip the leading 'v' if present so output is "pN".
        if (!name.empty() && name.front() == 'v') name.remove_prefix(1);
        w_->Write(name);
        NoteWrittenName(w_->snap_->meta.cls_name, "p" + std::string(name));  // dexllm#129
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
    void visit_astore(IRForm* array, IRForm* index, IRForm* rhs,
                      std::string_view kind) override {
        w_->WriteIndent();
        visit_ins(array);
        w_->Write("[");
        visit_ins(index);
        w_->Write("] = ");
        // `dArr[i] = <raw-bits int const>` → `= 0.5`; dexllm#102: `flags[i] =
        // true` (aput-boolean), `arr[i] = null` (aput-object).
        const std::string at = array ? array->get_type() : std::string();
        if (!emit_const_at(ConstContext::Value, ArrayStorePositionType(kind, at), rhs))
            visit_ins(rhs);
        w_->EndIns();
    }

    // ─── visit_put_static: DAD writer.py:518 ─────────────────────────────
    void visit_put_static(std::string_view cls, std::string_view name,
                          std::string_view ftype, IRForm* rhs) override {
        w_->WriteIndent();
        w_->Write(cls);
        w_->Write(".");
        w_->Write(name);
        w_->Write(" = ");
        if (!emit_const_at(ConstContext::Value, ftype, rhs)) visit_ins(rhs);
        w_->EndIns();
    }

    // ─── visit_put_instance: DAD writer.py:524 ───────────────────────────
    void visit_put_instance(IRForm* lhs, std::string_view name,
                            std::string_view ftype, IRForm* rhs,
                            std::string_view owner) override {
        NoteCapturedFieldWrite(w_->snap_->meta.cls_name, owner, name);  // dexllm#129
        w_->WriteIndent();
        emit_base_maybe_cast(lhs, owner);  // `((Owner) v).field = …` for Object v
        w_->Write(".");
        w_->Write(name);
        w_->Write(" = ");
        // `this.doubleField = <raw-bits int const>` → `= 0.5`; dexllm#102:
        // `this.flag = true`, `this.listener = null`.
        if (!emit_const_at(ConstContext::Value, ftype, rhs)) visit_ins(rhs);
        w_->EndIns();
    }

    // ─── visit_new: DAD writer.py:535 ────────────────────────────────────
    void visit_new(std::string_view atype, NewInstance* /*data*/) override {
        w_->Write("new ");
        w_->Write(GetType(atype));
    }

    // Beyond-DAD (LLM-comprehension): emit `((target) base)` when `base` is an
    // Object-typed variable used where a MORE SPECIFIC reference type is known
    // (a field owner, an array element), else emit `base` verbatim. Makes each
    // Object-var use type-explicit for the consuming LLM. `this` is never cast
    // (its type is the class); a no-op Object→Object target is skipped.
    void emit_base_maybe_cast(IRForm* base, std::string_view target) {
        if (base && !dynamic_cast<ThisParam*>(base)
            && base->get_type() == "Ljava/lang/Object;"
            && !target.empty() && target != "java.lang.Object"
            && target != "Object") {
            w_->Write("((");
            w_->Write(std::string(target));
            w_->Write(") ");
            visit_ins(base);
            w_->Write(")");
        } else {
            visit_ins(base);
        }
    }

    // dexllm#129 — the text a captured value is written as inside the body:
    // the site's own name for it. Only a value with no side effect can be
    // read again there; anything else leaves the class un-inlined.
    std::string pure_text(IRForm* a, const AnonymousClassInfo& info) {
        if (dynamic_cast<ThisParam*>(a)) {
            if (!info.site_this_nameable) return {};
            return GetType(w_->snap_->meta.cls_name) + ".this";
        }
        // The body reads the value as it was at construction, so the name
        // must hold that value for the whole method: a parameter never
        // written, a local written once.
        if (auto* pa = dynamic_cast<Param*>(a)) {
            if (defs_of(pa->Vid()) != 0) return {};
            std::string nm = pa->v();  // visit_param writes the register
            if (!nm.empty() && nm.front() == 'v') nm.erase(0, 1);
            return "p" + nm;
        }
        if (auto* v = dynamic_cast<Variable*>(a)) {
            if (!v->declared || defs_of(v->Vid()) != 1) return {};
            std::string nm = v->name;
            if (!nm.empty() && nm.front() == 'v') nm.erase(0, 1);
            return "v" + nm;
        }
        return {};
    }

    // How many instructions of this method define `vid`.
    int defs_of(const std::string& vid) const {
        int n = 0;
        for (const auto& [loc, ins] : w_->graph_->loc_to_ins) {
            if (!ins) continue;
            if (auto lhs = ins->GetLhsId(); lhs && *lhs == vid) ++n;
        }
        return n;
    }

    // dexllm#129 — a variable of an anonymous class written inline in this
    // method is declared with the type the inline text names (its base): no
    // source can name the anonymous class itself.
    std::string declared_type(const std::string& vt) {
        AnonymousInliner* inliner = CurrentAnonymousInliner();
        if (inliner == nullptr || vt.size() < 3 || vt.front() != 'L') return vt;
        const MethodMeta& m = w_->snap_->meta;
        auto info = inliner->Find(vt, m.cls_name + "->" + m.name + m.proto);
        return info ? info->base : vt;
    }

    // dexllm#129 — `new Outer$1(args)` of an anonymous class constructed only
    // here is written as `new Base(super_args) { body }`, as jadx does.
    bool try_inline_anonymous(IRForm* base, const std::vector<std::string>& ptype,
                              const std::vector<IRForm*>& args) {
        auto* ni = dynamic_cast<NewInstance*>(base);
        AnonymousInliner* inliner = CurrentAnonymousInliner();
        if (ni == nullptr || inliner == nullptr) return false;
        const MethodMeta& m = w_->snap_->meta;
        const std::string site = m.cls_name + "->" + m.name + m.proto;
        auto info = inliner->Find(ni->get_type(), site);
        if (!info || args.size() != info->captured_field.size()) return false;
        std::vector<bool> to_super(args.size(), false);
        for (uint32_t i : info->super_args) {
            if (i >= args.size()) return false;
            to_super[i] = true;
        }
        std::vector<std::string> captures(args.size());
        for (size_t i = 0; i < args.size(); ++i) {
            if (to_super[i]) continue;
            // A captured value is read again in the body, and a dropped one
            // not at all: neither may have a side effect.
            std::string t = args[i] ? pure_text(args[i], *info) : std::string{};
            if (t.empty()) return false;
            if (!info->captured_field[i].empty()) captures[i] = std::move(t);
        }
        std::optional<std::string> body;
        try {
            body = inliner->RenderBody(*info, captures);
        } catch (const std::exception&) {
            return false;  // the class stays by name, as it does when refused
        }
        if (!body) return false;
        // Each superclass argument at the type the bytecode's constructor
        // declares: `new Base(x)` is resolved by Java overload rules, and an
        // argument of another type could bind another constructor.
        if (info->super_params.size() != info->super_args.size()) return false;
        w_->Write("new ");
        w_->Write(GetType(info->base));
        w_->Write("(");
        for (size_t k = 0; k < info->super_args.size(); ++k) {
            if (k > 0) w_->Write(", ");
            const uint32_t i = info->super_args[k];
            const std::string& declared = info->super_params[k];
            // An integer constant is spelled for its position by emit_arg_at
            // (a null cast, a narrowing cast, a literal); a String or a
            // class literal is not, and an Object-typed variable is cast there.
            const std::string at = args[i] ? args[i]->get_type() : std::string{};
            const bool int_const = dynamic_cast<Constant*>(args[i]) != nullptr &&
                                   at.size() == 1;
            const bool cast = args[i] && !int_const && at != declared &&
                              at != "Ljava/lang/Object;";
            if (cast) {
                w_->Write("((");
                w_->Write(GetType(declared));
                w_->Write(") ");
            }
            emit_arg_at(args[i], declared);
            if (cast) w_->Write(")");
        }
        w_->Write(") {\n");
        const std::string indent = w_->Space() + "    ";
        std::string_view rest = *body;
        while (!rest.empty()) {
            size_t nl = rest.find('\n');
            std::string_view line = rest.substr(0, nl);
            if (!line.empty()) {
                w_->Write(indent);
                w_->Write(line);
            }
            w_->Write("\n");
            if (nl == std::string_view::npos) break;
            rest.remove_prefix(nl + 1);
        }
        w_->Write(w_->Space());
        w_->Write("}");
        return true;
    }

    // One invocation argument, as visit_invoke writes it.
    void emit_arg(size_t i, const std::vector<std::string>& ptype,
                  const std::vector<IRForm*>& args) {
        // A float/double param passed a raw-IEEE-bits int constant — emit
        // the literal (e.g. `Math.pow(x, 2.4)` not `Math.pow(x, raw-bits)`).
        emit_arg_at(args[i], i < ptype.size() ? std::string_view(ptype[i])
                                              : std::string_view());
    }

    // One argument at a position of declared type `pt`.
    void emit_arg_at(IRForm* arg, std::string_view pt) {
        // Beyond-DAD (LLM-comprehension): a genuinely-conflated register is
        // typed `Object` (see InferCascadeTypes). Where it is passed at a
        // MORE SPECIFIC reference-parameter position, emit an explicit
        // `(Type) v` cast so the consuming LLM sees its real type at THIS
        // use (the original dex reused one register for two types; the cast
        // makes each use's type explicit instead of a misleading single
        // declaration).
        if (arg && !pt.empty() && (pt.front() == 'L' || pt.front() == '[')
            && pt != "Ljava/lang/Object;"
            && arg->get_type() == "Ljava/lang/Object;") {
            w_->Write("((");
            w_->Write(GetType(std::string(pt)));
            w_->Write(") ");
            visit_ins(arg);
            w_->Write(")");
            return;
        }
        // dexllm#102: an invocation context — Z / reference / F / D, and an
        // explicit narrowing cast at a B / S / C parameter.
        if (!emit_const_at(ConstContext::Argument, pt, arg)) visit_ins(arg);
    }

    // ─── visit_invoke: DAD writer.py:542 ─────────────────────────────────
    void visit_invoke(std::string_view name, IRForm* base,
                      const std::vector<std::string>& ptype,
                      std::string_view /*rtype*/,
                      const std::vector<IRForm*>& args,
                      InvokeInstruction* invokeInstr) override {
        if (name == "<init>" && try_inline_anonymous(base, ptype, args)) return;
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
        // Beyond-DAD (LLM-comprehension): a conflated register typed `Object`
        // used as a method RECEIVER gets an explicit `((DeclClass) v).m()` cast
        // (the method's declaring class), so `Object v; v.m()` — which would not
        // compile and hides the receiver's real type — becomes an explicit,
        // type-clear call for the consuming LLM. Skip `this`/super and <init>.
        bool base_casted = false;
        if (invokeInstr && base && name != "<init>"
            && !dynamic_cast<ThisParam*>(base)
            && base->get_type() == "Ljava/lang/Object;"
            && !invokeInstr->cls().empty()
            && invokeInstr->cls() != "java.lang.Object"
            && invokeInstr->cls() != "Object") {  // no-op Object→Object cast
                                                  // (an Object method: getClass /
                                                  // equals / hashCode / …)
            w_->Write("((");
            w_->Write(invokeInstr->cls());
            w_->Write(") ");
            visit_ins(base);
            w_->Write(")");
            base_casted = true;
        }
        if (!base_casted) visit_ins(base);
        if (name != "<init>") {
            w_->Write(".");
            w_->Write(name);
        }
        w_->Write("(");
        bool first = true;
        for (size_t i = 0; i < args.size(); ++i) {
            if (!first) w_->Write(", ");
            first = false;
            emit_arg(i, ptype, args);
        }
        w_->Write(")");
        // dexllm#67 (beyond-DAD): an invoke-custom's bootstrap chain is a
        // RECONSTRUCTION of what the runtime does with the call site, not
        // instructions the dex contains. Say so, as jadx does — without it the
        // expanded chain reads as literal bytecode. Set on the outermost node of
        // the chain only, and inert for every other invoke.
        if (invokeInstr && invokeInstr->call_site_marker) {
            w_->Write(" /* invoke-custom */");
        }
    }

    void visit_return_void() override {
        // Beyond-DAD: `return` is a compile error inside a static initializer
        // (JLS §8.7), so drop a <clinit>'s return-void when it is in TAIL
        // POSITION (nothing executes after it → fall-through is equivalent). A
        // genuinely-early return (code runs after it on the fall-through path)
        // has tail_pos_ == false and is kept DAD-faithful. (Pairs with the
        // `static { }` header fix in WriteMethod.)
        if (w_->is_clinit_ && w_->tail_pos_) return;
        w_->WriteIndent();
        w_->Write("return");
        w_->EndIns();
    }
    void visit_return(IRForm* arg) override {
        w_->WriteIndent();
        w_->Write("return ");
        // Beyond-DAD: every `const*` opcode builds the value as an integer-typed
        // Constant (DAD opcode_ins.py:263+ — `Constant(val, 'I'/'J')`), so the
        // returned constant carries no boolean/reference/float/double type. DAD
        // emits the raw int verbatim, which is uncompilable when the method
        // returns Z / a reference / F / D. The declared return type is the
        // ground truth, so we render a spec-correct literal. Same precedent as
        // the catch (primitive) → Throwable clamp (no *DADFaithful sibling —
        // parity suites don't assert return emission; e2e improves where DAD
        // was invalid). Non-constant returns and type-matched returns fall
        // through to normal emission.
        // One rule for every typed position: `ConstantAt` (dexllm#102), shared
        // with the AST's ReturnStatement.
        static const std::string kEmptyRet;
        const std::string& rt =
            w_->snap_ ? w_->snap_->meta.ret_type : kEmptyRet;
        if (emit_const_at(ConstContext::Value, rt, arg)) {
            w_->EndIns();
            return;
        }
        visit_ins(arg);
        w_->EndIns();
    }
    void visit_nop() override {}

    void visit_switch(IRForm* arg) override { visit_ins(arg); }

    void visit_check_cast(IRForm* arg, std::string_view atype) override {
        w_->Write("((");
        w_->Write(atype);
        w_->Write(") ");
        // dexllm#102: a check-cast's target is always a reference type, so an
        // untyped constant there is the null reference — `(Void[]) null`.
        if (!emit_const_at(ConstContext::Value, "Ljava/lang/Object;", arg))
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
        // dexllm#117: an element is a typed position like an aput-object one, so
        // a `0` in a reference array is `null`.
        const std::string elem = FilledArrayElementPositionType(atype);
        for (size_t i = 0; i < args.size(); ++i) {
            if (!emit_const_at(ConstContext::Value, elem, args[i])) visit_ins(args[i]);
            if (i + 1 < args.size()) w_->Write(", ");
        }
        // DAD writer.py:652 writes '})' here, and nothing opens the ')' it
        // closes - so every filled-new-array line was unbalanced Java
        // (dexllm#96). Beyond-DAD emit fix: close the initializer only. The
        // AST (dast ArrayInitializer) never carried the ')'.
        w_->Write("}");
    }

    void visit_fill_array(IRForm* array, FillArrayExpression* owner) override {
        w_->WriteIndent();
        visit_ins(array);
        w_->Write(" = {");
        if (owner) {
            // Beyond-DAD (dexllm#93): DAD writes each element as the integer
            // the payload holds, so a `float[]` read `1065353216` for `1f`.
            const char elem = FillArrayElementType(*owner);
            const auto& values = owner->value();
            for (size_t i = 0; i < values.size(); ++i) {
                if (i > 0) w_->Write(", ");
                if (elem == 'F') {
                    const uint32_t bits = static_cast<uint32_t>(values[i]);
                    float f; std::memcpy(&f, &bits, sizeof(f));
                    w_->Write(FormatFloatLiteral(f));
                } else if (elem == 'D') {
                    const uint64_t bits = static_cast<uint64_t>(values[i]);
                    double d; std::memcpy(&d, &bits, sizeof(d));
                    w_->Write(FormatDoubleLiteral(d));
                } else if (elem == 'J') {
                    w_->Write(FormatLongLiteral(values[i]));
                } else if (elem == 'C') {
                    // a char is unsigned; the payload was read as a signed u2
                    w_->Write(std::to_string(static_cast<uint16_t>(values[i])));
                } else if (elem == 'Z' && (values[i] == 0 || values[i] == 1)) {
                    w_->Write(values[i] ? "true" : "false");
                } else {
                    w_->Write(std::to_string(values[i]));
                }
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
        // A caught exception is always a reference type (a Throwable subclass);
        // a catch type descriptor is always `Lcls;`. When type inference put an
        // invalid descriptor on the catch variable (a primitive like "I"/"Z" or
        // an array "[..."), `catch (int v)` / `catch (Object[] v)` is uncompilable
        // Java. DAD emits these verbatim (its `Constant`/type-inference quirk);
        // we deliberately diverge to spec-correct output: prefer the actual
        // catch-handler type carried on the MoveException, else Throwable.
        auto is_ref_catch = [](const std::string& t) {
            return t.size() >= 2 && t.front() == 'L' && t.back() == ';';
        };
        // dexllm#130: a catch clause names the class the HANDLER catches, so
        // the handler type wins over the variable's inferred type whenever it
        // is a reference. The variable's type is a reference that is not a
        // Throwable when the move-exception def never reached SplitVariables
        // (its value is unused) or a merged def won the version's type.
        if (data && is_ref_catch(data->get_type())) vt = data->get_type();
        else if (!is_ref_catch(vt)) vt = "Ljava/lang/Throwable;";
        // dexllm#132: a handler several catch types share is a multi-catch;
        // the variable keeps their join (Throwable) as its own type.
        const bool multi = catch_alts_ && catch_alts_->size() > 1;
        // A multi-catch parameter cannot be assigned, so a reassigned one
        // names the join and keeps the types in a comment.
        if (multi && !(data && data->reassigned))
            w_->Write(MultiCatchText(*catch_alts_));
        else
            w_->Write(GetType(vt));
        w_->Write(" v");
        std::string nm = var->name;
        if (!nm.empty() && nm.front() == 'v') nm.erase(0, 1);
        w_->Write(nm);
        if (multi && data && data->reassigned)
            w_->Write(" /* " + MultiCatchText(*catch_alts_) + " */");
        NoteWrittenName(w_->snap_->meta.cls_name, "v" + nm);  // dexllm#129
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
        // dexllm#102: only a reference is throwable — `throw null`.
        if (!emit_const_at(ConstContext::Value, "Ljava/lang/Throwable;", ref))
            visit_ins(ref);
        w_->EndIns();
    }

    // Beyond-DAD (dexllm#102): render an untyped integer Constant in the
    // declared type of the position that consumes it. WHAT it means is decided
    // by `ConstantAt` (instruction.h) — the one definition the AST emitter
    // shares; this only spells the answer. Returns true if it emitted.
    bool emit_const_at(ConstContext ctx, std::string_view target,
                       IRForm* operand) {
        const auto lit = ConstantAt(ctx, target, operand);
        if (!lit) return false;
        using K = ConstLiteral::Kind;
        switch (lit->kind) {
            case K::Bool: w_->Write(lit->raw ? "true" : "false"); break;
            case K::Null: w_->Write("null"); break;
            case K::NullCast:
                // dexllm#109: the spelling a check-cast of null gets
                w_->Write("((");
                w_->Write(GetType(std::string(target)));
                w_->Write(") null)");
                break;
            case K::Float: {
                const uint32_t bits = static_cast<uint32_t>(lit->raw);
                float f; std::memcpy(&f, &bits, sizeof(f));
                w_->Write(FormatFloatLiteral(f));
                break;
            }
            case K::Double: {
                const uint64_t bits = static_cast<uint64_t>(lit->raw);
                double d; std::memcpy(&d, &bits, sizeof(d));
                w_->Write(FormatDoubleLiteral(d));
                break;
            }
            case K::NarrowCast:
                // the spelling visit_cast gives a CastExpression: `((char) 125)`
                w_->Write(lit->narrow == 'C' ? "((char) "
                          : lit->narrow == 'B' ? "((byte) " : "((short) ");
                w_->Write(std::to_string(lit->raw));
                w_->Write(")");
                break;
        }
        return true;
    }

    void visit_binary_expression(std::string_view op, std::string_view etype,
                                  IRForm* arg1, IRForm* arg2) override {
        // dexllm#94: a 0/1 operand of a bitwise op the dataflow typed `Z` is
        // `false`/`true` (`flag |= cond` starts from `0 | …`, d8's `!b` is
        // `b ^ 1`); `boolean | int` does not compile. Same rule as the AST.
        auto operand = [&](IRForm* a) {
            if (auto b = BitwiseBoolConstant(op, etype, a)) {
                w_->Write(*b ? "true" : "false");
                return;
            }
            if (!emit_const_at(ConstContext::Operand, etype, a)) visit_ins(a);
        };
        w_->Write("(");
        operand(arg1);
        w_->Write(" ");
        w_->Write(op);
        w_->Write(" ");
        operand(arg2);
        w_->Write(")");
    }
    // dexllm#92: the operand goes through `ConstantAt` like every other typed
    // position — a `const-wide` read as a double here is `1.0`, not the long
    // `4607182418800017408L` (which javac accepts with the wrong value).
    void visit_unary_expression(std::string_view op, std::string_view operand_type,
                                IRForm* arg) override {
        w_->Write("(");
        w_->Write(op);
        w_->Write(" ");
        if (!emit_const_at(ConstContext::Operand, operand_type, arg)) visit_ins(arg);
        w_->Write(")");
    }
    void visit_cast(std::string_view op, std::string_view operand_type,
                    IRForm* arg) override {
        w_->Write("(");
        w_->Write(op);
        w_->Write(" ");
        if (!emit_const_at(ConstContext::Operand, operand_type, arg)) visit_ins(arg);
        w_->Write(")");
    }
    void visit_cond_expression(std::string_view op, std::string_view etype,
                                IRForm* arg1, IRForm* arg2) override {
        if (!emit_const_at(ConstContext::Operand, etype, arg1)) visit_ins(arg1);
        w_->Write(" ");
        w_->Write(op);
        w_->Write(" ");
        if (!emit_const_at(ConstContext::Operand, etype, arg2)) visit_ins(arg2);
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
                            std::string_view /*ftype*/,
                            std::string_view owner) override {
        // dexllm#129 — inside an inlined anonymous body, a captured value.
        if (const std::string* t = CapturedFieldText(
                w_->snap_->meta.cls_name, owner, name,
                dynamic_cast<ThisParam*>(arg) != nullptr)) {
            w_->Write(*t);
            return;
        }
        emit_base_maybe_cast(arg, owner);  // `((Owner) v).field` for Object v
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

    void write_ind_visit_end(IRForm* lhs, std::string_view sep, IRForm* rhs = nullptr,
                             ConstContext ctx = ConstContext::Operand) {
        w_->WriteIndent();
        visit_ins(lhs);
        w_->Write(sep);
        // `double v = <raw-bits int const>` → `double v = 0.5`: the lhs type is
        // the position's type (dexllm#102 — and in a Value context `boolean v =
        // true`, `Foo v = null`).
        if (rhs && !(lhs && emit_const_at(ctx, lhs->get_type(), rhs))) {
            visit_ins(rhs);
        }
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
                // the binary op's own type is the F/D context for arg2 (a
                // raw-bits int const in a double/float compound assign, e.g.
                // `p2 *= 2.0`). dexllm#94: a 0/1 operand of a bitwise op the
                // dataflow typed `Z` is `true`/`false` here too (`v ^= true`),
                // as in visit_binary_expression and the AST.
                if (auto b = BitwiseBoolConstant(bin->op(), bin->get_type(), arg2))
                    w_->Write(*b ? "true" : "false");
                else if (!emit_const_at(ConstContext::Operand, bin->get_type(), arg2))
                    visit_ins(arg2);
                w_->EndIns();
                return;
            }
        }
        // Beyond-DAD: the lhs's type is the position's type for an untyped
        // integer constant — `Foo v = null` (a Dalvik 0 in an object register),
        // `boolean v = true` (a Z register holds only 0/1), `double v = 0.5`
        // (raw bits). One rule for every position: `ConstantAt` (dexllm#102),
        // which the AST's typed_rhs_expr shares. Surfaces where a type pass has
        // correctly typed the lhs (FixInitResultTypes, the cascade, dexllm#86 /
        // #94) and DAD emitted `= 0`. A ThisParam lhs is NOT a local: `this = 0`
        // is the pre-existing DAD this-slot-reuse corruption (assignment to
        // `this`, already invalid) — kept DAD-faithful (Operand context: F/D
        // only) rather than silently diverging to `this = null`.
        write_ind_visit_end(lhs, " = ", rhs,
                            (lhs && !dynamic_cast<ThisParam*>(lhs))
                                ? ConstContext::Value : ConstContext::Operand);
    }

    static IRForm* MapGet(const IRForm* owner, const std::string& key) {
        if (!owner) return nullptr;
        auto it = owner->var_map.find(key);
        return it == owner->var_map.end() ? nullptr : it->second.get();
    }

    Writer* w_;
public:
    bool constructor_ = false;
    // dexllm#132: the clause's catch types when its handler catches several
    // (CatchBlock::catch_alternatives), set by EmitTry for the one visit of
    // that clause's move-exception.
    const std::vector<std::string>* catch_alts_ = nullptr;
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
    // Beyond-DAD: a <clinit> is a static initializer, not a callable method.
    // DAD (writer.py:167) sees its ACC_CONSTRUCTOR flag and emits
    // `static <ClassName>()` — invalid Java. Emit a `static { }` block instead:
    // the modifiers (just `static`) with NO name, return type, or parameters.
    // The trailing `return;` is separately suppressed in visit_return_void
    // (`return` is a compile error inside an initializer, JLS §8.7). No
    // *DADFaithful sibling — parity suites don't assert method signatures
    // (return-literal / catch-clamp precedent).
    is_clinit_ = (m.name == "<clinit>");
    Write("\n");
    Write(Space());
    if (is_clinit_) {
        // A static initializer block is exactly `static { }` — it takes NO
        // access modifier. A <clinit> may carry ACC_PUBLIC/etc. in dex (obfuscated
        // dex does), but `public static { }` is invalid Java, so emit only the
        // `static` keyword and drop any other modifier.
        Write("static");
    } else {
        if (!mods.empty()) {
            for (size_t i = 0; i < mods.size(); ++i) {
                if (i > 0) Write(" ");
                Write(mods[i]);
            }
            Write(" ");
        }
        if (is_constructor_) {
            // dexllm#128 — inside its outer class a member's constructor
            // takes the member's simple name, as its header does.
            const std::string_view nested_name = ConstructorNameFor(m.cls_name);
            std::string cls_desc(StripClassDesc(m.cls_name));
            auto slash = cls_desc.rfind('/');
            if (!nested_name.empty()) {
                Write(std::string(nested_name));
            } else {
                Write(slash == std::string::npos ? cls_desc
                                                 : cls_desc.substr(slash + 1));
            }
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
                NoteWrittenName(m.cls_name, "p" + std::to_string(reg));  // dexllm#129
                num_param += static_cast<int>(GetTypeSize(parsed_params[i]));
            }
        }
        Write(")");
    }

    if (!graph_ || !graph_->entry) {
        // A `<clinit>` reaching here has emitted the bare `static` keyword, and
        // `static;` is not Java. With no instruction nothing executes, so the
        // empty initializer block is both valid AND true — the one shape where
        // `{ }` is not the fabrication the marker exists to refuse (adversarial
        // review of dexllm#73). Scoped to the no-instruction case so the
        // pre-existing rendering of a code-less `<clinit>` is untouched.
        Write(is_clinit_ && snap_ && snap_->code_without_instructions
                  ? " { }"
                  : ";");
        // beyond-DAD (dexllm#73): a method whose code item carries no decodable
        // instruction has no body to emit, and the signature-only form it shares
        // with abstract/native says so only by the ABSENCE of a modifier. State
        // the refusal instead — the same "say that you could not render it"
        // choice dexllm#64 made for an unrenderable static initializer. A line
        // comment, and the text is fixed (no attacker-controlled bytes reach it).
        if (snap_ && snap_->code_without_instructions) Write("  // no instructions");
        Write("\n");
        return;
    }
    // beyond-DAD (dexllm#75): the code item opens with a payload, so the body
    // below starts at the first DECODABLE instruction rather than at byte offset
    // 0, where a VM would start — a REINTERPRETATION of a method that cannot
    // execute as written. State it instead of leaving it to be inferred, the
    // same "say what you could not do straight" choice dexllm#73 made for
    // `// no instructions` and dexllm#64 for `// = ...`. Fixed text (no
    // attacker-controlled bytes reach it), and the AST carries the identical
    // string in its `comments` array so the two emitters agree. Emitted HERE
    // rather than beside the signature-only marker above so it can never land
    // between the signature and that path's `;`. It is unreachable there in any
    // case: the two flags are mutually exclusive (that one needs an EMPTY
    // ins_storage, this one a non-empty front()).
    if (snap_ && snap_->entry_not_at_offset_zero) {
        Write("  // entry is not at offset 0");
    }
    // beyond-DAD (dexllm#77): a block is ENTERED at an offset that is not an
    // instruction — a target pointing into payload data or into the tail of a
    // multi-unit instruction — so the block is read from the first instruction
    // at or after it, and falls through when it holds none. Same "say what you
    // could not do straight" rule as the marker above, and the AST carries the
    // identical string. The two are independent, so a method can carry both;
    // each ends the DECLARATION line, never a body statement.
    if (graph_ && graph_->control_enters_non_instruction) {
        Write("  // control enters at a non-instruction offset");
    }
    Write("\n");
    Write(Space());
    Write("{\n");
    IncIndent();
    tail_pos_ = true;  // the method body's top-level chain is in tail position
    VisitNode(graph_->entry);
    DecIndent();
    Write(Space());
    Write("}\n");
}

// True when VisitNode(node) would return before writing anything — the same
// early-return conditions, in the same order.
// dexllm#138: the join node after an if / switch / try writes nothing at this
// point -- none, the loop exit, the header, or code already written -- so
// leaving the construct ends the loop body's chain here.
bool Writer::FollowEndsBody(NodeBase* follow) const {
    if (!follow || follow == loop_follow_.back() || follow == loop_head_.back())
        return true;
    auto* fn = dynamic_cast<Node*>(follow);
    return fn && !fn->type.is_return() && visited_.count(follow);
}

// dexllm#138: `n` runs straight into the next switch case -- the path
// EmitStatement ends with need_break_ = false so the case falls through. Only
// at the case's own level: inside a loop in the case a `break` would leave the
// loop instead.
bool Writer::FallsToNextCase(NodeBase* n) const {
    if (!next_case_ || loop_follow_.size() != case_loop_depth_) return false;
    for (int i = 0; n && i < 64; ++i) {
        if (n == next_case_) return true;
        if (!dynamic_cast<StatementBlock*>(n) || visited_.count(n)) return false;
        auto s = graph_->sucs(n);
        if (s.size() != 1) return false;
        n = s[0];
    }
    return false;
}

bool Writer::IsContinue(NodeBase* node) const {
    return node && node == loop_head_.back() && !loop_tail_ &&
           visited_.count(node);
}

bool Writer::EmitsNothing(NodeBase* node) const {
    if (!node) return true;
    if (node == if_follow_.back() || node == switch_follow_.back() ||
        node == loop_follow_.back() || node == latch_node_.back() ||
        node == try_follow_.back()) return true;
    if (IsContinue(node)) return false;
    auto* nn = dynamic_cast<Node*>(node);
    return nn && !nn->type.is_return() && visited_.count(node);
}

void Writer::VisitNode(NodeBase* node) {
    if (!node) return;
    // The graph DFS/post_order passes are iterative to avoid stack overflow on
    // large CFGs, but this structural emit walk recurses (EmitIf/EmitLoop/... ->
    // VisitNode). A crafted method with thousands of nested if/follow blocks would
    // overflow the native stack — an uncatchable SIGSEGV that the per-method
    // try/catch and safe.py's hang-only wrapper cannot contain. Cap the depth and
    // throw so decompiler.cpp's catch turns it into an empty decompile. Real
    // methods nest far below this (DAD's effective Python recursion limit is ~1k).
    struct DepthGuard {
        int& d;
        explicit DepthGuard(int& x) : d(x) { ++d; }
        ~DepthGuard() { --d; }
    } depth_guard(depth_);
    if (depth_ > 2000) {
        throw std::runtime_error("decompile: structured emit recursion too deep");
    }
    if (node == if_follow_.back() || node == switch_follow_.back() ||
        node == loop_follow_.back() || node == latch_node_.back() ||
        node == try_follow_.back()) return;
    // Beyond-DAD (dexllm#138): a back edge to the enclosing loop's header from
    // a point that does not fall off the end of the body. DAD has no
    // `continue`: the visited header emitted nothing and the edge read as
    // falling through to whatever the walk wrote next (an if's join code).
    // Like a return, it ends a switch case, which then takes no `break`.
    if (IsContinue(node)) {
        need_break_ = false;
        WriteIndent(); Write("continue"); EndIns();
        return;
    }
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
    need_break_ = false;  // dexllm#138: a throw ends the case like a return
    for (const auto& ins : thr->get_ins()) VisitIns(ins);
}

void Writer::EmitIf(CondBlock* cond) {
    // D-3 — map the `if (…)` header line once. All three emit forms below
    // (both-branches-same comment, break form, normal) open their header on the
    // current line and share the same if-test offset; recording once here is
    // cleaner than three call sites and the same-line dedup is a backstop.
    RecordLine(CondReprIns(cond));
    // Tail position (for the <clinit> return-void drop): the `if`'s branches are
    // in tail position only if the `if` itself is (entry_tail) AND has no follow
    // (nothing runs after the if/else join). Restore to entry_tail for the
    // follow visit. Conservative on the special forms below (false).
    const bool entry_tail = tail_pos_;
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
        tail_pos_ = false;
        VisitNode(cond->true_branch);
        tail_pos_ = entry_tail;
        DecIndent();
        WriteIndent();
        Write("// }\n");
        return;
    }
    // DAD writer.py:318-328 — break form. When a branch of this if leaves the
    // enclosing loop (targets loop_follow), emit `if (cond) { break; }` and then
    // continue with the in-loop branch. Without this the loop-exit edge produced
    // an empty `if (cond) {}` with the break silently dropped.
    NodeBase* loop_follow = loop_follow_.empty() ? nullptr : loop_follow_.back();
    if (loop_follow != nullptr && cond->false_branch == loop_follow) {
        cond->neg();
        std::swap(cond->true_branch, cond->false_branch);
    }
    if (loop_follow != nullptr &&
        (cond->true_branch == loop_follow || cond->false_branch == loop_follow)) {
        WriteIndent(); Write("if (");
        WriterImpl wib(this); wib.constructor_ = is_constructor_;
        cond->visit_cond(wib);
        Write(") {\n");
        IncIndent();
        WriteIndent(); Write("break;\n");
        DecIndent();
        WriteIndent(); Write("}\n");
        if (cond->false_branch) {
            tail_pos_ = entry_tail;  // the in-loop remainder inherits the if's tail
            VisitNode(cond->false_branch);
        }
        return;
    }
    NodeBase* follow = nullptr;
    auto it = cond->follow.find("if");
    if (it != cond->follow.end()) follow = it->second;
    // Branches are in tail position iff the if is AND there's no join code after.
    const bool branch_tail = entry_tail && (follow == nullptr);

    // DAD writer.py:352-363 — an if with NO follow (no join code after it)
    // visits BOTH arms unconditionally: no swap, no `if_follow` push, no
    // visited check on the false arm. dexllm#113: this branch used to be
    // folded into the follow path below, whose visited check dropped a false
    // arm that is a ReturnBlock already reached through the true arm —
    // returns are re-emitted at every reaching path (VisitNode's is_return
    // exemption), so the text lost a `return` the AST (dast.cpp, which ports
    // this branch) keeps. That path also pushed a nullptr `if_follow`; not
    // pushing is DAD's and dast's shape, and measured output-equivalent on
    // the whole corpus (IfStruct hands an enclosing follow to inner conds).
    if (follow == nullptr) {
        WriteIndent();
        Write("if (");
        WriterImpl wi3(this); wi3.constructor_ = is_constructor_;
        cond->visit_cond(wi3);
        Write(") {\n");
        IncIndent();
        tail_pos_ = branch_tail;
        // dexllm#138: need_break_ is "control reaches the end of what has been
        // written". Each arm starts reachable, and the if completes normally
        // when either arm does -- DAD let the LAST jump written in either arm
        // decide, so `if (c) return;` (or `continue;`) took the switch case's
        // `break;` with it.
        // When exactly one arm falls into the next case, the other one's
        // normal completion is a `break` of its own: one after the if would
        // stop the falling arm too.
        const bool t_falls = FallsToNextCase(cond->true_branch);
        const bool f_falls = FallsToNextCase(cond->false_branch);
        const bool split = t_falls != f_falls;
        need_break_ = true;
        VisitNode(cond->true_branch);
        if (split && !t_falls && need_break_) {
            WriteIndent(); Write("break"); EndIns(); need_break_ = false;
        }
        bool reach = need_break_;
        need_break_ = true;
        DecIndent();
        // DAD writes `} else {` here unconditionally, so an arm VisitNode
        // would emit nothing for (a follow guard, or an already-visited
        // non-return block) renders as an empty `} else { }`. Omit only that
        // empty arm: the AST keeps an empty block, which says the same thing.
        if (!EmitsNothing(cond->false_branch)) {
            WriteIndent(); Write("} else {\n");
            IncIndent();
            tail_pos_ = branch_tail;
            VisitNode(cond->false_branch);
            if (split && !f_falls && need_break_) {
                WriteIndent(); Write("break"); EndIns(); need_break_ = false;
            }
            DecIndent();
        }
        need_break_ = reach || need_break_;
        WriteIndent(); Write("}\n");
        tail_pos_ = entry_tail;
        return;
    }

    // DAD: writer.py:319-326 — if the true branch goes straight to the follow
    // (or to next_case inside a switch body), negate the condition and swap
    // branches so we emit `if (cond) { body }` instead of
    // `if (!cond) { } else { body }`. Also fires for the `cond.num > true.num`
    // ordering heuristic (true branch would be a backward jump).
    // dexllm#138: an arm falls off into the loop's back edge only when the
    // join code after the if writes nothing (no follow, or the loop exit).
    const bool entry_ltail = loop_tail_;
    const bool arm_ltail = entry_ltail && FollowEndsBody(follow);
    if (follow != nullptr && cond->true_branch != nullptr) {
        bool true_is_follow = (cond->true_branch == follow);
        bool true_is_next_case = (cond->true_branch == next_case_);
        bool backward_true = cond->num > cond->true_branch->num;
        // dexllm#138: a back edge to the loop header is backward, but beside a
        // false-branch follow it is a `continue` arm; swapping it into the
        // false position leaves it where no arm is written.
        if (backward_true && !arm_ltail && cond->false_branch == follow &&
            cond->true_branch == loop_head_.back() &&
            visited_.count(cond->true_branch))
            backward_true = false;
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
    loop_tail_ = arm_ltail;
    need_break_ = true;  // dexllm#138: see the no-follow path above
    if (cond->true_branch && cond->true_branch != follow) {
        if_follow_.push_back(follow);
        tail_pos_ = branch_tail;
        VisitNode(cond->true_branch);
        if_follow_.pop_back();
    }
    bool reach = need_break_;
    need_break_ = true;
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
        (!visited_.count(cond->false_branch) ||
         IsContinue(cond->false_branch))) {
        WriteIndent(); Write("} else {\n");
        IncIndent();
        if_follow_.push_back(follow);
        tail_pos_ = branch_tail;
        VisitNode(cond->false_branch);
        if_follow_.pop_back();
        DecIndent();
    }
    need_break_ = reach || need_break_;
    WriteIndent(); Write("}\n");
    loop_tail_ = entry_ltail;
    tail_pos_ = entry_tail;  // the follow (join code) inherits the if's tail
    if (follow) VisitNode(follow);
}

void Writer::EmitLoop(LoopBlock* loop) {
    NodeBase* follow = nullptr;
    auto fit = loop->follow.find("loop");
    if (fit != loop->follow.end()) follow = fit->second;
    WriterImpl wi(this); wi.constructor_ = is_constructor_;
    // A return inside a loop body is reached mid-iteration, never in the method's
    // tail position — keep it (conservative). The follow inherits the loop's tail.
    const bool entry_tail = tail_pos_;
    tail_pos_ = false;
    // dexllm#138: the body's own chain falls off into the back edge.
    const bool entry_ltail = loop_tail_;
    loop_head_.push_back(loop->looptype.is_posttest() ? nullptr : loop);
    loop_tail_ = true;

    if (loop->looptype.is_pretest()) {
        // DAD: writer.py:241-243 — if true branch is the loop exit, negate
        // the cond and swap so the body lives in true_branch.
        if (loop->true_branch != nullptr && loop->true_branch == follow) {
            loop->neg();
            std::swap(loop->true_branch, loop->false_branch);
        }
        RecordLine(CondReprIns(loop));  // D-3 — pretest `while (cond)` line
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
        // DAD writer.py:254 emits `while(true)` WITHOUT a space (unlike the
        // pretest `while (cond)` form) — match it exactly.
        WriteIndent(); Write("while(true) {\n");
        IncIndent();
        loop_follow_.push_back(follow);
        // DAD writer.py:262 visit_node(loop.cond) — the wrapped header node
        // (any block type), NOT only a CondBlock; a StatementBlock header here
        // carries the entire loop body.
        if (loop->cond_node) VisitNode(loop->cond_node);
        if (!written_latches_.count(loop->latch)) VisitNode(loop->latch);
        loop_follow_.pop_back();
        DecIndent();
        WriteIndent(); Write("}\n");
    } else {
        WriteIndent(); Write("do {\n");
        IncIndent();
        loop_follow_.push_back(follow);
        latch_node_.push_back(loop->latch);
        if (loop->cond_node) VisitNode(loop->cond_node);
        latch_node_.pop_back();
        loop_follow_.pop_back();
        DecIndent();
        // DAD writer.py:269 emits the posttest latch as `} while(` WITHOUT a
        // space (unlike the pretest `while (` form, like the endless
        // `while(true)`). Match it exactly.
        // D-3 — posttest `} while(latch)` line ↔ latch's dex offset.
        if (auto* latch_cb = dynamic_cast<CondBlock*>(loop->latch))
            RecordLine(CondReprIns(latch_cb));
        WriteIndent(); Write("} while(");
        // DAD writer.py:271 loop.latch.visit_cond(self). visit_cond dispatches
        // virtually: a plain CondBlock latch emits its single ins; a
        // ShortCircuitBlock latch (compound `&&`/`||` do-while condition) emits
        // the whole Condition tree. The old `get_ins().back()` path only handled
        // the single-ins case → short-circuit do-while conditions emitted as
        // empty `} while ()`.
        if (auto* latch_cond = dynamic_cast<CondBlock*>(loop->latch)) {
            latch_cond->visit_cond(wi);
        }
        Write(");\n");
        // dexllm#138: the latch is written now, as the loop's test. An outer
        // loop can share it as its own back-edge source, and an endless outer
        // loop visits its latch after the body -- it must not write it again.
        // (Only that visit: a path reaching the latch through a handler still
        // writes it, as DAD does.)
        if (loop->latch) written_latches_.insert(loop->latch);
    }
    loop_head_.pop_back();
    loop_tail_ = entry_ltail;
    // dexllm#138: a loop completes normally unless it is endless with no exit
    // (a jump inside its body says nothing about what follows the loop).
    need_break_ = !(loop->looptype.is_endless() && follow == nullptr);
    tail_pos_ = entry_tail;
    if (follow) VisitNode(follow);
}

void Writer::EmitSwitch(SwitchBlock* sw) {
    auto lins = sw->get_ins();
    WriterImpl wi(this); wi.constructor_ = is_constructor_;
    // Conservative: a return inside a switch case is kept (break/fall-through
    // structuring makes tail position ambiguous). The follow inherits the tail.
    const bool entry_tail = tail_pos_;
    tail_pos_ = false;
    for (size_t i = 0; i + 1 < lins.size(); ++i) VisitIns(lins[i]);
    if (!lins.empty()) RecordLine(lins.back().get());  // D-3 — `switch (x)` line
    WriteIndent(); Write("switch (");
    if (!lins.empty()) lins.back()->Accept(wi);
    Write(") {\n");
    IncIndent();
    NodeBase* follow = nullptr;
    auto sit = sw->follow.find("switch");
    if (sit != sw->follow.end()) follow = sit->second;
    switch_follow_.push_back(follow);
    // dexllm#138: a case left by `break` reaches the loop's back edge only
    // when nothing follows the switch; otherwise a back edge is `continue`.
    const bool entry_ltail = loop_tail_;
    loop_tail_ = entry_ltail && FollowEndsBody(follow);
    const size_t entry_case_depth = case_loop_depth_;
    NodeBase* default_node = sw->default_case;
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
        // DAD writer.py:398-400 — a case block that IS the default carries the
        // `default:` label here, and the trailing default emission is skipped.
        // dexllm#113: without this the shared block was emitted twice (under
        // its case labels and again under `default:`); dast.cpp ports it.
        if (case_node == default_node) {
            WriteIndent(); Write("default:\n");
            default_node = nullptr;
        }
        IncIndent();
        need_break_ = true;  // dexllm#138: a case starts reachable
        case_loop_depth_ = loop_follow_.size();
        VisitNode(case_node);
        if (need_break_) { WriteIndent(); Write("break"); EndIns(); }
        else need_break_ = true;
        DecIndent();
    }
    if (default_node && default_node != follow) {
        WriteIndent(); Write("default:\n");
        IncIndent(); VisitNode(default_node); DecIndent();
    }
    switch_follow_.pop_back();
    case_loop_depth_ = entry_case_depth;
    DecIndent();
    WriteIndent(); Write("}\n");
    loop_tail_ = entry_ltail;
    tail_pos_ = entry_tail;
    if (follow) VisitNode(follow);
}

const ScopeIndex* Writer::ScopeIndexFor() {
    if (!scope_index_) scope_index_ = BuildScopeIndex(*graph_);
    return scope_index_.get();
}

void Writer::EmitTry(TryBlock* tb) {
    // Conservative: returns inside try/catch bodies are kept (a return in a try
    // followed by a catch, or in a catch, is genuinely early). The try's follow
    // inherits the tail.
    const bool entry_tail = tail_pos_;
    tail_pos_ = false;
    // dexllm#138: falling off a try or catch body reaches the loop's back
    // edge only when nothing follows the try; otherwise one is `continue`.
    const bool entry_ltail = loop_tail_;
    loop_tail_ = entry_ltail && FollowEndsBody(tb->try_follow);
    // Beyond-DAD (dexllm#122): a local the try body defines and code outside it
    // reads is declared BEFORE the try -- Java scopes it to the block.
    if (graph_) {
        WriterImpl wi(this);
        std::vector<NodeBase*> bodies{tb->try_start};
        for (NodeBase* c : tb->catch_nodes)
            if (auto* cb = dynamic_cast<CatchBlock*>(c)) bodies.push_back(cb->catch_start);
        auto stop = [&](NodeBase* n) {
            if (visited_.count(n) || n == tb->try_follow || n == next_case_) return true;
            for (auto* st : {&loop_follow_, &if_follow_, &switch_follow_, &try_follow_, &latch_node_})
                for (NodeBase* f : *st) if (f && f == n) return true;
            return false;
        };
        for (Variable* v : ScopeEscapingDefs(*graph_, *ScopeIndexFor(), bodies, stop)) wi.visit_decl(v);
    }
    WriteIndent(); Write("try {\n");
    IncIndent();
    try_follow_.push_back(tb->try_follow);
    need_break_ = true;  // dexllm#138: reachable after the try if any body is
    VisitNode(tb->try_start);
    bool reach = need_break_;
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
            wi.catch_alts_ = &catch_block->catch_alternatives;
            catch_block->exception_ins->Accept(wi);
        } else if (catch_block->catch_alternatives.size() > 1) {
            Write(MultiCatchText(catch_block->catch_alternatives));  // dexllm#132
            Write(" _");
        } else {
            Write(JavaType(UnboundCatchType(*catch_block)));
            Write(" _");
        }
        Write(") {\n");
        IncIndent();
        need_break_ = true;
        VisitNode(catch_block->catch_start);
        reach = reach || need_break_;
        DecIndent();
        WriteIndent(); Write("}");
    }
    Write("\n");
    try_follow_.pop_back();
    need_break_ = reach;
    loop_tail_ = entry_ltail;
    tail_pos_ = entry_tail;
    if (tb->try_follow) VisitNode(tb->try_follow);
}

void Writer::VisitIns(const IRFormPtr& ins) {
    if (!ins) return;
    IRForm* op = ins.get();
    if (dynamic_cast<NopExpression*>(op)) return;
    // D-3 — map this statement's line, but ONLY if it emits a REAL statement.
    // An elided implicit super()/this() is an AssignExpression whose suppressed
    // invoke sets skip_ and omits the trailing `;`: it still writes the line
    // indent (so the buffer grows) yet contributes no statement, and the next
    // real statement reuses that indent on the same line. Recording its offset
    // (0) would then claim that line via first-anchor-wins and stamp the wrong
    // offset. Record iff the buffer grew AND the statement wasn't elided
    // (skip_ is set by the elision and not yet consumed by the next
    // WriteIndent). Mirrors the AST path, where ins_to_stmt returns null for
    // the elided super and add_off no-ops.
    const uint32_t line_at_start = current_line_;
    const auto pos_before = buffer_.tellp();
    WriterImpl wi(this);
    wi.constructor_ = is_constructor_;
    op->Accept(wi);
    if (buffer_.tellp() != pos_before && !skip_)
        RecordLineAt(line_at_start, op);
}

// D-3 — representative offset-bearing IR for a condition/loop/switch header.
// Delegates to CondBlock::repr_ins (virtual), which dispatches the
// ShortCircuitBlock / LoopBlock / plain-CondBlock cases in one place (the same
// recovery JSONWriter::pc_map uses). The returned pointer is graph-owned and
// outlives the call.
const IRForm* Writer::CondReprIns(CondBlock* node) {
    return node ? node->repr_ins() : nullptr;
}

// Kept for backwards-compat; new path uses WriterImpl via VisitIns.
void Writer::EmitExpr(IRForm* op) {
    if (!op) return;
    WriterImpl wi(this);
    wi.constructor_ = is_constructor_;
    op->Accept(wi);
}

}  // namespace dexkit::dad
