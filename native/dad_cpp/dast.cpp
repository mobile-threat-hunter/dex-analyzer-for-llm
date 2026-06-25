// dast.cpp — DAD dast.py port.
//
// JSONWriter is "a simplified version of writer.py that outputs an AST instead
// of source code" (dast.py module docstring). It walks the same structured CFG
// + IR as Writer but builds a nested-list AST (modelled here as AstValue).
// Every method below carries a `// DAD: dast.py:<lineno> <concept>` comment.

#include "dast.h"

#include <array>
#include <charconv>
#include <cmath>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <stdexcept>
#include <string>

#include "mutf8.h"
#include "opcode_ins.h"  // Op::EQUAL
#include "util.h"

namespace dexkit::dad {

namespace {

// ── small string helpers ────────────────────────────────────────────────────

// DAD's `clsdesc[1:-1]` / androguard get_triple()[0] — drop the first and last
// character of a class descriptor unconditionally (NOT a conditional L; strip).
// For "Ljava/lang/Object;" → "java/lang/Object"; for an array receiver
// "[Lcom/X;" → "Lcom/X" (matching androguard's slice, not a type strip).
std::string StripL(std::string_view d) {
    if (d.size() >= 2) return std::string(d.substr(1, d.size() - 2));
    return std::string(d);
}

// DAD emits `local('v{}'.format(var.name))` where var.name is the register
// number. Our Variable.name is already the "vN" string, so strip the leading
// 'v' to avoid double-prefix, then re-prefix.
std::string VarLocalName(std::string_view name) {
    if (!name.empty() && name.front() == 'v') name.remove_prefix(1);
    return "v" + std::string(name);
}

// Match Python's str(float) shortest round-trip repr closely enough for AST
// parity: std::to_chars gives the shortest round-tripping digits; we then
// ensure a '.'/'e' is present (Python always renders a float marker).
std::string PyFloatRepr(double f) {
    char buf[64];
    auto res = std::to_chars(buf, buf + sizeof(buf), f);
    std::string s(buf, res.ptr);
    if (s.find('.') == std::string::npos && s.find('e') == std::string::npos &&
        s.find('n') == std::string::npos && s.find('i') == std::string::npos) {
        s += ".0";
    }
    return s;
}

// Decode dex MUTF-8 → standard UTF-8 (the AST stores the decoded string VALUE,
// like DAD's Python str). Delegates to the shared ART-faithful decoder: MUTF-8 →
// UTF-16 code units → UTF-8 with valid surrogate pairs combined into one 4-byte
// code point. See native/dad_cpp/mutf8.h.
std::string Mutf8ToUtf8(std::string_view raw) {
    return mutf8::Mutf8ToUtf8(raw);
}

// ── AST factory helpers (DAD dast.py:600-766 static methods) ─────────────────

using AV = AstValue;

AV Tuple2(std::string a, int64_t b) {
    return AV::Arr({AV::Str(std::move(a)), AV::Int(b)});
}

// DAD: dast.py:737 literal(result, tt) → ['Literal', result, tt]
AV Literal(AV result, AV tt) {
    return AV::Arr({AV::Str("Literal"), std::move(result), std::move(tt)});
}
// DAD: dast.py:719 typen(baset, dim) → ['TypeName', (baset, dim)]
AV Typen(std::string baset, int64_t dim) {
    return AV::Arr({AV::Str("TypeName"), Tuple2(std::move(baset), dim)});
}
// DAD: dast.py:733 local(name) → ['Local', name]
AV Local(std::string name) {
    return AV::Arr({AV::Str("Local"), AV::Str(std::move(name))});
}
// DAD: dast.py:703 dummy(*args) → ['Dummy', args]
AV Dummy(std::vector<AV> args) {
    return AV::Arr({AV::Str("Dummy"), AV::Arr(std::move(args))});
}
// DAD: dast.py:723 parenthesis(expr) → ['Parenthesis', [expr]]
AV Parenthesis(AV expr) {
    return AV::Arr({AV::Str("Parenthesis"), AV::Arr({std::move(expr)})});
}
// DAD: dast.py:749 binary_infix(op, left, right) → ['BinaryInfix', [left,right], op]
AV BinaryInfix(std::string op, AV left, AV right) {
    return AV::Arr({AV::Str("BinaryInfix"),
                    AV::Arr({std::move(left), std::move(right)}),
                    AV::Str(std::move(op))});
}
// DAD: dast.py:752 assignment(lhs, rhs, op='') → ['Assignment', [lhs,rhs], op]
AV Assignment(AV lhs, AV rhs, std::string op = "") {
    return AV::Arr({AV::Str("Assignment"),
                    AV::Arr({std::move(lhs), std::move(rhs)}),
                    AV::Str(std::move(op))});
}
// DAD: dast.py:741 field_access(triple, left) → ['FieldAccess', [left], triple]
AV FieldAccess(AV triple, AV left) {
    return AV::Arr({AV::Str("FieldAccess"), AV::Arr({std::move(left)}),
                    std::move(triple)});
}
// DAD: dast.py:745 cast(tn, arg) → ['Cast', [tn, arg]]
AV Cast(AV tn, AV arg) {
    return AV::Arr({AV::Str("Cast"), AV::Arr({std::move(tn), std::move(arg)})});
}
// DAD: dast.py:711/714 unary_postfix/prefix → ['Unary', [left], op, is_postfix]
AV UnaryPrefix(std::string op, AV left) {
    return AV::Arr({AV::Str("Unary"), AV::Arr({std::move(left)}),
                    AV::Str(std::move(op)), AV::Bool(false)});
}
AV UnaryPostfix(AV left, std::string op) {
    return AV::Arr({AV::Str("Unary"), AV::Arr({std::move(left)}),
                    AV::Str(std::move(op)), AV::Bool(true)});
}
// DAD: dast.py:756 array_initializer(params, tn=None)
AV ArrayInitializer(std::vector<AV> params, AV tn = AV::Null()) {
    return AV::Arr({AV::Str("ArrayInitializer"), AV::Arr(std::move(params)),
                    std::move(tn)});
}
// DAD: dast.py:760 array_creation(tn, params, dim) → ['ArrayCreation', [tn]+params, dim]
AV ArrayCreation(AV tn, std::vector<AV> params, int64_t dim) {
    std::vector<AV> children;
    children.push_back(std::move(tn));
    for (auto& p : params) children.push_back(std::move(p));
    return AV::Arr({AV::Str("ArrayCreation"), AV::Arr(std::move(children)),
                    AV::Int(dim)});
}
// DAD: dast.py:764 array_access(arr, ind) → ['ArrayAccess', [arr, ind]]
AV ArrayAccess(AV arr, AV ind) {
    return AV::Arr({AV::Str("ArrayAccess"),
                    AV::Arr({std::move(arr), std::move(ind)})});
}
// DAD: dast.py:707 var_decl(typen, var) → [typen, var]
AV VarDecl(AV typen, AV var) {
    return AV::Arr({std::move(typen), std::move(var)});
}
// DAD: dast.py:726 method_invocation(triple, name, base, params)
AV MethodInvocation(AV triple, std::string name, AV base, std::vector<AV> params) {
    if (base.is_null()) {
        return AV::Arr({AV::Str("MethodInvocation"), AV::Arr(std::move(params)),
                        std::move(triple), AV::Str(std::move(name)),
                        AV::Bool(false)});
    }
    std::vector<AV> args;
    args.push_back(std::move(base));
    for (auto& p : params) args.push_back(std::move(p));
    return AV::Arr({AV::Str("MethodInvocation"), AV::Arr(std::move(args)),
                    std::move(triple), AV::Str(std::move(name)), AV::Bool(true)});
}

// literal_* helpers (DAD dast.py:600-636).
AV LiteralNull()          { return Literal(AV::Str("null"), Tuple2(".null", 0)); }
AV LiteralInt(int64_t b)  { return Literal(AV::Str(std::to_string(b)), Tuple2(".int", 0)); }
AV LiteralLong(int64_t b) { return Literal(AV::Str(std::to_string(b) + "L"), Tuple2(".long", 0)); }
AV LiteralFloat(double f) { return Literal(AV::Str(PyFloatRepr(f) + "f"), Tuple2(".float", 0)); }
AV LiteralDouble(double f){ return Literal(AV::Str(PyFloatRepr(f)), Tuple2(".double", 0)); }
AV LiteralBool(bool b)    { return Literal(AV::Str(b ? "true" : "false"), Tuple2(".boolean", 0)); }
// NaN/±Inf-aware variants used by the beyond-DAD return-literal correction
// (a F/D method returning the raw IEEE bits). PyFloatRepr renders NaN/Inf as
// "nan"/"-inf" (invalid Java, and inconsistent with the text Writer's
// Float.NaN / Double.NEGATIVE_INFINITY); emit the same Java tokens the text
// path uses so decompile_method_ast agrees with decompile_method_java.
AV LiteralFloatChecked(float f) {
    if (std::isnan(f)) return Literal(AV::Str("Float.NaN"), Tuple2(".float", 0));
    if (std::isinf(f)) {
        return Literal(AV::Str(f > 0 ? "Float.POSITIVE_INFINITY"
                                     : "Float.NEGATIVE_INFINITY"),
                       Tuple2(".float", 0));
    }
    return LiteralFloat(static_cast<double>(f));
}
AV LiteralDoubleChecked(double d) {
    if (std::isnan(d)) return Literal(AV::Str("Double.NaN"), Tuple2(".double", 0));
    if (std::isinf(d)) {
        return Literal(AV::Str(d > 0 ? "Double.POSITIVE_INFINITY"
                                     : "Double.NEGATIVE_INFINITY"),
                       Tuple2(".double", 0));
    }
    return LiteralDouble(d);
}
AV LiteralString(std::string s) {
    return Literal(AV::Str(Mutf8ToUtf8(s)), Tuple2("java/lang/String", 0));
}

// Statement helpers (DAD dast.py:659-700).
AV StatementBlockNode() {
    return AV::Arr({AV::Str("BlockStatement"), AV::Null(), AV::Arr()});
}
AV SwitchStmt(AV cond, std::vector<AV> ksv_pairs) {
    return AV::Arr({AV::Str("SwitchStatement"), AV::Null(), std::move(cond),
                    AV::Arr(std::move(ksv_pairs))});
}
AV IfStmt(AV cond, std::vector<AV> scopes) {
    return AV::Arr({AV::Str("IfStatement"), AV::Null(), std::move(cond),
                    AV::Arr(std::move(scopes))});
}
AV TryStmt(AV tryb, std::vector<AV> pairs) {
    return AV::Arr({AV::Str("TryStatement"), AV::Null(), std::move(tryb),
                    AV::Arr(std::move(pairs))});
}
AV LoopStmt(bool isdo, AV cond, AV body) {
    return AV::Arr({AV::Str(isdo ? "DoStatement" : "WhileStatement"), AV::Null(),
                    std::move(cond), std::move(body)});
}
AV JumpStmt(std::string keyword) {
    return AV::Arr({AV::Str("JumpStatement"), AV::Str(std::move(keyword)),
                    AV::Null()});
}
AV ThrowStmt(AV expr) {
    return AV::Arr({AV::Str("ThrowStatement"), std::move(expr)});
}
AV ReturnStmt(AV expr) {
    return AV::Arr({AV::Str("ReturnStatement"), std::move(expr)});
}
AV LocalDeclStmt(AV expr, AV decl) {
    return AV::Arr({AV::Str("LocalDeclarationStatement"), std::move(expr),
                    std::move(decl)});
}
AV ExpressionStmt(AV expr) {
    return AV::Arr({AV::Str("ExpressionStatement"), std::move(expr)});
}

// DAD: dast.py:559 / 727 method/field triple → (class, name, type) tuple.
AV TripleAV(const std::array<std::string, 3>& t) {
    return AV::Arr({AV::Str(t[0]), AV::Str(t[1]), AV::Str(t[2])});
}

const std::string kPrimitives = "VZBSCIJFD";

}  // namespace

// DAD: dast.py:639 parse_descriptor.
AstValue ParseDescriptor(std::string_view desc) {
    int64_t dim = 0;
    while (!desc.empty() && desc.front() == '[') {
        desc.remove_prefix(1);
        ++dim;
    }
    if (desc.size() == 1 && kPrimitives.find(desc[0]) != std::string::npos) {
        std::string_view java = LookupTypeDescriptor(desc[0]);
        return Typen("." + std::string(java), dim);
    }
    if (desc.size() >= 2 && desc.front() == 'L' && desc.back() == ';') {
        return Typen(std::string(desc.substr(1, desc.size() - 2)), dim);
    }
    return Dummy({AV::Str(std::string(desc))});
}

// DAD: dast.py:483 literal_class(desc) → literal(parse_descriptor(desc), ...).
static AV LiteralClass(std::string_view desc) {
    return Literal(ParseDescriptor(desc), Tuple2("java/lang/Class", 0));
}

// ── AstValue JSON serialization (ensure_ascii) ──────────────────────────────
void AstValue::Dump(std::string& out) const {
    switch (kind_) {
        case Kind::Null: out += "null"; return;
        case Kind::Bool: out += b_ ? "true" : "false"; return;
        case Kind::Int: out += std::to_string(i_); return;
        case Kind::Str: {
            out += '"';
            const uint8_t* p = reinterpret_cast<const uint8_t*>(s_.data());
            const uint8_t* end = p + s_.size();
            while (p < end) {
                uint8_t c = *p;
                if (c == '"') { out += "\\\""; ++p; }
                else if (c == '\\') { out += "\\\\"; ++p; }
                else if (c == '\n') { out += "\\n"; ++p; }
                else if (c == '\r') { out += "\\r"; ++p; }
                else if (c == '\t') { out += "\\t"; ++p; }
                else if (c < 0x20) {
                    char b[8]; std::snprintf(b, sizeof(b), "\\u%04x", c);
                    out += b; ++p;
                } else if (c < 0x80) { out += static_cast<char>(c); ++p; }
                else {
                    // Decode one UTF-8 codepoint, emit \uXXXX (or surrogate pair).
                    uint32_t cp = 0; size_t n = 0;
                    if ((c & 0xE0) == 0xC0) { cp = c & 0x1F; n = 2; }
                    else if ((c & 0xF0) == 0xE0) { cp = c & 0x0F; n = 3; }
                    else if ((c & 0xF8) == 0xF0) { cp = c & 0x07; n = 4; }
                    else { ++p; continue; }
                    if (p + n > end) break;
                    for (size_t i = 1; i < n; ++i) cp = (cp << 6) | (p[i] & 0x3F);
                    p += n;
                    char b[16];
                    if (cp >= 0x10000) {
                        cp -= 0x10000;
                        std::snprintf(b, sizeof(b), "\\u%04x\\u%04x",
                                      0xD800 + (cp >> 10), 0xDC00 + (cp & 0x3FF));
                    } else {
                        std::snprintf(b, sizeof(b), "\\u%04x", cp);
                    }
                    out += b;
                }
            }
            out += '"';
            return;
        }
        case Kind::Arr: {
            out += '[';
            for (size_t i = 0; i < arr_.size(); ++i) {
                if (i) out += ", ";
                arr_[i].Dump(out);
            }
            out += ']';
            return;
        }
        case Kind::Obj: {
            out += '{';
            for (size_t i = 0; i < obj_.size(); ++i) {
                if (i) out += ", ";
                out += '"'; out += obj_[i].first; out += "\": ";
                obj_[i].second.Dump(out);
            }
            out += '}';
            return;
        }
    }
}

// ── JSONWriter ──────────────────────────────────────────────────────────────

JSONWriter::JSONWriter(const MethodSnapshot* snap, const Graph* graph)
    : snap_(snap), graph_(graph) {}

IRForm* JSONWriter::MapGet(const IRForm* owner, const std::string& key) {
    if (!owner) return nullptr;
    auto it = owner->var_map.find(key);
    return it == owner->var_map.end() ? nullptr : it->second.get();
}

// DAD: dast.py:56 add — append to current context (skip None per _append).
void JSONWriter::add(AstValue v) {
    if (v.is_null()) return;  // DAD: _append only appends non-None.
    context_.back().at(2).push_back(std::move(v));
    ++ast_seq_;  // D-3 — count this appended statement node (add()-order key).
}

// D-3 — append + record this statement's dex offset against its add()-order
// index, then advance the shared counter (kept identical to add()'s bump so
// offset-less nodes don't desync the index).
void JSONWriter::add_off(AstValue v, uint32_t off) {
    if (v.is_null()) return;
    if (off != UINT32_MAX) ast_pc_map_.emplace_back(ast_seq_, off);
    context_.back().at(2).push_back(std::move(v));
    ++ast_seq_;
}

// D-3 — offset of a condition/loop/switch header's representative ins, via the
// shared CondBlock::repr_ins dispatch. UINT32_MAX when no offset-bearing ins.
uint32_t JSONWriter::CondReprOff(CondBlock* node) {
    const IRForm* ir = node ? node->repr_ins() : nullptr;
    return ir ? ir->source_byte_off : UINT32_MAX;
}

// DAD's `with self as scope:` — push a fresh BlockStatement, run body, pop it.
template <class F>
AstValue JSONWriter::scope(F&& body) {
    context_.push_back(StatementBlockNode());
    body();
    AstValue b = std::move(context_.back());
    context_.pop_back();
    return b;
}

AstValue JSONWriter::statement_block() { return StatementBlockNode(); }

// DAD: dast.py:63 get_ast.
AstValue JSONWriter::get_ast() {
    const MethodMeta& m = snap_->meta;

    // flags = access; constructor pulled out into the constructor_ flag.
    std::vector<std::string> flags;
    constructor_ = false;
    for (const auto& a : m.access) {
        if (a == "constructor") { constructor_ = true; continue; }
        flags.push_back(a);
    }

    // params = lparams[:]; if not static: drop the receiver register.
    bool is_static = false;
    for (const auto& a : m.access) if (a == "static") is_static = true;
    std::vector<int> params(m.lparams.begin(), m.lparams.end());
    if (!is_static && !params.empty()) params.erase(params.begin());
    // DAD doesn't create params for abstract/native methods.
    if (params.size() != m.params_type.size()) {
        params.clear();
        for (size_t i = 0; i < m.params_type.size(); ++i)
            params.push_back(static_cast<int>(i));
    }

    std::vector<AstValue> paramdecls;
    for (size_t i = 0; i < m.params_type.size(); ++i) {
        AstValue t = ParseDescriptor(m.params_type[i]);
        AstValue v = Local("p" + std::to_string(params[i]));
        paramdecls.push_back(VarDecl(std::move(t), std::move(v)));
    }

    AstValue body = AstValue::Null();
    if (graph_ && graph_->entry) {
        body = scope([&] { visit_node(graph_->entry); });
    }

    AstValue out = AstValue::Obj();
    out.set("triple", TripleAV(m.triple));
    std::vector<AstValue> flagv;
    for (auto& f : flags) flagv.push_back(AstValue::Str(f));
    out.set("flags", AstValue::Arr(std::move(flagv)));
    out.set("ret", ParseDescriptor(m.ret_type));
    out.set("params", AstValue::Arr(std::move(paramdecls)));
    out.set("comments", AstValue::Arr());
    out.set("body", std::move(body));
    return out;
}

// DAD: dast.py:101 _visit_condition.
AstValue JSONWriter::visit_condition(Condition& cond) {
    if (cond.isnot && cond.cond1) cond.cond1->neg();
    AstValue left = Parenthesis(get_cond_operand(cond.cond1.get()));
    AstValue right = Parenthesis(get_cond_operand(cond.cond2.get()));
    std::string op = cond.isand ? "&&" : "||";
    return BinaryInfix(op, std::move(left), std::move(right));
}

// DAD: dast.py:110 get_cond(node).
AstValue JSONWriter::get_cond_block(CondBlock* node) {
    if (auto* sc = dynamic_cast<ShortCircuitBlock*>(node)) {
        return visit_condition(*sc->cond);
    }
    if (auto* lp = dynamic_cast<LoopBlock*>(node)) {
        if (lp->cond) return visit_condition(*lp->cond);
        if (lp->cond_block) return get_cond_block(lp->cond_block);
        return AstValue::Null();
    }
    // plain CondBlock: assert len(ins) == 1; visit_expr(ins[-1]).
    if (node && !node->get_ins().empty())
        return visit_expr(node->get_ins().back().get());
    return AstValue::Null();
}

// In our port a Condition's operands are wrapped (CondBlockOperand /
// ConditionOperand) instead of being raw nodes like in DAD. Dispatch to the
// underlying node/condition so get_cond behaves like DAD's get_cond(cond.condN).
AstValue JSONWriter::get_cond_operand(Condition::Operand* op) {
    if (auto* cbo = dynamic_cast<CondBlockOperand*>(op)) {
        return get_cond_block(cbo->block());
    }
    if (auto* co = dynamic_cast<ConditionOperand*>(op)) {
        if (co->cond()) return visit_condition(*co->cond());
    }
    return AstValue::Null();
}

// DAD: dast.py:120 visit_node.
void JSONWriter::visit_node(NodeBase* node) {
    if (!node) return;
    // Stack-overflow guard: this AST emit walk recurses like the text Writer's
    // VisitNode (see the note there). Cap the depth and throw so ProcessAst's
    // catch turns a pathologically deep CFG into an empty/failed AST, not a SIGSEGV.
    struct DepthGuard {
        int& d;
        explicit DepthGuard(int& x) : d(x) { ++d; }
        ~DepthGuard() { --d; }
    } depth_guard(depth_);
    if (depth_ > 2000) {
        throw std::runtime_error("decompile: AST emit recursion too deep");
    }
    if (node == if_follow_.back() || node == switch_follow_.back() ||
        node == loop_follow_.back() || node == latch_node_.back() ||
        node == try_follow_.back())
        return;
    auto* nn = dynamic_cast<Node*>(node);
    bool is_return = nn && nn->type.is_return();
    if (!is_return && visited_nodes_.count(node)) return;
    visited_nodes_.insert(node);

    if (auto* bb = dynamic_cast<BasicBlock*>(node)) {
        for (const auto& var : bb->var_to_declare) {
            auto* v = dynamic_cast<Variable*>(var.get());
            if (v && !v->declared) add(visit_decl(v));
            if (v) v->declared = true;
        }
    }

    // node.visit(self) — dispatch by concrete block type (LoopBlock before
    // CondBlock since LoopBlock IS-A CondBlock).
    if (auto* x = dynamic_cast<StatementBlock*>(node)) { visit_statement_node(x); return; }
    if (auto* x = dynamic_cast<ReturnBlock*>(node))    { visit_return_node(x); return; }
    if (auto* x = dynamic_cast<ThrowBlock*>(node))     { visit_throw_node(x); return; }
    if (auto* x = dynamic_cast<LoopBlock*>(node))      { visit_loop_node(x); return; }
    if (auto* x = dynamic_cast<CondBlock*>(node))      { visit_cond_node(x); return; }
    if (auto* x = dynamic_cast<SwitchBlock*>(node))    { visit_switch_node(x); return; }
    if (auto* x = dynamic_cast<TryBlock*>(node))       { visit_try_node(x); return; }
}

// DAD: dast.py:138 visit_loop_node.
void JSONWriter::visit_loop_node(LoopBlock* loop) {
    bool isDo = false;
    AstValue cond_expr = AstValue::Null();
    NodeBase* follow = nullptr;
    auto fit = loop->follow.find("loop");
    if (fit != loop->follow.end()) follow = fit->second;

    if (loop->looptype.is_pretest()) {
        if (loop->true_branch == follow) {
            loop->neg();
            std::swap(loop->true_branch, loop->false_branch);
        }
        isDo = false;
        cond_expr = get_cond_block(loop);
    } else if (loop->looptype.is_posttest()) {
        isDo = true;
        latch_node_.push_back(loop->latch);
    } else if (loop->looptype.is_endless()) {
        isDo = false;
        cond_expr = LiteralBool(true);
    }

    AstValue body = scope([&] {
        loop_follow_.push_back(follow);
        if (loop->looptype.is_pretest()) {
            visit_node(loop->true_branch);
        } else {
            // DAD: visit_node(loop.cond) — wrapped header (any block type).
            if (loop->cond_node) visit_node(loop->cond_node);
        }
        loop_follow_.pop_back();

        if (loop->looptype.is_pretest()) {
            // nothing
        } else if (loop->looptype.is_posttest()) {
            latch_node_.pop_back();
            if (auto* lc = dynamic_cast<CondBlock*>(loop->latch))
                cond_expr = get_cond_block(lc);
        } else {
            visit_node(loop->latch);
        }
    });

    // D-3 — pretest header ↔ loop cond offset; posttest ↔ latch offset;
    // endless (while(true)) has no source op.
    uint32_t loop_off = UINT32_MAX;
    if (loop->looptype.is_pretest()) {
        loop_off = CondReprOff(loop);
    } else if (loop->looptype.is_posttest()) {
        if (auto* lc = dynamic_cast<CondBlock*>(loop->latch))
            loop_off = CondReprOff(lc);
    }
    add_off(LoopStmt(isDo, std::move(cond_expr), std::move(body)), loop_off);
    if (follow) visit_node(follow);
}

// DAD: dast.py:178 visit_cond_node.
void JSONWriter::visit_cond_node(CondBlock* cond) {
    std::vector<AstValue> scopes;
    NodeBase* follow = nullptr;
    auto fit = cond->follow.find("if");
    if (fit != cond->follow.end()) follow = fit->second;

    if (cond->false_branch == cond->true_branch) {
        add_off(ExpressionStmt(get_cond_block(cond)), CondReprOff(cond));  // D-3
        visit_node(cond->true_branch);
        return;
    }

    if (cond->false_branch == loop_follow_.back()) {
        cond->neg();
        std::swap(cond->true_branch, cond->false_branch);
    }

    NodeBase* lf = loop_follow_.back();
    if (lf != nullptr && (lf == cond->true_branch || lf == cond->false_branch)) {
        AstValue cond_expr = get_cond_block(cond);
        scopes.push_back(scope([&] { add(JumpStmt("break")); }));
        scopes.push_back(scope([&] { visit_node(cond->false_branch); }));
        add_off(IfStmt(std::move(cond_expr), std::move(scopes)),
                CondReprOff(cond));  // D-3
    } else if (follow != nullptr) {
        bool true_is_follow_or_next =
            cond->true_branch == follow || cond->true_branch == next_case_;
        bool backward = cond->true_branch && cond->num > cond->true_branch->num;
        if (true_is_follow_or_next || backward) {
            cond->neg();
            std::swap(cond->true_branch, cond->false_branch);
        }
        if_follow_.push_back(follow);
        AstValue cond_expr = AstValue::Null();
        if (cond->true_branch) {
            cond_expr = get_cond_block(cond);
            scopes.push_back(scope([&] { visit_node(cond->true_branch); }));
        }
        bool is_else = !(follow == cond->true_branch || follow == cond->false_branch);
        if (is_else && !visited_nodes_.count(cond->false_branch)) {
            scopes.push_back(scope([&] { visit_node(cond->false_branch); }));
        }
        if_follow_.pop_back();
        add_off(IfStmt(std::move(cond_expr), std::move(scopes)),
                CondReprOff(cond));  // D-3
        visit_node(follow);
    } else {
        AstValue cond_expr = get_cond_block(cond);
        scopes.push_back(scope([&] { visit_node(cond->true_branch); }));
        scopes.push_back(scope([&] { visit_node(cond->false_branch); }));
        add_off(IfStmt(std::move(cond_expr), std::move(scopes)),
                CondReprOff(cond));  // D-3
    }
}

// DAD: dast.py:238 visit_switch_node.
void JSONWriter::visit_switch_node(SwitchBlock* sw) {
    auto lins = sw->get_ins();
    for (size_t i = 0; i + 1 < lins.size(); ++i) visit_ins(lins[i]);
    AstValue cond_expr = AstValue::Null();
    if (!lins.empty()) cond_expr = visit_expr(lins.back().get());
    std::vector<AstValue> ksv_pairs;

    NodeBase* follow = nullptr;
    auto sit = sw->follow.find("switch");
    if (sit != sw->follow.end()) follow = sit->second;
    switch_follow_.push_back(follow);
    NodeBase* default_node = sw->default_case;
    const auto& cases = sw->cases;
    for (size_t i = 0; i < cases.size(); ++i) {
        NodeBase* node = cases[i];
        if (visited_nodes_.count(node)) continue;

        std::vector<AstValue> cur_ks;
        auto kit = sw->node_to_case.find(node);
        if (kit != sw->node_to_case.end())
            for (int64_t k : kit->second) cur_ks.push_back(AstValue::Int(k));

        next_case_ = (i + 1 < cases.size()) ? cases[i + 1] : nullptr;

        if (node == default_node) {
            cur_ks.push_back(AstValue::Null());
            default_node = nullptr;
        }

        AstValue body = scope([&] {
            visit_node(node);
            if (need_break_) add(JumpStmt("break"));
            else need_break_ = true;
        });
        ksv_pairs.push_back(AstValue::Arr({AstValue::Arr(std::move(cur_ks)),
                                           std::move(body)}));
    }

    if (default_node != nullptr && default_node != follow) {
        AstValue body = scope([&] { visit_node(default_node); });
        ksv_pairs.push_back(AstValue::Arr({AstValue::Arr({AstValue::Null()}),
                                           std::move(body)}));
    }

    add_off(SwitchStmt(std::move(cond_expr), std::move(ksv_pairs)),
            lins.empty() ? UINT32_MAX : lins.back()->source_byte_off);  // D-3
    switch_follow_.pop_back();
    visit_node(follow);
}

// DAD: dast.py:282 visit_statement_node.
void JSONWriter::visit_statement_node(StatementBlock* stmt) {
    auto sucs = graph_->sucs(stmt);
    for (const auto& ins : stmt->get_ins()) visit_ins(ins);
    if (sucs.size() == 1) {
        if (sucs[0] == loop_follow_.back()) add(JumpStmt("break"));
        else if (sucs[0] == next_case_) need_break_ = false;
        else visit_node(sucs[0]);
    }
}

// DAD: dast.py:294 visit_try_node.
void JSONWriter::visit_try_node(TryBlock* tb) {
    AstValue tryb = scope([&] {
        try_follow_.push_back(tb->try_follow);
        visit_node(tb->try_start);
    });
    // DAD does NOT pop try_follow until the end (see dast.py:321). Mirror by
    // popping after the catch loop below.

    std::vector<AstValue> pairs;
    for (NodeBase* catch_n : tb->catch_nodes) {
        auto* cb = dynamic_cast<CatchBlock*>(catch_n);
        if (!cb) continue;
        AstValue catch_decl;
        if (cb->exception_ins) {
            auto* var = dynamic_cast<Variable*>(
                MapGet(cb->exception_ins.get(),
                       cb->exception_ins->ref_id()));
            std::string ctype;
            std::string name = "_";
            if (var) {
                var->declared = true;
                ctype = var->get_type();
                name = VarLocalName(var->name);
            }
            if (ctype.empty()) ctype = cb->exception_ins->get_type();
            catch_decl = VarDecl(ParseDescriptor(ctype), Local(name));
        } else {
            std::string ctype = cb->catch_type.empty()
                ? std::string("Ljava/lang/Throwable;") : cb->catch_type;
            catch_decl = VarDecl(ParseDescriptor(ctype), Local("_"));
        }
        AstValue body = scope([&] { visit_node(cb->catch_start); });
        pairs.push_back(AstValue::Arr({std::move(catch_decl), std::move(body)}));
    }

    add(TryStmt(std::move(tryb), std::move(pairs)));
    NodeBase* tf = try_follow_.back();
    try_follow_.pop_back();
    visit_node(tf);
}

// DAD: dast.py:323 visit_return_node.
void JSONWriter::visit_return_node(ReturnBlock* ret) {
    need_break_ = false;
    for (const auto& ins : ret->get_ins()) visit_ins(ins);
}

// DAD: dast.py:328 visit_throw_node.
void JSONWriter::visit_throw_node(ThrowBlock* thr) {
    for (const auto& ins : thr->get_ins()) visit_ins(ins);
}

// DAD: dast.py:59 visit_ins.
void JSONWriter::visit_ins(const IRFormPtr& op) {
    if (!op) return;
    add_off(ins_to_stmt(op.get(), constructor_), op->source_byte_off);  // D-3
}

// DAD: dast.py:332 _visit_ins.
AstValue JSONWriter::ins_to_stmt(IRForm* op, bool is_ctor) {
    if (auto* r = dynamic_cast<ReturnInstruction*>(op)) {
        AstValue expr = AstValue::Null();
        if (r->arg()) {
            if (auto* a = MapGet(r, *r->arg())) {
                // Beyond-DAD: mirror writer.cpp visit_return so the AST agrees
                // with the text path. A const* return value is integer-typed;
                // the declared return type is the truth. Emit the type-correct
                // Literal (Z→bool, reference→null, F/D→IEEE literal), gated on a
                // genuine integer constant so const-class / const-string (typed
                // references whose get_int_value() is 0) are NOT nulled.
                auto* c = dynamic_cast<Constant*>(a);
                auto is_int_const = [](const std::string& ct) {
                    return ct == "I" || ct == "J" || ct == "B" || ct == "S" ||
                           ct == "C" || ct == "Z";
                };
                const std::string& rt = snap_->meta.ret_type;
                if (c && c->is_const() && !rt.empty() &&
                    is_int_const(c->get_type())) {
                    const int64_t iv = c->get_int_value();
                    if (rt == "Z" && (iv == 0 || iv == 1)) {
                        expr = LiteralBool(iv != 0);
                    } else if ((rt.front() == 'L' || rt.front() == '[') &&
                               iv == 0) {
                        expr = LiteralNull();
                    } else if (rt == "F") {
                        const uint32_t bits = static_cast<uint32_t>(iv);
                        float f;
                        std::memcpy(&f, &bits, sizeof(f));
                        expr = LiteralFloatChecked(f);
                    } else if (rt == "D") {
                        const uint64_t bits = static_cast<uint64_t>(iv);
                        double d;
                        std::memcpy(&d, &bits, sizeof(d));
                        expr = LiteralDoubleChecked(d);
                    } else {
                        expr = visit_expr(a);
                    }
                } else {
                    expr = visit_expr(a);
                }
            }
        }
        return ReturnStmt(std::move(expr));
    }
    if (auto* t = dynamic_cast<ThrowExpression*>(op)) {
        return ThrowStmt(visit_expr(MapGet(t, t->ref_id())));
    }
    if (dynamic_cast<NopExpression*>(op)) return AstValue::Null();

    // Local var decl statements (Assign / Move / MoveResult with fresh lhs).
    bool is_assign = dynamic_cast<AssignExpression*>(op);
    bool is_move = dynamic_cast<MoveExpression*>(op);  // also MoveResult
    if (is_assign || is_move) {
        auto lhs_id = op->GetLhsId();
        IRForm* lhs = lhs_id ? MapGet(op, *lhs_id) : nullptr;
        IRForm* rhs;
        if (auto* ae = dynamic_cast<AssignExpression*>(op)) {
            rhs = ae->rhs().get();
        } else {
            auto* me = static_cast<MoveExpression*>(op);
            rhs = MapGet(op, me->rhs_id());
        }
        if (auto* lv = dynamic_cast<Variable*>(lhs)) {
            if (!lv->declared) {
                lv->declared = true;
                AstValue expr = visit_expr(rhs);
                return visit_decl(lv, std::move(expr));
            }
        }
    }

    // Skip this() at top of constructors.
    if (is_ctor && is_assign) {
        auto* ae = static_cast<AssignExpression*>(op);
        if (!ae->lhs()) {
            if (auto* inv = dynamic_cast<InvokeInstruction*>(ae->rhs().get())) {
                if (inv->name() == "<init>" && inv->args().empty()) {
                    if (dynamic_cast<ThisParam*>(MapGet(inv, inv->base())))
                        return AstValue::Null();
                }
            }
        }
    }

    // MoveExpression skipped when lhs aliases rhs.
    if (auto* me = dynamic_cast<MoveExpression*>(op)) {
        if (MapGet(op, me->lhs_id()) == MapGet(op, me->rhs_id()))
            return AstValue::Null();
    }

    return ExpressionStmt(visit_expr(op));
}

// DAD: dast.py:382 write_inplace_if_possible.
AstValue JSONWriter::write_inplace_if_possible(IRForm* lhs, IRForm* rhs) {
    if (auto* bin = dynamic_cast<BinaryExpression*>(rhs)) {
        IRForm* arg1 = MapGet(bin, bin->arg1_id());
        if (lhs == arg1) {
            IRForm* exp_rhs = MapGet(bin, bin->arg2_id());
            auto* cst = dynamic_cast<Constant*>(exp_rhs);
            const std::string& bop = bin->op();
            if ((bop == "+" || bop == "-") && cst && cst->get_int_value() == 1) {
                return UnaryPostfix(visit_expr(lhs), bop + bop);
            }
            return Assignment(visit_expr(lhs),
                              visit_expr_fp_typed(exp_rhs, bin->get_type()), bop);
        }
    }
    // Beyond-DAD: an integer Constant 0 assigned to a REFERENCE lhs is the null
    // reference — emit a null literal (mirrors writer.cpp write_inplace and the
    // return-literal null fix; AST and text agree).
    if (lhs) {
        auto is_int_const = [](const std::string& ct) {
            return ct == "I" || ct == "J" || ct == "B" || ct == "S" ||
                   ct == "C" || ct == "Z";
        };
        const std::string lt = lhs->get_type();
        if (auto* c = dynamic_cast<Constant*>(rhs);
            c && c->is_const() && is_int_const(c->get_type()) &&
            c->get_int_value() == 0 && !lt.empty() &&
            (lt.front() == 'L' || lt.front() == '[')) {
            return Assignment(visit_expr(lhs), LiteralNull());
        }
    }
    // plain assignment: `double v = <raw-bits int const>` → reinterpret the rhs
    // const against the lhs F/D type (mirrors writer.cpp write_ind_visit_end).
    return Assignment(visit_expr(lhs),
                      visit_expr_fp_typed(rhs, lhs ? lhs->get_type()
                                                   : std::string_view()));
}

AstValue JSONWriter::visit_expr_fp_typed(IRForm* operand,
                                         std::string_view target) {
    if (operand && (target == "F" || target == "D")) {
        if (auto* c = dynamic_cast<Constant*>(operand); c && c->is_const()) {
            const std::string ct = c->get_type();
            if (ct == "I" || ct == "J" || ct == "B" || ct == "S" || ct == "C") {
                const int64_t iv = c->get_int_value();
                if (target == "F") {
                    const uint32_t bits = static_cast<uint32_t>(iv);
                    float f; std::memcpy(&f, &bits, sizeof(f));
                    return LiteralFloatChecked(f);
                }
                const uint64_t bits = static_cast<uint64_t>(iv);
                double d; std::memcpy(&d, &bits, sizeof(d));
                return LiteralDoubleChecked(d);
            }
        }
    }
    return visit_expr(operand);
}

// DAD: dast.py:401 visit_expr.
AstValue JSONWriter::visit_expr(IRForm* op) {
    if (!op) return Dummy({AstValue::Str("??? Unexpected op: null")});

    if (auto* x = dynamic_cast<ArrayLengthExpression*>(op)) {
        AstValue expr = visit_expr(MapGet(x, x->array_id()));
        AstValue triple = AstValue::Arr({AstValue::Null(),
                                         AstValue::Str("length"),
                                         AstValue::Null()});
        return FieldAccess(std::move(triple), std::move(expr));
    }
    if (auto* x = dynamic_cast<ArrayLoadExpression*>(op)) {
        return ArrayAccess(visit_expr(MapGet(x, x->array_id())),
                           visit_expr(MapGet(x, x->idx_id())));
    }
    if (auto* x = dynamic_cast<ArrayStoreInstruction*>(op)) {
        IRForm* array = MapGet(x, x->array_id());
        AstValue arr = ArrayAccess(visit_expr(array),
                                   visit_expr(MapGet(x, x->index_id())));
        const std::string at = array ? array->get_type() : std::string();
        const std::string_view comp =
            (at.size() >= 2 && at[0] == '[') ? std::string_view(at).substr(1)
                                             : std::string_view();
        return Assignment(std::move(arr),
                          visit_expr_fp_typed(MapGet(x, x->rhs_id()), comp));
    }
    if (auto* x = dynamic_cast<AssignExpression*>(op)) {
        auto lhs_id = x->GetLhsId();
        IRForm* lhs = lhs_id ? MapGet(x, *lhs_id) : nullptr;
        if (!lhs) return visit_expr(x->rhs().get());
        return write_inplace_if_possible(lhs, x->rhs().get());
    }
    if (auto* x = dynamic_cast<BaseClass*>(op)) {
        if (x->clsdesc().empty()) return Local(x->cls());  // "super"
        return ParseDescriptor(x->clsdesc());
    }
    if (auto* x = dynamic_cast<BinaryExpression*>(op)) {
        // the expression's own type ("D"/"F") is the reliable F/D context for a
        // raw-bits int-const operand (mirrors writer.cpp visit_binary_expression).
        const std::string et = x->get_type();
        IRForm* a1 = MapGet(x, x->arg1_id());
        IRForm* a2 = MapGet(x, x->arg2_id());
        AstValue expr = BinaryInfix(x->op(), visit_expr_fp_typed(a1, et),
                                    visit_expr_fp_typed(a2, et));
        if (!dynamic_cast<BinaryCompExpression*>(op)) expr = Parenthesis(std::move(expr));
        return expr;
    }
    if (auto* x = dynamic_cast<CheckCastExpression*>(op)) {
        return Parenthesis(Cast(ParseDescriptor(x->clsdesc()),
                                visit_expr(MapGet(x, x->arg_id()))));
    }
    if (auto* x = dynamic_cast<ConditionalExpression*>(op)) {
        const std::string et = x->get_type();
        IRForm* a1 = MapGet(x, x->arg1_id());
        IRForm* a2 = MapGet(x, x->arg2_id());
        return BinaryInfix(x->op(), visit_expr_fp_typed(a1, et),
                           visit_expr_fp_typed(a2, et));
    }
    if (auto* x = dynamic_cast<ConditionalZExpression*>(op)) {
        IRForm* arg = MapGet(x, x->arg_id());
        if (auto* bce = dynamic_cast<BinaryCompExpression*>(arg)) {
            bce->set_op(x->op());
            return visit_expr(arg);
        }
        AstValue expr = visit_expr(arg);
        std::string atype = arg ? arg->get_type() : std::string();
        if (atype == "Z") {
            if (x->op() == Op::EQUAL) expr = UnaryPrefix("!", std::move(expr));
        } else if (!atype.empty() &&
                   std::string("VBSCIJFD").find(atype[0]) != std::string::npos) {
            expr = BinaryInfix(x->op(), std::move(expr), LiteralInt(0));
        } else {
            expr = BinaryInfix(x->op(), std::move(expr), LiteralNull());
        }
        return expr;
    }
    if (auto* x = dynamic_cast<Constant*>(op)) {
        const std::string& t = x->type;
        if (t == "Ljava/lang/String;") {
            const auto* s = std::get_if<std::string>(&x->cst());
            return LiteralString(s ? *s : std::string());
        }
        if (t == "Z") return LiteralBool(x->get_int_value() == 0);
        if (t.size() == 1 && std::string("ISCB").find(t[0]) != std::string::npos)
            return LiteralInt(x->cst2());
        if (t == "J") return LiteralLong(x->cst2());
        if (t == "F") {
            const auto* d = std::get_if<double>(&x->cst());
            return LiteralFloat(d ? *d : 0.0);
        }
        if (t == "D") {
            const auto* d = std::get_if<double>(&x->cst());
            return LiteralDouble(d ? *d : 0.0);
        }
        if (t == "Ljava/lang/Class;") return LiteralClass(x->clsdesc());
        return Dummy({AstValue::Str("??? Unexpected constant: " + t)});
    }
    if (auto* x = dynamic_cast<FillArrayExpression*>(op)) {
        AstValue arr = visit_expr(MapGet(x, x->reg_id()));
        return Assignment(std::move(arr), visit_arr_data(x->value()));
    }
    if (auto* x = dynamic_cast<FilledArrayExpression*>(op)) {
        AstValue tn = ParseDescriptor(x->type);
        std::vector<AstValue> params;
        for (const auto& a : x->args()) params.push_back(visit_expr(MapGet(x, a)));
        return ArrayInitializer(std::move(params), std::move(tn));
    }
    if (auto* x = dynamic_cast<InstanceExpression*>(op)) {
        std::array<std::string, 3> tr{StripL(x->clsdesc()), x->name(), x->ftype()};
        return FieldAccess(TripleAV(tr), visit_expr(MapGet(x, x->arg_id())));
    }
    if (auto* x = dynamic_cast<InstanceInstruction*>(op)) {
        std::array<std::string, 3> tr{StripL(x->clsdesc()), x->name(), x->atype()};
        AstValue lhs = FieldAccess(TripleAV(tr), visit_expr(MapGet(x, x->lhs_id())));
        return Assignment(std::move(lhs),
                          visit_expr_fp_typed(MapGet(x, x->rhs_id()), x->atype()));
    }
    if (auto* x = dynamic_cast<InvokeInstruction*>(op)) {
        IRForm* base = MapGet(x, x->base());
        std::vector<AstValue> params;
        const auto& argids = x->args();
        const auto& pt = x->ptype();
        for (size_t i = 0; i < argids.size(); ++i) {
            const std::string_view target =
                i < pt.size() ? std::string_view(pt[i]) : std::string_view();
            params.push_back(visit_expr_fp_typed(MapGet(x, argids[i]), target));
        }
        // DAD's op.triple comes from androguard get_triple(): triple[0] is the
        // internal class name (no L;). Our InvokeInstruction stores the raw
        // descriptor, so strip it here for parity.
        std::array<std::string, 3> tr{StripL(x->triple()[0]), x->triple()[1],
                                      x->triple()[2]};
        if (x->name() == "<init>") {
            if (auto* tp = dynamic_cast<ThisParam*>(base)) {
                std::string keyword =
                    StripL(tp->get_type()) == tr[0] ? "this" : "super";
                return MethodInvocation(TripleAV(tr), keyword,
                                        AstValue::Null(), std::move(params));
            }
            if (auto* ni = dynamic_cast<NewInstance*>(base)) {
                return AstValue::Arr({AstValue::Str("ClassInstanceCreation"),
                                      TripleAV(tr),
                                      AstValue::Arr(std::move(params)),
                                      ParseDescriptor(ni->get_type())});
            }
            // else: Variable base — fall through to dummy <init> call.
        }
        return MethodInvocation(TripleAV(tr), x->name(),
                                visit_expr(base), std::move(params));
    }
    if (auto* x = dynamic_cast<MonitorEnterExpression*>(op)) {
        return Dummy({AstValue::Str("monitor enter("),
                      visit_expr(MapGet(x, x->ref_id())), AstValue::Str(")")});
    }
    if (auto* x = dynamic_cast<MonitorExitExpression*>(op)) {
        return Dummy({AstValue::Str("monitor exit("),
                      visit_expr(MapGet(x, x->ref_id())), AstValue::Str(")")});
    }
    // MoveExpression branch catches MoveResultExpression too (DAD-faithful: the
    // isinstance(MoveExpression) check at dast.py:540 fires first, so the
    // dast.py:544 MoveResult branch is dead code).
    if (auto* x = dynamic_cast<MoveExpression*>(op)) {
        IRForm* lhs = MapGet(x, x->lhs_id());
        IRForm* rhs = MapGet(x, x->rhs_id());
        return write_inplace_if_possible(lhs, rhs);
    }
    if (auto* x = dynamic_cast<NewArrayExpression*>(op)) {
        std::string t = x->type;
        if (!t.empty()) t = t.substr(1);  // strip leading '['
        AstValue tn = ParseDescriptor(t);
        return ArrayCreation(std::move(tn), {visit_expr(MapGet(x, x->size_id()))}, 1);
    }
    if (auto* x = dynamic_cast<NewInstance*>(op)) {
        return Dummy({AstValue::Str("new "), ParseDescriptor(x->get_type())});
    }
    if (auto* x = dynamic_cast<Param*>(op)) {
        if (dynamic_cast<ThisParam*>(op)) return Local("this");
        std::string v = x->v();
        if (!v.empty() && v.front() == 'v') v = v.substr(1);
        return Local("p" + v);
    }
    if (auto* x = dynamic_cast<StaticExpression*>(op)) {
        std::array<std::string, 3> tr{StripL(x->clsdesc()), x->name(), x->ftype()};
        return FieldAccess(TripleAV(tr), ParseDescriptor(x->clsdesc()));
    }
    if (auto* x = dynamic_cast<StaticInstruction*>(op)) {
        std::array<std::string, 3> tr{StripL(x->clsdesc()), x->name(), x->ftype()};
        AstValue lhs = FieldAccess(TripleAV(tr), ParseDescriptor(x->clsdesc()));
        return Assignment(std::move(lhs),
                          visit_expr_fp_typed(MapGet(x, x->rhs_id()), x->ftype()));
    }
    if (auto* x = dynamic_cast<SwitchExpression*>(op)) {
        return visit_expr(MapGet(x, x->src_id()));
    }
    if (auto* x = dynamic_cast<UnaryExpression*>(op)) {
        IRForm* lhs = MapGet(x, x->arg_id());
        AstValue expr;
        if (auto* ce = dynamic_cast<CastExpression*>(op)) {
            expr = Cast(ParseDescriptor(ce->clsdesc()), visit_expr(lhs));
        } else {
            expr = UnaryPrefix(x->op(), visit_expr(lhs));
        }
        return Parenthesis(std::move(expr));
    }
    if (auto* x = dynamic_cast<Variable*>(op)) {
        return Local(VarLocalName(x->name));
    }
    return Dummy({AstValue::Str("??? Unexpected op")});
}

// DAD: dast.py:583 visit_arr_data — our payload is pre-decoded ints.
AstValue JSONWriter::visit_arr_data(const std::vector<int64_t>& value) {
    std::vector<AstValue> tab;
    for (int64_t x : value) tab.push_back(LiteralInt(x));
    return ArrayInitializer(std::move(tab));
}

// DAD: dast.py:595 visit_decl.
AstValue JSONWriter::visit_decl(Variable* var, AstValue init) {
    AstValue t = ParseDescriptor(var->get_type());
    AstValue v = Local(VarLocalName(var->name));
    return LocalDeclStmt(std::move(init), VarDecl(std::move(t), std::move(v)));
}

}  // namespace dexkit::dad
