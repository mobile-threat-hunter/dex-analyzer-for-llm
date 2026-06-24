// instruction.h — C++ port of androguard DAD instruction.py
// DAD: androguard/decompiler/instruction.py
//
// Module-level constants:
//   - CONDS                   — DAD instruction.py:1218 condition opcode → ('op', neg_op) table
//
// PORT STATUS (all 8 chunks ported — 41/41 IR classes + CONDS table):
//   Ported:
//     - IRForm                  — DAD instruction.py:21   base class for all IR nodes
//     - Constant                — DAD instruction.py:75   literal constant IR
//     - BaseClass               — DAD instruction.py:123  class reference IR
//     - Variable                — DAD instruction.py:140  local variable IR
//     - Param                   — DAD instruction.py:166  formal parameter IR
//     - ThisParam               — DAD instruction.py:183  receiver (this) parameter IR
//     - AssignExpression        — DAD instruction.py:198  lhs = rhs assignment IR
//     - MoveExpression          — DAD instruction.py:247  register move IR
//     - MoveResultExpression    — DAD instruction.py:303  move-result after invoke IR
//     - ArrayStoreInstruction   — DAD instruction.py:322  a[i] = v IR
//     - StaticInstruction       — DAD instruction.py:386  sput-style IR
//     - InstanceInstruction     — DAD instruction.py:432  iput-style IR
//     - NewInstance             — DAD instruction.py:495  new-instance IR
//     - InvokeInstruction       — DAD instruction.py:516  invoke-* IR
//     - InvokeRangeInstruction  — DAD instruction.py:609  invoke-*/range IR
//     - InvokeDirectInstruction — DAD instruction.py:615  invoke-direct IR
//     - InvokeStaticInstruction — DAD instruction.py:620  invoke-static IR
//     - ReturnInstruction       — DAD instruction.py:632  return-* IR
//     - NopExpression           — DAD instruction.py:677  nop IR
//     - SwitchExpression        — DAD instruction.py:691  switch IR
//     - CheckCastExpression     — DAD instruction.py:725  check-cast IR
//     - ArrayExpression         — DAD instruction.py:766  array op base IR
//     - ArrayLoadExpression     — DAD instruction.py:771  aget IR
//     - ArrayLengthExpression   — DAD instruction.py:826  array-length IR
//     - NewArrayExpression      — DAD instruction.py:862  new-array IR
//     - FilledArrayExpression   — DAD instruction.py:899  filled-new-array IR
//     - FillArrayExpression     — DAD instruction.py:956  fill-array-data IR
//     - RefExpression           — DAD instruction.py:993  reference-typed op base IR
//     - MoveExceptionExpression — DAD instruction.py:1023 move-exception IR
//     - MonitorEnterExpression  — DAD instruction.py:1050 monitor-enter IR
//     - MonitorExitExpression   — DAD instruction.py:1058 monitor-exit IR
//     - ThrowExpression         — DAD instruction.py:1066 throw IR
//     - BinaryExpression        — DAD instruction.py:1077 binary op IR
//     - BinaryCompExpression    — DAD instruction.py:1138 cmp{l,g}-* IR
//     - BinaryExpression2Addr   — DAD instruction.py:1149 *-2addr binary IR
//     - BinaryExpressionLit     — DAD instruction.py:1154 *-lit binary IR
//     - UnaryExpression         — DAD instruction.py:1159 unary op IR
//     - CastExpression          — DAD instruction.py:1197 numeric cast IR
//     - ConditionalExpression   — DAD instruction.py:1228 if-* two-reg comparison IR
//     - ConditionalZExpression  — DAD instruction.py:1292 if-*z zero-comparison IR
//     - InstanceExpression      — DAD instruction.py:1335 iget read expression IR
//     - StaticExpression        — DAD instruction.py:1378 sget read expression IR
//   Deferred: none — instruction.py port complete.
//     - ArrayStoreInstruction   — DAD instruction.py:322  a[i] = v IR
//     - StaticInstruction       — DAD instruction.py:386  sget/sput-style IR
//     - InstanceInstruction     — DAD instruction.py:432  iget/iput-style IR
//     - NewInstance             — DAD instruction.py:495  new-instance IR
//     - InvokeInstruction       — DAD instruction.py:516  invoke-* IR
//     - InvokeRangeInstruction  — DAD instruction.py:609  invoke-*/range IR
//     - InvokeDirectInstruction — DAD instruction.py:615  invoke-direct IR
//     - InvokeStaticInstruction — DAD instruction.py:620  invoke-static IR
//     - ReturnInstruction       — DAD instruction.py:632  return-* IR
//     - NopExpression           — DAD instruction.py:677  nop IR
//     - SwitchExpression        — DAD instruction.py:691  switch IR
//     - CheckCastExpression     — DAD instruction.py:725  check-cast IR
//     - ArrayExpression         — DAD instruction.py:766  array op base IR
//     - ArrayLoadExpression     — DAD instruction.py:771  aget IR
//     - ArrayLengthExpression   — DAD instruction.py:826  array-length IR
//     - NewArrayExpression      — DAD instruction.py:862  new-array IR
//     - FilledArrayExpression   — DAD instruction.py:899  filled-new-array IR
//     - FillArrayExpression     — DAD instruction.py:956  fill-array-data IR
//     - RefExpression           — DAD instruction.py:993  reference-typed op base IR
//     - MoveExceptionExpression — DAD instruction.py:1023 move-exception IR
//     - MonitorEnterExpression  — DAD instruction.py:1050 monitor-enter IR
//     - MonitorExitExpression   — DAD instruction.py:1058 monitor-exit IR
//     - ThrowExpression         — DAD instruction.py:1066 throw IR
//     - BinaryExpression        — DAD instruction.py:1077 binary op IR
//     - BinaryCompExpression    — DAD instruction.py:1138 cmp{l,g}-* IR
//     - BinaryExpression2Addr   — DAD instruction.py:1149 *-2addr binary IR
//     - BinaryExpressionLit     — DAD instruction.py:1154 *-lit binary IR
//     - UnaryExpression         — DAD instruction.py:1159 unary op IR
//     - CastExpression          — DAD instruction.py:1197 numeric cast IR
//     - ConditionalExpression   — DAD instruction.py:1228 if-* two-reg comparison IR
//     - ConditionalZExpression  — DAD instruction.py:1292 if-*z zero-comparison IR
//     - InstanceExpression      — DAD instruction.py:1335 iget read expression IR
//     - StaticExpression        — DAD instruction.py:1378 sget read expression IR

#pragma once

#include <array>
#include <cstdint>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <unordered_map>
#include <unordered_set>
#include <variant>
#include <vector>

namespace dexkit::dad {

// Forward declaration — Visitor lives in writer.h (not yet ported). For chunk 1
// Accept() is a no-op so we don't need the full interface; subsequent chunks
// will wire it up.
class Visitor;

class IRForm;
using IRFormPtr = std::shared_ptr<IRForm>;

// DAD: instruction.py:21 IRForm — base class for every IR node.
class IRForm {
public:
    virtual ~IRForm() = default;

    // DAD: instruction.py:26 is_call
    virtual bool is_call()   const noexcept { return false; }
    // DAD: instruction.py:29 is_cond
    virtual bool is_cond()   const noexcept { return false; }
    // DAD: instruction.py:32 is_const
    virtual bool is_const()  const noexcept { return false; }
    // DAD: instruction.py:35 is_ident
    virtual bool is_ident()  const noexcept { return false; }
    // DAD: instruction.py:38 is_propagable — default True; overridden by some ops.
    virtual bool is_propagable() const noexcept { return true; }

    // DAD: instruction.py:41 get_type / 44 set_type — type is Dalvik descriptor.
    virtual std::string get_type() const { return type; }
    virtual void set_type(std::string_view t) { type = std::string{t}; }

    // DAD: instruction.py:47 has_side_effect
    virtual bool has_side_effect() const noexcept { return false; }

    // DAD: instruction.py:50 get_used_vars — list of variable IDs (the `v` field).
    virtual std::vector<std::string> get_used_vars() const { return {}; }

    // DAD: instruction.py:53/56/59 replace / replace_lhs / replace_var —
    // raise NotImplementedError in DAD when not overridden. Signature follows
    // the leaf concrete impl (MoveExpression): `old` is a variable id string
    // (the .v field), `new_` is an IRForm node. Higher levels pass through.
    // We mirror Python's NotImplementedError with std::logic_error so callers
    // see a clear failure instead of a silent no-op.
    virtual void replace(const std::string& old_v, const IRFormPtr& new_node);
    virtual void replace_lhs(const IRFormPtr& new_node);
    virtual void replace_var(const std::string& old_v, const IRFormPtr& new_node);

    // DAD: instruction.py:62 remove_defined_var — default no-op.
    virtual void remove_defined_var() {}

    // DAD: instruction.py:65 get_rhs — default empty list.
    virtual std::vector<IRFormPtr> get_rhs() const { return {}; }
    // DAD: instruction.py:68 get_lhs — default null (no lhs).
    // Note: DAD returns `self.lhs` (a string id) from AssignExpression /
    // MoveExpression overrides. We model that with GetLhsId() on those
    // classes; the base class returns nullopt for "no lhs".
    virtual std::optional<std::string> GetLhsId() const { return std::nullopt; }
    // Keep the IRForm-returning variant for compositional callers that
    // expect a node-like accessor; defaults to nullptr.
    virtual IRFormPtr get_lhs() const { return nullptr; }

    // DAD: instruction.py:71 visit(visitor) — default no-op. Subclasses
    // dispatch via visitor.visit_XXX. Visitor lives in writer.h (deferred).
    virtual void Accept(Visitor& /*visitor*/) {}

    // DAD: instruction.py:1248/1313 neg — flip condition opcode in-place.
    // Default no-op; only Conditional[Z]Expression and Condition override.
    // Needed so CondBlock::neg() (DAD basic_blocks.py:152) can call
    // ins[-1]->Neg() without downcasting.
    virtual void Neg() {}

    // The .v field varies per IRForm subclass (Variable / Constant / BaseClass
    // all define it but with different conventions: 'c<val>' for Constant /
    // BaseClass, the raw register name for Variable). Polymorphic accessor so
    // AssignExpression / MoveExpression / etc. can key var_map without
    // downcasting.
    virtual std::string Vid() const { return {}; }

    // Polymorphic str()-equivalent — Variable/Constant/etc. override.
    // Used by AssignExpression / MoveExpression __str__ to format children.
    virtual std::string ToString() const { return {}; }

    // DAD: instruction.py:23 self.var_map — dict keyed by the .v field of
    // each contained IRForm. Set by AssignExpression / MoveExpression / etc.
    std::unordered_map<std::string, IRFormPtr> var_map;
    // DAD: instruction.py:24 self.type — public; subclasses write directly.
    std::string type;

    // D-3 (dexllm#1) — byte offset of the dex instruction this IR node was
    // built from. UINT32_MAX = synthesized node (loop headers, short-circuit
    // wraps, structural braces — no underlying RawIns). Stamped once at the
    // dispatch funnel (basic_blocks.cpp BuildNodeFromBlock); harvested by the
    // Writer / JSONWriter into a (line ↔ offset) pc_map. NOT a DAD concept —
    // metadata only, never read by IR transforms, so DAD output parity is
    // unaffected. Independent of RawIns::branch_target (different semantics).
    uint32_t source_byte_off = UINT32_MAX;
};

// Constant.value in Python is dynamically typed; can be int, float, or
// string. C++ replicates via variant. The display form is built via std::to_string
// for numerics; strings pass through.
using ConstantValue = std::variant<int64_t, double, std::string>;

// DAD: instruction.py:75 Constant — literal constant IR.
class Constant : public IRForm {
public:
    // DAD: instruction.py:76 __init__(value, atype, int_value=None, descriptor=None)
    Constant(ConstantValue value,
             std::string_view atype,
             std::optional<int64_t> int_value = std::nullopt,
             std::string_view descriptor = {});

    // DAD: instruction.py:94 get_used_vars — empty (constants reference no vars).
    std::vector<std::string> get_used_vars() const override { return {}; }
    // DAD: instruction.py:97 is_const → true
    bool is_const() const noexcept override { return true; }
    // DAD: instruction.py:100 get_int_value → self.cst2
    int64_t get_int_value() const noexcept { return cst2_; }
    // DAD: instruction.py:103 get_type → self.type (inherited behaviour is identical)
    std::string get_type() const override { return type; }

    // DAD: instruction.py:106 visit — deferred until writer.py ports.
    // (no-op for now; chunk handling Visitor will fill in)

    // DAD: instruction.py:119 __str__ → 'CST_<repr(cst)>'
    std::string ToString() const override;

    // Accessors for parity testing.
    const ConstantValue& cst() const noexcept { return cst_; }
    int64_t cst2() const noexcept { return cst2_; }
    const std::string& v() const noexcept { return v_; }
    std::string Vid() const override { return v_; }
    const std::string& clsdesc() const noexcept { return clsdesc_; }

private:
    std::string v_;          // DAD: 'c%s' % value
    ConstantValue cst_;      // raw value
    int64_t cst2_ = 0;       // int_value if given, else int(value) if numeric
    std::string clsdesc_;
    void Accept(Visitor& v) override;
};

// DAD: instruction.py:123 BaseClass — class reference IR.
class BaseClass : public IRForm {
public:
    // DAD: instruction.py:124 __init__(name, descriptor=None)
    BaseClass(std::string_view name, std::string_view descriptor = {});

    // DAD: instruction.py:130 is_const → true
    bool is_const() const noexcept override { return true; }

    // DAD: instruction.py:136 __str__ → 'BASECLASS_<cls>'
    std::string ToString() const override;

    const std::string& cls() const noexcept { return cls_; }
    const std::string& v() const noexcept { return v_; }
    std::string Vid() const override { return v_; }
    const std::string& clsdesc() const noexcept { return clsdesc_; }

private:
    std::string v_;       // DAD: 'c%s' % name
    std::string cls_;
    std::string clsdesc_;
    void Accept(Visitor& v) override;
};

// DAD: instruction.py:140 Variable — local variable IR.
class Variable : public IRForm {
public:
    // DAD: instruction.py:141 __init__(value)
    explicit Variable(std::string_view value);

    // DAD: instruction.py:147 get_used_vars → [self.v]
    std::vector<std::string> get_used_vars() const override { return {v_}; }
    // DAD: instruction.py:150 is_ident → true
    bool is_ident() const noexcept override { return true; }

    // DAD: instruction.py:153 value() → self.v
    const std::string& value() const noexcept { return v_; }

    // DAD: instruction.py:162 __str__ → 'VAR_<name>'
    std::string ToString() const override;

    // Public-ish state (matches Python free attribute access).
    bool declared = false;
    std::string name;  // DAD: same as v at construction

    const std::string& v() const noexcept { return v_; }
    std::string Vid() const override { return v_; }

protected:
    std::string v_;
    void Accept(Visitor& v) override;
};

// DAD: instruction.py:166 Param — formal parameter IR (Variable subclass).
class Param : public Variable {
public:
    // DAD: instruction.py:167 __init__(value, atype) — declared=True, type=atype, this=False
    Param(std::string_view value, std::string_view atype);

    // DAD: instruction.py:173 is_const → true (Param is propagation-safe)
    bool is_const() const noexcept override { return true; }

    // DAD: instruction.py:179 __str__ → 'PARAM_<name>'
    std::string ToString() const override;

    // DAD: instruction.py:171 self.this — false in Param, true in ThisParam.
    bool this_flag = false;
    void Accept(Visitor& v) override;
};

// DAD: instruction.py:183 ThisParam — receiver parameter IR (Param subclass).
class ThisParam : public Param {
public:
    // DAD: instruction.py:184 __init__(value, atype) — this=True, super=False
    ThisParam(std::string_view value, std::string_view atype);

    // DAD: instruction.py:194 __str__ → 'THIS'
    std::string ToString() const override;

    // DAD: instruction.py:187 self.super — toggled by callers when emitting super().
    bool super_flag = false;
    void Accept(Visitor& v) override;
};

// DAD: instruction.py:198 AssignExpression — `lhs = rhs` assignment IR.
// DAD: instruction.py:199 __init__(lhs, rhs):
//   - If lhs is given: stash lhs.v as self.lhs, register lhs in var_map,
//     and propagate rhs.get_type() into lhs (lhs.set_type).
//   - rhs is stored directly (IRForm reference, NOT keyed via var_map).
class AssignExpression : public IRForm {
public:
    // `lhs` may be null (DAD's `if lhs:` branch) for void-result calls etc.
    AssignExpression(IRFormPtr lhs, IRFormPtr rhs);

    // DAD: instruction.py:209 is_propagable → rhs.is_propagable()
    bool is_propagable() const noexcept override;
    // DAD: instruction.py:212 is_call → rhs.is_call()
    bool is_call() const noexcept override;
    // DAD: instruction.py:215 has_side_effect → rhs.has_side_effect()
    bool has_side_effect() const noexcept override;

    // DAD: instruction.py:218 get_rhs → self.rhs (single IRForm, returned as
    // a one-element list to match the base IRForm::get_rhs() signature).
    std::vector<IRFormPtr> get_rhs() const override;
    // DAD: instruction.py:221 get_lhs → self.lhs (string id, may be missing).
    std::optional<std::string> GetLhsId() const override;

    // DAD: instruction.py:224 get_used_vars → rhs.get_used_vars()
    std::vector<std::string> get_used_vars() const override;

    // DAD: instruction.py:227 remove_defined_var → self.lhs = None
    void remove_defined_var() override;

    // DAD: instruction.py:230 replace → rhs.replace(old, new)
    void replace(const std::string& old_v, const IRFormPtr& new_node) override;
    // DAD: instruction.py:233 replace_lhs → self.lhs = new.v; var_map[new.v] = new
    void replace_lhs(const IRFormPtr& new_node) override;
    // DAD: instruction.py:237 replace_var → rhs.replace_var(old, new)
    void replace_var(const std::string& old_v, const IRFormPtr& new_node) override;

    // DAD: instruction.py:243 __str__ → 'ASSIGN(<var_map[lhs]>, <rhs>)'
    std::string ToString() const override;

    // Accessors for parity testing / downstream callers.
    const IRFormPtr& rhs() const noexcept { return rhs_; }
    const std::optional<std::string>& lhs() const noexcept { return lhs_; }

private:
    std::optional<std::string> lhs_;   // .v of the lhs Variable, or unset
    IRFormPtr rhs_;
    void Accept(Visitor& v) override;
};

// DAD: instruction.py:247 MoveExpression — register-to-register move IR.
// DAD: instruction.py:248 __init__(lhs, rhs):
//   - lhs/rhs are both Variable-like IRForms.
//   - self.lhs = lhs.v (string id), self.rhs = rhs.v (string id).
//   - var_map carries BOTH ends, looked up on demand.
class MoveExpression : public IRForm {
public:
    MoveExpression(IRFormPtr lhs, IRFormPtr rhs);

    // DAD: instruction.py:255 has_side_effect → False (explicit override).
    bool has_side_effect() const noexcept override { return false; }
    // DAD: instruction.py:258 is_call → var_map[rhs].is_call()
    bool is_call() const noexcept override;

    // DAD: instruction.py:261 get_used_vars → var_map[rhs].get_used_vars()
    std::vector<std::string> get_used_vars() const override;

    // DAD: instruction.py:264 get_rhs → var_map[rhs]  (one IRForm wrapped)
    std::vector<IRFormPtr> get_rhs() const override;
    // DAD: instruction.py:267 get_lhs → self.lhs (string id)
    std::optional<std::string> GetLhsId() const override;

    // DAD: instruction.py:274 replace — context-sensitive: if current rhs is
    // a non-trivial expression, recurse; otherwise rewrite var_map directly.
    void replace(const std::string& old_v, const IRFormPtr& new_node) override;
    // DAD: instruction.py:286 replace_lhs — drop old lhs key (unless aliased
    // to rhs), then install new.
    void replace_lhs(const IRFormPtr& new_node) override;
    // DAD: instruction.py:292 replace_var — drop old rhs key (unless aliased
    // to lhs), then install new.
    void replace_var(const std::string& old_v, const IRFormPtr& new_node) override;

    // DAD: instruction.py:298 __str__ → '<var_map[lhs]> = <var_map[rhs]>'
    std::string ToString() const override;

    const std::string& lhs_id() const noexcept { return lhs_; }
    const std::string& rhs_id() const noexcept { return rhs_; }

protected:
    std::string lhs_;
    std::string rhs_;
    void Accept(Visitor& v) override;
};

// DAD: instruction.py:303 MoveResultExpression — move-result after invoke IR.
// Inherits everything from MoveExpression; overrides is_propagable +
// has_side_effect to defer to the rhs (since the rhs is typically an Invoke
// expression which has its own propagability/side-effect characteristics).
class MoveResultExpression : public MoveExpression {
public:
    MoveResultExpression(IRFormPtr lhs, IRFormPtr rhs);

    // DAD: instruction.py:307 is_propagable → var_map[rhs].is_propagable()
    bool is_propagable() const noexcept override;
    // DAD: instruction.py:310 has_side_effect → var_map[rhs].has_side_effect()
    bool has_side_effect() const noexcept override;

    // DAD: instruction.py:317 __str__ — same shape as MoveExpression.
    std::string ToString() const override;
    void Accept(Visitor& v) override;
};

// DAD: instruction.py:322 ArrayStoreInstruction — `array[index] = rhs`.
class ArrayStoreInstruction : public IRForm {
public:
    ArrayStoreInstruction(IRFormPtr rhs, IRFormPtr array,
                          IRFormPtr index, std::string_view atype);

    bool has_side_effect() const noexcept override { return true; }
    std::vector<std::string> get_used_vars() const override;

    void replace_var(const std::string& old_v, const IRFormPtr& new_node) override;
    void replace(const std::string& old_v, const IRFormPtr& new_node) override;

    // DAD: instruction.py:379 __str__ → '<array>[<index>] = <rhs>'
    std::string ToString() const override;

    const std::string& rhs_id()   const noexcept { return rhs_; }
    const std::string& array_id() const noexcept { return array_; }
    const std::string& index_id() const noexcept { return index_; }

private:
    std::string rhs_;
    std::string array_;
    std::string index_;
    void Accept(Visitor& v) override;
};

// DAD: instruction.py:386 StaticInstruction — sput-style field write IR.
class StaticInstruction : public IRForm {
public:
    StaticInstruction(IRFormPtr rhs, std::string_view klass,
                      std::string_view ftype, std::string_view name);

    bool has_side_effect() const noexcept override { return true; }
    std::vector<std::string> get_used_vars() const override;

    // DAD: instruction.py:403 explicit get_lhs returning None.
    std::optional<std::string> GetLhsId() const override { return std::nullopt; }
    IRFormPtr get_lhs() const override { return nullptr; }

    void replace_var(const std::string& old_v, const IRFormPtr& new_node) override;
    void replace(const std::string& old_v, const IRFormPtr& new_node) override;

    // DAD: instruction.py:428 __str__ → '<cls>.<name> = <rhs>'
    std::string ToString() const override;

    const std::string& cls()      const noexcept { return cls_; }
    const std::string& ftype()    const noexcept { return ftype_; }
    const std::string& name()     const noexcept { return name_; }
    const std::string& clsdesc()  const noexcept { return clsdesc_; }
    const std::string& rhs_id()   const noexcept { return rhs_; }

private:
    std::string rhs_;
    std::string cls_;      // already converted to Java type via util.get_type
    std::string ftype_;
    std::string name_;
    std::string clsdesc_;  // original Dalvik descriptor
    void Accept(Visitor& v) override;
};

// DAD: instruction.py:432 InstanceInstruction — iput-style field write IR.
class InstanceInstruction : public IRForm {
public:
    InstanceInstruction(IRFormPtr rhs, IRFormPtr lhs,
                        std::string_view klass, std::string_view atype,
                        std::string_view name);

    bool has_side_effect() const noexcept override { return true; }
    std::vector<std::string> get_used_vars() const override;

    std::optional<std::string> GetLhsId() const override { return std::nullopt; }
    IRFormPtr get_lhs() const override { return nullptr; }

    void replace_var(const std::string& old_v, const IRFormPtr& new_node) override;
    void replace(const std::string& old_v, const IRFormPtr& new_node) override;

    // DAD: instruction.py:490 __str__ → '<lhs>.<name> = <rhs>'
    std::string ToString() const override;

    const std::string& cls()     const noexcept { return cls_; }
    const std::string& atype()   const noexcept { return atype_; }
    const std::string& name()    const noexcept { return name_; }
    const std::string& clsdesc() const noexcept { return clsdesc_; }
    const std::string& lhs_id()  const noexcept { return lhs_; }
    const std::string& rhs_id()  const noexcept { return rhs_; }

private:
    std::string lhs_;
    std::string rhs_;
    std::string atype_;
    std::string cls_;
    std::string name_;
    std::string clsdesc_;
    void Accept(Visitor& v) override;
};

// DAD: instruction.py:495 NewInstance — `new T` expression IR.
class NewInstance : public IRForm {
public:
    explicit NewInstance(std::string_view ins_type);

    // DAD: instruction.py:500 get_type → self.type (override pattern; base
    // returns the same `type` field so this is a defensive direct override).
    std::string get_type() const override { return type; }
    std::vector<std::string> get_used_vars() const override { return {}; }

    // DAD: instruction.py:509 replace → no-op (NewInstance has no operands).
    void replace(const std::string& /*old_v*/,
                 const IRFormPtr& /*new_node*/) override {}

    // DAD: instruction.py:512 __str__ → 'NEW(<type>)'
    std::string ToString() const override;
    void Accept(Visitor& v) override;
};

// DAD: instruction.py:516 InvokeInstruction — invoke-* IR.
class InvokeInstruction : public IRForm {
public:
    using Triple = std::array<std::string, 3>;  // (class, name, descriptor)

    InvokeInstruction(std::string_view clsname,
                      std::string_view name,
                      IRFormPtr base,
                      std::string_view rtype,
                      const std::vector<std::string>& ptype,
                      const std::vector<IRFormPtr>& args,
                      const Triple& triple);

    // DAD: instruction.py:532 get_type — for <init>, return base's type;
    // otherwise the declared return type.
    std::string get_type() const override;

    bool is_call() const noexcept override { return true; }
    bool has_side_effect() const noexcept override { return true; }

    void replace_var(const std::string& old_v, const IRFormPtr& new_node) override;
    void replace(const std::string& old_v, const IRFormPtr& new_node) override;
    std::vector<std::string> get_used_vars() const override;

    // DAD: instruction.py:600 __str__ → '<base>.<name>(<args...>)'
    std::string ToString() const override;

    const std::string& cls()   const noexcept { return cls_; }
    const std::string& name()  const noexcept { return name_; }
    const std::string& base()  const noexcept { return base_; }
    const std::string& rtype() const noexcept { return rtype_; }
    const std::vector<std::string>& ptype() const noexcept { return ptype_; }
    const std::vector<std::string>& args()  const noexcept { return args_; }
    const Triple& triple() const noexcept { return triple_; }

protected:
    std::string cls_;
    std::string name_;
    std::string base_;
    std::string rtype_;
    std::vector<std::string> ptype_;
    std::vector<std::string> args_;
    Triple triple_;
    void Accept(Visitor& v) override;
};

// DAD: instruction.py:609 InvokeRangeInstruction — args[0] becomes base.
class InvokeRangeInstruction : public InvokeInstruction {
public:
    InvokeRangeInstruction(std::string_view clsname,
                           std::string_view name,
                           std::string_view rtype,
                           const std::vector<std::string>& ptype,
                           std::vector<IRFormPtr> args,
                           const Triple& triple);
    void Accept(Visitor& v) override;
};

// DAD: instruction.py:615 InvokeDirectInstruction — trivial subclass.
class InvokeDirectInstruction : public InvokeInstruction {
public:
    using InvokeInstruction::InvokeInstruction;  // inherit constructor
    void Accept(Visitor& v) override;
};

// DAD: instruction.py:620 InvokeStaticInstruction — no base in used_vars.
class InvokeStaticInstruction : public InvokeInstruction {
public:
    using InvokeInstruction::InvokeInstruction;

    // DAD: instruction.py:624 get_used_vars — args only, no base.
    std::vector<std::string> get_used_vars() const override;
    void Accept(Visitor& v) override;
};

// DAD: instruction.py:632 ReturnInstruction — `return [arg]`. arg may be null
// for return-void.
class ReturnInstruction : public IRForm {
public:
    explicit ReturnInstruction(IRFormPtr arg);

    std::vector<std::string> get_used_vars() const override;
    std::optional<std::string> GetLhsId() const override { return std::nullopt; }
    IRFormPtr get_lhs() const override { return nullptr; }

    void replace_var(const std::string& old_v, const IRFormPtr& new_node) override;
    void replace(const std::string& old_v, const IRFormPtr& new_node) override;

    // DAD: instruction.py:671 __str__ → 'RETURN(<arg>)' or 'RETURN'
    std::string ToString() const override;

    const std::optional<std::string>& arg() const noexcept { return arg_; }

private:
    std::optional<std::string> arg_;  // unset = return-void
    void Accept(Visitor& v) override;
};

// DAD: instruction.py:677 NopExpression — explicit no-op.
//
// QUIRK (faithful to DAD): the Python __init__ body is just `pass`, with NO
// call to super().__init__(). That means a Python NopExpression has no
// `var_map` / `type` attributes (any attribute access would AttributeError).
// In C++ the base IRForm always default-constructs them, so they're
// harmlessly present-but-empty. Document as a known divergence.
class NopExpression : public IRForm {
public:
    NopExpression() = default;
    std::vector<std::string> get_used_vars() const override { return {}; }
    std::optional<std::string> GetLhsId() const override { return std::nullopt; }
    IRFormPtr get_lhs() const override { return nullptr; }
    void Accept(Visitor& v) override;
};

// DAD: instruction.py:691 SwitchExpression — switch(src) with branch payload.
//
// DAD stores `branch` opaquely — packedswitch/sparseswitch handlers pass
// `ins.BBBBBBBB` (the 32-bit signed offset to the payload). Case parsing
// happens later in the graph layer.
class SwitchExpression : public IRForm {
public:
    SwitchExpression(IRFormPtr src, int32_t branch);

    std::vector<std::string> get_used_vars() const override;
    void replace_var(const std::string& old_v, const IRFormPtr& new_node) override;
    void replace(const std::string& old_v, const IRFormPtr& new_node) override;

    // DAD: instruction.py:721 __str__ → 'SWITCH(<src>)'
    std::string ToString() const override;

    const std::string& src_id() const noexcept { return src_; }
    int32_t branch() const noexcept { return branch_; }

private:
    std::string src_;
    int32_t branch_ = 0;
    void Accept(Visitor& v) override;
};

// DAD: instruction.py:766 ArrayExpression — empty base for array IR family.
class ArrayExpression : public IRForm {
public:
    ArrayExpression() = default;
};

// DAD: instruction.py:771 ArrayLoadExpression — aget IR (array + index).
class ArrayLoadExpression : public ArrayExpression {
public:
    ArrayLoadExpression(IRFormPtr arg, IRFormPtr index, std::string_view atype);

    // DAD: instruction.py:789 get_type — strip one leading '[' from array's type.
    std::string get_type() const override;

    std::vector<std::string> get_used_vars() const override;
    void replace_var(const std::string& old_v, const IRFormPtr& new_node) override;
    void replace(const std::string& old_v, const IRFormPtr& new_node) override;

    // DAD: instruction.py:821 __str__ → 'ARRAYLOAD(<array>, <idx>)'
    std::string ToString() const override;

    const std::string& array_id() const noexcept { return array_; }
    const std::string& idx_id()   const noexcept { return idx_; }

private:
    std::string array_;
    std::string idx_;
    void Accept(Visitor& v) override;
};

// DAD: instruction.py:826 ArrayLengthExpression — array.length, returns int.
class ArrayLengthExpression : public ArrayExpression {
public:
    explicit ArrayLengthExpression(IRFormPtr array);

    // DAD: instruction.py:832 get_type → 'I'
    std::string get_type() const override { return "I"; }

    std::vector<std::string> get_used_vars() const override;
    void replace_var(const std::string& old_v, const IRFormPtr& new_node) override;
    void replace(const std::string& old_v, const IRFormPtr& new_node) override;

    // DAD: instruction.py:858 __str__ → 'ARRAYLEN(<array>)'
    std::string ToString() const override;

    const std::string& array_id() const noexcept { return array_; }

private:
    std::string array_;
    void Accept(Visitor& v) override;
};

// DAD: instruction.py:862 NewArrayExpression — `new T[size]`.
class NewArrayExpression : public ArrayExpression {
public:
    NewArrayExpression(IRFormPtr asize, std::string_view atype);

    bool is_propagable() const noexcept override { return false; }
    std::vector<std::string> get_used_vars() const override;
    void replace_var(const std::string& old_v, const IRFormPtr& new_node) override;
    void replace(const std::string& old_v, const IRFormPtr& new_node) override;

    // DAD: instruction.py:895 __str__ → 'NEWARRAY_<type>[<size>]'
    std::string ToString() const override;

    const std::string& size_id() const noexcept { return size_; }

private:
    std::string size_;
    void Accept(Visitor& v) override;
};

// DAD: instruction.py:899 FilledArrayExpression — `new T[]{args...}`.
//
// QUIRK (faithful): unlike sibling NewArrayExpression which stores
// `asize.v`, this class stores `asize` directly (an int count, not a
// register id). Reproduced exactly.
class FilledArrayExpression : public ArrayExpression {
public:
    FilledArrayExpression(int64_t asize, std::string_view atype,
                          const std::vector<IRFormPtr>& args);

    std::vector<std::string> get_used_vars() const override;
    void replace_var(const std::string& old_v, const IRFormPtr& new_node) override;
    void replace(const std::string& old_v, const IRFormPtr& new_node) override;

    int64_t size() const noexcept { return size_; }
    const std::vector<std::string>& args() const noexcept { return args_; }

private:
    int64_t size_;
    std::vector<std::string> args_;
    void Accept(Visitor& v) override;
};

// DAD: instruction.py:956 FillArrayExpression — fill-array-data (constant
// payload table). `value` is the raw constant data — opaque to the IR (just
// a payload reference). Modelled as std::vector<int64_t>.
//
// QUIRK (faithful): DAD's `get_rhs()` returns the register id STRING here
// rather than a list of IRForm like the base. We split the API: keep the
// base `get_rhs()` returning empty vector, and expose `reg_id()` for the
// string. Document callers should use the latter for FillArray.
class FillArrayExpression : public ArrayExpression {
public:
    FillArrayExpression(IRFormPtr reg, std::vector<int64_t> value);

    bool is_propagable() const noexcept override { return false; }
    std::vector<std::string> get_used_vars() const override;
    void replace_var(const std::string& old_v, const IRFormPtr& new_node) override;
    void replace(const std::string& old_v, const IRFormPtr& new_node) override;

    const std::string& reg_id() const noexcept { return reg_; }
    const std::vector<int64_t>& value() const noexcept { return value_; }

private:
    std::string reg_;
    std::vector<int64_t> value_;
    void Accept(Visitor& v) override;
};

// DAD: instruction.py:993 RefExpression — base for ref-typed ops.
class RefExpression : public IRForm {
public:
    explicit RefExpression(IRFormPtr ref);

    bool is_propagable() const noexcept override { return false; }
    std::vector<std::string> get_used_vars() const override;

    void replace_var(const std::string& old_v, const IRFormPtr& new_node) override;
    void replace(const std::string& old_v, const IRFormPtr& new_node) override;

    const std::string& ref_id() const noexcept { return ref_; }

protected:
    std::string ref_;
};

// DAD: instruction.py:1023 MoveExceptionExpression.
//
// QUIRK (faithful): DAD's `get_lhs()` returns `self.ref` (a string id).
// In our C++ split, this maps to `GetLhsId()` returning the ref string;
// base `get_lhs()` returns nullptr.
class MoveExceptionExpression : public RefExpression {
public:
    MoveExceptionExpression(IRFormPtr ref, std::string_view atype);

    std::optional<std::string> GetLhsId() const override { return ref_; }
    bool has_side_effect() const noexcept override { return true; }
    std::vector<std::string> get_used_vars() const override { return {}; }

    void replace_lhs(const IRFormPtr& new_node) override;

    // DAD: instruction.py:1046 __str__ → 'MOVE_EXCEPT <ref>'
    std::string ToString() const override;
    void Accept(Visitor& v) override;
};

// DAD: instruction.py:1050 MonitorEnterExpression — trivial RefExpression.
class MonitorEnterExpression : public RefExpression {
public:
    using RefExpression::RefExpression;
    void Accept(Visitor& v) override;
};

// DAD: instruction.py:1058 MonitorExitExpression — trivial RefExpression.
class MonitorExitExpression : public RefExpression {
public:
    using RefExpression::RefExpression;
    void Accept(Visitor& v) override;
};

// DAD: instruction.py:1066 ThrowExpression — trivial RefExpression with __str__.
class ThrowExpression : public RefExpression {
public:
    using RefExpression::RefExpression;
    // DAD: instruction.py:1073 __str__ → 'Throw <ref>'
    std::string ToString() const override;
    void Accept(Visitor& v) override;
};

// DAD: instruction.py:1077 BinaryExpression — `(op arg1 arg2)`.
class BinaryExpression : public IRForm {
public:
    BinaryExpression(std::string_view op, IRFormPtr arg1, IRFormPtr arg2,
                     std::string_view atype);

    bool has_side_effect() const noexcept override;
    std::vector<std::string> get_used_vars() const override;
    void replace_var(const std::string& old_v, const IRFormPtr& new_node) override;
    void replace(const std::string& old_v, const IRFormPtr& new_node) override;

    // DAD: instruction.py:1133 __str__ → '(<op> <arg1> <arg2>)'
    std::string ToString() const override;

    const std::string& op()       const noexcept { return op_; }
    const std::string& arg1_id()  const noexcept { return arg1_; }
    const std::string& arg2_id()  const noexcept { return arg2_; }
    // DAD writer.py:728-730 mutates `arg.op = new_op` when wrapping a
    // BinaryCompExpression in if-test context (so `cmp` is replaced with the
    // actual `<`/`==`/etc operator).
    void set_op(std::string_view new_op) { op_ = std::string{new_op}; }

protected:
    std::string op_;
    std::string arg1_;
    std::string arg2_;
    void Accept(Visitor& v) override;
};

// DAD: instruction.py:1138 BinaryCompExpression — trivial subclass, visit only.
class BinaryCompExpression : public BinaryExpression {
public:
    using BinaryExpression::BinaryExpression;
    void Accept(Visitor& v) override;
};

// DAD: instruction.py:1149 BinaryExpression2Addr — trivial subclass.
class BinaryExpression2Addr : public BinaryExpression {
public:
    using BinaryExpression::BinaryExpression;
};

// DAD: instruction.py:1154 BinaryExpressionLit — fixed type 'I'.
class BinaryExpressionLit : public BinaryExpression {
public:
    BinaryExpressionLit(std::string_view op, IRFormPtr arg1, IRFormPtr arg2);
};

// DAD: instruction.py:1159 UnaryExpression — `(op arg)` with type override.
class UnaryExpression : public IRForm {
public:
    UnaryExpression(std::string_view op, IRFormPtr arg, std::string_view atype);

    // DAD: instruction.py:1167 get_type → var_map[arg].get_type()
    std::string get_type() const override;

    std::vector<std::string> get_used_vars() const override;
    void replace_var(const std::string& old_v, const IRFormPtr& new_node) override;
    void replace(const std::string& old_v, const IRFormPtr& new_node) override;

    // DAD: instruction.py:1193 __str__ → '(<op>, <arg>)'
    std::string ToString() const override;

    const std::string& op()      const noexcept { return op_; }
    const std::string& arg_id()  const noexcept { return arg_; }

protected:
    std::string op_;
    std::string arg_;
    void Accept(Visitor& v) override;
};

// DAD: instruction.py:1197 CastExpression — `CAST_<op>(<arg>)`.
class CastExpression : public UnaryExpression {
public:
    CastExpression(std::string_view op, std::string_view atype, IRFormPtr arg);

    bool is_const() const noexcept override;
    // DAD: instruction.py:1205 get_type → self.type (NOT arg's type, unlike parent)
    std::string get_type() const override { return type; }

    // DAD: instruction.py:1214 __str__ → 'CAST_<op>(<arg>)'
    std::string ToString() const override;

    const std::string& clsdesc() const noexcept { return clsdesc_; }

private:
    std::string clsdesc_;
    void Accept(Visitor& v) override;
};

// DAD: instruction.py:1218 CONDS — comparison op → negated op.
const std::unordered_map<std::string, std::string>& CondsTable();

// DAD: instruction.py:1228 ConditionalExpression — `if-<op> arg1, arg2`.
class ConditionalExpression : public IRForm {
public:
    ConditionalExpression(std::string_view op, IRFormPtr arg1, IRFormPtr arg2);

    std::optional<std::string> GetLhsId() const override { return std::nullopt; }
    IRFormPtr get_lhs() const override { return nullptr; }
    bool is_cond() const noexcept override { return true; }
    std::vector<std::string> get_used_vars() const override;

    // DAD: instruction.py:1248 neg() — flip op via CONDS.
    void Neg() override;

    void replace_var(const std::string& old_v, const IRFormPtr& new_node) override;
    void replace(const std::string& old_v, const IRFormPtr& new_node) override;

    // DAD: instruction.py:1285 __str__ → 'COND(<op>, <arg1>, <arg2>)'
    std::string ToString() const override;

    const std::string& op()      const noexcept { return op_; }
    const std::string& arg1_id() const noexcept { return arg1_; }
    const std::string& arg2_id() const noexcept { return arg2_; }

private:
    std::string op_;
    std::string arg1_;
    std::string arg2_;
    void Accept(Visitor& v) override;
};

// DAD: instruction.py:1292 ConditionalZExpression — `if-<op>z arg`.
class ConditionalZExpression : public IRForm {
public:
    ConditionalZExpression(std::string_view op, IRFormPtr arg);

    std::optional<std::string> GetLhsId() const override { return std::nullopt; }
    IRFormPtr get_lhs() const override { return nullptr; }
    bool is_cond() const noexcept override { return true; }
    std::vector<std::string> get_used_vars() const override;

    void Neg() override;

    void replace_var(const std::string& old_v, const IRFormPtr& new_node) override;
    void replace(const std::string& old_v, const IRFormPtr& new_node) override;

    // DAD: instruction.py:1331 __str__ → '(IS<op>0, <arg>)'
    std::string ToString() const override;

    const std::string& op()      const noexcept { return op_; }
    const std::string& arg_id()  const noexcept { return arg_; }

private:
    std::string op_;
    std::string arg_;
    void Accept(Visitor& v) override;
};

// DAD: instruction.py:1335 InstanceExpression — iget read expression IR.
class InstanceExpression : public IRForm {
public:
    InstanceExpression(IRFormPtr arg, std::string_view klass,
                       std::string_view ftype, std::string_view name);

    // DAD: instruction.py:1346 get_type → self.ftype
    std::string get_type() const override { return ftype_; }
    std::vector<std::string> get_used_vars() const override;
    void replace_var(const std::string& old_v, const IRFormPtr& new_node) override;
    void replace(const std::string& old_v, const IRFormPtr& new_node) override;

    // DAD: instruction.py:1374 __str__ → '<arg>.<name>'
    std::string ToString() const override;

    const std::string& arg_id()  const noexcept { return arg_; }
    const std::string& cls()     const noexcept { return cls_; }
    const std::string& ftype()   const noexcept { return ftype_; }
    const std::string& name()    const noexcept { return name_; }
    const std::string& clsdesc() const noexcept { return clsdesc_; }

private:
    std::string arg_;
    std::string cls_;
    std::string ftype_;
    std::string name_;
    std::string clsdesc_;
    void Accept(Visitor& v) override;
};

// DAD: instruction.py:1378 StaticExpression — sget read expression IR.
class StaticExpression : public IRForm {
public:
    StaticExpression(std::string_view cls_name, std::string_view field_type,
                     std::string_view field_name);

    // DAD: instruction.py:1387 get_type → self.ftype
    std::string get_type() const override { return ftype_; }

    // DAD: instruction.py:1393 replace → pass (no-op)
    void replace(const std::string& /*old_v*/,
                 const IRFormPtr& /*new_node*/) override {}

    // DAD: instruction.py:1396 __str__ → '<cls>.<name>'
    std::string ToString() const override;

    const std::string& cls()     const noexcept { return cls_; }
    const std::string& ftype()   const noexcept { return ftype_; }
    const std::string& name()    const noexcept { return name_; }
    const std::string& clsdesc() const noexcept { return clsdesc_; }

private:
    std::string cls_;
    std::string ftype_;
    std::string name_;
    std::string clsdesc_;
    void Accept(Visitor& v) override;
};

// DAD: instruction.py:725 CheckCastExpression — check-cast IR.
class CheckCastExpression : public IRForm {
public:
    CheckCastExpression(IRFormPtr arg, std::string_view atype,
                        std::string_view descriptor = {});

    // DAD: instruction.py:734 is_const → var_map[arg].is_const()
    bool is_const() const noexcept override;

    std::vector<std::string> get_used_vars() const override;
    void replace_var(const std::string& old_v, const IRFormPtr& new_node) override;
    void replace(const std::string& old_v, const IRFormPtr& new_node) override;

    // DAD: instruction.py:762 __str__ → 'CAST(<type>) <arg>'
    std::string ToString() const override;

    const std::string& arg_id()  const noexcept { return arg_; }
    const std::string& clsdesc() const noexcept { return clsdesc_; }

private:
    std::string arg_;
    std::string clsdesc_;
    void Accept(Visitor& v) override;
};

}  // namespace dexkit::dad
