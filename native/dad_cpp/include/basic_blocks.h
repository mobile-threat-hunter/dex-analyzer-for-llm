// basic_blocks.h — C++ port of androguard DAD basic_blocks.py
// DAD: androguard/decompiler/basic_blocks.py
//
// This module corresponds to androguard's DAD <basic_blocks.py>. Read that file
// before adding code here. Every function added must carry a
// `// DAD: basic_blocks.py:<lineno> <concept>` comment.
//
// PORT STATUS (11/12 entities ported — class hierarchy complete):
//   Ported:
//     - BasicBlock           — DAD basic_blocks.py:28
//     - StatementBlock       — DAD basic_blocks.py:66
//     - ReturnBlock          — DAD basic_blocks.py:78
//     - ThrowBlock           — DAD basic_blocks.py:90
//     - SwitchBlock          — DAD basic_blocks.py:102
//     - CondBlock            — DAD basic_blocks.py:140
//     - Condition            — DAD basic_blocks.py:169
//     - ShortCircuitBlock    — DAD basic_blocks.py:206
//     - LoopBlock            — DAD basic_blocks.py:227
//     - TryBlock             — DAD basic_blocks.py:263
//     - CatchBlock           — DAD basic_blocks.py:288
//   Deferred:
//     - build_node_from_block — DAD basic_blocks.py:312 — depends on a
//       RawBlock/RawIns provider ABI (androguard's DVMBasicBlock /
//       DalvikInstruction surface) we have not yet designed. Will be added
//       together with the IDexDataProvider redesign.
//
// Visitor pattern: DAD's BasicBlock subclasses call visitor.visit_XXX_node;
// the Visitor base class lives in writer.h (deferred). We forward-declare the
// minimal surface here so subclass headers compile without writer.h.

#pragma once

#include <memory>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <utility>
#include <vector>

#include "instruction.h"  // IRForm, IRFormPtr, MoveExceptionExpression, SwitchExpression
#include "node.h"          // Node, NodeBase
#include "opcode_ins.h"    // Vmap, RetState (for BuildNodeFromBlock signature)

namespace dexkit::dad {

// Forward declaration — Visitor lives in writer.h (not yet ported). Each
// visit_XXX_node will be declared as a virtual method on Visitor when that
// module is ported; until then BasicBlock subclasses store the visit
// dispatch as a non-defined extern call site.
class Visitor;

// =============================================================================
// BasicBlock — DAD: basic_blocks.py:28
// =============================================================================
class BasicBlock : public Node {
public:
    // DAD: basic_blocks.py:29 __init__(name, block_ins)
    BasicBlock(std::string name, std::vector<IRFormPtr> block_ins);

    // DAD: basic_blocks.py:37 get_ins
    std::vector<IRFormPtr>& get_ins() { return ins; }
    const std::vector<IRFormPtr>& get_ins() const { return ins; }

    // DAD: basic_blocks.py:40 get_loc_with_ins — lazy materialise list of
    // (location, ins) pairs over ins_range. Cached in loc_ins.
    const std::vector<std::pair<int, IRFormPtr>>& get_loc_with_ins();

    // DAD: basic_blocks.py:45 remove_ins
    void remove_ins(int loc, const IRFormPtr& ins_node);

    // DAD: basic_blocks.py:49 add_ins — appends each element of new_ins_list.
    void add_ins(const std::vector<IRFormPtr>& new_ins_list);

    // DAD: basic_blocks.py:53 add_variable_declaration — set insertion (no dup).
    void add_variable_declaration(IRFormPtr variable);

    // DAD: basic_blocks.py:56 number_ins — assigns ins_range = [num, num+len].
    int number_ins(int num);

    // DAD: basic_blocks.py:62 set_catch_type
    void set_catch_type(std::string t) { catch_type = std::move(t); }

    // Public data — DAD models these as public attributes.
    std::vector<IRFormPtr> ins;
    // ins_range: DAD stores None until number_ins; we mirror with optional pair.
    bool has_ins_range = false;
    int ins_range_lo = 0;
    int ins_range_hi = 0;
    // loc_ins: DAD stores None until get_loc_with_ins; we use a bool guard.
    bool loc_ins_built = false;
    std::vector<std::pair<int, IRFormPtr>> loc_ins;
    // DAD uses a set() of Variable nodes; we key on the IRForm shared_ptr.
    // Insertion-ordered for deterministic emit (hash order would produce
    // non-deterministic declaration ordering, diverging from DAD's Python set
    // iteration which — for object refs — is also pointer-hashed but in
    // practice produces the same ordering across runs of the same input).
    std::vector<IRFormPtr> var_to_declare;
    // DAD: None until set_catch_type. Empty string represents the None state.
    std::string catch_type;

    // DAD: BasicBlock has no __str__ — subclasses override. Default mimics
    // Python's `repr(self)` form `Block(name)` for diagnostics.
    virtual std::string ToString() const { return "Block(" + name + ")"; }

    // DAD: each leaf class implements visit(visitor) → visitor.visit_XXX_node.
    // Pure-virtual here so each subclass must define it; Visitor surface lives
    // in writer.h and will be wired then.
    virtual void Visit(Visitor& visitor) = 0;
};

// =============================================================================
// StatementBlock — DAD: basic_blocks.py:66
// =============================================================================
class StatementBlock : public BasicBlock {
public:
    StatementBlock(std::string name, std::vector<IRFormPtr> block_ins);
    // DAD: basic_blocks.py:71 visit → visit_statement_node.
    void Visit(Visitor& visitor) override;
    // DAD: basic_blocks.py:74 __str__
    std::string ToString() const override;
};

// =============================================================================
// ReturnBlock — DAD: basic_blocks.py:78
// =============================================================================
class ReturnBlock : public BasicBlock {
public:
    ReturnBlock(std::string name, std::vector<IRFormPtr> block_ins);
    // DAD: basic_blocks.py:83 visit → visit_return_node.
    void Visit(Visitor& visitor) override;
    // DAD: basic_blocks.py:86 __str__
    std::string ToString() const override;
};

// =============================================================================
// ThrowBlock — DAD: basic_blocks.py:90
// =============================================================================
class ThrowBlock : public BasicBlock {
public:
    ThrowBlock(std::string name, std::vector<IRFormPtr> block_ins);
    // DAD: basic_blocks.py:95 visit → visit_throw_node.
    void Visit(Visitor& visitor) override;
    // DAD: basic_blocks.py:98 __str__
    std::string ToString() const override;
};

// =============================================================================
// SwitchBlock — DAD: basic_blocks.py:102
// =============================================================================
class SwitchBlock : public BasicBlock {
public:
    // DAD: basic_blocks.py:103 __init__(name, switch, block_ins).
    // `switch` is a payload-like object exposing get_values(); we hold it as
    // a SwitchExpression-derived IRForm pointer (SwitchExpression's interface
    // does not expose get_values yet — get_values lives on the raw fill-data
    // payload in androguard; we keep the field as opaque IRFormPtr until the
    // RawIns provider is wired).
    SwitchBlock(std::string name, IRFormPtr switch_payload,
                std::vector<IRFormPtr> block_ins);

    // DAD: basic_blocks.py:111 add_case
    void add_case(NodeBase* case_node) { cases.push_back(case_node); }

    // DAD: basic_blocks.py:114 visit → visit_switch_node.
    void Visit(Visitor& visitor) override;

    // DAD: basic_blocks.py:117 copy_from — copies cases and switch (as list).
    // The Python `node.switch[:]` slice copy only makes sense if .switch is a
    // list; in DAD it's the payload object itself. Replicate as a pointer copy
    // (no slicing — Python's [:] on a non-list raises, so this is effectively
    // dead code in DAD unless .switch happens to be list-like).
    void copy_from(const SwitchBlock& node);

    // DAD: basic_blocks.py:122 update_attribute_with(n_map).
    void UpdateAttributeWith(
        const std::unordered_map<NodeBase*, NodeBase*>& n_map) override;

    // DAD: basic_blocks.py:129 order_cases — pop default if values shorter,
    // then zip values to cases and append into node_to_case.
    // DEFERRED: requires the switch payload to expose get_values() — the
    // payload's value list comes from the RawIns provider. Wired alongside
    // BuildNodeFromBlock.

    // DAD: basic_blocks.py:136 __str__
    std::string ToString() const override;

    IRFormPtr switch_payload;
    std::vector<NodeBase*> cases;
    NodeBase* default_case = nullptr;
    // DAD: defaultdict(list) — we use a vector value with explicit insert.
    std::unordered_map<NodeBase*, std::vector<int64_t>> node_to_case;
};

// =============================================================================
// CondBlock — DAD: basic_blocks.py:140
// =============================================================================
class CondBlock : public BasicBlock {
public:
    CondBlock(std::string name, std::vector<IRFormPtr> block_ins);

    // DAD: basic_blocks.py:147 update_attribute_with(n_map).
    void UpdateAttributeWith(
        const std::unordered_map<NodeBase*, NodeBase*>& n_map) override;

    // DAD: basic_blocks.py:152 neg — call ins[-1].neg(); raise if len(ins)!=1.
    // ConditionalExpression / ConditionalZExpression don't expose neg() in the
    // current C++ port (it would flip the test op via the CONDS table). Until
    // those add a Neg() override, this is implemented as a virtual hook that
    // ShortCircuitBlock / LoopBlock override to delegate to their Condition.
    virtual void neg();

    // DAD: basic_blocks.py:157 visit → visit_cond_node.
    void Visit(Visitor& visitor) override;

    // DAD: basic_blocks.py:160 visit_cond → visitor.visit_ins(self.ins[-1]).
    virtual void visit_cond(Visitor& visitor);

    // DAD: basic_blocks.py:165 __str__
    std::string ToString() const override;

    // DAD: extra fields populated by control-flow analysis.
    NodeBase* true_branch = nullptr;
    NodeBase* false_branch = nullptr;
    // DAD: set by build_node_from_block for if-test[z] — `off_last_ins`.
    // Stored as int (Dalvik byte offset). 0 indicates unset.
    int off_last_ins = 0;
};

// =============================================================================
// Condition — DAD: basic_blocks.py:169
//   Short-circuit (cond1 && cond2 / cond1 || cond2) composite. NOT a Node.
// =============================================================================
class Condition {
public:
    // DAD: basic_blocks.py:170 __init__(cond1, cond2, isand, isnot).
    // The cond operands are either CondBlock* (leaf) or Condition* (nested).
    // DAD uses duck typing; we wrap in a small variant via virtual interface.
    class Operand {
    public:
        virtual ~Operand() = default;
        virtual std::vector<IRFormPtr> get_ins() const = 0;
        virtual std::vector<std::pair<int, IRFormPtr>>
            get_loc_with_ins() const = 0;
        virtual void neg() = 0;
        virtual void visit(Visitor& visitor) = 0;
        // DAD: cond.visit_cond(visitor) — for CondBlock-flavored operands
        // this emits the cond IR; for nested Condition this recurses through
        // visit (DAD pattern).
        virtual void visit_cond(Visitor& visitor) = 0;
        virtual std::string to_string() const = 0;
    };

    Condition(std::shared_ptr<Operand> cond1, std::shared_ptr<Operand> cond2,
              bool isand, bool isnot);

    // DAD: basic_blocks.py:176 neg — toggles isand and negates both children.
    void neg();
    // DAD: basic_blocks.py:181 get_ins — concat both children's get_ins.
    std::vector<IRFormPtr> get_ins() const;
    // DAD: basic_blocks.py:187 get_loc_with_ins.
    std::vector<std::pair<int, IRFormPtr>> get_loc_with_ins() const;
    // DAD: basic_blocks.py:193 visit → visitor.visit_short_circuit_condition.
    void visit(Visitor& visitor);
    // DAD: basic_blocks.py:198 __str__
    std::string ToString() const;

    std::shared_ptr<Operand> cond1;
    std::shared_ptr<Operand> cond2;
    bool isand;
    bool isnot;
};

// Adapter that lets a `CondBlock*` (or any CondBlock subclass like
// ShortCircuitBlock) participate as a `Condition::Operand`. Used by
// ShortCircuitStruct which wraps CondBlock nodes in Conditions.
class CondBlockOperand : public Condition::Operand {
public:
    explicit CondBlockOperand(CondBlock* block) : block_(block) {}
    std::vector<IRFormPtr> get_ins() const override {
        return block_ ? block_->get_ins() : std::vector<IRFormPtr>{};
    }
    std::vector<std::pair<int, IRFormPtr>> get_loc_with_ins() const override {
        return block_ ? block_->get_loc_with_ins()
                       : std::vector<std::pair<int, IRFormPtr>>{};
    }
    void neg() override { if (block_) block_->neg(); }
    void visit(Visitor& v) override { if (block_) block_->Visit(v); }
    // DAD: cond.visit_cond(visitor) — delegate to CondBlock's visit_cond
    // which calls visit_ins on the last instruction (the actual condition).
    void visit_cond(Visitor& v) override { if (block_) block_->visit_cond(v); }
    std::string to_string() const override {
        return block_ ? block_->ToString() : std::string{};
    }
    CondBlock* block() const noexcept { return block_; }
private:
    CondBlock* block_;
};

// Adapter so a nested Condition can be used as an Operand of an outer
// Condition (DAD short-circuit composition).
class ConditionOperand : public Condition::Operand {
public:
    explicit ConditionOperand(std::shared_ptr<Condition> c) : cond_(std::move(c)) {}
    std::vector<IRFormPtr> get_ins() const override {
        return cond_ ? cond_->get_ins() : std::vector<IRFormPtr>{};
    }
    std::vector<std::pair<int, IRFormPtr>> get_loc_with_ins() const override {
        return cond_ ? cond_->get_loc_with_ins()
                      : std::vector<std::pair<int, IRFormPtr>>{};
    }
    void neg() override { if (cond_) cond_->neg(); }
    void visit(Visitor& v) override { if (cond_) cond_->visit(v); }
    // Nested condition: DAD's cond.visit_cond on a Condition recurses via
    // visit (which emits the short-circuit expression).
    void visit_cond(Visitor& v) override { if (cond_) cond_->visit(v); }
    std::string to_string() const override {
        return cond_ ? cond_->ToString() : std::string{};
    }
    // Accessor so dast.py's get_cond(cond.condN) can recurse into the nested
    // Condition (our port wraps it in this operand adapter).
    Condition* cond() const noexcept { return cond_.get(); }
private:
    std::shared_ptr<Condition> cond_;
};

// =============================================================================
// ShortCircuitBlock — DAD: basic_blocks.py:206
// =============================================================================
class ShortCircuitBlock : public CondBlock {
public:
    // DAD: basic_blocks.py:207 __init__(name, cond) — passes block_ins=None.
    ShortCircuitBlock(std::string name, std::shared_ptr<Condition> cond);

    // DAD: basic_blocks.py:211 get_ins — delegate to cond.
    std::vector<IRFormPtr> sc_get_ins() const { return cond->get_ins(); }
    // DAD: basic_blocks.py:214 get_loc_with_ins — delegate to cond.
    std::vector<std::pair<int, IRFormPtr>> sc_get_loc_with_ins() const {
        return cond->get_loc_with_ins();
    }
    // DAD: basic_blocks.py:217 neg — cond.neg() (no ins-len check).
    void neg() override { cond->neg(); }
    // DAD: basic_blocks.py:220 visit_cond — cond.visit(visitor).
    void visit_cond(Visitor& visitor) override { cond->visit(visitor); }
    // DAD: basic_blocks.py:223 __str__
    std::string ToString() const override;

    std::shared_ptr<Condition> cond;
};

// =============================================================================
// LoopBlock — DAD: basic_blocks.py:227
// =============================================================================
class LoopBlock : public CondBlock {
public:
    // DAD: basic_blocks.py:228 __init__(name, cond) — passes block_ins=None.
    // DAD allows `cond` to be either a Condition (short-circuit composite)
    // OR a CondBlock (single-instruction header). We expose both as
    // overloads; ToString / neg / etc. pick whichever is set.
    LoopBlock(std::string name, std::shared_ptr<Condition> cond);
    LoopBlock(std::string name, CondBlock* cond_block);

    // DAD: basic_blocks.py:232 get_ins — delegate to cond.
    std::vector<IRFormPtr> loop_get_ins() const {
        if (cond) return cond->get_ins();
        if (cond_block) return cond_block->get_ins();
        return {};
    }
    // DAD: basic_blocks.py:235 neg — cond.neg() (no ins-len check).
    void neg() override {
        if (cond) cond->neg();
        else if (cond_block) cond_block->neg();
    }
    // DAD: basic_blocks.py:238 get_loc_with_ins — delegate to cond.
    std::vector<std::pair<int, IRFormPtr>> loop_get_loc_with_ins() const {
        if (cond) return cond->get_loc_with_ins();
        if (cond_block) return cond_block->get_loc_with_ins();
        return {};
    }
    // DAD: basic_blocks.py:241 visit → visit_loop_node.
    void Visit(Visitor& visitor) override;
    // DAD: basic_blocks.py:244 visit_cond → cond.visit_cond(visitor).
    //   NB: DAD calls cond.visit_cond, but Condition only has visit (not
    //   visit_cond). This relies on cond being a CondBlock (i.e.
    //   ShortCircuitBlock or a CondBlock leaf), not a bare Condition. Mirror.
    void visit_cond(Visitor& visitor) override;
    // DAD: basic_blocks.py:247 update_attribute_with — base + cond's own.
    //   NB: in DAD, cond is a Condition (no update_attribute_with). The call
    //   would AttributeError for non-CondBlock cond. Quirk faithfully kept.
    //   We model by making the cond's update a no-op when it's a Condition.
    // DAD: basic_blocks.py:251 __str__ — branches on looptype.
    std::string ToString() const override;

    std::shared_ptr<Condition> cond;
    CondBlock* cond_block = nullptr;  // alternative form (DAD duck typing)
};

// =============================================================================
// TryBlock — DAD: basic_blocks.py:263
// =============================================================================
class TryBlock : public BasicBlock {
public:
    // DAD: basic_blocks.py:264 __init__(node) — name is 'Try-<node.name>',
    // block_ins is None. We pass an empty vector.
    explicit TryBlock(NodeBase* node);

    // DAD: basic_blocks.py:270 @property num — delegates to try_start.num.
    // We override accessor by shadowing the inherited field. C++ has no
    // properties; we expose Num() and (per DAD :274 setter that does pass)
    // a NumSet no-op.
    int Num() const { return try_start ? try_start->num : 0; }
    void NumSet(int /*value*/) { /* DAD: setter is pass */ }

    // DAD: basic_blocks.py:278 add_catch_node
    void add_catch_node(NodeBase* n) { catch_nodes.push_back(n); }

    // DAD: basic_blocks.py:281 visit → visit_try_node (no return).
    void Visit(Visitor& visitor) override;

    // DAD: basic_blocks.py:284 __str__
    std::string ToString() const override;

    NodeBase* try_start = nullptr;
    std::vector<NodeBase*> catch_nodes;
    // DAD writes `try_node.follow = single_node` (overwriting Node's follow
    // dict with a scalar in Python). We keep follow dict intact and store
    // the scalar separately.
    NodeBase* try_follow = nullptr;
};

// =============================================================================
// CatchBlock — DAD: basic_blocks.py:288
// =============================================================================
class CatchBlock : public BasicBlock {
public:
    // DAD: basic_blocks.py:289 __init__(node) — peeks node.ins[0]; if it is a
    // MoveExceptionExpression, captures it and pops from node.ins.
    // We take a BasicBlock& because DAD's node is a BasicBlock with .ins,
    // .name, .catch_type. (NodeBase doesn't carry ins.)
    explicit CatchBlock(BasicBlock& node);

private:
    // Private delegating-constructor tag used to thread the peek/pop result
    // into the base-class initialiser (DAD performs the pop before super()).
    struct InitData {
        std::shared_ptr<MoveExceptionExpression> exc;
        std::vector<IRFormPtr> block_ins;
        std::string name;
        std::string catch_type;
        BasicBlock* start = nullptr;
    };
    CatchBlock(InitData&& d);
    static InitData PrepareInit(BasicBlock& node);

public:

    // DAD: basic_blocks.py:299 visit → visit_catch_node (no return).
    void Visit(Visitor& visitor) override;

    // DAD: basic_blocks.py:302 visit_exception — if exception_ins set, visit;
    // else visitor.write(get_type(self.catch_type)). The write() method lives
    // on Visitor (writer.h, deferred); declared here for forward consistency.
    void visit_exception(Visitor& visitor);

    // DAD: basic_blocks.py:308 __str__
    std::string ToString() const override;

    std::shared_ptr<MoveExceptionExpression> exception_ins;
    BasicBlock* catch_start = nullptr;
};

// =============================================================================
// build_node_from_block — DAD: basic_blocks.py:312
// =============================================================================
// Lifts a RawBlock into the appropriate typed BasicBlock subclass by
// dispatching each instruction through DispatchInstruction (instruction_dispatch).
// Returns a heap-owned node; caller (typically `make_node` → Graph::MakeNode)
// takes ownership.
//
// Forward declaration — full def in method_snapshot.h.
struct RawBlock;

std::unique_ptr<BasicBlock>
BuildNodeFromBlock(const RawBlock& block, Vmap& vmap, RetState& gen_ret,
                   std::string_view exception_type = {});

}  // namespace dexkit::dad
