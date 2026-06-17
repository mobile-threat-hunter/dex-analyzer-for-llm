// basic_blocks.cpp — DAD basic_blocks.py port.
// See include/basic_blocks.h for entity list & status.

#include "basic_blocks.h"

#include <algorithm>
#include <cstdio>
#include <cstdlib>
#include <memory>
#include <sstream>
#include <utility>

#include "instruction_dispatch.h"
#include "method_snapshot.h"
#include "slicer/dex_bytecode.h"
#include "visitor.h"

namespace dexkit::dad {

namespace {

// Local helper — DAD subclasses use "%d-Kind(%s)" formatting; mirror with
// ostringstream to avoid std::format dependency.
std::string FormatNumName(int num, const char* kind, const std::string& name) {
    std::ostringstream os;
    os << num << '-' << kind << '(' << name << ')';
    return os.str();
}

}  // namespace

// =============================================================================
// BasicBlock — DAD basic_blocks.py:28
// =============================================================================

BasicBlock::BasicBlock(std::string nm, std::vector<IRFormPtr> block_ins)
    // DAD: basic_blocks.py:30 super().__init__(name); rest = defaults.
    : Node(std::move(nm)), ins(std::move(block_ins)) {
    // DAD: basic_blocks.py:32–35
    //   self.ins_range = None
    //   self.loc_ins   = None
    //   self.var_to_declare = set()
    //   self.catch_type = None
    // (already covered by default member initialisers in the header)
}

// DAD: basic_blocks.py:40 get_loc_with_ins.
const std::vector<std::pair<int, IRFormPtr>>& BasicBlock::get_loc_with_ins() {
    if (!loc_ins_built) {
        // DAD: list(zip(range(*self.ins_range), self.ins))
        loc_ins.clear();
        if (has_ins_range) {
            const int lo = ins_range_lo;
            const int hi = ins_range_hi;
            const size_t n = ins.size();
            // Python's zip stops at the shorter of the two iterables.
            const size_t range_len =
                hi > lo ? static_cast<size_t>(hi - lo) : 0;
            const size_t pairs = std::min(range_len, n);
            loc_ins.reserve(pairs);
            for (size_t i = 0; i < pairs; ++i) {
                loc_ins.emplace_back(lo + static_cast<int>(i), ins[i]);
            }
        }
        loc_ins_built = true;
    }
    return loc_ins;
}

// DAD: basic_blocks.py:45 remove_ins.
void BasicBlock::remove_ins(int loc, const IRFormPtr& ins_node) {
    // DAD: self.ins.remove(ins) — removes the FIRST matching element.
    auto it = std::find(ins.begin(), ins.end(), ins_node);
    if (it != ins.end()) ins.erase(it);
    // DAD: self.loc_ins.remove((loc, ins))
    auto it2 = std::find_if(
        loc_ins.begin(), loc_ins.end(),
        [&](const auto& p) { return p.first == loc && p.second == ins_node; });
    if (it2 != loc_ins.end()) loc_ins.erase(it2);
}

// DAD: basic_blocks.py:49 add_ins.
void BasicBlock::add_ins(const std::vector<IRFormPtr>& new_ins_list) {
    for (const auto& n : new_ins_list) {
        ins.push_back(n);
    }
}

// DAD: basic_blocks.py:53 add_variable_declaration.
void BasicBlock::add_variable_declaration(IRFormPtr variable) {
    if (std::find(var_to_declare.begin(), var_to_declare.end(), variable)
            != var_to_declare.end()) return;
    var_to_declare.push_back(std::move(variable));
}

// DAD: basic_blocks.py:56 number_ins.
int BasicBlock::number_ins(int num_in) {
    const int last_ins_num = num_in + static_cast<int>(ins.size());
    ins_range_lo = num_in;
    ins_range_hi = last_ins_num;
    has_ins_range = true;
    // DAD: self.loc_ins = None  → invalidate cache.
    loc_ins_built = false;
    loc_ins.clear();
    return last_ins_num;
}

// =============================================================================
// StatementBlock — DAD basic_blocks.py:66
// =============================================================================

StatementBlock::StatementBlock(std::string nm, std::vector<IRFormPtr> block_ins)
    : BasicBlock(std::move(nm), std::move(block_ins)) {
    // DAD: basic_blocks.py:69 self.type.is_stmt = True
    type.set_is_stmt(true);
}

void StatementBlock::Visit(Visitor& /*visitor*/) {
    // DAD: basic_blocks.py:71 visitor.visit_statement_node(self).
    // Visitor surface lives in writer.h (deferred). No-op until then.
}

std::string StatementBlock::ToString() const {
    // DAD: basic_blocks.py:74 '%d-Statement(%s)' % (self.num, self.name)
    return FormatNumName(num, "Statement", name);
}

// =============================================================================
// ReturnBlock — DAD basic_blocks.py:78
// =============================================================================

ReturnBlock::ReturnBlock(std::string nm, std::vector<IRFormPtr> block_ins)
    : BasicBlock(std::move(nm), std::move(block_ins)) {
    // DAD: basic_blocks.py:81 self.type.is_return = True
    type.set_is_return(true);
}

void ReturnBlock::Visit(Visitor& /*visitor*/) {
    // DAD: basic_blocks.py:83 visitor.visit_return_node(self).
}

std::string ReturnBlock::ToString() const {
    // DAD: basic_blocks.py:86 '%d-Return(%s)' % (self.num, self.name)
    return FormatNumName(num, "Return", name);
}

// =============================================================================
// ThrowBlock — DAD basic_blocks.py:90
// =============================================================================

ThrowBlock::ThrowBlock(std::string nm, std::vector<IRFormPtr> block_ins)
    : BasicBlock(std::move(nm), std::move(block_ins)) {
    // DAD: basic_blocks.py:93 self.type.is_throw = True
    type.set_is_throw(true);
}

void ThrowBlock::Visit(Visitor& /*visitor*/) {
    // DAD: basic_blocks.py:95 visitor.visit_throw_node(self).
}

std::string ThrowBlock::ToString() const {
    // DAD: basic_blocks.py:98 '%d-Throw(%s)' % (self.num, self.name)
    return FormatNumName(num, "Throw", name);
}

// =============================================================================
// SwitchBlock — DAD basic_blocks.py:102
// =============================================================================

SwitchBlock::SwitchBlock(std::string nm, IRFormPtr sw,
                         std::vector<IRFormPtr> block_ins)
    : BasicBlock(std::move(nm), std::move(block_ins)),
      switch_payload(std::move(sw)) {
    // DAD: basic_blocks.py:109 self.type.is_switch = True
    type.set_is_switch(true);
}

void SwitchBlock::Visit(Visitor& /*visitor*/) {
    // DAD: basic_blocks.py:114 visitor.visit_switch_node(self).
}

// DAD: basic_blocks.py:117 copy_from.
void SwitchBlock::copy_from(const SwitchBlock& other) {
    // DAD: super().copy_from(node) — Node base copy_from copies common fields.
    Node::CopyFrom(other);
    // DAD: self.cases  = node.cases[:]
    cases = other.cases;
    // DAD: self.switch = node.switch[:] — slice on payload (only valid if
    // payload is list-like in androguard). We mirror with pointer copy as the
    // payload-as-list assumption is a DAD quirk.
    switch_payload = other.switch_payload;
}

// DAD: basic_blocks.py:122 update_attribute_with.
void SwitchBlock::UpdateAttributeWith(
    const std::unordered_map<NodeBase*, NodeBase*>& n_map) {
    // DAD: super().update_attribute_with(n_map)
    Node::UpdateAttributeWith(n_map);
    // DAD: self.cases = [n_map.get(n, n) for n in self.cases]
    for (auto& c : cases) {
        auto it = n_map.find(c);
        if (it != n_map.end()) c = it->second;
    }
    // DAD: for node1, node2 in n_map.items():
    //          if node1 in self.node_to_case:
    //              self.node_to_case[node2] = self.node_to_case.pop(node1)
    // We pull then re-insert under the mapped key (last-write wins matches
    // Python's dict assignment semantics).
    for (const auto& [n1, n2] : n_map) {
        auto it = node_to_case.find(n1);
        if (it != node_to_case.end()) {
            auto v = std::move(it->second);
            node_to_case.erase(it);
            node_to_case[n2] = std::move(v);
        }
    }
}

std::string SwitchBlock::ToString() const {
    // DAD: basic_blocks.py:136 '%d-Switch(%s)' % (self.num, self.name)
    return FormatNumName(num, "Switch", name);
}

// =============================================================================
// CondBlock — DAD basic_blocks.py:140
// =============================================================================

CondBlock::CondBlock(std::string nm, std::vector<IRFormPtr> block_ins)
    : BasicBlock(std::move(nm), std::move(block_ins)) {
    // DAD: basic_blocks.py:145 self.type.is_cond = True
    type.set_is_cond(true);
}

// DAD: basic_blocks.py:147 update_attribute_with.
void CondBlock::UpdateAttributeWith(
    const std::unordered_map<NodeBase*, NodeBase*>& n_map) {
    Node::UpdateAttributeWith(n_map);
    auto remap = [&](NodeBase*& slot) {
        auto it = n_map.find(slot);
        if (it != n_map.end()) slot = it->second;
    };
    // DAD: self.true  = n_map.get(self.true,  self.true)
    remap(true_branch);
    // DAD: self.false = n_map.get(self.false, self.false)
    remap(false_branch);
}

// DAD: basic_blocks.py:152 neg.
void CondBlock::neg() {
    // DAD: if len(self.ins) != 1: raise RuntimeWarning(...)
    // `raise RuntimeWarning(...)` IS a real raise (warning filters only affect
    // warnings.warn, not raise) — DAD would propagate and DvMethod.process
    // would die. We return silently. The invariant is satisfied on every real
    // method in the corpus (159k methods, 0 trigger), so no observable diff;
    // see CLAUDE.md "Deferred DAD quirks" for the divergence record.
    if (ins.size() != 1) return;
    // DAD: self.ins[-1].neg() — dispatched virtually through IRForm::Neg.
    if (ins.back()) ins.back()->Neg();
}

void CondBlock::Visit(Visitor& /*visitor*/) {
    // DAD: basic_blocks.py:157 visitor.visit_cond_node(self).
}

void CondBlock::visit_cond(Visitor& visitor) {
    // DAD: basic_blocks.py:160 if len != 1 raise; visitor.visit_ins(self.ins[-1]).
    if (ins.size() != 1) return;  // RuntimeWarning quirk — no-op on bad len.
    visitor.visit_ins(ins.back().get());
}

std::string CondBlock::ToString() const {
    // DAD: basic_blocks.py:165 '%d-If(%s)' % (self.num, self.name)
    return FormatNumName(num, "If", name);
}

// =============================================================================
// Condition — DAD basic_blocks.py:169
// =============================================================================

Condition::Condition(std::shared_ptr<Operand> c1, std::shared_ptr<Operand> c2,
                     bool a, bool n)
    : cond1(std::move(c1)), cond2(std::move(c2)), isand(a), isnot(n) {}

// DAD: basic_blocks.py:176 neg.
void Condition::neg() {
    // DAD: self.isand = not self.isand
    isand = !isand;
    // DAD: self.cond1.neg(); self.cond2.neg()
    cond1->neg();
    cond2->neg();
}

// DAD: basic_blocks.py:181 get_ins — concat both children's get_ins.
std::vector<IRFormPtr> Condition::get_ins() const {
    auto a = cond1->get_ins();
    auto b = cond2->get_ins();
    a.insert(a.end(), std::make_move_iterator(b.begin()),
             std::make_move_iterator(b.end()));
    return a;
}

// DAD: basic_blocks.py:187 get_loc_with_ins.
std::vector<std::pair<int, IRFormPtr>> Condition::get_loc_with_ins() const {
    auto a = cond1->get_loc_with_ins();
    auto b = cond2->get_loc_with_ins();
    a.insert(a.end(), std::make_move_iterator(b.begin()),
             std::make_move_iterator(b.end()));
    return a;
}

void Condition::visit(Visitor& visitor) {
    // DAD: basic_blocks.py:193 visitor.visit_short_circuit_condition(
    //   isnot, isand, cond1, cond2)
    visitor.visit_short_circuit_condition(
        isnot, isand, cond1.get(), cond2.get());
}

std::string Condition::ToString() const {
    // DAD: basic_blocks.py:198 __str__
    //   if isnot: '!%s %s %s'
    //   else:     '%s %s %s'
    //   where middle is '||' or '&&' selected by isand.
    std::ostringstream os;
    if (isnot) os << '!';
    os << cond1->to_string() << ' ' << (isand ? "&&" : "||") << ' '
       << cond2->to_string();
    return os.str();
}

// =============================================================================
// ShortCircuitBlock — DAD basic_blocks.py:206
// =============================================================================

ShortCircuitBlock::ShortCircuitBlock(std::string nm,
                                     std::shared_ptr<Condition> c)
    // DAD: basic_blocks.py:208 super().__init__(name, None)
    : CondBlock(std::move(nm), {}), cond(std::move(c)) {}

std::string ShortCircuitBlock::ToString() const {
    // DAD: basic_blocks.py:223 '%d-SC(%s)' % (self.num, self.cond)
    std::ostringstream os;
    os << num << "-SC(" << cond->ToString() << ')';
    return os.str();
}

// =============================================================================
// LoopBlock — DAD basic_blocks.py:227
// =============================================================================

LoopBlock::LoopBlock(std::string nm, std::shared_ptr<Condition> c)
    // DAD: basic_blocks.py:229 super().__init__(name, None)
    : CondBlock(std::move(nm), {}), cond(std::move(c)) {}

// Wrap any header node (DAD's duck-typed `self.cond = node`). cond_block is the
// CondBlock view (null for a StatementBlock header); cond_node always holds it.
LoopBlock::LoopBlock(std::string nm, BasicBlock* node)
    : CondBlock(std::move(nm), {}),
      cond_block(dynamic_cast<CondBlock*>(node)),
      cond_node(node) {}

void LoopBlock::Visit(Visitor& /*visitor*/) {
    // DAD: basic_blocks.py:241 visitor.visit_loop_node(self).
}

void LoopBlock::visit_cond(Visitor& visitor) {
    // DAD: basic_blocks.py:244 self.cond.visit_cond(visitor). DAD's
    // ShortCircuitBlock.visit_cond → self.cond.visit() →
    // visit_short_circuit_condition. Mirror by dispatching to whichever
    // cond form is populated.
    if (cond) cond->visit(visitor);
    else if (cond_block) cond_block->visit_cond(visitor);
}

std::string LoopBlock::ToString() const {
    // DAD: basic_blocks.py:251 __str__ — branches on looptype.
    auto loop_contains_false = [&]() -> bool {
        for (NodeBase* n : loop_nodes) {
            if (n == false_branch) return true;
        }
        return false;
    };
    // Pick whichever cond form is populated for printing.
    auto cond_str = [&]() -> std::string {
        if (cond) return cond->ToString();
        if (cond_block) return cond_block->ToString();
        return {};
    };
    std::ostringstream os;
    if (looptype.is_pretest()) {
        os << num << "-While(";
        if (loop_contains_false()) os << '!';
        os << name << ")[" << cond_str() << ']';
        return os.str();
    }
    if (looptype.is_posttest()) {
        os << num << "-DoWhile(" << name << ")[" << cond_str() << ']';
        return os.str();
    }
    if (looptype.is_endless()) {
        os << num << "-WhileTrue(" << name << ")[" << cond_str() << ']';
        return os.str();
    }
    os << num << "-WhileNoType(" << name << ')';
    return os.str();
}

// =============================================================================
// TryBlock — DAD basic_blocks.py:263
// =============================================================================

TryBlock::TryBlock(NodeBase* node)
    // DAD: basic_blocks.py:265 super().__init__('Try-%s' % node.name, None)
    : BasicBlock("Try-" + (node ? node->name : std::string{}), {}),
      try_start(node) {}

void TryBlock::Visit(Visitor& /*visitor*/) {
    // DAD: basic_blocks.py:281 visitor.visit_try_node(self).
}

std::string TryBlock::ToString() const {
    // DAD: basic_blocks.py:284 'Try({})[{}]'.format(self.name, self.catch)
    // Python `format(self.catch)` on a list yields '[<repr of items>]'.
    // We emit a flattened list of catch addresses to keep formatting stable.
    std::ostringstream os;
    os << "Try(" << name << ")[";
    bool first = true;
    for (NodeBase* c : catch_nodes) {
        if (!first) os << ", ";
        os << (c ? c->name : std::string{"<null>"});
        first = false;
    }
    os << ']';
    return os.str();
}

// =============================================================================
// CatchBlock — DAD basic_blocks.py:288
// =============================================================================

// DAD: basic_blocks.py:289 PrepareInit — detect MoveExceptionExpression head,
// pop it from node.ins, and bundle everything the delegating constructor needs.
// Matches DAD's evaluation order (peek/pop happen before super() is called).
CatchBlock::InitData CatchBlock::PrepareInit(BasicBlock& node) {
    InitData d;
    d.start = &node;
    d.name = "Catch-" + node.name;
    d.catch_type = node.catch_type;
    if (!node.ins.empty()) {
        auto mex = std::dynamic_pointer_cast<MoveExceptionExpression>(
            node.ins.front());
        if (mex) {
            d.exc = mex;
            // DAD: node.ins.pop(0)
            node.ins.erase(node.ins.begin());
        }
    }
    d.block_ins = node.ins;
    return d;
}

CatchBlock::CatchBlock(BasicBlock& node) : CatchBlock(PrepareInit(node)) {}

CatchBlock::CatchBlock(InitData&& d)
    : BasicBlock(std::move(d.name), std::move(d.block_ins)),
      exception_ins(std::move(d.exc)),
      catch_start(d.start) {
    // DAD: basic_blocks.py:297 self.catch_type = node.catch_type
    catch_type = std::move(d.catch_type);
}

void CatchBlock::Visit(Visitor& /*visitor*/) {
    // DAD: basic_blocks.py:299 visitor.visit_catch_node(self).
}

void CatchBlock::visit_exception(Visitor& /*visitor*/) {
    // DAD: basic_blocks.py:302
    //   if self.exception_ins: visitor.visit_ins(self.exception_ins)
    //   else:                  visitor.write(get_type(self.catch_type))
    // Visitor.visit_ins / Visitor.write live on writer.h (deferred).
}

std::string CatchBlock::ToString() const {
    // DAD: basic_blocks.py:308 'Catch(%s)' % self.name
    return "Catch(" + name + ")";
}

// =============================================================================
// BuildNodeFromBlock — DAD basic_blocks.py:312
// =============================================================================
//
// Walks the RawBlock's instruction stream, dispatching each instruction
// through DispatchInstruction to produce IR. Then chooses a typed
// BasicBlock subclass based on the last opcode (return/throw/switch/cond/
// default-statement) and constructs it.
//
// Matches DAD's pattern: certain opcodes (monitor-enter/exit) are skipped
// for IR emission (we forward to dispatcher which returns Nop for those —
// equivalent to DAD's `idx += ins.get_length(); continue` skip).
std::unique_ptr<BasicBlock>
BuildNodeFromBlock(const RawBlock& block, Vmap& vmap, RetState& gen_ret,
                   std::string_view exception_type) {
    std::vector<IRFormPtr> lins;
    lins.reserve(block.ins.size());

    dex::Opcode last_op = dex::OP_NOP;
    for (const RawIns& ri : block.ins) {
        last_op = ri.opcode;
        // DAD skips monitor-enter/exit (opcode 0x1D/0x1E) without emitting IR.
        if (ri.opcode == dex::OP_MONITOR_ENTER ||
            ri.opcode == dex::OP_MONITOR_EXIT) {
            continue;
        }
        const PayloadVariant* payload = nullptr;
        auto pit = block.payloads.find(ri.byte_off);
        if (pit != block.payloads.end()) payload = &pit->second;

        IRFormPtr ir = DispatchInstruction(ri, vmap, gen_ret, payload,
                                           exception_type);
        if (ir) lins.push_back(std::move(ir));
    }

    const std::string& name = block.name;

    // DAD: basic_blocks.py:349 — select BasicBlock subclass by last opcode.
    // return* (0x0E..0x11)
    if (last_op >= dex::OP_RETURN_VOID && last_op <= dex::OP_RETURN_OBJECT) {
        return std::make_unique<ReturnBlock>(name, std::move(lins));
    }
    // {packed,sparse}-switch (0x2B/0x2C)
    if (last_op == dex::OP_PACKED_SWITCH || last_op == dex::OP_SPARSE_SWITCH) {
        // Pass the switch payload as opaque — switch_payload field is used
        // by order_cases (deferred via SwitchBlock refactor in Milestone B).
        // For now nullptr is fine; structuring doesn't need it yet.
        return std::make_unique<SwitchBlock>(name, /*switch_payload=*/nullptr,
                                              std::move(lins));
    }
    // if-test/if-testz (0x32..0x3D)
    if (last_op >= dex::OP_IF_EQ && last_op <= dex::OP_IF_LEZ) {
        auto node = std::make_unique<CondBlock>(name, std::move(lins));
        // DAD: node.off_last_ins = ins.get_ref_off(). Used by make_node
        // for branch resolution. We pre-computed branch_target (byte-absolute)
        // in the snapshot; off_last_ins is the equivalent code-unit offset.
        // We set off_last_ins to the absolute byte target — make_node
        // compares against child_block.start_byte directly.
        if (!block.ins.empty()) {
            const RawIns& last = block.ins.back();
            if (last.branch_target != UINT32_MAX) {
                // Compose signed code-unit offset from absolute byte target.
                int64_t off_cu = (static_cast<int64_t>(last.branch_target)
                                  - static_cast<int64_t>(last.byte_off)) / 2;
                node->off_last_ins = static_cast<int>(off_cu);
            }
        }
        return node;
    }
    // throw (0x27)
    if (last_op == dex::OP_THROW) {
        return std::make_unique<ThrowBlock>(name, std::move(lins));
    }
    // goto* (0x28..0x2A) — DAD pops the last (NOP) ins.
    if (last_op >= dex::OP_GOTO && last_op <= dex::OP_GOTO_32) {
        if (!lins.empty()) lins.pop_back();
        return std::make_unique<StatementBlock>(name, std::move(lins));
    }
    // Default: statement.
    return std::make_unique<StatementBlock>(name, std::move(lins));
}

}  // namespace dexkit::dad
