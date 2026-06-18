// visitor.h — DAD-faithful Visitor base for Writer / JSONWriter.
//
// Method signatures match DAD's writer.py exactly so Writer override bodies
// can be 1:1 ports. IRForm::Accept(Visitor&) dispatches per DAD's IR.visit().
//
// Default implementations are no-ops so subclasses (Writer, etc.) override
// only what they need.

#pragma once

#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

#include "instruction.h"  // IRForm + variant types (Constant, Variable, etc.)

namespace dexkit::dad {

class StatementBlock;
class ReturnBlock;
class ThrowBlock;
class SwitchBlock;
class CondBlock;
class LoopBlock;
class TryBlock;
class CatchBlock;
class FillArrayExpression;     // for visit_fill_array's payload-typed param
class MoveExceptionExpression; // visit_move_exception's data param
class NewInstance;             // visit_new's data param
class InvokeInstruction;       // visit_invoke's invokeInstr param

class Visitor {
public:
    virtual ~Visitor() = default;

    // ─── Block-level (called from BasicBlock::Visit) ──────────────────────
    virtual void visit_statement_node(StatementBlock*)              {}
    virtual void visit_return_node(ReturnBlock*)                    {}
    virtual void visit_throw_node(ThrowBlock*)                      {}
    virtual void visit_switch_node(SwitchBlock*)                    {}
    virtual void visit_cond_node(CondBlock*)                        {}
    virtual void visit_loop_node(LoopBlock*)                        {}
    virtual void visit_try_node(TryBlock*)                          {}
    virtual void visit_catch_node(CatchBlock*)                      {}
    // DAD: visit_short_circuit_condition(nnot, aand, cond1, cond2) — cond1/2
    // are short-circuit operands (CondBlock-flavored, via Condition::Operand).
    // Forward-declared via basic_blocks.h is awkward (header cycle); we
    // accept `void*` and rely on the WriterImpl downcast convention. Since
    // visit_short_circuit_condition is only called from Condition::visit which
    // knows the type, this is safe.
    virtual void visit_short_circuit_condition(
        bool isnot, bool isand, void* cond1, void* cond2)           {}

    // ─── IR-level (called from IRForm::Accept) ────────────────────────────
    // visit_ins is the generic entry — most IR's Accept dispatches into a
    // more specific visit_X. Writer rarely overrides visit_ins itself.
    virtual void visit_ins(IRForm* op);                              // default → op->Accept(*this)

    virtual void visit_decl(Variable* /*var*/)                      {}
    // visit_constant: takes int, double, or string depending on Constant.type.
    // C++: split into three overloads for type safety.
    virtual void visit_constant_int(int64_t /*value*/)              {}
    virtual void visit_constant_double(double /*value*/)            {}
    virtual void visit_constant_string(std::string_view /*value*/)  {}
    // Boolean (Constant.type == "Z") — emitted as the bare keyword true/false,
    // NOT as a quoted string. Kept separate from visit_constant_string so a real
    // String constant whose value happens to be "true"/"false" still gets quoted.
    virtual void visit_constant_bool(bool /*value*/)                {}
    virtual void visit_base_class(std::string_view /*cls*/)         {}
    virtual void visit_variable(Variable* /*var*/)                  {}
    // DAD: visit_param(self.v, data=self.type) — int register + type str.
    virtual void visit_param(std::string_view /*name*/,
                              std::string_view /*type_desc*/)        {}
    virtual void visit_this()                                       {}
    virtual void visit_super()                                      {}

    virtual void visit_assign(IRForm* /*lhs*/, IRForm* /*rhs*/)     {}
    virtual void visit_move(IRForm* /*lhs*/, IRForm* /*rhs*/)       {}
    virtual void visit_move_result(IRForm* /*lhs*/, IRForm* /*rhs*/) {}
    virtual void visit_astore(IRForm* /*array*/, IRForm* /*index*/,
                              IRForm* /*rhs*/)                       {}
    virtual void visit_put_static(std::string_view /*cls*/,
                                  std::string_view /*name*/,
                                  std::string_view /*ftype*/,
                                  IRForm* /*rhs*/)                   {}
    virtual void visit_put_instance(IRForm* /*lhs*/,
                                    std::string_view /*name*/,
                                    std::string_view /*ftype*/,
                                    IRForm* /*rhs*/)                 {}
    virtual void visit_new(std::string_view /*atype*/,
                           NewInstance* /*data*/)                    {}

    // DAD: visit_invoke(name, base, ptype, rtype, args, invokeInstr)
    virtual void visit_invoke(std::string_view /*name*/,
                              IRForm* /*base*/,
                              const std::vector<std::string>& /*ptype*/,
                              std::string_view /*rtype*/,
                              const std::vector<IRForm*>& /*args*/,
                              InvokeInstruction* /*invokeInstr*/)    {}

    virtual void visit_return_void()                                {}
    virtual void visit_return(IRForm* /*arg*/)                      {}
    virtual void visit_nop()                                        {}
    virtual void visit_switch(IRForm* /*arg*/)                      {}
    virtual void visit_check_cast(IRForm* /*arg*/,
                                  std::string_view /*atype*/)        {}
    virtual void visit_aload(IRForm* /*array*/, IRForm* /*index*/)  {}
    virtual void visit_alength(IRForm* /*array*/)                   {}
    virtual void visit_new_array(std::string_view /*atype*/,
                                 IRForm* /*size*/)                   {}
    // DAD: visit_filled_new_array(atype, size, args)
    virtual void visit_filled_new_array(std::string_view /*atype*/,
                                        int /*size*/,
                                        const std::vector<IRForm*>& /*args*/) {}
    // DAD: visit_fill_array(array, value) where value is the FillArrayPayload
    // object (slicer ArrayData* or our PayloadFillArray). We pass the FillArray
    // IR so Writer can extract the payload data.
    virtual void visit_fill_array(IRForm* /*array*/,
                                  FillArrayExpression* /*owner*/)    {}
    virtual void visit_move_exception(Variable* /*var*/,
                                      MoveExceptionExpression* /*data*/) {}
    virtual void visit_monitor_enter(IRForm* /*ref*/)               {}
    virtual void visit_monitor_exit(IRForm* /*ref*/)                {}
    virtual void visit_throw(IRForm* /*ref*/)                       {}
    // `etype` is the expression's own Dalvik type ("D"/"F" for double/float
    // ops) — the reliable F/D context for reinterpreting raw-IEEE-bits integer
    // constant operands (an operand variable may not be inferred as D, but the
    // operation is).
    virtual void visit_binary_expression(std::string_view /*op*/,
                                          std::string_view /*etype*/,
                                          IRForm* /*arg1*/,
                                          IRForm* /*arg2*/)           {}
    virtual void visit_unary_expression(std::string_view /*op*/,
                                         IRForm* /*arg*/)             {}
    virtual void visit_cast(std::string_view /*op*/,
                            IRForm* /*arg*/)                          {}
    virtual void visit_cond_expression(std::string_view /*op*/,
                                        std::string_view /*etype*/,
                                        IRForm* /*arg1*/,
                                        IRForm* /*arg2*/)              {}
    virtual void visit_condz_expression(std::string_view /*op*/,
                                         IRForm* /*arg*/)              {}
    virtual void visit_get_instance(IRForm* /*arg*/,
                                     std::string_view /*name*/,
                                     std::string_view /*ftype*/)      {}
    virtual void visit_get_static(std::string_view /*cls*/,
                                   std::string_view /*name*/)         {}

    // ─── Text-emission utilities (Writer-only) ────────────────────────────
    virtual void write(std::string_view)                            {}
    virtual void inc_ind(int = 1)                                   {}
    virtual void dec_ind(int = 1)                                   {}
    virtual void end_ins()                                          {}
    virtual void write_ind()                                        {}

protected:
    Visitor() = default;
};

}  // namespace dexkit::dad
