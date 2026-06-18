// instruction_accept.cpp — IRForm::Accept overrides.
// DAD: each class's visit() method ports to Accept(Visitor&) here.

#include "instruction.h"
#include "visitor.h"
#include "util.h"

namespace dexkit::dad {

namespace {
IRForm* MapGet(const IRForm& owner, const std::string& key) {
    auto it = owner.var_map.find(key);
    return it == owner.var_map.end() ? nullptr : it->second.get();
}
}  // namespace

// Visitor::visit_ins default — re-enter via Accept (matches DAD's
// `op.visit(self)` recursive dispatch from one IR to its operands).
void Visitor::visit_ins(IRForm* op) {
    if (op) op->Accept(*this);
}

// =============================================================================
// Identity / literal nodes
// =============================================================================

void Constant::Accept(Visitor& v) {
    if (type == "Z") {
        int64_t i = std::holds_alternative<int64_t>(cst_)
                          ? std::get<int64_t>(cst_) : 0;
        v.visit_constant_bool(i != 0);
        return;
    }
    if (type == "Ljava/lang/Class;") {
        std::string_view s;
        if (std::holds_alternative<std::string>(cst_))
            s = std::get<std::string>(cst_);
        v.visit_base_class(s);
        return;
    }
    if (type == "I" || type == "J" || type == "B") {
        v.visit_constant_int(cst2_);
        return;
    }
    if (std::holds_alternative<std::string>(cst_)) {
        v.visit_constant_string(std::get<std::string>(cst_));
    } else if (std::holds_alternative<double>(cst_)) {
        v.visit_constant_double(std::get<double>(cst_));
    } else if (std::holds_alternative<int64_t>(cst_)) {
        v.visit_constant_int(std::get<int64_t>(cst_));
    }
}

void BaseClass::Accept(Visitor& v) {
    v.visit_base_class(cls_);
}

void Variable::Accept(Visitor& v) { v.visit_variable(this); }

void Param::Accept(Visitor& v) { v.visit_param(v_, type); }

void ThisParam::Accept(Visitor& v) {
    if (super_flag) v.visit_super();
    else            v.visit_this();
}

// =============================================================================
// Assign / Move / MoveResult
// =============================================================================
void AssignExpression::Accept(Visitor& v) {
    IRForm* lhs = lhs_.has_value() ? MapGet(*this, *lhs_) : nullptr;
    v.visit_assign(lhs, rhs_.get());
}

void MoveExpression::Accept(Visitor& v) {
    v.visit_move(MapGet(*this, lhs_), MapGet(*this, rhs_));
}

void MoveResultExpression::Accept(Visitor& v) {
    v.visit_move_result(MapGet(*this, lhs_), MapGet(*this, rhs_));
}

// =============================================================================
// Array / Field write
// =============================================================================
void ArrayStoreInstruction::Accept(Visitor& v) {
    v.visit_astore(MapGet(*this, array_), MapGet(*this, index_),
                   MapGet(*this, rhs_));
}

void StaticInstruction::Accept(Visitor& v) {
    v.visit_put_static(cls_, name_, ftype(), MapGet(*this, rhs_));
}

void InstanceInstruction::Accept(Visitor& v) {
    v.visit_put_instance(MapGet(*this, lhs_), name_, atype(), MapGet(*this, rhs_));
}

// =============================================================================
// new / invoke / return / nop / switch / check-cast
// =============================================================================
void NewInstance::Accept(Visitor& v) {
    v.visit_new(type, this);
}

void InvokeInstruction::Accept(Visitor& v) {
    std::vector<IRForm*> largs;
    largs.reserve(args_.size());
    for (const auto& a : args_) largs.push_back(MapGet(*this, a));
    v.visit_invoke(name_, MapGet(*this, base_), ptype_, rtype_, largs, this);
}

void InvokeRangeInstruction::Accept(Visitor& v) { InvokeInstruction::Accept(v); }
void InvokeDirectInstruction::Accept(Visitor& v) { InvokeInstruction::Accept(v); }
void InvokeStaticInstruction::Accept(Visitor& v) { InvokeInstruction::Accept(v); }

void ReturnInstruction::Accept(Visitor& v) {
    if (!arg_.has_value()) v.visit_return_void();
    else                    v.visit_return(MapGet(*this, *arg_));
}

void NopExpression::Accept(Visitor& v) { v.visit_nop(); }

void SwitchExpression::Accept(Visitor& v) {
    v.visit_switch(MapGet(*this, src_));
}

void CheckCastExpression::Accept(Visitor& v) {
    v.visit_check_cast(MapGet(*this, arg_), GetType(type));
}

// =============================================================================
// Array load / length / new / filled / fill
// =============================================================================
void ArrayLoadExpression::Accept(Visitor& v) {
    v.visit_aload(MapGet(*this, array_), MapGet(*this, idx_));
}

void ArrayLengthExpression::Accept(Visitor& v) {
    v.visit_alength(MapGet(*this, array_));
}

void NewArrayExpression::Accept(Visitor& v) {
    v.visit_new_array(type, MapGet(*this, size_));
}

void FilledArrayExpression::Accept(Visitor& v) {
    std::vector<IRForm*> largs;
    largs.reserve(args_.size());
    for (const auto& a : args_) largs.push_back(MapGet(*this, a));
    v.visit_filled_new_array(type, static_cast<int>(size_), largs);
}

void FillArrayExpression::Accept(Visitor& v) {
    v.visit_fill_array(MapGet(*this, reg_), this);
}

// =============================================================================
// Monitor / throw / move-exception
// =============================================================================
void MoveExceptionExpression::Accept(Visitor& v) {
    auto* var = dynamic_cast<Variable*>(MapGet(*this, ref_));
    v.visit_move_exception(var, this);
}

void MonitorEnterExpression::Accept(Visitor& v) {
    v.visit_monitor_enter(MapGet(*this, ref_));
}

void MonitorExitExpression::Accept(Visitor& v) {
    v.visit_monitor_exit(MapGet(*this, ref_));
}

void ThrowExpression::Accept(Visitor& v) {
    v.visit_throw(MapGet(*this, ref_));
}

// =============================================================================
// Binary / unary / cast / conditional / instance/static-expr
// =============================================================================
void BinaryExpression::Accept(Visitor& v) {
    v.visit_binary_expression(op_, MapGet(*this, arg1_), MapGet(*this, arg2_));
}

void BinaryCompExpression::Accept(Visitor& v) {
    v.visit_cond_expression(op_, MapGet(*this, arg1_), MapGet(*this, arg2_));
}

void UnaryExpression::Accept(Visitor& v) {
    v.visit_unary_expression(op_, MapGet(*this, arg_));
}

void CastExpression::Accept(Visitor& v) {
    v.visit_cast(op_, MapGet(*this, arg_));
}

void ConditionalExpression::Accept(Visitor& v) {
    v.visit_cond_expression(op_, MapGet(*this, arg1_), MapGet(*this, arg2_));
}

void ConditionalZExpression::Accept(Visitor& v) {
    v.visit_condz_expression(op_, MapGet(*this, arg_));
}

void InstanceExpression::Accept(Visitor& v) {
    v.visit_get_instance(MapGet(*this, arg_), name_, ftype_);
}

void StaticExpression::Accept(Visitor& v) {
    v.visit_get_static(cls_, name_);
}

}  // namespace dexkit::dad
