// opcode_ins.cpp — DAD opcode_ins.py port (chunk A).
// See include/opcode_ins.h for status and per-function DAD references.
//
// DAD: androguard/decompiler/opcode_ins.py

#include "opcode_ins.h"

#include <array>
#include <memory>

#include "util.h"

namespace dexkit::dad {

// DAD: opcode_ins.py:89 get_variables — single-arg path.
IRFormPtr GetVariable(Vmap& vmap, std::string_view variable) {
    std::string key{variable};
    auto it = vmap.find(key);
    if (it != vmap.end()) return it->second;
    auto v = std::make_shared<Variable>(variable);
    vmap.emplace(std::move(key), v);
    return v;
}

// DAD: opcode_ins.py:89 get_variables — multi-arg path.
std::vector<IRFormPtr> GetVariables(
        Vmap& vmap,
        std::initializer_list<std::string_view> variables) {
    std::vector<IRFormPtr> res;
    res.reserve(variables.size());
    for (auto v : variables) res.push_back(GetVariable(vmap, v));
    return res;
}

// DAD: opcode_ins.py:98 assign_const.
IRFormPtr AssignConst(std::string_view dest_reg, IRFormPtr cst, Vmap& vmap) {
    auto reg = GetVariable(vmap, dest_reg);
    return std::make_shared<AssignExpression>(std::move(reg), std::move(cst));
}

// DAD: opcode_ins.py:102 assign_cmp.
IRFormPtr AssignCmp(std::string_view val_a, std::string_view val_b,
                    std::string_view val_c, std::string_view cmp_type,
                    Vmap& vmap) {
    auto regs = GetVariables(vmap, {val_a, val_b, val_c});
    auto exp = std::make_shared<BinaryCompExpression>(
        Op::CMP, regs[1], regs[2], cmp_type);
    return std::make_shared<AssignExpression>(regs[0], std::move(exp));
}

// DAD: opcode_ins.py:108 load_array_exp.
IRFormPtr LoadArrayExp(std::string_view val_a, std::string_view val_b,
                       std::string_view val_c, std::string_view ar_type,
                       Vmap& vmap) {
    auto regs = GetVariables(vmap, {val_a, val_b, val_c});
    auto load = std::make_shared<ArrayLoadExpression>(regs[1], regs[2], ar_type);
    return std::make_shared<AssignExpression>(regs[0], std::move(load));
}

// DAD: opcode_ins.py:113 store_array_inst.
IRFormPtr StoreArrayInst(std::string_view val_a, std::string_view val_b,
                         std::string_view val_c, std::string_view ar_type,
                         Vmap& vmap) {
    auto regs = GetVariables(vmap, {val_a, val_b, val_c});
    return std::make_shared<ArrayStoreInstruction>(
        regs[0], regs[1], regs[2], ar_type);
}

// DAD: opcode_ins.py:118 assign_cast_exp.
IRFormPtr AssignCastExp(std::string_view val_a, std::string_view val_b,
                        std::string_view val_op, std::string_view op_type,
                        Vmap& vmap) {
    auto regs = GetVariables(vmap, {val_a, val_b});
    auto cast = std::make_shared<CastExpression>(val_op, op_type, regs[1]);
    return std::make_shared<AssignExpression>(regs[0], std::move(cast));
}

// DAD: opcode_ins.py:123 assign_binary_exp.
IRFormPtr AssignBinaryExp(std::string_view ins_aa, std::string_view ins_bb,
                          std::string_view ins_cc, std::string_view val_op,
                          std::string_view op_type, Vmap& vmap) {
    auto regs = GetVariables(vmap, {ins_aa, ins_bb, ins_cc});
    auto bin = std::make_shared<BinaryExpression>(
        val_op, regs[1], regs[2], op_type);
    return std::make_shared<AssignExpression>(regs[0], std::move(bin));
}

// DAD: opcode_ins.py:130 assign_binary_2addr_exp.
IRFormPtr AssignBinary2AddrExp(std::string_view ins_a, std::string_view ins_b,
                               std::string_view val_op,
                               std::string_view op_type, Vmap& vmap) {
    auto regs = GetVariables(vmap, {ins_a, ins_b});
    auto bin = std::make_shared<BinaryExpression2Addr>(
        val_op, regs[0], regs[1], op_type);
    return std::make_shared<AssignExpression>(regs[0], std::move(bin));
}

// DAD: opcode_ins.py:137 assign_lit.
IRFormPtr AssignLit(std::string_view op_type, int64_t val_cst,
                    std::string_view val_a, std::string_view val_b,
                    Vmap& vmap) {
    auto cst = std::make_shared<Constant>(ConstantValue{val_cst}, "I");
    auto regs = GetVariables(vmap, {val_a, val_b});
    auto bin = std::make_shared<BinaryExpressionLit>(op_type, regs[1], cst);
    return std::make_shared<AssignExpression>(regs[0], std::move(bin));
}

// =============================================================================
// Chunk B — single-opcode handlers.
// =============================================================================

namespace {

// Shared move-family body (move / movefrom16 / movewide / moveobject / etc.).
// `kind` records the move OPCODE class (beyond-DAD ground-truth for the
// type-inference pass — see MoveKind).
IRFormPtr MoveImpl(std::string_view dst, std::string_view src, Vmap& vmap,
                   MoveKind kind) {
    auto regs = GetVariables(vmap, {dst, src});
    auto mv = std::make_shared<MoveExpression>(regs[0], regs[1]);
    mv->set_move_kind(kind);
    return mv;
}

// Shared move-result body.
IRFormPtr MoveResultImpl(std::string_view dst, IRFormPtr ret, Vmap& vmap) {
    auto lhs = GetVariable(vmap, dst);
    return std::make_shared<MoveResultExpression>(std::move(lhs), std::move(ret));
}

// Shared return body.
IRFormPtr ReturnRegImpl(std::string_view src, Vmap& vmap) {
    return std::make_shared<ReturnInstruction>(GetVariable(vmap, src));
}

// Shared const body for primitive numeric (type 'I' or 'J').
IRFormPtr ConstNumImpl(std::string_view dst, int64_t value,
                       std::string_view atype, Vmap& vmap) {
    auto cst = std::make_shared<Constant>(ConstantValue{value}, atype);
    return AssignConst(dst, std::move(cst), vmap);
}

}  // namespace

// DAD: opcode_ins.py:147 nop
IRFormPtr Nop() { return std::make_shared<NopExpression>(); }

// DAD: opcode_ins.py:152-211 move family (10 variants, same body).
IRFormPtr Move(std::string_view a, std::string_view b, Vmap& v)              { return MoveImpl(a, b, v, MoveKind::Plain); }
IRFormPtr MoveFrom16(std::string_view aa, std::string_view bbbb, Vmap& v)    { return MoveImpl(aa, bbbb, v, MoveKind::Plain); }
IRFormPtr Move16(std::string_view aaaa, std::string_view bbbb, Vmap& v)      { return MoveImpl(aaaa, bbbb, v, MoveKind::Plain); }
IRFormPtr MoveWide(std::string_view a, std::string_view b, Vmap& v)          { return MoveImpl(a, b, v, MoveKind::Wide); }
IRFormPtr MoveWideFrom16(std::string_view aa, std::string_view bbbb, Vmap& v){ return MoveImpl(aa, bbbb, v, MoveKind::Wide); }
IRFormPtr MoveWide16(std::string_view aaaa, std::string_view bbbb, Vmap& v)  { return MoveImpl(aaaa, bbbb, v, MoveKind::Wide); }
IRFormPtr MoveObject(std::string_view a, std::string_view b, Vmap& v)        { return MoveImpl(a, b, v, MoveKind::Object); }
IRFormPtr MoveObjectFrom16(std::string_view aa, std::string_view bbbb, Vmap& v){return MoveImpl(aa, bbbb, v, MoveKind::Object);}
IRFormPtr MoveObject16(std::string_view aaaa, std::string_view bbbb, Vmap& v){ return MoveImpl(aaaa, bbbb, v, MoveKind::Object); }

// DAD: opcode_ins.py:215-229 move-result family.
IRFormPtr MoveResult(std::string_view aa, IRFormPtr ret, Vmap& v)       { return MoveResultImpl(aa, std::move(ret), v); }
IRFormPtr MoveResultWide(std::string_view aa, IRFormPtr ret, Vmap& v)   { return MoveResultImpl(aa, std::move(ret), v); }
IRFormPtr MoveResultObject(std::string_view aa, IRFormPtr ret, Vmap& v) { return MoveResultImpl(aa, std::move(ret), v); }

// DAD: opcode_ins.py:233 moveexception
IRFormPtr MoveException(std::string_view aa, std::string_view atype, Vmap& vmap) {
    // Catch-all handlers (handler with no explicit type in the exception
    // table) arrive with atype="". DAD's `get_type(None)` renders as
    // "Throwable"; mirror by defaulting to Ljava/lang/Throwable; here so
    // the catch variable gets a real type and the Writer doesn't emit
    // `catch (unknownType vN)`.
    std::string_view t = atype.empty() ? "Ljava/lang/Throwable;" : atype;
    return std::make_shared<MoveExceptionExpression>(
        GetVariable(vmap, aa), t);
}

// DAD: opcode_ins.py:239-258 return family.
IRFormPtr ReturnVoid() { return std::make_shared<ReturnInstruction>(nullptr); }
IRFormPtr ReturnReg(std::string_view aa, Vmap& v)    { return ReturnRegImpl(aa, v); }
IRFormPtr ReturnWide(std::string_view aa, Vmap& v)   { return ReturnRegImpl(aa, v); }
IRFormPtr ReturnObject(std::string_view aa, Vmap& v) { return ReturnRegImpl(aa, v); }

// DAD: opcode_ins.py:263-315 const family.
IRFormPtr Const4(std::string_view a, int64_t b, Vmap& v)              { return ConstNumImpl(a, b, "I", v); }
IRFormPtr Const16(std::string_view aa, int64_t bbbb, Vmap& v)         { return ConstNumImpl(aa, bbbb, "I", v); }
IRFormPtr Const(std::string_view aa, int64_t bbbbbbbb, Vmap& v)       { return ConstNumImpl(aa, bbbbbbbb, "I", v); }
// DAD: const/high16 — androguard's Instruction21h pre-shifts the raw 16-bit
// operand left by 16 (the dex encoding stores only the high 16 bits of the
// 32-bit int; the low 16 are zero). Our slicer hands us the raw `bbbb`, so
// we shift here to match DAD's value semantics. Without this, `1.0f` (bits
// 0x3F800000 = 1065353216) printed as the truncated 0x3F80 = 16256.
// Shift via uint64_t: a sign-extended negative `bbbb` (e.g. -1.0f high16 0xBF80)
// left-shifted as a signed int64 is UB before C++20; the unsigned idiom is
// well-defined and bit-identical on two's-complement. The F/D return fix
// (writer.cpp visit_return) reinterprets these bit patterns, so keep them exact.
IRFormPtr ConstHigh16(std::string_view aa, int64_t bbbb, Vmap& v)     { return ConstNumImpl(aa, static_cast<int64_t>(static_cast<uint64_t>(bbbb) << 16), "I", v); }
IRFormPtr ConstWide16(std::string_view aa, int64_t bbbb, Vmap& v)     { return ConstNumImpl(aa, bbbb, "J", v); }
IRFormPtr ConstWide32(std::string_view aa, int64_t bbbbbbbb, Vmap& v) { return ConstNumImpl(aa, bbbbbbbb, "J", v); }
IRFormPtr ConstWide(std::string_view aa, int64_t b64, Vmap& v)        { return ConstNumImpl(aa, b64, "J", v); }
// DAD: const-wide/high16 — same pre-shift, but to the high 16 bits of a
// 64-bit long (shift by 48).
IRFormPtr ConstWideHigh16(std::string_view aa, int64_t bbbb, Vmap& v) { return ConstNumImpl(aa, static_cast<int64_t>(static_cast<uint64_t>(bbbb) << 48), "J", v); }

// DAD: opcode_ins.py:319-340 const-string / const-class.
IRFormPtr ConstString(std::string_view aa, std::string_view raw_string,
                      Vmap& vmap) {
    auto cst = std::make_shared<Constant>(
        ConstantValue{std::string{raw_string}}, "Ljava/lang/String;");
    return AssignConst(aa, std::move(cst), vmap);
}
IRFormPtr ConstStringJumbo(std::string_view aa, std::string_view raw_string,
                           Vmap& vmap) {
    return ConstString(aa, raw_string, vmap);
}
IRFormPtr ConstClass(std::string_view aa, std::string_view kind, Vmap& vmap) {
    // DAD: Constant(util.get_type(ins.get_string()), 'Ljava/lang/Class;',
    //                descriptor=ins.get_string())
    auto cst = std::make_shared<Constant>(
        ConstantValue{GetType(kind)}, "Ljava/lang/Class;",
        std::nullopt, kind);
    return AssignConst(aa, std::move(cst), vmap);
}

// DAD: opcode_ins.py:344-353 monitor enter/exit.
IRFormPtr MonitorEnter(std::string_view aa, Vmap& vmap) {
    return std::make_shared<MonitorEnterExpression>(GetVariable(vmap, aa));
}
IRFormPtr MonitorExit(std::string_view aa, Vmap& vmap) {
    return std::make_shared<MonitorExitExpression>(GetVariable(vmap, aa));
}

// DAD: opcode_ins.py:357 check-cast.
IRFormPtr CheckCast(std::string_view aa, std::string_view translated_kind,
                    Vmap& vmap) {
    auto cast_var = GetVariable(vmap, aa);
    auto cast_type = GetType(translated_kind);
    auto cast_expr = std::make_shared<CheckCastExpression>(
        cast_var, cast_type, translated_kind);
    return std::make_shared<AssignExpression>(cast_var, std::move(cast_expr));
}

// DAD: opcode_ins.py:368 instance-of.
IRFormPtr InstanceOf(std::string_view a, std::string_view b,
                     std::string_view translated_kind, Vmap& vmap) {
    auto regs = GetVariables(vmap, {a, b});
    auto class_ref = std::make_shared<BaseClass>(
        GetType(translated_kind), translated_kind);
    auto exp = std::make_shared<BinaryExpression>(
        "instanceof", regs[1], class_ref, "Z");
    return std::make_shared<AssignExpression>(regs[0], std::move(exp));
}

// DAD: opcode_ins.py:380 array-length.
IRFormPtr ArrayLength(std::string_view a, std::string_view b, Vmap& vmap) {
    auto regs = GetVariables(vmap, {a, b});
    auto len = std::make_shared<ArrayLengthExpression>(regs[1]);
    return std::make_shared<AssignExpression>(regs[0], std::move(len));
}

// DAD: opcode_ins.py:387 new-instance.
IRFormPtr NewInstance_(std::string_view aa, std::string_view type_desc,
                       Vmap& vmap) {
    auto reg = GetVariable(vmap, aa);
    auto inst = std::make_shared<NewInstance>(type_desc);
    return std::make_shared<AssignExpression>(reg, std::move(inst));
}

// DAD: opcode_ins.py:395 new-array.
IRFormPtr NewArray(std::string_view a, std::string_view b,
                   std::string_view type_desc, Vmap& vmap) {
    auto regs = GetVariables(vmap, {a, b});
    auto exp = std::make_shared<NewArrayExpression>(regs[1], type_desc);
    return std::make_shared<AssignExpression>(regs[0], std::move(exp));
}

// DAD: opcode_ins.py:403 filled-new-array — count is ins.A; only first
// `count` registers are passed to FilledArrayExpression (DAD slices the list).
IRFormPtr FilledNewArray(int64_t count, std::string_view type_desc,
                         std::string_view c, std::string_view d,
                         std::string_view e, std::string_view f,
                         std::string_view g, IRFormPtr ret, Vmap& vmap) {
    std::array<std::string_view, 5> all = {c, d, e, f, g};
    std::vector<IRFormPtr> args;
    args.reserve(static_cast<size_t>(count));
    for (int64_t i = 0; i < count && i < 5; ++i) {
        args.push_back(GetVariable(vmap, all[i]));
    }
    auto exp = std::make_shared<FilledArrayExpression>(
        count, type_desc, args);
    return std::make_shared<AssignExpression>(std::move(ret), std::move(exp));
}

// DAD: opcode_ins.py:412 filled-new-array/range — bug-faithful: DAD
// declares `a, c, n = get_variables(vmap, ins.AA, ins.CCCC, ins.NNNN)` but
// then ignores `a` (count) and passes only `[c, n]` to FilledArrayExpression,
// despite the range being `cccc..nnnn` (a contiguous span). Faithful port:
// emit a 2-element FilledArrayExpression with first and last register.
IRFormPtr FilledNewArrayRange(int64_t count, std::string_view type_desc,
                              std::string_view cccc, std::string_view nnnn,
                              IRFormPtr ret, Vmap& vmap) {
    auto regs = GetVariables(vmap, {cccc, nnnn});
    auto exp = std::make_shared<FilledArrayExpression>(
        count, type_desc, regs);
    return std::make_shared<AssignExpression>(std::move(ret), std::move(exp));
}

// DAD: opcode_ins.py:421 fill-array-data.
IRFormPtr FillArrayData(std::string_view aa, std::vector<int64_t> value,
                        Vmap& vmap) {
    return std::make_shared<FillArrayExpression>(
        GetVariable(vmap, aa), std::move(value));
}

// DAD: opcode_ins.py:427 fill-array-data-payload — bug-faithful: DAD body
// is `return FillArrayExpression(None)` which would crash because the
// FillArrayExpression constructor dereferences `reg.v`. We throw to surface
// the broken upstream path; callers must not invoke this.
IRFormPtr FillArrayDataPayload() {
    throw std::logic_error(
        "fill-array-data-payload: DAD body crashes (None passed to "
        "FillArrayExpression). Drivers must not dispatch to this opcode.");
}

// DAD: opcode_ins.py:433 throw
IRFormPtr Throw(std::string_view aa, Vmap& vmap) {
    return std::make_shared<ThrowExpression>(GetVariable(vmap, aa));
}

// DAD: opcode_ins.py:439-450 goto family — all return NopExpression.
IRFormPtr Goto()   { return std::make_shared<NopExpression>(); }
IRFormPtr Goto16() { return std::make_shared<NopExpression>(); }
IRFormPtr Goto32() { return std::make_shared<NopExpression>(); }

// DAD: opcode_ins.py:454 packed-switch.
IRFormPtr PackedSwitch(std::string_view aa, int32_t branch, Vmap& vmap) {
    return std::make_shared<SwitchExpression>(GetVariable(vmap, aa), branch);
}

// DAD: opcode_ins.py:461 sparse-switch — identical body to packed-switch.
IRFormPtr SparseSwitch(std::string_view aa, int32_t branch, Vmap& vmap) {
    return std::make_shared<SwitchExpression>(GetVariable(vmap, aa), branch);
}

// =============================================================================
// Chunk C — cmp / if / aget+aput / iget+iput / sget+sput families.
// =============================================================================

namespace {

// Shared body for InstanceExpression-builder (iget family).
IRFormPtr IGetImpl(std::string_view a, std::string_view b,
                   std::string_view klass, std::string_view ftype,
                   std::string_view name, Vmap& vmap) {
    auto regs = GetVariables(vmap, {a, b});
    auto exp = std::make_shared<InstanceExpression>(
        regs[1], klass, ftype, name);
    return std::make_shared<AssignExpression>(regs[0], std::move(exp));
}

// Shared body for InstanceInstruction (iput family).
IRFormPtr IPutImpl(std::string_view a, std::string_view b,
                   std::string_view klass, std::string_view atype,
                   std::string_view name, Vmap& vmap) {
    auto regs = GetVariables(vmap, {a, b});
    return std::make_shared<InstanceInstruction>(
        regs[0], regs[1], klass, atype, name);
}

// Shared body for StaticExpression (sget family).
IRFormPtr SGetImpl(std::string_view aa, std::string_view klass,
                   std::string_view atype, std::string_view name,
                   Vmap& vmap) {
    auto exp = std::make_shared<StaticExpression>(klass, atype, name);
    auto reg = GetVariable(vmap, aa);
    return std::make_shared<AssignExpression>(std::move(reg), std::move(exp));
}

// Shared body for StaticInstruction (sput family).
IRFormPtr SPutImpl(std::string_view aa, std::string_view klass,
                   std::string_view ftype, std::string_view name,
                   Vmap& vmap) {
    auto reg = GetVariable(vmap, aa);
    return std::make_shared<StaticInstruction>(
        std::move(reg), klass, ftype, name);
}

}  // namespace

// DAD: opcode_ins.py:468-494 cmp-{l,g}-{float,double} / cmp-long.
IRFormPtr CmplFloat (std::string_view aa, std::string_view bb,
                     std::string_view cc, Vmap& v) { return AssignCmp(aa, bb, cc, "F", v); }
IRFormPtr CmpgFloat (std::string_view aa, std::string_view bb,
                     std::string_view cc, Vmap& v) { return AssignCmp(aa, bb, cc, "F", v); }
IRFormPtr CmplDouble(std::string_view aa, std::string_view bb,
                     std::string_view cc, Vmap& v) { return AssignCmp(aa, bb, cc, "D", v); }
IRFormPtr CmpgDouble(std::string_view aa, std::string_view bb,
                     std::string_view cc, Vmap& v) { return AssignCmp(aa, bb, cc, "D", v); }
IRFormPtr CmpLong   (std::string_view aa, std::string_view bb,
                     std::string_view cc, Vmap& v) { return AssignCmp(aa, bb, cc, "J", v); }

// DAD: opcode_ins.py:498-536 if-{eq,ne,lt,ge,gt,le}.
namespace {
IRFormPtr IfCondImpl(std::string_view op, std::string_view a,
                     std::string_view b, Vmap& vmap) {
    auto regs = GetVariables(vmap, {a, b});
    return std::make_shared<ConditionalExpression>(op, regs[0], regs[1]);
}
IRFormPtr IfZCondImpl(std::string_view op, std::string_view aa, Vmap& vmap) {
    return std::make_shared<ConditionalZExpression>(op, GetVariable(vmap, aa));
}
}  // namespace

IRFormPtr IfEq(std::string_view a, std::string_view b, Vmap& v) { return IfCondImpl(Op::EQUAL,   a, b, v); }
IRFormPtr IfNe(std::string_view a, std::string_view b, Vmap& v) { return IfCondImpl(Op::NEQUAL,  a, b, v); }
IRFormPtr IfLt(std::string_view a, std::string_view b, Vmap& v) { return IfCondImpl(Op::LOWER,   a, b, v); }
IRFormPtr IfGe(std::string_view a, std::string_view b, Vmap& v) { return IfCondImpl(Op::GEQUAL,  a, b, v); }
IRFormPtr IfGt(std::string_view a, std::string_view b, Vmap& v) { return IfCondImpl(Op::GREATER, a, b, v); }
IRFormPtr IfLe(std::string_view a, std::string_view b, Vmap& v) { return IfCondImpl(Op::LEQUAL,  a, b, v); }

IRFormPtr IfEqz(std::string_view aa, Vmap& v) { return IfZCondImpl(Op::EQUAL,   aa, v); }
IRFormPtr IfNez(std::string_view aa, Vmap& v) { return IfZCondImpl(Op::NEQUAL,  aa, v); }
IRFormPtr IfLtz(std::string_view aa, Vmap& v) { return IfZCondImpl(Op::LOWER,   aa, v); }
IRFormPtr IfGez(std::string_view aa, Vmap& v) { return IfZCondImpl(Op::GEQUAL,  aa, v); }
IRFormPtr IfGtz(std::string_view aa, Vmap& v) { return IfZCondImpl(Op::GREATER, aa, v); }
IRFormPtr IfLez(std::string_view aa, Vmap& v) { return IfZCondImpl(Op::LEQUAL,  aa, v); }

// DAD: opcode_ins.py:577-615 aget family.
// `aget` itself passes None for type — we pass empty string_view.
IRFormPtr AGet       (std::string_view aa, std::string_view bb,
                      std::string_view cc, Vmap& v) { return LoadArrayExp(aa, bb, cc, "",  v); }
IRFormPtr AGetWide   (std::string_view aa, std::string_view bb,
                      std::string_view cc, Vmap& v) { return LoadArrayExp(aa, bb, cc, "W", v); }
IRFormPtr AGetObject (std::string_view aa, std::string_view bb,
                      std::string_view cc, Vmap& v) { return LoadArrayExp(aa, bb, cc, "O", v); }
IRFormPtr AGetBoolean(std::string_view aa, std::string_view bb,
                      std::string_view cc, Vmap& v) { return LoadArrayExp(aa, bb, cc, "Z", v); }
IRFormPtr AGetByte   (std::string_view aa, std::string_view bb,
                      std::string_view cc, Vmap& v) { return LoadArrayExp(aa, bb, cc, "B", v); }
IRFormPtr AGetChar   (std::string_view aa, std::string_view bb,
                      std::string_view cc, Vmap& v) { return LoadArrayExp(aa, bb, cc, "C", v); }
IRFormPtr AGetShort  (std::string_view aa, std::string_view bb,
                      std::string_view cc, Vmap& v) { return LoadArrayExp(aa, bb, cc, "S", v); }

// DAD: opcode_ins.py:619-657 aput family.
IRFormPtr APut       (std::string_view aa, std::string_view bb,
                      std::string_view cc, Vmap& v) { return StoreArrayInst(aa, bb, cc, "",  v); }
IRFormPtr APutWide   (std::string_view aa, std::string_view bb,
                      std::string_view cc, Vmap& v) { return StoreArrayInst(aa, bb, cc, "W", v); }
IRFormPtr APutObject (std::string_view aa, std::string_view bb,
                      std::string_view cc, Vmap& v) { return StoreArrayInst(aa, bb, cc, "O", v); }
IRFormPtr APutBoolean(std::string_view aa, std::string_view bb,
                      std::string_view cc, Vmap& v) { return StoreArrayInst(aa, bb, cc, "Z", v); }
IRFormPtr APutByte   (std::string_view aa, std::string_view bb,
                      std::string_view cc, Vmap& v) { return StoreArrayInst(aa, bb, cc, "B", v); }
IRFormPtr APutChar   (std::string_view aa, std::string_view bb,
                      std::string_view cc, Vmap& v) { return StoreArrayInst(aa, bb, cc, "C", v); }
IRFormPtr APutShort  (std::string_view aa, std::string_view bb,
                      std::string_view cc, Vmap& v) { return StoreArrayInst(aa, bb, cc, "S", v); }

// DAD: opcode_ins.py:661-720 iget family (all 7 variants identical body).
IRFormPtr IGet       (std::string_view a, std::string_view b, std::string_view k,
                      std::string_view t, std::string_view n, Vmap& v) { return IGetImpl(a, b, k, t, n, v); }
IRFormPtr IGetWide   (std::string_view a, std::string_view b, std::string_view k,
                      std::string_view t, std::string_view n, Vmap& v) { return IGetImpl(a, b, k, t, n, v); }
IRFormPtr IGetObject (std::string_view a, std::string_view b, std::string_view k,
                      std::string_view t, std::string_view n, Vmap& v) { return IGetImpl(a, b, k, t, n, v); }
IRFormPtr IGetBoolean(std::string_view a, std::string_view b, std::string_view k,
                      std::string_view t, std::string_view n, Vmap& v) { return IGetImpl(a, b, k, t, n, v); }
IRFormPtr IGetByte   (std::string_view a, std::string_view b, std::string_view k,
                      std::string_view t, std::string_view n, Vmap& v) { return IGetImpl(a, b, k, t, n, v); }
IRFormPtr IGetChar   (std::string_view a, std::string_view b, std::string_view k,
                      std::string_view t, std::string_view n, Vmap& v) { return IGetImpl(a, b, k, t, n, v); }
IRFormPtr IGetShort  (std::string_view a, std::string_view b, std::string_view k,
                      std::string_view t, std::string_view n, Vmap& v) { return IGetImpl(a, b, k, t, n, v); }

// DAD: opcode_ins.py:724-776 iput family.
IRFormPtr IPut       (std::string_view a, std::string_view b, std::string_view k,
                      std::string_view t, std::string_view n, Vmap& v) { return IPutImpl(a, b, k, t, n, v); }
IRFormPtr IPutWide   (std::string_view a, std::string_view b, std::string_view k,
                      std::string_view t, std::string_view n, Vmap& v) { return IPutImpl(a, b, k, t, n, v); }
IRFormPtr IPutObject (std::string_view a, std::string_view b, std::string_view k,
                      std::string_view t, std::string_view n, Vmap& v) { return IPutImpl(a, b, k, t, n, v); }
IRFormPtr IPutBoolean(std::string_view a, std::string_view b, std::string_view k,
                      std::string_view t, std::string_view n, Vmap& v) { return IPutImpl(a, b, k, t, n, v); }
IRFormPtr IPutByte   (std::string_view a, std::string_view b, std::string_view k,
                      std::string_view t, std::string_view n, Vmap& v) { return IPutImpl(a, b, k, t, n, v); }
IRFormPtr IPutChar   (std::string_view a, std::string_view b, std::string_view k,
                      std::string_view t, std::string_view n, Vmap& v) { return IPutImpl(a, b, k, t, n, v); }
IRFormPtr IPutShort  (std::string_view a, std::string_view b, std::string_view k,
                      std::string_view t, std::string_view n, Vmap& v) { return IPutImpl(a, b, k, t, n, v); }

// DAD: opcode_ins.py:780-839 sget family.
IRFormPtr SGet       (std::string_view aa, std::string_view k, std::string_view t,
                      std::string_view n, Vmap& v) { return SGetImpl(aa, k, t, n, v); }
IRFormPtr SGetWide   (std::string_view aa, std::string_view k, std::string_view t,
                      std::string_view n, Vmap& v) { return SGetImpl(aa, k, t, n, v); }
IRFormPtr SGetObject (std::string_view aa, std::string_view k, std::string_view t,
                      std::string_view n, Vmap& v) { return SGetImpl(aa, k, t, n, v); }
IRFormPtr SGetBoolean(std::string_view aa, std::string_view k, std::string_view t,
                      std::string_view n, Vmap& v) { return SGetImpl(aa, k, t, n, v); }
IRFormPtr SGetByte   (std::string_view aa, std::string_view k, std::string_view t,
                      std::string_view n, Vmap& v) { return SGetImpl(aa, k, t, n, v); }
IRFormPtr SGetChar   (std::string_view aa, std::string_view k, std::string_view t,
                      std::string_view n, Vmap& v) { return SGetImpl(aa, k, t, n, v); }
IRFormPtr SGetShort  (std::string_view aa, std::string_view k, std::string_view t,
                      std::string_view n, Vmap& v) { return SGetImpl(aa, k, t, n, v); }

// DAD: opcode_ins.py:843-895 sput family.
IRFormPtr SPut       (std::string_view aa, std::string_view k, std::string_view t,
                      std::string_view n, Vmap& v) { return SPutImpl(aa, k, t, n, v); }
IRFormPtr SPutWide   (std::string_view aa, std::string_view k, std::string_view t,
                      std::string_view n, Vmap& v) { return SPutImpl(aa, k, t, n, v); }
IRFormPtr SPutObject (std::string_view aa, std::string_view k, std::string_view t,
                      std::string_view n, Vmap& v) { return SPutImpl(aa, k, t, n, v); }
IRFormPtr SPutBoolean(std::string_view aa, std::string_view k, std::string_view t,
                      std::string_view n, Vmap& v) { return SPutImpl(aa, k, t, n, v); }
IRFormPtr SPutByte   (std::string_view aa, std::string_view k, std::string_view t,
                      std::string_view n, Vmap& v) { return SPutImpl(aa, k, t, n, v); }
IRFormPtr SPutChar   (std::string_view aa, std::string_view k, std::string_view t,
                      std::string_view n, Vmap& v) { return SPutImpl(aa, k, t, n, v); }
IRFormPtr SPutShort  (std::string_view aa, std::string_view k, std::string_view t,
                      std::string_view n, Vmap& v) { return SPutImpl(aa, k, t, n, v); }

// =============================================================================
// Chunk D — invoke family.
// =============================================================================

// DAD: opcode_ins.py:898 get_args.
//
// Iterates param_type, picking a register from largs at the current offset,
// and advancing by util.get_type_size(type_) (1 for primitives/refs, 2 for J/D).
// If param_type has a single element (DAD's common case due to the
// get_params_type bug), returns [get_variables(vmap, args)] — i.e. wrapped
// in a single-element list. Otherwise returns get_variables(vmap, *args)
// which is a multi-element list.
std::vector<IRFormPtr> GetArgs(Vmap& vmap,
                               const std::vector<std::string>& param_type,
                               const std::vector<std::string>& largs) {
    if (param_type.size() > largs.size()) {
        // DAD: warns + returns []
        return {};
    }
    std::vector<std::string> args;
    size_t num_param = 0;
    for (const auto& t : param_type) {
        if (num_param >= largs.size()) break;
        args.push_back(largs[num_param]);
        num_param += GetTypeSize(t);
    }
    if (param_type.size() == 1) {
        return {GetVariable(vmap, args[0])};
    }
    std::vector<IRFormPtr> result;
    result.reserve(args.size());
    for (const auto& s : args) result.push_back(GetVariable(vmap, s));
    return result;
}

namespace {

// Build the largs vector for "small" (4-reg) invokes — d,e,f,g.
std::vector<std::string> BuildLargs4(std::string_view d, std::string_view e,
                                     std::string_view f, std::string_view g) {
    return {std::string{d}, std::string{e}, std::string{f}, std::string{g}};
}

// Build the largs vector for invoke-static which includes ins.C too.
std::vector<std::string> BuildLargs5(std::string_view c, std::string_view d,
                                     std::string_view e, std::string_view f,
                                     std::string_view g) {
    return {std::string{c}, std::string{d}, std::string{e},
            std::string{f}, std::string{g}};
}

}  // namespace

// DAD: opcode_ins.py:915 invoke-virtual.
IRFormPtr InvokeVirtual(const MethodRef& m,
                        std::string_view c, std::string_view d,
                        std::string_view e, std::string_view f,
                        std::string_view g, RetState& ret, Vmap& vmap) {
    auto largs = BuildLargs4(d, e, f, g);
    auto args = GetArgs(vmap, m.param_type, largs);
    auto c_reg = GetVariable(vmap, c);
    IRFormPtr returned = (m.ret_type == "V") ? IRFormPtr{} : ret.New();
    auto exp = std::make_shared<InvokeInstruction>(
        m.cls_name, m.name, c_reg, m.ret_type, m.param_type, args, m.triple);
    return std::make_shared<AssignExpression>(std::move(returned),
                                              std::move(exp));
}

// DAD: opcode_ins.py:933 invoke-super.
IRFormPtr InvokeSuper(const MethodRef& m,
                      std::string_view /*c*/, std::string_view d,
                      std::string_view e, std::string_view f,
                      std::string_view g, RetState& ret, Vmap& vmap) {
    auto largs = BuildLargs4(d, e, f, g);
    auto args = GetArgs(vmap, m.param_type, largs);
    auto superclass = std::make_shared<BaseClass>("super");
    IRFormPtr returned = (m.ret_type == "V") ? IRFormPtr{} : ret.New();
    auto exp = std::make_shared<InvokeInstruction>(
        m.cls_name, m.name, superclass, m.ret_type, m.param_type, args, m.triple);
    return std::make_shared<AssignExpression>(std::move(returned),
                                              std::move(exp));
}

// DAD: opcode_ins.py:957 invoke-direct — special-cases void <init>.
IRFormPtr InvokeDirect(const MethodRef& m,
                       std::string_view c, std::string_view d,
                       std::string_view e, std::string_view f,
                       std::string_view g, RetState& ret, Vmap& vmap) {
    auto largs = BuildLargs4(d, e, f, g);
    auto args = GetArgs(vmap, m.param_type, largs);
    auto base = GetVariable(vmap, c);
    IRFormPtr returned;
    if (m.ret_type == "V") {
        // DAD: isinstance(base, ThisParam) → None else returned=base+set_to(base).
        if (std::dynamic_pointer_cast<ThisParam>(base)) {
            returned = nullptr;
        } else {
            returned = base;
            ret.SetTo(base);
        }
    } else {
        returned = ret.New();
    }
    auto exp = std::make_shared<InvokeDirectInstruction>(
        m.cls_name, m.name, base, m.ret_type, m.param_type, args, m.triple);
    return std::make_shared<AssignExpression>(std::move(returned),
                                              std::move(exp));
}

// DAD: opcode_ins.py:982 invoke-static — largs include C, base is BaseClass.
IRFormPtr InvokeStatic(const MethodRef& m,
                       std::string_view c, std::string_view d,
                       std::string_view e, std::string_view f,
                       std::string_view g, RetState& ret, Vmap& vmap) {
    auto largs = BuildLargs5(c, d, e, f, g);
    auto args = GetArgs(vmap, m.param_type, largs);
    auto base = std::make_shared<BaseClass>(m.cls_name, m.original_cls_descriptor);
    IRFormPtr returned = (m.ret_type == "V") ? IRFormPtr{} : ret.New();
    auto exp = std::make_shared<InvokeStaticInstruction>(
        m.cls_name, m.name, base, m.ret_type, m.param_type, args, m.triple);
    return std::make_shared<AssignExpression>(std::move(returned),
                                              std::move(exp));
}

// DAD: opcode_ins.py:1000 invoke-interface — body identical to invoke-virtual.
IRFormPtr InvokeInterface(const MethodRef& m,
                          std::string_view c, std::string_view d,
                          std::string_view e, std::string_view f,
                          std::string_view g, RetState& ret, Vmap& vmap) {
    return InvokeVirtual(m, c, d, e, f, g, ret, vmap);
}

// DAD: opcode_ins.py:1018 invoke-virtual/range.
IRFormPtr InvokeVirtualRange(const MethodRef& m,
                             const std::vector<std::string>& regs,
                             RetState& ret, Vmap& vmap) {
    if (regs.empty()) {
        throw std::logic_error("InvokeVirtualRange: empty register range");
    }
    auto this_arg = GetVariable(vmap, regs[0]);
    std::vector<std::string> tail(regs.begin() + 1, regs.end());
    auto args = GetArgs(vmap, m.param_type, tail);
    IRFormPtr returned = (m.ret_type == "V") ? IRFormPtr{} : ret.New();
    std::vector<IRFormPtr> all_args;
    all_args.reserve(args.size() + 1);
    all_args.push_back(std::move(this_arg));
    for (auto& a : args) all_args.push_back(std::move(a));
    auto exp = std::make_shared<InvokeRangeInstruction>(
        m.cls_name, m.name, m.ret_type, m.param_type, std::move(all_args),
        m.triple);
    return std::make_shared<AssignExpression>(std::move(returned),
                                              std::move(exp));
}

// DAD: opcode_ins.py:1041 invoke-super/range.
IRFormPtr InvokeSuperRange(const MethodRef& m,
                           const std::vector<std::string>& regs,
                           RetState& ret, Vmap& vmap) {
    if (regs.empty()) {
        throw std::logic_error("InvokeSuperRange: empty register range");
    }
    std::vector<std::string> tail(regs.begin() + 1, regs.end());
    auto args = GetArgs(vmap, m.param_type, tail);
    // Beyond-DAD (root-cause of the `this = super.m()` invalid Java): DAD's
    // invokesuperrange sets `returned = base` (the receiver) for a VOID call,
    // producing an assignment to the receiver register. The NON-range
    // `invokesuper` nulls `returned` for void — and invoke-super is NEVER an
    // `<init>` (super constructor calls use invoke-direct), so the receiver never
    // needs to become the result. Match the non-range handler: null for void, so
    // a void super call renders as a bare `super.m(...);` in BOTH the text and the
    // AST (fixed at the IR builder, not masked in the Writer). `base`/`ret.SetTo`
    // are dropped — the void "result" was never read (no move-result follows a
    // void call), so the gen_ret chain is unaffected.
    IRFormPtr returned = (m.ret_type == "V") ? IRFormPtr{} : ret.New();
    auto superclass = std::make_shared<BaseClass>("super");
    std::vector<IRFormPtr> all_args;
    all_args.reserve(args.size() + 1);
    all_args.push_back(std::move(superclass));
    for (auto& a : args) all_args.push_back(std::move(a));
    auto exp = std::make_shared<InvokeRangeInstruction>(
        m.cls_name, m.name, m.ret_type, m.param_type, std::move(all_args),
        m.triple);
    return std::make_shared<AssignExpression>(std::move(returned),
                                              std::move(exp));
}

// DAD: opcode_ins.py:1069 invoke-direct/range — both this_arg AND base from regs[0].
IRFormPtr InvokeDirectRange(const MethodRef& m,
                            const std::vector<std::string>& regs,
                            RetState& ret, Vmap& vmap) {
    if (regs.empty()) {
        throw std::logic_error("InvokeDirectRange: empty register range");
    }
    auto this_arg = GetVariable(vmap, regs[0]);
    std::vector<std::string> tail(regs.begin() + 1, regs.end());
    auto args = GetArgs(vmap, m.param_type, tail);
    // DAD redundantly: base = get_variables(vmap, ins.CCCC) — same as this_arg.
    auto base = GetVariable(vmap, regs[0]);
    // Beyond-DAD (root-cause of the `this = this.priv()` / `this = super(...)`
    // invalid Java): DAD's invokedirectrange sets `returned = base` for a VOID
    // call UNCONDITIONALLY, unlike the NON-range `invokedirect`, which nulls it
    // when `base` is a ThisParam (a void `this.<init>()`/`super()` delegation or a
    // void `this.privateMethod()` must not assign to the receiver). Match the
    // non-range handler: for void, null when base is a ThisParam, else keep
    // `returned = base` + `ret.set_to` (the `newObj = new X()` constructor
    // pattern). Fixes text AND AST at the IR builder.
    IRFormPtr returned;
    if (m.ret_type == "V") {
        if (std::dynamic_pointer_cast<ThisParam>(base)) {
            returned = nullptr;
        } else {
            returned = base;
            ret.SetTo(base);
        }
    } else {
        returned = ret.New();
    }
    std::vector<IRFormPtr> all_args;
    all_args.reserve(args.size() + 1);
    all_args.push_back(std::move(this_arg));
    for (auto& a : args) all_args.push_back(std::move(a));
    auto exp = std::make_shared<InvokeRangeInstruction>(
        m.cls_name, m.name, m.ret_type, m.param_type, std::move(all_args),
        m.triple);
    return std::make_shared<AssignExpression>(std::move(returned),
                                              std::move(exp));
}

// DAD: opcode_ins.py:1097 invoke-static/range — no receiver, all regs are args.
IRFormPtr InvokeStaticRange(const MethodRef& m,
                            const std::vector<std::string>& regs,
                            RetState& ret, Vmap& vmap) {
    auto args = GetArgs(vmap, m.param_type, regs);
    auto base = std::make_shared<BaseClass>(m.cls_name, m.original_cls_descriptor);
    IRFormPtr returned = (m.ret_type == "V") ? IRFormPtr{} : ret.New();
    auto exp = std::make_shared<InvokeStaticInstruction>(
        m.cls_name, m.name, base, m.ret_type, m.param_type, args, m.triple);
    return std::make_shared<AssignExpression>(std::move(returned),
                                              std::move(exp));
}

// DAD: opcode_ins.py:1115 invoke-interface/range.
IRFormPtr InvokeInterfaceRange(const MethodRef& m,
                               const std::vector<std::string>& regs,
                               RetState& ret, Vmap& vmap) {
    if (regs.empty()) {
        throw std::logic_error("InvokeInterfaceRange: empty register range");
    }
    auto base_arg = GetVariable(vmap, regs[0]);
    std::vector<std::string> tail(regs.begin() + 1, regs.end());
    auto args = GetArgs(vmap, m.param_type, tail);
    IRFormPtr returned = (m.ret_type == "V") ? IRFormPtr{} : ret.New();
    std::vector<IRFormPtr> all_args;
    all_args.reserve(args.size() + 1);
    all_args.push_back(std::move(base_arg));
    for (auto& a : args) all_args.push_back(std::move(a));
    auto exp = std::make_shared<InvokeRangeInstruction>(
        m.cls_name, m.name, m.ret_type, m.param_type, std::move(all_args),
        m.triple);
    return std::make_shared<AssignExpression>(std::move(returned),
                                              std::move(exp));
}

// =============================================================================
// Chunk E — unary + type-conv + arithmetic (3-addr / 2addr / lit16 / lit8).
// =============================================================================

namespace {

// Shared body for neg/not — UnaryExpression(op, b, type).
IRFormPtr UnaryImpl(std::string_view a, std::string_view b,
                    std::string_view op, std::string_view type,
                    Vmap& vmap) {
    auto regs = GetVariables(vmap, {a, b});
    auto exp = std::make_shared<UnaryExpression>(op, regs[1], type);
    return std::make_shared<AssignExpression>(regs[0], std::move(exp));
}

}  // namespace

// DAD: opcode_ins.py:1138-1182 neg/not family.
IRFormPtr NegInt   (std::string_view a, std::string_view b, Vmap& v) { return UnaryImpl(a, b, Op::NEG,  "I", v); }
IRFormPtr NotInt   (std::string_view a, std::string_view b, Vmap& v) { return UnaryImpl(a, b, Op::NOT_, "I", v); }
IRFormPtr NegLong  (std::string_view a, std::string_view b, Vmap& v) { return UnaryImpl(a, b, Op::NEG,  "J", v); }
IRFormPtr NotLong  (std::string_view a, std::string_view b, Vmap& v) { return UnaryImpl(a, b, Op::NOT_, "J", v); }
IRFormPtr NegFloat (std::string_view a, std::string_view b, Vmap& v) { return UnaryImpl(a, b, Op::NEG,  "F", v); }
IRFormPtr NegDouble(std::string_view a, std::string_view b, Vmap& v) { return UnaryImpl(a, b, Op::NEG,  "D", v); }

// DAD: opcode_ins.py:1186-1272 type-conv via assign_cast_exp.
IRFormPtr IntToLong   (std::string_view a, std::string_view b, Vmap& v) { return AssignCastExp(a, b, "(long)",   "J", v); }
IRFormPtr IntToFloat  (std::string_view a, std::string_view b, Vmap& v) { return AssignCastExp(a, b, "(float)",  "F", v); }
IRFormPtr IntToDouble (std::string_view a, std::string_view b, Vmap& v) { return AssignCastExp(a, b, "(double)", "D", v); }
IRFormPtr LongToInt   (std::string_view a, std::string_view b, Vmap& v) { return AssignCastExp(a, b, "(int)",    "I", v); }
IRFormPtr LongToFloat (std::string_view a, std::string_view b, Vmap& v) { return AssignCastExp(a, b, "(float)",  "F", v); }
IRFormPtr LongToDouble(std::string_view a, std::string_view b, Vmap& v) { return AssignCastExp(a, b, "(double)", "D", v); }
IRFormPtr FloatToInt   (std::string_view a, std::string_view b, Vmap& v) { return AssignCastExp(a, b, "(int)",    "I", v); }
IRFormPtr FloatToLong  (std::string_view a, std::string_view b, Vmap& v) { return AssignCastExp(a, b, "(long)",   "J", v); }
IRFormPtr FloatToDouble(std::string_view a, std::string_view b, Vmap& v) { return AssignCastExp(a, b, "(double)", "D", v); }
IRFormPtr DoubleToInt  (std::string_view a, std::string_view b, Vmap& v) { return AssignCastExp(a, b, "(int)",    "I", v); }
IRFormPtr DoubleToLong (std::string_view a, std::string_view b, Vmap& v) { return AssignCastExp(a, b, "(long)",   "J", v); }
IRFormPtr DoubleToFloat(std::string_view a, std::string_view b, Vmap& v) { return AssignCastExp(a, b, "(float)",  "F", v); }
IRFormPtr IntToByte (std::string_view a, std::string_view b, Vmap& v) { return AssignCastExp(a, b, "(byte)",  "B", v); }
IRFormPtr IntToChar (std::string_view a, std::string_view b, Vmap& v) { return AssignCastExp(a, b, "(char)",  "C", v); }
IRFormPtr IntToShort(std::string_view a, std::string_view b, Vmap& v) { return AssignCastExp(a, b, "(short)", "S", v); }

// DAD: opcode_ins.py:1276-1404 int/long arithmetic 3-addr.
IRFormPtr AddInt (std::string_view aa, std::string_view bb, std::string_view cc, Vmap& v) { return AssignBinaryExp(aa, bb, cc, Op::ADD,    "I", v); }
IRFormPtr SubInt (std::string_view aa, std::string_view bb, std::string_view cc, Vmap& v) { return AssignBinaryExp(aa, bb, cc, Op::SUB,    "I", v); }
IRFormPtr MulInt (std::string_view aa, std::string_view bb, std::string_view cc, Vmap& v) { return AssignBinaryExp(aa, bb, cc, Op::MUL,    "I", v); }
IRFormPtr DivInt (std::string_view aa, std::string_view bb, std::string_view cc, Vmap& v) { return AssignBinaryExp(aa, bb, cc, Op::DIV,    "I", v); }
IRFormPtr RemInt (std::string_view aa, std::string_view bb, std::string_view cc, Vmap& v) { return AssignBinaryExp(aa, bb, cc, Op::MOD,    "I", v); }
IRFormPtr AndInt (std::string_view aa, std::string_view bb, std::string_view cc, Vmap& v) { return AssignBinaryExp(aa, bb, cc, Op::AND_,   "I", v); }
IRFormPtr OrInt  (std::string_view aa, std::string_view bb, std::string_view cc, Vmap& v) { return AssignBinaryExp(aa, bb, cc, Op::OR_,    "I", v); }
IRFormPtr XorInt (std::string_view aa, std::string_view bb, std::string_view cc, Vmap& v) { return AssignBinaryExp(aa, bb, cc, Op::XOR_,   "I", v); }
IRFormPtr ShlInt (std::string_view aa, std::string_view bb, std::string_view cc, Vmap& v) { return AssignBinaryExp(aa, bb, cc, Op::INTSHL, "I", v); }
IRFormPtr ShrInt (std::string_view aa, std::string_view bb, std::string_view cc, Vmap& v) { return AssignBinaryExp(aa, bb, cc, Op::INTSHR, "I", v); }
// DAD QUIRK: ushrint uses INTSHR (same as shrint) — not a separate operator.
IRFormPtr UShrInt(std::string_view aa, std::string_view bb, std::string_view cc, Vmap& v) { return AssignBinaryExp(aa, bb, cc, Op::INTSHR, "I", v); }
IRFormPtr AddLong (std::string_view aa, std::string_view bb, std::string_view cc, Vmap& v) { return AssignBinaryExp(aa, bb, cc, Op::ADD,     "J", v); }
IRFormPtr SubLong (std::string_view aa, std::string_view bb, std::string_view cc, Vmap& v) { return AssignBinaryExp(aa, bb, cc, Op::SUB,     "J", v); }
IRFormPtr MulLong (std::string_view aa, std::string_view bb, std::string_view cc, Vmap& v) { return AssignBinaryExp(aa, bb, cc, Op::MUL,     "J", v); }
IRFormPtr DivLong (std::string_view aa, std::string_view bb, std::string_view cc, Vmap& v) { return AssignBinaryExp(aa, bb, cc, Op::DIV,     "J", v); }
IRFormPtr RemLong (std::string_view aa, std::string_view bb, std::string_view cc, Vmap& v) { return AssignBinaryExp(aa, bb, cc, Op::MOD,     "J", v); }
IRFormPtr AndLong (std::string_view aa, std::string_view bb, std::string_view cc, Vmap& v) { return AssignBinaryExp(aa, bb, cc, Op::AND_,    "J", v); }
IRFormPtr OrLong  (std::string_view aa, std::string_view bb, std::string_view cc, Vmap& v) { return AssignBinaryExp(aa, bb, cc, Op::OR_,     "J", v); }
IRFormPtr XorLong (std::string_view aa, std::string_view bb, std::string_view cc, Vmap& v) { return AssignBinaryExp(aa, bb, cc, Op::XOR_,    "J", v); }
IRFormPtr ShlLong (std::string_view aa, std::string_view bb, std::string_view cc, Vmap& v) { return AssignBinaryExp(aa, bb, cc, Op::LONGSHL, "J", v); }
IRFormPtr ShrLong (std::string_view aa, std::string_view bb, std::string_view cc, Vmap& v) { return AssignBinaryExp(aa, bb, cc, Op::LONGSHR, "J", v); }
IRFormPtr UShrLong(std::string_view aa, std::string_view bb, std::string_view cc, Vmap& v) { return AssignBinaryExp(aa, bb, cc, Op::LONGSHR, "J", v); }

// DAD: opcode_ins.py:1408-1464 float/double arithmetic 3-addr.
IRFormPtr AddFloat (std::string_view aa, std::string_view bb, std::string_view cc, Vmap& v) { return AssignBinaryExp(aa, bb, cc, Op::ADD, "F", v); }
IRFormPtr SubFloat (std::string_view aa, std::string_view bb, std::string_view cc, Vmap& v) { return AssignBinaryExp(aa, bb, cc, Op::SUB, "F", v); }
IRFormPtr MulFloat (std::string_view aa, std::string_view bb, std::string_view cc, Vmap& v) { return AssignBinaryExp(aa, bb, cc, Op::MUL, "F", v); }
IRFormPtr DivFloat (std::string_view aa, std::string_view bb, std::string_view cc, Vmap& v) { return AssignBinaryExp(aa, bb, cc, Op::DIV, "F", v); }
IRFormPtr RemFloat (std::string_view aa, std::string_view bb, std::string_view cc, Vmap& v) { return AssignBinaryExp(aa, bb, cc, Op::MOD, "F", v); }
IRFormPtr AddDouble(std::string_view aa, std::string_view bb, std::string_view cc, Vmap& v) { return AssignBinaryExp(aa, bb, cc, Op::ADD, "D", v); }
IRFormPtr SubDouble(std::string_view aa, std::string_view bb, std::string_view cc, Vmap& v) { return AssignBinaryExp(aa, bb, cc, Op::SUB, "D", v); }
IRFormPtr MulDouble(std::string_view aa, std::string_view bb, std::string_view cc, Vmap& v) { return AssignBinaryExp(aa, bb, cc, Op::MUL, "D", v); }
IRFormPtr DivDouble(std::string_view aa, std::string_view bb, std::string_view cc, Vmap& v) { return AssignBinaryExp(aa, bb, cc, Op::DIV, "D", v); }
IRFormPtr RemDouble(std::string_view aa, std::string_view bb, std::string_view cc, Vmap& v) { return AssignBinaryExp(aa, bb, cc, Op::MOD, "D", v); }

// DAD: opcode_ins.py:1468-1656 arithmetic 2-addr.
IRFormPtr AddInt2Addr (std::string_view a, std::string_view b, Vmap& v) { return AssignBinary2AddrExp(a, b, Op::ADD,    "I", v); }
IRFormPtr SubInt2Addr (std::string_view a, std::string_view b, Vmap& v) { return AssignBinary2AddrExp(a, b, Op::SUB,    "I", v); }
IRFormPtr MulInt2Addr (std::string_view a, std::string_view b, Vmap& v) { return AssignBinary2AddrExp(a, b, Op::MUL,    "I", v); }
IRFormPtr DivInt2Addr (std::string_view a, std::string_view b, Vmap& v) { return AssignBinary2AddrExp(a, b, Op::DIV,    "I", v); }
IRFormPtr RemInt2Addr (std::string_view a, std::string_view b, Vmap& v) { return AssignBinary2AddrExp(a, b, Op::MOD,    "I", v); }
IRFormPtr AndInt2Addr (std::string_view a, std::string_view b, Vmap& v) { return AssignBinary2AddrExp(a, b, Op::AND_,   "I", v); }
IRFormPtr OrInt2Addr  (std::string_view a, std::string_view b, Vmap& v) { return AssignBinary2AddrExp(a, b, Op::OR_,    "I", v); }
IRFormPtr XorInt2Addr (std::string_view a, std::string_view b, Vmap& v) { return AssignBinary2AddrExp(a, b, Op::XOR_,   "I", v); }
IRFormPtr ShlInt2Addr (std::string_view a, std::string_view b, Vmap& v) { return AssignBinary2AddrExp(a, b, Op::INTSHL, "I", v); }
IRFormPtr ShrInt2Addr (std::string_view a, std::string_view b, Vmap& v) { return AssignBinary2AddrExp(a, b, Op::INTSHR, "I", v); }
IRFormPtr UShrInt2Addr(std::string_view a, std::string_view b, Vmap& v) { return AssignBinary2AddrExp(a, b, Op::INTSHR, "I", v); }
IRFormPtr AddLong2Addr (std::string_view a, std::string_view b, Vmap& v) { return AssignBinary2AddrExp(a, b, Op::ADD,     "J", v); }
IRFormPtr SubLong2Addr (std::string_view a, std::string_view b, Vmap& v) { return AssignBinary2AddrExp(a, b, Op::SUB,     "J", v); }
IRFormPtr MulLong2Addr (std::string_view a, std::string_view b, Vmap& v) { return AssignBinary2AddrExp(a, b, Op::MUL,     "J", v); }
IRFormPtr DivLong2Addr (std::string_view a, std::string_view b, Vmap& v) { return AssignBinary2AddrExp(a, b, Op::DIV,     "J", v); }
IRFormPtr RemLong2Addr (std::string_view a, std::string_view b, Vmap& v) { return AssignBinary2AddrExp(a, b, Op::MOD,     "J", v); }
IRFormPtr AndLong2Addr (std::string_view a, std::string_view b, Vmap& v) { return AssignBinary2AddrExp(a, b, Op::AND_,    "J", v); }
IRFormPtr OrLong2Addr  (std::string_view a, std::string_view b, Vmap& v) { return AssignBinary2AddrExp(a, b, Op::OR_,     "J", v); }
IRFormPtr XorLong2Addr (std::string_view a, std::string_view b, Vmap& v) { return AssignBinary2AddrExp(a, b, Op::XOR_,    "J", v); }
IRFormPtr ShlLong2Addr (std::string_view a, std::string_view b, Vmap& v) { return AssignBinary2AddrExp(a, b, Op::LONGSHL, "J", v); }
IRFormPtr ShrLong2Addr (std::string_view a, std::string_view b, Vmap& v) { return AssignBinary2AddrExp(a, b, Op::LONGSHR, "J", v); }
IRFormPtr UShrLong2Addr(std::string_view a, std::string_view b, Vmap& v) { return AssignBinary2AddrExp(a, b, Op::LONGSHR, "J", v); }
IRFormPtr AddFloat2Addr (std::string_view a, std::string_view b, Vmap& v) { return AssignBinary2AddrExp(a, b, Op::ADD, "F", v); }
IRFormPtr SubFloat2Addr (std::string_view a, std::string_view b, Vmap& v) { return AssignBinary2AddrExp(a, b, Op::SUB, "F", v); }
IRFormPtr MulFloat2Addr (std::string_view a, std::string_view b, Vmap& v) { return AssignBinary2AddrExp(a, b, Op::MUL, "F", v); }
IRFormPtr DivFloat2Addr (std::string_view a, std::string_view b, Vmap& v) { return AssignBinary2AddrExp(a, b, Op::DIV, "F", v); }
IRFormPtr RemFloat2Addr (std::string_view a, std::string_view b, Vmap& v) { return AssignBinary2AddrExp(a, b, Op::MOD, "F", v); }
IRFormPtr AddDouble2Addr(std::string_view a, std::string_view b, Vmap& v) { return AssignBinary2AddrExp(a, b, Op::ADD, "D", v); }
IRFormPtr SubDouble2Addr(std::string_view a, std::string_view b, Vmap& v) { return AssignBinary2AddrExp(a, b, Op::SUB, "D", v); }
IRFormPtr MulDouble2Addr(std::string_view a, std::string_view b, Vmap& v) { return AssignBinary2AddrExp(a, b, Op::MUL, "D", v); }
IRFormPtr DivDouble2Addr(std::string_view a, std::string_view b, Vmap& v) { return AssignBinary2AddrExp(a, b, Op::DIV, "D", v); }
IRFormPtr RemDouble2Addr(std::string_view a, std::string_view b, Vmap& v) { return AssignBinary2AddrExp(a, b, Op::MOD, "D", v); }

// DAD: opcode_ins.py:1659-1706 *-lit16 wrappers.
IRFormPtr AddIntLit16(std::string_view a, std::string_view b, int64_t cccc, Vmap& v) { return AssignLit(Op::ADD,  cccc, a, b, v); }
IRFormPtr MulIntLit16(std::string_view a, std::string_view b, int64_t cccc, Vmap& v) { return AssignLit(Op::MUL,  cccc, a, b, v); }
IRFormPtr DivIntLit16(std::string_view a, std::string_view b, int64_t cccc, Vmap& v) { return AssignLit(Op::DIV,  cccc, a, b, v); }
IRFormPtr RemIntLit16(std::string_view a, std::string_view b, int64_t cccc, Vmap& v) { return AssignLit(Op::MOD,  cccc, a, b, v); }
IRFormPtr AndIntLit16(std::string_view a, std::string_view b, int64_t cccc, Vmap& v) { return AssignLit(Op::AND_, cccc, a, b, v); }
IRFormPtr OrIntLit16 (std::string_view a, std::string_view b, int64_t cccc, Vmap& v) { return AssignLit(Op::OR_,  cccc, a, b, v); }
IRFormPtr XorIntLit16(std::string_view a, std::string_view b, int64_t cccc, Vmap& v) { return AssignLit(Op::XOR_, cccc, a, b, v); }

// DAD: opcode_ins.py:1666 rsubint — `var_a = cst - var_b` (reversed).
IRFormPtr RSubInt(std::string_view a, std::string_view b, int64_t cccc, Vmap& vmap) {
    auto regs = GetVariables(vmap, {a, b});
    auto cst = std::make_shared<Constant>(ConstantValue{cccc}, "I");
    auto bin = std::make_shared<BinaryExpressionLit>(Op::SUB, cst, regs[1]);
    return std::make_shared<AssignExpression>(regs[0], std::move(bin));
}

// DAD: opcode_ins.py:1710 addintlit8 — DAD QUIRK: swaps op based on sign of CC.
//   literal, op = [(ins.CC, ADD), (-ins.CC, SUB)][ins.CC < 0]
// When CC<0, the literal becomes -CC and the op switches to SUB. Faithful port.
IRFormPtr AddIntLit8(std::string_view aa, std::string_view bb, int64_t cc, Vmap& vmap) {
    int64_t literal = cc;
    std::string_view op = Op::ADD;
    if (cc < 0) { literal = -cc; op = Op::SUB; }
    return AssignLit(op, literal, aa, bb, vmap);
}

// DAD: opcode_ins.py:1717 rsubintlit8 — `var_a = cst - var_b` reversed.
IRFormPtr RSubIntLit8(std::string_view aa, std::string_view bb, int64_t cc, Vmap& vmap) {
    auto regs = GetVariables(vmap, {aa, bb});
    auto cst = std::make_shared<Constant>(ConstantValue{cc}, "I");
    auto bin = std::make_shared<BinaryExpressionLit>(Op::SUB, cst, regs[1]);
    return std::make_shared<AssignExpression>(regs[0], std::move(bin));
}

IRFormPtr MulIntLit8(std::string_view aa, std::string_view bb, int64_t cc, Vmap& v) { return AssignLit(Op::MUL,    cc, aa, bb, v); }
IRFormPtr DivIntLit8(std::string_view aa, std::string_view bb, int64_t cc, Vmap& v) { return AssignLit(Op::DIV,    cc, aa, bb, v); }
IRFormPtr RemIntLit8(std::string_view aa, std::string_view bb, int64_t cc, Vmap& v) { return AssignLit(Op::MOD,    cc, aa, bb, v); }
IRFormPtr AndIntLit8(std::string_view aa, std::string_view bb, int64_t cc, Vmap& v) { return AssignLit(Op::AND_,   cc, aa, bb, v); }
IRFormPtr OrIntLit8 (std::string_view aa, std::string_view bb, int64_t cc, Vmap& v) { return AssignLit(Op::OR_,    cc, aa, bb, v); }
IRFormPtr XorIntLit8(std::string_view aa, std::string_view bb, int64_t cc, Vmap& v) { return AssignLit(Op::XOR_,   cc, aa, bb, v); }
IRFormPtr ShlIntLit8(std::string_view aa, std::string_view bb, int64_t cc, Vmap& v) { return AssignLit(Op::INTSHL, cc, aa, bb, v); }
IRFormPtr ShrIntLit8(std::string_view aa, std::string_view bb, int64_t cc, Vmap& v) { return AssignLit(Op::INTSHR, cc, aa, bb, v); }
IRFormPtr UShrIntLit8(std::string_view aa, std::string_view bb, int64_t cc, Vmap& v) { return AssignLit(Op::INTSHR, cc, aa, bb, v); }

// =============================================================================
// Chunk F — INSTRUCTION_SET dispatch table.
//
// DAD's array order is faithfully preserved. "Unused" slots in DAD (filled
// with `nop` in Python) map to OpcodeKind::Nop here. Opcodes beyond 0xE2
// (which DAD's array doesn't cover) map to OpcodeKind::Unused so the driver
// can distinguish them from real nops.
// =============================================================================

const std::array<OpcodeKind, 256> kInstructionSet = []() {
    std::array<OpcodeKind, 256> t{};
    t.fill(OpcodeKind::Unused);
    using K = OpcodeKind;
    // 0x00
    t[0x00] = K::Nop;
    t[0x01] = K::Move;
    t[0x02] = K::MoveFrom16;
    t[0x03] = K::Move16;
    t[0x04] = K::MoveWide;
    t[0x05] = K::MoveWideFrom16;
    t[0x06] = K::MoveWide16;
    t[0x07] = K::MoveObject;
    t[0x08] = K::MoveObjectFrom16;
    t[0x09] = K::MoveObject16;
    t[0x0A] = K::MoveResult;
    t[0x0B] = K::MoveResultWide;
    t[0x0C] = K::MoveResultObject;
    t[0x0D] = K::MoveException;
    t[0x0E] = K::ReturnVoid;
    t[0x0F] = K::ReturnReg;
    // 0x10
    t[0x10] = K::ReturnWide;
    t[0x11] = K::ReturnObject;
    t[0x12] = K::Const4;
    t[0x13] = K::Const16;
    t[0x14] = K::Const;
    t[0x15] = K::ConstHigh16;
    t[0x16] = K::ConstWide16;
    t[0x17] = K::ConstWide32;
    t[0x18] = K::ConstWide;
    t[0x19] = K::ConstWideHigh16;
    t[0x1A] = K::ConstString;
    t[0x1B] = K::ConstStringJumbo;
    t[0x1C] = K::ConstClass;
    t[0x1D] = K::MonitorEnter;
    t[0x1E] = K::MonitorExit;
    t[0x1F] = K::CheckCast;
    // 0x20
    t[0x20] = K::InstanceOf;
    t[0x21] = K::ArrayLength;
    t[0x22] = K::NewInstance_;
    t[0x23] = K::NewArray;
    t[0x24] = K::FilledNewArray;
    t[0x25] = K::FilledNewArrayRange;
    t[0x26] = K::FillArrayData;
    t[0x27] = K::Throw;
    t[0x28] = K::Goto;
    t[0x29] = K::Goto16;
    t[0x2A] = K::Goto32;
    t[0x2B] = K::PackedSwitch;
    t[0x2C] = K::SparseSwitch;
    t[0x2D] = K::CmplFloat;
    t[0x2E] = K::CmpgFloat;
    t[0x2F] = K::CmplDouble;
    // 0x30
    t[0x30] = K::CmpgDouble;
    t[0x31] = K::CmpLong;
    t[0x32] = K::IfEq;
    t[0x33] = K::IfNe;
    t[0x34] = K::IfLt;
    t[0x35] = K::IfGe;
    t[0x36] = K::IfGt;
    t[0x37] = K::IfLe;
    t[0x38] = K::IfEqz;
    t[0x39] = K::IfNez;
    t[0x3A] = K::IfLtz;
    t[0x3B] = K::IfGez;
    t[0x3C] = K::IfGtz;
    t[0x3D] = K::IfLez;
    t[0x3E] = K::Nop;  // unused → DAD falls back to nop
    t[0x3F] = K::Nop;  // unused
    // 0x40
    t[0x40] = K::Nop;  // unused
    t[0x41] = K::Nop;  // unused
    t[0x42] = K::Nop;  // unused
    t[0x43] = K::Nop;  // unused
    t[0x44] = K::AGet;
    t[0x45] = K::AGetWide;
    t[0x46] = K::AGetObject;
    t[0x47] = K::AGetBoolean;
    t[0x48] = K::AGetByte;
    t[0x49] = K::AGetChar;
    t[0x4A] = K::AGetShort;
    t[0x4B] = K::APut;
    t[0x4C] = K::APutWide;
    t[0x4D] = K::APutObject;
    t[0x4E] = K::APutBoolean;
    t[0x4F] = K::APutByte;
    // 0x50
    t[0x50] = K::APutChar;
    t[0x51] = K::APutShort;
    t[0x52] = K::IGet;
    t[0x53] = K::IGetWide;
    t[0x54] = K::IGetObject;
    t[0x55] = K::IGetBoolean;
    t[0x56] = K::IGetByte;
    t[0x57] = K::IGetChar;
    t[0x58] = K::IGetShort;
    t[0x59] = K::IPut;
    t[0x5A] = K::IPutWide;
    t[0x5B] = K::IPutObject;
    t[0x5C] = K::IPutBoolean;
    t[0x5D] = K::IPutByte;
    t[0x5E] = K::IPutChar;
    t[0x5F] = K::IPutShort;
    // 0x60
    t[0x60] = K::SGet;
    t[0x61] = K::SGetWide;
    t[0x62] = K::SGetObject;
    t[0x63] = K::SGetBoolean;
    t[0x64] = K::SGetByte;
    t[0x65] = K::SGetChar;
    t[0x66] = K::SGetShort;
    t[0x67] = K::SPut;
    t[0x68] = K::SPutWide;
    t[0x69] = K::SPutObject;
    t[0x6A] = K::SPutBoolean;
    t[0x6B] = K::SPutByte;
    t[0x6C] = K::SPutChar;
    t[0x6D] = K::SPutShort;
    t[0x6E] = K::InvokeVirtual;
    t[0x6F] = K::InvokeSuper;
    // 0x70
    t[0x70] = K::InvokeDirect;
    t[0x71] = K::InvokeStatic;
    t[0x72] = K::InvokeInterface;
    t[0x73] = K::Nop;  // unused
    t[0x74] = K::InvokeVirtualRange;
    t[0x75] = K::InvokeSuperRange;
    t[0x76] = K::InvokeDirectRange;
    t[0x77] = K::InvokeStaticRange;
    t[0x78] = K::InvokeInterfaceRange;
    t[0x79] = K::Nop;  // unused
    t[0x7A] = K::Nop;  // unused
    t[0x7B] = K::NegInt;
    t[0x7C] = K::NotInt;
    t[0x7D] = K::NegLong;
    t[0x7E] = K::NotLong;
    t[0x7F] = K::NegFloat;
    // 0x80
    t[0x80] = K::NegDouble;
    t[0x81] = K::IntToLong;
    t[0x82] = K::IntToFloat;
    t[0x83] = K::IntToDouble;
    t[0x84] = K::LongToInt;
    t[0x85] = K::LongToFloat;
    t[0x86] = K::LongToDouble;
    t[0x87] = K::FloatToInt;
    t[0x88] = K::FloatToLong;
    t[0x89] = K::FloatToDouble;
    t[0x8A] = K::DoubleToInt;
    t[0x8B] = K::DoubleToLong;
    t[0x8C] = K::DoubleToFloat;
    t[0x8D] = K::IntToByte;
    t[0x8E] = K::IntToChar;
    t[0x8F] = K::IntToShort;
    // 0x90
    t[0x90] = K::AddInt;
    t[0x91] = K::SubInt;
    t[0x92] = K::MulInt;
    t[0x93] = K::DivInt;
    t[0x94] = K::RemInt;
    t[0x95] = K::AndInt;
    t[0x96] = K::OrInt;
    t[0x97] = K::XorInt;
    t[0x98] = K::ShlInt;
    t[0x99] = K::ShrInt;
    t[0x9A] = K::UShrInt;
    t[0x9B] = K::AddLong;
    t[0x9C] = K::SubLong;
    t[0x9D] = K::MulLong;
    t[0x9E] = K::DivLong;
    t[0x9F] = K::RemLong;
    // 0xA0
    t[0xA0] = K::AndLong;
    t[0xA1] = K::OrLong;
    t[0xA2] = K::XorLong;
    t[0xA3] = K::ShlLong;
    t[0xA4] = K::ShrLong;
    t[0xA5] = K::UShrLong;
    t[0xA6] = K::AddFloat;
    t[0xA7] = K::SubFloat;
    t[0xA8] = K::MulFloat;
    t[0xA9] = K::DivFloat;
    t[0xAA] = K::RemFloat;
    t[0xAB] = K::AddDouble;
    t[0xAC] = K::SubDouble;
    t[0xAD] = K::MulDouble;
    t[0xAE] = K::DivDouble;
    t[0xAF] = K::RemDouble;
    // 0xB0
    t[0xB0] = K::AddInt2Addr;
    t[0xB1] = K::SubInt2Addr;
    t[0xB2] = K::MulInt2Addr;
    t[0xB3] = K::DivInt2Addr;
    t[0xB4] = K::RemInt2Addr;
    t[0xB5] = K::AndInt2Addr;
    t[0xB6] = K::OrInt2Addr;
    t[0xB7] = K::XorInt2Addr;
    t[0xB8] = K::ShlInt2Addr;
    t[0xB9] = K::ShrInt2Addr;
    t[0xBA] = K::UShrInt2Addr;
    t[0xBB] = K::AddLong2Addr;
    t[0xBC] = K::SubLong2Addr;
    t[0xBD] = K::MulLong2Addr;
    t[0xBE] = K::DivLong2Addr;
    t[0xBF] = K::RemLong2Addr;
    // 0xC0
    t[0xC0] = K::AndLong2Addr;
    t[0xC1] = K::OrLong2Addr;
    t[0xC2] = K::XorLong2Addr;
    t[0xC3] = K::ShlLong2Addr;
    t[0xC4] = K::ShrLong2Addr;
    t[0xC5] = K::UShrLong2Addr;
    t[0xC6] = K::AddFloat2Addr;
    t[0xC7] = K::SubFloat2Addr;
    t[0xC8] = K::MulFloat2Addr;
    t[0xC9] = K::DivFloat2Addr;
    t[0xCA] = K::RemFloat2Addr;
    t[0xCB] = K::AddDouble2Addr;
    t[0xCC] = K::SubDouble2Addr;
    t[0xCD] = K::MulDouble2Addr;
    t[0xCE] = K::DivDouble2Addr;
    t[0xCF] = K::RemDouble2Addr;
    // 0xD0
    t[0xD0] = K::AddIntLit16;
    t[0xD1] = K::RSubInt;
    t[0xD2] = K::MulIntLit16;
    t[0xD3] = K::DivIntLit16;
    t[0xD4] = K::RemIntLit16;
    t[0xD5] = K::AndIntLit16;
    t[0xD6] = K::OrIntLit16;
    t[0xD7] = K::XorIntLit16;
    t[0xD8] = K::AddIntLit8;
    t[0xD9] = K::RSubIntLit8;
    t[0xDA] = K::MulIntLit8;
    t[0xDB] = K::DivIntLit8;
    t[0xDC] = K::RemIntLit8;
    t[0xDD] = K::AndIntLit8;
    t[0xDE] = K::OrIntLit8;
    t[0xDF] = K::XorIntLit8;
    // 0xE0
    t[0xE0] = K::ShlIntLit8;
    t[0xE1] = K::ShrIntLit8;
    t[0xE2] = K::UShrIntLit8;
    // 0xE3-0xFF stay Unused (filled by t.fill above)
    return t;
}();

}  // namespace dexkit::dad
