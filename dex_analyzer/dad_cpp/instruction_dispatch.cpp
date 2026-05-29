// instruction_dispatch.cpp — RawIns → typed IR via OpcodeKind switch.
//
// Bug-for-bug parity with DAD's `INSTRUCTION_SET[opcode](ins, vmap, ...)`.
// Each case extracts operands from the slicer-decoded form and forwards to
// the corresponding typed handler declared in opcode_ins.h.
//
// OPERAND CONVENTION (from slicer dex_bytecode.cc):
//   k11x/k11n  : vA = reg, vB = literal
//   k12x       : vA, vB = regs
//   k22x/k21c  : vA = reg, vB = (reg / lit / const-pool idx)
//   k23x       : vA, vB, vC = regs
//   k22b       : vA, vB = regs, vC = signed 8-bit lit
//   k22c       : vA, vB = regs, vC = const-pool idx
//   k22s/k22t  : vA, vB = regs, vC = signed 16-bit lit/offset
//   k31i/k31t  : vA = reg, vB = 32-bit lit/offset
//   k35c       : vA = count (0-5), vB = method_idx,
//                arg[0]=vC, arg[1]=vD, arg[2]=vE, arg[3]=vF, arg[4]=vG
//   k3rc       : vA = count, vB = method_idx, vC = first_reg

#include "instruction_dispatch.h"

#include <algorithm>
#include <cstdint>
#include <stdexcept>
#include <string>
#include <vector>

#include "instruction.h"
#include "method_snapshot.h"
#include "opcode_ins.h"
#include "slicer/dex_bytecode.h"
#include "util.h"

namespace dexkit::dad {

namespace {

// ─── const-pool reference extraction ──────────────────────────────────────

const StringConst* AsString(const ConstRef& cr) {
    return std::get_if<StringConst>(&cr);
}
const TypeConst* AsType(const ConstRef& cr) {
    return std::get_if<TypeConst>(&cr);
}
const MethodConst* AsMethod(const ConstRef& cr) {
    return std::get_if<MethodConst>(&cr);
}
const FieldConst* AsField(const ConstRef& cr) {
    return std::get_if<FieldConst>(&cr);
}

// Build the MethodRef struct expected by InvokeVirtual / etc. Applies the
// same util.get_type / util.get_params_type transforms DAD does.
MethodRef BuildMethodRef(const MethodConst& mc) {
    MethodRef m;
    // DAD's util.get_type for cls descriptor (with the documented lstrip quirk).
    m.cls_name = GetType(mc.triple[0]);
    m.name = std::string(mc.triple[1]);
    // DAD: util.get_params_type — whitespace-split quirk. DAD relies on
    // androguard's get_descriptor() returning `(LA; LB;)V` (with spaces),
    // so DAD's `.split()` correctly splits into N args. Our internal proto
    // is spaceless (`(LA;LB;)V`), so DAD-faithful GetParamsType would
    // return a single-element list and GetArgs would drop arguments.
    // Use the proper Dalvik parser here so invoke args are preserved;
    // GetParamsType remains available for parity tests of the DAD quirk.
    m.param_type = ParseParamsType(std::string(mc.triple[2]));
    auto paren = mc.triple[2].rfind(')');
    m.ret_type = (paren == std::string_view::npos)
                     ? "V"
                     : std::string(mc.triple[2].substr(paren + 1));
    // InvokeInstruction::Triple is {cls, name, proto} — Smali form preserved.
    m.triple = {std::string(mc.triple[0]),
                std::string(mc.triple[1]),
                std::string(mc.triple[2])};
    m.original_cls_descriptor = std::string(mc.triple[0]);
    return m;
}

// Convert payload bytes to vector<int64_t> for FillArrayExpression.
std::vector<int64_t> FillArrayValues(const PayloadFillArray& pa) {
    std::vector<int64_t> result;
    result.reserve(pa.size);
    for (uint32_t i = 0; i < pa.size; ++i) {
        const uint8_t* base = pa.data.data() + i * pa.element_width;
        int64_t v = 0;
        switch (pa.element_width) {
            case 1: v = static_cast<int8_t>(base[0]); break;
            case 2: v = *reinterpret_cast<const int16_t*>(base); break;
            case 4: v = *reinterpret_cast<const int32_t*>(base); break;
            case 8: v = *reinterpret_cast<const int64_t*>(base); break;
            default: v = 0;
        }
        result.push_back(v);
    }
    return result;
}

// Build the register list for invoke-range (3rc).
std::vector<std::string> BuildRangeRegs(uint32_t count, uint32_t first_reg) {
    std::vector<std::string> regs;
    regs.reserve(count);
    for (uint32_t i = 0; i < count; ++i) {
        regs.push_back(RegName(first_reg + i));
    }
    return regs;
}

// Helper to materialize at most 5 register names for invoke-kind (35c).
// Returns 5 strings; unused slots are empty per handler convention.
struct InvokeRegs {
    std::string c, d, e, f, g;
};
InvokeRegs BuildInvokeRegs(const dex::Instruction& dec) {
    InvokeRegs r;
    uint32_t count = dec.vA;
    if (count > 0) r.c = RegName(dec.arg[0]);
    if (count > 1) r.d = RegName(dec.arg[1]);
    if (count > 2) r.e = RegName(dec.arg[2]);
    if (count > 3) r.f = RegName(dec.arg[3]);
    if (count > 4) r.g = RegName(dec.arg[4]);
    return r;
}

}  // namespace

// ============================================================================
// DispatchInstruction — 256-case switch
// ============================================================================

IRFormPtr DispatchInstruction(const RawIns& ri,
                              Vmap& vmap,
                              RetState& gen_ret,
                              const PayloadVariant* payload,
                              std::string_view exception_type) {
    using K = OpcodeKind;

    if (ri.opcode > 0xFF) return std::make_shared<NopExpression>();
    K kind = kInstructionSet[static_cast<uint8_t>(ri.opcode)];

    const dex::Instruction& d = ri.decoded;
    const std::string vA = RegName(d.vA);
    auto str_const = [&]() -> std::string_view {
        if (auto* s = AsString(ri.const_ref)) return s->value;
        return {};
    };
    auto type_desc = [&]() -> std::string_view {
        if (auto* t = AsType(ri.const_ref)) return t->descriptor;
        return {};
    };

    switch (kind) {
        // ── Nop / Unused (0x00 + 0xE3..0xFF) ────────────────────────────
        case K::Nop:
        case K::Unused:
            return std::make_shared<NopExpression>();

        // ── Move family ────────────────────────────────────────────────
        case K::Move:           return Move(vA, RegName(d.vB), vmap);
        case K::MoveFrom16:     return MoveFrom16(vA, RegName(d.vB), vmap);
        case K::Move16:         return Move16(vA, RegName(d.vB), vmap);
        case K::MoveWide:       return MoveWide(vA, RegName(d.vB), vmap);
        case K::MoveWideFrom16: return MoveWideFrom16(vA, RegName(d.vB), vmap);
        case K::MoveWide16:     return MoveWide16(vA, RegName(d.vB), vmap);
        case K::MoveObject:     return MoveObject(vA, RegName(d.vB), vmap);
        case K::MoveObjectFrom16: return MoveObjectFrom16(vA, RegName(d.vB), vmap);
        case K::MoveObject16:   return MoveObject16(vA, RegName(d.vB), vmap);

        // ── Move-result family ─────────────────────────────────────────
        case K::MoveResult:       return MoveResult(vA, gen_ret.Last(), vmap);
        case K::MoveResultWide:   return MoveResultWide(vA, gen_ret.Last(), vmap);
        case K::MoveResultObject: return MoveResultObject(vA, gen_ret.Last(), vmap);

        // ── Move-exception ─────────────────────────────────────────────
        case K::MoveException:
            return MoveException(vA, exception_type, vmap);

        // ── Returns ────────────────────────────────────────────────────
        case K::ReturnVoid:   return ReturnVoid();
        case K::ReturnReg:    return ReturnReg(vA, vmap);
        case K::ReturnWide:   return ReturnWide(vA, vmap);
        case K::ReturnObject: return ReturnObject(vA, vmap);

        // ── Const family ───────────────────────────────────────────────
        case K::Const4:           return Const4(vA, static_cast<int64_t>(static_cast<int8_t>(d.vB << 4) >> 4), vmap);
        case K::Const16:          return Const16(vA, static_cast<int64_t>(static_cast<int16_t>(d.vB)), vmap);
        case K::Const:            return Const(vA, static_cast<int64_t>(static_cast<int32_t>(d.vB)), vmap);
        case K::ConstHigh16:      return ConstHigh16(vA, static_cast<int64_t>(static_cast<int16_t>(d.vB)), vmap);
        case K::ConstWide16:      return ConstWide16(vA, static_cast<int64_t>(static_cast<int16_t>(d.vB)), vmap);
        case K::ConstWide32:      return ConstWide32(vA, static_cast<int64_t>(static_cast<int32_t>(d.vB)), vmap);
        case K::ConstWide:        return ConstWide(vA, static_cast<int64_t>(d.vB_wide), vmap);
        case K::ConstWideHigh16:  return ConstWideHigh16(vA, static_cast<int64_t>(static_cast<int16_t>(d.vB)), vmap);

        case K::ConstString:
        case K::ConstStringJumbo:
            return (kind == K::ConstString)
                ? ConstString(vA, str_const(), vmap)
                : ConstStringJumbo(vA, str_const(), vmap);

        case K::ConstClass:
            return ConstClass(vA, type_desc(), vmap);

        // ── Monitors ───────────────────────────────────────────────────
        case K::MonitorEnter: return MonitorEnter(vA, vmap);
        case K::MonitorExit:  return MonitorExit(vA, vmap);

        // ── Type checks ────────────────────────────────────────────────
        case K::CheckCast:
            return CheckCast(vA, type_desc(), vmap);
        case K::InstanceOf:
            return InstanceOf(vA, RegName(d.vB), type_desc(), vmap);

        // ── Array ──────────────────────────────────────────────────────
        case K::ArrayLength:
            return ArrayLength(vA, RegName(d.vB), vmap);
        case K::NewInstance_:
            return NewInstance_(vA, type_desc(), vmap);
        case K::NewArray:
            return NewArray(vA, RegName(d.vB), type_desc(), vmap);

        case K::FilledNewArray: {
            auto regs = BuildInvokeRegs(d);
            return FilledNewArray(d.vA, type_desc(),
                                  regs.c, regs.d, regs.e, regs.f, regs.g,
                                  gen_ret.New(), vmap);
        }
        case K::FilledNewArrayRange: {
            uint32_t last = d.vC + (d.vA > 0 ? d.vA - 1 : 0);
            return FilledNewArrayRange(d.vA, type_desc(),
                                       RegName(d.vC), RegName(last),
                                       gen_ret.New(), vmap);
        }

        case K::FillArrayData: {
            std::vector<int64_t> values;
            if (payload) {
                if (auto* pa = std::get_if<PayloadFillArray>(payload)) {
                    values = FillArrayValues(*pa);
                }
            }
            return FillArrayData(vA, std::move(values), vmap);
        }

        // ── Throw ──────────────────────────────────────────────────────
        case K::Throw: return Throw(vA, vmap);

        // ── Goto family ────────────────────────────────────────────────
        case K::Goto:   return Goto();
        case K::Goto16: return Goto16();
        case K::Goto32: return Goto32();

        // ── Switch ─────────────────────────────────────────────────────
        case K::PackedSwitch:
            return PackedSwitch(vA, static_cast<int32_t>(d.vB), vmap);
        case K::SparseSwitch:
            return SparseSwitch(vA, static_cast<int32_t>(d.vB), vmap);

        // ── Compare ────────────────────────────────────────────────────
        case K::CmplFloat:  return CmplFloat (vA, RegName(d.vB), RegName(d.vC), vmap);
        case K::CmpgFloat:  return CmpgFloat (vA, RegName(d.vB), RegName(d.vC), vmap);
        case K::CmplDouble: return CmplDouble(vA, RegName(d.vB), RegName(d.vC), vmap);
        case K::CmpgDouble: return CmpgDouble(vA, RegName(d.vB), RegName(d.vC), vmap);
        case K::CmpLong:    return CmpLong   (vA, RegName(d.vB), RegName(d.vC), vmap);

        // ── If-test (22t) ───────────────────────────────────────────────
        case K::IfEq: return IfEq(vA, RegName(d.vB), vmap);
        case K::IfNe: return IfNe(vA, RegName(d.vB), vmap);
        case K::IfLt: return IfLt(vA, RegName(d.vB), vmap);
        case K::IfGe: return IfGe(vA, RegName(d.vB), vmap);
        case K::IfGt: return IfGt(vA, RegName(d.vB), vmap);
        case K::IfLe: return IfLe(vA, RegName(d.vB), vmap);

        // ── If-testz (21t) ──────────────────────────────────────────────
        case K::IfEqz: return IfEqz(vA, vmap);
        case K::IfNez: return IfNez(vA, vmap);
        case K::IfLtz: return IfLtz(vA, vmap);
        case K::IfGez: return IfGez(vA, vmap);
        case K::IfGtz: return IfGtz(vA, vmap);
        case K::IfLez: return IfLez(vA, vmap);

        // ── Aget family ────────────────────────────────────────────────
        case K::AGet:        return AGet       (vA, RegName(d.vB), RegName(d.vC), vmap);
        case K::AGetWide:    return AGetWide   (vA, RegName(d.vB), RegName(d.vC), vmap);
        case K::AGetObject:  return AGetObject (vA, RegName(d.vB), RegName(d.vC), vmap);
        case K::AGetBoolean: return AGetBoolean(vA, RegName(d.vB), RegName(d.vC), vmap);
        case K::AGetByte:    return AGetByte   (vA, RegName(d.vB), RegName(d.vC), vmap);
        case K::AGetChar:    return AGetChar   (vA, RegName(d.vB), RegName(d.vC), vmap);
        case K::AGetShort:   return AGetShort  (vA, RegName(d.vB), RegName(d.vC), vmap);

        // ── Aput family ────────────────────────────────────────────────
        case K::APut:        return APut       (vA, RegName(d.vB), RegName(d.vC), vmap);
        case K::APutWide:    return APutWide   (vA, RegName(d.vB), RegName(d.vC), vmap);
        case K::APutObject:  return APutObject (vA, RegName(d.vB), RegName(d.vC), vmap);
        case K::APutBoolean: return APutBoolean(vA, RegName(d.vB), RegName(d.vC), vmap);
        case K::APutByte:    return APutByte   (vA, RegName(d.vB), RegName(d.vC), vmap);
        case K::APutChar:    return APutChar   (vA, RegName(d.vB), RegName(d.vC), vmap);
        case K::APutShort:   return APutShort  (vA, RegName(d.vB), RegName(d.vC), vmap);

        // ── Iget/Iput families (resolve field triple from const_ref) ───
        case K::IGet:
        case K::IGetWide:
        case K::IGetObject:
        case K::IGetBoolean:
        case K::IGetByte:
        case K::IGetChar:
        case K::IGetShort:
        case K::IPut:
        case K::IPutWide:
        case K::IPutObject:
        case K::IPutBoolean:
        case K::IPutByte:
        case K::IPutChar:
        case K::IPutShort: {
            const FieldConst* fc = AsField(ri.const_ref);
            std::string_view klass = fc ? fc->triple[0] : std::string_view{};
            std::string_view name  = fc ? fc->triple[1] : std::string_view{};
            std::string_view ftype = fc ? fc->triple[2] : std::string_view{};
            std::string vB = RegName(d.vB);
            switch (kind) {
                case K::IGet:        return IGet       (vA, vB, klass, ftype, name, vmap);
                case K::IGetWide:    return IGetWide   (vA, vB, klass, ftype, name, vmap);
                case K::IGetObject:  return IGetObject (vA, vB, klass, ftype, name, vmap);
                case K::IGetBoolean: return IGetBoolean(vA, vB, klass, ftype, name, vmap);
                case K::IGetByte:    return IGetByte   (vA, vB, klass, ftype, name, vmap);
                case K::IGetChar:    return IGetChar   (vA, vB, klass, ftype, name, vmap);
                case K::IGetShort:   return IGetShort  (vA, vB, klass, ftype, name, vmap);
                case K::IPut:        return IPut       (vA, vB, klass, ftype, name, vmap);
                case K::IPutWide:    return IPutWide   (vA, vB, klass, ftype, name, vmap);
                case K::IPutObject:  return IPutObject (vA, vB, klass, ftype, name, vmap);
                case K::IPutBoolean: return IPutBoolean(vA, vB, klass, ftype, name, vmap);
                case K::IPutByte:    return IPutByte   (vA, vB, klass, ftype, name, vmap);
                case K::IPutChar:    return IPutChar   (vA, vB, klass, ftype, name, vmap);
                case K::IPutShort:   return IPutShort  (vA, vB, klass, ftype, name, vmap);
                default: break;
            }
            return std::make_shared<NopExpression>();
        }

        // ── Sget/Sput families ─────────────────────────────────────────
        case K::SGet:
        case K::SGetWide:
        case K::SGetObject:
        case K::SGetBoolean:
        case K::SGetByte:
        case K::SGetChar:
        case K::SGetShort:
        case K::SPut:
        case K::SPutWide:
        case K::SPutObject:
        case K::SPutBoolean:
        case K::SPutByte:
        case K::SPutChar:
        case K::SPutShort: {
            const FieldConst* fc = AsField(ri.const_ref);
            std::string_view klass = fc ? fc->triple[0] : std::string_view{};
            std::string_view name  = fc ? fc->triple[1] : std::string_view{};
            std::string_view ftype = fc ? fc->triple[2] : std::string_view{};
            switch (kind) {
                case K::SGet:        return SGet       (vA, klass, ftype, name, vmap);
                case K::SGetWide:    return SGetWide   (vA, klass, ftype, name, vmap);
                case K::SGetObject:  return SGetObject (vA, klass, ftype, name, vmap);
                case K::SGetBoolean: return SGetBoolean(vA, klass, ftype, name, vmap);
                case K::SGetByte:    return SGetByte   (vA, klass, ftype, name, vmap);
                case K::SGetChar:    return SGetChar   (vA, klass, ftype, name, vmap);
                case K::SGetShort:   return SGetShort  (vA, klass, ftype, name, vmap);
                case K::SPut:        return SPut       (vA, klass, ftype, name, vmap);
                case K::SPutWide:    return SPutWide   (vA, klass, ftype, name, vmap);
                case K::SPutObject:  return SPutObject (vA, klass, ftype, name, vmap);
                case K::SPutBoolean: return SPutBoolean(vA, klass, ftype, name, vmap);
                case K::SPutByte:    return SPutByte   (vA, klass, ftype, name, vmap);
                case K::SPutChar:    return SPutChar   (vA, klass, ftype, name, vmap);
                case K::SPutShort:   return SPutShort  (vA, klass, ftype, name, vmap);
                default: break;
            }
            return std::make_shared<NopExpression>();
        }

        // ── Invoke-kind (35c) ──────────────────────────────────────────
        case K::InvokeVirtual:
        case K::InvokeSuper:
        case K::InvokeDirect:
        case K::InvokeStatic:
        case K::InvokeInterface: {
            const MethodConst* mc = AsMethod(ri.const_ref);
            if (!mc) return std::make_shared<NopExpression>();
            MethodRef m = BuildMethodRef(*mc);
            auto regs = BuildInvokeRegs(d);
            switch (kind) {
                case K::InvokeVirtual:
                    return InvokeVirtual(m, regs.c, regs.d, regs.e, regs.f, regs.g, gen_ret, vmap);
                case K::InvokeSuper:
                    return InvokeSuper(m, regs.c, regs.d, regs.e, regs.f, regs.g, gen_ret, vmap);
                case K::InvokeDirect:
                    return InvokeDirect(m, regs.c, regs.d, regs.e, regs.f, regs.g, gen_ret, vmap);
                case K::InvokeStatic:
                    return InvokeStatic(m, regs.c, regs.d, regs.e, regs.f, regs.g, gen_ret, vmap);
                case K::InvokeInterface:
                    return InvokeInterface(m, regs.c, regs.d, regs.e, regs.f, regs.g, gen_ret, vmap);
                default: break;
            }
            return std::make_shared<NopExpression>();
        }

        // ── Invoke-range (3rc) ─────────────────────────────────────────
        case K::InvokeVirtualRange:
        case K::InvokeSuperRange:
        case K::InvokeDirectRange:
        case K::InvokeStaticRange:
        case K::InvokeInterfaceRange: {
            const MethodConst* mc = AsMethod(ri.const_ref);
            if (!mc) return std::make_shared<NopExpression>();
            MethodRef m = BuildMethodRef(*mc);
            auto regs = BuildRangeRegs(d.vA, d.vC);
            switch (kind) {
                case K::InvokeVirtualRange:
                    return InvokeVirtualRange(m, regs, gen_ret, vmap);
                case K::InvokeSuperRange:
                    return InvokeSuperRange(m, regs, gen_ret, vmap);
                case K::InvokeDirectRange:
                    return InvokeDirectRange(m, regs, gen_ret, vmap);
                case K::InvokeStaticRange:
                    return InvokeStaticRange(m, regs, gen_ret, vmap);
                case K::InvokeInterfaceRange:
                    return InvokeInterfaceRange(m, regs, gen_ret, vmap);
                default: break;
            }
            return std::make_shared<NopExpression>();
        }

        // ── Unary (12x) ────────────────────────────────────────────────
        case K::NegInt:    return NegInt   (vA, RegName(d.vB), vmap);
        case K::NotInt:    return NotInt   (vA, RegName(d.vB), vmap);
        case K::NegLong:   return NegLong  (vA, RegName(d.vB), vmap);
        case K::NotLong:   return NotLong  (vA, RegName(d.vB), vmap);
        case K::NegFloat:  return NegFloat (vA, RegName(d.vB), vmap);
        case K::NegDouble: return NegDouble(vA, RegName(d.vB), vmap);

        // ── Type conversion (12x) ──────────────────────────────────────
        case K::IntToLong:    return IntToLong   (vA, RegName(d.vB), vmap);
        case K::IntToFloat:   return IntToFloat  (vA, RegName(d.vB), vmap);
        case K::IntToDouble:  return IntToDouble (vA, RegName(d.vB), vmap);
        case K::LongToInt:    return LongToInt   (vA, RegName(d.vB), vmap);
        case K::LongToFloat:  return LongToFloat (vA, RegName(d.vB), vmap);
        case K::LongToDouble: return LongToDouble(vA, RegName(d.vB), vmap);
        case K::FloatToInt:    return FloatToInt   (vA, RegName(d.vB), vmap);
        case K::FloatToLong:   return FloatToLong  (vA, RegName(d.vB), vmap);
        case K::FloatToDouble: return FloatToDouble(vA, RegName(d.vB), vmap);
        case K::DoubleToInt:   return DoubleToInt  (vA, RegName(d.vB), vmap);
        case K::DoubleToLong:  return DoubleToLong (vA, RegName(d.vB), vmap);
        case K::DoubleToFloat: return DoubleToFloat(vA, RegName(d.vB), vmap);
        case K::IntToByte:  return IntToByte (vA, RegName(d.vB), vmap);
        case K::IntToChar:  return IntToChar (vA, RegName(d.vB), vmap);
        case K::IntToShort: return IntToShort(vA, RegName(d.vB), vmap);

        // ── Arithmetic 3-addr (23x) ────────────────────────────────────
        case K::AddInt: return AddInt(vA, RegName(d.vB), RegName(d.vC), vmap);
        case K::SubInt: return SubInt(vA, RegName(d.vB), RegName(d.vC), vmap);
        case K::MulInt: return MulInt(vA, RegName(d.vB), RegName(d.vC), vmap);
        case K::DivInt: return DivInt(vA, RegName(d.vB), RegName(d.vC), vmap);
        case K::RemInt: return RemInt(vA, RegName(d.vB), RegName(d.vC), vmap);
        case K::AndInt: return AndInt(vA, RegName(d.vB), RegName(d.vC), vmap);
        case K::OrInt:  return OrInt (vA, RegName(d.vB), RegName(d.vC), vmap);
        case K::XorInt: return XorInt(vA, RegName(d.vB), RegName(d.vC), vmap);
        case K::ShlInt: return ShlInt(vA, RegName(d.vB), RegName(d.vC), vmap);
        case K::ShrInt: return ShrInt(vA, RegName(d.vB), RegName(d.vC), vmap);
        case K::UShrInt:return UShrInt(vA, RegName(d.vB), RegName(d.vC), vmap);

        case K::AddLong: return AddLong(vA, RegName(d.vB), RegName(d.vC), vmap);
        case K::SubLong: return SubLong(vA, RegName(d.vB), RegName(d.vC), vmap);
        case K::MulLong: return MulLong(vA, RegName(d.vB), RegName(d.vC), vmap);
        case K::DivLong: return DivLong(vA, RegName(d.vB), RegName(d.vC), vmap);
        case K::RemLong: return RemLong(vA, RegName(d.vB), RegName(d.vC), vmap);
        case K::AndLong: return AndLong(vA, RegName(d.vB), RegName(d.vC), vmap);
        case K::OrLong:  return OrLong (vA, RegName(d.vB), RegName(d.vC), vmap);
        case K::XorLong: return XorLong(vA, RegName(d.vB), RegName(d.vC), vmap);
        case K::ShlLong: return ShlLong(vA, RegName(d.vB), RegName(d.vC), vmap);
        case K::ShrLong: return ShrLong(vA, RegName(d.vB), RegName(d.vC), vmap);
        case K::UShrLong:return UShrLong(vA, RegName(d.vB), RegName(d.vC), vmap);

        case K::AddFloat: return AddFloat(vA, RegName(d.vB), RegName(d.vC), vmap);
        case K::SubFloat: return SubFloat(vA, RegName(d.vB), RegName(d.vC), vmap);
        case K::MulFloat: return MulFloat(vA, RegName(d.vB), RegName(d.vC), vmap);
        case K::DivFloat: return DivFloat(vA, RegName(d.vB), RegName(d.vC), vmap);
        case K::RemFloat: return RemFloat(vA, RegName(d.vB), RegName(d.vC), vmap);
        case K::AddDouble:return AddDouble(vA, RegName(d.vB), RegName(d.vC), vmap);
        case K::SubDouble:return SubDouble(vA, RegName(d.vB), RegName(d.vC), vmap);
        case K::MulDouble:return MulDouble(vA, RegName(d.vB), RegName(d.vC), vmap);
        case K::DivDouble:return DivDouble(vA, RegName(d.vB), RegName(d.vC), vmap);
        case K::RemDouble:return RemDouble(vA, RegName(d.vB), RegName(d.vC), vmap);

        // ── Arithmetic 2-addr (12x) ────────────────────────────────────
        case K::AddInt2Addr:  return AddInt2Addr (vA, RegName(d.vB), vmap);
        case K::SubInt2Addr:  return SubInt2Addr (vA, RegName(d.vB), vmap);
        case K::MulInt2Addr:  return MulInt2Addr (vA, RegName(d.vB), vmap);
        case K::DivInt2Addr:  return DivInt2Addr (vA, RegName(d.vB), vmap);
        case K::RemInt2Addr:  return RemInt2Addr (vA, RegName(d.vB), vmap);
        case K::AndInt2Addr:  return AndInt2Addr (vA, RegName(d.vB), vmap);
        case K::OrInt2Addr:   return OrInt2Addr  (vA, RegName(d.vB), vmap);
        case K::XorInt2Addr:  return XorInt2Addr (vA, RegName(d.vB), vmap);
        case K::ShlInt2Addr:  return ShlInt2Addr (vA, RegName(d.vB), vmap);
        case K::ShrInt2Addr:  return ShrInt2Addr (vA, RegName(d.vB), vmap);
        case K::UShrInt2Addr: return UShrInt2Addr(vA, RegName(d.vB), vmap);
        case K::AddLong2Addr: return AddLong2Addr(vA, RegName(d.vB), vmap);
        case K::SubLong2Addr: return SubLong2Addr(vA, RegName(d.vB), vmap);
        case K::MulLong2Addr: return MulLong2Addr(vA, RegName(d.vB), vmap);
        case K::DivLong2Addr: return DivLong2Addr(vA, RegName(d.vB), vmap);
        case K::RemLong2Addr: return RemLong2Addr(vA, RegName(d.vB), vmap);
        case K::AndLong2Addr: return AndLong2Addr(vA, RegName(d.vB), vmap);
        case K::OrLong2Addr:  return OrLong2Addr (vA, RegName(d.vB), vmap);
        case K::XorLong2Addr: return XorLong2Addr(vA, RegName(d.vB), vmap);
        case K::ShlLong2Addr: return ShlLong2Addr(vA, RegName(d.vB), vmap);
        case K::ShrLong2Addr: return ShrLong2Addr(vA, RegName(d.vB), vmap);
        case K::UShrLong2Addr:return UShrLong2Addr(vA, RegName(d.vB), vmap);
        case K::AddFloat2Addr:return AddFloat2Addr(vA, RegName(d.vB), vmap);
        case K::SubFloat2Addr:return SubFloat2Addr(vA, RegName(d.vB), vmap);
        case K::MulFloat2Addr:return MulFloat2Addr(vA, RegName(d.vB), vmap);
        case K::DivFloat2Addr:return DivFloat2Addr(vA, RegName(d.vB), vmap);
        case K::RemFloat2Addr:return RemFloat2Addr(vA, RegName(d.vB), vmap);
        case K::AddDouble2Addr:return AddDouble2Addr(vA, RegName(d.vB), vmap);
        case K::SubDouble2Addr:return SubDouble2Addr(vA, RegName(d.vB), vmap);
        case K::MulDouble2Addr:return MulDouble2Addr(vA, RegName(d.vB), vmap);
        case K::DivDouble2Addr:return DivDouble2Addr(vA, RegName(d.vB), vmap);
        case K::RemDouble2Addr:return RemDouble2Addr(vA, RegName(d.vB), vmap);

        // ── Arithmetic literal-16 (22s) — slicer already sign-extended vC
        //    into u4. Re-interpret as int32_t to recover the signed value
        //    before widening to int64_t (avoids zero-extension bug).
        case K::AddIntLit16: return AddIntLit16(vA, RegName(d.vB), static_cast<int32_t>(d.vC), vmap);
        case K::RSubInt:     return RSubInt    (vA, RegName(d.vB), static_cast<int32_t>(d.vC), vmap);
        case K::MulIntLit16: return MulIntLit16(vA, RegName(d.vB), static_cast<int32_t>(d.vC), vmap);
        case K::DivIntLit16: return DivIntLit16(vA, RegName(d.vB), static_cast<int32_t>(d.vC), vmap);
        case K::RemIntLit16: return RemIntLit16(vA, RegName(d.vB), static_cast<int32_t>(d.vC), vmap);
        case K::AndIntLit16: return AndIntLit16(vA, RegName(d.vB), static_cast<int32_t>(d.vC), vmap);
        case K::OrIntLit16:  return OrIntLit16 (vA, RegName(d.vB), static_cast<int32_t>(d.vC), vmap);
        case K::XorIntLit16: return XorIntLit16(vA, RegName(d.vB), static_cast<int32_t>(d.vC), vmap);

        // ── Arithmetic literal-8 (22b) — same sign-extension recovery. ──
        case K::AddIntLit8: return AddIntLit8(vA, RegName(d.vB), static_cast<int32_t>(d.vC), vmap);
        case K::RSubIntLit8:return RSubIntLit8(vA, RegName(d.vB), static_cast<int32_t>(d.vC), vmap);
        case K::MulIntLit8: return MulIntLit8(vA, RegName(d.vB), static_cast<int32_t>(d.vC), vmap);
        case K::DivIntLit8: return DivIntLit8(vA, RegName(d.vB), static_cast<int32_t>(d.vC), vmap);
        case K::RemIntLit8: return RemIntLit8(vA, RegName(d.vB), static_cast<int32_t>(d.vC), vmap);
        case K::AndIntLit8: return AndIntLit8(vA, RegName(d.vB), static_cast<int32_t>(d.vC), vmap);
        case K::OrIntLit8:  return OrIntLit8 (vA, RegName(d.vB), static_cast<int32_t>(d.vC), vmap);
        case K::XorIntLit8: return XorIntLit8(vA, RegName(d.vB), static_cast<int32_t>(d.vC), vmap);
        case K::ShlIntLit8: return ShlIntLit8(vA, RegName(d.vB), static_cast<int32_t>(d.vC), vmap);
        case K::ShrIntLit8: return ShrIntLit8(vA, RegName(d.vB), static_cast<int32_t>(d.vC), vmap);
        case K::UShrIntLit8:return UShrIntLit8(vA, RegName(d.vB), static_cast<int32_t>(d.vC), vmap);
    }

    // Should be unreachable; defensive fall-through.
    return std::make_shared<NopExpression>();
}

}  // namespace dexkit::dad
