// opcode_ins.h — C++ port of androguard DAD opcode_ins.py
// DAD: androguard/decompiler/opcode_ins.py
//
// This module corresponds to androguard's DAD <opcode_ins.py>. Every function
// added carries a `// DAD: opcode_ins.py:<lineno> <concept>` comment in the .cpp.
//
// PORT STATUS (chunks A-F — opcode_ins.py 100% complete):
//   Ported (A — helpers):
//     - Op / get_variables / assign_* helpers (DAD opcode_ins.py:65-141)
//   Ported (B — 41 ops, lines 147-465):
//     - nop / move family / return / const / monitor / check-cast / etc.
//   Ported (C — 59 ops, lines 467-895):
//     - cmpl/cmpg-float, cmpl/cmpg-double, cmp-long (5)
//     - if-{eq,ne,lt,ge,gt,le} (6) and if-{eq,ne,lt,ge,gt,le}z (6)
//     - aget family (7) + aput family (7)
//     - iget family (7) + iput family (7)
//     - sget family (7) + sput family (7)
//   Ported (D — invoke family, 10 ops + get_args helper, lines 898-1134):
//     - get_args (DAD-quirky single-arg fallback)
//     - invoke-{virtual,super,direct,static,interface} (5)
//     - invoke-{virtual,super,direct,static,interface}/range (5)
//   Ported (E — unary/cast + arithmetic family, lines 1137-1775):
//     - neg/not (6) + type-conv (14) + arithmetic 3-addr (32)
//     - arithmetic 2addr (32) + lit16 (8) + lit8 (11)
//     - rsubint / rsubintlit8 (reversed operand order, not assign_lit)
//   Ported (F — INSTRUCTION_SET dispatch table, line 1780):
//     - kInstructionSet: opcode (uint8_t) → OpcodeKind enum
//     - DAD's "unused" slots map to OpcodeKind::Nop (matching the Python
//       fallback). Opcodes beyond 0xE2 map to OpcodeKind::Unused since
//       DAD's array doesn't cover them.
//   Deferred: none — opcode_ins.py port complete.
//
// Notes:
//   * Handlers in DAD take an `ins` object (androguard's Instruction) and
//     access fields like `ins.AA / ins.B / ins.BBBBBBBB`. Since androguard's
//     instruction format is out of DAD's port scope, we ditch the abstraction
//     and accept operand fields explicitly — drivers extract them from
//     whatever Dalvik decoder they're using and pass them in.
//   * `vmap` is the per-method register-id → IRForm cache. Variable nodes are
//     created lazily on first reference (setdefault semantics).

#pragma once

#include <initializer_list>
#include <string>
#include <string_view>
#include <unordered_map>
#include <vector>

#include "instruction.h"

namespace dexkit::dad {

// DAD: opcode_ins.py:65 Op — string constants for IR operators.
namespace Op {
inline constexpr std::string_view CMP      = "cmp";
inline constexpr std::string_view ADD      = "+";
inline constexpr std::string_view SUB      = "-";
inline constexpr std::string_view MUL      = "*";
inline constexpr std::string_view DIV      = "/";
inline constexpr std::string_view MOD      = "%";
inline constexpr std::string_view AND_     = "&";
inline constexpr std::string_view OR_      = "|";
inline constexpr std::string_view XOR_     = "^";
inline constexpr std::string_view EQUAL    = "==";
inline constexpr std::string_view NEQUAL   = "!=";
inline constexpr std::string_view GREATER  = ">";
inline constexpr std::string_view LOWER    = "<";
inline constexpr std::string_view GEQUAL   = ">=";
inline constexpr std::string_view LEQUAL   = "<=";
inline constexpr std::string_view NEG      = "-";
inline constexpr std::string_view NOT_     = "~";
inline constexpr std::string_view INTSHL   = "<<";  // '(%s << ( %s & 0x1f ))'
inline constexpr std::string_view INTSHR   = ">>";  // '(%s >> ( %s & 0x1f ))'
inline constexpr std::string_view LONGSHL  = "<<";  // '(%s << ( %s & 0x3f ))'
inline constexpr std::string_view LONGSHR  = ">>";  // '(%s >> ( %s & 0x3f ))'
}  // namespace Op

// vmap: per-method cache of register-id → IRForm node (initially Variable).
using Vmap = std::unordered_map<std::string, IRFormPtr>;

// DAD: opcode_ins.py:89 get_variables — single-arg overload.
//
// Python's `vmap.setdefault(variable, Variable(variable))` returns the
// existing entry if present, otherwise inserts a fresh Variable and returns
// it. We mirror that semantic; on insert the new Variable's `.v` and `.name`
// both equal `variable`.
IRFormPtr GetVariable(Vmap& vmap, std::string_view variable);

// DAD: opcode_ins.py:89 get_variables — multi-arg overload.
//
// Python returns a single Variable when called with one arg, otherwise a
// list. We split into two named functions; callers pick by arity.
std::vector<IRFormPtr> GetVariables(
        Vmap& vmap,
        std::initializer_list<std::string_view> variables);

// DAD: opcode_ins.py:98 assign_const — AssignExpression(dest, cst).
IRFormPtr AssignConst(std::string_view dest_reg, IRFormPtr cst, Vmap& vmap);

// DAD: opcode_ins.py:102 assign_cmp.
IRFormPtr AssignCmp(std::string_view val_a, std::string_view val_b,
                    std::string_view val_c, std::string_view cmp_type,
                    Vmap& vmap);

// DAD: opcode_ins.py:108 load_array_exp.
IRFormPtr LoadArrayExp(std::string_view val_a, std::string_view val_b,
                       std::string_view val_c, std::string_view ar_type,
                       Vmap& vmap);

// DAD: opcode_ins.py:113 store_array_inst.
IRFormPtr StoreArrayInst(std::string_view val_a, std::string_view val_b,
                         std::string_view val_c, std::string_view ar_type,
                         Vmap& vmap);

// DAD: opcode_ins.py:118 assign_cast_exp.
IRFormPtr AssignCastExp(std::string_view val_a, std::string_view val_b,
                        std::string_view val_op, std::string_view op_type,
                        Vmap& vmap);

// DAD: opcode_ins.py:123 assign_binary_exp.
// `ins.AA / ins.BB / ins.CC` mapped here to explicit operand IDs.
IRFormPtr AssignBinaryExp(std::string_view ins_aa, std::string_view ins_bb,
                          std::string_view ins_cc, std::string_view val_op,
                          std::string_view op_type, Vmap& vmap);

// DAD: opcode_ins.py:130 assign_binary_2addr_exp.
// `ins.A / ins.B` mapped to explicit operand IDs.
IRFormPtr AssignBinary2AddrExp(std::string_view ins_a, std::string_view ins_b,
                               std::string_view val_op,
                               std::string_view op_type, Vmap& vmap);

// DAD: opcode_ins.py:137 assign_lit.
IRFormPtr AssignLit(std::string_view op_type, int64_t val_cst,
                    std::string_view val_a, std::string_view val_b,
                    Vmap& vmap);

// =============================================================================
// Chunk B — single-opcode handlers (lines 147-465).
//
// Each handler maps a single Dalvik opcode to an IR node. Operand fields are
// passed explicitly (DAD's `ins.AA / ins.B / ins.BBBBBBBB` etc.); the driver
// is responsible for extracting them from whatever instruction decoder it
// uses. `vmap` is the running register-id → IRForm cache.
//
// Register operands (e.g. `ins.A`, `ins.AA`, `ins.BBBB`) are passed as
// `std::string_view` because Variable construction wants a string `.v`.
// Immediate / literal / index operands are passed as int64_t or std::string
// (raw string for const-string, descriptor for class refs).
// =============================================================================

// DAD: opcode_ins.py:147 nop
IRFormPtr Nop();

// DAD: opcode_ins.py:152 move (also movefrom16, move16, movewide, movewide16,
// movewidefrom16, moveobject, moveobjectfrom16, moveobject16). All 10
// variants share the same IR construction; we expose one helper named per
// DAD entry point for 1:1 mapping with the INSTRUCTION_SET dispatch table.
IRFormPtr Move(std::string_view a, std::string_view b, Vmap& vmap);
IRFormPtr MoveFrom16(std::string_view aa, std::string_view bbbb, Vmap& vmap);
IRFormPtr Move16(std::string_view aaaa, std::string_view bbbb, Vmap& vmap);
IRFormPtr MoveWide(std::string_view a, std::string_view b, Vmap& vmap);
IRFormPtr MoveWideFrom16(std::string_view aa, std::string_view bbbb, Vmap& vmap);
IRFormPtr MoveWide16(std::string_view aaaa, std::string_view bbbb, Vmap& vmap);
IRFormPtr MoveObject(std::string_view a, std::string_view b, Vmap& vmap);
IRFormPtr MoveObjectFrom16(std::string_view aa, std::string_view bbbb, Vmap& vmap);
IRFormPtr MoveObject16(std::string_view aaaa, std::string_view bbbb, Vmap& vmap);

// DAD: opcode_ins.py:215 moveresult / 221 moveresultwide / 227 moveresultobject.
// The `ret` IRForm represents the value the preceding invoke returned —
// driver tracks this across instructions.
IRFormPtr MoveResult(std::string_view aa, IRFormPtr ret, Vmap& vmap);
IRFormPtr MoveResultWide(std::string_view aa, IRFormPtr ret, Vmap& vmap);
IRFormPtr MoveResultObject(std::string_view aa, IRFormPtr ret, Vmap& vmap);

// DAD: opcode_ins.py:233 moveexception
IRFormPtr MoveException(std::string_view aa, std::string_view atype, Vmap& vmap);

// DAD: opcode_ins.py:239-258 return-{void,reg,wide,object}
IRFormPtr ReturnVoid();
IRFormPtr ReturnReg(std::string_view aa, Vmap& vmap);
IRFormPtr ReturnWide(std::string_view aa, Vmap& vmap);
IRFormPtr ReturnObject(std::string_view aa, Vmap& vmap);

// DAD: opcode_ins.py:263-315 const family (8 variants).
// `dest` is the register id; `value` is the literal (int64 holds all variants).
IRFormPtr Const4(std::string_view a, int64_t b, Vmap& vmap);
IRFormPtr Const16(std::string_view aa, int64_t bbbb, Vmap& vmap);
IRFormPtr Const(std::string_view aa, int64_t bbbbbbbb, Vmap& vmap);
IRFormPtr ConstHigh16(std::string_view aa, int64_t bbbb, Vmap& vmap);
IRFormPtr ConstWide16(std::string_view aa, int64_t bbbb, Vmap& vmap);
IRFormPtr ConstWide32(std::string_view aa, int64_t bbbbbbbb, Vmap& vmap);
IRFormPtr ConstWide(std::string_view aa, int64_t b64, Vmap& vmap);
IRFormPtr ConstWideHigh16(std::string_view aa, int64_t bbbb, Vmap& vmap);

// DAD: opcode_ins.py:319-340 const-string{,jumbo} and const-class.
IRFormPtr ConstString(std::string_view aa, std::string_view raw_string, Vmap& vmap);
IRFormPtr ConstStringJumbo(std::string_view aa, std::string_view raw_string, Vmap& vmap);
// `kind` is the Dalvik type descriptor (e.g. "Lcom/X;") for the class-ref.
IRFormPtr ConstClass(std::string_view aa, std::string_view kind, Vmap& vmap);

// DAD: opcode_ins.py:344-353 monitor enter/exit.
IRFormPtr MonitorEnter(std::string_view aa, Vmap& vmap);
IRFormPtr MonitorExit(std::string_view aa, Vmap& vmap);

// DAD: opcode_ins.py:357 check-cast — `translated_kind` is descriptor.
IRFormPtr CheckCast(std::string_view aa, std::string_view translated_kind,
                    Vmap& vmap);

// DAD: opcode_ins.py:368 instance-of — `translated_kind` is descriptor.
IRFormPtr InstanceOf(std::string_view a, std::string_view b,
                     std::string_view translated_kind, Vmap& vmap);

// DAD: opcode_ins.py:380 array-length.
IRFormPtr ArrayLength(std::string_view a, std::string_view b, Vmap& vmap);

// DAD: opcode_ins.py:387 new-instance — `type_desc` is descriptor of new type.
IRFormPtr NewInstance_(std::string_view aa, std::string_view type_desc,
                       Vmap& vmap);

// DAD: opcode_ins.py:395 new-array — `type_desc` is element-array descriptor.
IRFormPtr NewArray(std::string_view a, std::string_view b,
                   std::string_view type_desc, Vmap& vmap);

// DAD: opcode_ins.py:403 filled-new-array — `count` = ins.A (0..5),
// `type_desc` = ins.cm.get_type(ins.BBBB), regs c,d,e,f,g are operand register
// strings (caller can pass empty strings for unused slots; we trim by count).
// `ret` represents the receiving register (driver-supplied).
IRFormPtr FilledNewArray(int64_t count, std::string_view type_desc,
                         std::string_view c, std::string_view d,
                         std::string_view e, std::string_view f,
                         std::string_view g, IRFormPtr ret, Vmap& vmap);

// DAD: opcode_ins.py:412 filled-new-array/range — pass first/last register
// IDs of the range as `cccc`/`nnnn`; `aa` = count.
IRFormPtr FilledNewArrayRange(int64_t count, std::string_view type_desc,
                              std::string_view cccc, std::string_view nnnn,
                              IRFormPtr ret, Vmap& vmap);

// DAD: opcode_ins.py:421 fill-array-data — `value` is the payload (vector
// of int64_t covering all DAD payload widths).
IRFormPtr FillArrayData(std::string_view aa, std::vector<int64_t> value,
                        Vmap& vmap);

// DAD: opcode_ins.py:427 fill-array-data-payload — DAD's body is wrong here:
// `return FillArrayExpression(None)` — would crash. Reproduce faithfully:
// throw on call so callers know this path is broken upstream.
IRFormPtr FillArrayDataPayload();

// DAD: opcode_ins.py:433 throw
IRFormPtr Throw(std::string_view aa, Vmap& vmap);

// DAD: opcode_ins.py:439-450 goto/goto16/goto32 — all return NopExpression.
IRFormPtr Goto();
IRFormPtr Goto16();
IRFormPtr Goto32();

// DAD: opcode_ins.py:454-464 packed-switch / sparse-switch.
// `branch` is the 32-bit relative offset (DAD passes raw `ins.BBBBBBBB`).
IRFormPtr PackedSwitch(std::string_view aa, int32_t branch, Vmap& vmap);
IRFormPtr SparseSwitch(std::string_view aa, int32_t branch, Vmap& vmap);

// =============================================================================
// Chunk C — comparison / branch / array+instance+static accessor handlers
// (DAD opcode_ins.py:467-895).
// =============================================================================

// DAD: opcode_ins.py:467-494 cmp{l,g}-float / cmp{l,g}-double / cmp-long.
// All five funnel into assign_cmp with a different cmp_type ('F','D','J').
IRFormPtr CmplFloat (std::string_view aa, std::string_view bb,
                     std::string_view cc, Vmap& vmap);
IRFormPtr CmpgFloat (std::string_view aa, std::string_view bb,
                     std::string_view cc, Vmap& vmap);
IRFormPtr CmplDouble(std::string_view aa, std::string_view bb,
                     std::string_view cc, Vmap& vmap);
IRFormPtr CmpgDouble(std::string_view aa, std::string_view bb,
                     std::string_view cc, Vmap& vmap);
IRFormPtr CmpLong   (std::string_view aa, std::string_view bb,
                     std::string_view cc, Vmap& vmap);

// DAD: opcode_ins.py:498-536 if-{eq,ne,lt,ge,gt,le}.
IRFormPtr IfEq(std::string_view a, std::string_view b, Vmap& vmap);
IRFormPtr IfNe(std::string_view a, std::string_view b, Vmap& vmap);
IRFormPtr IfLt(std::string_view a, std::string_view b, Vmap& vmap);
IRFormPtr IfGe(std::string_view a, std::string_view b, Vmap& vmap);
IRFormPtr IfGt(std::string_view a, std::string_view b, Vmap& vmap);
IRFormPtr IfLe(std::string_view a, std::string_view b, Vmap& vmap);

// DAD: opcode_ins.py:540-572 if-{eq,ne,lt,ge,gt,le}z.
IRFormPtr IfEqz(std::string_view aa, Vmap& vmap);
IRFormPtr IfNez(std::string_view aa, Vmap& vmap);
IRFormPtr IfLtz(std::string_view aa, Vmap& vmap);
IRFormPtr IfGez(std::string_view aa, Vmap& vmap);
IRFormPtr IfGtz(std::string_view aa, Vmap& vmap);
IRFormPtr IfLez(std::string_view aa, Vmap& vmap);

// DAD: opcode_ins.py:577-615 aget family — load_array_exp with type tag.
// `aget` uses type=None (we pass ""); other variants tag with W/O/Z/B/C/S.
IRFormPtr AGet       (std::string_view aa, std::string_view bb,
                      std::string_view cc, Vmap& vmap);
IRFormPtr AGetWide   (std::string_view aa, std::string_view bb,
                      std::string_view cc, Vmap& vmap);
IRFormPtr AGetObject (std::string_view aa, std::string_view bb,
                      std::string_view cc, Vmap& vmap);
IRFormPtr AGetBoolean(std::string_view aa, std::string_view bb,
                      std::string_view cc, Vmap& vmap);
IRFormPtr AGetByte   (std::string_view aa, std::string_view bb,
                      std::string_view cc, Vmap& vmap);
IRFormPtr AGetChar   (std::string_view aa, std::string_view bb,
                      std::string_view cc, Vmap& vmap);
IRFormPtr AGetShort  (std::string_view aa, std::string_view bb,
                      std::string_view cc, Vmap& vmap);

// DAD: opcode_ins.py:619-657 aput family — store_array_inst with type tag.
IRFormPtr APut       (std::string_view aa, std::string_view bb,
                      std::string_view cc, Vmap& vmap);
IRFormPtr APutWide   (std::string_view aa, std::string_view bb,
                      std::string_view cc, Vmap& vmap);
IRFormPtr APutObject (std::string_view aa, std::string_view bb,
                      std::string_view cc, Vmap& vmap);
IRFormPtr APutBoolean(std::string_view aa, std::string_view bb,
                      std::string_view cc, Vmap& vmap);
IRFormPtr APutByte   (std::string_view aa, std::string_view bb,
                      std::string_view cc, Vmap& vmap);
IRFormPtr APutChar   (std::string_view aa, std::string_view bb,
                      std::string_view cc, Vmap& vmap);
IRFormPtr APutShort  (std::string_view aa, std::string_view bb,
                      std::string_view cc, Vmap& vmap);

// DAD: opcode_ins.py:661-720 iget family — InstanceExpression read.
// DAD calls `ins.cm.get_field(ins.CCCC)` to resolve (klass, ftype, name).
// Since we ditched the `cm`/`ins` abstraction the driver pre-resolves and
// passes those three fields explicitly. All 7 variants share identical body.
IRFormPtr IGet       (std::string_view a, std::string_view b,
                      std::string_view klass, std::string_view ftype,
                      std::string_view name, Vmap& vmap);
IRFormPtr IGetWide   (std::string_view a, std::string_view b,
                      std::string_view klass, std::string_view ftype,
                      std::string_view name, Vmap& vmap);
IRFormPtr IGetObject (std::string_view a, std::string_view b,
                      std::string_view klass, std::string_view ftype,
                      std::string_view name, Vmap& vmap);
IRFormPtr IGetBoolean(std::string_view a, std::string_view b,
                      std::string_view klass, std::string_view ftype,
                      std::string_view name, Vmap& vmap);
IRFormPtr IGetByte   (std::string_view a, std::string_view b,
                      std::string_view klass, std::string_view ftype,
                      std::string_view name, Vmap& vmap);
IRFormPtr IGetChar   (std::string_view a, std::string_view b,
                      std::string_view klass, std::string_view ftype,
                      std::string_view name, Vmap& vmap);
IRFormPtr IGetShort  (std::string_view a, std::string_view b,
                      std::string_view klass, std::string_view ftype,
                      std::string_view name, Vmap& vmap);

// DAD: opcode_ins.py:724-776 iput family — InstanceInstruction write.
IRFormPtr IPut       (std::string_view a, std::string_view b,
                      std::string_view klass, std::string_view atype,
                      std::string_view name, Vmap& vmap);
IRFormPtr IPutWide   (std::string_view a, std::string_view b,
                      std::string_view klass, std::string_view atype,
                      std::string_view name, Vmap& vmap);
IRFormPtr IPutObject (std::string_view a, std::string_view b,
                      std::string_view klass, std::string_view atype,
                      std::string_view name, Vmap& vmap);
IRFormPtr IPutBoolean(std::string_view a, std::string_view b,
                      std::string_view klass, std::string_view atype,
                      std::string_view name, Vmap& vmap);
IRFormPtr IPutByte   (std::string_view a, std::string_view b,
                      std::string_view klass, std::string_view atype,
                      std::string_view name, Vmap& vmap);
IRFormPtr IPutChar   (std::string_view a, std::string_view b,
                      std::string_view klass, std::string_view atype,
                      std::string_view name, Vmap& vmap);
IRFormPtr IPutShort  (std::string_view a, std::string_view b,
                      std::string_view klass, std::string_view atype,
                      std::string_view name, Vmap& vmap);

// DAD: opcode_ins.py:780-839 sget family — StaticExpression read.
IRFormPtr SGet       (std::string_view aa, std::string_view klass,
                      std::string_view atype, std::string_view name, Vmap& vmap);
IRFormPtr SGetWide   (std::string_view aa, std::string_view klass,
                      std::string_view atype, std::string_view name, Vmap& vmap);
IRFormPtr SGetObject (std::string_view aa, std::string_view klass,
                      std::string_view atype, std::string_view name, Vmap& vmap);
IRFormPtr SGetBoolean(std::string_view aa, std::string_view klass,
                      std::string_view atype, std::string_view name, Vmap& vmap);
IRFormPtr SGetByte   (std::string_view aa, std::string_view klass,
                      std::string_view atype, std::string_view name, Vmap& vmap);
IRFormPtr SGetChar   (std::string_view aa, std::string_view klass,
                      std::string_view atype, std::string_view name, Vmap& vmap);
IRFormPtr SGetShort  (std::string_view aa, std::string_view klass,
                      std::string_view atype, std::string_view name, Vmap& vmap);

// DAD: opcode_ins.py:843-895 sput family — StaticInstruction write.
IRFormPtr SPut       (std::string_view aa, std::string_view klass,
                      std::string_view ftype, std::string_view name, Vmap& vmap);
IRFormPtr SPutWide   (std::string_view aa, std::string_view klass,
                      std::string_view ftype, std::string_view name, Vmap& vmap);
IRFormPtr SPutObject (std::string_view aa, std::string_view klass,
                      std::string_view ftype, std::string_view name, Vmap& vmap);
IRFormPtr SPutBoolean(std::string_view aa, std::string_view klass,
                      std::string_view ftype, std::string_view name, Vmap& vmap);
IRFormPtr SPutByte   (std::string_view aa, std::string_view klass,
                      std::string_view ftype, std::string_view name, Vmap& vmap);
IRFormPtr SPutChar   (std::string_view aa, std::string_view klass,
                      std::string_view ftype, std::string_view name, Vmap& vmap);
IRFormPtr SPutShort  (std::string_view aa, std::string_view klass,
                      std::string_view ftype, std::string_view name, Vmap& vmap);

// =============================================================================
// Chunk D — invoke family (lines 897-1134).
//
// `ret` tracks the cross-instruction "next return slot" — analogous to
// DAD's stateful `ret` parameter. The driver implements RetState so it can
// flow info to the subsequent move-result handler.
//
// MethodRef bundles what DAD computes from `ins.cm.get_method_ref(idx)`:
// the resolved class name (java-style via util.get_type), method name,
// parameter / return types, and the (class, name, descriptor) triple. The
// original Dalvik class descriptor is preserved for BaseClass on static
// invokes that need the descriptor field.
// =============================================================================

// DAD's stateful "return value tracker" — implementation provided by driver.
// DAD: graph.py:439 GenInvokeRetName — { num, ret; new(); set_to(r); last(); }.
class RetState {
public:
    virtual ~RetState() = default;
    // DAD: graph.py:444 new — bump counter, mint Variable('tmp%d'), store as ret.
    virtual IRFormPtr New() = 0;
    // DAD: graph.py:449 set_to — pin .ret to a specific IRForm (invoke-direct
    // on a temp receiver for `<init>` patterns).
    virtual void SetTo(IRFormPtr v) = 0;
    // DAD: graph.py:452 last — return the last minted/pinned .ret (or null).
    // Used by build_node_from_block for the move-result* family. Provided as
    // a non-pure default returning nullptr so existing parity tests (which
    // never trigger move-result) need not override.
    virtual IRFormPtr Last() { return nullptr; }
};

struct MethodRef {
    std::string cls_name;        // util.get_type(method.get_class_name())
    std::string name;            // method.get_name()
    std::vector<std::string> param_type;  // DAD-quirky single-elem list
    std::string ret_type;        // 'V' or descriptor (e.g. 'I', 'Lcom/X;')
    InvokeInstruction::Triple triple;
    std::string original_cls_descriptor;  // for BaseClass.descriptor field
};

// DAD: opcode_ins.py:898 get_args — replicates DAD's quirky single-arg
// fallback (driven by util.get_params_type returning single-element list).
std::vector<IRFormPtr> GetArgs(Vmap& vmap,
                               const std::vector<std::string>& param_type,
                               const std::vector<std::string>& largs);

// DAD: opcode_ins.py:915 invoke-virtual.
// Operand layout: `c` = receiver register; `d,e,f,g` = up to 4 arg regs
// (pass empty for unused). Driver pre-resolves the method via MethodRef.
IRFormPtr InvokeVirtual(const MethodRef& m,
                        std::string_view c, std::string_view d,
                        std::string_view e, std::string_view f,
                        std::string_view g, RetState& ret, Vmap& vmap);

// DAD: opcode_ins.py:933 invoke-super — uses a synthetic BaseClass("super").
IRFormPtr InvokeSuper(const MethodRef& m,
                      std::string_view c, std::string_view d,
                      std::string_view e, std::string_view f,
                      std::string_view g, RetState& ret, Vmap& vmap);

// DAD: opcode_ins.py:957 invoke-direct — special case for void <init> on
// temp (returned = base, ret.set_to(base)).
IRFormPtr InvokeDirect(const MethodRef& m,
                       std::string_view c, std::string_view d,
                       std::string_view e, std::string_view f,
                       std::string_view g, RetState& ret, Vmap& vmap);

// DAD: opcode_ins.py:982 invoke-static — note the `largs` here include
// ins.C (no receiver), so 5 reg slots total.
IRFormPtr InvokeStatic(const MethodRef& m,
                       std::string_view c, std::string_view d,
                       std::string_view e, std::string_view f,
                       std::string_view g, RetState& ret, Vmap& vmap);

// DAD: opcode_ins.py:1000 invoke-interface — identical body to invoke-virtual
// modulo class kind. (DAD wraps in InvokeInstruction, not a dedicated class.)
IRFormPtr InvokeInterface(const MethodRef& m,
                          std::string_view c, std::string_view d,
                          std::string_view e, std::string_view f,
                          std::string_view g, RetState& ret, Vmap& vmap);

// DAD: opcode_ins.py:1018-1134 invoke-*/range — driver pre-expands the
// register range [CCCC..NNNN] into a string vector.
IRFormPtr InvokeVirtualRange(const MethodRef& m,
                             const std::vector<std::string>& regs,
                             RetState& ret, Vmap& vmap);
IRFormPtr InvokeSuperRange(const MethodRef& m,
                           const std::vector<std::string>& regs,
                           RetState& ret, Vmap& vmap);
IRFormPtr InvokeDirectRange(const MethodRef& m,
                            const std::vector<std::string>& regs,
                            RetState& ret, Vmap& vmap);
IRFormPtr InvokeStaticRange(const MethodRef& m,
                            const std::vector<std::string>& regs,
                            RetState& ret, Vmap& vmap);
IRFormPtr InvokeInterfaceRange(const MethodRef& m,
                               const std::vector<std::string>& regs,
                               RetState& ret, Vmap& vmap);

// =============================================================================
// Chunk E — unary + type-conv + arithmetic (3-addr / 2addr / lit16 / lit8).
// All trivial wrappers around UnaryExpression / AssignCastExp /
// AssignBinaryExp / AssignBinary2AddrExp / AssignLit, except rsubint and
// rsubintlit8 which reverse operand order.
// =============================================================================

// DAD: opcode_ins.py:1138-1182 neg/not — UnaryExpression with op+type.
IRFormPtr NegInt   (std::string_view a, std::string_view b, Vmap& vmap);
IRFormPtr NotInt   (std::string_view a, std::string_view b, Vmap& vmap);
IRFormPtr NegLong  (std::string_view a, std::string_view b, Vmap& vmap);
IRFormPtr NotLong  (std::string_view a, std::string_view b, Vmap& vmap);
IRFormPtr NegFloat (std::string_view a, std::string_view b, Vmap& vmap);
IRFormPtr NegDouble(std::string_view a, std::string_view b, Vmap& vmap);

// DAD: opcode_ins.py:1186-1272 type-conv — assign_cast_exp wrappers.
IRFormPtr IntToLong   (std::string_view a, std::string_view b, Vmap& vmap);
IRFormPtr IntToFloat  (std::string_view a, std::string_view b, Vmap& vmap);
IRFormPtr IntToDouble (std::string_view a, std::string_view b, Vmap& vmap);
IRFormPtr LongToInt   (std::string_view a, std::string_view b, Vmap& vmap);
IRFormPtr LongToFloat (std::string_view a, std::string_view b, Vmap& vmap);
IRFormPtr LongToDouble(std::string_view a, std::string_view b, Vmap& vmap);
IRFormPtr FloatToInt   (std::string_view a, std::string_view b, Vmap& vmap);
IRFormPtr FloatToLong  (std::string_view a, std::string_view b, Vmap& vmap);
IRFormPtr FloatToDouble(std::string_view a, std::string_view b, Vmap& vmap);
IRFormPtr DoubleToInt  (std::string_view a, std::string_view b, Vmap& vmap);
IRFormPtr DoubleToLong (std::string_view a, std::string_view b, Vmap& vmap);
IRFormPtr DoubleToFloat(std::string_view a, std::string_view b, Vmap& vmap);
IRFormPtr IntToByte (std::string_view a, std::string_view b, Vmap& vmap);
IRFormPtr IntToChar (std::string_view a, std::string_view b, Vmap& vmap);
IRFormPtr IntToShort(std::string_view a, std::string_view b, Vmap& vmap);

// DAD: opcode_ins.py:1276-1404 int/long arithmetic 3-addr — (aa,bb,cc).
IRFormPtr AddInt (std::string_view aa, std::string_view bb, std::string_view cc, Vmap& vmap);
IRFormPtr SubInt (std::string_view aa, std::string_view bb, std::string_view cc, Vmap& vmap);
IRFormPtr MulInt (std::string_view aa, std::string_view bb, std::string_view cc, Vmap& vmap);
IRFormPtr DivInt (std::string_view aa, std::string_view bb, std::string_view cc, Vmap& vmap);
IRFormPtr RemInt (std::string_view aa, std::string_view bb, std::string_view cc, Vmap& vmap);
IRFormPtr AndInt (std::string_view aa, std::string_view bb, std::string_view cc, Vmap& vmap);
IRFormPtr OrInt  (std::string_view aa, std::string_view bb, std::string_view cc, Vmap& vmap);
IRFormPtr XorInt (std::string_view aa, std::string_view bb, std::string_view cc, Vmap& vmap);
IRFormPtr ShlInt (std::string_view aa, std::string_view bb, std::string_view cc, Vmap& vmap);
IRFormPtr ShrInt (std::string_view aa, std::string_view bb, std::string_view cc, Vmap& vmap);
IRFormPtr UShrInt(std::string_view aa, std::string_view bb, std::string_view cc, Vmap& vmap);
IRFormPtr AddLong (std::string_view aa, std::string_view bb, std::string_view cc, Vmap& vmap);
IRFormPtr SubLong (std::string_view aa, std::string_view bb, std::string_view cc, Vmap& vmap);
IRFormPtr MulLong (std::string_view aa, std::string_view bb, std::string_view cc, Vmap& vmap);
IRFormPtr DivLong (std::string_view aa, std::string_view bb, std::string_view cc, Vmap& vmap);
IRFormPtr RemLong (std::string_view aa, std::string_view bb, std::string_view cc, Vmap& vmap);
IRFormPtr AndLong (std::string_view aa, std::string_view bb, std::string_view cc, Vmap& vmap);
IRFormPtr OrLong  (std::string_view aa, std::string_view bb, std::string_view cc, Vmap& vmap);
IRFormPtr XorLong (std::string_view aa, std::string_view bb, std::string_view cc, Vmap& vmap);
IRFormPtr ShlLong (std::string_view aa, std::string_view bb, std::string_view cc, Vmap& vmap);
IRFormPtr ShrLong (std::string_view aa, std::string_view bb, std::string_view cc, Vmap& vmap);
IRFormPtr UShrLong(std::string_view aa, std::string_view bb, std::string_view cc, Vmap& vmap);

// DAD: opcode_ins.py:1408-1464 float/double arithmetic 3-addr.
IRFormPtr AddFloat (std::string_view aa, std::string_view bb, std::string_view cc, Vmap& vmap);
IRFormPtr SubFloat (std::string_view aa, std::string_view bb, std::string_view cc, Vmap& vmap);
IRFormPtr MulFloat (std::string_view aa, std::string_view bb, std::string_view cc, Vmap& vmap);
IRFormPtr DivFloat (std::string_view aa, std::string_view bb, std::string_view cc, Vmap& vmap);
IRFormPtr RemFloat (std::string_view aa, std::string_view bb, std::string_view cc, Vmap& vmap);
IRFormPtr AddDouble(std::string_view aa, std::string_view bb, std::string_view cc, Vmap& vmap);
IRFormPtr SubDouble(std::string_view aa, std::string_view bb, std::string_view cc, Vmap& vmap);
IRFormPtr MulDouble(std::string_view aa, std::string_view bb, std::string_view cc, Vmap& vmap);
IRFormPtr DivDouble(std::string_view aa, std::string_view bb, std::string_view cc, Vmap& vmap);
IRFormPtr RemDouble(std::string_view aa, std::string_view bb, std::string_view cc, Vmap& vmap);

// DAD: opcode_ins.py:1468-1656 arithmetic 2-addr (vA, vB) — int/long/float/double.
IRFormPtr AddInt2Addr (std::string_view a, std::string_view b, Vmap& vmap);
IRFormPtr SubInt2Addr (std::string_view a, std::string_view b, Vmap& vmap);
IRFormPtr MulInt2Addr (std::string_view a, std::string_view b, Vmap& vmap);
IRFormPtr DivInt2Addr (std::string_view a, std::string_view b, Vmap& vmap);
IRFormPtr RemInt2Addr (std::string_view a, std::string_view b, Vmap& vmap);
IRFormPtr AndInt2Addr (std::string_view a, std::string_view b, Vmap& vmap);
IRFormPtr OrInt2Addr  (std::string_view a, std::string_view b, Vmap& vmap);
IRFormPtr XorInt2Addr (std::string_view a, std::string_view b, Vmap& vmap);
IRFormPtr ShlInt2Addr (std::string_view a, std::string_view b, Vmap& vmap);
IRFormPtr ShrInt2Addr (std::string_view a, std::string_view b, Vmap& vmap);
IRFormPtr UShrInt2Addr(std::string_view a, std::string_view b, Vmap& vmap);
IRFormPtr AddLong2Addr (std::string_view a, std::string_view b, Vmap& vmap);
IRFormPtr SubLong2Addr (std::string_view a, std::string_view b, Vmap& vmap);
IRFormPtr MulLong2Addr (std::string_view a, std::string_view b, Vmap& vmap);
IRFormPtr DivLong2Addr (std::string_view a, std::string_view b, Vmap& vmap);
IRFormPtr RemLong2Addr (std::string_view a, std::string_view b, Vmap& vmap);
IRFormPtr AndLong2Addr (std::string_view a, std::string_view b, Vmap& vmap);
IRFormPtr OrLong2Addr  (std::string_view a, std::string_view b, Vmap& vmap);
IRFormPtr XorLong2Addr (std::string_view a, std::string_view b, Vmap& vmap);
IRFormPtr ShlLong2Addr (std::string_view a, std::string_view b, Vmap& vmap);
IRFormPtr ShrLong2Addr (std::string_view a, std::string_view b, Vmap& vmap);
IRFormPtr UShrLong2Addr(std::string_view a, std::string_view b, Vmap& vmap);
IRFormPtr AddFloat2Addr (std::string_view a, std::string_view b, Vmap& vmap);
IRFormPtr SubFloat2Addr (std::string_view a, std::string_view b, Vmap& vmap);
IRFormPtr MulFloat2Addr (std::string_view a, std::string_view b, Vmap& vmap);
IRFormPtr DivFloat2Addr (std::string_view a, std::string_view b, Vmap& vmap);
IRFormPtr RemFloat2Addr (std::string_view a, std::string_view b, Vmap& vmap);
IRFormPtr AddDouble2Addr(std::string_view a, std::string_view b, Vmap& vmap);
IRFormPtr SubDouble2Addr(std::string_view a, std::string_view b, Vmap& vmap);
IRFormPtr MulDouble2Addr(std::string_view a, std::string_view b, Vmap& vmap);
IRFormPtr DivDouble2Addr(std::string_view a, std::string_view b, Vmap& vmap);
IRFormPtr RemDouble2Addr(std::string_view a, std::string_view b, Vmap& vmap);

// DAD: opcode_ins.py:1659-1706 *-lit16 — (vA, vB, #CCCC).
IRFormPtr AddIntLit16(std::string_view a, std::string_view b, int64_t cccc, Vmap& vmap);
// QUIRK: rsubint reverses operand order — `var_a = cst - var_b` not `var_b op cst`.
IRFormPtr RSubInt   (std::string_view a, std::string_view b, int64_t cccc, Vmap& vmap);
IRFormPtr MulIntLit16(std::string_view a, std::string_view b, int64_t cccc, Vmap& vmap);
IRFormPtr DivIntLit16(std::string_view a, std::string_view b, int64_t cccc, Vmap& vmap);
IRFormPtr RemIntLit16(std::string_view a, std::string_view b, int64_t cccc, Vmap& vmap);
IRFormPtr AndIntLit16(std::string_view a, std::string_view b, int64_t cccc, Vmap& vmap);
IRFormPtr OrIntLit16 (std::string_view a, std::string_view b, int64_t cccc, Vmap& vmap);
IRFormPtr XorIntLit16(std::string_view a, std::string_view b, int64_t cccc, Vmap& vmap);

// DAD: opcode_ins.py:1709-1775 *-lit8 — (vAA, vBB, #CC).
// QUIRK: addintlit8 swaps op→SUB and negates the literal when CC<0
// (per DAD's `[(ins.CC, ADD), (-ins.CC, SUB)][ins.CC < 0]` trick).
IRFormPtr AddIntLit8(std::string_view aa, std::string_view bb, int64_t cc, Vmap& vmap);
// QUIRK: rsubintlit8 reverses operand order.
IRFormPtr RSubIntLit8(std::string_view aa, std::string_view bb, int64_t cc, Vmap& vmap);
IRFormPtr MulIntLit8(std::string_view aa, std::string_view bb, int64_t cc, Vmap& vmap);
IRFormPtr DivIntLit8(std::string_view aa, std::string_view bb, int64_t cc, Vmap& vmap);
IRFormPtr RemIntLit8(std::string_view aa, std::string_view bb, int64_t cc, Vmap& vmap);
IRFormPtr AndIntLit8(std::string_view aa, std::string_view bb, int64_t cc, Vmap& vmap);
IRFormPtr OrIntLit8 (std::string_view aa, std::string_view bb, int64_t cc, Vmap& vmap);
IRFormPtr XorIntLit8(std::string_view aa, std::string_view bb, int64_t cc, Vmap& vmap);
IRFormPtr ShlIntLit8(std::string_view aa, std::string_view bb, int64_t cc, Vmap& vmap);
IRFormPtr ShrIntLit8(std::string_view aa, std::string_view bb, int64_t cc, Vmap& vmap);
IRFormPtr UShrIntLit8(std::string_view aa, std::string_view bb, int64_t cc, Vmap& vmap);

// =============================================================================
// Chunk F — INSTRUCTION_SET dispatch table (DAD opcode_ins.py:1780).
//
// DAD stores a Python list of function objects indexed by opcode. Since C++
// handler signatures differ per opcode (some take Vmap only, some take
// RetState, some take MethodRef + range, etc.), we can't model the table
// as a function-pointer array. Instead, kInstructionSet maps each opcode to
// an OpcodeKind enum; the driver switches on that enum to dispatch with the
// appropriate operand types.
// =============================================================================

enum class OpcodeKind : uint16_t {
    Nop,    // 0x00 + DAD-"unused" slots fall back to Nop
    Move,
    MoveFrom16,
    Move16,
    MoveWide,
    MoveWideFrom16,
    MoveWide16,
    MoveObject,
    MoveObjectFrom16,
    MoveObject16,
    MoveResult,
    MoveResultWide,
    MoveResultObject,
    MoveException,
    ReturnVoid,
    ReturnReg,
    ReturnWide,
    ReturnObject,
    Const4,
    Const16,
    Const,
    ConstHigh16,
    ConstWide16,
    ConstWide32,
    ConstWide,
    ConstWideHigh16,
    ConstString,
    ConstStringJumbo,
    ConstClass,
    MonitorEnter,
    MonitorExit,
    CheckCast,
    InstanceOf,
    ArrayLength,
    NewInstance_,
    NewArray,
    FilledNewArray,
    FilledNewArrayRange,
    FillArrayData,
    Throw,
    Goto,
    Goto16,
    Goto32,
    PackedSwitch,
    SparseSwitch,
    CmplFloat,
    CmpgFloat,
    CmplDouble,
    CmpgDouble,
    CmpLong,
    IfEq, IfNe, IfLt, IfGe, IfGt, IfLe,
    IfEqz, IfNez, IfLtz, IfGez, IfGtz, IfLez,
    AGet, AGetWide, AGetObject, AGetBoolean, AGetByte, AGetChar, AGetShort,
    APut, APutWide, APutObject, APutBoolean, APutByte, APutChar, APutShort,
    IGet, IGetWide, IGetObject, IGetBoolean, IGetByte, IGetChar, IGetShort,
    IPut, IPutWide, IPutObject, IPutBoolean, IPutByte, IPutChar, IPutShort,
    SGet, SGetWide, SGetObject, SGetBoolean, SGetByte, SGetChar, SGetShort,
    SPut, SPutWide, SPutObject, SPutBoolean, SPutByte, SPutChar, SPutShort,
    InvokeVirtual, InvokeSuper, InvokeDirect, InvokeStatic, InvokeInterface,
    InvokeVirtualRange, InvokeSuperRange, InvokeDirectRange,
    InvokeStaticRange, InvokeInterfaceRange,
    NegInt, NotInt, NegLong, NotLong, NegFloat, NegDouble,
    IntToLong, IntToFloat, IntToDouble,
    LongToInt, LongToFloat, LongToDouble,
    FloatToInt, FloatToLong, FloatToDouble,
    DoubleToInt, DoubleToLong, DoubleToFloat,
    IntToByte, IntToChar, IntToShort,
    AddInt, SubInt, MulInt, DivInt, RemInt,
    AndInt, OrInt, XorInt, ShlInt, ShrInt, UShrInt,
    AddLong, SubLong, MulLong, DivLong, RemLong,
    AndLong, OrLong, XorLong, ShlLong, ShrLong, UShrLong,
    AddFloat, SubFloat, MulFloat, DivFloat, RemFloat,
    AddDouble, SubDouble, MulDouble, DivDouble, RemDouble,
    AddInt2Addr, SubInt2Addr, MulInt2Addr, DivInt2Addr, RemInt2Addr,
    AndInt2Addr, OrInt2Addr, XorInt2Addr,
    ShlInt2Addr, ShrInt2Addr, UShrInt2Addr,
    AddLong2Addr, SubLong2Addr, MulLong2Addr, DivLong2Addr, RemLong2Addr,
    AndLong2Addr, OrLong2Addr, XorLong2Addr,
    ShlLong2Addr, ShrLong2Addr, UShrLong2Addr,
    AddFloat2Addr, SubFloat2Addr, MulFloat2Addr, DivFloat2Addr, RemFloat2Addr,
    AddDouble2Addr, SubDouble2Addr, MulDouble2Addr,
    DivDouble2Addr, RemDouble2Addr,
    AddIntLit16, RSubInt, MulIntLit16, DivIntLit16, RemIntLit16,
    AndIntLit16, OrIntLit16, XorIntLit16,
    AddIntLit8, RSubIntLit8, MulIntLit8, DivIntLit8, RemIntLit8,
    AndIntLit8, OrIntLit8, XorIntLit8,
    ShlIntLit8, ShrIntLit8, UShrIntLit8,
    Unused,  // opcodes beyond DAD's table (0xE3-0xFF)
};

// Opcode → OpcodeKind table. Size 256; entries 0xE3..0xFF are Unused.
extern const std::array<OpcodeKind, 256> kInstructionSet;

}  // namespace dexkit::dad
