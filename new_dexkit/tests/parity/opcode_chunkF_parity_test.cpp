// Parity test for INSTRUCTION_SET dispatch table.
#include "opcode_ins.h"
#include <cstdio>
namespace dad = dexkit::dad;
static int g_fail = 0;

static void check_op(uint8_t opcode, dad::OpcodeKind want, const char* desc) {
    dad::OpcodeKind got = dad::kInstructionSet[opcode];
    bool eq = (got == want);
    if (!eq) ++g_fail;
    std::printf("%s 0x%02x %-24s got=%-4d want=%d\n",
                eq?"[ok]  ":"[FAIL]", opcode, desc,
                static_cast<int>(got), static_cast<int>(want));
}

int main() {
    using K = dad::OpcodeKind;
    // Sample across all rows
    check_op(0x00, K::Nop,                   "nop");
    check_op(0x01, K::Move,                  "move");
    check_op(0x0A, K::MoveResult,            "move-result");
    check_op(0x0E, K::ReturnVoid,            "return-void");
    check_op(0x12, K::Const4,                "const/4");
    check_op(0x1A, K::ConstString,           "const-string");
    check_op(0x1C, K::ConstClass,            "const-class");
    check_op(0x22, K::NewInstance_,          "new-instance");
    check_op(0x27, K::Throw,                 "throw");
    check_op(0x28, K::Goto,                  "goto");
    check_op(0x2B, K::PackedSwitch,          "packed-switch");
    check_op(0x2D, K::CmplFloat,             "cmpl-float");
    check_op(0x32, K::IfEq,                  "if-eq");
    check_op(0x38, K::IfEqz,                 "if-eqz");
    check_op(0x44, K::AGet,                  "aget");
    check_op(0x4B, K::APut,                  "aput");
    check_op(0x52, K::IGet,                  "iget");
    check_op(0x59, K::IPut,                  "iput");
    check_op(0x60, K::SGet,                  "sget");
    check_op(0x67, K::SPut,                  "sput");
    check_op(0x6E, K::InvokeVirtual,         "invoke-virtual");
    check_op(0x74, K::InvokeVirtualRange,    "invoke-virtual/range");
    check_op(0x7B, K::NegInt,                "neg-int");
    check_op(0x81, K::IntToLong,             "int-to-long");
    check_op(0x8D, K::IntToByte,             "int-to-byte");
    check_op(0x90, K::AddInt,                "add-int");
    check_op(0x9A, K::UShrInt,               "ushr-int");
    check_op(0xA6, K::AddFloat,              "add-float");
    check_op(0xB0, K::AddInt2Addr,           "add-int/2addr");
    check_op(0xC6, K::AddFloat2Addr,         "add-float/2addr");
    check_op(0xD0, K::AddIntLit16,           "add-int/lit16");
    check_op(0xD1, K::RSubInt,               "rsub-int");
    check_op(0xD8, K::AddIntLit8,            "add-int/lit8");
    check_op(0xD9, K::RSubIntLit8,           "rsub-int/lit8");
    check_op(0xE2, K::UShrIntLit8,           "ushr-int/lit8");
    // DAD-"unused" slots map to Nop (within table range)
    check_op(0x3E, K::Nop,                   "unused (DAD-nop)");
    check_op(0x3F, K::Nop,                   "unused (DAD-nop)");
    check_op(0x40, K::Nop,                   "unused (DAD-nop)");
    check_op(0x73, K::Nop,                   "unused (DAD-nop)");
    check_op(0x79, K::Nop,                   "unused (DAD-nop)");
    check_op(0x7A, K::Nop,                   "unused (DAD-nop)");
    // Beyond DAD's table → Unused
    check_op(0xE3, K::Unused,                "beyond DAD");
    check_op(0xFF, K::Unused,                "beyond DAD");

    std::printf("\n%s — %d failure(s)\n", g_fail ? "FAIL" : "PASS", g_fail);
    return g_fail ? 1 : 0;
}
