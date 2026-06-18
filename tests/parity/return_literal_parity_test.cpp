// Return-type-mismatched constant literals — beyond-DAD production fix.
//
// Every Dalvik `const*` opcode builds an integer-typed Constant; the declared
// return type is the ground truth. visit_return (writer.cpp) and the dast
// ReturnInstruction branch (dast.cpp) rewrite an integer-constant return so a
// Z/reference/F/D method emits a spec-correct literal instead of the raw int
// DAD leaves behind. This suite locks in BOTH the text and AST paths (they must
// agree) across all four categories, the NaN/±Inf cases, the const*/high16
// negative-shift path, and the regression guards (int returns stay numeric;
// const-class returns keep their class literal, not null).
#include "dast.h"
#include "decompile.h"
#include "method_snapshot.h"
#include "mock_code_source.h"
#include "slicer/dex_bytecode.h"
#include <cstdio>
#include <string>
#include <vector>

namespace dad = dexkit::dad;
namespace mck = dexkit::dad::testing;
static int g_fail = 0;

static void check_contains(const char* label, const std::string& got,
                           const char* needle) {
    bool ok = got.find(needle) != std::string::npos;
    if (!ok) ++g_fail;
    std::printf("%s %-34s needle=%s\n", ok ? "[ok]  " : "[FAIL]", label, needle);
    if (!ok) std::printf("        got:\n%s\n", got.c_str());
}

static void check_absent(const char* label, const std::string& got,
                         const char* needle) {
    bool ok = got.find(needle) == std::string::npos;
    if (!ok) ++g_fail;
    std::printf("%s %-34s absent=%s\n", ok ? "[ok]  " : "[FAIL]", label, needle);
    if (!ok) std::printf("        got:\n%s\n", got.c_str());
}

// Build a static method `m()<ret>` from raw bytecode, return its decompiled
// Java text. `regs` registers, 0 ins (static, no params here).
static std::string TextOf(const std::vector<dex::u2>& insns, const char* ret,
                          uint16_t regs, uint32_t mid) {
    mck::MockCodeSource src;
    auto code = mck::FakeCodeItem::Make(regs, 0, 0, insns);
    src.RegisterMethod(0, mid, 0x9 /*public+static*/, "Lcom/X;", "m", ret,
                       std::move(code));
    auto snap = dad::MethodSnapshotBuilder::BuildShared(src, 0, mid);
    dad::DvMethod dv(snap);
    dv.Process();
    return dv.GetSource();
}
static std::string AstOf(const std::vector<dex::u2>& insns, const char* ret,
                         uint16_t regs, uint32_t mid) {
    mck::MockCodeSource src;
    auto code = mck::FakeCodeItem::Make(regs, 0, 0, insns);
    src.RegisterMethod(0, mid, 0x9, "Lcom/X;", "m", ret, std::move(code));
    auto snap = dad::MethodSnapshotBuilder::BuildShared(src, 0, mid);
    dad::DvMethod dv(snap);
    return dv.ProcessAst().dump();
}

// Bytecode fragments (little-endian u2).
static const dex::u2 CONST4_V0_0   = 0x0012;  // const/4 v0, #0
static const dex::u2 CONST4_V0_1   = 0x1012;  // const/4 v0, #1
static const dex::u2 RETURN_V0     = 0x000f;  // return v0
static const dex::u2 RETURN_OBJ_V0 = 0x0011;  // return-object v0
static const dex::u2 RETURN_WIDE_V0 = 0x0010; // return-wide v0
// const/high16 v0, #BBBB  → 0x0015, BBBB   (value = BBBB << 16)
// const-wide/high16 v0, #BBBB → 0x0019, BBBB (value = BBBB << 48)

int main() {
    // 1. boolean: return false / true.
    {
        std::string t = TextOf({CONST4_V0_0, RETURN_V0}, "()Z", 1, 10);
        std::string a = AstOf({CONST4_V0_0, RETURN_V0}, "()Z", 1, 11);
        check_contains("Z false TEXT", t, "return false;");
        check_contains("Z false AST", a, "[\"Literal\", \"false\", [\".boolean\", 0]]");
        std::string t1 = TextOf({CONST4_V0_1, RETURN_V0}, "()Z", 1, 12);
        std::string a1 = AstOf({CONST4_V0_1, RETURN_V0}, "()Z", 1, 13);
        check_contains("Z true TEXT", t1, "return true;");
        check_contains("Z true AST", a1, "[\"Literal\", \"true\", [\".boolean\", 0]]");
    }

    // 2. reference: return null (the 5892-case category).
    {
        std::string t = TextOf({CONST4_V0_0, RETURN_OBJ_V0},
                               "()Ljava/lang/Object;", 1, 20);
        std::string a = AstOf({CONST4_V0_0, RETURN_OBJ_V0},
                              "()Ljava/lang/Object;", 1, 21);
        check_contains("ref null TEXT", t, "return null;");
        check_absent("ref no bare-0 TEXT", t, "return 0;");
        check_contains("ref null AST", a, "[\"Literal\", \"null\", [\".null\", 0]]");
    }

    // 3. float: raw IEEE bits → literal. 0x3F80<<16 = 0x3F800000 = 1.0f.
    {
        std::string t = TextOf({0x0015, 0x3F80, RETURN_V0}, "()F", 1, 30);
        std::string a = AstOf({0x0015, 0x3F80, RETURN_V0}, "()F", 1, 31);
        check_contains("F 1.0 TEXT", t, "return 1f;");
        check_absent("F no raw-bits TEXT", t, "1065353216");
        check_contains("F .float AST", a, "[\".float\", 0]");
    }

    // 4. float NaN/Inf: 0x7FC0<<16 = NaN; 0xFF80<<16 = -Inf (sign bit set).
    {
        std::string tnan = TextOf({0x0015, 0x7FC0, RETURN_V0}, "()F", 1, 40);
        check_contains("F NaN TEXT", tnan, "return Float.NaN;");
        std::string anan = AstOf({0x0015, 0x7FC0, RETURN_V0}, "()F", 1, 41);
        check_contains("F NaN AST", anan, "Float.NaN");
        std::string tinf = TextOf({0x0015, 0xFF80, RETURN_V0}, "()F", 1, 42);
        check_contains("F -Inf TEXT", tinf, "return Float.NEGATIVE_INFINITY;");
        std::string ainf = AstOf({0x0015, 0xFF80, RETURN_V0}, "()F", 1, 43);
        check_contains("F -Inf AST", ainf, "Float.NEGATIVE_INFINITY");
    }

    // 5. double: const-wide/high16. 0xC000<<48 = 0xC000000000000000 = -2.0
    //    (exercises the negative high16 shift hardening); 0xFFF0<<48 = -Inf.
    {
        std::string t = TextOf({0x0019, 0xC000, RETURN_WIDE_V0}, "()D", 2, 50);
        std::string a = AstOf({0x0019, 0xC000, RETURN_WIDE_V0}, "()D", 2, 51);
        check_contains("D -2.0 TEXT", t, "return -2;");
        check_contains("D .double AST", a, "[\".double\", 0]");
        std::string tinf = TextOf({0x0019, 0xFFF0, RETURN_WIDE_V0}, "()D", 2, 52);
        check_contains("D -Inf TEXT", tinf, "return Double.NEGATIVE_INFINITY;");
        std::string ainf = AstOf({0x0019, 0xFFF0, RETURN_WIDE_V0}, "()D", 2, 53);
        check_contains("D -Inf AST", ainf, "Double.NEGATIVE_INFINITY");
        check_absent("D -Inf AST no -inf token", ainf, "\"-inf\"");
    }

    // 6. regression guards: int/char returns stay numeric (NOT false/null).
    {
        std::string ti = TextOf({0x0013, 0x002A, RETURN_V0}, "()I", 1, 60);
        check_contains("int stays 42 TEXT", ti, "return 42;");
        check_absent("int not false", ti, "false");
        check_absent("int not null", ti, "null");
        // char return of a small constant stays an int literal (valid via
        // constant narrowing; matches DAD, not rewritten).
        std::string tc = TextOf({CONST4_V0_1, RETURN_V0}, "()C", 1, 61);
        check_contains("char stays 1 TEXT", tc, "return 1;");
        check_absent("char not true", tc, "true");
    }

    std::printf("\n%s — %d failure(s)\n", g_fail ? "FAIL" : "PASS", g_fail);
    return g_fail ? 1 : 0;
}
