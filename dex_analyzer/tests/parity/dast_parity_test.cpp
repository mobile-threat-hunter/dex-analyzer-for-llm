// End-to-end test: snapshot → DvMethod::ProcessAst → JSONWriter AST.
// DAD: dast.py JSONWriter — verifies the nested-list AST shape.
//
// Asserts the dumped JSON contains the expected DAD AST tags. Byte-exact
// parity vs androguard DAD is verified separately by the Python e2e script
// (/tmp/dast_parity.py); these are structural smoke checks in the C++ suite.
#include "dast.h"
#include "decompile.h"
#include "method_snapshot.h"
#include "mock_code_source.h"
#include "slicer/dex_bytecode.h"
#include <cstdio>
#include <string>

namespace dad = dexkit::dad;
namespace mck = dexkit::dad::testing;
static int g_fail = 0;

static void check_contains(const char* label, const std::string& got,
                            const char* needle) {
    bool ok = got.find(needle) != std::string::npos;
    if (!ok) ++g_fail;
    std::printf("%s %-40s needle=%s\n",
                ok ? "[ok]  " : "[FAIL]", label, needle);
    if (!ok) std::printf("        got:\n%s\n", got.c_str());
}

int main() {
    using namespace dad;

    // Test 1: trivial empty static void method.
    {
        mck::MockCodeSource src;
        std::vector<dex::u2> insns = {0x000e};  // return-void
        auto code = mck::FakeCodeItem::Make(1, 0, 0, insns);
        src.RegisterMethod(0, 1, 0x9 /*public+static*/,
                           "Lcom/X;", "f", "()V", std::move(code));
        auto snap = MethodSnapshotBuilder::BuildShared(src, 0, 1);
        DvMethod dv(snap);
        std::string out = dv.ProcessAst().dump();
        std::printf("=== Test 1 (void f()) ===\n%s\n", out.c_str());
        check_contains("triple key", out, "\"triple\"");
        check_contains("flags public/static", out, "[\"public\", \"static\"]");
        check_contains("ret void TypeName", out, "[\"TypeName\", [\".void\", 0]]");
        check_contains("empty params", out, "\"params\": []");
        check_contains("body BlockStatement", out, "[\"BlockStatement\"");
    }

    // Test 2: const + return → return-literal AST.
    {
        mck::MockCodeSource src;
        std::vector<dex::u2> insns = {
            0x0013, 0x002A,   // const/16 v0, #42
            0x000f,           // return v0
        };
        auto code = mck::FakeCodeItem::Make(1, 0, 0, insns);
        src.RegisterMethod(0, 2, 0x9, "Lcom/X;", "g", "()I", std::move(code));
        auto snap = MethodSnapshotBuilder::BuildShared(src, 0, 2);
        DvMethod dv(snap);
        std::string out = dv.ProcessAst().dump();
        std::printf("\n=== Test 2 (int g(){return 42;}) ===\n%s\n", out.c_str());
        check_contains("ret int TypeName", out, "[\"TypeName\", [\".int\", 0]]");
        check_contains("ReturnStatement", out, "\"ReturnStatement\"");
        check_contains("literal 42", out, "[\"Literal\", \"42\", [\".int\", 0]]");
    }

    // Test 3: instance method foo(int) → param decl AST.
    {
        mck::MockCodeSource src;
        std::vector<dex::u2> insns = {0x000e};
        auto code = mck::FakeCodeItem::Make(2, 2, 0, insns);
        src.RegisterMethod(0, 3, 0x1 /*public*/,
                           "Lcom/X;", "foo", "(I)V", std::move(code));
        auto snap = MethodSnapshotBuilder::BuildShared(src, 0, 3);
        DvMethod dv(snap);
        std::string out = dv.ProcessAst().dump();
        std::printf("\n=== Test 3 (void foo(int)) ===\n%s\n", out.c_str());
        check_contains("param int TypeName", out, "[\"TypeName\", [\".int\", 0]]");
        check_contains("param local p", out, "[\"Local\", \"p");
    }

    std::printf("\n%s — %d failure(s)\n", g_fail ? "FAIL" : "PASS", g_fail);
    return g_fail ? 1 : 0;
}
