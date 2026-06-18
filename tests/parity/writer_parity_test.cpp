// End-to-end test: snapshot → Construct → Writer.
// Verifies the full pipeline produces Java-shaped output.
#include "method_snapshot.h"
#include "mock_code_source.h"
#include "basic_blocks.h"
#include "graph.h"
#include "writer.h"
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
    std::printf("%s %-42s needle=\"%s\"\n",
                ok ? "[ok]  " : "[FAIL]", label, needle);
    if (!ok) std::printf("        got:\n%s\n", got.c_str());
}

int main() {
    using namespace dad;

    // Test 1: trivial empty method
    {
        mck::MockCodeSource src;
        std::vector<dex::u2> insns = {0x000e};
        auto code = mck::FakeCodeItem::Make(1, 0, 0, insns);
        src.RegisterMethod(0, 1, 0x9 /*public+static*/,
                           "Lcom/X;", "f", "()V", std::move(code));
        auto snap = MethodSnapshotBuilder::Build(src, 0, 1);
        Vmap vm; GenInvokeRetName ret;
        auto g = Construct(*snap, vm, ret);
        Writer w(snap.get(), g.get());
        w.WriteMethod();
        std::string out = w.str();
        std::printf("=== Test 1 (void f()) ===\n%s\n", out.c_str());
        check_contains("public static signature", out, "public static");
        check_contains("void return type", out, "void f()");
        check_contains("braces", out, "{");
    }

    // Test 2: const + return
    {
        mck::MockCodeSource src;
        std::vector<dex::u2> insns = {
            0x0013, 0x002A,   // const/16 v0, #42
            0x000f,           // return v0
        };
        auto code = mck::FakeCodeItem::Make(1, 0, 0, insns);
        src.RegisterMethod(0, 2, 0x9, "Lcom/X;", "g", "()I", std::move(code));
        auto snap = MethodSnapshotBuilder::Build(src, 0, 2);
        Vmap vm; GenInvokeRetName ret;
        auto g = Construct(*snap, vm, ret);
        Writer w(snap.get(), g.get());
        w.WriteMethod();
        std::string out = w.str();
        std::printf("\n=== Test 2 (int g() { return 42; }) ===\n%s\n", out.c_str());
        check_contains("int return type", out, "int g()");
        check_contains("contains return", out, "return");
        check_contains("contains 42", out, "42");
    }

    // Test 3: instance method foo(I)
    {
        mck::MockCodeSource src;
        std::vector<dex::u2> insns = {0x000e};
        auto code = mck::FakeCodeItem::Make(2, 2, 0, insns);
        src.RegisterMethod(0, 3, 0x1 /*public*/,
                           "Lcom/X;", "foo", "(I)V", std::move(code));
        auto snap = MethodSnapshotBuilder::Build(src, 0, 3);
        Vmap vm; GenInvokeRetName ret;
        auto g = Construct(*snap, vm, ret);
        Writer w(snap.get(), g.get());
        w.WriteMethod();
        std::string out = w.str();
        std::printf("\n=== Test 3 (void foo(int p1)) ===\n%s\n", out.c_str());
        check_contains("public modifier", out, "public");
        check_contains("foo with param", out, "foo(int p1)");
    }

    // Test 4: EscapeJavaString emits readable UTF-8 (not \uXXXX) for non-ASCII.
    {
        // "연결" = U+C5F0 U+ACB0, MUTF-8/UTF-8 = EC 97 B0 EA B2 B0.
        std::string korean = "\xEC\x97\xB0\xEA\xB2\xB0";
        std::string esc = dad::EscapeJavaString(korean);
        std::printf("\n=== Test 4 (EscapeJavaString UTF-8) ===\n%s\n", esc.c_str());
        check_contains("korean utf8 passthrough", esc, "\xEC\x97\xB0\xEA\xB2\xB0");
        bool no_u = esc.find("\\u") == std::string::npos;
        if (!no_u) ++g_fail;
        std::printf("%s %-42s\n", no_u ? "[ok]  " : "[FAIL]",
                    "no \\uXXXX escape for BMP char");
        // backslash / quote still escaped; control char still \\u.
        std::string ctrl = std::string("a\x01\"\\", 4);
        std::string e2 = dad::EscapeJavaString(ctrl);
        check_contains("control char escaped", e2, "\\u0001");
        check_contains("quote escaped", e2, "\\\"");
        check_contains("backslash escaped", e2, "\\\\");
        // 4-byte supplementary (😀 U+1F600 = F0 9F 98 80) passes through as UTF-8.
        std::string emoji = "\xF0\x9F\x98\x80";
        std::string e3 = dad::EscapeJavaString(emoji);
        check_contains("emoji 4-byte utf8 passthrough", e3, "\xF0\x9F\x98\x80");
    }

    std::printf("\n%s — %d failure(s)\n", g_fail ? "FAIL" : "PASS", g_fail);
    return g_fail ? 1 : 0;
}
