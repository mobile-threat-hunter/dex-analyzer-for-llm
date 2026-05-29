// Standalone parity test for dad_cpp/util.cpp against androguard DAD util.py.
// Compile:
//   g++ -std=gnu++20 -I /home/nyahumi/Project/Dexkit/new_dexkit/dad_cpp/include \
//       /tmp/util_parity_test.cpp \
//       /home/nyahumi/Project/Dexkit/new_dexkit/build/cp313-cp313-linux_x86_64/libdexkit_dad.a \
//       -o /tmp/util_parity_test && /tmp/util_parity_test

#include "util.h"

#include <cassert>
#include <cstdio>
#include <string>
#include <vector>

namespace dad = dexkit::dad;

static int g_fail = 0;

static void check_vec(const char* label,
                      const std::vector<std::string>& got,
                      const std::vector<std::string>& want) {
    bool eq = (got == want);
    if (!eq) ++g_fail;
    std::printf("%s %-40s got=[", eq ? "[ok]  " : "[FAIL]", label);
    for (size_t i = 0; i < got.size(); ++i)
        std::printf("%s%s", i ? "," : "", got[i].c_str());
    std::printf("]  want=[");
    for (size_t i = 0; i < want.size(); ++i)
        std::printf("%s%s", i ? "," : "", want[i].c_str());
    std::printf("]\n");
}

static void check_str(const char* label,
                      const std::string& got, const std::string& want) {
    bool eq = (got == want);
    if (!eq) ++g_fail;
    std::printf("%s %-40s got=%-30s want=%s\n",
                eq ? "[ok]  " : "[FAIL]", label, got.c_str(), want.c_str());
}

static void check_u(const char* label, unsigned got, unsigned want) {
    bool eq = (got == want);
    if (!eq) ++g_fail;
    std::printf("%s %-40s got=%u want=%u\n",
                eq ? "[ok]  " : "[FAIL]", label, got, want);
}

int main() {
    // Reference values captured from androguard.decompiler.util — see
    // commit message / parity-test run output for the source python invocations.

    // get_access_class
    check_vec("get_access_class(0x11)",
              dad::GetAccessClass(0x11), {"public","final"});
    check_vec("get_access_class(0x800001)",
              dad::GetAccessClass(0x800001), {"public"});

    // get_access_method
    check_vec("get_access_method(0x109)",
              dad::GetAccessMethod(0x109), {"public","static","native"});

    // get_access_field
    check_vec("get_access_field(0x18)",
              dad::GetAccessField(0x18), {"static","final"});

    // get_type_size
    check_u("get_type_size(J)", dad::GetTypeSize("J"), 2);
    check_u("get_type_size(I)", dad::GetTypeSize("I"), 1);
    check_u("get_type_size(D)", dad::GetTypeSize("D"), 2);

    // get_type — primitives
    check_str("get_type(I)", dad::GetType("I"), "int");
    check_str("get_type(V)", dad::GetType("V"), "void");
    check_str("get_type(J)", dad::GetType("J"), "long");

    // get_type (production / fixed) — proper prefix strip of "java/lang/".
    check_str("get_type(Ljava/lang/Object;)",
              dad::GetType("Ljava/lang/Object;"), "Object");
    check_str("get_type(Ljava/lang/annotation/Foo;) [FIXED]",
              dad::GetType("Ljava/lang/annotation/Foo;"), "annotation.Foo");
    check_str("get_type(Lcom/x/Y;)",
              dad::GetType("Lcom/x/Y;"), "com.x.Y");
    check_str("get_type(Ljava/lang/reflect/Method;) [FIXED]",
              dad::GetType("Ljava/lang/reflect/Method;"), "reflect.Method");

    // get_type (DAD-faithful) — char-set lstrip bug preserved for byte-match
    // comparison against androguard DAD.
    check_str("get_type_faithful(Ljava/lang/Object;)",
              dad::GetTypeDADFaithful("Ljava/lang/Object;"), "Object");
    check_str("get_type_faithful(Ljava/lang/annotation/Foo;) [DAD-BUG]",
              dad::GetTypeDADFaithful("Ljava/lang/annotation/Foo;"), "otation.Foo");

    // get_type — arrays (production / fixed)
    check_str("get_type([I)", dad::GetType("[I"), "int[]");
    check_str("get_type([[Ljava/lang/String;)",
              dad::GetType("[[Ljava/lang/String;"), "String[][]");

    // get_params_type [DAD-FAITHFUL ONLY] — Python's
    // `descriptor.split(')')[0][1:].split()` whitespace-splits a spaceless
    // string, returning the whole param chunk as ONE element regardless of
    // how many params there really are. We replicate the bug here for parity.
    //
    // Production code path does NOT use this function — multi-arg signature
    // emission (Writer, BuildMethodRef, MethodMeta::params_type) uses
    // `ParseParamsType` (util.h:84), a proper Dalvik descriptor parser that
    // splits "(IL.../X;[I)V" into ["I", "L.../X;", "[I"].
    check_vec("get_params_type((II)V) [DAD-BUG: 1 elem, not 2]",
              dad::GetParamsType("(II)V"), {"II"});
    check_vec("get_params_type(()V)",
              dad::GetParamsType("()V"), {});

    // Production parser sanity check — multi-arg correctly split.
    check_vec("parse_params_type((IJLjava/lang/String;[I)V) [PRODUCTION]",
              dad::ParseParamsType("(IJLjava/lang/String;[I)V"),
              {"I", "J", "Ljava/lang/String;", "[I"});

    std::printf("\n%s — %d failure(s)\n", g_fail ? "FAIL" : "PASS", g_fail);
    return g_fail ? 1 : 0;
}
