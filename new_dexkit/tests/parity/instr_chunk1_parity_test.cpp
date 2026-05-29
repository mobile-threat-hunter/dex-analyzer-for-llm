// Standalone parity test for dad_cpp/instruction.cpp chunk 1 against
// androguard DAD instruction.py.
// Compile:
//   g++ -std=gnu++20 -I /home/nyahumi/Project/Dexkit/new_dexkit/dad_cpp/include \
//       /tmp/instr_chunk1_parity_test.cpp \
//       /home/nyahumi/Project/Dexkit/new_dexkit/build/cp313-cp313-linux_x86_64/libdexkit_dad.a \
//       -o /tmp/instr_chunk1_parity_test && /tmp/instr_chunk1_parity_test

#include "instruction.h"

#include <cstdio>
#include <stdexcept>

namespace dad = dexkit::dad;

static int g_fail = 0;

template <typename A, typename B>
static void check(const char* label, A got, B want) {
    bool eq = (got == want);
    if (!eq) ++g_fail;
    std::printf("%s %-44s got=%-14lld want=%lld\n",
                eq ? "[ok]  " : "[FAIL]", label,
                (long long)got, (long long)want);
}

static void check_str(const char* label, const std::string& got,
                      const char* want) {
    bool eq = (got == want);
    if (!eq) ++g_fail;
    std::printf("%s %-44s got=%-30s want=%s\n",
                eq ? "[ok]  " : "[FAIL]", label, got.c_str(), want);
}

int main() {
    // Constant(42, 'I') — int primitive.
    dad::Constant c1(dad::ConstantValue{(int64_t)42}, "I");
    check_str("Constant(42,I).v",       c1.v(),                      "c42");
    check_str("Constant(42,I).type",    c1.get_type(),               "I");
    check    ("Constant(42,I).cst2",    c1.cst2(),                   42);
    check    ("Constant(42,I).is_const",(int)c1.is_const(),          1);
    check    ("Constant(42,I).get_int", c1.get_int_value(),          42);
    check_str("Constant(42,I).__str__", c1.ToString(),               "CST_42");

    // Constant("hello", string-type)
    dad::Constant c2(dad::ConstantValue{std::string{"hello"}},
                     "Ljava/lang/String;");
    check_str("Constant(hello).v",      c2.v(),                      "chello");
    check_str("Constant(hello).__str__",c2.ToString(),               "CST_'hello'");
    check_str("Constant(hello).type",   c2.get_type(),               "Ljava/lang/String;");

    // BaseClass
    dad::BaseClass bc("Lcom/X;", "Lcom/X;");
    check_str("BaseClass.v",            bc.v(),                      "cLcom/X;");
    check_str("BaseClass.cls",          bc.cls(),                    "Lcom/X;");
    check_str("BaseClass.clsdesc",      bc.clsdesc(),                "Lcom/X;");
    check    ("BaseClass.is_const",     (int)bc.is_const(),          1);
    check_str("BaseClass.__str__",      bc.ToString(),               "BASECLASS_Lcom/X;");

    // Variable
    dad::Variable v("v3");
    check_str("Variable.v",             v.v(),                       "v3");
    check_str("Variable.name",          v.name,                      "v3");
    check    ("Variable.declared",      (int)v.declared,             0);
    check    ("Variable.is_ident",      (int)v.is_ident(),           1);
    check    ("Variable.is_const",      (int)v.is_const(),           0);
    {
        auto used = v.get_used_vars();
        check("Variable.used_vars.size", used.size(), (size_t)1);
        if (!used.empty()) check_str("Variable.used_vars[0]", used[0], "v3");
    }
    check_str("Variable.__str__",       v.ToString(),                "VAR_v3");

    // Param
    dad::Param p("p1", "I");
    check_str("Param.v",                p.v(),                       "p1");
    check    ("Param.declared",         (int)p.declared,             1);
    check_str("Param.type",             p.get_type(),                "I");
    check    ("Param.this_flag",        (int)p.this_flag,            0);
    check    ("Param.is_const",         (int)p.is_const(),           1);
    check    ("Param.is_ident",         (int)p.is_ident(),           1);
    check_str("Param.__str__",          p.ToString(),                "PARAM_p1");

    // ThisParam
    dad::ThisParam t("p0", "Lcom/X;");
    check_str("ThisParam.v",            t.v(),                       "p0");
    check    ("ThisParam.declared",     (int)t.declared,             1);
    check_str("ThisParam.type",         t.get_type(),                "Lcom/X;");
    check    ("ThisParam.this_flag",    (int)t.this_flag,            1);
    check    ("ThisParam.super_flag",   (int)t.super_flag,           0);
    check    ("ThisParam.is_const",     (int)t.is_const(),           1);
    check_str("ThisParam.__str__",      t.ToString(),                "THIS");

    // IRForm — base class defaults + replace() raises.
    dad::IRForm base;
    check("IRForm.is_call",             (int)base.is_call(),         0);
    check("IRForm.is_cond",             (int)base.is_cond(),         0);
    check("IRForm.is_const",            (int)base.is_const(),        0);
    check("IRForm.is_ident",            (int)base.is_ident(),        0);
    check("IRForm.is_propagable",       (int)base.is_propagable(),   1);
    check("IRForm.has_side_effect",     (int)base.has_side_effect(), 0);
    check("IRForm.get_used_vars.empty", base.get_used_vars().empty(), true);
    check("IRForm.get_rhs.empty",       base.get_rhs().empty(),       true);
    check("IRForm.get_lhs.null",        (base.get_lhs() == nullptr),  true);
    try {
        base.replace("v0", nullptr);
        std::printf("[FAIL] IRForm.replace did not throw\n");
        ++g_fail;
    } catch (const std::logic_error&) {
        std::printf("[ok]   IRForm.replace throws logic_error\n");
    }
    try {
        base.replace_lhs(nullptr);
        std::printf("[FAIL] IRForm.replace_lhs did not throw\n");
        ++g_fail;
    } catch (const std::logic_error&) {
        std::printf("[ok]   IRForm.replace_lhs throws logic_error\n");
    }
    try {
        base.replace_var("v0", nullptr);
        std::printf("[FAIL] IRForm.replace_var did not throw\n");
        ++g_fail;
    } catch (const std::logic_error&) {
        std::printf("[ok]   IRForm.replace_var throws logic_error\n");
    }

    std::printf("\n%s — %d failure(s)\n", g_fail ? "FAIL" : "PASS", g_fail);
    return g_fail ? 1 : 0;
}
