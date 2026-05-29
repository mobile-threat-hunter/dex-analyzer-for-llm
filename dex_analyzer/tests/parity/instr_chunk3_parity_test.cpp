// Parity test for instruction.cpp chunk 3.
// Compile:
//   g++ -std=gnu++20 -I /home/nyahumi/Project/Dexkit/dex_analyzer/dad_cpp/include \
//       /tmp/instr_chunk3_parity_test.cpp \
//       /home/nyahumi/Project/Dexkit/dex_analyzer/build/cp313-cp313-linux_x86_64/libdexkit_dad.a \
//       -o /tmp/instr_chunk3_parity_test && /tmp/instr_chunk3_parity_test

#include "instruction.h"

#include <algorithm>
#include <cstdio>
#include <memory>

namespace dad = dexkit::dad;

static int g_fail = 0;

template <typename A, typename B>
static void check(const char* label, A got, B want) {
    bool eq = (got == want);
    if (!eq) ++g_fail;
    std::printf("%s %-50s got=%-14lld want=%lld\n",
                eq ? "[ok]  " : "[FAIL]", label,
                (long long)got, (long long)want);
}

static void check_str(const char* label, const std::string& got,
                      const char* want) {
    bool eq = (got == want);
    if (!eq) ++g_fail;
    std::printf("%s %-50s got=%-32s want=%s\n",
                eq ? "[ok]  " : "[FAIL]", label, got.c_str(), want);
}

static void check_vec_sorted(const char* label,
                             std::vector<std::string> got,
                             std::vector<std::string> want) {
    std::sort(got.begin(), got.end());
    std::sort(want.begin(), want.end());
    bool eq = (got == want);
    if (!eq) ++g_fail;
    std::printf("%s %-50s got=[", eq ? "[ok]  " : "[FAIL]", label);
    for (size_t i = 0; i < got.size(); ++i)
        std::printf("%s%s", i ? "," : "", got[i].c_str());
    std::printf("]  want=[");
    for (size_t i = 0; i < want.size(); ++i)
        std::printf("%s%s", i ? "," : "", want[i].c_str());
    std::printf("]\n");
}

int main() {
    // ArrayStoreInstruction
    auto rhs = std::make_shared<dad::Variable>("v1");
    auto arr = std::make_shared<dad::Variable>("v2");
    auto idx = std::make_shared<dad::Constant>(
        dad::ConstantValue{(int64_t)3}, "I");
    dad::ArrayStoreInstruction asi(rhs, arr, idx, "I");
    check_str("ASI.rhs",       asi.rhs_id(),                "v1");
    check_str("ASI.array",     asi.array_id(),              "v2");
    check_str("ASI.index",     asi.index_id(),              "c3");
    check_str("ASI.type",      asi.get_type(),              "I");
    check("ASI.has_side_effect", (int)asi.has_side_effect(),  1);
    check_vec_sorted("ASI.used_vars", asi.get_used_vars(), {"v1","v2"});
    check_str("ASI.__str__",   asi.ToString(),              "VAR_v2[CST_3] = VAR_v1");

    // StaticInstruction
    auto srhs = std::make_shared<dad::Variable>("v0");
    dad::StaticInstruction si(srhs, "Lcom/X;", "I", "foo");
    check_str("SI.rhs",        si.rhs_id(),                 "v0");
    check_str("SI.cls",        si.cls(),                    "com.X");
    check_str("SI.name",       si.name(),                   "foo");
    check_str("SI.clsdesc",    si.clsdesc(),                "Lcom/X;");
    check("SI.has_side_effect", (int)si.has_side_effect(),  1);
    check_vec_sorted("SI.used_vars", si.get_used_vars(), {"v0"});
    check("SI.get_lhs null", (si.get_lhs() == nullptr),     true);
    check("SI.GetLhsId empty", !si.GetLhsId().has_value(),  true);
    check_str("SI.__str__",    si.ToString(),               "com.X.foo = VAR_v0");

    // InstanceInstruction
    auto ilhs = std::make_shared<dad::Variable>("v0");
    auto irhs = std::make_shared<dad::Variable>("v1");
    dad::InstanceInstruction ii(irhs, ilhs, "Lcom/X;", "I", "bar");
    check_str("II.lhs",        ii.lhs_id(),                 "v0");
    check_str("II.rhs",        ii.rhs_id(),                 "v1");
    check_str("II.cls",        ii.cls(),                    "com.X");
    check_str("II.name",       ii.name(),                   "bar");
    check("II.has_side_effect", (int)ii.has_side_effect(),  1);
    check_vec_sorted("II.used_vars", ii.get_used_vars(), {"v0","v1"});
    check("II.get_lhs null", (ii.get_lhs() == nullptr),     true);
    check_str("II.__str__",    ii.ToString(),               "VAR_v0.bar = VAR_v1");

    // NewInstance
    dad::NewInstance ni("Lcom/Y;");
    check_str("NI.type",       ni.get_type(),               "Lcom/Y;");
    check("NI.used_vars empty", ni.get_used_vars().empty(), true);
    check_str("NI.__str__",    ni.ToString(),               "NEW(Lcom/Y;)");

    // InvokeInstruction
    auto base = std::make_shared<dad::Variable>("v0");
    auto a1 = std::make_shared<dad::Variable>("v1");
    auto a2 = std::make_shared<dad::Constant>(
        dad::ConstantValue{(int64_t)7}, "I");
    dad::InvokeInstruction inv("Lcom/X;", "foo", base, "I",
                                {"I","I"}, {a1, a2},
                                {"Lcom/X;","foo","(II)I"});
    check_str("Inv.cls",       inv.cls(),                   "Lcom/X;");
    check_str("Inv.name",      inv.name(),                  "foo");
    check_str("Inv.base",      inv.base(),                  "v0");
    check_str("Inv.rtype",     inv.rtype(),                 "I");
    check("Inv.is_call",       (int)inv.is_call(),          1);
    check("Inv.has_side_effect", (int)inv.has_side_effect(), 1);
    check_vec_sorted("Inv.used_vars", inv.get_used_vars(), {"v0","v1"});
    check_str("Inv.get_type",  inv.get_type(),              "I");
    check_str("Inv.__str__",   inv.ToString(),              "VAR_v0.foo(VAR_v1, CST_7)");

    // InvokeInstruction with <init> — base type propagates.
    auto initbase = std::make_shared<dad::Variable>("v0");
    initbase->set_type("Lcom/Z;");
    dad::InvokeInstruction inv2("Lcom/Z;", "<init>", initbase, "V",
                                 {}, {}, {"Lcom/Z;","<init>","()V"});
    check_str("Inv<init>.get_type", inv2.get_type(),        "Lcom/Z;");

    // InvokeRangeInstruction — args[0] becomes base.
    auto rb = std::make_shared<dad::Variable>("v0");
    auto ra = std::make_shared<dad::Variable>("v1");
    dad::InvokeRangeInstruction inr("Lcom/X;", "foo", "I", {"I"},
                                     {rb, ra}, {"Lcom/X;","foo","(I)I"});
    check_str("InvRange.base",  inr.base(),                 "v0");
    {
        auto args = inr.args();
        check("InvRange.args.size", args.size(),            (size_t)1);
        if (!args.empty()) check_str("InvRange.args[0]", args[0], "v1");
    }
    check_str("InvRange.__str__", inr.ToString(),           "VAR_v0.foo(VAR_v1)");

    // InvokeStaticInstruction — used_vars excludes base.
    auto sb = std::make_shared<dad::Variable>("v0");
    auto sa = std::make_shared<dad::Variable>("v1");
    dad::InvokeStaticInstruction ins("Lcom/X;", "foo", sb, "I",
                                      {"I"}, {sa},
                                      {"Lcom/X;","foo","(I)I"});
    check_vec_sorted("InvStatic.used_vars (no base)",
                     ins.get_used_vars(), {"v1"});

    std::printf("\n%s — %d failure(s)\n", g_fail ? "FAIL" : "PASS", g_fail);
    return g_fail ? 1 : 0;
}
