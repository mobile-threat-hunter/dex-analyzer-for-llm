// Standalone parity test for dad_cpp/instruction.cpp chunk 2.
// Compile:
//   g++ -std=gnu++20 -I /home/nyahumi/Project/Dexkit/dex_analyzer/dad_cpp/include \
//       /tmp/instr_chunk2_parity_test.cpp \
//       /home/nyahumi/Project/Dexkit/dex_analyzer/build/cp313-cp313-linux_x86_64/libdexkit_dad.a \
//       -o /tmp/instr_chunk2_parity_test && /tmp/instr_chunk2_parity_test

#include "instruction.h"

#include <cstdio>
#include <memory>

namespace dad = dexkit::dad;

static int g_fail = 0;

template <typename A, typename B>
static void check(const char* label, A got, B want) {
    bool eq = (got == want);
    if (!eq) ++g_fail;
    std::printf("%s %-48s got=%-14lld want=%lld\n",
                eq ? "[ok]  " : "[FAIL]", label,
                (long long)got, (long long)want);
}

static void check_str(const char* label, const std::string& got,
                      const char* want) {
    bool eq = (got == want);
    if (!eq) ++g_fail;
    std::printf("%s %-48s got=%-30s want=%s\n",
                eq ? "[ok]  " : "[FAIL]", label, got.c_str(), want);
}

int main() {
    // AssignExpression(Variable(v0), Constant(42, 'I'))
    auto lhs = std::make_shared<dad::Variable>("v0");
    auto rhs = std::make_shared<dad::Constant>(
        dad::ConstantValue{(int64_t)42}, "I");
    dad::AssignExpression ae(lhs, rhs);

    check("AssignExpr.lhs has_value",        ae.lhs().has_value(),   true);
    check_str("AssignExpr.lhs value",        ae.lhs().value_or(""),  "v0");
    check("AssignExpr.is_call",              (int)ae.is_call(),       0);
    check("AssignExpr.is_propagable",        (int)ae.is_propagable(), 1);
    check("AssignExpr.has_side_effect",      (int)ae.has_side_effect(),0);
    auto rhs_list = ae.get_rhs();
    check("AssignExpr.get_rhs.size",         rhs_list.size(),         (size_t)1);
    check("AssignExpr.get_rhs[0] is rhs",    (rhs_list.size()==1 && rhs_list[0]==rhs), true);
    check_str("AssignExpr.GetLhsId",         ae.GetLhsId().value_or(""), "v0");
    check("AssignExpr.used_vars empty",      ae.get_used_vars().empty(), true);
    check_str("Variable.type propagated",    lhs->get_type(),         "I");
    check_str("AssignExpr.__str__",          ae.ToString(),           "ASSIGN(VAR_v0, CST_42)");

    // AssignExpression with lhs=None
    dad::AssignExpression ae2(nullptr, rhs);
    check("AssignExpr(None).lhs empty",      !ae2.lhs().has_value(),  true);
    check_str("AssignExpr(None).__str__",    ae2.ToString(),          "ASSIGN(None, CST_42)");

    // remove_defined_var
    auto lhs2 = std::make_shared<dad::Variable>("v0");
    auto rhs2 = std::make_shared<dad::Constant>(
        dad::ConstantValue{(int64_t)42}, "I");
    dad::AssignExpression ae3(lhs2, rhs2);
    ae3.remove_defined_var();
    check("After remove_defined_var: empty", !ae3.lhs().has_value(),  true);

    // replace_lhs
    auto lhs3 = std::make_shared<dad::Variable>("v0");
    auto rhs3 = std::make_shared<dad::Constant>(
        dad::ConstantValue{(int64_t)1}, "I");
    dad::AssignExpression ae4(lhs3, rhs3);
    auto new_lhs = std::make_shared<dad::Variable>("v9");
    ae4.replace_lhs(new_lhs);
    check_str("After replace_lhs: lhs",      ae4.lhs().value_or(""),  "v9");
    check("var_map[v9] == new_lhs",          (ae4.var_map.count("v9")==1 && ae4.var_map["v9"]==new_lhs), true);

    // MoveExpression
    auto ml = std::make_shared<dad::Variable>("v0");
    auto mr = std::make_shared<dad::Variable>("v1");
    dad::MoveExpression me(ml, mr);
    check_str("MoveExpr.lhs_id",             me.lhs_id(),             "v0");
    check_str("MoveExpr.rhs_id",             me.rhs_id(),             "v1");
    {
        auto used = me.get_used_vars();
        check("MoveExpr.used_vars.size",     used.size(),             (size_t)1);
        if (!used.empty()) check_str("MoveExpr.used_vars[0]", used[0], "v1");
    }
    {
        auto r = me.get_rhs();
        check("MoveExpr.get_rhs == var_map[v1]",
              (r.size()==1 && r[0]==mr), true);
    }
    check("MoveExpr.is_call",                (int)me.is_call(),       0);
    check("MoveExpr.has_side_effect",        (int)me.has_side_effect(),0);
    check_str("MoveExpr.__str__",            me.ToString(),           "VAR_v0 = VAR_v1");

    // MoveExpression.replace_lhs(v8) drops v0, installs v8.
    auto me2_l = std::make_shared<dad::Variable>("v0");
    auto me2_r = std::make_shared<dad::Variable>("v1");
    dad::MoveExpression me2(me2_l, me2_r);
    auto v8 = std::make_shared<dad::Variable>("v8");
    me2.replace_lhs(v8);
    check_str("MoveExpr.replace_lhs lhs",    me2.lhs_id(),            "v8");
    check("var_map.count(v0)==0",            me2.var_map.count("v0"), (size_t)0);
    check("var_map.count(v8)==1",            me2.var_map.count("v8"), (size_t)1);

    // MoveResultExpression
    auto mrl = std::make_shared<dad::Variable>("v2");
    auto mrr = std::make_shared<dad::Variable>("v3");
    dad::MoveResultExpression mre(mrl, mrr);
    check("MoveResult.is_propagable",        (int)mre.is_propagable(),1);
    check("MoveResult.has_side_effect",      (int)mre.has_side_effect(),0);
    check_str("MoveResult.__str__",          mre.ToString(),          "VAR_v2 = VAR_v3");

    std::printf("\n%s — %d failure(s)\n", g_fail ? "FAIL" : "PASS", g_fail);
    return g_fail ? 1 : 0;
}
