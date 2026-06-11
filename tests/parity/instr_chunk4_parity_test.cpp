// Parity test for instruction.cpp chunk 4 (Return/Nop/Switch/CheckCast).
#include "instruction.h"

#include <cstdio>
#include <memory>

namespace dad = dexkit::dad;
static int g_fail = 0;

template <typename A, typename B>
static void check(const char* l, A g, B w) {
    bool eq = (g == w); if (!eq) ++g_fail;
    std::printf("%s %-48s got=%-14lld want=%lld\n",
                eq?"[ok]  ":"[FAIL]", l, (long long)g, (long long)w);
}
static void check_str(const char* l, const std::string& g, const char* w) {
    bool eq = (g == w); if (!eq) ++g_fail;
    std::printf("%s %-48s got=%-32s want=%s\n",
                eq?"[ok]  ":"[FAIL]", l, g.c_str(), w);
}

int main() {
    // ReturnInstruction with arg
    auto rarg = std::make_shared<dad::Variable>("v0");
    dad::ReturnInstruction r1(rarg);
    check_str("Return(v0).arg",  r1.arg().value_or(""), "v0");
    {
        auto used = r1.get_used_vars();
        check("Return(v0).used.size", used.size(), (size_t)1);
        if (!used.empty()) check_str("Return(v0).used[0]", used[0], "v0");
    }
    check_str("Return(v0).__str__", r1.ToString(), "RETURN(VAR_v0)");

    // ReturnInstruction with None
    dad::ReturnInstruction r2(nullptr);
    check("Return(None).arg empty", !r2.arg().has_value(), true);
    check("Return(None).used empty", r2.get_used_vars().empty(), true);
    check_str("Return(None).__str__", r2.ToString(), "RETURN");

    // NopExpression
    dad::NopExpression n;
    check("Nop.used.empty", n.get_used_vars().empty(), true);
    check("Nop.get_lhs == nullptr", (n.get_lhs() == nullptr), true);

    // SwitchExpression — branch is now int32 offset (matching DAD's raw arg).
    auto src = std::make_shared<dad::Variable>("v0");
    dad::SwitchExpression sw(src, 0x1234);
    check_str("Switch.src", sw.src_id(), "v0");
    check("Switch.branch == 0x1234", sw.branch(), (int32_t)0x1234);
    {
        auto used = sw.get_used_vars();
        check("Switch.used.size", used.size(), (size_t)1);
        if (!used.empty()) check_str("Switch.used[0]", used[0], "v0");
    }
    check_str("Switch.__str__", sw.ToString(), "SWITCH(VAR_v0)");

    // CheckCastExpression
    auto a = std::make_shared<dad::Variable>("v0");
    dad::CheckCastExpression cc(a, "[I", "Lcom/X;");
    check_str("CheckCast.arg",  cc.arg_id(),  "v0");
    check_str("CheckCast.type", cc.get_type(),"Lcom/X;");
    check_str("CheckCast.clsdesc", cc.clsdesc(), "Lcom/X;");
    check("CheckCast.is_const(Variable)", (int)cc.is_const(), 0);
    {
        auto used = cc.get_used_vars();
        check("CheckCast.used.size", used.size(), (size_t)1);
        if (!used.empty()) check_str("CheckCast.used[0]", used[0], "v0");
    }
    check_str("CheckCast.__str__", cc.ToString(), "CAST(Lcom/X;) VAR_v0");

    std::printf("\n%s — %d failure(s)\n", g_fail ? "FAIL" : "PASS", g_fail);
    return g_fail ? 1 : 0;
}
