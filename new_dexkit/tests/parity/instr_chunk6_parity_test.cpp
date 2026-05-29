// Parity test for instruction.cpp chunk 6 (Ref/MoveException/Monitor/Throw).
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
    std::printf("%s %-48s got=%-30s want=%s\n",
                eq?"[ok]  ":"[FAIL]", l, g.c_str(), w);
}

int main() {
    // MoveExceptionExpression
    auto v = std::make_shared<dad::Variable>("v0");
    dad::MoveExceptionExpression me(v, "Ljava/lang/Throwable;");
    check_str("MoveExc.ref",       me.ref_id(),                   "v0");
    check_str("MoveExc.type",      me.get_type(),                 "Ljava/lang/Throwable;");
    check_str("MoveExc.v.type",    v->get_type(),                 "Ljava/lang/Throwable;");
    check_str("MoveExc.GetLhsId",  me.GetLhsId().value_or(""),    "v0");
    check("MoveExc.has_side_effect", (int)me.has_side_effect(),    1);
    check("MoveExc.used empty",     me.get_used_vars().empty(),    true);
    check_str("MoveExc.__str__",   me.ToString(),                  "MOVE_EXCEPT VAR_v0");

    // MonitorEnter
    auto v2 = std::make_shared<dad::Variable>("v1");
    dad::MonitorEnterExpression mon(v2);
    check_str("MonEnt.ref",        mon.ref_id(),                   "v1");
    check("MonEnt.is_propagable",  (int)mon.is_propagable(),       0);
    {
        auto used = mon.get_used_vars();
        check("MonEnt.used.size",  used.size(),                    (size_t)1);
        if (!used.empty()) check_str("MonEnt.used[0]", used[0],    "v1");
    }

    // MonitorExit
    auto v3 = std::make_shared<dad::Variable>("v2");
    dad::MonitorExitExpression mox(v3);
    check_str("MonExt.ref",        mox.ref_id(),                   "v2");

    // Throw
    auto v4 = std::make_shared<dad::Variable>("v3");
    dad::ThrowExpression th(v4);
    check_str("Throw.ref",         th.ref_id(),                    "v3");
    check_str("Throw.__str__",     th.ToString(),                  "Throw VAR_v3");

    std::printf("\n%s — %d failure(s)\n", g_fail ? "FAIL" : "PASS", g_fail);
    return g_fail ? 1 : 0;
}
