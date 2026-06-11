// Parity test for instruction.cpp chunk 8 — final chunk (Instance/StaticExpression).
#include "instruction.h"
#include <cstdio>
#include <memory>
namespace dad = dexkit::dad;
static int g_fail = 0;
static void check_str(const char* l, const std::string& g, const char* w) {
    bool eq = (g == w); if (!eq) ++g_fail;
    std::printf("%s %-48s got=%-30s want=%s\n",
                eq?"[ok]  ":"[FAIL]", l, g.c_str(), w);
}
template <typename A, typename B>
static void check(const char* l, A g, B w) {
    bool eq = (g == w); if (!eq) ++g_fail;
    std::printf("%s %-48s got=%-14lld want=%lld\n",
                eq?"[ok]  ":"[FAIL]", l, (long long)g, (long long)w);
}

int main() {
    // InstanceExpression
    auto v = std::make_shared<dad::Variable>("v0");
    dad::InstanceExpression ie(v, "Lcom/X;", "I", "fld");
    check_str("Instance.arg",     ie.arg_id(),    "v0");
    check_str("Instance.cls",     ie.cls(),       "com.X");
    check_str("Instance.ftype",   ie.ftype(),     "I");
    check_str("Instance.name",    ie.name(),      "fld");
    check_str("Instance.clsdesc", ie.clsdesc(),   "Lcom/X;");
    check_str("Instance.get_type",ie.get_type(),  "I");
    {
        auto used = ie.get_used_vars();
        check("Instance.used.size", used.size(), (size_t)1);
        if (!used.empty()) check_str("Instance.used[0]", used[0], "v0");
    }
    check_str("Instance.__str__", ie.ToString(),  "VAR_v0.fld");

    // StaticExpression
    dad::StaticExpression se("Lcom/X;", "I", "fld");
    check_str("Static.cls",       se.cls(),       "com.X");
    check_str("Static.ftype",     se.ftype(),     "I");
    check_str("Static.name",      se.name(),      "fld");
    check_str("Static.clsdesc",   se.clsdesc(),   "Lcom/X;");
    check_str("Static.get_type",  se.get_type(),  "I");
    check_str("Static.__str__",   se.ToString(),  "com.X.fld");

    std::printf("\n%s — %d failure(s)\n", g_fail ? "FAIL" : "PASS", g_fail);
    return g_fail ? 1 : 0;
}
