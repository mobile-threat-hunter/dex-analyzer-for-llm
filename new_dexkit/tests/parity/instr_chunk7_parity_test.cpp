// Parity test for instruction.cpp chunk 7 (Binary/Unary/Cast/Conditional).
#include "instruction.h"
#include <algorithm>
#include <cstdio>
#include <memory>
namespace dad = dexkit::dad;
static int g_fail = 0;
template <typename A, typename B>
static void check(const char* l, A g, B w) {
    bool eq = (g == w); if (!eq) ++g_fail;
    std::printf("%s %-50s got=%-14lld want=%lld\n",
                eq?"[ok]  ":"[FAIL]", l, (long long)g, (long long)w);
}
static void check_str(const char* l, const std::string& g, const char* w) {
    bool eq = (g == w); if (!eq) ++g_fail;
    std::printf("%s %-50s got=%-32s want=%s\n",
                eq?"[ok]  ":"[FAIL]", l, g.c_str(), w);
}
static void check_vec_sorted(const char* l, std::vector<std::string> g,
                             std::vector<std::string> w) {
    std::sort(g.begin(), g.end()); std::sort(w.begin(), w.end());
    bool eq = (g == w); if (!eq) ++g_fail;
    std::printf("%s %-50s got=[", eq?"[ok]  ":"[FAIL]", l);
    for (size_t i=0;i<g.size();++i) std::printf("%s%s", i?",":"", g[i].c_str());
    std::printf("] want=[");
    for (size_t i=0;i<w.size();++i) std::printf("%s%s", i?",":"", w[i].c_str());
    std::printf("]\n");
}

int main() {
    // BinaryExpression
    auto v1 = std::make_shared<dad::Variable>("v1");
    auto v2 = std::make_shared<dad::Variable>("v2");
    dad::BinaryExpression be("+", v1, v2, "I");
    check_str("BinExp.op",      be.op(),               "+");
    check_str("BinExp.arg1",    be.arg1_id(),          "v1");
    check_str("BinExp.arg2",    be.arg2_id(),          "v2");
    check_str("BinExp.type",    be.get_type(),         "I");
    check_vec_sorted("BinExp.used", be.get_used_vars(), {"v1","v2"});
    check("BinExp.side",        (int)be.has_side_effect(), 0);
    check_str("BinExp.__str__", be.ToString(),         "(+ VAR_v1 VAR_v2)");

    // BinaryExpressionLit
    auto v0 = std::make_shared<dad::Variable>("v0");
    auto c5 = std::make_shared<dad::Constant>(
        dad::ConstantValue{(int64_t)5}, "I");
    dad::BinaryExpressionLit bel("+", v0, c5);
    check_str("BinLit.type",    bel.get_type(),        "I");
    check_str("BinLit.__str__", bel.ToString(),        "(+ VAR_v0 CST_5)");

    // UnaryExpression — note Python's get_type returns var's type (None for fresh Variable)
    auto v0b = std::make_shared<dad::Variable>("v0");
    dad::UnaryExpression ue("-", v0b, "I");
    check_str("UnExp.op",       ue.op(),               "-");
    check_str("UnExp.arg",      ue.arg_id(),           "v0");
    check_str("UnExp.type",     ue.type,               "I");
    // get_type returns var's type — Variable inits with empty type (matches Python None)
    check_str("UnExp.get_type", ue.get_type(),         "");
    check_vec_sorted("UnExp.used", ue.get_used_vars(), {"v0"});
    check_str("UnExp.__str__",  ue.ToString(),         "(-, VAR_v0)");

    // CastExpression
    auto v0c = std::make_shared<dad::Variable>("v0");
    dad::CastExpression ce("I", "Lcom/X;", v0c);
    check_str("CastExp.op",     ce.op(),               "I");
    check_str("CastExp.type",   ce.type,               "Lcom/X;");
    check_str("CastExp.clsdesc",ce.clsdesc(),          "Lcom/X;");
    check_str("CastExp.get_type",ce.get_type(),        "Lcom/X;");
    check("CastExp.is_const",   (int)ce.is_const(),    0);
    check_str("CastExp.__str__",ce.ToString(),         "CAST_I(VAR_v0)");

    // ConditionalExpression
    auto cv0 = std::make_shared<dad::Variable>("v0");
    auto cv1 = std::make_shared<dad::Variable>("v1");
    dad::ConditionalExpression cnd("<", cv0, cv1);
    check_str("Cond.op",        cnd.op(),              "<");
    check("Cond.is_cond",       (int)cnd.is_cond(),    1);
    check_vec_sorted("Cond.used", cnd.get_used_vars(), {"v0","v1"});
    check_str("Cond.__str__",   cnd.ToString(),        "COND(<, VAR_v0, VAR_v1)");
    cnd.Neg();
    check_str("Cond after neg", cnd.op(),              ">=");

    // ConditionalZExpression
    auto czv = std::make_shared<dad::Variable>("v0");
    dad::ConditionalZExpression cz("==", czv);
    check_str("CondZ.op",       cz.op(),               "==");
    check("CondZ.is_cond",      (int)cz.is_cond(),     1);
    check_str("CondZ.__str__",  cz.ToString(),         "(IS==0, VAR_v0)");
    cz.Neg();
    check_str("CondZ after neg",cz.op(),               "!=");

    std::printf("\n%s — %d failure(s)\n", g_fail ? "FAIL" : "PASS", g_fail);
    return g_fail ? 1 : 0;
}
