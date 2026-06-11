// Parity test for instruction.cpp chunk 5 (Array family).
#include "instruction.h"
#include <algorithm>
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
static void check_vec_sorted(const char* l, std::vector<std::string> g,
                             std::vector<std::string> w) {
    std::sort(g.begin(), g.end()); std::sort(w.begin(), w.end());
    bool eq = (g == w); if (!eq) ++g_fail;
    std::printf("%s %-48s got=[", eq?"[ok]  ":"[FAIL]", l);
    for (size_t i=0;i<g.size();++i) std::printf("%s%s", i?",":"", g[i].c_str());
    std::printf("] want=[");
    for (size_t i=0;i<w.size();++i) std::printf("%s%s", i?",":"", w[i].c_str());
    std::printf("]\n");
}

int main() {
    // ArrayLoadExpression
    auto arr = std::make_shared<dad::Variable>("v0");
    arr->set_type("[I");
    auto idx = std::make_shared<dad::Constant>(
        dad::ConstantValue{(int64_t)2}, "I");
    dad::ArrayLoadExpression ld(arr, idx, "I");
    check_str("ALd.array",     ld.array_id(),     "v0");
    check_str("ALd.idx",       ld.idx_id(),       "c2");
    check_str("ALd.get_type",  ld.get_type(),     "I");
    check_vec_sorted("ALd.used_vars", ld.get_used_vars(), {"v0"});
    check_str("ALd.__str__",   ld.ToString(),     "ARRAYLOAD(VAR_v0, CST_2)");

    // ArrayLengthExpression
    auto a = std::make_shared<dad::Variable>("v3");
    dad::ArrayLengthExpression al(a);
    check_str("ALen.array",    al.array_id(),     "v3");
    check_str("ALen.get_type", al.get_type(),     "I");
    check_vec_sorted("ALen.used_vars", al.get_used_vars(), {"v3"});
    check_str("ALen.__str__",  al.ToString(),     "ARRAYLEN(VAR_v3)");

    // NewArrayExpression
    auto sz = std::make_shared<dad::Variable>("v1");
    dad::NewArrayExpression na(sz, "[I");
    check_str("NewArr.size",   na.size_id(),      "v1");
    check_str("NewArr.type",   na.get_type(),     "[I");
    check("NewArr.propagable", (int)na.is_propagable(), 0);
    check_vec_sorted("NewArr.used", na.get_used_vars(), {"v1"});
    check_str("NewArr.__str__",na.ToString(),     "NEWARRAY_[I[VAR_v1]");

    // FilledArrayExpression — note size is int, not Variable
    auto a1 = std::make_shared<dad::Variable>("v1");
    auto a2 = std::make_shared<dad::Constant>(
        dad::ConstantValue{(int64_t)7}, "I");
    dad::FilledArrayExpression fa(2, "[Ljava/lang/Object;", {a1, a2});
    check("FilledArr.size",    fa.size(),         (int64_t)2);
    check_str("FilledArr.type",fa.get_type(),     "[Ljava/lang/Object;");
    check("FilledArr.args.size",fa.args().size(), (size_t)2);
    check_vec_sorted("FilledArr.used", fa.get_used_vars(), {"v1"});

    // FillArrayExpression — note get_rhs quirk (returns reg id, not list)
    auto reg = std::make_shared<dad::Variable>("v0");
    dad::FillArrayExpression fia(reg, {1, 2, 3});
    check_str("FillArr.reg",   fia.reg_id(),      "v0");
    check("FillArr.value.size",fia.value().size(),(size_t)3);
    check("FillArr.propagable",(int)fia.is_propagable(), 0);
    check_vec_sorted("FillArr.used",fia.get_used_vars(),{"v0"});
    // base get_rhs returns empty vector (we split the API)
    check("FillArr.get_rhs (base) empty", fia.get_rhs().empty(), true);

    std::printf("\n%s — %d failure(s)\n", g_fail ? "FAIL" : "PASS", g_fail);
    return g_fail ? 1 : 0;
}
