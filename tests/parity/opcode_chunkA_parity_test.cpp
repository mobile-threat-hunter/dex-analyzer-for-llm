// Parity test for opcode_ins.cpp chunk A.
#include "opcode_ins.h"
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
static void check_str_view(const char* l, std::string_view g, const char* w) {
    bool eq = (g == w); if (!eq) ++g_fail;
    std::printf("%s %-48s got=%-32s want=%s\n",
                eq?"[ok]  ":"[FAIL]", l, std::string{g}.c_str(), w);
}

int main() {
    // Op constants
    check_str_view("Op::ADD",    dad::Op::ADD,    "+");
    check_str_view("Op::CMP",    dad::Op::CMP,    "cmp");
    check_str_view("Op::LEQUAL", dad::Op::LEQUAL, "<=");
    check_str_view("Op::INTSHL", dad::Op::INTSHL, "<<");

    // GetVariable (setdefault semantics)
    dad::Vmap vmap;
    auto v0 = dad::GetVariable(vmap, "v0");
    check_str("GetVariable.v0.str", v0->ToString(),     "VAR_v0");
    check("vmap has v0",           vmap.count("v0"),    (size_t)1);
    auto v0b = dad::GetVariable(vmap, "v0");
    check("Second GetVariable returns same ptr",
          (v0 == v0b), true);

    // GetVariables (3-arg)
    dad::Vmap vmap2;
    auto r = dad::GetVariables(vmap2, {"v0", "v1", "v2"});
    check("GetVariables.size",     r.size(),            (size_t)3);
    if (r.size() == 3) {
        check_str("GetVariables[0]", r[0]->ToString(),  "VAR_v0");
        check_str("GetVariables[1]", r[1]->ToString(),  "VAR_v1");
        check_str("GetVariables[2]", r[2]->ToString(),  "VAR_v2");
    }

    // AssignConst
    dad::Vmap vmap3;
    auto cst = std::make_shared<dad::Constant>(
        dad::ConstantValue{(int64_t)42}, "I");
    auto ae = dad::AssignConst("v0", cst, vmap3);
    check_str("AssignConst.__str__",
              ae->ToString(),                            "ASSIGN(VAR_v0, CST_42)");
    check("vmap3 has v0",          vmap3.count("v0"),    (size_t)1);

    // AssignCmp
    dad::Vmap vmap4;
    auto ac = dad::AssignCmp("v0", "v1", "v2", "I", vmap4);
    check_str("AssignCmp.__str__",
              ac->ToString(),
              "ASSIGN(VAR_v0, (cmp VAR_v1 VAR_v2))");

    // LoadArrayExp — pre-seed v1 with type to avoid the DAD None-crash quirk.
    dad::Vmap vmap5;
    auto v1 = std::make_shared<dad::Variable>("v1");
    v1->set_type("[I");
    vmap5["v1"] = v1;
    auto ld = dad::LoadArrayExp("v0", "v1", "v2", "I", vmap5);
    check_str("LoadArrayExp.__str__",
              ld->ToString(),
              "ASSIGN(VAR_v0, ARRAYLOAD(VAR_v1, VAR_v2))");

    // StoreArrayInst
    dad::Vmap vmap6;
    auto st = dad::StoreArrayInst("v0", "v1", "v2", "I", vmap6);
    check_str("StoreArrayInst.__str__",
              st->ToString(),
              "VAR_v1[VAR_v2] = VAR_v0");

    // AssignCastExp
    dad::Vmap vmap7;
    auto ax = dad::AssignCastExp("v0", "v1", "I", "Lcom/X;", vmap7);
    check_str("AssignCastExp.__str__",
              ax->ToString(),
              "ASSIGN(VAR_v0, CAST_I(VAR_v1))");

    // AssignBinaryExp
    dad::Vmap vmap8;
    auto ab = dad::AssignBinaryExp("v0", "v1", "v2", dad::Op::ADD, "I", vmap8);
    check_str("AssignBinaryExp.__str__",
              ab->ToString(),
              "ASSIGN(VAR_v0, (+ VAR_v1 VAR_v2))");

    // AssignBinary2AddrExp
    dad::Vmap vmap9;
    auto ab2 = dad::AssignBinary2AddrExp("v0", "v1", dad::Op::SUB, "I", vmap9);
    check_str("AssignBinary2AddrExp.__str__",
              ab2->ToString(),
              "ASSIGN(VAR_v0, (- VAR_v0 VAR_v1))");

    // AssignLit
    dad::Vmap vmap10;
    auto al = dad::AssignLit(dad::Op::ADD, 5, "v0", "v1", vmap10);
    check_str("AssignLit.__str__",
              al->ToString(),
              "ASSIGN(VAR_v0, (+ VAR_v1 CST_5))");

    std::printf("\n%s — %d failure(s)\n", g_fail ? "FAIL" : "PASS", g_fail);
    return g_fail ? 1 : 0;
}
