// Parity test for opcode_ins.cpp chunk C.
#include "opcode_ins.h"
#include <cstdio>
#include <memory>
namespace dad = dexkit::dad;
static int g_fail = 0;
static void check_str(const char* l, const std::string& g, const char* w) {
    bool eq = (g == w); if (!eq) ++g_fail;
    std::printf("%s %-40s got=%-44s want=%s\n",
                eq?"[ok]  ":"[FAIL]", l, g.c_str(), w);
}

int main() {
    using namespace dad;

    // cmp family — all produce same shape, cmp_type differs internally.
    Vmap vm; check_str("CmplFloat",  CmplFloat ("v0","v1","v2",vm)->ToString(),
              "ASSIGN(VAR_v0, (cmp VAR_v1 VAR_v2))");
    Vmap vm2; check_str("CmpgFloat", CmpgFloat ("v0","v1","v2",vm2)->ToString(),
              "ASSIGN(VAR_v0, (cmp VAR_v1 VAR_v2))");
    Vmap vm3; check_str("CmplDouble",CmplDouble("v0","v1","v2",vm3)->ToString(),
              "ASSIGN(VAR_v0, (cmp VAR_v1 VAR_v2))");
    Vmap vm4; check_str("CmpgDouble",CmpgDouble("v0","v1","v2",vm4)->ToString(),
              "ASSIGN(VAR_v0, (cmp VAR_v1 VAR_v2))");
    Vmap vm5; check_str("CmpLong",   CmpLong   ("v0","v1","v2",vm5)->ToString(),
              "ASSIGN(VAR_v0, (cmp VAR_v1 VAR_v2))");

    // if-* / if-*z
    Vmap vmA; check_str("IfEq", IfEq("v0","v1",vmA)->ToString(), "COND(==, VAR_v0, VAR_v1)");
    Vmap vmB; check_str("IfNe", IfNe("v0","v1",vmB)->ToString(), "COND(!=, VAR_v0, VAR_v1)");
    Vmap vmC; check_str("IfLt", IfLt("v0","v1",vmC)->ToString(), "COND(<, VAR_v0, VAR_v1)");
    Vmap vmD; check_str("IfGe", IfGe("v0","v1",vmD)->ToString(), "COND(>=, VAR_v0, VAR_v1)");
    Vmap vmE; check_str("IfGt", IfGt("v0","v1",vmE)->ToString(), "COND(>, VAR_v0, VAR_v1)");
    Vmap vmF; check_str("IfLe", IfLe("v0","v1",vmF)->ToString(), "COND(<=, VAR_v0, VAR_v1)");
    Vmap vmG; check_str("IfEqz", IfEqz("v0",vmG)->ToString(), "(IS==0, VAR_v0)");
    Vmap vmH; check_str("IfNez", IfNez("v0",vmH)->ToString(), "(IS!=0, VAR_v0)");
    Vmap vmI; check_str("IfLtz", IfLtz("v0",vmI)->ToString(), "(IS<0, VAR_v0)");
    Vmap vmJ; check_str("IfGez", IfGez("v0",vmJ)->ToString(), "(IS>=0, VAR_v0)");
    Vmap vmK; check_str("IfGtz", IfGtz("v0",vmK)->ToString(), "(IS>0, VAR_v0)");
    Vmap vmL; check_str("IfLez", IfLez("v0",vmL)->ToString(), "(IS<=0, VAR_v0)");

    // aget / aput — pre-seed array type to avoid DAD-style crash on None.
    auto seed = [](Vmap& m, const char* k, const char* t) {
        auto v = std::make_shared<Variable>(k);
        v->set_type(t);
        m[k] = v;
    };
    Vmap vmM; seed(vmM, "v1", "[I");
    check_str("AGet",        AGet       ("v0","v1","v2",vmM)->ToString(), "ASSIGN(VAR_v0, ARRAYLOAD(VAR_v1, VAR_v2))");
    Vmap vmN; seed(vmN, "v1", "[Ljava/lang/Object;");
    check_str("AGetObject",  AGetObject ("v0","v1","v2",vmN)->ToString(), "ASSIGN(VAR_v0, ARRAYLOAD(VAR_v1, VAR_v2))");
    Vmap vmO; seed(vmO, "v1", "[Z");
    check_str("AGetBoolean", AGetBoolean("v0","v1","v2",vmO)->ToString(), "ASSIGN(VAR_v0, ARRAYLOAD(VAR_v1, VAR_v2))");
    Vmap vmP; check_str("APut",      APut     ("v0","v1","v2",vmP)->ToString(), "VAR_v1[VAR_v2] = VAR_v0");
    Vmap vmQ; check_str("APutByte",  APutByte ("v0","v1","v2",vmQ)->ToString(), "VAR_v1[VAR_v2] = VAR_v0");
    Vmap vmR; check_str("APutShort", APutShort("v0","v1","v2",vmR)->ToString(), "VAR_v1[VAR_v2] = VAR_v0");

    // iget / iput
    Vmap vmS; check_str("IGet",       IGet      ("v0","v1","Lcom/X;","I","foo",vmS)->ToString(), "ASSIGN(VAR_v0, VAR_v1.foo)");
    Vmap vmT; check_str("IGetWide",   IGetWide  ("v0","v1","Lcom/X;","J","foo",vmT)->ToString(), "ASSIGN(VAR_v0, VAR_v1.foo)");
    Vmap vmU; check_str("IGetObject", IGetObject("v0","v1","Lcom/X;","Lcom/Y;","foo",vmU)->ToString(), "ASSIGN(VAR_v0, VAR_v1.foo)");
    Vmap vmV; check_str("IPut",       IPut      ("v0","v1","Lcom/X;","I","foo",vmV)->ToString(), "VAR_v1.foo = VAR_v0");
    Vmap vmW; check_str("IPutObject", IPutObject("v0","v1","Lcom/X;","Lcom/Y;","foo",vmW)->ToString(), "VAR_v1.foo = VAR_v0");

    // sget / sput
    Vmap vmX; check_str("SGet",       SGet      ("v0","Lcom/X;","I","foo",vmX)->ToString(), "ASSIGN(VAR_v0, com.X.foo)");
    Vmap vmY; check_str("SGetWide",   SGetWide  ("v0","Lcom/X;","J","foo",vmY)->ToString(), "ASSIGN(VAR_v0, com.X.foo)");
    Vmap vmZ; check_str("SGetObject", SGetObject("v0","Lcom/X;","Lcom/Y;","foo",vmZ)->ToString(), "ASSIGN(VAR_v0, com.X.foo)");
    Vmap vmAA; check_str("SPut",      SPut      ("v0","Lcom/X;","I","foo",vmAA)->ToString(), "com.X.foo = VAR_v0");
    Vmap vmBB; check_str("SPutObject",SPutObject("v0","Lcom/X;","Lcom/Y;","foo",vmBB)->ToString(), "com.X.foo = VAR_v0");

    std::printf("\n%s — %d failure(s)\n", g_fail ? "FAIL" : "PASS", g_fail);
    return g_fail ? 1 : 0;
}
