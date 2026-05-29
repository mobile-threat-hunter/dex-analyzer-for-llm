// Parity test for opcode_ins.cpp chunk E.
#include "opcode_ins.h"
#include <cstdio>
namespace dad = dexkit::dad;
static int g_fail = 0;
static void check_str(const char* l, const std::string& g, const char* w) {
    bool eq = (g == w); if (!eq) ++g_fail;
    std::printf("%s %-30s got=%-44s want=%s\n",
                eq?"[ok]  ":"[FAIL]", l, g.c_str(), w);
}

int main() {
    using namespace dad;

    // neg/not
    Vmap vm; check_str("NegInt",    NegInt   ("v0","v1",vm)->ToString(), "ASSIGN(VAR_v0, (-, VAR_v1))");
    Vmap vm2; check_str("NotInt",    NotInt   ("v0","v1",vm2)->ToString(), "ASSIGN(VAR_v0, (~, VAR_v1))");
    Vmap vm3; check_str("NegLong",   NegLong  ("v0","v1",vm3)->ToString(), "ASSIGN(VAR_v0, (-, VAR_v1))");
    Vmap vm4; check_str("NotLong",   NotLong  ("v0","v1",vm4)->ToString(), "ASSIGN(VAR_v0, (~, VAR_v1))");
    Vmap vm5; check_str("NegFloat",  NegFloat ("v0","v1",vm5)->ToString(), "ASSIGN(VAR_v0, (-, VAR_v1))");
    Vmap vm6; check_str("NegDouble", NegDouble("v0","v1",vm6)->ToString(), "ASSIGN(VAR_v0, (-, VAR_v1))");

    // type-conv (sample)
    Vmap vm7;  check_str("IntToLong",    IntToLong   ("v0","v1",vm7)->ToString(),  "ASSIGN(VAR_v0, CAST_(long)(VAR_v1))");
    Vmap vm8;  check_str("IntToFloat",   IntToFloat  ("v0","v1",vm8)->ToString(),  "ASSIGN(VAR_v0, CAST_(float)(VAR_v1))");
    Vmap vm9;  check_str("IntToDouble",  IntToDouble ("v0","v1",vm9)->ToString(),  "ASSIGN(VAR_v0, CAST_(double)(VAR_v1))");
    Vmap vm10; check_str("IntToChar",    IntToChar   ("v0","v1",vm10)->ToString(), "ASSIGN(VAR_v0, CAST_(char)(VAR_v1))");
    Vmap vm11; check_str("DoubleToFloat",DoubleToFloat("v0","v1",vm11)->ToString(),"ASSIGN(VAR_v0, CAST_(float)(VAR_v1))");
    Vmap vm12; check_str("FloatToLong",  FloatToLong ("v0","v1",vm12)->ToString(), "ASSIGN(VAR_v0, CAST_(long)(VAR_v1))");

    // arithmetic 3-addr (sample)
    Vmap vmA; check_str("AddInt",   AddInt  ("v0","v1","v2",vmA)->ToString(), "ASSIGN(VAR_v0, (+ VAR_v1 VAR_v2))");
    Vmap vmB; check_str("SubInt",   SubInt  ("v0","v1","v2",vmB)->ToString(), "ASSIGN(VAR_v0, (- VAR_v1 VAR_v2))");
    Vmap vmC; check_str("MulLong",  MulLong ("v0","v1","v2",vmC)->ToString(), "ASSIGN(VAR_v0, (* VAR_v1 VAR_v2))");
    Vmap vmD; check_str("DivDouble",DivDouble("v0","v1","v2",vmD)->ToString(),"ASSIGN(VAR_v0, (/ VAR_v1 VAR_v2))");
    Vmap vmE; check_str("ShlInt",   ShlInt  ("v0","v1","v2",vmE)->ToString(), "ASSIGN(VAR_v0, (<< VAR_v1 VAR_v2))");
    Vmap vmF; check_str("UShrInt",  UShrInt ("v0","v1","v2",vmF)->ToString(), "ASSIGN(VAR_v0, (>> VAR_v1 VAR_v2))");
    Vmap vmG; check_str("OrLong",   OrLong  ("v0","v1","v2",vmG)->ToString(), "ASSIGN(VAR_v0, (| VAR_v1 VAR_v2))");

    // 2-addr (sample)
    Vmap vmH; check_str("AddInt2Addr",   AddInt2Addr ("v0","v1",vmH)->ToString(), "ASSIGN(VAR_v0, (+ VAR_v0 VAR_v1))");
    Vmap vmI; check_str("SubLong2Addr",  SubLong2Addr("v0","v1",vmI)->ToString(), "ASSIGN(VAR_v0, (- VAR_v0 VAR_v1))");
    Vmap vmJ; check_str("MulDouble2Addr",MulDouble2Addr("v0","v1",vmJ)->ToString(),"ASSIGN(VAR_v0, (* VAR_v0 VAR_v1))");

    // lit16
    Vmap vmK; check_str("AddIntLit16", AddIntLit16("v0","v1",42,vmK)->ToString(), "ASSIGN(VAR_v0, (+ VAR_v1 CST_42))");
    Vmap vmL; check_str("MulIntLit16", MulIntLit16("v0","v1",42,vmL)->ToString(), "ASSIGN(VAR_v0, (* VAR_v1 CST_42))");

    // rsubint: reversed operand
    Vmap vmM; check_str("RSubInt",   RSubInt("v0","v1",42,vmM)->ToString(), "ASSIGN(VAR_v0, (- CST_42 VAR_v1))");

    // lit8 + addintlit8 quirk (negative literal swaps to SUB)
    Vmap vmN; check_str("AddIntLit8 +5", AddIntLit8("v0","v1",5,vmN)->ToString(),  "ASSIGN(VAR_v0, (+ VAR_v1 CST_5))");
    Vmap vmO; check_str("AddIntLit8 -3", AddIntLit8("v0","v1",-3,vmO)->ToString(), "ASSIGN(VAR_v0, (- VAR_v1 CST_3))");
    Vmap vmP; check_str("RSubIntLit8",   RSubIntLit8("v0","v1",5,vmP)->ToString(), "ASSIGN(VAR_v0, (- CST_5 VAR_v1))");
    Vmap vmQ; check_str("MulIntLit8",    MulIntLit8("v0","v1",5,vmQ)->ToString(),  "ASSIGN(VAR_v0, (* VAR_v1 CST_5))");
    Vmap vmR; check_str("ShrIntLit8",    ShrIntLit8("v0","v1",5,vmR)->ToString(),  "ASSIGN(VAR_v0, (>> VAR_v1 CST_5))");

    std::printf("\n%s — %d failure(s)\n", g_fail ? "FAIL" : "PASS", g_fail);
    return g_fail ? 1 : 0;
}
