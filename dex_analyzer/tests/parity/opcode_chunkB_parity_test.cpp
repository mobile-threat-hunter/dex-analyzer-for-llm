// Parity test for opcode_ins.cpp chunk B.
#include "opcode_ins.h"
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

int main() {
    using namespace dad;

    // nop
    check_str("Nop.__str__",         Nop()->ToString(),                "");  // NopExpression default ToString
    // ReturnVoid
    check_str("ReturnVoid.__str__",  ReturnVoid()->ToString(),         "RETURN");

    // Move
    Vmap vm; check_str("Move.__str__", Move("v0","v1",vm)->ToString(), "VAR_v0 = VAR_v1");
    check("vmap has v0", vm.count("v0"), (size_t)1);
    check("vmap has v1", vm.count("v1"), (size_t)1);

    // MoveFrom16 / Move16 / MoveWide* / MoveObject* — same body
    Vmap vm2; check_str("MoveFrom16.__str__",     MoveFrom16("v2","v3",vm2)->ToString(),     "VAR_v2 = VAR_v3");
    Vmap vm3; check_str("Move16.__str__",         Move16("v4","v5",vm3)->ToString(),         "VAR_v4 = VAR_v5");
    Vmap vm4; check_str("MoveWide.__str__",       MoveWide("v6","v7",vm4)->ToString(),       "VAR_v6 = VAR_v7");
    Vmap vm5; check_str("MoveObject.__str__",     MoveObject("v8","v9",vm5)->ToString(),     "VAR_v8 = VAR_v9");

    // MoveResult
    Vmap vm6;
    auto rv = std::make_shared<Variable>("retval");
    check_str("MoveResult.__str__",  MoveResult("v0", rv, vm6)->ToString(),
              "VAR_v0 = VAR_retval");

    // MoveException
    Vmap vm7;
    check_str("MoveException.__str__",
              MoveException("v0","Ljava/lang/Throwable;",vm7)->ToString(),
              "MOVE_EXCEPT VAR_v0");

    // Return reg / object / wide — all RETURN(<reg>)
    Vmap vm8; check_str("ReturnReg.__str__",     ReturnReg("v0",vm8)->ToString(),     "RETURN(VAR_v0)");
    Vmap vm9; check_str("ReturnObject.__str__",  ReturnObject("v0",vm9)->ToString(),  "RETURN(VAR_v0)");
    Vmap vmA; check_str("ReturnWide.__str__",    ReturnWide("v0",vmA)->ToString(),    "RETURN(VAR_v0)");

    // Const family
    Vmap vmB; check_str("Const4.__str__",        Const4("v0",5,vmB)->ToString(),       "ASSIGN(VAR_v0, CST_5)");
    Vmap vmC; check_str("Const16.__str__",       Const16("v0",42,vmC)->ToString(),     "ASSIGN(VAR_v0, CST_42)");
    Vmap vmD; check_str("Const.__str__",         Const("v0",0xCAFE,vmD)->ToString(),   "ASSIGN(VAR_v0, CST_51966)");
    Vmap vmE; check_str("ConstWide16.__str__",   ConstWide16("v0",42,vmE)->ToString(), "ASSIGN(VAR_v0, CST_42)");

    // ConstString
    Vmap vmF;
    check_str("ConstString.__str__",
              ConstString("v0","hello",vmF)->ToString(),
              "ASSIGN(VAR_v0, CST_'hello')");

    // ConstClass — wraps in CST_'<java type>'
    Vmap vmG;
    check_str("ConstClass.__str__",
              ConstClass("v0","Lcom/X;",vmG)->ToString(),
              "ASSIGN(VAR_v0, CST_'com.X')");

    // MonitorEnter / MonitorExit — base RefExpression has no __str__ override,
    // falls back to IRForm::ToString() = "" (matches Python's missing __str__).
    Vmap vmH;
    check_str("MonitorEnter.__str__",
              MonitorEnter("v0",vmH)->ToString(), "");

    // CheckCast (driver passes Dalvik descriptor like "Lcom/Y;")
    Vmap vmI;
    check_str("CheckCast.__str__",
              CheckCast("v0","Lcom/Y;",vmI)->ToString(),
              "ASSIGN(VAR_v0, CAST(Lcom/Y;) VAR_v0)");

    // InstanceOf
    Vmap vmJ;
    check_str("InstanceOf.__str__",
              InstanceOf("v0","v1","Lcom/Y;",vmJ)->ToString(),
              "ASSIGN(VAR_v0, (instanceof VAR_v1 BASECLASS_com.Y))");

    // ArrayLength
    Vmap vmK;
    check_str("ArrayLength.__str__",
              ArrayLength("v0","v1",vmK)->ToString(),
              "ASSIGN(VAR_v0, ARRAYLEN(VAR_v1))");

    // NewInstance
    Vmap vmL;
    check_str("NewInstance.__str__",
              NewInstance_("v0","Lcom/X;",vmL)->ToString(),
              "ASSIGN(VAR_v0, NEW(Lcom/X;))");

    // NewArray
    Vmap vmM;
    check_str("NewArray.__str__",
              NewArray("v0","v1","[I",vmM)->ToString(),
              "ASSIGN(VAR_v0, NEWARRAY_[I[VAR_v1])");

    // Throw
    Vmap vmN;
    check_str("Throw.__str__",
              Throw("v0",vmN)->ToString(),
              "Throw VAR_v0");

    // Goto family
    check_str("Goto.__str__",   Goto()->ToString(),   "");
    check_str("Goto16.__str__", Goto16()->ToString(), "");
    check_str("Goto32.__str__", Goto32()->ToString(), "");

    // PackedSwitch / SparseSwitch
    Vmap vmO;
    auto ps = PackedSwitch("v0", 0x1234, vmO);
    check_str("PackedSwitch.__str__", ps->ToString(), "SWITCH(VAR_v0)");
    // We can peek branch by casting back
    auto sw = std::dynamic_pointer_cast<SwitchExpression>(ps);
    check("PackedSwitch.branch", sw ? sw->branch() : 0, (int32_t)0x1234);

    std::printf("\n%s — %d failure(s)\n", g_fail ? "FAIL" : "PASS", g_fail);
    return g_fail ? 1 : 0;
}
