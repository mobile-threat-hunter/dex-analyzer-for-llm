// Parity test for opcode_ins.cpp chunk D (invoke family).
#include "opcode_ins.h"
#include <cstdio>
#include <memory>
#include <vector>
namespace dad = dexkit::dad;
static int g_fail = 0;
template <typename A, typename B>
static void check(const char* l, A g, B w) {
    bool eq = (g == w); if (!eq) ++g_fail;
    std::printf("%s %-44s got=%-30lld want=%lld\n",
                eq?"[ok]  ":"[FAIL]", l, (long long)g, (long long)w);
}
static void check_str(const char* l, const std::string& g, const char* w) {
    bool eq = (g == w); if (!eq) ++g_fail;
    std::printf("%s %-44s got=%-44s want=%s\n",
                eq?"[ok]  ":"[FAIL]", l, g.c_str(), w);
}

// Minimal RetState impl for testing — mirrors DAD's Ret object.
class TestRetState : public dad::RetState {
public:
    int counter = 0;
    dad::IRFormPtr pinned;
    dad::IRFormPtr New() override {
        auto v = std::make_shared<dad::Variable>("ret" + std::to_string(counter++));
        return v;
    }
    void SetTo(dad::IRFormPtr v) override { pinned = std::move(v); }
};

int main() {
    using namespace dad;

    // invoke-virtual: foo(I)I — param_type = ['I'] (DAD-quirky single-elem)
    MethodRef m_vi{"com.X", "foo", {"I"}, "I",
                   {"Lcom/X;","foo","(I)I"}, "Lcom/X;"};
    Vmap vm; TestRetState ret;
    check_str("InvokeVirtual.__str__",
              InvokeVirtual(m_vi, "v0","v1","","","",ret,vm)->ToString(),
              "ASSIGN(VAR_ret0, VAR_v0.foo(VAR_v1))");

    // invoke-static: static foo(I)I — base is BaseClass("com.X")
    MethodRef m_st{"com.X", "foo", {"I"}, "I",
                   {"Lcom/X;","foo","(I)I"}, "Lcom/X;"};
    Vmap vm2; TestRetState ret2;
    check_str("InvokeStatic.__str__",
              InvokeStatic(m_st, "v0","v1","","","",ret2,vm2)->ToString(),
              "ASSIGN(VAR_ret0, BASECLASS_com.X.foo(VAR_v0))");

    // invoke-direct <init>: receiver=v0, void return.
    // Since receiver isn't ThisParam, returned=base, ret.set_to(base).
    MethodRef m_di{"com.X", "<init>", {}, "V",
                   {"Lcom/X;","<init>","()V"}, "Lcom/X;"};
    Vmap vm3; TestRetState ret3;
    auto inv_di = InvokeDirect(m_di, "v0","","","","",ret3,vm3);
    check_str("InvokeDirect<init>.__str__",
              inv_di->ToString(), "ASSIGN(VAR_v0, VAR_v0.<init>())");
    check("InvokeDirect ret.SetTo called", (ret3.pinned != nullptr), true);

    // invoke-super: base is BaseClass("super"), name foo
    MethodRef m_su{"com.X", "foo", {"I"}, "I",
                   {"Lcom/X;","foo","(I)I"}, "Lcom/X;"};
    Vmap vm4; TestRetState ret4;
    check_str("InvokeSuper.__str__",
              InvokeSuper(m_su, "v0","v1","","","",ret4,vm4)->ToString(),
              "ASSIGN(VAR_ret0, BASECLASS_super.foo(VAR_v1))");

    // invoke-interface: same as invoke-virtual shape.
    MethodRef m_in{"com.X", "foo", {"I"}, "I",
                   {"Lcom/X;","foo","(I)I"}, "Lcom/X;"};
    Vmap vm5; TestRetState ret5;
    check_str("InvokeInterface.__str__",
              InvokeInterface(m_in, "v0","v1","","","",ret5,vm5)->ToString(),
              "ASSIGN(VAR_ret0, VAR_v0.foo(VAR_v1))");

    // invoke-virtual/range: regs [v0, v1, v2]; this=v0, args=[v1] (single
    // due to param_type=['I'] quirk).
    MethodRef m_vr{"com.X", "foo", {"I"}, "I",
                   {"Lcom/X;","foo","(I)I"}, "Lcom/X;"};
    Vmap vm6; TestRetState ret6;
    std::vector<std::string> regs = {"v0","v1","v2"};
    check_str("InvokeVirtualRange.__str__",
              InvokeVirtualRange(m_vr, regs, ret6, vm6)->ToString(),
              "ASSIGN(VAR_ret0, VAR_v0.foo(VAR_v1))");

    // invoke-static/range — no receiver; all regs are args (but GetArgs
    // only picks the first due to DAD quirk).
    MethodRef m_sr{"com.X", "bar", {"I"}, "V",
                   {"Lcom/X;","bar","(I)V"}, "Lcom/X;"};
    Vmap vm7; TestRetState ret7;
    std::vector<std::string> regs7 = {"v0"};
    check_str("InvokeStaticRange.__str__",
              InvokeStaticRange(m_sr, regs7, ret7, vm7)->ToString(),
              "ASSIGN(None, BASECLASS_com.X.bar(VAR_v0))");

    std::printf("\n%s — %d failure(s)\n", g_fail ? "FAIL" : "PASS", g_fail);
    return g_fail ? 1 : 0;
}
