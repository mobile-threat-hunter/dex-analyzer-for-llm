// Parity test for instruction_dispatch.
// Exercises a representative subset of OpcodeKind values, comparing
// dispatcher output (via ToString()) against expected IR formatting.

#include "instruction_dispatch.h"
#include "instruction.h"
#include "method_snapshot.h"
#include "opcode_ins.h"
#include "slicer/dex_bytecode.h"
#include <cstdio>
#include <memory>

namespace dad = dexkit::dad;
static int g_fail = 0;

static void check_str(const char* label, const std::string& got,
                      const char* want) {
    bool eq = (got == want);
    if (!eq) ++g_fail;
    std::printf("%s %-44s got=%-40s want=%s\n",
                eq ? "[ok]  " : "[FAIL]", label, got.c_str(), want);
}

// Minimal RetState for tests — like the one used in chunk D parity test.
class TestRetState : public dad::RetState {
public:
    int counter = 0;
    dad::IRFormPtr pinned;
    dad::IRFormPtr last_ret;
    dad::IRFormPtr New() override {
        last_ret = std::make_shared<dad::Variable>("ret" + std::to_string(counter++));
        return last_ret;
    }
    void SetTo(dad::IRFormPtr v) override {
        pinned = v;
        last_ret = std::move(v);
    }
    dad::IRFormPtr Last() override { return last_ret; }
};

// Helper to build a RawIns with a given opcode + decoded operands.
static dad::RawIns MakeIns(dex::Opcode op,
                           uint32_t vA = 0, uint32_t vB = 0, uint32_t vC = 0,
                           uint64_t vB_wide = 0) {
    dad::RawIns ri;
    ri.opcode = op;
    ri.decoded.opcode = op;
    ri.decoded.vA = vA;
    ri.decoded.vB = vB;
    ri.decoded.vC = vC;
    ri.decoded.vB_wide = vB_wide;
    return ri;
}

int main() {
    using namespace dad;
    TestRetState ret;

    // ─── nop / unused ─────────────────────────────────────────────────
    {
        Vmap vm;
        auto r = DispatchInstruction(MakeIns(dex::OP_NOP), vm, ret);
        check_str("nop → NopExpression", r->ToString(), "");
    }

    // ─── move / move-result / return ──────────────────────────────────
    {
        Vmap vm;
        auto r = DispatchInstruction(MakeIns(dex::OP_MOVE, 0, 1), vm, ret);
        check_str("move v0, v1", r->ToString(), "VAR_v0 = VAR_v1");
    }
    {
        Vmap vm;
        auto r = DispatchInstruction(MakeIns(dex::OP_RETURN_VOID), vm, ret);
        check_str("return-void", r->ToString(), "RETURN");
    }
    {
        Vmap vm;
        auto r = DispatchInstruction(MakeIns(dex::OP_RETURN, 3), vm, ret);
        check_str("return v3", r->ToString(), "RETURN(VAR_v3)");
    }

    // ─── const family ─────────────────────────────────────────────────
    {
        Vmap vm;
        auto r = DispatchInstruction(MakeIns(dex::OP_CONST_16, 0, 42), vm, ret);
        check_str("const/16 v0, #42", r->ToString(), "ASSIGN(VAR_v0, CST_42)");
    }
    {
        Vmap vm;
        // const/16 v0, #-3
        auto ri = MakeIns(dex::OP_CONST_16, 0, 0xFFFD);  // -3 as u16
        auto r = DispatchInstruction(ri, vm, ret);
        check_str("const/16 v0, #-3", r->ToString(), "ASSIGN(VAR_v0, CST_-3)");
    }
    {
        Vmap vm;
        dad::RawIns ri = MakeIns(dex::OP_CONST_STRING, 5);
        ri.const_ref = StringConst{"hello", 0};
        auto r = DispatchInstruction(ri, vm, ret);
        check_str("const-string v5, \"hello\"",
                  r->ToString(), "ASSIGN(VAR_v5, CST_'hello')");
    }
    {
        Vmap vm;
        dad::RawIns ri = MakeIns(dex::OP_CONST_CLASS, 2);
        ri.const_ref = TypeConst{"Lcom/X;", 0};
        auto r = DispatchInstruction(ri, vm, ret);
        check_str("const-class v2, Lcom/X; (DAD lstrip quirk)",
                  r->ToString(), "ASSIGN(VAR_v2, CST_'com.X')");
    }

    // ─── arithmetic 3-addr ────────────────────────────────────────────
    {
        Vmap vm;
        auto r = DispatchInstruction(MakeIns(dex::OP_ADD_INT, 0, 1, 2), vm, ret);
        check_str("add-int v0, v1, v2",
                  r->ToString(), "ASSIGN(VAR_v0, (+ VAR_v1 VAR_v2))");
    }
    {
        Vmap vm;
        auto r = DispatchInstruction(MakeIns(dex::OP_MUL_LONG, 0, 1, 2), vm, ret);
        check_str("mul-long v0, v1, v2",
                  r->ToString(), "ASSIGN(VAR_v0, (* VAR_v1 VAR_v2))");
    }

    // ─── 2-addr ────────────────────────────────────────────────────────
    {
        Vmap vm;
        auto r = DispatchInstruction(MakeIns(dex::OP_ADD_INT_2ADDR, 0, 1), vm, ret);
        check_str("add-int/2addr v0, v1",
                  r->ToString(), "ASSIGN(VAR_v0, (+ VAR_v0 VAR_v1))");
    }

    // ─── lit16 / lit8 ─────────────────────────────────────────────────
    {
        Vmap vm;
        auto r = DispatchInstruction(MakeIns(dex::OP_ADD_INT_LIT16, 0, 1, 100), vm, ret);
        check_str("add-int/lit16 v0, v1, 100",
                  r->ToString(), "ASSIGN(VAR_v0, (+ VAR_v1 CST_100))");
    }
    {
        Vmap vm;
        // rsub-int v0, v1, 50
        auto r = DispatchInstruction(MakeIns(dex::OP_RSUB_INT, 0, 1, 50), vm, ret);
        check_str("rsub-int v0, v1, 50 (reversed)",
                  r->ToString(), "ASSIGN(VAR_v0, (- CST_50 VAR_v1))");
    }
    {
        Vmap vm;
        // add-int/lit8 v0, v1, -3 → becomes SUB per DAD quirk
        auto r = DispatchInstruction(
            MakeIns(dex::OP_ADD_INT_LIT8, 0, 1, static_cast<uint32_t>(-3)), vm, ret);
        check_str("add-int/lit8 v0, v1, -3 (quirk → SUB)",
                  r->ToString(), "ASSIGN(VAR_v0, (- VAR_v1 CST_3))");
    }

    // ─── if-test / if-testz ───────────────────────────────────────────
    {
        Vmap vm;
        auto r = DispatchInstruction(MakeIns(dex::OP_IF_EQ, 0, 1), vm, ret);
        check_str("if-eq v0, v1", r->ToString(), "COND(==, VAR_v0, VAR_v1)");
    }
    {
        Vmap vm;
        auto r = DispatchInstruction(MakeIns(dex::OP_IF_EQZ, 0), vm, ret);
        check_str("if-eqz v0", r->ToString(), "(IS==0, VAR_v0)");
    }

    // ─── invoke-virtual ───────────────────────────────────────────────
    {
        Vmap vm;
        dad::RawIns ri = MakeIns(dex::OP_INVOKE_VIRTUAL,
                                  /*count vA=*/2,
                                  /*method_idx vB=*/0,
                                  /*ignored*/0);
        ri.decoded.arg[0] = 0;  // vC = v0 (receiver)
        ri.decoded.arg[1] = 1;  // vD = v1 (arg)
        ri.const_ref = MethodConst{{"Lcom/X;", "foo", "(I)I"}, 0};
        auto r = DispatchInstruction(ri, vm, ret);
        check_str("invoke-virtual {v0,v1}, X.foo(I)I",
                  r->ToString(), "ASSIGN(VAR_ret0, VAR_v0.foo(VAR_v1))");
    }

    // ─── invoke-static (no receiver) ──────────────────────────────────
    {
        Vmap vm;
        dad::RawIns ri = MakeIns(dex::OP_INVOKE_STATIC, /*count*/1, 0);
        ri.decoded.arg[0] = 5;  // single arg
        ri.const_ref = MethodConst{{"Lcom/X;", "bar", "(I)V"}, 0};
        auto r = DispatchInstruction(ri, vm, ret);
        check_str("invoke-static {v5}, X.bar(I)V",
                  r->ToString(),
                  "ASSIGN(None, BASECLASS_com.X.bar(VAR_v5))");
    }

    // ─── goto ─────────────────────────────────────────────────────────
    {
        Vmap vm;
        auto r = DispatchInstruction(MakeIns(dex::OP_GOTO), vm, ret);
        check_str("goto → Nop (empty IR)", r->ToString(), "");
    }

    // ─── neg ──────────────────────────────────────────────────────────
    {
        Vmap vm;
        auto r = DispatchInstruction(MakeIns(dex::OP_NEG_INT, 0, 1), vm, ret);
        check_str("neg-int v0, v1",
                  r->ToString(), "ASSIGN(VAR_v0, (-, VAR_v1))");
    }

    // ─── int-to-long ──────────────────────────────────────────────────
    {
        Vmap vm;
        auto r = DispatchInstruction(MakeIns(dex::OP_INT_TO_LONG, 0, 1), vm, ret);
        check_str("int-to-long v0, v1",
                  r->ToString(), "ASSIGN(VAR_v0, CAST_(long)(VAR_v1))");
    }

    // ─── aget / aput ──────────────────────────────────────────────────
    {
        Vmap vm;
        auto r = DispatchInstruction(MakeIns(dex::OP_AGET, 0, 1, 2), vm, ret);
        check_str("aget v0, v1, v2",
                  r->ToString(), "ASSIGN(VAR_v0, ARRAYLOAD(VAR_v1, VAR_v2))");
    }

    // ─── iget / sget (field) ──────────────────────────────────────────
    {
        Vmap vm;
        dad::RawIns ri = MakeIns(dex::OP_IGET, 0, 1);
        ri.const_ref = FieldConst{{"Lcom/X;", "fld", "I"}, 0};
        auto r = DispatchInstruction(ri, vm, ret);
        check_str("iget v0, v1, X.fld:I",
                  r->ToString(), "ASSIGN(VAR_v0, VAR_v1.fld)");
    }

    // ─── monitor-enter ────────────────────────────────────────────────
    {
        Vmap vm;
        auto r = DispatchInstruction(MakeIns(dex::OP_MONITOR_ENTER, 0), vm, ret);
        check_str("monitor-enter v0 (no ToString override)",
                  r->ToString(), "");
    }

    // ─── throw ────────────────────────────────────────────────────────
    {
        Vmap vm;
        auto r = DispatchInstruction(MakeIns(dex::OP_THROW, 0), vm, ret);
        check_str("throw v0", r->ToString(), "Throw VAR_v0");
    }

    std::printf("\n%s — %d failure(s)\n", g_fail ? "FAIL" : "PASS", g_fail);
    return g_fail ? 1 : 0;
}
