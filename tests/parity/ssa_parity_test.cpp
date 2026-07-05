// Unit test for ssa.cpp (Additive SSA analysis — NOT a DAD parity test; the
// *_parity_test.cpp glob just auto-registers it with ctest).
//
// Phase 1a: dominance frontiers (Cytron). Textbook CFGs with hand-computed
// frontiers, incl. the loop shape whose heuristic mis-split motivated the SSA
// rewrite (docs/ssa-design.md).
// Phase 1b: SSA construction (phi insertion + renaming) on synthetic IR.
#include "ssa.h"
#include "graph.h"
#include "basic_blocks.h"
#include "instruction.h"
#include "dataflow.h"
#include <algorithm>
#include <cstdio>
#include <set>
#include <string>

namespace dad = dexkit::dad;
static int g_fail = 0;

// Assert DF(node) == expected set of node names.
static void check_df(
    const char* label,
    const std::unordered_map<dad::NodeBase*, std::vector<dad::NodeBase*>>& df,
    dad::NodeBase* node, std::set<std::string> want) {
    std::set<std::string> got;
    auto it = df.find(node);
    if (it != df.end())
        for (dad::NodeBase* n : it->second) got.insert(n->name);
    bool eq = (got == want);
    if (!eq) ++g_fail;
    auto join = [](const std::set<std::string>& s) {
        std::string r = "{";
        for (auto& x : s) { if (r.size() > 1) r += ","; r += x; }
        return r + "}";
    };
    std::printf("%s %-30s got=%-14s want=%s\n", eq ? "[ok]  " : "[FAIL]",
                label, join(got).c_str(), join(want).c_str());
}

int main() {
    using namespace dad;

    // --- Diamond: A → {T, F} → J -----------------------------------------
    // A dominates all; T,F each dominate only themselves; J is the join.
    // DF(T)=DF(F)={J}, DF(A)=DF(J)={}.
    {
        Graph g;
        StatementBlock a("A", {}), t("T", {}), f("F", {}), j("J", {});
        g.add_node(&a); g.add_node(&t); g.add_node(&f); g.add_node(&j);
        g.entry = &a;
        g.add_edge(&a, &t); g.add_edge(&a, &f);
        g.add_edge(&t, &j); g.add_edge(&f, &j);
        g.compute_rpo();
        auto df = DominanceFrontiers(g);
        check_df("diamond DF(A)", df, &a, {});
        check_df("diamond DF(T)", df, &t, {"J"});
        check_df("diamond DF(F)", df, &f, {"J"});
        check_df("diamond DF(J)", df, &j, {});
    }

    // --- Loop: P → H → B → H (back-edge), H → X --------------------------
    // P is the preheader (distinct from the header, as in real methods where the
    // entry defines params before the loop). H is the loop header (2 preds: P +
    // back-edge B). A loop header is in its OWN dominance frontier.
    // DF(B)={H}, DF(H)={H}, DF(P)=DF(X)={}.
    {
        Graph g;
        StatementBlock p("P", {}), h("H", {}), b("B", {}), x("X", {});
        g.add_node(&p); g.add_node(&h); g.add_node(&b); g.add_node(&x);
        g.entry = &p;
        g.add_edge(&p, &h);
        g.add_edge(&h, &b);
        g.add_edge(&b, &h);   // back-edge
        g.add_edge(&h, &x);   // exit
        g.compute_rpo();
        auto df = DominanceFrontiers(g);
        check_df("loop DF(P)", df, &p, {});
        check_df("loop DF(B)", df, &b, {"H"});
        check_df("loop DF(H)", df, &h, {"H"});
        check_df("loop DF(X)", df, &x, {});
    }

    // --- Loop with an inner branch (the v1 mis-split shape) ---------------
    // P → H ; H → B ; B → {L, S} ; L → C ; S → C ; C → H (back) ; H → X.
    // A register defined on both L and S arms and again around the loop is
    // exactly what the heuristic mis-split. The genuine merges are C (join of
    // L,S) and H (loop header). DF(L)=DF(S)={C}; DF(C)={H}; DF(B)={H}; DF(H)={H}.
    {
        Graph g;
        StatementBlock p("P", {}), h("H", {}), b("B", {}), l("L", {}),
            s("S", {}), c("C", {}), x("X", {});
        for (NodeBase* n : std::initializer_list<NodeBase*>{
                 &p, &h, &b, &l, &s, &c, &x}) g.add_node(n);
        g.entry = &p;
        g.add_edge(&p, &h);
        g.add_edge(&h, &b);
        g.add_edge(&b, &l); g.add_edge(&b, &s);
        g.add_edge(&l, &c); g.add_edge(&s, &c);
        g.add_edge(&c, &h);   // back-edge
        g.add_edge(&h, &x);   // exit
        g.compute_rpo();
        auto df = DominanceFrontiers(g);
        check_df("inner DF(L)", df, &l, {"C"});
        check_df("inner DF(S)", df, &s, {"C"});
        check_df("inner DF(C)", df, &c, {"H"});
        check_df("inner DF(B)", df, &b, {"H"});
        check_df("inner DF(H)", df, &h, {"H"});
        check_df("inner DF(X)", df, &x, {});
    }

    // === Phase 1b: SSA construction (phi insertion + renaming) ===========
    auto icheck = [](const char* label, long got, long want) {
        bool eq = (got == want);
        if (!eq) ++g_fail;
        std::printf("%s %-30s got=%-8ld want=%ld\n", eq ? "[ok]  " : "[FAIL]",
                    label, got, want);
    };

    // --- Diamond with a conflated register --------------------------------
    // A → {T, F} → J.  T: v0=1 ; F: v0=2 ; J: v1 = v0.
    // v0 is defined on both arms → a phi for v0 at J. The use of v0 in J reads
    // the phi result (its newest version), not either arm directly.
    {
        Graph g;
        auto c1 = std::make_shared<Constant>("1", "I");
        auto c2 = std::make_shared<Constant>("2", "I");
        auto v0t = std::make_shared<Variable>("v0");
        auto v0f = std::make_shared<Variable>("v0");
        auto v0u = std::make_shared<Variable>("v0");
        auto v1 = std::make_shared<Variable>("v1");
        auto dt = std::make_shared<AssignExpression>(v0t, c1);   // T: v0 = 1
        auto df_ = std::make_shared<AssignExpression>(v0f, c2);  // F: v0 = 2
        auto ju = std::make_shared<MoveExpression>(v1, v0u);     // J: v1 = v0
        StatementBlock a("A", {}), t("T", {dt}), f("F", {df_}), j("J", {ju});
        g.add_node(&a); g.add_node(&t); g.add_node(&f); g.add_node(&j);
        g.entry = &a;
        g.add_edge(&a, &t); g.add_edge(&a, &f);
        g.add_edge(&t, &j); g.add_edge(&f, &j);
        g.compute_rpo();
        g.number_ins();
        auto ssa = BuildSsa(g, {});

        icheck("diamond #phi", (long)ssa.phis.size(), 1);
        if (ssa.phis.size() == 1) {
            const auto& phi = ssa.phis[0];
            icheck("diamond phi reg==v0", phi.reg == "v0" ? 1 : 0, 1);
            icheck("diamond phi @ J", phi.block == &j ? 1 : 0, 1);
            icheck("diamond phi #operands", (long)phi.operands.size(), 2);
            // v0's use in J reads the phi result version (the newest v0 version).
            long used = -1;
            for (auto& [k, ver] : ssa.use_version)
                if (k.first == "v0") used = ver;
            icheck("diamond v0-use reads phi", used == phi.result ? 1 : 0, 1);
            icheck("diamond phi result is phi-def",
                   ssa.def_site[{"v0", phi.result}] == SsaResult::DEF_PHI ? 1 : 0,
                   1);
        }
    }

    // --- Loop: a register defined before AND inside the loop ---------------
    // P: v0=0 ; H(header) ; B(body): v0 = v0 ... (redef) ; back-edge B→H ; H→X.
    // v0 defined in P and B; the loop header H is in DF(B) → a phi for v0 at H.
    {
        Graph g;
        auto c0 = std::make_shared<Constant>("0", "I");
        auto v0p = std::make_shared<Variable>("v0");
        auto v0b_lhs = std::make_shared<Variable>("v0");
        auto v0b_rhs = std::make_shared<Variable>("v0");
        auto dp = std::make_shared<AssignExpression>(v0p, c0);       // P: v0 = 0
        auto db = std::make_shared<MoveExpression>(v0b_lhs, v0b_rhs);// B: v0 = v0
        StatementBlock p("P", {dp}), h("H", {}), b("B", {db}), x("X", {});
        g.add_node(&p); g.add_node(&h); g.add_node(&b); g.add_node(&x);
        g.entry = &p;
        g.add_edge(&p, &h);
        g.add_edge(&h, &b);
        g.add_edge(&b, &h);   // back-edge
        g.add_edge(&h, &x);   // exit
        g.compute_rpo();
        g.number_ins();
        auto ssa = BuildSsa(g, {});

        icheck("loop #phi", (long)ssa.phis.size(), 1);
        if (ssa.phis.size() == 1) {
            const auto& phi = ssa.phis[0];
            icheck("loop phi reg==v0", phi.reg == "v0" ? 1 : 0, 1);
            icheck("loop phi @ H", phi.block == &h ? 1 : 0, 1);
            // Header phi has 2 operands: the preheader def and the back-edge.
            icheck("loop phi #operands", (long)phi.operands.size(), 2);
        }
    }

    // === Phase 1c: oracle mutation test (non-vacuity) ====================
    // Design requires proving VerifySsa is not vacuous: build a real method,
    // confirm 0 mismatches vs reaching-def, then corrupt the SSA and assert the
    // oracle FIRES. (Adversarial + correctness reviewers flagged VerifySsa was
    // untested.)
    {
        Graph g;
        auto c1 = std::make_shared<Constant>("1", "I");
        auto c2 = std::make_shared<Constant>("2", "I");
        auto v0t = std::make_shared<Variable>("v0");
        auto v0f = std::make_shared<Variable>("v0");
        auto v0u = std::make_shared<Variable>("v0");
        auto v1 = std::make_shared<Variable>("v1");
        auto dt = std::make_shared<AssignExpression>(v0t, c1);
        auto df_ = std::make_shared<AssignExpression>(v0f, c2);
        auto ju = std::make_shared<MoveExpression>(v1, v0u);
        StatementBlock a("A", {}), t("T", {dt}), f("F", {df_}), j("J", {ju});
        g.add_node(&a); g.add_node(&t); g.add_node(&f); g.add_node(&j);
        g.entry = &a;
        g.add_edge(&a, &t); g.add_edge(&a, &f);
        g.add_edge(&t, &j); g.add_edge(&f, &j);
        g.compute_rpo();
        g.number_ins();
        auto chains = BuildDefUse(g, {});
        auto ssa = BuildSsa(g, {});
        auto ok = VerifySsa(g, {}, ssa, chains.ud);
        icheck("oracle clean (0 mismatch)", ok.mismatches, 0);
        icheck("oracle checked >0 uses", ok.uses_checked > 0 ? 1 : 0, 1);

        // Mutation 1: corrupt a use to a non-existent version → must fire.
        auto bad1 = ssa;
        for (auto& [k, ver] : bad1.use_version) ver = 99999;
        icheck("oracle fires on bad use_version",
               VerifySsa(g, {}, bad1, chains.ud).mismatches > 0 ? 1 : 0, 1);

        // Mutation 2: drop a phi operand → the merge loses an arm → must fire.
        if (!ssa.phis.empty()) {
            auto bad2 = ssa;
            bad2.phis[0].operands.pop_back();
            icheck("oracle fires on dropped phi operand",
                   VerifySsa(g, {}, bad2, chains.ud).mismatches > 0 ? 1 : 0, 1);
        }
    }

    // === Phase 1c: determinism invariant — res.phis is totally ordered =====
    // res.phis must be sorted by (reg, block num, name) so its vector order is
    // process-independent (it is built off a pointer-keyed worklist; Phase 2
    // iterates it). Exercise a register with TWO phis (defined in P, L, S of the
    // inner-branch loop → phis at C and H).
    {
        Graph g;
        auto c0 = std::make_shared<Constant>("0", "I");
        auto c1 = std::make_shared<Constant>("1", "I");
        auto c2 = std::make_shared<Constant>("2", "I");
        auto v0p = std::make_shared<Variable>("v0");
        auto v0l = std::make_shared<Variable>("v0");
        auto v0s = std::make_shared<Variable>("v0");
        auto v0x = std::make_shared<Variable>("v0");
        auto v1x = std::make_shared<Variable>("v1");
        auto dp = std::make_shared<AssignExpression>(v0p, c0);
        auto dl = std::make_shared<AssignExpression>(v0l, c1);
        auto ds = std::make_shared<AssignExpression>(v0s, c2);
        // v0 USED after the loop (X: v1=v0) so it stays live across the join /
        // header — under pruned SSA a DEAD register gets no phi.
        auto ux = std::make_shared<MoveExpression>(v1x, v0x);
        StatementBlock p("P", {dp}), h("H", {}), b("B", {}), l("L", {dl}),
            s("S", {ds}), c("C", {}), x("X", {ux});
        for (NodeBase* n : std::initializer_list<NodeBase*>{
                 &p, &h, &b, &l, &s, &c, &x}) g.add_node(n);
        g.entry = &p;
        g.add_edge(&p, &h); g.add_edge(&h, &b);
        g.add_edge(&b, &l); g.add_edge(&b, &s);
        g.add_edge(&l, &c); g.add_edge(&s, &c);
        g.add_edge(&c, &h); g.add_edge(&h, &x);
        g.compute_rpo();
        g.number_ins();
        auto ssa = BuildSsa(g, {});
        icheck("det: >=2 phis produced", ssa.phis.size() >= 2 ? 1 : 0, 1);
        bool sorted = true;
        for (size_t i = 1; i < ssa.phis.size(); ++i) {
            const auto& a = ssa.phis[i - 1];
            const auto& b2 = ssa.phis[i];
            bool le = a.reg < b2.reg ||
                      (a.reg == b2.reg &&
                       (a.block->num < b2.block->num ||
                        (a.block->num == b2.block->num &&
                         a.block->name <= b2.block->name)));
            if (!le) sorted = false;
        }
        icheck("det: res.phis totally ordered", sorted ? 1 : 0, 1);
    }

    // === Phase 1c: hang regression — cyclic (non-tree) external idom ========
    // DominanceFrontiers' two-arg overload accepts an external idom map. A
    // cyclic map (idom[B]=C, idom[C]=B) must NOT spin (0-hang invariant) — the
    // bounded runner-walk returns. Test completing == no hang.
    {
        Graph g;
        StatementBlock a("A", {}), b("B", {}), c("C", {}), j("J", {});
        g.add_node(&a); g.add_node(&b); g.add_node(&c); g.add_node(&j);
        g.entry = &a;
        g.add_edge(&a, &b); g.add_edge(&a, &c);
        g.add_edge(&b, &j); g.add_edge(&c, &j);
        g.compute_rpo();
        std::unordered_map<NodeBase*, NodeBase*> cyclic;
        cyclic[&a] = nullptr; cyclic[&b] = &c; cyclic[&c] = &b; cyclic[&j] = &a;
        auto df = DominanceFrontiers(g, cyclic);   // must return, not hang
        icheck("hang: cyclic idom returns", 1, 1);
        (void)df;
    }

    // === Phase B1: type-bounds model =====================================
    auto scheck = [&](const char* label, const std::string& got,
                      const std::string& want) {
        bool eq = (got == want);
        if (!eq) ++g_fail;
        std::printf("%s %-34s got=%-24s want=%s\n", eq ? "[ok]  " : "[FAIL]",
                    label, got.c_str(), want.c_str());
    };
    auto has_use = [](const dad::BoundsResult& b, const std::string& reg,
                      int ver, const std::string& t) {
        auto it = b.bounds.find({reg, ver});
        if (it == b.bounds.end()) return false;
        return std::find(it->second.uses.begin(), it->second.uses.end(), t)
               != it->second.uses.end();
    };
    auto assign_of = [](const dad::BoundsResult& b, const std::string& reg,
                        int ver) -> std::string {
        auto it = b.bounds.find({reg, ver});
        return it == b.bounds.end() ? std::string{} : it->second.assign;
    };

    // (1) ASSIGN from a new-instance def + USE from the receiver of a later
    //     call; a prim const passed at a reference param = an int↔ref CONFLICT.
    //   A: v0 = new LFoo;        (assign v0#1 = LFoo)
    //      v0.bar()              (use    v0#1 = LFoo, receiver)
    //      v2 = 5                (assign v2#1 = I)
    //      v0.baz(v2)            (use    v2#1 = String  → v2 conflicts I vs String)
    {
        Graph g;
        auto ni = std::make_shared<NewInstance>("LFoo;");
        auto v0d = std::make_shared<Variable>("v0");
        auto d0 = std::make_shared<AssignExpression>(v0d, ni);
        auto v0r = std::make_shared<Variable>("v0");
        // clsname ("Foo") is the GetType-CONVERTED form cls() returns in the real
        // pipeline; the raw Dalvik descriptor lives in triple()[0] ("LFoo;"). The
        // receiver USE bound MUST be recorded from triple()[0] — a converted
        // "Foo" would fail BoundIsRef and be silently dropped (correctness fix).
        InvokeInstruction::Triple tr{"LFoo;", "bar", "()V"};
        auto call = std::make_shared<InvokeInstruction>(
            "Foo", "bar", v0r, "V", std::vector<std::string>{},
            std::vector<IRFormPtr>{}, tr);
        auto c5 = std::make_shared<Constant>(std::string("5"), "I", int64_t{5});
        auto v2d = std::make_shared<Variable>("v2");
        auto d2 = std::make_shared<AssignExpression>(v2d, c5);
        auto v0r2 = std::make_shared<Variable>("v0");
        auto v2u = std::make_shared<Variable>("v2");
        InvokeInstruction::Triple tr2{"LFoo;", "baz", "(Ljava/lang/String;)V"};
        auto call2 = std::make_shared<InvokeInstruction>(
            "LFoo;", "baz", v0r2, "V",
            std::vector<std::string>{"Ljava/lang/String;"},
            std::vector<IRFormPtr>{v2u}, tr2);
        StatementBlock a("A", {d0, call, d2, call2});
        g.add_node(&a);
        g.entry = &a;
        g.compute_rpo();
        g.number_ins();
        auto ssa = BuildSsa(g, {});
        auto bnds = ComputeTypeBounds(g, ssa, {}, "V");
        scheck("bounds: v0#1 assign new-instance", assign_of(bnds, "v0", 1),
               "LFoo;");
        icheck("bounds: v0#1 used as receiver",
               has_use(bnds, "v0", 1, "LFoo;") ? 1 : 0, 1);
        scheck("bounds: v2#1 assign const-int", assign_of(bnds, "v2", 1), "I");
        icheck("bounds: v2#1 used as String-arg",
               has_use(bnds, "v2", 1, "Ljava/lang/String;") ? 1 : 0, 1);
    }

    // (2) A live-in PARAM's ASSIGN bound comes from param_types; a `return v`
    //     contributes the method-return-type USE bound.
    //   entry: return v3   (params={v3:LBar;}, ret=LBar;)
    {
        Graph g;
        auto v3u = std::make_shared<Variable>("v3");
        auto ret = std::make_shared<ReturnInstruction>(v3u);
        StatementBlock a("A", {ret});
        g.add_node(&a);
        g.entry = &a;
        g.compute_rpo();
        g.number_ins();
        auto ssa = BuildSsa(g, {"v3"});
        auto bnds = ComputeTypeBounds(g, ssa, {{"v3", "LBar;"}}, "LBar;");
        scheck("bounds: v3#0 live-in assign", assign_of(bnds, "v3", 0), "LBar;");
        icheck("bounds: v3#0 return USE bound",
               has_use(bnds, "v3", 0, "LBar;") ? 1 : 0, 1);
    }

    // === Phase B2: phi-web merge + hierarchy selection ===================
    auto sel_of = [](const dad::SelectResult& s, const std::string& reg,
                     int ver) -> dad::SelectedType {
        auto it = s.types.find({reg, ver});
        return it == s.types.end() ? dad::SelectedType{} : it->second;
    };

    // (3) A single-def reference version resolves to its produced type; a
    //     prim-def used as a reference is a CONFLICT → Object.
    //   A: v0 = new LFoo;  v0.bar();  v2 = 5;  v0.baz(v2)   (baz param0 = String)
    {
        Graph g;
        auto ni = std::make_shared<NewInstance>("LFoo;");
        auto v0d = std::make_shared<Variable>("v0");
        auto d0 = std::make_shared<AssignExpression>(v0d, ni);
        auto v0r = std::make_shared<Variable>("v0");
        // clsname ("Foo") is the GetType-CONVERTED form cls() returns in the real
        // pipeline; the raw Dalvik descriptor lives in triple()[0] ("LFoo;"). The
        // receiver USE bound MUST be recorded from triple()[0] — a converted
        // "Foo" would fail BoundIsRef and be silently dropped (correctness fix).
        InvokeInstruction::Triple tr{"LFoo;", "bar", "()V"};
        auto call = std::make_shared<InvokeInstruction>(
            "Foo", "bar", v0r, "V", std::vector<std::string>{},
            std::vector<IRFormPtr>{}, tr);
        auto c5 = std::make_shared<Constant>(std::string("5"), "I", int64_t{5});
        auto v2d = std::make_shared<Variable>("v2");
        auto d2 = std::make_shared<AssignExpression>(v2d, c5);
        auto v0r2 = std::make_shared<Variable>("v0");
        auto v2u = std::make_shared<Variable>("v2");
        InvokeInstruction::Triple tr2{"LFoo;", "baz", "(Ljava/lang/String;)V"};
        auto call2 = std::make_shared<InvokeInstruction>(
            "LFoo;", "baz", v0r2, "V",
            std::vector<std::string>{"Ljava/lang/String;"},
            std::vector<IRFormPtr>{v2u}, tr2);
        StatementBlock a("A", {d0, call, d2, call2});
        g.add_node(&a);
        g.entry = &a;
        g.compute_rpo();
        g.number_ins();
        auto ssa = BuildSsa(g, {});
        auto bnds = ComputeTypeBounds(g, ssa, {}, "V");
        auto sel = SelectTypes(ssa, bnds, nullptr);
        scheck("select: v0#1 -> LFoo", sel_of(sel, "v0", 1).type, "LFoo;");
        icheck("select: v0#1 not conflict", sel_of(sel, "v0", 1).conflict ? 1 : 0,
               0);
        scheck("select: v2#1 conflict -> Object", sel_of(sel, "v2", 1).type,
               "Ljava/lang/Object;");
        icheck("select: v2#1 is conflict", sel_of(sel, "v2", 1).conflict ? 1 : 0,
               1);
    }

    // (4) PHI-WEB merge: a register defined as a reference on one arm and an int
    //     on the other, merging at a join, is one conflated web → Object across
    //     ALL its versions (the residual B3 resolves with Object + casts).
    //   A → {T, F} → J.  T: v0 = new LFoo ;  F: v0 = 7 ;  J: v0.bar()
    {
        Graph g;
        auto ni = std::make_shared<NewInstance>("LFoo;");
        auto v0t = std::make_shared<Variable>("v0");
        auto dt = std::make_shared<AssignExpression>(v0t, ni);   // T: v0 = new
        auto c7 = std::make_shared<Constant>(std::string("7"), "I", int64_t{7});
        auto v0f = std::make_shared<Variable>("v0");
        auto df_ = std::make_shared<AssignExpression>(v0f, c7);  // F: v0 = 7
        auto v0j = std::make_shared<Variable>("v0");
        InvokeInstruction::Triple tr{"LFoo;", "bar", "()V"};
        auto call = std::make_shared<InvokeInstruction>(
            "LFoo;", "bar", v0j, "V", std::vector<std::string>{},
            std::vector<IRFormPtr>{}, tr);
        StatementBlock a("A", {}), t("T", {dt}), f("F", {df_}), j("J", {call});
        g.add_node(&a); g.add_node(&t); g.add_node(&f); g.add_node(&j);
        g.entry = &a;
        g.add_edge(&a, &t); g.add_edge(&a, &f);
        g.add_edge(&t, &j); g.add_edge(&f, &j);
        g.compute_rpo();
        g.number_ins();
        auto ssa = BuildSsa(g, {});
        auto bnds = ComputeTypeBounds(g, ssa, {}, "V");
        auto sel = SelectTypes(ssa, bnds, nullptr);
        icheck("select: phi-web #conflicts==1", sel.conflicts == 1 ? 1 : 0, 1);
        // Every BOUND v0 version (the two arm defs + the phi result — NOT the
        // unused v0#0 entry value) is Object across the merged web.
        bool all_obj = true;
        for (auto& [k, tb] : bnds.bounds) {
            (void)tb;
            if (k.first != "v0") continue;
            if (sel_of(sel, k.first, k.second).type != "Ljava/lang/Object;")
                all_obj = false;
        }
        icheck("select: phi-web bound v0 -> Object", all_obj ? 1 : 0, 1);
    }

    // (5) A `const 0` merged with a reference is the NULL reference, NOT an
    //     int↔ref conflict. Narrow-zero contributes no ASSIGN bound, so the web
    //     resolves to the reference (regression guard for the false-conflict the
    //     naive model produced on every `cond ? obj : null`).
    //   A → {T, F} → J.  T: v0 = new LFoo ;  F: v0 = 0 (null) ;  J: v0.bar()
    {
        Graph g;
        auto ni = std::make_shared<NewInstance>("LFoo;");
        auto v0t = std::make_shared<Variable>("v0");
        auto dt = std::make_shared<AssignExpression>(v0t, ni);
        auto c0 = std::make_shared<Constant>(std::string("0"), "I", int64_t{0});
        auto v0f = std::make_shared<Variable>("v0");
        auto df_ = std::make_shared<AssignExpression>(v0f, c0);  // F: v0 = null
        auto v0j = std::make_shared<Variable>("v0");
        InvokeInstruction::Triple tr{"LFoo;", "bar", "()V"};
        auto call = std::make_shared<InvokeInstruction>(
            "LFoo;", "bar", v0j, "V", std::vector<std::string>{},
            std::vector<IRFormPtr>{}, tr);
        StatementBlock a("A", {}), t("T", {dt}), f("F", {df_}), j("J", {call});
        g.add_node(&a); g.add_node(&t); g.add_node(&f); g.add_node(&j);
        g.entry = &a;
        g.add_edge(&a, &t); g.add_edge(&a, &f);
        g.add_edge(&t, &j); g.add_edge(&f, &j);
        g.compute_rpo();
        g.number_ins();
        auto ssa = BuildSsa(g, {});
        auto bnds = ComputeTypeBounds(g, ssa, {}, "V");
        auto sel = SelectTypes(ssa, bnds, nullptr);
        icheck("select: null-merge NOT a conflict", sel.conflicts == 0 ? 1 : 0, 1);
        bool all_foo = true;
        for (auto& [k, tb] : bnds.bounds) {
            (void)tb;
            if (k.first == "v0" &&
                sel_of(sel, k.first, k.second).type != "LFoo;")
                all_foo = false;
        }
        icheck("select: null-merge web -> LFoo", all_foo ? 1 : 0, 1);
    }

    // (6) Pruned SSA regression: a register defined but DEAD at a join gets no
    //     phi, so its unrelated redefinitions do NOT merge into one web. Here v0
    //     is defined as a reference in T and an int in F, but NEVER used after
    //     the join — no phi, no false int↔ref conflict.
    //   A → {T, F} → J(empty).  T: v0 = new LFoo ;  F: v0 = 7 ;  (v0 dead at J)
    {
        Graph g;
        auto ni = std::make_shared<NewInstance>("LFoo;");
        auto v0t = std::make_shared<Variable>("v0");
        auto dt = std::make_shared<AssignExpression>(v0t, ni);
        auto c7 = std::make_shared<Constant>(std::string("7"), "I", int64_t{7});
        auto v0f = std::make_shared<Variable>("v0");
        auto df_ = std::make_shared<AssignExpression>(v0f, c7);
        StatementBlock a("A", {}), t("T", {dt}), f("F", {df_}), j("J", {});
        g.add_node(&a); g.add_node(&t); g.add_node(&f); g.add_node(&j);
        g.entry = &a;
        g.add_edge(&a, &t); g.add_edge(&a, &f);
        g.add_edge(&t, &j); g.add_edge(&f, &j);
        g.compute_rpo();
        g.number_ins();
        auto ssa = BuildSsa(g, {});
        icheck("prune: dead v0 -> no phi", ssa.phis.empty() ? 1 : 0, 1);
        auto bnds = ComputeTypeBounds(g, ssa, {}, "V");
        auto sel = SelectTypes(ssa, bnds, nullptr);
        icheck("prune: dead redef -> no conflict", sel.conflicts == 0 ? 1 : 0, 1);
    }

    std::printf(g_fail ? "\n%d checks FAILED\n" : "\nall SSA checks passed\n",
                g_fail);
    return g_fail ? 1 : 0;
}
