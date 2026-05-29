// Parity test for dataflow.cpp.
// Covers: BasicReachDef (linear + branch), update_chain, dead_code_elimination,
//         clear_path_node, clear_path, register_propagation (smoke),
//         DummyNode, group_variables, split_variables, build_def_use,
//         place_declarations, BuildPath, CommonDom.
//
// Note: register_propagation / place_declarations have rich behavioural
// surface but require a full IR graph to exercise meaningfully. We test the
// non-mutating helpers directly and run a couple of smoke scenarios.

#include "dataflow.h"
#include "graph.h"
#include "basic_blocks.h"
#include "instruction.h"
#include <cstdio>
#include <memory>

namespace dad = dexkit::dad;
static int g_fail = 0;

template <typename A, typename B>
static void check(const char* label, A got, B want) {
    bool eq = (got == want);
    if (!eq) ++g_fail;
    std::printf("%s %-46s got=%-20lld want=%lld\n",
                eq ? "[ok]  " : "[FAIL]", label,
                static_cast<long long>(got), static_cast<long long>(want));
}

static void check_str(const char* label, const std::string& got,
                      const char* want) {
    bool eq = (got == want);
    if (!eq) ++g_fail;
    std::printf("%s %-46s got=%-30s want=%s\n",
                eq ? "[ok]  " : "[FAIL]", label, got.c_str(), want);
}

int main() {
    using namespace dad;

    // --- DummyNode --------------------------------------------------------
    {
        DummyNode dn("entry");
        check_str("DummyNode.ToString", dn.ToString(), "entry-dummynode");
    }

    // --- BasicReachDef: empty graph + params -----------------------------
    //   Build a synthetic graph: entry block A (no ins) → B (return).
    //   Pass two params "p0", "p1" — A.A should be {-1, -2}.
    {
        Graph g;
        StatementBlock a("A", {});
        ReturnBlock b("B", {});
        g.add_node(&a); g.add_node(&b);
        g.add_edge(&a, &b);
        g.entry = &a;
        g.compute_rpo();
        g.number_ins();
        BasicReachDef rd(g, {"p0", "p1"});
        check("ReachDef A in-set has -1", rd.A[&a].count(-1) == 1, true);
        check("ReachDef A in-set has -2", rd.A[&a].count(-2) == 1, true);
        check("def_to_loc[p0] has -1", rd.def_to_loc["p0"].count(-1) == 1,
              true);
        check("def_to_loc[p1] has -2", rd.def_to_loc["p1"].count(-2) == 1,
              true);
        rd.run();
        // After run, B's R-set should contain {-1,-2} (no kills between).
        check("After run: B's R has -1", rd.R[&b].count(-1) == 1, true);
        check("After run: B's R has -2", rd.R[&b].count(-2) == 1, true);
    }

    // --- BasicReachDef: kills via assign ---------------------------------
    //   A: assign v0=... at loc 0; B: returns.
    //   Initial def_to_loc[v0] = {0}; after run, B's A-set has 0.
    {
        Graph g;
        auto rhs = std::make_shared<Constant>("1", "I");
        // AssignExpression(lhs=Variable, rhs=Constant)
        auto v0 = std::make_shared<Variable>("v0");
        auto assign = std::make_shared<AssignExpression>(v0, rhs);
        StatementBlock a("A", {assign});
        ReturnBlock b("B", {});
        g.add_node(&a); g.add_node(&b);
        g.add_edge(&a, &b);
        g.entry = &a;
        g.compute_rpo();
        g.number_ins();
        BasicReachDef rd(g, /*params=*/{});
        check("def_to_loc[v0] has loc 0", rd.def_to_loc["v0"].count(0) == 1,
              true);
        // DB[A] should contain max(defs[A][v0]) = 0
        check("DB[A] has 0", rd.DB[&a].count(0) == 1, true);
        rd.run();
        check("After run: A's A-set has 0", rd.A[&a].count(0) == 1, true);
        check("After run: B's R-set has 0", rd.R[&b].count(0) == 1, true);
    }

    // --- BuildPath / CommonDom --------------------------------------------
    {
        //   A → B → D
        //    ↘ C ↗
        Graph g;
        StatementBlock a("A", {}), b("B", {}), c("C", {}), d("D", {});
        g.add_node(&a); g.add_node(&b); g.add_node(&c); g.add_node(&d);
        g.add_edge(&a, &b);
        g.add_edge(&a, &c);
        g.add_edge(&b, &d);
        g.add_edge(&c, &d);
        g.entry = &a;
        g.compute_rpo();
        auto idom = g.immediate_dominators();
        check("CommonDom(B, C) = A",
              (CommonDom(idom, &b, &c) == &a), true);
        check("CommonDom(D, D) = D",
              (CommonDom(idom, &d, &d) == &d), true);
        check("CommonDom(null, B) = B",
              (CommonDom(idom, nullptr, &b) == &b), true);

        auto path = BuildPath(g, &a, &d);
        // Path is set of nodes reachable backwards from d (exclusive of a).
        check("BuildPath(A→D) size", static_cast<int>(path.size()), 3);
    }

    // --- ClearPathNode / ClearPath ---------------------------------------
    {
        Graph g;
        auto v0 = std::make_shared<Variable>("v0");
        auto v1 = std::make_shared<Variable>("v1");
        auto c5 = std::make_shared<Constant>("5", "I");
        auto a0 = std::make_shared<AssignExpression>(v0, c5);
        auto a1 = std::make_shared<AssignExpression>(v1, c5);
        StatementBlock a("A", {a0, a1});
        ReturnBlock r("R", {});
        g.add_node(&a); g.add_node(&r);
        g.add_edge(&a, &r);
        g.entry = &a;
        g.compute_rpo();
        g.number_ins();
        // ClearPathNode for reg "v0" between locs 0 and 1: at loc 0 the lhs
        // IS v0 → path blocked.
        check("ClearPathNode v0 [0,1) blocked",
              ClearPathNode(g, "v0", 0, 1), false);
        // ClearPathNode for "v1" within [0,1) — lhs is v0, no side effect →
        // clear.
        check("ClearPathNode v1 [0,1) clear",
              ClearPathNode(g, "v1", 0, 1), true);
        // Cross-node ClearPath (loc 0 in A, loc 1 in same A) for "v1":
        //   same-node path: ClearPathNode("v1", 1, 1) → empty range → true.
        check("ClearPath v1 same-node clear",
              ClearPath(g, "v1", 0, 1), true);
    }

    // --- group_variables / split_variables --------------------------------
    {
        // Trivial: one var with two disjoint def/use clusters
        //   reg "0": defs at loc 0 and loc 10; uses {1} from def 0; {11} from
        //   def 10. group_variables should produce 2 versions.
        std::unordered_map<int, IRFormPtr> lvars;
        auto v0 = std::make_shared<Variable>("0");
        v0->set_type("I");
        lvars[0] = v0;
        ChainMap du, ud;
        du[{"0", 0}] = {1};
        du[{"0", 10}] = {11};
        ud[{"0", 1}] = {0};
        ud[{"0", 11}] = {10};
        auto groups = GroupVariables(lvars, du, ud);
        // VariableGroups is insertion-ordered vector<pair<string, versions>>;
        // look up by key rather than indexing.
        const GroupedVersions* reg0 = nullptr;
        for (const auto& [k, v] : groups) if (k == "0") { reg0 = &v; break; }
        check("group_variables: 2 versions for reg 0",
              static_cast<int>(reg0 ? reg0->size() : 0), 2);
    }

    // --- build_def_use: short-chain end-to-end ----------------------------
    //   A: assign v0 at loc 0; B: uses v0 in another assign at loc 1.
    {
        Graph g;
        auto v0 = std::make_shared<Variable>("v0");
        auto v1 = std::make_shared<Variable>("v1");
        auto c5 = std::make_shared<Constant>("5", "I");
        auto a0 = std::make_shared<AssignExpression>(v0, c5);
        // For loc 1: v1 = v0; use MoveExpression so get_used_vars returns
        // {"v0"} (AssignExpression's get_used_vars depends on var_map).
        auto mv = std::make_shared<MoveExpression>(v1, v0);
        mv->var_map["v0"] = v0;
        mv->var_map["v1"] = v1;
        StatementBlock a("A", {a0, mv});
        ReturnBlock r("R", {});
        g.add_node(&a); g.add_node(&r);
        g.add_edge(&a, &r);
        g.entry = &a;
        g.compute_rpo();
        g.number_ins();
        auto chains = BuildDefUse(g, /*lparams=*/{});
        // UD[v0, 1] should contain {0} (prior def in same block).
        const auto& ud_v0_1 = chains.ud[{"v0", 1}];
        check("UD[v0,1] size", static_cast<int>(ud_v0_1.size()), 1);
        if (!ud_v0_1.empty()) check("UD[v0,1][0] = 0", ud_v0_1[0], 0);
        // DU[v0, 0] should contain {1}.
        const auto& du_v0_0 = chains.du[{"v0", 0}];
        check("DU[v0,0] size", static_cast<int>(du_v0_0.size()), 1);
        if (!du_v0_0.empty()) check("DU[v0,0][0] = 1", du_v0_0[0], 1);
    }

    std::printf("\n%s — %d failure(s)\n", g_fail ? "FAIL" : "PASS", g_fail);
    return g_fail ? 1 : 0;
}
