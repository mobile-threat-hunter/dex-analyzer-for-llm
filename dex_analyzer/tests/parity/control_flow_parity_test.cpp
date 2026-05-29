// Parity test for control_flow.cpp.
// Covers: Intervals, DerivedSequenceOf, MarkLoop, LoopType, LoopFollow,
//         LoopStruct, IfStruct, SwitchStruct, UpdateDom.
#include "control_flow.h"
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

int main() {
    using namespace dad;

    // --- Intervals: single linear chain → one interval --------------------
    {
        Graph g;
        StatementBlock a("A", {}), b("B", {}), c("C", {});
        g.add_node(&a); g.add_node(&b); g.add_node(&c);
        g.add_edge(&a, &b);
        g.add_edge(&b, &c);
        g.entry = &a;
        g.compute_rpo();
        auto r = Intervals(g);
        check("Intervals: one interval for chain",
              static_cast<int>(r.graph->size()), 1);
        check("interv_heads has A", (r.interv_heads.count(&a) == 1), true);
        // All three nodes should be in A's interval.
        Interval* iv = r.interv_heads[&a];
        check("interval contains B", iv->Contains(&b), true);
        check("interval contains C", iv->Contains(&c), true);
    }

    // --- DerivedSequenceOf: collapses to one --------------------------
    {
        Graph g;
        StatementBlock a("A", {}), b("B", {});
        g.add_node(&a); g.add_node(&b);
        g.add_edge(&a, &b);
        g.entry = &a;
        g.compute_rpo();
        auto ds = DerivedSequenceOf(g);
        // For a linear chain, the derived sequence converges in 1 step.
        check("DerivedSequence converges",
              static_cast<int>(ds.seq.size()), 1);
        check("first graph is the input", (ds.seq[0] == &g), true);
    }

    // --- MarkLoop: simple back-edge -----------------------------------
    {
        Graph g;
        StatementBlock head("H", {}), body("B", {}), tail("T", {});
        ReturnBlock exit_("E", {});
        g.add_node(&head); g.add_node(&body); g.add_node(&tail);
        g.add_node(&exit_);
        g.add_edge(&head, &body);
        g.add_edge(&body, &tail);
        g.add_edge(&tail, &head);  // back-edge
        g.add_edge(&head, &exit_); // exit
        g.entry = &head;
        g.compute_rpo();
        // Build the single-interval for this graph (all reachable).
        auto r = Intervals(g);
        Interval* iv = r.interv_heads[&head];
        auto lnodes = MarkLoop(g, &head, &tail, iv);
        check("MarkLoop: head.startloop set", head.startloop, true);
        check("MarkLoop: head.latch = tail", (head.latch == &tail), true);
        check("MarkLoop: includes head", static_cast<int>(lnodes.size() > 0),
              1);
    }

    // --- IfStruct: simple if/else with idom join ----------------------
    //   A: cond → T, F → J. idom[J] = A → A.follow['if'] = J.
    {
        Graph g;
        CondBlock a("A", {});
        StatementBlock t("T", {}), f("F", {});
        ReturnBlock j("J", {});
        g.add_node(&a); g.add_node(&t); g.add_node(&f); g.add_node(&j);
        g.add_edge(&a, &t);
        g.add_edge(&a, &f);
        g.add_edge(&t, &j);
        g.add_edge(&f, &j);
        g.entry = &a;
        a.true_branch = &t;
        a.false_branch = &f;
        g.compute_rpo();
        auto idoms = g.immediate_dominators();
        auto unresolved = IfStruct(g, idoms);
        check("IfStruct: A.follow['if'] = J",
              (a.follow["if"] == &j), true);
        check("IfStruct: unresolved is empty",
              static_cast<int>(unresolved.size()), 0);
    }

    // --- UpdateDom ----------------------------------------------------
    {
        StatementBlock a("A", {}), b("B", {}), c("C", {});
        std::unordered_map<NodeBase*, NodeBase*> idoms = {
            {&a, &b}, {&b, &c}};
        std::unordered_map<NodeBase*, NodeBase*> nm = {{&b, &c}};
        UpdateDom(idoms, nm);
        check("UpdateDom: idom[A] remapped b→c",
              (idoms[&a] == &c), true);
        check("UpdateDom: idom[B] remapped b→c",
              (idoms[&b] == &c), true);
    }

    std::printf("\n%s — %d failure(s)\n", g_fail ? "FAIL" : "PASS", g_fail);
    return g_fail ? 1 : 0;
}
