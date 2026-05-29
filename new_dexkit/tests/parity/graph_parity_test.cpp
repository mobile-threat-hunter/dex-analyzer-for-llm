// Parity test for graph.cpp.
// Covers: Graph (sucs/all_sucs/preds/all_preds, add/remove edges/nodes,
//                number_ins, compute_rpo, post_order), Simplify, DomLt,
//                GenInvokeRetName. SplitIfNodes is deferred (needs
//                node-ownership model).
#include "graph.h"
#include "basic_blocks.h"
#include "instruction.h"
#include <cstdio>
#include <memory>
#include <string>
#include <unordered_set>

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

    // --- Graph: basic add_node / add_edge / sucs / preds -----------------
    {
        Graph g;
        StatementBlock a("A", {}), b("B", {}), c("C", {});
        g.add_node(&a); g.add_node(&b); g.add_node(&c);
        g.add_edge(&a, &b);
        g.add_edge(&a, &c);
        g.add_edge(&b, &c);
        check("g.size()", static_cast<int>(g.size()), 3);
        check("sucs(A) size", static_cast<int>(g.sucs(&a).size()), 2);
        check("sucs(B) size", static_cast<int>(g.sucs(&b).size()), 1);
        check("preds(C) size", static_cast<int>(g.preds(&c).size()), 2);
        check("all_sucs(A) size", static_cast<int>(g.all_sucs(&a).size()), 2);
        // Duplicate add_edge — set semantics.
        g.add_edge(&a, &b);
        check("add_edge dedup", static_cast<int>(g.sucs(&a).size()), 2);
    }

    // --- Graph: add_catch_edge propagates catch_type ---------------------
    {
        Graph g;
        StatementBlock t("T", {}), c1("C1", {});
        t.catch_type = "Ljava/lang/Throwable;";
        g.add_node(&t); g.add_node(&c1);
        g.add_catch_edge(&t, &c1);
        check_str("add_catch_edge propagates type", c1.catch_type,
                  "Ljava/lang/Throwable;");
        check("catch_edges sucs", static_cast<int>(g.all_sucs(&t).size()), 1);
        check("all_preds size", static_cast<int>(g.all_preds(&c1).size()), 1);
    }

    // --- Graph: remove_node cleans all edge tables -----------------------
    {
        Graph g;
        StatementBlock a("A", {}), b("B", {}), c("C", {});
        g.add_node(&a); g.add_node(&b); g.add_node(&c);
        g.add_edge(&a, &b);
        g.add_edge(&b, &c);
        g.add_catch_edge(&a, &c);
        g.remove_node(&b);
        check("remove_node: nodes size", static_cast<int>(g.size()), 2);
        check("remove_node: sucs(A) trimmed",
              static_cast<int>(g.sucs(&a).size()), 0);
        check("remove_node: preds(C) trimmed",
              static_cast<int>(g.preds(&c).size()), 0);
        // catch_edge from A→C should remain.
        check("remove_node: catch edge A→C kept",
              static_cast<int>(g.all_sucs(&a).size()), 1);
    }

    // --- Graph: compute_rpo / post_order / number_ins --------------------
    //   Linear chain: A → B → C → D (return)
    {
        Graph g;
        auto v0 = std::make_shared<Variable>("v0");
        StatementBlock a("A", {v0}), b("B", {v0}), c("C", {v0});
        ReturnBlock d("D", {v0});
        g.add_node(&a); g.add_node(&b); g.add_node(&c); g.add_node(&d);
        g.add_edge(&a, &b);
        g.add_edge(&b, &c);
        g.add_edge(&c, &d);
        g.entry = &a;
        g.compute_rpo();
        // RPO of a chain A→B→C→D: nums should be 1,2,3,4.
        check("RPO A.num", a.num, 1);
        check("RPO B.num", b.num, 2);
        check("RPO C.num", c.num, 3);
        check("RPO D.num", d.num, 4);
        check("rpo[0] is A", (g.rpo[0] == &a), true);
        check("rpo[3] is D", (g.rpo[3] == &d), true);

        g.number_ins();
        check("number_ins: A ins_range [0,1)", a.ins_range_lo, 0);
        check("number_ins: B ins_range [1,2)", b.ins_range_lo, 1);
        check("get_ins_from_loc(2) = C's ins", (g.get_ins_from_loc(2) == v0),
              true);
        check("get_node_from_loc(2) = C", (g.get_node_from_loc(2) == &c),
              true);
    }

    // --- Simplify: merge empty stmt into successor ------------------------
    //   Chain: A → EMPTY → B (return). EMPTY should be dropped, A → B.
    {
        Graph g;
        auto v0 = std::make_shared<Variable>("v0");
        StatementBlock a("A", {v0});
        StatementBlock empty("E", {});   // empty stmt
        ReturnBlock b("B", {v0});
        g.add_node(&a); g.add_node(&empty); g.add_node(&b);
        g.add_edge(&a, &empty);
        g.add_edge(&empty, &b);
        g.entry = &a;

        Simplify(g);

        check("Simplify drops empty node", static_cast<int>(g.size()), 2);
        check("Simplify reroutes A→B", (g.sucs(&a).size() == 1 &&
                                         g.sucs(&a)[0] == &b),
              true);
    }

    // --- Simplify: merge consecutive stmt nodes --------------------------
    //   Chain: A(ins=[v0]) → B(ins=[v1]) → R. B has only A as pred and
    //   isn't an entry/catch target — should merge into A.
    {
        Graph g;
        auto v0 = std::make_shared<Variable>("v0");
        auto v1 = std::make_shared<Variable>("v1");
        StatementBlock a("A", {v0});
        StatementBlock b("B", {v1});
        ReturnBlock r("R", {});
        g.add_node(&a); g.add_node(&b); g.add_node(&r);
        g.add_edge(&a, &b);
        g.add_edge(&b, &r);
        g.entry = &a;

        Simplify(g);

        check("Simplify merges B into A", static_cast<int>(g.size()), 2);
        check("A.ins size after merge",
              static_cast<int>(a.get_ins().size()), 2);
        // After merge: A → R direct.
        check("A → R direct after merge",
              (g.sucs(&a).size() == 1 && g.sucs(&a)[0] == &r), true);
    }

    // --- DomLt: trivial single-node ---------------------------------------
    {
        Graph g;
        StatementBlock a("A", {});
        g.add_node(&a);
        g.entry = &a;
        auto dom = DomLt(g);
        check("DomLt single-node: entry → null",
              (dom[&a] == nullptr), true);
    }

    // --- DomLt: chain A → B → C → D ---------------------------------------
    {
        Graph g;
        StatementBlock a("A", {}), b("B", {}), c("C", {}), d("D", {});
        g.add_node(&a); g.add_node(&b); g.add_node(&c); g.add_node(&d);
        g.add_edge(&a, &b);
        g.add_edge(&b, &c);
        g.add_edge(&c, &d);
        g.entry = &a;
        auto dom = DomLt(g);
        check("dom[A] = null (entry)", (dom[&a] == nullptr), true);
        check("dom[B] = A", (dom[&b] == &a), true);
        check("dom[C] = B", (dom[&c] == &b), true);
        check("dom[D] = C", (dom[&d] == &c), true);
    }

    // --- DomLt: diamond  A → B,C ; B → D ; C → D --------------------------
    {
        Graph g;
        StatementBlock a("A", {}), b("B", {}), c("C", {}), d("D", {});
        g.add_node(&a); g.add_node(&b); g.add_node(&c); g.add_node(&d);
        g.add_edge(&a, &b);
        g.add_edge(&a, &c);
        g.add_edge(&b, &d);
        g.add_edge(&c, &d);
        g.entry = &a;
        auto dom = DomLt(g);
        check("diamond: dom[A] = null", (dom[&a] == nullptr), true);
        check("diamond: dom[B] = A", (dom[&b] == &a), true);
        check("diamond: dom[C] = A", (dom[&c] == &a), true);
        check("diamond: dom[D] = A (join)", (dom[&d] == &a), true);
    }

    // --- GenInvokeRetName -------------------------------------------------
    {
        GenInvokeRetName g;
        auto r1 = g.New();
        check("New() returns non-null", (r1 != nullptr), true);
        check_str("New() name = tmp1", r1->ToString(), "VAR_tmp1");
        auto r2 = g.New();
        check_str("Second New() = tmp2", r2->ToString(), "VAR_tmp2");
        check_str("Last() returns most-recent", g.Last()->ToString(),
                  "VAR_tmp2");
        auto custom = std::make_shared<Variable>("custom");
        g.SetTo(custom);
        check_str("SetTo pins ret", g.Last()->ToString(), "VAR_custom");
        check("num counter = 2", g.num(), 2);
    }

    std::printf("\n%s — %d failure(s)\n", g_fail ? "FAIL" : "PASS", g_fail);
    return g_fail ? 1 : 0;
}
