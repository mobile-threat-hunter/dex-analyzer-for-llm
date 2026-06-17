// control_flow.cpp — DAD control_flow.py port.
// See include/control_flow.h for entity list & status.

#include <cstdio>
#include "control_flow.h"

#include <algorithm>
#include <limits>
#include <memory>
#include <utility>

namespace dexkit::dad {

// =============================================================================
// intervals — DAD control_flow.py:34
// =============================================================================
IntervalResult Intervals(Graph& graph) {
    IntervalResult result;
    result.graph = std::make_unique<Graph>();
    Graph& interval_graph = *result.graph;
    auto& interv_heads = result.interv_heads;
    auto& owned_intervals = result.intervals;

    std::vector<NodeBase*> heads;
    if (graph.entry) heads.push_back(graph.entry);
    std::unordered_map<NodeBase*, bool> processed;
    for (NodeBase* n : graph.nodes) processed[n] = false;
    std::unordered_map<Interval*, std::vector<NodeBase*>> edges;

    while (!heads.empty()) {
        NodeBase* head = heads.front();
        heads.erase(heads.begin());
        if (processed[head]) continue;
        processed[head] = true;

        auto interval_owned = std::make_unique<Interval>(head);
        Interval* interv = interval_owned.get();
        owned_intervals.push_back(std::move(interval_owned));
        interv_heads[head] = interv;

        // DAD: while change: ... add nodes whose preds all live in this interv.
        bool change = true;
        while (change) {
            change = false;
            // DAD: for node in graph.rpo[1:]
            for (size_t ri = 1; ri < graph.rpo.size(); ++ri) {
                NodeBase* node = graph.rpo[ri];
                if (interv->Contains(node)) continue;
                bool all_in = true;
                for (NodeBase* p : graph.all_preds(node)) {
                    if (!interv->Contains(p)) { all_in = false; break; }
                }
                if (all_in) change |= interv->AddNode(node);
            }
        }
        // DAD: for node in graph: collect new headers reachable from interval.
        for (NodeBase* node : graph.nodes) {
            if (interv->Contains(node)) continue;
            if (std::find(heads.begin(), heads.end(), node) != heads.end())
                continue;
            for (NodeBase* p : graph.all_preds(node)) {
                if (interv->Contains(p)) {
                    edges[interv].push_back(node);
                    heads.push_back(node);
                    break;
                }
            }
        }
        interval_graph.add_node(interv);
        interv->ComputeEnd(graph);
    }

    // DAD: for interval, heads in edges.items(): for head in heads: ...
    // DETERMINISM: `edges` is a pointer-keyed unordered_map, so iterating it
    // directly gives ASLR-dependent order — and that order seeds the interval
    // graph's edges → compute_rpo → loop detection, making loop structuring
    // non-deterministic across runs. DAD's `edges` (a Python dict) iterates in
    // INSERTION order, which here equals interval-creation order (each interval
    // appends its own edges as it is processed). Iterate owned_intervals (that
    // exact creation order) to match DAD and be reproducible.
    for (const auto& iv_ptr : owned_intervals) {
        Interval* interv = iv_ptr.get();
        auto eit = edges.find(interv);
        if (eit == edges.end()) continue;
        for (NodeBase* h : eit->second) {
            auto it = interv_heads.find(h);
            if (it != interv_heads.end()) {
                interval_graph.add_edge(interv, it->second);
            }
        }
    }

    // DAD: interval_graph.entry = graph.entry.interval
    if (graph.entry) interval_graph.entry = graph.entry->interval;
    if (graph.exit) interval_graph.exit = graph.exit->interval;
    return result;
}

// =============================================================================
// derived_sequence — DAD control_flow.py:93
// =============================================================================
DerivedSequence DerivedSequenceOf(Graph& graph) {
    DerivedSequence ds;
    ds.seq.push_back(&graph);
    Graph* current = &graph;
    bool single_node = false;
    while (!single_node) {
        IntervalResult r = Intervals(*current);
        Graph* next = r.graph.get();
        single_node = (next->size() == 1);
        if (!single_node) ds.seq.push_back(next);
        // Mutate next.rpo before stashing ownership.
        next->compute_rpo();
        ds.results.push_back(std::move(r));
        current = ds.results.back().graph.get();
    }
    return ds;
}

// =============================================================================
// mark_loop_rec / mark_loop — DAD control_flow.py:119/128
// =============================================================================
namespace {
void MarkLoopRec(Graph& graph, NodeBase* node, int s_num, int e_num,
                 Interval* interval, std::vector<NodeBase*>& nodes_in_loop) {
    if (std::find(nodes_in_loop.begin(), nodes_in_loop.end(), node) !=
        nodes_in_loop.end()) return;
    nodes_in_loop.push_back(node);
    for (NodeBase* pred : graph.all_preds(node)) {
        if (s_num < pred->num && pred->num <= e_num &&
            interval && interval->Contains(pred)) {
            MarkLoopRec(graph, pred, s_num, e_num, interval, nodes_in_loop);
        }
    }
}
}  // namespace

std::vector<NodeBase*> MarkLoop(Graph& graph, NodeBase* start, NodeBase* end,
                                Interval* interval) {
    NodeBase* head = start ? start->GetHead() : nullptr;
    NodeBase* latch = end ? end->GetEnd() : nullptr;
    std::vector<NodeBase*> nodes_in_loop;
    if (head) nodes_in_loop.push_back(head);
    if (head && latch) {
        MarkLoopRec(graph, latch, head->num, latch->num, interval,
                    nodes_in_loop);
    }
    if (auto* hn = dynamic_cast<Node*>(head)) {
        hn->startloop = true;
        hn->latch = latch;
    }
    return nodes_in_loop;
}

// =============================================================================
// loop_type — DAD control_flow.py:139
// =============================================================================
void LoopType(NodeBase* start, NodeBase* end,
              const std::vector<NodeBase*>& nodes_in_loop) {
    if (!start) return;
    auto* sb = dynamic_cast<Node*>(start);
    auto* eb = dynamic_cast<Node*>(end);
    if (!sb) return;
    auto in_loop = [&](NodeBase* n) {
        return n && std::find(nodes_in_loop.begin(), nodes_in_loop.end(), n) !=
                       nodes_in_loop.end();
    };
    // DAD checks the `.type.is_cond` FLAG, not the runtime class. This matters
    // for LoopBlock: it subclasses CondBlock (so dynamic_cast is always
    // non-null) but copy_from() copied the WRAPPED header's type — a LoopBlock
    // wrapping a StatementBlock has type.is_cond == false. Using RTTI here
    // forced every such loop to `pretest` (→ empty `while ()`); the flag
    // correctly yields `endless` (`while (true)`), matching DAD.
    auto* s_cond = dynamic_cast<CondBlock*>(start);
    const bool s_is_cond = sb->type.is_cond();
    const bool e_is_cond = eb && eb->type.is_cond();
    if (e_is_cond && eb) {
        if (s_is_cond) {
            if (in_loop(s_cond->true_branch) &&
                in_loop(s_cond->false_branch)) {
                sb->looptype.set_is_posttest(true);
            } else {
                sb->looptype.set_is_pretest(true);
            }
        } else {
            sb->looptype.set_is_posttest(true);
        }
    } else {
        if (s_is_cond) {
            if (in_loop(s_cond->true_branch) &&
                in_loop(s_cond->false_branch)) {
                sb->looptype.set_is_endless(true);
            } else {
                sb->looptype.set_is_pretest(true);
            }
        } else {
            sb->looptype.set_is_endless(true);
        }
    }
}

// =============================================================================
// loop_follow — DAD control_flow.py:158
// =============================================================================
void LoopFollow(NodeBase* start, NodeBase* end,
                const std::vector<NodeBase*>& nodes_in_loop) {
    if (!start) return;
    auto* sn = dynamic_cast<Node*>(start);
    if (!sn) return;
    auto in_loop = [&](NodeBase* n) {
        return n && std::find(nodes_in_loop.begin(), nodes_in_loop.end(), n) !=
                       nodes_in_loop.end();
    };
    NodeBase* follow = nullptr;
    auto* s_cond = dynamic_cast<CondBlock*>(start);
    auto* e_cond = dynamic_cast<CondBlock*>(end);
    if (sn->looptype.is_pretest()) {
        if (s_cond) {
            follow = in_loop(s_cond->true_branch) ? s_cond->false_branch
                                                  : s_cond->true_branch;
        }
    } else if (sn->looptype.is_posttest()) {
        if (e_cond) {
            follow = in_loop(e_cond->true_branch) ? e_cond->false_branch
                                                  : e_cond->true_branch;
        }
    } else {
        int num_next = std::numeric_limits<int>::max();
        for (NodeBase* node : nodes_in_loop) {
            auto* cb = dynamic_cast<CondBlock*>(node);
            if (!cb) continue;
            NodeBase* t = cb->true_branch;
            NodeBase* f = cb->false_branch;
            if (t && t->num < num_next && !in_loop(t)) {
                follow = t;
                num_next = follow->num;
            } else if (f && f->num < num_next && !in_loop(f)) {
                follow = f;
                num_next = follow->num;
            }
        }
    }
    sn->follow["loop"] = follow;
    for (NodeBase* n : nodes_in_loop) {
        auto* nn = dynamic_cast<Node*>(n);
        if (nn) nn->follow["loop"] = follow;
    }
}

// =============================================================================
// loop_struct — DAD control_flow.py:190
// =============================================================================
void LoopStruct(const std::vector<Graph*>& graphs_list,
                const std::vector<IntervalResult>& intervals_list) {
    if (graphs_list.empty() || intervals_list.empty()) return;
    Graph* first_graph = graphs_list[0];
    for (size_t i = 0;
         i < graphs_list.size() && i < intervals_list.size(); ++i) {
        Graph* gr = graphs_list[i];
        const auto& interv = intervals_list[i].interv_heads;
        std::vector<NodeBase*> sorted_heads;
        sorted_heads.reserve(interv.size());
        for (const auto& [head, _] : interv) sorted_heads.push_back(head);
        std::sort(sorted_heads.begin(), sorted_heads.end(),
                  [](NodeBase* a, NodeBase* b) { return a->num < b->num; });
        for (NodeBase* head : sorted_heads) {
            std::vector<NodeBase*> loop_nodes;
            for (NodeBase* p : gr->all_preds(head)) {
                if (p->interval == head->interval) {
                    auto lnodes = MarkLoop(*first_graph, head, p,
                                           head->interval);
                    for (NodeBase* ln : lnodes) {
                        if (std::find(loop_nodes.begin(), loop_nodes.end(),
                                      ln) == loop_nodes.end()) {
                            loop_nodes.push_back(ln);
                        }
                    }
                }
            }
            NodeBase* h_head = head ? head->GetHead() : nullptr;
            if (auto* hn = dynamic_cast<Node*>(h_head)) {
                hn->loop_nodes = loop_nodes;
            }
        }
    }
}

// =============================================================================
// if_struct — DAD control_flow.py:205
// =============================================================================
std::unordered_set<NodeBase*> IfStruct(
    Graph& graph,
    const std::unordered_map<NodeBase*, NodeBase*>& idoms) {
    std::unordered_set<NodeBase*> unresolved;
    for (NodeBase* node : graph.post_order()) {
        auto* cb = dynamic_cast<CondBlock*>(node);
        if (!cb || !cb->type.is_cond()) continue;
        std::vector<NodeBase*> ldominates;
        for (const auto& [n, idom] : idoms) {
            if (node == idom) {
                const auto rit = graph.reverse_edges.find(n);
                if (rit != graph.reverse_edges.end() && rit->second.size() > 1) {
                    // An if's follow is the merge point of its branches, which
                    // live in the same exception context as the cond. A node
                    // reachable only through catch handlers (in_catch) when the
                    // cond is NOT in_catch is a catch-handler tail, not a valid
                    // structured-if follow — selecting it (it often has the max
                    // num) pulls the catch body into the try region, leaving the
                    // catch variable undeclared (`Log.e(.., Object[] vN, vM)`).
                    // DAD's graph/num state never selects it; we exclude it
                    // explicitly. (When the cond itself is in_catch, an in_catch
                    // follow is legitimate, so only filter the context mismatch.)
                    auto* nn = dynamic_cast<Node*>(n);
                    if (nn && nn->in_catch && !cb->in_catch) continue;
                    ldominates.push_back(n);
                }
            }
        }
        if (!ldominates.empty()) {
            NodeBase* n = *std::max_element(
                ldominates.begin(), ldominates.end(),
                [](NodeBase* a, NodeBase* b) { return a->num < b->num; });
            cb->follow["if"] = n;
            auto snapshot = unresolved;
            for (NodeBase* x : snapshot) {
                if (node->num < x->num && x->num < n->num) {
                    auto* xb = dynamic_cast<Node*>(x);
                    if (xb) xb->follow["if"] = n;
                    unresolved.erase(x);
                }
            }
        } else {
            unresolved.insert(node);
        }
    }
    return unresolved;
}

// =============================================================================
// switch_struct — DAD control_flow.py:225
// =============================================================================
void SwitchStruct(Graph& graph,
                  const std::unordered_map<NodeBase*, NodeBase*>& idoms) {
    std::unordered_set<NodeBase*> unresolved;
    for (NodeBase* node : graph.post_order()) {
        auto* sb = dynamic_cast<SwitchBlock*>(node);
        if (!sb || !sb->type.is_switch()) continue;
        NodeBase* m = node;
        for (NodeBase* suc : graph.sucs(node)) {
            auto it = idoms.find(suc);
            if (it == idoms.end() || it->second != node) {
                m = CommonDom(idoms, node, suc);
            }
        }
        std::vector<NodeBase*> ldominates;
        for (const auto& [n, dom] : idoms) {
            if (m == dom && graph.all_preds(n).size() > 1) {
                ldominates.push_back(n);
            }
        }
        if (!ldominates.empty()) {
            NodeBase* n = *std::max_element(
                ldominates.begin(), ldominates.end(),
                [](NodeBase* a, NodeBase* b) { return a->num < b->num; });
            sb->follow["switch"] = n;
            for (NodeBase* x : unresolved) {
                auto* xn = dynamic_cast<Node*>(x);
                if (xn) xn->follow["switch"] = n;
            }
            unresolved.clear();
        } else {
            unresolved.insert(node);
        }
        // DAD: node.order_cases() — our SwitchBlock::order_cases is deferred
        // (depends on switch payload's get_values).
    }
}

// =============================================================================
// update_dom — DAD control_flow.py:406
// =============================================================================
void UpdateDom(std::unordered_map<NodeBase*, NodeBase*>& idoms,
               const std::unordered_map<NodeBase*, NodeBase*>& node_map) {
    for (auto& [n, dom] : idoms) {
        auto it = node_map.find(dom);
        if (it != node_map.end()) dom = it->second;
    }
}

// =============================================================================
// short_circuit_struct — DAD control_flow.py:249
// =============================================================================
namespace {
NodeBase* MapGet(const std::unordered_map<NodeBase*, NodeBase*>& m,
                 NodeBase* k) {
    auto it = m.find(k);
    return it == m.end() ? k : it->second;
}

// MergeNodes — fuses node1 + node2 into a new ShortCircuitBlock. DAD lines
// 250-286. Adapts both CondBlock pointers via CondBlockOperand.
NodeBase* MergeShortCircuit(Graph& graph,
                            CondBlock* node1, CondBlock* node2,
                            bool is_and, bool is_not,
                            std::unordered_map<NodeBase*, NodeBase*>& idom,
                            std::unordered_map<NodeBase*, NodeBase*>& node_map,
                            std::unordered_set<NodeBase*>& done) {
    std::unordered_set<NodeBase*> lpreds, ldests;
    for (CondBlock* node : {node1, node2}) {
        for (NodeBase* p : graph.preds(node)) lpreds.insert(p);
        for (NodeBase* s : graph.sucs(node)) ldests.insert(s);
        graph.remove_node(node);
        done.insert(node);
    }
    lpreds.erase(node1); lpreds.erase(node2);
    ldests.erase(node1); ldests.erase(node2);

    const bool entry = (graph.entry == node1 || graph.entry == node2);
    std::string new_name = node1->name + "+" + node2->name;
    auto cond1 = std::make_shared<CondBlockOperand>(node1);
    auto cond2 = std::make_shared<CondBlockOperand>(node2);
    auto condition = std::make_shared<Condition>(cond1, cond2, is_and, is_not);

    // Create new ShortCircuitBlock owned by graph.
    auto* new_node = graph.MakeNode<ShortCircuitBlock>(new_name, condition);
    for (auto& [old_n, new_n] : node_map) {
        if (new_n == node1 || new_n == node2) node_map[old_n] = new_node;
    }
    node_map[node1] = new_node;
    node_map[node2] = new_node;
    idom[new_node] = idom[node1];
    idom.erase(node1);
    idom.erase(node2);
    new_node->CopyFrom(*node1);

    // DETERMINISM: lpreds/ldests are pointer-keyed unordered_sets, so iterating
    // them to add_edge wires new_node's pred/suc vectors in ASLR-dependent order.
    // That order seeds the next post_order() the merge loop walks, which changes
    // which short-circuits merge and with what De-Morgan polarity → fully
    // non-deterministic output (DAD's Python `set` has the same flaw). Sort by
    // post-order num (ties broken by the deterministic block name) so the merge
    // sequence — and the decompiled output — is reproducible across processes.
    auto by_num = [](NodeBase* a, NodeBase* b) {
        return a->num != b->num ? a->num < b->num : a->name < b->name;
    };
    std::vector<NodeBase*> lpreds_v(lpreds.begin(), lpreds.end());
    std::vector<NodeBase*> ldests_v(ldests.begin(), ldests.end());
    std::sort(lpreds_v.begin(), lpreds_v.end(), by_num);
    std::sort(ldests_v.begin(), ldests_v.end(), by_num);
    for (NodeBase* pred : lpreds_v) {
        pred->UpdateAttributeWith(node_map);
        graph.add_edge(MapGet(node_map, pred), new_node);
    }
    for (NodeBase* dest : ldests_v) {
        graph.add_edge(new_node, MapGet(node_map, dest));
    }
    if (entry) graph.entry = new_node;
    return new_node;
}
}  // namespace

void ShortCircuitStruct(
    Graph& graph,
    std::unordered_map<NodeBase*, NodeBase*>& idom,
    std::unordered_map<NodeBase*, NodeBase*>& node_map) {
    // SAFETY CAP: the DAD-faithful outer `while (change)` loop occasionally
    // fails to reach a fixed point on real APK classes (FlowLayout.onMeasure,
    // Guideline.addToSolver, AppCompatDelegateImpl.reopenMenu — caught via
    // gdb on hung sweeps). The trigger is non-deterministic, depending on
    // unordered_map<NodeBase*, ...> iteration order between processes; some
    // orderings let MergeShortCircuit keep introducing new ShortCircuitBlocks
    // each iteration so the loop never converges. DAD Python has the same
    // structure but appears to converge in practice — likely because Python's
    // dict iteration happens to give a benign order here.
    //
    // The cap is generous (10 * original node count) — each merge removes
    // 2 nodes and adds 1, so a healthy run converges in ~N iters. Hitting
    // the cap means we're in the pathological loop; bail with a stderr
    // warning so callers can see we abandoned the pass. The graph is left
    // in a partially-merged but consistent state; downstream Writer
    // tolerates this (worst case: less pretty short-circuit collapsing).
    const size_t kMaxIters = std::max<size_t>(graph.nodes.size() * 10, 1000);
    size_t iter = 0;
    bool change = true;
    // Diagnostic: (node_count, merges_this_iter) per iter.
    std::vector<std::pair<size_t, size_t>> traj;
    traj.reserve(64);
    traj.push_back({graph.nodes.size(), 0});
    while (change) {
        if (++iter > kMaxIters) {
            std::fprintf(stderr,
                "[dexkit-dad] ShortCircuitStruct: bailing after %zu iters\n"
                "  iter | nodes | merges (first %zu samples)\n",
                iter, std::min<size_t>(traj.size(), 30));
            for (size_t i = 0; i < std::min<size_t>(traj.size(), 30); ++i) {
                std::fprintf(stderr, "  %4zu | %5zu | %zu\n",
                             i, traj[i].first, traj[i].second);
            }
            std::fprintf(stderr, "  ...\n  final node count = %zu\n",
                         graph.nodes.size());
            break;
        }
        change = false;
        size_t merges_this_iter = 0;
        std::unordered_set<NodeBase*> done;
        for (NodeBase* n : graph.post_order()) {
            auto* node = dynamic_cast<CondBlock*>(n);
            if (!node || !node->type.is_cond() || done.count(n)) continue;
            CondBlock* then_b = dynamic_cast<CondBlock*>(node->true_branch);
            CondBlock* els_b = dynamic_cast<CondBlock*>(node->false_branch);
            NodeBase* then_n = node->true_branch;
            NodeBase* els_n = node->false_branch;
            if (then_n == node || els_n == node) continue;

            if (then_b && graph.preds(then_b).size() == 1) {
                if (node == then_b->true_branch ||
                    node == then_b->false_branch) continue;
                if (then_b->false_branch == els_n) {        // node && t
                    change = true;
                    ++merges_this_iter;
                    auto* merged = dynamic_cast<CondBlock*>(
                        MergeShortCircuit(graph, node, then_b, true, false,
                                          idom, node_map, done));
                    merged->true_branch = then_b->true_branch;
                    merged->false_branch = els_n;
                } else if (then_b->true_branch == els_n) {  // !node || t
                    change = true;
                    ++merges_this_iter;
                    auto* merged = dynamic_cast<CondBlock*>(
                        MergeShortCircuit(graph, node, then_b, false, true,
                                          idom, node_map, done));
                    merged->true_branch = els_n;
                    merged->false_branch = then_b->false_branch;
                }
            } else if (els_b && graph.preds(els_b).size() == 1) {
                if (node == els_b->false_branch ||
                    node == els_b->true_branch) continue;
                if (els_b->false_branch == then_n) {        // !node && e
                    change = true;
                    ++merges_this_iter;
                    auto* merged = dynamic_cast<CondBlock*>(
                        MergeShortCircuit(graph, node, els_b, true, true,
                                          idom, node_map, done));
                    merged->true_branch = els_b->true_branch;
                    merged->false_branch = then_n;
                } else if (els_b->true_branch == then_n) {  // node || e
                    change = true;
                    ++merges_this_iter;
                    auto* merged = dynamic_cast<CondBlock*>(
                        MergeShortCircuit(graph, node, els_b, false, false,
                                          idom, node_map, done));
                    merged->true_branch = then_n;
                    merged->false_branch = els_b->false_branch;
                }
            }
            done.insert(n);
        }
        if (change) graph.compute_rpo();
        traj.push_back({graph.nodes.size(), merges_this_iter});
    }
}

// =============================================================================
// while_block_struct — DAD control_flow.py:329
// =============================================================================
void WhileBlockStruct(Graph& graph,
                      std::unordered_map<NodeBase*, NodeBase*>& node_map) {
    bool change = false;
    std::vector<NodeBase*> snapshot = graph.rpo;
    for (NodeBase* n : snapshot) {
        auto* nn = dynamic_cast<Node*>(n);
        if (!nn || !nn->startloop) continue;
        // DAD: LoopBlock(node.name, node) wraps the loop header REGARDLESS of
        // type. A header that SplitIfNodes turned into a plain StatementBlock
        // (the common endless-loop case) must still be wrapped; passing the
        // generic BasicBlock* (not a CondBlock* that dynamic_cast's to null)
        // keeps the body reachable. cond_block is derived inside the ctor.
        auto* bb = dynamic_cast<BasicBlock*>(n);
        change = true;
        auto* new_node = graph.MakeNode<LoopBlock>(nn->name, bb);
        node_map[n] = new_node;
        new_node->CopyFrom(*nn);

        const bool entry = (n == graph.entry);
        auto lpreds = graph.preds(n);
        auto lsuccs = graph.sucs(n);
        for (NodeBase* p : lpreds) {
            graph.add_edge(MapGet(node_map, p), new_node);
        }
        for (NodeBase* s : lsuccs) {
            graph.add_edge(new_node, MapGet(node_map, s));
        }
        if (entry) graph.entry = new_node;
        // DAD: if node.type.is_cond: new_node.true = node.true; .false = .false
        if (auto* cb = dynamic_cast<CondBlock*>(n); cb && cb->type.is_cond()) {
            new_node->true_branch = cb->true_branch;
            new_node->false_branch = cb->false_branch;
        }
        graph.remove_node(n);
        // The LoopBlock wraps `n` as its cond_node; the Writer emits the do-while
        // / endless BODY via visit_node(loop.cond) (== n) and follows n's OWN
        // successors (EmitStatement → graph.sucs(n)). DAD relies on remove_node
        // leaving those stale edges intact; our remove_node erases them (the
        // ShortCircuit hang fix), which truncates the loop body at the header's
        // own ins and leaves body-local vars undeclared (e.g. `} while (int v3 >=
        // T[] v2.length)`). Restore n's FORWARD successor edges so the body walk
        // continues. Safe: n is out of graph.nodes/rpo, so later passes ignore it;
        // only the Writer's forward `sucs(n)` walk reads these.
        //
        // ONE-WAY (edges[n] only, NOT reverse_edges[suc]): this mirrors DAD's
        // remove_node, which leaves edges[node] populated while the reverse side
        // was already cleaned. One-way is REQUIRED for nested loops: a two-way
        // add_edge would re-insert `n` into reverse_edges[suc], so when the INNER
        // loop header (== suc) is later wrapped and remove_node'd, its pred-walk
        // (`for pred in reverse_edges[suc]: edges[pred].remove(suc)`) would erase
        // this restored edge — truncating the OUTER loop body to just the
        // header's own instructions (e.g. gson JsonReader.skipQuotedValue lost
        // its whole `if (v1_0 >= v2) {...}` chain). Adding only to edges[n] keeps
        // the stale edge invisible to those pred-walks, exactly like DAD.
        for (NodeBase* s : lsuccs) {
            NodeBase* ms = MapGet(node_map, s);
            auto& es = graph.edges[n];
            if (std::find(es.begin(), es.end(), ms) == es.end()) {
                es.push_back(ms);
            }
        }
    }
    if (change) graph.compute_rpo();
}

// =============================================================================
// catch_struct — DAD control_flow.py:361
// =============================================================================
void CatchStruct(Graph& graph,
                 const std::unordered_map<NodeBase*, NodeBase*>& idoms) {
    std::unordered_map<NodeBase*, TryBlock*> block_try_nodes;
    std::unordered_map<NodeBase*, NodeBase*> node_map;

    // DAD iterates reverse_catch_edges — every block that is a catch target.
    // We iterate the keys (a copy, since we mutate graph).
    std::vector<NodeBase*> catch_keys;
    for (const auto& [k, _] : graph.reverse_catch_edges) catch_keys.push_back(k);
    // DETERMINISM: reverse_catch_edges is a pointer-keyed unordered_map, so the
    // collection order above is ASLR-dependent (pointer hash) — DAD iterates a
    // Python dict in insertion order, deterministically. Sort by post-order num
    // (stable, ASLR-independent) so the try/catch structuring is reproducible.
    std::sort(catch_keys.begin(), catch_keys.end(),
              [](NodeBase* a, NodeBase* b) { return a->num < b->num; });

    for (NodeBase* catch_block : catch_keys) {
        // Skip if this block itself has outgoing catch edges (handler of an
        // inner try) — DAD: `if catch_block in graph.catch_edges: continue`.
        if (graph.catch_edges.find(catch_block) != graph.catch_edges.end()) {
            continue;
        }
        auto* cbb = dynamic_cast<BasicBlock*>(catch_block);
        if (!cbb) continue;
        auto catch_node = std::make_unique<CatchBlock>(*cbb);
        CatchBlock* catch_raw = catch_node.get();
        graph.owned_nodes_.push_back(std::move(catch_node));
        graph.add_node(catch_raw);

        // idom of the catch block is the try block in DAD.
        auto idom_it = idoms.find(catch_block);
        if (idom_it == idoms.end()) continue;
        NodeBase* try_block = idom_it->second;
        if (!try_block) continue;

        auto try_it = block_try_nodes.find(try_block);
        TryBlock* try_node = (try_it == block_try_nodes.end())
                              ? nullptr : try_it->second;
        if (try_node == nullptr) {
            try_node = graph.MakeNode<TryBlock>(try_block);
            block_try_nodes[try_block] = try_node;

            node_map[try_block] = try_node;
            for (NodeBase* p : graph.all_preds(try_block)) {
                p->UpdateAttributeWith(node_map);
                // Remove direct edge p → try_block (DAD: graph.edges[pred].remove)
                const auto pred_sucs = graph.sucs(p);
                if (std::find(pred_sucs.begin(), pred_sucs.end(),
                              try_block) != pred_sucs.end()) {
                    auto& edges = graph.edges[p];
                    edges.erase(std::remove(edges.begin(), edges.end(),
                                            try_block), edges.end());
                }
                graph.add_edge(p, try_node);
            }

            auto* try_basic = dynamic_cast<BasicBlock*>(try_block);
            auto* try_n = dynamic_cast<Node*>(try_block);
            if (try_basic && try_basic->type.is_stmt()) {
                auto follow = graph.sucs(try_block);
                try_node->try_follow = follow.empty() ? nullptr : follow[0];
            } else if (try_basic && try_basic->type.is_cond() && try_n) {
                auto loop_it = try_n->follow.find("loop");
                NodeBase* loop_follow =
                    loop_it == try_n->follow.end() ? nullptr : loop_it->second;
                if (loop_follow) {
                    try_node->try_follow = loop_follow;
                } else {
                    auto if_it = try_n->follow.find("if");
                    try_node->try_follow =
                        if_it == try_n->follow.end() ? nullptr : if_it->second;
                }
            } else if (try_basic && try_basic->type.is_switch() && try_n) {
                auto sw_it = try_n->follow.find("switch");
                try_node->try_follow =
                    sw_it == try_n->follow.end() ? nullptr : sw_it->second;
            } else {
                try_node->try_follow = nullptr;  // return / throw
            }
        }
        try_node->add_catch_node(catch_raw);
    }
    for (NodeBase* n : graph.nodes) {
        n->UpdateAttributeWith(node_map);
    }
    auto it = node_map.find(graph.entry);
    if (it != node_map.end()) graph.entry = it->second;
}

// =============================================================================
// identify_structures — DAD control_flow.py:411 (top-level driver)
// =============================================================================
void IdentifyStructures(Graph& graph,
                        std::unordered_map<NodeBase*, NodeBase*>& idoms) {
    auto ds = DerivedSequenceOf(graph);
    SwitchStruct(graph, idoms);
    LoopStruct(ds.seq, ds.results);
    std::unordered_map<NodeBase*, NodeBase*> node_map;

    ShortCircuitStruct(graph, idoms, node_map);
    UpdateDom(idoms, node_map);

    auto if_unresolved = IfStruct(graph, idoms);

    WhileBlockStruct(graph, node_map);
    UpdateDom(idoms, node_map);

    std::vector<NodeBase*> loop_starts;
    for (NodeBase* n : graph.rpo) {
        n->UpdateAttributeWith(node_map);
        auto* nn = dynamic_cast<Node*>(n);
        if (nn && nn->startloop) loop_starts.push_back(n);
    }
    for (NodeBase* n : loop_starts) {
        auto* nn = dynamic_cast<Node*>(n);
        if (nn) {
            LoopType(n, nn->latch, nn->loop_nodes);
            LoopFollow(n, nn->latch, nn->loop_nodes);
        }
    }

    for (NodeBase* n : if_unresolved) {
        auto* nn = dynamic_cast<Node*>(n);
        if (!nn) continue;
        std::vector<NodeBase*> follows;
        auto loop_it = nn->follow.find("loop");
        if (loop_it != nn->follow.end() && loop_it->second)
            follows.push_back(loop_it->second);
        auto sw_it = nn->follow.find("switch");
        if (sw_it != nn->follow.end() && sw_it->second)
            follows.push_back(sw_it->second);
        if (!follows.empty()) {
            NodeBase* follow = *std::min_element(
                follows.begin(), follows.end(),
                [](NodeBase* a, NodeBase* b) { return a->num < b->num; });
            nn->follow["if"] = follow;
        }
    }

    CatchStruct(graph, idoms);
}

}  // namespace dexkit::dad
