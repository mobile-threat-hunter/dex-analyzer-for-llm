// graph.cpp — DAD graph.py port.
// See include/graph.h for entity list & status.

#include "graph.h"

#include <algorithm>
#include <cstdio>
#include <limits>
#include <memory>
#include <string>
#include <utility>

#include "method_snapshot.h"

namespace dexkit::dad {

namespace {

// Erase first matching element from a vector (mirrors Python list.remove).
template <typename T>
void EraseFirst(std::vector<T>& v, const T& val) {
    auto it = std::find(v.begin(), v.end(), val);
    if (it != v.end()) v.erase(it);
}

// Return the vector for a node from a defaultdict-like map (empty if absent).
const std::vector<NodeBase*>& GetOrEmpty(
    const std::unordered_map<NodeBase*, std::vector<NodeBase*>>& m,
    NodeBase* k) {
    static const std::vector<NodeBase*> kEmpty;
    auto it = m.find(k);
    return it == m.end() ? kEmpty : it->second;
}

}  // namespace

// =============================================================================
// Graph
// =============================================================================

// DAD: graph.py:51 sucs.
std::vector<NodeBase*> Graph::sucs(NodeBase* node) const {
    return GetOrEmpty(edges, node);
}

// DAD: graph.py:54 all_sucs.
std::vector<NodeBase*> Graph::all_sucs(NodeBase* node) const {
    const auto& a = GetOrEmpty(edges, node);
    const auto& b = GetOrEmpty(catch_edges, node);
    std::vector<NodeBase*> out;
    out.reserve(a.size() + b.size());
    out.insert(out.end(), a.begin(), a.end());
    out.insert(out.end(), b.begin(), b.end());
    return out;
}

// DAD: graph.py:57 preds — filter out in_catch.
std::vector<NodeBase*> Graph::preds(NodeBase* node) const {
    const auto& src = GetOrEmpty(reverse_edges, node);
    std::vector<NodeBase*> out;
    out.reserve(src.size());
    for (NodeBase* n : src) {
        if (!n->in_catch) out.push_back(n);
    }
    return out;
}

// DAD: graph.py:60 all_preds.
std::vector<NodeBase*> Graph::all_preds(NodeBase* node) const {
    const auto& a = GetOrEmpty(reverse_edges, node);
    const auto& b = GetOrEmpty(reverse_catch_edges, node);
    std::vector<NodeBase*> out;
    out.reserve(a.size() + b.size());
    out.insert(out.end(), a.begin(), a.end());
    out.insert(out.end(), b.begin(), b.end());
    return out;
}

// DAD: graph.py:65 add_node.
void Graph::add_node(NodeBase* node) {
    nodes.push_back(node);
}

// DAD: graph.py:73 add_edge.
void Graph::add_edge(NodeBase* e1, NodeBase* e2) {
    auto& lsucs = edges[e1];
    if (std::find(lsucs.begin(), lsucs.end(), e2) == lsucs.end()) {
        lsucs.push_back(e2);
    }
    auto& lpreds = reverse_edges[e2];
    if (std::find(lpreds.begin(), lpreds.end(), e1) == lpreds.end()) {
        lpreds.push_back(e1);
    }
}

// DAD: graph.py:81 add_catch_edge.
void Graph::add_catch_edge(NodeBase* e1, NodeBase* e2) {
    // DAD: active_type = e1.catch_type or e2.catch_type
    //      e1.set_catch_type(active_type); e2.set_catch_type(active_type)
    auto* b1 = dynamic_cast<BasicBlock*>(e1);
    auto* b2 = dynamic_cast<BasicBlock*>(e2);
    if (b1 && b2) {
        std::string active_type =
            !b1->catch_type.empty() ? b1->catch_type : b2->catch_type;
        b1->set_catch_type(active_type);
        b2->set_catch_type(active_type);
    }
    auto& lsucs = catch_edges[e1];
    if (std::find(lsucs.begin(), lsucs.end(), e2) == lsucs.end()) {
        lsucs.push_back(e2);
    }
    auto& lpreds = reverse_catch_edges[e2];
    if (std::find(lpreds.begin(), lpreds.end(), e1) == lpreds.end()) {
        lpreds.push_back(e1);
    }
}

// DAD: graph.py:93 remove_node.
void Graph::remove_node(NodeBase* node) {
    // DAD: preds = self.reverse_edges.get(node, [])
    //      for pred in preds: self.edges[pred].remove(node)
    if (auto it = reverse_edges.find(node); it != reverse_edges.end()) {
        for (NodeBase* pred : it->second) {
            auto pit = edges.find(pred);
            if (pit != edges.end()) EraseFirst(pit->second, node);
        }
    }
    // DAD: succs = self.edges.get(node, [])
    //      for suc in succs: self.reverse_edges[suc].remove(node)
    if (auto it = edges.find(node); it != edges.end()) {
        for (NodeBase* suc : it->second) {
            auto sit = reverse_edges.find(suc);
            if (sit != reverse_edges.end()) EraseFirst(sit->second, node);
        }
    }
    // DAD: exc_preds = self.reverse_catch_edges.pop(node, [])
    //      for pred in exc_preds: self.catch_edges[pred].remove(node)
    if (auto it = reverse_catch_edges.find(node);
        it != reverse_catch_edges.end()) {
        auto exc_preds = std::move(it->second);
        reverse_catch_edges.erase(it);
        for (NodeBase* pred : exc_preds) {
            auto pit = catch_edges.find(pred);
            if (pit != catch_edges.end()) EraseFirst(pit->second, node);
        }
    }
    // DAD: exc_succs = self.catch_edges.pop(node, [])
    //      for suc in exc_succs: self.reverse_catch_edges[suc].remove(node)
    if (auto it = catch_edges.find(node); it != catch_edges.end()) {
        auto exc_succs = std::move(it->second);
        catch_edges.erase(it);
        for (NodeBase* suc : exc_succs) {
            auto sit = reverse_catch_edges.find(suc);
            if (sit != reverse_catch_edges.end()) EraseFirst(sit->second, node);
        }
    }
    // DAD: self.nodes.remove(node)
    EraseFirst(nodes, node);
    // DAD: if node in self.rpo: self.rpo.remove(node)
    EraseFirst(rpo, node);
    // DAD: del node — Python no-op for shared refs; we don't own storage.
}

// DAD: graph.py:120 number_ins.
void Graph::number_ins() {
    has_loc_indexes = true;
    loc_to_ins.clear();
    loc_to_node.clear();
    int num = 0;
    for (NodeBase* node : rpo) {
        auto* bb = dynamic_cast<BasicBlock*>(node);
        if (!bb) continue;
        const int start_node = num;
        num = bb->number_ins(num);
        const int end_node = num - 1;
        for (const auto& [loc, ins] : bb->get_loc_with_ins()) {
            loc_to_ins[loc] = ins;
        }
        loc_to_node.push_back({start_node, end_node, node});
    }
}

// DAD: graph.py:131 get_ins_from_loc.
IRFormPtr Graph::get_ins_from_loc(int loc) const {
    auto it = loc_to_ins.find(loc);
    return it == loc_to_ins.end() ? IRFormPtr{} : it->second;
}

// DAD: graph.py:134 get_node_from_loc.
NodeBase* Graph::get_node_from_loc(int loc) const {
    for (const auto& r : loc_to_node) {
        if (r.start <= loc && loc <= r.end) return r.node;
    }
    return nullptr;
}

// DAD: graph.py:139 remove_ins.
void Graph::remove_ins(int loc) {
    IRFormPtr ins = get_ins_from_loc(loc);
    NodeBase* node = get_node_from_loc(loc);
    if (node) {
        if (auto* bb = dynamic_cast<BasicBlock*>(node)) {
            bb->remove_ins(loc, ins);
        }
    }
    loc_to_ins.erase(loc);
}

// DAD: graph.py:155 post_order — iterative (Python recursion limit on large
// CFGs is a known DAD pain point; iterative form is safer in C++).
std::vector<NodeBase*> Graph::post_order() {
    std::vector<NodeBase*> out;
    if (!entry) return out;
    struct Frame { NodeBase* n; std::vector<NodeBase*> sucs; size_t i; };
    std::vector<Frame> stack;
    std::unordered_set<NodeBase*> visited;
    visited.insert(entry);
    stack.push_back({entry, all_sucs(entry), 0});
    int cnt = 1;
    while (!stack.empty()) {
        auto& top = stack.back();
        bool descended = false;
        while (top.i < top.sucs.size()) {
            NodeBase* suc = top.sucs[top.i++];
            if (visited.insert(suc).second) {
                stack.push_back({suc, all_sucs(suc), 0});
                descended = true;
                break;
            }
        }
        if (!descended) {
            // DAD: n.po = cnt; yield cnt + 1, n
            top.n->po = cnt;
            out.push_back(top.n);
            ++cnt;
            stack.pop_back();
        }
    }
    return out;
}

// DAD: graph.py:144 compute_rpo.
void Graph::compute_rpo() {
    // DAD: nb = len(self.nodes) + 1
    const int nb = static_cast<int>(nodes.size()) + 1;
    auto po_seq = post_order();
    for (NodeBase* n : po_seq) {
        n->num = nb - n->po;
    }
    // DAD: self.rpo = sorted(self.nodes, key=lambda n: n.num)
    rpo = nodes;
    std::sort(rpo.begin(), rpo.end(),
              [](NodeBase* a, NodeBase* b) { return a->num < b->num; });
}

// DAD: graph.py:214 immediate_dominators.
std::unordered_map<NodeBase*, NodeBase*> Graph::immediate_dominators() {
    return DomLt(*this);
}

// =============================================================================
// SplitIfNodes — DAD graph.py:228
// =============================================================================
namespace {
NodeBase* SnapshotMapGet(
    const std::unordered_map<NodeBase*, NodeBase*>& m, NodeBase* k) {
    auto it = m.find(k);
    return it == m.end() ? k : it->second;
}
}  // namespace

void SplitIfNodes(Graph& graph) {
    std::unordered_map<NodeBase*, NodeBase*> node_map;
    for (NodeBase* n : graph.nodes) node_map[n] = n;
    std::unordered_set<NodeBase*> to_update;
    std::vector<NodeBase*> snapshot = graph.nodes;

    for (NodeBase* node : snapshot) {
        auto* cb = dynamic_cast<CondBlock*>(node);
        if (!cb || !cb->type.is_cond()) {
            to_update.insert(node);
            continue;
        }
        if (cb->get_ins().size() <= 1) continue;

        std::vector<IRFormPtr> pre_ins(
            cb->get_ins().begin(), cb->get_ins().end() - 1);
        IRFormPtr last_ins = cb->get_ins().back();
        auto* pre_node = graph.MakeNode<StatementBlock>(
            cb->name + "-pre", std::move(pre_ins));
        auto* cond_node = graph.MakeNode<CondBlock>(
            cb->name + "-cond", std::vector<IRFormPtr>{last_ins});

        node_map[node] = pre_node;
        node_map[pre_node] = pre_node;
        node_map[cond_node] = cond_node;

        pre_node->CopyFrom(*cb);
        cond_node->CopyFrom(*cb);
        for (const auto& var : cb->var_to_declare) {
            pre_node->add_variable_declaration(var);
        }
        pre_node->type.set_is_stmt(true);
        cond_node->true_branch = cb->true_branch;
        cond_node->false_branch = cb->false_branch;

        for (NodeBase* pred : graph.all_preds(node)) {
            NodeBase* pred_node = SnapshotMapGet(node_map, pred);
            const auto pred_sucs = graph.sucs(pred);
            const bool node_in_sucs =
                std::find(pred_sucs.begin(), pred_sucs.end(), node) !=
                pred_sucs.end();
            if (!node_in_sucs) {
                graph.add_catch_edge(pred_node, pre_node);
                continue;
            }
            if (pred == node) pred_node = cond_node;
            auto* pred_cb = dynamic_cast<CondBlock*>(pred);
            if (pred_cb && pred_cb->type.is_cond()) {
                auto* pn_cb = dynamic_cast<CondBlock*>(pred_node);
                if (pn_cb) {
                    if (pred_cb->true_branch == node) pn_cb->true_branch = pre_node;
                    if (pred_cb->false_branch == node) pn_cb->false_branch = pre_node;
                }
            }
            graph.add_edge(pred_node, pre_node);
        }
        for (NodeBase* suc : graph.sucs(node)) {
            graph.add_edge(cond_node, SnapshotMapGet(node_map, suc));
        }
        auto it = graph.catch_edges.find(node);
        if (it != graph.catch_edges.end()) {
            for (NodeBase* suc : it->second) {
                graph.add_catch_edge(pre_node, SnapshotMapGet(node_map, suc));
            }
        }
        if (node == graph.entry) graph.entry = pre_node;

        graph.add_edge(pre_node, cond_node);
        pre_node->UpdateAttributeWith(node_map);
        cond_node->UpdateAttributeWith(node_map);
        graph.remove_node(node);
    }
    for (NodeBase* n : to_update) {
        n->UpdateAttributeWith(node_map);
    }
}

// =============================================================================
// Simplify — DAD graph.py:291
// =============================================================================
void Simplify(Graph& graph) {
    bool redo = true;
    while (redo) {
        redo = false;
        std::unordered_map<NodeBase*, NodeBase*> node_map;
        std::unordered_set<NodeBase*> to_update;
        std::vector<NodeBase*> snapshot = graph.nodes;
        auto in_graph = [&](NodeBase* n) {
            return std::find(graph.nodes.begin(), graph.nodes.end(), n) !=
                   graph.nodes.end();
        };
        for (NodeBase* node : snapshot) {
            auto* bb = dynamic_cast<BasicBlock*>(node);
            if (bb && bb->type.is_stmt() && in_graph(node)) {
                auto sucs = graph.all_sucs(node);
                if (sucs.size() != 1) continue;
                NodeBase* suc = sucs[0];
                if (bb->get_ins().empty()) {
                    // DAD: if any(pred.type.is_switch for pred in
                    //               graph.all_preds(node)): continue
                    bool any_switch = false;
                    for (NodeBase* p : graph.all_preds(node)) {
                        auto* pb = dynamic_cast<BasicBlock*>(p);
                        if (pb && pb->type.is_switch()) {
                            any_switch = true;
                            break;
                        }
                    }
                    if (any_switch) continue;
                    if (node == suc) continue;
                    node_map[node] = suc;
                    for (NodeBase* pred : graph.all_preds(node)) {
                        pred->UpdateAttributeWith(node_map);
                        const auto pred_sucs = graph.sucs(pred);
                        const bool node_in_pred_sucs =
                            std::find(pred_sucs.begin(), pred_sucs.end(),
                                      node) != pred_sucs.end();
                        if (!node_in_pred_sucs) {
                            graph.add_catch_edge(pred, suc);
                            continue;
                        }
                        graph.add_edge(pred, suc);
                    }
                    redo = true;
                    if (node == graph.entry) graph.entry = suc;
                    graph.remove_node(node);
                } else {
                    auto* sb = dynamic_cast<BasicBlock*>(suc);
                    const bool can_merge =
                        sb && sb->type.is_stmt() &&
                        graph.all_preds(suc).size() == 1 &&
                        graph.catch_edges.find(suc) ==
                            graph.catch_edges.end() &&
                        node != suc && suc != graph.entry;
                    if (can_merge) {
                        const auto ins_to_merge = sb->get_ins();
                        bb->add_ins(ins_to_merge);
                        for (const auto& var : sb->var_to_declare) {
                            bb->add_variable_declaration(var);
                        }
                        const auto new_sucs = graph.sucs(suc);
                        if (!new_sucs.empty() && new_sucs[0]) {
                            graph.add_edge(node, new_sucs[0]);
                        }
                        auto it = graph.catch_edges.find(suc);
                        if (it != graph.catch_edges.end()) {
                            const auto exc_succs = it->second;
                            for (NodeBase* es : exc_succs) {
                                graph.add_catch_edge(node, es);
                            }
                        }
                        redo = true;
                        graph.remove_node(suc);
                    }
                }
            } else {
                to_update.insert(node);
            }
        }
        for (NodeBase* n : to_update) {
            n->UpdateAttributeWith(node_map);
        }
    }
}

// =============================================================================
// DomLt — DAD graph.py:352  Lengauer-Tarjan immediate dominators
// =============================================================================
std::unordered_map<NodeBase*, NodeBase*> DomLt(Graph& graph) {
    std::unordered_map<NodeBase*, int> semi;
    std::unordered_map<int, NodeBase*> vertex;
    std::unordered_map<NodeBase*, NodeBase*> parent;
    std::unordered_map<NodeBase*, NodeBase*> ancestor;
    std::unordered_map<NodeBase*, NodeBase*> label;
    std::unordered_map<NodeBase*, NodeBase*> dom;
    std::unordered_map<NodeBase*, std::unordered_set<NodeBase*>> pred;
    std::unordered_map<NodeBase*, std::unordered_set<NodeBase*>> bucket;

    // DAD: semi = {v: 0 for v in graph.nodes}
    for (NodeBase* v : graph.nodes) semi[v] = 0;

    // DAD: _dfs(v, n) — iterative form.
    auto dfs = [&](NodeBase* root) -> int {
        struct F { NodeBase* v; std::vector<NodeBase*> sucs; size_t i; };
        std::vector<F> stack;
        int n = 0;
        auto enter = [&](NodeBase* v) {
            // DAD: semi[v] = n = n + 1; vertex[n] = label[v] = v;
            //      ancestor[v] = 0
            ++n;
            semi[v] = n;
            vertex[n] = v;
            label[v] = v;
            ancestor[v] = nullptr;
            stack.push_back({v, graph.all_sucs(v), 0});
        };
        enter(root);
        while (!stack.empty()) {
            auto& top = stack.back();
            if (top.i < top.sucs.size()) {
                NodeBase* w = top.sucs[top.i++];
                // DAD: pred[w].add(v) — always.
                pred[w].insert(top.v);
                // DAD: if not semi[w] — only descend if unvisited.
                auto si = semi.find(w);
                if (si != semi.end() && si->second == 0) {
                    parent[w] = top.v;
                    enter(w);
                }
            } else {
                stack.pop_back();
            }
        }
        return n;
    };

    // DAD: _compress(v) — iterative bottom-up.
    auto compress = [&](NodeBase* v) {
        std::vector<NodeBase*> path;
        // Collect every cur whose grandparent (ancestor[ancestor[cur]]) is
        // non-null — matches DAD's `if ancestor[u]:` recursion guard.
        for (NodeBase* cur = v;
             ancestor[cur] && ancestor[ancestor[cur]];
             cur = ancestor[cur]) {
            path.push_back(cur);
        }
        // Apply updates starting from the deepest collected node.
        for (auto it = path.rbegin(); it != path.rend(); ++it) {
            NodeBase* node = *it;
            NodeBase* u = ancestor[node];
            if (semi[label[u]] < semi[label[node]]) {
                label[node] = label[u];
            }
            ancestor[node] = ancestor[u];
        }
    };

    auto eval = [&](NodeBase* v) -> NodeBase* {
        if (ancestor[v]) {
            compress(v);
            return label[v];
        }
        return v;
    };

    auto link = [&](NodeBase* v, NodeBase* w) { ancestor[w] = v; };

    // Step 1.
    const int n = dfs(graph.entry);

    // Step 2 + 3.
    for (int i = n; i > 1; --i) {
        NodeBase* w = vertex[i];
        NodeBase* y_vertex = nullptr;
        for (NodeBase* v : pred[w]) {
            NodeBase* u = eval(v);
            if (semi[u] < semi[w]) semi[w] = semi[u];
            y_vertex = vertex[semi[w]];
        }
        if (y_vertex) bucket[y_vertex].insert(w);
        NodeBase* pw = parent[w];
        link(pw, w);
        // Step 3: drain bucket[pw].
        auto bit = bucket.find(pw);
        if (bit != bucket.end()) {
            auto bpw = std::move(bit->second);
            bucket.erase(bit);
            while (!bpw.empty()) {
                NodeBase* v = *bpw.begin();
                bpw.erase(bpw.begin());
                NodeBase* u = eval(v);
                dom[v] = (semi[u] < semi[v]) ? u : pw;
            }
        }
    }

    // Step 4.
    for (int i = 2; i <= n; ++i) {
        NodeBase* w = vertex[i];
        auto dit = dom.find(w);
        if (dit == dom.end()) continue;
        NodeBase* dw = dit->second;
        if (dw != vertex[semi[w]]) {
            dom[w] = dom[dw];
        }
    }
    // DAD: dom[graph.entry] = None
    dom[graph.entry] = nullptr;
    return dom;
}

// =============================================================================
// Construct — DAD graph.py:502
// =============================================================================
// Builds the typed-BasicBlock CFG from a snapshot. Each RawBlock becomes a
// BasicBlock subclass via BuildNodeFromBlock. Edges flow from RawBlock.childs
// (and exception_handlers → catch edges).
std::unique_ptr<Graph> Construct(const MethodSnapshot& snap,
                                 Vmap& vmap, GenInvokeRetName& gen_ret) {
    auto g = std::make_unique<Graph>();
    if (!snap.entry_block_id) {
        // Native / abstract — no CFG.
        return g;
    }

    // STEP 1: Build BasicBlock for each RawBlock; index by block_id.
    // For catch-handler blocks, pass the catch type as exception_type
    // (DAD: build_node_from_block(block, vmap, gen_ret, _type)).
    std::vector<std::string_view> exception_type_for(snap.blocks.size(),
                                                      std::string_view{});
    for (const auto& er : snap.exceptions) {
        for (const auto& ci : er.handlers) {
            if (ci.handler_block_id < exception_type_for.size()) {
                exception_type_for[ci.handler_block_id] = ci.catch_type;
            }
        }
    }

    std::vector<BasicBlock*> nodes;
    nodes.reserve(snap.blocks.size());
    for (size_t i = 0; i < snap.blocks.size(); ++i) {
        const RawBlock& rb = snap.blocks[i];
        auto block_node = BuildNodeFromBlock(rb, vmap, gen_ret,
                                              exception_type_for[i]);
        // Transfer ownership to Graph via owned_nodes_; we re-implement the
        // adopt-and-add pattern of MakeNode here since we can't construct
        // in-place (BuildNodeFromBlock owns).
        BasicBlock* raw = block_node.get();
        g->owned_nodes_.push_back(std::move(block_node));
        g->add_node(raw);
        nodes.push_back(raw);
    }

    // STEP 2: Wire edges.
    for (size_t i = 0; i < snap.blocks.size(); ++i) {
        const RawBlock& rb = snap.blocks[i];
        BasicBlock* node = nodes[i];
        for (const auto& edge : rb.childs) {
            if (edge.target_block_id >= nodes.size()) continue;
            BasicBlock* tgt = nodes[edge.target_block_id];
            g->add_edge(node, tgt);
            // Type-specific wiring
            if (auto* cb = dynamic_cast<CondBlock*>(node)) {
                if (edge.kind == ChildEdge::Kind::Branch) cb->true_branch = tgt;
                if (edge.kind == ChildEdge::Kind::BranchFalse) cb->false_branch = tgt;
            }
            if (auto* sb = dynamic_cast<SwitchBlock*>(node)) {
                if (edge.kind == ChildEdge::Kind::SwitchCase) {
                    // Dedup add_case: same tgt may appear for multiple keys.
                    if (std::find(sb->cases.begin(), sb->cases.end(), tgt)
                            == sb->cases.end()) {
                        sb->add_case(tgt);
                    }
                    // DAD basic_blocks.py:130 order_cases populates
                    // `node_to_case[node].append(case_value)` so the Writer can
                    // emit `case N:` labels. We get the key from edge.label
                    // (set by the snapshot builder from PayloadPackedSwitch /
                    // PayloadSparseSwitch keys).
                    sb->node_to_case[tgt].push_back(edge.label);
                }
                if (edge.kind == ChildEdge::Kind::SwitchDefault) sb->default_case = tgt;
            }
        }
        // Catch edges from exception handlers attached to this block.
        for (const auto& ci : rb.exception_handlers) {
            if (ci.handler_block_id >= nodes.size()) continue;
            BasicBlock* handler = nodes[ci.handler_block_id];
            handler->in_catch = true;
            // DAD graph.py:470-471 — set_catch_type on both the try block
            // and the catch handler. Empty ci.catch_type means catch-all;
            // we keep the empty string here and let MoveException default
            // to Throwable (so the variable's type is correctly typed).
            node->set_catch_type(std::string{ci.catch_type});
            handler->set_catch_type(std::string{ci.catch_type});
            g->add_catch_edge(node, handler);
        }
        // DAD: "If both branch of the if point to something. It may happen
        // that both branch point to the same node, in this case the false
        // branch will be None. So we set it to the right node."
        if (auto* cb = dynamic_cast<CondBlock*>(node)) {
            if (cb->true_branch != nullptr && cb->false_branch == nullptr) {
                cb->false_branch = cb->true_branch;
            }
        }
    }

    // STEP 3: entry/exit + rpo + numbering.
    g->entry = nodes[*snap.entry_block_id];

    g->compute_rpo();

    // Mark in_catch for nodes whose all <-num preds are in_catch.
    for (NodeBase* n : g->rpo) {
        auto preds = g->all_preds(n);
        std::vector<NodeBase*> active;
        for (auto* p : preds) if (p->num < n->num) active.push_back(p);
        if (!active.empty()) {
            bool all_catch = true;
            for (auto* p : active) if (!p->in_catch) { all_catch = false; break; }
            if (all_catch) n->in_catch = true;
        }
    }

    g->number_ins();

    // Locate exit (return) node.
    NodeBase* exit_node = nullptr;
    for (NodeBase* n : g->nodes) {
        auto* bb = dynamic_cast<BasicBlock*>(n);
        if (bb && bb->type.is_return()) {
            if (exit_node == nullptr) exit_node = n;
            else { exit_node = nullptr; break; }  // multiple — leave null
        }
    }
    g->exit = exit_node;

    return g;
}

// =============================================================================
// GenInvokeRetName — DAD graph.py:439
// =============================================================================
IRFormPtr GenInvokeRetName::New() {
    // DAD: self.num += 1; self.ret = Variable('tmp%d' % self.num); return ret
    ++num_;
    ret_ = std::make_shared<Variable>("tmp" + std::to_string(num_));
    return ret_;
}

// =============================================================================
// Interval::ComputeEnd — DAD node.py:149
// =============================================================================
void Interval::ComputeEnd(Graph& graph) {
    // DAD: e_max = -inf; for sucs in self.content: for end in graph.sucs(sucs):
    //          if end not in self.content and e_max < end.num:
    //              self.end = end; e_max = end.num
    int e_max = std::numeric_limits<int>::min();
    for (NodeBase* member : content()) {
        for (NodeBase* end : graph.sucs(member)) {
            if (content().count(end) == 0 && e_max < end->num) {
                end_ = end;
                e_max = end->num;
            }
        }
    }
}

// =============================================================================
// BuildPath — DAD util.py:134
// =============================================================================
namespace {
void BuildPathRecurse(Graph& graph, NodeBase* node1, NodeBase* node2,
                      std::vector<NodeBase*>& path) {
    // DAD: if node1 is node2: return path
    if (node1 == node2) return;
    // DAD: path.append(node2)
    path.push_back(node2);
    // DAD: for pred in graph.all_preds(node2):
    //          if pred in path: continue
    //          build_path(graph, node1, pred, path)
    for (NodeBase* pred : graph.all_preds(node2)) {
        if (std::find(path.begin(), path.end(), pred) != path.end()) continue;
        BuildPathRecurse(graph, node1, pred, path);
    }
}
}  // namespace

std::vector<NodeBase*> BuildPath(Graph& graph, NodeBase* node1,
                                 NodeBase* node2) {
    std::vector<NodeBase*> path;
    BuildPathRecurse(graph, node1, node2, path);
    return path;
}

// =============================================================================
// CommonDom — DAD util.py:153
// =============================================================================
NodeBase* CommonDom(
    const std::unordered_map<NodeBase*, NodeBase*>& idom,
    NodeBase* cur, NodeBase* pred) {
    // DAD: if not (cur and pred): return cur or pred
    if (!cur || !pred) return cur ? cur : pred;
    auto idom_of = [&](NodeBase* n) -> NodeBase* {
        auto it = idom.find(n);
        return it == idom.end() ? nullptr : it->second;
    };
    // DAD: while cur is not pred:
    //          while cur.num < pred.num: pred = idom[pred]
    //          while cur.num > pred.num: cur = idom[cur]
    while (cur != pred) {
        while (pred && cur && cur->num < pred->num) pred = idom_of(pred);
        while (cur && pred && cur->num > pred->num) cur = idom_of(cur);
        // Guards (DAD-faithful would raise/KeyError on these):
        //  - either side became null → return the other
        //  - both non-null with equal num but still different nodes → would
        //    spin forever (defensive against malformed dominator trees with
        //    duplicate post-order numbers, e.g. unreachable nodes at num=0).
        if (!cur || !pred) return cur ? cur : pred;
        if (cur->num == pred->num) return cur;
    }
    return cur;
}

}  // namespace dexkit::dad
