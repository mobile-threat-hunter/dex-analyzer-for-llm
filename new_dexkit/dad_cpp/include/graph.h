// graph.h — C++ port of androguard DAD graph.py
// DAD: androguard/decompiler/graph.py
//
// This module corresponds to androguard's DAD <graph.py>. Read that file
// before adding code here. Every function added must carry a
// `// DAD: graph.py:<lineno> <concept>` comment.
//
// PORT STATUS (4/8 entities ported):
//   Ported:
//     - Graph             — DAD graph.py:30  CFG container (all methods minus
//                                              draw() which needs pydot)
//     - GenInvokeRetName  — DAD graph.py:439 concrete RetState implementation
//     - simplify          — DAD graph.py:291 simplify trivial CFG patterns
//     - dom_lt            — DAD graph.py:352 Lengauer-Tarjan dominators
//   Deferred:
//     - split_if_nodes    — DAD graph.py:228 needs a node-ownership model
//                                              for in-function-created
//                                              StatementBlock/CondBlock pairs.
//                                              Will land with the Graph's
//                                              MakeAndAddNode<T>(...) helper.
//   Deferred (need RawBlock/RawIns provider ABI — same blocker as
//   basic_blocks.py:312 build_node_from_block):
//     - bfs               — DAD graph.py:415 needs DVMBasicBlock.childs &
//                                              .exception_analysis
//     - make_node         — DAD graph.py:456 calls build_node_from_block
//     - construct         — DAD graph.py:502 full CFG construction entry
//
// MUST RE-APPLY (lost with L6 deletion):
//   When parsing the encoded_catch_handler_list inside `construct()`,
//   the `addr` field of encoded_type_addr_pair and the `catch_all_addr`
//   are in CODE UNITS (per dex format spec) — NOT bytes. Multiply by 2
//   when treating as byte offset for leader/BB construction. Prior C++
//   bug treated them as bytes, causing leaders to land mid-instruction,
//   producing phantom OP_RETURN_VOID / cmpl-double / orphan goto in 230+
//   methods and SLICER_CHECK aborts in 16 methods.

#pragma once

#include <cstddef>
#include <memory>
#include <unordered_map>
#include <unordered_set>
#include <vector>

#include "basic_blocks.h"   // BasicBlock / CondBlock / SwitchBlock / StatementBlock
#include "instruction.h"    // IRFormPtr, Variable
#include "node.h"           // NodeBase, Node
#include "opcode_ins.h"     // RetState

namespace dexkit::dad {

// DAD: graph.py:30 Graph — CFG container.
class Graph {
public:
    Graph() = default;

    // --- DAD: graph.py:51-63 successor / predecessor accessors -------------
    // DAD: graph.py:51 sucs.
    std::vector<NodeBase*> sucs(NodeBase* node) const;
    // DAD: graph.py:54 all_sucs — edges + catch_edges.
    std::vector<NodeBase*> all_sucs(NodeBase* node) const;
    // DAD: graph.py:57 preds — filters out in_catch predecessors.
    std::vector<NodeBase*> preds(NodeBase* node) const;
    // DAD: graph.py:60 all_preds — reverse_edges + reverse_catch_edges.
    std::vector<NodeBase*> all_preds(NodeBase* node) const;

    // --- DAD: graph.py:65-91 mutation --------------------------------------
    // DAD: graph.py:65 add_node.
    void add_node(NodeBase* node);
    // DAD: graph.py:73 add_edge — set-semantics: skip if already present.
    void add_edge(NodeBase* e1, NodeBase* e2);
    // DAD: graph.py:81 add_catch_edge — propagates catch_type via
    // BasicBlock::set_catch_type. Both endpoints must be BasicBlock instances.
    void add_catch_edge(NodeBase* e1, NodeBase* e2);
    // DAD: graph.py:93 remove_node — purges from all edge tables, nodes,
    // and rpo. We do NOT delete the node object (DAD does `del node` which
    // is a Python no-op since other refs may exist; ownership stays with the
    // creator).
    void remove_node(NodeBase* node);

    // --- DAD: graph.py:120-142 location/instruction indexing ---------------
    // DAD: graph.py:120 number_ins — assigns ins_range per rpo node, builds
    // loc_to_ins and loc_to_node maps. Requires every rpo entry to be a
    // BasicBlock (down-cast checked).
    void number_ins();
    // DAD: graph.py:131 get_ins_from_loc.
    IRFormPtr get_ins_from_loc(int loc) const;
    // DAD: graph.py:134 get_node_from_loc — linear scan over loc_to_node.
    NodeBase* get_node_from_loc(int loc) const;
    // DAD: graph.py:139 remove_ins — removes from owning node and from
    // loc_to_ins map.
    void remove_ins(int loc);

    // --- DAD: graph.py:144-172 traversal -----------------------------------
    // DAD: graph.py:144 compute_rpo — runs post_order, assigns num, sorts rpo.
    void compute_rpo();
    // DAD: graph.py:155 post_order — yields nodes in post-order. Materialised
    // into a vector since C++ has no Python generator equivalent here.
    std::vector<NodeBase*> post_order();

    // --- DAD: graph.py:214-225 misc ---------------------------------------
    // DAD: graph.py:214 immediate_dominators — delegates to dom_lt.
    std::unordered_map<NodeBase*, NodeBase*> immediate_dominators();
    // DAD: graph.py:217 __len__.
    size_t size() const noexcept { return nodes.size(); }
    // draw() — DAD graph.py:174 — skipped (pydot dependency).

    // Graph-owned node creation. Constructs a T in-place, takes ownership,
    // and adds the raw pointer to `nodes`. Returns the raw pointer for
    // immediate use. Lifetime: until Graph is destroyed (remove_node does
    // NOT delete, matching DAD's GC semantics).
    //   Required by `construct()`, `SplitIfNodes`, `ShortCircuitStruct`,
    //   `WhileBlockStruct`, `CatchStruct` — any pass that synthesizes nodes.
    template <typename T, typename... Args>
    T* MakeNode(Args&&... args) {
        auto up = std::make_unique<T>(std::forward<Args>(args)...);
        T* raw = up.get();
        owned_nodes_.push_back(std::move(up));
        nodes.push_back(raw);
        return raw;
    }

    // Public state — DAD treats these as public attributes.
    NodeBase* entry = nullptr;
    NodeBase* exit = nullptr;
    std::vector<NodeBase*> nodes;
    // DAD: defaultdict(list) — keys default to empty vector on read; we use
    // explicit get-with-default in the accessors above.
    std::unordered_map<NodeBase*, std::vector<NodeBase*>> edges;
    std::vector<NodeBase*> rpo;
    std::unordered_map<NodeBase*, std::vector<NodeBase*>> catch_edges;
    std::unordered_map<NodeBase*, std::vector<NodeBase*>> reverse_edges;
    std::unordered_map<NodeBase*, std::vector<NodeBase*>> reverse_catch_edges;
    // loc_to_ins / loc_to_node: None in DAD until number_ins() is called.
    // We use a presence-flag + map to mirror that.
    bool has_loc_indexes = false;
    std::unordered_map<int, IRFormPtr> loc_to_ins;
    // Owned synthetic nodes (allocated via MakeNode). Pointer-stable.
    std::vector<std::unique_ptr<NodeBase>> owned_nodes_;
    // DAD: loc_to_node keyed by (start, end) tuple. We store as a list of
    // (start, end, node) triples because tuple-keyed unordered_map needs a
    // custom hash and the lookup is a linear scan anyway (get_node_from_loc).
    struct LocRange { int start; int end; NodeBase* node; };
    std::vector<LocRange> loc_to_node;
};

// DAD: graph.py:228 split_if_nodes — splits compound if-condition nodes
// into (pre-statement, cond) pairs via Graph::MakeNode.
void SplitIfNodes(Graph& graph);

// DAD: graph.py:291 simplify — merge/delete trivial statement nodes. Mutates
// graph in place. Iterates until no further simplification possible.
void Simplify(Graph& graph);

// DAD: graph.py:352 dom_lt — Lengauer-Tarjan immediate dominators.
//   Returns: { node → idom(node) }, with entry mapped to nullptr.
std::unordered_map<NodeBase*, NodeBase*> DomLt(Graph& graph);

// DAD: graph.py:439 GenInvokeRetName — concrete RetState implementation.
class GenInvokeRetName : public RetState {
public:
    // DAD: graph.py:444 new — Variable('tmp%d' % ++num); ret = it; return it.
    IRFormPtr New() override;
    // DAD: graph.py:449 set_to.
    void SetTo(IRFormPtr v) override { ret_ = std::move(v); }
    // DAD: graph.py:452 last.
    IRFormPtr Last() override { return ret_; }

    int num() const noexcept { return num_; }

private:
    int num_ = 0;
    IRFormPtr ret_;
};

// DAD: util.py:134 build_path — recursive backward BFS from node2 to node1.
// Lives with the graph because it consumes Graph::all_preds.
std::vector<NodeBase*> BuildPath(Graph& graph, NodeBase* node1,
                                 NodeBase* node2);

// DAD: util.py:153 common_dom — nearest common dominator of cur and pred under
// an idom map. Both arguments may be null.
NodeBase* CommonDom(
    const std::unordered_map<NodeBase*, NodeBase*>& idom,
    NodeBase* cur, NodeBase* pred);

// DAD: graph.py:502 construct — full CFG construction from a MethodSnapshot.
// Produces an owning Graph whose nodes are BasicBlock subclasses created via
// Graph::MakeNode. The returned Graph has:
//   - entry / exit set (exit nullptr if no return node)
//   - edges populated (Branch / BranchFalse / SwitchCase / SwitchDefault /
//                      Fallthrough)
//   - catch_edges populated from snapshot's exception_handlers
//   - rpo + numbering computed (compute_rpo + number_ins called)
//
// bfs / make_node are subsumed: we iterate snapshot.blocks linearly (block
// IDs are stable), building each BasicBlock and wiring edges.
class MethodSnapshot;  // fwd — method_snapshot.h
std::unique_ptr<Graph> Construct(const MethodSnapshot& snap,
                                 Vmap& vmap, GenInvokeRetName& gen_ret);

}  // namespace dexkit::dad
