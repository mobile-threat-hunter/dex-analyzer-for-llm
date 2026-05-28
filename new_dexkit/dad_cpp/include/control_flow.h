// control_flow.h — C++ port of androguard DAD control_flow.py
// DAD: androguard/decompiler/control_flow.py
//
// PORT STATUS (10/14 entities ported):
//   Ported:
//     - intervals             — DAD control_flow.py:34
//     - derived_sequence      — DAD control_flow.py:93
//     - mark_loop_rec         — DAD control_flow.py:119
//     - mark_loop             — DAD control_flow.py:128
//     - loop_type             — DAD control_flow.py:139
//     - loop_follow           — DAD control_flow.py:158
//     - loop_struct           — DAD control_flow.py:190
//     - if_struct             — DAD control_flow.py:205
//     - switch_struct         — DAD control_flow.py:225
//                                (order_cases deferred inside SwitchBlock)
//     - update_dom            — DAD control_flow.py:406
//   Deferred (ABI bridges needed):
//     - short_circuit_struct  — DAD control_flow.py:249 needs Condition to
//         accept CondBlock* as an Operand (DAD passes nodes directly).
//     - while_block_struct    — DAD control_flow.py:329 needs LoopBlock(
//         name, CondBlock*) constructor; ours takes shared_ptr<Condition>.
//     - catch_struct          — DAD control_flow.py:361 needs TryBlock.follow
//         scalar-assign attribute (DAD overrides Node.follow dict with a
//         single node — type-system surgery required).
//     - identify_structures   — DAD control_flow.py:411 driver depends on the
//         three deferred passes above.

#pragma once

#include <cstddef>
#include <memory>
#include <unordered_map>
#include <unordered_set>
#include <vector>

#include "basic_blocks.h"
#include "graph.h"
#include "node.h"

namespace dexkit::dad {

// DAD: control_flow.py:34 intervals.
//   Returns the derived interval graph plus the {header → Interval} map.
//   Intervals are owned by the returned IntervalResult.
struct IntervalResult {
    std::unique_ptr<Graph> graph;
    std::unordered_map<NodeBase*, Interval*> interv_heads;
    std::vector<std::unique_ptr<Interval>> intervals;
};
IntervalResult Intervals(Graph& graph);

// DAD: control_flow.py:93 derived_sequence.
//   seq[0] is the input graph (borrowed). seq[1..] / results[1..] are owned
//   by the IntervalResult entries.
struct DerivedSequence {
    std::vector<Graph*> seq;
    std::vector<IntervalResult> results;
};
DerivedSequence DerivedSequenceOf(Graph& graph);

// DAD: control_flow.py:128 mark_loop (calls mark_loop_rec internally).
std::vector<NodeBase*> MarkLoop(Graph& graph, NodeBase* start, NodeBase* end,
                                Interval* interval);

// DAD: control_flow.py:139 loop_type.
void LoopType(NodeBase* start, NodeBase* end,
              const std::vector<NodeBase*>& nodes_in_loop);

// DAD: control_flow.py:158 loop_follow.
void LoopFollow(NodeBase* start, NodeBase* end,
                const std::vector<NodeBase*>& nodes_in_loop);

// DAD: control_flow.py:190 loop_struct.
void LoopStruct(const std::vector<Graph*>& graphs_list,
                const std::vector<IntervalResult>& intervals_list);

// DAD: control_flow.py:205 if_struct.
std::unordered_set<NodeBase*> IfStruct(
    Graph& graph,
    const std::unordered_map<NodeBase*, NodeBase*>& idoms);

// DAD: control_flow.py:225 switch_struct.
void SwitchStruct(Graph& graph,
                  const std::unordered_map<NodeBase*, NodeBase*>& idoms);

// DAD: control_flow.py:406 update_dom.
void UpdateDom(std::unordered_map<NodeBase*, NodeBase*>& idoms,
               const std::unordered_map<NodeBase*, NodeBase*>& node_map);

// DAD: control_flow.py:249 short_circuit_struct.
//   Merges adjacent CondBlock pairs into ShortCircuitBlocks (via Condition
//   wrapping). Mutates graph (new nodes via Graph::MakeNode) and idom map.
void ShortCircuitStruct(
    Graph& graph,
    std::unordered_map<NodeBase*, NodeBase*>& idom,
    std::unordered_map<NodeBase*, NodeBase*>& node_map);

// DAD: control_flow.py:329 while_block_struct.
//   Wraps each `startloop` node in a LoopBlock.
void WhileBlockStruct(Graph& graph,
                      std::unordered_map<NodeBase*, NodeBase*>& node_map);

// DAD: control_flow.py:361 catch_struct.
//   Wraps each try region in a TryBlock + attaches CatchBlocks.
void CatchStruct(Graph& graph,
                 const std::unordered_map<NodeBase*, NodeBase*>& idoms);

// DAD: control_flow.py:411 identify_structures.
//   Top-level driver: derived_sequence → switch/loop/short-circuit/if/
//   while/catch struct passes. Mutates graph + idoms.
void IdentifyStructures(Graph& graph,
                        std::unordered_map<NodeBase*, NodeBase*>& idoms);

}  // namespace dexkit::dad
