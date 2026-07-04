// ssa.h — Additive SSA analysis (version-split done right).
//
// NOT a DAD port. This is a beyond-DAD analysis layer (design:
// docs/ssa-design.md, approved 2026-07-05) that computes precise per-value
// types and the precise int↔reference conflation set, replacing the unsound
// GroupVariables/SplitConflatedVersion heuristics. It is ADDITIVE: it runs as a
// new analysis over the existing CFG (reusing DomLt / all_preds / all_sucs) and
// informs the SplitVariables stage; the Writer/dast/parity pipeline is
// unchanged.
//
// Phase 1a (this file, first cut): dominance frontiers (Cytron et al.), the
// foundation for phi placement. Pure function over the CFG — no IR mutation.

#pragma once

#include <map>
#include <string>
#include <unordered_map>
#include <utility>
#include <vector>

#include "dataflow.h"   // ChainMap (for the SSA oracle)
#include "node.h"

namespace dexkit::dad {

class Graph;

// Dominance frontiers (Cytron, Ferrante, Rosen, Wegman & Zadeck 1991).
//   DF(n) = the set of nodes w such that n dominates a predecessor of w but does
//   NOT strictly dominate w. Phi functions for a value defined in n are placed
//   at the iterated dominance frontier of n's def-blocks.
//
// Uses the SAME edge set as the reaching-def analysis and DomLt: `all_preds` /
// `all_sucs` (normal + catch edges), rooted at `graph.entry`. Only nodes
// reachable from entry (present in the idom map) are considered; unreachable
// nodes get an empty frontier.
//
// The returned per-node frontier vector is sorted by (num, name) for
// deterministic downstream consumption (no pointer-hash iteration order feeds a
// decision — the historical non-determinism root cause).
std::unordered_map<NodeBase*, std::vector<NodeBase*>>
DominanceFrontiers(Graph& graph);

// Same, but reusing a precomputed idom map (node → immediate dominator, entry →
// nullptr, as returned by DomLt). Avoids recomputing dominators when the caller
// already has them.
std::unordered_map<NodeBase*, std::vector<NodeBase*>>
DominanceFrontiers(Graph& graph,
                   const std::unordered_map<NodeBase*, NodeBase*>& idom);

// -----------------------------------------------------------------------------
// Phase 1b: SSA construction (phi insertion + renaming) — pure ANALYSIS.
// -----------------------------------------------------------------------------
// Works on the same string-keyed register model as the reaching-def analysis: a
// "register" is any var key that is a parameter or appears as an instruction's
// GetLhsId() (a def); a use is any entry of get_used_vars(). Does NOT mutate the
// IR — it computes an SSA view (which version each use reads, each version's def
// site, and the phi nodes) that Phase 2 will consume for out-of-SSA typing.
//
// SSA value identity: (reg, version). version 0 = live-in (a parameter, or an
// entry-undefined register); version >= 1 = a real def or a phi result.

// A phi function: reg = phi(operand per predecessor), placed at a join block.
struct SsaPhi {
    NodeBase* block = nullptr;
    std::string reg;
    int result = 0;                                   // result version
    // (predecessor block, incoming version) — one per reachable predecessor,
    // sorted by (num, name) for determinism.
    std::vector<std::pair<NodeBase*, int>> operands;
};

struct SsaResult {
    static constexpr int DEF_PHI = -1;      // def_site value: defined by a phi
    static constexpr int DEF_LIVEIN = -2;   // def_site value: a PARAMETER live-in
    static constexpr int DEF_UNDEF = -3;    // def_site value: a non-param register's
                                            // entry value (uninitialized — NOT a
                                            // reaching def; reaching-def has no
                                            // negative loc for it)

    // (reg, use-loc) -> the version read at that use.
    std::map<std::pair<std::string, int>, int> use_version;
    // (reg, version) -> def loc, or DEF_PHI / DEF_LIVEIN.
    std::map<std::pair<std::string, int>, int> def_site;
    // (reg, version) -> index into `phis` (only when def_site == DEF_PHI).
    std::map<std::pair<std::string, int>, int> phi_index;
    std::vector<SsaPhi> phis;
    bool ok = true;                          // false if the CFG had no entry
};

// Build the SSA view. `params` is the method's parameter var keys (lparams), as
// passed to BuildDefUse — they are the live-in defs at entry. Deterministic
// (blocks in dominator-tree order with sorted children, registers in sorted
// order, phi operands sorted by predecessor).
SsaResult BuildSsa(Graph& graph, const std::vector<std::string>& params);

// -----------------------------------------------------------------------------
// Phase 1c: SSA oracle — reconstruction-faithfulness check.
// -----------------------------------------------------------------------------
// Independently validates the SSA view against the reaching-def chains
// (BuildDefUse's `ud`, computed by a different algorithm): for every use, the
// set of REAL def locs obtained by resolving the SSA version through phis must
// equal `ud`'s reaching real-def locs, and the "a live-in / param reaches"
// bit must agree. A corpus-wide 0-mismatch proves the SSA analysis neither lost
// nor invented a def/use edge — so wiring it into the pipeline (Phase 2) is
// sound. Analysis-only; never mutates the IR.
struct SsaOracle {
    long uses_checked = 0;
    long mismatches = 0;
    std::string first;   // first mismatch detail (for triage)
};
SsaOracle VerifySsa(Graph& graph, const std::vector<std::string>& params,
                    const SsaResult& ssa, const ChainMap& ud);

}  // namespace dexkit::dad
