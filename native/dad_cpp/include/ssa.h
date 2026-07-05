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

#include <functional>
#include <map>
#include <string>
#include <string_view>
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

// -----------------------------------------------------------------------------
// Phase B1: type-bounds model (jadx-informed; docs/type-inference-v2-design.md).
// -----------------------------------------------------------------------------
// For each SSA value (reg, version) collect the two kinds of constraint jadx's
// TypeInferenceVisitor uses:
//   * ASSIGN bound — the type the DEFINING instruction produces (NEW→class,
//     INVOKE→return, IGET/SGET→field, CONST→literal, MOVE_EXCEPTION→catch,
//     CHECK_CAST→cast, a live-in param→its declared type). At most one per
//     version (a version has one def); a phi/undef version has none of its own
//     (Phase B2 merges the operand bounds across the phi web).
//   * USE bounds — for every use position, the type that position REQUIRES
//     (invoke receiver→declaring class, invoke arg→param type, iput/sput
//     value→field type, iget/iput owner→declaring class, throw→Throwable,
//     return→method return type, arithmetic/array-index/ordered-compare
//     operand→a primitive of the operation's width). One version can carry
//     several USE bounds (used at several positions).
//
// This GENERALISES the ad-hoc object_vids / int_use_vids boolean gates the
// FixInitResultTypes heuristics built — every position now contributes a TYPED
// bound keyed by the exact SSA value, not a per-register boolean. Pure ANALYSIS:
// it reads the IR and the SSA view, mutates nothing (output byte-identical).
// Phase B2 will merge these across phi webs and select the best type; B3 wires
// the selection into SplitVariables.
struct TypeBounds {
    std::string assign;                // the def's produced type ("" if none)
    std::vector<std::string> uses;     // required types at use positions
                                       // (sorted, deduped for determinism)
};

struct BoundsResult {
    // (reg, version) -> its ASSIGN + USE bounds. std::map for deterministic
    // iteration (sorted by reg then version).
    std::map<std::pair<std::string, int>, TypeBounds> bounds;
};

// Build the bounds model over an already-computed SSA view. `param_types` maps a
// parameter's register key ("v<N>") to its declared Dalvik descriptor (the `this`
// receiver → its class); it supplies the ASSIGN bound of every live-in version.
// `ret_type` is the method's declared return descriptor (the USE bound at every
// `return v`). Deterministic.
BoundsResult ComputeTypeBounds(
    Graph& graph, const SsaResult& ssa,
    const std::map<std::string, std::string>& param_types,
    const std::string& ret_type);

// -----------------------------------------------------------------------------
// Phase B2: phi-web merge + hierarchy-based type selection — pure ANALYSIS.
// -----------------------------------------------------------------------------
// jadx mergePhiBounds + selectBestTypeFromBounds, on our SSA + `is_assignable`:
//   1. MERGE — a phi ties its result and every operand into ONE constraint set
//      (the whole phi web shares bounds). We union the versions a phi connects
//      (all versions of the same register) and pool their ASSIGN/USE bounds.
//   2. SELECT — per web, choose the type that satisfies every constraint:
//      * a primitive bound AND a reference bound in the same web = a genuine
//        int↔reference conflation (no single Java type) → CONFLICT → Object
//        (Phase B3 emits the reference-use casts, already in writer.cpp).
//      * all-reference: the narrowest type that is a supertype of every ASSIGN
//        (each produced value assignable to it) and a subtype of every USE
//        (assignable to each required position), decided by `is_assignable`
//        (partial-sound; unknown → conservative, never a false positive).
//      * all-primitive: widen to the widest rank present (Z/B/C/S/I < J < F < D).
// Produces a per-version `version → type` map (web-shared). Analysis-only in B2
// (env-gated compare vs the current typing); Phase B3 feeds it into
// SplitVariables. Deterministic (sorted webs, sorted bound sets).
struct SelectedType {
    std::string type;        // chosen descriptor ("Ljava/lang/Object;" on conflict)
    bool conflict = false;   // int↔ref conflation (Object + reference-use casts)
    bool resolved = false;   // a concrete type (or conflict) was determined
    std::string note;        // analysis-only: pooled bounds on a conflict web
};

struct SelectResult {
    std::map<std::pair<std::string, int>, SelectedType> types;
    long webs = 0;           // number of phi-webs / singleton versions selected
    long conflicts = 0;      // webs classified as int↔ref conflations
    long conflicts_use = 0;  // subset: prim AND ref both come from a real USE
                             // position (a genuine read forces both) — vs an
                             // assign-only merge (likely a dead-phi artifact).
};

// `is_assignable(sub, super)` → true iff sub is assignable to super (a partial-
// sound dex-hierarchy oracle; may be null → exact-equality fallback).
SelectResult SelectTypes(
    const SsaResult& ssa, const BoundsResult& bounds,
    const std::function<bool(std::string_view, std::string_view)>&
        is_assignable);

}  // namespace dexkit::dad
