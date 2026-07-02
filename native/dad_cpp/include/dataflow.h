// dataflow.h — C++ port of androguard DAD dataflow.py
// DAD: androguard/decompiler/dataflow.py
//
// PORT STATUS (12/12 entities ported):
//   - BasicReachDef          — DAD dataflow.py:27
//   - update_chain           — DAD dataflow.py:80
//   - dead_code_elimination  — DAD dataflow.py:116
//   - clear_path_node        — DAD dataflow.py:148
//   - clear_path             — DAD dataflow.py:162
//   - register_propagation   — DAD dataflow.py:190
//   - DummyNode              — DAD dataflow.py:323
//   - group_variables        — DAD dataflow.py:337
//   - split_variables        — DAD dataflow.py:368
//   - reach_def_analysis     — DAD dataflow.py:406
//   - build_def_use          — DAD dataflow.py:432
//   - place_declarations     — DAD dataflow.py:471
//
// Type-mapping notes:
//   - DAD's `defs[node][reg]` keys regs by Variable identity (same vmap
//     instance shared across uses). We key by the variable's id string
//     (IRForm::Vid()) since that's identity-equivalent for vmap-managed
//     Variables and stable across moves.
//   - DAD's DU/UD chains are dicts keyed by (var, loc) tuples. We mirror with
//     unordered_map keyed by (string, int).
//   - DAD's `loc` is an int (with negatives marking params). Same in C++.

#pragma once

#include <cstddef>
#include <functional>
#include <set>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <utility>
#include <vector>

#include "graph.h"
#include "instruction.h"
#include "node.h"

namespace dexkit::dad {

// (string, int) key with a small hash — used for DU/UD chains.
struct VarLocKey {
    std::string var;
    int loc;
    bool operator==(const VarLocKey& o) const noexcept {
        return loc == o.loc && var == o.var;
    }
};
struct VarLocHash {
    size_t operator()(const VarLocKey& k) const noexcept {
        return std::hash<std::string>{}(k.var) ^
               (std::hash<int>{}(k.loc) << 1);
    }
};

// DU / UD chain types. DAD uses defaultdict(list); we mirror via
// unordered_map<key, vector<int>>.
using ChainMap = std::unordered_map<VarLocKey, std::vector<int>, VarLocHash>;

// DAD: dataflow.py:27 BasicReachDef — reaching-definitions worklist analysis.
class BasicReachDef {
public:
    // DAD: dataflow.py:28 __init__(graph, params)
    //   `params` is the list of formal-parameter variable ids; DAD uses them
    //   to seed defs at the synthetic entry node with locations -1, -2, ...
    BasicReachDef(Graph& graph, const std::vector<std::string>& params);

    // DAD: dataflow.py:51 run — fixed-point worklist.
    void run();

    // Public (DAD treats these as attributes).
    Graph& g;
    std::unordered_map<NodeBase*, std::set<int>> A;  // out-set per node
    std::unordered_map<NodeBase*, std::set<int>> R;  // in-set per node
    std::unordered_map<NodeBase*, std::set<int>> DB; // kill set per node
    // defs[node][reg_id] = set of locations defining reg in node.
    std::unordered_map<NodeBase*,
                       std::unordered_map<std::string, std::set<int>>> defs;
    // def_to_loc[reg_id] = set of all locations that define reg across graph.
    std::unordered_map<std::string, std::set<int>> def_to_loc;
};

// DAD: dataflow.py:80 update_chain.
void UpdateChain(Graph& graph, int loc, ChainMap& du, ChainMap& ud);

// DAD: dataflow.py:116 dead_code_elimination.
void DeadCodeElimination(Graph& graph, ChainMap& du, ChainMap& ud);

// DAD: dataflow.py:148 clear_path_node.
bool ClearPathNode(Graph& graph, const std::string& reg, int loc1, int loc2);

// DAD: dataflow.py:162 clear_path.
//   `reg` is empty string when DAD passes None (side-effect-only check).
bool ClearPath(Graph& graph, const std::string& reg, int loc1, int loc2);

// DAD: dataflow.py:190 register_propagation.
void RegisterPropagation(Graph& graph, ChainMap& du, ChainMap& ud);

// Beyond-DAD (dexllm) — type the result of a `vRes = vBase.<init>()` constructor
// call as the constructed object. split_variables derives a version's type from
// its def's rhs, but `InvokeInstruction::get_type()` for <init> returns the LIVE
// base Variable type, and the base's own version is finalized only in a LATER
// split iteration (vRes has the lower index) — so at derivation time the base is
// still the shared register carrying a stale (e.g. trailing-int) type, mistyping
// vRes `int`. Run this AFTER split_variables (bases finalized) and BEFORE
// register_propagation (the <init> node still intact): re-read each <init>
// result's finalized base type and apply it when the result is non-reference.
// No-op on already-correct output; reference results (incl. more-derived) left
// alone. Scoped to the <init> result only — does not touch the multi-def type
// derivation that handles conflated (object-or-null) merge variables.
//
// It ALSO runs a second, general beyond-DAD pass that fixes move-chain type
// CASCADES in BOTH directions. DAD types every split version from the register's
// last write, so a register reused across incompatible types can leave a version
// mistyped; resolving each def to its transitive GROUND TRUTH (following moves to
// their ultimate producer) recovers the real type:
//   - ref→prim: a REFERENCE-typed version whose ground-truth producers are all
//     primitive/null (the reference was copied off a sibling conflated register by
//     a move) is genuinely a primitive — an obfuscator's 0/1 flag reusing an
//     object slot — emitting uncompilable `ArrayList v = 1;`. Re-typed to its
//     (resolved-width 'I'/'J'/…) primitive descriptor.
//   - prim→ref: a PRIMITIVE-typed version whose ground-truth producers are a
//     reference + null (e.g. `int v = ObjectAnimator.ofFloat(...)` then `v = 0`,
//     used as `v.addListener()` / `return v`) is genuinely that reference.
//     Re-typed to the (agreeing) reference class; the `= 0` then renders `= null`.
// def-anchored AND use-corroborated. Re-type ONLY when the ground truth is
// UNAMBIGUOUS: no def is UNRESOLVED (a move-cycle 'M' or unknown-type 'U' producer
// might be a hidden reference), the producers do not mix a real primitive with a
// real reference — where a MOVE SOURCE is itself a conflated register holding both
// a primitive and a reference, gt() reports 'U' (it aggregates ALL sibling defs
// and does NOT short-circuit on the first 'R'), so such a genuine conflation is
// left untouched (needs a version split — the PR#7 int/ref regression direction) —
// and the reference producers agree on one class. USE-CORROBORATION (symmetric):
// the ref→prim direction skips a version used AS AN OBJECT (`v.m()` / `v.f`); the
// prim→ref direction skips a version used AS AN INT (an arithmetic operand, an
// array index, or an ORDERED comparison `v < n` / `v <= null`). Both guards make
// the pass sound for lenient/unverified dex too, not only where the verifier
// guarantees the def/use web. Classification reads only pre-mutation types
// (two-phase) so the directions cannot interfere. Adversarial-review-hardened:
// the move-source short-circuit + missing int-use guard once mis-typed a
// conflated `int` limit to `String` (`v6 <= null`; fixed). Enforced regression
// tests: `prim = new` and `RefType v = <int>` (bounded) and `v <op> null`
// (bounded over a separate PRE-EXISTING typing residual) in test_cascade_type.py;
// the `0 new ref-used-as-int` / `prim.member` claims were a/b-MEASURED (mirror on
// vs off) rather than each independently CI-enforced.
void FixInitResultTypes(Graph& graph);

// DAD: dataflow.py:323 DummyNode — placeholder Node with empty loc-with-ins.
class DummyNode : public Node {
public:
    explicit DummyNode(std::string n);
    // DAD: dataflow.py:327 get_loc_with_ins → returns [] (empty list).
    // We expose as the same call shape used by Graph::number_ins (a
    // BasicBlock cast). DummyNode is a Node, not BasicBlock, so Graph
    // ignores it during number_ins. (DAD's reach_def_analysis removes the
    // dummies before number_ins gets called.)
    // String form: DAD __str__ → '<name>-dummynode'.
    std::string ToString() const { return name + "-dummynode"; }
};

// DAD: dataflow.py:337 group_variables.
//   DAD's `lvars` is `{int_register_id → Variable}`. We mirror as
//   `unordered_map<int, IRFormPtr>`.
//   DAD's DU keys are (var, loc) where var is the int register id.
//   We re-use ChainMap (string key) and require the caller to encode int
//   registers as `std::to_string(reg)` — keeping DU/UD consistent with the
//   rest of the module.
//   Returns: variables[reg_str] → list of (defs, uses) pairs.
using GroupedVersions =
    std::vector<std::pair<std::vector<int>, std::vector<int>>>;
// Insertion-ordered map: vector of (var_str, versions) pairs. DAD relies on
// Python dict's insertion ordering (3.7+); unordered_map iteration is hash
// order and would produce non-deterministic nb_vars assignments — leading
// to variable suffixes that differ from DAD even when the structure is
// otherwise identical (e.g. `v0_5` vs `v0_3`).
using VariableGroups =
    std::vector<std::pair<std::string, GroupedVersions>>;
VariableGroups GroupVariables(
    const std::unordered_map<int, IRFormPtr>& lvars,
    const ChainMap& du, const ChainMap& ud);

// DAD: dataflow.py:368 split_variables.
void SplitVariables(Graph& graph,
                    std::unordered_map<int, IRFormPtr>& lvars,
                    ChainMap& du, ChainMap& ud);

// DAD: dataflow.py:406 reach_def_analysis — driver.
//   Returns the analysis object so callers can read .defs / .def_to_loc / .R.
//   The driver inserts/removes synthetic entry & exit DummyNodes; ownership
//   for those nodes is held by the analysis object via a unique_ptr stash.
class ReachDefResult {
public:
    explicit ReachDefResult(Graph& g, const std::vector<std::string>& params);

    BasicReachDef& analysis() noexcept { return *analysis_; }

private:
    std::unique_ptr<DummyNode> dummy_entry_;
    std::unique_ptr<DummyNode> dummy_exit_;
    std::unique_ptr<BasicReachDef> analysis_;
};

// DAD: dataflow.py:432 build_def_use.
//   Returns (UD, DU) — DAD's call is `UD, DU = build_def_use(graph, lparams)`.
struct DefUseChains { ChainMap ud; ChainMap du; };
DefUseChains BuildDefUse(Graph& graph,
                         const std::vector<std::string>& lparams);

// DAD: dataflow.py:471 place_declarations.
//   dvars maps reg_string → Variable IRForm; place each declaration in the
//   nearest common dominator of its def points (subject to DAD's range guard).
void PlaceDeclarations(Graph& graph,
                       const std::unordered_map<std::string, IRFormPtr>& dvars,
                       const ChainMap& du, const ChainMap& ud);

}  // namespace dexkit::dad
