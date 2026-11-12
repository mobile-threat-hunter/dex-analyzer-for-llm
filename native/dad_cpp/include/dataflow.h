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

#include <string_view>
#include <cstddef>
#include <functional>
#include <memory>
#include <set>
#include <string>
#include <unordered_map>
#include <map>
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
// `side_effects_block` (default, DAD): any side-effecting instruction on the
// path blocks. Beyond-DAD (dexllm#123): a plain register COPY reads nothing a
// call can change, so for it only a redefinition of the source blocks.
// Beyond-DAD (dexllm#123): a `reg` no instruction defines, meaning "the
// value being moved is a STATIC FIELD READ" — only something that can write a
// static field (a call, an sput) is in its way, not every side effect.
inline const std::string kStaticReadReg = "\x01static-read";
bool ClearPathNode(Graph& graph, const std::string& reg, int loc1, int loc2,
                   bool side_effects_block = true);
// Beyond-DAD (dexllm#123): the blocks that lie on a CFG cycle (an SCC of more
// than one block, or a self-edge), over normal and exception edges.
std::unordered_set<NodeBase*> CycleBlocks(Graph& graph);

// DAD: dataflow.py:162 clear_path.
//   `reg` is empty string when DAD passes None (side-effect-only check).
// Beyond-DAD (dexllm#123): what ClearPath needs to know about loops — the
// blocks on a CFG cycle (CycleBlocks) and a memo of ReachesAvoiding queries.
// Beyond-DAD (dexllm#125): is the field (declaring class, name, type) one no
// write in the method being decompiled can change? Empty, or false, means
// unknown: the read is ordered against every call and store.
using StableFieldFn = std::function<bool(std::string_view cls,
                                         std::string_view name,
                                         std::string_view type,
                                         bool is_static)>;
struct LoopInfo {
    std::unordered_set<NodeBase*> cycles;
    std::map<std::pair<NodeBase*, NodeBase*>, bool> reaches_avoiding;
    // Beyond-DAD (dexllm#125): set by RegisterPropagation. When non-null, a
    // side-effecting definition (`reg` empty) is also blocked by a memory read
    // it would move past: the read ran after the call in the bytecode.
    const StableFieldFn* stable_field = nullptr;
    bool reads_block = false;
};
// `loops` (optional, dexllm#123): when the use's block is on a cycle that
// returns to it without passing the definition's block, the use runs again
// without the definition re-running. DAD checks the use's block only up to
// the use, so what follows it on the way round went unseen: a copy read the
// updated source, a loop-invariant expression was re-evaluated with changed
// inputs, and a call made once before a loop ran once per iteration.
bool ClearPath(Graph& graph, const std::string& reg, int loc1, int loc2,
               bool side_effects_block = true, LoopInfo* loops = nullptr);

// DAD: dataflow.py:190 register_propagation.
void RegisterPropagation(Graph& graph, ChainMap& du, ChainMap& ud,
                         const StableFieldFn& stable_field = {});

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
// array index, or an ORDERED comparison `v < n` / `v <= null` — but NOT an
// `instanceof` operand, which is a reference; and NOT a `boolean` (Z) value,
// which can't be a valid int operand and whose int use marks a genuine
// boolean/int conflation that neither type resolves — left untouched). Both
// guards make the pass sound for lenient/unverified dex too, not only where the
// verifier guarantees the def/use web. The ref→prim CASCADE also handles a
// SINGLE-def version when it is int-USE-corroborated: a lone primitive-returning
// method typed reference by register conflation (`String v = p.indexOf(','); v >=
// null; v + 1`) is re-typed to the resolved primitive (`int v = …indexOf(); v >=
// 0`), width-correct (`Long.parseLong` → `long`). Multi-def prim merges keep the
// def-driven behaviour (no use requirement); a single-def version never used as an
// int is ambiguous (`String v = indexOf(); return v` where the method returns
// String) and is left untouched rather than guessed. A further USE-DRIVEN ref→prim
// branch handles a reference-typed version that is int-USED but whose reference is
// a spurious conflation artifact (no real object use): it re-types to the width
// resolved from the def closure — but ONLY when EVERY def resolves to an AGREEING
// primitive width, so a genuine object+int merge (a real allocation / reference
// method among the defs) or a mixed-width conflation is left for a real version
// split (adversarial-review hardening). Classification reads only
// pre-mutation types (two-phase) so the directions cannot interfere. Adversarial-
// review-hardened (three review rounds): the move-source short-circuit + missing
// int-use guard once mis-typed a conflated `int` limit to `String` (`v6 <= null`);
// the single-def cascade was verified over 1155 re-types / 6 obfuscated apks with
// 0 valid→invalid regressions. Enforced regression tests (test_cascade_type.py):
// `prim = new` and `RefType v = <int>` and `v <op> null` (bounded); the `0 new
// ref-used-as-int` / `prim.member` / boolean-arith claims were a/b-MEASURED
// (change on vs off) rather than each independently CI-enforced.
// `ret_type` is the method's declared return type — the use-bound typing (design
// §3) uses it as a fallback-tier reference type for a `return v` position. It
// defaults to empty (no return-position source) for callers that lack it (the
// unit-parity tests), which is behaviour-neutral (`is_ref("")` is false).
// `ud` (dexllm#94) is the use→reaching-def chain for the graph AS IT IS when
// this runs; the narrow-integral pass reads it to see that a use's value is a
// lone constant. Null (the unit-parity callers) means no such exemption.
void FixInitResultTypes(
    Graph& graph, const std::string& ret_type = {},
    const std::unordered_map<std::string, std::string>& declared_params = {},
    const ChainMap* ud = nullptr);

// Beyond-DAD: materialise a reused `this` register as a fresh local.
//
// When a method reuses its receiver register (p0) as a scratch local — reading
// `this` early, then overwriting it (`move-result` / `const 0`) and reading the
// new value later, the two merging at a shared use — GroupVariables collapses
// the param-def and the reuse-defs into ONE version (they share the merge use),
// so SplitVariables leaves it unsplit and the register keeps its `ThisParam`
// identity. DAD (and our 1:1 port) then emit `this = <value>` — always invalid
// Java (you cannot assign to `this`). Confirmed same bug in androguard DAD.
//
// Fix (validate-then-mutate — atomic): (1) allocate a fresh local `vX` typed as
// the method's RETURN type, (2) rewrite every graph reference to the receiver →
// `vX`, (3) inject `vX = this` at the entry block head. The sole remaining `this`
// is the entry copy's rhs → `<Ret> vX = this; … vX = …; return vX;` (valid). Runs
// AFTER SplitVariables (so a surviving `this =` LHS is exactly the unsplit-reuse
// case — a split reuse was already renamed to `vN`) and BEFORE the chain
// consumers, which requires the caller to recompute BuildDefUse after a `true`
// return (the injected copy + renumbered locs).
//
// TYPE SAFETY: `vX` is typed as an ANCHOR — a reference type the receiver's value
// is pinned to by a TYPED SINK it flows to: a `return this` (the method return
// type) or a reference argument `m(…, this, …)` (the parameter type). A single
// consistent reference anchor is required (two differing sinks → bail). The pass
// fires only when it can PROVE the injected `<anchor> vX = this` up-cast is valid,
// i.e. cls_name <: anchor, via EITHER (a) the injected `is_assignable` class-
// hierarchy oracle (cls's superclass/interface chain — handles a subtype up-cast
// like `List vX = this` where cls implements List), OR (b) the entry `this`
// REACHES an anchor sink through a reassignment-free CFG path (the verifier then
// proves cls_name <: anchor, covering framework-transitive chains the dex-only
// oracle cannot see). Every reassignment must likewise be `is_assignable` to the
// anchor (subtype ok) or the narrow-integer constant 0 (null). A non-reference
// sink, a sink conflict, an unprovable up-cast, a genuine primitive (`this = 5`),
// or a void-invoke artifact all bail, leaving DAD's (invalid but no-worse)
// `this = X`. Excludes `<init>` (super()/this() uses the receiver specially).
// `is_assignable` may be null → falls back to exact-equality (conservative).
// Returns true iff it materialised (the caller then recomputes chains).
bool MaterializeReusedThis(Graph& graph,
                           std::unordered_map<int, IRFormPtr>& lvars,
                           int this_reg, const std::string& cls_name,
                           const std::string& ret_type, bool is_ctor,
                           const std::function<bool(std::string_view,
                                                    std::string_view)>&
                               is_assignable);

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

// Beyond-DAD (dexllm#121): `new-instance vA` makes an UNINITIALIZED reference
// and `invoke-direct {vA, ...} <init>` initializes that same object in place,
// so a `move-object vD, vA` between the two copies a reference that, once the
// constructor has run, IS the constructed object. DAD models the constructor as
// a fresh definition of vA alone (`vA = vA.<init>(...)`), which leaves vD reading
// the pre-construction definition: RegisterPropagation then cannot fold
// `new X` into its <init> (the allocation has two uses) and the Writer renders
// the constructor as a call on a variable, `vA(args)`.
//
// Within one basic block, runs the <init> on the allocation's own register
// (d8's /range form names a COPY as the receiver) and hoists every copy to just
// after it, so each copy reads the constructed value. Moving it is semantics-preserving because an
// uninitialized reference admits no use but a move and its own <init> (ART's
// method verifier); the pass also refuses whenever an instruction in between
// reads or writes vA or a copy's destination, or the <init> is not in the same
// block, so on a crafted dex that breaks that rule it does nothing.
// Runs after Construct and before BuildDefUse; returns true iff it reordered
// anything (the caller then renumbers the graph).
bool HoistUninitializedCopies(Graph& graph);

// Beyond-DAD (dexllm#122): the locals a `try` statement must declare BEFORE
// itself. Java scopes a local to the block it is declared in and the emitters
// declare a local at its first assignment, so a local defined in the try body
// (or in one of its catches) and read anywhere outside that body names nothing
// there. `bodies` are the try's start and each catch's start; a body's region is
// what the emitter will write inside it -- the nodes reached from its start
// without passing a node `stop` says belongs to an enclosing structure (a
// follow, or a node already written). Every other instruction in the method
// counts as outside, so a use the walk cannot attribute (a short-circuit
// condition) only ever adds a declaration, which is still valid Java. Returns
// undeclared Variables, never a parameter, `this` or a catch variable (its
// declaration is the `catch (T v)` itself), ordered by first definition loc
// then name -- a total order, independent of pointer values.
struct ScopeIndex;  // built once per emission (BuildScopeIndex)
std::shared_ptr<const ScopeIndex> BuildScopeIndex(const Graph& graph);
std::vector<Variable*> ScopeEscapingDefs(
    const Graph& graph, const ScopeIndex& index,
    const std::vector<NodeBase*>& bodies,
    const std::function<bool(NodeBase*)>& stop);

}  // namespace dexkit::dad
