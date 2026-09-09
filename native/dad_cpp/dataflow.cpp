// dataflow.cpp — DAD dataflow.py port.
// See include/dataflow.h for entity list & status.

#include "dataflow.h"

#include <algorithm>
#include <cstdio>
#include <cstdlib>
#include <functional>
#include <iterator>
#include <memory>
#include <set>
#include <string>
#include <string_view>
#include <utility>

namespace dexkit::dad {

namespace {

// Helper: read an ins's LHS variable id (matches DAD `ins.get_lhs()` where
// non-None values are Variable objects keyed by their underlying register id).
// Returns empty string if no LHS (DAD's None case).
std::string GetLhsKey(const IRFormPtr& ins) {
    if (!ins) return {};
    auto opt = ins->GetLhsId();
    return opt.has_value() ? *opt : std::string{};
}

// Helper: drop a value from a vector (DAD's list.remove — first occurrence).
template <typename T>
void EraseFirst(std::vector<T>& v, const T& val) {
    auto it = std::find(v.begin(), v.end(), val);
    if (it != v.end()) v.erase(it);
}

// Helper: typed access to a node's loc-with-ins iterator (DummyNode returns
// empty; BasicBlock returns its loc_ins).
std::vector<std::pair<int, IRFormPtr>> LocWithIns(NodeBase* n) {
    if (auto* bb = dynamic_cast<BasicBlock*>(n)) {
        return bb->get_loc_with_ins();
    }
    return {};
}

}  // namespace

// =============================================================================
// BasicReachDef — DAD dataflow.py:27
// =============================================================================

BasicReachDef::BasicReachDef(Graph& graph,
                             const std::vector<std::string>& params)
    : g(graph) {
    // DAD: entry = graph.entry
    //      self.A[entry] = set(range(-1, -len(params) - 1, -1))
    //      for loc, param in enumerate(params, 1):
    //          self.defs[entry][param].add(-loc)
    //          self.def_to_loc[param].add(-loc)
    NodeBase* entry = graph.entry;
    if (entry) {
        auto& a_set = A[entry];
        for (size_t i = 0; i < params.size(); ++i) {
            const int loc = -static_cast<int>(i + 1);
            a_set.insert(loc);
            defs[entry][params[i]].insert(loc);
            def_to_loc[params[i]].insert(loc);
        }
    }
    // DAD: for node in graph.rpo:
    //          for i, ins in node.get_loc_with_ins():
    //              kill = ins.get_lhs()
    //              if kill is not None:
    //                  self.defs[node][kill].add(i)
    //                  self.def_to_loc[kill].add(i)
    //          for defs, values in self.defs[node].items():
    //              self.DB[node].add(max(values))
    for (NodeBase* node : graph.rpo) {
        for (const auto& [i, ins] : LocWithIns(node)) {
            std::string kill = GetLhsKey(ins);
            if (!kill.empty()) {
                defs[node][kill].insert(i);
                def_to_loc[kill].insert(i);
            }
        }
        auto dit = defs.find(node);
        if (dit != defs.end()) {
            for (const auto& [reg, vals] : dit->second) {
                if (!vals.empty()) DB[node].insert(*vals.rbegin());
            }
        }
    }
}

void BasicReachDef::run() {
    // DAD: nodes = list(self.g.rpo); while nodes: node = nodes.pop(0); ...
    std::vector<NodeBase*> nodes(g.rpo.begin(), g.rpo.end());
    while (!nodes.empty()) {
        NodeBase* node = nodes.front();
        nodes.erase(nodes.begin());

        // DAD: newR = set(); for pred in g.all_preds(node): newR.update(A[pred])
        std::set<int> newR;
        for (NodeBase* pred : g.all_preds(node)) {
            const auto& a = A[pred];
            newR.insert(a.begin(), a.end());
        }
        if (!newR.empty() && newR != R[node]) {
            R[node] = newR;
            for (NodeBase* suc : g.all_sucs(node)) {
                if (std::find(nodes.begin(), nodes.end(), suc) ==
                    nodes.end()) {
                    nodes.push_back(suc);
                }
            }
        }

        std::set<int> killed_locs;
        auto dit = defs.find(node);
        if (dit != defs.end()) {
            for (const auto& [reg, _] : dit->second) {
                auto kit = def_to_loc.find(reg);
                if (kit != def_to_loc.end()) {
                    killed_locs.insert(kit->second.begin(), kit->second.end());
                }
            }
        }

        std::set<int> Aset;
        for (int loc : R[node]) {
            if (killed_locs.find(loc) == killed_locs.end()) Aset.insert(loc);
        }
        std::set<int> newA(Aset);
        newA.insert(DB[node].begin(), DB[node].end());
        if (newA != A[node]) {
            A[node] = newA;
            for (NodeBase* suc : g.all_sucs(node)) {
                if (std::find(nodes.begin(), nodes.end(), suc) ==
                    nodes.end()) {
                    nodes.push_back(suc);
                }
            }
        }
    }
}

// =============================================================================
// update_chain — DAD dataflow.py:80
// =============================================================================
void UpdateChain(Graph& graph, int loc, ChainMap& du, ChainMap& ud) {
    IRFormPtr ins = graph.get_ins_from_loc(loc);
    if (!ins) return;
    for (const auto& var : ins->get_used_vars()) {
        VarLocKey ud_key{var, loc};
        std::vector<int> def_locs;
        auto udit = ud.find(ud_key);
        if (udit != ud.end()) {
            std::set<int> uniq(udit->second.begin(), udit->second.end());
            def_locs.assign(uniq.begin(), uniq.end());
        }
        for (int def_loc : def_locs) {
            VarLocKey du_key{var, def_loc};
            auto& du_vec = du[du_key];
            EraseFirst(du_vec, loc);
            auto& ud_vec = ud[ud_key];
            EraseFirst(ud_vec, def_loc);
            auto ud_it = ud.find(ud_key);
            if (ud_it != ud.end() && ud_it->second.empty()) {
                ud.erase(ud_it);
            }
            if (def_loc >= 0 && du_vec.empty()) {
                du.erase(du_key);
                IRFormPtr def_ins = graph.get_ins_from_loc(def_loc);
                if (!def_ins) continue;
                if (def_ins->is_call()) {
                    def_ins->remove_defined_var();
                } else if (def_ins->has_side_effect()) {
                    continue;
                } else {
                    UpdateChain(graph, def_loc, du, ud);
                    graph.remove_ins(def_loc);
                }
            }
        }
    }
}

// =============================================================================
// dead_code_elimination — DAD dataflow.py:116
// =============================================================================
void DeadCodeElimination(Graph& graph, ChainMap& du, ChainMap& ud) {
    std::vector<NodeBase*> rpo_snapshot(graph.rpo.begin(), graph.rpo.end());
    for (NodeBase* node : rpo_snapshot) {
        for (const auto& [i, ins] : LocWithIns(node)) {
            if (!ins) continue;
            std::string reg = GetLhsKey(ins);
            if (reg.empty()) continue;
            VarLocKey key{reg, i};
            if (du.find(key) == du.end()) {
                if (ins->is_call()) {
                    ins->remove_defined_var();
                } else if (ins->has_side_effect()) {
                    continue;
                } else {
                    UpdateChain(graph, i, du, ud);
                    graph.remove_ins(i);
                }
            }
        }
    }
}

// =============================================================================
// clear_path_node / clear_path — DAD dataflow.py:148/162
// =============================================================================
bool ClearPathNode(Graph& graph, const std::string& reg, int loc1, int loc2) {
    for (int loc = loc1; loc < loc2; ++loc) {
        IRFormPtr ins = graph.get_ins_from_loc(loc);
        if (!ins) continue;
        std::string lhs = GetLhsKey(ins);
        if (!reg.empty() && lhs == reg) return false;
        if (ins->has_side_effect()) return false;
    }
    return true;
}

bool ClearPath(Graph& graph, const std::string& reg, int loc1, int loc2) {
    NodeBase* node1 = graph.get_node_from_loc(loc1);
    NodeBase* node2 = graph.get_node_from_loc(loc2);
    if (node1 == node2) {
        return ClearPathNode(graph, reg, loc1 + 1, loc2);
    }
    auto* bb1 = dynamic_cast<BasicBlock*>(node1);
    if (!bb1 || !bb1->has_ins_range) return false;
    if (!ClearPathNode(graph, reg, loc1 + 1, bb1->ins_range_hi)) return false;
    auto path = BuildPath(graph, node1, node2);
    for (NodeBase* p : path) {
        auto* bb = dynamic_cast<BasicBlock*>(p);
        if (!bb || !bb->has_ins_range) continue;
        const int lo = bb->ins_range_lo;
        const int hi = bb->ins_range_hi;
        const int end_loc = (lo <= loc2 && loc2 <= hi) ? loc2 : hi;
        if (!ClearPathNode(graph, reg, lo, end_loc)) return false;
    }
    return true;
}

// =============================================================================
// register_propagation — DAD dataflow.py:190
// =============================================================================
void RegisterPropagation(Graph& graph, ChainMap& du, ChainMap& ud) {
    bool change = true;
    while (change) {
        change = false;
        std::vector<NodeBase*> rpo_snapshot(graph.rpo.begin(),
                                            graph.rpo.end());
        for (NodeBase* node : rpo_snapshot) {
            for (const auto& [i, ins] : LocWithIns(node)) {
                if (!ins) continue;
                for (const auto& var : ins->get_used_vars()) {
                    VarLocKey ud_key{var, i};
                    auto udit = ud.find(ud_key);
                    if (udit == ud.end()) continue;
                    const auto& locs = udit->second;
                    if (locs.size() != 1) continue;
                    const int loc = locs[0];
                    if (loc < 0) continue;
                    // Beyond-DAD (dexllm#76) — a definition is never
                    // propagated INTO ITSELF.  `ud[{var, i}] == {i}` says the
                    // only definition of `var` reaching the use at `i` is the
                    // one `i` makes, which is a circular data dependency: a
                    // loop back edge carries `i`'s own def to `i`'s own use,
                    // and no other def reaches, i.e. the register is READ
                    // BEFORE IT IS EVER WRITTEN.  ART's runtime verifier
                    // rejects that; the structural verifier this port mirrors
                    // does not (instruction dataflow is out of its documented
                    // scope), so such a dex loads and `verify()` calls it valid
                    // in BOTH modes.  Substituting a value into its own
                    // computation is meaningless, and mechanically it splices
                    // `ins`'s own rhs underneath itself — `BinaryExpression::
                    // replace` does `var_map[old_v] = new_node`, so the node
                    // becomes its own operand and `get_used_vars` recurses
                    // without bound: an uncatchable SIGSEGV (a signal unwinds
                    // nothing, so the per-method catch and safe.py's deadline
                    // both miss it).  Upstream DAD has no such guard —
                    // dataflow.py goes from `if loc < 0: continue` (:219)
                    // straight to `get_ins_from_loc(loc)` (:221) — and it
                    // hits the identical defect on the identical bytes.
                    // Same family as the `SplitVariables` no-op recorded
                    // under "Root-cause fixes": a variable substituted
                    // into its own def chain.  Skipping is a pure no-op —
                    // everything below this point MUTATES (replace, the
                    // ud/du rewrite, remove_ins, change), nothing is read
                    // and abandoned, so no chain is left half-rewritten
                    // and the outer fixpoint cannot gain an iteration.
                    if (loc == i) continue;
                    IRFormPtr orig_ins = graph.get_ins_from_loc(loc);
                    if (!orig_ins) continue;
                    if (!orig_ins->is_propagable()) continue;

                    auto rhs_vec = orig_ins->get_rhs();
                    IRFormPtr rhs = rhs_vec.empty() ? nullptr : rhs_vec[0];
                    const bool rhs_is_const = rhs && rhs->is_const();
                    if (!rhs_is_const) {
                        VarLocKey du_key{var, loc};
                        auto duit = du.find(du_key);
                        if (duit == du.end()) continue;
                        if (duit->second.size() > 1) continue;
                        bool safe = true;
                        for (const auto& var2 : orig_ins->get_used_vars()) {
                            if (!ClearPath(graph, var2, loc, i)) {
                                safe = false;
                                break;
                            }
                        }
                        if (!safe) continue;
                    }
                    if (orig_ins->has_side_effect()) {
                        if (!ClearPath(graph, /*reg=*/{}, loc, i)) continue;
                    }
                    if (rhs) ins->replace(var, rhs);

                    EraseFirst(ud[ud_key], loc);
                    if (ud[ud_key].empty()) ud.erase(ud_key);

                    for (const auto& var2 : orig_ins->get_used_vars()) {
                        VarLocKey ud_v2_loc{var2, loc};
                        auto udo = ud.find(ud_v2_loc);
                        if (udo == ud.end()) continue;
                        auto old_ud = udo->second;
                        auto& ud_v2_i = ud[VarLocKey{var2, i}];
                        ud_v2_i.insert(ud_v2_i.end(), old_ud.begin(),
                                       old_ud.end());
                        ud.erase(udo);
                        for (int def_loc : old_ud) {
                            VarLocKey du_v2_dl{var2, def_loc};
                            auto& vec = du[du_v2_dl];
                            EraseFirst(vec, loc);
                            vec.push_back(i);
                        }
                    }
                    VarLocKey du_key{var, loc};
                    auto& new_du = du[du_key];
                    EraseFirst(new_du, i);
                    if (new_du.empty()) {
                        du.erase(du_key);
                        graph.remove_ins(loc);
                        change = true;
                    }
                }
            }
        }
    }
}

// Beyond-DAD — see dataflow.h. Re-type `<init>` results from the finalized base.
// Beyond-DAD (design §1 — allocation ground truth). Re-type a version whose
// value is a `new`/`<init>`/move-from-allocation result but which DAD typed
// non-reference (or a wrong reference for a single-def authoritative result).
// See docs/type-inference-design.md and the per-branch comments below.
static void FixAllocationResultTypes(Graph& graph) {
    auto is_ref = [](const std::string& t) {
        return !t.empty() && (t.front() == 'L' || t.front() == '[');
    };
    // The move-from-reference recovery below (`vDst = move vSrc`) is restricted
    // to vSrc being a freshly-ALLOCATED object (new-instance / new-array): the
    // allocation is unambiguously a reference, so a register that receives the
    // move IS that object, and recovering its type is sound. We deliberately do
    // NOT promote a move whose source is merely ref-TYPED (a method result, a
    // catch var, another move) — an adversarial expanded-sample review showed
    // that mistypes genuinely-conflated int/ref registers (DAD reuses one Dalvik
    // register for both), producing uncompilable Java (`String v = -1`,
    // `SolverVariable v = 6`, an `int` loop counter typed as a reference and
    // used in `arr[v]` / `v++`). Allocation sources carry no such ambiguity.
    // Pre-map each version to its single defining instruction (skip multi-def
    // versions — a conflated source is not a clean allocation).
    std::unordered_map<std::string, IRForm*> def_ins;
    std::unordered_set<std::string> multi_def;
    for (NodeBase* n : graph.nodes) {
        auto* bb = dynamic_cast<BasicBlock*>(n);
        if (!bb) continue;
        for (auto& ins : bb->get_ins()) {
            if (!ins) continue;
            auto lid = ins->GetLhsId();
            if (!lid) continue;
            if (def_ins.count(*lid)) { multi_def.insert(*lid); continue; }
            def_ins[*lid] = ins.get();
        }
    }
    auto source_is_allocation = [&](IRForm* src) -> bool {
        if (!src) return false;
        const std::string sid = src->Vid();
        if (multi_def.count(sid)) return false;       // conflated source
        auto dit = def_ins.find(sid);
        if (dit == def_ins.end() || !dit->second) return false;
        auto srhs = dit->second->get_rhs();
        if (srhs.empty() || !srhs[0]) return false;
        return dynamic_cast<NewInstance*>(srhs[0].get()) ||
               dynamic_cast<NewArrayExpression*>(srhs[0].get());
    };

    for (NodeBase* n : graph.nodes) {
        auto* bb = dynamic_cast<BasicBlock*>(n);
        if (!bb) continue;
        for (auto& ins : bb->get_ins()) {
            if (!ins) continue;
            auto rhs = ins->get_rhs();
            if (rhs.empty() || !rhs[0]) continue;
            auto lid = ins->GetLhsId();
            if (!lid) continue;
            // The constructed/allocated object's reference type. For an <init>
            // invoke get_type() returns the FINALIZED base (receiver) type; for
            // a direct new-instance / new-array the rhs's own type is the class
            // / array descriptor (static). All three define a register that can
            // only legally hold a reference, so a non-reference lhs is the bug.
            std::string bt;
            // `authoritative` — the result's type is DEFINITIONALLY the
            // constructed class (a direct new-instance / new-array, or an <init>
            // whose base resolves to the class). Such a result can be a WRONG
            // reference too, not just a mistyped primitive: register conflation
            // (e.g. the slot reused as a `catch (Throwable v)` variable) makes
            // split_variables type the <init> result `Throwable`, which
            // get_type()'s `!is_ref` gate below would leave untouched. For a
            // SINGLE-def authoritative result we override even a reference,
            // because the object IS exactly that class. A move source (PR#7,
            // below) is NOT authoritative in this sense — kept non-ref-only.
            bool authoritative = false;
            if (auto* inv = dynamic_cast<InvokeInstruction*>(rhs[0].get())) {
                if (inv->name() == "<init>") {
                    bt = inv->get_type();
                    // A `invoke-direct/range` <init> (InvokeRangeInstruction)
                    // carries no separate base, so get_type() falls back to its
                    // "V" rtype. The constructed object's type is the class —
                    // use cls() when get_type() isn't a reference.
                    if (!is_ref(bt)) bt = inv->cls();
                    authoritative = true;
                }
            } else if (dynamic_cast<NewInstance*>(rhs[0].get()) ||
                       dynamic_cast<NewArrayExpression*>(rhs[0].get())) {
                bt = rhs[0]->get_type();
                authoritative = true;
            } else if (rhs[0]->is_ident() && source_is_allocation(rhs[0].get())) {
                // `vDst = move vNew` where vNew is a fresh new-instance/new-array
                // (e.g. `new-instance v10` → `move-object v0, v10` →
                // `invoke-direct/range {v0..} <init>`). split_variables' move-
                // source ref-trust read a STALE primitive for vNew (its
                // reference version finalized in a LATER split iteration than
                // vDst), so it didn't trust it and vDst kept orig_type (int).
                // The source is an allocation → unambiguously a reference, so
                // recover its type now that all versions are final.
                if (is_ref(rhs[0]->get_type())) bt = rhs[0]->get_type();
            }
            if (!is_ref(bt)) continue;
            auto it = ins->var_map.find(*lid);
            if (it == ins->var_map.end() || !it->second) continue;
            const std::string cur = it->second->get_type();
            // Correct: (a) the classic non-reference result of `new` (int → ref),
            // OR (b) a SINGLE-def AUTHORITATIVE result whose current type is a
            // DIFFERENT reference — a conflation artifact (e.g. `Throwable` from a
            // reused catch slot). Multi-def is excluded: a conflated int/ref
            // register genuinely typed as a supertype merge must keep its type
            // (PR#7 regression lesson). The ref-override also EXCLUDES a ThisParam
            // lhs: a `super()`/`this()` via invoke-direct/range keeps returned=base
            // (no ThisParam guard in InvokeDirectRange, unlike InvokeDirect), so
            // the <init> result can be `this` with cls() = the SUPERCLASS —
            // re-typing it would corrupt `this` and flip the writer's super-vs-this
            // detection. `this` is never a mistyped allocation result, so a
            // structural exclusion is free (review-hardening; the multi_def guard
            // happened to block the in-corpus cases but that is data-dependent).
            const bool fix =
                !is_ref(cur) ||
                (authoritative && cur != bt && !multi_def.count(*lid) &&
                 !dynamic_cast<ThisParam*>(it->second.get()));
            if (fix) it->second->set_type(bt);
        }
    }

}

// Beyond-DAD (design §2/§3 — move-chain cascade/mirror, def-anchored +
// use-corroborated). Re-type a version whose declared type disagrees with its
// transitive ground-truth producers: a reference cascade artifact → its
// primitive (ref→prim), a primitive mistyped over a reference+null → the
// reference class (prim→ref mirror), or a too-narrow primitive → the def width.
// Two-phase classify-then-apply; every re-type is def-anchored and, where it
// could be ambiguous, use-corroborated. See docs/type-inference-design.md.
static void InferCascadeTypes(
    Graph& graph, const std::string& ret_type,
    const std::unordered_map<std::string, std::string>& declared_params) {
    auto is_ref = [](const std::string& t) {
        return !t.empty() && (t.front() == 'L' || t.front() == '[');
    };
    // Beyond-DAD — re-type move-chain type CASCADE versions (dataflow.h).
    // A register reused across incompatible types leaves split versions typed by
    // the register's last write (DAD types every version from orig_var.type).
    // Where a version is currently a REFERENCE but its transitive GROUND-TRUTH
    // producers are all primitive/null (NO allocation / method-ref / field-ref /
    // cast / array anywhere in its def closure, resolving moves to their ultimate
    // source), the reference type is a cascade artifact — a move copied a stale
    // reference type off a sibling conflated register. Such a version is genuinely
    // a primitive (an obfuscator's 0/1 flag reusing an object register), so DAD /
    // our own last-write typing emits uncompilable `ArrayList v = 1;`. We re-type
    // it to its primitive descriptor. This is def-anchored + use-corroborated: we
    // ONLY re-type when there is no ground-truth reference AND the version is never
    // an object receiver (a `v.m()` use would prove it holds an object — in valid
    // Dalvik that implies a reference producer we must not have missed). A version
    // with BOTH a real allocation AND a real primitive forcer is a GENUINE merge
    // (needs a version split, not a re-type) and is left untouched — the narrow
    // splitting pass handles those. Regression-safe direction: we only make an
    // object-less version primitive, never the reverse (never re-introduces
    // `prim = new`), and the receiver guard prevents creating `prim.member`.
    // Vid → all defining instructions (multi included).
    std::unordered_map<std::string, std::vector<IRForm*>> defs_of;
    // Vids used AS AN OBJECT anywhere — a receiver of `v.m()`, the owner of a
    // field access `v.f` / `v.f = …`, etc. Such a version provably holds an
    // object, so it is never re-typed to a primitive (use corroboration —
    // guards against a missed reference producer creating `int v; v.f`).
    std::unordered_set<std::string> object_vids;
    // Vids used in an INTEGER context — an arithmetic operand, an array
    // index, or a unary operand (incl. a primitive cast). Such a version
    // provably holds a primitive, so the prim→ref MIRROR never re-types it
    // (use-corroboration symmetric to object_vids for the ref→prim cascade).
    std::unordered_set<std::string> int_use_vids;
    // Vids used where an INT is specifically REQUIRED and a wider primitive
    // is invalid: an array INDEX (`arr[v]`), a `switch` selector
    // (`switch(v)` — long/float/double are not switchable), or an array
    // CREATION size (`new int[v]`). These break a WIDENING re-type
    // (int→long/float/double) whereas ordinary arithmetic / comparison on a
    // wide value is fine, so the prim→wider branch guards on this narrower set
    // (not all `int_use_vids`).
    std::unordered_set<std::string> int_required_vids;
    // Vids used as the ARRAY BASE of an aget / aput / array-length — such a
    // version is provably an ARRAY (`arr[i]`, `arr.length` require an array
    // operand in valid Dalvik). Where DAD typed it a non-array (e.g. `Object`
    // from a conflation / a lost move-source array type), we re-type it to the
    // array type recovered from its def(s), so every array use becomes valid at
    // once (root-cause, vs a per-use `((T[]) v)` cast).
    std::unordered_set<std::string> array_use_vids;
    // Move-opcode ground truth (beyond-DAD): a vid used as the SOURCE of a
    // `move-object` provably holds a REFERENCE there; a vid used as the source of
    // a `move`/`move-wide` provably holds a PRIMITIVE there. These corroborate a
    // move-DEST re-type (below) AND, symmetrically, BLOCK it: a version whose def
    // is a plain move (→ prim) but which is ALSO a move-object source is a
    // GENUINE prim+ref conflation (no single type), so the guard leaves it.
    std::unordered_set<std::string> moveobj_src_vids;   // source of a move-object
    std::unordered_set<std::string> moveprim_src_vids;  // source of a move/-wide
    // `==`/`!=` ConditionalExpression operand pairs — resolved in a post-pass
    // (once defs_of is complete): if one operand is a nonzero int constant,
    // the other is proven a primitive and joins int_use_vids.
    std::vector<std::pair<std::string, std::string>> eqne_pairs;
    // dexllm#86 — vids RETURNED by a method whose declared return type is `Z`.
    // A use-bound BOOLEAN source, kept SEPARATE from the reference machinery
    // below (`arg_type`/`store_type`, which `record` gates on `is_ref`) because
    // the two need OPPOSITE soundness arguments — see the `Z` branch in the
    // classification loop.
    std::unordered_set<std::string> bool_ret_vids;
    // dexllm#86 — vids used where a NON-BOOLEAN PRIMITIVE is required: an invoke
    // argument at an `I`/`J`/`F`/`D`/`B`/`S`/`C` parameter, the value stored by
    // an `iput`/`sput` into such a field, and the value stored by a non-boolean
    // `aput`. `int_use_vids` covers arithmetic, ordered comparison and array
    // INDEXING and does NOT reach any of these — `note_obj` records an invoke
    // argument only when the parameter is a reference, and `record` drops a
    // non-reference field type on its first line — so a version used ONLY this
    // way looked unconstrained. **An adversarial review found that on unmodified
    // corpus input**: `AppCompatReceiveContentHelper`'s flag is `return`ed from a
    // `Z` method AND passed to `Builder.setFlags(I)`, so re-typing it turned
    // valid Java into `setFlags(boolean)`.
    //
    // A SEPARATE set, not a widening of `int_use_vids`, because that one is read
    // by the cascade / mirror / prim→WIDER branches: widening it would change
    // their verdicts and need their own a/b. This set is consulted by the `Z`
    // branch and its propagation and by nothing else.
    //
    // `Z` is excluded on purpose — passing a boolean at a `Z` parameter or
    // storing it into a `Z` field is exactly correct and must not block.
    std::unordered_set<std::string> prim_use_vids;
    auto is_prim_nonbool = [](const std::string& t) {
        return t.size() == 1 &&
               std::string("IJBSCFD").find(t[0]) != std::string::npos;
    };
    // USE-BOUND reference type (design §3): vid → the reference type a USE pins
    // on it. Unlike `object_vids` (a boolean object-use flag) this carries the
    // TYPE, so a primitive-typed version with NO genuine primitive producer (its
    // reference nature hidden in a conflated register, present only in the USE)
    // can be re-typed to the use's reference type — the v4 = p10(Function1)
    // shape. Sources (all `type(v) <: T` in verified Dalvik, so the def-derived
    // allocation would satisfy them — here we use them to TYPE a def-less
    // conflated version): a REFERENCE ARGUMENT (`f(…, v, …)` → paramType), a
    // FIELD STORE (`obj.f = v` / `Cls.f = v` → the field type), and a THROW
    // (`throw v` → Throwable). `ref_use_conflict` holds vids pinned at ≥2
    // DIFFERENT types (kept exact-match-conservative: skip on disagreement
    // rather than compute a least-upper-bound). A RETURN is a source too
    // (Phase 2c — `ret_type` is threaded in from the method meta), but only
    // for a REFERENCE return type: `record` drops everything else, which is
    // why a `Z` return needs the separate channel below (dexllm#86).
    // ARRAY-STORE is still NOT a source — the element type needs the array's
    // own type (deferred, design §3 residual).
    // Two TIERS, so a lower-priority source can never disable a higher one by
    // introducing a spurious conflict. PRIMARY = a reference ARGUMENT (a param
    // type is exact and reliable). FALLBACK = a field store / throw (used only
    // when no ref-arg pins the vid). A conflict WITHIN a tier (two different
    // types) skips THAT tier; the primary always wins over the fallback (which
    // preserves every ref-arg re-type exactly — a field store to an unrelated
    // type does not revert it, matching the pre-extension committed behaviour).
    std::unordered_map<std::string, std::string> arg_type, store_type;
    std::unordered_set<std::string> arg_conflict, store_conflict;
    auto record = [&](std::unordered_map<std::string, std::string>& m,
                      std::unordered_set<std::string>& c,
                      const std::string& vid, const std::string& t) {
        if (vid.empty() || !is_ref(t)) return;
        object_vids.insert(vid);
        auto it = m.find(vid);
        if (it == m.end()) m[vid] = t;
        else if (it->second != t) c.insert(vid);
    };
    auto note_ref_arg = [&](const std::string& vid, const std::string& t) {
        record(arg_type, arg_conflict, vid, t);
    };
    auto note_ref_store = [&](const std::string& vid, const std::string& t) {
        record(store_type, store_conflict, vid, t);
    };
    // Resolve the use-bound reference type for a vid: the primary (ref-arg) if
    // present and unconflicted; else the fallback (field-store/throw) if present
    // and unconflicted; else empty (no re-type). A PRESENT-but-CONFLICTED
    // primary returns EMPTY — it does NOT descend to the fallback: a vid passed
    // at two DIFFERENT ref-param types is a genuine least-upper-bound case no
    // exact-match tier can satisfy, and the store/throw type is not more
    // trustworthy than the arg types it disagrees with — descending could
    // re-type to a type incompatible with the arg uses (`Runnable v` passed at
    // `m(List v)`; adversarial + correctness review converged on this). So a
    // conflicted primary is left as DAD's type (no-worse), not guessed.
    auto ref_use_type = [&](const std::string& vid) -> std::string {
        auto a = arg_type.find(vid);
        if (a != arg_type.end())
            return arg_conflict.count(vid) ? std::string{} : a->second;
        auto s = store_type.find(vid);
        if (s != store_type.end() && !store_conflict.count(vid)) return s->second;
        return {};
    };
    auto note_obj = [&](IRForm* f) {
        if (auto* inv = dynamic_cast<InvokeInstruction*>(f)) {
            if (!inv->base().empty()) object_vids.insert(inv->base());
            // A value passed at a REFERENCE parameter position is provably a
            // reference in valid Dalvik (you cannot pass an int where a `Lcls;`/
            // array param is declared), so it corroborates the object type — the
            // mirror re-types a `prim v` used ONLY as `m(v)` at a ref-arg (e.g.
            // `int v3 = findViewById(); removeView(v3)` → `View v3`), and the
            // ref→prim cascade conservatively skips it. args↔ptype are 1:1
            // (ParseParamsType); a size mismatch (varargs edge) is skipped.
            const auto& a = inv->args();
            const auto& pt = inv->ptype();
            if (a.size() == pt.size())
                for (size_t i = 0; i < a.size(); ++i) {
                    if (a[i].empty()) continue;
                    if (is_ref(pt[i])) note_ref_arg(a[i], pt[i]);
                    // dexllm#86 — a NON-BOOLEAN primitive parameter position.
                    else if (is_prim_nonbool(pt[i])) prim_use_vids.insert(a[i]);
                }
        } else if (auto* ie = dynamic_cast<InstanceExpression*>(f)) {
            if (!ie->arg_id().empty()) object_vids.insert(ie->arg_id());
        } else if (auto* ii = dynamic_cast<InstanceInstruction*>(f)) {
            // iput `obj.field = rhs`: the OWNER is an object; the STORED value is
            // pinned (fallback tier) to the field's declared type (atype).
            if (!ii->lhs_id().empty()) object_vids.insert(ii->lhs_id());
            note_ref_store(ii->rhs_id(), ii->atype());
            if (!ii->rhs_id().empty() && is_prim_nonbool(ii->atype()))
                prim_use_vids.insert(ii->rhs_id());   // dexllm#86
        } else if (auto* si = dynamic_cast<StaticInstruction*>(f)) {
            // sput `Cls.field = rhs`: the stored value is pinned to the field type.
            note_ref_store(si->rhs_id(), si->ftype());
            if (!si->rhs_id().empty() && is_prim_nonbool(si->ftype()))
                prim_use_vids.insert(si->rhs_id());   // dexllm#86
        } else if (auto* te = dynamic_cast<ThrowExpression*>(f)) {
            // `throw v`: v is a Throwable in verified Dalvik (only a reference is
            // throwable). Cast to ThrowExpression SPECIFICALLY — a sibling
            // RefExpression (MoveExceptionExpression) carries its ref as a catch
            // DEF, not a use, so a generic RefExpression branch would misread it.
            note_ref_store(te->ref_id(), "Ljava/lang/Throwable;");
        } else if (auto* ret = dynamic_cast<ReturnInstruction*>(f)) {
            // `return v`: v is assignment-compatible with the method's declared
            // return type, so a REFERENCE return type pins v as that reference
            // (fallback tier — a return type can be a supertype of the value, so
            // a more specific ref-arg use wins). `ret_type` is the Dalvik
            // descriptor threaded in from the method meta.
            if (ret->arg()) {
                note_ref_store(*ret->arg(), ret_type);
                // dexllm#86 — `record` above keeps only a REFERENCE type, so a
                // `Z` return type was dropped and the returned flag kept DAD's
                // `int`, giving the uncompilable `boolean m(){ int v=1; …
                // return v; }`. Record it on its own channel; the branch that
                // consumes it carries the boolean-specific proof.
                if (ret_type == "Z" && !ret->arg()->empty())
                    bool_ret_vids.insert(*ret->arg());
            }
        }
    };
    auto note_int = [&](IRForm* f) {
        auto add = [&](const std::string& v) {
            if (!v.empty()) int_use_vids.insert(v); };
        // A UnaryExpression covers CastExpression (a prim cast); a reference
        // check-cast is a separate CheckCastExpression, so this stays int.
        if (auto* be = dynamic_cast<BinaryExpression*>(f)) {
            // `instanceof` is lowered to a BinaryExpression whose arg1 is the
            // tested OBJECT (a reference), not an integer — exclude it so a
            // `v instanceof T` use does not falsely corroborate an int type.
            if (be->op() != "instanceof") {
                add(be->arg1_id()); add(be->arg2_id());
            }
        } else if (auto* ue = dynamic_cast<UnaryExpression*>(f)) {
            add(ue->arg_id());
        } else if (auto* al = dynamic_cast<ArrayLoadExpression*>(f)) {
            add(al->idx_id());
            if (!al->idx_id().empty())
                int_required_vids.insert(al->idx_id());
        } else if (auto* as = dynamic_cast<ArrayStoreInstruction*>(f)) {
            add(as->index_id());
            if (!as->index_id().empty())
                int_required_vids.insert(as->index_id());
            // dexllm#86 — the STORED VALUE, which the index rule above does not
            // touch. An ArrayStoreInstruction carries the opcode's CATEGORY
            // marker as its type: "" (aput, int/float), "W", "B", "C", "S" are
            // non-boolean primitives; "Z" is a boolean array (correct, skip) and
            // "O" is an object (a different guard's business).
            if (!as->rhs_id().empty()) {
                const std::string& m = as->get_type();
                if (m.empty() || m == "W" || m == "B" || m == "C" || m == "S")
                    prim_use_vids.insert(as->rhs_id());
            }
        } else if (auto* fa = dynamic_cast<FilledArrayExpression*>(f)) {
            // dexllm#86 — `new int[]{v, …}`.  Each ELEMENT sits at the array's
            // element type, which is the FOURTH int-requiring position and the
            // one a delta review found still open after the other three were
            // closed: `new int[]{boolean}` does not compile, and javac + d8
            // produce the shape without any crafting (`sink(new int[]{ b ? 1 :
            // 0 })` folds the ternary onto the flag's own register).  A
            // `FilledArrayExpression` carries the ARRAY descriptor as its type,
            // so the element type is what follows the '['.
            //
            // STATED LIMIT — the `/range` form is NOT covered, and the reason is
            // one level down: `FilledNewArrayRange` is bug-faithful to DAD and
            // hands the expression only `{cccc, nnnn}`, so `args()` holds TWO
            // registers whatever the real element count is. The middle elements
            // are not in the IR at all, so no guard here can see them — such a
            // method's rendering is already lossy, with or without this pass.
            // Measured: 45 `/range` sites corpus-wide and **0** of them inside a
            // `)Z` method, so the residual is 0-incidence rather than latent.
            const std::string& at = fa->get_type();
            if (at.size() >= 2 && at[0] == '[' &&
                is_prim_nonbool(at.substr(1)))
                for (const std::string& e : fa->args())
                    if (!e.empty()) prim_use_vids.insert(e);
        } else if (auto* na = dynamic_cast<NewArrayExpression*>(f)) {
            // `new int[v]` — the CREATION size must be an int (a widened
            // long/float/double there is invalid). (The def-side new-array
            // itself is a reference producer, handled elsewhere; here we only
            // record its SIZE operand as an int-required use.)
            if (!na->size_id().empty())
                int_required_vids.insert(na->size_id());
        } else if (auto* sw = dynamic_cast<SwitchExpression*>(f)) {
            // `switch(v)` — the selector must be char/byte/short/int (never
            // long/float/double), so a widened selector is invalid Java.
            if (!sw->src_id().empty())
                int_required_vids.insert(sw->src_id());
        } else if (auto* cz = dynamic_cast<ConditionalZExpression*>(f)) {
            // vs-ZERO comparisons (if-ltz/lez/gtz/gez → `<`/`<=`/`>`/`>=`)
            // require a numeric operand; if-eqz/nez (`==`/`!=`) are the
            // reference null-check, so only the ordered ops prove an int use.
            const std::string& op = cz->op();
            if (op == "<" || op == "<=" || op == ">" || op == ">=") {
                add(cz->arg_id());
            }
        } else if (auto* ce = dynamic_cast<ConditionalExpression*>(f)) {
            // ORDERED comparisons (`<`/`<=`/`>`/`>=`) require numeric
            // operands; `==`/`!=` also work on references (object identity /
            // null check), so only the ordered ops prove an integer use here.
            const std::string& op = ce->op();
            if (op == "<" || op == "<=" || op == ">" || op == ">=") {
                add(ce->arg1_id()); add(ce->arg2_id());
            } else if (op == "==" || op == "!=") {
                // `v == <nonzero int const>` DOES prove v is a primitive (a
                // reference is `==` only to null or another reference, never a
                // nonzero literal). We cannot check the sibling's def here
                // (defs_of is still being built) — defer to a post-pass.
                eqne_pairs.emplace_back(ce->arg1_id(), ce->arg2_id());
            }
        }
    };
    for (NodeBase* n : graph.nodes) {
        auto* bb = dynamic_cast<BasicBlock*>(n);
        if (!bb) continue;
        for (auto& ins : bb->get_ins()) {
            if (!ins) continue;
            auto lid = ins->GetLhsId();
            if (lid) defs_of[*lid].push_back(ins.get());
            note_obj(ins.get());
            note_int(ins.get());
            auto note_arr = [&](IRForm* f) {
                if (auto* al = dynamic_cast<ArrayLoadExpression*>(f)) {
                    if (!al->array_id().empty())
                        array_use_vids.insert(al->array_id());
                } else if (auto* as = dynamic_cast<ArrayStoreInstruction*>(f)) {
                    if (!as->array_id().empty())
                        array_use_vids.insert(as->array_id());
                } else if (auto* aln = dynamic_cast<ArrayLengthExpression*>(f)) {
                    if (!aln->array_id().empty())
                        array_use_vids.insert(aln->array_id());
                }
            };
            note_arr(ins.get());
            // Move-opcode ground truth: record the SOURCE vid by kind. A
            // MoveResultExpression is a MoveExpression subclass but carries
            // MoveKind::Unknown, so it is naturally excluded.
            if (auto* mv = dynamic_cast<MoveExpression*>(ins.get())) {
                switch (mv->move_kind()) {
                    case MoveKind::Object:
                        if (!mv->rhs_id().empty())
                            moveobj_src_vids.insert(mv->rhs_id());
                        break;
                    case MoveKind::Plain:
                    case MoveKind::Wide:
                        if (!mv->rhs_id().empty())
                            moveprim_src_vids.insert(mv->rhs_id());
                        break;
                    default: break;
                }
            }
            auto rhs = ins->get_rhs();
            if (!rhs.empty() && rhs[0]) { note_obj(rhs[0].get());
                note_int(rhs[0].get()); note_arr(rhs[0].get()); }
        }
    }
    auto is_prim_desc = [](const std::string& t) {
        return t.size() == 1 &&
               std::string("IJZBSCFD").find(t[0]) != std::string::npos;
    };
    // POST-PASS: `v == <nonzero int const>` / `v != <nonzero>` proves v is a
    // primitive (a reference compares `==` only to null or another reference,
    // never to a nonzero literal). eq/ne were excluded from int_use above
    // because `== null` (const 0) is a valid null check; here we add the
    // operand whose SIBLING resolves to a NONZERO integer constant.
    // NOTE: this runs pre-RegisterPropagation (this pass precedes
    // register_propagation in decompile.cpp), so the compared constant is
    // still a distinct `const` def in defs_of and the operand is still its
    // register vid. If that order ever changed, this would silently no-op
    // (the inlined-const vid absent from defs_of) — a safe failure.
    auto is_nonzero_int_const = [&](const std::string& v) -> bool {
        if (v.empty()) return false;
        auto it = defs_of.find(v);
        if (it == defs_of.end()) return false;
        // PATH-ROBUSTNESS (adversarial-review): trust `v == <const>` as an
        // integer proof for the SIBLING only when `v` is UNAMBIGUOUSLY a
        // primitive — no reference def anywhere in its def set. A genuinely
        // int/ref-conflated `v` (a nonzero-int def on one arm, a reference def
        // on another) would path-insensitively mark its reference-arm
        // comparison partner as int-used and wrongly veto that partner's
        // prim→ref mirror (`int v = someObject()`). Requiring no reference def
        // makes the proof path-independent.
        bool has_nonzero = false;
        for (IRForm* d : it->second) {
            auto dr = d->get_rhs();
            if (dr.empty() || !dr[0]) continue;
            if (is_ref(dr[0]->get_type())) return false;  // conflated → refuse
            auto* c = dynamic_cast<Constant*>(dr[0].get());
            if (c && is_prim_desc(c->get_type()) && c->get_int_value() != 0)
                has_nonzero = true;
        }
        return has_nonzero;
    };
    for (auto& [a, b] : eqne_pairs) {
        if (!a.empty() && is_nonzero_int_const(b)) int_use_vids.insert(a);
        if (!b.empty() && is_nonzero_int_const(a)) int_use_vids.insert(b);
    }
    // Ground-truth of a def's rhs: 'R' ref producer, 'P' prim forcer,
    // 'N' null/zero-neutral, 'U' unknown, 'M' unresolved-move (cycle).
    // SAFETY-FIRST: 'P' only when the producer's OWN type is a genuine
    // primitive descriptor (or a structural const-nonzero / arithmetic);
    // 'R' whenever the type is a reference; everything else 'U'/'M'/'N'.
    // This guarantees a real object is NEVER mislabeled prim (the regression
    // direction — re-typing an object to int would reintroduce `prim=new`).
    // `type_out` receives the resolved concrete DESCRIPTOR of whatever the
    // producer is — the primitive width ('I'/'J'/…) when 'P' (so a long
    // cascade is not narrowed to `int v = <huge>`), or the reference
    // descriptor ('L…;'/'[…') when 'R' (so a mirror re-type below knows the
    // exact class). Set for BOTH 'P' and 'R'.
    // An UNAMBIGUOUS reference producer — a value that is definitionally an
    // object regardless of a possibly-corrupt declared type. Shared by `gt`
    // (→ 'R') and `resolve_prim_width` (→ "", no primitive width).
    auto is_alloc_producer = [](IRForm* r) {
        return dynamic_cast<NewInstance*>(r) ||
               dynamic_cast<NewArrayExpression*>(r) ||
               dynamic_cast<FilledArrayExpression*>(r) ||
               dynamic_cast<MoveExceptionExpression*>(r) ||
               dynamic_cast<CheckCastExpression*>(r);
    };
    // Work budget for gt(). The per-path DFS-stack backtracking below (needed so
    // a move-DIAMOND is not mistaken for a cycle) means a diamond's two arms are
    // RE-EXPLORED rather than short-circuited (the old shared-`seen`, never
    // popped, returned 'M' on the second arm), so a crafted chain of N nested
    // move-diamonds could drive O(2^N) gt() calls — an uncatchable CPU-spin hang on
    // machine-generated / lenient-load bytecode (adversarial-review finding, same
    // family as the emit-walk and ShortCircuitStruct hangs the project caps). Cap
    // the total gt() calls per pass; on exhaustion gt() returns 'U' — the
    // CONSERVATIVE verdict (blocks re-typing, never a wrong type), so the only
    // effect is that a pathological method's versions are left at DAD's type. The
    // budget is far above any natural method (verified 0 output change vs uncapped
    // on the bundled + obfuscated corpus), so it bites ONLY crafted input.
    size_t gt_budget = 2'000'000;
    std::function<char(IRForm*, std::set<std::string>&, std::string&)> gt =
        [&](IRForm* rhsv, std::set<std::string>& seen,
            std::string& type_out) -> char {
        if (gt_budget == 0) return 'U';  // work cap → conservative bail
        --gt_budget;
        if (!rhsv) return 'U';
        if (rhsv->is_ident()) {  // move — resolve source transitively
            const std::string sid = rhsv->Vid();
            if (seen.count(sid)) return 'M';
            seen.insert(sid);
            // BACKTRACK sid on every exit of this frame, so `seen` is a proper
            // DFS ancestor STACK: a sibling move path starts from the same set
            // this frame did (per-path cycle detection) — WITHOUT the O(depth)
            // copy a naive per-sibling `seen` clone needs (which turned a deep
            // linear move chain into O(N^2)). A move-DIAMOND's two arms are then
            // re-explored (a node is only 'M' when it is a LIVE ancestor on the
            // current path, not merely visited-and-popped by an earlier arm); the
            // resulting O(2^N) re-exploration on a crafted diamond chain is bounded
            // by the gt_budget cap above (adversarial-review finding).
            struct Pop { std::set<std::string>& s; const std::string& k;
                         ~Pop() { s.erase(k); } } pop_{seen, sid};
            auto dit = defs_of.find(sid);
            if (dit == defs_of.end()) {  // param/no def — declared type
                const std::string t = rhsv->get_type();
                if (is_ref(t)) { type_out = t; return 'R'; }
                if (is_prim_desc(t)) { type_out = t; return 'P'; }
                return 'U';
            }
            // Aggregate ALL sibling defs — do NOT short-circuit on the first
            // 'R'. A conflated move source holding BOTH a reference and a
            // primitive (an obfuscator reusing one register for an int arg
            // AND a String) must report as AMBIGUOUS ('U'), not pure-
            // reference: the earlier short-circuit-on-'R' had INVERTED safety
            // polarity for the prim→ref mirror — it swallowed the primitive
            // sibling, so a genuine int/ref merge looked like `has_ref &&
            // !has_prim` and the mirror re-typed a real `int` to a reference
            // (adversarial-review finding: `int v6` → `String v6; v6 <= null;
            // v6 - 1`). Precedence: MIXED (R && P) or any unknown/cycle → 'U'
            // (blocks either direction); else all-reference → 'R'; else
            // all-primitive → 'P'; else null-neutral → 'N'.
            bool sib_r = false, sib_p = false, sib_u = false, sib_any = false;
            std::string ref_seen, prim_seen;
            for (IRForm* d : dit->second) {
                auto dr = d->get_rhs();
                if (dr.empty() || !dr[0]) { sib_u = true; sib_any = true;
                    continue; }
                std::string ct;
                // Shared `seen` as a backtracked DFS stack (each recursive frame
                // pops its own id, above): a DIAMOND's second arm sees the first
                // arm's nodes already POPPED, so it is not mistaken for a cycle —
                // only a genuine back-edge to a LIVE ancestor returns 'M'. (A
                // spurious 'M' here would, with 'M' now neutral, HIDE a reference
                // reached only on that arm.)
                char c = gt(dr[0].get(), seen, ct);
                if (c == 'R') { sib_r = true; sib_any = true;
                    if (ref_seen.empty()) ref_seen = ct; }
                else if (c == 'P') { sib_p = true; sib_any = true;
                    if (prim_seen.empty()) prim_seen = ct; }
                else if (c == 'U') { sib_u = true; sib_any = true; }
                else if (c == 'N') sib_any = true;
                // 'M' (a genuine cycle back-edge on this path) carries NO new
                // ground truth: it targets an ANCESTOR frame (the `sid` already
                // in `seen`) that OWNS the cycle member's real defs and resolves
                // its type there — this back-edge frame merely defers to it. A
                // reference entering the cycle does so via some member's non-move
                // def, which that ancestor frame aggregates and reports 'R' on its
                // FIRST visit (a back-edge never re-reads it), so a reference can
                // never be hidden. Hence NEUTRAL, not blocking. A pure move-cycle
                // with no ground producer falls to the !sib_any guard below.
            }
            if (sib_u || (sib_r && sib_p)) return 'U';  // ambiguous → block
            if (sib_r) { if (type_out.empty()) type_out = ref_seen;
                return 'R'; }
            if (sib_p) { if (type_out.empty()) type_out = prim_seen;
                return 'P'; }
            if (!sib_any) return 'U';  // pure move-cycle, no ground → undetermined
            return 'N';
        }
        // Unambiguous reference producers.
        if (is_alloc_producer(rhsv)) {
            // An allocation is definitionally a reference; only set the
            // descriptor when it is actually one (a corrupt/empty type under
            // lenient load leaves type_out empty → the mirror's is_ref gate
            // then skips, consistent with the other 'R' branches).
            const std::string t = rhsv->get_type();
            if (is_ref(t)) type_out = t;
            return 'R';
        }
        if (auto* c = dynamic_cast<Constant*>(rhsv)) {
            if (is_ref(c->get_type())) {                 // const-class/string
                type_out = c->get_type(); return 'R'; }
            if (c->get_int_value() == 0) return 'N';     // 0 = null-neutral
            type_out = is_prim_desc(c->get_type()) ? c->get_type() : "I";
            return 'P';
        }
        // Structural primitives (arithmetic / length / comparison / prim
        // cast) — but a ref-typed result still wins as 'R' (never mislabel).
        if (dynamic_cast<BinaryExpression*>(rhsv) ||
            dynamic_cast<UnaryExpression*>(rhsv) ||
            dynamic_cast<ArrayLengthExpression*>(rhsv)) {
            const std::string t = rhsv->get_type();
            if (is_ref(t)) { type_out = t; return 'R'; }
            type_out = is_prim_desc(t) ? t : "I";
            return 'P';
        }
        // Everything else (invoke, field-get, array-load, …): type-driven.
        // An empty type is UNKNOWN, not primitive — a corrupted-type
        // reference producer (e.g. aget-object off a mistyped array) must
        // NOT read as primitive, or the version could be wrongly re-typed.
        const std::string t = rhsv->get_type();
        if (is_ref(t)) { type_out = t; return 'R'; }
        if (is_prim_desc(t)) { type_out = t; return 'P'; }
        return 'U';
    };
    // Resolve the PRIMITIVE WIDTH a version's value really has, by walking its
    // defs (through moves to the ultimate producer) to the first genuine
    // primitive descriptor. Unlike gt(), it does NOT stop at a reference — a
    // reference in the def closure of an INT-USED version is a spurious
    // conflation type (in valid Dalvik an ordered-compare / arithmetic operand
    // cannot be a reference), so it is skipped and the walk continues to the
    // real primitive. Returns "" (UNKNOWN) when no primitive producer is found
    // — e.g. a genuine allocation / reference-returning method — so such a
    // version is left untouched rather than guessed. This is what preserves
    // width: a `long`/`float`/`double`-returning method mistyped a reference is
    // re-typed to 'J'/'F'/'D', never narrowed to int.
    std::function<std::string(IRForm*, std::set<std::string>&)>
        resolve_prim_width =
        [&](IRForm* r, std::set<std::string>& seen) -> std::string {
        if (!r) return {};
        if (r->is_ident()) {
            const std::string sid = r->Vid();
            if (seen.count(sid)) return {};
            seen.insert(sid);
            auto it = defs_of.find(sid);
            if (it == defs_of.end())  // param/no def — declared type
                return is_prim_desc(r->get_type()) ? r->get_type()
                                                   : std::string{};
            // AGGREGATE all sibling defs — do NOT return the first non-empty
            // width (adversarial-review hardening, symmetric to gt()): a
            // conflated move source holding two DIFFERENT primitive widths
            // (a `long` call on one path, a `const int` on another) must
            // report AMBIGUOUS ("") so the widen branch leaves it untouched,
            // not commit whichever def happens to iterate first. Empty
            // (reference / no primitive) siblings are neutral — skipped.
            std::string agreed;
            for (IRForm* d : it->second) {
                auto dr = d->get_rhs();
                if (dr.empty() || !dr[0]) continue;
                std::string w = resolve_prim_width(dr[0].get(), seen);
                if (w.empty()) continue;
                if (agreed.empty()) agreed = w;
                else if (agreed != w) return {};  // width disagreement
            }
            return agreed;
        }
        // A genuine allocation is definitively a reference — no primitive
        // width, so an int-used allocation (impossible in valid Dalvik) is
        // never re-typed.
        if (is_alloc_producer(r)) return {};
        const std::string t = r->get_type();
        return is_prim_desc(t) ? t : std::string{};
    };
    // The single primitive width ALL of a version's defs agree on, or "" — a def
    // that is a genuine reference producer / unresolved (`resolve_prim_width`
    // returns "") or a width disagreement fails the aggregate. Shared by the two
    // branches that re-type only on an unambiguous agreed width: the USE-DRIVEN
    // ref→prim branch (A) and the prim→WIDER branch (D). (Extracted from two
    // byte-identical copies — the sole true duplication in this pass.)
    auto agreed_prim_width = [&](const std::string& vid,
                                 const std::vector<IRForm*>& dvec) -> std::string {
        std::string w;
        for (IRForm* d : dvec) {
            auto dr = d->get_rhs();
            if (dr.empty() || !dr[0]) return {};
            std::set<std::string> seen{vid};
            std::string dw = resolve_prim_width(dr[0].get(), seen);
            if (dw.empty() || (!w.empty() && w != dw)) return {};
            if (w.empty()) w = dw;
        }
        return w;
    };
    // USE-BOUND prim→ref support (design §3). Does an rhs form transitively
    // (through moves) contain a genuine primitive PRODUCER? A move is resolved
    // to its source's defs; a move to a PARAM / input (no def) is NOT a producer
    // — the register's stale primitive type is a conflation artifact, and a
    // ref-arg USE pins the version as a reference in verified Dalvik. A NONZERO
    // constant, an arithmetic / unary / array-length expression, or a
    // PRIMITIVE-returning invoke/field-get IS a producer (that version really
    // holds an int on some path — a genuine conflation needing a split, or
    // lenient-dex garbage — so we must not force it to a reference). Resolving
    // moves is what distinguishes `v4 = p10(Function1 param)` (fixable — the
    // move bottoms out at a param) from `v0 = move vR; vR = x.intValue()`
    // (blocked — the move bottoms out at a genuine int producer, which a
    // form-only check would miss). A move-CYCLE is neutral; an unresolvable def
    // (empty rhs) is treated as a possible producer (block), conservatively.
    //
    // WORK CAP (adversarial-review, mirrors gt_budget): the per-path RAII
    // backtracking below is O(2^N) on a crafted nested move-DIAMOND chain — the
    // same uncatchable CPU-spin family as gt() (which carries gt_budget for
    // exactly this). Today the classification loop always runs gt() on the same
    // (superset) closure FIRST, so gt_budget exhaustion forces `has_unknown →
    // continue` before this ever runs on a pathological closure — but that
    // defense is EMERGENT. Make it EXPLICIT with an independent budget; on
    // exhaustion return `true` (a possible producer → BLOCK the re-type, the
    // conservative/safe bail, matching gt()'s 'U').
    size_t pp_budget = 2'000'000;
    std::function<bool(IRForm*, std::set<std::string>&)> has_prim_producer =
        [&](IRForm* r, std::set<std::string>& seen) -> bool {
            if (pp_budget == 0) return true;          // work cap → conservative
            --pp_budget;
            if (!r) return true;                      // unknown → conservative
            if (r->is_ident()) {                      // move — resolve source
                const std::string sid = r->Vid();
                if (seen.count(sid)) return false;    // cycle → neutral
                seen.insert(sid);
                struct Pop { std::set<std::string>& s; const std::string& k;
                             ~Pop() { s.erase(k); } } pop_{seen, sid};
                auto it = defs_of.find(sid);
                if (it == defs_of.end()) return false;  // param/input — NOT a producer
                for (IRForm* d : it->second) {
                    auto dr = d->get_rhs();
                    if (dr.empty() || !dr[0]) return true;  // unresolvable → block
                    if (has_prim_producer(dr[0].get(), seen)) return true;
                }
                return false;
            }
            if (auto* c = dynamic_cast<Constant*>(r)) {
                if (is_ref(c->get_type())) return false;  // const-string/class
                return c->get_int_value() != 0;           // nonzero int = producer
            }
            if (dynamic_cast<BinaryExpression*>(r) ||
                dynamic_cast<UnaryExpression*>(r) ||
                dynamic_cast<ArrayLengthExpression*>(r))
                return true;                          // arithmetic → real int
            return is_prim_desc(r->get_type());       // prim invoke/field result
        };
    auto no_genuine_prim_producer = [&](const std::string& vid,
                                        const std::vector<IRForm*>& dvec) -> bool {
        for (IRForm* d : dvec) {
            auto dr = d->get_rhs();
            if (dr.empty() || !dr[0]) return false;   // unknown def form → block
            std::set<std::string> seen{vid};
            if (has_prim_producer(dr[0].get(), seen)) return false;
        }
        return true;
    };
    // The narrow-integer family — the widths a `boolean` shares its storage
    // with. J/F/D are excluded so a wide value can never be narrowed to `Z`.
    auto is_narrow_int = [](const std::string& t) {
        return t.size() == 1 &&
               std::string("ZBSCI").find(t[0]) != std::string::npos;
    };
    // dexllm#86 support — is an rhs form provably BOOLEAN-VALUED?
    //
    // The soundness argument INVERTS relative to `has_prim_producer` above, and
    // that inversion is the whole defect. For a REFERENCE re-type a nonzero int
    // constant is proof the value is NOT a reference, so that walk BLOCKS on
    // one. Dalvik has no boolean type — `const/4 v,#1` is exactly how a `true`
    // is written — so the very same constant is proof FOR the boolean. Only 0
    // and 1 qualify: any other integer is a genuine int that a `Z` return
    // cannot be reconciled with, and is left alone (no-worse).
    //
    // Boolean-valued forms: a narrow-int Constant whose value is 0 or 1, and
    // any form whose own type is already `Z` (a Z-returning invoke or
    // field-get). A move is resolved to its source's defs, ALL of which must
    // qualify (aggregating rather than short-circuiting, symmetric to
    // `resolve_prim_width`); a move to a PARAM / input with no def qualifies
    // only if its declared type is `Z`. Everything else — a wider primitive, a
    // reference, an int outside {0,1}, an unresolvable def — BLOCKS.
    //
    // A back edge is NEUTRAL, and a `ground` flag is what makes that safe —
    // the same pair `gt()` arrived at for move CYCLES, for the same reason and
    // with the same two halves. A cycle back edge targets an ancestor frame
    // that already owns that node's defs, so it carries no new ground truth:
    // re-descending would only re-check what the ancestor is checking. Nothing
    // can hide behind it, because this is an ALL-quantifier that short-circuits
    // only on FAILURE — every node reached from the root has its own defs
    // walked on the path that first reaches it, and the root's own defs are
    // walked by `all_defs_boolean_valued` itself.
    //
    // Blocking the back edge instead was the first cut, and it cost the fix on
    // the single most common shape in the corpus: `equals` compiles to a pair of
    // registers that move into EACH OTHER across the branch (`v6 = v5` on one
    // arm, `v5 = v6` on the other), so 749 of the 752 residual sites were this
    // and nothing else.
    //
    // `ground` is the `!sib_any` half: a PURE move cycle with no producer
    // anywhere would otherwise satisfy an all-quantifier vacuously — every step
    // is a move, no step is a counter-example, and the version would be called
    // boolean on no evidence. At least one CONSTANT 0/1 or `Z`-typed producer
    // must be reached. (gt() already reports 'M' → has_unknown → `continue` for
    // that shape, so this is defence in depth, but it makes the resolver answer
    // for itself rather than lean on a caller's guard.)
    //
    // WORK CAP (mirrors pp_budget / gt_budget): the per-path backtracking is
    // O(2^N) on a crafted nested move-diamond chain. On exhaustion return false
    // (BLOCK — the conservative bail, so a crafted input loses a fix rather
    // than gaining a wrong type).
    size_t bv_budget = 2'000'000;
    std::function<bool(IRForm*, std::set<std::string>&, bool&)> is_bool_valued =
        [&](IRForm* r, std::set<std::string>& seen, bool& ground) -> bool {
            if (bv_budget == 0) return false;         // work cap → conservative
            --bv_budget;
            if (!r) return false;                     // unknown → conservative
            if (r->is_ident()) {                      // move — resolve the source
                const std::string sid = r->Vid();
                if (seen.count(sid)) return true;     // back edge → neutral
                seen.insert(sid);
                struct Pop { std::set<std::string>& s; const std::string& k;
                             ~Pop() { s.erase(k); } } pop_{seen, sid};
                auto it = defs_of.find(sid);
                if (it == defs_of.end()) {
                    // A def-less source is a PARAMETER (or an input the graph
                    // does not define).  Consult the DECLARED type where there
                    // is one: a `Param`'s own `get_type()` is mutated by a write
                    // to its register — the same corruption this pass repairs —
                    // so reading it here would contradict the rule the branch
                    // above enforces at the root.  A delta review caught that
                    // this arm said `declared` in its pin and read `get_type()`
                    // in the code; corpus-neutral, and now they agree.
                    auto dp = declared_params.find(sid);
                    const std::string& dt =
                        dp != declared_params.end() ? dp->second : r->get_type();
                    if (dt != "Z") return false;
                    ground = true;
                    return true;
                }
                for (IRForm* d : it->second) {
                    auto dr = d->get_rhs();
                    if (dr.empty() || !dr[0]) return false;  // unresolvable → block
                    if (!is_bool_valued(dr[0].get(), seen, ground)) return false;
                }
                return true;
            }
            if (auto* c = dynamic_cast<Constant*>(r)) {
                if (!is_narrow_int(c->get_type())) return false;  // ref/wide const
                const auto cv = c->get_int_value();
                if (cv != 0 && cv != 1) return false;
                ground = true;
                return true;
            }
            if (r->get_type() != "Z") return false;
            ground = true;
            return true;
        };
    // Is EVERY def of a version provably boolean-valued? The caller skips an
    // empty def set and an unresolvable def blocks, so this is a genuine
    // all-quantifier over ground truth — and `ground` keeps it from being
    // satisfied vacuously by a closure that is nothing but moves.
    // dexllm#86 — a version that IS a PARAMETER carries an implicit incoming
    // definition that `defs_of` does not hold, so `all_defs_boolean_valued` walks
    // only the writes INSIDE the method and cannot see it.  A parameter is
    // re-typable only when its DECLARED type is already `Z`; the `Param`'s own
    // `get_type()` is NOT usable, because writing to a param register mutates it
    // (the same mechanism that corrupts `this`) and that corruption is exactly
    // what this pass repairs.  An unknown vid — no map, i.e. the unit-parity
    // callers — is refused, which is the conservative direction.
    auto declared_param_is_boolean = [&](const std::string& vid,
                                         IRForm* var) -> bool {
        if (!dynamic_cast<Param*>(var)) return true;   // not a parameter at all
        auto it = declared_params.find(vid);
        return it != declared_params.end() && it->second == "Z";
    };
    auto all_defs_boolean_valued = [&](const std::string& vid,
                                       const std::vector<IRForm*>& dvec) -> bool {
        bool ground = false;
        for (IRForm* d : dvec) {
            auto dr = d->get_rhs();
            if (dr.empty() || !dr[0]) return false;
            std::set<std::string> seen{vid};
            if (!is_bool_valued(dr[0].get(), seen, ground)) return false;
        }
        return ground;
    };
    // Recover the ARRAY type of an array-used version from its def(s): every def
    // must produce an ARRAY (a def rhs whose type starts with '[', incl. a
    // check-cast to an array, a move off an array var, an array-returning
    // method) or be the null constant (array-compatible). A non-array,
    // non-null def, an unresolved def, or two disagreeing array types → bail
    // (a genuine conflation, not a lost array type). Returns the agreed array
    // descriptor, else "".
    auto resolve_array_type = [&](const std::vector<IRForm*>& dvec)
            -> std::string {
        std::string at;
        for (IRForm* d : dvec) {
            auto dr = d->get_rhs();
            if (dr.empty() || !dr[0]) return {};       // unknown → bail
            if (auto* c = dynamic_cast<Constant*>(dr[0].get()))
                if (!is_ref(c->get_type()) && c->get_int_value() == 0)
                    continue;                          // null → array-compatible
            std::string t = dr[0]->get_type();
            if (t.size() >= 2 && t[0] == '[') {        // an array producer
                if (at.empty()) at = std::move(t);
                else if (at != t) return {};           // conflicting arrays
            } else {
                return {};                             // non-array, non-null
            }
        }
        return at;
    };
    // Two-phase: classify every version reading ONLY pre-mutation types
    // (so the two directions can't interfere), then apply. Direction is
    // symmetric: a version whose current type disagrees with its provable
    // ground truth (ALL defs primitive/null → primitive; ALL defs
    // reference/null with agreeing class → that class) is re-typed. A
    // version with BOTH a real primitive forcer and a real reference is a
    // GENUINE conflation (needs a version split) and is left untouched, as
    // is any version with an unresolved ('U'/'M') def.
    std::vector<std::pair<IRForm*, std::string>> retypes;
    std::vector<std::string> z_seeds;   // dexllm#86 — vids the Z branch re-typed
    for (auto& [vid, dvec] : defs_of) {
        if (dvec.empty()) continue;
        auto vit = dvec[0]->var_map.find(vid);
        if (vit == dvec[0]->var_map.end() || !vit->second) continue;
        const std::string cur = vit->second->get_type();
        // B (array-use-driven typing): a version used as an array base but typed
        // a NON-array (`Object` from a conflation, or a lost move-source array
        // type) is re-typed to the array type recovered from its def(s), so
        // every array use (`v[i]`, `v.length`, `arr = v`) becomes valid at once
        // — the root-cause fix vs a per-use `((T[]) v)` cast.
        if (array_use_vids.count(vid) && !(cur.size() >= 2 && cur[0] == '[')) {
            std::string at = resolve_array_type(dvec);
            if (!at.empty()) {
                retypes.emplace_back(vit->second.get(), at);
                continue;
            }
        }
        const bool cur_ref = is_ref(cur), cur_prim = is_prim_desc(cur);
        if (!cur_ref && !cur_prim) continue;
        bool has_ref = false, has_prim = false, has_unknown = false;
        bool ref_conflict = false;
        std::string prim_type, ref_type;
        for (IRForm* d : dvec) {
            std::set<std::string> seen{vid};
            auto dr = d->get_rhs();
            if (dr.empty() || !dr[0]) { has_unknown = true; continue; }
            std::string ct;
            char c = gt(dr[0].get(), seen, ct);
            if (c == 'R') { has_ref = true;
                if (ref_type.empty()) ref_type = ct;
                else if (is_ref(ct) && ct != ref_type) ref_conflict = true; }
            else if (c == 'U' || c == 'M') has_unknown = true;
            else if (c == 'P') { has_prim = true;
                if (prim_type.empty()) prim_type = ct; }
            // 'N' (null/zero) is neutral — compatible with either type.
        }
        // USE-DRIVEN ref→prim (width-resolved) — runs BEFORE the def-only
        // guards below. A reference-typed version USED AS AN INTEGER (an
        // ordered comparison / arithmetic operand / array index) is, in valid
        // Dalvik, provably a primitive on that path: the verifier rejects
        // those operations on a reference, so a 'R' reached only through moves
        // is a SPURIOUS conflation type (a stale reference copied off a
        // mistyped sibling register). This is the residual that looked like it
        // needed a "version split" but has NO real reference use.
        //
        // ADVERSARIAL-REVIEW HARDENING: re-type ONLY when EVERY def resolves
        // to a primitive width AND they all AGREE. If ANY def is a GENUINE
        // reference producer (an allocation / reference-returning method /
        // reference field — `resolve_prim_width` returns ""), the register is
        // a GENUINE object+int conflation (a real object on one path, an int
        // on another) that needs a version split — left untouched, so it is
        // never re-typed to `int` while `return v` / `throw v` / a reference
        // argument uses the object arm (the `object_vids` receiver/field guard
        // does not cover those positions). If the widths DISAGREE (I vs J) the
        // register is a genuine mixed-width conflation — left untouched to
        // avoid truncating a long/float/double to int. A boolean (Z) width is
        // left too (a boolean used as an int is a genuine boolean/int
        // conflation). The `object_vids` check is kept as belt-and-suspenders.
        if (cur_ref && int_use_vids.count(vid) &&
            !object_vids.count(vid)) {
            std::string w = agreed_prim_width(vid, dvec);
            if (!w.empty() && w != "Z") {
                retypes.emplace_back(vit->second.get(), w);
                continue;
            }
        }
        // Any unresolved def, a genuine ref+prim merge, or disagreeing
        // reference producers → refuse (the genuine ref+prim conflation is typed
        // Object by SplitVariables, which has the reaching-def info to identify
        // it PRECISELY — the gt-based has_ref/has_prim here over-includes
        // arithmetic/false-'R' cases that render fine, so it must NOT act).
        if (has_unknown || (has_ref && has_prim)) continue;
        if (cur_ref && has_prim) {
            // CASCADE (ref→prim): ref-typed but provably primitive. Skip if
            // used AS AN OBJECT (a reference producer we failed to detect).
            if (object_vids.count(vid)) continue;
            // A MULTI-def all-primitive version is def-confirmed. A SINGLE-def
            // version (a lone primitive-returning method typed reference by
            // register conflation — `String v = p.indexOf(',')` then `v >= 0`
            // / `v + 1`) additionally requires USE-corroboration: a clear
            // integer use proves the primitive, and an ambiguous single-def
            // version (never used as an int — e.g. `String v = indexOf();
            // return v` where the method returns String) is a genuine
            // conflation no single type satisfies, so it is left untouched
            // rather than guessed. (Multi-def prim merges keep the original,
            // def-driven behaviour — no use requirement.)
            if (dvec.size() < 2 && !int_use_vids.count(vid)) continue;
            // A `boolean` (Z) value cannot be an arithmetic / ordered-compare
            // operand in Java, and `int v = booleanMethod()` is equally
            // invalid — a Z-returning def that reaches an integer use is a
            // genuine boolean/int register conflation no single type
            // satisfies. Leave it (DAD's reference type) rather than emit a
            // new `boolean v; v + 1` flavour of invalid Java (adversarial-
            // review nit; needs a version split to resolve). B/S/C stay
            // re-typed — `byte v; v + 1` is valid (numeric promotion).
            if (prim_type == "Z" && int_use_vids.count(vid)) continue;
            retypes.emplace_back(vit->second.get(),
                                 prim_type.empty() ? "I" : prim_type);
        } else if (cur_prim && has_ref && is_ref(ref_type) && !ref_conflict &&
                   (dvec.size() >= 2 || object_vids.count(vid)) &&
                   !dynamic_cast<ThisParam*>(vit->second.get())) {
            // Belt-and-suspenders (adversarial-review): a `this` / super
            // <init>-base register is always reference-typed, so the cur_prim
            // gate already excludes it; the explicit ThisParam check makes the
            // exclusion STRUCTURAL (matching the first FixInitResultTypes
            // pass) rather than incidental — re-typing `this` would corrupt
            // the writer's super-vs-this detection.
            // MIRROR (prim→ref): primitive-typed but really a reference. Two
            // shapes: a MULTI-def version whose defs are a reference + null
            // (`int v = ObjectAnimator.ofFloat(...)` + `v = 0`, then
            // `v.addListener()` / `return v`); or a SINGLE-def version that is
            // USE-corroborated as an OBJECT — a lone reference-returning method
            // typed `int` by register conflation (`int v2 =
            // getChildViewHolderInt(...); v2.isRemoved(); v2.itemView`), where
            // the receiver / field-owner use proves the reference (symmetric
            // to the single-def cascade's int-use proof).
            // USE-CORROBORATION (symmetric to object_vids, adversarial-review
            // hardening): skip if the version is ever used in an INTEGER
            // context (arithmetic operand, array index, unary operand). The
            // DEF side can look all-reference for a genuinely-conflated
            // register whose reference arm is a String param moved in while
            // the same register is reused as an int — split_variables did not
            // separate them, so `v = strParam` (an 'R' def) and `v = 0` (an
            // 'N' def) hide the int nature that only the USES expose. Without
            // this guard the mirror mis-typed `int v6` → `String v6` with
            // `v6 - 1` / `v6 <= 10` (uncompilable). An int-used version is a
            // genuine conflation (needs a version split) → leave DAD's type.
            if (int_use_vids.count(vid)) continue;
            retypes.emplace_back(vit->second.get(), ref_type);
        } else if (cur_prim && !has_ref && !int_use_vids.count(vid) &&
                   !ref_use_type(vid).empty() &&
                   no_genuine_prim_producer(vid, dvec) &&
                   !dynamic_cast<ThisParam*>(vit->second.get())) {
            // USE-BOUND prim→ref (design §3, Phase 2 — jadx "type bound from
            // use"): a primitive-typed version with NO reference DEF (the
            // existing mirror needs one — `has_ref`) but whose reference nature
            // is pinned only by a USE (a reference argument, a field store, or a
            // throw — see `ref_use_type`). The `v4 = p10(Function1)` shape: a
            // Dalvik register shared between a Function1 param and a scratch
            // local, so split_variables typed the version `int` (last write),
            // the reference is lost from every def (a move off the conflated
            // register reports type I), and it survives ONLY at the ref use
            // `actor(…, v4, …)`. In VERIFIED Dalvik a value at a reference USE
            // position IS a reference (the verifier rejects an int there), and
            // this version is NEVER used as an int (`!int_use_vids`) and has NO
            // genuine primitive producer (`no_genuine_prim_producer` — only
            // moves / null / non-prim results), so it cannot really be an int:
            // the primitive type is a register-conflation artifact. Re-type to
            // the use-bound reference type (exact-match: `ref_use_conflict` skips
            // a version pinned at two different types rather than computing an
            // LUB). The `= 0` def then renders `= null` via the existing
            // reference-lhs null render. Lenient-dex caveat: an unverified
            // `refCall(intVar)` could over-fire, but that is garbage-in/garbage-
            // out (same documented precedent as the other use-corroborated
            // re-types).
            retypes.emplace_back(vit->second.get(), ref_use_type(vid));
        } else if (cur_prim && cur != "Z" && is_narrow_int(cur) &&
                   bool_ret_vids.count(vid) &&
                   !int_use_vids.count(vid) &&
                   !int_required_vids.count(vid) &&
                   !prim_use_vids.count(vid) &&
                   !object_vids.count(vid) &&
                   !dynamic_cast<ThisParam*>(vit->second.get()) &&
                   declared_param_is_boolean(vid, vit->second.get()) &&
                   all_defs_boolean_valued(vid, dvec)) {
            // USE-BOUND int→Z (dexllm#86) — the RETURN TYPE as a constraint.
            // Dalvik has no boolean, so every `const*` builds an int-typed
            // value and DAD's last-write typing leaves a boolean flag declared
            // `int`; returning it from a `Z` method is uncompilable Java
            // (`int` → `boolean` has no widening). Measured on the bundled
            // corpus this is not an occasional slip: 57 of the 60 sites where a
            // `boolean` method returns a VARIABLE declared it `int`.
            //
            // The return position is the proof, exactly as a reference ARGUMENT
            // is for the mirror branch above: in verified Dalvik `return v` in a
            // `Z` method requires v to hold a boolean, so a version reaching one
            // IS a boolean and its `int` type is a register-conflation artifact.
            // The `record`/`ref_use_type` channel cannot carry this — it is
            // gated on `is_ref`, by design, because every OTHER use-bound source
            // pins a reference.
            //
            // The anti-conflation guards are needed because a register genuinely
            // shared between a flag and an int satisfies neither type. THREE
            // sets, and it takes all three — the first cut had two and an
            // adversarial review turned valid corpus Java into invalid with the
            // third missing:
            //   `int_use_vids`      arithmetic, ordered comparison, array INDEX.
            //                       `==`/`!=` are correctly excluded, so a plain
            //                       `if (v != 0)` flag test does NOT block.
            //   `int_required_vids` array-creation size and `switch` selector —
            //                       NOT a subset of the above, which is why it
            //                       is consulted separately.
            //   `prim_use_vids`     a non-boolean primitive ARGUMENT, field
            //                       store or array-store VALUE (dexllm#86) —
            //                       positions neither of the others records.
            // `object_vids` blocks a version also used as an object, and the
            // ThisParam exclusion is the same structural belt-and-suspenders the
            // mirror branch carries (a `this = X` reuse can leave the receiver
            // primitive-typed, and re-typing it would corrupt the writer's
            // super-vs-this detection).
            //
            // DEF-anchored as well as use-corroborated: EVERY def must be
            // provably boolean-valued (`all_defs_boolean_valued`), so a version
            // holding a real int on any path is left. `is_narrow_int(cur)` keeps
            // a J/F/D version out, so nothing can be narrowed.
            //
            // No emitter change is needed and that is the point of fixing it
            // HERE: with the version typed `Z`, `write_inplace_if_possible`
            // already renders `= true` / `= false` and the declaration already
            // renders `boolean v`, in the text AND the AST. Doing it in the
            // Writer would have been the masking variant.
            retypes.emplace_back(vit->second.get(), "Z");
            z_seeds.push_back(vid);
        } else if (cur_prim && !int_required_vids.count(vid)) {
            // prim→WIDER-prim: an `int`-typed version whose value is really a
            // WIDER primitive — `int v = System.currentTimeMillis()` /
            // `int v = Long.parseLong(s)` (long returned into a wide register
            // whose split version DAD mistyped `int`). `int v = <long>` is an
            // uncompilable narrowing. Re-type to the def width when EVERY def
            // resolves to the SAME primitive and it is WIDER than the current
            // type (an assignment `cur v = w` that would be an invalid
            // narrowing). Disjoint from the ref→prim / mirror branches
            // (cur_prim, not cur_ref). Guarded by INT-REQUIRED use — an array
            // index (`arr[longV]`), a `switch` selector (`switch(longV)`), or
            // an array-creation size (`new int[longV]`) are all invalid for a
            // wide type — but NOT by ordinary arithmetic / comparison, which
            // is valid on a wide value, so unlike the mirror this does not
            // skip all int uses.
            std::string w = agreed_prim_width(vid, dvec);
            // Java widening order for assignment: {Z,B,C,S,I}=1 < J=2 < F=3 <
            // D=4. `cur v = w` is an invalid narrowing iff rank(w) > rank(cur).
            auto rank = [](const std::string& t) {
                if (t == "D") return 4; if (t == "F") return 3;
                if (t == "J") return 2; return 1;
            };
            if (!w.empty() && rank(w) > rank(cur))
                retypes.emplace_back(vit->second.get(), w);
        }
    }
    // dexllm#86 — PROPAGATE `Z` BACKWARDS along move edges, so a move-connected
    // group is re-typed TOGETHER.  Typing only the RETURNED member is a partial
    // answer that trades one invalid line for another: `equals` compiles to two
    // registers that move into each other, so re-typing just the returned one
    // gives `boolean v6 = false; … v6 = v5;` with `v5` still `int` — the
    // `T v = varOfOtherKind` bucket, measured at +16 lines for the def-blocking
    // variant of the resolver and +147 for the cycle-neutral one.  Both are the
    // SAME structural flaw, so it is fixed here rather than avoided by keeping
    // the resolver weak.
    //
    // SOUND for the same reason the seed is: if `v6` provably holds a boolean
    // and its value came from `move v6, v5`, then `v5` held that boolean at the
    // move.  So a source is re-typed only when it independently satisfies EVERY
    // guard the seed did — never int-used, never object-used, not `this`, a
    // narrow non-Z primitive today, and all of its OWN defs boolean-valued.  A
    // source failing any of them is a genuine conflation and is left, which is
    // exactly the case the `v = v` line will still show.
    //
    // TERMINATES: a version enters `zed` once and is never revisited, so the
    // worklist is bounded by the number of versions and each is expanded once.
    // DETERMINISM: `z_seeds` follows `defs_of`, an unordered_map, so the
    // worklist ORDER varies per process. The resulting SET does not — a source
    // is re-typed iff it is move-reachable from a seed and passes guards that
    // read only PRE-mutation state. That holds WHILE `bv_budget` is unexhausted:
    // the budget is one per-pass counter spent in `defs_of` order, so on
    // exhaustion WHICH versions were resolved before it ran out is
    // order-dependent — the same posture as the pre-existing `gt_budget`, and
    // unreached on every measured input (9 runs x 3 `PYTHONHASHSEED`s give one
    // digest). A version another branch already
    // re-typed would be a genuine hazard: two entries for one Variable with
    // DIFFERENT types, resolved by whichever `retypes` order the run produced.
    // No branch can currently collide (each requires def shapes this one
    // excludes), so `already` is defence in depth by POINTER identity, which is
    // the identity that decides the outcome.
    {
        std::unordered_set<const IRForm*> already;
        for (auto& [var, t] : retypes) already.insert(var);
        std::unordered_set<std::string> zed(z_seeds.begin(), z_seeds.end());
        std::vector<std::string> work = z_seeds;
        while (!work.empty()) {
            const std::string cur_vid = work.back();
            work.pop_back();
            auto dit = defs_of.find(cur_vid);
            if (dit == defs_of.end()) continue;
            for (IRForm* d : dit->second) {
                auto dr = d->get_rhs();
                if (dr.empty() || !dr[0] || !dr[0]->is_ident()) continue;
                const std::string sid = dr[0]->Vid();
                if (sid.empty() || zed.count(sid)) continue;
                auto sdefs = defs_of.find(sid);
                if (sdefs == defs_of.end() || sdefs->second.empty()) continue;
                auto svit = sdefs->second[0]->var_map.find(sid);
                if (svit == sdefs->second[0]->var_map.end() || !svit->second) continue;
                const std::string st = svit->second->get_type();
                if (st == "Z" || !is_narrow_int(st)) continue;
                if (int_use_vids.count(sid) || int_required_vids.count(sid) ||
                    prim_use_vids.count(sid) || object_vids.count(sid)) continue;
                if (dynamic_cast<ThisParam*>(svit->second.get())) continue;
                if (!declared_param_is_boolean(sid, svit->second.get())) continue;
                if (already.count(svit->second.get())) continue;
                if (!all_defs_boolean_valued(sid, sdefs->second)) continue;
                retypes.emplace_back(svit->second.get(), "Z");
                already.insert(svit->second.get());
                zed.insert(sid);
                work.push_back(sid);
            }
        }
    }
    for (auto& [var, t] : retypes) var->set_type(t);

    // MOVE-OPCODE ground truth (beyond-DAD) — a SEPARATE fixpoint pass AFTER the
    // cascade/mirror retypes are applied, so it reads FINAL types. A single-def
    // version whose def is a MoveExpression carries the KIND of the moved value
    // in the Dalvik opcode (move-object → reference, move/-wide → primitive).
    // When the DECLARED type contradicts that kind the register was reused and
    // DAD's last-write typed this version wrong (`int v3 = v24` where v24 is a
    // View via move-object; `Listener v4 = v1` where v1 is an int via move) — the
    // opcode is authoritative, so re-type the DEST to agree.
    //
    // Reads FINAL types (not the two-phase pre-mutation snapshot) — closes the
    // reviewer-found hole where a source independently re-typed by the cascade/
    // mirror would make `<Type> v = src` kind-INCONSISTENT (`ref v = primSrc`):
    // the guard `is_ref(st)` / `is_prim_desc(st)` now sees the source's settled
    // type. A BOUNDED FIXPOINT (iterate while changed, cap 32) converges a move
    // CHAIN — fixing the first `move-object` link makes the second link's source
    // a reference on the next round (a single pass would leave `int v2 = LFoo v1`
    // because v1 was still primitive when v2 was visited).
    //
    // ANTI-CONFLATION GUARDS (unchanged): the version must NOT also be used as
    // the contradicting kind — a direct use (`object_vids` — which includes
    // return/throw/ref-arg/ref-field-store via `record` — / `int_use_vids`) OR a
    // move-SOURCE of the contradicting opcode (`moveobj_src_vids` /
    // `moveprim_src_vids`). A prim-move DEST that is also a move-object source is
    // a GENUINE prim+ref conflation (no single Java type) and is left. On
    // VERIFIED dex the move opcode is ground truth (the verifier rejects a
    // move-object of a primitive, and a genuine primitive value stored via
    // aput-object / ref-cast); on lenient dex an uncovered object-use position
    // (aput-object / check-cast) is GIGO, matching the documented precedent.
    //
    // TERMINATION: each version's def is ONE move with ONE fixed opcode kind, so
    // a version can fire at most its single matching branch (move-object → the
    // →ref branch, needs cur_prim; move/-wide → the →prim branch, needs cur_ref)
    // and, once flipped, its cur no longer satisfies that branch — so EVERY
    // version re-types AT MOST ONCE. The fixpoint therefore converges in ≤(#move
    // versions) rounds regardless of the cap, and a pure move-cycle with no
    // ground-truth producer re-types nothing (is_ref/is_prim_desc never holds) →
    // no oscillation. The `round < 32` cap is a crafted-input WORK backstop (not
    // needed for correctness): a real move chain is ≤3 links (measured 0 added
    // lines OFF→ON on 188k+43k methods), so 32 always fully converges. A crafted
    // move-object chain LONGER than 32 links crossing a type-reuse boundary could
    // truncate at the frontier and leave one boundary `int vK+1 = LFoo vK` line —
    // deterministic (unseeded string-hash iteration + fixed cap), no crash, no
    // worse than DAD's baseline on that crafted input; same "no silent cap"
    // documented-GIGO posture as gt_budget / the emit-walk depth guard.
    bool moved = true;
    for (int round = 0; moved && round < 32; ++round) {
        moved = false;
        for (auto& [vid, dvec] : defs_of) {
            if (dvec.size() != 1) continue;
            auto* mv = dynamic_cast<MoveExpression*>(dvec[0]);
            if (!mv) continue;
            auto vit = dvec[0]->var_map.find(vid);
            if (vit == dvec[0]->var_map.end() || !vit->second) continue;
            const std::string cur = vit->second->get_type();
            const bool cur_ref = is_ref(cur), cur_prim = is_prim_desc(cur);
            if (!cur_ref && !cur_prim) continue;
            auto srcr = mv->get_rhs();
            IRForm* src = (!srcr.empty() && srcr[0]) ? srcr[0].get() : nullptr;
            if (!src) continue;
            const std::string st = src->get_type();  // FINAL source type
            MoveKind mk = mv->move_kind();
            if (mk == MoveKind::Object && cur_prim && is_ref(st) &&
                !int_use_vids.count(vid) && !moveprim_src_vids.count(vid)) {
                vit->second->set_type(st);
                moved = true;
            } else if ((mk == MoveKind::Plain || mk == MoveKind::Wide) &&
                       cur_ref && is_prim_desc(st) &&
                       !object_vids.count(vid) && !moveobj_src_vids.count(vid)) {
                vit->second->set_type(st);
                moved = true;
            }
        }
    }
}

// Driver — DAD types every register version from the register's LAST write
// (orig_var.type), so a Dalvik register reused across incompatible types
// leaves its split versions mistyped. This corrects them at the VALUE/version
// level in two def-anchored passes (docs/type-inference-design.md).
void FixInitResultTypes(
    Graph& graph, const std::string& ret_type,
    const std::unordered_map<std::string, std::string>& declared_params) {
    FixAllocationResultTypes(graph);  // design §1: allocation ground truth
    InferCascadeTypes(graph, ret_type, declared_params);  // §2/§3 + use-bound
}

// Beyond-DAD: see dataflow.h. Materialise a reused receiver register as a local.
bool MaterializeReusedThis(Graph& graph,
                           std::unordered_map<int, IRFormPtr>& lvars,
                           int this_reg, const std::string& cls_name,
                           const std::string& ret_type, bool is_ctor,
                           const std::function<bool(std::string_view,
                                                    std::string_view)>&
                               is_assignable) {
    auto is_ref = [](const std::string& t) {
        return !t.empty() && (t.front() == 'L' || t.front() == '[');
    };
    // `sub <: super` via the injected class-hierarchy oracle, or exact-equality
    // when it is unset (conservative — a source without a hierarchy proves only
    // the trivial case, keeping every widening decision below sound).
    auto assignable = [&](const std::string& sub, const std::string& super) {
        return is_assignable ? is_assignable(sub, super) : sub == super;
    };
    if (is_ctor) return false;  // super()/this() uses the receiver specially

    // The receiver must still be a ThisParam: SplitVariables keeps an UNSPLIT
    // reuse as ThisParam (the buggy `this = X` case); a reuse it DID split was
    // already renamed to a fresh vN, so nothing to do there.
    auto tit = lvars.find(this_reg);
    if (tit == lvars.end() ||
        !dynamic_cast<ThisParam*>(tit->second.get())) return false;
    IRFormPtr this_param = tit->second;
    const std::string this_vid = "v" + std::to_string(this_reg);

    // ---- PHASE A: validate (NO mutation). Bail cleanly on any disqualifier so
    // the graph is never left half-rewritten. ------------------------------
    auto* entry_bb = dynamic_cast<BasicBlock*>(graph.entry);
    if (!entry_bb) return false;

    // The anchor is the single reference type a TYPED SINK pins the receiver's
    // value to: a `return this` (return type) or a reference arg `m(…, this, …)`
    // (the parameter type). Two differing sinks → bail (no common bound without a
    // full lattice). Sink/reassign blocks are recorded for the reaches-a-sink
    // proof below.
    std::string anchor;
    bool sink_conflict = false;
    std::unordered_set<NodeBase*> sink_blocks, reassign_blocks;
    auto note_sink = [&](const std::string& ty, NodeBase* blk) {
        if (!is_ref(ty)) return;
        sink_blocks.insert(blk);
        if (anchor.empty()) anchor = ty;
        else if (anchor != ty) sink_conflict = true;
    };
    bool reused = false, returned = false;
    // Reassignment rhs descriptors: a reference type, "" for the null constant,
    // or "!" for void / primitive / non-const (disqualifying).
    std::vector<std::string> reassign;
    // DEF-anchor tracking: is EVERY reassignment a `new C` of the SAME class C?
    bool all_alloc = true;
    std::string alloc_type;
    for (NodeBase* n : graph.rpo) {
        auto* bb = dynamic_cast<BasicBlock*>(n);
        if (!bb) continue;
        for (const auto& ins : bb->ins) {
            if (!ins) continue;
            // SINK: `return this` → the method return type.
            if (dynamic_cast<ReturnInstruction*>(ins.get())) {
                for (const auto& u : ins->get_used_vars())
                    if (u == this_vid) { note_sink(ret_type, n);
                                         returned = true; break; }
            }
            // SINK: reference argument `m(…, this, …)` → the parameter type. The
            // receiver (base) of the invoke is a real-this read, NOT a sink. A
            // statement-level invoke is the RHS of an AssignExpression (every
            // opcode_ins handler wraps it), so inspect the rhs, not `ins`. (args↔
            // ptype are 1:1 via ParseParamsType; a size mismatch is skipped.)
            auto rr = ins->get_rhs();
            if (!rr.empty() && rr[0]) {
                if (auto* inv = dynamic_cast<InvokeInstruction*>(rr[0].get())) {
                    const auto& a = inv->args();
                    const auto& pt = inv->ptype();
                    if (a.size() == pt.size())
                        for (size_t i = 0; i < a.size(); ++i)
                            if (a[i] == this_vid) note_sink(pt[i], n);
                }
            }
            if (GetLhsKey(ins) != this_vid) continue;
            reused = true;
            reassign_blocks.insert(n);
            const std::string t =
                (!rr.empty() && rr[0]) ? rr[0]->get_type() : std::string{};
            // DEF-anchor: track whether this reassignment is a `new C` allocation
            // (new-instance / new-array) and whether all of them share one C.
            bool alloc = !rr.empty() && rr[0] &&
                         (dynamic_cast<NewInstance*>(rr[0].get()) ||
                          dynamic_cast<NewArrayExpression*>(rr[0].get()));
            if (alloc && is_ref(t)) {
                if (alloc_type.empty()) alloc_type = t;
                else if (alloc_type != t) all_alloc = false;
            } else {
                all_alloc = false;
            }
            if (is_ref(t)) { reassign.push_back(t); continue; }
            auto* c = !rr.empty() ? dynamic_cast<Constant*>(rr[0].get())
                                  : nullptr;
            reassign.push_back(
                (c && c->get_int_value() == 0 && t.size() == 1 &&
                 std::string("IZBSC").find(t) != std::string::npos)
                    ? std::string{}     // null reference
                    : std::string{"!"});  // void / primitive / non-const const
        }
    }
    if (!reused || sink_conflict) return false;

    // Is the entry `this` value ever read? Two reachability notions must BOTH be
    // clear (the materialisation rewrites `this` -> vX over graph.rpo, i.e. every
    // block reachable through NORMAL *and* EXCEPTION edges, so any this-read the
    // scan misses becomes an invalid `vX.m()` / use-before-def):
    //   (1) NORMAL def-clear: BFS from entry over normal successors, stopping at
    //       reassign blocks (they consume the entry value). A this-use in a
    //       reached block — or BEFORE the reassignment inside a reassign block —
    //       reads the entry value. rhs reads are checked BEFORE the LHS break: a
    //       reassignment whose OWN rhs reads the receiver (`this = new C[this]` —
    //       the array-size operand aliases the receiver register) reads the
    //       PRE-def (entry) value in the same instruction (verified dex rejects a
    //       reference array size; lenient load can reach here — declining keeps
    //       the claim true instead of emitting `C[] vX = new C[vX]`).
    //   (2) EXCEPTION: a catch handler observes the register at the THROW point,
    //       which is the entry `this` when the exception fires before the
    //       reassignment completes (the reassignment itself can throw). So a
    //       this-read in ANY `in_catch` handler or its (all-edge) downstream also
    //       reads the entry value, at ANY position (no reassign-stop). Without
    //       this the def-anchor drops the seed and corrupts a catch that still
    //       references `this` (adversarial-review finding).
    auto entry_this_read = [&]() -> bool {
        std::unordered_set<NodeBase*> normal;
        std::vector<NodeBase*> work{graph.entry};
        while (!work.empty()) {
            NodeBase* b = work.back();
            work.pop_back();
            if (!b || !normal.insert(b).second) continue;
            if (reassign_blocks.count(b)) continue;  // entry value consumed
            for (NodeBase* s : graph.sucs(b)) work.push_back(s);
        }
        // Exception-reachable closure: seed with every catch handler, follow all
        // edges (handler + downstream see the throw-point merge, incl. entry-this).
        std::unordered_set<NodeBase*> excpt;
        for (NodeBase* b : graph.rpo)
            if (b && b->in_catch) work.push_back(b);
        while (!work.empty()) {
            NodeBase* b = work.back();
            work.pop_back();
            if (!b || !excpt.insert(b).second) continue;
            for (NodeBase* s : graph.all_sucs(b)) work.push_back(s);
        }
        for (NodeBase* b : normal) {
            if (excpt.count(b)) continue;  // scanned fully below
            auto* bb = dynamic_cast<BasicBlock*>(b);
            if (!bb) continue;
            const bool is_reassign = reassign_blocks.count(b) != 0;
            for (const auto& ins : bb->ins) {
                if (!ins) continue;
                for (const auto& u : ins->get_used_vars())
                    if (u == this_vid) return true;
                if (is_reassign && GetLhsKey(ins) == this_vid) break;
            }
        }
        for (NodeBase* b : excpt) {  // catch-reachable: entry-this at any position
            auto* bb = dynamic_cast<BasicBlock*>(b);
            if (!bb) continue;
            for (const auto& ins : bb->ins) {
                if (!ins) continue;
                for (const auto& u : ins->get_used_vars())
                    if (u == this_vid) return true;
            }
        }
        return false;
    };

    // DEF-anchor: whenever EVERY reassignment is `new C` of one class C AND the
    // entry `this` value is never read, type vX = C (the exact allocation class)
    // and inject NO `vX = this` seed. This takes PRIORITY over any use-sink
    // anchor: the value genuinely IS a C, so every use — including a return/arg
    // sink — is exactly what the verified bytecode did with a `new C` register,
    // hence valid for a C-typed variable with NO framework-transitive subtype
    // proof (which the dex-only oracle cannot supply). E.g.
    // `this = new MarginLayoutParams; this(-1,-2); return this` returning
    // ViewGroup$LayoutParams: `C <: ret` holds only by the verifier, so the
    // use-sink path's reassign-assignability check `assignable(C, ret)` fails on
    // the dex-only oracle and bails — the def-anchor sidesteps it (vX = C exact,
    // and the dead seed's cls<:anchor up-cast is never emitted). The receiver is
    // pure scratch for the allocation (`this = new X(); this.<init>(); throw this`
    // OR `... ; return this`).
    //
    // Verified-bytecode dependency: soundness rests on the value at each use being
    // exactly what the (verified) bytecode did with a `new C` register. Under a
    // lenient load (VerifyInsns skipped) a hand-crafted `sink(this)` whose param
    // type is unrelated to C would emit `C vX = new C(); sink(vX)` with an
    // incompatible arg — but that input is already type-incompatible garbage, so
    // the output is uncompilable-in / uncompilable-out (no worse than DAD's
    // `this = new C`, cannot crash). A verified dex makes it unreachable.
    bool def_anchor = false;
    if (all_alloc && !alloc_type.empty() && !entry_this_read()) {
        anchor = alloc_type;
        def_anchor = true;
    } else if (anchor.empty()) {
        return false;  // no typed use-sink and not a clean allocation scratch
    }

    // Every reassignment must be assignable to the anchor (a subtype ok via the
    // hierarchy oracle) or the null constant — else `vX` (typed anchor) would
    // hold an incompatible value (the phi-web intermediate-use hazard). For the
    // def-anchor every reassignment is exactly `alloc_type == anchor`, so this
    // trivially passes.
    for (const auto& rt : reassign) {
        if (rt == "!") return false;                       // void / primitive
        if (!rt.empty() && !assignable(rt, anchor)) return false;
    }
    // cls_name <: anchor (the injected `<anchor> vX = this` up-cast) is proven by
    // EITHER the hierarchy oracle (cls's super/interface chain), OR the entry
    // `this` reaching an anchor sink through a reassignment-free CFG path (the
    // verifier then proves it — covering framework-transitive chains the dex-only
    // oracle cannot see). A reassign block CONSUMES the entry value, so it stops
    // the walk and a sink inside it is disqualified (conservative but sound).
    //
    // The pre-existing (v0.1.11) return-anchor trust ALSO passes — a `return this`
    // was already trusted to imply cls <: ret_type (0-manifest theoretical gap,
    // 4-reviewer-accepted), kept so the sound hierarchy/reachability additions
    // never REGRESS an already-emitted valid materialisation (a framework-
    // transitive `<Super> vX = this` the dex-only oracle can't prove and where
    // `this` never reaches the return). But that trust applies ONLY when the
    // anchor genuinely IS the reference return type: `returned` alone is set even
    // for a NON-reference `return <this_reg>` (a register-reuse artifact on
    // lenient dex), and if an ARG sink then supplies an unrelated anchor,
    // trusting `returned` would bless an unproven `<Unrelated> vX = this`
    // (adversarial-review CONFIRMED). So gate it on `is_ref(ret_type) && anchor ==
    // ret_type`; every other (arg-sink) case must use the sound proof below.
    // The def-anchor injects no `vX = this` seed, so there is no up-cast to
    // prove — skip the cls<:anchor gate entirely (entry value reaches no use).
    if (!def_anchor) {
        bool cls_ok = (returned && is_ref(ret_type) && anchor == ret_type) ||
                      assignable(cls_name, anchor);
        if (!cls_ok) {
            std::unordered_set<NodeBase*> reached;
            std::vector<NodeBase*> work{graph.entry};
            while (!work.empty()) {
                NodeBase* b = work.back();
                work.pop_back();
                if (!b || !reached.insert(b).second) continue;
                if (reassign_blocks.count(b)) continue;  // entry value consumed
                for (NodeBase* s : graph.sucs(b)) work.push_back(s);
            }
            for (NodeBase* sb : sink_blocks)
                if (reached.count(sb) && !reassign_blocks.count(sb)) {
                    cls_ok = true;
                    break;
                }
        }
        if (!cls_ok) return false;
    }

    // ---- PHASE B: mutate (all validation passed → atomic). ---------------
    // Fresh local vid beyond every existing lvars key (no collision; the stoi
    // passes that allocate vids already ran), typed as the return type.
    int fresh_reg = this_reg;
    for (const auto& [reg, var] : lvars) {
        (void)var;
        if (reg > fresh_reg) fresh_reg = reg;
    }
    ++fresh_reg;
    const std::string fresh_vid = "v" + std::to_string(fresh_reg);
    auto vX = std::make_shared<Variable>(fresh_vid);
    vX->set_type(anchor);
    lvars[fresh_reg] = vX;

    // Rewrite EVERY reference to the receiver → vX. Pre-RegisterPropagation the
    // IR is flat (each use is a direct operand), so per-instruction replace_lhs /
    // replace_var reaches all of them (every get_used_vars type has a working
    // replace_var; verified against the overrides).
    for (NodeBase* n : graph.rpo) {
        auto* bb = dynamic_cast<BasicBlock*>(n);
        if (!bb) continue;
        for (const auto& ins : bb->ins) {
            if (!ins) continue;
            if (GetLhsKey(ins) == this_vid) ins->replace_lhs(vX);
            for (const auto& u : ins->get_used_vars()) {
                if (u == this_vid) { ins->replace_var(this_vid, vX); break; }
            }
        }
    }

    // Inject `vX = this` at the entry block head — the sole remaining `this`. vX
    // is undeclared and its def now dominates every use from the entry, so
    // PlaceDeclarations lets this copy double as the inline declaration
    // (`<Ret> vX = this;`); DCE drops it when the receiver value is never read.
    // The receiver ThisParam type was CORRUPTED during Construct (each `this = X`
    // AssignExpression ctor did `this_param.set_type(X.get_type())`); restore it
    // to the class before it seeds the copy, and re-assert vX's return type after
    // the copy ctor (which re-propagates the — now restored — receiver type).
    //
    // The DEF-anchor path skips this: the entry value is never read, so vX is
    // fully defined by its `new C` reassignments — a `vX = this` seed would be
    // dead (and, being `C vX = this` with cls⊄C, invalid). vX's declaration is
    // then placed at its allocation def(s) by PlaceDeclarations.
    if (!def_anchor) {
        this_param->set_type(cls_name);
        entry_bb->ins.insert(entry_bb->ins.begin(),
                             std::make_shared<AssignExpression>(vX, this_param));
        vX->set_type(anchor);
    }
    return true;
}

// =============================================================================
// DummyNode — DAD dataflow.py:323
// =============================================================================
DummyNode::DummyNode(std::string n) : Node(std::move(n)) {}

// =============================================================================
// group_variables — DAD dataflow.py:337
// =============================================================================
VariableGroups GroupVariables(
    const std::unordered_map<int, IRFormPtr>& lvars,
    const ChainMap& du, const ChainMap& ud) {
    std::unordered_map<std::string, std::vector<int>> treated;
    VariableGroups variables;
    // Lookup: var_str → index in variables (for O(1) append-to-existing-group).
    std::unordered_map<std::string, size_t> var_idx;

    std::vector<VarLocKey> keys;
    keys.reserve(du.size());
    for (const auto& kv : du) keys.push_back(kv.first);
    std::sort(keys.begin(), keys.end(),
              [](const VarLocKey& a, const VarLocKey& b) {
                  if (a.var != b.var) return a.var < b.var;
                  return std::to_string(a.loc) < std::to_string(b.loc);
              });

    // VarLocKey.var arrives as "vN" (the IR's string register form, e.g.
    // from get_used_vars). `lvars` is int-keyed by register number — DAD
    // uses int register IDs throughout. Strip the leading 'v' before stoi
    // so the lookup succeeds; previously every check raised invalid_argument
    // and was silently swallowed, leaving `variables` empty and disabling
    // SplitVariables (root cause of the IR-cycle masking guards).
    auto in_lvars = [&](const std::string& s) -> bool {
        std::string_view sv{s};
        if (!sv.empty() && sv.front() == 'v') sv.remove_prefix(1);
        if (sv.empty()) return false;
        try {
            const int k = std::stoi(std::string{sv});
            return lvars.find(k) != lvars.end();
        } catch (...) {
            return false;
        }
    };

    for (const VarLocKey& k : keys) {
        const std::string& var = k.var;
        const int loc = k.loc;
        if (!in_lvars(var)) continue;
        auto& trv = treated[var];
        if (std::find(trv.begin(), trv.end(), loc) != trv.end()) continue;
        std::vector<int> defs = {loc};
        std::set<int> uses;
        auto duit = du.find(k);
        if (duit != du.end()) uses.insert(duit->second.begin(),
                                          duit->second.end());
        bool change = true;
        while (change) {
            change = false;
            for (int use : uses) {
                VarLocKey uk{var, use};
                auto udit = ud.find(uk);
                if (udit == ud.end()) continue;
                for (int ldef : udit->second) {
                    if (std::find(defs.begin(), defs.end(), ldef) ==
                        defs.end()) {
                        defs.push_back(ldef);
                        change = true;
                    }
                }
            }
            for (size_t di = 1; di < defs.size(); ++di) {
                VarLocKey dk{var, defs[di]};
                auto duit2 = du.find(dk);
                if (duit2 == du.end()) continue;
                std::set<int> luses(duit2->second.begin(),
                                    duit2->second.end());
                for (int use : luses) {
                    if (uses.insert(use).second) change = true;
                }
            }
        }
        trv.insert(trv.end(), defs.begin(), defs.end());
        auto vit = var_idx.find(var);
        if (vit == var_idx.end()) {
            var_idx[var] = variables.size();
            variables.emplace_back(var, GroupedVersions{});
            vit = var_idx.find(var);
        }
        variables[vit->second].second.emplace_back(
            defs, std::vector<int>(uses.begin(), uses.end()));
    }
    return variables;
}

// =============================================================================
// split_variables — DAD dataflow.py:368
// =============================================================================
// Beyond-DAD (jadx-informed, dupConst/splitByPhi concept — FixTypesVisitor):
// DAD's GroupVariables merges a register's ref-typed def(s) and prim-typed
// def(s) into ONE version when they reach a common use, so a register reused
// across a reference and a primitive (e.g. `FontCallback v = param` on one path,
// `v = -3` on another) is typed once and emits invalid Java. Where the two
// type-regions' USES are DISJOINT (no single use reached by BOTH a ref def and a
// prim def — i.e. no genuine merge/phi point), the version can be split back
// into a ref-version and a prim-version by pure renaming (the jadx SSA model
// keeps them separate to begin with; we re-separate after the fact). A version
// with a genuine phi-use (a use reached by both regions) is left unsplit (a
// later cut may insert a move, as jadx's tryInsertAdditionalMove does).
//
// Returns the sub-partitions of a conflated version if it splits cleanly, else
// an empty vector (caller keeps the original single version). Each partition is
// (defs, uses) like a GroupVariables version; the existing SplitVariables loop
// then types each from its own defs.
// `conflated` is set true when the version is a GENUINE ref+prim conflation (a
// real reference def AND a real primitive def, confirmed from the DIRECT def
// types — NOT the gt-based over-approximation) regardless of whether it splits
// cleanly. The caller: clean partitions → split; else if conflated → type the
// version `Object` (jadx Object+cast, for the phi-use case); else normal.
static std::vector<std::pair<std::vector<int>, std::vector<int>>>
SplitConflatedVersion(const std::string& var_str,
                      const std::vector<int>& defs,
                      const std::vector<int>& uses,
                      const ChainMap& ud, Graph& graph, bool& conflated) {
    auto is_ref = [](const std::string& t) {
        return !t.empty() && (t.front() == 'L' || t.front() == '[');
    };
    auto is_prim = [](const std::string& t) {
        return t.size() == 1 &&
               std::string("IJZBSCFD").find(t[0]) != std::string::npos;
    };
    // Region of a def, NARROW to the clearest genuine-invalid conflation signal:
    //   'R' a REFERENCE producer (a ref-typed def, incl. a move off a ref var —
    //       an object trivially widens to Object, never a false conflation),
    //   'P' a NONZERO INTEGER LITERAL constant (`= -3`) — a literal int in the
    //       SAME register as a reference is the irreconcilable conflation that
    //       renders `RefType v = -3`; a move / arithmetic / method-result prim
    //       is NOT counted (it may resolve, and typing such a register Object
    //       would degrade a clean primitive — the over-fire we must avoid),
    //   'N' the null constant (0 in a ref slot) — neutral,
    //   'U' anything else → bail (do not risk a wrong Object-typing).
    auto region_of = [&](int loc) -> char {
        if (loc < 0) return 'U';
        IRFormPtr in = graph.get_ins_from_loc(loc);
        if (!in) return 'U';
        auto rhs = in->get_rhs();
        if (rhs.empty() || !rhs[0]) return 'U';
        if (auto* c = dynamic_cast<Constant*>(rhs[0].get())) {
            if (is_ref(c->get_type())) return 'R';       // const-string / class
            if (c->get_int_value() == 0) return 'N';     // null / zero
            if (is_prim(c->get_type())) return 'P';      // nonzero int literal
            return 'U';
        }
        // A move (`v = vSrc`) is classified by vSrc's LIVE type — the SAME
        // move-source policy the split-time typing 30 lines below uses (it too
        // trusts a move source only when it is a reference). A stale/false ref
        // move-source could in principle mislabel a clean primitive 'R'
        // (adversarial-review, conf 45) — but this is the established, accepted
        // trust direction (an object only widens; the over-fire we actively
        // avoid is the reverse — a non-const PRIM move → 'U' bail below), and it
        // did NOT manifest as any invalid-Java increase on the corpus a/b
        // (25,309 classes, ref/Object=nonzero-int count unchanged). A non-ref
        // move / method-result / field is 'U' (bail) — never a false 'P'.
        const std::string t = rhs[0]->get_type();
        if (is_ref(t)) return 'R';                       // ref producer / move
        return 'U';                                      // non-const prim → bail
    };
    std::unordered_map<int, char> dreg;
    bool has_r = false, has_p = false;
    for (int d : defs) {
        char r = region_of(d);
        if (r == 'U') return {};                 // unclassifiable def → bail
        dreg[d] = r;
        if (r == 'R') has_r = true;
        if (r == 'P') has_p = true;
    }
    if (!has_r || !has_p) return {};             // not a ref+prim conflation
    conflated = true;                            // genuine ref+prim conflation
    // Partition each use by the regions of the defs that REACH it (ud). A use
    // reached by both an R def and a P def is a genuine phi — bail (no clean
    // rename). 'N' (null) defs are neutral and do not force a region.
    std::vector<int> uses_r, uses_p;
    for (int u : uses) {
        auto it = ud.find(VarLocKey{var_str, u});
        if (it == ud.end()) return {};           // no reaching info → bail
        bool ur = false, up = false;
        for (int d : it->second) {
            auto dit = dreg.find(d);
            if (dit == dreg.end()) continue;      // a def from another version
            if (dit->second == 'R') ur = true;
            else if (dit->second == 'P') up = true;
        }
        if (ur && up) return {};                  // genuine phi-use → bail
        if (ur) uses_r.push_back(u);
        else if (up) uses_p.push_back(u);
        else return {};                           // reached only by 'N' → ambiguous
    }
    // Split the defs by region ('N' null defs go with... the prim side, since a
    // `= 0` on a reference renders `= null` anyway and on a prim is a real 0;
    // but a genuine conflation here has no bare N — keep it simple: N with R).
    std::vector<int> defs_r, defs_p;
    for (int d : defs) {
        char r = dreg[d];
        if (r == 'R' || r == 'N') defs_r.push_back(d);
        else defs_p.push_back(d);
    }
    if (defs_r.empty() || defs_p.empty()) return {};
    return {{defs_r, uses_r}, {defs_p, uses_p}};
}

void SplitVariables(Graph& graph,
                    std::unordered_map<int, IRFormPtr>& lvars,
                    ChainMap& du, ChainMap& ud) {
    auto variables = GroupVariables(lvars, du, ud);
    int nb_vars = 0;
    for (const auto& [k, _] : lvars) nb_vars = std::max(nb_vars, k + 1);

    // Beyond-DAD (jadx-informed): a genuine ref+prim conflation — a register
    // reused across a reference and a primitive, merged by GroupVariables into
    // one version. Where the two regions' USES are disjoint, split cleanly
    // (rename). Where they merge at a phi-use (no clean split), type the version
    // `Object` — the honest common type; the Writer then emits an explicit cast
    // at each type-specific use so the consuming LLM sees the real type there
    // (see writer.cpp visit_invoke). An unsplit conflation is a single version
    // the rename loop skips, so it is Object-typed inline here.
    for (auto& [var_str, versions] : variables) {
        std::vector<std::pair<std::vector<int>, std::vector<int>>> expanded;
        bool changed = false, any_conflated_unsplit = false;
        for (auto& [defs, uses] : versions) {
            bool conflated = false;
            auto parts =
                SplitConflatedVersion(var_str, defs, uses, ud, graph, conflated);
            if (parts.empty()) {
                expanded.emplace_back(defs, uses);
                if (conflated) any_conflated_unsplit = true;
            } else {
                for (auto& p : parts) expanded.push_back(std::move(p));
                changed = true;
            }
        }
        if (changed) versions.swap(expanded);
        // Only a still-single (unsplit) conflated register is Object-typed here;
        // a register that also split otherwise is handled per-version below.
        if (any_conflated_unsplit && versions.size() == 1) {
            std::string_view sv{var_str};
            if (!sv.empty() && sv.front() == 'v') sv.remove_prefix(1);
            try {
                int vi = std::stoi(std::string{sv});
                auto it = lvars.find(vi);
                // Exclude a PARAM: its declared type comes from the method proto
                // (the signature is emitted from that, not the Variable), so
                // Object-typing it would only make the body uses render `(Type)
                // p` casts that disagree with the unchanged signature — redundant
                // noise, not a genuine conflation fix.
                if (it != lvars.end() && it->second &&
                    !dynamic_cast<Param*>(it->second.get()) &&
                    !dynamic_cast<ThisParam*>(it->second.get()))
                    it->second->set_type("Ljava/lang/Object;");
            } catch (...) {}
        }
    }

    for (auto& [var_str, versions] : variables) {
        if (versions.size() == 1) continue;
        // var_str is "vN" — strip leading 'v' for the int-keyed lvars lookup
        // (same fix as in_lvars in GroupVariables above).
        std::string_view sv{var_str};
        if (!sv.empty() && sv.front() == 'v') sv.remove_prefix(1);
        if (sv.empty()) continue;
        int var_int = 0;
        try { var_int = std::stoi(std::string{sv}); } catch (...) { continue; }
        auto orig_it = lvars.find(var_int);
        if (orig_it == lvars.end()) continue;
        IRFormPtr orig_var = orig_it->second;
        lvars.erase(orig_it);
        std::string orig_type = orig_var ? orig_var->get_type() : std::string{};

        for (size_t i = 0; i < versions.size(); ++i) {
            const auto& [defs_vec, uses_vec] = versions[i];
            const int dmin = *std::min_element(defs_vec.begin(),
                                               defs_vec.end());
            IRFormPtr new_version;
            if (dmin < 0) {
                auto* tp = dynamic_cast<ThisParam*>(orig_var.get());
                if (tp) {
                    new_version =
                        std::make_shared<ThisParam>(var_str, orig_type);
                } else {
                    new_version =
                        std::make_shared<Param>(var_str, orig_type);
                }
                lvars[var_int] = new_version;
            } else {
                // Match the "vN" convention used everywhere else in vmap/dvars.
                // Previously we used bare std::to_string(nb_vars), making the
                // new split variable's Vid() "5" while dvars keys are "v5" —
                // PlaceDeclarations then never found the var and skipped its
                // declaration, leaving inline `int v5 = 0;` in branch scope.
                new_version = std::make_shared<Variable>(
                    "v" + std::to_string(nb_vars));
                new_version->set_type(orig_type);
                lvars[nb_vars] = new_version;
                ++nb_vars;
            }
            if (auto* v = dynamic_cast<Variable*>(new_version.get())) {
                v->name = var_str + "_" + std::to_string(i);
            }
            const std::string nv = new_version->Vid();
            // Beyond-DAD type fix: each split version's type must come from its
            // OWN definition, not orig_var's last-written type. DAD copies
            // orig_var.type to every version (dataflow.py:382), so when a
            // register is reused across types — e.g. `const v0,#1` then
            // `new-instance v0, LFoo;` then `iget v0,…:I` — the object version
            // inherits the last `int`, emitting invalid Java
            // `int v0_x = new Foo()`. We read the defining instruction's rhs
            // type instead (the value actually assigned). Param versions
            // (dmin<0) keep orig_type (the declared parameter type). On
            // multi-def disagreement prefer a reference/array type over a
            // primitive (the bug direction). Empty/absent rhs → keep orig_type.
            // A `vDst = move vSrc` def is only PARTLY trusted: its rhs is the
            // live, SHARED source Variable, whose get_type() reflects vSrc's
            // LAST mutation — if vSrc is reused across types after the move the
            // read is stale. The dangerous direction is a stale PRIMITIVE
            // making an object version look primitive (the very bug we fix), so
            // from a move source (is_ident rhs) we trust only a REFERENCE/array
            // type (which can only make the version more object-like, never
            // wrongly primitive). An intrinsically-typed rhs (new-instance /
            // const / field / invoke / cast — non-ident) is always trusted.
            std::string def_type;
            auto is_ref = [](const std::string& t) {
                return !t.empty() && (t.front() == 'L' || t.front() == '[');
            };
            for (int loc : defs_vec) {
                if (loc < 0) continue;
                IRFormPtr ins = graph.get_ins_from_loc(loc);
                if (!ins) continue;
                ins->replace_lhs(new_version);
                auto rhs = ins->get_rhs();
                if (!rhs.empty() && rhs[0]) {
                    std::string t = rhs[0]->get_type();
                    const bool trust =
                        !t.empty() && (!rhs[0]->is_ident() || is_ref(t));
                    if (trust &&
                        (def_type.empty() || (is_ref(t) && !is_ref(def_type)))) {
                        def_type = std::move(t);
                    }
                }
                VarLocKey old_k{var_str, loc};
                auto it = du.find(old_k);
                if (it != du.end()) {
                    auto val = std::move(it->second);
                    du.erase(it);
                    du[VarLocKey{nv, loc}] = std::move(val);
                }
            }
            if (dmin >= 0 && !def_type.empty()) {
                // Beyond-DAD (mixed-version conflation): among a multi-version
                // register, a version that is itself a genuine ref+nonzero-int
                // conflation (a real reference def AND a real int-literal def
                // merging at a phi) has no single Java type — the multi-def
                // ref-preference above would type it a reference and render the
                // misleading `zzj v = 1`. The size==1 pre-pass Object-types the
                // unsplit case; here we cover the split-register case, typing
                // such a version `Object` (the Writer then casts its ref uses).
                // Safe to call mid-rename: `conflated` is decided purely from
                // DIRECT def rhs types — the preceding def-loop's replace_lhs
                // touches only the LHS, not the rhs region_of reads, and this
                // version's `ud` use-keys are still intact (each use-loc belongs
                // to exactly one version, re-keyed only in its own uses-loop
                // below). Only the flag is consumed; partitions are discarded.
                bool conflated = false;
                SplitConflatedVersion(var_str, defs_vec, uses_vec, ud, graph,
                                      conflated);
                new_version->set_type(conflated ? std::string("Ljava/lang/Object;")
                                                 : def_type);
            }
            for (int loc : uses_vec) {
                IRFormPtr ins = graph.get_ins_from_loc(loc);
                if (!ins) continue;
                ins->replace_var(var_str, new_version);
                VarLocKey old_k{var_str, loc};
                auto it = ud.find(old_k);
                if (it != ud.end()) {
                    auto val = std::move(it->second);
                    ud.erase(it);
                    ud[VarLocKey{nv, loc}] = std::move(val);
                }
            }
        }
    }
}

// =============================================================================
// ReachDefResult — DAD dataflow.py:406 reach_def_analysis
// =============================================================================
ReachDefResult::ReachDefResult(Graph& graph,
                               const std::vector<std::string>& params) {
    NodeBase* old_entry = graph.entry;
    NodeBase* old_exit = graph.exit;
    dummy_entry_ = std::make_unique<DummyNode>("entry");
    graph.add_node(dummy_entry_.get());
    if (old_entry) graph.add_edge(dummy_entry_.get(), old_entry);
    graph.entry = dummy_entry_.get();
    if (old_exit) {
        dummy_exit_ = std::make_unique<DummyNode>("exit");
        graph.add_node(dummy_exit_.get());
        graph.add_edge(old_exit, dummy_exit_.get());
        graph.rpo.push_back(dummy_exit_.get());
    }

    analysis_ = std::make_unique<BasicReachDef>(graph, params);
    analysis_->run();

    graph.remove_node(dummy_entry_.get());
    if (dummy_exit_) graph.remove_node(dummy_exit_.get());
    graph.entry = old_entry;
}

// =============================================================================
// build_def_use — DAD dataflow.py:432
// =============================================================================
DefUseChains BuildDefUse(Graph& graph,
                         const std::vector<std::string>& lparams) {
    ReachDefResult result(graph, lparams);
    BasicReachDef& analysis = result.analysis();

    DefUseChains chains;
    for (NodeBase* node : graph.rpo) {
        for (const auto& [i, ins] : LocWithIns(node)) {
            if (!ins) continue;
            for (const auto& var : ins->get_used_vars()) {
                if (analysis.def_to_loc.find(var) ==
                    analysis.def_to_loc.end()) {
                    continue;
                }
                auto& ldefs = analysis.defs[node];
                int prior_def = -1;
                auto lit = ldefs.find(var);
                if (lit != ldefs.end()) {
                    for (int v : lit->second) {
                        if (prior_def < v && v < i) prior_def = v;
                    }
                }
                if (prior_def >= 0) {
                    chains.ud[VarLocKey{var, i}].push_back(prior_def);
                } else {
                    const auto& dlocs = analysis.def_to_loc[var];
                    const auto& rset = analysis.R[node];
                    auto& target = chains.ud[VarLocKey{var, i}];
                    for (int v : dlocs) {
                        if (rset.find(v) != rset.end()) target.push_back(v);
                    }
                }
            }
        }
    }
    for (const auto& [k, defs_loc] : chains.ud) {
        for (int def_loc : defs_loc) {
            chains.du[VarLocKey{k.var, def_loc}].push_back(k.loc);
        }
    }
    return chains;
}

// =============================================================================
// place_declarations — DAD dataflow.py:471
// =============================================================================
void PlaceDeclarations(
    Graph& graph,
    const std::unordered_map<std::string, IRFormPtr>& dvars,
    const ChainMap& /*du*/, const ChainMap& ud) {
    auto idom = graph.immediate_dominators();
    for (NodeBase* node : graph.post_order()) {
        for (const auto& [loc, ins] : LocWithIns(node)) {
            if (!ins) continue;
            auto used = ins->get_used_vars();
            for (const auto& var : used) {
                auto dit = dvars.find(var);
                if (dit == dvars.end()) continue;
                auto* v = dynamic_cast<Variable*>(dit->second.get());
                if (!v) continue;
                if (dynamic_cast<Param*>(dit->second.get())) continue;

                auto udit = ud.find(VarLocKey{var, loc});
                if (udit == ud.end()) continue;
                const auto& var_defs_locs = udit->second;
                std::unordered_set<NodeBase*> def_nodes;
                for (int def_loc : var_defs_locs) {
                    NodeBase* dn = graph.get_node_from_loc(def_loc);
                    if (!dn || dn->in_catch) continue;
                    // Skip unreachable nodes — they aren't in the idom map
                    // and have num=0, which would make CommonDom spin (DAD
                    // never sees these because post_order() yields only
                    // reachable nodes; our get_node_from_loc returns any
                    // node holding the loc, reachable or not).
                    if (idom.find(dn) == idom.end() && dn != graph.entry) continue;
                    def_nodes.insert(dn);
                }
                if (def_nodes.empty()) continue;
                auto dn_it = def_nodes.begin();
                NodeBase* common_dominator = *dn_it;
                def_nodes.erase(dn_it);
                for (NodeBase* dn : def_nodes) {
                    common_dominator =
                        CommonDom(idom, common_dominator, dn);
                }
                auto* cd_bb = dynamic_cast<BasicBlock*>(common_dominator);
                if (!cd_bb || !cd_bb->has_ins_range) continue;
                // DAD dataflow.py:495-499 — skip declaration when ANY def loc
                // is inside the common dominator's instruction range (the
                // def itself doubles as the declaration).
                bool any_in_range = false;
                for (int v_loc : var_defs_locs) {
                    if (v_loc >= cd_bb->ins_range_lo &&
                        v_loc < cd_bb->ins_range_hi) {
                        any_in_range = true;
                        break;
                    }
                }
                if (any_in_range) continue;
                cd_bb->add_variable_declaration(dit->second);
            }
        }
    }
}

}  // namespace dexkit::dad
