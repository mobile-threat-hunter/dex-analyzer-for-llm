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
static void InferCascadeTypes(Graph& graph) {
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
    // `==`/`!=` ConditionalExpression operand pairs — resolved in a post-pass
    // (once defs_of is complete): if one operand is a nonzero int constant,
    // the other is proven a primitive and joins int_use_vids.
    std::vector<std::pair<std::string, std::string>> eqne_pairs;
    auto note_obj = [&](IRForm* f) {
        if (auto* inv = dynamic_cast<InvokeInstruction*>(f)) {
            if (!inv->base().empty()) object_vids.insert(inv->base());
        } else if (auto* ie = dynamic_cast<InstanceExpression*>(f)) {
            if (!ie->arg_id().empty()) object_vids.insert(ie->arg_id());
        } else if (auto* ii = dynamic_cast<InstanceInstruction*>(f)) {
            if (!ii->lhs_id().empty()) object_vids.insert(ii->lhs_id());
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
            auto rhs = ins->get_rhs();
            if (!rhs.empty() && rhs[0]) { note_obj(rhs[0].get());
                note_int(rhs[0].get()); }
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
    std::function<char(IRForm*, std::set<std::string>&, std::string&)> gt =
        [&](IRForm* rhsv, std::set<std::string>& seen,
            std::string& type_out) -> char {
        if (!rhsv) return 'U';
        if (rhsv->is_ident()) {  // move — resolve source transitively
            const std::string sid = rhsv->Vid();
            if (seen.count(sid)) return 'M';
            seen.insert(sid);
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
            bool sib_r = false, sib_p = false, sib_u = false;
            std::string ref_seen, prim_seen;
            for (IRForm* d : dit->second) {
                auto dr = d->get_rhs();
                if (dr.empty() || !dr[0]) { sib_u = true; continue; }
                std::string ct;
                char c = gt(dr[0].get(), seen, ct);
                if (c == 'R') { sib_r = true;
                    if (ref_seen.empty()) ref_seen = ct; }
                else if (c == 'P') { sib_p = true;
                    if (prim_seen.empty()) prim_seen = ct; }
                else if (c == 'U' || c == 'M') sib_u = true;
                // 'N' (null/zero) is neutral.
            }
            if (sib_u || (sib_r && sib_p)) return 'U';  // ambiguous → block
            if (sib_r) { if (type_out.empty()) type_out = ref_seen;
                return 'R'; }
            if (sib_p) { if (type_out.empty()) type_out = prim_seen;
                return 'P'; }
            return 'N';
        }
        // Unambiguous reference producers.
        if (dynamic_cast<NewInstance*>(rhsv) ||
            dynamic_cast<NewArrayExpression*>(rhsv) ||
            dynamic_cast<FilledArrayExpression*>(rhsv) ||
            dynamic_cast<MoveExceptionExpression*>(rhsv) ||
            dynamic_cast<CheckCastExpression*>(rhsv)) {
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
        if (dynamic_cast<NewInstance*>(r) ||
            dynamic_cast<NewArrayExpression*>(r) ||
            dynamic_cast<FilledArrayExpression*>(r) ||
            dynamic_cast<MoveExceptionExpression*>(r) ||
            dynamic_cast<CheckCastExpression*>(r))
            return {};
        const std::string t = r->get_type();
        return is_prim_desc(t) ? t : std::string{};
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
    for (auto& [vid, dvec] : defs_of) {
        if (dvec.empty()) continue;
        auto vit = dvec[0]->var_map.find(vid);
        if (vit == dvec[0]->var_map.end() || !vit->second) continue;
        const std::string cur = vit->second->get_type();
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
            std::string w;
            bool ok = true;
            for (IRForm* d : dvec) {
                auto dr = d->get_rhs();
                if (dr.empty() || !dr[0]) { ok = false; break; }
                std::set<std::string> seen{vid};
                std::string dw = resolve_prim_width(dr[0].get(), seen);
                if (dw.empty()) { ok = false; break; }   // genuine ref / unknown
                if (w.empty()) w = dw;
                else if (w != dw) { ok = false; break; }  // width disagreement
            }
            if (ok && !w.empty() && w != "Z") {
                retypes.emplace_back(vit->second.get(), w);
                continue;
            }
        }
        // Any unresolved def, a genuine ref+prim merge, or disagreeing
        // reference producers → refuse (would risk a wrong guess).
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
            std::string w;
            bool ok = true;
            for (IRForm* d : dvec) {
                auto dr = d->get_rhs();
                if (dr.empty() || !dr[0]) { ok = false; break; }
                std::set<std::string> seen{vid};
                std::string dw = resolve_prim_width(dr[0].get(), seen);
                if (dw.empty()) { ok = false; break; }
                if (w.empty()) w = dw;
                else if (w != dw) { ok = false; break; }
            }
            // Java widening order for assignment: {Z,B,C,S,I}=1 < J=2 < F=3 <
            // D=4. `cur v = w` is an invalid narrowing iff rank(w) > rank(cur).
            auto rank = [](const std::string& t) {
                if (t == "D") return 4; if (t == "F") return 3;
                if (t == "J") return 2; return 1;
            };
            if (ok && !w.empty() && rank(w) > rank(cur))
                retypes.emplace_back(vit->second.get(), w);
        }
    }
    for (auto& [var, t] : retypes) var->set_type(t);
}

// Driver — DAD types every register version from the register's LAST write
// (orig_var.type), so a Dalvik register reused across incompatible types
// leaves its split versions mistyped. This corrects them at the VALUE/version
// level in two def-anchored passes (docs/type-inference-design.md).
void FixInitResultTypes(Graph& graph) {
    FixAllocationResultTypes(graph);  // design §1: allocation ground truth
    InferCascadeTypes(graph);         // design §2/§3: move-chain cascade/mirror
}

// Beyond-DAD: see dataflow.h. Materialise a reused receiver register as a local.
bool MaterializeReusedThis(Graph& graph,
                           std::unordered_map<int, IRFormPtr>& lvars,
                           int this_reg, const std::string& cls_name,
                           const std::string& ret_type, bool is_ctor) {
    auto is_ref = [](const std::string& t) {
        return !t.empty() && (t.front() == 'L' || t.front() == '[');
    };
    // The materialised local is typed as the method's RETURN type — the one
    // assignability anchor valid Dalvik gives us: everything that flows to a
    // `return` is assignable to it. So we only fire when the reused slot is
    // RETURNED and the return type is a reference (`return this` requires the
    // receiver — hence the class — to be assignable to it, so `<Ret> vX = this`
    // is a valid up-cast, and every reuse value returned alongside is likewise
    // assignable). This provably yields valid Java for the case handled and
    // leaves everything else as DAD's (invalid-but-no-worse) `this = X`.
    if (is_ctor) return false;         // super()/this() uses the receiver specially
    if (!is_ref(ret_type)) return false;  // no reference return anchor

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

    bool reused = false, returned = false;
    for (NodeBase* n : graph.rpo) {
        auto* bb = dynamic_cast<BasicBlock*>(n);
        if (!bb) continue;
        for (const auto& ins : bb->ins) {
            if (!ins) continue;
            // Is the receiver returned? (a ReturnInstruction using it.)
            if (dynamic_cast<ReturnInstruction*>(ins.get())) {
                for (const auto& u : ins->get_used_vars())
                    if (u == this_vid) { returned = true; break; }
            }
            if (GetLhsKey(ins) != this_vid) continue;
            reused = true;
            // Every reassignment rhs must be provably assignable to `vX` (typed
            // ret_type):
            //  - a reference whose type EXACTLY equals ret_type. Exact equality
            //    (not just is_ref) is REQUIRED: SplitVariables leaves the reuse as
            //    a single unsplit phi-web, which GroupVariables can bind a def into
            //    that reaches only an INTERMEDIATE use (never the return) whose
            //    type is unrelated to ret_type — `vX = getBar()` where Bar ⊄ Foo
            //    (adversarial-review CONFIRMED). Without a type hierarchy or a
            //    per-def reaches-the-return analysis, exact match is the only
            //    sound proof; a valid subtype up-cast is conservatively skipped
            //    too (correctness over coverage).
            //  - the NARROW-integer constant 0 (`const/4 0`) = the null reference.
            //    A wide const-0 (`const-wide`, type J/D) is NOT null (lenient-load
            //    PLAUSIBLE) — require a narrow int descriptor.
            // A VOID invoke or a genuine primitive (`this = 5`) also bails — left
            // as DAD's output. NOTE: the void `this = <call>` case no longer
            // occurs (the opcode_ins InvokeSuperRange/InvokeDirectRange root-cause
            // fix nulls `returned` for void, so no such AssignExpression is built);
            // this VOID guard is now DEFENSIVE — retained so a future DAD-artifact
            // (or a revert of that fix) that reintroduces a void `this =` still
            // bails here rather than emitting `<Ret> vX = <void call>`.
            auto rhs = ins->get_rhs();
            const std::string t =
                (!rhs.empty() && rhs[0]) ? rhs[0]->get_type() : std::string{};
            if (is_ref(t)) {
                if (t != ret_type) return false;           // not provably assignable
                continue;
            }
            auto* c = !rhs.empty() ? dynamic_cast<Constant*>(rhs[0].get())
                                   : nullptr;
            if (c && c->get_int_value() == 0 && t.size() == 1 &&
                std::string("IZBSC").find(t) != std::string::npos)
                continue;                                  // null reference — ok
            return false;                                  // void / primitive / non-exact ref
        }
    }
    if (!reused || !returned) return false;

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
    vX->set_type(ret_type);
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
    this_param->set_type(cls_name);
    entry_bb->ins.insert(entry_bb->ins.begin(),
                         std::make_shared<AssignExpression>(vX, this_param));
    vX->set_type(ret_type);
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
void SplitVariables(Graph& graph,
                    std::unordered_map<int, IRFormPtr>& lvars,
                    ChainMap& du, ChainMap& ud) {
    auto variables = GroupVariables(lvars, du, ud);
    int nb_vars = 0;
    for (const auto& [k, _] : lvars) nb_vars = std::max(nb_vars, k + 1);

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
                new_version->set_type(def_type);
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
