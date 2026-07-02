// dataflow.cpp — DAD dataflow.py port.
// See include/dataflow.h for entity list & status.

#include "dataflow.h"

#include <algorithm>
#include <cstdio>
#include <cstdlib>
#include <iterator>
#include <memory>
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
void FixInitResultTypes(Graph& graph) {
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
