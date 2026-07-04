// ssa.cpp — Additive SSA analysis. See ssa.h / docs/ssa-design.md.
//
// Phase 1a: dominance frontiers (Cytron et al.). Pure function over the CFG.

#include "ssa.h"

#include <algorithm>
#include <functional>
#include <set>
#include <unordered_set>

#include "basic_blocks.h"  // BasicBlock::get_loc_with_ins
#include "graph.h"
#include "instruction.h"   // IRForm::GetLhsId / get_used_vars

namespace dexkit::dad {

// Mirror of dataflow.cpp's (anonymous-namespace) LocWithIns: a node's (loc, ins)
// pairs. DummyNode → empty; BasicBlock → its loc_ins.
static std::vector<std::pair<int, IRFormPtr>> LocWithIns(NodeBase* n) {
    if (auto* bb = dynamic_cast<BasicBlock*>(n)) return bb->get_loc_with_ins();
    return {};
}

std::unordered_map<NodeBase*, std::vector<NodeBase*>>
DominanceFrontiers(Graph& graph,
                   const std::unordered_map<NodeBase*, NodeBase*>& idom) {
    std::unordered_map<NodeBase*, std::vector<NodeBase*>> df;

    auto idom_of = [&](NodeBase* n) -> NodeBase* {
        auto it = idom.find(n);
        return it == idom.end() ? nullptr : it->second;
    };
    auto reachable = [&](NodeBase* n) -> bool {
        // A node is in the dominator tree iff it appears as a key in idom
        // (DomLt maps entry → nullptr, every other reachable node → its idom).
        return idom.find(n) != idom.end();
    };

    // Seed every reachable node with an empty frontier (so callers can iterate
    // df for all reachable nodes without a missing-key check). We accumulate
    // into sets first to dedup, then materialise sorted vectors.
    std::unordered_map<NodeBase*, std::unordered_set<NodeBase*>> acc;
    for (NodeBase* n : graph.nodes)
        if (reachable(n)) acc[n];

    // Cytron: for each join node b (>= 2 reachable predecessors), walk up the
    // dominator tree from each predecessor to idom(b), adding b to every node's
    // frontier along the way.
    //
    // Entry exception: the entry block carries an IMPLICIT method-start edge
    // that is not a graph predecessor. When the entry is also a loop header (a
    // back-edge targets it — DAD's CFG has no preheader), it can have a single
    // graph predecessor yet still be a genuine join (implicit-entry + back-edge
    // = 2). Treat the entry as a join whenever it has >= 1 graph predecessor so
    // a register defined on the back-edge gets its phi placed at the entry
    // (matching reaching-def, which seeds A[entry] with the param defs). Sound
    // because the entry dominates every node, so every graph predecessor of the
    // entry is necessarily a back-edge (never a spurious non-loop join).
    const size_t walk_cap = graph.nodes.size() + 1;   // idom-tree depth bound
    for (NodeBase* b : graph.nodes) {
        if (!reachable(b)) continue;
        std::vector<NodeBase*> preds;
        for (NodeBase* p : graph.all_preds(b))
            if (reachable(p)) preds.push_back(p);
        // Dedup: a block reached from a predecessor by BOTH a normal and a catch
        // edge appears twice in all_preds; a predecessor BLOCK counts once (SSA
        // merges one value per predecessor block, and the join test counts
        // distinct preds). Pointer sort here is dedup-only (not an ordering that
        // feeds output).
        std::sort(preds.begin(), preds.end());
        preds.erase(std::unique(preds.begin(), preds.end()), preds.end());
        const size_t min_preds = (b == graph.entry) ? 1 : 2;
        if (preds.size() < min_preds) continue;
        NodeBase* ib = idom_of(b);
        for (NodeBase* p : preds) {
            NodeBase* runner = p;
            // Walk up to idom(b): b is on the frontier of every node strictly
            // dominated by that predecessor up to (not including) idom(b). A
            // genuine Lengauer-Tarjan idom map is a tree so this terminates; the
            // public two-arg overload accepts an EXTERNAL idom map, so bound the
            // walk (a cyclic non-tree idom would otherwise spin — 0-hang
            // invariant).
            for (size_t steps = 0; runner && runner != ib; ++steps) {
                if (steps > walk_cap) break;      // non-tree idom → bail
                acc[runner].insert(b);
                NodeBase* next = idom_of(runner);
                if (next == runner) break;        // self-idom (1-cycle)
                runner = next;
            }
        }
    }

    // Materialise: sort each frontier by (num, name) for determinism.
    for (auto& [n, s] : acc) {
        std::vector<NodeBase*> v(s.begin(), s.end());
        std::sort(v.begin(), v.end(), [](NodeBase* a, NodeBase* b) {
            if (a->num != b->num) return a->num < b->num;
            return a->name < b->name;
        });
        df[n] = std::move(v);
    }
    return df;
}

std::unordered_map<NodeBase*, std::vector<NodeBase*>>
DominanceFrontiers(Graph& graph) {
    return DominanceFrontiers(graph, DomLt(graph));
}

// -----------------------------------------------------------------------------
// Phase 1b: SSA construction (phi insertion + renaming).
// -----------------------------------------------------------------------------
SsaResult BuildSsa(Graph& graph, const std::vector<std::string>& params) {
    SsaResult res;
    NodeBase* entry = graph.entry;
    if (!entry) { res.ok = false; return res; }

    auto idom = DomLt(graph);
    auto reachable = [&](NodeBase* n) { return idom.find(n) != idom.end(); };
    auto df = DominanceFrontiers(graph, idom);

    // Reachable blocks in a deterministic order (by num, name).
    std::vector<NodeBase*> blocks;
    for (NodeBase* n : graph.nodes) if (reachable(n)) blocks.push_back(n);
    std::sort(blocks.begin(), blocks.end(), [](NodeBase* a, NodeBase* b) {
        if (a->num != b->num) return a->num < b->num;
        return a->name < b->name;
    });

    // --- collect registers + their def-blocks --------------------------------
    // A "register" is a parameter or any GetLhsId() def key. def_blocks[reg] =
    // the set of blocks defining reg (params defined at entry).
    std::set<std::string> regs;
    std::map<std::string, std::set<NodeBase*>> def_blocks;
    for (const std::string& p : params) {
        regs.insert(p);
        def_blocks[p].insert(entry);
    }
    for (NodeBase* b : blocks) {
        for (const auto& [loc, ins] : LocWithIns(b)) {
            if (!ins) continue;
            auto lhs = ins->GetLhsId();
            if (lhs.has_value() && !lhs->empty()) {
                regs.insert(*lhs);
                def_blocks[*lhs].insert(b);
            }
        }
    }

    // --- phi insertion (Cytron iterated dominance frontier) ------------------
    // phis_at[block] = phi indices placed at that block. has_phi[(reg,block)]
    // dedups. Registers processed in sorted order for determinism.
    std::map<NodeBase*, std::vector<int>> phis_at;
    std::set<std::pair<std::string, NodeBase*>> has_phi;
    for (const std::string& reg : regs) {
        std::vector<NodeBase*> work(def_blocks[reg].begin(),
                                    def_blocks[reg].end());
        std::set<NodeBase*> in_work(work.begin(), work.end());
        while (!work.empty()) {
            NodeBase* b = work.back();
            work.pop_back();
            in_work.erase(b);
            auto dfit = df.find(b);
            if (dfit == df.end()) continue;
            for (NodeBase* w : dfit->second) {   // DF is (num,name)-sorted
                if (has_phi.count({reg, w})) continue;
                has_phi.insert({reg, w});
                int idx = static_cast<int>(res.phis.size());
                SsaPhi phi;
                phi.block = w;
                phi.reg = reg;
                res.phis.push_back(std::move(phi));
                phis_at[w].push_back(idx);
                // A phi is itself a def of reg at w — iterate.
                if (!def_blocks[reg].count(w) && !in_work.count(w)) {
                    work.push_back(w);
                    in_work.insert(w);
                }
            }
        }
    }
    // Keep each block's phi list in sorted-reg order (determinism of numbering).
    for (auto& [b, idxs] : phis_at) {
        std::sort(idxs.begin(), idxs.end(), [&](int a, int c) {
            return res.phis[a].reg < res.phis[c].reg;
        });
    }

    // --- renaming (iterative dominator-tree DFS) -----------------------------
    // Dom-tree children from idom, sorted (num, name).
    std::map<NodeBase*, std::vector<NodeBase*>> children;
    for (NodeBase* n : blocks) {
        auto it = idom.find(n);
        if (it != idom.end() && it->second) children[it->second].push_back(n);
    }
    for (auto& [p, cs] : children)
        std::sort(cs.begin(), cs.end(), [](NodeBase* a, NodeBase* b) {
            if (a->num != b->num) return a->num < b->num;
            return a->name < b->name;
        });

    // Per-register version stack + next-version counter. Seed every reg with
    // version 0 (the entry value). A PARAMETER's version 0 is a real live-in
    // (DEF_LIVEIN, matching reaching-def's negative param loc); a non-param
    // register's version 0 is uninitialized (DEF_UNDEF — not a reaching def).
    std::set<std::string> param_set(params.begin(), params.end());
    std::map<std::string, std::vector<int>> stack;
    std::map<std::string, int> counter;
    for (const std::string& reg : regs) {
        stack[reg].push_back(0);
        counter[reg] = 0;
        res.def_site[{reg, 0}] =
            param_set.count(reg) ? SsaResult::DEF_LIVEIN : SsaResult::DEF_UNDEF;
    }

    struct Frame { NodeBase* b; bool exit; std::vector<std::string> pushed; };
    std::vector<Frame> wl;
    wl.push_back({entry, false, {}});
    while (!wl.empty()) {
        Frame fr = std::move(wl.back());
        wl.pop_back();
        if (fr.exit) {
            for (const std::string& reg : fr.pushed) stack[reg].pop_back();
            continue;
        }
        NodeBase* b = fr.b;
        std::vector<std::string> pushed;

        // 0. The entry block has an implicit method-start edge with no
        // predecessor block. If the entry is also a loop header (back-edges
        // target it — DAD's CFG has no preheader), its phis would otherwise miss
        // the live-in operand. Add it now (a nullptr pred = the entry edge),
        // BEFORE the phis push, so the stack top is still the live-in version 0.
        if (b == entry) {
            auto e0 = phis_at.find(b);
            if (e0 != phis_at.end())
                for (int idx : e0->second) {
                    SsaPhi& phi = res.phis[idx];
                    phi.operands.push_back({nullptr, stack[phi.reg].back()});
                }
        }

        // 1. phi results define new versions.
        auto pit = phis_at.find(b);
        if (pit != phis_at.end()) {
            for (int idx : pit->second) {
                SsaPhi& phi = res.phis[idx];
                int v = ++counter[phi.reg];
                phi.result = v;
                res.def_site[{phi.reg, v}] = SsaResult::DEF_PHI;
                res.phi_index[{phi.reg, v}] = idx;
                stack[phi.reg].push_back(v);
                pushed.push_back(phi.reg);
            }
        }
        // 2. instructions in loc order: uses read top-of-stack, then defs push.
        for (const auto& [loc, ins] : LocWithIns(b)) {
            if (!ins) continue;
            for (const std::string& u : ins->get_used_vars()) {
                auto sit = stack.find(u);
                if (sit == stack.end() || sit->second.empty()) continue;  // not a reg
                res.use_version[{u, loc}] = sit->second.back();
            }
            auto lhs = ins->GetLhsId();
            if (lhs.has_value() && !lhs->empty() && stack.count(*lhs)) {
                int v = ++counter[*lhs];
                res.def_site[{*lhs, v}] = loc;
                stack[*lhs].push_back(v);
                pushed.push_back(*lhs);
            }
        }
        // 3. fill each successor's phi operands from this predecessor. Dedup
        // successors: a block reached from b by BOTH a normal and a catch edge
        // appears twice in all_sucs — a predecessor contributes exactly ONE
        // operand per phi (SSA: one value per predecessor block).
        std::set<NodeBase*> seen_suc;
        for (NodeBase* s : graph.all_sucs(b)) {
            if (!seen_suc.insert(s).second) continue;
            auto sp = phis_at.find(s);
            if (sp == phis_at.end()) continue;
            for (int idx : sp->second) {
                SsaPhi& phi = res.phis[idx];
                res.phis[idx].operands.push_back({b, stack[phi.reg].back()});
            }
        }
        // 4. schedule undo, then dom-tree children (sorted → push reversed).
        wl.push_back({b, true, std::move(pushed)});
        auto cit = children.find(b);
        if (cit != children.end())
            for (auto rit = cit->second.rbegin(); rit != cit->second.rend();
                 ++rit)
                wl.push_back({*rit, false, {}});
    }

    // Sort each phi's operands by predecessor (num, name) for determinism. A
    // nullptr predecessor (the entry / live-in edge) sorts first — handled
    // explicitly so no raw-pointer `<` (unspecified ordering) feeds the sort.
    for (SsaPhi& phi : res.phis)
        std::sort(phi.operands.begin(), phi.operands.end(),
                  [](const std::pair<NodeBase*, int>& a,
                     const std::pair<NodeBase*, int>& b) {
                      const bool an = !a.first, bn = !b.first;
                      if (an || bn) return an && !bn;   // nullptr sorts first
                      if (a.first->num != b.first->num)
                          return a.first->num < b.first->num;
                      return a.first->name < b.first->name;
                  });

    // Deterministic phi ORDER. res.phis is appended in phi-DISCOVERY order,
    // which comes off a pointer-keyed worklist (def_blocks is keyed by
    // NodeBase*) — so the vector order is ASLR/pointer-dependent. Phase 1 output
    // is unaffected (only the (reg,version) maps are read downstream, and they
    // are stable), but Phase 2 ITERATES res.phis to classify merges, so a
    // pointer-order-dependent vector order would leak non-determinism into
    // output. Impose a total order by (reg, block num, name) — one phi per
    // (reg, block) so it is unique — and rebuild phi_index for the new indices.
    std::sort(res.phis.begin(), res.phis.end(),
              [](const SsaPhi& a, const SsaPhi& b) {
                  if (a.reg != b.reg) return a.reg < b.reg;
                  if (a.block->num != b.block->num)
                      return a.block->num < b.block->num;
                  return a.block->name < b.block->name;
              });
    res.phi_index.clear();
    for (int i = 0; i < static_cast<int>(res.phis.size()); ++i)
        res.phi_index[{res.phis[i].reg, res.phis[i].result}] = i;
    return res;
}

// -----------------------------------------------------------------------------
// Phase 1c: SSA oracle — reconstruction faithfulness vs reaching-def `ud`.
// -----------------------------------------------------------------------------
// Scope: checks only uses recorded in `ssa.use_version` (uses of a param or a
// defined register — the same predicate BuildDefUse uses to emit a `ud` entry).
// A use of a never-defined non-param register is dropped by BOTH analyses
// (verified dex forbids use-before-def; such shapes only arise on lenient /
// unverified packer dumps), so the reconstruction proof is silent — not
// contradicted — there. Relies on `graph.nodes == reachable-from-entry` (DAD's
// Construct builds only bfs-reachable blocks); BasicReachDef walks the same set.
SsaOracle VerifySsa(Graph& graph, const std::vector<std::string>& /*params*/,
                    const SsaResult& ssa, const ChainMap& ud) {
    SsaOracle rep;
    (void)graph;

    // resolve(reg, version) → the set of REAL def locs (>=0) reaching this SSA
    // value plus whether a live-in reaches it. Computed as a reachability BFS
    // over the phi-operand graph (all operands are versions of the SAME reg): a
    // real-def node contributes its loc, a live-in node sets the flag, a phi
    // node expands to its operands. A `visited` set makes it cycle-safe (a loop
    // phi web is one SCC — BFS collects every real def in it once). No partial
    // memoisation (that corrupts SCC results); per-use BFS is cheap on real
    // methods.
    auto resolve = [&](const std::string& reg,
                       int start) -> std::pair<std::set<int>, bool> {
        std::set<int> real;
        bool livein = false;
        std::set<int> visited{start};
        std::vector<int> stack{start};
        while (!stack.empty()) {
            int v = stack.back();
            stack.pop_back();
            auto dit = ssa.def_site.find({reg, v});
            if (dit == ssa.def_site.end() ||
                dit->second == SsaResult::DEF_UNDEF) {
                // Uninitialized entry value of a non-param register — not a
                // reaching def (matches reaching-def, which has no loc for it).
            } else if (dit->second == SsaResult::DEF_LIVEIN) {
                livein = true;
            } else if (dit->second == SsaResult::DEF_PHI) {
                auto pit = ssa.phi_index.find({reg, v});
                if (pit != ssa.phi_index.end())
                    for (const auto& [pred, ov] : ssa.phis[pit->second].operands) {
                        (void)pred;
                        if (visited.insert(ov).second) stack.push_back(ov);
                    }
            } else {
                real.insert(dit->second);            // a real def loc
            }
        }
        return {real, livein};
    };

    for (const auto& [key, ver] : ssa.use_version) {
        const std::string& reg = key.first;
        const int use_loc = key.second;
        ++rep.uses_checked;
        auto ssa_res = resolve(reg, ver);
        // ud's reaching defs for this use: partition into real (>=0) and
        // live-in (negative = param).
        std::set<int> ud_real;
        bool ud_livein = false;
        auto uit = ud.find(VarLocKey{reg, use_loc});
        if (uit != ud.end()) {
            for (int d : uit->second) {
                if (d < 0) ud_livein = true;
                else ud_real.insert(d);
            }
        }
        if (ssa_res.first != ud_real || ssa_res.second != ud_livein) {
            ++rep.mismatches;
            if (rep.first.empty()) {
                rep.first = reg + "@" + std::to_string(use_loc) +
                            " ssa_real=" + std::to_string(ssa_res.first.size()) +
                            " ud_real=" + std::to_string(ud_real.size()) +
                            " ssa_livein=" + std::to_string(ssa_res.second) +
                            " ud_livein=" + std::to_string(ud_livein);
            }
        }
    }
    return rep;
}

}  // namespace dexkit::dad
