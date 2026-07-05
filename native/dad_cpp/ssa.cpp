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

    // --- liveness (pruned SSA) -----------------------------------------------
    // Minimal (Cytron) SSA places a phi at the iterated dominance frontier of
    // EVERY def, including for registers that are DEAD at the join. In optimized
    // / obfuscated dex a single Dalvik register is reused across many unrelated
    // live ranges; a dead phi at a join FALSELY merges those ranges into one SSA
    // web, manufacturing int↔reference conflicts corpus-wide. Pruned SSA places
    // a phi for reg at block w ONLY when reg is LIVE-IN at w. Backward dataflow:
    //   use[b]  = registers used in b before being (re)defined in b
    //   def[b]  = registers defined in b
    //   live_in[b]  = use[b] ∪ (live_out[b] \ def[b])
    //   live_out[b] = ∪ live_in[succ]
    // Monotone → terminates. Reachable blocks only (same set as phi placement).
    std::map<NodeBase*, std::set<std::string>> use_b, def_b, live_in;
    for (NodeBase* b : blocks) {
        std::set<std::string> defined;
        for (const auto& [loc, ins] : LocWithIns(b)) {
            if (!ins) continue;
            for (const std::string& u : ins->get_used_vars())
                if (regs.count(u) && !defined.count(u)) use_b[b].insert(u);
            auto lhs = ins->GetLhsId();
            if (lhs.has_value() && !lhs->empty()) {
                def_b[b].insert(*lhs);
                defined.insert(*lhs);
            }
        }
        live_in[b];   // seed every reachable block (empty)
    }
    for (bool changed = true; changed;) {
        changed = false;
        for (auto it = blocks.rbegin(); it != blocks.rend(); ++it) {
            NodeBase* b = *it;
            std::set<std::string> out;
            std::set<NodeBase*> seen;
            for (NodeBase* s : graph.all_sucs(b)) {
                if (!reachable(s) || !seen.insert(s).second) continue;
                auto lit = live_in.find(s);
                if (lit != live_in.end())
                    out.insert(lit->second.begin(), lit->second.end());
            }
            std::set<std::string> in = use_b[b];
            for (const std::string& v : out)
                if (!def_b[b].count(v)) in.insert(v);
            if (in != live_in[b]) { live_in[b] = std::move(in); changed = true; }
        }
    }

    // --- phi insertion (Cytron iterated dominance frontier, liveness-pruned) --
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
                // Pruned SSA: no phi where reg is not live-in (dead phi).
                auto lvit = live_in.find(w);
                if (lvit == live_in.end() || !lvit->second.count(reg)) continue;
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

// -----------------------------------------------------------------------------
// Phase B1: type-bounds model.
// -----------------------------------------------------------------------------
namespace {

// A Dalvik reference descriptor is `L...;` (class) or `[...` (array). Everything
// else that is a real descriptor is a primitive (Z/B/C/S/I/J/F/D) or void.
// (Local mirror of dataflow.cpp's anonymous is_ref — kept small, not shared, to
// avoid a header dependency for a two-line test.)
bool BoundIsRef(const std::string& t) {
    return !t.empty() && (t.front() == 'L' || t.front() == '[');
}
bool BoundIsPrim(const std::string& t) {
    static const std::string kPrim = "ZBCSIJFD";
    return t.size() == 1 && kPrim.find(t[0]) != std::string::npos;
}

// The type the DEFINING instruction produces = the type of its rhs expression.
// get_type() already resolves per IR class (NEW→class, INVOKE→return/base,
// CONST→literal type, field→field type, MOVE_EXCEPTION→catch type, CHECK_CAST→
// cast type), which is exactly what SplitVariables reads as the def type.
//
// EXCEPTION — an ARRAY LOAD (`vDst = vArr[i]`) derives its element type by
// stripping one '[' from the ARRAY operand's CURRENT (shared, DAD last-write)
// Variable type — STALE when the array register is reused across types, so it
// reports e.g. "I" for a `String[]` load (the exact false conflict this creates:
// an aget-object result mistyped I merges with a reference use). Same staleness
// family as a reg-move; return "" (no ASSIGN bound — the version's type comes
// from its USES / Phase B4 propagation). A primitive/reference aget alike is
// affected, so all array loads are skipped.
std::string ProducedType(IRForm* ins) {
    auto rhs = ins->get_rhs();
    if (rhs.empty() || !rhs[0]) return {};
    if (dynamic_cast<ArrayLoadExpression*>(rhs[0].get())) return {};
    return rhs[0]->get_type();
}

// A narrow-int literal 0 is the polymorphic null/zero — in Dalvik `const 0` is
// BOTH the integer 0 and the null reference (the writer already renders `= null`
// for a reference lhs). It constrains NEITHER primitive nor reference on its own;
// recording its ASSIGN bound as "I" would force a FALSE int↔ref conflict wherever
// a `cond ? obj : null` phi-merges the 0 with a real reference. So a def whose rhs
// is such a literal contributes NO ASSIGN bound — the version's type is decided by
// its USE positions. (A wide/float/double zero — J/F/D — is a genuine primitive
// 0, NOT null-compatible, so it is NOT skipped.)
bool IsNarrowZeroConst(IRForm* ins) {
    auto rhs = ins->get_rhs();
    if (rhs.empty() || !rhs[0]) return false;
    auto* c = dynamic_cast<Constant*>(rhs[0].get());
    if (!c || c->get_int_value() != 0) return false;
    const std::string& t = c->get_type();
    return t == "I" || t == "Z" || t == "B" || t == "C" || t == "S";
}

// A register-to-register move (`vDst = move[/object/wide] vSrc`) copies a value;
// its produced type is the SOURCE's type. But get_type() reads the source
// Variable's CURRENT (DAD last-write) type — STALE when the source register is
// reused across types after the move, so it reports e.g. "I" for a value that is
// really an array. Taking that as the ASSIGN bound manufactures false int↔ref
// conflicts corpus-wide. In real SSA a move is an equality edge resolved by type
// PROPAGATION (jadx TypeUpdate; our Phase B4). Until then, a reg-move def
// contributes NO ASSIGN bound — the version's type comes from its USES (which are
// position-exact). A move-RESULT (MoveKind::Unknown — the result of an invoke)
// keeps its assign: its source is a fresh gen-ret typed by the callee return, not
// a reused register, so it is reliable.
bool IsRegMoveDef(IRForm* ins) {
    auto* mv = dynamic_cast<MoveExpression*>(ins);
    return mv && mv->move_kind() != MoveKind::Unknown;
}

}  // namespace

BoundsResult ComputeTypeBounds(
    Graph& graph, const SsaResult& ssa,
    const std::map<std::string, std::string>& param_types,
    const std::string& ret_type) {
    BoundsResult out;

    // Reverse def_site: a real def loc -> the (reg, version) it defines. Each loc
    // defines at most one register (the instruction's single LHS), so this is
    // well-formed. Live-in versions (DEF_LIVEIN) get their ASSIGN bound directly
    // from param_types; phi / undef versions have no ASSIGN bound of their own.
    std::map<int, std::pair<std::string, int>> real_def;   // loc -> (reg, ver)
    for (const auto& [key, loc] : ssa.def_site) {
        if (loc >= 0) {
            real_def[loc] = key;
        } else if (loc == SsaResult::DEF_LIVEIN) {
            auto pit = param_types.find(key.first);
            if (pit != param_types.end() && !pit->second.empty())
                out.bounds[key].assign = pit->second;
        }
    }

    // Record a USE bound: vid used at loc L requires type `t`. Map the use to its
    // SSA version via use_version, then attach the typed bound to that value.
    auto note_use = [&](const std::string& vid, int loc, const std::string& t) {
        if (vid.empty() || t.empty()) return;
        auto vit = ssa.use_version.find({vid, loc});
        if (vit == ssa.use_version.end()) return;   // not an SSA-tracked use
        out.bounds[{vid, vit->second}].uses.push_back(t);
    };

    // Detect the required type of each operand position of `f` at loc L. Mirrors
    // note_obj / note_int in dataflow.cpp, but every position now yields a TYPED
    // bound instead of a boolean gate. Run on both the instruction and its rhs[0]
    // (a value-producing invoke/field-access is nested in rhs, a void statement
    // is the top-level ins — same dual dispatch note_obj uses).
    auto note_bounds = [&](IRForm* f, int loc) {
        if (auto* inv = dynamic_cast<InvokeInstruction*>(f)) {
            // receiver requires the method's declaring class. Use the RAW Dalvik
            // descriptor triple()[0] — NOT cls(), which is the GetType()-CONVERTED
            // Java form ("Foo" / "java.lang.String"). Every other bound in the
            // model (and is_assignable) is a raw descriptor; a converted receiver
            // bound would fail BoundIsRef and be silently dropped, losing the
            // "used as a reference" signal.
            note_use(inv->base(), loc, inv->triple()[0]);
            const auto& a = inv->args();
            const auto& pt = inv->ptype();
            if (a.size() == pt.size())
                for (size_t i = 0; i < a.size(); ++i)
                    note_use(a[i], loc, pt[i]);   // arg requires the param type
        } else if (auto* ie = dynamic_cast<InstanceExpression*>(f)) {
            // iget `v = obj.field`: the object requires the declaring class
            // (raw descriptor via clsdesc(), not the converted cls()).
            note_use(ie->arg_id(), loc, ie->clsdesc());
        } else if (auto* ii = dynamic_cast<InstanceInstruction*>(f)) {
            // iput `obj.field = rhs`: owner requires class (raw clsdesc()), value
            // requires the field type (atype, already a raw descriptor).
            note_use(ii->lhs_id(), loc, ii->clsdesc());
            note_use(ii->rhs_id(), loc, ii->atype());
        } else if (auto* si = dynamic_cast<StaticInstruction*>(f)) {
            // sput `Cls.field = rhs`: the stored value requires the field type.
            note_use(si->rhs_id(), loc, si->ftype());
        } else if (auto* te = dynamic_cast<ThrowExpression*>(f)) {
            note_use(te->ref_id(), loc, "Ljava/lang/Throwable;");
        } else if (auto* ret = dynamic_cast<ReturnInstruction*>(f)) {
            if (ret->arg()) note_use(*ret->arg(), loc, ret_type);
        } else if (auto* be = dynamic_cast<BinaryExpression*>(f)) {
            // arithmetic operands require the operation's primitive width;
            // `instanceof` (arg1 is the tested OBJECT) is not an int use.
            if (be->op() != "instanceof") {
                std::string w = BoundIsPrim(be->get_type()) ? be->get_type() : "I";
                note_use(be->arg1_id(), loc, w);
                note_use(be->arg2_id(), loc, w);
            }
        } else if (auto* ue = dynamic_cast<UnaryExpression*>(f)) {
            std::string w = BoundIsPrim(ue->get_type()) ? ue->get_type() : "I";
            note_use(ue->arg_id(), loc, w);
        } else if (auto* al = dynamic_cast<ArrayLoadExpression*>(f)) {
            note_use(al->idx_id(), loc, "I");            // array index is int
        } else if (auto* as = dynamic_cast<ArrayStoreInstruction*>(f)) {
            note_use(as->index_id(), loc, "I");
        } else if (auto* na = dynamic_cast<NewArrayExpression*>(f)) {
            note_use(na->size_id(), loc, "I");           // array size is int
        } else if (auto* sw = dynamic_cast<SwitchExpression*>(f)) {
            note_use(sw->src_id(), loc, "I");            // switch selector is int
        } else if (auto* cz = dynamic_cast<ConditionalZExpression*>(f)) {
            // Dalvik if-ltz/lez/gtz/gez compare an INT; if-eqz/nez is the
            // reference null-check, so only the ordered ops prove an int use.
            const std::string& op = cz->op();
            if (op == "<" || op == "<=" || op == ">" || op == ">=")
                note_use(cz->arg_id(), loc, "I");
        } else if (auto* ce = dynamic_cast<ConditionalExpression*>(f)) {
            const std::string& op = ce->op();
            if (op == "<" || op == "<=" || op == ">" || op == ">=") {
                note_use(ce->arg1_id(), loc, "I");
                note_use(ce->arg2_id(), loc, "I");
            }
        }
    };

    for (NodeBase* n : graph.nodes) {
        auto* bb = dynamic_cast<BasicBlock*>(n);
        if (!bb) continue;
        for (const auto& [loc, ins] : bb->get_loc_with_ins()) {
            if (!ins) continue;
            // ASSIGN bound for the version defined at this loc.
            auto dit = real_def.find(loc);
            if (dit != real_def.end() && !IsNarrowZeroConst(ins.get()) &&
                !IsRegMoveDef(ins.get())) {
                std::string p = ProducedType(ins.get());
                if (!p.empty()) out.bounds[dit->second].assign = p;
            }
            // USE bounds from this instruction (and its rhs value expression).
            note_bounds(ins.get(), loc);
            auto rhs = ins->get_rhs();
            if (!rhs.empty() && rhs[0]) note_bounds(rhs[0].get(), loc);
        }
    }

    // Dedup + sort each version's USE bounds for determinism.
    for (auto& [key, tb] : out.bounds) {
        std::sort(tb.uses.begin(), tb.uses.end());
        tb.uses.erase(std::unique(tb.uses.begin(), tb.uses.end()), tb.uses.end());
    }
    return out;
}

// -----------------------------------------------------------------------------
// Phase B2: phi-web merge + hierarchy-based selection.
// -----------------------------------------------------------------------------
namespace {

int PrimRank(char c) {
    switch (c) {
        case 'J': return 2;       // long
        case 'F': return 3;       // float
        case 'D': return 4;       // double
        default:  return 1;       // Z/B/C/S/I (int-category)
    }
}

// Pick the narrowest reference satisfying every constraint: a supertype of each
// ASSIGN (each produced value assignable to it) AND a subtype of each USE
// (assignable to each required position), decided by the partial-sound oracle.
// Falls back conservatively (a single produced type, else the sorted-first
// bound) when the oracle cannot prove a unifying relationship — never invents a
// type outside the bound set. `refs` is the sorted-deduped union of all ref
// bounds; `assigns` / `uses` are their sorted-deduped ref subsets.
std::string SelectRef(
    const std::vector<std::string>& assigns,
    const std::vector<std::string>& uses,
    const std::vector<std::string>& refs,
    const std::function<bool(std::string_view, std::string_view)>& is_assignable) {
    auto assignable = [&](const std::string& a, const std::string& b) {
        return a == b || (is_assignable && is_assignable(a, b));
    };
    // A candidate c is valid iff every ASSIGN is assignable to c and c is
    // assignable to every USE.
    std::vector<std::string> valid;
    for (const std::string& c : refs) {
        bool ok = true;
        for (const std::string& a : assigns)
            if (!assignable(a, c)) { ok = false; break; }
        if (ok)
            for (const std::string& u : uses)
                if (!assignable(c, u)) { ok = false; break; }
        if (ok) valid.push_back(c);
    }
    if (!valid.empty()) {
        // Narrowest = a valid type assignable to every other valid (most
        // specific). refs is sorted → the first such is deterministic.
        for (const std::string& c : valid) {
            bool narrowest = true;
            for (const std::string& o : valid)
                if (!assignable(c, o)) { narrowest = false; break; }
            if (narrowest) return c;
        }
        return valid.front();      // no provable minimum → deterministic first
    }
    // No candidate satisfies every bound under the partial-sound oracle.
    //  * A SINGLE produced (assign) type is authoritative: the value IS that
    //    type, and an unprovable USE relationship is a framework subtype the
    //    dex-only oracle cannot see (real, just invisible) — return it.
    //  * TWO OR MORE mutually-incompatible reference types (assigns the oracle
    //    cannot unify, or uses with no common assign) is a genuine ref-vs-ref
    //    conflation the design defers — return EMPTY so SelectTypes marks the
    //    web UNRESOLVED rather than picking a type that satisfies no USE
    //    position (the unsound arbitrary pick an adversarial review flagged).
    if (assigns.size() == 1) return assigns.front();
    if (assigns.empty() && uses.size() == 1) return uses.front();
    if (assigns.empty() && uses.empty())
        return refs.empty() ? std::string{} : refs.front();
    return {};
}

}  // namespace

SelectResult SelectTypes(
    const SsaResult& ssa, const BoundsResult& bounds,
    const std::function<bool(std::string_view, std::string_view)>&
        is_assignable) {
    SelectResult out;

    // --- version universe + index map (for union-find) -----------------------
    // Every version appears as a def_site key (real / phi / live-in / undef).
    std::vector<std::pair<std::string, int>> vers;
    std::map<std::pair<std::string, int>, int> idx;
    for (const auto& [key, loc] : ssa.def_site) {
        (void)loc;
        idx[key] = static_cast<int>(vers.size());
        vers.push_back(key);
    }
    const int N = static_cast<int>(vers.size());
    if (N == 0) return out;

    // --- union-find: a phi ties its result and every operand (same reg) -------
    std::vector<int> parent(N);
    for (int i = 0; i < N; ++i) parent[i] = i;
    std::function<int(int)> find = [&](int x) {
        while (parent[x] != x) { parent[x] = parent[parent[x]]; x = parent[x]; }
        return x;
    };
    auto unite = [&](int a, int b) { parent[find(a)] = find(b); };
    for (const SsaPhi& phi : ssa.phis) {
        auto rit = idx.find({phi.reg, phi.result});
        if (rit == idx.end()) continue;
        for (const auto& [pred, ov] : phi.operands) {
            (void)pred;
            auto oit = idx.find({phi.reg, ov});
            if (oit != idx.end()) unite(rit->second, oit->second);
        }
    }

    // --- pool each web's ASSIGN / USE bounds ---------------------------------
    // Root index → the set of ASSIGN + USE bound types (deduped, split ref/prim).
    std::map<int, std::vector<std::string>> web_assign, web_use;
    for (int i = 0; i < N; ++i) {
        auto bit = bounds.bounds.find(vers[i]);
        if (bit == bounds.bounds.end()) continue;
        int r = find(i);
        if (!bit->second.assign.empty())
            web_assign[r].push_back(bit->second.assign);
        for (const std::string& u : bit->second.uses)
            web_use[r].push_back(u);
    }

    // --- select per web, then broadcast to every member ----------------------
    std::map<int, SelectedType> web_type;
    std::set<int> roots;
    for (int i = 0; i < N; ++i) roots.insert(find(i));
    for (int r : roots) {
        SelectedType sel;
        std::vector<std::string>& A = web_assign[r];
        std::vector<std::string>& U = web_use[r];
        auto sortdedup = [](std::vector<std::string>& v) {
            std::sort(v.begin(), v.end());
            v.erase(std::unique(v.begin(), v.end()), v.end());
        };
        sortdedup(A);
        sortdedup(U);

        std::vector<std::string> ref_a, ref_u, refs, prims;
        bool has_ref = false, has_prim = false;
        bool ref_use = false, prim_use = false;
        auto classify = [&](const std::string& t, std::vector<std::string>& refbin,
                            bool is_use) {
            if (BoundIsRef(t)) {
                has_ref = true; refbin.push_back(t); refs.push_back(t);
                if (is_use) ref_use = true;
            } else if (BoundIsPrim(t)) {
                has_prim = true; prims.push_back(t);
                if (is_use) prim_use = true;
            }
        };
        for (const std::string& a : A) classify(a, ref_a, false);
        for (const std::string& u : U) classify(u, ref_u, true);
        sortdedup(refs);

        ++out.webs;
        if (has_ref && has_prim) {
            // Genuine int↔reference conflation — no single Java type.
            sel.type = "Ljava/lang/Object;";
            sel.conflict = true;
            sel.resolved = true;
            sel.note = "prim={";
            for (const auto& p : prims) { sel.note += p; sel.note += ','; }
            sel.note += "} ref={";
            for (const auto& r : refs) { sel.note += r; sel.note += ','; }
            sel.note += "}";
            ++out.conflicts;
            if (ref_use && prim_use) ++out.conflicts_use;
        } else if (has_ref) {
            sel.type = SelectRef(ref_a, ref_u, refs, is_assignable);
            sel.resolved = !sel.type.empty();
        } else if (has_prim) {
            // Widen to the widest rank present (I vs J vs F vs D).
            std::string best;
            int best_rank = 0;
            for (const std::string& p : prims) {
                int rk = PrimRank(p[0]);
                if (rk > best_rank) { best_rank = rk; best = p; }
            }
            sel.type = best;
            sel.resolved = !best.empty();
        }
        web_type[r] = std::move(sel);
    }
    for (int i = 0; i < N; ++i)
        out.types[vers[i]] = web_type[find(i)];
    return out;
}

}  // namespace dexkit::dad
