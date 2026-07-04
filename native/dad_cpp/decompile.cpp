// decompile.cpp — DAD decompile.py port (DvMethod only).

#include "decompile.h"

#include <algorithm>
#include <memory>
#include <string>

#include "basic_blocks.h"
#include "control_flow.h"
#include "dast.h"
#include "dataflow.h"
#include "graph.h"
#include "instruction.h"
#include "instruction_dispatch.h"
#include "ssa.h"
#include "util.h"
#include "writer.h"

#include <cstdio>
#include <cstdlib>

namespace dexkit::dad {

DvMethod::DvMethod(std::shared_ptr<const MethodSnapshot> snap)
    : snap_(std::move(snap)) {}

void DvMethod::Process() {
    if (!BuildProcessedGraph()) {
        // No usable graph. Distinguish:
        //   (a) External reference (access empty = no ClassDef in this dex)
        //       → emit empty string; this method's code lives elsewhere.
        //   (b) Abstract/native or empty-construct → emit signature.
        if (snap_ && snap_->meta.access.empty()) {
            source_ = "";  // external reference: nothing to emit
            return;
        }
        Writer w(snap_.get(), nullptr);
        w.WriteMethod();
        source_ = w.str();
        return;
    }
    Writer w(snap_.get(), graph_.get());
    w.WriteMethod();
    source_ = w.str();
    pc_map_ = w.pc_map();  // D-3 — (line ↔ dex offset)
}

AstValue DvMethod::ProcessAst() {
    if (!BuildProcessedGraph()) {
        // Native/abstract/external — DAD's get_ast with graph None still
        // emits the signature with body = null.
        JSONWriter jw(snap_.get(), nullptr);
        return jw.get_ast();
    }
    JSONWriter jw(snap_.get(), graph_.get());
    AstValue ast = jw.get_ast();
    pc_map_ = jw.pc_map();  // D-3 — (statement_seq ↔ dex offset)
    return ast;
}

bool DvMethod::BuildProcessedGraph() {
    if (!snap_ || !snap_->entry_block_id) return false;

    const MethodMeta& m = snap_->meta;

    // 1. Pre-populate Vmap with ThisParam/Param.
    //    DAD: DvMethod.__init__ lines 116-130.
    int start = static_cast<int>(snap_->registers_size)
              - static_cast<int>(snap_->ins_size);
    int num_param = 0;
    bool is_static = std::find(m.access.begin(), m.access.end(), "static")
                     != m.access.end();
    if (!is_static) {
        const std::string key = "v" + std::to_string(start);
        vmap_[key] = std::make_shared<ThisParam>(key, m.cls_name);
        lparams_.push_back(start);
        ++num_param;
    }
    for (const std::string& ptype : m.params_type) {
        int reg = start + num_param;
        const std::string key = "v" + std::to_string(reg);
        vmap_[key] = std::make_shared<Param>(key, ptype);
        lparams_.push_back(reg);
        num_param += static_cast<int>(GetTypeSize(ptype));
    }

    // 2. CFG construction.
    graph_ = Construct(*snap_, vmap_, gen_ret_);
    if (!graph_ || !graph_->entry) {
        // Construct returned empty — caller falls back to signature-only.
        return false;
    }

    // 3. Dataflow analyses.
    //    lparams as string keys (DAD uses int keys; we use "v<N>").
    std::vector<std::string> lparam_keys;
    for (int reg : lparams_) lparam_keys.push_back("v" + std::to_string(reg));

    auto chains = BuildDefUse(*graph_, lparam_keys);

    // Phase 1c (SSA rollout): analysis-only oracle. Builds the SSA view and
    // checks it reconstructs the reaching-def chains, WITHOUT mutating the IR
    // (output stays byte-identical). Env-gated so it only runs during
    // validation sweeps. Removed / replaced by the real wiring in Phase 2.
    if (std::getenv("DEXLLM_SSA_VERIFY")) {
        auto ssa = BuildSsa(*graph_, lparam_keys);
        auto rep = VerifySsa(*graph_, lparam_keys, ssa, chains.ud);
        if (rep.mismatches) {
            std::fprintf(stderr,
                         "SSA_ORACLE cls=%s m=%s uses=%ld mism=%ld first=%s\n",
                         m.cls_name.c_str(), m.name.c_str(), rep.uses_checked,
                         rep.mismatches, rep.first.c_str());
        }
    }

    // var_to_name (DAD): int-keyed lvars dict. DAD seeds `var_to_name` with
    // params, then `construct()` populates it with every register it sees
    // through `get_variables(vmap, reg)`. By the time `split_variables` runs,
    // var_to_name covers all locals too — that's what makes per-register
    // splitting work.
    // We mirror that by walking the full string-keyed vmap and converting
    // every `"vN"` key into its int form. (Previously we only copied params,
    // so SplitVariables saw an empty set of candidates and produced un-split
    // variables — the root of the IR-cycle / `v1` vs `v1_1` divergence.)
    std::unordered_map<int, IRFormPtr> lvars;
    for (const auto& [key, var] : vmap_) {
        if (key.empty() || key.front() != 'v') continue;
        try {
            const int reg = std::stoi(key.substr(1));
            lvars[reg] = var;
        } catch (...) {
            continue;
        }
    }
    SplitVariables(*graph_, lvars, chains.du, chains.ud);
    // Beyond-DAD: an unsplit reused `this` register (`this = X`, invalid Java) is
    // materialised as a fresh local seeded `vX = this`. Only fires when a `this =`
    // would be emitted; on success the graph changed (injected copy + renumbered
    // locs), so the def-use chains are recomputed below before their consumers.
    bool mat_this = false;
    if (!is_static) {
        mat_this = MaterializeReusedThis(*graph_, lvars, start, m.cls_name,
                                         m.ret_type, m.name == "<init>",
                                         is_assignable_);
    }
    // Beyond-DAD: re-type `<init>` constructor results from the now-finalized
    // base (split_variables can read a stale base for them — version order).
    FixInitResultTypes(*graph_, m.ret_type);
    if (mat_this) {
        graph_->number_ins();
        chains = BuildDefUse(*graph_, lparam_keys);
    }
    DeadCodeElimination(*graph_, chains.du, chains.ud);
    RegisterPropagation(*graph_, chains.du, chains.ud);

    // dvars for PlaceDeclarations — string-keyed mirror of lvars.
    std::unordered_map<std::string, IRFormPtr> dvars;
    for (const auto& [reg, var] : lvars) {
        dvars["v" + std::to_string(reg)] = var;
    }
    PlaceDeclarations(*graph_, dvars, chains.du, chains.ud);

    // 4. Structural passes.
    SplitIfNodes(*graph_);
    Simplify(*graph_);
    graph_->compute_rpo();
    auto idoms = graph_->immediate_dominators();
    IdentifyStructures(*graph_, idoms);

    return true;
}

}  // namespace dexkit::dad
