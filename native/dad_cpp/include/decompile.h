// decompile.h — C++ port of androguard DAD decompile.py
// DAD: androguard/decompiler/decompile.py
//
// PORT STATUS:
//   - DvMethod  — DAD decompile.py:87  per-method driver — ported
//   - get_field_ast / DvClass / DvMachine — DEFERRED (DexKit's pybind11
//     layer iterates classes externally; AST output unused by current API).

#pragma once

#include <functional>
#include <memory>
#include <string>

#include "dast.h"
#include "graph.h"
#include "method_snapshot.h"
#include "opcode_ins.h"
#include "writer.h"

namespace dexkit::dad {

// DAD: decompile.py:87 DvMethod — full per-method decompilation pipeline.
//   1. Pre-populate Vmap with ThisParam/Param entries for registers.
//   2. construct(snapshot, vmap, gen_ret) → typed CFG.
//   3. dataflow passes: BuildDefUse → SplitVariables → DCE →
//      RegisterPropagation → PlaceDeclarations.
//   4. structural passes: SplitIfNodes → Simplify → IdentifyStructures.
//   5. Writer.WriteMethod() → Java text.
class DvMethod {
public:
    explicit DvMethod(std::shared_ptr<const MethodSnapshot> snap);

    // Class-hierarchy assignability oracle (`sub <: super`), injected by the
    // Decompiler from the IDexCodeSource so the hierarchy-free dad_cpp core can
    // do sound type inference (the reused-`this` materialisation). Defaults to
    // exact-equality (conservative) when unset. Set before Process()/ProcessAst().
    using IsAssignableFn =
        std::function<bool(std::string_view sub, std::string_view super)>;
    void SetIsAssignable(IsAssignableFn f) { is_assignable_ = std::move(f); }

    // Runs the full pipeline. Idempotent if called twice; second call is
    // currently not supported (mutable state). Throws on malformed IR.
    void Process();

    // DAD: decompile.py:135 DvMethod.process(doAST=True) — runs the same
    // pipeline but emits a nested AST (via JSONWriter) instead of Java text.
    // Use a fresh DvMethod instance (mutually exclusive with Process()).
    AstValue ProcessAst();

    // Returns the emitted Java source. Empty string before Process() is
    // called or if the method was native/abstract (no body).
    std::string GetSource() const { return source_; }

    // D-3 (dexllm#1) — (line ↔ dex offset) map captured during Process();
    // (statement_seq ↔ dex offset) map captured during ProcessAst(). Empty
    // before the corresponding run. See Writer::pc_map / JSONWriter::pc_map.
    const std::vector<std::pair<uint32_t, uint32_t>>& GetPcMap() const {
        return pc_map_;
    }

private:
    // Steps 1-4 of the pipeline (param seeding → Construct → dataflow →
    // structural passes). Returns true iff a usable graph (with entry) was
    // built; false for native/abstract/external methods with no code.
    bool BuildProcessedGraph();

    std::shared_ptr<const MethodSnapshot> snap_;
    IsAssignableFn is_assignable_;
    Vmap vmap_;
    std::vector<int> lparams_;
    std::unique_ptr<Graph> graph_;
    GenInvokeRetName gen_ret_;
    std::string source_;
    // D-3 — populated by Process() (line keys) or ProcessAst() (seq keys).
    std::vector<std::pair<uint32_t, uint32_t>> pc_map_;
};

}  // namespace dexkit::dad
