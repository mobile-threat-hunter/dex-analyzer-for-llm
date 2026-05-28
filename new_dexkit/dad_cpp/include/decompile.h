// decompile.h — C++ port of androguard DAD decompile.py
// DAD: androguard/decompiler/decompile.py
//
// PORT STATUS:
//   - DvMethod  — DAD decompile.py:87  per-method driver — ported
//   - get_field_ast / DvClass / DvMachine — DEFERRED (DexKit's pybind11
//     layer iterates classes externally; AST output unused by current API).

#pragma once

#include <memory>
#include <string>

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

    // Runs the full pipeline. Idempotent if called twice; second call is
    // currently not supported (mutable state). Throws on malformed IR.
    void Process();

    // Returns the emitted Java source. Empty string before Process() is
    // called or if the method was native/abstract (no body).
    std::string GetSource() const { return source_; }

private:
    std::shared_ptr<const MethodSnapshot> snap_;
    Vmap vmap_;
    std::vector<int> lparams_;
    std::unique_ptr<Graph> graph_;
    GenInvokeRetName gen_ret_;
    std::string source_;
};

}  // namespace dexkit::dad
